// OAuth state for the hosted MCP server (docs/hosting.md "OAuth for MCP clients"): the
// DCR clients and the grants (one per approved sign-in) with their CURRENT access and
// refresh token hashes. Codes and in-flight sign-ins are memory-only (src/mcp-oauth.ts).
//
//   tokens     zeusi_at_<43> (access, 1 h), zeusi_rt_<43> (refresh, 30 d, rotated on every use):
//              32 random bytes, base64url. Only HMAC-SHA256(signing key, token) is stored; the
//              plaintext lives in the HTTP response and nowhere else. A new signing key makes
//              every stored hash unusable (kill switch: rotate ZEUSI_OAUTH_SIGNING_KEY).
//   reuse      a refresh token that was already rotated away revokes its whole grant.
//   file       { "version": 1, "clients": [...], "grants": [...] } on the Fly volume, 0600 in a
//              0700 directory owned by the process user, written atomically (temp + rename)
//              under the same O_EXCL lock-file convention as the tokens file. It is re-read
//              when its stat signature changes, so `zeusi mcp-oauth revoke` takes effect
//              without a restart. A file that does not validate is never overwritten and
//              turns OAuth off (fail closed).
//   bounds     at most MAX_CLIENTS clients and MAX_GRANTS grants; expired / revoked rows are
//              pruned first, then the oldest client without a live grant / the oldest grant.
//   tenant     the workspace a grant reads (docs/plans/2026-11-18-open-signup-workspaces-plan.md
//              KTD7): `team` or a personal workspace id, set at sign-in from the server's own
//              routing and kept through every rotation. A grant WITHOUT the field was written before
//              open sign-up, when only allowlisted operator identities could get a grant at all, so it
//              reads as `team`. No request can change it.
//   scope      `zeusi.read`, or `zeusi.read zeusi.workspace_write` (docs/plans/2026-11-18-workspace-write-import-plan.md
//              KTD1): write into the grant's OWN personal workspace only. Only a personal tenant can
//              carry it (the file refuses anything else), it is set at sign-in by the server (never
//              from the client's requested scope) and kept through every rotation; a read-only grant
//              is never upgraded in place: the user signs in again (new consent, new grant).
//   session    (C4, docs/plans/2026-11-18-c4-enroll.md KTD3) a PERSONAL grant may carry
//   wraps      `session_wraps`: the workspace DEK wrapped under its current access token and under its
//              current refresh token (two 61-byte C1 wraps, base64url, wrap ids sess:access|refresh:<grant_id>).
//              They open only with those tokens, which this file never holds. Written in the same commit
//              as the grant (code exchange) or the rotation (refresh: old wraps replaced, never kept);
//              removed on every revoke (and a revoked or expired grant is pruned from the file at the next
//              commit). The store never wraps or unwraps itself: callers pass the sealed values.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, closeSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { z } from 'zod';
import { TOKEN_ID_RE } from './mcp-tokens.ts';
import { WORK_TENANT, TENANT_ID_RE, TENANT_REF_RE } from './tenant-ddl.ts';

export const ACCESS_TTL_MS = 60 * 60_000;
export const REFRESH_TTL_MS = 30 * 86_400_000;
export const MAX_CLIENTS = 500;
export const MAX_GRANTS = 1000;
/** Rotated-away refresh hashes kept per grant for reuse detection. */
export const RETIRED_KEEP = 8;
export const GRANT_SCOPE_READ = 'zeusi.read';
export const GRANT_SCOPE_WORKSPACE_WRITE = 'zeusi.read zeusi.workspace_write';
export const OAUTH_ACCESS_RE = /^zeusi_at_[A-Za-z0-9_-]{43}$/;
export const OAUTH_REFRESH_RE = /^zeusi_rt_[A-Za-z0-9_-]{43}$/;
export const CLIENT_ID_RE = /^zc_[A-Za-z0-9_-]{22}$/;
const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
/** A C1 wrapped DEK (61 bytes: 0x01 || nonce || ct || tag) in base64url without padding. */
const SEALED_DEK_B64U = /^A[A-Za-z0-9_-]{81}$/;
/** A signature no file has: forces the next sync() to re-read the file. */
const STALE = 'stale';

export class OAuthStoreError extends Error {
  override name = 'OAuthStoreError';
}

const isoTs = z.iso.datetime({ offset: true });
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
const ClientRow = z.strictObject({
  client_id: z.string().regex(CLIENT_ID_RE),
  client_name: z.string().max(100).nullable(),
  redirect_uris: z.array(z.string().max(512)).min(1).max(10),
  created_at: isoTs,
  revoked_at: isoTs.nullable(),
});
const GrantRowShape = z.strictObject({
  grant_id: z.string().regex(TOKEN_ID_RE),
  client_id: z.string().max(512),
  subject: z.string().regex(/^github:[0-9]{1,20}$/),
  login: z.string().regex(/^[A-Za-z0-9-]{1,39}$/),
  scope: z.enum([GRANT_SCOPE_READ, GRANT_SCOPE_WORKSPACE_WRITE]),
  /** Absent only on grants written before open sign-up: those read as `team` (tenantOf). */
  tenant: z.string().regex(TENANT_REF_RE).optional(),
  created_at: isoTs,
  revoked_at: isoTs.nullable(),
  access_hash: hex64,
  access_expires_at: isoTs,
  refresh_hash: hex64,
  refresh_expires_at: isoTs,
  retired_refresh: z.array(hex64).max(RETIRED_KEEP),
  /** C4: the workspace DEK wrapped under this grant's current tokens (personal grants only). */
  session_wraps: z.strictObject({
    key_version: z.number().int().min(1).max(32767),
    access: z.string().regex(SEALED_DEK_B64U),
    refresh: z.string().regex(SEALED_DEK_B64U),
  }).optional(),
});
/** A write-own-workspace grant must name a personal workspace: never `team`, never a legacy row. */
const GrantRow = GrantRowShape
  .refine((g) => g.scope === GRANT_SCOPE_READ || (g.tenant !== undefined && TENANT_ID_RE.test(g.tenant)))
  // Session wraps exist only for a personal workspace: never `team`, never a legacy row (C4).
  .refine((g) => g.session_wraps === undefined || (g.tenant !== undefined && TENANT_ID_RE.test(g.tenant)));
const StoreFile = z.strictObject({ version: z.literal(1), clients: z.array(ClientRow), grants: z.array(GrantRow) });
export type OAuthClientRow = z.infer<typeof ClientRow>;
export type OAuthGrantRow = z.infer<typeof GrantRow>;
export type GrantSessionWraps = NonNullable<OAuthGrantRow['session_wraps']>;
/** Seals the session wraps of a new grant / rotation from its id and its new tokens (C4). */
export type SealSession = (grantId: string, accessToken: string, refreshToken: string) => GrantSessionWraps;
/** Rewraps at refresh from the OLD refresh token; null drops the wraps (fail closed). */
export type ResealSession = (grant: OAuthGrantRow, oldRefresh: string, accessToken: string, refreshToken: string) => GrantSessionWraps | null;
/** Why a grant's session ended (C7 hook, D13). */
export type SessionEndReason = 'revoked' | 'reused_refresh' | 'client_revoked' | 'revoked_all' | 'tenant_revoked';
type StoreDoc = z.infer<typeof StoreFile>;

export interface IssuedTokens {
  grant: OAuthGrantRow;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface OAuthStoreOptions {
  /**
   * HMAC key for token hashes (the OAuth signing key). Omitted only by the offline admin CLI
   * (list / revoke by id), which never hashes a token: every token operation then throws.
   */
  hashKey?: string | undefined;
  /** Volume file; omitted = memory only (tests, and nothing persists). */
  path?: string | undefined;
  now?: (() => number) | undefined;
  /** TEST seam: the uid the file and its directory must belong to (default the process uid). */
  uid?: number | undefined;
  /**
   * C4 KTD15: called after a commit that ended grants (revoke, reused refresh, client revoke, revokeAll,
   * revokeTenant), once per grant, with its id and workspace. Chip C7 evicts the B1 cache for that
   * workspace here (D13). Errors are swallowed: the revoke already happened.
   */
  onSessionEnded?: ((e: { grantId: string; tenant: string; reason: SessionEndReason }) => void) | undefined;
}

const iso = (ms: number) => new Date(ms).toISOString();

/** True only for a grant that may write into its own personal workspace (KTD1). */
export function grantWritesOwn(g: Pick<OAuthGrantRow, 'tenant' | 'scope'>): boolean {
  return g.scope === GRANT_SCOPE_WORKSPACE_WRITE && g.tenant !== undefined && TENANT_ID_RE.test(g.tenant);
}

/** The workspace a grant reads. A legacy grant (no field) is a team grant (header, `tenant`). */
export function tenantOf(g: Pick<OAuthGrantRow, 'tenant'>): string {
  return g.tenant ?? WORK_TENANT;
}

export function newToken(prefix: 'at' | 'rt' | 'ac'): string {
  return `zeusi_${prefix}_${randomBytes(32).toString('base64url')}`;
}

function newGrantId(): string {
  return [...randomBytes(12)].map((b) => BASE32[b & 31]).join('');
}

/** The grant without its session wraps (revoked or rotated without a reseal). */
function withoutWraps(g: OAuthGrantRow): OAuthGrantRow {
  const { session_wraps: _dropped, ...rest } = g;
  return rest;
}

function errCode(e: unknown): string {
  return String((e as { code?: unknown })?.code ?? 'unknown').replace(/[^A-Z0-9_]/g, '') || 'unknown';
}

export class OAuthStore {
  private readonly o: OAuthStoreOptions;
  private readonly now: () => number;
  private doc: StoreDoc = { version: 1, clients: [], grants: [] };
  private sig: string | null = null;
  private byAccess = new Map<string, OAuthGrantRow>();
  private byRefresh = new Map<string, OAuthGrantRow>();
  private byRetired = new Map<string, OAuthGrantRow>();

  constructor(o: OAuthStoreOptions) {
    if (o.hashKey !== undefined && o.hashKey.length < 32) throw new OAuthStoreError('signing key too short');
    this.o = o;
    this.now = o.now ?? Date.now;
    this.load(true);
  }

  /** HMAC-SHA256 of a token under the signing key (hex). Never the token itself. */
  hash(token: string): string {
    if (this.o.hashKey === undefined) throw new OAuthStoreError('no signing key (admin store cannot hash tokens)');
    return createHmac('sha256', this.o.hashKey).update(token, 'utf8').digest('hex');
  }

  private signature(): string | null {
    if (!this.o.path) return null;
    try {
      const f = statSync(this.o.path);
      return [f.ino, f.size, f.mtimeMs, f.ctimeMs, f.mode].join(':');
    } catch {
      return null;
    }
  }

  /**
   * (Re)read the file when its signature changed. `initial`: a missing file is an empty store.
   * Any invalid state throws OAuthStoreError (the caller turns OAuth off / answers 503).
   */
  private load(initial = false): void {
    const path = this.o.path;
    if (!path) return;
    const sig = this.signature();
    if (!initial && sig === this.sig) return;
    // C7 KTD4: an OFFLINE change (`zeusi mcp-oauth revoke` in another process) ends sessions too: every grant
    // that was live before this re-read and is revoked or gone after it fires the session-end hook (D13 eviction).
    const before = initial ? null : this.doc;
    try {
      this.loadFile(path, sig);
    } finally {
      if (before && this.doc !== before) this.endedOffline(before);
    }
  }

  /** The grants live in `before` that the current document revoked or dropped: the session-end hook, once each. */
  private endedOffline(before: StoreDoc): void {
    const now = new Map(this.doc.grants.map((g) => [g.grant_id, g]));
    const gone = before.grants.filter((g) => g.revoked_at === null && (now.get(g.grant_id)?.revoked_at ?? 'gone') !== null);
    if (gone.length > 0) this.ended(gone, 'revoked');
  }

  private loadFile(path: string, sig: string | null): void {
    const uid = this.o.uid ?? process.getuid?.();
    let d;
    try {
      d = statSync(dirname(path));
    } catch {
      throw new OAuthStoreError('oauth store directory missing');
    }
    if (!d.isDirectory() || (d.mode & 0o077) !== 0) throw new OAuthStoreError('oauth store directory must be 0700');
    if (uid !== undefined && d.uid !== uid) throw new OAuthStoreError('oauth store directory has another owner');
    if (sig === null) {
      // Missing: empty store (created on the first write). A file that vanished later is
      // also treated as empty: every grant is gone, so nothing authenticates (fail closed).
      this.sig = null;
      this.replace({ version: 1, clients: [], grants: [] });
      return;
    }
    const f = lstatSync(path);
    if (!f.isFile() || (f.mode & 0o077) !== 0) throw new OAuthStoreError('oauth store file must be a 0600 regular file');
    if (uid !== undefined && f.uid !== uid) throw new OAuthStoreError('oauth store file has another owner');
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(path, 'utf8'));
    } catch {
      throw new OAuthStoreError('oauth store file does not parse');
    }
    const r = StoreFile.safeParse(parsed);
    if (!r.success) throw new OAuthStoreError('oauth store file does not validate');
    this.sig = sig;
    this.replace(r.data);
  }

  private replace(doc: StoreDoc): void {
    this.doc = doc;
    this.byAccess = new Map(doc.grants.map((g) => [g.access_hash, g]));
    this.byRefresh = new Map(doc.grants.map((g) => [g.refresh_hash, g]));
    this.byRetired = new Map(doc.grants.flatMap((g) => g.retired_refresh.map((h) => [h, g] as const)));
  }

  /** Pick up an offline change (revoke) before answering. Throws OAuthStoreError when invalid. */
  sync(): void {
    this.load(false);
  }

  /**
   * Prune, validate and persist (atomic, 0600, under the lock), then re-index. If the file
   * changed since it was last read (an offline `zeusi mcp-oauth revoke` raced this write), or
   * anything fails, nothing is written, the in-memory change is dropped (the next sync()
   * re-reads the file) and OAuthStoreError is thrown: the request answers 503 and the client
   * retries, so an offline revoke is never overwritten.
   */
  private commit(): void {
    this.prune();
    const valid = StoreFile.parse(this.doc);
    const path = this.o.path;
    if (!path) {
      this.replace(valid);
      return;
    }
    const lock = `${path}.lock`;
    let lockFd: number;
    try {
      lockFd = openSync(lock, 'wx', 0o600);
    } catch (e) {
      this.sig = STALE;
      throw new OAuthStoreError(errCode(e) === 'EEXIST' ? 'oauth store is locked by another writer' : `oauth store lock not created (${errCode(e)})`);
    }
    try {
      if (this.signature() !== this.sig) throw new OAuthStoreError('oauth store changed on disk; retry');
      const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
      try {
        const fd = openSync(tmp, 'wx', 0o600);
        try {
          writeSync(fd, `${JSON.stringify(valid, null, 2)}\n`);
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
        chmodSync(tmp, 0o600);
        renameSync(tmp, path);
      } catch (e) {
        try { unlinkSync(tmp); } catch { /* already gone */ }
        throw new OAuthStoreError(`oauth store not written (${errCode(e)})`);
      }
      this.sig = this.signature();
      this.replace(valid);
    } catch (e) {
      this.sig = STALE;
      throw e;
    } finally {
      closeSync(lockFd);
      try { unlinkSync(lock); } catch { /* already gone */ }
    }
  }

  /** C7 hook (KTD15), after the commit that ended these grants. Never throws. */
  private ended(grants: readonly OAuthGrantRow[], reason: SessionEndReason): void {
    const hook = this.o.onSessionEnded;
    if (!hook) return;
    for (const g of grants) {
      try { hook({ grantId: g.grant_id, tenant: tenantOf(g), reason }); } catch { /* the revoke stands */ }
    }
  }

  private live(g: OAuthGrantRow, now: number): boolean {
    return g.revoked_at === null && Date.parse(g.refresh_expires_at) > now;
  }

  private prune(): void {
    const now = this.now();
    const grants = this.doc.grants.filter((g) => this.live(g, now));
    while (grants.length > MAX_GRANTS) grants.shift();
    const liveClients = new Set(grants.map((g) => g.client_id));
    const clients = this.doc.clients.filter((c) => c.revoked_at === null);
    while (clients.length > MAX_CLIENTS) {
      const i = clients.findIndex((c) => !liveClients.has(c.client_id));
      clients.splice(i >= 0 ? i : 0, 1);
    }
    this.doc = { version: 1, clients, grants };
  }

  // -------------------------------------------------------------------------
  // Clients (DCR)

  registerClient(meta: { clientName: string | null; redirectUris: string[] }): OAuthClientRow {
    this.sync();
    const row: OAuthClientRow = {
      client_id: `zc_${randomBytes(16).toString('base64url')}`, client_name: meta.clientName, redirect_uris: [...meta.redirectUris],
      created_at: iso(this.now()), revoked_at: null,
    };
    this.doc = { ...this.doc, clients: [...this.doc.clients, row] };
    this.commit();
    return row;
  }

  /** A registered, not revoked client, or null. */
  client(clientId: string): OAuthClientRow | null {
    this.sync();
    const c = this.doc.clients.find((x) => x.client_id === clientId);
    return c && c.revoked_at === null ? c : null;
  }

  /** Revoke a client and every grant it holds. False when unknown. */
  revokeClient(clientId: string): boolean {
    this.sync();
    const at = iso(this.now());
    let hit = false;
    const clients = this.doc.clients.map((c) => (c.client_id === clientId && c.revoked_at === null ? (hit = true, { ...c, revoked_at: at }) : c));
    const ended = this.doc.grants.filter((g) => g.client_id === clientId && g.revoked_at === null);
    const grants = this.doc.grants.map((g) => (g.client_id === clientId && g.revoked_at === null ? (hit = true, { ...withoutWraps(g), revoked_at: at }) : g));
    if (!hit) return false;
    this.doc = { version: 1, clients, grants };
    this.commit();
    this.ended(ended, 'client_revoked');
    return true;
  }

  // -------------------------------------------------------------------------
  // Grants

  /**
   * `workspaceWrite`: the consent the user just approved covered writing into their own workspace.
   * Honoured only for a personal tenant; a team grant is always read-only.
   */
  createGrant(g: { clientId: string; subject: string; login: string; tenant: string; workspaceWrite?: boolean; seal?: SealSession | undefined }): IssuedTokens {
    if (!TENANT_REF_RE.test(g.tenant)) throw new OAuthStoreError('grant without a valid workspace');
    const scope = g.workspaceWrite === true && TENANT_ID_RE.test(g.tenant) ? GRANT_SCOPE_WORKSPACE_WRITE : GRANT_SCOPE_READ;
    this.sync();
    const now = this.now();
    const accessToken = newToken('at');
    const refreshToken = newToken('rt');
    const grantId = newGrantId();
    // C4: the session wraps are sealed BEFORE the one commit, so the grant and its wraps land together.
    if (g.seal !== undefined && !TENANT_ID_RE.test(g.tenant)) throw new OAuthStoreError('session wraps need a personal workspace');
    const wraps = g.seal?.(grantId, accessToken, refreshToken);
    const grant: OAuthGrantRow = {
      grant_id: grantId, client_id: g.clientId, subject: g.subject, login: g.login, scope, tenant: g.tenant,
      created_at: iso(now), revoked_at: null,
      access_hash: this.hash(accessToken), access_expires_at: iso(now + ACCESS_TTL_MS),
      refresh_hash: this.hash(refreshToken), refresh_expires_at: iso(now + REFRESH_TTL_MS), retired_refresh: [],
      ...(wraps ? { session_wraps: wraps } : {}),
    };
    this.doc = { ...this.doc, grants: [...this.doc.grants, grant] };
    this.commit();
    return { grant, accessToken, refreshToken, expiresIn: ACCESS_TTL_MS / 1000 };
  }

  /** The live grant for an access token, or null (unknown, expired, revoked). */
  grantForAccess(accessToken: string): OAuthGrantRow | null {
    if (!OAUTH_ACCESS_RE.test(accessToken)) return null;
    this.sync();
    const h = this.hash(accessToken);
    const g = this.byAccess.get(h);
    if (!g || !timingSafeEqual(Buffer.from(g.access_hash), Buffer.from(h))) return null;
    const now = this.now();
    return this.live(g, now) && Date.parse(g.access_expires_at) > now ? g : null;
  }

  /**
   * C4: the session wraps of the live grant behind a live access token, or null (unknown, expired or
   * revoked token or grant, a grant without wraps, or a non-personal grant). Wraps only: opening them
   * needs the token itself (src/workspace-keys.ts openSessionDek).
   */
  sessionWrapsFor(accessToken: string): { grantId: string; tenant: string; wraps: GrantSessionWraps } | null {
    const g = this.grantForAccess(accessToken);
    if (!g || !g.session_wraps || g.tenant === undefined || !TENANT_ID_RE.test(g.tenant)) return null;
    return { grantId: g.grant_id, tenant: g.tenant, wraps: g.session_wraps };
  }

  /**
   * Rotate a refresh token: new access + new refresh in one step, the old refresh retired.
   * 'invalid' for anything else; a retired refresh token (reuse) also revokes the grant.
   * C4: a grant with session wraps gets them rewrapped by `reseal` (from the old refresh token) in the
   * same commit; without `reseal`, or when it returns null, the wraps are dropped, never kept.
   */
  rotate(refreshToken: string, clientId: string, reseal?: ResealSession): IssuedTokens | 'invalid' {
    if (!OAUTH_REFRESH_RE.test(refreshToken)) return 'invalid';
    this.sync();
    const now = this.now();
    const h = this.hash(refreshToken);
    const reused = this.byRetired.get(h);
    if (reused) {
      if (reused.revoked_at === null) this.revokeGrant(reused.grant_id, 'reused_refresh');
      return 'invalid';
    }
    const g = this.byRefresh.get(h);
    if (!g || !this.live(g, now) || g.client_id !== clientId) return 'invalid';
    const accessToken = newToken('at');
    const next = newToken('rt');
    let wraps: GrantSessionWraps | null = null;
    if (g.session_wraps && reseal) {
      try {
        wraps = reseal(g, refreshToken, accessToken, next);
      } catch {
        wraps = null;
      }
    }
    const updated: OAuthGrantRow = {
      ...withoutWraps(g), ...(wraps ? { session_wraps: wraps } : {}),
      access_hash: this.hash(accessToken), access_expires_at: iso(now + ACCESS_TTL_MS),
      refresh_hash: this.hash(next), refresh_expires_at: iso(now + REFRESH_TTL_MS),
      retired_refresh: [...g.retired_refresh, g.refresh_hash].slice(-RETIRED_KEEP),
    };
    this.doc = { ...this.doc, grants: this.doc.grants.map((x) => (x.grant_id === g.grant_id ? updated : x)) };
    this.commit();
    return { grant: updated, accessToken, refreshToken: next, expiresIn: ACCESS_TTL_MS / 1000 };
  }

  /** Revoke one grant; its session wraps go in the same commit (C4). */
  revokeGrant(grantId: string, reason: SessionEndReason = 'revoked'): boolean {
    this.sync();
    const at = iso(this.now());
    const ended = this.doc.grants.filter((g) => g.grant_id === grantId && g.revoked_at === null);
    if (ended.length === 0) return false;
    this.doc = { ...this.doc, grants: this.doc.grants.map((g) => (g.grant_id === grantId && g.revoked_at === null ? { ...withoutWraps(g), revoked_at: at } : g)) };
    this.commit();
    this.ended(ended, reason);
    return true;
  }

  /**
   * THE definition of "the grants of a workspace" (docs/plans/2026-11-20-workspaces-delete.md KTD11): every grant of
   * `tenant` not revoked yet. revokeTenant ends exactly these; countTenantGrants counts exactly these.
   */
  private tenantGrants(tenant: string): OAuthGrantRow[] {
    return this.doc.grants.filter((g) => g.revoked_at === null && tenantOf(g) === tenant);
  }

  /** How many grants revokeTenant(tenant) would end now. Read-only: re-reads the file, never commits or locks. */
  countTenantGrants(tenant: string): number {
    this.sync();
    return this.tenantGrants(tenant).length;
  }

  /** "Log out everywhere" for one workspace (C4): revoke every live grant of `tenant` in one commit. */
  revokeTenant(tenant: string): number {
    this.sync();
    const at = iso(this.now());
    const ended = this.tenantGrants(tenant);
    if (ended.length === 0) return 0;
    const ids = new Set(ended.map((g) => g.grant_id));
    this.doc = { ...this.doc, grants: this.doc.grants.map((g) => (ids.has(g.grant_id) ? { ...withoutWraps(g), revoked_at: at } : g)) };
    this.commit();
    this.ended(ended, 'tenant_revoked');
    return ended.length;
  }

  /** RFC 7009: revoke the grant behind an access or refresh token (the client must match). */
  revokeToken(token: string, clientId: string | null): void {
    this.sync();
    const h = this.hash(token);
    const g = this.byAccess.get(h) ?? this.byRefresh.get(h);
    if (g && (clientId === null || g.client_id === clientId)) this.revokeGrant(g.grant_id);
  }

  /** Revoke every live grant (operator kill switch). Returns how many. */
  revokeAll(): number {
    this.sync();
    const live = this.doc.grants.filter((g) => g.revoked_at === null).map((g) => g.grant_id);
    for (const id of live) this.revokeGrant(id, 'revoked_all');
    return live.length;
  }

  /** Operator view: ids, client, login, dates. Never a hash. */
  list(): { clients: Array<Omit<OAuthClientRow, never>>; grants: Array<Pick<OAuthGrantRow, 'grant_id' | 'client_id' | 'login' | 'created_at' | 'refresh_expires_at' | 'revoked_at'> & { tenant: string }> } {
    this.sync();
    return {
      clients: this.doc.clients.map((c) => ({ ...c })),
      grants: this.doc.grants.map((g) => ({
        grant_id: g.grant_id, client_id: g.client_id, login: g.login, tenant: tenantOf(g), created_at: g.created_at, refresh_expires_at: g.refresh_expires_at, revoked_at: g.revoked_at,
      })),
    };
  }
}
