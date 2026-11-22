// Bearer-token authentication for the hosted MCP server (docs/hosting.md "Auth"). Decides
// "who is calling and may they proceed" without an HTTP server, in this order:
//
//   0. tokens file state (re-read when its stat signature changes; the success cache is
//      cleared on every change). Unconfigured -> 503 not_configured, before parsing, no hash.
//   1. exactly one Authorization value, "Bearer <token>" (scheme case-insensitive, one space),
//      token matching zeusi_<12>_<43>. Malformed -> counted per IP only, 401, no hash.
//   2. success cache by token_id (SHA-256 of the full token, TTL 5 min). A hit re-checks that
//      the row is still usable and passes without a slow hash or the failed-auth gate.
//   3. failed-auth gate: 10 failures/min per client IP, 60/min global. Hashes still running
//      count against both (in-flight reservation), and at most 8 hashes may be in flight or
//      queued at once. Over -> 429, no hash.
//   4. row lookup: unknown, revoked or expired -> counted per IP only, 401, no hash.
//   5. slow hash + timingSafeEqual. Mismatch -> counted per IP and global, 401. Match -> cache fill.
//
// OAuth access tokens (src/mcp-oauth.ts, only when OAuth is configured) are a SECOND credential:
// a "Bearer zeusi_at_<43>" value skips the tokens file, passes the same per-IP failed-auth gate,
// then a keyed-hash lookup (no slow hash: the token is 256 random bits). The principal is always
// class "read"; a personal grant with scope zeusi.workspace_write also carries ownWrite (its own
// workspace only, docs/plans/2026-11-18-workspace-write-import-plan.md KTD1). With OAuth on, a request with NO Authorization header is a plain 401 (not 503,
// not counted) so claude.ai can discover the authorization server even before tokens exist.
//
// Every 401 is the same generic result; nothing says which check failed or how many tokens
// exist. Only failures count toward the failed-auth limits. The global bucket only counts
// failures that cost a slow hash, so anonymous garbage (malformed headers, invented ids)
// from many addresses cannot close the gate for every real token.

import { timingSafeEqual } from 'node:crypto';
import {
  isUsable, loadTokenStore, parseToken, storeSignature, tokenDigest, verifySecret, type TokenClass, type TokenRow, type TokenStore,
} from './mcp-tokens.ts';
import { OAUTH_ACCESS_RE } from './mcp-oauth-store.ts';
import { WORK_TENANT, TENANT_ID_RE } from './tenant-ddl.ts';
import { SlidingWindowLimiter } from './rate-limit.ts';

export const FAILED_AUTH_PER_IP = 10;
export const FAILED_AUTH_GLOBAL = 60;
export const AUTH_CACHE_TTL_MS = 5 * 60_000;
/** Slow hashes allowed to be running or queued on the single hash slot at once. */
export const MAX_INFLIGHT_HASHES = 8;

export interface AuthPrincipal {
  tokenId: string;
  assistant: string;
  cls: TokenClass;
  /**
   * The ONE workspace this credential reads (docs/plans/2026-11-18-open-signup-workspaces-plan.md
   * KTD7): `team` for every static bearer token and every the team / legacy OAuth grant, a personal
   * workspace id for a personal grant. Comes from the server's own records, never from the request.
   */
  tenant: string;
  /**
   * Personal OAuth grants with scope zeusi.workspace_write only
   * (docs/plans/2026-11-18-workspace-write-import-plan.md KTD1): may write into `tenant`, nothing
   * else. Never set for a static bearer token or a team grant. `cls` stays 'read'.
   */
  ownWrite?: true | undefined;
  /** The GitHub subject (`github:<id>`) of an OAuth grant: the write audit names it. Never a login or email. */
  subject?: string | undefined;
}

export type AuthResult =
  | { ok: true; principal: AuthPrincipal }
  | {
    ok: false; status: 401 | 429 | 503; errorClass: 'unauthorized' | 'auth_rate_limited' | 'not_configured';
    /** Only for the log: the id of an existing row that failed (never a caller-invented id). */
    tokenId?: string | undefined; retryAfterSec?: number | undefined;
  };

export interface AuthenticatorOptions {
  tokensPath: string;
  now?: (() => number) | undefined;
  /** TEST seam: the slow verify (default verifySecret). */
  verify?: ((row: TokenRow, secret: string) => Promise<boolean>) | undefined;
  limiter?: SlidingWindowLimiter | undefined;
  failedPerIp?: number | undefined;
  failedGlobal?: number | undefined;
  cacheTtlMs?: number | undefined;
  maxInflightHashes?: number | undefined;
  /** TEST seam: the uid the tokens file must belong to (default the process uid). */
  uid?: number | undefined;
  /** OAuth access-token lookup (src/mcp-oauth.ts OAuthServer); unset = OAuth off. */
  oauth?: { principalFor(accessToken: string): AuthPrincipal | null } | undefined;
}

interface CacheEntry {
  digest: Buffer;
  expires: number;
}

const UNAUTHORIZED = { ok: false, status: 401, errorClass: 'unauthorized' } as const;

export class Authenticator {
  private readonly o: AuthenticatorOptions;
  private readonly now: () => number;
  private readonly verify: (row: TokenRow, secret: string) => Promise<boolean>;
  private readonly limiter: SlidingWindowLimiter;
  private readonly cache = new Map<string, CacheEntry>();
  private sig: string | null | undefined;
  private store: TokenStore = { state: 'unconfigured', reason: 'not_loaded' };
  private inflight = 0;
  private readonly inflightByIp = new Map<string, number>();

  constructor(o: AuthenticatorOptions) {
    this.o = o;
    this.now = o.now ?? Date.now;
    this.verify = o.verify ?? verifySecret;
    this.limiter = o.limiter ?? new SlidingWindowLimiter({ maxKeys: 4096 });
  }

  /** Re-read the tokens file if its signature changed. Returns the current store. */
  refresh(): TokenStore {
    const sig = storeSignature(this.o.tokensPath);
    if (sig === null) {
      if (this.sig !== null) this.cache.clear();
      this.sig = null;
      this.store = { state: 'unconfigured', reason: 'unreadable' };
      return this.store;
    }
    if (sig !== this.sig) {
      this.sig = sig;
      this.cache.clear();
      this.store = loadTokenStore(this.o.tokensPath, { uid: this.o.uid });
    }
    return this.store;
  }

  /** `hashed`: a slow hash ran for this failure; only those fill the global bucket. */
  private fail(ip: string, now: number, hashed: boolean, tokenId?: string): AuthResult {
    this.limiter.add(`ip:${ip}`, 1, now);
    if (hashed) this.limiter.add('global', 1, now);
    return tokenId ? { ...UNAUTHORIZED, tokenId } : { ...UNAUTHORIZED };
  }

  /** Hashes currently running or queued (TEST/ops visibility). */
  inflightHashes(): number {
    return this.inflight;
  }

  /** `authorization`: every raw Authorization header value of the request. */
  async authenticate(authorization: readonly string[], ip: string): Promise<AuthResult> {
    const oauth = this.o.oauth;
    if (oauth) {
      if (authorization.length === 0) return { ...UNAUTHORIZED };
      const om = authorization.length === 1 ? /^(\S+) (\S+)$/.exec(authorization[0]!) : null;
      if (om && om[1]!.toLowerCase() === 'bearer' && OAUTH_ACCESS_RE.test(om[2]!)) {
        const now = this.now();
        const perIp = this.limiter.retryAfter(`ip:${ip}`, this.o.failedPerIp ?? FAILED_AUTH_PER_IP, 1 + (this.inflightByIp.get(ip) ?? 0), now);
        if (perIp > 0) return { ok: false, status: 429, errorClass: 'auth_rate_limited', retryAfterSec: perIp };
        const p = oauth.principalFor(om[2]!);
        if (!p) return this.fail(ip, now, false);
        // Re-shaped here so nothing but these fields can pass: class read, the grant's own tenant, and
        // ownWrite only together with a personal workspace id.
        const own = p.ownWrite === true && TENANT_ID_RE.test(p.tenant);
        return {
          ok: true,
          principal: {
            tokenId: p.tokenId, assistant: p.assistant, cls: 'read', tenant: p.tenant,
            ...(own ? { ownWrite: true as const } : {}), ...(p.subject && /^github:[0-9]{1,20}$/.test(p.subject) ? { subject: p.subject } : {}),
          },
        };
      }
    }
    const store = this.refresh();
    if (store.state !== 'loaded') return { ok: false, status: 503, errorClass: 'not_configured' };
    const now = this.now();

    const m = authorization.length === 1 ? /^(\S+) (\S+)$/.exec(authorization[0]!) : null;
    const parsed = m && m[1]!.toLowerCase() === 'bearer' ? parseToken(m[2]!) : null;
    if (!m || !parsed) return this.fail(ip, now, false);
    const token = m[2]!;
    const { tokenId, secret } = parsed;

    const cached = this.cache.get(tokenId);
    if (cached && cached.expires > now && timingSafeEqual(cached.digest, tokenDigest(token))) {
      const row = store.byId.get(tokenId);
      if (row && isUsable(row, now)) return { ok: true, principal: principal(row) };
      this.cache.delete(tokenId);
      return this.fail(ip, now, false, row ? tokenId : undefined);
    }

    // Every hash still in flight is treated as a pending failure, so N concurrent wrong
    // secrets for a known token_id cannot all pass the gate before the first one is counted.
    const ipInflight = this.inflightByIp.get(ip) ?? 0;
    const perIp = this.limiter.retryAfter(`ip:${ip}`, this.o.failedPerIp ?? FAILED_AUTH_PER_IP, 1 + ipInflight, now);
    const global = this.limiter.retryAfter('global', this.o.failedGlobal ?? FAILED_AUTH_GLOBAL, 1 + this.inflight, now);
    if (perIp > 0 || global > 0) return { ok: false, status: 429, errorClass: 'auth_rate_limited', retryAfterSec: Math.max(perIp, global) };

    const row = store.byId.get(tokenId);
    if (!row || !isUsable(row, now)) return this.fail(ip, now, false, row ? tokenId : undefined);
    if (this.inflight >= (this.o.maxInflightHashes ?? MAX_INFLIGHT_HASHES)) {
      return { ok: false, status: 429, errorClass: 'auth_rate_limited', retryAfterSec: 1 };
    }

    this.inflight++;
    this.inflightByIp.set(ip, ipInflight + 1);
    let good: boolean;
    try {
      good = await this.verify(row, secret);
    } finally {
      this.inflight--;
      const left = (this.inflightByIp.get(ip) ?? 1) - 1;
      if (left > 0) this.inflightByIp.set(ip, left);
      else this.inflightByIp.delete(ip);
    }
    if (!good) return this.fail(ip, now, true, tokenId);
    this.cache.set(tokenId, { digest: tokenDigest(token), expires: now + (this.o.cacheTtlMs ?? AUTH_CACHE_TTL_MS) });
    return { ok: true, principal: principal(row) };
  }
}

/** Static bearer tokens (the tokens file) are the team credentials, always. */
function principal(row: TokenRow): AuthPrincipal {
  return { tokenId: row.token_id, assistant: row.assistant, cls: row.class, tenant: WORK_TENANT };
}
