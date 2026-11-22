// Test-only harness for open sign-up (docs/plans/2026-11-18-open-signup-workspaces-plan.md): the
// hosted handler on an ephemeral 127.0.0.1 port with OAuth (FAKE GitHub, injected), static bearer
// tokens, the team read path (SET ROLE zeusi_box_ro on PGlite) and personal workspaces (real
// provisioning and real workspace sessions, test/helpers/tenant-fixture.ts). Nothing leaves loopback.
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync } from 'node:fs';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../../src/db.ts';
import { Authenticator } from '../../src/mcp-auth.ts';
import { createHostedHandler, type HostedLimits, type TenantRoutes, type WorkspaceWriteLimits } from '../../src/mcp-hosted.ts';
import { CLAUDE_CALLBACK, OAuthServer, pkceChallenge, type OAuthLimits, type TenantSignup } from '../../src/mcp-oauth.ts';
import type { GithubApi, GithubIdentity } from '../../src/mcp-oauth-github.ts';
import { OAuthStore } from '../../src/mcp-oauth-store.ts';
import { createMcpState, type McpDeps, type McpState } from '../../src/mcp-server.ts';
import { sessionEndHook } from '../../src/mcp.ts';
import { B1Cache } from '../../src/b1-cache.ts';
import { b1IndexHook, type HookStats } from '../../src/b1-index.ts';
import { RecoveryAttemptLimiter } from '../../src/recovery-limit.ts';
import { generateToken, hashSecret, verifySecret, withTokenFile, type TokenRow } from '../../src/mcp-tokens.ts';
import { search as realSearch, type SearchOptions } from '../../src/search.ts';
import { buildAuditLine } from '../../src/signin-audit.ts';
import { TenantDirectory, TenantRouter, TenantWriter, TENANT_WR_ROLE } from '../../src/tenants.ts';
import { buildWsAuditLine } from '../../src/workspace-audit.ts';
import { WorkspaceWrites } from '../../src/workspace-write.ts';
import { safeMkdtemp } from './safe-tmp.ts';
import { asLogin } from './tenant-fixture.ts';

export const ISSUER = 'https://mcp.zeusi.dev';
export const RESOURCE = `${ISSUER}/mcp`;
const KEY = 's'.repeat(48);
const FAST = { alg: 'argon2id' as const, params: { m: 64, t: 1, p: 1, dkLen: 32 } };
export const HOTMAIL = 'near-miss@example.invalid';
export const STRANGER_EMAIL = ['someone', 'example.com'].join('@');

/** GitHub codes the fake accepts. operator members first; everyone else gets a personal workspace. */
export const IDENTITIES: Record<string, GithubIdentity> = {
  'gh-login': { id: 101, login: 'OperatorOwner', verifiedEmails: [] },
  'gh-operator': { id: 102, login: 'operator-bot', verifiedEmails: ['operator@example.com'] },
  'gh-gmail': { id: 103, login: 'other-name', verifiedEmails: ['owner@example.com'] },
  'gh-hotmail': { id: 104, login: 'hot-user', verifiedEmails: [HOTMAIL] },
  'gh-stranger': { id: 105, login: 'stranger', verifiedEmails: [STRANGER_EMAIL] },
  'gh-stranger-renamed': { id: 105, login: 'stranger2', verifiedEmails: [] },
  'gh-visitor': { id: 106, login: 'open-user', verifiedEmails: [['visitor', 'sovra.ch'].join('@')] },
  'gh-b': { id: 107, login: 'user-b', verifiedEmails: [] },
};
/** n0..n49: distinct new identities for limit tests. */
for (let i = 0; i < 50; i++) IDENTITIES[`gh-n${i}`] = { id: 5000 + i, login: `newbie-${i}`, verifiedEmails: [] };

function fakeGithub(): GithubApi {
  return {
    async exchange(code) {
      return code in IDENTITIES ? `ghtok-${code}` : null;
    },
    async identity(t) {
      return IDENTITIES[t.replace(/^ghtok-/, '')] ?? null;
    },
  };
}

export function tokDir(): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-signup-'));
  chmodSync(d, 0o700);
  return d;
}

export async function mintStatic(cls: 'read' | 'write'): Promise<{ token: string; row: TokenRow }> {
  const g = generateToken();
  const now = Date.now();
  return {
    token: g.token,
    row: {
      token_id: g.tokenId, assistant: cls === 'write' ? 'zeus' : 'atlas', class: cls, hash: await hashSecret(g.tokenId, g.secret, FAST),
      issued_at: new Date(now - 1000).toISOString(), expires_at: new Date(now + 86_400_000).toISOString(), revoked_at: null,
    },
  };
}

/** A HOME with a service file naming the read-only the team login (the read gate parses it offline). */
export function serviceHome(): string {
  const home = tokDir();
  const svc = (name: string, user: string) => `[${name}]\nhost=db.invalid\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;
  writeFileSync(join(home, '.pg_service.conf'), [svc('zeusi_ro', 'zeusi_box_ro'), svc('zeusi_decision', 'zeusi_box_decision')].join('\n'));
  return home;
}

export interface TenantHarness {
  port: number;
  logs: string[];
  audits: string[];
  store: OAuthStore;
  dir: TenantDirectory | null;
  router: TenantRouter | null;
  /** Own-workspace writes (PR 2), when `writer` was asked for. */
  writes: WorkspaceWrites | null;
  /** Workspace-write audit lines (allowlisted JSON). */
  wsAudits: string[];
  /** C7: the process's B1 cache (wired like src/mcp.ts: the store's session-end hook evicts it). */
  cache: B1Cache;
  /** C7: the shared MCP state (feedback memo). */
  state: McpState;
  /** C7: the real index hook's counts across every sealed write. */
  hookStats: HookStats;
  /** C7: session-end hook calls (grant, tenant, reason). */
  ended: Array<{ grantId: string; tenant: string; reason: string }>;
  close: () => Promise<void>;
}

export interface TenantHarnessOptions {
  db: Db;
  home: string;
  tokensRows?: TokenRow[];
  limits?: Partial<OAuthLimits>;
  /** 'on' (default): real directory + router; 'off': none; or a fake directory (router stays real). */
  tenants?: 'on' | 'off' | TenantSignup;
  maxTenants?: number;
  over?: Partial<McpDeps>;
  /** Set to give the read path a write service too (a personal grant must still never write). */
  writeService?: string;
  /** TenantRouter.check() cache (default the module default). */
  routerCacheMs?: number;
  /** Replace the request-side routes handed to the hosted handler (e.g. a catalog outage). */
  routes?: TenantRoutes;
  /** Replace the authenticator (e.g. a principal the real one never produces). */
  authenticator?: Authenticator;
  /** /mcp message limits (src/mcp-hosted.ts HostedLimits). */
  hostedLimits?: Partial<HostedLimits>;
  /**
   * PR 2 own-workspace writes: 'on' = writer service on (needs tenantTestDb({ writer: true })) and
   * personal consents offer writes; 'grant-only' = consents offer writes but the server has no writer
   * (writes off after sign-in). Default: neither (the PR 1 behaviour).
   */
  writer?: 'on' | 'grant-only';
  wsLimits?: Partial<WorkspaceWriteLimits>;
  /** The preview work root (default: a fresh private dir); must end in `workspace-import`. */
  workRoot?: string;
  /**
   * C7 end to end: ZEUSI_WORKSPACE_ENCRYPTION=on as src/mcp.ts wires it: new workspaces born encrypted
   * (TenantDirectory bornEncrypted) and the consent page's keys (catalog = the directory) with `newDek`.
   */
  flagOn?: {
    newDek: () => Buffer;
    /**
     * The consent page's keys mode (default 'on', as src/mcp.ts wires the flag). 'enroll' = the rollback value
     * with born-on workspaces still present: the consent page then still offers approve without a passkey, the
     * only way the real consent flow mints a passkey-less grant of a born-on workspace (the LOCKED case some C7
     * tests need). Under 'on' the server refuses that (docs/plans/2026-11-19-c4-webauthn-verify.md KTD7).
     */
    keysMode?: 'enroll' | 'on';
  };
  /** C7: the cache (default a fresh B1Cache). */
  cache?: B1Cache;
}

function asRole(db: Db, role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

export async function startTenantHosted(o: TenantHarnessOptions): Promise<TenantHarness> {
  const logs: string[] = [];
  const audits: string[] = [];
  const tokensPath = join(tokDir(), 'mcp-tokens.json');
  await withTokenFile(tokensPath, () => ({ version: 1 as const, tokens: o.tokensRows ?? [] }));
  const state = createMcpState();
  const cache = o.cache ?? new B1Cache();
  const ended: TenantHarness['ended'] = [];
  const hookStats: HookStats = { segments: 0, rebuilds: 0, compactions: 0, skippedNoTable: 0 };
  const dataDir = tokDir();
  // C7 KTD4: the session-end hook src/mcp.ts wires (the same function), plus a record of each call.
  const hook = sessionEndHook(cache, state);
  const store = new OAuthStore({
    hashKey: KEY, path: join(dataDir, 'mcp-oauth.json'),
    onSessionEnded: (e) => {
      ended.push(e);
      hook(e);
    },
  });
  const mode = o.tenants ?? 'on';
  const dir = mode === 'off' ? null : new TenantDirectory({ connectAdmin: asLogin(o.db, 'zeusi_tenant_admin'), maxTenants: o.maxTenants, bornEncrypted: o.flagOn !== undefined });
  const router = mode === 'off' ? null : new TenantRouter({ connectRuntime: asLogin(o.db, 'zeusi_tenant_rt'), cacheMs: o.routerCacheMs });
  const signup: TenantSignup | undefined = mode === 'off' ? undefined : mode === 'on' ? dir! : mode;
  const wsAudits: string[] = [];
  const writes = o.writer === 'on' && router
    ? new WorkspaceWrites({
      workRoot: o.workRoot ?? join(tokDir(), 'workspace-import'),
      openWrite: (t) => new TenantWriter({ connectWriter: asLogin(o.db, TENANT_WR_ROLE), check: (x) => router.check(x) }).open(t),
      encState: (t) => router.encState(t),
      audit: (e) => wsAudits.push(buildWsAuditLine(e)),
      indexHook: (key) => b1IndexHook(key, hookStats),
    })
    : null;
  const server = new OAuthServer({
    issuer: ISSUER, githubClientId: 'Iv1.testclientid', github: fakeGithub(), signingKey: KEY, store, limits: o.limits,
    cimdFetch: async () => { throw new Error('unreachable'); }, tenants: signup, audit: (e) => audits.push(buildAuditLine(e)),
    workspaceWrite: o.writer !== undefined,
    ...(o.flagOn && dir ? {
      keys: { mode: o.flagOn.keysMode ?? 'on', catalog: dir, limiter: new RecoveryAttemptLimiter({ hashKey: KEY, file: join(dataDir, '.zeusi', 'recovery-attempts.json') }), newDek: o.flagOn.newDek },
    } : {}),
  });
  const srv: Server = createServer();
  await new Promise<void>((res) => srv.listen(0, '127.0.0.1', res));
  const port = (srv.address() as AddressInfo).port;
  const deps: McpDeps = {
    env: { HOME: o.home }, home: o.home, readService: 'zeusi_ro', writeService: o.writeService,
    connectRead: asRole(o.db, 'zeusi_box_ro'), connectWrite: asRole(o.db, 'zeusi_box_decision'),
    embeddings: () => null, searchFn: (s: SearchOptions) => realSearch(s),
    feedbackPath: join(o.home, '.zeusi', 'search-feedback.jsonl'), queryLedgerPath: join(o.home, '.zeusi', 'query-embed-ledger.json'),
    ...(o.over ?? {}),
  };
  const authenticator = o.authenticator ?? new Authenticator({ tokensPath, verify: (r, s) => verifySecret(r, s), oauth: server });
  srv.on('request', createHostedHandler({
    deps, state, authenticator, allowedHosts: [`127.0.0.1:${port}`], log: (l) => logs.push(l),
    oauth: { state: 'enabled', server }, tenants: o.routes ?? router ?? undefined, limits: o.hostedLimits,
    writes: writes ?? undefined, wsAudit: (e) => wsAudits.push(buildWsAuditLine(e)), wsLimits: o.wsLimits, cache,
  }));
  return {
    port, logs, audits, store, dir, router, writes, wsAudits, cache, state, hookStats, ended,
    close: () => new Promise((res) => srv.close(() => { writes?.close(); res(); })),
  };
}

export interface Resp { status: number; headers: Record<string, string | string[] | undefined>; body: string }

export function send(port: number, o: { method?: string; path: string; headers?: Record<string, string>; body?: string }): Promise<Resp> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method: o.method ?? 'GET', path: o.path, headers: o.headers ?? {} }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (o.body !== undefined) req.write(o.body);
    req.end();
  });
}

const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const VERIFIER = 'v'.repeat(50) + '-._~';
const loc = (r: Resp) => new URL(String(r.headers.location));
const hidden = (html: string, name: string) => new RegExp(`name="${name}" value="([^"]+)"`).exec(html)![1]!;

export async function dcrClient(h: TenantHarness): Promise<string> {
  const r = await send(h.port, { method: 'POST', path: '/register', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [CLAUDE_CALLBACK], client_name: 'Claude' }) });
  assert.equal(r.status, 201, r.body);
  return (JSON.parse(r.body) as { client_id: string }).client_id;
}

/** /authorize -> fake GitHub -> callback (from `ip`). Returns the callback response and the cookie. */
export async function toConsent(h: TenantHarness, clientId: string, ghCode: string, ip = '198.51.100.10'): Promise<{ consent: Resp; cookie: string }> {
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: CLAUDE_CALLBACK, code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: 'S256', state: 'st-123', scope: 'zeusi.read offline_access', resource: RESOURCE,
  });
  const a = await send(h.port, { path: `/authorize?${q.toString()}`, headers: { 'fly-client-ip': ip } });
  assert.equal(a.status, 302, a.body);
  const cookie = String((a.headers['set-cookie'] as string[])[0]).split(';')[0]!;
  const consent = await send(h.port, { path: `/oauth/github/callback?code=${ghCode}&state=${loc(a).searchParams.get('state')}`, headers: { cookie, 'fly-client-ip': ip } });
  return { consent, cookie };
}

/** The whole sign-in for a GitHub code: consent approved, code exchanged. Returns the tokens. */
export async function signIn(h: TenantHarness, ghCode: string, ip?: string): Promise<{ access: string; refresh: string; clientId: string; consent: Resp; scope: string }> {
  const clientId = await dcrClient(h);
  const { consent, cookie } = await toConsent(h, clientId, ghCode, ip);
  assert.equal(consent.status, 200, `${ghCode}: ${consent.body}`);
  const ok = await send(h.port, {
    method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie },
    body: form({ txn: hidden(consent.body, 'txn'), csrf: hidden(consent.body, 'csrf'), decision: 'approve' }),
  });
  assert.equal(ok.status, 302);
  const code = loc(ok).searchParams.get('code')!;
  const t = await send(h.port, {
    method: 'POST', path: '/token', headers: FORM,
    body: form({ grant_type: 'authorization_code', code, redirect_uri: CLAUDE_CALLBACK, client_id: clientId, code_verifier: VERIFIER, resource: RESOURCE }),
  });
  assert.equal(t.status, 200, t.body);
  const j = JSON.parse(t.body) as { access_token: string; refresh_token: string; scope: string };
  return { access: j.access_token, refresh: j.refresh_token, clientId, consent, scope: j.scope };
}

export async function refresh(h: TenantHarness, clientId: string, refreshToken: string): Promise<{ access: string; refresh: string }> {
  const t = await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId }) });
  assert.equal(t.status, 200, t.body);
  const j = JSON.parse(t.body) as { access_token: string; refresh_token: string };
  return { access: j.access_token, refresh: j.refresh_token };
}

export const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } };
export const LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };
export const callTool = (name: string, args: Record<string, unknown>, id = 3) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

export function mcpPost(port: number, token: string | null, body: unknown, extra: Record<string, string> = {}): Promise<Resp> {
  return send(port, {
    method: 'POST', path: '/mcp', body: JSON.stringify(body),
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(token ? { authorization: `Bearer ${token}` } : {}), ...extra },
  });
}

/** The tool result JSON (the first text content) of a tools/call response, or the error text. */
export function toolJson(r: Resp): { isError: boolean; json: Record<string, unknown> | null; text: string } {
  const j = JSON.parse(r.body) as { result?: { isError?: boolean; content?: Array<{ text?: string }> }; error?: { message?: string } };
  if (j.error) return { isError: true, json: null, text: String(j.error.message ?? '') };
  const text = j.result?.content?.map((c) => c.text ?? '').join('\n') ?? '';
  let json: Record<string, unknown> | null = null;
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch { /* an error text */ }
  return { isError: j.result?.isError === true, json, text };
}
