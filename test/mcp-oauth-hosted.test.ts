// OAuth on the hosted MCP server (src/mcp-oauth.ts via src/mcp-hosted.ts), end to end on an
// ephemeral 127.0.0.1 port: discovery, 401 challenge, DCR, CIMD, GitHub (FAKE, injected),
// allowlist, consent, PKCE, token, refresh rotation, revoke, read-only principal, limits,
// logs; plus the scripted e2e with the official MCP SDK OAuth client. The issuer is the real
// https://mcp.zeusi.dev string; a rewriting fetch sends those URLs to the local port, so
// nothing leaves loopback. Bearer tokens are minted into temp dirs. No token value is ever
// asserted into a failure message.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync } from 'node:fs';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { search as realSearch, type SearchOptions } from '../src/search.ts';
import { createMcpState, type McpDeps } from '../src/mcp-server.ts';
import { Authenticator } from '../src/mcp-auth.ts';
import { createHostedHandler, HSTS_VALUE } from '../src/mcp-hosted.ts';
import { LOG_FIELDS } from '../src/mcp-log.ts';
import { CLAUDE_CALLBACK, OAuthServer, pkceChallenge, type CimdFetcher, type OAuthLimits, type OAuthSetup } from '../src/mcp-oauth.ts';
import type { GithubApi, GithubIdentity } from '../src/mcp-oauth-github.ts';
import { OAuthStore } from '../src/mcp-oauth-store.ts';
import { generateToken, hashSecret, verifySecret, withTokenFile, type TokenRow } from '../src/mcp-tokens.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { assertGuardedChannels, assertGuardLog, plantGuardFixtures } from './helpers/fixa-guard.ts';
import { assertToolsAgree, CONTEXT_NOT_PERMISSION_RE, NOT_A_GO_RE, toolNamesIn } from './helpers/tool-agreement.ts';

const ISSUER = 'https://mcp.zeusi.dev';
const RESOURCE = `${ISSUER}/mcp`;
const KEY = 's'.repeat(48);
const GH_CLIENT_ID = 'Iv1.testclientid';
const SHA = 'ab'.repeat(32);
const FAST = { alg: 'argon2id' as const, params: { m: 64, t: 1, p: 1, dkLen: 32 } };
const HOTMAIL = 'near-miss@example.invalid';
const CC_CIMD = 'https://claude.ai/oauth/claude-code-client-metadata';

let db: Db;
let home: string;

function asRole(role: string, log?: string[]): (service: string) => Promise<Db> {
  return async (service: string) => {
    log?.push(`${service}:${role}`);
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-oauth-hosted-'));
  const svc = (name: string, user: string) => `[${name}]\nhost=db.invalid\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;
  writeFileSync(join(home, '.pg_service.conf'), [svc('zeusi_ro', 'zeusi_box_ro'), svc('zeusi_decision', 'zeusi_box_decision')].join('\n'));
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  const nid = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/research/oauth.md', 'oauth', 'b', now(), 'work', 'vault_note', 'vault:Work/research/oauth.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  await db.exec('ALTER TABLE zeusi.chunks DISABLE TRIGGER zeusi_90_wall');
  await db.query(
    `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
     VALUES ($1, 0, 'OAuth', $2, sha256(convert_to($2, 'UTF8')), 5, 'vault:Work/research/oauth.md#c0')`, [nid, 'wombat oauth connector chunk body']);
  await db.exec('ALTER TABLE zeusi.chunks ENABLE TRIGGER zeusi_90_wall');
});
after(async () => db.close());

// ---------------------------------------------------------------------------
// Harness

const IDENTITIES: Record<string, GithubIdentity> = {
  'gh-login': { id: 101, login: 'OperatorOwner', verifiedEmails: [] },
  'gh-operator': { id: 102, login: 'operator-bot', verifiedEmails: ['operator@example.com'] },
  'gh-gmail': { id: 103, login: 'other-name', verifiedEmails: ['owner@example.com'] },
  'gh-hotmail': { id: 104, login: 'hot-user', verifiedEmails: [HOTMAIL] },
  'gh-stranger': { id: 105, login: 'stranger', verifiedEmails: ['someone@example.com'] },
};

function fakeGithub(calls: string[]): GithubApi {
  return {
    async exchange(code, redirectUri) {
      calls.push(`exchange:${redirectUri}`);
      return code in IDENTITIES ? `ghtok-${code}` : null;
    },
    async identity(t) {
      return IDENTITIES[t.replace(/^ghtok-/, '')] ?? null;
    },
  };
}

const CC_DOC = { client_id: CC_CIMD, client_name: 'Claude Code', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], token_endpoint_auth_method: 'none' };

interface H {
  port: number;
  base: string;
  logs: string[];
  github: string[];
  cimd: string[];
  store: OAuthStore;
  server: OAuthServer;
  close: () => Promise<void>;
}

function tokDir(): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-oauth-tok-'));
  chmodSync(d, 0o700);
  return d;
}

interface Opts {
  tokensRows?: TokenRow[] | null;
  over?: Partial<McpDeps>;
  limits?: Partial<OAuthLimits>;
  cimdFetch?: CimdFetcher;
  oauth?: 'enabled' | 'disabled' | 'none';
}

async function mint(cls: 'read' | 'write'): Promise<{ token: string; row: TokenRow }> {
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

async function hosted(o: Opts = {}): Promise<H> {
  const logs: string[] = [];
  const github: string[] = [];
  const cimd: string[] = [];
  const tokensPath = join(tokDir(), 'mcp-tokens.json');
  if (o.tokensRows !== null) await withTokenFile(tokensPath, () => ({ version: 1 as const, tokens: o.tokensRows ?? [] }));
  const storeDir = tokDir();
  const store = new OAuthStore({ hashKey: KEY, path: join(storeDir, 'mcp-oauth.json') });
  const server = new OAuthServer({
    issuer: ISSUER, githubClientId: GH_CLIENT_ID, github: fakeGithub(github), signingKey: KEY, store, limits: o.limits,
    cimdFetch: o.cimdFetch ?? (async (u) => { cimd.push(u); if (u === CC_CIMD) return CC_DOC; throw new Error('unreachable'); }),
  });
  const mode = o.oauth ?? 'enabled';
  const setup: OAuthSetup | undefined = mode === 'enabled' ? { state: 'enabled', server } : mode === 'disabled' ? { state: 'disabled', reason: 'test' } : undefined;
  const srv: Server = createServer();
  await new Promise<void>((res) => srv.listen(0, '127.0.0.1', res));
  const port = (srv.address() as AddressInfo).port;
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro',
    connectRead: asRole('zeusi_box_ro'), connectWrite: asRole('zeusi_box_decision'),
    embeddings: () => null, searchFn: (s: SearchOptions) => realSearch(s),
    feedbackPath: join(home, '.zeusi', 'search-feedback.jsonl'), queryLedgerPath: join(home, '.zeusi', 'query-embed-ledger.json'),
    ...(o.over ?? {}),
  };
  const authenticator = new Authenticator({ tokensPath, verify: (r, s) => verifySecret(r, s), oauth: mode === 'enabled' ? server : undefined });
  srv.on('request', createHostedHandler({
    deps, state: createMcpState(), authenticator, allowedHosts: [`127.0.0.1:${port}`], log: (l) => logs.push(l), oauth: setup,
  }));
  return { port, base: `http://127.0.0.1:${port}`, logs, github, cimd, store, server, close: () => new Promise((res) => srv.close(() => res())) };
}

interface Resp { status: number; headers: Record<string, string | string[] | undefined>; body: string }

function send(port: number, o: { method?: string; path: string; headers?: Record<string, string>; body?: string }): Promise<Resp> {
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
const mcpPost = (port: number, token: string | null, body: unknown) => send(port, {
  method: 'POST', path: '/mcp', body: JSON.stringify(body),
  headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(token ? { authorization: `Bearer ${token}` } : {}) },
});
const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } };
const LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };
const call = (name: string, args: Record<string, unknown>) => ({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name, arguments: args } });
const VERIFIER = 'v'.repeat(50) + '-._~';
const loc = (r: Resp) => new URL(String(r.headers.location));

async function register(h: H, redirectUris: string[] = [CLAUDE_CALLBACK], extra: Record<string, unknown> = {}): Promise<Resp> {
  return send(h.port, { method: 'POST', path: '/register', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: redirectUris, client_name: 'Claude', ...extra }) });
}

function authorizeQuery(clientId: string, over: Record<string, string | null> = {}): string {
  const p: Record<string, string | null> = {
    response_type: 'code', client_id: clientId, redirect_uri: CLAUDE_CALLBACK, code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: 'S256', state: 'st-123', scope: 'zeusi.read offline_access', resource: RESOURCE, ...over,
  };
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) if (v !== null) q.set(k, v);
  return `/authorize?${q.toString()}`;
}

/** /authorize -> fake GitHub -> callback. Returns the consent response and the browser cookie. */
async function toConsent(h: H, clientId: string, ghCode: string, over: Record<string, string | null> = {}): Promise<{ consent: Resp; cookie: string }> {
  const a = await send(h.port, { path: authorizeQuery(clientId, over) });
  assert.equal(a.status, 302, a.body);
  const gh = loc(a);
  assert.equal(gh.origin + gh.pathname, 'https://github.com/login/oauth/authorize');
  assert.equal(gh.searchParams.get('redirect_uri'), `${ISSUER}/oauth/github/callback`);
  assert.equal(gh.searchParams.get('scope'), 'read:user user:email');
  const cookie = String((a.headers['set-cookie'] as string[])[0]).split(';')[0]!;
  assert.match(String((a.headers['set-cookie'] as string[])[0]), /HttpOnly; Secure; SameSite=Lax/);
  const consent = await send(h.port, { path: `/oauth/github/callback?code=${ghCode}&state=${gh.searchParams.get('state')}`, headers: { cookie } });
  return { consent, cookie };
}

function hidden(html: string, name: string): string {
  return new RegExp(`name="${name}" value="([^"]+)"`).exec(html)![1]!;
}

async function approve(h: H, consent: Resp, cookie: string, decision = 'approve'): Promise<Resp> {
  return send(h.port, {
    method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie },
    body: form({ txn: hidden(consent.body, 'txn'), csrf: hidden(consent.body, 'csrf'), decision }),
  });
}

async function fullCode(h: H, clientId: string, ghCode = 'gh-login', over: Record<string, string | null> = {}): Promise<string> {
  const { consent, cookie } = await toConsent(h, clientId, ghCode, over);
  assert.equal(consent.status, 200);
  const r = await approve(h, consent, cookie);
  assert.equal(r.status, 302);
  return loc(r).searchParams.get('code')!;
}

async function exchange(h: H, clientId: string, code: string, over: Record<string, string> = {}): Promise<Resp> {
  return send(h.port, {
    method: 'POST', path: '/token', headers: FORM,
    body: form({ grant_type: 'authorization_code', code, redirect_uri: CLAUDE_CALLBACK, client_id: clientId, code_verifier: VERIFIER, resource: RESOURCE, ...over }),
  });
}

async function dcrClient(h: H): Promise<string> {
  return (JSON.parse((await register(h)).body) as { client_id: string }).client_id;
}

async function tokensFor(h: H): Promise<{ clientId: string; access: string; refresh: string }> {
  const clientId = await dcrClient(h);
  const r = await exchange(h, clientId, await fullCode(h, clientId));
  assert.equal(r.status, 200);
  const j = JSON.parse(r.body) as { access_token: string; refresh_token: string };
  return { clientId, access: j.access_token, refresh: j.refresh_token };
}

// ---------------------------------------------------------------------------
// Discovery and the 401 challenge

test('oauth: well-known documents (RFC 9728 + RFC 8414) match what Claude requires; HSTS everywhere', async () => {
  const h = await hosted();
  try {
    for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const r = await send(h.port, { path: p });
      assert.equal(r.status, 200);
      assert.equal(r.headers['strict-transport-security'], HSTS_VALUE);
      const j = JSON.parse(r.body) as Record<string, unknown>;
      assert.equal(j['resource'], RESOURCE);
      assert.deepEqual(j['authorization_servers'], [ISSUER]);
      assert.deepEqual(j['scopes_supported'], ['zeusi.read']);
      assert.equal(j['resource_name'], 'Zeusi');
      assert.equal(j['resource_documentation'], 'https://zeusi.ai');
      assert.equal(j['resource_policy_uri'], undefined);
      assert.equal(j['resource_tos_uri'], undefined);
    }
    const r = await send(h.port, { path: '/.well-known/oauth-authorization-server' });
    assert.equal(r.status, 200);
    assert.equal(r.headers['strict-transport-security'], HSTS_VALUE);
    const m = JSON.parse(r.body) as Record<string, unknown>;
    assert.equal(m['issuer'], ISSUER);
    assert.equal(m['authorization_endpoint'], `${ISSUER}/authorize`);
    assert.equal(m['token_endpoint'], `${ISSUER}/token`);
    assert.equal(m['registration_endpoint'], `${ISSUER}/register`);
    assert.deepEqual(m['code_challenge_methods_supported'], ['S256']);
    assert.equal(m['client_id_metadata_document_supported'], true);
    assert.deepEqual(m['token_endpoint_auth_methods_supported'], ['none']);
    assert.deepEqual(m['grant_types_supported'], ['authorization_code', 'refresh_token']);
    assert.ok(!JSON.stringify(m).includes('client_credentials'));
    assert.ok((m['scopes_supported'] as string[]).includes('offline_access'));
    assert.equal(m['service_documentation'], 'https://zeusi.ai');
    assert.equal(m['logo_uri'], 'https://mcp.zeusi.dev/favicon.png');
    assert.equal(m['policy_uri'], undefined);
    assert.equal(m['tos_uri'], undefined);
    assert.equal(m['op_policy_uri'], undefined);
    assert.equal(m['op_tos_uri'], undefined);
  } finally {
    await h.close();
  }
});

test('oauth: unauthenticated /mcp is 401 with resource_metadata (also with no tokens file); /, /sse, unknown paths stay 404', async () => {
  for (const rows of [[] as TokenRow[], null]) {
    const h = await hosted({ tokensRows: rows });
    try {
      for (const body of [INIT, LIST]) {
        const r = await mcpPost(h.port, null, body);
        assert.equal(r.status, 401);
        assert.equal(r.headers['www-authenticate'], `Bearer realm="zeusi", resource_metadata="${ISSUER}/.well-known/oauth-protected-resource", scope="zeusi.read"`);
        assert.equal(r.headers['strict-transport-security'], HSTS_VALUE);
      }
      for (const p of ['/', '/sse', '/.well-known/openid-configuration', '/oauth', '/token/x', '/mcp/x']) {
        const r = await send(h.port, { path: p });
        assert.equal(r.status, 404, p);
        assert.equal(r.headers['strict-transport-security'], HSTS_VALUE);
      }
    } finally {
      await h.close();
    }
  }
});

test('oauth: with OAuth secrets missing every OAuth route answers 503, /mcp keeps the plain challenge, bearer still works', async () => {
  const read = await mint('read');
  const h = await hosted({ oauth: 'disabled', tokensRows: [read.row] });
  try {
    for (const [method, p] of [['GET', '/.well-known/oauth-protected-resource'], ['GET', '/.well-known/oauth-authorization-server'], ['GET', '/authorize'], ['POST', '/token'], ['POST', '/register'], ['GET', '/oauth/github/callback']] as const) {
      const r = await send(h.port, { method, path: p });
      assert.equal(r.status, 503, p);
      assert.equal(r.headers['strict-transport-security'], HSTS_VALUE);
    }
    const u = await mcpPost(h.port, null, LIST);
    assert.equal(u.status, 401);
    assert.equal(u.headers['www-authenticate'], 'Bearer realm="zeusi"');
    assert.equal((await mcpPost(h.port, read.token, LIST)).status, 200);
  } finally {
    await h.close();
  }
});

test('oauth: a handler without OAuth (loopback/tests) has no OAuth routes at all (404)', async () => {
  const h = await hosted({ oauth: 'none' });
  try {
    for (const p of ['/.well-known/oauth-protected-resource', '/authorize', '/register']) assert.equal((await send(h.port, { path: p })).status, 404);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// DCR

test('oauth DCR: JSON registration gives a public client; bad redirects, grant types and content types are refused', async () => {
  const h = await hosted();
  try {
    const r = await register(h, [CLAUDE_CALLBACK, 'http://localhost/callback'], { token_endpoint_auth_method: 'client_secret_post', grant_types: ['authorization_code', 'refresh_token'] });
    assert.equal(r.status, 201, r.body);
    const j = JSON.parse(r.body) as Record<string, unknown>;
    assert.match(String(j['client_id']), /^zc_/);
    assert.equal(j['token_endpoint_auth_method'], 'none');
    assert.ok(!('client_secret' in j), 'never a secret');
    for (const uris of [['https://claude.com/api/mcp/auth_callback'], ['http://evil/callback'], ['https://evil.example/cb'], [], 'x']) {
      const b = await send(h.port, { method: 'POST', path: '/register', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: uris }) });
      assert.equal(b.status, 400);
      assert.equal((JSON.parse(b.body) as { error: string }).error, 'invalid_redirect_uri');
    }
    assert.equal((await register(h, [CLAUDE_CALLBACK], { grant_types: ['client_credentials'] })).status, 400);
    assert.equal((await register(h, [CLAUDE_CALLBACK], { token_endpoint_auth_method: 'private_key_jwt' })).status, 400);
    const formBody = await send(h.port, { method: 'POST', path: '/register', headers: FORM, body: form({ redirect_uris: CLAUDE_CALLBACK }) });
    assert.equal(formBody.status, 415);
    assert.equal((await send(h.port, { method: 'POST', path: '/register', headers: { 'content-type': 'application/json' }, body: '[1' })).status, 400);
  } finally {
    await h.close();
  }
});

test('oauth DCR: registration is rate limited per IP (429 with Retry-After)', async () => {
  const h = await hosted({ limits: { register: 3 } });
  try {
    for (let i = 0; i < 3; i++) assert.equal((await register(h)).status, 201);
    const r = await register(h);
    assert.equal(r.status, 429);
    assert.ok(Number(r.headers['retry-after']) > 0);
    assert.equal(h.store.list().clients.length, 3);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// /authorize: client, redirect, PKCE

test('oauth authorize: unknown client or a redirect outside the client/allowlist is an error page, never a redirect', async () => {
  const h = await hosted();
  try {
    const id = await dcrClient(h);
    for (const q of [
      authorizeQuery('zc_doesnotexistdoesnotex'),
      authorizeQuery(id, { redirect_uri: 'https://claude.com/api/mcp/auth_callback' }),
      authorizeQuery(id, { redirect_uri: 'http://evil/callback' }),
      authorizeQuery(id, { redirect_uri: 'http://localhost:3000/callback' }), // allowed in general, not registered for this client
      authorizeQuery(id, { redirect_uri: null }),
      authorizeQuery(id) + `&client_id=${id}`, // repeated parameter
    ]) {
      const r = await send(h.port, { path: q });
      assert.equal(r.status, 400, q);
      assert.equal(r.headers.location, undefined);
      assert.match(String(r.headers['content-type']), /text\/html/);
      assert.match(String(r.headers['content-security-policy']), /default-src 'none'/);
      assert.equal(r.headers['strict-transport-security'], HSTS_VALUE);
    }
  } finally {
    await h.close();
  }
});

test('oauth authorize: PKCE S256 is required (missing, plain, malformed -> error redirect, no GitHub, no cookie)', async () => {
  const h = await hosted();
  try {
    const id = await dcrClient(h);
    for (const over of [
      { code_challenge: null }, { code_challenge_method: null }, { code_challenge_method: 'plain' }, { code_challenge: 'short' },
      { response_type: 'token' }, { scope: 'zeusi.write' }, { resource: 'https://mcp.zeusi.dev/other' },
    ]) {
      const r = await send(h.port, { path: authorizeQuery(id, over) });
      assert.equal(r.status, 302, JSON.stringify(over));
      const u = loc(r);
      assert.equal(u.origin + u.pathname, CLAUDE_CALLBACK);
      assert.ok(u.searchParams.get('error'));
      assert.equal(u.searchParams.get('code'), null);
      assert.equal(u.searchParams.get('state'), 'st-123');
      assert.equal(r.headers['set-cookie'], undefined);
    }
    assert.deepEqual(h.github, []);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// GitHub allowlist + consent

test('oauth identity: OperatorOwner, verified operator@example.com and owner@example.com reach the unchanged the team consent; without a workspace directory, hotmail and strangers get "not available" (never "Access denied") and no grant', async () => {
  const h = await hosted();
  try {
    const id = await dcrClient(h);
    for (const code of ['gh-login', 'gh-operator', 'gh-gmail']) {
      const { consent } = await toConsent(h, id, code);
      assert.equal(consent.status, 200, code);
      assert.match(consent.body, /Allow read-only access to Zeusi/);
      assert.match(consent.body, /claude\.ai/, 'redirect host shown');
      assert.match(String(consent.headers['content-security-policy']), /form-action 'self' https:\/\/claude\.ai/);
      assert.ok(!/personal workspace/i.test(consent.body), 'the team consent screen does not change');
    }
    for (const code of ['gh-hotmail', 'gh-stranger']) {
      const { consent } = await toConsent(h, id, code);
      assert.equal(consent.status, 503, code);
      assert.match(consent.body, /New workspaces are not available/);
      assert.ok(!/Access denied|not allowed/.test(consent.body), code);
      for (const leak of ['operator@example.com', 'gmail', 'OperatorOwner', 'hotmail', 'allowlist', 'stranger']) assert.ok(!consent.body.includes(leak), `page leaks ${leak}`);
    }
    assert.equal(h.store.list().grants.length, 0);
  } finally {
    await h.close();
  }
});

test('oauth consent: bound to the browser cookie and the CSRF value; deny issues no code; a consent cannot be replayed', async () => {
  const h = await hosted();
  try {
    const id = await dcrClient(h);
    // Callback without the browser cookie (login CSRF / stolen state): refused.
    const a = await send(h.port, { path: authorizeQuery(id) });
    const state = loc(a).searchParams.get('state')!;
    assert.equal((await send(h.port, { path: `/oauth/github/callback?code=gh-login&state=${state}` })).status, 400);
    assert.equal((await send(h.port, { path: `/oauth/github/callback?code=gh-login&state=${state}`, headers: { cookie: '__Host-zeusi_oauth=forged' } })).status, 400);

    const { consent, cookie } = await toConsent(h, id, 'gh-login');
    const txn = hidden(consent.body, 'txn');
    const bad = await send(h.port, { method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie }, body: form({ txn, csrf: 'wrong', decision: 'approve' }) });
    assert.equal(bad.status, 400);
    const noCookie = await send(h.port, { method: 'POST', path: '/oauth/consent', headers: FORM, body: form({ txn, csrf: hidden(consent.body, 'csrf'), decision: 'approve' }) });
    assert.equal(noCookie.status, 400);

    const deny = await approve(h, consent, cookie, 'deny');
    assert.equal(deny.status, 302);
    assert.equal(loc(deny).searchParams.get('error'), 'access_denied');
    assert.equal(loc(deny).searchParams.get('code'), null);
    assert.equal((await approve(h, consent, cookie)).status, 400, 'the same consent cannot be approved after a deny');

    const second = await toConsent(h, id, 'gh-login');
    const ok = await approve(h, second.consent, second.cookie);
    assert.equal(ok.status, 302);
    assert.ok(loc(ok).searchParams.get('code'));
    assert.equal(loc(ok).searchParams.get('state'), 'st-123');
    assert.equal(loc(ok).searchParams.get('iss'), ISSUER);
    assert.equal((await approve(h, second.consent, second.cookie)).status, 400, 'no second code from one consent');
    assert.equal(h.store.list().grants.length, 0, 'no grant before the token exchange');
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Token endpoint

test('oauth token: code + S256 verifier gives read-only tokens; wrong verifier, client, redirect or replay is invalid_grant', async () => {
  const h = await hosted();
  try {
    const id = await dcrClient(h);
    for (const over of [{ code_verifier: 'w'.repeat(50) }, { code_verifier: '' }, { client_id: await dcrClient(h) }, { redirect_uri: 'http://localhost:1/callback' }]) {
      const code = await fullCode(h, id);
      const r = await exchange(h, id, code, over);
      assert.equal(r.status, 400);
      assert.equal((JSON.parse(r.body) as { error: string }).error, 'invalid_grant', String(Object.keys(over)[0]));
      assert.equal((await exchange(h, id, code)).status, 400, 'a failed attempt still burns the code');
    }
    const code = await fullCode(h, id);
    const json = await send(h.port, { method: 'POST', path: '/token', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', code }) });
    assert.equal(json.status, 415);
    const r = await exchange(h, id, code);
    assert.equal(r.status, 200, r.body);
    assert.equal(r.headers['cache-control'], 'no-store');
    const t = JSON.parse(r.body) as Record<string, unknown>;
    assert.equal(t['token_type'], 'Bearer');
    assert.equal(t['expires_in'], 3600);
    assert.equal(t['scope'], 'zeusi.read');
    assert.match(String(t['access_token']), /^zeusi_at_/);
    assert.match(String(t['refresh_token']), /^zeusi_rt_/);
    // Replay of a redeemed code: invalid_grant AND the grant it produced is revoked.
    assert.equal((await exchange(h, id, code)).status, 400);
    assert.equal((await mcpPost(h.port, String(t['access_token']), LIST)).status, 401);
    assert.equal((JSON.parse((await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'client_credentials', client_id: id }) })).body) as { error: string }).error, 'unsupported_grant_type');
  } finally {
    await h.close();
  }
});

test('oauth token: refresh rotates (new pair in the same response), a reused refresh is invalid_grant and revokes the grant', async () => {
  const h = await hosted();
  try {
    const t = await tokensFor(h);
    const r1 = await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'refresh_token', refresh_token: t.refresh, client_id: t.clientId }) });
    assert.equal(r1.status, 200);
    const n = JSON.parse(r1.body) as { access_token: string; refresh_token: string };
    assert.ok(n.refresh_token !== t.refresh && n.access_token !== t.access);
    assert.equal((await mcpPost(h.port, n.access_token, LIST)).status, 200);
    assert.equal((await mcpPost(h.port, t.access, LIST)).status, 401, 'old access token replaced');
    const reuse = await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'refresh_token', refresh_token: t.refresh, client_id: t.clientId }) });
    assert.equal(reuse.status, 400);
    assert.equal((JSON.parse(reuse.body) as { error: string }).error, 'invalid_grant');
    assert.equal((await mcpPost(h.port, n.access_token, LIST)).status, 401, 'reuse revoked the whole grant');
    const garbage = await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'refresh_token', refresh_token: 'nope', client_id: t.clientId }) });
    assert.equal((JSON.parse(garbage.body) as { error: string }).error, 'invalid_grant');
  } finally {
    await h.close();
  }
});

test('oauth token: a Basic header that does not decode, or names another client, is invalid_client (never a 500)', async () => {
  const h = await hosted();
  try {
    const bad = await send(h.port, { method: 'POST', path: '/token', headers: { ...FORM, authorization: `Basic ${Buffer.from('%E0%A4%A:x').toString('base64')}` }, body: form({ grant_type: 'refresh_token', refresh_token: 'x' }) });
    assert.equal(bad.status, 401);
    assert.equal((JSON.parse(bad.body) as { error: string }).error, 'invalid_client');
    const other = await send(h.port, { method: 'POST', path: '/token', headers: { ...FORM, authorization: `Basic ${Buffer.from('zc_a:x').toString('base64')}` }, body: form({ grant_type: 'refresh_token', refresh_token: 'x', client_id: 'zc_b' }) });
    assert.equal(other.status, 401);
  } finally {
    await h.close();
  }
});

test('oauth token: rate limited per IP', async () => {
  const h = await hosted({ limits: { token: 2 } });
  try {
    for (let i = 0; i < 2; i++) assert.equal((await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'refresh_token', refresh_token: 'x', client_id: 'y' }) })).status, 400);
    assert.equal((await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({}) })).status, 429);
  } finally {
    await h.close();
  }
});

test('oauth authorize and callback: rate limited per IP', async () => {
  const h = await hosted({ limits: { authorize: 2, callback: 1 } });
  try {
    const id = await dcrClient(h);
    assert.equal((await send(h.port, { path: authorizeQuery(id) })).status, 302);
    assert.equal((await send(h.port, { path: authorizeQuery(id) })).status, 302);
    assert.equal((await send(h.port, { path: authorizeQuery(id) })).status, 429);
    assert.equal((await send(h.port, { path: '/oauth/github/callback?state=x&code=y' })).status, 400);
    assert.equal((await send(h.port, { path: '/oauth/github/callback?state=x&code=y' })).status, 429);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// The OAuth principal on /mcp: read-only

test('oauth on /mcp: initialize, tools/list and zeusi_search work; no write tool is listed; log_decision is 401 even with --write-service', async () => {
  const write = await mint('write');
  const writes: string[] = [];
  const h = await hosted({ tokensRows: [write.row], over: { writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', writes) } });
  try {
    const t = await tokensFor(h);
    assert.equal((await mcpPost(h.port, t.access, INIT)).status, 200);
    const l = await mcpPost(h.port, t.access, LIST);
    const names = (JSON.parse(l.body) as { result: { tools: Array<{ name: string }> } }).result.tools.map((x) => x.name);
    assert.ok(names.includes('zeusi_search') && names.includes('zeusi_startup') && names.includes('zeusi_search_feedback'));
    assert.ok(!names.includes('zeusi_log_decision') && !names.includes('log_decision'));
    const s = await mcpPost(h.port, t.access, call('zeusi_search', { query: 'wombat' }));
    assert.equal(s.status, 200);
    assert.ok((JSON.parse((JSON.parse(s.body) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text) as { hits: unknown[] }).hits.length >= 1);
    for (const n of ['zeusi_log_decision', 'log_decision']) {
      const r = await mcpPost(h.port, t.access, call(n, { kind: 'go' }));
      assert.equal(r.status, 401, n);
    }
    assert.deepEqual(writes, [], 'nothing connected for writing');
    // The static write token on the same server still writes-class as before (scope check passes).
    const wl = await mcpPost(h.port, write.token, LIST);
    assert.ok((JSON.parse(wl.body) as { result: { tools: Array<{ name: string }> } }).result.tools.some((x) => x.name === 'zeusi_log_decision'));
  } finally {
    await h.close();
  }
});

test('oauth on /mcp: revoked (RFC 7009 /revoke or operator) and garbage tokens are a generic 401; failed-auth limit still applies', async () => {
  const h = await hosted();
  try {
    const t = await tokensFor(h);
    assert.equal((await mcpPost(h.port, t.access, LIST)).status, 200);
    const rv = await send(h.port, { method: 'POST', path: '/revoke', headers: FORM, body: form({ token: t.refresh, client_id: t.clientId }) });
    assert.equal(rv.status, 200);
    const r = await mcpPost(h.port, t.access, LIST);
    assert.equal(r.status, 401);
    assert.equal(r.body, '{"error":"unauthorized"}');
    const t2 = await tokensFor(h);
    h.store.revokeAll();
    assert.equal((await mcpPost(h.port, t2.access, LIST)).status, 401);
    let last = 0;
    for (let i = 0; i < 12; i++) last = (await mcpPost(h.port, `zeusi_at_${'A'.repeat(43)}`, LIST)).status;
    assert.equal(last, 429, 'per-IP failed-auth limit');
  } finally {
    await h.close();
  }
});

test('oauth: bearer path unchanged: static read token works, bad static token generic 401, static token with no tokens file 503', async () => {
  const read = await mint('read');
  const h = await hosted({ tokensRows: [read.row] });
  try {
    assert.equal((await mcpPost(h.port, read.token, LIST)).status, 200);
    const bad = await mcpPost(h.port, generateToken().token, LIST);
    assert.equal(bad.status, 401);
    assert.equal(bad.body, '{"error":"unauthorized"}');
  } finally {
    await h.close();
  }
  const none = await hosted({ tokensRows: null });
  try {
    assert.equal((await mcpPost(none.port, read.token, LIST)).status, 503);
    const t = await tokensFor(none);
    assert.equal((await mcpPost(none.port, t.access, LIST)).status, 200, 'OAuth works without a tokens file');
  } finally {
    await none.close();
  }
});

// ---------------------------------------------------------------------------
// Logs

test('oauth logs: allowlisted keys only; never an access/refresh token, code, verifier, GitHub token or state', async () => {
  const h = await hosted();
  try {
    const clientId = await dcrClient(h);
    const { consent, cookie } = await toConsent(h, clientId, 'gh-login');
    const redirect = await approve(h, consent, cookie);
    const code = loc(redirect).searchParams.get('code')!;
    const tr = JSON.parse((await exchange(h, clientId, code)).body) as { access_token: string; refresh_token: string };
    await mcpPost(h.port, tr.access_token, call('zeusi_search', { query: 'wombat' }));
    await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'refresh_token', refresh_token: tr.refresh_token, client_id: clientId }) });
    await new Promise((res) => setImmediate(res));
    const lines = h.logs.map((l) => JSON.parse(l) as Record<string, unknown>);
    for (const l of lines) assert.deepEqual(Object.keys(l), [...LOG_FIELDS]);
    const mcp = lines.find((l) => l['tool'] === 'zeusi_search')!;
    assert.equal(mcp['class'], 'read');
    assert.equal(mcp['assistant'], 'claude-oauth');
    assert.match(String(mcp['token_id']), /^[a-z2-7]{12}$/);
    const all = h.logs.join('\n');
    for (const bad of [tr.access_token, tr.refresh_token, code, VERIFIER, 'ghtok-', hidden(consent.body, 'txn'), cookie.split('=')[1]!, 'st-123', 'wombat', KEY]) {
      assert.ok(!all.includes(bad), 'a secret-shaped value reached the log');
    }
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// CIMD

test('oauth CIMD: Claude Code metadata URL as client_id, loopback redirect on any port, full flow; fetch failure or bad doc refuses', async () => {
  const h = await hosted();
  try {
    const redirect = 'http://localhost:53121/callback';
    const { consent, cookie } = await toConsent(h, CC_CIMD, 'gh-login', { redirect_uri: redirect });
    assert.equal(consent.status, 200);
    assert.match(consent.body, /claude\.ai/, 'the client_id host names the app');
    assert.match(consent.body, /localhost:53121/);
    assert.match(consent.body, /program on this computer/);
    const ok = await approve(h, consent, cookie);
    const code = loc(ok).searchParams.get('code')!;
    assert.equal(loc(ok).origin, 'http://localhost:53121');
    const tr = await exchange(h, CC_CIMD, code, { redirect_uri: redirect });
    assert.equal(tr.status, 200, tr.body);
    assert.ok(h.cimd.includes(CC_CIMD));

    for (const [cid, doc] of [
      ['https://claude.ai/oauth/other', { client_id: 'https://evil.example/x', redirect_uris: [CLAUDE_CALLBACK] }],
      ['https://claude.ai/oauth/evil-redirect', { client_id: 'https://claude.ai/oauth/evil-redirect', redirect_uris: ['https://evil.example/cb'] }],
    ] as const) {
      const hh = await hosted({ cimdFetch: async () => doc });
      try {
        assert.equal((await send(hh.port, { path: authorizeQuery(cid) })).status, 400);
      } finally {
        await hh.close();
      }
    }
    const down = await hosted({ cimdFetch: async () => { throw new Error('ECONNREFUSED'); } });
    try {
      const r = await send(down.port, { path: authorizeQuery(CC_CIMD, { redirect_uri: redirect }) });
      assert.equal(r.status, 400);
      assert.equal(r.headers.location, undefined);
    } finally {
      await down.close();
    }
    for (const bad of ['http://claude.ai/oauth/x', 'https://127.0.0.1/x', 'https://claude.ai/']) {
      assert.equal((await send(h.port, { path: authorizeQuery(bad) })).status, 400, bad);
    }
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Scripted e2e with the official MCP SDK OAuth client (DCR and CIMD)

interface TestProvider extends OAuthClientProvider {
  authUrl: URL | null;
}

function testProvider(redirect: string, cimd?: string): TestProvider {
  let info: unknown;
  let toks: unknown;
  let verifier = '';
  const p: TestProvider = {
    authUrl: null,
    get redirectUrl() { return redirect; },
    get clientMetadata() {
      return { client_name: 'e2e', redirect_uris: [redirect], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' };
    },
    state: () => 'e2e-state',
    clientInformation: () => info as never,
    saveClientInformation: (i) => { info = i; },
    tokens: () => toks as never,
    saveTokens: (t) => { toks = t; },
    redirectToAuthorization: (u) => { p.authUrl = u; },
    saveCodeVerifier: (v) => { verifier = v; },
    codeVerifier: () => verifier,
  };
  if (cimd) p.clientMetadataUrl = cimd;
  return p;
}

async function sdkFlow(h: H, provider: TestProvider): Promise<void> {
  const rewrite = (u: string | URL | Request) => String(u instanceof Request ? u.url : u).replace(ISSUER, h.base);
  const fetchFn = ((u: string | URL | Request, init?: RequestInit) => fetch(rewrite(u), init)) as typeof fetch;
  const first = new StreamableHTTPClientTransport(new URL(RESOURCE), { authProvider: provider, fetch: fetchFn });
  const c1 = new Client({ name: 'e2e', version: '0' });
  await assert.rejects(c1.connect(first), UnauthorizedError);
  assert.ok(provider.authUrl, 'the SDK found /authorize through discovery');
  // The "browser": /authorize -> (fake) GitHub -> callback -> consent -> approve.
  const authPath = provider.authUrl!.pathname + provider.authUrl!.search;
  const a = await send(h.port, { path: authPath });
  assert.equal(a.status, 302, a.body);
  const cookie = String((a.headers['set-cookie'] as string[])[0]).split(';')[0]!;
  const consent = await send(h.port, { path: `/oauth/github/callback?code=gh-login&state=${loc(a).searchParams.get('state')}`, headers: { cookie } });
  const ok = await approve(h, consent, cookie);
  const back = loc(ok);
  assert.equal(back.searchParams.get('state'), 'e2e-state');
  await first.finishAuth(back.searchParams.get('code')!);
  const c2 = new Client({ name: 'e2e', version: '0' });
  await c2.connect(new StreamableHTTPClientTransport(new URL(RESOURCE), { authProvider: provider, fetch: fetchFn }));
  try {
    const tools = (await c2.listTools()).tools.map((t) => t.name);
    assert.ok(tools.includes('zeusi_search') && !tools.includes('zeusi_log_decision'));
    const r = (await c2.callTool({ name: 'zeusi_search', arguments: { query: 'wombat' } })) as { content: Array<{ text: string }> };
    assert.ok((JSON.parse(r.content[0]!.text) as { hits: unknown[] }).hits.length >= 1);
  } finally {
    await c2.close();
  }
}

test('oauth e2e (SDK client, DCR, claude.ai callback): 401 -> discovery -> register -> authorize -> GitHub -> consent -> token -> initialize, tools/list, search', async () => {
  const h = await hosted();
  try {
    await sdkFlow(h, testProvider(CLAUDE_CALLBACK));
    assert.equal(h.store.list().clients.length, 1, 'registered through DCR');
    assert.equal(h.store.list().grants.length, 1);
  } finally {
    await h.close();
  }
});

test('oauth e2e (SDK client, CIMD, loopback callback): no registration call, same result', async () => {
  const h = await hosted();
  try {
    await sdkFlow(h, testProvider('http://127.0.0.1:41234/callback', CC_CIMD));
    assert.equal(h.store.list().clients.length, 0, 'CIMD: nothing registered');
    assert.ok(h.cimd.includes(CC_CIMD));
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Speaks up first (plan U4) for an OAuth read grant: same read tools, prompt and resource as a
// read bearer token; still no write path. Synthetic fixture (invent=NO), created on first use.

test('oauth F4/F5: an OAuth read grant is told only about the tools it lists (no write tool named, even with --write-service); context, not permission', async () => {
  const h = await hosted({ tokensRows: [(await mint('read')).row], over: { writeService: 'zeusi_decision' } });
  try {
    const t = await tokensFor(h);
    const ins = (JSON.parse((await mcpPost(h.port, t.access, INIT)).body) as { result: { instructions?: string } }).result.instructions ?? '';
    const names = (JSON.parse((await mcpPost(h.port, t.access, LIST)).body) as { result: { tools: Array<{ name: string }> } }).result.tools.map((x) => x.name);
    assertToolsAgree(ins, names, 'oauth read grant');
    const res = await mcpPost(h.port, t.access, { jsonrpc: '2.0', id: 4, method: 'resources/read', params: { uri: 'zeusi://about' } });
    const about = (JSON.parse(res.body) as { result: { contents: Array<{ text: string }> } }).result.contents[0]!.text;
    for (const x of [ins, about]) {
      assert.doesNotMatch(x, /log_decision/);
      assert.match(x, /Writing decisions is not available on this connection/);
      assert.match(x, CONTEXT_NOT_PERMISSION_RE);
      assert.match(x, NOT_A_GO_RE);
    }
    for (const n of toolNamesIn(about)) assert.ok(names.includes(n), `about names ${n}, which is listed`);
  } finally {
    await h.close();
  }
});

let oauthPrimeReady: Promise<void> | undefined;
const oauthPrimeFixtures = () => (oauthPrimeReady ??= (async () => {
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('synthetic-owner', 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/synthetic-owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  await db.query(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind,
                                  source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('lock', (SELECT id FROM zeusi.people WHERE handle = 'synthetic-owner'), now() - interval '2 days', 'minute',
             'SYNTHETIC FIXTURE: lock the wombat release during market hours', false, ARRAY['wombat'], 'work', 'manual',
             'test:oauth-lock', now() - interval '2 days', sha256(convert_to('test:oauth-lock', 'UTF8')), $1)`, [run]);
})());

test('oauth on /mcp: an OAuth read grant lists and calls zeusi_context_for_task / prime, reads zeusi://about, gets start-task; log_decision stays 401', async () => {
  await oauthPrimeFixtures();
  const writes: string[] = [];
  const h = await hosted({ tokensRows: [(await mint('read')).row], over: { writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', writes) } });
  try {
    const t = await tokensFor(h);
    const init = await mcpPost(h.port, t.access, INIT);
    assert.equal(init.status, 200);
    const ir = (JSON.parse(init.body) as { result: { instructions?: string; capabilities: Record<string, unknown> } }).result;
    assert.match(ir.instructions ?? '', /zeusi_context_for_task/);
    assert.ok(ir.capabilities['prompts'] && ir.capabilities['resources']);
    const names = (JSON.parse((await mcpPost(h.port, t.access, LIST)).body) as { result: { tools: Array<{ name: string }> } }).result.tools.map((x) => x.name);
    for (const n of ['zeusi_context_for_task', 'context_for_task', 'prime']) assert.ok(names.includes(n), n);
    assert.ok(!names.includes('zeusi_log_decision') && !names.includes('log_decision'));
    for (const n of ['zeusi_context_for_task', 'prime']) {
      const r = await mcpPost(h.port, t.access, call(n, { task: 'ship the wombat release' }));
      assert.equal(r.status, 200, n);
      const j = JSON.parse((JSON.parse(r.body) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text) as { items: Array<{ source_uri: string; kind: string }> };
      assert.deepEqual(j.items.map((i) => [i.source_uri, i.kind]), [['test:oauth-lock', 'lock']]);
    }
    const res = await mcpPost(h.port, t.access, { jsonrpc: '2.0', id: 4, method: 'resources/read', params: { uri: 'zeusi://about' } });
    assert.equal(res.status, 200);
    assert.match(res.body, /named after a cat/);
    const p = await mcpPost(h.port, t.access, { jsonrpc: '2.0', id: 5, method: 'prompts/get', params: { name: 'start-task', arguments: { task: 'ship the wombat release' } } });
    assert.equal(p.status, 200);
    assert.match(p.body, /zeusi_context_for_task/);
    for (const n of ['zeusi_log_decision', 'log_decision']) assert.equal((await mcpPost(h.port, t.access, call(n, { kind: 'go' }))).status, 401, n);
    assert.deepEqual(writes, [], 'nothing connected for writing');
    // the log for the OAuth call: tool name and counts, never the task text
    assert.ok(!h.logs.join('\n').includes('wombat release'));
  } finally {
    await h.close();
  }
});

test('oauth on /mcp (Fix PR A): an OAuth read grant gets standing note-lock rules in zeusi_startup and note locks in context_for_task; no write path; log has no lock or task text', async () => {
  const LOCK = 'SYNTHETIC OAUTH LOCK: no echidnadeploy on Fridays';
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(
    `INSERT INTO zeusi.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/ops/oauth-locks.md', 'OAuth locks (synthetic)', jsonb_build_object('locks', $1::text), 'synthetic body', now(),
             'work', 'vault_note', 'vault:Work/ops/oauth-locks.md', now(), decode($2, 'hex'), $3)`, [LOCK, SHA, run]);
  const writes: string[] = [];
  const h = await hosted({ tokensRows: [(await mint('read')).row], over: { writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', writes) } });
  try {
    const t = await tokensFor(h);
    const body = (r: { body: string }) => JSON.parse((JSON.parse(r.body) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text) as Record<string, unknown>;
    const s = await mcpPost(h.port, t.access, call('zeusi_startup', {}));
    assert.equal(s.status, 200);
    const rules = body(s)['rules'] as Array<{ origin: string; text: string; who: unknown; source_uri: string }>;
    // compact startup form (session-start gaps U2): no speaker field at all for a note lock (never an invented who)
    assert.deepEqual(rules.filter((r) => r.origin === 'note_lock').map((r) => [r.text, 'who' in r, r.source_uri]), [[LOCK, false, 'vault:Work/ops/oauth-locks.md']]);
    const c = await mcpPost(h.port, t.access, call('prime', { task: 'echidnadeploy (oauth-marker-6262)' }));
    assert.equal(c.status, 200);
    assert.deepEqual((body(c)['items'] as Array<{ origin: string; exact_words: string }>).map((i) => [i.origin, i.exact_words]), [['note_lock', LOCK]]);
    assert.equal((await mcpPost(h.port, t.access, call('zeusi_log_decision', { kind: 'go' }))).status, 401);
    assert.deepEqual(writes, []);
    const logs = h.logs.join('\n');
    for (const bad of ['echidnadeploy', 'oauth-marker-6262', 'SYNTHETIC OAUTH LOCK', 'OAuth locks']) assert.ok(!logs.includes(bad), bad);
  } finally {
    await h.close();
  }
});

test('oauth on /mcp (PR2 U6): an OAuth read grant lists and calls zeusi_onboarding_status / onboarding_status and gets the onboarding prompt; no write path; log has no row text', async () => {
  const writes: string[] = [];
  const h = await hosted({ tokensRows: [(await mint('read')).row], over: { writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', writes) } });
  try {
    const t = await tokensFor(h);
    const names = (JSON.parse((await mcpPost(h.port, t.access, LIST)).body) as { result: { tools: Array<{ name: string }> } }).result.tools.map((x) => x.name);
    for (const n of ['zeusi_onboarding_status', 'onboarding_status']) assert.ok(names.includes(n), n);
    for (const n of ['zeusi_onboarding_status', 'onboarding_status']) {
      const r = await mcpPost(h.port, t.access, call(n, {}));
      assert.equal(r.status, 200, n);
      const j = JSON.parse((JSON.parse(r.body) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text) as { counts: Record<string, number>; empty: boolean };
      assert.equal(typeof j.empty, 'boolean');
      assert.equal(typeof j.counts['notes'], 'number');
    }
    const p = await mcpPost(h.port, t.access, { jsonrpc: '2.0', id: 6, method: 'prompts/get', params: { name: 'onboarding', arguments: {} } });
    assert.equal(p.status, 200);
    assert.match(p.body, /zeusi_onboarding_status/);
    assert.doesNotMatch(p.body, /log_decision/);
    assert.equal((await mcpPost(h.port, t.access, call('zeusi_log_decision', { kind: 'go' }))).status, 401);
    assert.deepEqual(writes, [], 'nothing connected for writing');
    const logs = h.logs.join('\n');
    for (const bad of ['SYNTHETIC', 'echidnadeploy']) assert.ok(!logs.includes(bad), bad);
  } finally {
    await h.close();
  }
});

test('oauth on /mcp (Fix PR A x #23 serve guard): an OAuth read grant never gets a planted partial key from a lock item, a note title, a linked field or a hybrid hit; withheld and counted, log counts only', async () => {
  const cleanup = await plantGuardFixtures(db);
  const h = await hosted({ tokensRows: [(await mint('read')).row] });
  try {
    const t = await tokensFor(h);
    await assertGuardedChannels(async (name, args) => {
      const r = await mcpPost(h.port, t.access, call(name, args));
      const json = r.status === 200 ? JSON.parse((JSON.parse(r.body) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text) as Record<string, unknown> : {};
      return { status: r.status, body: r.body, json };
    });
    await new Promise((res) => setImmediate(res));
    assertGuardLog(h.logs);
  } finally {
    await h.close();
    await cleanup();
  }
});

test('oauth on /mcp (lock lifecycle): an OAuth read grant and a read bearer see the same rule counts; onboarding rules == startup total; superseded / expired locks not served; log has no lock text', async () => {
  const OLD = 'SYNTHETIC LIFECYCLE LOCK: platypus desk runs distro-A (superseded)';
  const NEW = 'SYNTHETIC LIFECYCLE LOCK: platypus desk runs its chosen OS';
  const LAPSED = 'SYNTHETIC LIFECYCLE LOCK: through Sat 24 Oct platypus uses tool-A';
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  const ins = (path: string, fm: Record<string, unknown>, ts: string) => db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, $1, $2::jsonb, 'synthetic body', now(), 'work', 'vault_note', 'vault:' || $1, $3::timestamptz, decode($4, 'hex'), $5) RETURNING id::int AS id`,
    [path, JSON.stringify(fm), ts, SHA, run]);
  const ids = [
    (await ins('Work/ops/lc-old.md', { locks: [OLD] }, '2026-10-29T00:00:00Z')).rows[0]!.id,
    (await ins('Work/ops/lc-new.md', { locks: [NEW], supersedes: ['1: [[lc-old]] lock 1'] }, '2026-11-11T00:00:00Z')).rows[0]!.id,
    (await ins('Work/ops/lc-lapsed.md', { locks: [LAPSED], lock_until: ['1: 2026-10-25T00:00+02:00'] }, '2026-10-20T00:00:00Z')).rows[0]!.id,
  ];
  const bearer = await mint('read');
  const h = await hosted({ tokensRows: [bearer.row] });
  try {
    const t = await tokensFor(h);
    const body = (r: { body: string }) => JSON.parse((JSON.parse(r.body) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text) as Record<string, unknown>;
    const seen: Array<{ rules: number; total: unknown; byOrigin: unknown; status: number[] }> = [];
    for (const tok of [t.access, bearer.token]) {
      const s = body(await mcpPost(h.port, tok, call('zeusi_startup', {})));
      const o = body(await mcpPost(h.port, tok, call('onboarding_status', {})));
      const texts = (s['rules'] as Array<{ text: string }>).map((r) => r.text);
      assert.ok(texts.includes(NEW) && !texts.includes(OLD) && !texts.includes(LAPSED));
      const c = o['counts'] as Record<string, number>;
      assert.equal(c['rules'], (s['rules_total'] as { total: number }).total);
      seen.push({ rules: c['rules']!, total: s['rules_total'], byOrigin: o['rules_by_origin'], status: [c['note_locks_current']!, c['note_locks_superseded']!, c['note_locks_expired']!] });
    }
    assert.deepEqual(seen[0], seen[1], 'OAuth zeusi.read and the read bearer agree');
    assert.ok(seen[0]!.status[1]! >= 1 && seen[0]!.status[2]! >= 1);
    const logs = h.logs.join('\n');
    for (const bad of ['SYNTHETIC LIFECYCLE', 'platypus', 'lc-old', 'lc-new']) assert.ok(!logs.includes(bad), bad);
  } finally {
    await h.close();
    await db.query(`DELETE FROM zeusi.notes WHERE id = ANY($1::bigint[])`, [ids]);
  }
});
