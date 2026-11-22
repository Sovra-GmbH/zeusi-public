// C4 end to end (docs/plans/2026-11-18-c4-enroll.md): the consent page with ZEUSI_WORKSPACE_ENCRYPTION=enroll
// (enroll -> recovery code once -> continue -> /token -> refresh -> unlock by passkey and by recovery code ->
// revoke) on an ephemeral 127.0.0.1 port through the real hosted handler, PGlite catalog, fake GitHub, temp
// dirs. Covers §7 items 3, 8, 9 (end to end), 12, flag off unchanged, the team refused.
// The browser is emulated: a fake authenticator derives the PRF output as HMAC(test secret, credential, salt).
// Every DEK, PRF output, recovery code and token below is a TEST value. No live service is contacted.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { chmodSync, existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import type { Db } from '../src/db.ts';
import { Authenticator } from '../src/mcp-auth.ts';
import { createHostedHandler } from '../src/mcp-hosted.ts';
import { createMcpState, type McpDeps } from '../src/mcp-server.ts';
import { CLAUDE_CALLBACK, OAUTH_PATHS, OAuthServer, pkceChallenge, type WrapCatalog } from '../src/mcp-oauth.ts';
import type { GithubApi, GithubIdentity } from '../src/mcp-oauth-github.ts';
import { OAuthStore } from '../src/mcp-oauth-store.ts';
import { CONSENT_SCRIPT, CONSENT_SCRIPT_HASH, consentPage, esc, RECOVERY_WARNING_BORN, RECOVERY_WARNING_KEY, recoveryCodePage } from '../src/mcp-oauth-views.ts';
import { enrollAuditSink } from '../src/enroll-audit.ts';
import { RecoveryAttemptLimiter } from '../src/recovery-limit.ts';
import { TenantDirectory } from '../src/tenants.ts';
import { encryptionMode, formatRecoveryCode, openSessionDek, parseRecoveryCode } from '../src/workspace-keys.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, tenantTestDb } from './helpers/tenant-fixture.ts';
import { overclaims } from './helpers/overclaim.ts';
import { enrollFields, SoftAuthenticator, unlockFields } from './helpers/soft-webauthn.ts';

const ISSUER = 'https://mcp.zeusi.dev';
const RESOURCE = `${ISSUER}/mcp`;
const KEY = 'c'.repeat(48);
const DEK = Buffer.from('c4-test-dek-pattern-0123456789ab', 'utf8'); // 32 bytes
const AUTH_SECRET = 'c4-test-authenticator-secret';
const VERIFIER = 'w'.repeat(50) + '-._~';
const OLD_CSP = (origin: string) => `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${origin}; frame-ancestors 'none'; base-uri 'none'`;
/** The OAuth routes before C4: C4 adds none (no recovery or passkey guess endpoint). */
const PRE_C4_PATHS = [
  '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-authorization-server',
  '/authorize', '/token', '/register', '/revoke', '/oauth/github/callback', '/oauth/consent',
];

const IDS: Record<string, GithubIdentity> = {
  'gh-p1': { id: 9101, login: 'person-one', verifiedEmails: ['p1@example.com'] },
  'gh-p2': { id: 9102, login: 'person-two', verifiedEmails: ['p2@example.com'] },
  'gh-p3': { id: 9103, login: 'person-three', verifiedEmails: [] },
  'gh-operator': { id: 9104, login: 'operator-bot', verifiedEmails: ['operator@example.com'] },
  'gh-born': { id: 9105, login: 'person-born', verifiedEmails: [] },
};
const github: GithubApi = {
  async exchange(code) { return code in IDS ? `ghtok-${code}` : null; },
  async identity(t) { return IDS[t.replace(/^ghtok-/, '')] ?? null; },
};

/** The fake authenticator: PRF(credential, salt). */
const prfFor = (cred: Buffer, salt: Buffer) => createHmac('sha256', AUTH_SECRET).update(cred).update(salt).digest();

let db: Db;
let dir: TenantDirectory;
const seenPrf: Buffer[] = [];
const seenCodes: string[] = [];
const roots: string[] = [];

before(async () => {
  db = await tenantTestDb({ writer: true });
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
});
after(async () => db.close());

function tmp(prefix: string): string {
  const d = safeMkdtemp(join(tmpdir(), prefix));
  chmodSync(d, 0o700);
  roots.push(d);
  return d;
}

interface Calls { view: number; wraps: number; enroll: number; counter?: number }

function spyCatalog(calls: Calls, d: TenantDirectory = dir): WrapCatalog {
  return {
    encryptionView: (t) => { calls.view++; return d.encryptionView(t); },
    wrapsFor: (t, k) => { calls.wraps++; return d.wrapsFor(t, k); },
    enroll: (t, r) => { calls.enroll++; return d.enroll(t, r); },
    advanceSignCount: (t, c, from, to) => { calls.counter = (calls.counter ?? 0) + 1; return d.advanceSignCount(t, c, from, to); },
  };
}

interface H {
  port: number;
  logs: string[];
  audit: string[];
  calls: Calls;
  store: OAuthStore;
  root: string;
  close: () => Promise<void>;
}

async function hosted(o: { keys: boolean; root?: string; dir?: TenantDirectory }): Promise<H> {
  const d = o.dir ?? dir;
  const root = o.root ?? tmp('zeusi-c4-data-');
  const logs: string[] = [];
  const audit: string[] = [];
  const calls: Calls = { view: 0, wraps: 0, enroll: 0 };
  const store = new OAuthStore({ hashKey: KEY, path: join(root, 'mcp-oauth.json') });
  const server = new OAuthServer({
    issuer: ISSUER, githubClientId: 'Iv1.c4test', github, signingKey: KEY, store, tenants: d, workspaceWrite: false,
    limits: { authorize: 1000, callback: 1000, consent: 1000, token: 1000, register: 1000, registerGlobal: 1000, revoke: 1000, signupPerIp: 1000, signupGlobal: 1000 },
    audit: (e) => logs.push(`signin:${JSON.stringify(e)}`),
    ...(o.keys ? {
      keys: {
        mode: 'enroll',
        catalog: spyCatalog(calls, d),
        limiter: new RecoveryAttemptLimiter({ hashKey: KEY, file: join(root, '.zeusi', 'recovery-attempts.json') }),
        audit: enrollAuditSink({ log: (l) => audit.push(l), file: join(root, '.zeusi', 'enroll-audit.jsonl') }),
        newDek: () => Buffer.from(DEK),
      },
    } : {}),
  });
  const srv: Server = createServer();
  await new Promise<void>((res) => srv.listen(0, '127.0.0.1', res));
  const port = (srv.address() as AddressInfo).port;
  const deps: McpDeps = {
    env: { HOME: root }, home: root, readService: 'zeusi_ro',
    connectRead: async () => { throw new Error('not used'); }, connectWrite: async () => { throw new Error('not used'); },
    embeddings: () => null, feedbackPath: join(root, '.zeusi', 'search-feedback.jsonl'), queryLedgerPath: join(root, '.zeusi', 'q.json'),
  };
  const authenticator = new Authenticator({ tokensPath: join(root, 'mcp-tokens.json'), oauth: server });
  srv.on('request', createHostedHandler({
    deps, state: createMcpState(), authenticator, allowedHosts: [`127.0.0.1:${port}`], log: (l) => logs.push(l), oauth: { state: 'enabled', server },
  }));
  return { port, logs, audit, calls, store, root, close: () => new Promise((res) => srv.close(() => res())) };
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
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
const loc = (r: Resp) => new URL(String(r.headers.location));
const attr = (html: string, name: string) => new RegExp(`${name}="([^"]*)"`).exec(html)?.[1];
const hidden = (html: string, name: string, formId?: string) => {
  const scope = formId ? html.slice(html.indexOf(`id="${formId}"`)) : html;
  return new RegExp(`name="${name}" value="([^"]+)"`).exec(scope)![1]!;
};

async function client(h: H): Promise<string> {
  const r = await send(h.port, { method: 'POST', path: '/register', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [CLAUDE_CALLBACK], client_name: 'C4' }) });
  return (JSON.parse(r.body) as { client_id: string }).client_id;
}

async function toConsent(h: H, clientId: string, gh: string, ip = '203.0.113.7'): Promise<{ consent: Resp; cookie: string; ip: string }> {
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: CLAUDE_CALLBACK, code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: 'S256', state: 'st', scope: 'zeusi.read offline_access', resource: RESOURCE,
  });
  const a = await send(h.port, { path: `/authorize?${q}`, headers: { 'fly-client-ip': ip } });
  assert.equal(a.status, 302);
  const cookie = String((a.headers['set-cookie'] as string[])[0]).split(';')[0]!;
  const consent = await send(h.port, { path: `/oauth/github/callback?code=${gh}&state=${loc(a).searchParams.get('state')}`, headers: { cookie, 'fly-client-ip': ip } });
  return { consent, cookie, ip };
}

function post(h: H, cookie: string, ip: string, fields: Record<string, string>): Promise<Resp> {
  return send(h.port, { method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie, 'fly-client-ip': ip }, body: form(fields) });
}

async function exchange(h: H, clientId: string, code: string): Promise<{ access: string; refresh: string }> {
  const r = await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'authorization_code', code, redirect_uri: CLAUDE_CALLBACK, client_id: clientId, code_verifier: VERIFIER, resource: RESOURCE }) });
  assert.equal(r.status, 200, r.body);
  const j = JSON.parse(r.body) as { access_token: string; refresh_token: string };
  return { access: j.access_token, refresh: j.refresh_token };
}

/** §7 item 12 checker: one hash-pinned inline script, no request-capable source, none of `forbidden` in the page. */
function assertHardened(html: string, csp: string | undefined, forbidden: readonly string[]): void {
  assert.ok(typeof csp === 'string' && csp.length > 0, 'a CSP header is sent');
  const dirs = new Map(csp.split(';').map((d) => d.trim()).filter(Boolean).map((d) => [d.split(' ')[0]!, d.split(' ').slice(1)] as const));
  assert.deepEqual(dirs.get('default-src'), ["'none'"]);
  assert.deepEqual(dirs.get('frame-ancestors'), ["'none'"]);
  assert.deepEqual(dirs.get('base-uri'), ["'none'"]);
  for (const d of ['connect-src', 'img-src', 'font-src', 'frame-src', 'media-src', 'object-src', 'worker-src']) assert.equal(dirs.get(d), undefined, `${d} stays at default-src 'none'`);
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1, 'exactly one script');
  assert.equal(scripts[0]![1]!.trim(), '', 'inline, no src or other attribute');
  const body = scripts[0]![2]!;
  assert.deepEqual(dirs.get('script-src'), [`'sha256-${createHash('sha256').update(body, 'utf8').digest('base64')}'`], 'script-src pins exactly this script');
  for (const bad of ['fetch(', 'XMLHttpRequest', 'sendBeacon', 'WebSocket', 'EventSource', 'import(', 'http:', 'https:', 'eval(', 'Function(', 'innerHTML', 'document.write']) {
    assert.ok(!body.includes(bad), `script has no ${bad}`);
  }
  assert.doesNotMatch(html, /<(link|img|iframe|object|embed|audio|video|source)\b/i);
  assert.doesNotMatch(html, /\s(src|href)=/i);
  assert.doesNotMatch(html, /https?:\/\//i, 'no absolute URL in the page');
  for (const f of forbidden) if (f) assert.ok(!html.includes(f), 'a secret is echoed in the page');
}

function b64Forms(b: Buffer): string[] {
  return [b.toString('hex'), b.toString('base64'), b.toString('base64url'), b.toString('base64').replace(/=+$/, '')];
}

// ---------------------------------------------------------------------------

test('C4 flag off: consentPage without keys is BYTE-IDENTICAL to the pre-C4 page (snapshot rendered from 3157ee5)', () => {
  // test/fixtures/c4-pre-consent-pages.json: the pre-C4 src/mcp-oauth-views.ts (git 3157ee5) rendered with these inputs.
  const pre = JSON.parse(readFileSync('test/fixtures/c4-pre-consent-pages.json', 'utf8')) as string[];
  const base = { clientLabel: { kind: 'cimd' as const, host: 'claude.ai', name: 'Claude' }, redirectHost: 'claude.ai', local: false, login: 'person-one', txn: 'T'.repeat(43), csrf: 'C'.repeat(43) };
  const now = [
    consentPage(base),
    consentPage({ ...base, personal: { created: true, write: true } }),
    consentPage({ ...base, clientLabel: { kind: 'dcr', name: 'x' }, redirectHost: 'localhost:1234', local: true, personal: { created: false, write: false } }),
  ];
  assert.equal(pre.length, 3);
  for (let i = 0; i < 3; i++) assert.equal(now[i], pre[i], `variant ${i}`);
});

test('C4 flag off: the consent page is the pre-C4 page (no script, same CSP); nothing is read or written; flag parsing', async () => {
  const h = await hosted({ keys: false });
  try {
    const c = await client(h);
    const { consent } = await toConsent(h, c, 'gh-p3');
    assert.equal(consent.status, 200);
    assert.equal(consent.headers['content-security-policy'], OLD_CSP('https://claude.ai'));
    assert.doesNotMatch(consent.body, /<script|zeusi-keys|passkey|recovery/i);
    assert.deepEqual([...consent.body.matchAll(/<(?:input|button)\b[^>]*name="([a-z]+)"/g)].map((m) => m[1]), ['txn', 'csrf', 'decision', 'decision']);
    assert.ok(!existsSync(join(h.root, '.zeusi', 'recovery-attempts.json')) && !existsSync(join(h.root, '.zeusi', 'enroll-audit.jsonl')));
    // enc fields posted at a flag-off server are refused, never acted on.
    const again = await toConsent(h, c, 'gh-p3');
    const r = await post(h, again.cookie, again.ip, { txn: hidden(again.consent.body, 'txn'), csrf: hidden(again.consent.body, 'csrf'), decision: 'approve', enc: 'recover', recovery: '0000' });
    assert.equal(r.status, 400);
    const t = (await dir.lookup('github:9103'))!.tenantId;
    assert.equal(await asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi_tenants.key_wraps WHERE tenant_id = $1`, [t])).rows[0]!.n), 0);
  } finally {
    await h.close();
  }
  assert.deepEqual(encryptionMode({}), { mode: 'off' });
  assert.deepEqual(encryptionMode({ ZEUSI_WORKSPACE_ENCRYPTION: 'off' }), { mode: 'off' });
  assert.deepEqual(encryptionMode({ ZEUSI_WORKSPACE_ENCRYPTION: 'enroll' }), { mode: 'enroll' });
  // C5 KTD13 (docs/plans/2026-11-19-c5-tenant-ddl.md): `on` is understood since C5; it was `off` under C4.
  assert.deepEqual(encryptionMode({ ZEUSI_WORKSPACE_ENCRYPTION: 'on' }), { mode: 'on' });
  for (const v of ['true', 'ENROLL', 'zz-weird-value']) {
    const m = encryptionMode({ ZEUSI_WORKSPACE_ENCRYPTION: v });
    assert.equal(m.mode, 'off');
    assert.ok(m.log && m.log.includes('ZEUSI_WORKSPACE_ENCRYPTION') && !m.log.includes(v), 'names the variable, never the value');
  }
  assert.doesNotMatch(readFileSync('fly.toml', 'utf8'), /ZEUSI_WORKSPACE_ENCRYPTION/, 'production config does not enable it');
  assert.deepEqual([...OAUTH_PATHS], PRE_C4_PATHS, 'C4 adds no route (no recovery or passkey guess endpoint)');
});

test('C4 flag on, operator member: no passkey block, no script, no catalog call (team is refused)', async () => {
  const h = await hosted({ keys: true });
  try {
    const { consent } = await toConsent(h, await client(h), 'gh-operator');
    assert.equal(consent.status, 200);
    assert.equal(consent.headers['content-security-policy'], OLD_CSP('https://claude.ai'));
    assert.doesNotMatch(consent.body, /<script|zeusi-keys/);
    assert.deepEqual(h.calls, { view: 0, wraps: 0, enroll: 0 });
  } finally {
    await h.close();
  }
});

test('C4 flag on: enroll -> recovery code once -> continue -> /token -> refresh -> unlock (passkey, recovery) -> revoke; §7 items 3, 9, 12', async () => {
  const root = tmp('zeusi-c4-data-');
  const h = await hosted({ keys: true, root });
  const pages: string[] = [];
  // Real process stderr during the whole flow (the production audit sink writes there).
  const stderr: string[] = [];
  const realWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
    stderr.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk as Uint8Array).toString('utf8'));
    return (realWrite as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;
  try {
    const c = await client(h);
    // ---- enroll
    const s1 = await toConsent(h, c, 'gh-p1');
    assert.equal(s1.consent.status, 200);
    pages.push(s1.consent.body);
    assert.equal(attr(s1.consent.body, 'data-mode'), 'enroll');
    assert.equal(attr(s1.consent.body, 'data-rp'), 'mcp.zeusi.dev');
    assertHardened(s1.consent.body, s1.consent.headers['content-security-policy'] as string, []);
    assert.ok((s1.consent.headers['content-security-policy'] as string).includes(`script-src ${CONSENT_SCRIPT_HASH}`));
    assert.ok((s1.consent.headers['content-security-policy'] as string).includes("form-action 'self' https://claude.ai"));
    assert.deepEqual(overclaims(s1.consent.body.replace(/<script>[\s\S]*<\/script>/, '')), [], 'no encryption claim on the page');
    const tenant = (await dir.lookup('github:9101'))!.tenantId;
    const cred = Buffer.from('c4-test-credential-p1');
    const auth = new SoftAuthenticator({ credentialId: cred });
    const salt = Buffer.from(attr(s1.consent.body, 'data-salt')!, 'base64url');
    assert.equal(salt.length, 32);
    const prf = auth.prf(salt);
    seenPrf.push(prf);
    const e = await post(h, s1.cookie, s1.ip, {
      txn: hidden(s1.consent.body, 'txn'), csrf: hidden(s1.consent.body, 'csrf'), decision: 'approve', ...enrollFields(auth, s1.consent.body, ISSUER),
    });
    assert.equal(e.status, 200, e.body);
    pages.push(e.body);
    const shown = /id="zeusi-recovery-code">([^<]+)</.exec(e.body)![1]!;
    seenCodes.push(shown);
    assert.ok(parseRecoveryCode(shown), 'a valid recovery code');
    assert.equal(e.body.split(shown).length, 2, 'shown exactly once');
    assert.doesNotMatch(e.body, /<script/);
    assert.equal(e.headers['content-security-policy'], OLD_CSP('https://claude.ai'), 'the recovery page has no script-src');
    assert.ok(!e.body.includes(prf.toString('base64url')) && !e.body.includes(cred.toString('base64url')));
    assert.deepEqual(overclaims(e.body), []);
    // An `off` workspace moves to `enrolled`: only the key is set up, its content stays plain (mutant: offer.born true -> red).
    assert.ok(e.body.includes(esc(RECOVERY_WARNING_KEY)) && !e.body.includes(esc(RECOVERY_WARNING_BORN)), 'the key warning, not the born one');
    assert.equal(e.headers['set-cookie'], undefined, 'the browser binding stays for the continue step');
    assert.equal(await asOwner(db, async () => (await db.query<{ s: string }>(`SELECT enc_state AS s FROM zeusi_tenants.tenants WHERE tenant_id = $1`, [tenant])).rows[0]!.s), 'enrolled');
    // continue -> code -> token
    const cont = await post(h, s1.cookie, s1.ip, { txn: hidden(e.body, 'txn'), csrf: hidden(e.body, 'csrf'), decision: 'approve' });
    assert.equal(cont.status, 302);
    const tok = await exchange(h, c, loc(cont).searchParams.get('code')!);
    assert.deepEqual(openSessionDek(h.store, tok.access)!.dek, DEK, 'the session wrap opens the enrolled DEK');
    assert.equal(openSessionDek(h.store, tok.access)!.tenant, tenant);
    // the continuation is single use
    assert.equal((await post(h, s1.cookie, s1.ip, { txn: hidden(e.body, 'txn'), csrf: hidden(e.body, 'csrf'), decision: 'approve' })).status, 400);
    // ---- refresh rewraps
    const rr = await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'refresh_token', refresh_token: tok.refresh, client_id: c }) });
    assert.equal(rr.status, 200);
    const t2 = JSON.parse(rr.body) as { access_token: string; refresh_token: string };
    assert.deepEqual(openSessionDek(h.store, t2.access_token)!.dek, DEK);
    assert.equal(openSessionDek(h.store, tok.access), null);
    // ---- unlock with the passkey on a new sign-in
    const s2 = await toConsent(h, c, 'gh-p1');
    pages.push(s2.consent.body);
    assert.equal(attr(s2.consent.body, 'data-mode'), 'unlock');
    assert.equal(attr(s2.consent.body, 'data-creds'), `${cred.toString('base64url')}.${salt.toString('base64url')}`);
    assertHardened(s2.consent.body, s2.consent.headers['content-security-policy'] as string, [prf.toString('base64url'), shown]);
    const u = await post(h, s2.cookie, s2.ip, {
      txn: hidden(s2.consent.body, 'txn'), csrf: hidden(s2.consent.body, 'csrf'), decision: 'approve', ...unlockFields(auth, s2.consent.body, ISSUER),
    });
    assert.equal(u.status, 302, u.body);
    const tok3 = await exchange(h, c, loc(u).searchParams.get('code')!);
    assert.deepEqual(openSessionDek(h.store, tok3.access)!.dek, DEK);
    // a wrong PRF output: refused, nothing issued, never echoed; the sign-in is consumed
    const s3 = await toConsent(h, c, 'gh-p1');
    const wrongPrf = prfFor(cred, Buffer.alloc(32, 9));
    seenPrf.push(wrongPrf);
    const bad = { txn: hidden(s3.consent.body, 'txn'), csrf: hidden(s3.consent.body, 'csrf'), decision: 'approve', ...unlockFields(auth, s3.consent.body, ISSUER, { prf: wrongPrf }) };
    const w = await post(h, s3.cookie, s3.ip, bad);
    assert.equal(w.status, 400);
    assert.equal(w.headers.location, undefined);
    assert.ok(!w.body.includes(wrongPrf.toString('base64url')));
    assert.equal((await post(h, s3.cookie, s3.ip, { ...bad, prf: prf.toString('base64url') })).status, 400, 'one attempt per sign-in');
    // ---- unlock with the recovery code (typed in lower case with spaces)
    const s4 = await toConsent(h, c, 'gh-p1');
    pages.push(s4.consent.body);
    const typed = shown.toLowerCase().replace(/-/g, ' ');
    const rc = await post(h, s4.cookie, s4.ip, { txn: hidden(s4.consent.body, 'txn', 'zeusi-recover'), csrf: hidden(s4.consent.body, 'csrf', 'zeusi-recover'), enc: 'recover', decision: 'approve', recovery: typed });
    assert.equal(rc.status, 302, rc.body);
    const tok4 = await exchange(h, c, loc(rc).searchParams.get('code')!);
    assert.deepEqual(openSessionDek(h.store, tok4.access)!.dek, DEK);
    // ---- revoke: the grant's wraps go
    const before = readFileSync(join(root, 'mcp-oauth.json'), 'utf8');
    const wraps4 = h.store.sessionWrapsFor(tok4.access)!.wraps;
    assert.ok(before.includes(wraps4.access));
    assert.equal((await send(h.port, { method: 'POST', path: '/revoke', headers: FORM, body: form({ token: tok4.refresh, client_id: c }) })).status, 200);
    assert.equal(openSessionDek(h.store, tok4.access), null);
    assert.ok(!readFileSync(join(root, 'mcp-oauth.json'), 'utf8').includes(wraps4.access));
    // audit: counts only
    const lines = h.audit.map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.deepEqual(lines.map((l) => [l.action, l.outcome, l.count]), [
      ['enroll', 'ok', null], ['unlock_passkey', 'ok', null], ['unlock_passkey', 'failed', null], ['unlock_recovery', 'ok', 1],
    ]);
    for (const l of lines) assert.deepEqual(Object.keys(l), ['ts', 'request_id', 'tenant_id', 'action', 'outcome', 'count']);
  } finally {
    process.stderr.write = realWrite;
    await h.close();
  }

  // ---- §7 item 3: no unwrapped key at rest, nowhere
  const needles: Array<[string, Buffer | string]> = [];
  for (const f of b64Forms(DEK)) needles.push(['DEK', f]);
  needles.push(['DEK raw', DEK]);
  for (const p of seenPrf) {
    for (const f of b64Forms(p)) needles.push(['PRF', f]);
    needles.push(['PRF raw', p]);
  }
  for (const code of seenCodes) {
    const raw = parseRecoveryCode(code)!;
    needles.push(['code', code], ['code', code.replace(/-/g, '')], ['code', code.toLowerCase()], ['code raw', raw]);
    for (const f of b64Forms(raw)) needles.push(['code', f]);
  }
  const hay: Array<[string, Buffer]> = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else hay.push([p, readFileSync(p)]);
    }
  };
  walk(root);
  assert.ok(hay.some(([p]) => p.endsWith('mcp-oauth.json')) && hay.some(([p]) => p.endsWith('enroll-audit.jsonl')) && hay.some(([p]) => p.endsWith('recovery-attempts.json')));
  const catalog = await asOwner(db, async () => (await db.query<{ t: string }>(
    `SELECT string_agg(concat_ws('|', tenant_id, wrap_id, kind, key_version, encode(sealed_dek, 'hex'), encode(sealed_dek, 'base64'), encode(credential_id, 'hex'), encode(prf_salt, 'hex')), E'\\n') AS t
       FROM zeusi_tenants.key_wraps`)).rows[0]!.t);
  const raws = await asOwner(db, async () => (await db.query<{ s: Uint8Array }>(`SELECT sealed_dek AS s FROM zeusi_tenants.key_wraps`)).rows.map((r) => Buffer.from(r.s)));
  hay.push(['catalog', Buffer.from(catalog, 'utf8')], ['catalog raw', Buffer.concat(raws)]);
  hay.push(['tenants', Buffer.from(JSON.stringify(await asOwner(db, async () => (await db.query(`SELECT to_jsonb(t)::text AS j FROM zeusi_tenants.tenants t`)).rows)), 'utf8')]);
  hay.push(['logs', Buffer.from(h.logs.join('\n'), 'utf8')], ['audit', Buffer.from(h.audit.join('\n'), 'utf8')], ['stderr', Buffer.from(stderr.join(''), 'utf8')]);
  // The pages the server sent, other than the one-time recovery page, must not carry any of them either.
  hay.push(['pages', Buffer.from(pages.filter((p) => !p.includes('zeusi-recovery-code')).join('\n'), 'utf8')]);
  const hits: string[] = [];
  for (const [where, buf] of hay) {
    for (const [what, n] of needles) if (buf.indexOf(typeof n === 'string' ? Buffer.from(n, 'utf8') : n) >= 0) hits.push(`${what} in ${where}`);
  }
  assert.deepEqual(hits, []);
});

test('C4 §7 item 8: the sixth recovery attempt in the hour is 429 + a count-only audit (per workspace, whatever the IP); persisted across a restart; a typo never reaches the catalog', async () => {
  const root = tmp('zeusi-c4-rl-');
  const h = await hosted({ keys: true, root });
  let c: string;
  let code: string;
  try {
    c = await client(h);
    // enroll person-two
    const s = await toConsent(h, c, 'gh-p2', '198.51.100.1');
    const auth = new SoftAuthenticator({ credentialId: Buffer.from('c4-test-credential-p2') });
    const e = await post(h, s.cookie, s.ip, { txn: hidden(s.consent.body, 'txn'), csrf: hidden(s.consent.body, 'csrf'), decision: 'approve', ...enrollFields(auth, s.consent.body, ISSUER) });
    code = /id="zeusi-recovery-code">([^<]+)</.exec(e.body)![1]!;
    seenCodes.push(code);
    // A typo (one symbol): refused before any wrap is read, and not echoed.
    const sym = code.replace(/-/g, '');
    const typo = `${sym.slice(0, 3)}${sym[3] === 'A' ? 'B' : 'A'}${sym.slice(4)}`;
    for (let i = 1; i <= 5; i++) {
      const ip = `198.51.100.${10 + i}`;
      const t = await toConsent(h, c, 'gh-p2', ip);
      const wrapsBefore = h.calls.wraps;
      const r = await post(h, t.cookie, ip, { txn: hidden(t.consent.body, 'txn', 'zeusi-recover'), csrf: hidden(t.consent.body, 'csrf', 'zeusi-recover'), enc: 'recover', decision: 'approve', recovery: typo });
      assert.equal(r.status, 400, `attempt ${i}`);
      assert.equal(h.calls.wraps, wrapsBefore, 'a typo fails the check symbol before any wrap is read');
      assert.ok(!r.body.includes(typo) && !r.body.includes(code), 'never echoed');
      assertHardened(t.consent.body, t.consent.headers['content-security-policy'] as string, [code]);
    }
    // Sixth, from yet another IP and with the RIGHT code: 429, nothing issued.
    const t6 = await toConsent(h, c, 'gh-p2', '198.51.100.99');
    const r6 = await post(h, t6.cookie, t6.ip, { txn: hidden(t6.consent.body, 'txn', 'zeusi-recover'), csrf: hidden(t6.consent.body, 'csrf', 'zeusi-recover'), enc: 'recover', decision: 'approve', recovery: code });
    assert.equal(r6.status, 429);
    assert.ok(Number(r6.headers['retry-after']) > 0);
    assert.equal(r6.headers.location, undefined);
    assert.ok(!r6.body.includes(code));
    const last = JSON.parse(h.audit.at(-1)!) as Record<string, unknown>;
    assert.deepEqual([last.action, last.outcome, last.count], ['unlock_recovery', 'rate_limited', 6]);
    for (const l of h.audit) assert.ok(!l.includes(code) && !l.includes(typo) && !l.includes('198.51.100'), 'the audit holds counts only');
  } finally {
    await h.close();
  }
  // The counts file: timestamps per workspace and per keyed IP hash, nothing else.
  const file = readFileSync(join(root, '.zeusi', 'recovery-attempts.json'), 'utf8');
  assert.equal(statSync(join(root, '.zeusi', 'recovery-attempts.json')).mode & 0o777, 0o600);
  assert.ok(!file.includes('198.51.100') && !file.includes(code));
  const doc = JSON.parse(file) as { tenants: Record<string, number[]>; ips: Record<string, number[]> };
  assert.equal(Object.values(doc.tenants)[0]!.length, 5);
  // Restart: a new server and limiter on the same volume still refuse.
  const h2 = await hosted({ keys: true, root });
  try {
    const c2 = await client(h2);
    const t = await toConsent(h2, c2, 'gh-p2', '192.0.2.200');
    const r = await post(h2, t.cookie, t.ip, { txn: hidden(t.consent.body, 'txn', 'zeusi-recover'), csrf: hidden(t.consent.body, 'csrf', 'zeusi-recover'), enc: 'recover', decision: 'approve', recovery: code });
    assert.equal(r.status, 429, 'persisted: the restart did not reset the count');
    // The passkey path has no server-side counter to guess against, and no route but this single-use POST takes a PRF.
    assert.deepEqual([...OAUTH_PATHS], PRE_C4_PATHS);
  } finally {
    await h2.close();
  }
  // A counts file that does not validate refuses recovery (fail closed) and is not overwritten.
  const lim = new RecoveryAttemptLimiter({ hashKey: KEY, file: join(root, '.zeusi', 'recovery-attempts.json') });
  chmodSync(join(root, '.zeusi', 'recovery-attempts.json'), 0o644);
  assert.deepEqual(lim.attempt('zt_aaaaaaaaaaaaaaaaaaaaaaaaaa', '192.0.2.1').ok, false);
  chmodSync(join(root, '.zeusi', 'recovery-attempts.json'), 0o600);
  // A file that parses but does not validate: refused, and its bytes are left as they are.
  const bogus = join(tmp('zeusi-c4-rl2-'), 'recovery-attempts.json');
  writeFileSync(bogus, '{"version":2}\n', { mode: 0o600 });
  const lim2 = new RecoveryAttemptLimiter({ hashKey: KEY, file: bogus });
  const r2 = lim2.attempt('zt_aaaaaaaaaaaaaaaaaaaaaaaaaa', '192.0.2.1');
  assert.deepEqual([r2.ok, r2.ok ? null : r2.reason], [false, 'unavailable']);
  assert.equal(readFileSync(bogus, 'utf8'), '{"version":2}\n', 'never overwritten');
  // A per-IP limit also holds across workspaces.
  const mem = new RecoveryAttemptLimiter({ hashKey: KEY });
  for (let i = 0; i < 5; i++) assert.equal(mem.attempt(`zt_${String.fromCharCode(97 + i).repeat(26)}`, '192.0.2.50').ok, true);
  assert.deepEqual(mem.attempt('zt_ffffffffffffffffffffffffff', '192.0.2.50').ok, false);
});

test('C4 §7 item 12 mutants: the checker fails when the CSP is dropped or loosened, the hash does not match, or a code is echoed', () => {
  const v = { clientLabel: { kind: 'dcr' as const, name: null }, redirectHost: 'claude.ai', local: false, login: 'u', txn: 't'.repeat(43), csrf: 'c'.repeat(43) };
  const code = formatRecoveryCode(Buffer.alloc(16, 0x2a));
  // Build a real flag-on page through the view (no server needed).
  return import('../src/mcp-oauth-views.ts').then(({ consentPage }) => {
    const html = consentPage({ ...v, keys: { mode: 'unlock', rpId: 'mcp.zeusi.dev', challenge: 'x'.repeat(43), creds: [{ id: 'aWQ', salt: 'c2FsdA' }], recovery: true } });
    const csp = `default-src 'none'; style-src 'unsafe-inline'; script-src ${CONSENT_SCRIPT_HASH}; form-action 'self' https://claude.ai; frame-ancestors 'none'; base-uri 'none'`;
    assertHardened(html, csp, [code]);
    assert.throws(() => assertHardened(html, undefined, [code]), 'no CSP');
    assert.throws(() => assertHardened(html, csp.replace(/; script-src [^;]+/, ''), [code]), 'script-src dropped');
    assert.throws(() => assertHardened(html, csp.replace(CONSENT_SCRIPT_HASH, "'unsafe-inline'"), [code]), 'unsafe-inline');
    assert.throws(() => assertHardened(html, csp.replace("default-src 'none'", 'default-src *'), [code]), 'default-src loosened');
    assert.throws(() => assertHardened(html.replace('(function () {', '(function () { fetch("/x");'), csp, [code]), 'script changed: hash mismatch');
    assert.throws(() => assertHardened(html.replace('</section>', `<p>${code}</p></section>`), csp, [code]), 'code echoed');
    assert.throws(() => assertHardened(html.replace('</main>', '<img src="https://example.com/x.png"></main>'), csp, [code]), 'third-party request');
    assert.throws(() => assertHardened(`${html}<script>1</script>`, csp, [code]), 'a second script');
  });
});

test('C4 script (KTD7, KTD8): enroll without a PRF result from create() calls get() at once with the same salt; unlock uses evalByCredential; fills the form and submits', async () => {
  const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  async function run(attrs: Record<string, string>, creds: { create?: (o: unknown) => Promise<unknown>; get: (o: unknown) => Promise<unknown> }) {
    const fields: Record<string, { value: string }> = Object.fromEntries(['enc', 'cred', 'prf', 'att', 'cdj', 'acdj', 'ad', 'sig'].map((k) => [k, { value: '' }]));
    let submittedWith: unknown = null;
    const handler: { click: (() => void) | null } = { click: null };
    const approve = { id: 'zeusi-approve' };
    const go = { disabled: false, addEventListener: (_: string, f: () => void) => { handler.click = f; } };
    const status = { textContent: '', hidden: true };
    const els: Record<string, unknown> = {
      'zeusi-keys': { getAttribute: (n: string) => attrs[n] ?? null },
      'zeusi-consent': { elements: { namedItem: (n: string) => fields[n] }, requestSubmit: (b: unknown) => { submittedWith = b; } },
      'zeusi-keys-go': go, 'zeusi-approve': approve, 'zeusi-keys-status': status,
    };
    const ctx = {
      document: { getElementById: (id: string) => els[id] ?? null }, navigator: { credentials: creds }, window: { PublicKeyCredential: function PKC() {} },
      atob: globalThis.atob, btoa: globalThis.btoa, Uint8Array, String, JSON,
    };
    runInNewContext(CONSENT_SCRIPT, ctx);
    const click = handler.click;
    assert.ok(click, 'a click handler is installed');
    click();
    for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
    return { fields, submittedWith, approve, status };
  }
  const salt = Buffer.alloc(32, 7);
  const rawId = Buffer.from('raw-cred-id');
  const out = Buffer.alloc(32, 0x33);
  const calls: Array<{ kind: string; o: any }> = [];
  // WebAuthn response bytes (docs/plans/2026-11-19-c4-webauthn-verify.md): the script posts them as they are.
  const ab = (b: Buffer) => b.buffer.slice(b.byteOffset, b.byteOffset + b.length);
  const att = Buffer.from('test-attestation-object');
  const cdj = Buffer.from('{"type":"webauthn.create"}');
  const acdj = Buffer.from('{"type":"webauthn.get"}');
  const adata = Buffer.alloc(37, 5);
  const sig = Buffer.from('test-signature');
  const assertion = { clientDataJSON: ab(acdj), authenticatorData: ab(adata), signature: ab(sig) };
  const enroll = await run(
    { 'data-mode': 'enroll', 'data-rp': 'mcp.zeusi.dev', 'data-user': b64u(Buffer.alloc(16, 1)), 'data-name': 'u', 'data-challenge': b64u(Buffer.alloc(32, 2)), 'data-challenge2': b64u(Buffer.alloc(32, 4)), 'data-salt': b64u(salt) },
    {
      create: async (o) => { calls.push({ kind: 'create', o }); return { rawId: ab(rawId), response: { attestationObject: ab(att), clientDataJSON: ab(cdj) }, getClientExtensionResults: () => ({ prf: { enabled: true } }) }; },
      get: async (o) => { calls.push({ kind: 'get', o }); return { rawId: ab(rawId), response: assertion, getClientExtensionResults: () => ({ prf: { results: { first: out.buffer.slice(out.byteOffset, out.byteOffset + 32) } } }) }; },
    },
  );
  assert.deepEqual(calls.map((x) => x.kind), ['create', 'get']);
  assert.equal(calls[0]!.o.publicKey.rp.id, 'mcp.zeusi.dev');
  assert.equal(calls[0]!.o.publicKey.attestation, 'none');
  assert.deepEqual(Array.from(calls[0]!.o.publicKey.pubKeyCredParams, (x: { alg: number }) => x.alg), [-8, -7, -257]);
  assert.deepEqual(Buffer.from(calls[0]!.o.publicKey.challenge), Buffer.alloc(32, 2), 'create() uses data-challenge');
  assert.deepEqual(Buffer.from(calls[1]!.o.publicKey.challenge), Buffer.alloc(32, 4), 'the get() fallback uses data-challenge2');
  assert.deepEqual([enroll.fields.att!.value, enroll.fields.cdj!.value, enroll.fields.acdj!.value, enroll.fields.ad!.value, enroll.fields.sig!.value],
    [b64u(att), b64u(cdj), b64u(acdj), b64u(adata), b64u(sig)], 'attestation + the fallback assertion are posted');
  assert.deepEqual(Buffer.from(calls[0]!.o.publicKey.extensions.prf.eval.first), salt);
  assert.deepEqual(Buffer.from(calls[1]!.o.publicKey.extensions.prf.eval.first), salt, 'get() reuses the enrollment salt');
  assert.deepEqual(Buffer.from(calls[1]!.o.publicKey.allowCredentials[0].id), rawId);
  assert.deepEqual([enroll.fields.enc!.value, enroll.fields.cred!.value, enroll.fields.prf!.value], ['enroll', b64u(rawId), b64u(out)]);
  assert.equal(enroll.submittedWith, enroll.approve);

  calls.length = 0;
  const unlock = await run(
    { 'data-mode': 'unlock', 'data-rp': 'mcp.zeusi.dev', 'data-challenge': b64u(Buffer.alloc(32, 2)), 'data-creds': `${b64u(rawId)}.${b64u(salt)}` },
    { get: async (o) => { calls.push({ kind: 'get', o }); return { rawId: rawId.buffer.slice(rawId.byteOffset, rawId.byteOffset + rawId.length), response: assertion, getClientExtensionResults: () => ({ prf: { results: { first: out } } }) }; } },
  );
  assert.deepEqual([unlock.fields.att!.value, unlock.fields.cdj!.value, unlock.fields.acdj!.value, unlock.fields.ad!.value, unlock.fields.sig!.value], ['', '', b64u(acdj), b64u(adata), b64u(sig)]);
  assert.deepEqual(Buffer.from(calls[0]!.o.publicKey.extensions.prf.evalByCredential[b64u(rawId)].first), salt);
  assert.equal(unlock.fields.enc!.value, 'unlock');
  assert.equal(unlock.submittedWith, unlock.approve);

  // No PRF at all (an authenticator without the extension): nothing submitted, the user is told.
  const none = await run(
    { 'data-mode': 'enroll', 'data-rp': 'mcp.zeusi.dev', 'data-user': 'AQ', 'data-name': 'u', 'data-challenge': 'Ag', 'data-salt': b64u(salt) },
    {
      create: async () => ({ rawId: new ArrayBuffer(3), response: { attestationObject: new ArrayBuffer(1), clientDataJSON: new ArrayBuffer(1) }, getClientExtensionResults: () => ({}) }),
      get: async () => ({ rawId: new ArrayBuffer(3), response: assertion, getClientExtensionResults: () => ({}) }),
    },
  );
  assert.equal(none.submittedWith, null);
  assert.equal(none.fields.prf!.value, '');
  assert.equal(none.status.hidden, false);
  assert.match(none.status.textContent, /cannot do this here/, 'the no-PRF message, not the error path');
});

test('recovery page (flag on since v32): the warning follows the workspace state; no "switched on" promise, no encryption wording', () => {
  const page = (born: boolean) => recoveryCodePage({ code: 'CODE', txn: 'txn', csrf: 'csrf', born });
  assert.ok(page(true).includes(esc(RECOVERY_WARNING_BORN)) && !page(true).includes(esc(RECOVERY_WARNING_KEY)));
  assert.ok(page(false).includes(esc(RECOVERY_WARNING_KEY)) && !page(false).includes(esc(RECOVERY_WARNING_BORN)));
  for (const b of [true, false]) {
    assert.doesNotMatch(page(b), /switched on|Once the protection/, 'the stale pre-flag sentence is gone');
    assert.deepEqual(overclaims(page(b)), [], `born=${b}: no over-claim`);
  }
  // Each warning still says Zeusi cannot recover it (true: the only wraps are passkey and recovery, src/tenants.ts KEY_WRAP_KINDS).
  for (const w of [RECOVERY_WARNING_BORN, RECOVERY_WARNING_KEY]) assert.match(w, /Zeusi cannot get (it|the key) back for you\.$/);
  // Exact served text (review r1 P3-2: plain wording for the not-born case; it names the key, not the content).
  assert.equal(RECOVERY_WARNING_BORN, 'You need this code or one of your passkeys to unlock this workspace when you sign in. If you lose all of them, Zeusi cannot get it back for you.');
  assert.equal(RECOVERY_WARNING_KEY, 'You need this code or one of your passkeys to unlock your workspace key when you sign in. If you lose all of them, Zeusi cannot get the key back for you.');
  assert.doesNotMatch(page(false), /open the key of this workspace/, 'the awkward r0 phrase is gone');
});

test('C5 flag on (KTD11): a born-encrypted workspace (enc_state on, no wrap) gets the enroll offer; enrolling shows the recovery code once and leaves enc_state on', async () => {
  const born = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin'), bornEncrypted: true });
  const h = await hosted({ keys: true, dir: born });
  try {
    const c = await client(h);
    const s1 = await toConsent(h, c, 'gh-born');
    assert.equal(s1.consent.status, 200);
    const tenant = (await born.lookup('github:9105'))!.tenantId;
    assert.equal((await born.encryptionView(tenant))!.encState, 'on', 'provisioned at the GitHub callback, born on');
    assert.equal(attr(s1.consent.body, 'data-mode'), 'enroll', 'mutant: keysOffer only for off -> no passkey block');
    assert.deepEqual(overclaims(s1.consent.body.replace(/<script>[\s\S]*<\/script>/, '')), [], 'no encryption claim on the page');
    const auth = new SoftAuthenticator({ credentialId: Buffer.from('c5-test-credential-born') });
    const prf = auth.prf(Buffer.from(attr(s1.consent.body, 'data-salt')!, 'base64url'));
    const e = await post(h, s1.cookie, s1.ip, {
      txn: hidden(s1.consent.body, 'txn'), csrf: hidden(s1.consent.body, 'csrf'), decision: 'approve', ...enrollFields(auth, s1.consent.body, ISSUER),
    });
    assert.equal(e.status, 200, e.body);
    const shown = /id="zeusi-recovery-code">([^<]+)</.exec(e.body)![1]!;
    assert.ok(parseRecoveryCode(shown), 'a valid recovery code');
    assert.equal(e.body.split(shown).length, 2, 'shown exactly once');
    // Born encrypted: the workspace itself needs the passkey or this code (mutant: offer.born false -> red).
    assert.ok(e.body.includes(esc(RECOVERY_WARNING_BORN)) && !e.body.includes(esc(RECOVERY_WARNING_KEY)), 'the born warning, not the key one');
    assert.deepEqual(overclaims(e.body), []);
    const v = (await born.encryptionView(tenant))!;
    assert.deepEqual({ state: v.encState, passkeys: v.passkeys.length, recovery: v.recovery }, { state: 'on', passkeys: 1, recovery: 1 });
    prf.fill(0);
  } finally {
    await h.close();
  }
});
