// OAuth for any verified MCP client (src/mcp-oauth.ts EXACT_REDIRECTS + loopback), over HTTP
// on an ephemeral 127.0.0.1 port against OAuthServer.handle: every allowed redirect registers
// (DCR) and reaches GitHub from /authorize; every refused one is a 400 at /register and an
// error page (no redirect to it) at /authorize; the real VS Code / Cursor / Gemini CLI / ChatGPT
// registration bodies and the live ChatGPT / VS Code / Claude / Claude Code CIMD documents
// work; ChatGPT signs in end to end as a public client. GitHub is a fake; CIMD is served from
// test/fixtures/oauth-clients.ts; nothing leaves loopback. Rate limits are raised for THIS
// harness only (OAUTH_LIMITS itself is covered by test/mcp-oauth-hosted.test.ts).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync } from 'node:fs';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CLAUDE_CALLBACK, CHATGPT_CALLBACK, OAUTH_LIMITS, OAUTH_PATHS, OAuthServer, pkceChallenge } from '../src/mcp-oauth.ts';
import { OPERATOR_GITHUB_LOGINS, type GithubApi } from '../src/mcp-oauth-github.ts';
import { OAuthStore } from '../src/mcp-oauth-store.ts';
import { CIMD_DOCS, DCR_BODIES, EXACT_OK, LOOPBACK_OK, REDIRECT_BAD } from './fixtures/oauth-clients.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const ISSUER = 'https://mcp.zeusi.dev';
const RESOURCE = `${ISSUER}/mcp`;
const KEY = 'q'.repeat(48);
const VERIFIER = 'w'.repeat(50) + '-._~';
const HIGH = 100_000;

// An allowlisted identity, taken from the server's own (unchanged) allowlist.
const github: GithubApi = {
  async exchange(code) { return code === 'gh-ok' ? 'ghtok' : null; },
  async identity() { return { id: 7, login: OPERATOR_GITHUB_LOGINS[0]!, verifiedEmails: [] }; },
};

const cimdByUrl = new Map<string, unknown>(Object.values(CIMD_DOCS).map((c) => [c.url, c.doc]));

const d = safeMkdtemp(join(tmpdir(), 'zeusi-oauth-any-'));
chmodSync(d, 0o700);
const server = new OAuthServer({
  issuer: ISSUER, githubClientId: 'Iv1.testclientid', github, signingKey: KEY,
  store: new OAuthStore({ hashKey: KEY, path: join(d, 'mcp-oauth.json') }),
  cimdFetch: async (u) => { if (cimdByUrl.has(u)) return cimdByUrl.get(u); throw new Error('unreachable'); },
  limits: { authorize: HIGH, callback: HIGH, consent: HIGH, token: HIGH, register: HIGH, registerGlobal: HIGH, revoke: HIGH, metadata: HIGH },
});
const srv: Server = createServer((req, res) => {
  const path = new URL(req.url ?? '/', 'http://x').pathname;
  if (!OAUTH_PATHS.includes(path)) return void res.writeHead(404).end();
  void server.handle(path, req, res, '203.0.113.9');
});
const ready = new Promise<number>((res) => srv.listen(0, '127.0.0.1', () => res((srv.address() as AddressInfo).port)));
after(() => new Promise<void>((res) => srv.close(() => res())));

interface Resp { status: number; headers: Record<string, string | string[] | undefined>; body: string }

async function send(o: { method?: string; path: string; headers?: Record<string, string>; body?: string }): Promise<Resp> {
  const port = await ready;
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

const register = (body: unknown) => send({ method: 'POST', path: '/register', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

async function dcr(redirectUris: string[]): Promise<string> {
  const r = await register({ client_name: 'Test', redirect_uris: redirectUris });
  assert.equal(r.status, 201, r.body);
  return (JSON.parse(r.body) as { client_id: string }).client_id;
}

function authorizePath(clientId: string, redirectUri: string): string {
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri, code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: 'S256', state: 'st-1', scope: 'zeusi.read offline_access', resource: RESOURCE,
  });
  return `/authorize?${q.toString()}`;
}

/** /authorize reached GitHub: a 302 to github.com, never to the client. */
function assertToGithub(r: Resp, what: string): URL {
  assert.equal(r.status, 302, `${what}: ${r.body}`);
  const u = new URL(String(r.headers.location));
  assert.equal(u.origin + u.pathname, 'https://github.com/login/oauth/authorize', what);
  return u;
}

/** /authorize refused before any redirect: an HTML error page, no Location at all. */
function assertRefusedPage(r: Resp, what: string): void {
  assert.equal(r.status, 400, what);
  assert.equal(r.headers.location, undefined, `${what}: no redirect`);
  assert.match(String(r.headers['content-type']), /^text\/html/, what);
  assert.match(r.body, /Start again from the app you were connecting\./, what);
}

/** Same port-free loopback, but with another port, to prove the port is ignored. */
function otherPort(uri: string): string {
  return uri.replace(/^(http:\/\/(?:localhost|127\.0\.0\.1))(?::[0-9]+)?\//, '$1:54321/');
}

// ---------------------------------------------------------------------------

test('limits: OAUTH_LIMITS defaults are unchanged by this harness (plus the hourly new-workspace limits of open sign-up)', () => {
  assert.deepEqual(OAUTH_LIMITS, {
    authorize: 30, callback: 20, consent: 20, token: 60, register: 10, registerGlobal: 30, revoke: 30, metadata: 120, signupPerIp: 3, signupGlobal: 20,
  });
});

test('/register + /authorize: every allowed redirect registers and reaches GitHub (loopback on any port)', async () => {
  for (const uri of [...EXACT_OK, ...LOOPBACK_OK]) {
    const clientId = await dcr([uri]);
    assertToGithub(await send({ path: authorizePath(clientId, uri) }), uri);
    if (uri.startsWith('http://')) assertToGithub(await send({ path: authorizePath(clientId, otherPort(uri)) }), `${uri} on another port`);
  }
});

test('/register: every refused redirect is 400 invalid_redirect_uri, alone or next to an allowed one', async () => {
  for (const bad of REDIRECT_BAD) {
    for (const uris of [[bad], [CLAUDE_CALLBACK, bad]]) {
      const r = await register({ client_name: 'Test', redirect_uris: uris });
      assert.equal(r.status, 400, JSON.stringify(uris));
      assert.equal((JSON.parse(r.body) as { error: string }).error, 'invalid_redirect_uri', JSON.stringify(uris));
    }
  }
});

test('/authorize: every refused redirect gets an error page, never a redirect (DCR and CIMD clients)', async () => {
  const clientId = await dcr([...EXACT_OK, 'http://localhost/callback', 'http://127.0.0.1/', 'http://localhost/oauth/callback']);
  for (const bad of REDIRECT_BAD) {
    assertRefusedPage(await send({ path: authorizePath(clientId, bad) }), `dcr ${JSON.stringify(bad)}`);
    assertRefusedPage(await send({ path: authorizePath(CIMD_DOCS.chatgpt.url, bad) }), `cimd ${JSON.stringify(bad)}`);
  }
});

test('/authorize: an allowed redirect the client did not declare, or another loopback host / path, is refused', async () => {
  const clientId = await dcr(['http://localhost/callback']);
  for (const uri of [CLAUDE_CALLBACK, CHATGPT_CALLBACK, 'http://127.0.0.1/callback', 'http://localhost/oauth/callback', 'http://localhost:3000/']) {
    assertRefusedPage(await send({ path: authorizePath(clientId, uri) }), uri);
  }
  assertRefusedPage(await send({ path: authorizePath(CIMD_DOCS.chatgpt.url, CLAUDE_CALLBACK) }), 'chatgpt cimd -> claude callback');
  assertRefusedPage(await send({ path: authorizePath(CIMD_DOCS.claudeCode.url, 'http://localhost:4000/oauth/callback') }), 'claude code cimd path');
});

test('/register: the real VS Code, Cursor, Gemini CLI and ChatGPT registration bodies register as public clients', async () => {
  for (const [name, body] of Object.entries(DCR_BODIES)) {
    const r = await register(body);
    assert.equal(r.status, 201, `${name}: ${r.body}`);
    const j = JSON.parse(r.body) as Record<string, unknown>;
    assert.equal(j.token_endpoint_auth_method, 'none', name);
    assert.deepEqual(j.grant_types, ['authorization_code', 'refresh_token'], `${name}: extra grants ignored`);
    assert.deepEqual(j.redirect_uris, body.redirect_uris, name);
    assert.ok(!('client_secret' in j), `${name}: no client_secret issued`);
    for (const uri of body.redirect_uris) {
      const asked = uri.startsWith('http://') ? otherPort(uri) : uri;
      assertToGithub(await send({ path: authorizePath(String(j.client_id), asked) }), `${name} ${asked}`);
    }
  }
});

test('/register: still refuses client_credentials, implicit, a secret-JWT method, and non-code response types', async () => {
  for (const extra of [
    { grant_types: ['authorization_code', 'client_credentials'] }, { grant_types: ['implicit'] }, { grant_types: ['authorization_code', 'password'] },
    { token_endpoint_auth_method: 'private_key_jwt' }, { response_types: ['token'] },
  ]) {
    const r = await register({ ...DCR_BODIES.cursor, ...extra });
    assert.equal(r.status, 400, JSON.stringify(extra));
  }
});

test('CIMD: the live ChatGPT, VS Code, Claude and Claude Code documents reach GitHub for each declared redirect', async () => {
  for (const [name, { url, doc }] of Object.entries(CIMD_DOCS)) {
    for (const uri of doc.redirect_uris) {
      assertToGithub(await send({ path: authorizePath(url, uri) }), `${name} ${uri}`);
      if (uri.startsWith('http://')) assertToGithub(await send({ path: authorizePath(url, otherPort(uri)) }), `${name} ${uri} other port`);
    }
  }
});

async function consentFor(clientId: string, redirectUri: string): Promise<{ html: string; cookie: string }> {
  const a = await send({ path: authorizePath(clientId, redirectUri) });
  const gh = assertToGithub(a, redirectUri);
  const cookie = String((a.headers['set-cookie'] as string[])[0]).split(';')[0]!;
  const c = await send({ path: `/oauth/github/callback?code=gh-ok&state=${gh.searchParams.get('state')}`, headers: { cookie } });
  assert.equal(c.status, 200, c.body);
  return { html: c.body, cookie };
}

const hidden = (html: string, name: string) => new RegExp(`name="${name}" value="([^"]+)"`).exec(html)![1]!;

test('ChatGPT (CIMD, private_key_jwt preferred): consent shows chatgpt.com, then a public-client token exchange works', async () => {
  const { url } = CIMD_DOCS.chatgpt;
  const { html, cookie } = await consentFor(url, CHATGPT_CALLBACK);
  assert.match(html, /App asking<\/p>\n<code class="big">chatgpt\.com<\/code>/);
  assert.match(html, /Calls itself <strong>ChatGPT<\/strong> \(declared by <code>chatgpt\.com<\/code>\)/);
  assert.match(html, /Access is sent to<\/p>\n<code class="big">chatgpt\.com<\/code>/);
  assert.ok(!/program on this computer/.test(html));
  const ok = await send({
    method: 'POST', path: '/oauth/consent', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ txn: hidden(html, 'txn'), csrf: hidden(html, 'csrf'), decision: 'approve' }).toString(),
  });
  assert.equal(ok.status, 302);
  const back = new URL(String(ok.headers.location));
  assert.equal(back.origin + back.pathname, CHATGPT_CALLBACK);
  assert.equal(back.searchParams.get('iss'), ISSUER, 'RFC 9207 iss on the stable ChatGPT redirect');
  assert.equal(back.searchParams.get('state'), 'st-1');
  const t = await send({
    method: 'POST', path: '/token', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: back.searchParams.get('code')!, redirect_uri: CHATGPT_CALLBACK, client_id: url, code_verifier: VERIFIER, resource: RESOURCE }).toString(),
  });
  assert.equal(t.status, 200, 'public client (none): no client authentication needed');
  const j = JSON.parse(t.body) as Record<string, unknown>;
  assert.equal(j.token_type, 'Bearer');
  assert.equal(j.scope, 'zeusi.read');
});

test('consent: a DCR client shows its self-declared name; a loopback app gets the neutral local-program warning', async () => {
  const r = await register(DCR_BODIES.gemini);
  const clientId = (JSON.parse(r.body) as { client_id: string }).client_id;
  const { html } = await consentFor(clientId, 'http://localhost:61234/oauth/callback');
  assert.match(html, /<p class="note">Name it gave itself: &quot;Gemini CLI MCP Client&quot; \(not verified\)/);
  assert.ok(!/class="big">Gemini/.test(html));
  assert.match(html, /Access is sent to<\/p>\n<code class="big">localhost:61234<\/code>/);
  assert.match(html, /program on this computer/);
  assert.ok(!/Claude/.test(html), 'no client named in the generic wording');
});

test('consent: a DCR client that calls itself "chatgpt.com" shows only the redirect host prominently', async () => {
  const r = await register({ ...DCR_BODIES.cursor, client_name: 'chatgpt.com' });
  assert.equal(r.status, 201, r.body);
  const clientId = (JSON.parse(r.body) as { client_id: string }).client_id;
  const { html } = await consentFor(clientId, 'https://www.cursor.com/agents/mcp/oauth/callback');
  const strong = [...html.matchAll(/<(?:code|strong)[^>]*>([^<]*)<\/(?:code|strong)>/g)].filter((m) => /class="big"|<strong>/.test(m[0])).map((m) => m[1]);
  assert.deepEqual(strong, ['www.cursor.com']);
  assert.equal([...html.matchAll(/chatgpt\.com/g)].length, 1);
  assert.match(html, /<p class="note">Name it gave itself: &quot;chatgpt\.com&quot; \(not verified\)/);
});

test('consent: https://vscode.dev/redirect and insiders get the hand-off-to-this-computer warning (CIMD and DCR)', async () => {
  const cimd = await consentFor(CIMD_DOCS.vscode.url, 'https://vscode.dev/redirect');
  assert.match(cimd.html, /This sign-in is handed to an app on this computer through <code>vscode\.dev<\/code>/);
  const r = await register(DCR_BODIES.vscode);
  const clientId = (JSON.parse(r.body) as { client_id: string }).client_id;
  const dcr = await consentFor(clientId, 'https://insiders.vscode.dev/redirect');
  assert.match(dcr.html, /This sign-in is handed to an app on this computer through <code>insiders\.vscode\.dev<\/code>/);
  const web = await consentFor(CIMD_DOCS.chatgpt.url, CHATGPT_CALLBACK);
  assert.ok(!/class="warn"/.test(web.html));
});
