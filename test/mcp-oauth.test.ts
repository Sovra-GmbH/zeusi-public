// OAuth building blocks (src/mcp-oauth.ts, src/mcp-oauth-store.ts, src/mcp-oauth-github.ts):
// redirect allowlist, PKCE, scopes, CIMD validation, SSRF address filter, GitHub allowlist,
// the hashed store (rotation, reuse, revoke, file modes, reload) and the env gate. No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CLAUDE_CALLBACK, EXACT_REDIRECTS, cimdUrlOk, isPublicAddress, oauthFromEnv, parseScope, pkceChallenge, pkceVerify, redirectAllowed, redirectMatches,
  validateCimd, GITHUB_CLIENT_ID_ENV, GITHUB_CLIENT_SECRET_ENV, SIGNING_KEY_ENV,
} from '../src/mcp-oauth.ts';
import { isOperatorMember, liveGithubApi } from '../src/mcp-oauth-github.ts';
import { ACCESS_TTL_MS, OAuthStore, OAuthStoreError, REFRESH_TTL_MS, tenantOf } from '../src/mcp-oauth-store.ts';
import { consentPage, errorPage, esc } from '../src/mcp-oauth-views.ts';
import { CIMD_DOCS, EXACT_OK, LOOPBACK_OK, REDIRECT_BAD } from './fixtures/oauth-clients.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const KEY = 'k'.repeat(40);
const HOTMAIL = 'near-miss@example.invalid';

function dir(): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-oauth-'));
  chmodSync(d, 0o700);
  return d;
}

// ---------------------------------------------------------------------------
// Redirects

test('redirect allowlist: every verified exact https URI and loopback host x path x port is accepted', () => {
  assert.deepEqual(EXACT_REDIRECTS.map((e) => e.uri).sort(), [...EXACT_OK].sort(), 'the table and the fixture list the same URIs');
  for (const e of EXACT_REDIRECTS) assert.match(e.doc, /^https:\/\//, `${e.uri} cites a doc URL`);
  assert.equal(LOOPBACK_OK.length, 2 * 3 * 5);
  for (const ok of [...EXACT_OK, ...LOOPBACK_OK]) assert.equal(redirectAllowed(ok), true, ok);
});

test('redirect allowlist: look-alikes, variants, custom schemes, empty and oversized are refused', () => {
  for (const bad of REDIRECT_BAD) assert.equal(redirectAllowed(bad), false, JSON.stringify(bad));
  assert.equal(redirectAllowed(undefined as unknown as string), false);
});

test('redirect match: exact for https, port-agnostic for loopback, host and path must match', () => {
  assert.equal(redirectMatches(CLAUDE_CALLBACK, [CLAUDE_CALLBACK]), true);
  assert.equal(redirectMatches('https://vscode.dev/redirect', ['https://insiders.vscode.dev/redirect']), false);
  assert.equal(redirectMatches('http://localhost:4000/callback', ['http://localhost/callback']), true);
  assert.equal(redirectMatches('http://127.0.0.1:4000/callback', ['http://127.0.0.1:9/callback']), true);
  assert.equal(redirectMatches('http://127.0.0.1:50123/', ['http://127.0.0.1:33418/']), true, 'VS Code random port fallback');
  assert.equal(redirectMatches('http://localhost:50123/oauth/callback', ['http://localhost:7777/oauth/callback']), true, 'Gemini CLI port');
  assert.equal(redirectMatches('http://127.0.0.1:4000/callback', ['http://localhost/callback']), false, 'host must match');
  assert.equal(redirectMatches('http://localhost:4000/callback', ['http://127.0.0.1/callback']), false, 'host must match');
  assert.equal(redirectMatches('http://localhost:4000/oauth/callback', ['http://localhost/callback']), false, 'path must match');
  assert.equal(redirectMatches('http://127.0.0.1:4000/', ['http://127.0.0.1/callback']), false, 'path must match');
  assert.equal(redirectMatches(CLAUDE_CALLBACK, ['http://localhost/callback']), false);
  assert.equal(redirectMatches('https://evil.example/callback', ['https://evil.example/callback']), false, 'never outside the allowlist');
  assert.equal(redirectMatches('http://localhost:4000/callback', ['http://localhost.evil.com/callback']), false);
});

// ---------------------------------------------------------------------------
// PKCE, scope

test('PKCE: S256 verifier matches; wrong, short, or plain-equal verifier fails', () => {
  const v = 'a'.repeat(43) + '-._~';
  const c = pkceChallenge(v);
  assert.equal(pkceVerify(v, c), true);
  assert.equal(pkceVerify('b'.repeat(47), c), false);
  assert.equal(pkceVerify('short', pkceChallenge('short')), false);
  assert.equal(pkceVerify(undefined, c), false);
  const plain = 'p'.repeat(43);
  assert.equal(pkceVerify(plain, plain), false, 'plain (challenge == verifier) is not S256');
});

test('scope: zeusi.read and offline_access only; empty means zeusi.read', () => {
  assert.deepEqual(parseScope(null), ['zeusi.read']);
  assert.deepEqual(parseScope('zeusi.read offline_access'), ['zeusi.read', 'offline_access']);
  assert.equal(parseScope('zeusi.write'), null);
  assert.equal(parseScope('zeusi.read admin'), null);
});

// ---------------------------------------------------------------------------
// CIMD

test('CIMD URL: https DNS host with a path only', () => {
  assert.equal(cimdUrlOk('https://claude.ai/oauth/claude-code-client-metadata'), true);
  for (const bad of [
    'http://claude.ai/x', 'https://claude.ai/', 'https://claude.ai', 'https://127.0.0.1/x', 'https://[::1]/x', 'https://localhost/x',
    'https://claude.ai:8443/x', 'https://u:p@claude.ai/x', 'https://claude.ai/x?y=1', 'https://claude.ai/x#f', `https://claude.ai/${'a'.repeat(600)}`,
  ]) assert.equal(cimdUrlOk(bad), false, bad);
});

test('CIMD document: client_id must equal the URL, redirects must pass the allowlist, public client only', () => {
  const id = 'https://claude.ai/oauth/claude-code-client-metadata';
  const good = { client_id: id, client_name: 'Claude Code', redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'], token_endpoint_auth_method: 'none' };
  assert.deepEqual(validateCimd(id, good)?.redirectUris, good.redirect_uris);
  assert.equal(validateCimd(id, { ...good, client_id: 'https://evil.example/x' }), null);
  assert.equal(validateCimd(id, { ...good, redirect_uris: ['https://evil.example/cb'] }), null);
  assert.equal(validateCimd(id, { ...good, redirect_uris: [CLAUDE_CALLBACK, 'http://evil/callback'] }), null);
  assert.notEqual(validateCimd(id, { ...good, token_endpoint_auth_method: 'private_key_jwt' }), null, 'a preferred method is not a refusal; Zeusi treats it as public');
  assert.equal(validateCimd(id, { ...good, token_endpoint_auth_method: 'client_secret_basic' }), null, 'a CIMD client cannot hold a secret');
  assert.equal(validateCimd(id, { ...good, token_endpoint_auth_method: 7 }), null);
  for (const m of ['client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'tls_client_auth', 'self_signed_tls_client_auth', 'foo', '', 'None', 7, null, ['none']]) {
    assert.equal(validateCimd(id, { ...good, token_endpoint_auth_method: m }), null, `singular ${JSON.stringify(m)} refused`);
    assert.equal(validateCimd(id, { ...good, token_endpoint_auth_methods_supported: ['none', m] }), null, `plural with ${JSON.stringify(m)} refused`);
  }
  assert.equal(validateCimd(id, { ...good, token_endpoint_auth_methods_supported: 'none' }), null, 'plural must be a list');
  assert.notEqual(validateCimd(id, { ...good, token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'] }), null, 'the ChatGPT shape validates');
  assert.notEqual(validateCimd(id, { ...good, token_endpoint_auth_method: undefined }), null, 'the method may be omitted');
  assert.equal(validateCimd(id, { ...good, redirect_uris: [] }), null);
  assert.equal(validateCimd(id, 'not an object'), null);
});

test('CIMD document: the live ChatGPT, VS Code, Claude and Claude Code documents validate as published', () => {
  for (const [name, { url, doc }] of Object.entries(CIMD_DOCS)) {
    assert.equal(cimdUrlOk(url), true, name);
    const c = validateCimd(url, doc);
    assert.ok(c, name);
    assert.deepEqual(c.redirectUris, doc.redirect_uris, name);
    assert.equal(c.clientName, doc.client_name, name);
  }
});

test('AS metadata: advertises only the token auth method Zeusi accepts (none), never private_key_jwt', () => {
  const on = oauthFromEnv({ [GITHUB_CLIENT_ID_ENV]: 'Iv1.x', [GITHUB_CLIENT_SECRET_ENV]: 'y', [SIGNING_KEY_ENV]: KEY }, { issuer: 'https://mcp.zeusi.dev', dataDir: dir() });
  assert.equal(on.state, 'enabled');
  if (on.state !== 'enabled') return;
  const m = on.server.authorizationServerMetadata();
  assert.deepEqual(m['token_endpoint_auth_methods_supported'], ['none']);
  assert.deepEqual(m['grant_types_supported'], ['authorization_code', 'refresh_token']);
  assert.equal(m['authorization_response_iss_parameter_supported'], true, 'ChatGPT stable redirect relies on RFC 9207 iss');
});

test('AS and protected-resource metadata: website, logo, no terms/privacy pages (they do not exist)', () => {
  const on = oauthFromEnv({ [GITHUB_CLIENT_ID_ENV]: 'Iv1.x', [GITHUB_CLIENT_SECRET_ENV]: 'y', [SIGNING_KEY_ENV]: KEY }, { issuer: 'https://mcp.zeusi.dev', dataDir: dir() });
  assert.equal(on.state, 'enabled');
  if (on.state !== 'enabled') return;
  const as = on.server.authorizationServerMetadata();
  assert.equal(as['service_documentation'], 'https://zeusi.ai');
  assert.equal(as['logo_uri'], 'https://mcp.zeusi.dev/favicon.png');
  for (const k of ['policy_uri', 'tos_uri', 'op_policy_uri', 'op_tos_uri']) {
    assert.equal(as[k], undefined, k);
  }
  const pr = on.server.protectedResourceMetadata();
  assert.equal(pr['resource_name'], 'Zeusi');
  assert.equal(pr['resource_documentation'], 'https://zeusi.ai');
  for (const k of ['resource_policy_uri', 'resource_tos_uri', 'policy_uri', 'tos_uri']) {
    assert.equal(pr[k], undefined, k);
  }
});

test('SSRF filter: CIMD fetches go to public unicast addresses only', () => {
  for (const ok of ['160.79.104.10', '140.82.112.3', '2a00:1450:4001:80b::200e']) assert.equal(isPublicAddress(ok), true, ok);
  for (const bad of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fdaa:0:1::3', 'fe80::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', '224.0.0.1', 'not-an-ip']) {
    assert.equal(isPublicAddress(bad), false, bad);
  }
});

// ---------------------------------------------------------------------------
// GitHub allowlist

test('operator members: OperatorOwner (any case) or a verified operator email; a near-miss and strangers are not members (they get a personal workspace)', () => {
  assert.equal(isOperatorMember({ id: 1, login: 'OperatorOwner', verifiedEmails: [] }), true);
  assert.equal(isOperatorMember({ id: 1, login: 'OPERATOROWNER', verifiedEmails: [] }), true);
  assert.equal(isOperatorMember({ id: 2, login: 'someone', verifiedEmails: ['operator@example.com'] }), true);
  assert.equal(isOperatorMember({ id: 3, login: 'someone', verifiedEmails: ['owner@example.com'] }), true);
  assert.equal(isOperatorMember({ id: 4, login: 'someone', verifiedEmails: [HOTMAIL] }), false);
  assert.equal(isOperatorMember({ id: 5, login: 'OperatorOwner-evil', verifiedEmails: ['x@example.com'] }), false);
  assert.equal(isOperatorMember({ id: 6, login: 'stranger', verifiedEmails: [] }), false);
});

test('GitHub live client: only VERIFIED emails count; the GitHub secret goes only to the token URL', async () => {
  const seen: Array<{ url: string; body: string; auth: string }> = [];
  const fake = async (url: string, init: RequestInit) => {
    seen.push({ url, body: String(init.body ?? ''), auth: String((init.headers as Record<string, string>)?.authorization ?? '') });
    const json = (o: unknown) => new Response(JSON.stringify(o), { status: 200, headers: { 'content-type': 'application/json' } });
    if (url.endsWith('/access_token')) return json({ access_token: 'gho_fake' });
    if (url.endsWith('/user')) return json({ id: 42, login: 'stranger' });
    return json([{ email: 'owner@example.com', verified: false }, { email: 'x@example.com', verified: true }]);
  };
  const gh = liveGithubApi('Iv1.fakeid', 'fake-gh-secret-value', fake);
  const tok = await gh.exchange('code1', 'https://mcp.zeusi.dev/oauth/github/callback');
  assert.equal(tok, 'gho_fake');
  const who = await gh.identity(tok!);
  assert.deepEqual(who, { id: 42, login: 'stranger', verifiedEmails: ['x@example.com'] });
  assert.equal(isOperatorMember(who!), false, 'an unverified allowlisted email does not count');
  assert.ok(seen[0]!.body.includes('client_secret='));
  assert.ok(seen.slice(1).every((s) => !s.body.includes('fake-gh-secret-value') && !s.url.includes('fake-gh-secret-value')));
});

// ---------------------------------------------------------------------------
// Store

test('store: tokens are hashed at rest, file 0600, access works, refresh rotates, reuse revokes the grant', () => {
  const d = dir();
  const path = join(d, 'mcp-oauth.json');
  let now = Date.parse('2026-11-17T10:00:00Z');
  const s = new OAuthStore({ hashKey: KEY, path, now: () => now });
  const c = s.registerClient({ clientName: 'Claude', redirectUris: [CLAUDE_CALLBACK] });
  const t1 = s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  const text = readFileSync(path, 'utf8');
  assert.ok(!text.includes(t1.accessToken) && !text.includes(t1.refreshToken), 'no plaintext token on disk');
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(s.grantForAccess(t1.accessToken)?.grant_id, t1.grant.grant_id);
  assert.equal(t1.expiresIn, ACCESS_TTL_MS / 1000);

  assert.equal(s.rotate(t1.refreshToken, 'zc_wrongclientwrongclien'), 'invalid', 'client must match');
  const t2 = s.rotate(t1.refreshToken, c.client_id);
  assert.notEqual(t2, 'invalid');
  if (t2 === 'invalid') return;
  assert.ok(t2.refreshToken !== t1.refreshToken, 'the refresh token rotates');
  assert.equal(s.grantForAccess(t1.accessToken), null, 'old access replaced');
  assert.ok(s.grantForAccess(t2.accessToken));
  // Reuse of the rotated-away refresh token: invalid AND the grant is revoked.
  assert.equal(s.rotate(t1.refreshToken, c.client_id), 'invalid');
  assert.equal(s.grantForAccess(t2.accessToken), null);
  assert.equal(s.rotate(t2.refreshToken, c.client_id), 'invalid');

  const t3 = s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  now += ACCESS_TTL_MS + 1;
  assert.equal(s.grantForAccess(t3.accessToken), null, 'access expires after 1 h');
  assert.notEqual(s.rotate(t3.refreshToken, c.client_id), 'invalid', 'refresh still good');
  now += REFRESH_TTL_MS + 1;
  const t4 = s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  assert.ok(s.grantForAccess(t4.accessToken));
});

test('store (open sign-up KTD7): a grant carries its workspace through rotation; a legacy grant without the field reads as team', () => {
  const d = dir();
  const path = join(d, 'mcp-oauth.json');
  const s = new OAuthStore({ hashKey: KEY, path });
  const c = s.registerClient({ clientName: 'Claude', redirectUris: [CLAUDE_CALLBACK] });
  const ws = `zt_${'m'.repeat(26)}`;
  const t = s.createGrant({ clientId: c.client_id, subject: 'github:105', login: 'stranger', tenant: ws });
  assert.equal(tenantOf(s.grantForAccess(t.accessToken)!), ws);
  const r = s.rotate(t.refreshToken, c.client_id);
  assert.notEqual(r, 'invalid');
  if (r === 'invalid') return;
  assert.equal(tenantOf(s.grantForAccess(r.accessToken)!), ws, 'rotation keeps the workspace');
  assert.equal(s.list().grants[0]!.tenant, ws);
  // A file written before open sign-up: same rows, no tenant field. Loads, and reads as the team.
  const legacy = s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  const doc = JSON.parse(readFileSync(path, 'utf8')) as { grants: Array<Record<string, unknown>> };
  for (const g of doc.grants) if (g['grant_id'] === legacy.grant.grant_id) delete g['tenant'];
  writeFileSync(path, JSON.stringify(doc));
  chmodSync(path, 0o600);
  const reloaded = new OAuthStore({ hashKey: KEY, path });
  const lg = reloaded.grantForAccess(legacy.accessToken)!;
  assert.equal(lg.tenant, undefined);
  assert.equal(tenantOf(lg), 'work');
  assert.equal(tenantOf(reloaded.grantForAccess(r.accessToken)!), ws, 'the personal grant still reads its own workspace');
});

test('store (open sign-up KTD7): a grant cannot be created without a valid workspace; a file naming another schema fails closed', () => {
  const d = dir();
  const path = join(d, 'mcp-oauth.json');
  const s = new OAuthStore({ hashKey: KEY, path });
  const c = s.registerClient({ clientName: null, redirectUris: [CLAUDE_CALLBACK] });
  for (const bad of ['', 'zeusi', 'public', 'zeusi_tenants', 'zt_short', `zt_${'A'.repeat(26)}`, `team; DROP`]) {
    assert.throws(() => s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'x', tenant: bad }), OAuthStoreError, bad);
  }
  s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  for (const bad of ['zeusi', 'public', 'zt_', 42]) {
    const doc = JSON.parse(readFileSync(path, 'utf8')) as { grants: Array<Record<string, unknown>> };
    doc.grants[0]!['tenant'] = bad;
    writeFileSync(path, JSON.stringify(doc));
    chmodSync(path, 0o600);
    assert.throws(() => new OAuthStore({ hashKey: KEY, path }), OAuthStoreError, String(bad));
  }
});

test('store: an offline revoke (another process) takes effect on the running store; revokeClient kills its grants', () => {
  const d = dir();
  const path = join(d, 'mcp-oauth.json');
  const server = new OAuthStore({ hashKey: KEY, path });
  const c = server.registerClient({ clientName: null, redirectUris: [CLAUDE_CALLBACK] });
  const t = server.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  const admin = new OAuthStore({ hashKey: KEY, path });
  assert.equal(admin.revokeGrant(t.grant.grant_id), true);
  assert.equal(server.grantForAccess(t.accessToken), null);
  const t2 = server.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  assert.equal(admin.revokeClient(c.client_id), true);
  assert.equal(server.grantForAccess(t2.accessToken), null);
  assert.equal(server.client(c.client_id), null);
});

test('store: a wrong signing key cannot use stored hashes; loose modes and invalid files fail closed and are not overwritten', () => {
  const d = dir();
  const path = join(d, 'mcp-oauth.json');
  const s = new OAuthStore({ hashKey: KEY, path });
  const c = s.registerClient({ clientName: null, redirectUris: [CLAUDE_CALLBACK] });
  const t = s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  assert.equal(new OAuthStore({ hashKey: 'z'.repeat(40), path }).grantForAccess(t.accessToken), null);
  chmodSync(path, 0o644);
  assert.throws(() => new OAuthStore({ hashKey: KEY, path }), OAuthStoreError);
  chmodSync(path, 0o600);
  writeFileSync(path, '{"version":2}');
  assert.throws(() => new OAuthStore({ hashKey: KEY, path }), OAuthStoreError);
  assert.equal(readFileSync(path, 'utf8'), '{"version":2}');
  const loose = safeMkdtemp(join(tmpdir(), 'zeusi-oauth-loose-'));
  chmodSync(loose, 0o755);
  assert.throws(() => new OAuthStore({ hashKey: KEY, path: join(loose, 'mcp-oauth.json') }), OAuthStoreError);
  assert.throws(() => new OAuthStore({ hashKey: 'short', path }), OAuthStoreError);
});

test('store: a write that cannot take the lock fails closed and leaves nothing half-applied in memory', () => {
  const d = dir();
  const path = join(d, 'mcp-oauth.json');
  const s = new OAuthStore({ hashKey: KEY, path });
  const c = s.registerClient({ clientName: null, redirectUris: [CLAUDE_CALLBACK] });
  const t = s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  writeFileSync(`${path}.lock`, '', { mode: 0o600 });
  assert.throws(() => s.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' }), OAuthStoreError);
  assert.throws(() => s.rotate(t.refreshToken, c.client_id), OAuthStoreError);
  rmSync(`${path}.lock`);
  assert.equal(s.list().grants.length, 1, 'the failed grant was dropped (re-read from the file)');
  const r = s.rotate(t.refreshToken, c.client_id);
  assert.notEqual(r, 'invalid', 'the failed rotation did not retire the refresh token');
});

test('store: DCR clients are capped (oldest without a live grant goes first), memory stays bounded', () => {
  const s = new OAuthStore({ hashKey: KEY });
  const first = s.registerClient({ clientName: 'keep', redirectUris: [CLAUDE_CALLBACK] });
  s.createGrant({ clientId: first.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  for (let i = 0; i < 510; i++) s.registerClient({ clientName: null, redirectUris: [CLAUDE_CALLBACK] });
  assert.equal(s.list().clients.length, 500);
  assert.ok(s.client(first.client_id), 'a client with a live grant survives');
});

// ---------------------------------------------------------------------------
// Env gate, views

test('oauthFromEnv: off (with env var NAMES only) unless all three secrets are set; never echoes a value', () => {
  const d = dir();
  const off = oauthFromEnv({ [GITHUB_CLIENT_ID_ENV]: 'Iv1.abc' }, { issuer: 'https://mcp.zeusi.dev', dataDir: d });
  assert.equal(off.state, 'disabled');
  if (off.state === 'disabled') {
    assert.match(off.reason, /ZEUSI_GITHUB_CLIENT_SECRET/);
    assert.ok(!off.reason.includes('Iv1.abc'));
  }
  const short = oauthFromEnv({ [GITHUB_CLIENT_ID_ENV]: 'Iv1.abc', [GITHUB_CLIENT_SECRET_ENV]: 'sec-value', [SIGNING_KEY_ENV]: 'tooshort' }, { issuer: 'https://mcp.zeusi.dev', dataDir: d });
  assert.equal(short.state, 'disabled');
  if (short.state === 'disabled') assert.ok(!short.reason.includes('tooshort') && !short.reason.includes('sec-value'));
  const on = oauthFromEnv({ [GITHUB_CLIENT_ID_ENV]: 'Iv1.abc', [GITHUB_CLIENT_SECRET_ENV]: 'sec-value', [SIGNING_KEY_ENV]: KEY }, { issuer: 'https://mcp.zeusi.dev', dataDir: d });
  assert.equal(on.state, 'enabled');
  if (on.state === 'enabled') {
    assert.equal(on.server.resource, 'https://mcp.zeusi.dev/mcp');
    assert.equal(on.server.authorizationServerMetadata()['issuer'], 'https://mcp.zeusi.dev');
  }
});

test('views: the consent page escapes every value, names the redirect host, warns for loopback, loads nothing external', () => {
  for (const clientLabel of [{ kind: 'dcr', name: '<script>x</script>' }, { kind: 'cimd', host: 'chatgpt.com', name: '<script>x</script>' }] as const) {
    const html = consentPage({ clientLabel, redirectHost: 'localhost:3118', local: true, login: 'a<b', txn: 't"x', csrf: 'c' });
    assert.ok(!html.includes('<script>x'));
    assert.ok(html.includes(esc('<script>x</script>')));
    assert.ok(html.includes('<code class="big">localhost:3118</code>'), 'redirect host in large code text');
    assert.match(html, /program on this computer/);
    assert.ok(!/Claude/.test(html), 'client-neutral wording');
    assert.ok(!/<script|src=|href="http/i.test(html));
  }
});

test('views: consent says who asks (CIMD host + declared name; DCR self-declared name) and where access goes', () => {
  const cimd = consentPage({ clientLabel: { kind: 'cimd', host: 'chatgpt.com', name: 'ChatGPT' }, redirectHost: 'chatgpt.com', local: false, login: 'u', txn: 't', csrf: 'c' });
  assert.match(cimd, /App asking<\/p>\n<code class="big">chatgpt\.com<\/code>/);
  assert.match(cimd, /Calls itself <strong>ChatGPT<\/strong> \(declared by <code>chatgpt\.com<\/code>\)/);
  assert.match(cimd, /Access is sent to<\/p>\n<code class="big">chatgpt\.com<\/code>/);
  assert.ok(!/program on this computer/.test(cimd));
  const dcr = consentPage({ clientLabel: { kind: 'dcr', name: 'Cursor' }, redirectHost: 'www.cursor.com', local: false, login: 'u', txn: 't', csrf: 'c' });
  assert.match(dcr, /<p class="note">Name it gave itself: &quot;Cursor&quot; \(not verified\)/);
  assert.match(dcr, /Access is sent to<\/p>\n<code class="big">www\.cursor\.com<\/code>/);
  const anon = consentPage({ clientLabel: { kind: 'dcr', name: null }, redirectHost: '127.0.0.1:33418', local: true, login: 'u', txn: 't', csrf: 'c' });
  assert.match(anon, /registered itself without a name \(not verified\)/);
  assert.equal(prominent(anon), '127.0.0.1:33418');
  assert.match(errorPage('x'), /Start again from the app you were connecting\./);
  assert.ok(!/Claude/.test(errorPage('x')));
});

/** Text of every prominent element (.big or <strong>), joined by '|'. */
function prominent(html: string): string {
  return [...html.matchAll(/<(code|strong)\b[^>]*class="big"[^>]*>([^<]*)<\/\1>|<strong>([^<]*)<\/strong>/g)].map((m) => m[2] ?? m[3]).join('|');
}

test('views: a DCR client named "chatgpt.com" cannot look verified; only the redirect host is prominent', () => {
  const html = consentPage({ clientLabel: { kind: 'dcr', name: 'chatgpt.com' }, redirectHost: 'www.cursor.com', local: false, login: 'u', txn: 't', csrf: 'c' });
  assert.equal(prominent(html), 'www.cursor.com', 'the big/strong elements hold only the verified redirect host');
  const mentions = [...html.matchAll(/chatgpt\.com/g)];
  assert.equal(mentions.length, 1, 'the self-chosen name appears exactly once');
  assert.match(html, /<p class="note">Name it gave itself: &quot;chatgpt\.com&quot; \(not verified\)/);
  // A CIMD client_id host IS verified (Zeusi fetched the document from it): it stays prominent.
  const cimd = consentPage({ clientLabel: { kind: 'cimd', host: 'vscode.dev', name: null }, redirectHost: '127.0.0.1:33418', local: true, login: 'u', txn: 't', csrf: 'c' });
  assert.equal(prominent(cimd), '127.0.0.1:33418|vscode.dev');
});

test('views: vscode.dev / insiders.vscode.dev redirects get the hand-off-to-this-computer warning', () => {
  for (const host of ['vscode.dev', 'insiders.vscode.dev']) {
    const html = consentPage({ clientLabel: { kind: 'dcr', name: 'Visual Studio Code' }, redirectHost: host, local: true, login: 'u', txn: 't', csrf: 'c' });
    assert.ok(html.includes(`<p class="warn">This sign-in is handed to an app on this computer through <code>${host}</code>.`), host);
    assert.ok(!/Claude|VS Code|Visual Studio Code<\/strong>/.test(html.replace(/Name it gave itself: &quot;Visual Studio Code&quot;/, '')), 'client-neutral warning');
  }
  const web = consentPage({ clientLabel: { kind: 'dcr', name: null }, redirectHost: 'www.cursor.com', local: false, login: 'u', txn: 't', csrf: 'c' });
  assert.ok(!/class="warn"/.test(web));
});

// ---------------------------------------------------------------------------
// Operator CLI

test('zeusi mcp-oauth list / revoke: ids only (no hash, no token); a revoke stops the running store', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
  const d = dir();
  const path = join(d, 'mcp-oauth.json');
  const server = new OAuthStore({ hashKey: KEY, path });
  const c = server.registerClient({ clientName: 'Claude', redirectUris: [CLAUDE_CALLBACK] });
  const t = server.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  const run = (args: string[]) => spawnSync(process.execPath, [cli, 'mcp-oauth', ...args, '--file', path], {
    encoding: 'utf8', timeout: 60_000, env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: d },
  });
  const l = run(['list']);
  assert.equal(l.status, 0, l.stderr);
  assert.ok(l.stdout.includes(t.grant.grant_id) && l.stdout.includes(c.client_id) && l.stdout.includes('OperatorOwner'));
  assert.ok(!l.stdout.includes(t.grant.access_hash) && !l.stdout.includes(t.accessToken) && !l.stdout.includes(t.refreshToken));
  assert.equal(run(['revoke']).status, 2, 'one of --grant/--client/--all is required');
  const r = run(['revoke', '--grant', t.grant.grant_id]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(server.grantForAccess(t.accessToken), null);
  assert.equal(run(['revoke', '--grant', t.grant.grant_id]).status, 2, 'already revoked');
  const t2 = server.createGrant({ clientId: c.client_id, subject: 'github:1', login: 'OperatorOwner', tenant: 'work' });
  assert.equal(run(['revoke', '--all']).status, 0);
  assert.equal(server.grantForAccess(t2.accessToken), null);
});

// ---------------------------------------------------------------------------
// Loopback --http: never OAuth

test('loopback --http (the real bin): no OAuth routes even with all OAuth secrets set; still unauthenticated on 127.0.0.1', async () => {
  const { spawn } = await import('node:child_process');
  const { createServer } = await import('node:net');
  const { fileURLToPath } = await import('node:url');
  const port = await new Promise<number>((res) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => res(p));
    });
  });
  const d = dir();
  const bin = fileURLToPath(new URL('../src/mcp.ts', import.meta.url));
  const child = spawn(process.execPath, [bin, '--http', '--port', String(port)], {
    env: {
      PATH: process.env['PATH'] ?? '/usr/bin:/bin', HOME: d, ZEUSI_TEST_NO_REAL_CREDS: '1', PGSERVICEFILE: join(d, 'missing.conf'),
      [GITHUB_CLIENT_ID_ENV]: 'Iv1.abc', [GITHUB_CLIENT_SECRET_ENV]: 'sec-value', [SIGNING_KEY_ENV]: KEY,
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  try {
    await new Promise<void>((res, rej) => {
      const t = setTimeout(() => rej(new Error('server did not start')), 20_000);
      child.stderr!.on('data', (c: Buffer) => { if (c.toString().includes('loopback only')) { clearTimeout(t); res(); } });
      child.on('exit', () => rej(new Error('server exited')));
    });
    const base = `http://127.0.0.1:${port}`;
    for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-authorization-server', '/authorize', '/token', '/register', '/oauth/github/callback']) {
      assert.equal((await fetch(`${base}${p}`)).status, 404, p);
    }
    const init = await fetch(`${base}/mcp`, {
      method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } }),
    });
    assert.equal(init.status, 200, 'no auth on loopback');
    assert.equal(init.headers.get('www-authenticate'), null);
  } finally {
    child.kill();
  }
});
