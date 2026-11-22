// C4 follow-up (docs/plans/2026-11-19-c4-webauthn-verify.md): server-side WebAuthn verification on the consent
// page, and no passkey-less approve for a flag-`on` born-encrypted workspace without a wrap (C7 review P2-3).
//
//   A. src/webauthn.ts units with a software authenticator (real ES256 / RS256 / EdDSA keys, real CBOR).
//   B. The real consent handler end to end (ephemeral 127.0.0.1 port, PGlite catalog, fake GitHub): enroll and
//      unlock succeed, and EVERY negative is refused AND creates / opens no wrap. Each negative posts the
//      CORRECT PRF output, so the one check it targets is the only thing standing between it and success:
//      the mutant named in each case (that check deleted) turns it green -> the test red.
//   C. KTD7: flag `on` + born on + no wrap: no approve-without-passkey button, the server refuses it, and the
//      script's no-WebAuthn message; flag `enroll` and `off` workspaces keep today's behaviour.
// Every key, PRF output, DEK and token here is a TEST value made in this run. No live service is contacted.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import type { Db } from '../src/db.ts';
import { Authenticator } from '../src/mcp-auth.ts';
import { createHostedHandler } from '../src/mcp-hosted.ts';
import { createMcpState, type McpDeps } from '../src/mcp-server.ts';
import { CLAUDE_CALLBACK, OAuthServer, pkceChallenge, type WrapCatalog } from '../src/mcp-oauth.ts';
import type { GithubApi } from '../src/mcp-oauth-github.ts';
import { OAuthStore } from '../src/mcp-oauth-store.ts';
import { CONSENT_SCRIPT } from '../src/mcp-oauth-views.ts';
import { enrollAuditSink } from '../src/enroll-audit.ts';
import { RecoveryAttemptLimiter } from '../src/recovery-limit.ts';
import { KEY_WRAP_MAX_COSE_BYTES, TenantDirectory } from '../src/tenants.ts';
import { enrollmentWraps, openSessionDek, parseRecoveryCode } from '../src/workspace-keys.ts';
import {
  cborDecode, MAX_ASSERTION_AUTH_DATA_BYTES, MAX_ATTESTATION_BYTES, MAX_CLIENT_DATA_BYTES, MAX_COSE_KEY_BYTES, MAX_SIGNATURE_BYTES,
  verifyAssertion, verifyRegistration, WEBAUTHN_CHALLENGE_TTL_MS, type Expected,
} from '../src/webauthn.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, tenantTestDb } from './helpers/tenant-fixture.ts';
import { overclaims } from './helpers/overclaim.ts';
import { cbor, enrollFields, FLAGS, keyPair, keysOf, SoftAuthenticator, unlockFields, type Alg, type CborIn, type Tweak } from './helpers/soft-webauthn.ts';

const ISSUER = 'https://mcp.zeusi.dev';
const RP = 'mcp.zeusi.dev';
const RESOURCE = `${ISSUER}/mcp`;
const KEY = 'w'.repeat(48);
const DEK = Buffer.from('webauthn-test-dek-pattern-012345', 'utf8'); // 32 bytes, a TEST value
const VERIFIER = 'q'.repeat(50) + '-._~';
const { UP, UV, AT, ED } = FLAGS;

// =============================================================================================== A. units

const EXP: Expected = { challenge: randomBytes(32).toString('base64url'), origin: ISSUER, rpId: RP };
const ctx = { rpId: RP, origin: ISSUER, challenge: EXP.challenge };

function reg(a: SoftAuthenticator, t: Tweak = {}, expected: Expected = EXP, posted: Buffer = a.credentialId) {
  const r = a.create(ctx, t);
  return verifyRegistration({ clientDataJSON: r.cdj, attestationObject: r.att, credentialId: posted, expected });
}

function asrt(a: SoftAuthenticator, publicKey: Buffer, stored: number, t: Tweak = {}, expected: Expected = EXP) {
  const g = a.get(ctx, t);
  return verifyAssertion({ clientDataJSON: g.acdj, authenticatorData: g.ad, signature: g.sig, publicKey, storedSignCount: stored, expected });
}

const reason = (r: { ok: boolean; reason?: string }) => (r.ok ? 'ok' : r.reason);

test('webauthn units: ES256, RS256 and EdDSA register (fmt none and packed self) and assert; the stored key is the attested COSE key', () => {
  for (const alg of [-7, -257, -8] as Alg[]) {
    for (const fmt of ['none', 'packed']) {
      const a = new SoftAuthenticator({ alg });
      const r = reg(a, { fmt });
      assert.ok(r.ok, `${alg} ${fmt}: ${reason(r)}`);
      assert.equal(r.value.alg, alg);
      assert.deepEqual(r.value.publicKey, a.key.cose);
      assert.deepEqual(r.value.credentialId, a.credentialId);
      assert.equal(r.value.signCount, 1);
      const s = asrt(a, r.value.publicKey, r.value.signCount);
      assert.ok(s.ok, `${alg} ${fmt} assertion: ${reason(s)}`);
      assert.equal(s.value.signCount, 2);
    }
  }
  // Extensions (ED) on both, e.g. hmac-secret at create and a credProtect-like value: parsed and consumed exactly.
  const a = new SoftAuthenticator();
  const r = reg(a, { extensions: new Map<string, CborIn>([['hmac-secret', true], ['credProtect', 2]]) });
  assert.ok(r.ok, String(reason(r)));
  assert.ok(asrt(a, r.value.publicKey, r.value.signCount, { extensions: new Map<string, CborIn>([['hmac-secret', Buffer.alloc(32)]]) }).ok);
  assert.equal(KEY_WRAP_MAX_COSE_BYTES, MAX_COSE_KEY_BYTES, 'the catalog CHECK bound is the verifier bound');
});

test('webauthn units: each registration property is checked (one refusal per mutant)', () => {
  const a = new SoftAuthenticator();
  const other = keyPair(-7);
  const cases: Array<[string, Tweak | (() => ReturnType<typeof reg>), string]> = [
    ['type webauthn.get at create (mutant: no type check)', { type: 'webauthn.get' }, 'type'],
    ['wrong challenge (mutant: no challenge compare)', { challenge: randomBytes(32).toString('base64url') }, 'challenge'],
    ['wrong origin (mutant: no origin compare)', { origin: 'https://mcp.zeusi.dev.evil.example' }, 'origin'],
    ['crossOrigin true', { crossOrigin: true }, 'cross_origin'],
    ['topOrigin present', { topOrigin: ISSUER }, 'cross_origin'],
    ['wrong rpIdHash (mutant: no rpIdHash compare)', { rpId: 'zeusi.dev' }, 'rp_id'],
    ['UP missing (mutant: no UP check)', { flags: UV | AT }, 'user_present'],
    ['UV missing (mutant: no UV check)', { flags: UP | AT }, 'user_verified'],
    ['BS without BE', { flags: UP | UV | AT | 0x10 }, 'flags'],
    ['AT missing', { flags: UP | UV }, 'flags'],
    ['trailing bytes after the credential', { trailing: Buffer.of(0) }, 'malformed'],
    ['packed, signature corrupted (mutant: no attStmt signature check)', { fmt: 'packed', corruptSig: true }, 'attestation'],
    ['packed, signed by another key (mutant: verify with the signer, not the credential)', { fmt: 'packed', signer: other }, 'attestation'],
    ['an unsupported format', { fmt: 'fido-u2f' }, 'format'],
    ['attested credential id differs from the posted one (mutant: no id binding)', { attestedId: randomBytes(16) }, 'credential'],
    ['malformed CBOR', { rawAttestation: Buffer.of(0xa3, 0x63, 0x66) }, 'malformed'],
    ['indefinite-length map', { rawAttestation: Buffer.of(0xbf, 0xff) }, 'malformed'],
    ['a CBOR tag', { rawAttestation: Buffer.concat([Buffer.of(0xd8, 0x18), cbor(new Map())]) }, 'malformed'],
    ['oversized attestationObject', { rawAttestation: Buffer.alloc(MAX_ATTESTATION_BYTES + 1, 0xa0) }, 'too_large'],
    ['oversized clientDataJSON', { rawClientData: Buffer.alloc(MAX_CLIENT_DATA_BYTES + 1, 0x20) }, 'too_large'],
    ['clientDataJSON not UTF-8', { rawClientData: Buffer.of(0xff, 0xfe) }, 'client_data'],
    ['clientDataJSON not an object', { rawClientData: Buffer.from('[1]') }, 'client_data'],
  ];
  for (const [name, t, want] of cases) {
    const r = typeof t === 'function' ? t() : reg(a, t);
    assert.equal(reason(r), want, name);
  }
  // fmt none must carry an empty attStmt; extra top-level keys and duplicate keys are refused.
  const good = a.create(ctx);
  const m = cborDecode(good.att).value as Map<string, CborIn>;
  const withStmt = cbor(new Map<string, CborIn>([['fmt', 'none'], ['attStmt', new Map<string, CborIn>([['x', 1]])], ['authData', m.get('authData')!]]));
  assert.equal(reason(verifyRegistration({ clientDataJSON: good.cdj, attestationObject: withStmt, credentialId: a.credentialId, expected: EXP })), 'attestation');
  const extra = cbor(new Map<string, CborIn>([...m, ['x', 1]]));
  assert.equal(reason(verifyRegistration({ clientDataJSON: good.cdj, attestationObject: extra, credentialId: a.credentialId, expected: EXP })), 'malformed');
  const dup = Buffer.concat([Buffer.of(0xa3), cbor('fmt'), cbor('none'), cbor('fmt'), cbor('none'), cbor('authData'), cbor(m.get('authData')!)]);
  assert.equal(reason(verifyRegistration({ clientDataJSON: good.cdj, attestationObject: dup, credentialId: a.credentialId, expected: EXP })), 'malformed');
  // An unsupported COSE algorithm (ES384) and a weak RSA key (1024 bit) are refused.
  const es384 = cbor(new Map<number, CborIn>([[1, 2], [3, -35], [-1, 2], [-2, Buffer.alloc(48, 1)], [-3, Buffer.alloc(48, 2)]]));
  const swapKey = (cose: Buffer) => {
    const ad = m.get('authData') as Buffer;
    const at = 37 + 18 + a.credentialId.length;
    return cbor(new Map<string, CborIn>([['fmt', 'none'], ['attStmt', new Map()], ['authData', Buffer.concat([ad.subarray(0, at), cose])]]));
  };
  assert.equal(reason(verifyRegistration({ clientDataJSON: good.cdj, attestationObject: swapKey(es384), credentialId: a.credentialId, expected: EXP })), 'key');
  const rsa1024 = cbor(new Map<number, CborIn>([[1, 3], [3, -257], [-1, Buffer.alloc(128, 0xc1)], [-2, Buffer.of(1, 0, 1)]]));
  assert.equal(reason(verifyRegistration({ clientDataJSON: good.cdj, attestationObject: swapKey(rsa1024), credentialId: a.credentialId, expected: EXP })), 'key');
  // CBOR bounds: depth and item count.
  let deep: CborIn = 1;
  for (let i = 0; i < 6; i++) deep = [deep];
  assert.throws(() => cborDecode(cbor(deep)), /too deep/);
  assert.throws(() => cborDecode(cbor(Array.from({ length: 65 }, () => 0))), /too many/);
  assert.throws(() => cborDecode(Buffer.of(0x5a, 0xff, 0xff, 0xff, 0xff)), /truncated/, 'a length beyond the buffer');
  assert.throws(() => cborDecode(Buffer.of(0xfb, 0, 0, 0, 0, 0, 0, 0, 0)), /float/);
});

test('webauthn units: each assertion property is checked, incl. the signature counter (one refusal per mutant)', () => {
  const a = new SoftAuthenticator();
  const r = reg(a);
  assert.ok(r.ok);
  const pk = r.value.publicKey;
  const other = new SoftAuthenticator();
  const cases: Array<[string, Tweak, number, string]> = [
    ['type webauthn.create at unlock (mutant: no type check)', { type: 'webauthn.create' }, 1, 'type'],
    ['wrong challenge', { challenge: randomBytes(32).toString('base64url') }, 1, 'challenge'],
    ['wrong origin', { origin: 'http://mcp.zeusi.dev' }, 1, 'origin'],
    ['wrong rpIdHash', { rpId: 'evil.example' }, 1, 'rp_id'],
    ['UP missing', { flags: UV }, 1, 'user_present'],
    ['UV missing', { flags: UP }, 1, 'user_verified'],
    ['AT set on an assertion', { flags: UP | UV | AT }, 1, 'flags'],
    ['ED set but no extensions', { flags: UP | UV | ED }, 1, 'malformed'],
    ['trailing bytes', { trailing: Buffer.of(1) }, 1, 'malformed'],
    ['signature corrupted (mutant: no signature check)', { corruptSig: true }, 1, 'signature'],
    ['signed by a different key (mutant: verify with the signer)', { signer: other.key }, 1, 'signature'],
    ['counter equal to the stored one (mutant: no counter check)', { counter: 5 }, 5, 'counter'],
    ['counter regression', { counter: 3 }, 5, 'counter'],
    ['counter 0 after a non-zero stored counter', { counter: 0 }, 5, 'counter'],
    ['authData too short', { rawAuthData: Buffer.alloc(36) }, 1, 'malformed'],
    ['authData oversized', { rawAuthData: Buffer.alloc(MAX_ASSERTION_AUTH_DATA_BYTES + 1) }, 1, 'too_large'],
  ];
  for (const [name, t, stored, want] of cases) assert.equal(reason(asrt(a, pk, stored, t)), want, name);
  // A counter-less authenticator (0 -> 0) passes; a growing counter passes and is returned.
  const z = new SoftAuthenticator({ step: 0 });
  const zr = reg(z);
  assert.ok(zr.ok && zr.value.signCount === 0);
  assert.deepEqual(asrt(z, zr.value.publicKey, 0), { ok: true, value: { signCount: 0 } });
  assert.deepEqual(asrt(a, pk, 6, { counter: 7 }), { ok: true, value: { signCount: 7 } });
  // Oversized signature; a stored key that is not an accepted COSE key.
  const g = a.get(ctx, { counter: 9 });
  assert.equal(reason(verifyAssertion({ clientDataJSON: g.acdj, authenticatorData: g.ad, signature: Buffer.alloc(MAX_SIGNATURE_BYTES + 1), publicKey: pk, storedSignCount: 1, expected: EXP })), 'too_large');
  assert.equal(reason(verifyAssertion({ clientDataJSON: g.acdj, authenticatorData: g.ad, signature: g.sig, publicKey: Buffer.from('not cose'), storedSignCount: 1, expected: EXP })), 'key');
  // A key of one type with the alg of another never verifies (ES256 signature, RS256 key).
  const rsa = new SoftAuthenticator({ alg: -257 });
  assert.equal(reason(verifyAssertion({ clientDataJSON: g.acdj, authenticatorData: g.ad, signature: g.sig, publicKey: rsa.key.cose, storedSignCount: 1, expected: EXP })), 'signature');
});

// ======================================================================================= B. end to end

let db: Db;
before(async () => {
  db = await tenantTestDb({ writer: true });
});
after(async () => db.close());

const github: GithubApi = {
  async exchange(code) { return /^u[0-9]{1,8}$/.test(code) ? `ghtok-${code}` : null; },
  async identity(t) { const n = Number(t.replace(/^ghtok-u/, '')); return Number.isSafeInteger(n) ? { id: n, login: `wa-user-${n}`, verifiedEmails: [] } : null; },
};

interface Calls { view: number; wraps: number; enroll: number; counter: number }
interface H {
  port: number; dir: TenantDirectory; calls: Calls; audit: string[]; store: OAuthStore; clock: { t: number };
  close: () => Promise<void>;
}

async function hosted(o: { mode: 'enroll' | 'on'; born: boolean }): Promise<H> {
  const dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin'), bornEncrypted: o.born });
  const root = safeMkdtemp(join(tmpdir(), 'zeusi-webauthn-'));
  const calls: Calls = { view: 0, wraps: 0, enroll: 0, counter: 0 };
  const audit: string[] = [];
  const clock = { t: Date.now() };
  const catalog: WrapCatalog = {
    encryptionView: (t) => { calls.view++; return dir.encryptionView(t); },
    wrapsFor: (t, k) => { calls.wraps++; return dir.wrapsFor(t, k); },
    enroll: (t, r) => { calls.enroll++; return dir.enroll(t, r); },
    advanceSignCount: (t, c, f, n) => { calls.counter++; return dir.advanceSignCount(t, c, f, n); },
  };
  const store = new OAuthStore({ hashKey: KEY, path: join(root, 'mcp-oauth.json'), now: () => clock.t });
  const server = new OAuthServer({
    issuer: ISSUER, githubClientId: 'Iv1.watest', github, signingKey: KEY, store, tenants: dir, workspaceWrite: false, now: () => clock.t,
    limits: { authorize: 10_000, callback: 10_000, consent: 10_000, token: 10_000, register: 10_000, registerGlobal: 10_000, revoke: 10_000, signupPerIp: 10_000, signupGlobal: 10_000 },
    keys: {
      mode: o.mode, catalog, limiter: new RecoveryAttemptLimiter({ hashKey: KEY, file: join(root, '.zeusi', 'recovery-attempts.json') }),
      audit: enrollAuditSink({ log: (l) => audit.push(l), file: join(root, '.zeusi', 'enroll-audit.jsonl') }), newDek: () => Buffer.from(DEK),
    },
  });
  const srv: Server = createServer();
  await new Promise<void>((res) => srv.listen(0, '127.0.0.1', res));
  const port = (srv.address() as AddressInfo).port;
  const deps: McpDeps = {
    env: { HOME: root }, home: root, readService: 'zeusi_ro',
    connectRead: async () => { throw new Error('not used'); }, connectWrite: async () => { throw new Error('not used'); },
    embeddings: () => null, feedbackPath: join(root, '.zeusi', 'search-feedback.jsonl'), queryLedgerPath: join(root, '.zeusi', 'q.json'),
  };
  srv.on('request', createHostedHandler({
    deps, state: createMcpState(), authenticator: new Authenticator({ tokensPath: join(root, 'mcp-tokens.json'), oauth: server }),
    allowedHosts: [`127.0.0.1:${port}`], log: () => {}, oauth: { state: 'enabled', server },
  }));
  return { port, dir, calls, audit, store, clock, close: () => new Promise((res) => srv.close(() => res())) };
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
const hidden = (html: string, name: string, formId?: string) => new RegExp(`name="${name}" value="([^"]+)"`).exec(formId ? html.slice(html.indexOf(`id="${formId}"`)) : html)![1]!;

let nextUser = 6000;
interface Sign { body: string; cookie: string; txn: string; csrf: string; clientId: string; gh: string }

async function signIn(h: H, gh: string): Promise<Sign> {
  const r = await send(h.port, { method: 'POST', path: '/register', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [CLAUDE_CALLBACK], client_name: 'WA' }) });
  const clientId = (JSON.parse(r.body) as { client_id: string }).client_id;
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: CLAUDE_CALLBACK, code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: 'S256', state: 'st', scope: 'zeusi.read offline_access', resource: RESOURCE,
  });
  const a = await send(h.port, { path: `/authorize?${q}`, headers: { 'fly-client-ip': '203.0.113.9' } });
  assert.equal(a.status, 302, a.body);
  const cookie = String((a.headers['set-cookie'] as string[])[0]).split(';')[0]!;
  const c = await send(h.port, { path: `/oauth/github/callback?code=${gh}&state=${new URL(String(a.headers.location)).searchParams.get('state')}`, headers: { cookie, 'fly-client-ip': '203.0.113.9' } });
  assert.equal(c.status, 200, c.body);
  return { body: c.body, cookie, txn: hidden(c.body, 'txn'), csrf: hidden(c.body, 'csrf'), clientId, gh };
}

function post(h: H, s: Sign, fields: Record<string, string>, txn = s.txn, csrf = s.csrf): Promise<Resp> {
  return send(h.port, { method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie: s.cookie, 'fly-client-ip': '203.0.113.9' }, body: new URLSearchParams({ txn, csrf, decision: 'approve', ...fields }).toString() });
}

async function tenantOf(h: H, gh: string): Promise<string> {
  return (await h.dir.lookup(`github:${gh.slice(1)}`))!.tenantId;
}
const wrapRows = (tenant: string) => asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi_tenants.key_wraps WHERE tenant_id = $1`, [tenant])).rows[0]!.n);
const encState = (tenant: string) => asOwner(db, async () => (await db.query<{ s: string }>(`SELECT enc_state AS s FROM zeusi_tenants.tenants WHERE tenant_id = $1`, [tenant])).rows[0]!.s);
const storedCounter = (tenant: string) => asOwner(db, async () => (await db.query<{ c: string }>(`SELECT webauthn_sign_count::text AS c FROM zeusi_tenants.key_wraps WHERE tenant_id = $1 AND kind = 'passkey'`, [tenant])).rows[0]!.c);

async function finish(h: H, s: Sign, page: Resp): Promise<string> {
  const cont = await post(h, s, {}, hidden(page.body, 'txn'), hidden(page.body, 'csrf'));
  assert.equal(cont.status, 302, cont.body);
  const code = new URL(String(cont.headers.location)).searchParams.get('code')!;
  const t = await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: CLAUDE_CALLBACK, client_id: s.clientId, code_verifier: VERIFIER, resource: RESOURCE }).toString() });
  assert.equal(t.status, 200, t.body);
  return (JSON.parse(t.body) as { access_token: string }).access_token;
}

/** A new identity, enrolled with `auth` (verified). Returns its tenant. */
async function enrolledUser(h: H, auth: SoftAuthenticator): Promise<{ gh: string; tenant: string }> {
  const gh = `u${nextUser++}`;
  const s = await signIn(h, gh);
  const e = await post(h, s, enrollFields(auth, s.body, ISSUER));
  assert.equal(e.status, 200, e.body);
  assert.ok(parseRecoveryCode(/id="zeusi-recovery-code">([^<]+)</.exec(e.body)![1]!));
  await finish(h, s, e);
  return { gh, tenant: await tenantOf(h, gh) };
}

test('e2e: enroll (create PRF; get() fallback; ES256, RS256, EdDSA) stores the attested key and counter; unlock verifies, advances the counter and opens the DEK', async () => {
  const h = await hosted({ mode: 'enroll', born: false });
  try {
    for (const [alg, via] of [[-7, 'create'], [-257, 'get'], [-8, 'create'], [-7, 'get']] as Array<[Alg, 'create' | 'get']>) {
      const auth = new SoftAuthenticator({ alg });
      const gh = `u${nextUser++}`;
      const s = await signIn(h, gh);
      const k = keysOf(s.body);
      assert.equal(k.mode, 'enroll');
      assert.ok(k.challenge2 && k.challenge2 !== k.challenge, 'two distinct challenges (create, get fallback)');
      assert.equal(k.required, false, 'flag enroll: never required');
      const e = await post(h, s, enrollFields(auth, s.body, ISSUER, { via }));
      assert.equal(e.status, 200, `${alg} ${via}: ${e.body}`);
      const tenant = await tenantOf(h, gh);
      const w = (await h.dir.wrapsFor(tenant, 'passkey'))[0]!;
      assert.deepEqual(w.webauthnPublicKey, auth.key.cose, 'the attested COSE key is stored');
      assert.equal(w.webauthnSignCount, via === 'get' ? 2 : 1, 'the counter of the last verified response');
      assert.deepEqual(openSessionDek(h.store, await finish(h, s, e))!.dek, DEK);
      // unlock on a new sign-in
      const s2 = await signIn(h, gh);
      assert.equal(keysOf(s2.body).mode, 'unlock');
      const u = await post(h, s2, unlockFields(auth, s2.body, ISSUER));
      assert.equal(u.status, 302, u.body);
      assert.equal(await storedCounter(tenant), String(auth.counter), 'counter advanced to the assertion value');
    }
  } finally {
    await h.close();
  }
});

test('e2e enroll negatives: each is refused (400) and creates NO wrap (enc_state stays off, catalog.enroll never called)', async () => {
  const h = await hosted({ mode: 'enroll', born: false });
  try {
    const other = keyPair(-7);
    type Case = [string, (a: SoftAuthenticator, s: Sign, o: Sign) => Record<string, string>];
    const cases: Case[] = [
      ['wrong challenge (mutant: no challenge compare)', (a, s) => enrollFields(a, s.body, ISSUER, { create: { challenge: randomBytes(32).toString('base64url') } })],
      ['challenge of another consent / tenant (mutant: challenge not bound to this txn)', (a, _s, o) => enrollFields(a, o.body, ISSUER)],
      ['wrong origin (mutant: no origin compare)', (a, s) => enrollFields(a, s.body, ISSUER, { create: { origin: 'https://evil.example' } })],
      ['wrong rpIdHash (mutant: no rpIdHash compare)', (a, s) => enrollFields(a, s.body, ISSUER, { create: { rpId: 'evil.example' } })],
      ['type webauthn.get at enroll (mutant: no type check)', (a, s) => enrollFields(a, s.body, ISSUER, { create: { type: 'webauthn.get' } })],
      ['UP missing (mutant: no UP check)', (a, s) => enrollFields(a, s.body, ISSUER, { create: { flags: UV | AT } })],
      ['UV missing (mutant: no UV check)', (a, s) => enrollFields(a, s.body, ISSUER, { create: { flags: UP | AT } })],
      ['packed: bad signature (mutant: attStmt not verified)', (a, s) => enrollFields(a, s.body, ISSUER, { create: { fmt: 'packed', corruptSig: true } })],
      ['packed: signed by a different key', (a, s) => enrollFields(a, s.body, ISSUER, { create: { fmt: 'packed', signer: other } })],
      ['posted credential id is not the attested one (mutant: no id binding)', (a, s) => enrollFields(a, s.body, ISSUER, { cred: randomBytes(16) })],
      ['malformed CBOR attestation', (a, s) => enrollFields(a, s.body, ISSUER, { create: { rawAttestation: Buffer.of(0xa3, 0x01) } })],
      ['oversized attestation (form bound)', (a, s) => enrollFields(a, s.body, ISSUER, { create: { rawAttestation: Buffer.alloc(MAX_ATTESTATION_BYTES + 1, 0xa0) } })],
      ['PRF posted without an attestation (mutant: PRF accepted unverified)', (a, s) => ({ ...enrollFields(a, s.body, ISSUER), att: '', cdj: '' })],
      ['get() fallback: assertion with the create challenge (mutant: fallback assertion not checked)', (a, s) => enrollFields(a, s.body, ISSUER, { via: 'get', get: { challenge: keysOf(s.body).challenge } })],
      ['get() fallback: assertion signed by a different key', (a, s) => enrollFields(a, s.body, ISSUER, { via: 'get', get: { signer: other } })],
      ['get() fallback: type webauthn.create', (a, s) => enrollFields(a, s.body, ISSUER, { via: 'get', get: { type: 'webauthn.create' } })],
      ['get() fallback: counter not above the attested one', (a, s) => enrollFields(a, s.body, ISSUER, { via: 'get', get: { counter: 1 } })],
      ['get() fallback: half the assertion fields', (a, s) => ({ ...enrollFields(a, s.body, ISSUER, { via: 'get' }), sig: '' })],
    ];
    for (const [name, build] of cases) {
      const s = await signIn(h, `u${nextUser++}`);
      const o = await signIn(h, `u${nextUser++}`);
      const tenant = await tenantOf(h, s.gh);
      const enrolls = h.calls.enroll;
      const r = await post(h, s, build(new SoftAuthenticator(), s, o));
      assert.equal(r.status, 400, `${name}: ${r.status}`);
      assert.match(r.body, /The passkey step did not complete\. Nothing was changed\./, name);
      assert.deepEqual(overclaims(r.body), [], name);
      assert.equal(h.calls.enroll, enrolls, `${name}: catalog.enroll not called`);
      assert.equal(await wrapRows(tenant), 0, `${name}: no wrap`);
      assert.equal(await encState(tenant), 'off', name);
    }
  } finally {
    await h.close();
  }
});

test('e2e enroll: expired challenge, and a challenge is consumed by a FAILED attempt (the valid response on the same txn is then refused)', async () => {
  const h = await hosted({ mode: 'enroll', born: false });
  try {
    // expired (mutant: no expiry check): the txn itself still lives (10 min), the challenge (5 min) does not.
    const s = await signIn(h, `u${nextUser++}`);
    h.clock.t += WEBAUTHN_CHALLENGE_TTL_MS + 1000;
    const r = await post(h, s, enrollFields(new SoftAuthenticator(), s.body, ISSUER));
    assert.equal(r.status, 400, r.body);
    assert.equal(await wrapRows(await tenantOf(h, s.gh)), 0);
    // consumed on failure
    const s2 = await signIn(h, `u${nextUser++}`);
    const a = new SoftAuthenticator();
    assert.equal((await post(h, s2, enrollFields(a, s2.body, ISSUER, { create: { origin: 'https://evil.example' } }))).status, 400);
    assert.equal((await post(h, s2, enrollFields(a, s2.body, ISSUER))).status, 400, 'the sign-in (and its challenge) is gone');
    assert.equal(await wrapRows(await tenantOf(h, s2.gh)), 0);
    // replay: a valid response of a sign-in that succeeded, posted on a new sign-in of the same user
    const s3 = await signIn(h, `u${nextUser++}`);
    const fields = enrollFields(a, s3.body, ISSUER);
    assert.equal((await post(h, s3, fields)).status, 200);
    assert.equal((await post(h, s3, fields)).status, 400, 'replayed on the same (consumed) sign-in');
  } finally {
    await h.close();
  }
});

test('e2e unlock negatives: each is refused (400, no code, no grant) with the CORRECT PRF; the counter never moves backwards; a valid unlock still works after them', async () => {
  const h = await hosted({ mode: 'enroll', born: false });
  try {
    const auth = new SoftAuthenticator();
    const x = await enrolledUser(h, auth);
    const yAuth = new SoftAuthenticator();
    const y = await enrolledUser(h, yAuth);
    const other = new SoftAuthenticator();
    type Case = [string, (s: Sign, ys: Sign) => Record<string, string>];
    const cases: Case[] = [
      ['wrong challenge (mutant: no challenge compare)', (s) => unlockFields(auth, s.body, ISSUER, { get: { challenge: randomBytes(32).toString('base64url') } })],
      ['challenge of another consent / tenant (mutant: challenge not bound to this txn)', (_s, ys) => unlockFields(auth, ys.body, ISSUER)],
      ['wrong origin (mutant: no origin compare)', (s) => unlockFields(auth, s.body, ISSUER, { get: { origin: 'https://evil.example' } })],
      ['wrong rpIdHash (mutant: no rpIdHash compare)', (s) => unlockFields(auth, s.body, ISSUER, { get: { rpId: 'evil.example' } })],
      ['type webauthn.create at unlock (mutant: no type check)', (s) => unlockFields(auth, s.body, ISSUER, { get: { type: 'webauthn.create' } })],
      ['bad signature (mutant: no signature check)', (s) => unlockFields(auth, s.body, ISSUER, { get: { corruptSig: true } })],
      ['signature by a different key (mutant: key not the stored one)', (s) => unlockFields(auth, s.body, ISSUER, { get: { signer: other.key } })],
      ['credential id not registered for this tenant (mutant: any wrap accepted)', (s) => unlockFields(other, s.body, ISSUER, { prf: auth.prf(Buffer.from(keysOf(s.body).creds[0]!.salt, 'base64url')) })],
      ['credential of ANOTHER tenant (its own valid assertion)', (s) => unlockFields(yAuth, s.body, ISSUER)],
      ['counter regression (mutant: no counter check)', (s) => unlockFields(auth, s.body, ISSUER, { get: { counter: 1 } })],
      ['UP missing (mutant: no UP check)', (s) => unlockFields(auth, s.body, ISSUER, { get: { flags: UV } })],
      ['UV missing (mutant: no UV check)', (s) => unlockFields(auth, s.body, ISSUER, { get: { flags: UP } })],
      ['malformed authenticatorData', (s) => unlockFields(auth, s.body, ISSUER, { get: { rawAuthData: Buffer.alloc(40, 0xa5) } })],
      ['oversized authenticatorData (form bound)', (s) => unlockFields(auth, s.body, ISSUER, { get: { rawAuthData: Buffer.alloc(MAX_ASSERTION_AUTH_DATA_BYTES + 1) } })],
      ['PRF posted without an assertion (mutant: PRF accepted unverified)', (s) => ({ ...unlockFields(auth, s.body, ISSUER), acdj: '', ad: '', sig: '' })],
    ];
    for (const [name, build] of cases) {
      const s = await signIn(h, x.gh);
      const ys = await signIn(h, y.gh);
      const before = await storedCounter(x.tenant);
      const r = await post(h, s, build(s, ys));
      assert.equal(r.status, 400, `${name}: ${r.status} ${r.body.slice(0, 200)}`);
      assert.equal(r.headers.location, undefined, `${name}: no code`);
      assert.match(r.body, /The passkey did not unlock this workspace\. Nothing was shared\./, name);
      assert.ok(Number(await storedCounter(x.tenant)) >= Number(before), `${name}: the counter never goes backwards`);
    }
    // replay of a verified assertion: same sign-in (consumed), then on a new sign-in (other challenge)
    const s = await signIn(h, x.gh);
    const ok = unlockFields(auth, s.body, ISSUER);
    assert.equal((await post(h, s, ok)).status, 302, 'a valid unlock still works after the negatives');
    assert.equal((await post(h, s, ok)).status, 400, 'replayed on the consumed sign-in');
    const s2 = await signIn(h, x.gh);
    assert.equal((await post(h, s2, ok)).status, 400, 'replayed on a new sign-in (mutant: challenge from the client)');
    // expired challenge (mutant: no expiry check)
    const s3 = await signIn(h, x.gh);
    h.clock.t += WEBAUTHN_CHALLENGE_TTL_MS + 1000;
    assert.equal((await post(h, s3, unlockFields(auth, s3.body, ISSUER))).status, 400, 'expired');
    // a cloned authenticator: same key, an old counter, after the real one moved on (§6.1.1)
    const s4 = await signIn(h, x.gh);
    const stored = Number(await storedCounter(x.tenant));
    assert.equal((await post(h, s4, unlockFields(auth, s4.body, ISSUER, { get: { counter: stored } }))).status, 400, 'clone: counter not above the stored one');
    const lines = h.audit.map((l) => JSON.parse(l) as { action: string; outcome: string });
    assert.ok(lines.filter((l) => l.action === 'unlock_passkey' && l.outcome === 'failed').length >= cases.length + 3);
  } finally {
    await h.close();
  }
});

test('e2e unlock: a passkey wrap without a stored WebAuthn key (enrolled before verification, KTD6) is refused with a neutral re-enroll line; no silent bypass', async () => {
  const h = await hosted({ mode: 'enroll', born: false });
  try {
    const gh = `u${nextUser++}`;
    await signIn(h, gh);
    const tenant = await tenantOf(h, gh);
    const auth = new SoftAuthenticator();
    const salt = randomBytes(32);
    const e = enrollmentWraps({ tenant, prfOutput: auth.prf(salt), credentialId: auth.credentialId, prfSalt: salt, newDek: () => Buffer.from(DEK) });
    assert.equal(await h.dir.enroll(tenant, { passkey: e.passkey, recovery: e.recovery }), 'enrolled', 'a legacy row: no webauthn fields');
    assert.equal((await h.dir.wrapsFor(tenant, 'passkey'))[0]!.webauthnPublicKey, null);
    const s = await signIn(h, gh);
    const r = await post(h, s, unlockFields(auth, s.body, ISSUER));
    assert.equal(r.status, 400, 'mutant: a wrap without a key skips verification -> 302');
    assert.match(r.body, /has to be set up again/);
    assert.match(r.body, /recovery code/);
    assert.deepEqual(overclaims(r.body), []);
    assert.equal(await h.dir.advanceSignCount(tenant, auth.credentialId, 0, 1), false, 'a legacy row has no counter to advance');
  } finally {
    await h.close();
  }
});

// ============================================================================ C. KTD7 (C7 review P2-3)

test('KTD7 flag on + born on + no wrap: no approve-without-passkey button, and the SERVER refuses a passkey-less approve (no code, no wrap)', async () => {
  const h = await hosted({ mode: 'on', born: true });
  try {
    const s = await signIn(h, `u${nextUser++}`);
    const tenant = await tenantOf(h, s.gh);
    assert.equal(await encState(tenant), 'on');
    const k = keysOf(s.body);
    assert.equal(k.mode, 'enroll');
    assert.equal(k.required, true, 'mutant: required never set -> red');
    assert.doesNotMatch(s.body, /without a passkey/, 'no visible approve without a passkey');
    assert.match(s.body, /<button type="submit" name="decision" value="approve" id="zeusi-approve" hidden>/, 'only the hidden submitter of the script');
    assert.match(s.body, /Passkey \(needed\)/);
    assert.deepEqual(overclaims(s.body), [], 'no encryption claim, script included');
    // the server refuses enc='' + approve (mutant: the refusal deleted -> a 302 with a code)
    const r = await post(h, s, { enc: '' });
    assert.equal(r.status, 400, r.body);
    assert.equal(r.headers.location, undefined);
    assert.match(r.body, /needs a passkey/);
    assert.deepEqual(overclaims(r.body), []);
    const r2 = await send(h.port, { method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie: s.cookie }, body: new URLSearchParams({ txn: s.txn, csrf: s.csrf, decision: 'approve' }).toString() });
    assert.equal(r2.status, 400, 'no enc field at all: the sign-in was consumed by the refusal');
    const s2 = await signIn(h, s.gh);
    const r3 = await send(h.port, { method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie: s2.cookie }, body: new URLSearchParams({ txn: s2.txn, csrf: s2.csrf, decision: 'approve' }).toString() });
    assert.equal(r3.status, 400, 'no enc field at all on a fresh sign-in: refused too');
    assert.equal(await wrapRows(tenant), 0);
    // deny still works
    const s3 = await signIn(h, s.gh);
    const d = await send(h.port, { method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie: s3.cookie }, body: new URLSearchParams({ txn: s3.txn, csrf: s3.csrf, decision: 'deny' }).toString() });
    assert.equal(d.status, 302);
    assert.equal(new URL(String(d.headers.location)).searchParams.get('error'), 'access_denied');
    // the verified passkey path works and leaves enc_state on
    const s4 = await signIn(h, s.gh);
    const e = await post(h, s4, enrollFields(new SoftAuthenticator(), s4.body, ISSUER));
    assert.equal(e.status, 200, e.body);
    assert.deepEqual(openSessionDek(h.store, await finish(h, s4, e))!.dek, DEK);
    assert.equal(await encState(tenant), 'on');
  } finally {
    await h.close();
  }
});

test('KTD7 scope: flag `on` with an `off` workspace, and flag `enroll` with a born-on workspace, keep the approve without a passkey (today\'s behaviour)', async () => {
  // flag on, workspace created while the flag was off (not born encrypted): optional, as before.
  const hOff = await hosted({ mode: 'on', born: false });
  try {
    const s = await signIn(hOff, `u${nextUser++}`);
    assert.equal(keysOf(s.body).required, false);
    assert.match(s.body, /Approve without a passkey/);
    const r = await post(hOff, s, { enc: '' });
    assert.equal(r.status, 302, 'approve without a passkey still issues a code');
    assert.ok(new URL(String(r.headers.location)).searchParams.get('code'));
  } finally {
    await hOff.close();
  }
  // flag enroll (the rollback value) with a born-on workspace: not required.
  const hEnroll = await hosted({ mode: 'enroll', born: true });
  try {
    const s = await signIn(hEnroll, `u${nextUser++}`);
    assert.equal(await encState(await tenantOf(hEnroll, s.gh)), 'on');
    assert.equal(keysOf(s.body).required, false);
    assert.equal((await post(hEnroll, s, { enc: '' })).status, 302);
  } finally {
    await hEnroll.close();
  }
});

test('KTD7 script: required + no WebAuthn says a passkey-capable device or browser is needed (never "you can still approve"); required + no PRF says try another passkey', async () => {
  async function run(attrs: Record<string, string>, creds: unknown, pkc: boolean) {
    const fields: Record<string, { value: string }> = Object.fromEntries(['enc', 'cred', 'prf', 'att', 'cdj', 'acdj', 'ad', 'sig'].map((k) => [k, { value: '' }]));
    let submitted = false;
    const handler: { click: (() => void) | null } = { click: null };
    const go = { disabled: false, addEventListener: (_: string, f: () => void) => { handler.click = f; } };
    const status = { textContent: '', hidden: true };
    const els: Record<string, unknown> = {
      'zeusi-keys': { getAttribute: (n: string) => attrs[n] ?? null },
      'zeusi-consent': { elements: { namedItem: (n: string) => fields[n] }, requestSubmit: () => { submitted = true; } },
      'zeusi-keys-go': go, 'zeusi-approve': {}, 'zeusi-keys-status': status,
    };
    runInNewContext(CONSENT_SCRIPT, {
      document: { getElementById: (id: string) => els[id] ?? null }, navigator: { credentials: creds }, window: pkc ? { PublicKeyCredential: function PKC() {} } : {},
      atob: globalThis.atob, btoa: globalThis.btoa, Uint8Array, String, JSON,
    });
    if (handler.click) {
      handler.click();
      for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
    }
    return { status, go, submitted, fields };
  }
  const attrs = { 'data-mode': 'enroll', 'data-rp': RP, 'data-user': 'AQ', 'data-name': 'u', 'data-challenge': 'Ag', 'data-challenge2': 'Aw', 'data-salt': 'BA', 'data-required': 'yes' };
  const noWebAuthn = await run(attrs, undefined, false);
  assert.equal(noWebAuthn.go.disabled, true);
  assert.match(noWebAuthn.status.textContent, /needs a passkey/);
  assert.match(noWebAuthn.status.textContent, /device or browser that supports passkeys/);
  assert.doesNotMatch(noWebAuthn.status.textContent, /approve/i);
  assert.deepEqual(overclaims(noWebAuthn.status.textContent), []);
  const notRequired = await run({ ...attrs, 'data-required': '' }, undefined, false);
  assert.match(notRequired.status.textContent, /You can still approve/, 'flag enroll: unchanged message');
  const resp = { attestationObject: new ArrayBuffer(1), clientDataJSON: new ArrayBuffer(1), authenticatorData: new ArrayBuffer(37), signature: new ArrayBuffer(8) };
  const noPrf = await run(attrs, {
    create: async () => ({ rawId: new ArrayBuffer(3), response: resp, getClientExtensionResults: () => ({}) }),
    get: async () => ({ rawId: new ArrayBuffer(3), response: resp, getClientExtensionResults: () => ({}) }),
  }, true);
  assert.equal(noPrf.submitted, false);
  assert.match(noPrf.status.textContent, /Try another passkey or device/);
  assert.doesNotMatch(noPrf.status.textContent, /approve/i);
});

test('webauthn: the challenges are 32 random bytes, single-use per sign-in, and the TTL is shorter than the sign-in', async () => {
  assert.ok(WEBAUTHN_CHALLENGE_TTL_MS < 10 * 60_000);
  const h = await hosted({ mode: 'enroll', born: false });
  try {
    const seen = new Set<string>();
    for (let i = 0; i < 3; i++) {
      const k = keysOf((await signIn(h, `u${nextUser++}`)).body);
      for (const c of [k.challenge, k.challenge2!]) {
        assert.equal(Buffer.from(c, 'base64url').length, 32);
        assert.ok(!seen.has(c));
        seen.add(c);
      }
    }
    assert.equal(createHash('sha256').update(RP).digest().length, 32);
  } finally {
    await h.close();
  }
});
