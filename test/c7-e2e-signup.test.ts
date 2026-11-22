// C7 end to end (operator brief: "after C7, with ZEUSI_WORKSPACE_ENCRYPTION=on, does a brand-new sign-up work end to
// end"): the REAL hosted handler wired as src/mcp.ts wires it with the flag `on` (born-encrypted provisioning, the
// consent page's keys, the writer, the real B1 index hook, the B1 cache and its session-end hook). A new GitHub
// identity signs in: provisioned born `on` at the callback -> enrolls on the consent page (passkey PRF from a fake
// authenticator + recovery code shown once) -> continue -> /token (a write grant with C4 session wraps) -> fills the
// workspace through /mcp (zeusi_import_preview + zeusi_import_commit, zeusi_sync_batch incl. a deletion) -> reads it
// back through EVERY read tool. The output equals the same corpus in an `off` workspace (P), compared after deleting
// query_id and generated_at. §7 item 7 (reads): the canary of a note and of a query is in no stderr line, request
// log line, audit line, feedback ledger or file under the data / work roots. PGlite, fake GitHub, TEST secrets only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { Db } from '../src/db.ts';
import { TenantDirectory } from '../src/tenants.ts';
import { openSessionDek, parseRecoveryCode } from '../src/workspace-keys.ts';
import { CLAUDE_CALLBACK, pkceChallenge } from '../src/mcp-oauth.ts';
import { esc, RECOVERY_WARNING_BORN } from '../src/mcp-oauth-views.ts';
import { ISSUER, RESOURCE, callTool, dcrClient, mcpPost, send, serviceHome, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { callerOf } from './helpers/c6-fixture.ts';
import { C7_NOW, C7_SYNC_DELETED, c7DecisionLog, c7Notes, c7Sync, normalised, readCalls, stable } from './helpers/c7-fixture.ts';
import { asLogin, tenantTestDb } from './helpers/tenant-fixture.ts';
import { overclaims } from './helpers/overclaim.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { enrollFields, SoftAuthenticator } from './helpers/soft-webauthn.ts';

const E2E_DEK = Buffer.from('c7-e2e-test-dek-pattern-01234567', 'utf8'); // 32 bytes, a TEST value
const VERIFIER = 'v'.repeat(50) + '-._~';
const CANARY = 'c7e2ecanarywombat';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
const hidden = (html: string, name: string) => new RegExp(`name="${name}" value="([^"]+)"`).exec(html)![1]!;
const attr = (html: string, name: string) => new RegExp(`${name}="([^"]*)"`).exec(html)?.[1];

let db: Db;
let h: TenantHarness;
let home: string;
let work: string;
const stderr: string[] = [];
let realWrite: typeof process.stderr.write;

before(async () => {
  assert.equal(E2E_DEK.length, 32);
  db = await tenantTestDb({ writer: true });
  home = serviceHome();
  work = safeMkdtemp(join(tmpdir(), 'zeusi-c7-e2e-work-'));
  h = await startTenantHosted({
    db, home, writer: 'on', workRoot: join(work, 'workspace-import'), flagOn: { newDek: () => Buffer.from(E2E_DEK) }, routerCacheMs: 0,
    limits: { authorize: 1000, callback: 1000, consent: 1000, token: 1000, register: 1000, registerGlobal: 1000, revoke: 1000, signupPerIp: 1000, signupGlobal: 1000 },
    hostedLimits: { perToken: 100_000, global: 100_000 }, wsLimits: { preview: 100, commit: 100, sync: 100 },
    // A fixed tool clock (lock expiry, recency): P and S are read at different instants; their scores must not drift.
    over: { now: () => C7_NOW },
  });
  realWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
    stderr.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk as Uint8Array).toString('utf8'));
    return (realWrite as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;
});
after(async () => {
  process.stderr.write = realWrite;
  await h.close();
  await db.close();
});

const call = async (tok: string, name: string, args: Record<string, unknown> = {}) => toolJson(await mcpPost(h.port, tok, callTool(name, args)));

/** The whole flag-on sign-up of one new identity: callback (provision, born on) -> consent enroll -> continue -> /token. */
async function signUpEnrolled(gh: string): Promise<{ access: string; refresh: string; tenant: string; clientId: string; recoveryShown: string; scope: string }> {
  const clientId = await dcrClient(h);
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: CLAUDE_CALLBACK, code_challenge: pkceChallenge(VERIFIER),
    code_challenge_method: 'S256', state: 'st-e2e', scope: 'zeusi.read offline_access', resource: RESOURCE,
  });
  const a = await send(h.port, { path: `/authorize?${q}`, headers: { 'fly-client-ip': '198.51.100.70' } });
  assert.equal(a.status, 302);
  const cookie = String((a.headers['set-cookie'] as string[])[0]).split(';')[0]!;
  const consent = await send(h.port, { path: `/oauth/github/callback?code=${gh}&state=${new URL(String(a.headers.location)).searchParams.get('state')}`, headers: { cookie, 'fly-client-ip': '198.51.100.70' } });
  assert.equal(consent.status, 200, consent.body);
  assert.equal(attr(consent.body, 'data-mode'), 'enroll', 'the passkey enroll offer');
  assert.deepEqual(overclaims(consent.body.replace(/<script>[\s\S]*<\/script>/, '')), [], 'no encryption claim on the consent page');
  // docs/plans/2026-11-19-c4-webauthn-verify.md: a software authenticator posts a real, verified attestation.
  assert.equal(attr(consent.body, 'data-required'), 'yes', 'flag on + born on: a passkey is required (KTD7)');
  assert.doesNotMatch(consent.body, /without a passkey/, 'no approve without a passkey is offered');
  const auth = new SoftAuthenticator({ credentialId: Buffer.from(`c7-e2e-credential-${gh}`) });
  const salt = Buffer.from(attr(consent.body, 'data-salt')!, 'base64url');
  const prf = auth.prf(salt);
  const post = (fields: Record<string, string>) => send(h.port, { method: 'POST', path: '/oauth/consent', headers: { ...FORM, cookie, 'fly-client-ip': '198.51.100.70' }, body: form(fields) });
  const e = await post({ txn: hidden(consent.body, 'txn'), csrf: hidden(consent.body, 'csrf'), decision: 'approve', ...enrollFields(auth, consent.body, ISSUER) });
  assert.equal(e.status, 200, e.body);
  const shown = /id="zeusi-recovery-code">([^<]+)</.exec(e.body)![1]!;
  assert.ok(parseRecoveryCode(shown), 'a valid recovery code, shown once');
  assert.equal(e.body.split(shown).length, 2);
  assert.deepEqual(overclaims(e.body), []);
  assert.ok(e.body.includes(esc(RECOVERY_WARNING_BORN)), 'flag on, born encrypted: the born warning on the recovery page');
  const cont = await post({ txn: hidden(e.body, 'txn'), csrf: hidden(e.body, 'csrf'), decision: 'approve' });
  assert.equal(cont.status, 302, cont.body);
  const code = new URL(String(cont.headers.location)).searchParams.get('code')!;
  const t = await send(h.port, { method: 'POST', path: '/token', headers: FORM, body: form({ grant_type: 'authorization_code', code, redirect_uri: CLAUDE_CALLBACK, client_id: clientId, code_verifier: VERIFIER, resource: RESOURCE }) });
  assert.equal(t.status, 200, t.body);
  const j = JSON.parse(t.body) as { access_token: string; refresh_token: string; scope: string };
  const s = openSessionDek(h.store, j.access_token);
  assert.ok(s, 'the grant carries C4 session wraps');
  const dek = s.dek;
  assert.ok(dek.equals(E2E_DEK), 'the wrap opens the enrolled DEK');
  dek.fill(0);
  prf.fill(0);
  return { access: j.access_token, refresh: j.refresh_token, tenant: s.tenant, clientId, recoveryShown: shown, scope: j.scope };
}

/** The C7 corpus through /mcp: previews + commits, the decision log, a sync and a sync deletion. */
async function fillOverMcp(tok: string, extra: Array<{ kind: 'markdown'; title: string; text: string }> = []): Promise<void> {
  const notes = [...c7Notes(), ...extra];
  for (const part of [notes.slice(0, 20), notes.slice(20), [c7DecisionLog()]]) {
    const p = await call(tok, 'zeusi_import_preview', { documents: part });
    assert.equal(p.isError, false, p.text);
    const c = await call(tok, 'zeusi_import_commit', { preview_id: (p.json as { preview_id: string }).preview_id, confirm: true });
    assert.equal(c.isError, false, c.text);
  }
  const s1 = await call(tok, 'zeusi_sync_batch', { items: c7Sync() });
  assert.equal(s1.isError, false, s1.text);
  const s2 = await call(tok, 'zeusi_sync_batch', { deleted: [...C7_SYNC_DELETED] });
  assert.equal(s2.isError, false, s2.text);
}

test('flag on, end to end: a new sign-up is born encrypted, enrolls (passkey + recovery code), writes sealed through /mcp, and every read tool returns the same output as the same corpus in an off workspace', async () => {
  const u = await signUpEnrolled('gh-n48');
  assert.equal((await h.router!.encState(u.tenant)).encState, 'on', 'born on; enrolling leaves it on (C5 KTD11)');
  assert.match(u.scope, /workspace/, 'a grant that may write its own workspace');
  await fillOverMcp(u.access, [{ kind: 'markdown', title: `Canary ${CANARY}`, text: `# ${CANARY}\n\nthe ${CANARY} note.\n` }]);
  // Sealed at rest: every content row of the five tables carries key_version 1 and no plain text.
  const plain = await (await import('./helpers/tenant-fixture.ts')).asOwner(db, async () => (await db.query<{ n: number }>(
    `SELECT ((SELECT count(*) FROM "${u.tenant}".notes WHERE key_version IS NULL) + (SELECT count(*) FROM "${u.tenant}".chunks WHERE key_version IS NULL)
      + (SELECT count(*) FROM "${u.tenant}".decisions WHERE key_version IS NULL) + (SELECT count(*) FROM "${u.tenant}".facts WHERE key_version IS NULL))::int AS n`)).rows[0]!.n);
  assert.equal(plain, 0, 'nothing plain');
  assert.ok(h.hookStats.segments > 10, 'the real hook persisted the B1 index');

  // P: the same corpus (without the canary note) in an `off` workspace on the same server, read through /mcp too.
  const offDir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  const P = ((await offDir.provision('github:7999')) as { tenantId: string }).tenantId;
  const pCaller = callerOf(P);
  for (const part of [c7Notes().slice(0, 20), c7Notes().slice(20), [c7DecisionLog()]]) {
    const pv = await h.writes!.preview(pCaller, part);
    await h.writes!.commit(pCaller, (pv as { preview_id: string }).preview_id);
  }
  await h.writes!.sync(pCaller, c7Sync(), []);
  await h.writes!.sync(pCaller, [], [...C7_SYNC_DELETED]);
  const pTok = h.store.createGrant({ clientId: u.clientId, subject: 'github:7999', login: 'p-user', tenant: P, workspaceWrite: true }).accessToken;

  // S without the canary note must equal P: compare on a second born-on sign-up filled with exactly the corpus.
  const v = await signUpEnrolled('gh-n49');
  await fillOverMcp(v.access);
  let compared = 0;
  for (const [tool, args] of readCalls()) {
    const p = await call(pTok, tool, args);
    const s = await call(v.access, tool, args);
    assert.equal(p.isError, false, `P ${tool}: ${p.text.slice(0, 200)}`);
    assert.equal(s.isError, false, `S ${tool}: ${s.text.slice(0, 200)}`);
    assert.deepEqual(stable(normalised(s.json)), stable(normalised(p.json)), `${tool} ${JSON.stringify(args)}`);
    compared++;
  }
  assert.equal(compared, readCalls().length);
  assert.ok(h.cache.list().some((e) => e.tenant === v.tenant), 'served from the one cached copy');

  // The canary workspace answers its own canary; feedback works on the sealed route (keyed memo, no text kept).
  const q = await call(u.access, 'zeusi_search', { query: CANARY });
  const hits = q.json!['hits'] as Array<{ source_uri: string; text: string }>;
  assert.equal(hits.length, 1);
  assert.equal(hits[0]!.text, `the ${CANARY} note.`);
  const fb = await call(u.access, 'zeusi_search_feedback', { query_id: q.json!['query_id'] as string, source_uri: hits[0]!.source_uri, useful: true });
  assert.equal(fb.isError, false, fb.text);
  const memo = [...h.state.queries.values()].find((m) => m.hashed === true)!;
  assert.ok(memo && memo.texts.length === 0 && ![...memo.uris].some((x) => x.includes('import:')), 'the sealed memo holds keyed hashes, no text (KTD12)');
  assert.equal((await call(u.access, 'zeusi_search_feedback', { query_id: q.json!['query_id'] as string, source_uri: 'import:team/other.md', useful: true })).isError, true);
  for (const tool of ['zeusi_startup', 'zeusi_onboarding_status'] as const) assert.equal((await call(u.access, tool)).isError, false);
  assert.equal((await call(u.access, 'zeusi_context_for_task', { task: `work on ${CANARY}` })).isError, false);

  // §7.7 (reads): the canary is in no stderr line, request-log line, audit line, ledger or file under the roots.
  const logs = [...stderr, ...h.logs, ...h.audits, ...h.wsAudits].join('\n');
  assert.ok(!logs.includes(CANARY), 'no canary in stderr, the request log or an audit line');
  const files: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else files.push(p);
    }
  };
  for (const root of [home, work, dirname((h.store as unknown as { o: { path: string } }).o.path)]) walk(root);
  assert.ok(files.some((f) => f.endsWith('mcp-oauth.json')), 'the OAuth data dir was walked');
  for (const f of files) assert.ok(!readFileSync(f).includes(CANARY), 'no canary in a file under the home, data or work roots');

  // Revoke: the workspace's copy is evicted at once.
  assert.ok(h.cache.list().some((e) => e.tenant === u.tenant));
  h.store.revokeTenant(u.tenant);
  assert.ok(!h.cache.list().some((e) => e.tenant === u.tenant), 'log out everywhere evicts');
});
