// U4 (docs/plans/2026-11-18-open-signup-workspaces-plan.md): open GitHub sign-up end to end on the
// hosted handler (127.0.0.1, FAKE GitHub). operator members keep the team workspace and its unchanged
// consent screen; every other GitHub identity gets its own personal workspace, created once and
// reused by GitHub user id. Nobody is special-cased by email domain (an operator address does not make a visitor a
// operator member). Every sign-in outcome is audited with allowlisted fields only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { isOperatorMember } from '../src/mcp-oauth-github.ts';
import { AUDIT_FIELDS } from '../src/signin-audit.ts';
import { TENANT_ID_RE } from '../src/tenant-ddl.ts';
import { IDENTITIES, serviceHome, signIn, startTenantHosted, STRANGER_EMAIL, HOTMAIL, toConsent, dcrClient, send, type TenantHarness } from './helpers/hosted-tenants.ts';
import { asOwner, plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let home: string;
let h: TenantHarness;

before(async () => {
  db = await tenantTestDb();
  await plantTeam(db);
  home = serviceHome();
  // Flow tests, not limit tests (test/signup-limits.test.ts): every sign-in here comes from one test IP.
  h = await startTenantHosted({ db, home, limits: { signupPerIp: 50, signupGlobal: 50 } });
});
after(async () => {
  await h.close();
  await db.close();
});

const catalog = () => asOwner(db, async () => (await db.query<{ subject: string; tenant_id: string }>(
  `SELECT subject, tenant_id FROM zeusi_tenants.members ORDER BY subject`).catch(() => ({ rows: [] }))).rows);
const auditObjs = () => h.audits.map((l) => JSON.parse(l) as Record<string, unknown>);
const hidden = (html: string, name: string) => new RegExp(`name="${name}" value="([^"]+)"`).exec(html)![1]!;

test('open sign-up (AE1): a stranger gets a NEW empty personal workspace, the consent screen says so, never "Access denied"; tokens are bound to it', async () => {
  const s = await signIn(h, 'gh-stranger');
  assert.match(s.consent.body, /Allow read-only access to Zeusi/);
  assert.match(s.consent.body, /Your personal workspace<\/strong> \(new, empty\)/);
  assert.match(s.consent.body, /separate from every other Zeusi workspace/);
  assert.ok(!/Access denied|not allowed/.test(s.consent.body));
  for (const leak of ['zt_', STRANGER_EMAIL, 'OperatorOwner', 'sovra.ch']) assert.ok(!s.consent.body.includes(leak), leak);
  const rows = await catalog();
  const mine = rows.find((r) => r.subject === 'github:105');
  assert.ok(mine && TENANT_ID_RE.test(mine.tenant_id));
  const grants = h.store.list().grants.filter((g) => g.login === 'stranger');
  assert.equal(grants.length, 1);
  assert.equal(grants[0]!.tenant, mine!.tenant_id, 'the grant reads that workspace');
  const a = auditObjs().find((x) => x['github_id'] === 105 && x['action'] === 'signup');
  assert.deepEqual(a && { outcome: a['outcome'], tenant_id: a['tenant_id'], login: a['login'] }, { outcome: 'created', tenant_id: mine!.tenant_id, login: 'stranger' });
});

test('open sign-up (AE2): the same GitHub id with a changed login reuses its workspace; nothing new is created', async () => {
  const n0 = (await catalog()).length;
  const s = await signIn(h, 'gh-stranger-renamed');
  assert.match(s.consent.body, /Your personal workspace<\/strong>\. It is separate/, 'reused: not "(new, empty)"');
  assert.equal((await catalog()).length, n0);
  const g = h.store.list().grants.filter((x) => x.login === 'stranger2');
  const first = (await catalog()).find((r) => r.subject === 'github:105')!;
  assert.equal(g[0]!.tenant, first.tenant_id);
  assert.ok(auditObjs().some((x) => x['github_id'] === 105 && x['action'] === 'reuse' && x['outcome'] === 'ok' && x['login'] === 'stranger2'));
});

test('open sign-up (R4): an open GitHub user and a near-miss email get personal workspaces, never the team workspace', async () => {
  assert.equal(isOperatorMember(IDENTITIES['gh-visitor']!), false);
  assert.equal(isOperatorMember(IDENTITIES['gh-hotmail']!), false);
  for (const [code, login] of [['gh-visitor', 'open-user'], ['gh-hotmail', 'hot-user']] as const) {
    const s = await signIn(h, code);
    assert.match(s.consent.body, /Your personal workspace/);
    const g = h.store.list().grants.find((x) => x.login === login)!;
    assert.match(g.tenant, TENANT_ID_RE, `${login} is bound to a personal workspace`);
    assert.notEqual(g.tenant, 'work');
  }
  const ids = new Set((await catalog()).map((r) => r.tenant_id));
  assert.equal(ids.size, (await catalog()).length, 'one workspace per GitHub id');
  assert.ok(!JSON.stringify(h.audits).includes(HOTMAIL));
});

test('open sign-up (R1, R13): operator members reach the unchanged the team consent; no catalog row is made for them; their grants read team', async () => {
  const before0 = await catalog();
  for (const code of ['gh-login', 'gh-operator', 'gh-gmail']) {
    const s = await signIn(h, code);
    assert.ok(!/personal workspace/i.test(s.consent.body), code);
    assert.match(s.consent.body, /Allow read-only access to Zeusi/);
  }
  assert.deepEqual(await catalog(), before0);
  for (const id of [101, 102, 103]) assert.equal(await h.dir!.lookup(`github:${id}`), null);
  for (const login of ['OperatorOwner', 'operator-bot', 'other-name']) assert.equal(h.store.list().grants.find((g) => g.login === login)!.tenant, 'work');
  assert.ok(auditObjs().filter((x) => x['action'] === 'signin').every((x) => x['tenant_id'] === 'work' && x['outcome'] === 'ok'));
});

test('open sign-up: deny at consent issues no grant (the empty workspace stays); a disabled workspace gets the denied page and no grant', async () => {
  const clientId = await dcrClient(h);
  const grants0 = h.store.list().grants.length;
  const { consent, cookie } = await toConsent(h, clientId, 'gh-b');
  assert.equal(consent.status, 200);
  const deny = await send(h.port, {
    method: 'POST', path: '/oauth/consent', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ txn: hidden(consent.body, 'txn'), csrf: hidden(consent.body, 'csrf'), decision: 'deny' }).toString(),
  });
  assert.equal(deny.status, 302);
  assert.equal(new URL(String(deny.headers.location)).searchParams.get('error'), 'access_denied');
  assert.equal(h.store.list().grants.length, grants0);
  const b = (await h.dir!.lookup('github:107'))!;
  assert.equal(b.status, 'active');
  await asOwner(db, () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'disabled' WHERE tenant_id = $1`, [b.tenantId]));
  try {
    const again = await toConsent(h, clientId, 'gh-b');
    assert.equal(again.consent.status, 403);
    assert.match(again.consent.body, /Access denied/);
    assert.ok(!again.consent.body.includes(b.tenantId));
    assert.equal(h.store.list().grants.length, grants0);
    assert.ok(auditObjs().some((x) => x['github_id'] === 107 && x['action'] === 'denied' && x['outcome'] === 'disabled'));
  } finally {
    await asOwner(db, () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'active' WHERE tenant_id = $1`, [b.tenantId]));
  }
});

test('open sign-up: a workspace directory outage or no directory at all is a static 503 "not available", no grant; operator members still sign in', async () => {
  const down = await startTenantHosted({
    db, home, tenants: { lookup: async () => { throw new Error('ECONNREFUSED db.internal password=hunter2'); }, provision: async () => { throw new Error('x'); } },
  });
  const none = await startTenantHosted({ db, home, tenants: 'off' });
  try {
    for (const hh of [down, none]) {
      const clientId = await dcrClient(hh);
      const { consent } = await toConsent(hh, clientId, 'gh-n40');
      assert.equal(consent.status, 503);
      assert.match(consent.body, /New workspaces are not available/);
      for (const leak of ['hunter2', 'db.internal', 'ECONNREFUSED', 'newbie']) assert.ok(!consent.body.includes(leak), leak);
      assert.equal(hh.store.list().grants.length, 0);
      await signIn(hh, 'gh-login');
      assert.equal(hh.store.list().grants[0]!.tenant, 'work');
    }
    assert.ok(down.audits.some((l) => /"action":"error","outcome":"failed"/.test(l)));
    assert.ok(none.audits.some((l) => /"action":"denied","outcome":"unavailable"/.test(l)));
  } finally {
    await down.close();
    await none.close();
  }
});

test('open sign-up (R15): audit lines carry exactly the allowlisted fields; never an email, token, code, state or IP', async () => {
  assert.ok(h.audits.length >= 8);
  for (const line of h.audits) {
    const o = JSON.parse(line) as Record<string, unknown>;
    assert.deepEqual(Object.keys(o), [...AUDIT_FIELDS]);
    for (const bad of [STRANGER_EMAIL, HOTMAIL, 'sovra.ch', 'gmail', 'zeusi_at_', 'zeusi_rt_', 'zeusi_ac_', 'ghtok-', 'st-123', '198.51.100']) {
      assert.ok(!line.includes(bad), `audit line holds ${bad}`);
    }
  }
  // Request logs for the OAuth routes keep the existing allowlist too.
  for (const line of h.logs) assert.ok(!line.includes(STRANGER_EMAIL) && !/zt_[a-z2-7]{26}/.test(line), 'no workspace id or email in the request log');
});
