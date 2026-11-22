// U4 abuse limits (docs/plans/2026-11-18-open-signup-workspaces-plan.md KTD9, R14, AE5): new personal
// workspaces are limited per client IP and globally per hour, and capped in total. Over a limit:
// HTTP 429, a static page, Retry-After, and NO workspace is created (catalog, schemas and roles are
// unchanged). A returning identity is never blocked by these limits.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { dcrClient, serviceHome, signIn, startTenantHosted, toConsent, type TenantHarness } from './helpers/hosted-tenants.ts';
import { asOwner, plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let home: string;

before(async () => {
  db = await tenantTestDb();
  await plantTeam(db);
  home = serviceHome();
});
after(async () => db.close());

const counts = () => asOwner(db, async () => (await db.query<{ t: number; n: number; r: number }>(
  `SELECT (SELECT count(*) FROM zeusi_tenants.tenants)::int t, (SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'zt\\_%')::int n,
          (SELECT count(*) FROM pg_roles WHERE rolname LIKE 'zt\\_%')::int r`).catch(() => ({ rows: [{ t: 0, n: 0, r: 0 }] }))).rows[0]!);

function assertLimited(r: { status: number; headers: Record<string, string | string[] | undefined>; body: string }, what: string): void {
  assert.equal(r.status, 429, what);
  const retry = Number(r.headers['retry-after']);
  assert.ok(Number.isInteger(retry) && retry >= 1 && retry <= 3600, `${what}: Retry-After ${String(r.headers['retry-after'])}`);
  assert.match(r.body, /Too many new workspaces right now/);
  assert.match(r.body, /Nothing was created/);
  for (const leak of ['newbie', 'zt_', 'github:', '203.0.113']) assert.ok(!r.body.includes(leak), `${what}: page leaks ${leak}`);
  assert.equal(r.headers['cache-control'], 'no-store');
}

test('signup limits (AE5): the per-IP hourly limit gives 429 + Retry-After and creates no workspace; another IP still signs up', async () => {
  const h = await startTenantHosted({ db, home, limits: { signupPerIp: 2, signupGlobal: 100 } });
  try {
    const ip = '203.0.113.7';
    await signIn(h, 'gh-n0', ip);
    await signIn(h, 'gh-n1', ip);
    const c0 = await counts();
    const grants0 = h.store.list().grants.length;
    const { consent } = await toConsent(h, await dcrClient(h), 'gh-n2', ip);
    assertLimited(consent, 'third new identity from one IP');
    assert.deepEqual(await counts(), c0, 'no catalog row, schema or role');
    assert.equal(h.store.list().grants.length, grants0, 'no grant');
    assert.equal(await h.dir!.lookup('github:5002'), null);
    // A returning identity from the limited IP is not blocked.
    const back = await signIn(h, 'gh-n0', ip);
    assert.match(back.consent.body, /Your personal workspace/);
    // A different IP may still create one.
    await signIn(h, 'gh-n2', '203.0.113.8');
    assert.ok(await h.dir!.lookup('github:5002'));
    assert.ok(h.audits.some((l) => /"login":"newbie-2","tenant_id":null,"action":"signup","outcome":"rate_limited"/.test(l)));
  } finally {
    await h.close();
  }
});

test('signup limits: the global hourly limit gives 429 across IPs and creates nothing', async () => {
  const h = await startTenantHosted({ db, home, limits: { signupPerIp: 100, signupGlobal: 2 } });
  try {
    await signIn(h, 'gh-n10', '192.0.2.10');
    await signIn(h, 'gh-n11', '192.0.2.11');
    const c0 = await counts();
    for (const [code, ip] of [['gh-n12', '192.0.2.12'], ['gh-n13', '192.0.2.13']] as const) {
      const { consent } = await toConsent(h, await dcrClient(h), code, ip);
      assertLimited(consent, `${code} over the global limit`);
    }
    assert.deepEqual(await counts(), c0);
  } finally {
    await h.close();
  }
});

test('signup limits: the durable total cap gives 429 and creates nothing; existing workspaces still sign in', async () => {
  const c0 = await counts();
  const h = await startTenantHosted({ db, home, maxTenants: c0.t });
  try {
    const { consent } = await toConsent(h, await dcrClient(h), 'gh-n20', '192.0.2.20');
    assertLimited(consent, 'total cap');
    assert.equal(consent.headers['retry-after'], '3600');
    assert.deepEqual(await counts(), c0);
    assert.ok(h.audits.some((l) => /"action":"signup","outcome":"cap_reached"/.test(l)));
    const back = await signIn(h, 'gh-n0', '192.0.2.21');
    assert.match(back.consent.body, /Your personal workspace/);
  } finally {
    await h.close();
  }
});

test('signup limits: limits are counted on attempt (a failing provision still counts) and the per-minute callback limit still applies', async () => {
  let calls = 0;
  const h = await startTenantHosted({
    db, home, limits: { signupPerIp: 1, signupGlobal: 100, callback: 100 },
    tenants: { lookup: async () => null, provision: async () => { calls++; throw new Error('boom'); } },
  });
  try {
    const first = await toConsent(h, await dcrClient(h), 'gh-n30', '192.0.2.30');
    assert.equal(first.consent.status, 503);
    const second = await toConsent(h, await dcrClient(h), 'gh-n31', '192.0.2.30');
    assertLimited(second.consent, 'second attempt after a failed one');
    assert.equal(calls, 1, 'the limited attempt never reached the provisioner');
  } finally {
    await h.close();
  }
  const tight = await startTenantHosted({ db, home, limits: { callback: 1 } });
  try {
    const clientId = await dcrClient(tight);
    await toConsent(tight, clientId, 'gh-n0', '192.0.2.40');
    const { consent } = await toConsent(tight, clientId, 'gh-n0', '192.0.2.40');
    assert.equal(consent.status, 429);
  } finally {
    await tight.close();
  }
});
