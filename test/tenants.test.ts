// U2 (docs/plans/2026-11-18-open-signup-workspaces-plan.md): catalog, provisioning and the workspace
// session, on PGlite with the real migrations and real roles. Logins are emulated with
// SET SESSION AUTHORIZATION (test/helpers/tenant-fixture.ts), so SET ROLE checks real membership.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { Db } from '../src/db.ts';
import { TENANT_ID_RE } from '../src/tenant-ddl.ts';
import { newTenantId, schemaTranslatingDb, TenantDirectory, TenantError, TenantRefused, TenantRouter, translateSql } from '../src/tenants.ts';
import { asLogin, asOwner, OWNER_SQL, plantInWorkspace, plantTeam, TEAM_MARKER, tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let dir: TenantDirectory;
let router: TenantRouter;
let A: string;
let B: string;

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? (e as Error).name;
  }
}

before(async () => {
  db = await tenantTestDb();
  await plantTeam(db);
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  router = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt') });
  A = ((await dir.provision('github:201')) as { tenantId: string }).tenantId;
  B = ((await dir.provision('github:202')) as { tenantId: string }).tenantId;
  await plantInWorkspace(db, A, 'wombatworkspacea');
});
after(async () => db.close());

test('tenants: the owner SQL is idempotent; neither workspace login can touch schema zeusi or holds a team group', async () => {
  await asOwner(db, async () => {
    await db.exec(readFileSync(OWNER_SQL, 'utf8'));
    const r = (await db.query<{ rolname: string; rolinherit: boolean; rolcreaterole: boolean; rolsuper: boolean; rolbypassrls: boolean; rolcreatedb: boolean }>(
      `SELECT rolname, rolinherit, rolcreaterole, rolsuper, rolbypassrls, rolcreatedb FROM pg_roles WHERE rolname IN ('zeusi_tenant_admin', 'zeusi_tenant_rt') ORDER BY 1`)).rows;
    assert.deepEqual(r, [
      { rolname: 'zeusi_tenant_admin', rolinherit: false, rolcreaterole: true, rolsuper: false, rolbypassrls: false, rolcreatedb: false },
      { rolname: 'zeusi_tenant_rt', rolinherit: false, rolcreaterole: false, rolsuper: false, rolbypassrls: false, rolcreatedb: false },
    ]);
    for (const login of ['zeusi_tenant_admin', 'zeusi_tenant_rt']) {
      assert.equal((await db.query<{ u: boolean }>(`SELECT has_schema_privilege($1::text, 'zeusi', 'USAGE') AS u`, [login])).rows[0]!.u, false, login);
      for (const g of ['zeusi_read', 'zeusi_ingest', 'zeusi_agent_write', 'zeusi_backup', 'zeusi_decision_write']) {
        assert.equal((await db.query<{ m: boolean }>(`SELECT pg_has_role($1::text, $2::text, 'MEMBER') AS m`, [login, g])).rows[0]!.m, false, `${login} in ${g}`);
      }
    }
  });
});

test('tenants: ids are zt_ + 26 base32; provisioning creates a schema, a role and catalog rows; the same subject reuses', async () => {
  for (let i = 0; i < 50; i++) assert.match(newTenantId(), TENANT_ID_RE);
  assert.match(A, TENANT_ID_RE);
  assert.notEqual(A, B);
  const again = await dir.provision('github:201');
  assert.deepEqual(again, { kind: 'existing', tenantId: A, status: 'active' });
  assert.deepEqual(await dir.lookup('github:201'), { tenantId: A, status: 'active' });
  assert.equal(await dir.lookup('github:999999'), null);
  await asOwner(db, async () => {
    const m = (await db.query<{ subject: string; tenant_id: string }>(`SELECT subject, tenant_id FROM zeusi_tenants.members ORDER BY 1`)).rows;
    assert.deepEqual(m, [{ subject: 'github:201', tenant_id: A }, { subject: 'github:202', tenant_id: B }]);
    const role = (await db.query<{ rolcanlogin: boolean; rolinherit: boolean }>(`SELECT rolcanlogin, rolinherit FROM pg_roles WHERE rolname = $1`, [`${A}_r`])).rows[0]!;
    assert.deepEqual(role, { rolcanlogin: false, rolinherit: false });
    // The runtime login may SET ROLE to it, never inherits it.
    const g = (await db.query<{ inh: boolean; st: boolean }>(
      `SELECT m.inherit_option AS inh, m.set_option AS st FROM pg_auth_members m WHERE m.roleid = $1::text::regrole AND m.member = 'zeusi_tenant_rt'::regrole`, [`${A}_r`])).rows[0]!;
    assert.deepEqual(g, { inh: false, st: true });
  });
});

test('tenants: a subject already in the catalog is reused inside the provisioning transaction (the race path); bad subjects are refused', async () => {
  await assert.rejects(dir.provision('github:abc'), TenantRefused);
  await assert.rejects(dir.lookup('open-user'), TenantRefused);
  await assert.rejects(dir.provision('github:1; DROP SCHEMA zeusi'), TenantRefused);
  // Concurrent provisioning is serialised by pg_advisory_xact_lock (one PGlite connection cannot show
  // two sessions); the re-check under that lock is what a loser of the race takes:
  const before0 = await asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int n FROM zeusi_tenants.tenants`)).rows[0]!.n);
  const r = await dir.provision('github:202');
  assert.deepEqual(r, { kind: 'existing', tenantId: B, status: 'active' });
  assert.equal(await asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int n FROM zeusi_tenants.tenants`)).rows[0]!.n), before0);
});

test('tenants: the total cap refuses a new workspace and creates nothing (no schema, role or catalog row)', async () => {
  const count = () => asOwner(db, async () => (await db.query<{ t: number; n: number; r: number }>(
    `SELECT (SELECT count(*) FROM zeusi_tenants.tenants)::int t, (SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'zt\\_%')::int n,
            (SELECT count(*) FROM pg_roles WHERE rolname LIKE 'zt\\_%')::int r`)).rows[0]!);
  const c0 = await count();
  const capped = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin'), maxTenants: c0.t });
  assert.deepEqual(await capped.provision('github:303'), { kind: 'cap_reached' });
  assert.deepEqual(await count(), c0);
  // A returning subject is still served under the cap.
  assert.deepEqual(await capped.provision('github:201'), { kind: 'existing', tenantId: A, status: 'active' });
});

test('tenants: the provisioner refuses a session that is not exactly zeusi_tenant_admin, or one that can read zeusi', async () => {
  const wrong = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_rt') });
  await assert.rejects(wrong.provision('github:404'), (e: unknown) => e instanceof TenantError && /provisioner session refused/.test((e as Error).message));
  await asOwner(db, () => db.exec('GRANT USAGE ON SCHEMA zeusi TO zeusi_tenant_admin'));
  try {
    await assert.rejects(dir.provision('github:405'), (e: unknown) => e instanceof TenantError && /the zeusi schema/.test((e as Error).message));
  } finally {
    await asOwner(db, () => db.exec('REVOKE USAGE ON SCHEMA zeusi FROM zeusi_tenant_admin'));
  }
  const down = new TenantDirectory({ connectAdmin: async () => { throw new Error('ECONNREFUSED db.internal:5432 password=hunter2'); } });
  await assert.rejects(down.lookup('github:1'), (e: unknown) => e instanceof TenantError && !/hunter2|db\.internal/.test((e as Error).message));
});

test('tenants: a workspace session is exactly its role, read-only, and reads only its own schema through the translating Db', async () => {
  const s = await router.open(A);
  try {
    const who = (await s.query<{ cu: string; su: string; ro: string }>(`SELECT current_user::text cu, session_user::text su, current_setting('transaction_read_only') ro`)).rows[0]!;
    assert.deepEqual(who, { cu: `${A}_r`, su: 'zeusi_tenant_rt', ro: 'on' });
    // `zeusi.` is rewritten to the workspace schema: A's own row, never the zeusi schema's.
    const notes = (await s.query<{ body: string }>(`SELECT body FROM zeusi.notes`)).rows.map((r) => r.body);
    assert.deepEqual(notes, ['own body wombatworkspacea']);
    assert.equal(await code(s.query(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('x', 'y', 'manual')`)), '25006', 'read-only transaction');
  } finally {
    await s.close();
  }
});

test('tenants: as a workspace role, the team, the catalog and another workspace are denied by privilege, whatever the search_path', async () => {
  const conn = asLogin(db, 'zeusi_tenant_rt');
  const raw = await conn();
  try {
    await raw.exec(`SET ROLE "${B}_r"`);
    for (const sql of [
      'SELECT * FROM zeusi.notes', 'SELECT * FROM zeusi.chunks', 'SELECT * FROM zeusi.facts_current', 'SELECT * FROM zeusi.decisions_current',
      'SELECT * FROM zeusi.decisions WHERE id = 1', 'SELECT zeusi.wall_audit()', `SELECT * FROM zeusi_tenants.members`, `SELECT * FROM zeusi_tenants.tenants`,
      `SELECT * FROM "${A}".notes`, `SELECT "${A}".wall_audit()`, `SELECT * FROM "${B}".schema_migrations`, `SELECT * FROM "${B}".wall_denylist`,
    ]) {
      assert.equal(await code(raw.query(sql)), '42501', sql);
    }
    // search_path tricks: an unqualified name never resolves into a schema without USAGE.
    for (const sp of ['zeusi', `zeusi, "${A}"`, `"${A}"`, 'zeusi_tenants']) {
      await raw.exec(`SET search_path = ${sp}`);
      const c = await code(raw.query('SELECT * FROM notes'));
      assert.ok(c === '42P01' || c === '42501', `${sp}: ${c}`);
    }
    // Switching to a team role or the owner is not possible from this login.
    for (const r of ['zeusi_read', 'zeusi_box_ro', 'zeusi_tenant_admin', 'postgres']) assert.equal(await code(raw.exec(`SET ROLE ${r}`)), '42501', r);
    // No leak by text either: nothing a workspace role can select holds the team marker.
    await raw.exec(`SET search_path = "${B}", public`);
    const hits = (await raw.query<{ n: number }>(`SELECT count(*)::int n FROM "${B}".chunks WHERE text LIKE '%' || $1 || '%'`, [TEAM_MARKER])).rows[0]!.n;
    assert.equal(hits, 0);
  } finally {
    await raw.close();
  }
});

test('tenants: the router refuses a malformed id before connecting, an unknown or disabled workspace, and a session with extra privileges', async () => {
  const log: string[] = [];
  const counted = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt', log) });
  for (const bad of ['zeusi', 'work', 'zt_short', `${A}; DROP SCHEMA zeusi`, `ZT_${'A'.repeat(26)}`]) {
    await assert.rejects(counted.open(bad), TenantRefused, bad);
    assert.equal(await counted.check(bad), 'unknown', bad);
  }
  assert.deepEqual(log, [], 'no connection for a malformed id');
  const unknown = `zt_${'q'.repeat(26)}`;
  await assert.rejects(router.open(unknown), TenantRefused);
  assert.equal(await router.check(unknown), 'unknown');

  for (const [grant, revoke] of [
    ['GRANT USAGE ON SCHEMA zeusi TO', 'REVOKE USAGE ON SCHEMA zeusi FROM'],
    [`GRANT INSERT ON "${A}".notes TO`, `REVOKE INSERT ON "${A}".notes FROM`],
    [`GRANT USAGE ON SCHEMA "${B}" TO`, `REVOKE USAGE ON SCHEMA "${B}" FROM`],
    ['GRANT USAGE ON SCHEMA zeusi_tenants TO', 'REVOKE USAGE ON SCHEMA zeusi_tenants FROM'],
  ] as const) {
    await asOwner(db, () => db.exec(`${grant} "${A}_r"`));
    try {
      await assert.rejects(router.open(A), (e: unknown) => e instanceof TenantRefused && /session refused/.test((e as Error).message), grant);
    } finally {
      await asOwner(db, () => db.exec(`${revoke} "${A}_r"`));
    }
  }
  // A session under a different login is refused too (session_user must be the runtime login).
  const viaAdmin = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_admin') });
  await assert.rejects(viaAdmin.open(A));

  await asOwner(db, () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'disabled' WHERE tenant_id = $1`, [B]));
  try {
    await assert.rejects(router.open(B), TenantRefused);
    assert.equal(await router.check(B), 'unknown');
    assert.deepEqual(await dir.lookup('github:202'), { tenantId: B, status: 'disabled' });
  } finally {
    await asOwner(db, () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'active' WHERE tenant_id = $1`, [B]));
  }
});

test('tenants: check() caches an active answer for a short time only; a runtime outage is a TenantError without detail', async () => {
  let t = 1_000_000;
  const log: string[] = [];
  const r = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt', log), now: () => t, cacheMs: 1000 });
  assert.equal(await r.check(A), 'active');
  assert.equal(await r.check(A), 'active');
  assert.equal(log.length, 1, 'second answer from the cache');
  t += 1001;
  assert.equal(await r.check(A), 'active');
  assert.equal(log.length, 2);
  const down = new TenantRouter({ connectRuntime: async () => { throw new Error('ECONNREFUSED secret-host password=hunter2'); } });
  await assert.rejects(down.check(A), (e: unknown) => e instanceof TenantError && !/hunter2|secret-host/.test((e as Error).message));
  await assert.rejects(down.open(A), TenantError);
});

test('tenants: translateSql rewrites zeusi. qualifiers and the schema literal only', () => {
  assert.equal(translateSql(`SELECT 1 FROM zeusi.notes n JOIN zeusi.people p ON true WHERE t.schemaname = 'zeusi' AND x = 'mcp.zeusi.dev'`, A),
    `SELECT 1 FROM ${A}.notes n JOIN ${A}.people p ON true WHERE t.schemaname = '${A}' AND x = 'mcp.zeusi.dev'`);
  assert.throws(() => translateSql('SELECT 1', 'zeusi'));
  const seen: string[] = [];
  const fake: Db = { label: 'x', query: async (sql) => { seen.push(sql); return { rows: [] }; }, exec: async (sql) => { seen.push(sql); }, close: async () => {} };
  const t = schemaTranslatingDb(fake, A);
  void t.query('SELECT * FROM zeusi.chunks');
  void t.exec('BEGIN READ ONLY');
  assert.deepEqual(seen, [`SELECT * FROM ${A}.chunks`, 'BEGIN READ ONLY']);
  assert.equal(t.label, 'personal workspace session');
});
