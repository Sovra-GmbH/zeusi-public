// C6 KTD2 (docs/plans/2026-11-19-c6-write-path.md): migration 0016 grants the runtime login SELECT (enc_state) on
// the catalog, the same column privilege the provisioner's ensure path (src/tenants.ts CONTROL_DDL) now grants.
// Pinned like 0014 / 0015 (test/c3-catalog.test.ts, test/c4-catalog.test.ts): catalog DDL, never workspace DDL;
// on a C5 catalog it is the one pending file and gives the same catalog as the ensure path; re-runs are no-ops;
// a runner without SET is refused; skip paths; ROLLBACK-0016.md returns the C5 ACL. PGlite only; nothing live.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { listMigrations, migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { TENANT_EXCLUDED_FILES, tenantDdl } from '../src/tenant-ddl.ts';
import { TenantDirectory, TenantRouter, TENANT_RT_COLUMNS } from '../src/tenants.ts';
import { pgliteDb } from './pglite-db.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, OWNER_SQL } from './helpers/tenant-fixture.ts';

const MIG16 = '0016_catalog_rt_enc_state.sql';
const MIG16_SQL = readFileSync(join(MIGRATIONS_DIR, MIG16), 'utf8');
/** docs/plans/2026-11-19-c4-webauthn-verify.md KTD5: the next catalog file (a no-op where the ensure path ran). */
const MIG17 = '0017_key_wraps_webauthn.sql';
const REVOKE = 'SET ROLE zeusi_tenant_admin; REVOKE SELECT (enc_state) ON zeusi_tenants.tenants FROM zeusi_tenant_rt; RESET ROLE';

function subsetDir(keep: (name: string) => boolean): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-mig16-'));
  for (const f of listMigrations()) if (keep(f.name)) copyFileSync(join(MIGRATIONS_DIR, f.name), join(d, f.name));
  return d;
}

/** Owners and every ACL of the catalog, column ACLs included (names and grants only, never rows). */
async function aclShape(d: Db): Promise<unknown> {
  return asOwner(d, async () => ({
    rels: (await d.query(`SELECT c.relname::text AS rel, c.relowner::regrole::text AS owner, c.relacl::text AS acl
                            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'zeusi_tenants' ORDER BY 1`)).rows,
    cols: (await d.query(`SELECT c.relname::text AS rel, a.attname::text AS col, a.attacl::text AS acl
                            FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                           WHERE n.nspname = 'zeusi_tenants' AND a.attnum > 0 AND a.attacl IS NOT NULL ORDER BY 1, 2`)).rows,
  }));
}

/** A DB at 0015 with the logins and a catalog made by the ensure path, minus the 0016 grant (a C5 catalog). */
async function c5Catalog(): Promise<Db> {
  const d = await pgliteDb();
  await migrate(d, { dir: subsetDir((n) => n < MIG16) });
  await d.exec(readFileSync(OWNER_SQL, 'utf8'));
  await new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') }).provision('github:1601');
  await asOwner(d, () => d.exec(REVOKE));
  return d;
}

test('C6 0016: catalog DDL, excluded from workspaces; on a C5 catalog: pending exactly 0016, snapshot flag, same catalog as the ensure path; re-runs no-op', async () => {
  assert.ok(TENANT_EXCLUDED_FILES.includes(MIG16));
  const ddl = tenantDdl('zt_dddddddddddddddddddddddddd');
  assert.ok(!ddl.applied.some((a) => a.name === MIG16));
  assert.ok(!ddl.statements.some((s) => /zeusi_tenants|enc_state/.test(s)));
  assert.deepEqual([...TENANT_RT_COLUMNS], ['tenant_id', 'status', 'enc_state']);
  const ensured = await pgliteDb();
  const d = await c5Catalog();
  try {
    await migrate(ensured);
    await ensured.exec(readFileSync(OWNER_SQL, 'utf8'));
    await new TenantDirectory({ connectAdmin: asLogin(ensured, 'zeusi_tenant_admin') }).lookup('github:1602');
    const c5 = await aclShape(d);
    assert.notDeepEqual(c5, await aclShape(ensured), 'the C5 catalog lacks the grant');
    const rt = new TenantRouter({ connectRuntime: asLogin(d, 'zeusi_tenant_rt'), cacheMs: 0 });
    const t = await asOwner(d, async () => (await d.query<{ t: string }>('SELECT tenant_id AS t FROM zeusi_tenants.tenants LIMIT 1')).rows[0]!.t);
    await assert.rejects(rt.encState(t), (e: Error) => e.name === 'TenantError', 'before 0016 the state read fails (writes refuse: fail closed)');
    assert.deepEqual((await migrate(d, { dryRun: true })).pending, [MIG16, MIG17]);
    await assert.rejects(migrate(d), /snapshot/);
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, [MIG16, MIG17]);
    assert.deepEqual(await aclShape(d), await aclShape(ensured), 'the migration and the ensure path give the same catalog');
    assert.deepEqual(await rt.encState(t), { status: 'active', encState: 'off' });
    assert.equal(await asOwner(d, async () => (await d.query<{ u: string }>('SELECT current_user::text AS u')).rows[0]!.u), 'postgres', 'role reset');
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, []);
    await asOwner(d, () => d.exec(MIG16_SQL));
    await new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') }).lookup('github:1603');
    assert.deepEqual(await aclShape(d), await aclShape(ensured), 'replaying 0016 or the ensure path changes nothing');
  } finally {
    await d.close();
    await ensured.close();
  }
});

test('C6 0016: a runner without SET is refused and nothing changes; skips with no role or no catalog; ROLLBACK-0016.md restores the C5 ACL', async () => {
  const bare = await pgliteDb();
  try {
    assert.ok((await migrate(bare)).applied.includes(MIG16), 'no tenant roles: recorded, nothing granted');
  } finally {
    await bare.close();
  }
  const early = await pgliteDb();
  try {
    await migrate(early, { dir: subsetDir((n) => n < MIG16) });
    await early.exec(readFileSync(OWNER_SQL, 'utf8'));
    assert.deepEqual((await migrate(early, { tookSnapshot: true })).applied, [MIG16, MIG17], 'no catalog yet: recorded, skipped');
  } finally {
    await early.close();
  }
  const d = await c5Catalog();
  try {
    const c5 = await aclShape(d);
    await asOwner(d, () => d.exec('CREATE ROLE c6_noset LOGIN NOSUPERUSER; CREATE ROLE c6_set LOGIN NOSUPERUSER; GRANT zeusi_tenant_admin TO c6_set WITH INHERIT FALSE, SET TRUE'));
    await d.exec('SET SESSION AUTHORIZATION c6_noset');
    await assert.rejects(d.exec(MIG16_SQL), /cannot SET ROLE zeusi_tenant_admin/);
    assert.deepEqual(await aclShape(d), c5, 'refused: nothing changed');
    await d.exec('SET SESSION AUTHORIZATION c6_set');
    await d.exec(MIG16_SQL);
    const full = await aclShape(d);
    assert.notDeepEqual(full, c5);
    assert.ok(JSON.stringify(full).includes('zeusi_tenant_rt=r/zeusi_tenant_admin'), 'granted by the catalog owner');
    // Converged: the runner WITHOUT SET now passes (no-op, no role switch).
    await d.exec('SET SESSION AUTHORIZATION c6_noset');
    await d.exec(MIG16_SQL);
    // Rollback runbook.
    const md = readFileSync(join(MIGRATIONS_DIR, 'ROLLBACK-0016.md'), 'utf8');
    const sql = /## SQL\s+```sql\n([\s\S]*?)```/.exec(md)?.[1];
    assert.ok(sql);
    await asOwner(d, () => d.exec(sql));
    assert.deepEqual(await aclShape(d), c5);
    assert.equal(await asOwner(d, async () => (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.schema_migrations WHERE filename = $1`, [MIG16])).rows[0]!.n), 0);
  } finally {
    await d.close();
  }
});
