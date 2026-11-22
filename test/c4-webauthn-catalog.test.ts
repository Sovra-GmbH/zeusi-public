// docs/plans/2026-11-19-c4-webauthn-verify.md KTD5 / KTD6: migration 0017 (key_wraps.webauthn_public_key +
// webauthn_sign_count + key_wraps_webauthn_check) and its ensure-path twin (src/tenants.ts KEY_WRAP_WEBAUTHN_ALTER).
// Pinned like 0014..0016: catalog DDL, never workspace DDL; the migration and the ensure path run the SAME
// statement and give the same catalog; on a 0016 catalog it is the one pending file; re-runs are no-ops; a runner
// without SET is refused; skip paths; ROLLBACK-0017.md returns the 0016 shape. Plus the CHECK, the counter
// compare-and-swap and the read of the stored key. PGlite only; every key byte is a TEST pattern; nothing live.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { listMigrations, migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { TENANT_EXCLUDED_FILES, tenantDdl } from '../src/tenant-ddl.ts';
import { CONTROL_SCHEMA, KEY_WRAP_WEBAUTHN_ALTER, TenantDirectory } from '../src/tenants.ts';
import { enrollmentWraps } from '../src/workspace-keys.ts';
import { pgliteDb } from './pglite-db.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, OWNER_SQL, tenantTestDb } from './helpers/tenant-fixture.ts';

const MIG17 = '0017_key_wraps_webauthn.sql';
const MIG17_SQL = readFileSync(join(MIGRATIONS_DIR, MIG17), 'utf8');

/** The catalog exactly as CONTROL_DDL made it before C3 (as test/c3-catalog.test.ts builds it). */
const LEGACY_CONTROL_DDL = `
CREATE SCHEMA IF NOT EXISTS zeusi_tenants;
CREATE TABLE IF NOT EXISTS zeusi_tenants.tenants (
  tenant_id  text PRIMARY KEY CHECK (tenant_id ~ '^zt_[a-z2-7]{26}$'),
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS zeusi_tenants.members (
  subject    text PRIMARY KEY CHECK (subject ~ '^github:[0-9]{1,20}$'),
  tenant_id  text NOT NULL UNIQUE REFERENCES zeusi_tenants.tenants(tenant_id),
  created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON SCHEMA zeusi_tenants FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA zeusi_tenants FROM PUBLIC;
GRANT USAGE ON SCHEMA zeusi_tenants TO zeusi_tenant_rt;
GRANT SELECT (tenant_id, status) ON zeusi_tenants.tenants TO zeusi_tenant_rt;
`;

function subsetDir(keep: (name: string) => boolean): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-mig17-'));
  for (const f of listMigrations()) if (keep(f.name)) copyFileSync(join(MIGRATIONS_DIR, f.name), join(d, f.name));
  return d;
}

/** A genuine 0016 catalog: a pre-C3 catalog upgraded by 0014, 0015 and 0016 (no WebAuthn columns). */
async function catalog0016(): Promise<Db> {
  const d = await pgliteDb();
  await migrate(d, { dir: subsetDir((n) => n < '0014') });
  await d.exec(readFileSync(OWNER_SQL, 'utf8'));
  await d.exec('SET SESSION AUTHORIZATION zeusi_tenant_admin');
  await d.exec(LEGACY_CONTROL_DDL);
  await d.exec('RESET ROLE; SET SESSION AUTHORIZATION postgres');
  await migrate(d, { dir: subsetDir((n) => n < MIG17), tookSnapshot: true });
  return d;
}

/** A fresh catalog made by the ensure path only (every migration recorded first, all of them skipped). */
async function ensured(): Promise<Db> {
  const d = await pgliteDb();
  await migrate(d);
  await d.exec(readFileSync(OWNER_SQL, 'utf8'));
  await new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') }).lookup('github:1701');
  return d;
}

/** Shape, constraints, owners and every ACL of the catalog (as test/c3-catalog.test.ts fingerprint). */
async function fingerprint(d: Db): Promise<unknown> {
  return asOwner(d, async () => ({
    schema: (await d.query(`SELECT nspowner::regrole::text AS owner, nspacl::text AS acl FROM pg_namespace WHERE nspname = 'zeusi_tenants'`)).rows,
    rels: (await d.query(
      `SELECT c.relname::text AS rel, c.relkind::text AS kind, c.relowner::regrole::text AS owner, c.relacl::text AS acl
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'zeusi_tenants' ORDER BY 1`)).rows,
    cols: (await d.query(
      `SELECT c.relname::text AS rel, a.attnum::int AS n, a.attname::text AS col, format_type(a.atttypid, a.atttypmod) AS type,
              a.attnotnull AS notnull, pg_get_expr(ad.adbin, ad.adrelid) AS def, a.attacl::text AS acl
         FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
         LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE n.nspname = 'zeusi_tenants' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY 1, 2`)).rows,
    cons: (await d.query(
      `SELECT conrelid::regclass::text AS rel, conname::text AS name, pg_get_constraintdef(oid) AS def
         FROM pg_constraint WHERE connamespace = 'zeusi_tenants'::regnamespace ORDER BY 1, 2`)).rows,
  }));
}

const webauthnCols = (d: Db) => asOwner(d, async () => (await d.query<{ c: string }>(
  `SELECT a.attname::text AS c FROM pg_attribute a WHERE a.attrelid = 'zeusi_tenants.key_wraps'::regclass AND a.attname LIKE 'webauthn_%' AND NOT a.attisdropped ORDER BY 1`)).rows.map((r) => r.c));

test('0017: catalog DDL, excluded from workspaces; the migration runs the SAME statement as the ensure path (one rule)', () => {
  assert.ok(TENANT_EXCLUDED_FILES.includes(MIG17));
  const ddl = tenantDdl('zt_dddddddddddddddddddddddddd');
  assert.ok(!ddl.applied.some((a) => a.name === MIG17));
  assert.ok(!ddl.statements.some((s) => /zeusi_tenants|webauthn/.test(s)));
  assert.equal(CONTROL_SCHEMA, 'zeusi_tenants');
  // mutant: edit either copy of the ALTER (a bound, a column, the CHECK) -> red.
  assert.ok(MIG17_SQL.includes(`  ${KEY_WRAP_WEBAUTHN_ALTER};`), 'migrations/0017 holds src/tenants.ts KEY_WRAP_WEBAUTHN_ALTER verbatim');
  assert.doesNotMatch(MIG17_SQL, /\b(DROP|DELETE|UPDATE|INSERT|GRANT|TRUNCATE)\b/, 'additive only: no drop, no row change, no grant');
});

test('0017 on a 0016 catalog: pending exactly 0017, snapshot flag, same catalog as the ensure path; re-runs and the ensure path are no-ops', async () => {
  const d = await catalog0016();
  const e = await ensured();
  try {
    assert.deepEqual(await webauthnCols(d), [], 'a genuine 0016 catalog has no WebAuthn columns');
    assert.notDeepEqual(await fingerprint(d), await fingerprint(e));
    const lines: string[] = [];
    assert.deepEqual((await migrate(d, { dryRun: true, log: (l) => lines.push(l) })).pending, [MIG17]);
    assert.deepEqual(lines, [`pending: ${MIG17}`]);
    await assert.rejects(migrate(d), /snapshot/);
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, [MIG17]);
    const via = await fingerprint(d);
    assert.deepEqual(via, await fingerprint(e), 'the migration and the ensure path give the same catalog');
    assert.equal(await asOwner(d, async () => (await d.query<{ u: string }>('SELECT current_user::text AS u')).rows[0]!.u), 'postgres', 'role reset');
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, []);
    await asOwner(d, () => d.exec(MIG17_SQL));
    await new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') }).lookup('github:1702');
    assert.deepEqual(await fingerprint(d), via, 'replaying 0017 or the ensure path changes nothing');
  } finally {
    await d.close();
    await e.close();
  }
});

test('0017 ensure path on a 0016 catalog: adds the columns (bounded lock wait restored), existing wraps read null key / null counter; idempotent', async () => {
  const d = await catalog0016();
  try {
    const dir = new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') });
    const lt0 = (await d.query<{ v: string }>(`SELECT current_setting('lock_timeout') AS v`)).rows[0]!.v;
    assert.equal(await dir.lookup('github:1703'), null);
    assert.equal((await d.query<{ v: string }>(`SELECT current_setting('lock_timeout') AS v`)).rows[0]!.v, lt0);
    assert.deepEqual(await webauthnCols(d), ['webauthn_public_key', 'webauthn_sign_count']);
    const once = await fingerprint(d);
    await dir.lookup('github:1704');
    assert.deepEqual(await fingerprint(d), once, 'converged');
  } finally {
    await d.close();
  }
});

test('0017: a runner without SET is refused and nothing changes; skips with no role, no catalog, or no key_wraps; ROLLBACK-0017.md returns the 0016 shape and 0017 re-applies', async () => {
  const bare = await pgliteDb();
  try {
    assert.ok((await migrate(bare)).applied.includes(MIG17), 'no tenant roles: recorded, nothing created');
  } finally {
    await bare.close();
  }
  const early = await pgliteDb();
  try {
    await migrate(early, { dir: subsetDir((n) => n < MIG17) });
    await early.exec(readFileSync(OWNER_SQL, 'utf8'));
    assert.deepEqual((await migrate(early, { tookSnapshot: true })).applied, [MIG17], 'no catalog yet: recorded, skipped');
    // a catalog (pre-C3) without key_wraps: skipped, nothing created
    await early.exec('SET SESSION AUTHORIZATION zeusi_tenant_admin');
    await early.exec(LEGACY_CONTROL_DDL);
    await early.exec('RESET ROLE; SET SESSION AUTHORIZATION postgres');
    await early.exec(MIG17_SQL);
    assert.equal((await early.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_class WHERE relname = 'key_wraps'`)).rows[0]!.n, 0);
  } finally {
    await early.close();
  }
  const d = await catalog0016();
  try {
    const c16 = await fingerprint(d);
    await asOwner(d, () => d.exec('CREATE ROLE c17_noset LOGIN NOSUPERUSER; CREATE ROLE c17_set LOGIN NOSUPERUSER; GRANT zeusi_tenant_admin TO c17_set WITH INHERIT FALSE, SET TRUE'));
    await d.exec('SET SESSION AUTHORIZATION c17_noset');
    await d.exec('BEGIN');
    await assert.rejects(d.exec(MIG17_SQL), /cannot SET ROLE zeusi_tenant_admin/);
    await d.exec('ROLLBACK');
    assert.deepEqual(await fingerprint(d), c16, 'refused: nothing changed');
    await d.exec('SET SESSION AUTHORIZATION c17_set');
    await d.exec('BEGIN');
    await d.exec(MIG17_SQL);
    assert.equal((await d.query<{ u: string }>('SELECT current_user::text AS u')).rows[0]!.u, 'c17_set', 'RESET ROLE before the runner records the file');
    await d.exec('COMMIT');
    assert.deepEqual(await webauthnCols(d), ['webauthn_public_key', 'webauthn_sign_count']);
    assert.ok(JSON.stringify(await fingerprint(d)).includes('key_wraps_webauthn_check'));
    // converged: the runner WITHOUT SET passes (no-op, no role switch)
    await d.exec('SET SESSION AUTHORIZATION c17_noset');
    await d.exec(MIG17_SQL);
    await d.exec('RESET ROLE; SET SESSION AUTHORIZATION postgres');
    // rollback runbook
    const md = readFileSync(join(MIGRATIONS_DIR, 'ROLLBACK-0017.md'), 'utf8');
    const sql = /## SQL\s+```sql\n([\s\S]*?)```/.exec(md)?.[1];
    assert.ok(sql);
    await asOwner(d, () => d.exec(sql));
    assert.deepEqual(await fingerprint(d), c16, 'ROLLBACK-0017 returns the 0016 shape');
    await asOwner(d, () => d.exec(MIG17_SQL));
    assert.deepEqual(await webauthnCols(d), ['webauthn_public_key', 'webauthn_sign_count'], '0017 re-applies');
  } finally {
    await d.close();
  }
  // a catalog owned by anyone else is refused
  const other = await pgliteDb();
  try {
    await migrate(other, { dir: subsetDir((n) => n < '0014') });
    await other.exec(readFileSync(OWNER_SQL, 'utf8'));
    await other.exec('CREATE SCHEMA zeusi_tenants');
    await assert.rejects(other.exec(MIG17_SQL), /not owned by zeusi_tenant_admin/);
  } finally {
    await other.close();
  }
});

// ------------------------------------------------------------------------------ CHECK, CAS, read

let db: Db;
let dir: TenantDirectory;
before(async () => {
  db = await tenantTestDb({ writer: true });
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
});
after(async () => db.close());

const SEALED = () => Buffer.concat([Buffer.of(0x01), Buffer.alloc(60, 0x5a)]);
async function ins(o: { tenant: string; kind?: string; key?: Buffer | null; count?: string | null }): Promise<string> {
  return asOwner(db, async () => {
    await db.exec('BEGIN');
    try {
      const passkey = (o.kind ?? 'passkey') === 'passkey';
      await db.query(
        `INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek, credential_id, prf_salt, webauthn_public_key, webauthn_sign_count)
         VALUES ($1, 'w-17', $2, 1, $3, $4, $5, $6, $7::bigint)`,
        [o.tenant, o.kind ?? 'passkey', SEALED(), passkey ? Buffer.from('cred-17') : null, passkey ? Buffer.alloc(32, 3) : null, o.key ?? null, o.count ?? null]);
      return 'ok';
    } catch (e) {
      return (e as { code?: string }).code ?? (e as Error).message;
    } finally {
      await db.exec('ROLLBACK');
    }
  });
}

test('0017 CHECK: both null (recovery, or a legacy passkey) or a passkey with a 1..1024-byte key and a 0..2^32-1 counter; anything else refused', async () => {
  const t = ((await dir.provision('github:1710')) as { tenantId: string }).tenantId;
  const K = Buffer.alloc(77, 0x42);
  assert.equal(await ins({ tenant: t, key: K, count: '0' }), 'ok');
  assert.equal(await ins({ tenant: t, key: Buffer.alloc(1024, 1), count: '4294967295' }), 'ok');
  assert.equal(await ins({ tenant: t }), 'ok', 'a legacy passkey row (both null)');
  assert.equal(await ins({ tenant: t, kind: 'recovery' }), 'ok');
  assert.equal(await ins({ tenant: t, key: K, count: null }), '23514', 'key without counter');
  assert.equal(await ins({ tenant: t, key: null, count: '1' }), '23514', 'counter without key');
  assert.equal(await ins({ tenant: t, key: Buffer.alloc(0), count: '1' }), '23514', 'empty key');
  assert.equal(await ins({ tenant: t, key: Buffer.alloc(1025, 1), count: '1' }), '23514', 'key over 1024 bytes');
  assert.equal(await ins({ tenant: t, key: K, count: '-1' }), '23514', 'negative counter');
  assert.equal(await ins({ tenant: t, key: K, count: '4294967296' }), '23514', 'counter over 2^32-1');
  assert.equal(await ins({ tenant: t, kind: 'recovery', key: K, count: '1' }), '23514', 'a recovery row never holds a WebAuthn key');
});

test('enroll stores the WebAuthn key and counter; wrapsFor reads them; advanceSignCount is a compare-and-swap (mutant: drop the `= from` guard -> red)', async () => {
  const t = ((await dir.provision('github:1711')) as { tenantId: string }).tenantId;
  const u = ((await dir.provision('github:1712')) as { tenantId: string }).tenantId;
  const cred = Buffer.from('cred-cas-17');
  const salt = Buffer.alloc(32, 9);
  const key = Buffer.alloc(77, 0x24);
  const e = enrollmentWraps({ tenant: t, prfOutput: Buffer.alloc(32, 1), credentialId: cred, prfSalt: salt, newDek: () => Buffer.alloc(32, 2) });
  assert.equal(await dir.enroll(t, { passkey: { ...e.passkey, webauthn: { publicKey: key, signCount: 4 } }, recovery: e.recovery }), 'enrolled');
  const w = (await dir.wrapsFor(t, 'passkey'))[0]!;
  assert.deepEqual([w.webauthnPublicKey, w.webauthnSignCount], [key, 4]);
  const r = (await dir.wrapsFor(t, 'recovery'))[0]!;
  assert.deepEqual([r.webauthnPublicKey, r.webauthnSignCount], [null, null]);
  assert.equal(await dir.advanceSignCount(t, cred, 3, 9), false, 'stale `from`');
  assert.equal(await dir.advanceSignCount(t, cred, 4, 4), false, 'not an advance');
  assert.equal(await dir.advanceSignCount(t, cred, 4, 2), false, 'a regression');
  assert.equal(await dir.advanceSignCount(u, cred, 4, 9), false, 'another workspace');
  assert.equal(await dir.advanceSignCount(t, Buffer.from('other'), 4, 9), false, 'another credential');
  assert.equal(await dir.advanceSignCount(t, cred, 4, 0x1_0000_0000), false, 'over 2^32-1');
  assert.equal(await dir.advanceSignCount(t, cred, 4, 9), true);
  assert.equal((await dir.wrapsFor(t, 'passkey'))[0]!.webauthnSignCount, 9);
  assert.equal(await dir.advanceSignCount(t, cred, 4, 10), false, 'a concurrent unlock already moved it');
  // a disabled workspace: never
  await asOwner(db, () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'disabled' WHERE tenant_id = $1`, [t]));
  assert.equal(await dir.advanceSignCount(t, cred, 9, 10), false);
});
