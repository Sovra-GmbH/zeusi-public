// C3 (docs/plans/2026-11-18-c3-catalog-enc-state.md): catalog zeusi_tenants.key_wraps and
// tenants.enc_state. Hermetic: PGlite with the real migrations and the real owner SQL; logins are
// emulated with SET SESSION AUTHORIZATION (test/helpers/tenant-fixture.ts). No network, no Neon.
// Every wrap blob, credential id and salt below is a TEST byte pattern, never a production secret.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { listMigrations, migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { TENANT_EXCLUDED_FILES, tenantDdl } from '../src/tenant-ddl.ts';
import {
  ENC_STATES, KEY_WRAP_KINDS, KEY_WRAP_MAX_KEY_VERSION, KEY_WRAP_SEALED_BYTES, TenantDirectory, TenantRouter,
} from '../src/tenants.ts';
import { MAX_KEY_VERSION, wrapDek, unwrapDek, passkeyKek } from '../src/crypto-envelope.ts';
import { pgliteDb } from './pglite-db.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, OWNER_SQL, tenantTestDb, WRITER_OWNER_SQL } from './helpers/tenant-fixture.ts';

const MIG = '0014_catalog_key_wraps.sql';
const MIG_SQL = readFileSync(join(MIGRATIONS_DIR, MIG), 'utf8');
// C4 (docs/plans/2026-11-18-c4-enroll.md KTD1): the ensure path now also builds 0015's credential index,
// so "same catalog as the ensure path" holds for 0014 followed by 0015 (test/c4-catalog.test.ts covers 0015).
const MIG15 = '0015_key_wraps_credential_unique.sql';
const MIG15_SQL = readFileSync(join(MIGRATIONS_DIR, MIG15), 'utf8');
// C6 (docs/plans/2026-11-19-c6-write-path.md KTD2): the ensure path also grants the runtime login enc_state,
// so "same catalog as the ensure path" holds for 0014, 0015 and 0016 (test/c6-catalog.test.ts covers 0016).
const MIG16 = '0016_catalog_rt_enc_state.sql';
const MIG16_SQL = readFileSync(join(MIGRATIONS_DIR, MIG16), 'utf8');
// docs/plans/2026-11-19-c4-webauthn-verify.md KTD5: the ensure path also adds 0017's WebAuthn columns, so "same
// catalog as the ensure path" holds for 0014..0017 (test/c4-webauthn-catalog.test.ts covers 0017).
const MIG17 = '0017_key_wraps_webauthn.sql';
const MIG17_SQL = readFileSync(join(MIGRATIONS_DIR, MIG17), 'utf8');

/** The catalog exactly as CONTROL_DDL made it before C3 (src/tenants.ts at 0d29ff3). */
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
const T1 = 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa';
const T2 = 'zt_bbbbbbbbbbbbbbbbbbbbbbbbbb';

function subsetDir(keep: (name: string) => boolean): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-mig14-'));
  for (const f of listMigrations()) if (keep(f.name)) copyFileSync(join(MIGRATIONS_DIR, f.name), join(dir, f.name));
  return dir;
}

/** A DB at 0013 with the workspace logins and a pre-C3 catalog holding two workspaces (no zt_* schema needed). */
async function legacyDb(): Promise<Db> {
  const d = await pgliteDb();
  await migrate(d, { dir: subsetDir((n) => n < '0014') });
  await d.exec(readFileSync(OWNER_SQL, 'utf8'));
  await d.exec('SET SESSION AUTHORIZATION zeusi_tenant_admin');
  await d.exec(LEGACY_CONTROL_DDL);
  await d.query(`INSERT INTO zeusi_tenants.tenants (tenant_id, status, created_at) VALUES ($1, 'active', '2026-11-01T00:00:00Z'), ($2, 'disabled', '2026-11-02T00:00:00Z')`, [T1, T2]);
  await d.query(`INSERT INTO zeusi_tenants.members (subject, tenant_id, created_at) VALUES ('github:301', $1, '2026-11-01T00:00:00Z'), ('github:302', $2, '2026-11-02T00:00:00Z')`, [T1, T2]);
  await d.exec('RESET ROLE; SET SESSION AUTHORIZATION postgres');
  return d;
}

/** Shape, constraints, owners and every ACL of the catalog: names and definitions only, never rows. */
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

async function catalogRows(d: Db): Promise<unknown> {
  return asOwner(d, async () => ({
    tenants: (await d.query(`SELECT tenant_id, status, created_at::text AS created_at FROM zeusi_tenants.tenants ORDER BY 1`)).rows,
    members: (await d.query(`SELECT subject, tenant_id, created_at::text AS created_at FROM zeusi_tenants.members ORDER BY 1`)).rows,
  }));
}

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? (e as Error).message;
  }
}

// --------------------------------------------------------------------------- fresh catalog

let db: Db;
let dir: TenantDirectory;
let A: string;

before(async () => {
  db = await tenantTestDb({ writer: true });
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  A = ((await dir.provision('github:401')) as { tenantId: string }).tenantId;
});
after(async () => db.close());

const SEALED = (first = 0x01, len = KEY_WRAP_SEALED_BYTES) => Buffer.concat([Buffer.of(first), Buffer.alloc(len - 1, 0x5a)]);
const CRED = Buffer.from('test-credential-id-c3', 'utf8');
const SALT = Buffer.alloc(32, 0x33);

async function insWrap(d: Db, o: { tenant?: string; wrapId?: string; kind?: string; kv?: number; sealed?: Buffer; cred?: Buffer | null; salt?: Buffer | null }): Promise<string> {
  return asOwner(d, async () => {
    await d.exec('BEGIN');
    try {
      return await code(d.query(
        `INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek, credential_id, prf_salt) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [o.tenant ?? A, o.wrapId ?? 'w-1', o.kind ?? 'passkey', o.kv ?? 1, o.sealed ?? SEALED(),
          o.cred === undefined ? CRED : o.cred, o.salt === undefined ? SALT : o.salt]));
    } finally {
      await d.exec('ROLLBACK');
    }
  });
}

test('C3 fresh catalog: provisioning creates enc_state (default off) and an empty key_wraps, both owned by zeusi_tenant_admin', async () => {
  await asOwner(db, async () => {
    assert.deepEqual((await db.query(`SELECT enc_state FROM zeusi_tenants.tenants WHERE tenant_id = $1`, [A])).rows, [{ enc_state: 'off' }]);
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi_tenants.key_wraps`)).rows[0]!.n, 0);
    const own = (await db.query<{ rel: string; owner: string }>(
      `SELECT c.relname::text AS rel, c.relowner::regrole::text AS owner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'zeusi_tenants' AND c.relkind = 'r' ORDER BY 1`)).rows;
    assert.deepEqual(own, [
      { rel: 'key_wraps', owner: 'zeusi_tenant_admin' }, { rel: 'members', owner: 'zeusi_tenant_admin' }, { rel: 'tenants', owner: 'zeusi_tenant_admin' }]);
    const cols = (await db.query<{ col: string; type: string; notnull: boolean }>(
      `SELECT a.attname::text AS col, format_type(a.atttypid, a.atttypmod) AS type, a.attnotnull AS notnull FROM pg_attribute a
        WHERE a.attrelid = 'zeusi_tenants.key_wraps'::regclass AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`)).rows;
    assert.deepEqual(cols, [
      { col: 'tenant_id', type: 'text', notnull: true },
      { col: 'wrap_id', type: 'text', notnull: true },
      { col: 'kind', type: 'text', notnull: true },
      { col: 'key_version', type: 'smallint', notnull: true },
      { col: 'sealed_dek', type: 'bytea', notnull: true },
      { col: 'credential_id', type: 'bytea', notnull: false },
      { col: 'prf_salt', type: 'bytea', notnull: false },
      { col: 'created_at', type: 'timestamp with time zone', notnull: true },
      { col: 'webauthn_public_key', type: 'bytea', notnull: false },
      { col: 'webauthn_sign_count', type: 'bigint', notnull: false },
    ]);
  });
});

test('C3 key_wraps CHECKs: key_version 1..32767 (0 and 32768 refused), kinds passkey|recovery only, shape per kind, sealed DEK = C1 layout', async () => {
  assert.equal(await insWrap(db, {}), 'ok', 'a passkey wrap');
  assert.equal(await insWrap(db, { kind: 'recovery', cred: null, salt: null }), 'ok', 'a recovery wrap');
  assert.equal(await insWrap(db, { kv: KEY_WRAP_MAX_KEY_VERSION }), 'ok', 'key_version 32767');
  assert.equal(await insWrap(db, { kv: 0 }), '23514', 'key_version 0: CHECK');
  assert.equal(await insWrap(db, { kv: -1 }), '23514', 'key_version -1: CHECK');
  assert.equal(await insWrap(db, { kv: 32768 }), '22003', 'key_version 32768: smallint out of range');
  assert.equal(await insWrap(db, { kind: 'session', cred: null, salt: null }), '23514', 'session wraps never live in the catalog');
  assert.equal(await insWrap(db, { salt: null }), '23514', 'passkey without salt');
  assert.equal(await insWrap(db, { cred: null }), '23514', 'passkey without credential id');
  assert.equal(await insWrap(db, { salt: Buffer.alloc(31, 1) }), '23514', 'salt is 32 bytes');
  assert.equal(await insWrap(db, { cred: Buffer.alloc(0) }), '23514', 'empty credential id');
  assert.equal(await insWrap(db, { cred: Buffer.alloc(1024, 1) }), '23514', 'credential id over 1023 bytes');
  assert.equal(await insWrap(db, { kind: 'recovery', cred: null }), '23514', 'recovery with a salt');
  assert.equal(await insWrap(db, { kind: 'recovery', salt: null }), '23514', 'recovery with a credential id');
  assert.equal(await insWrap(db, { sealed: SEALED(0x01, 60) }), '23514', 'sealed DEK too short');
  assert.equal(await insWrap(db, { sealed: SEALED(0x01, 62) }), '23514', 'sealed DEK too long');
  assert.equal(await insWrap(db, { sealed: SEALED(0x02) }), '23514', 'unknown format byte');
  assert.equal(await insWrap(db, { wrapId: '' }), '23514', 'empty wrap id');
  assert.equal(await insWrap(db, { wrapId: 'a\nb' }), '23514', 'control character in wrap id');
  assert.equal(await insWrap(db, { wrapId: 'x'.repeat(256) }), '23514', 'wrap id over 255 bytes');
  assert.equal(await insWrap(db, { wrapId: 'x'.repeat(255) }), 'ok', 'wrap id of 255 bytes');
  assert.equal(await insWrap(db, { tenant: 'zt_cccccccccccccccccccccccccc' }), '23503', 'unknown workspace: FK');
  // Primary key (tenant_id, wrap_id).
  await asOwner(db, async () => {
    await db.exec('BEGIN');
    try {
      await db.query(`INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek) VALUES ($1, 'r-1', 'recovery', 1, $2)`, [A, SEALED()]);
      assert.equal(await code(db.query(`INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek) VALUES ($1, 'r-1', 'recovery', 2, $2)`, [A, SEALED()])), '23505');
    } finally {
      await db.exec('ROLLBACK');
    }
  });
  assert.equal(await asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi_tenants.key_wraps`)).rows[0]!.n), 0, 'nothing stays');
});

test('C3: the key_version bound is MAX_KEY_VERSION of the C1 module; a real C1 wrap fits the row and opens with the row\'s own fields', async () => {
  assert.equal(KEY_WRAP_MAX_KEY_VERSION, MAX_KEY_VERSION);
  assert.match(MIG_SQL, /CHECK \(key_version BETWEEN 1 AND 32767\)/);
  assert.match(MIG_SQL, /MAX_KEY_VERSION in src\/crypto-envelope\.ts/);
  assert.match(MIG_SQL, /SET LOCAL lock_timeout = '5s';\n[\s\S]*ALTER TABLE zeusi_tenants\.tenants ADD COLUMN/, 'bounded lock wait before the ALTER');
  // TEST values only (fixed byte patterns).
  const kek = passkeyKek(Buffer.alloc(32, 0x11), 'w-real');
  const dek = Buffer.alloc(32, 0x22);
  const sealed = wrapDek(kek, 7, { tenant: A, wrapId: 'w-real' }, dek);
  assert.equal(sealed.length, KEY_WRAP_SEALED_BYTES);
  await asOwner(db, async () => {
    await db.exec('BEGIN');
    try {
      await db.query(`INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek, credential_id, prf_salt) VALUES ($1, 'w-real', 'passkey', 7, $2, $3, $4)`,
        [A, sealed, CRED, SALT]);
      const r = (await db.query<{ tenant_id: string; wrap_id: string; key_version: number; sealed_dek: Uint8Array }>(
        `SELECT tenant_id, wrap_id, key_version, sealed_dek FROM zeusi_tenants.key_wraps WHERE tenant_id = $1`, [A])).rows[0]!;
      // Stored exactly as passed to wrapAad: reading the row back reopens the wrap.
      assert.deepEqual(unwrapDek(kek, r.key_version, { tenant: r.tenant_id, wrapId: r.wrap_id }, Buffer.from(r.sealed_dek)), dek);
    } finally {
      await db.exec('ROLLBACK');
    }
  });
});

test('C3 enc_state CHECK: the seven states are accepted, anything else refused; status and members are not touched', async () => {
  assert.deepEqual([...ENC_STATES], ['off', 'enrolled', 'encrypting', 'verified', 'on', 'decrypting', 'decrypted']);
  assert.deepEqual([...KEY_WRAP_KINDS], ['passkey', 'recovery']);
  await asOwner(db, async () => {
    for (const s of ENC_STATES) {
      await db.exec('BEGIN');
      try {
        assert.equal(await code(db.query(`UPDATE zeusi_tenants.tenants SET enc_state = $1 WHERE tenant_id = $2`, [s, A])), 'ok', s);
      } finally {
        await db.exec('ROLLBACK');
      }
    }
    for (const s of ['OFF', 'enabled', '', 'unknown']) {
      await db.exec('BEGIN');
      try {
        assert.equal(await code(db.query(`UPDATE zeusi_tenants.tenants SET enc_state = $1 WHERE tenant_id = $2`, [s, A])), '23514', s);
      } finally {
        await db.exec('ROLLBACK');
      }
    }
    await db.exec('BEGIN');
    try {
      assert.equal(await code(db.query(`UPDATE zeusi_tenants.tenants SET enc_state = NULL WHERE tenant_id = $1`, [A])), '23502');
    } finally {
      await db.exec('ROLLBACK');
    }
  });
});

test('C3 catalog ACL (C6: + enc_state): nothing to PUBLIC; zeusi_tenant_rt has USAGE on the schema and SELECT (tenant_id, status, enc_state) only; key_wraps is the owner\'s alone', async () => {
  await asOwner(db, async () => {
    const acl = (await db.query<{ obj: string; grantee: string; priv: string; grantable: boolean }>(
      `WITH ns AS (SELECT oid, nspowner, nspacl FROM pg_namespace WHERE nspname = 'zeusi_tenants')
       SELECT 'schema' AS obj, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS grantee, a.privilege_type AS priv, a.is_grantable AS grantable
         FROM ns, aclexplode(coalesce(ns.nspacl, acldefault('n', ns.nspowner))) a WHERE a.grantee <> ns.nspowner
       UNION ALL
       SELECT c.relname::text, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END, a.privilege_type, a.is_grantable
         FROM pg_class c JOIN ns ON c.relnamespace = ns.oid, aclexplode(coalesce(c.relacl, acldefault((CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END)::"char", c.relowner))) a
        WHERE a.grantee <> c.relowner
       UNION ALL
       SELECT c.relname::text || '.' || at.attname::text, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END, a.privilege_type, a.is_grantable
         FROM pg_class c JOIN ns ON c.relnamespace = ns.oid JOIN pg_attribute at ON at.attrelid = c.oid AND at.attnum > 0 AND at.attacl IS NOT NULL,
              aclexplode(at.attacl) a
        WHERE a.grantee <> c.relowner
       ORDER BY 1, 2, 3`)).rows;
    // C6 KTD2 (deliberate): the runtime login reads enc_state too (write routing; C7 reads later).
    assert.deepEqual(acl, [
      { obj: 'schema', grantee: 'zeusi_tenant_rt', priv: 'USAGE', grantable: false },
      { obj: 'tenants.enc_state', grantee: 'zeusi_tenant_rt', priv: 'SELECT', grantable: false },
      { obj: 'tenants.status', grantee: 'zeusi_tenant_rt', priv: 'SELECT', grantable: false },
      { obj: 'tenants.tenant_id', grantee: 'zeusi_tenant_rt', priv: 'SELECT', grantable: false },
    ]);
    // Every login and workspace role: nothing on key_wraps; enc_state readable by the runtime login only (C6), written by none.
    for (const role of ['zeusi_tenant_rt', 'zeusi_tenant_wr', `${A}_r`, `${A}_w`, 'zeusi_read', 'zeusi_ingest', 'zeusi_backup']) {
      const r = (await db.query<{ kw: boolean; es: boolean }>(
        `SELECT has_table_privilege($1::text, 'zeusi_tenants.key_wraps', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER') AS kw,
                has_column_privilege($1::text, 'zeusi_tenants.tenants', 'enc_state', 'SELECT, INSERT, UPDATE, REFERENCES') AS es`, [role])).rows[0]!;
      assert.deepEqual(r, { kw: false, es: role === 'zeusi_tenant_rt' }, role);
      assert.equal((await db.query<{ w: boolean }>(`SELECT has_column_privilege($1::text, 'zeusi_tenants.tenants', 'enc_state', 'INSERT, UPDATE, REFERENCES') AS w`, [role])).rows[0]!.w, false, role);
    }
  });
  // As the runtime login itself: key_wraps and enc_state are denied by privilege; the router still works.
  const rt = await asLogin(db, 'zeusi_tenant_rt')();
  try {
    assert.equal(await code(rt.query('SELECT count(*) FROM zeusi_tenants.key_wraps')), '42501');
    assert.equal(await code(rt.query('SELECT enc_state FROM zeusi_tenants.tenants')), 'ok', 'C6: the runtime login reads enc_state');
    assert.equal(await code(rt.query('SELECT created_at FROM zeusi_tenants.tenants')), '42501');
    assert.equal(await code(rt.query('UPDATE zeusi_tenants.tenants SET enc_state = enc_state')), '42501');
    assert.equal(await code(rt.query('SELECT tenant_id, status FROM zeusi_tenants.tenants')), 'ok');
  } finally {
    await rt.close();
  }
  const router = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt') });
  assert.equal(await router.check(A), 'active', 'the router still reads tenant_id, status');
});

test('C3: 0014 is catalog DDL, never workspace DDL (excluded; no workspace statement names zeusi_tenants; a workspace records no 0014)', async () => {
  assert.ok(TENANT_EXCLUDED_FILES.includes(MIG));
  const ddl = tenantDdl('zt_dddddddddddddddddddddddddd');
  assert.ok(!ddl.applied.some((a) => a.name === MIG));
  assert.ok(!ddl.statements.some((s) => /zeusi_tenants|key_wraps|enc_state/.test(s)));
  await asOwner(db, async () => {
    const files = (await db.query<{ f: string }>(`SELECT filename AS f FROM "${A}".schema_migrations ORDER BY 1`)).rows.map((r) => r.f);
    assert.ok(!files.includes(MIG));
    assert.ok(files.includes('0013_decision_links.sql'));
  });
});

// --------------------------------------------------------------------------- existing (pre-C3) catalogs

test('C3 ensure path on a pre-C3 catalog: existing rows get enc_state off and nothing else; key_wraps appears empty; idempotent', async () => {
  const d = await legacyDb();
  try {
    const rows0 = await catalogRows(d);
    const legacy = await fingerprint(d);
    const ldir = new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') });
    const lt0 = (await d.query<{ v: string }>(`SELECT current_setting('lock_timeout') AS v`)).rows[0]!.v;
    assert.equal(await ldir.lookup('github:999'), null, 'a lookup runs the ensure path');
    assert.equal((await d.query<{ v: string }>(`SELECT current_setting('lock_timeout') AS v`)).rows[0]!.v, lt0, 'the bounded lock wait is restored');
    assert.deepEqual(await catalogRows(d), rows0, 'status, members and created_at unchanged');
    assert.deepEqual(await asOwner(d, async () => (await d.query(`SELECT tenant_id, enc_state FROM zeusi_tenants.tenants ORDER BY 1`)).rows),
      [{ tenant_id: T1, enc_state: 'off' }, { tenant_id: T2, enc_state: 'off' }]);
    assert.equal(await asOwner(d, async () => (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi_tenants.key_wraps`)).rows[0]!.n), 0);
    const once = await fingerprint(d);
    assert.notDeepEqual(once, legacy);
    await ldir.lookup('github:301');
    await ldir.lookup('github:302');
    assert.deepEqual(await fingerprint(d), once, 'converged: a second ensure changes nothing');
    assert.deepEqual(await fingerprint(d), await fingerprint(db), 'an upgraded catalog equals a fresh one');
  } finally {
    await d.close();
  }
});

test('C3 migrate (0014) on a pre-C3 catalog: pending exactly 0014, needs the snapshot flag, then gives the same catalog as the ensure path; re-runs are no-ops', async () => {
  const d = await legacyDb();
  try {
    const rows0 = await catalogRows(d);
    const lines: string[] = [];
    const dry = await migrate(d, { dryRun: true, log: (l) => lines.push(l) });
    assert.deepEqual(dry.pending, [MIG, MIG15, MIG16, MIG17]);
    assert.deepEqual(lines, [`pending: ${MIG}`, `pending: ${MIG15}`, `pending: ${MIG16}`, `pending: ${MIG17}`]);
    await assert.rejects(migrate(d), /snapshot/);
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, [MIG, MIG15, MIG16, MIG17]);
    assert.deepEqual(await catalogRows(d), rows0, 'status, members and created_at unchanged');
    assert.deepEqual(await asOwner(d, async () => (await d.query(`SELECT enc_state, count(*)::int AS n FROM zeusi_tenants.tenants GROUP BY 1`)).rows), [{ enc_state: 'off', n: 2 }]);
    assert.equal(await asOwner(d, async () => (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi_tenants.key_wraps`)).rows[0]!.n), 0);
    assert.equal(await asOwner(d, async () => (await d.query<{ u: string }>(`SELECT current_user::text AS u`)).rows[0]!.u), 'postgres', 'the role was reset');
    const viaMigrate = await fingerprint(d);
    assert.deepEqual(viaMigrate, await fingerprint(db), 'the migration and the ensure path give the same catalog');
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, []);
    await asOwner(d, () => d.exec(MIG_SQL + MIG15_SQL + MIG16_SQL + MIG17_SQL));
    const ldir = new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') });
    await ldir.lookup('github:301');
    assert.deepEqual(await fingerprint(d), viaMigrate, 'replaying 0014 or the ensure path changes nothing');
  } finally {
    await d.close();
  }
});

test('C3 0014 as a narrow runner: a non-superuser that may SET ROLE zeusi_tenant_admin applies it; one that may not is refused and nothing changes', async () => {
  const d = await legacyDb();
  try {
    await asOwner(d, () => d.exec(`
      CREATE ROLE c3_owner_set LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
      CREATE ROLE c3_owner_noset LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS;
      GRANT zeusi_tenant_admin TO c3_owner_set WITH INHERIT FALSE, SET TRUE;`));
    const legacy = await fingerprint(d);
    const rows0 = await catalogRows(d);
    await d.exec('SET SESSION AUTHORIZATION c3_owner_noset');
    await d.exec('BEGIN');
    await assert.rejects(d.exec(MIG_SQL), /cannot SET ROLE zeusi_tenant_admin/);
    await d.exec('ROLLBACK');
    assert.deepEqual(await fingerprint(d), legacy, 'refused: nothing changed');

    await d.exec('SET SESSION AUTHORIZATION c3_owner_set');
    await d.exec('BEGIN');
    await d.exec(MIG_SQL + MIG15_SQL + MIG16_SQL + MIG17_SQL);
    assert.equal((await d.query<{ u: string }>(`SELECT current_user::text AS u`)).rows[0]!.u, 'c3_owner_set', 'RESET ROLE before the runner records the file');
    await d.exec('COMMIT');
    assert.deepEqual(await fingerprint(d), await fingerprint(db), 'same catalog as the ensure path, owned by zeusi_tenant_admin');
    assert.deepEqual(await catalogRows(d), rows0);
    // Converged: a runner WITHOUT the SET right now passes (no-op, no role switch).
    await d.exec('SET SESSION AUTHORIZATION c3_owner_noset');
    await d.exec('BEGIN');
    await d.exec(MIG_SQL + MIG15_SQL + MIG16_SQL + MIG17_SQL);
    await d.exec('COMMIT');
  } finally {
    await d.close();
  }
});

test('C3 0014 skip paths: no zeusi_tenant_admin role, or no catalog yet: recorded, nothing created; a catalog owned by anyone else is refused', async () => {
  const bare = await pgliteDb();
  try {
    const r = await migrate(bare);
    assert.ok(r.applied.includes(MIG));
    assert.equal((await bare.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = 'zeusi_tenants'`)).rows[0]!.n, 0);
  } finally {
    await bare.close();
  }
  const roles = await pgliteDb();
  try {
    await migrate(roles, { dir: subsetDir((n) => n < '0014') });
    await roles.exec(readFileSync(OWNER_SQL, 'utf8'));
    assert.deepEqual((await migrate(roles, { tookSnapshot: true })).applied, [MIG, MIG15, MIG16, MIG17]);
    assert.equal((await roles.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = 'zeusi_tenants'`)).rows[0]!.n, 0);
    await roles.exec(`CREATE SCHEMA zeusi_tenants`);
    await assert.rejects(roles.exec(MIG_SQL), /not owned by zeusi_tenant_admin/);
  } finally {
    await roles.close();
  }
});

test('C3 ROLLBACK-0014.md: refuses while a wrap exists; otherwise returns the pre-C3 catalog, rows intact; 0014 re-applies', async () => {
  const md = readFileSync(join(MIGRATIONS_DIR, 'ROLLBACK-0014.md'), 'utf8');
  const sql = /## SQL\s+```sql\n([\s\S]*?)```/.exec(md)?.[1];
  assert.ok(sql, 'the runbook has one sql block under ## SQL');
  const d = await legacyDb();
  try {
    const legacy = await fingerprint(d);
    const rows0 = await catalogRows(d);
    await migrate(d, { tookSnapshot: true });
    await asOwner(d, () => d.query(`INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek) VALUES ($1, 'r-1', 'recovery', 1, $2)`, [T1, SEALED()]));
    await assert.rejects(asOwner(d, () => d.exec(sql)), /not unused/);
    await asOwner(d, () => d.exec('ROLLBACK'));
    await asOwner(d, () => d.query(`DELETE FROM zeusi_tenants.key_wraps`));
    // A workspace that is no longer 'off' (enrolled) also blocks the rollback.
    await asOwner(d, () => d.query(`UPDATE zeusi_tenants.tenants SET enc_state = 'enrolled' WHERE tenant_id = $1`, [T2]));
    await assert.rejects(asOwner(d, () => d.exec(sql)), /not unused/);
    await asOwner(d, () => d.exec('ROLLBACK'));
    assert.equal(await asOwner(d, async () => (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.schema_migrations WHERE filename = $1`, [MIG])).rows[0]!.n), 1, 'refused: still applied');
    await asOwner(d, () => d.query(`UPDATE zeusi_tenants.tenants SET enc_state = 'off' WHERE tenant_id = $1`, [T2]));
    await asOwner(d, () => d.exec(sql));
    assert.deepEqual(await fingerprint(d), legacy, 'pre-C3 shape, owners and ACLs');
    assert.deepEqual(await catalogRows(d), rows0);
    assert.equal(await asOwner(d, async () => (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.schema_migrations WHERE filename = $1`, [MIG])).rows[0]!.n), 0);
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, [MIG]);
  } finally {
    await d.close();
  }
});

test('C3: the writer login owner SQL (re-run after C3) grants nothing in zeusi_tenants', async () => {
  // The writer owner SQL runs after C3 on an existing catalog without error, and grants nothing in zeusi_tenants.
  await asOwner(db, () => db.exec(readFileSync(WRITER_OWNER_SQL, 'utf8')));
  const n = await asOwner(db, async () => (await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace, aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
      WHERE s.nspname = 'zeusi_tenants' AND a.grantee = 'zeusi_tenant_wr'::regrole`)).rows[0]!.n);
  assert.equal(n, 0);
});
