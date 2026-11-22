// C4 U1 (docs/plans/2026-11-18-c4-enroll.md KTD1, KTD5): the credential UNIQUE (0015 and the ensure path),
// enrollment off -> enrolled atomically with the first wraps, re-enroll upsert, no new runtime grant.
// Hermetic: PGlite with the real migrations and owner SQL (test/helpers/tenant-fixture.ts). No Neon.
// Every wrap, credential id, salt and PRF output below is a TEST byte pattern.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { listMigrations, migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { TENANT_EXCLUDED_FILES } from '../src/tenant-ddl.ts';
import { KEY_WRAP_CREDENTIAL_INDEX, TenantDirectory } from '../src/tenants.ts';
import { enrollmentWraps, passkeyWrapId, unlockWithPasskey, unlockWithRecovery, wrapForCredential } from '../src/workspace-keys.ts';
import { passkeyKek, wrapDek } from '../src/crypto-envelope.ts';
import { pgliteDb } from './pglite-db.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, OWNER_SQL, tenantTestDb } from './helpers/tenant-fixture.ts';

const MIG15 = '0015_key_wraps_credential_unique.sql';
const MIG15_SQL = readFileSync(join(MIGRATIONS_DIR, MIG15), 'utf8');
/** C6 (docs/plans/2026-11-19-c6-write-path.md KTD2): the next catalog file; pending together with 0015 on a C3 catalog. */
const MIG16 = '0016_catalog_rt_enc_state.sql';
/** docs/plans/2026-11-19-c4-webauthn-verify.md KTD5: pending after 0016 (test/c4-webauthn-catalog.test.ts covers it). */
const MIG17 = '0017_key_wraps_webauthn.sql';
const PRF = Buffer.alloc(32, 0x50);
const SALT = Buffer.alloc(32, 0x51);
const CRED = Buffer.from('test-credential-c4-one', 'utf8');
const DEK = Buffer.alloc(32, 0x44);

let db: Db;
let dir: TenantDirectory;

before(async () => {
  db = await tenantTestDb({ writer: true });
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
});
after(async () => db.close());

async function newTenant(n: number): Promise<string> {
  return ((await dir.provision(`github:${5000 + n}`)) as { tenantId: string }).tenantId;
}
const rows = (tenant: string) => asOwner(db, async () => (await db.query<{ wrap_id: string; kind: string; credential_id: Uint8Array | null }>(
  `SELECT wrap_id, kind, credential_id FROM zeusi_tenants.key_wraps WHERE tenant_id = $1 ORDER BY kind, wrap_id`, [tenant])).rows);
const encState = (tenant: string) => asOwner(db, async () => (await db.query<{ s: string }>(`SELECT enc_state AS s FROM zeusi_tenants.tenants WHERE tenant_id = $1`, [tenant])).rows[0]!.s);

function subsetDir(keep: (name: string) => boolean): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-mig15-'));
  for (const f of listMigrations()) if (keep(f.name)) copyFileSync(join(MIGRATIONS_DIR, f.name), join(d, f.name));
  return d;
}

async function catalogShape(d: Db): Promise<unknown> {
  return asOwner(d, async () => ({
    rels: (await d.query(`SELECT c.relname::text AS rel, c.relkind::text AS kind, c.relowner::regrole::text AS owner, c.relacl::text AS acl
                            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'zeusi_tenants' ORDER BY 1`)).rows,
    idx: (await d.query(`SELECT indexrelid::regclass::text AS name, pg_get_indexdef(indexrelid) AS def
                           FROM pg_index WHERE indrelid = 'zeusi_tenants.key_wraps'::regclass ORDER BY 1`)).rows,
  }));
}

test('C4 enroll: off -> enrolled with the first passkey + recovery wraps in one transaction; both open the DEK', async () => {
  const t = await newTenant(1);
  assert.deepEqual(await dir.encryptionView(t), { encState: 'off', passkeys: [], recovery: 0 });
  const e = enrollmentWraps({ tenant: t, prfOutput: PRF, credentialId: CRED, prfSalt: SALT, newDek: () => Buffer.from(DEK) });
  assert.equal(await dir.enroll(t, { passkey: e.passkey, recovery: e.recovery }), 'enrolled');
  assert.equal(await encState(t), 'enrolled');
  const v = (await dir.encryptionView(t))!;
  assert.equal(v.encState, 'enrolled');
  assert.deepEqual(v.passkeys, [{ credentialId: CRED, prfSalt: SALT }]);
  assert.equal(v.recovery, 1);
  const pk = wrapForCredential(await dir.wrapsFor(t, 'passkey'), CRED)!;
  assert.equal(pk.wrapId, passkeyWrapId(CRED));
  assert.deepEqual(unlockWithPasskey(t, pk, PRF)!.dek, DEK);
  assert.deepEqual(unlockWithRecovery(t, await dir.wrapsFor(t, 'recovery'), e.recoveryCode)!.dek, DEK);
  assert.equal(unlockWithPasskey(t, pk, Buffer.alloc(32, 0x52)), null, 'a wrong PRF output fails the tag');
  assert.equal(unlockWithRecovery(t, await dir.wrapsFor(t, 'recovery'), Buffer.alloc(16, 1)), null);
  // §7 item 4 (catalog side): the rows alone open nothing, and a wrap copied to another workspace fails.
  const other = 'zt_cccccccccccccccccccccccccc';
  assert.equal(unlockWithPasskey(other, pk, PRF), null, 'passkey wrap moved to another tenant');
  assert.equal(unlockWithRecovery(other, await dir.wrapsFor(t, 'recovery'), e.recoveryCode), null, 'recovery wrap moved to another tenant');
  assert.equal(unlockWithPasskey(t, { ...pk, wrapId: 'pk:other' }, PRF), null, 'wrap moved to another wrap id');
  assert.equal(unlockWithPasskey(t, { ...pk, keyVersion: 2 }, PRF), null, 'another key_version');
  assert.equal(unlockWithPasskey(t, pk, pk.prfSalt!), null, 'the stored salt is not the secret');
  assert.throws(() => enrollmentWraps({ tenant: 'work', prfOutput: PRF, credentialId: CRED, prfSalt: SALT }), 'team is refused');
  assert.throws(() => enrollmentWraps({ tenant: t, prfOutput: Buffer.alloc(31), credentialId: CRED, prfSalt: SALT }), 'PRF output must be 32 bytes');
  // A second enrollment is refused and changes nothing.
  const e2 = enrollmentWraps({ tenant: t, prfOutput: PRF, credentialId: Buffer.from('other-cred'), prfSalt: SALT });
  assert.equal(await dir.enroll(t, { passkey: e2.passkey, recovery: e2.recovery }), 'already');
  assert.equal((await rows(t)).length, 2);
});

test('C4 enroll is atomic: a failing insert after the first wrap leaves enc_state off and NO wrap row', async () => {
  const t = await newTenant(2);
  const e = enrollmentWraps({ tenant: t, prfOutput: PRF, credentialId: CRED, prfSalt: SALT });
  // The recovery insert fails its CHECK (sealed DEK one byte short) after the passkey row went in.
  await assert.rejects(dir.enroll(t, { passkey: e.passkey, recovery: { ...e.recovery, sealedDek: e.recovery.sealedDek.subarray(0, 60) } }));
  assert.equal(await encState(t), 'off');
  assert.deepEqual(await rows(t), []);
  // A failing passkey row (bad salt length) likewise.
  await assert.rejects(dir.enroll(t, { passkey: { ...e.passkey, prfSalt: Buffer.alloc(31) }, recovery: e.recovery }));
  assert.equal(await encState(t), 'off');
  assert.deepEqual(await rows(t), []);
  // A disabled or unknown workspace is never enrolled.
  assert.equal(await dir.enroll('zt_zzzzzzzzzzzzzzzzzzzzzzzzzz', { passkey: e.passkey, recovery: e.recovery }), 'unknown');
  assert.equal(await dir.enroll('work', { passkey: e.passkey, recovery: e.recovery }), 'unknown');
  assert.equal(await dir.encryptionView('work'), null);
  // Then it still enrolls cleanly.
  assert.equal(await dir.enroll(t, { passkey: e.passkey, recovery: e.recovery }), 'enrolled');
});

test('C4 KTD1: UNIQUE (tenant_id, credential_id): a second live row for one credential is refused; re-enroll updates the row; a new device adds one', async () => {
  const t = await newTenant(3);
  const e = enrollmentWraps({ tenant: t, prfOutput: PRF, credentialId: CRED, prfSalt: SALT, newDek: () => Buffer.from(DEK) });
  assert.equal(await dir.enroll(t, { passkey: e.passkey, recovery: e.recovery }), 'enrolled');
  // Direct second row with the same credential under another wrap_id: refused by the index.
  const err = await asOwner(db, async () => {
    try {
      await db.query(`INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek, credential_id, prf_salt) VALUES ($1, 'pk:dup', 'passkey', 1, $2, $3, $4)`,
        [t, e.passkey.sealedDek, CRED, SALT]);
      return 'ok';
    } catch (x) {
      return (x as { code?: string }).code ?? 'error';
    }
  });
  assert.equal(err, '23505');
  // Re-enroll of the same credential (new salt, new PRF): ONE row, updated, opening with the new PRF only.
  const salt2 = Buffer.alloc(32, 0x61);
  const prf2 = Buffer.alloc(32, 0x62);
  const id = passkeyWrapId(CRED);
  const sealed2 = wrapDek(passkeyKek(prf2, id), 1, { tenant: t, wrapId: id }, DEK);
  assert.equal(await dir.putPasskeyWrap(t, { wrapId: id, keyVersion: 1, sealedDek: sealed2, credentialId: CRED, prfSalt: salt2 }), 'updated');
  const pks = await dir.wrapsFor(t, 'passkey');
  assert.equal(pks.length, 1);
  assert.deepEqual(pks[0]!.prfSalt, salt2);
  assert.deepEqual(unlockWithPasskey(t, pks[0]!, prf2)!.dek, DEK);
  assert.equal(unlockWithPasskey(t, pks[0]!, PRF), null, 'the replaced wrap is gone');
  // A new device: a new credential id, a new row.
  const cred2 = Buffer.from('test-credential-c4-two');
  const id2 = passkeyWrapId(cred2);
  assert.equal(await dir.putPasskeyWrap(t, { wrapId: id2, keyVersion: 1, sealedDek: wrapDek(passkeyKek(prf2, id2), 1, { tenant: t, wrapId: id2 }, DEK), credentialId: cred2, prfSalt: salt2 }), 'inserted');
  assert.equal((await dir.wrapsFor(t, 'passkey')).length, 2);
  // Recovery rows (NULL credential id) are not constrained by the index.
  const before = (await rows(t)).length;
  await asOwner(db, () => db.query(`INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek) VALUES ($1, 'rc:second', 'recovery', 1, $2)`, [t, e.recovery.sealedDek]));
  assert.equal((await rows(t)).length, before + 1);
  // putPasskeyWrap never enrolls: a workspace still off is refused.
  const off = await newTenant(4);
  assert.equal(await dir.putPasskeyWrap(off, { wrapId: id, keyVersion: 1, sealedDek: sealed2, credentialId: CRED, prfSalt: salt2 }), 'not_enrolled');
  assert.deepEqual(await rows(off), []);
});

test('C4 KTD5 (C6: + enc_state): zeusi_tenant_rt has SELECT (tenant_id, status, enc_state) only, nothing on key_wraps', async () => {
  const acl = await asOwner(db, async () => ({
    wraps: (await db.query<{ g: string }>(`SELECT DISTINCT a.grantee::regrole::text AS g FROM pg_class c, aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
                                            WHERE c.oid = 'zeusi_tenants.key_wraps'::regclass ORDER BY 1`)).rows.map((r) => r.g),
    rtCols: (await db.query<{ col: string }>(`SELECT column_name::text AS col FROM information_schema.column_privileges
                                               WHERE table_schema = 'zeusi_tenants' AND grantee = 'zeusi_tenant_rt' ORDER BY 1`)).rows.map((r) => r.col),
    idxOwner: (await db.query<{ o: string }>(`SELECT relowner::regrole::text AS o FROM pg_class WHERE relname = $1`, [KEY_WRAP_CREDENTIAL_INDEX])).rows[0]?.o,
  }));
  assert.deepEqual(acl.wraps, ['zeusi_tenant_admin']);
  // C6 KTD2 (deliberate): the runtime login reads enc_state (write routing); C4 itself added no grant.
  assert.deepEqual(acl.rtCols, ['enc_state', 'status', 'tenant_id']);
  assert.equal(acl.idxOwner, 'zeusi_tenant_admin');
});

test('C4 0015: catalog DDL, excluded from workspaces; on a C3 catalog: pending exactly 0015, snapshot flag, same catalog as the ensure path; re-runs no-op', async () => {
  assert.ok(TENANT_EXCLUDED_FILES.includes(MIG15));
  const d = await pgliteDb();
  try {
    await migrate(d, { dir: subsetDir((n) => n < MIG15) });
    await d.exec(readFileSync(OWNER_SQL, 'utf8'));
    // A C3-era catalog: the ensure path's shape without the index (what the C3 provisioner left).
    await new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') }).lookup('github:76');
    await asOwner(d, () => d.exec(`SET ROLE zeusi_tenant_admin; DROP INDEX zeusi_tenants.${KEY_WRAP_CREDENTIAL_INDEX}; RESET ROLE`));
    assert.equal(await asOwner(d, async () => (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_class WHERE relname = $1`, [KEY_WRAP_CREDENTIAL_INDEX])).rows[0]!.n), 0);
    const lines: string[] = [];
    assert.deepEqual((await migrate(d, { dryRun: true, log: (l) => lines.push(l) })).pending, [MIG15, MIG16, MIG17]);
    await assert.rejects(migrate(d), /snapshot/);
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, [MIG15, MIG16, MIG17]);
    assert.deepEqual(await catalogShape(d), await catalogShape(db), 'the migration and the ensure path give the same catalog');
    assert.equal(await asOwner(d, async () => (await d.query<{ u: string }>('SELECT current_user::text AS u')).rows[0]!.u), 'postgres', 'role reset');
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, []);
    await asOwner(d, () => d.exec(MIG15_SQL));
    await new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') }).lookup('github:77');
    assert.deepEqual(await catalogShape(d), await catalogShape(db), 'replaying 0015 or the ensure path changes nothing');
  } finally {
    await d.close();
  }
});

test('C4 0015: a runner without SET is refused and nothing changes; skips with no role or no catalog; ROLLBACK-0015.md drops only the index', async () => {
  const bare = await pgliteDb();
  try {
    assert.ok((await migrate(bare)).applied.includes(MIG15), 'no zeusi_tenant_admin: recorded, nothing created');
  } finally {
    await bare.close();
  }
  const d = await pgliteDb();
  try {
    await migrate(d, { dir: subsetDir((n) => n < MIG15) });
    await d.exec(readFileSync(OWNER_SQL, 'utf8'));
    assert.deepEqual((await migrate(d, { tookSnapshot: true })).applied, [MIG15, MIG16, MIG17], 'no catalog yet: recorded, skipped');
    // The ensure path builds the full catalog; drop the index to emulate a C3 catalog for the SET checks.
    await new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') }).lookup('github:78');
    const full = await catalogShape(d);
    await asOwner(d, () => d.exec(`SET ROLE zeusi_tenant_admin; DROP INDEX zeusi_tenants.${KEY_WRAP_CREDENTIAL_INDEX}; RESET ROLE`));
    await asOwner(d, () => d.exec('CREATE ROLE c4_noset LOGIN NOSUPERUSER; CREATE ROLE c4_set LOGIN NOSUPERUSER; GRANT zeusi_tenant_admin TO c4_set WITH INHERIT FALSE, SET TRUE'));
    const c3 = await catalogShape(d);
    await d.exec('SET SESSION AUTHORIZATION c4_noset');
    await assert.rejects(d.exec(MIG15_SQL), /cannot SET ROLE zeusi_tenant_admin/);
    assert.deepEqual(await catalogShape(d), c3, 'refused: nothing changed');
    await d.exec('SET SESSION AUTHORIZATION c4_set');
    await d.exec(MIG15_SQL);
    assert.deepEqual(await catalogShape(d), full, 'applied by a narrow runner, owned by zeusi_tenant_admin');
    // Rollback runbook.
    const md = readFileSync(join(MIGRATIONS_DIR, 'ROLLBACK-0015.md'), 'utf8');
    const sql = /## SQL\s+```sql\n([\s\S]*?)```/.exec(md)?.[1];
    assert.ok(sql);
    await asOwner(d, () => d.exec(sql));
    assert.deepEqual(await catalogShape(d), c3);
    assert.equal(await asOwner(d, async () => (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.schema_migrations WHERE filename = $1`, [MIG15])).rows[0]!.n), 0);
  } finally {
    await d.close();
  }
});
