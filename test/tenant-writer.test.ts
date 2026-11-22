// U2 + U3 (docs/plans/2026-11-18-workspace-write-import-plan.md KTD3, KTD4): the per-workspace
// writer role zt_<id>_w, its backfill, and the fail-closed write session, on PGlite with the real
// migrations, tenant-roles.sql and tenant-writer-role.sql (test/helpers/tenant-fixture.ts: logins
// emulated with SET SESSION AUTHORIZATION, so SET ROLE checks real membership). No network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { Db } from '../src/db.ts';
import { TENANT_ACL_AUDIT_SQL, tenantRole, tenantWriterRole } from '../src/tenant-ddl.ts';
import { SESSION_RESET_SQL, TenantDirectory, TenantError, TenantRefused, TenantRouter, TenantWriter, TENANT_WR_ROLE } from '../src/tenants.ts';
import {
  asLogin, asOwner, plantInWorkspace, plantTeam, pooledLogin, sessionState, TEAM_MARKER, tenantTestDb, WRITER_OWNER_SQL,
} from './helpers/tenant-fixture.ts';

let db: Db;
let dir: TenantDirectory;
let router: TenantRouter;
let A: string;
let B: string;

const writerFor = (connect = asLogin(db, TENANT_WR_ROLE)) => new TenantWriter({ connectWriter: connect, check: (t) => router.check(t) });

before(async () => {
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  router = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt'), cacheMs: 0 });
  A = ((await dir.provision('github:401')) as { tenantId: string }).tenantId;
  B = ((await dir.provision('github:402')) as { tenantId: string }).tenantId;
  await plantInWorkspace(db, B, 'wombatworkspaceb');
});
after(async () => db.close());

const membership = (role: string) => asOwner(db, async () => (await db.query<{ inh: boolean; set: boolean }>(
  `SELECT m.inherit_option AS inh, m.set_option AS set FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
    WHERE r.rolname = $1 AND u.rolname = $2`, [role, TENANT_WR_ROLE])).rows);

test('owner SQL: zeusi_tenant_wr is a NOINHERIT login with nothing on zeusi or zeusi_tenants; the file is idempotent and holds no password', async () => {
  const sql = readFileSync(WRITER_OWNER_SQL, 'utf8');
  assert.doesNotMatch(sql, /PASSWORD\s+'/i, 'no password literal');
  await asOwner(db, async () => {
    await db.exec(sql); // second run: idempotent
    const r = (await db.query<{ login: boolean; inh: boolean; su: boolean; cr: boolean; conn: number; team: boolean; ctl: boolean }>(
      `SELECT rolcanlogin AS login, rolinherit AS inh, rolsuper AS su, rolcreaterole AS cr, rolconnlimit AS conn,
              has_schema_privilege('zeusi_tenant_wr', 'zeusi', 'USAGE') AS team,
              has_schema_privilege('zeusi_tenant_wr', 'zeusi_tenants', 'USAGE') AS ctl
         FROM pg_roles WHERE rolname = 'zeusi_tenant_wr'`)).rows[0]!;
    assert.deepEqual(r, { login: true, inh: false, su: false, cr: false, conn: 4, team: false, ctl: false });
  });
});

test('provision: the workspace gets its writer role <id>_w, granted to zeusi_tenant_wr SET TRUE / INHERIT FALSE, never to the runtime login; ACL audit clean', async () => {
  assert.deepEqual(await membership(tenantWriterRole(A)), [{ inh: false, set: true }]);
  await asOwner(db, async () => {
    const rt = (await db.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
        WHERE r.rolname = $1 AND u.rolname = 'zeusi_tenant_rt'`, [tenantWriterRole(A)])).rows[0]!.n;
    assert.equal(rt, 0, 'the read login can never become a writer');
    assert.deepEqual((await db.query(TENANT_ACL_AUDIT_SQL, [A, tenantRole(A)])).rows, []);
    // The read role still has no write privilege (the router's can_write check stays meaningful).
    const w = (await db.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind = 'r'
          AND has_table_privilege($2, c.oid, 'INSERT')`, [A, tenantRole(A)])).rows[0]!.n;
    assert.equal(w, 0);
  });
});

test('writer session: exactly its own role and login, writes its own schema; zeusi, the catalog and another workspace are unreachable', async () => {
  const s = await writerFor().open(A);
  try {
    const who = (await s.query<{ cu: string; su: string }>('SELECT current_user::text AS cu, session_user::text AS su')).rows[0]!;
    assert.deepEqual(who, { cu: tenantWriterRole(A), su: TENANT_WR_ROLE });
    const run = (await s.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('t', 'h', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    assert.ok(run > 0);
    // Through the translating Db every `zeusi.` is the workspace: the zeusi-schema rows are not there.
    assert.equal((await s.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes WHERE body LIKE '%' || $1 || '%'`, [TEAM_MARKER])).rows[0]!.n, 0);
    // Raw statements (no translation) on the same session: refused by the database.
    await assert.rejects(db.query(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('x', 'h', 'manual')`), /permission denied/);
    await assert.rejects(db.query(`SELECT 1 FROM zeusi.notes LIMIT 1`), /permission denied/);
    await assert.rejects(db.query(`DELETE FROM "${B}".notes`), /permission denied/);
    await assert.rejects(db.query(`SELECT status FROM zeusi_tenants.tenants`), /permission denied/);
    await db.exec('ROLLBACK').catch(() => {});
    // search_path tricks change nothing: the role still has no USAGE on zeusi or B.
    await db.exec(`SET search_path = zeusi, "${B}", public`);
    await assert.rejects(db.query(`INSERT INTO notes (vault_path) VALUES ('x')`), /permission denied|does not exist/);
  } finally {
    await s.close();
  }
  // (asLogin's close returns to the owner; the pooled test below proves close() resets the login session.)
});

test('writer session on a pooled connection left dirty as workspace B (role + path): reset first, bound to A only', async () => {
  const dirty = () => `SET ROLE "${tenantWriterRole(B)}"; SET search_path = "${B}", public`;
  try {
    const s = await writerFor(pooledLogin(db, TENANT_WR_ROLE, { dirty })).open(A);
    const who = (await s.query<{ cu: string; path: string }>(`SELECT current_user::text AS cu, current_setting('search_path') AS path`)).rows[0]!;
    assert.equal(who.cu, tenantWriterRole(A));
    assert.ok(who.path.includes(A) && !who.path.includes(B));
    await s.close();
    const st = await sessionState(db);
    assert.equal(st.cu, TENANT_WR_ROLE, 'close() reset the role on the pooled connection');
  } finally {
    await asOwner(db, async () => {});
  }
});

test('forged / unknown / disabled workspace ids and a non-writer login are refused before any write', async () => {
  const w = writerFor();
  for (const bad of ['zeusi', 'work', `${A}; DROP TABLE x`, `zt_${'q'.repeat(26)}`, '', 'zt_ABC']) {
    await assert.rejects(w.open(bad), TenantRefused, bad);
  }
  // A runtime (read) login posing as the writer: the login assert refuses it.
  await assert.rejects(new TenantWriter({ connectWriter: asLogin(db, 'zeusi_tenant_rt'), check: (t) => router.check(t) }).open(A), TenantError);
  await asOwner(db, async () => {});
  // Disabled in the catalog: refused.
  await asOwner(db, async () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'disabled' WHERE tenant_id = $1`, [B]));
  await assert.rejects(w.open(B), TenantRefused);
  await asOwner(db, async () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'active' WHERE tenant_id = $1`, [B]));
  await asOwner(db, async () => {});
});

test('a writer role that was granted on ANOTHER workspace (or on zeusi) is refused: no write session at all', async () => {
  await asOwner(db, async () => db.exec(`GRANT USAGE ON SCHEMA "${B}" TO "${tenantWriterRole(A)}"; GRANT INSERT ON "${B}".notes TO "${tenantWriterRole(A)}"`));
  try {
    await assert.rejects(writerFor().open(A), TenantRefused);
  } finally {
    await asOwner(db, async () => db.exec(`REVOKE ALL ON "${B}".notes FROM "${tenantWriterRole(A)}"; REVOKE ALL ON SCHEMA "${B}" FROM "${tenantWriterRole(A)}"`));
  }
  await asOwner(db, async () => db.exec(`GRANT INSERT ON zeusi.notes TO "${tenantWriterRole(A)}"`));
  try {
    await assert.rejects(writerFor().open(A), TenantRefused, 'a write privilege outside its own schema');
  } finally {
    await asOwner(db, async () => db.exec(`REVOKE ALL ON zeusi.notes FROM "${tenantWriterRole(A)}"`));
  }
  // B's writer role handed to A's writer role (inheritable): A's session would reach B: refused.
  await asOwner(db, async () => db.exec(`GRANT "${tenantWriterRole(B)}" TO "${tenantWriterRole(A)}" WITH INHERIT TRUE`));
  try {
    await assert.rejects(writerFor().open(A), TenantRefused);
  } finally {
    await asOwner(db, async () => db.exec(`REVOKE "${tenantWriterRole(B)}" FROM "${tenantWriterRole(A)}"`));
  }
  const s = await writerFor().open(A);
  await s.close();
});

test('backfill: a workspace provisioned before the writer login existed gets its role later; idempotent; dry run changes nothing', async () => {
  const db2 = await tenantTestDb(); // no writer login yet
  try {
    const d2 = new TenantDirectory({ connectAdmin: asLogin(db2, 'zeusi_tenant_admin') });
    const C = ((await d2.provision('github:501')) as { tenantId: string }).tenantId;
    // Simulate a pre-PR-2 workspace: no writer role at all.
    await asOwner(db2, async () => db2.exec(`DROP OWNED BY "${tenantWriterRole(C)}"; DROP ROLE "${tenantWriterRole(C)}"`));
    assert.deepEqual(await d2.backfillWriters({ dryRun: true }), { active: 1, ready: 0, no_login: 0, failed: 0, missing_role: 1 });
    assert.deepEqual(await d2.backfillWriters({ dryRun: false }), { active: 1, ready: 0, no_login: 1, failed: 0, missing_role: 1 });
    await asOwner(db2, async () => db2.exec(readFileSync(WRITER_OWNER_SQL, 'utf8')));
    assert.deepEqual(await d2.backfillWriters({ dryRun: false }), { active: 1, ready: 1, no_login: 0, failed: 0, missing_role: 0 });
    assert.deepEqual(await d2.backfillWriters({ dryRun: false }), { active: 1, ready: 1, no_login: 0, failed: 0, missing_role: 0 }, 'idempotent');
    assert.equal(await d2.ensureWriter(C), 'ready');
    assert.equal(await d2.ensureWriter(`zt_${'q'.repeat(26)}`), 'unknown');
    await asOwner(db2, async () => assert.deepEqual((await db2.query(TENANT_ACL_AUDIT_SQL, [C, tenantRole(C)])).rows, []));
    const r2 = new TenantRouter({ connectRuntime: asLogin(db2, 'zeusi_tenant_rt'), cacheMs: 0 });
    const s = await new TenantWriter({ connectWriter: asLogin(db2, TENANT_WR_ROLE), check: (t) => r2.check(t) }).open(C);
    await s.close();
  } finally {
    await db2.close();
  }
});

test('review fix: a writer role that is not as provisioned (LOGIN, or a member of another role) makes ensureWriter refuse; a SECURITY DEFINER function outside its schema refuses the session', async () => {
  const w = tenantWriterRole(A);
  await asOwner(db, async () => db.exec(`ALTER ROLE "${w}" LOGIN`));
  try {
    await assert.rejects(dir.ensureWriter(A), TenantError);
  } finally {
    await asOwner(db, async () => db.exec(`ALTER ROLE "${w}" NOLOGIN`));
  }
  await asOwner(db, async () => db.exec(`GRANT zeusi_read TO "${w}"`));
  try {
    await assert.rejects(dir.ensureWriter(A), TenantError);
  } finally {
    await asOwner(db, async () => db.exec(`REVOKE zeusi_read FROM "${w}"`));
  }
  assert.equal(await dir.ensureWriter(A), 'ready');
  // A SECURITY DEFINER function in public that the writer may run (PUBLIC EXECUTE by default).
  await asOwner(db, async () => db.exec(`CREATE FUNCTION public.zz_escape() RETURNS int LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`));
  try {
    await assert.rejects(writerFor().open(A), TenantRefused);
  } finally {
    await asOwner(db, async () => db.exec('DROP FUNCTION public.zz_escape()'));
  }
  await (await writerFor().open(A)).close();
});

// P2-3 (review of #31): the acquire-time RESET and the current_user check on the writer are pinned.
test('review P2-3: the writer resets first on acquire; a pooled session left read-only (only RESET clears it) still writes its own schema', async () => {
  const log: string[] = [];
  const pooled = pooledLogin(db, TENANT_WR_ROLE, { dirty: () => 'SET default_transaction_read_only = on' });
  const logged = async (): Promise<Db> => {
    const d = await pooled();
    return {
      ...d,
      query: (sql, p) => { log.push(sql); return d.query(sql, p); },
      exec: (sql) => { log.push(sql); return d.exec(sql); },
    };
  };
  try {
    const s = await writerFor(logged).open(A);
    assert.equal(log[0], SESSION_RESET_SQL, 'the first statement on the writer session is the reset');
    try {
      const run = (await s.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('p2-3', 'h', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
      assert.ok(run > 0, 'the read-only default left by the previous user was reset');
    } finally {
      await s.close();
    }
  } finally {
    await asOwner(db, async () => {});
  }
});

test('review P2-3: a writer session whose current_user is not exactly <id>_w after SET ROLE is refused, even when every other check passes', async () => {
  const log: string[] = [];
  let closed = 0;
  for (const cu of [tenantWriterRole(B), TENANT_WR_ROLE, tenantRole(A)]) {
    const fake: Db = {
      label: 'fake writer',
      async query<T>(sql: string) {
        log.push(sql);
        if (/AS outside/.test(sql)) {
          return { rows: [{ cu, su: TENANT_WR_ROLE, power: false, own: true, team: false, ctl: false, other: false, outside: false } as T] };
        }
        return { rows: [{ cu: TENANT_WR_ROLE, su: TENANT_WR_ROLE } as T] };
      },
      async exec(sql: string) {
        log.push(sql);
      },
      async close() {
        closed++;
      },
    };
    await assert.rejects(writerFor(async () => fake).open(A), TenantRefused, cu);
  }
  assert.equal(closed, 3, 'every refused session is closed');
  assert.ok(!log.some((s) => /^\s*(INSERT|UPDATE|DELETE)\b/i.test(s)), 'nothing written');
});

// P2-5 (review of #31): the ACL audit compares the writer role's privileges EXACTLY with tenantWriterGrants.
test('review P2-5: an extra <id>_w privilege on the wall tables, quarantine or schema_migrations fails the ACL audit; revoking it makes the audit clean again', async () => {
  const w = tenantWriterRole(A);
  const audit = () => asOwner(db, async () => (await db.query<{ kind: string; name: string }>(TENANT_ACL_AUDIT_SQL, [A, tenantRole(A)])).rows);
  assert.deepEqual(await audit(), [], 'clean as provisioned');
  for (const [table, priv] of [['wall_denylist', 'INSERT'], ['wall_allow', 'UPDATE'], ['quarantine', 'INSERT'], ['schema_migrations', 'INSERT'], ['wall_denylist', 'DELETE'], ['notes', 'TRUNCATE']] as const) {
    await asOwner(db, async () => db.exec(`GRANT ${priv} ON "${A}".${table} TO "${w}"`));
    try {
      assert.deepEqual(await audit(), [{ kind: 'relation', name: table }], `${priv} on ${table}`);
    } finally {
      await asOwner(db, async () => db.exec(`REVOKE ${priv} ON "${A}".${table} FROM "${w}"`));
    }
  }
  // An expected privilege, but WITH GRANT OPTION: also a violation.
  await asOwner(db, async () => db.exec(`GRANT SELECT ON "${A}".people TO "${w}" WITH GRANT OPTION`));
  try {
    assert.deepEqual(await audit(), [{ kind: 'relation', name: 'people' }]);
  } finally {
    await asOwner(db, async () => db.exec(`REVOKE GRANT OPTION FOR SELECT ON "${A}".people FROM "${w}"`));
  }
  // A function other than quarantine_record: a violation.
  await asOwner(db, async () => db.exec(`CREATE FUNCTION "${A}".zz_extra() RETURNS int LANGUAGE sql AS 'SELECT 1'; REVOKE ALL ON FUNCTION "${A}".zz_extra() FROM PUBLIC; GRANT EXECUTE ON FUNCTION "${A}".zz_extra() TO "${w}"`));
  try {
    assert.deepEqual(await audit(), [{ kind: 'function', name: 'zz_extra' }]);
  } finally {
    await asOwner(db, async () => db.exec(`DROP FUNCTION "${A}".zz_extra()`));
  }
  assert.deepEqual(await audit(), [], 'clean again');
  assert.equal(await dir.ensureWriter(A), 'ready');
});
