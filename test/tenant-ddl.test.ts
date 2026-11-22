// U1 (docs/plans/2026-11-18-open-signup-workspaces-plan.md): workspace DDL from the migration files.
// Pure transform checks, then PGlite with the real migrations: a provisioned workspace has the same
// shape as zeusi, nothing in it is granted beyond its own role, zeusi is untouched, and a role-bound
// statement that slips the filter cannot commit.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { listMigrations, type MigrationFile } from '../src/migrate.ts';
import {
  assertNoBareSchema, classifyStatement, lex, renameSchema, splitStatements, TENANT_ACL_AUDIT_SQL, TENANT_EXCLUDED_FILES, TENANT_READ_TABLES,
  tenantStatements, TenantDdlError,
} from '../src/tenant-ddl.ts';
import { TenantDirectory, TenantError } from '../src/tenants.ts';
import { asLogin, asOwner, plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';

const S = `zt_${'a'.repeat(26)}`;
let db: Db;
let dir: TenantDirectory;

before(async () => {
  db = await tenantTestDb();
  await plantTeam(db);
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
});
after(async () => db.close());

// ---------------------------------------------------------------------------
// Lexer, split, classify, rename (pure)

test('tenant-ddl: the splitter keeps a dollar-quoted body with inner ; as one statement; strings and comments hide ;', () => {
  const sql = `CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ BEGIN PERFORM 1; RETURN 2; END $$;
-- a comment; with a semicolon
SELECT 'a;b', E'it\\'s;', $tag$ x; y $tag$; /* block ; /* nested ; */ */ SELECT 3`;
  const st = splitStatements(sql);
  assert.equal(st.length, 3);
  assert.match(st[0]!, /RETURN 2; END \$\$$/);
  assert.match(st[1]!, /\$tag\$ x; y \$tag\$/);
  assert.match(st[2]!, /SELECT 3$/);
  assert.throws(() => lex(`SELECT 'open`), TenantDdlError);
  assert.throws(() => lex('SELECT $$ open'), TenantDdlError);
  assert.throws(() => lex('/* open'), TenantDdlError);
});

test('tenant-ddl: the rename covers qualifiers, CREATE SCHEMA, function search_path and format() strings; never longer names, hosts or messages', () => {
  const r = renameSchema(`CREATE SCHEMA IF NOT EXISTS zeusi;
CREATE FUNCTION zeusi.f() RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
BEGIN RAISE EXCEPTION 'zeusi wall: % row', 1; PERFORM my_zeusi.x; PERFORM 'mcp.zeusi.dev'; EXECUTE format('SELECT 1 FROM zeusi.%I', 't'); RETURN zeusi."q"(); END $$`, S);
  assert.match(r, new RegExp(`CREATE SCHEMA IF NOT EXISTS ${S};`));
  assert.match(r, new RegExp(`CREATE FUNCTION ${S}\\.f\\(\\)`));
  assert.match(r, new RegExp(`search_path = pg_catalog, ${S} AS`));
  assert.match(r, new RegExp(`format\\('SELECT 1 FROM ${S}\\.%I'`));
  assert.match(r, new RegExp(`RETURN ${S}\\."q"\\(\\)`));
  assert.match(r, /'zeusi wall: % row'/, 'message text unchanged');
  assert.match(r, /my_zeusi\.x/);
  assert.match(r, /'mcp\.zeusi\.dev'/);
  assert.throws(() => renameSchema('SELECT 1', 'zeusi'), /not a workspace id/);
  assert.throws(() => assertNoBareSchema(`ALTER ROLE x SET search_path = zeusi, public`, 'f'), TenantDdlError);
  assert.doesNotThrow(() => assertNoBareSchema(`SELECT 'zeusi: a message' -- zeusi in a comment`, 'f'));
});

test('tenant-ddl: role-bound statements are dropped; shape statements (including ALTER TYPE ... ADD VALUE) are kept', () => {
  const dropped = [
    'GRANT SELECT ON zeusi.notes TO zeusi_read', 'REVOKE ALL ON zeusi.notes FROM PUBLIC',
    'CREATE POLICY p ON zeusi.notes FOR SELECT TO zeusi_read USING (true)', 'DROP POLICY IF EXISTS p ON zeusi.notes',
    'ALTER ROLE zeusi_box_ro SET search_path = zeusi, public', 'CREATE ROLE x NOLOGIN', 'CREATE EXTENSION IF NOT EXISTS vector',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA zeusi GRANT SELECT ON TABLES TO zeusi_read', 'ALTER TABLE zeusi.notes OWNER TO zeusi_read',
    'SET ROLE zeusi_read', 'SET SESSION AUTHORIZATION zeusi_read', '-- lead comment\nGRANT USAGE ON SCHEMA zeusi TO x',
    `DO $$ BEGIN EXECUTE format($p$CREATE POLICY a ON zeusi.%I FOR SELECT TO zeusi_read USING (true)$p$, 't'); END $$`,
    `DO $$ BEGIN IF true THEN CREATE ROLE y; END IF; END $$`,
  ];
  for (const s of dropped) assert.equal(classifyStatement(s).keep, false, s);
  const kept = [
    `ALTER TYPE zeusi.scope ADD VALUE IF NOT EXISTS 'client' AFTER 'product'`, 'CREATE TABLE zeusi.t (id int)',
    `INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason, added_by) VALUES ('regex', true, 'x', 'y', 'z')`,
    'ALTER TABLE zeusi.decision_links ENABLE ROW LEVEL SECURITY', `DO $$ BEGIN PERFORM 1; END $$`,
  ];
  for (const s of kept) assert.equal(classifyStatement(s).keep, true, s);
});

test('tenant-ddl: the real migrations transform cleanly; the role files are excluded; no zeusi. qualifier survives', () => {
  const files = tenantStatements(S);
  const names = files.map((f) => f.name);
  for (const x of TENANT_EXCLUDED_FILES) assert.ok(!names.includes(x), x);
  assert.ok(names.includes('0001_core.sql') && names.includes('0013_decision_links.sql'));
  for (const f of files) {
    for (const s of f.statements) {
      assert.ok(!/(?<![\w.$])zeusi\.(?=[A-Za-z_"%])/.test(s), `${f.name}: zeusi. left`);
      assert.equal(classifyStatement(s).keep, true);
    }
  }
  // 0010's work-scope read policy (a DO block) is dropped; its scope enum value is kept.
  const f10 = files.find((f) => f.name === '0010_wall_client_admit.sql')!;
  assert.ok(f10.statements.some((s) => /ADD VALUE IF NOT EXISTS 'client'/.test(s)));
  assert.ok(!f10.statements.some((s) => /POLICY/.test(s)));
});

test('tenant-ddl: a migration that leaves a bare zeusi reference refuses the whole DDL', () => {
  const bad: MigrationFile[] = [...listMigrations(), { name: '9999_bad.sql', sha256: '0'.repeat(64), sql: `CREATE FUNCTION zeusi.g() RETURNS int LANGUAGE sql SET search_path = zeusi AS $$ SELECT 1 $$;` }];
  assert.throws(() => tenantStatements(S, bad), /9999_bad\.sql: a bare zeusi schema reference/);
});

// ---------------------------------------------------------------------------
// PGlite: a provisioned workspace

async function shape(schema: string): Promise<Record<string, string[]>> {
  return asOwner(db, async () => {
    // The schema name inside a signature (a type of the same schema) is the only expected difference.
    const rows = async (sql: string) => (await db.query<{ x: string }>(sql, [schema])).rows.map((r) => r.x.split(`${schema}.`).join('zeusi.')).sort();
    return {
      columns: await rows(`SELECT table_name || '.' || column_name || ':' || data_type || ':' || is_nullable AS x FROM information_schema.columns WHERE table_schema = $1 AND table_name <> 'schema_migrations'`),
      relations: await rows(`SELECT c.relname || ':' || c.relkind::text AS x FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname NOT LIKE 'schema_migrations%'`),
      functions: await rows(`SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' || p.prosecdef::text AS x FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1`),
      triggers: await rows(`SELECT c.relname || '.' || t.tgname AS x FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND NOT t.tgisinternal`),
      enums: await rows(`SELECT ty.typname || ':' || string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder) AS x FROM pg_type ty JOIN pg_enum e ON e.enumtypid = ty.oid JOIN pg_namespace n ON n.oid = ty.typnamespace WHERE n.nspname = $1 GROUP BY ty.typname`),
      wallSeeds: await rows(`SELECT 'n=' || count(*)::text AS x FROM ${schema === 'zeusi' ? 'zeusi' : `"${schema}"`}.wall_denylist WHERE $1::text IS NOT NULL`),
    };
  });
}

async function teamSnapshot(): Promise<string> {
  return asOwner(db, async () => JSON.stringify({
    acl: (await db.query(`SELECT c.relname, c.relacl::text AS acl, c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'zeusi' ORDER BY 1`)).rows,
    fnacl: (await db.query(`SELECT p.proname, p.proacl::text AS acl FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'zeusi' ORDER BY 1, 2`)).rows,
    nsacl: (await db.query(`SELECT nspacl::text AS acl FROM pg_namespace WHERE nspname = 'zeusi'`)).rows,
    policies: (await db.query(`SELECT tablename, policyname, roles::text, qual FROM pg_policies WHERE schemaname = 'zeusi' ORDER BY 1, 2`)).rows,
    counts: (await db.query(`SELECT (SELECT count(*) FROM zeusi.notes)::int n, (SELECT count(*) FROM zeusi.chunks)::int c, (SELECT count(*) FROM zeusi.decisions)::int d,
                                    (SELECT count(*) FROM zeusi.facts)::int f, (SELECT count(*) FROM zeusi.wall_denylist)::int w, (SELECT count(*) FROM zeusi.schema_migrations)::int m`)).rows,
  }));
}

let provisioned: string;

test('tenant-ddl (PGlite): a workspace provisioned as zeusi_tenant_admin has the shape of zeusi; zeusi itself is unchanged', async () => {
  const beforeSnap = await teamSnapshot();
  const r = await dir.provision('github:9001');
  assert.equal(r.kind, 'created');
  provisioned = (r as { tenantId: string }).tenantId;
  const [a, b] = [await shape('zeusi'), await shape(provisioned)];
  for (const k of Object.keys(a)) assert.deepEqual(b[k], a[k], `${k} differ`);
  assert.equal(await teamSnapshot(), beforeSnap, 'zeusi ACLs, policies and row counts are unchanged');
  const applied = await asOwner(db, async () => (await db.query<{ filename: string }>(`SELECT filename FROM "${provisioned}".schema_migrations ORDER BY 1`)).rows.map((x) => x.filename));
  assert.deepEqual(applied, listMigrations().map((f) => f.name).filter((n) => !TENANT_EXCLUDED_FILES.includes(n)));
});

test('tenant-ddl (PGlite): workspace objects are granted only to the owner and the workspace role; no the team role can read them', async () => {
  await asOwner(db, async () => {
    const role = `${provisioned}_r`;
    assert.deepEqual((await db.query(TENANT_ACL_AUDIT_SQL, [provisioned, role])).rows, []);
    for (const r of ['zeusi_read', 'zeusi_box_ro', 'zeusi_cloud_ro', 'zeusi_ingest', 'zeusi_backup', 'zeusi_tenant_rt']) {
      assert.equal((await db.query<{ u: boolean }>(`SELECT has_schema_privilege($1::text, $2::text, 'USAGE') AS u`, [r, provisioned])).rows[0]!.u, false, r);
      assert.equal((await db.query<{ s: boolean }>(`SELECT has_table_privilege($1::text, $2::text, 'SELECT') AS s`, [r, `${provisioned}.notes`])).rows[0]!.s, false, r);
    }
    const pols = (await db.query<{ roles: string; name: string; cmd: string }>(`SELECT roles::text, policyname AS name, cmd FROM pg_policies WHERE schemaname = $1`, [provisioned])).rows;
    // PR 2 (docs/plans/2026-11-18-workspace-write-import-plan.md KTD3): read policies name only the
    // workspace role; the writer role <id>_w has its own tenant_write policies and nothing else.
    const readPols = pols.filter((p) => p.name !== 'tenant_write');
    assert.ok(readPols.length >= 10 && readPols.every((p) => p.roles === `{${role}}` && p.cmd === 'SELECT'));
    assert.ok(pols.filter((p) => p.name === 'tenant_write').every((p) => p.roles === `{${provisioned}_w}`));
    for (const t of ['wall_denylist', 'wall_allow', 'quarantine', 'schema_migrations']) {
      assert.equal((await db.query<{ s: boolean }>(`SELECT has_table_privilege($1::text, $2::text, 'SELECT') AS s`, [role, `${provisioned}.${t}`])).rows[0]!.s, false, t);
    }
  });
});

test('tenant-ddl (PGlite): TENANT_READ_TABLES is exactly what zeusi_read may SELECT in zeusi', async () => {
  const team = await asOwner(db, async () => (await db.query<{ relname: string }>(
    `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'zeusi' AND c.relkind IN ('r', 'v', 'p') AND has_table_privilege('zeusi_read', c.oid, 'SELECT') ORDER BY 1`)).rows.map((r) => r.relname));
  assert.deepEqual([...TENANT_READ_TABLES].sort(), team);
});

test('tenant-ddl (PGlite): a grant that slips the statement filter is caught by the ACL audit; nothing is committed', async () => {
  // To a team role: the epilogue's REVOKE ... FROM PUBLIC would not remove it (a PUBLIC grant it would).
  const sneaky = `DO $$ BEGIN EXECUTE 'GR' || 'ANT SELECT ON zeusi.notes TO zeusi_read'; END $$;`;
  assert.equal(classifyStatement(sneaky).keep, true, 'the filter alone does not see it');
  const files: MigrationFile[] = [...listMigrations(), { name: '9998_sneaky.sql', sha256: '0'.repeat(64), sql: sneaky }];
  const count = async () => asOwner(db, async () => (await db.query<{ n: number; r: number }>(
    `SELECT (SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'zt\\_%')::int n, (SELECT count(*) FROM pg_roles WHERE rolname LIKE 'zt\\_%')::int r`)).rows[0]!);
  const before0 = await count();
  const d = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin'), files });
  await assert.rejects(d.provision('github:9002'), (e: unknown) => e instanceof TenantError && /ACL audit failed/.test((e as Error).message));
  assert.deepEqual(await count(), before0, 'no schema, no role left behind');
  assert.equal(await dir.lookup('github:9002'), null, 'no catalog row');
});
