// `zeusi workspaces delete` (docs/plans/2026-11-20-workspaces-delete.md): the audit keys (U1), one predicate for a
// workspace's grants (U2) and TenantDirectory.deleteWorkspace (U3), on PGlite with the real migrations, the real tenant
// logins and the writer login (test/helpers/tenant-fixture.ts), and a real OAuth store file in a 0700 temp dir.
// Every token, DEK, PRF output and recovery code below is a TEST value. No network, no Neon, no real workspace.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Db } from '../src/db.ts';
import { mintToken } from '../src/mcp-token-admin.ts';
import { OAuthStore, OAuthStoreError } from '../src/mcp-oauth-store.ts';
import { parseToken, readTokenFile, verifySecret } from '../src/mcp-tokens.ts';
import { TENANT_ACL_AUDIT_SQL, tenantRole, tenantWriterRole } from '../src/tenant-ddl.ts';
import {
  TENANT_ADMIN_ROLE, TENANT_RT_ROLE, TENANT_WR_ROLE, TenantBusy, TenantCommitUnknown, TenantDirectory, TenantError, TenantRefused, TenantRouter, TenantWriter,
} from '../src/tenants.ts';
import { AUDIT_COUNT_KEYS, buildWsAuditLine, WS_AUDIT_ACTIONS, WS_AUDIT_FIELDS, WS_AUDIT_OUTCOMES, wsAuditSink } from '../src/workspace-audit.ts';
import {
  deleteRefusal, runWorkspaceDelete, WorkspaceDeleteRefused, type WorkspaceDeleteArgs, type WorkspaceDeleteDeps, type WorkspaceDeleteDirectory,
} from '../src/workspace-delete.ts';
import { enrollmentWraps } from '../src/workspace-keys.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { fingerprint } from './redact.ts';
import { asLogin, asOwner, plantInWorkspace, plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';

/** One lexical token in every planted workspace value: a leak is a substring match. */
const CANARY = 'wsdelcanarynumbat';
const KEY = 'k'.repeat(48);

let db: Db;
let dir: TenantDirectory;
let dirOn: TenantDirectory;
let router: TenantRouter;
let writer: TenantWriter;
/** Admin sessions opened so far (a refusal must not open one). */
let connects = 0;
/** When set, every statement of an admin session is recorded here. */
let sqlLog: string[] | null = null;
/** FAULT INJECTION: an admin-session statement matching this is silently not executed (as if it did nothing). */
let skipSql: RegExp | null = null;
/** FAULT INJECTION: an admin-session statement matching `re` throws a database error with SQLSTATE `code` instead. */
let failSql: { re: RegExp; code: string } | null = null;
let subjects = 7100;
const nextSubject = () => `github:${subjects++}`;

before(async () => {
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  const admin = asLogin(db, TENANT_ADMIN_ROLE);
  const connectAdmin = async (): Promise<Db> => {
    connects++;
    const s = await admin();
    const log = sqlLog;
    const skip = skipSql;
    const fail = failSql;
    if (!log && !skip && !fail) return s;
    const boom = (sql: string) => {
      if (fail?.re.test(sql)) throw Object.assign(new Error('injected failure'), { code: fail.code });
    };
    return {
      ...s,
      query: (sql, params) => { log?.push(sql); boom(sql); return s.query(sql, params); },
      exec: async (sql) => { log?.push(sql); boom(sql); if (!skip?.test(sql)) await s.exec(sql); },
    };
  };
  dir = new TenantDirectory({ connectAdmin });
  dirOn = new TenantDirectory({ connectAdmin, bornEncrypted: true });
  router = new TenantRouter({ connectRuntime: asLogin(db, TENANT_RT_ROLE), cacheMs: 0 });
  writer = new TenantWriter({ connectWriter: asLogin(db, TENANT_WR_ROLE), check: (t) => router.check(t) });
});
after(async () => {
  await db.close();
});

// ---------------------------------------------------------------------------
// Helpers (as the PGlite superuser)

const one = async <T>(sql: string, params: unknown[] = []) => asOwner(db, async () => (await db.query<T>(sql, params)).rows[0]!);
const ownerExec = (sql: string) => asOwner(db, async () => db.exec(sql));
const provision = async (d = dir) => ((await d.provision(nextSubject())) as { tenantId: string }).tenantId;
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');
const sqlState = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? (e as Error).name;
  }
};

async function enroll(d: TenantDirectory, t: string): Promise<void> {
  const e = enrollmentWraps({ tenant: t, prfOutput: randomBytes(32), credentialId: randomBytes(16), prfSalt: randomBytes(32) });
  assert.equal(await d.enroll(t, { passkey: e.passkey, recovery: e.recovery }), 'enrolled');
  e.dek.fill(0);
}

/** A provisioned workspace with content, a writer role and two key wraps. */
async function fullWorkspace(): Promise<string> {
  const t = await provision();
  await plantInWorkspace(db, t, `${CANARY}${t.slice(-4)}`);
  await enroll(dir, t);
  return t;
}

/** What is left of workspace `t` anywhere: schema, roles, memberships, shared deps, catalog rows. */
async function traces(t: string, roleOids: readonly number[] = []): Promise<Record<string, number>> {
  const r = await one<Record<string, number>>(`
    SELECT (SELECT count(*)::int FROM pg_namespace WHERE nspname = $1) AS schema,
           (SELECT count(*)::int FROM pg_roles WHERE rolname IN ($1 || '_r', $1 || '_w')) AS roles,
           (SELECT count(*)::int FROM pg_auth_members m WHERE m.roleid::int8 = ANY ($2::int8[]) OR m.member::int8 = ANY ($2::int8[])) AS memberships,
           (SELECT count(*)::int FROM pg_shdepend WHERE refclassid = 'pg_authid'::regclass AND refobjid::int8 = ANY ($2::int8[])) AS shdepend,
           (SELECT count(*)::int FROM zeusi_tenants.tenants WHERE tenant_id = $1) AS tenants,
           (SELECT count(*)::int FROM zeusi_tenants.members WHERE tenant_id = $1) AS members,
           (SELECT count(*)::int FROM zeusi_tenants.key_wraps WHERE tenant_id = $1) AS key_wraps`, [t, [...roleOids]]);
  return { ...r };
}

async function roleOids(t: string): Promise<number[]> {
  return asOwner(db, async () => (await db.query<{ oid: number }>(`SELECT oid::int8 AS oid FROM pg_roles WHERE rolname IN ($1 || '_r', $1 || '_w') ORDER BY 1`, [t])).rows
    .map((r) => Number(r.oid)));
}

/**
 * Everything in the database EXCEPT workspace `t` (its schema, its two roles and their memberships, its catalog rows):
 * namespaces, relations, columns, constraints, functions, triggers, policies, defaults (with ACLs), roles,
 * memberships and a digest of every row of every table. A delete of `t` must leave this string byte-identical.
 */
async function worldExcept(t: string): Promise<string> {
  return asOwner(db, async () => {
    const rs = [`${t}_r`, `${t}_w`];
    const keep = `n.nspname NOT IN ($1::text, 'pg_catalog', 'information_schema', 'pg_toast') AND n.nspname NOT LIKE 'pg\\_temp\\_%' AND n.nspname NOT LIKE 'pg\\_toast\\_temp\\_%'`;
    const shape = (await db.query<{ x: string }>(`
      SELECT concat_ws(' ', 'ns', n.nspname, n.nspacl::text) AS x FROM pg_namespace n WHERE ${keep}
      UNION ALL SELECT concat_ws(' ', 'rel', n.nspname, c.relname, c.relkind, c.relacl::text, c.relrowsecurity) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE ${keep}
      UNION ALL SELECT concat_ws(' ', 'col', n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull)
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE ${keep} AND a.attnum > 0 AND NOT a.attisdropped
      UNION ALL SELECT concat_ws(' ', 'con', n.nspname, k.conname, pg_get_constraintdef(k.oid)) FROM pg_constraint k JOIN pg_namespace n ON n.oid = k.connamespace WHERE ${keep}
      UNION ALL SELECT concat_ws(' ', 'fn', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), p.proacl::text, md5(coalesce(p.prosrc, '')))
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE ${keep}
      UNION ALL SELECT concat_ws(' ', 'trg', n.nspname, c.relname, g.tgname, g.tgenabled) FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE ${keep}
      UNION ALL SELECT concat_ws(' ', 'pol', n.nspname, c.relname, p.polname, p.polroles::regrole[]::text, pg_get_expr(p.polqual, p.polrelid))
        FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE ${keep}
      UNION ALL SELECT concat_ws(' ', 'def', n.nspname, c.relname, d.adnum, pg_get_expr(d.adbin, d.adrelid)) FROM pg_attrdef d JOIN pg_class c ON c.oid = d.adrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE ${keep}
      UNION ALL SELECT concat_ws(' ', 'role', rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls, rolconnlimit) FROM pg_roles WHERE rolname <> ALL ($2::text[])
      UNION ALL SELECT concat_ws(' ', 'mem', r.rolname, u.rolname, g.rolname, m.admin_option, m.inherit_option, m.set_option)
        FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member JOIN pg_roles g ON g.oid = m.grantor
       WHERE r.rolname <> ALL ($2::text[]) AND u.rolname <> ALL ($2::text[])
      ORDER BY 1`, [t, rs])).rows.map((r) => r.x);
    const tables = (await db.query<{ s: string; t: string }>(
      `SELECT n.nspname AS s, c.relname AS t FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE ${keep} AND c.relkind IN ('r', 'p') ORDER BY 1, 2`, [t])).rows;
    const rows: string[] = [];
    for (const x of tables) {
      const cat = x.s === 'zeusi_tenants';
      const r = (await db.query<{ n: number; h: string }>(
        `SELECT count(*)::int AS n, md5(coalesce(string_agg(to_jsonb(x)::text, ',' ORDER BY to_jsonb(x)::text), '')) AS h FROM "${x.s}"."${x.t}" x${cat ? ' WHERE x.tenant_id <> $1' : ''}`,
        cat ? [t] : [])).rows[0]!;
      rows.push(`rows ${x.s}.${x.t} ${r.n} ${r.h}`);
    }
    return [...shape, ...rows].join('\n');
  });
}

/** Workspace `t` itself: its schema shape and rows, roles, memberships and catalog rows (a dry run must not move it). */
async function workspaceItself(t: string): Promise<string> {
  return asOwner(db, async () => {
    const x = (await db.query<{ x: string }>(`
      SELECT concat_ws(' ', 'rel', c.relname, c.relkind, c.relacl::text) AS x FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1
      UNION ALL SELECT concat_ws(' ', 'role', rolname, rolcanlogin, rolinherit) FROM pg_roles WHERE rolname IN ($1 || '_r', $1 || '_w')
      UNION ALL SELECT concat_ws(' ', 'mem', r.rolname, u.rolname, m.admin_option, m.set_option) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
       WHERE r.rolname IN ($1 || '_r', $1 || '_w')
      UNION ALL SELECT concat_ws(' ', 'tenant', status, enc_state) FROM zeusi_tenants.tenants WHERE tenant_id = $1
      UNION ALL SELECT concat_ws(' ', 'member', subject) FROM zeusi_tenants.members WHERE tenant_id = $1
      UNION ALL SELECT concat_ws(' ', 'wrap', wrap_id, kind, md5(sealed_dek)) FROM zeusi_tenants.key_wraps WHERE tenant_id = $1
      ORDER BY 1`, [t])).rows.map((r) => r.x);
    for (const tb of (await db.query<{ t: string }>(`SELECT c.relname AS t FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind = 'r' ORDER BY 1`, [t])).rows) {
      x.push(`rows ${tb.t} ${(await db.query<{ h: string }>(`SELECT md5(coalesce(string_agg(to_jsonb(x)::text, ',' ORDER BY to_jsonb(x)::text), '')) AS h FROM "${t}"."${tb.t}" x`)).rows[0]!.h}`);
    }
    return x.join('\n');
  });
}

// ---------------------------------------------------------------------------
// U1: the audit allowlist

test('U1 audit: a workspace_delete line carries the seven new count keys, the dry_run outcome, and exactly the existing fields', () => {
  assert.ok((WS_AUDIT_ACTIONS as readonly string[]).includes('workspace_delete'));
  assert.ok((WS_AUDIT_OUTCOMES as readonly string[]).includes('dry_run'));
  for (const k of ['grants', 'members', 'key_wraps', 'tenants', 'schemas', 'roles', 'rows']) assert.ok((AUDIT_COUNT_KEYS as readonly string[]).includes(k), k);
  const T = `zt_${'d'.repeat(26)}`;
  const counts = { grants: 3, members: 1, key_wraps: 2, tenants: 1, schemas: 1, roles: 2, rows: 41 };
  for (const outcome of ['ok', 'dry_run', 'empty', 'busy', 'failed', 'partial'] as const) {
    const line = JSON.parse(buildWsAuditLine({ requestId: null, subject: null, tenantId: T, grantId: null, action: 'workspace_delete', outcome, counts }));
    assert.deepEqual(Object.keys(line), [...WS_AUDIT_FIELDS], outcome);
    assert.equal(line.action, 'workspace_delete');
    assert.equal(line.outcome, outcome);
    assert.equal(line.tenant_id, T);
    assert.deepEqual(line.counts, counts);
    assert.equal(line.github_subject, null);
    assert.equal(line.grant_hash, null);
  }
});

test('U1 audit: a refused delete of team serialises tenant_id null and no reason; unknown count keys and non-numbers are dropped', () => {
  const line = JSON.parse(buildWsAuditLine({
    requestId: null, subject: null, tenantId: 'work', grantId: null, action: 'workspace_delete', outcome: 'refused',
    counts: { grants: 1, reason: 4, roles: 'two', schemas: -1, rows: 1.5 } as never,
  }));
  assert.deepEqual(Object.keys(line), [...WS_AUDIT_FIELDS]);
  assert.equal(line.tenant_id, null);
  assert.equal(line.outcome, 'refused');
  assert.deepEqual(line.counts, { grants: 1 });
  assert.ok(!('reason' in line));
});

// ---------------------------------------------------------------------------
// U2: one predicate for "the grants of a workspace"

test('U2 store: countTenantGrants uses the revokeTenant predicate (equal count, target only) and never writes the file', () => {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-wsdel-store-'));
  chmodSync(d, 0o700);
  const path = join(d, 'mcp-oauth.json');
  const store = new OAuthStore({ hashKey: KEY, path });
  const T = `zt_${'e'.repeat(26)}`;
  const N = `zt_${'f'.repeat(26)}`;
  const grant = (tenant: string) => store.createGrant({ clientId: 'zc_client', subject: 'github:9', login: 'u', tenant, workspaceWrite: tenant !== 'work' });
  grant(T);
  grant(T);
  const gone = grant(T);
  grant(N);
  grant('work');
  const legacy = grant('work');
  assert.equal(store.revokeGrant(gone.grant.grant_id), true, 'a revoked grant is not counted');
  // A grant written before open sign-up has no tenant field and reads as team.
  const doc = JSON.parse(readFileSync(path, 'utf8'));
  delete doc.grants.find((g: { grant_id: string }) => g.grant_id === legacy.grant.grant_id).tenant;
  writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600 });
  const reader = new OAuthStore({ path });
  const bytes = sha(readFileSync(path));
  const mtime = statSync(path).mtimeMs;
  assert.equal(reader.countTenantGrants(T), 2);
  assert.equal(reader.countTenantGrants(N), 1);
  assert.equal(reader.countTenantGrants('work'), 2, 'the work grant and the legacy grant: the same predicate as revokeTenant');
  assert.equal(reader.countTenantGrants(`zt_${'g'.repeat(26)}`), 0);
  assert.equal(sha(readFileSync(path)), bytes, 'counting never writes');
  assert.equal(statSync(path).mtimeMs, mtime);
  assert.ok(!existsSync(`${path}.lock`), 'counting never takes the write lock');
  assert.equal(reader.revokeTenant(T), 2, 'revokeTenant takes exactly what countTenantGrants counted');
  assert.equal(reader.countTenantGrants(T), 0);
  assert.equal(reader.countTenantGrants(N), 1, 'the neighbour keeps its grant');
  assert.equal(reader.countTenantGrants('work'), 2, 'the work tenant keeps its grants');
});

// ---------------------------------------------------------------------------
// U3: TenantDirectory.deleteWorkspace

test('U3 refusal (KTD2): team, zeusi, wildcard, quote, comment, oversized and role-shaped ids are refused before any connection', async () => {
  const A = await provision();
  const bad = [
    'work', 'zeusi', 'zeusi_tenants', 'public', 'pg_catalog', '%', '_', 'zt\\_%', `zt_${'a'.repeat(25)}%`, `zt_${'a'.repeat(25)}_`,
    "zt_'aaaaaaaaaaaaaaaaaaaaaaaaa", `${A}'`, `${A}"`, `${A}; DROP SCHEMA zeusi CASCADE`, `${A}--`, `${A} `, ` ${A}`, `${A}\n`,
    `zt_${'a'.repeat(27)}`, `zt_${'a'.repeat(5000)}`, `zt_${'a'.repeat(25)}`, `${A}_r`, `${A}_w`, A.toUpperCase(), `zt_${'1'.repeat(26)}`, '',
  ];
  const n0 = connects;
  const w0 = await worldExcept('zt_none');
  for (const id of bad) {
    for (const dryRun of [true, false]) {
      await assert.rejects(dir.deleteWorkspace(id, { dryRun }), TenantRefused, JSON.stringify(id));
    }
  }
  await assert.rejects(dir.deleteWorkspace(undefined as unknown as string, { dryRun: false }), TenantRefused);
  await assert.rejects(dir.deleteWorkspace(42 as unknown as string, { dryRun: false }), TenantRefused);
  assert.equal(connects, n0, 'no admin session was opened');
  assert.equal(await worldExcept('zt_none'), w0, 'nothing changed anywhere');
  assert.deepEqual(await traces(A), { schema: 1, roles: 2, memberships: 0, shdepend: 0, tenants: 1, members: 1, key_wraps: 0 });
});

test('U3 dry run (KTD3): one READ ONLY transaction, no lock, no ensure, no write; counts and names of what would go', async () => {
  // A database whose catalog was never created: the dry run must not create it (not even the ensure path).
  const fresh = await tenantTestDb({ writer: true });
  try {
    assert.equal((await fresh.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = 'zeusi_tenants'`)).rows[0]!.n, 0, 'no catalog yet');
    const d0 = new TenantDirectory({ connectAdmin: asLogin(fresh, TENANT_ADMIN_ROLE) });
    const r0 = await d0.deleteWorkspace(`zt_${'h'.repeat(26)}`, { dryRun: true });
    assert.deepEqual([r0.before.tenants, r0.before.members, r0.before.keyWraps, r0.before.schema, r0.before.rows], [0, 0, 0, false, 0]);
    assert.deepEqual(r0.before.roles.map((r) => r.exists), [false, false]);
    assert.equal((await fresh.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = 'zeusi_tenants'`)).rows[0]!.n, 0);
  } finally {
    await fresh.close();
  }
  const D = await fullWorkspace();
  await dir.overlayStep(D, 'prepare', { dryRun: false });
  const itself = await workspaceItself(D);
  const world = await worldExcept(D);
  sqlLog = [];
  const r = await dir.deleteWorkspace(D, { dryRun: true });
  const log = sqlLog;
  sqlLog = null;
  assert.equal(r.dryRun, true);
  assert.equal(r.tenantId, D);
  assert.deepEqual([r.before.tenants, r.before.members, r.before.keyWraps, r.before.schema], [1, 1, 2, true]);
  assert.deepEqual(r.before.roles.map((x) => [x.role, x.exists, x.admin, x.held, x.otherMemberships]), [
    [tenantRole(D), true, true, true, 0], [tenantWriterRole(D), true, true, true, 0],
  ]);
  const byName = new Map(r.before.tables.map((t) => [t.table, t.rows]));
  assert.equal(byName.get('notes'), 1);
  assert.equal(byName.get('chunks'), 1);
  assert.ok(byName.has('enc_progress') && byName.has('b1_index'), 'the overlay tables are listed');
  assert.ok(r.before.tables.every((t) => /^[a-z_][a-z0-9_]*$/.test(t.table)));
  assert.equal(r.before.rows, r.before.tables.reduce((a, t) => a + (t.rows ?? 0), 0));
  assert.deepEqual(r.removed, { tenants: 0, members: 0, keyWraps: 0, schemas: 0, roles: 0, rows: 0 });
  assert.equal(await workspaceItself(D), itself, 'the workspace is untouched');
  assert.equal(await worldExcept(D), world, 'nothing else moved');
  assert.deepEqual(log.filter((s) => /^BEGIN/i.test(s)), ['BEGIN TRANSACTION READ ONLY'], 'one READ ONLY transaction');
  assert.ok(!log.some((s) => /pg_advisory|CREATE SCHEMA IF NOT EXISTS/i.test(s)), 'no lock, no catalog ensure');
  assert.ok(!log.some((s) => /^\s*(DELETE|DROP|INSERT|UPDATE|CREATE|ALTER|GRANT|REVOKE|TRUNCATE|COMMIT)\b/i.test(s)), log.join('\n'));
  assert.ok(log.includes('ROLLBACK'));
  assert.ok(!JSON.stringify(r).includes(CANARY), 'the result carries no value');
});

test('U3 apply (KTD3, KTD6): schema, both roles, their memberships and shared deps, and the catalog rows go; everything else is byte-identical', async () => {
  const T = await fullWorkspace();
  const N = await fullWorkspace();
  const oids = await roleOids(T);
  assert.equal(oids.length, 2);
  assert.notDeepEqual(await traces(T, oids), { schema: 0, roles: 0, memberships: 0, shdepend: 0, tenants: 0, members: 0, key_wraps: 0 });
  const world = await worldExcept(T);
  const before = await dir.deleteWorkspace(T, { dryRun: true });
  sqlLog = [];
  const r = await dir.deleteWorkspace(T, { dryRun: false });
  const log = sqlLog;
  sqlLog = null;
  assert.equal(r.dryRun, false);
  assert.deepEqual(r.removed, { tenants: 1, members: 1, keyWraps: 2, schemas: 1, roles: 2, rows: before.before.rows });
  assert.ok(r.removed.rows > 0);
  assert.deepEqual(await traces(T, oids), { schema: 0, roles: 0, memberships: 0, shdepend: 0, tenants: 0, members: 0, key_wraps: 0 });
  assert.equal(await worldExcept(T), world, 'the neighbour, the work tenant and every other object are byte-identical');
  // One transaction, the fixed order of KTD3.
  const at = (re: RegExp) => log.findIndex((s) => re.test(s));
  const order = [/^BEGIN$/, /lock_timeout = '5s'/, /pg_advisory_xact_lock/, /CREATE SCHEMA IF NOT EXISTS zeusi_tenants/, /DELETE FROM zeusi_tenants\.key_wraps/,
    /DELETE FROM zeusi_tenants\.members/, /DELETE FROM zeusi_tenants\.tenants/, /^DROP SCHEMA IF EXISTS "zt_[a-z2-7]{26}" CASCADE$/,
    /^DROP ROLE IF EXISTS "zt_[a-z2-7]{26}_r"$/, /^DROP ROLE IF EXISTS "zt_[a-z2-7]{26}_w"$/, /^COMMIT$/].map(at);
  assert.ok(order.every((i, k) => i >= 0 && (k === 0 || i > order[k - 1]!)), `order ${order.join(',')}`);
  assert.equal(log.filter((s) => /^(BEGIN|COMMIT)$/.test(s)).length, 2, 'exactly one transaction');
  const destructive = log.filter((s) => /^\s*(DELETE|DROP)\b/i.test(s));
  assert.equal(destructive.length, 6, destructive.join('\n'));
  assert.ok(destructive.every((s) => !/\bLIKE\b|\$\{|%/i.test(s)), 'no pattern match in a destructive statement');
  assert.ok(destructive.filter((s) => /^DELETE/.test(s)).every((s) => /WHERE tenant_id = \$1 /.test(s)), 'catalog deletes bind the id');
  assert.ok(!log.some((s) => /DROP OWNED/i.test(s)));
  // The neighbour still works end to end.
  const rd = await router.open(N);
  assert.equal((await rd.query<{ n: number }>('SELECT count(*)::int AS n FROM zeusi.notes')).rows[0]!.n, 1);
  await rd.close();
  const wr = await writer.open(N);
  await wr.close();
  assert.equal((await asOwner(db, async () => (await db.query(TENANT_ACL_AUDIT_SQL, [N, tenantRole(N)])).rows)).length, 0);
  // The deleted workspace cannot be opened any more.
  await assert.rejects(router.open(T), TenantRefused);
  await assert.rejects(writer.open(T), TenantRefused);
});

test('U3 idempotent (R13): a second apply and an apply on a never-provisioned id report zeros and do not throw', async () => {
  const T = await fullWorkspace();
  await dir.deleteWorkspace(T, { dryRun: false });
  const world = await worldExcept(T);
  const zero = { tenants: 0, members: 0, keyWraps: 0, schemas: 0, roles: 0, rows: 0 };
  assert.deepEqual((await dir.deleteWorkspace(T, { dryRun: false })).removed, zero);
  assert.deepEqual((await dir.deleteWorkspace(T, { dryRun: true })).before.roles.map((x) => x.exists), [false, false]);
  const never = `zt_${'j'.repeat(26)}`;
  assert.deepEqual((await dir.deleteWorkspace(never, { dryRun: false })).removed, zero);
  assert.equal(await worldExcept(T), world);
});

test('U3 partial leftovers: a lone role, a lone schema or lone catalog rows are each removed', async () => {
  const R = `zt_${'k'.repeat(26)}`;
  const admin = await asLogin(db, TENANT_ADMIN_ROLE)();
  await admin.exec(`CREATE ROLE "${R}_r" NOLOGIN NOINHERIT; CREATE SCHEMA "${R}"`);
  await admin.close();
  const r1 = await dir.deleteWorkspace(R, { dryRun: false });
  assert.deepEqual([r1.removed.roles, r1.removed.schemas, r1.removed.tenants], [1, 1, 0]);
  const C = `zt_${'m'.repeat(26)}`;
  await asOwner(db, async () => {
    await db.query(`INSERT INTO zeusi_tenants.tenants (tenant_id) VALUES ($1)`, [C]);
    await db.query(`INSERT INTO zeusi_tenants.members (subject, tenant_id) VALUES ($1, $2)`, [nextSubject(), C]);
  });
  const r2 = await dir.deleteWorkspace(C, { dryRun: false });
  assert.deepEqual([r2.removed.tenants, r2.removed.members, r2.removed.schemas, r2.removed.roles], [1, 1, 0, 0]);
  for (const t of [R, C]) assert.deepEqual(await traces(t), { schema: 0, roles: 0, memberships: 0, shdepend: 0, tenants: 0, members: 0, key_wraps: 0 });
});

test('U3 outside objects (KTD5): anything outside the schema that CASCADE would take aborts the whole transaction', async () => {
  const V = await fullWorkspace();
  const itself = await workspaceItself(V);
  // Each one is created by the database owner, outside the workspace schema, and depends on an object inside it.
  const outside: Array<[string, string, string]> = [
    ['a view in public', `CREATE VIEW public.wsdel_v1 AS SELECT id FROM "${V}".notes`, 'DROP VIEW public.wsdel_v1'],
    ['a view in zeusi', `CREATE VIEW zeusi.wsdel_v2 AS SELECT id FROM "${V}".chunks`, 'DROP VIEW zeusi.wsdel_v2'],
    ['a column of a workspace row type', `CREATE TABLE public.wsdel_t1 (id int, n "${V}".notes)`, 'DROP TABLE public.wsdel_t1'],
    ['a foreign key into the workspace', `CREATE TABLE public.wsdel_t2 (note_id bigint REFERENCES "${V}".notes (id))`, 'DROP TABLE public.wsdel_t2'],
    ['a default on a workspace sequence', `CREATE TABLE public.wsdel_t3 (n bigint DEFAULT nextval('"${V}".notes_id_seq'))`, 'DROP TABLE public.wsdel_t3'],
    ['a function over a workspace type', `CREATE FUNCTION public.wsdel_f(x "${V}".notes) RETURNS int LANGUAGE sql AS 'SELECT 1'`, 'DROP FUNCTION public.wsdel_f'],
  ];
  for (const [what, create, drop] of outside) {
    await ownerExec(create);
    const world = await worldExcept(V);
    const err = await dir.deleteWorkspace(V, { dryRun: false }).then(() => null, (e: unknown) => e);
    assert.ok(err instanceof TenantError, `${what}: refused`);
    assert.match((err as Error).message, /outside the workspace schema/, what);
    assert.match((err as Error).message, /rolled back, nothing changed/, what);
    assert.doesNotMatch((err as Error).message, /wsdel|zt_|public|zeusi\./, `${what}: no object name in the message`);
    assert.equal(await worldExcept(V), world, `${what}: the outside object survives`);
    assert.equal(await workspaceItself(V), itself, `${what}: the workspace survives (rolled back)`);
    await ownerExec(drop);
  }
  assert.equal((await dir.deleteWorkspace(V, { dryRun: false })).removed.schemas, 1, 'with nothing outside, the delete goes ahead');
});

test('U3 rollback (KTD6): the provisioner without ADMIN on the read role fails with a constant message and SQLSTATE; nothing moved', async () => {
  const L = await fullWorkspace();
  await ownerExec(`REVOKE ADMIN OPTION FOR "${L}_r" FROM ${TENANT_ADMIN_ROLE} CASCADE`);
  const itself = await workspaceItself(L);
  const world = await worldExcept(L);
  const err = await dir.deleteWorkspace(L, { dryRun: false }).then(() => null, (e: unknown) => e);
  assert.ok(err instanceof TenantError);
  assert.equal((err as Error).message, 'workspace delete failed (SQLSTATE 42501); rolled back, nothing changed');
  assert.equal(await workspaceItself(L), itself, 'schema, roles, catalog rows and key wraps are back');
  assert.equal(await worldExcept(L), world);
  const dry = await dir.deleteWorkspace(L, { dryRun: true });
  assert.equal(dry.before.roles[0]!.admin, false, 'the dry run shows the missing ADMIN option');
  // Recovery: the owner gives the ADMIN option back; the delete then completes.
  await ownerExec(`GRANT "${L}_r" TO ${TENANT_ADMIN_ROLE} WITH ADMIN OPTION`);
  assert.equal((await dir.deleteWorkspace(L, { dryRun: false })).removed.roles, 2);
  assert.equal((await traces(L)).schema, 0);
});

test('U3 leftover check (KTD3 step 8): a drop that silently did nothing rolls the whole delete back instead of committing a half-deleted workspace', async () => {
  const H = await fullWorkspace();
  const itself = await workspaceItself(H);
  skipSql = /^DROP ROLE IF EXISTS "zt_[a-z2-7]{26}_w"$/;
  const err = await dir.deleteWorkspace(H, { dryRun: false }).then(() => null, (e: unknown) => e).finally(() => { skipSql = null; });
  assert.ok(err instanceof TenantError);
  assert.equal((err as Error).message, 'workspace delete left part of the workspace behind; rolled back, nothing changed');
  assert.equal(await workspaceItself(H), itself, 'schema, both roles and the catalog rows are back');
  assert.equal((await dir.deleteWorkspace(H, { dryRun: false })).removed.roles, 2, 'without the fault the delete completes');
});

test('U3 failure classes: a lock wait is TenantBusy, a statement timeout is not; a COMMIT that did not complete is TenantCommitUnknown; all constant texts', async () => {
  const F = await fullWorkspace();
  const itself = await workspaceItself(F);
  const outcome = async (re: RegExp, code: string) => {
    failSql = { re, code };
    try {
      return await dir.deleteWorkspace(F, { dryRun: false }).then(() => null, (e: unknown) => e as Error);
    } finally {
      failSql = null;
    }
  };
  const lock = await outcome(/^DROP SCHEMA/, '55P03');
  assert.ok(lock instanceof TenantBusy);
  assert.equal(lock!.message, 'workspace delete waited too long for a lock (SQLSTATE 55P03); rolled back, nothing changed');
  const slow = await outcome(/^DROP SCHEMA/, '57014');
  assert.ok(slow instanceof TenantError && !(slow instanceof TenantBusy), 'a statement timeout is not reported as a lock wait');
  assert.equal(slow!.message, 'workspace delete failed (SQLSTATE 57014); rolled back, nothing changed');
  const commit = await outcome(/^COMMIT$/, '08006');
  assert.ok(commit instanceof TenantCommitUnknown);
  assert.equal(commit!.message, 'workspace delete: COMMIT did not complete (SQLSTATE 08006); the outcome is unknown: run the dry run to see what is left');
  assert.equal(await workspaceItself(F), itself, 'every injected failure rolled back here');
  const odd = await outcome(/^DROP SCHEMA/, 'bad code; DROP TABLE x');
  assert.equal(odd!.message, 'workspace delete failed; rolled back, nothing changed', 'an off-shape code is not echoed');
  assert.equal((await dir.deleteWorkspace(F, { dryRun: false })).removed.schemas, 1);
});

test('U3 authz (security bootstrap): the workspace roles and the runtime and writer logins cannot drop the schema or a role, or delete a catalog row', async () => {
  const X = await fullWorkspace();
  const destructive = [
    `DROP SCHEMA "${X}" CASCADE`, `DROP ROLE "${X}_r"`, `DROP ROLE "${X}_w"`,
    `DELETE FROM zeusi_tenants.tenants WHERE tenant_id = '${X}'`, `DELETE FROM zeusi_tenants.members WHERE tenant_id = '${X}'`,
    `DELETE FROM zeusi_tenants.key_wraps WHERE tenant_id = '${X}'`,
  ];
  for (const [login, role] of [[TENANT_RT_ROLE, null], [TENANT_WR_ROLE, null], [TENANT_RT_ROLE, `${X}_r`], [TENANT_WR_ROLE, `${X}_w`]] as const) {
    for (const sql of destructive) {
      const s = await asLogin(db, login)();
      try {
        if (role) await s.exec(`SET ROLE "${role}"`);
        assert.equal(await sqlState(s.exec(sql)), '42501', `${role ?? login}: ${sql}`);
      } finally {
        await s.close();
      }
    }
  }
  assert.deepEqual(await traces(X), { schema: 1, roles: 2, memberships: 0, shdepend: 0, tenants: 1, members: 1, key_wraps: 2 });
});

test('U3 born encrypted (flag on): a prepared, flipped workspace with wraps is removed, enc_progress and b1_index included', async () => {
  const B = await provision(dirOn);
  await enroll(dirOn, B);
  const dry = await dirOn.deleteWorkspace(B, { dryRun: true });
  const names = dry.before.tables.map((t) => t.table);
  assert.ok(names.includes('enc_progress') && names.includes('b1_index'), names.join(','));
  const oids = await roleOids(B);
  const r = await dirOn.deleteWorkspace(B, { dryRun: false });
  assert.deepEqual([r.removed.tenants, r.removed.members, r.removed.keyWraps, r.removed.schemas, r.removed.roles], [1, 1, 2, 1, 2]);
  assert.deepEqual(await traces(B, oids), { schema: 0, roles: 0, memberships: 0, shdepend: 0, tenants: 0, members: 0, key_wraps: 0 });
});

test('U3 after a delete: provisioning still works, and the deleted subject gets a new, different workspace', async () => {
  const subject = nextSubject();
  const first = ((await dir.provision(subject)) as { tenantId: string }).tenantId;
  await dir.deleteWorkspace(first, { dryRun: false });
  const again = await dir.provision(subject);
  assert.equal(again.kind, 'created');
  const second = (again as { tenantId: string }).tenantId;
  assert.notEqual(second, first);
  assert.equal((await dir.provision(nextSubject())).kind, 'created');
  const rd = await router.open(second);
  await rd.close();
});

// ---------------------------------------------------------------------------
// Security bootstrap (authz): an owner-only CLI path; nothing hosted can reach it

test('security bootstrap (authz): no MCP / hosted source references the delete; only the operator CLI imports its module', () => {
  const src = fileURLToPath(new URL('../src/', import.meta.url));
  const files = (readdirSync(src, { recursive: true }) as string[]).filter((f) => f.endsWith('.ts')).map((f) => f.split('\\').join('/'));
  assert.ok(files.length > 40, 'the scan sees the sources');
  const text = (f: string) => readFileSync(join(src, f), 'utf8');
  for (const f of files.filter((x) => /^mcp[\w-]*\.ts$/.test(x))) {
    assert.doesNotMatch(text(f), /deleteWorkspace|workspace-delete|workspaces delete|DROP SCHEMA|DROP ROLE/, f);
  }
  assert.deepEqual(files.filter((f) => /\bdeleteWorkspace\b/.test(text(f))).sort(), files.filter((f) => ['tenants.ts', 'workspace-delete.ts'].includes(f)).sort(),
    'deleteWorkspace: defined in tenants.ts, called only by src/workspace-delete.ts');
  assert.ok(files.filter((f) => /from '\.\/workspace-delete\.ts'/.test(text(f))).every((f) => f === 'cli.ts'), 'only the CLI imports the delete module');
  // An executed statement starts a string literal; a comment that names the words does not count.
  const drops = files.filter((f) => /[`'"]\s*DROP (SCHEMA|ROLE)\b/.test(text(f)));
  assert.deepEqual(drops, ['tenants.ts'], 'the only DROP SCHEMA / DROP ROLE statements are the delete transaction');
});

// ---------------------------------------------------------------------------
// U4: src/workspace-delete.ts (gates, confirmation, OAuth order, audit, output) on PGlite and a real store file

interface Harness {
  root: string;
  store: string;
  tokens: string;
  /** The hosted server's view of the store (it can hash tokens: grantForAccess). */
  hosted: OAuthStore;
  out: string[];
  err: string[];
  audits: Array<Record<string, unknown>>;
  calls: { preflight: number; asked: string[]; open: number; count: string[]; revoke: string[]; deleted: Array<[string, boolean]> };
  deps: WorkspaceDeleteDeps;
}

/** A 0700 data dir like /data (store file + assistant tokens file) and spying dependencies over the PGlite directory. */
function harness(o: { interactive?: boolean; answer?: string | null; refusePreflight?: string; directory?: WorkspaceDeleteDirectory } = {}): Harness {
  const root = safeMkdtemp(join(tmpdir(), 'zeusi-wsdel-data-'));
  chmodSync(root, 0o700);
  const store = join(root, 'mcp-oauth.json');
  const out: string[] = [];
  const err: string[] = [];
  const audits: Array<Record<string, unknown>> = [];
  const calls: Harness['calls'] = { preflight: 0, asked: [], open: 0, count: [], revoke: [], deleted: [] };
  const target = o.directory ?? dir;
  const deps: WorkspaceDeleteDeps = {
    preflight: () => {
      calls.preflight++;
      if (o.refusePreflight) throw new WorkspaceDeleteRefused(o.refusePreflight);
      return { directory: { deleteWorkspace: (id, x) => { calls.deleted.push([id, x.dryRun]); return target.deleteWorkspace(id, x); } }, warnings: [] };
    },
    interactive: o.interactive ?? false,
    ask: async (q) => { calls.asked.push(q); return o.answer ?? null; },
    storeExists: (p) => existsSync(p),
    openStore: (p) => {
      calls.open++;
      const s = new OAuthStore({ path: p });
      return { countTenantGrants: (t) => { calls.count.push(t); return s.countTenantGrants(t); }, revokeTenant: (t) => { calls.revoke.push(t); return s.revokeTenant(t); } };
    },
    audit: wsAuditSink({ log: (line) => audits.push(JSON.parse(line) as Record<string, unknown>) }),
    out: (l) => out.push(l),
    err: (l) => err.push(l),
  };
  return { root, store, tokens: join(root, 'mcp-tokens.json'), hosted: new OAuthStore({ hashKey: KEY, path: store }), out, err, audits, calls, deps };
}

const dryArgs = (h: Harness, tenantId: string, o: Partial<WorkspaceDeleteArgs> = {}): WorkspaceDeleteArgs => ({
  tenantId, apply: false, confirm: undefined, iTookASnapshot: false, iKnowThisIsMain: false, storePath: h.store, ...o,
});
const applyArgs = (h: Harness, tenantId: string, o: Partial<WorkspaceDeleteArgs> = {}): WorkspaceDeleteArgs => ({
  tenantId, apply: true, confirm: tenantId, iTookASnapshot: true, iKnowThisIsMain: false, storePath: h.store, ...o,
});

/** `n` grants of `tenant` written by the hosted server: their ids and access credentials (TEST values). */
function grantsOf(h: Harness, tenant: string, n = 1) {
  return Array.from({ length: n }, () => {
    const g = h.hosted.createGrant({ clientId: 'zc_client', subject: 'github:4242', login: 'wsdel-user', tenant, workspaceWrite: tenant !== 'work' });
    return { id: g.grant.grant_id, at: g.accessToken, rt: g.refreshToken, hashes: [g.grant.access_hash, g.grant.refresh_hash] };
  });
}
/** Which of these grants still authenticate on the hosted server (it re-reads the file on change). */
const live = (h: Harness, gs: ReadonlyArray<{ at: string }>) => gs.map((g) => h.hosted.grantForAccess(g.at) !== null);
/** Rewrite one grant as written before open sign-up (no tenant field: it reads as team). */
function makeLegacy(h: Harness, grantId: string): void {
  const doc = JSON.parse(readFileSync(h.store, 'utf8'));
  delete doc.grants.find((g: { grant_id: string }) => g.grant_id === grantId).tenant;
  writeFileSync(h.store, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600 });
}
/** One hosted assistant token (argon2id row in mcp-tokens.json): the file digest + mtime, and whether it still verifies. */
async function assistantToken(h: Harness): Promise<{ digest: () => string; verifies: () => Promise<boolean> }> {
  const outFile = join(h.root, 'assistant.token');
  await mintToken({ file: h.tokens, out: outFile, label: 'assistant-one', cls: 'read' });
  const parsed = parseToken(readFileSync(outFile, 'utf8').trim())!;
  return {
    digest: () => `${sha(readFileSync(h.tokens))} ${statSync(h.tokens).mtimeMs}`,
    verifies: async () => {
      const row = readTokenFile(h.tokens).tokens.find((t) => t.token_id === parsed.tokenId);
      return row !== undefined && row.revoked_at === null && (await verifySecret(row, parsed.secret));
    },
  };
}
const ZERO_TRACES = { schema: 0, roles: 0, memberships: 0, shdepend: 0, tenants: 0, members: 0, key_wraps: 0 };

test('U4 gate 1 (KTD2): team, zeusi and malformed ids are refused in dry run and apply before the preflight, the store or the directory', async () => {
  const N = await provision();
  const h = harness({ interactive: true, answer: 'work' });
  const kept = [...grantsOf(h, N), ...grantsOf(h, 'work')];
  const tok = await assistantToken(h);
  const store0 = sha(readFileSync(h.store));
  const tokens0 = tok.digest();
  const world = await worldExcept('zt_none');
  const bad = ['work', 'zeusi', 'ACME', 'the team', '', '%', '_', `${N};--`, `${N} `, `${N}_r`, `${N}_w`, `zt_${'a'.repeat(27)}`, "zt_'x", 'zeusi_tenants', 'public'];
  for (const id of bad) {
    for (const apply of [false, true]) {
      const n = h.audits.length;
      assert.equal(await runWorkspaceDelete(apply ? applyArgs(h, id) : dryArgs(h, id), h.deps), 2, `${JSON.stringify(id)} apply=${apply}`);
      assert.equal(h.audits.length, n + 1, 'exactly one audit line');
      assert.deepEqual([h.audits.at(-1)!['action'], h.audits.at(-1)!['outcome'], h.audits.at(-1)!['tenant_id']], ['workspace_delete', 'refused', null]);
      assert.deepEqual(h.audits.at(-1)!['counts'], {});
    }
  }
  assert.deepEqual([h.calls.preflight, h.calls.asked.length, h.calls.open, h.calls.count.length, h.calls.revoke.length, h.calls.deleted.length], [0, 0, 0, 0, 0, 0]);
  assert.ok(h.err.some((l) => l === 'workspaces delete: refused: work is the team workspace; it is never deleted'));
  assert.ok(h.err.some((l) => l === 'workspaces delete: refused: zeusi is the zeusi schema; it is never deleted'));
  assert.ok(h.err.every((l) => !l.includes(N) && !l.includes("'x")), 'a refused input is never echoed');
  assert.deepEqual(h.out, []);
  assert.equal(sha(readFileSync(h.store)), store0, 'the OAuth store is untouched');
  assert.deepEqual(live(h, kept), [true, true]);
  assert.equal(tok.digest(), tokens0, 'the assistant tokens file is untouched');
  assert.ok(await tok.verifies());
  assert.equal(await worldExcept('zt_none'), world, 'the database is untouched');
  assert.equal(deleteRefusal({ tenantId: 'work', apply: false, confirm: undefined, iTookASnapshot: false, iKnowThisIsMain: false }, true),
    'refused: work is the team workspace; it is never deleted');
});

test('U4 gate 2 (KTD7, KTD8): --confirm, --i-took-a-snapshot and --i-know-this-is-main go with --apply only; --apply needs --i-took-a-snapshot', async () => {
  const h = harness({ interactive: true, answer: 'x' });
  const T = `zt_${'n'.repeat(26)}`;
  for (const [a, re] of [
    [dryArgs(h, T, { confirm: T }), /refused: --confirm goes with --apply$/],
    [dryArgs(h, T, { iTookASnapshot: true }), /refused: --i-took-a-snapshot goes with --apply$/],
    [dryArgs(h, T, { iKnowThisIsMain: true }), /refused: --i-know-this-is-main goes with --apply$/],
    [applyArgs(h, T, { iTookASnapshot: false }), /refused: --apply needs --i-took-a-snapshot: take a Neon snapshot or branch/],
  ] as const) {
    assert.equal(await runWorkspaceDelete(a, h.deps), 2);
    assert.match(h.err.at(-1)!, re);
    assert.deepEqual([h.audits.at(-1)!['outcome'], h.audits.at(-1)!['tenant_id']], ['refused', T]);
  }
  assert.deepEqual([h.calls.preflight, h.calls.asked.length, h.calls.open, h.calls.deleted.length], [0, 0, 0, 0]);
});

test('U4 gate 3 (KTD7): --confirm must equal the id character for character; a neighbour, empty, spaced or upper-case confirm refuses with nothing opened', async () => {
  const T = await fullWorkspace();
  const N = await provision();
  const h = harness();
  const tg = grantsOf(h, T, 2);
  const store0 = sha(readFileSync(h.store));
  const world = await worldExcept('zt_none');
  for (const confirm of [N, '', `${T} `, ` ${T}`, `${T}\n`, T.toUpperCase(), T.slice(0, -1), 'work']) {
    assert.equal(await runWorkspaceDelete(applyArgs(h, T, { confirm }), h.deps), 2, JSON.stringify(confirm));
    assert.equal(h.err.at(-1), 'workspaces delete: refused: --confirm does not match the workspace id; nothing changed');
  }
  assert.deepEqual([h.calls.preflight, h.calls.asked.length, h.calls.open, h.calls.revoke.length, h.calls.deleted.length], [0, 0, 0, 0, 0]);
  assert.equal(sha(readFileSync(h.store)), store0);
  assert.deepEqual(live(h, tg), [true, true]);
  assert.equal(await worldExcept('zt_none'), world, 'nothing in the database moved, the target included');
});

test('U4 typed confirmation (KTD7): no terminal refuses; asked once, only after the preflight; any other answer refuses; the exact id proceeds', async () => {
  const T = await fullWorkspace();
  const h1 = harness({ interactive: false });
  assert.equal(await runWorkspaceDelete(applyArgs(h1, T, { confirm: undefined }), h1.deps), 2);
  assert.equal(h1.err.at(-1), 'workspaces delete: refused: --apply needs --confirm <zt_id> (or a terminal to type the id); nothing changed');
  assert.deepEqual([h1.calls.preflight, h1.calls.asked.length, h1.calls.deleted.length], [0, 0, 0]);
  const h2 = harness({ interactive: true, answer: T, refusePreflight: 'refused: test preflight refusal' });
  assert.equal(await runWorkspaceDelete(applyArgs(h2, T, { confirm: undefined }), h2.deps), 2);
  assert.deepEqual([h2.calls.preflight, h2.calls.asked.length, h2.calls.deleted.length], [1, 0, 0], 'the preflight refused: never asked');
  for (const answer of [`${T} `, T.toUpperCase(), '', `zt_${'q'.repeat(26)}`, null]) {
    const h3 = harness({ interactive: true, answer });
    grantsOf(h3, T);
    assert.equal(await runWorkspaceDelete(applyArgs(h3, T, { confirm: undefined }), h3.deps), 2, JSON.stringify(answer));
    assert.equal(h3.err.at(-1), 'workspaces delete: refused: the typed id does not match; nothing changed');
    assert.deepEqual([h3.calls.preflight, h3.calls.asked.length, h3.calls.open, h3.calls.revoke.length, h3.calls.deleted.length], [1, 1, 0, 0, 0]);
  }
  assert.equal((await traces(T)).schema, 1);
  const h4 = harness({ interactive: true, answer: T });
  grantsOf(h4, T);
  assert.equal(await runWorkspaceDelete(applyArgs(h4, T, { confirm: undefined }), h4.deps), 0);
  assert.equal(h4.calls.asked.length, 1);
  assert.ok(h4.calls.asked[0]!.includes(T), 'the prompt names the workspace');
  assert.deepEqual(h4.calls.deleted, [[T, false]]);
  assert.deepEqual(await traces(T), ZERO_TRACES);
});

test('U4 apply (KTD4, R3-R5): revokeTenant(target) before and after ONE transaction; target grants dead; neighbour, the team, legacy grants and the assistant token intact; audit ok', async () => {
  const T = await fullWorkspace();
  const N = await fullWorkspace();
  const h = harness();
  const tg = grantsOf(h, T, 2);
  const kept = [...grantsOf(h, N), ...grantsOf(h, 'work'), ...grantsOf(h, 'work')];
  makeLegacy(h, kept[2]!.id);
  const tok = await assistantToken(h);
  const tokens0 = tok.digest();
  const oids = await roleOids(T);
  const world = await worldExcept(T);
  const rows = (await dir.deleteWorkspace(T, { dryRun: true })).before.rows;
  assert.equal(await runWorkspaceDelete(applyArgs(h, T), h.deps), 0, h.err.join('\n'));
  assert.deepEqual(h.calls.revoke, [T, T], 'revokeTenant with the target id only, before and after the transaction');
  assert.ok(!h.calls.revoke.includes('work'));
  assert.deepEqual(h.calls.deleted, [[T, false]], 'one database transaction, no dry run');
  assert.deepEqual(live(h, tg), [false, false], 'the target grants no longer authenticate');
  assert.deepEqual(live(h, kept), [true, true, true], 'the neighbour, the work tenant and legacy work grants still do');
  assert.equal(tok.digest(), tokens0, 'the assistant tokens file is untouched');
  assert.ok(await tok.verifies(), 'the assistant token still verifies');
  assert.deepEqual(await traces(T, oids), ZERO_TRACES, 'no orphan');
  assert.equal(await worldExcept(T), world, 'the neighbour, the work tenant and everything else are byte-identical');
  assert.equal(h.audits.length, 1);
  const a = h.audits[0]!;
  assert.deepEqual([a['action'], a['outcome'], a['tenant_id'], a['github_subject'], a['grant_hash'], a['request_id']], ['workspace_delete', 'ok', T, null, null, null]);
  assert.deepEqual(a['counts'], { grants: 2, members: 1, key_wraps: 2, tenants: 1, schemas: 1, roles: 2, rows });
  assert.deepEqual(h.out, [
    `workspace ${T}: deleted`,
    '  OAuth grants revoked: 2',
    '  catalog zeusi_tenants rows removed: tenants 1, members 1, key_wraps 2',
    `  schema ${T} dropped (${(await dir.deleteWorkspace(N, { dryRun: true })).before.tables.length} tables, ${rows} rows)`,
    `  roles dropped: ${T}_r, ${T}_w`,
  ]);
  // Idempotent (R13): again, exit 0, nothing left, outcome empty, zero counts.
  assert.equal(await runWorkspaceDelete(applyArgs(h, T), h.deps), 0);
  assert.deepEqual([h.audits[1]!['outcome'], h.audits[1]!['counts']], ['empty', { grants: 0, members: 0, key_wraps: 0, tenants: 0, schemas: 0, roles: 0, rows: 0 }]);
  assert.deepEqual(h.out.slice(5), [`workspace ${T}: nothing left to delete (already gone); OAuth grants revoked 0`]);
  assert.deepEqual(live(h, kept), [true, true, true]);
  assert.equal(await worldExcept(T), world);
});

test('U4 dry run (R10): counts and names of what would go; the store file and the database unchanged; one dry_run audit line', async () => {
  const T = await fullWorkspace();
  const h = harness();
  grantsOf(h, T, 3);
  grantsOf(h, 'work');
  const store0 = sha(readFileSync(h.store));
  const mtime0 = statSync(h.store).mtimeMs;
  const world = await worldExcept('zt_none');
  assert.equal(await runWorkspaceDelete(dryArgs(h, T), h.deps), 0, h.err.join('\n'));
  assert.deepEqual(h.calls.count, [T]);
  assert.deepEqual(h.calls.revoke, [], 'a dry run never revokes');
  assert.deepEqual(h.calls.deleted, [[T, true]]);
  assert.equal(sha(readFileSync(h.store)), store0);
  assert.equal(statSync(h.store).mtimeMs, mtime0);
  assert.equal(await worldExcept('zt_none'), world);
  const text = h.out.join('\n');
  for (const want of [
    `workspace ${T}: dry run, nothing changed`, '  OAuth grants to revoke: 3', '  catalog zeusi_tenants: tenants 1, members 1, key_wraps 2', `  schema ${T}: present, `,
    'notes 1', 'chunks 1', `  role ${T}_r: present; held by zeusi_tenant_rt yes;`, `  role ${T}_w: present; held by zeusi_tenant_wr yes;`, 'provisioner ADMIN option yes',
    '  would remove: OAuth grants 3, catalog rows 4, schemas 1, roles 2, rows ', `zeusi workspaces delete ${T} --apply --confirm ${T} --i-took-a-snapshot`,
  ]) assert.ok(text.includes(want), want);
  assert.equal(h.audits.length, 1);
  assert.deepEqual([h.audits[0]!['outcome'], h.audits[0]!['tenant_id']], ['dry_run', T]);
  const c = h.audits[0]!['counts'] as Record<string, number>;
  assert.deepEqual([c['grants'], c['tenants'], c['members'], c['key_wraps'], c['schemas'], c['roles']], [3, 1, 1, 2, 1, 2]);
  assert.ok(c['rows']! > 0);
  // Without the store file a dry run says so (KTD10) and still reports the database.
  const h2 = harness();
  assert.equal(await runWorkspaceDelete(dryArgs(h2, T), h2.deps), 0);
  assert.ok(h2.out.includes('  OAuth store file missing: --apply refuses without it (run it on the hosted machine as the user that owns the store)'));
  assert.equal(h2.calls.open, 0);
  assert.ok(!('grants' in (h2.audits[0]!['counts'] as object)));
  // A never-provisioned id without the store: no database object, but the grants are unknown, so never "already gone".
  const h3 = harness();
  const never = `zt_${'r'.repeat(26)}`;
  assert.equal(await runWorkspaceDelete(dryArgs(h3, never), h3.deps), 0);
  assert.ok(h3.out.includes(`  schema ${never}: absent`) && h3.out.includes(`  role ${never}_r: absent`));
  assert.ok(h3.out.includes('  would remove: no database objects; OAuth grants unknown (the store file is missing)'), h3.out.join('\n'));
  assert.ok(!h3.out.some((l) => /already gone/.test(l)));
  // With the store (no grant of that id in it): nothing at all, already gone.
  const h4 = harness();
  grantsOf(h4, 'work');
  assert.equal(await runWorkspaceDelete(dryArgs(h4, never), h4.deps), 0);
  assert.ok(h4.out.includes('  would remove: nothing (already gone)'));
  assert.ok(!h4.out.some((l) => /to delete it/.test(l)));
});

test('U4 database failure after the first revoke (KTD4 step 2): exit 1, audit failed, workspace intact, the output says the grants were revoked and to re-run', async () => {
  const L = await fullWorkspace();
  await ownerExec(`REVOKE ADMIN OPTION FOR "${L}_r" FROM ${TENANT_ADMIN_ROLE} CASCADE`);
  const h = harness();
  const lg = grantsOf(h, L, 2);
  const itself = await workspaceItself(L);
  assert.equal(await runWorkspaceDelete(applyArgs(h, L), h.deps), 1);
  assert.deepEqual(h.calls.revoke, [L], 'revoked before the transaction; no sweep after a rollback');
  assert.deepEqual(live(h, lg), [false, false], 'a failure after step 1 never leaves a usable grant');
  assert.equal(await workspaceItself(L), itself, 'the database rolled back: the workspace is intact');
  assert.deepEqual([h.audits[0]!['outcome'], h.audits[0]!['counts']], ['failed', { grants: 2 }]);
  assert.deepEqual(h.err, [
    'workspaces delete: workspace delete failed (SQLSTATE 42501); rolled back, nothing changed',
    `workspaces delete: 2 OAuth grant(s) of ${L} were revoked before the database step; the database is unchanged. Fix the cause, then re-run --apply.`,
  ]);
  await ownerExec(`GRANT "${L}_r" TO ${TENANT_ADMIN_ROLE} WITH ADMIN OPTION`);
  assert.equal(await runWorkspaceDelete(applyArgs(h, L), h.deps), 0, 'the re-run completes');
  assert.deepEqual([h.audits[1]!['outcome'], (h.audits[1]!['counts'] as Record<string, number>)['grants']], ['ok', 0]);
  assert.deepEqual(await traces(L), ZERO_TRACES);
});

test('U4 OAuth store busy at the first revoke (KTD4 step 1): exit 1, audit busy, the database untouched, nothing revoked', async () => {
  const T = await fullWorkspace();
  const h = harness();
  const tg = grantsOf(h, T);
  const world = await worldExcept('zt_none');
  writeFileSync(`${h.store}.lock`, '', { mode: 0o600 });
  try {
    assert.equal(await runWorkspaceDelete(applyArgs(h, T), h.deps), 1);
  } finally {
    rmSync(`${h.store}.lock`);
  }
  assert.deepEqual(h.calls.deleted, [], 'the transaction never ran');
  assert.equal(await worldExcept('zt_none'), world);
  assert.deepEqual(live(h, tg), [true]);
  assert.deepEqual([h.audits[0]!['outcome'], h.audits[0]!['counts']], ['busy', {}]);
  assert.deepEqual(h.err, ['workspaces delete: the OAuth store is busy (another writer); nothing changed, retry']);
});

test('U4 final sweep fails after COMMIT (KTD4 step 3): exit 1, audit partial with the database counts, re-run sweeps', async () => {
  const T = await fullWorkspace();
  const h = harness();
  grantsOf(h, T);
  const open = h.deps.openStore;
  let revokes = 0;
  h.deps.openStore = (p) => {
    const s = open(p);
    return { countTenantGrants: (t) => s.countTenantGrants(t), revokeTenant: (t) => { if (++revokes === 2) throw new OAuthStoreError('oauth store is locked by another writer'); return s.revokeTenant(t); } };
  };
  assert.equal(await runWorkspaceDelete(applyArgs(h, T), h.deps), 1);
  assert.deepEqual(await traces(T), ZERO_TRACES, 'the database part committed');
  assert.equal(h.audits[0]!['outcome'], 'partial');
  assert.deepEqual([(h.audits[0]!['counts'] as Record<string, number>)['grants'], (h.audits[0]!['counts'] as Record<string, number>)['schemas']], [1, 1]);
  assert.match(h.err.join('\n'), /removed from the database, but the final OAuth grant sweep failed .*re-run --apply/);
  h.deps.openStore = open;
  assert.equal(await runWorkspaceDelete(applyArgs(h, T), h.deps), 0);
  assert.equal(h.audits[1]!['outcome'], 'empty');
});

test('U4 COMMIT outcome unknown (KTD4): the final sweep still runs, exit 1 failed, and the output does not claim the database is unchanged', async () => {
  const T = await fullWorkspace();
  const h = harness();
  const tg = grantsOf(h, T, 2);
  failSql = { re: /^COMMIT$/, code: '08006' };
  let code: number;
  try {
    code = await runWorkspaceDelete(applyArgs(h, T), h.deps);
  } finally {
    failSql = null;
  }
  assert.equal(code, 1);
  assert.deepEqual(h.calls.revoke, [T, T], 'the sweep after the transaction runs even though the outcome is unknown');
  assert.deepEqual(live(h, tg), [false, false]);
  assert.deepEqual([h.audits[0]!['outcome'], h.audits[0]!['counts']], ['failed', { grants: 2 }]);
  assert.deepEqual(h.err, [
    'workspaces delete: workspace delete: COMMIT did not complete (SQLSTATE 08006); the outcome is unknown: run the dry run to see what is left',
    `workspaces delete: 2 OAuth grant(s) of ${T} were revoked; whether the database part committed is unknown. Run the dry run to see what is left, then re-run --apply.`,
  ]);
  assert.ok(!h.err.some((l) => /database is unchanged/.test(l)));
  assert.equal(await runWorkspaceDelete(applyArgs(h, T), h.deps), 0, 'the re-run completes');
  assert.deepEqual(await traces(T), ZERO_TRACES);
});

test('U4 a table the provisioner cannot read: listed as unreadable in the dry run, dropped with the schema, and the report says its rows were not counted', async () => {
  const U = await fullWorkspace();
  await ownerExec(`CREATE TABLE "${U}".wsdel_owner_only (x int); INSERT INTO "${U}".wsdel_owner_only VALUES (1), (2)`);
  const h = harness();
  grantsOf(h, U);
  assert.equal(await runWorkspaceDelete(dryArgs(h, U), h.deps), 0);
  assert.match(h.out.join('\n'), /wsdel_owner_only unreadable/);
  assert.equal(await runWorkspaceDelete(applyArgs(h, U), h.deps), 0, h.err.join('\n'));
  assert.match(h.out.join('\n'), /dropped \(\d+ tables, \d+ rows; 1 table\(s\) not counted \(unreadable\)\)/);
  assert.deepEqual(await traces(U), ZERO_TRACES);
});

test('U4 gate 6 (KTD10): --apply refuses without the OAuth store file, after the preflight and before the directory', async () => {
  const T = await fullWorkspace();
  const h = harness();
  assert.ok(!existsSync(h.store));
  assert.equal(await runWorkspaceDelete(applyArgs(h, T), h.deps), 2);
  assert.match(h.err.at(-1)!, /refused: --apply needs the OAuth store file/);
  assert.deepEqual([h.calls.preflight, h.calls.open, h.calls.revoke.length, h.calls.deleted.length], [1, 0, 0, 0]);
  assert.equal(h.audits[0]!['outcome'], 'refused');
  assert.equal((await traces(T)).schema, 1);
});

test('U4 data exposure (R15): no output or audit line carries content, a token, a grant id or hash, a subject, a login, a client id, wrap or credential bytes, or a path', async () => {
  const T = await provision();
  await plantInWorkspace(db, T, CANARY);
  const e = enrollmentWraps({ tenant: T, prfOutput: randomBytes(32), credentialId: randomBytes(16), prfSalt: randomBytes(32) });
  assert.equal(await dir.enroll(T, { passkey: e.passkey, recovery: e.recovery }), 'enrolled');
  const h = harness();
  const gs = grantsOf(h, T, 2);
  assert.equal(await runWorkspaceDelete(dryArgs(h, T), h.deps), 0);
  assert.equal(await runWorkspaceDelete(applyArgs(h, T), h.deps), 0);
  const all = [...h.out, ...h.err, ...h.audits.map((a) => JSON.stringify(a))].join('\n');
  const needles = [
    CANARY, 'mine/notes.md', ...gs.flatMap((g) => [g.at, g.rt, g.id, ...g.hashes]), 'github:4242', 'wsdel-user', 'zc_client', 'zeusi_at_', 'zeusi_rt_',
    e.passkey.wrapId, e.recovery.wrapId,
    ...[e.passkey.sealedDek, e.recovery.sealedDek, e.passkey.credentialId, e.passkey.prfSalt, e.recoveryCode]
      .flatMap((b) => [b.toString('hex'), b.toString('base64'), b.toString('base64url')]),
    h.root, h.store,
  ];
  e.dek.fill(0);
  e.recoveryCode.fill(0);
  assert.ok(needles.every((n) => typeof n === 'string' && n.length >= 8), 'every needle is a real string');
  for (const n of needles) assert.ok(!all.includes(n), `leaked ${fingerprint(n)}`);
});

// ---------------------------------------------------------------------------
// U5: the CLI (spawned, offline: a temp HOME, a scrubbed env, no real credential store, no network)

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
/** A fake owner URL in .env.local: it must never be printed (R15). TEST value, never a real host. */
const FAKE_OWNER = ['postgresql://', 'owner', ':', 'wsdelFakeOwnerPw', '@', 'ep-wsdel-fake-1', '.eu-central-1.aws.neon.tech/zeusi'].join('');
const SVC = (o: { user?: string; host?: string } = {}) => [
  '[zeusi_tenant_admin]', `host=${o.host ?? 'ep-wsdel-test-1.invalid'}`, 'port=5432', 'dbname=zeusi', `user=${o.user ?? TENANT_ADMIN_ROLE}`,
  'sslmode=verify-full', 'sslrootcert=system', 'channel_binding=require', '',
].join('\n');

function cli(args: string[], o: { service?: string; envLocal?: string; env?: Record<string, string>; setup?: (home: string) => void } = {}) {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-wsdel-cli-'));
  o.setup?.(home);
  writeFileSync(join(home, '.env.local'), `DATABASE_URL=${FAKE_OWNER}\nDATABASE_URL_UNPOOLED=${FAKE_OWNER}\n${o.envLocal ?? ''}`);
  const serviceFile = join(home, 'pg_service.conf');
  if (o.service !== undefined) writeFileSync(serviceFile, o.service);
  const r = spawnSync(process.execPath, [CLI, 'workspaces', 'delete', ...args], {
    cwd: home, encoding: 'utf8', timeout: 30_000, input: '',
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: home, PGSERVICEFILE: serviceFile, ...o.env },
  });
  const auditLines = `${r.stderr}`.split('\n').filter((l) => l.startsWith('{')).map((l) => JSON.parse(l) as Record<string, unknown>);
  return { code: r.status, out: `${r.stdout}${r.stderr}`, stdout: `${r.stdout}`, audit: auditLines, home };
}
const T_CLI = `zt_${'s'.repeat(26)}`;
const noOwner = (out: string) => !out.includes('wsdelFakeOwnerPw') && !/postgres(ql)?:\/\//.test(out) && !out.includes('ep-wsdel-fake-1');

test('U5 CLI: every offline refusal happens before the service lookup; the owner URL is never printed; one audit line once the args parse', () => {
  for (const [args, re, audited] of [
    [['work'], /refused: work is the team workspace; it is never deleted/, true],
    [['work', '--apply', '--confirm', 'work', '--i-took-a-snapshot'], /refused: work is the team workspace/, true],
    [['zeusi'], /refused: zeusi is the zeusi schema; it is never deleted/, true],
    [['zt_short'], /refused: not a workspace id \(zt_ \+ 26 base32\)/, true],
    [[`${T_CLI}; DROP SCHEMA zeusi CASCADE`], /refused: not a workspace id/, true],
    [[], /usage: workspaces delete <zt_id>/, false],
    [[T_CLI, `zt_${'t'.repeat(26)}`], /usage: workspaces delete <zt_id>/, false],
    [[T_CLI, '--real'], /usage: workspaces delete <zt_id>/, false],
    [[T_CLI, '--confirm', T_CLI], /refused: --confirm goes with --apply/, true],
    [[T_CLI, '--apply', '--confirm', T_CLI], /refused: --apply needs --i-took-a-snapshot/, true],
    [[T_CLI, '--apply', '--confirm', `zt_${'t'.repeat(26)}`, '--i-took-a-snapshot'], /refused: --confirm does not match the workspace id; nothing changed/, true],
    [[T_CLI, '--apply', '--i-took-a-snapshot'], /refused: --apply needs --confirm <zt_id> \(or a terminal to type the id\)/, true],
  ] as Array<[string[], RegExp, boolean]>) {
    const r = cli(args);
    assert.equal(r.code, 2, `${args.join(' ')}: ${r.out}`);
    assert.match(r.out, re, args.join(' '));
    assert.doesNotMatch(r.out, /Service "/, `${args.join(' ')}: no service lookup, no connection`);
    assert.ok(noOwner(r.out), `${args.join(' ')}: the owner URL is never printed`);
    assert.equal(r.audit.length, audited ? 1 : 0, `${args.join(' ')}: audit lines`);
    if (audited) assert.deepEqual([r.audit[0]!['action'], r.audit[0]!['outcome']], ['workspace_delete', 'refused']);
    assert.equal(r.stdout, '', 'nothing on stdout for a refusal');
  }
});

test('U5 CLI: the transport gate refuses it under ZEUSI_TRANSPORT=serverless; help lists it', () => {
  const r = cli([T_CLI], { env: { ZEUSI_TRANSPORT: 'serverless' } });
  assert.equal(r.code, 2);
  assert.match(r.out, /ZEUSI_TRANSPORT=serverless is only for search and doctor/);
  assert.equal(r.audit.length, 0);
  const help = spawnSync(process.execPath, [CLI, 'help'], { encoding: 'utf8', env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1' } });
  assert.match(help.stdout, /workspaces delete <zt_id> \[--admin-service <name>\] \[--file <oauth store>\] \[--audit-file <f>\]/);
  assert.match(help.stdout, /--apply --confirm <zt_id> --i-took-a-snapshot \[--i-know-this-is-main\]/);
});

test('U5 CLI preflight (KTD9): the admin service must be the provisioner on a direct host; --apply runs the main-branch guard with .env.local loaded', () => {
  const apply = [T_CLI, '--apply', '--confirm', T_CLI, '--i-took-a-snapshot'];
  const noService = cli([T_CLI]);
  assert.equal(noService.code, 2);
  assert.match(noService.out, /Service "zeusi_tenant_admin" not found/);
  assert.deepEqual(noService.audit.map((a) => a['outcome']), ['refused']);
  const badName = cli([T_CLI, '--admin-service', 'x;y']);
  assert.match(badName.out, /--admin-service: letters, digits, _ and - only/);
  assert.doesNotMatch(badName.out, /Service "/);
  const wrongUser = cli([T_CLI], { service: SVC({ user: 'zeusi_ingest' }) });
  assert.equal(wrongUser.code, 2);
  assert.match(wrongUser.out, /--admin-service must log in as zeusi_tenant_admin/);
  const pooled = cli([T_CLI], { service: SVC({ host: 'ep-wsdel-test-1-pooler.invalid' }) });
  assert.equal(pooled.code, 2);
  assert.match(pooled.out, /points at a pooled endpoint/);
  // --apply, no ZEUSI_MAIN_ENDPOINT_ID anywhere: refused by the guard, before the store or a connection.
  const noMain = cli(apply, { service: SVC() });
  assert.equal(noMain.code, 2);
  assert.match(noMain.out, /refused: cannot tell whether the target is Neon main: set ZEUSI_MAIN_ENDPOINT_ID/);
  // ZEUSI_MAIN_ENDPOINT_ID from .env.local (loaded for this command) equal to the service's endpoint: refused as main.
  const onMain = cli(apply, { service: SVC(), envLocal: 'ZEUSI_MAIN_ENDPOINT_ID=ep-wsdel-test-1\n' });
  assert.equal(onMain.code, 2);
  assert.match(onMain.out, /refused: the write service targets the default branch \(main\) endpoint/);
  // A branch endpoint, or --i-know-this-is-main: past the guard; the next gate is the store file (missing here).
  const branch = cli(apply, { service: SVC(), envLocal: 'ZEUSI_MAIN_ENDPOINT_ID=ep-wsdel-main-9\n' });
  assert.equal(branch.code, 2);
  assert.match(branch.out, /refused: --apply needs the OAuth store file/);
  const iKnow = cli([...apply, '--i-know-this-is-main'], { service: SVC() });
  assert.equal(iKnow.code, 2);
  assert.match(iKnow.out, /WARNING: --i-know-this-is-main: this workspace will be deleted from a target that may be Neon main/);
  assert.match(iKnow.out, /refused: --apply needs the OAuth store file/);
  // A dangling symlink (or a directory) at the store path is not a store: OAuthStore would read it as EMPTY (KTD10).
  const dangling = cli([...apply, '--i-know-this-is-main', '--file', 'data/mcp-oauth.json'], {
    service: SVC(), setup: (home) => { mkdirSync(join(home, 'data'), { mode: 0o700 }); symlinkSync(join(home, 'nowhere.json'), join(home, 'data', 'mcp-oauth.json')); },
  });
  assert.equal(dangling.code, 2);
  assert.match(dangling.out, /refused: --apply needs the OAuth store file/);
  // A symlink to a real store exists, so OAuthStore checks it and refuses it with its own reason (dry run and apply).
  const linked = (args: string[]) => cli([...args, '--file', 'data/mcp-oauth.json'], {
    service: SVC(), setup: (home) => {
      mkdirSync(join(home, 'data'), { mode: 0o700 });
      new OAuthStore({ hashKey: KEY, path: join(home, 'data', 'real.json') }).createGrant({ clientId: 'zc_client', subject: 'github:4244', login: 'wsdel-user', tenant: T_CLI });
      symlinkSync(join(home, 'data', 'real.json'), join(home, 'data', 'mcp-oauth.json'));
    },
  });
  const linkDry = linked([T_CLI]);
  const linkApply = linked([...apply, '--i-know-this-is-main']);
  for (const r of [linkDry, linkApply]) {
    assert.equal(r.code, 2, r.out);
    assert.match(r.out, /refused: oauth store file must be a 0600 regular file/);
  }
  for (const r of [noService, badName, wrongUser, pooled, noMain, onMain, branch, iKnow, dangling, linkDry, linkApply]) {
    assert.ok(noOwner(r.out), 'the owner URL is never printed');
    assert.doesNotMatch(r.out, /ep-wsdel-test-1/, 'the service host is never printed');
    assert.equal(r.audit.length, 1);
  }
});

test('U5 CLI: with a valid store and service the dry run gets as far as the connection, which fails closed offline (no password): exit 1, audit failed, no write', () => {
  const run = (args: string[]) => {
    const home = safeMkdtemp(join(tmpdir(), 'zeusi-wsdel-cli-'));
    const dataDir = join(home, 'data');
    writeFileSync(join(home, 'pg_service.conf'), SVC());
    writeFileSync(join(home, '.env.local'), `DATABASE_URL=${FAKE_OWNER}\n`);
    mkdirSync(dataDir, { mode: 0o700 });
    chmodSync(dataDir, 0o700);
    const s = new OAuthStore({ hashKey: KEY, path: join(dataDir, 'mcp-oauth.json') });
    s.createGrant({ clientId: 'zc_client', subject: 'github:4243', login: 'wsdel-user', tenant: T_CLI, workspaceWrite: true });
    const bytes = sha(readFileSync(join(dataDir, 'mcp-oauth.json')));
    const r = spawnSync(process.execPath, [CLI, 'workspaces', 'delete', T_CLI, '--file', join(dataDir, 'mcp-oauth.json'), '--audit-file', join(home, 'audit', 'delete.jsonl'), ...args], {
      cwd: home, encoding: 'utf8', timeout: 30_000, input: '',
      env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: home, PGSERVICEFILE: join(home, 'pg_service.conf') },
    });
    const ledger = existsSync(join(home, 'audit', 'delete.jsonl')) ? readFileSync(join(home, 'audit', 'delete.jsonl'), 'utf8') : '';
    return { r, out: `${r.stdout}${r.stderr}`, ledger, sameStore: sha(readFileSync(join(dataDir, 'mcp-oauth.json'))) === bytes, mode: statSync(join(home, 'audit', 'delete.jsonl')).mode & 0o777 };
  };
  const dry = run([]);
  assert.equal(dry.r.status, 1, dry.out);
  assert.match(dry.out, /workspaces delete: workspace directory not reachable/);
  assert.ok(dry.sameStore, 'the dry run did not write the store');
  assert.equal(dry.ledger.trim().split('\n').length, 1, 'one line in --audit-file');
  assert.deepEqual([JSON.parse(dry.ledger)['outcome'], JSON.parse(dry.ledger)['tenant_id']], ['failed', T_CLI]);
  assert.equal(dry.mode, 0o600);
  assert.ok(noOwner(dry.out) && !dry.out.includes('ep-wsdel-test-1'));
});
