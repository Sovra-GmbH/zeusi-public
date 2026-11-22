// migrations/0012_decision_write_role.sql (DESIGN, NOT applied on Neon): the narrow decision-write
// login zeusi_box_decision / group zeusi_decision_write, tested on PGlite only. No network, no Neon.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { listMigrations, migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { roleCatalogChecks, OPTIONAL_LOGINS } from '../src/roles.ts';
import { insertDecision, type DecisionInput } from '../src/decisions.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const SHA = 'ab'.repeat(32);
const ROLE = 'zeusi_box_decision';
const GROUP = 'zeusi_decision_write';
const MIGRATION = '0012_decision_write_role.sql';
const WALLED = ['Plan', 'kiva synthetic wall probe'].join('');
let db: Db;
let run: number;

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? 'unknown';
  }
}

async function asRole<T>(d: Db, role: string, fn: () => Promise<T>): Promise<T> {
  await d.exec(`SET ROLE ${role}`);
  try {
    return await fn();
  } finally {
    await d.exec('RESET ROLE');
  }
}

/** A migrations dir with only the named files (to apply 0012 without 0010/0011, or to leave it out). */
function subsetDir(keep: (name: string) => boolean): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-mig-'));
  for (const f of listMigrations()) if (keep(f.name)) copyFileSync(join(MIGRATIONS_DIR, f.name), join(dir, f.name));
  return dir;
}

const decision = (over: Partial<DecisionInput> = {}): DecisionInput => ({
  kind: 'go', who: 'owner-0012', saidAt: '2026-11-16T10:00:00Z', saidAtPrecision: 'minute', exactWords: 'Decision role synthetic GO',
  exactWordsVerbatim: true, appliesTo: ['zeusi'], scope: 'work', sourceUri: 'hq:0012-a', sourceTs: '2026-11-16T10:00:00Z', ...over,
});

async function seed(d: Db): Promise<number> {
  const r = Number((await d.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
  await d.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                 VALUES ('owner-0012', 'the owner', 'human', 'work', 'work', 'manual', 'manual:people/owner-0012', now(), decode($1, 'hex'), $2)`, [SHA, r]);
  await d.query(`INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                 VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner-0012'), now(), 'minute', 'private synthetic', true, 'personal', 'manual', 'hq:0012-personal', now(), decode($1, 'hex'), $2)`, [SHA, r]);
  return r;
}

before(async () => {
  db = await pgliteDb();
  await migrate(db);
  run = await seed(db);
});
after(async () => db.close());

test('0012: the file has no password, no secret env name and no host; it is design-only (says NOT APPLIED)', () => {
  const sql = readFileSync(join(MIGRATIONS_DIR, MIGRATION), 'utf8');
  const code = sql.split('\n').filter((l) => !l.trimStart().startsWith('--')).join('\n');
  assert.doesNotMatch(code, /PASSWORD/i, 'no PASSWORD clause in any statement');
  assert.doesNotMatch(sql, /ZEUSI_NEON_|ZEUSI_OPENAI_|postgres(ql)?:\/\/|neon\.tech|\bep-[a-z0-9-]+/i);
  assert.match(sql, /NOT APPLIED/);
  assert.doesNotMatch(code, /zeusi_agent_write|default_transaction_read_only/, 'no grant to/from the broad agent group; not read-only by default');
  assert.doesNotMatch(code, /\bTO\s+PUBLIC\b/i);
});

test('0012: login and group exist with the designed attributes, timeouts, connection limit and membership', async () => {
  const r = (await db.query<{ rolname: string; rolcanlogin: boolean; rolsuper: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolreplication: boolean; rolbypassrls: boolean; rolconnlimit: number; rolconfig: string[] | null }>(
    `SELECT rolname, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolconnlimit, rolconfig FROM pg_roles WHERE rolname = ANY($1) ORDER BY rolname`,
    [[ROLE, GROUP]])).rows;
  const login = r.find((x) => x.rolname === ROLE)!;
  const group = r.find((x) => x.rolname === GROUP)!;
  assert.equal(login.rolcanlogin, true);
  assert.equal(group.rolcanlogin, false);
  for (const x of [login, group]) {
    assert.deepEqual([x.rolsuper, x.rolcreaterole, x.rolcreatedb, x.rolreplication, x.rolbypassrls], [false, false, false, false, false], x.rolname);
  }
  assert.equal(login.rolconnlimit, 5);
  const cfg = login.rolconfig ?? [];
  for (const c of ['statement_timeout=30s', 'idle_in_transaction_session_timeout=30s', 'search_path=zeusi, public']) assert.ok(cfg.includes(c), c);
  assert.ok(!cfg.some((c) => c.startsWith('default_transaction_read_only')), 'not read-only by default (it writes)');
  const m = (a: string, b: string) => db.query<{ m: boolean }>(`SELECT pg_has_role($1, $2, 'MEMBER') AS m`, [a, b]).then((q) => q.rows[0]!.m);
  assert.equal(await m(ROLE, GROUP), true);
  assert.equal(await m(ROLE, 'zeusi_read'), true, 'reads through zeusi_read');
  for (const g of ['zeusi_agent_write', 'zeusi_ingest', 'zeusi_backup']) assert.equal(await m(ROLE, g), false, `not in ${g}`);
  // no password was set by the migration
  const pw = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_authid WHERE rolname = $1 AND rolpassword IS NOT NULL`, [ROLE]).catch(() => null);
  if (pw) assert.equal(pw.rows[0]!.n, 0);
});

test('0012: zeusi_box_decision inserts a sourced decision (own ingest run, opened and closed) through insertDecision', async () => {
  const r = await asRole(db, ROLE, () => insertDecision(db, decision()));
  assert.equal(r.status, 'inserted');
  const row = (await db.query<Record<string, unknown>>(
    `SELECT d.source_kind::text AS sk, r.importer, r.mode, r.status, r.finished_at IS NOT NULL AS finished
     FROM zeusi.decisions d JOIN zeusi.ingest_runs r ON r.id = d.ingest_run_id WHERE d.id = $1`, [(r as { id: number }).id])).rows[0]!;
  assert.deepEqual(row, { sk: 'agent_write', importer: 'mcp', mode: 'agent', status: 'ok', finished: true });
});

test('0012: a walled decision is quarantined via quarantine_record (uri + hash only), not stored', async () => {
  const r = await asRole(db, ROLE, () => insertDecision(db, decision({ sourceUri: 'hq:0012-walled', exactWords: `walled ${WALLED}` })));
  assert.equal(r.status, 'quarantined');
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:0012-walled'`)).rows[0]!.n, 0);
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.quarantine WHERE source_uri = 'hq:0012-walled'`)).rows[0]!.n, 1);
});

test('0012: zeusi_box_decision can supersede a decision through supersede_decision', async () => {
  const a = await asRole(db, ROLE, () => insertDecision(db, decision({ sourceUri: 'hq:0012-s1', sourceTs: '2026-11-16T10:00:00Z', exactWords: 'first synthetic' })));
  const b = await asRole(db, ROLE, () => insertDecision(db, decision({ sourceUri: 'hq:0012-s2', sourceTs: '2026-11-16T11:00:00Z', exactWords: 'second synthetic' })));
  assert.equal(await code(asRole(db, ROLE, () => db.query(`SELECT zeusi.supersede_decision($1, $2)`, [(a as { id: number }).id, (b as { id: number }).id]))), 'ok');
  assert.equal(await code(asRole(db, ROLE, () => db.query(`SELECT zeusi.supersede_fact(1, 2)`))), '42501', 'not supersede_fact');
});

test('0012: it cannot write any other content table, cannot UPDATE/DELETE decisions, and cannot touch the wall', async () => {
  const priv = (t: string, p: string) => db.query<{ x: boolean }>(`SELECT has_table_privilege($1, $2, $3) AS x`, [ROLE, `zeusi.${t}`, p]).then((q) => q.rows[0]!.x);
  for (const t of ['facts', 'episodes', 'chunks', 'routine_runs', 'notes', 'people', 'prs', 'pr_reviews', 'backup_runs', 'embed_usage']) {
    assert.equal(await priv(t, 'INSERT'), false, `no INSERT on ${t}`);
  }
  for (const t of ['decisions', 'facts', 'people', 'notes', 'chunks']) {
    assert.equal(await priv(t, 'UPDATE'), false, `no UPDATE on ${t}`);
    assert.equal(await priv(t, 'DELETE'), false, `no DELETE on ${t}`);
  }
  for (const t of ['wall_denylist', 'wall_allow', 'quarantine']) {
    assert.equal(await priv(t, 'SELECT'), false, `no SELECT on ${t}`);
    assert.equal(await priv(t, 'INSERT, UPDATE, DELETE, TRUNCATE'), false, `no write on ${t}`);
  }
  assert.equal(await priv('decisions', 'INSERT'), true);
  assert.equal(await priv('ingest_runs', 'INSERT'), true);
  assert.equal(await priv('ingest_runs', 'DELETE'), false);
  await asRole(db, ROLE, async () => {
    assert.equal(await code(db.query(`INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
      VALUES ('other', 'x', 'work', 'agent_write', 'agent:0012/fact', now(), decode($1, 'hex'), $2)`, [SHA, run])), '42501');
    assert.equal(await code(db.query(`INSERT INTO zeusi.episodes (occurred_at, day, actor, kind, summary, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
      VALUES (now(), current_date, 'zeus', 'note', 'x', 'work', 'agent_write', 'agent:0012/ep', now(), decode($1, 'hex'), $2)`, [SHA, run])), '42501');
    assert.equal(await code(db.query(`UPDATE zeusi.decisions SET exact_words = 'changed' WHERE source_uri = 'hq:0012-a'`)), '42501');
    assert.equal(await code(db.query(`DELETE FROM zeusi.decisions WHERE source_uri = 'hq:0012-a'`)), '42501');
    assert.equal(await code(db.query(`SELECT count(*) FROM zeusi.wall_denylist`)), '42501');
    assert.equal(await code(db.query(`INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ('x', decode($1, 'hex'), 1)`, [SHA])), '42501');
    assert.equal(await code(db.exec(`ALTER TABLE zeusi.decisions DISABLE TRIGGER zeusi_90_wall`)), '42501');
  });
  const fn = (sig: string) => db.query<{ x: boolean }>(`SELECT has_function_privilege($1, $2, 'EXECUTE') AS x`, [ROLE, sig]).then((q) => q.rows[0]!.x);
  assert.equal(await fn('zeusi.wall_audit()'), false);
  assert.equal(await fn('zeusi.wall_eval(text, jsonb)'), false);
});

test('0012: it never reads or writes personal (same RLS as zeusi_read)', async () => {
  await asRole(db, ROLE, async () => {
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE scope = 'personal'`)).rows[0]!.n, 0);
    assert.ok((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE scope = 'work'`)).rows[0]!.n >= 1);
    const rid = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('mcp', 'box', 'agent') RETURNING id::int AS id`)).rows[0]!.id;
    assert.equal(await code(db.query(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner-0012'), now(), 'minute', 'p', true, 'personal', 'agent_write', 'hq:0012-p', now(), decode($1, 'hex'), $2)`,
      [SHA, rid])), '42501');
  });
});

test('0012: doctor --roles catalog checks pass with 0012 applied, including the decision login', async () => {
  const checks = await roleCatalogChecks(db);
  assert.deepEqual(checks.filter((c) => !c.ok), []);
  const names = checks.map((c) => c.check);
  assert.ok(names.includes(`${ROLE} is a member of ${GROUP}`));
  assert.ok(names.includes(`${ROLE} is not a member of zeusi_agent_write`));
  assert.ok(names.includes(`${GROUP} exists and is NOLOGIN`));
  assert.deepEqual(OPTIONAL_LOGINS.map((l) => [l.role, l.group, l.migration]), [[ROLE, GROUP, '0012']]);
  // and as the read-only login inside a read-only transaction (doctor --roles --service zeusi_ro)
  await asRole(db, 'zeusi_box_ro', async () => {
    await db.exec('BEGIN READ ONLY');
    try {
      assert.deepEqual((await roleCatalogChecks(db)).filter((c) => !c.ok), []);
    } finally {
      await db.exec('ROLLBACK');
    }
  });
});

test('0012: the catalog check fails a half-applied or widened decision role', async () => {
  await db.exec('BEGIN');
  try {
    await db.exec(`GRANT zeusi_agent_write TO ${ROLE}`);
    await db.exec(`ALTER ROLE ${ROLE} CONNECTION LIMIT 50`);
    const failed = (await roleCatalogChecks(db)).filter((c) => !c.ok).map((c) => c.check);
    assert.deepEqual(failed.sort(), [`${ROLE} CONNECTION LIMIT 5`, `${ROLE} is not a member of zeusi_agent_write`].sort());
  } finally {
    await db.exec('ROLLBACK');
  }
});

test('0012 does not depend on 0010/0011: 0001-0009 + 0012 apply and the role writes; without 0012 doctor still passes', async () => {
  const only = await pgliteDb();
  try {
    const r = await migrate(only, { dir: subsetDir((n) => n < '0010' || n === MIGRATION) });
    assert.ok(r.applied.includes(MIGRATION));
    assert.ok(!r.applied.some((n) => n.startsWith('0010') || n.startsWith('0011')));
    await seed(only);
    const ins = await asRole(only, ROLE, () => insertDecision(only, decision({ sourceUri: 'hq:0012-only' })));
    assert.equal(ins.status, 'inserted');
    assert.deepEqual((await roleCatalogChecks(only)).filter((c) => !c.ok), []);
  } finally {
    await only.close();
  }
  const without = await pgliteDb();
  try {
    // 0013 (decision_links) grants to zeusi_decision_write, so it needs 0012: leave it out too.
    await migrate(without, { dir: subsetDir((n) => n !== MIGRATION && n < '0013') });
    const checks = await roleCatalogChecks(without);
    assert.deepEqual(checks.filter((c) => !c.ok), [], 'doctor passes when 0012 is not applied');
    const na = checks.find((c) => c.check === `${ROLE} (0012) not applied`);
    assert.ok(na && na.ok, 'and says so');
    // a half-applied 0012 (group only) fails
    await without.exec(`CREATE ROLE ${GROUP} NOLOGIN`);
    const failed = (await roleCatalogChecks(without)).filter((c) => !c.ok).map((c) => c.check);
    assert.deepEqual(failed, [`${ROLE} exists and can log in`]);
  } finally {
    await without.close();
  }
});

test('0012 is idempotent (re-running the file changes nothing and keeps grants)', async () => {
  const sql = readFileSync(join(MIGRATIONS_DIR, MIGRATION), 'utf8');
  await db.exec('BEGIN');
  try {
    await db.exec(sql);
    assert.deepEqual((await roleCatalogChecks(db)).filter((c) => !c.ok), []);
    assert.equal((await db.query<{ x: boolean }>(`SELECT has_table_privilege($1, 'zeusi.decisions', 'INSERT') AS x`, [ROLE])).rows[0]!.x, true);
  } finally {
    await db.exec('ROLLBACK');
  }
});
