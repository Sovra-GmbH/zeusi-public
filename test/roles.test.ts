// U2 gap scenarios + U3 role matrix against PGlite with the real migrations and grants.
// Live Neon checks (15 s cancel, 6th connection refused) need a Neon branch; here we
// assert the role settings that implement them (rolconfig / rolconnlimit).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { EXPECTED_LOGINS, roleCatalogChecks } from '../src/roles.ts';
import { dummyVector, vectorQueryUsesHnsw } from '../src/facts.ts';

const SHA = 'ab'.repeat(32);
const CONTENT_TABLES = ['people', 'facts', 'decisions', 'prs', 'pr_reviews', 'episodes', 'routine_runs', 'notes', 'chunks'] as const;
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

async function asRole<T>(role: string, fn: () => Promise<T>): Promise<T> {
  await db.exec(`SET ROLE ${role}`);
  try {
    return await fn();
  } finally {
    await db.exec('RESET ROLE');
  }
}

before(async () => {
  db = await pgliteDb();
  await migrate(db);
  run = Number((await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
  // One personal row per table that can hold one (as owner), to prove readers never see it.
  await db.query(
    `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('other', 'private synthetic', 'personal', 'manual', 'zeusi:test/personal-fact', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  await db.query(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/p.md', 'p', 'private synthetic', now(), 'personal', 'vault_note', 'vault:Work/p.md', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  await db.query(
    `INSERT INTO zeusi.episodes (occurred_at, day, actor, kind, summary, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES (now(), current_date, 'zeus', 'note', 'private synthetic', 'personal', 'manual', 'zeusi:test/personal-ep', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  await db.query(
    `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('other', 'public synthetic', 'work', 'manual', 'zeusi:test/team-fact', now(), decode($1, 'hex'), $2)`, [SHA, run]);
});
after(async () => db.close());

// ---------------------------------------------------------------------------
// U2 scenarios not covered in schema.test.ts

test('U2: a fact without source_uri or source_ts is rejected', async () => {
  const ins = (uri: string | null, ts: string | null) => db.query(
    `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('other', 'x', 'work', 'manual', $1, $2::timestamptz, decode($3, 'hex'), $4)`, [uri, ts, SHA, run]);
  assert.equal(await code(ins(null, '2026-11-01T00:00:00Z')), '23502');
  assert.equal(await code(ins('zeusi:test/no-ts', null)), '23502');
  assert.equal(await code(ins('', '2026-11-01T00:00:00Z')), '23514');
});

test('U2: every content table requires the full provenance block', async () => {
  const r = await db.query<{ table_name: string; column_name: string; is_nullable: string }>(
    `SELECT table_name, column_name, is_nullable FROM information_schema.columns
     WHERE table_schema = 'zeusi' AND column_name IN ('scope', 'source_kind', 'source_uri', 'source_ts', 'source_sha256', 'ingest_run_id', 'ingested_at', 'ingested_by')
       AND table_name = ANY($1)`, [CONTENT_TABLES as unknown as string[]]);
  for (const t of CONTENT_TABLES) {
    const cols = r.rows.filter((x) => x.table_name === t);
    assert.equal(cols.length, 8, `${t} has the 8 provenance columns`);
    assert.ok(cols.every((c) => c.is_nullable === 'NO'), `${t} provenance is NOT NULL`);
  }
});

test('U2: decisions_current hides an expired decision', async () => {
  const who = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('u2-owner', 'the owner', 'human', 'work', 'work', 'manual', 'zeusi:test/u2-people', now(), decode($1, 'hex'), $2) RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  const dec = (uri: string, expires: string | null) => db.query<{ id: number }>(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, expires_at,
                                  scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('go', $1, now(), 'minute', 'GO synthetic', true, '{ops-console}', $2::timestamptz, 'work', 'lane_md', $3, now(), decode($4, 'hex'), $5)
     RETURNING id::int AS id`, [who, expires, uri, SHA, run]);
  const expired = (await dec('zeusi:test/u2-expired', '2026-01-01T00:00:00Z')).rows[0]!.id;
  const live = (await dec('zeusi:test/u2-live', null)).rows[0]!.id;
  const future = (await dec('zeusi:test/u2-future', '2099-01-01T00:00:00Z')).rows[0]!.id;
  const cur = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.decisions_current WHERE id = ANY($1) ORDER BY id`, [[expired, live, future]])).rows.map((x) => x.id);
  assert.deepEqual(cur, [live, future]);
});

test('U2: the HNSW index is used for ORDER BY embedding <=> $1 LIMIT 10 with the embed_model filter', async () => {
  const p = await vectorQueryUsesHnsw(db, dummyVector(1));
  assert.ok(p.used, p.plan);
});

// ---------------------------------------------------------------------------
// U3 role matrix

test('U3: zeusi_cloud_ro cannot INSERT into any table in schema zeusi', async () => {
  const tables = (await db.query<{ t: string }>(
    `SELECT c.relname AS t FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'zeusi' AND c.relkind = 'r' ORDER BY 1`)).rows.map((r) => r.t);
  assert.ok(tables.length >= 14);
  for (const t of tables) {
    const priv = await db.query<{ ok: boolean }>(`SELECT has_table_privilege('zeusi_cloud_ro', $1, 'INSERT, UPDATE, DELETE, TRUNCATE') AS ok`, [`zeusi.${t}`]);
    assert.equal(priv.rows[0]!.ok, false, `cloud_ro has no write privilege on ${t}`);
  }
  await asRole('zeusi_cloud_ro', async () => {
    assert.equal(await code(db.query(`INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
      VALUES ('other', 'x', 'work', 'manual', 'zeusi:test/cloud', now(), decode($1, 'hex'), $2)`, [SHA, run])), '42501');
    assert.equal(await code(db.query(`INSERT INTO zeusi.backup_runs (host, kind, started_at, status) VALUES ('x', 'full', now(), 'ok')`)), '42501');
  });
});

test('U3: readers see no personal row in any content table', async () => {
  for (const role of ['zeusi_cloud_ro', 'zeusi_box_ro', 'zeusi_box_rw', 'zeusi_mini_ingest']) {
    await asRole(role, async () => {
      for (const t of CONTENT_TABLES) {
        const n = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.${t} WHERE scope = 'personal'`)).rows[0]!.n;
        assert.equal(n, 0, `${role} sees no personal rows in ${t}`);
      }
      const pub = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.facts WHERE source_uri = 'zeusi:test/team-fact'`)).rows[0]!.n;
      assert.equal(pub, 1, `${role} sees team rows`);
    });
  }
  // The owner sees them (they exist).
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.facts WHERE scope = 'personal'`)).rows[0]!.n, 1);
});

test('U3: zeusi_box_rw inserts a fact but cannot UPDATE its text or DELETE it, on any content table', async () => {
  for (const t of CONTENT_TABLES) {
    const r = await db.query<{ u: boolean; d: boolean }>(
      `SELECT has_table_privilege('zeusi_box_rw', $1, 'UPDATE') AS u, has_table_privilege('zeusi_box_rw', $1, 'DELETE') AS d`, [`zeusi.${t}`]);
    assert.deepEqual(r.rows[0], { u: false, d: false }, `box_rw cannot UPDATE/DELETE ${t}`);
  }
  await asRole('zeusi_box_rw', async () => {
    const rid = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('agent:zeus', 'box', 'agent') RETURNING id::int AS id`)).rows[0]!.id;
    assert.equal(await code(db.query(`INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
      VALUES ('state', 'agent synthetic', 'work', 'agent_write', 'agent:zeus/u3', now(), decode($1, 'hex'), $2)`, [SHA, rid])), 'ok');
    assert.equal(await code(db.query(`UPDATE zeusi.facts SET text = 'changed' WHERE source_uri = 'agent:zeus/u3'`)), '42501');
    assert.equal(await code(db.query(`DELETE FROM zeusi.facts WHERE source_uri = 'agent:zeus/u3'`)), '42501');
  });
});

test('U3: zeusi_box_rw (and every non-owner role) cannot write wall_denylist, wall_allow, or quarantine directly', async () => {
  for (const role of ['zeusi_box_rw', 'zeusi_box_ro', 'zeusi_cloud_ro', 'zeusi_mini_ingest', 'zeusi_mini_backup']) {
    for (const t of ['wall_denylist', 'wall_allow', 'quarantine']) {
      const r = await db.query<{ w: boolean }>(`SELECT has_table_privilege($1, $2, 'INSERT, UPDATE, DELETE, TRUNCATE') AS w`, [role, `zeusi.${t}`]);
      assert.equal(r.rows[0]!.w, false, `${role} cannot write ${t}`);
    }
  }
  await asRole('zeusi_box_rw', async () => {
    assert.equal(await code(db.query(`INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ('x', decode($1, 'hex'), 1)`, [SHA])), '42501');
    assert.equal(await code(db.query(`UPDATE zeusi.wall_denylist SET hard = false`)), '42501');
  });
});

test('U3: zeusi_mini_ingest cannot DISABLE TRIGGER on any content table', async () => {
  await asRole('zeusi_mini_ingest', async () => {
    for (const t of CONTENT_TABLES) {
      assert.equal(await code(db.exec(`ALTER TABLE zeusi.${t} DISABLE TRIGGER zeusi_90_wall`)), '42501', t);
      assert.equal(await code(db.exec(`ALTER TABLE zeusi.${t} DISABLE TRIGGER ALL`)), '42501', t);
    }
    assert.equal(await code(db.exec(`SET session_replication_role = replica`)), '42501');
  });
});

test('U3: role catalog checks pass (no login in neon_superuser; rolconnlimit and rolconfig as designed)', async () => {
  const checks = await roleCatalogChecks(db);
  const failed = checks.filter((c) => !c.ok);
  assert.deepEqual(failed, []);
  assert.ok(checks.length >= EXPECTED_LOGINS.length * 3);
  // Statement timeout + connection limit exist for the cloud role (live cancel / 6th connection: needs Neon branch).
  const cloud = await db.query<{ rolconnlimit: number; rolconfig: string[] }>(`SELECT rolconnlimit, rolconfig FROM pg_roles WHERE rolname = 'zeusi_cloud_ro'`);
  assert.equal(cloud.rows[0]!.rolconnlimit, 5);
  assert.ok(cloud.rows[0]!.rolconfig.includes('statement_timeout=15s'));
  assert.ok(cloud.rows[0]!.rolconfig.includes('default_transaction_read_only=on'));
});

test('U3: the catalog check catches a login role inside neon_superuser', async () => {
  await db.exec('BEGIN');
  try {
    await db.exec(`CREATE ROLE neon_superuser NOLOGIN`);
    await db.exec(`GRANT neon_superuser TO zeusi_box_ro`);
    const failed = (await roleCatalogChecks(db)).filter((c) => !c.ok);
    assert.equal(failed.length, 1);
    assert.match(failed[0]!.check, /zeusi_box_ro.*neon_superuser/);
  } finally {
    await db.exec('ROLLBACK');
  }
});

test('U3: the catalog check runs read-only and as zeusi_mini_backup (doctor --roles)', async () => {
  await asRole('zeusi_mini_backup', async () => {
    await db.exec('BEGIN READ ONLY');
    try {
      const failed = (await roleCatalogChecks(db)).filter((c) => !c.ok);
      assert.deepEqual(failed, []);
    } finally {
      await db.exec('ROLLBACK');
    }
  });
});

test('U3/U4: wall audit and report functions are executable by ingest and backup, not by readers', async () => {
  for (const [role, ok] of [['zeusi_mini_ingest', true], ['zeusi_mini_backup', true], ['zeusi_cloud_ro', false], ['zeusi_box_rw', false]] as const) {
    const r = await db.query<{ x: boolean }>(`SELECT has_function_privilege($1, 'zeusi.wall_audit()', 'EXECUTE') AS x`, [role]);
    assert.equal(r.rows[0]!.x, ok, `${role} wall_audit`);
  }
  const pub = await db.query<{ x: boolean }>(`SELECT has_function_privilege('public', 'zeusi.wall_eval(text, jsonb)', 'EXECUTE') AS x`);
  assert.equal(pub.rows[0]!.x, false, 'wall_eval is not executable by PUBLIC');
});

// ---------------------------------------------------------------------------
// U6: `zeusi doctor --roles --service zeusi_ro` works as the read-only login.

test('U6: role catalog checks and doctor run as zeusi_box_ro inside a read-only transaction', async () => {
  const { collectDoctor } = await import('../src/doctor.ts');
  await db.exec('SET ROLE zeusi_box_ro');
  try {
    await db.exec('BEGIN READ ONLY');
    try {
      const info = await collectDoctor(db, 'zeusi_ro');
      assert.equal(info.role, 'zeusi_box_ro');
      assert.equal(info.migrations, null, 'schema_migrations is not visible to the reader');
      const checks = await roleCatalogChecks(db);
      assert.ok(checks.length > 0);
      assert.ok(checks.every((c) => c.ok), checks.filter((c) => !c.ok).map((c) => c.check).join('; '));
    } finally {
      await db.exec('ROLLBACK');
    }
  } finally {
    await db.exec('RESET ROLE');
  }
});
