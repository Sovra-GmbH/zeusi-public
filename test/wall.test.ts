// U4 wall suite (PLAN.md U4 + the owner's Plankiva hard rule, 14 Nov 2026 14:17 Zurich).
// Synthetic fixtures only. Runs against PGlite with all migrations applied.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import {
  compileWall, contentSha256, globToRegex, jsonbText, loadWall, SEED_RULES, wallContent, wallGate, rowTags,
  wallNorm, pctDecode, WALL_IGNORABLE_RANGES, WALL_MARK_RANGES, WALL_CONFUSABLES,
  type Verdict, type WallTable,
} from '../src/wall.ts';
import { wallAllow, wallAudit, wallReport } from '../src/wall-admin.ts';
import { wallCases, type Ctx } from './fixtures/wall/cases.ts';

let db: Db;
let ctx: Ctx;

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? 'unknown';
  }
}

/** INSERT a row given as a to_jsonb-shaped object, through the real triggers. */
function insertRow(table: WallTable, row: Record<string, unknown>) {
  const cols = Object.keys(row);
  const list = cols.map((c) => `"${c}"`).join(', ');
  // bytea columns travel as hex in the fixtures; jsonb_populate_record wants '\\x<hex>'.
  const dbRow = Object.fromEntries(Object.entries(row).map(([k, v]) => [k, k.endsWith('sha256') && typeof v === 'string' ? `\\x${v}` : v]));
  return db.query(
    `INSERT INTO zeusi.${table} (${list}) SELECT ${list} FROM jsonb_populate_record(NULL::zeusi.${table}, $1::jsonb)`,
    [JSON.stringify(dbRow)],
  );
}

/** Run fn inside a transaction that is always rolled back. */
async function rolledBack<T>(fn: () => Promise<T>): Promise<T> {
  await db.exec('BEGIN');
  try {
    return await fn();
  } finally {
    await db.exec('ROLLBACK');
  }
}

async function sqlVerdict(table: string, row: Record<string, unknown>) {
  const r = await db.query<{ rule_id: number | null; kind: string | null; hard: boolean | null; sha: string }>(
    `SELECT rule_id, kind::text AS kind, hard, encode(content_sha256, 'hex') AS sha FROM zeusi.wall_eval($1, $2::jsonb)`,
    [table, JSON.stringify(row)],
  );
  return r.rows[0]!;
}

/** Outcome of a real INSERT through the trigger: 'ok' or the rule id from the ZW001 DETAIL. */
async function triggerVerdict(table: WallTable, row: Record<string, unknown>): Promise<{ ruleId: number | null; code: string }> {
  return rolledBack(async () => {
    try {
      await insertRow(table, row);
      return { ruleId: null, code: 'ok' };
    } catch (e) {
      const err = e as { code?: string; detail?: string };
      const m = /rule_id=(\d+)/.exec(err.detail ?? '');
      return { ruleId: m ? Number(m[1]) : null, code: err.code ?? 'unknown' };
    }
  });
}

const label = (v: Verdict) => (v.blocked ? `${v.hard ? 'hard' : 'soft'}:${v.kind}` : 'pass');

before(async () => {
  db = await pgliteDb();
  await migrate(db);
  const run = Number((await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
  const SHA = 'cd'.repeat(32);
  const personId = Number((await db.query<{ id: number }>(
    `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'zeusi:test/people', now(), decode($1, 'hex'), $2) RETURNING id::int AS id`, [SHA, run])).rows[0]!.id);
  const noteId = Number((await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/ops/parent.md', 'Parent', 'clean parent', now(), 'work', 'vault_note', 'vault:Work/ops/parent.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id);
  // FK target for the pr_reviews fixture.
  await db.query(
    `INSERT INTO zeusi.prs (repo, number, title, head_sha, state, gh_updated_at, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('example-org/ops-console', 101, 'base', $1, 'open', now(), 'work', 'github_api', 'gh:example-org/ops-console#101', now(), decode($2, 'hex'), $3)`,
    ['a'.repeat(40), SHA, run]);
  ctx = { run, personId, noteId };
});
after(async () => db.close());

// ---------------------------------------------------------------------------
// Seeds and schema

test('0006/0007 seed hard Plankiva tag and term rules; re-running the seed is idempotent', async () => {
  const r = await db.query<{ kind: string; hard: boolean; pattern: string }>(
    `SELECT kind::text AS kind, hard, pattern FROM zeusi.wall_denylist WHERE lower(pattern) = 'plankiva' ORDER BY id`);
  assert.deepEqual(r.rows.map((x) => `${x.kind}:${x.hard}`), ['tag:true', 'term:true']);
  const before = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.wall_denylist`)).rows[0]!.n;
  await rolledBack(async () => {
    const { readFileSync } = await import('node:fs');
    const { MIGRATIONS_DIR } = await import('../src/migrate.ts');
    await db.exec(readFileSync(`${MIGRATIONS_DIR}/0007_wall_protected_name.sql`, 'utf8'));
    const after = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.wall_denylist`)).rows[0]!.n;
    assert.equal(after, before, 're-applying 0007 adds no rules');
  });
});

test('a pre-existing soft plankiva term is hardened by 0007', async () => {
  await rolledBack(async () => {
    await db.exec(`DELETE FROM zeusi.wall_denylist WHERE kind = 'term' AND pattern = 'plankiva'`);
    await db.exec(`INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason) VALUES ('term', false, 'plankiva', 'soft probe')`);
    const { readFileSync } = await import('node:fs');
    const { MIGRATIONS_DIR } = await import('../src/migrate.ts');
    await db.exec(readFileSync(`${MIGRATIONS_DIR}/0007_wall_protected_name.sql`, 'utf8'));
    const r = await db.query<{ hard: boolean }>(`SELECT hard FROM zeusi.wall_denylist WHERE kind = 'term' AND pattern = 'plankiva'`);
    assert.equal(r.rows[0]!.hard, true);
  });
});

test('tag rules are always hard (CHECK) and cannot be softened', async () => {
  assert.equal(await code(rolledBack(() => db.query(`INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason) VALUES ('tag', false, 'x-tag', 'probe')`))), '23514');
  assert.equal(await code(rolledBack(() => db.query(`UPDATE zeusi.wall_denylist SET hard = false WHERE kind = 'tag'`))), 'ZW002');
  assert.equal(await code(rolledBack(() => db.query(`UPDATE zeusi.wall_denylist SET hard = false WHERE kind = 'term' AND pattern = 'plankiva'`))), 'ZW002');
});

test('SEED_RULES in src/wall.ts match the DB seeds exactly (no drift)', async () => {
  const r = await db.query<{ kind: string; hard: boolean; pattern: string }>(
    `SELECT kind::text AS kind, hard, pattern FROM zeusi.wall_denylist ORDER BY id`);
  assert.deepEqual(r.rows.map((x) => ({ kind: x.kind, hard: x.hard, pattern: x.pattern })), SEED_RULES.map((s) => ({ kind: s.kind, hard: s.hard, pattern: s.pattern })));
});

test('quarantine stores no text: the column set has no body field', async () => {
  const cols = (await db.query<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns WHERE table_schema = 'zeusi' AND table_name = 'quarantine' ORDER BY ordinal_position`)).rows.map((r) => r.column_name);
  assert.deepEqual(cols, ['id', 'source_kind', 'source_uri', 'source_sha256', 'content_sha256', 'target_table', 'rule_id', 'ingest_run_id', 'detected_at', 'detected_by']);
  const types = (await db.query<{ data_type: string; column_name: string }>(
    `SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = 'zeusi' AND table_name = 'quarantine'
       AND data_type IN ('text', 'jsonb', 'json', 'character varying')`)).rows.map((r) => r.column_name).sort();
  // Only identifiers, never content.
  assert.deepEqual(types, ['detected_by', 'source_uri', 'target_table']);
});

// ---------------------------------------------------------------------------
// Parity: wall.ts == zeusi.wall_eval() == the real trigger, on the shared fixture table.

test('parity: wall.ts, zeusi.wall_eval() and the trigger agree on every fixture row', async () => {
  const wall = await loadWall(db);
  const cases = wallCases(ctx);
  assert.ok(cases.length >= 78);
  for (const c of cases) {
    const ts = wall.check(c.table, c.row);
    const sql = await sqlVerdict(c.table, c.row);
    const trg = await triggerVerdict(c.table, c.row);
    assert.equal(label(ts), c.expect, `${c.name}: wall.ts verdict`);
    assert.equal(ts.ruleId, sql.rule_id, `${c.name}: rule id wall.ts vs wall_eval`);
    assert.equal(ts.kind, sql.kind, `${c.name}: kind`);
    assert.equal(ts.contentSha256, sql.sha, `${c.name}: content sha wall.ts vs SQL`);
    assert.equal(trg.ruleId, ts.ruleId, `${c.name}: trigger rule id`);
    assert.equal(trg.code, ts.blocked ? 'ZW001' : 'ok', `${c.name}: trigger outcome`);
  }
});

test('parity: wall_content and its sha match SQL for every fixture row', async () => {
  for (const c of wallCases(ctx)) {
    const r = await db.query<{ content: string; sha: string }>(
      `SELECT zeusi.wall_content($1, $2::jsonb) AS content, encode(zeusi.wall_content_sha256($1, $2::jsonb), 'hex') AS sha`,
      [c.table, JSON.stringify(c.row)]);
    assert.equal(wallContent(c.table, c.row), r.rows[0]!.content, `${c.name}: content text`);
    assert.equal(contentSha256(c.table, c.row), r.rows[0]!.sha, `${c.name}: sha`);
  }
});

test('parity: jsonb text rendering matches Postgres', async () => {
  const samples: unknown[] = [
    { b: 1, a: 'x', aa: [1, 2, { z: null, y: true }] },
    ['é', 'quote " back \\ slash /', 'tab\tnl\ncr\r', '\u0001'],
    { tags: ['ops', 'Plankiva'], date: '2026-11-10', n: 1.5, m: -0, big: 12345678901234 },
    {},
    [],
  ];
  for (const s of samples) {
    const r = await db.query<{ t: string }>(`SELECT $1::jsonb::text AS t`, [JSON.stringify(s)]);
    assert.equal(jsonbText(s), r.rows[0]!.t);
  }
});

test('parity: glob_to_regex matches SQL', async () => {
  for (const g of ['ClientCo/**', '**plankiva**', '~/PlankivaVault/**', 'Work/ops/attic/**', '*pnl*', 'example-org/clientco-*', 'a?b.md', '**/x/**']) {
    for (const cross of [false, true]) {
      const r = await db.query<{ re: string }>(`SELECT zeusi.glob_to_regex($1, $2) AS re`, [g, cross]);
      assert.equal(globToRegex(g, cross), r.rows[0]!.re, `${g} cross=${cross}`);
    }
  }
});

test('tags: frontmatter list/string/tag key and inline #tags are extracted', () => {
  assert.deepEqual(rowTags('notes', { frontmatter: { tags: ['a', 'B'] }, body: 'x #c y', title: 't' }), ['a', 'B', 'c']);
  assert.deepEqual(rowTags('notes', { frontmatter: { tags: 'one two', tag: 'three' }, body: '', title: 't' }), ['one two', 'three']);
  assert.deepEqual(rowTags('chunks', { heading_path: 'H #x', text: 'a#notatag #real/nested-tag' }), ['x', 'real/nested-tag']);
});

// ---------------------------------------------------------------------------
// Plan U4 scenarios, end to end.

test('U4 + 0010: a ClientCo path passes the importer gate and inserts; an plankiva file under ClientCo/ is quarantined and rejected', async () => {
  const wall = await loadWall(db);
  const ok = wallCases(ctx).find((c) => c.name === 'ClientCo folder note with scope clientco')!.row;
  assert.equal((await wallGate(db, wall, { table: 'notes', row: ok, ingestRunId: ctx.run })).status, 'pass');
  assert.equal(await code(rolledBack(() => insertRow('notes', ok))), 'ok');
  const row = wallCases(ctx).find((c) => c.name === 'plankiva file under ClientCo folder')!.row;
  const g = await wallGate(db, wall, { table: 'notes', row, ingestRunId: ctx.run });
  assert.equal(g.status, 'quarantined');
  assert.ok(g.verdict.hard);
  const q = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.quarantine WHERE source_uri = $1`, [row['source_uri']]);
  assert.equal(q.rows[0]!.n, 1);
  assert.equal(await code(rolledBack(() => insertRow('notes', row))), 'ZW001');
});

test('U4: a PnL path is hard-denied even with a wall_allow row', async () => {
  const wall = await loadWall(db);
  const row = wallCases(ctx).find((c) => c.name === 'PnL in path')!.row;
  const v = wall.check('facts', row);
  assert.ok(v.blocked && v.hard);
  // Allowing the hard rule itself is refused by the guard.
  assert.equal(await code(rolledBack(() => db.query(
    `INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ($1, decode($2, 'hex'), $3)`,
    [row['source_uri'], v.contentSha256, v.ruleId]))), 'ZW002');
  // An allow for every soft rule at that exact hash still does not help.
  await rolledBack(async () => {
    await db.query(`INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id)
                    SELECT $1, decode($2, 'hex'), id FROM zeusi.wall_denylist WHERE NOT hard`, [row['source_uri'], v.contentSha256]);
    const w2 = await loadWall(db);
    assert.ok(w2.check('facts', row).blocked, 'wall.ts also ignores allows for hard rules');
    assert.equal(await code(insertRow('facts', row)), 'ZW001');
  });
});

// 0011 lifted the soft currency rule; the soft account-number rule stays and carries this test.
test('U4: account number is quarantined, admitted after wall_allow of its exact sha, quarantined again after one edit', async () => {
  const base = wallCases(ctx).find((c) => c.name === 'synthetic account number')!.row;
  const row: Record<string, unknown> = { ...base, source_uri: 'zeusi:test/acct-e2e' };
  let wall = await loadWall(db);
  const g1 = await wallGate(db, wall, { table: 'facts', row, ingestRunId: ctx.run });
  assert.equal(g1.status, 'quarantined');
  assert.equal(g1.verdict.hard, false);
  // the owner (owner) allows the exact hash.
  const a = await wallAllow(db, String(row['source_uri']), g1.verdict.contentSha256);
  assert.equal(a.ruleId, g1.verdict.ruleId);
  wall = await loadWall(db);
  const g2 = await wallGate(db, wall, { table: 'facts', row, ingestRunId: ctx.run });
  assert.equal(g2.status, 'pass');
  assert.equal(await code(insertRow('facts', row)), 'ok');
  // One edit → new content sha → quarantined again (wall.ts and trigger).
  const edited = { ...row, text: `${row['text']}!`, source_sha256: 'ef'.repeat(32) };
  assert.equal((await wallGate(db, wall, { table: 'facts', row: edited, ingestRunId: ctx.run })).status, 'quarantined');
  assert.equal(await code(rolledBack(() => insertRow('facts', edited))), 'ZW001');
  // The allowed row does not trip the audit; the quarantined edit is not in content.
  assert.deepEqual(await wallAudit(db), []);
});

test('U4 + 0010: a PR from example-org/clientco-hedging-engine is admitted; an plankiva repo PR is still rejected, also by the repo rule alone', async () => {
  const clientcoPr = wallCases(ctx).find((c) => c.name === 'ClientCo repo PR')!.row;
  assert.equal(await code(rolledBack(() => insertRow('prs', clientcoPr))), 'ok');
  assert.ok(!(await loadWall(db)).check('prs', clientcoPr).blocked);
  const row = wallCases(ctx).find((c) => c.name === 'plankiva repo PR')!.row;
  assert.equal(await code(rolledBack(() => insertRow('prs', row))), 'ZW001');
  // The repo rule alone (uri without the name) also rejects it.
  const bare = { ...row, source_uri: 'gh:pr/6' };
  assert.equal((await loadWall(db)).check('prs', bare).kind, 'repo');
  assert.equal(await code(rolledBack(() => insertRow('prs', bare))), 'ZW001');
});

test('U4: UPDATE that puts a denied term into a clean note body is rejected', async () => {
  const id = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.notes WHERE vault_path = 'Work/ops/parent.md'`)).rows[0]!.id;
  assert.equal(await code(rolledBack(() => db.query(`UPDATE zeusi.notes SET body = 'now mentions Plankiva' WHERE id = $1`, [id]))), 'ZW001');
  assert.equal(await code(rolledBack(() => db.query(`UPDATE zeusi.notes SET body = 'acct 99999999 synthetic' WHERE id = $1`, [id]))), 'ZW001');
  assert.equal(await code(rolledBack(() => db.query(`UPDATE zeusi.notes SET frontmatter = '{"tags": ["plankiva"]}' WHERE id = $1`, [id]))), 'ZW001');
});

test('U4: Plankiva hard rules cannot be overridden by wall_allow (tag and term)', async () => {
  for (const name of ['frontmatter tags list contains Plankiva', 'plankiva in note body']) {
    const c = wallCases(ctx).find((x) => x.name === name)!;
    const v = (await loadWall(db)).check(c.table, c.row);
    assert.ok(v.blocked && v.hard, name);
    assert.equal(await code(rolledBack(() => db.query(
      `INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ($1, decode($2, 'hex'), $3)`,
      [c.row['source_uri'], v.contentSha256, v.ruleId]))), 'ZW002', name);
    await assert.rejects(wallAllow(db, String(c.row['source_uri']), v.contentSha256, v.ruleId!), /hard/, name);
  }
});

test('U4: wall allow refuses an Plankiva/hard path even for a soft rule id', async () => {
  const soft = (await db.query<{ id: number }>(`SELECT min(id)::int AS id FROM zeusi.wall_denylist WHERE NOT hard`)).rows[0]!.id;
  await assert.rejects(wallAllow(db, 'file:~/PlankivaVault/requests/form-009.md', 'ab'.repeat(32), soft), /hard/);
  await assert.rejects(wallAllow(db, 'vault:ClientCo/plankiva-x.md', 'ab'.repeat(32), soft), /hard/);
  await assert.rejects(wallAllow(db, 'vault:ClientCo/P-l-a-n-k-i-v-a.md', 'ab'.repeat(32), soft), /hard/);
  await assert.rejects(wallAllow(db, 'zeusi:test/never-quarantined', 'ab'.repeat(32)), /no quarantine row/);
  await assert.rejects(wallAllow(db, 'zeusi:test/x', 'nothex'), /64 hex/);
});

test('U4: wall audit is zero on a clean DB, flags forced hard rows (path, tag, term) and quarantined (uri, sha) in content', async () => {
  assert.deepEqual(await wallAudit(db), []);
  await rolledBack(async () => {
    for (const t of ['notes', 'facts', 'chunks'] as const) await db.exec(`ALTER TABLE zeusi.${t} DISABLE TRIGGER zeusi_90_wall`);
    const cs = wallCases(ctx);
    await insertRow('facts', cs.find((c) => c.name === 'PlankivaVault requests path (~)')!.row);
    await insertRow('notes', cs.find((c) => c.name === 'frontmatter tags string contains plankiva')!.row);
    await insertRow('chunks', cs.find((c) => c.name === 'PLANKIVA in chunk text')!.row);
    const rows = await wallAudit(db);
    assert.equal(rows.length, 3, JSON.stringify(rows));
    assert.ok(rows.every((r) => /^hard rule \d+ \((path_glob|tag|term)\)$/.test(r.problem)));
    // Audit output carries no content.
    assert.doesNotMatch(JSON.stringify(rows), /PLANKIVA asked|synthetic request text|synthetic body/);
  });
  await rolledBack(async () => {
    // A quarantined (uri, sha) that is somehow present in content.
    await db.query(`SELECT zeusi.quarantine_record('manual', 'zeusi:test/q-present', decode($1, 'hex'), NULL, $2, 'facts', NULL)`, ['cd'.repeat(32), ctx.run]);
    await insertRow('facts', { kind: 'other', subject: null, text: 'clean', scope: 'work', source_kind: 'manual', source_uri: 'zeusi:test/q-present',
                               source_ts: '2026-11-10T09:00:00Z', source_sha256: 'cd'.repeat(32), ingest_run_id: ctx.run });
    const rows = await wallAudit(db);
    assert.equal(rows.length, 1);
    assert.match(rows[0]!.problem, /quarantined/);
  });
});

test('U4: wall report lists quarantined uris and rule ids, never content', async () => {
  const rep = await wallReport(db);
  assert.ok(rep.length >= 1);
  for (const r of rep) {
    assert.deepEqual(Object.keys(r).sort(), ['content_sha256', 'detected_at', 'hard', 'id', 'rule_id', 'rule_kind', 'source_kind', 'source_uri', 'target_table']);
  }
});

test('U4: Plankiva content is blocked for every content table (one synthetic row each)', async () => {
  const wall = await loadWall(db);
  const tables = new Set<string>();
  for (const c of wallCases(ctx).filter((x) => /plankiva/i.test(x.name))) {
    const v = wall.check(c.table, c.row);
    assert.ok(v.blocked && v.hard, c.name);
    tables.add(c.table);
  }
  assert.deepEqual([...tables].sort(), ['chunks', 'decisions', 'episodes', 'facts', 'notes', 'people', 'pr_reviews', 'prs', 'routine_runs']);
});

test('wall.ts fails closed on a regex rule it cannot translate', () => {
  assert.throws(() => compileWall([{ id: 1, kind: 'regex', hard: false, pattern: '[[:alpha:]]+' }], []), /unsupported/);
  assert.throws(() => compileWall([{ id: 1, kind: 'regex', hard: false, pattern: '\\y' }], []), /unsupported/);
});

// ---------------------------------------------------------------------------
// r1 MINOR-1 / MINOR-2 / MINOR-3 / MINOR-4 (0008)

/** Code points at and around every boundary of the ranges, plus a few inside. */
function boundaryPoints(ranges: ReadonlyArray<readonly [number, number]>): number[] {
  const out = new Set<number>();
  for (const [lo, hi] of ranges) for (const c of [lo - 1, lo, Math.floor((lo + hi) / 2), hi, hi + 1]) out.add(c);
  // No surrogates and no NUL: neither can be stored in Postgres text.
  return [...out].filter((c) => c > 0 && !(c >= 0xd800 && c <= 0xdfff) && c <= 0x10ffff);
}

test('0008 wall_norm: wall.ts and SQL agree on every ignorable / mark boundary and every confusable', async () => {
  const samples: string[] = [
    ...boundaryPoints(WALL_IGNORABLE_RANGES).map((c) => `pla${String.fromCodePoint(c)}nkiva`),
    ...boundaryPoints(WALL_MARK_RANGES).map((c) => `pla${String.fromCodePoint(c)}nkiva`),
    ...[...WALL_CONFUSABLES.keys()].map((c) => `pl${c}nkiva ${c.toLowerCase()} ${c.toUpperCase()}`),
    '\uFF30\uFF2C\uFF21\uFF2E\uFF2B\uFF29\uFF36\uFF21', '\u24C5lankiva', '\u{1D40F}lankiva', '\uFB01le', 'K\u212A', '\u0130stanbul', '\u00C4 \u00D6 \u00DF \u1E9E',
    'Plain ASCII Text 123', '', '\u3164\uFFA0x',
  ];
  for (const t of samples) {
    // Compared as UTF-8 hex: PGlite's result decoding drops a leading U+FEFF.
    const r = await db.query<{ n: string }>(`SELECT encode(convert_to(zeusi.wall_norm($1), 'UTF8'), 'hex') AS n`, [t]);
    assert.equal(Buffer.from(wallNorm(t)).toString('hex'), r.rows[0]!.n, `wall_norm(${JSON.stringify(t)})`);
  }
  for (const t of ['Plan\u200Bkiva', 'Plan\u00ADkiva', '\uFF30lankiva', 'Pl\u0410nkiva', 'Pla\u0308nkiva', 'pl\u0430n\u03BA\u0456va', 'Pl\u2060an\uFE0Fkiva', 'Plan\u{E0041}kiva']) {
    assert.equal(wallNorm(t), 'plankiva', JSON.stringify(t));
  }
  assert.equal(wallNorm('\uFF23\uFF2C\uFF29\uFF25\uFF2E\uFF34\uFF23\uFF2F \u0440n\u04CF'), 'clientco pni', 'fullwidth ClientCo; Cyrillic er + palochka fold to p / i');
});

test('0008 pct_decode: wall.ts and SQL agree (bounded repeat, invalid UTF-8, %00 kept)', async () => {
  const samples = [
    'vault:Work/%50lankivaVault/requests/x.md', '%2541', '%252550lankiva', '%25252525252525252550', 'a%20b', '%e2%82%ac', '%E2%82', '%FF%41',
    '%00x', '%zz', '%', '100%', 'caf%C3%A9', '%F0%9F%98%80', '%ED%A0%80', '%C0%AF', 'plain', '\u00E9%41', '%EF%BB%BFbom',
  ];
  for (const t of samples) {
    const r = await db.query<{ d: string }>(`SELECT encode(convert_to(zeusi.pct_decode($1), 'UTF8'), 'hex') AS d`, [t]);
    assert.equal(Buffer.from(pctDecode(t)).toString('hex'), r.rows[0]!.d, `pct_decode(${JSON.stringify(t)})`);
  }
  assert.equal(pctDecode('%50lankiva'), 'Plankiva');
  assert.equal(pctDecode('%2550lankiva'), 'Plankiva');
  assert.equal(pctDecode('%FF%41'), '%FFA', 'invalid UTF-8 \u2192 only ASCII escapes decoded');
  assert.equal(pctDecode('%00x'), '%00x', 'NUL is never decoded');
  assert.equal(pctDecode('%EF%BB%BFbom'), '\uFEFFbom', 'a leading BOM is kept (as Postgres does)');
});

test('0008 MINOR-3: chunks.embed_model is in the hard text (wall.ts == wall_eval)', async () => {
  const wall = await loadWall(db);
  const row = { note_id: ctx.noteId, chunk_index: 9, heading_path: 'H', text: 'clean', token_count: 1, embed_model: 'probe/plankiva@1',
                ...{ scope: 'work', source_kind: 'vault_note', source_uri: 'vault:Work/ops/parent.md#H', source_ts: '2026-11-10T09:00:00Z',
                     source_sha256: 'cd'.repeat(32), ingest_run_id: ctx.run } };
  const ts = wall.check('chunks', row);
  const sql = await sqlVerdict('chunks', row);
  assert.equal(label(ts), 'hard:term');
  assert.equal(ts.ruleId, sql.rule_id);
});

test('0008 MINOR-1: normalisation does not change wall_content or its sha (existing wall_allow pins stay valid)', async () => {
  const fns = (await db.query<{ src: string }>(`SELECT prosrc AS src FROM pg_proc WHERE oid = 'zeusi.wall_content(text, jsonb)'::regprocedure`)).rows[0]!.src;
  assert.doesNotMatch(fns, /wall_norm|pct_decode/);
  const row = { kind: 'other', subject: null, text: 'Plan\u200Bkiva', source_uri: 'zeusi:test/x' };
  assert.equal(wallContent('facts', row), 'Plan\u200Bkiva');
});

test('0008 MINOR-4: wall_audit masks source_uri of personal rows for non-owner callers', async () => {
  // Own throwaway DB: PGlite cannot undo SET SESSION AUTHORIZATION on ROLLBACK.
  const iso = await pgliteDb();
  try {
    await migrate(iso);
    const run = Number((await iso.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
    await iso.exec(`ALTER TABLE zeusi.facts DISABLE TRIGGER zeusi_90_wall`);
    for (const [scope, uri] of [['personal', 'zeusi:test/personal-secret-uri'], ['work', 'zeusi:test/team-visible-uri']]) {
      await iso.query(
        `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ('other', 'synthetic plankiva probe', $1, 'manual', $2, now(), decode($3, 'hex'), $4)`, [scope, uri, 'cd'.repeat(32), run]);
    }
    await iso.exec(`ALTER TABLE zeusi.facts ENABLE TRIGGER zeusi_90_wall`);
    // The owner (the function owner, here the test superuser) sees both uris.
    assert.deepEqual((await wallAudit(iso)).map((r) => r.source_uri).sort(), ['zeusi:test/personal-secret-uri', 'zeusi:test/team-visible-uri']);
    // Non-owner logins see the personal row masked; the row_ref stays.
    for (const login of ['zeusi_mini_ingest', 'zeusi_mini_backup']) {
      await iso.exec(`SET SESSION AUTHORIZATION ${login}`);
      const rows = await wallAudit(iso);
      assert.equal(rows.length, 2, login);
      assert.deepEqual(rows.map((r) => r.source_uri).sort(), ['personal:<masked>', 'zeusi:test/team-visible-uri'], login);
      assert.ok(rows.every((r) => /^\d+$/.test(r.row_ref)), login);
      assert.doesNotMatch(JSON.stringify(rows), /personal-secret-uri/, login);
    }
  } finally {
    await iso.close();
  }
});

test('0008 is re-runnable and keeps grants: helpers not executable by PUBLIC or readers, executable by ingest', async () => {
  await rolledBack(async () => {
    const { readFileSync } = await import('node:fs');
    const { MIGRATIONS_DIR } = await import('../src/migrate.ts');
    await db.exec(readFileSync(`${MIGRATIONS_DIR}/0008_wall_normalise.sql`, 'utf8'));
  });
  for (const fn of ['zeusi.wall_norm(text)', 'zeusi.pct_decode(text)', 'zeusi.pct_decode_once(text)', 'zeusi.wall_eval(text, jsonb)']) {
    for (const [role, ok] of [['public', false], ['zeusi_cloud_ro', false], ['zeusi_box_ro', false], ['zeusi_mini_ingest', true]] as const) {
      const r = await db.query<{ x: boolean }>(`SELECT has_function_privilege($1, $2, 'EXECUTE') AS x`, [role, fn]);
      assert.equal(r.rows[0]!.x, ok, `${role} ${fn}`);
    }
  }
});

test('0008: zeusi_mini_ingest can run the wall pre-check (wall_eval) with the new helpers', async () => {
  await db.exec('SET ROLE zeusi_mini_ingest');
  try {
    const r = await db.query<{ rule_id: number | null }>(`SELECT rule_id FROM zeusi.wall_eval('facts', $1::jsonb)`,
      [JSON.stringify({ kind: 'other', text: 'plankiva', source_uri: 'vault:Work/%50lankiva.md' })]);
    assert.notEqual(r.rows[0]!.rule_id, null);
  } finally {
    await db.exec('RESET ROLE');
  }
});

// ---------------------------------------------------------------------------
// r2 MINOR-B / MINOR-D (0009)

const UNDECODED_TERM = 'zeusi-wall:undecoded-percent-escape';

test('0009 MINOR-B: a %XX left after the decode rounds hits the hard undecoded-escape rule (wall.ts == wall_eval)', async () => {
  const id = Number((await db.query<{ id: number }>(
    `SELECT id FROM zeusi.wall_denylist WHERE kind = 'term' AND pattern = $1 AND hard`, [UNDECODED_TERM])).rows[0]?.id);
  assert.ok(id > 0, 'rule seeded');
  const wall = await loadWall(db);
  for (const uri of [`vault:Work/%${'25'.repeat(8)}50lankivaVault/x.md`, 'vault:x%00.md', 'vault:Pl%D0%90nkiva%FF.md', 'vault:a%2500']) {
    const row = { kind: 'other', subject: null, text: 'synthetic', source_uri: uri };
    const ts = wall.check('facts', row);
    assert.equal(ts.ruleId, id, uri);
    assert.equal((await sqlVerdict('facts', row)).rule_id, id, uri);
    assert.equal(wall.checkUri(uri).ruleId, id, `checkUri ${uri}`);
  }
  // Hard: an allow on it is refused by the guard.
  assert.equal(await code(rolledBack(() => db.query(
    `INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ('vault:x%00.md', decode($1, 'hex'), $2)`,
    ['ab'.repeat(32), id]))), 'ZW002');
});

test('0009 fuzz parity: wall_norm, pct_decode and the verdict agree on seeded random strings', async () => {
  // Deterministic PRNG (mulberry32): the same strings on every run.
  let seed = 0x5eed2026;
  const rnd = () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = seed;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)]!;
  const folds = [...WALL_CONFUSABLES.keys()];
  const atoms = [
    ' ', '#', '-', '.', '/', '9', 'A', 'a', 'c', 'g', 'I', 'i', 'K', 'k', 'l', 'N', 'n', 'p', 'v', 'x',
    '%', '%25', '%41', '%61', '%2541', '%00', '%FF', '%C3', '%A9', '%D0%90', '%E2%80%8B', '%zz', '25',
    '\u200B', '\u00AD', '\uFE0F', '\u0308', '\uFF21', '\u{1D400}', '\u{E0041}', '\u00E9', '\u0130',
    // 0010: separators and leetspeak
    '4', '@', '1', '!', '|', '_', '*', '**', '\t', '\n', '\uFF14', 'ClientCo', 'clientco-',
  ];
  const strings: string[] = [];
  for (let n = 0; n < 400; n++) {
    let s = '';
    const len = 1 + Math.floor(rnd() * 14);
    for (let j = 0; j < len; j++) s += rnd() < 0.3 ? pick(folds) : pick(atoms);
    strings.push(s);
  }
  // A few that must hit: every Cherokee / Lisu fold spelled into plankiva.
  for (const [ch, to] of WALL_CONFUSABLES) if ('ank'.includes(to) || to === 'i') strings.push('plankiva'.replace(to, ch));
  // 0010: separator / leetspeak spellings, also under a ClientCo folder.
  const spelled = ['P l a n k i v a', 'p.l.a.n.k.i.v.a', 'Plan-kiva', '**Plan**kiva', 'pl4nkiva', 'pl@nk1va', 'PLAN_KIVA', 'p - l - a - n - k - i - v - a', '\uFF30lankiva'];
  for (const sp of spelled) strings.push(sp, `ClientCo/${sp}`);

  const hex = (x: string) => Buffer.from(x).toString('hex');
  const r = await db.query<{ n: string; d: string }>(
    `SELECT encode(convert_to(zeusi.wall_norm(s), 'UTF8'), 'hex') AS n, encode(convert_to(zeusi.pct_decode(s), 'UTF8'), 'hex') AS d
     FROM unnest($1::text[]) WITH ORDINALITY AS t(s, o) ORDER BY o`, [strings]);
  strings.forEach((s, i) => {
    assert.equal(hex(wallNorm(s)), r.rows[i]!.n, `wall_norm(${JSON.stringify(s)})`);
    assert.equal(hex(pctDecode(s)), r.rows[i]!.d, `pct_decode(${JSON.stringify(s)})`);
  });

  const wall = await loadWall(db);
  const rows = strings.map((s) => ({ kind: 'other', subject: null, text: s, source_uri: `vault:Work/${s}` }));
  const v = await db.query<{ rule_id: number | null }>(
    `SELECT v.rule_id FROM jsonb_array_elements($1::jsonb) WITH ORDINALITY AS t(r, o)
       CROSS JOIN LATERAL zeusi.wall_eval('facts', t.r) AS v ORDER BY t.o`, [JSON.stringify(rows)]);
  let blocked = 0;
  rows.forEach((row, i) => {
    const ts = wall.check('facts', row);
    assert.equal(ts.ruleId, v.rows[i]!.rule_id, `verdict ${JSON.stringify(row.source_uri)}`);
    if (ts.blocked) blocked++;
  });
  for (const s of strings.slice(400)) assert.ok(wall.check('facts', { kind: 'other', subject: null, text: s, source_uri: 'zeusi:t' }).blocked, JSON.stringify(s));
  assert.ok(blocked > 20 && blocked < rows.length, `a mix of verdicts (${blocked}/${rows.length} blocked)`);
});

test('0009 MINOR-D: wall_audit masks row_ref of personal prs rows for non-owner callers', async () => {
  const iso = await pgliteDb();
  try {
    await migrate(iso);
    const run = Number((await iso.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
    await iso.exec(`ALTER TABLE zeusi.prs DISABLE TRIGGER zeusi_90_wall`);
    for (const [scope, repo, n] of [['personal', 'owner/secret-side-repo', 7], ['work', 'example-org/team-hq', 8]] as const) {
      await iso.query(
        `INSERT INTO zeusi.prs (repo, number, title, head_sha, state, gh_updated_at, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ($1, $2::int, 'synthetic plankiva probe', $3, 'open', now(), $4, 'github_api', 'gh:' || $1 || '#' || $2::int::text, now(), decode($5, 'hex'), $6)`,
        [repo, n, 'a'.repeat(40), scope, 'cd'.repeat(32), run]);
    }
    await iso.exec(`ALTER TABLE zeusi.prs ENABLE TRIGGER zeusi_90_wall`);
    assert.deepEqual((await wallAudit(iso)).map((r) => r.row_ref).sort(), ['example-org/team-hq#8', 'owner/secret-side-repo#7']);
    for (const login of ['zeusi_mini_ingest', 'zeusi_mini_backup']) {
      await iso.exec(`SET SESSION AUTHORIZATION ${login}`);
      const rows = await wallAudit(iso);
      assert.deepEqual(rows.map((r) => r.row_ref).sort(), ['example-org/team-hq#8', 'personal:<masked>'], login);
      assert.ok(rows.every((r) => r.table_name === 'prs'), login);
      assert.doesNotMatch(JSON.stringify(rows), /secret-side-repo/, login);
    }
  } finally {
    await iso.close();
  }
});

test('0009 is re-runnable and keeps grants', async () => {
  await rolledBack(async () => {
    const { readFileSync } = await import('node:fs');
    const { MIGRATIONS_DIR } = await import('../src/migrate.ts');
    const sql = readFileSync(`${MIGRATIONS_DIR}/0009_wall_r2.sql`, 'utf8');
    await db.exec(sql);
    await db.exec(sql);
  });
  const r = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.wall_denylist WHERE pattern = $1`, [UNDECODED_TERM]);
  assert.equal(r.rows[0]!.n, 1);
  for (const fn of ['zeusi.wall_norm(text)', 'zeusi.wall_eval(text, jsonb)', 'zeusi.wall_audit()']) {
    for (const [role, ok] of [['public', false], ['zeusi_cloud_ro', false], ['zeusi_box_ro', false], ['zeusi_mini_ingest', true]] as const) {
      const x = await db.query<{ x: boolean }>(`SELECT has_function_privilege($1, $2, 'EXECUTE') AS x`, [role, fn]);
      assert.equal(x.rows[0]!.x, ok, `${role} ${fn}`);
    }
  }
});
