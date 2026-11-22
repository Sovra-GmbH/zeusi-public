// 0011 (the owner's decisions, 15 Nov 2026 01:09 Zurich): "Plankiva" (one n) IS Plankiva: one HARD regex rule
// for the name and its variants (no wall_allow, ever). The SOFT currency rule and the SOFT P&L rule are
// lifted so ClientCo / Northbank content is admitted. Every credential / identifier guard stays.
// Synthetic exclusion probes only (never real Plankiva data). PGlite only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import {
  PROTECTED_VARIANTS_REGEX, PROTECTED_SPELLING_REGEX, LIFTED_0011, loadWall, pgRegexToJs, SEED_RULES, seedRulesWithIds, seedWall,
  wall0010SeedWall, type Row,
} from '../src/wall.ts';
import { mentionsProtectedName, parseToml, sourcePathGate, validateSources } from '../src/sources.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const SHA = 'cd'.repeat(32);
const M0011 = '0011_wall_name_variants_soft_lift.sql';
const CURRENCY = '(USD|EUR|CHF|GBP|JPY)[ ]?[0-9]|\\$[ ]?[0-9]';
const PNL = '(p&l|\\mpnl\\M|\\mbook\\M)[^\\n]*[0-9]';
const ACCT = '\\m(login|account|acct)\\M[^0-9\\n]{0,4}[0-9]{5,}';
const IBAN = '(?c)\\m[A-Z]{2}[0-9]{2}[ ]?([A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\\M';

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

async function rolledBack<T>(fn: () => Promise<T>): Promise<T> {
  await db.exec('BEGIN');
  try {
    return await fn();
  } finally {
    await db.exec('ROLLBACK');
  }
}

before(async () => {
  db = await pgliteDb();
  await migrate(db);
  run = Number((await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
});
after(async () => db.close());

const plankivaId = () => seedWall().rules.find((r) => r.kind === 'regex' && r.pattern === PROTECTED_VARIANTS_REGEX)!.id;
/** Term, 0010 spelling, or 0011 variants: any of these may be the first hit for a Plankiva signal. */
const plankivaFamilyIds = (): Set<number> => new Set(seedWall().rules.filter((r) =>
  (r.kind === 'regex' && (r.pattern === PROTECTED_VARIANTS_REGEX || r.pattern === PROTECTED_SPELLING_REGEX))
  || (r.kind === 'term' && r.pattern === 'plankiva')
  || (r.kind === 'tag' && r.pattern === 'plankiva')
  || (r.kind === 'path_glob' && /plankiva/i.test(r.pattern))
  || (r.kind === 'lane' && /plankiva/i.test(r.pattern))
  || (r.kind === 'repo' && /plankiva/i.test(r.pattern))
).map((r) => r.id));

/** wall_eval rule ids for many rows in one query (same order). */
async function sqlRuleIds(d: Db, table: string, rows: Row[]): Promise<Array<number | null>> {
  const r = await d.query<{ rule_id: number | null }>(
    `SELECT v.rule_id FROM jsonb_array_elements($2::jsonb) WITH ORDINALITY AS t(r, o)
       CROSS JOIN LATERAL zeusi.wall_eval($1, t.r) AS v ORDER BY t.o`, [table, JSON.stringify(rows)]);
  return r.rows.map((x) => x.rule_id);
}

// ---------------------------------------------------------------------------
// Rules

test('0011 rules: currency and P&L soft rules are gone; account number and IBAN stay soft; the Plankiva rule is hard and after the 0010 regex', async () => {
  const rules = (await db.query<{ id: number; kind: string; pattern: string; hard: boolean }>(
    `SELECT id::int AS id, kind::text AS kind, pattern, hard FROM zeusi.wall_denylist ORDER BY id`)).rows;
  assert.deepEqual(rules.filter((r) => !r.hard).map((r) => r.pattern), [ACCT, IBAN]);
  for (const p of [CURRENCY, PNL]) assert.ok(!rules.some((r) => r.pattern === p), `${p} lifted`);
  assert.deepEqual(LIFTED_0011.map((r) => `${r.kind} ${r.pattern}`), [`regex ${CURRENCY}`, `regex ${PNL}`]);
  const rx = rules.find((r) => r.kind === 'regex' && r.pattern === PROTECTED_VARIANTS_REGEX);
  assert.ok(rx && rx.hard, 'hard Plankiva variants regex seeded');
  assert.ok(rx!.id > rules.find((r) => r.kind === 'regex' && r.pattern === PROTECTED_SPELLING_REGEX)!.id);
  assert.deepEqual(seedRulesWithIds(), rules.map((r) => ({ id: r.id, kind: r.kind, hard: r.hard, pattern: r.pattern })), 'TS ids == DB ids');
  assert.ok(SEED_RULES.some((r) => r.pattern === PROTECTED_VARIANTS_REGEX && r.hard));
  // Kept on purpose (HQ judgement calls, reported to the owner): desk P&L path / lane rules and the agent-config repo rule.
  for (const p of ['**pnl**', '**p&l**', '*pnl*', 'session-pnl', 'desk-pnl', 'example-org/agent-config-backup*']) {
    assert.ok(rules.some((r) => r.pattern === p && r.hard), p);
  }
  // Never allowable, never softened.
  assert.equal(await code(rolledBack(() => db.query(
    `INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ('zeusi:test/x', decode($1, 'hex'), $2)`, [SHA, rx!.id]))), 'ZW002');
  assert.equal(await code(rolledBack(() => db.query(`UPDATE zeusi.wall_denylist SET hard = false WHERE id = $1`, [rx!.id]))), 'ZW002');
});

test('0011 does not replace any wall function (wall_eval stays fail-closed) and never names a scope value', async () => {
  const sql = readFileSync(join(MIGRATIONS_DIR, M0011), 'utf8').replace(/--.*$/gm, '');
  assert.doesNotMatch(sql, /CREATE\s+(OR\s+REPLACE\s+)?FUNCTION/i);
  assert.doesNotMatch(sql, /ALTER\s+TYPE|POLICY|GRANT|REVOKE/i);
  assert.equal(await code(db.query(`SELECT * FROM zeusi.wall_eval('nope', '{}'::jsonb)`)), '22023');
  assert.equal(await code(db.query(`SELECT * FROM zeusi.wall_eval(NULL, '{}'::jsonb)`)), '22023');
});

test('0011 upgrade from a 0010 database: exactly 2 rules deleted and 1 added (every other rule byte-identical); allows of the lifted rules go; their quarantine rows stay with rule_id NULL (no quarantine delete)', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-0011-'));
  const iso = await pgliteDb();
  try {
    for (const f of readdirSync(MIGRATIONS_DIR).filter((x) => x < '0011')) cpSync(join(MIGRATIONS_DIR, f), join(dir, f));
    await migrate(iso, { dir });
    const rid = Number((await iso.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
    const snap = async () => (await iso.query<{ id: number; kind: string; hard: boolean; pattern: string; reason: string; added_by: string }>(
      `SELECT id::int AS id, kind::text AS kind, hard, pattern, reason, added_by FROM zeusi.wall_denylist ORDER BY id`)).rows;
    const before = await snap();
    const idOf = (p: string) => before.find((r) => r.pattern === p)!.id;
    const w0 = await loadWall(iso);
    // A note quarantined by the currency rule, one by the P&L rule, one by the account rule, plus a hard path-hash row.
    const fxRow = { kind: 'other', subject: null, text: 'synthetic amount USD 12,345 noted', source_uri: 'zeusi:test/fx' };
    const v = w0.check('facts', fxRow);
    assert.equal(v.ruleId, idOf(CURRENCY));
    const q = (uri: string, sha: string, rule: number, csha: string | null) => iso.query(
      `SELECT zeusi.quarantine_record('manual', $1, decode($2, 'hex'), $3, $4, 'facts', CASE WHEN $5::text IS NULL THEN NULL ELSE decode($5, 'hex') END)`,
      [uri, sha, rule, rid, csha]);
    await q('zeusi:test/fx', 'a1'.repeat(32), idOf(CURRENCY), v.contentSha256);
    await q('zeusi:test/pnl', 'a2'.repeat(32), idOf(PNL), 'b2'.repeat(32));
    await q('zeusi:test/acct', 'a3'.repeat(32), idOf(ACCT), 'b3'.repeat(32));
    await q(`vault-path-sha256:${'a4'.repeat(32)}`, 'a4'.repeat(32), idOf('**plankiva**'), null);
    const allow = (uri: string, sha: string, rule: number) => iso.query(
      `INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ($1, decode($2, 'hex'), $3)`, [uri, sha, rule]);
    await allow('zeusi:test/fx-allowed', 'c1'.repeat(32), idOf(CURRENCY));
    await allow('zeusi:test/pnl-allowed', 'c2'.repeat(32), idOf(PNL));
    await allow('zeusi:test/acct', 'b3'.repeat(32), idOf(ACCT));

    cpSync(join(MIGRATIONS_DIR, M0011), join(dir, M0011));
    const res = await migrate(iso, { dir, tookSnapshot: true });
    assert.deepEqual(res.applied, [M0011]);

    const after = await snap();
    const lifted = new Set([CURRENCY, PNL]);
    assert.deepEqual(after.filter((r) => r.pattern !== PROTECTED_VARIANTS_REGEX), before.filter((r) => !lifted.has(r.pattern)),
      'every kept rule (credential, identifier, desk P&L, area, Plankiva, escape rules) is byte-identical, same id');
    const added = after.filter((r) => r.pattern === PROTECTED_VARIANTS_REGEX);
    assert.equal(added.length, 1);
    assert.ok(added[0]!.hard && added[0]!.kind === 'regex' && added[0]!.id > Math.max(...before.map((r) => r.id)));

    const allows = (await iso.query<{ uri: string; rule_id: number }>(`SELECT source_uri AS uri, rule_id FROM zeusi.wall_allow ORDER BY 1`)).rows;
    assert.deepEqual(allows, [{ uri: 'zeusi:test/acct', rule_id: idOf(ACCT) }], 'allows pinned to the lifted rules are removed (CASCADE); others stay');
    const qs = (await iso.query<{ uri: string; rule_id: number | null }>(`SELECT source_uri AS uri, rule_id FROM zeusi.quarantine ORDER BY 1`)).rows;
    assert.deepEqual(qs, [
      { uri: `vault-path-sha256:${'a4'.repeat(32)}`, rule_id: idOf('**plankiva**') },
      { uri: 'zeusi:test/acct', rule_id: idOf(ACCT) },
      { uri: 'zeusi:test/fx', rule_id: null },
      { uri: 'zeusi:test/pnl', rule_id: null },
    ], '0011 deletes no quarantine row: those of the lifted rules keep uri + hashes with rule_id NULL (ON DELETE SET NULL); others keep their rule');

    // The once-quarantined currency content is now admitted (wall.ts and trigger). Its stale quarantine row
    // collides with it in the audit until the owner SQL (scripts/owner-sql/quarantine-lifted-rules.sql) clears it.
    const w1 = await loadWall(iso);
    assert.ok(!w1.check('facts', fxRow).blocked);
    await iso.query(
      `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('other', $1, 'client', 'manual', 'zeusi:test/fx', now(), decode($2, 'hex'), $3)`, [fxRow.text, 'a1'.repeat(32), rid]);
    assert.deepEqual((await iso.query<{ table_name: string; source_uri: string; problem: string }>(
      `SELECT table_name, source_uri, problem FROM zeusi.wall_audit()`)).rows,
      [{ table_name: 'facts', source_uri: 'zeusi:test/fx', problem: 'quarantined (uri, sha) present in content' }]);
  } finally {
    await iso.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('0011 is re-runnable (same rules, allows and quarantine after a second run)', async () => {
  const snap = async () => JSON.stringify([
    (await db.query(`SELECT id, kind::text, hard, pattern, reason FROM zeusi.wall_denylist ORDER BY id`)).rows,
    (await db.query(`SELECT count(*)::int AS n FROM zeusi.wall_allow`)).rows,
    (await db.query(`SELECT count(*)::int AS n FROM zeusi.quarantine`)).rows,
  ]);
  const before = await snap();
  await rolledBack(async () => {
    await db.exec(readFileSync(join(MIGRATIONS_DIR, M0011), 'utf8'));
    await db.exec(readFileSync(join(MIGRATIONS_DIR, M0011), 'utf8'));
    assert.equal(await snap(), before);
  });
});

// ---------------------------------------------------------------------------
// The Plankiva rule: variants x placements, wall.ts == wall_eval

/** Synthetic spellings that must be blocked (text placement). */
const VARIANTS = [
  'Plankiva', 'plankiva', 'PLANKIVA', 'Plaankiva', 'Plannkiva', 'Plankkiva', 'Plannnkiva', 'Aplankiva', 'Plankivaa', 'xPlankivax', 'Plankivas',
  'P-l-a-n-k-i-v-a', 'P l a n k i v a', 'P.l.a.n.k.i.v.a', 'P_l_a_n_k_i_v_a', '**Plan**kiva', 'P - l - a - n - k - i - v - a', 'P l a n n n k i v a', 'Plan-nkiva',
  'pl4nk1v@', 'Plank!va', 'Plank|va', 'PL4NK1V4',
  'Ｐlankiva', 'Ｐｌａｎｋｉｖａ', 'PlАnkiva', 'plаnκіva', 'Plan​kiva', 'Plan­kiva', 'Plänkiva',
  'Pl⁠an️kiva', 'Ꮲlankiva', 'Plꭺnkiva', 'Plan\u{E0041}kiva',
  // 0007 / 0010 spellings stay covered (first hit may be the older rule)
  'Plankiva', 'P l a n k i v a', 'pl4nkiva',
];
/** Synthetic near-misses that must pass. */
const BENIGN = [
  'plan', 'kiva', 'plankton', 'planking', 'ankiva', 'plan kiva boat', 'Plan K.', 'kivas',
  'piano kayak', 'PLAN IVA', 'plank', 'lava plan', 'clean synthetic text',
];
/** Accepted, documented over-blocks: common words that embed the letters (measured: none in the vault or lane notes). */
const ACCEPTED_OVERBLOCK = ['mechplankiva', 'botplankiva', 'titplankiva', 'Pplankivattacke', 'Kplankiva', 'orgplankiva'];

function placements(v: string): Array<{ table: string; row: Row; where: string }> {
  const P = { scope: 'work', source_kind: 'manual', source_ts: '2026-11-15T01:09:00Z', source_sha256: SHA, ingest_run_id: 1 };
  return [
    { where: 'text', table: 'facts', row: { kind: 'other', subject: null, text: `met ${v} today`, ...P, source_uri: 'zeusi:test/t' } },
    { where: 'source_uri path', table: 'facts', row: { kind: 'other', subject: null, text: 'synthetic', ...P, source_uri: `vault:Work/notes/${v}-sync.md` } },
    { where: 'source_uri fragment', table: 'facts', row: { kind: 'other', subject: null, text: 'synthetic', ...P, source_uri: `vault:Work/x.md#${v}` } },
    { where: 'note title', table: 'notes', row: { vault_path: 'Work/x.md', title: `Call with ${v}`, body: 'synthetic', frontmatter: {}, file_mtime: P.source_ts, status: 'active', ...P, source_kind: 'vault_note', source_uri: 'vault:Work/x.md' } },
    { where: 'vault_path', table: 'notes', row: { vault_path: `ClientCo/${v}/x.md`, title: 'x', body: 'synthetic', frontmatter: {}, file_mtime: P.source_ts, status: 'active', ...P, scope: 'client', source_kind: 'vault_note', source_uri: 'vault:ClientCo/y.md' } },
    { where: 'frontmatter tag', table: 'notes', row: { vault_path: 'Work/x.md', title: 'x', body: 'synthetic', frontmatter: { tags: ['ops', v] }, file_mtime: P.source_ts, status: 'active', ...P, source_kind: 'vault_note', source_uri: 'vault:Work/x.md' } },
    { where: 'inline tag', table: 'notes', row: { vault_path: 'Work/x.md', title: 'x', body: `## Sync #${v}\nsynthetic`, frontmatter: {}, file_mtime: P.source_ts, status: 'active', ...P, source_kind: 'vault_note', source_uri: 'vault:Work/x.md' } },
    { where: 'lane', table: 'episodes', row: { occurred_at: P.source_ts, day: '2026-11-15', actor: 'zeus', lane: `${v}-sync`, kind: 'note', summary: 'synthetic', links: [], ...P, source_uri: 'zeusi:test/e' } },
    { where: 'repo', table: 'prs', row: { repo: `example-org/${v}-site`, number: 1, title: 'x', author_login: null, base_ref: 'main', head_ref: 'x', head_sha: 'a'.repeat(40), state: 'open', gh_updated_at: P.source_ts, ...P, source_kind: 'github_api', source_uri: 'gh:example-org/team-hq#1' } },
  ];
}

test('0011 Plankiva variants are hard-blocked at every level (text, uri, title, path, tag, inline tag, lane, repo); wall.ts == wall_eval', async () => {
  const wall = await loadWall(db);
  const plankiva = plankivaId();
  for (const v of VARIANTS) {
    const ps = placements(v);
    for (const p of ps) {
      const ts = wall.check(p.table, p.row);
      const [sq] = await sqlRuleIds(db, p.table, [p.row]);
      assert.ok(ts.blocked && ts.hard, `${JSON.stringify(v)} in ${p.where}: blocked hard`);
      assert.equal(ts.ruleId, sq, `${JSON.stringify(v)} in ${p.where}: wall.ts == wall_eval`);
      assert.ok(ts.ruleId != null && plankivaFamilyIds().has(ts.ruleId), `${JSON.stringify(v)} in ${p.where}: a Plankiva-family rule (got ${ts.ruleId})`);
    }
  }
  // Percent-encoded forms in uris and paths are decoded first (0008) and also hit.
  for (const uri of ['vault:Work/%50lankiva.md', 'file:~/notes/%2550lankiva/x.md', 'lane:%70lankiva-sync']) {
    const row = { kind: 'other', subject: null, text: 'synthetic', source_uri: uri };
    const ts = wall.check('facts', row);
    assert.ok(ts.blocked && ts.hard, uri);
    assert.deepEqual([ts.ruleId], await sqlRuleIds(db, 'facts', [row]), uri);
  }
});

test('0011 near-misses pass; the accepted over-blocks (words that embed the letters) are blocked and documented', async () => {
  const wall = await loadWall(db);
  const rows = BENIGN.map((b) => ({ kind: 'other', subject: null, text: `synthetic ${b} line`, source_uri: 'zeusi:test/b' }));
  const sq = await sqlRuleIds(db, 'facts', rows);
  rows.forEach((r, i) => {
    assert.equal(wall.check('facts', r).ruleId, null, JSON.stringify(BENIGN[i]));
    assert.equal(sq[i], null, JSON.stringify(BENIGN[i]));
    assert.ok(!mentionsProtectedName(BENIGN[i]!), JSON.stringify(BENIGN[i]));
  });
  const over = ACCEPTED_OVERBLOCK.map((b) => ({ kind: 'other', subject: null, text: b, source_uri: 'zeusi:test/o' }));
  const so = await sqlRuleIds(db, 'facts', over);
  over.forEach((r, i) => {
    assert.ok(plankivaFamilyIds().has(wall.check('facts', r).ruleId!), ACCEPTED_OVERBLOCK[i]!);
    assert.ok(so[i] != null && plankivaFamilyIds().has(so[i]!), ACCEPTED_OVERBLOCK[i]!);
  });
});

test('0011 Plankiva rows are rejected by the trigger on every content table', async () => {
  const notes = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/p.md', 'P', 'clean', now(), 'work', 'vault_note', 'vault:Work/p.md', now(), decode($1, 'hex'), $2) RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  const person = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('p-0011', 'P', 'human', 'work', 'work', 'manual', 'zeusi:test/p0011', now(), decode($1, 'hex'), $2) RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  const prov = `'work', 'manual', 'zeusi:test/probe-row', now(), decode('${SHA}', 'hex'), ${run}`;
  const stmts: Array<[string, string]> = [
    ['facts', `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id) VALUES ('other', 'met Plankiva', ${prov})`],
    ['decisions', `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id) VALUES ('go', ${person}, now(), 'minute', 'GO for Plankiva', true, ${prov})`],
    ['episodes', `INSERT INTO zeusi.episodes (occurred_at, day, actor, kind, summary, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id) VALUES (now(), current_date, 'zeus', 'note', 'Plaankiva sync', ${prov})`],
    ['notes', `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id) VALUES ('Work/q.md', 'Q', 'P-l-a-n-k-i-v-a', now(), 'work', 'vault_note', 'vault:Work/q.md', now(), decode('${SHA}', 'hex'), ${run})`],
    ['chunks', `INSERT INTO zeusi.chunks (note_id, chunk_index, text, text_sha256, token_count, source_uri) VALUES (${notes}, 0, 'ask PlАnkiva', decode('${SHA}', 'hex'), 2, 'vault:Work/p.md#c0')`],
    ['prs', `INSERT INTO zeusi.prs (repo, number, title, head_sha, state, gh_updated_at, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id) VALUES ('example-org/team-hq', 77, 'Plankkiva form', '${'a'.repeat(40)}', 'open', now(), 'work', 'github_api', 'gh:example-org/team-hq#77', now(), decode('${SHA}', 'hex'), ${run})`],
    ['pr_reviews', `INSERT INTO zeusi.pr_reviews (repo, number, review_round, verdict, verdict_head, reviewer, review_ref, reviewed_at, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id) VALUES ('example-org/plankiva-site', 1, 1, 'SAFE', '${'a'.repeat(40)}', 'opus', null, now(), 'work', 'review_ledger', 'ledger:x:L1', now(), decode('${SHA}', 'hex'), ${run})`],
    ['routine_runs', `INSERT INTO zeusi.routine_runs (routine, run_key, host, login_label, started_at, status, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id) VALUES ('sync', 'mini:plankiva:1', 'mini', 'work', now(), 'ok', 'work', 'runner_log', 'run:mini:sync:77', now(), decode('${SHA}', 'hex'), ${run})`],
    ['people', `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id) VALUES ('p-probe', 'Plannnkiva P', 'human', 'work', ${prov})`],
  ];
  for (const [t, s] of stmts) assert.equal(await code(rolledBack(() => db.query(s))), 'ZW001', t);
});

test('0011 seeded fuzz: random Plankiva spellings (repeats, case, leetspeak, look-alikes, separators, embedded) are blocked by wall.ts and wall_eval alike; random strings agree', async () => {
  let seed = 0x0a11c0de;
  const rnd = () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = seed;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)]!;
  const forms: Record<string, string[]> = {
    p: ['p', 'P', 'Ｐ', 'ｐ', 'Р', 'р'],
    l: ['l', 'L', 'ｌ'],
    a: ['a', 'A', '4', '@', 'Ａ', 'ａ', 'А', 'а', 'α', 'Ꭺ', 'ꓮ', 'á'],
    n: ['n', 'N', 'ｎ', 'п', 'η', 'ɴ'],
    k: ['k', 'K', 'к', 'κ', 'Ꮶ', 'ｋ'],
    i: ['i', 'I', '1', '!', '|', 'і', 'ı', 'Ꭵ', 'ｉ'],
    v: ['v', 'V', 'ｖ', 'ν'],
  };
  const tight = ['', '', '', '-', '.', '_', '*', '**', '/', '​', '­', "'", '~'];
  const loose = [' ', ' - ', '. ', '  ', '\t', ' / '];
  const must: string[] = [];
  for (let n = 0; n < 300; n++) {
    const spaced = rnd() < 0.25;
    let s = '';
    const letters = ['p', 'l', 'a', 'n', 'k', 'i', 'v', 'a'];
    letters.forEach((l, li) => {
      const reps = 1 + Math.floor(rnd() * 3);
      for (let r = 0; r < reps; r++) {
        if (s !== '' && !(li === 0 && r === 0)) s += spaced ? pick(loose) : pick(tight);
        s += pick(forms[l]!);
      }
    });
    const pre = rnd() < 0.5 ? pick(['x', 'Mr ', '', '[[', 'team/', '#']) : '';
    const post = rnd() < 0.5 ? pick(['x', 's', ' sync', ']]', '-notes', '']) : '';
    must.push(pre + s + post);
  }
  const atoms = ['p', 'l', 'a', 'n', 'k', 'i', 'v', 'P', 'L', 'A', 'N', 'K', 'I', 'V', '4', '@', '1', '!', '|', ' ', '-', '.', '_', '*', 'o', 'e', 'x', 'А', 'к', '​', 'Ａ'];
  const random: string[] = [];
  for (let n = 0; n < 200; n++) {
    let s = '';
    const len = 3 + Math.floor(rnd() * 12);
    for (let j = 0; j < len; j++) s += pick(atoms);
    random.push(s);
  }
  // Mutants of the must-block spellings (1-2 chars replaced, dropped or inserted): hits and near-misses.
  for (let n = 0; n < 200; n++) {
    const cps = [...pick(must)];
    for (let m = 0; m < 1 + Math.floor(rnd() * 2); m++) {
      const at = Math.floor(rnd() * cps.length);
      const op = rnd();
      if (op < 0.4) cps[at] = pick(atoms);
      else if (op < 0.7) cps.splice(at, 1);
      else cps.splice(at, 0, pick(atoms));
    }
    random.push(cps.join(''));
  }
  const wall = await loadWall(db);
  const all = [...must, ...random];
  const rows = all.map((s) => ({ kind: 'other', subject: null, text: s, source_uri: 'zeusi:test/fuzz' }));
  const sq = await sqlRuleIds(db, 'facts', rows);
  let randomBlocked = 0;
  rows.forEach((r, i) => {
    const ts = wall.check('facts', r);
    assert.equal(ts.ruleId, sq[i], `verdict ${JSON.stringify(all[i])}`);
    if (i < must.length) {
      assert.ok(ts.blocked && ts.hard, `must block ${JSON.stringify(all[i])}`);
      assert.ok(mentionsProtectedName(all[i]!), `gate check ${JSON.stringify(all[i])}`);
    } else if (ts.blocked) randomBlocked++;
  });
  assert.ok(randomBlocked > 0 && randomBlocked < random.length, `a mix of verdicts on random strings (${randomBlocked}/${random.length})`);
});

test('0011 ReDoS: the Plankiva regex is linear in JS and in Postgres on 100k-400k char adversarial inputs', async (t) => {
  const re = pgRegexToJs(PROTECTED_VARIANTS_REGEX);
  const units = ['@', '@!|', 'p-', 'pl', 'p l ', 'n', 'p@!|l', 'p.l.a.n.k.i.v.x.', 'p l a n k i v x ', '4@4@', 'p-l-a-n-k-i-v-x', 'ppp---lll---aaa---xxx',
    '@@@nnn!!!kkk!', 'plankx', 'p  l  a  n  k  x  ', '|||!!!', 'p|l|a|n|x|', 'pé', 'p**l**a**n**x**', 'p - - l - - '];
  let jsMax = 0;
  let pgMax = 0;
  for (const n of [100_000, 400_000]) {
    for (const u of units) {
      const s = u.repeat(Math.ceil(n / u.length)).slice(0, n) + '#';
      let t1 = performance.now();
      re.test(s);
      jsMax = Math.max(jsMax, performance.now() - t1);
      t1 = performance.now();
      await db.query('SELECT $1 ~* $2 AS m', [s, PROTECTED_VARIANTS_REGEX]);
      pgMax = Math.max(pgMax, performance.now() - t1);
    }
  }
  assert.ok(jsMax < 1500, `JS worst ${jsMax.toFixed(0)} ms`);
  assert.ok(pgMax < 3000, `PG worst ${pgMax.toFixed(0)} ms`);
  // The whole verdict on a 400k-char near-miss note stays fast on both sides.
  const big = 'p-l-a-n-k-i-v-x '.repeat(40_000);
  let t0 = performance.now();
  const wall = await loadWall(db);
  assert.ok(!wall.check('facts', { kind: 'other', subject: null, text: big, source_uri: 'zeusi:test/big' }).blocked);
  const jsFull = performance.now() - t0;
  t0 = performance.now();
  assert.deepEqual(await sqlRuleIds(db, 'facts', [{ kind: 'other', subject: null, text: big, source_uri: 'zeusi:test/big' }]), [null]);
  const pgFull = performance.now() - t0;
  t.diagnostic(`regex worst case over ${units.length} inputs x 100k/400k chars: JS ${jsMax.toFixed(0)} ms, PG ${pgMax.toFixed(0)} ms; full verdict on 400k chars: JS ${jsFull.toFixed(0)} ms, PG ${pgFull.toFixed(0)} ms`);
  assert.ok(jsFull < 5000 && pgFull < 10000, `full verdict: JS ${jsFull.toFixed(0)} ms, PG ${pgFull.toFixed(0)} ms`);
});

// ---------------------------------------------------------------------------
// Gate level (config, importer path gate) and the soft lift

test('0011 gates: config strings and importer paths with Plankiva variants are refused; a clientco config stays valid', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-0011-cfg-'));
  try {
    const cfg = (extra: string) => parseToml(`
[[source]]
name = "vault-client"
kind = "vault_note"
scope = "client"
root = "~/KnowledgeVault"
include = ["ClientCo/**/*.md"]
${extra}`);
    assert.equal(validateSources(cfg(''), seedWall(), { home }).sources[0]!.scope, 'client');
    for (const bad of ['Plankiva', 'plaankiva', 'P-l-a-n-k-i-v-a', 'pl4nk1v@', 'PlАnkiva', '%50lankiva', 'xPlankivax']) {
      assert.ok(mentionsProtectedName(bad), bad);
      assert.throws(() => validateSources(cfg(`exclude = ["ClientCo/${bad}/**"]`), seedWall(), { home }), /plankiva/i, bad);
      assert.equal(sourcePathGate(`~/KnowledgeVault/ClientCo/${bad}/x.md`, { home }).ok, false, bad);
      assert.ok(seedWall().checkUri(`vault:ClientCo/${bad}/x.md`).blocked, bad);
    }
    const gh = (repo: string) => parseToml(`[github]\norg = "example-org"\nrepos = ["${repo}"]\n`);
    assert.throws(() => validateSources(gh('plankiva-tools'), seedWall(), { home }), /plankiva/i);
    assert.doesNotThrow(() => validateSources(gh('clientco-hedging-engine'), seedWall(), { home }));
    // The head (0010) wall did not know the one-n spelling: the dry-run comparison relies on that difference.
    assert.ok(!wall0010SeedWall().checkUri('vault:ClientCo/Plaankiva/x.md').blocked);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('0011 soft lift: currency amounts and P&L / book lines are admitted (team, clientco, product); account number, IBAN, desk P&L paths/lanes and agent-config repos stay blocked', async () => {
  const wall = await loadWall(db);
  const texts = ['synthetic amount USD 12,345', 'list price $ 49 per seat', 'CHF 1200 budget', 'EUR5 fee', 'JPY 100', 'P&L 2025: +3.2', 'pnl 42', 'book 7 trades'];
  for (const scope of ['work', 'client', 'product']) {
    for (const text of texts) {
      const row = { kind: 'other', subject: null, text, source_uri: `zeusi:test/lift-${scope}` };
      assert.ok(!wall.check('facts', row).blocked, `${scope}: ${text}`);
      assert.deepEqual(await sqlRuleIds(db, 'facts', [row]), [null], `${scope}: ${text}`);
      assert.equal(await code(rolledBack(() => db.query(
        `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ('other', $1, $2::zeusi.scope, 'manual', $3, now(), decode($4, 'hex'), $5)`, [text, scope, `zeusi:test/lift-${scope}`, SHA, run]))), 'ok', `${scope}: ${text}`);
    }
  }
  const soft = (text: string) => wall.check('facts', { kind: 'other', subject: null, text, source_uri: 'zeusi:test/s' });
  for (const t of ['acct 1234567 is a fake number', 'login: 99887766', 'pay to CH93 0076 2011 6238 5295 7 please']) {
    const v = soft(t);
    assert.ok(v.blocked && !v.hard, t);
  }
  for (const uri of ['vault:Work/ops/Desk-PnL-weekly.md', 'vault:ClientCo/p&l/q3.md', 'lane:session-pnl', 'gh:example-org/agent-config-backup-x#1']) {
    const v = wall.checkUri(uri);
    assert.ok(v.blocked && v.hard, uri);
  }
});
