// 0010 (owner rule): ClientCo and Northbank go INTO Zeusi
// (scope clientco for ClientCo); ONLY Plankiva stays out. Synthetic fixtures only, PGlite only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import {
  PROTECTED_VARIANTS_REGEX, PROTECTED_SPELLING_REGEX, LEGACY_SEED_RULES, LIFTED_0010, LIFTED_0011, legacySeedWall, loadWall, SEED_RULES, seedRulesWithIds, seedWall,
} from '../src/wall.ts';
import { mentionsProtectedName, parseToml, validateSources } from '../src/sources.ts';
import { SCOPES, validateFact } from '../src/facts.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const SHA = 'cd'.repeat(32);
const M0010 = '0010_wall_client_admit.sql';
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

const fact = (d: Db, uri: string, scope: string, text = 'synthetic') => d.query(
  `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
   VALUES ('other', $1, $2::zeusi.scope, 'manual', $3, now(), decode($4, 'hex'), $5)`, [text, scope, uri, SHA, run]);

before(async () => {
  db = await pgliteDb();
  await migrate(db);
  run = Number((await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
});
after(async () => db.close());

const LIFTED = [
  ['path_glob', 'ClientCo/**'], ['path_glob', '**clientco**'], ['lane', '*clientco*'],
  ['repo', 'example-org/clientco-*'], ['repo', 'example-org/*clientco*'], ['repo', '*/*clientco*'],
] as const;
/** Every Plankiva exclusion rule of 0003 / 0007, by (kind, pattern). */
const PLANKIVA = [
  ['path_glob', 'plankiva/**'], ['path_glob', '**plankiva**'], ['path_glob', '~/PlankivaVault/**'], ['path_glob', '**/PlankivaVault/**'],
  ['path_glob', '~/.assistant/memory/plankiva*'], ['path_glob', '**/.assistant/memory/plankiva*'],
  ['lane', '*plankiva*'], ['repo', '*plankiva*'], ['tag', 'plankiva'], ['term', 'plankiva'],
] as const;

test('0010 removes exactly the six ClientCo-name hard rules; no seeded rule names clientco any more', async () => {
  const rules = (await db.query<{ kind: string; pattern: string; hard: boolean }>(
    `SELECT kind::text AS kind, pattern, hard FROM zeusi.wall_denylist ORDER BY id`)).rows;
  for (const [k, p] of LIFTED) assert.ok(!rules.some((r) => r.kind === k && r.pattern === p), `${k} ${p} lifted`);
  assert.deepEqual(rules.filter((r) => /clientco/i.test(r.pattern)), [], 'no rule pattern mentions clientco');
  assert.deepEqual([...LIFTED_0010].map((x) => `${x.kind} ${x.pattern}`).sort(), LIFTED.map(([k, p]) => `${k} ${p}`).sort());
  // Kept on purpose (not a ClientCo-name rule): agent config backups.
  assert.ok(rules.some((r) => r.kind === 'repo' && r.pattern === 'example-org/agent-config-backup*' && r.hard));
  // Desk P&L, area and soft rules are untouched.
  for (const p of ['**pnl**', '**p&l**', '*pnl*', 'session-pnl', 'desk-pnl', 'Work/intake/**', 'personal/**']) {
    assert.ok(rules.some((r) => r.pattern === p && r.hard), p);
  }
  // 0010 itself keeps the four soft content rules; 0011 (applied here too) lifts currency and P&L, leaving two.
  assert.equal(rules.filter((r) => !r.hard).length, 2, 'account number and IBAN stay soft after 0011');
});

test('0010 keeps every Plankiva rule hard, with the ids a fresh database gave them, and adds the hard separator / leetspeak regex', async () => {
  const rules = (await db.query<{ id: number; kind: string; pattern: string; hard: boolean }>(
    `SELECT id::int AS id, kind::text AS kind, pattern, hard FROM zeusi.wall_denylist ORDER BY id`)).rows;
  for (const [k, p] of PLANKIVA) {
    const r = rules.find((x) => x.kind === k && x.pattern === p);
    assert.ok(r && r.hard, `${k} ${p}`);
    const legacyId = LEGACY_SEED_RULES.findIndex((x) => x.kind === k && x.pattern === p) + 1;
    assert.equal(r!.id, legacyId, `${k} ${p} keeps id ${legacyId}`);
  }
  const rx = rules.find((x) => x.kind === 'regex' && x.pattern === PROTECTED_SPELLING_REGEX);
  assert.ok(rx && rx.hard, 'hard Plankiva spelling regex seeded');
  assert.ok(rx!.id > rules.find((x) => x.kind === 'term' && x.pattern === 'plankiva')!.id, 'checked after the plankiva term (first hit wins)');
  // TS ids == DB ids for every current rule.
  assert.deepEqual(seedRulesWithIds(), rules.map((r) => ({ id: r.id, kind: r.kind, hard: r.hard, pattern: r.pattern })));
  // The regex is hard: no allow, no softening.
  assert.equal(await code(rolledBack(() => db.query(
    `INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ('zeusi:test/x', decode($1, 'hex'), $2)`, [SHA, rx!.id]))), 'ZW002');
  assert.equal(await code(rolledBack(() => db.query(`UPDATE zeusi.wall_denylist SET hard = false WHERE id = $1`, [rx!.id]))), 'ZW002');
});

test('0010 does not replace wall_eval / wall_norm / pct_decode / wall_content (their bodies carry no ClientCo logic)', () => {
  const sql = readFileSync(join(MIGRATIONS_DIR, M0010), 'utf8').replace(/--.*$/gm, '');
  assert.doesNotMatch(sql, /FUNCTION\s+zeusi\.(wall_eval|wall_norm|pct_decode|pct_decode_once|wall_content|wall_check|glob_to_regex)\b/i);
  // The new enum value is never used inside 0010 (a new enum value cannot be used in the transaction that adds it).
  assert.doesNotMatch(sql, /'client'\s*::\s*zeusi\.scope|scope\s*(=|<>|IN)\s*\(?\s*'client'/i);
});

test('0010 scope enum is exactly work, product, client, personal; TS SCOPES match', async () => {
  const r = await db.query<{ v: string }>(
    `SELECT enumlabel AS v FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'zeusi' AND t.typname = 'scope' ORDER BY e.enumsortorder`);
  assert.deepEqual(r.rows.map((x) => x.v), ['work', 'product', 'client', 'personal']);
  assert.deepEqual([...SCOPES].sort(), ['client', 'personal', 'product', 'work']);
  assert.ok(validateFact({ kind: 'other', text: 'x', scope: 'client', sourceKind: 'manual', sourceUri: 'u', sourceTs: '2026-01-01', sourceSha256: 'ab'.repeat(32) }));
  assert.throws(() => validateFact({ kind: 'other', text: 'x', scope: 'personal', sourceKind: 'manual', sourceUri: 'u', sourceTs: '2026-01-01', sourceSha256: 'ab'.repeat(32) }), /personal/);
});

test('0010 RLS: clientco rows insert (owner, box_rw, ingest) and are read like team by the reader roles; personal stays hidden', async () => {
  const iso = await pgliteDb(); // own DB: PGlite cannot undo SET SESSION AUTHORIZATION on ROLLBACK
  try {
    await migrate(iso);
    const rid = Number((await iso.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
    const ins = (uri: string, scope: string) => iso.query(
      `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('other', 'synthetic ClientCo fact', $1::zeusi.scope, 'manual', $2, now(), decode($3, 'hex'), $4)`, [scope, uri, SHA, rid]);
    await ins('vault:ClientCo/clientco-erp/owner.md', 'client');
    await ins('zeusi:test/team', 'work');
    await ins('zeusi:test/northbank', 'product');
    await ins('zeusi:test/personal', 'personal');
    // Writers: clientco allowed like team (agent_write and ingest groups).
    for (const role of ['zeusi_box_rw', 'zeusi_mini_ingest']) {
      await iso.exec(`SET ROLE ${role}`);
      try {
        await ins(`vault:ClientCo/clientco-erp/${role}.md`, 'client');
      } finally {
        await iso.exec('RESET ROLE');
      }
    }
    // A clientco chunk inherits the parent's scope.
    const nid = Number((await iso.query<{ id: number }>(
      `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('ClientCo/clientco-erp/overview.md', 'ClientCo ERP', 'synthetic', now(), 'client', 'vault_note', 'vault:ClientCo/clientco-erp/overview.md', now(), decode($1, 'hex'), $2)
       RETURNING id::int AS id`, [SHA, rid])).rows[0]!.id);
    await iso.query(`INSERT INTO zeusi.chunks (note_id, chunk_index, text, text_sha256, token_count, source_uri) VALUES ($1, 0, 'synthetic', decode($2, 'hex'), 1, 'vault:ClientCo/clientco-erp/overview.md#c0')`, [nid, SHA]);
    assert.equal((await iso.query<{ s: string }>(`SELECT scope::text AS s FROM zeusi.chunks WHERE note_id = $1`, [nid])).rows[0]!.s, 'client');

    for (const login of ['zeusi_box_ro', 'zeusi_cloud_ro', 'zeusi_box_rw', 'zeusi_mini_ingest']) {
      await iso.exec(`SET ROLE ${login}`);
      try {
        const seen = (await iso.query<{ s: string; n: number }>(
          `SELECT scope::text AS s, count(*)::int AS n FROM zeusi.facts GROUP BY 1 ORDER BY 1`)).rows;
        assert.deepEqual(seen.map((x) => x.s), ['client', 'product', 'work'], login);
        assert.equal(seen.find((x) => x.s === 'client')!.n, 3, login);
        assert.equal((await iso.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.chunks WHERE scope::text = 'client'`)).rows[0]!.n, 1, login);
        assert.equal((await iso.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.facts_current WHERE scope::text = 'client'`)).rows[0]!.n, 3, `${login} view`);
      } finally {
        await iso.exec('RESET ROLE');
      }
    }
    // Writers still cannot write personal; backup still reads everything.
    await iso.exec('SET ROLE zeusi_box_rw');
    try {
      assert.equal(await code(ins('zeusi:test/personal-2', 'personal')), '42501');
    } finally {
      await iso.exec('RESET ROLE');
    }
    await iso.exec('SET ROLE zeusi_mini_backup');
    try {
      assert.equal((await iso.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.facts`)).rows[0]!.n, 6);
    } finally {
      await iso.exec('RESET ROLE');
    }
    // Every content table has the read policy with clientco (no table left on the 0005 policy);
    // 0013's decision_links is the tenth and carries the same policy.
    const pol = (await iso.query<{ t: string; q: string }>(
      `SELECT tablename::text AS t, qual AS q FROM pg_policies WHERE schemaname = 'zeusi' AND policyname = 'read_allowed_scopes' ORDER BY 1`)).rows;
    assert.equal(pol.length, 10);
    assert.ok(pol.some((p) => p.t === 'decision_links'));
    for (const p of pol) assert.match(p.q, /'client'/, p.t);
    for (const p of pol) assert.doesNotMatch(p.q, /personal/, p.t);
  } finally {
    await iso.close();
  }
});

test('0010 upgrade from a 0009 database: one transaction via migrate(); quarantine rows that pointed at a lifted rule keep uri + hash; Plankiva rules keep their ids', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-0010-'));
  const iso = await pgliteDb();
  try {
    for (const f of readdirSync(MIGRATIONS_DIR).filter((x) => x < '0010')) cpSync(join(MIGRATIONS_DIR, f), join(dir, f));
    await migrate(iso, { dir });
    const rid = Number((await iso.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
    // Old wall: the ClientCo path is a hard block; record it as the importer would (path hash only).
    const old = await loadWall(iso);
    assert.deepEqual(old.rules.map((r) => ({ kind: r.kind, hard: r.hard, pattern: r.pattern })), LEGACY_SEED_RULES.map((r) => ({ kind: r.kind, hard: r.hard, pattern: r.pattern })));
    const v = old.checkUri('vault:ClientCo/clientco-erp/x.md');
    assert.ok(v.blocked && v.hard);
    await iso.query(`SELECT zeusi.quarantine_record('vault_note', 'vault-path-sha256:' || $1, decode($1, 'hex'), $2, $3, 'notes', NULL)`, ['ef'.repeat(32), v.ruleId, rid]);
    const plankivaBefore = (await iso.query<{ id: number; kind: string; pattern: string }>(
      `SELECT id::int AS id, kind::text AS kind, pattern FROM zeusi.wall_denylist WHERE pattern ILIKE '%plankiva%' ORDER BY id`)).rows;

    cpSync(join(MIGRATIONS_DIR, M0010), join(dir, M0010));
    const res = await migrate(iso, { dir, tookSnapshot: true });
    assert.deepEqual(res.applied, [M0010]);
    const q = (await iso.query<{ rule_id: number | null; uri: string }>(`SELECT rule_id, source_uri AS uri FROM zeusi.quarantine`)).rows;
    assert.deepEqual(q, [{ rule_id: null, uri: `vault-path-sha256:${'ef'.repeat(32)}` }]);
    const plankivaAfter = (await iso.query<{ id: number; kind: string; pattern: string }>(
      `SELECT id::int AS id, kind::text AS kind, pattern FROM zeusi.wall_denylist WHERE pattern ILIKE '%plankiva%' AND kind <> 'regex' ORDER BY id`)).rows;
    assert.deepEqual(plankivaAfter, plankivaBefore);
    const now = await loadWall(iso);
    assert.ok(!now.checkUri('vault:ClientCo/clientco-erp/x.md').blocked);
    assert.ok(now.checkUri('vault:ClientCo/plankiva/x.md').blocked);
    // clientco is usable after the commit.
    await iso.query(
      `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('other', 'synthetic', 'client', 'manual', 'vault:ClientCo/x.md', now(), decode($1, 'hex'), $2)`, [SHA, rid]);
    assert.deepEqual(await iso.query(`SELECT * FROM zeusi.wall_audit()`).then((r) => r.rows), []);
  } finally {
    await iso.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('0010 is re-runnable (same rules, policies and grants after a second run)', async () => {
  const snap = async () => JSON.stringify([
    (await db.query(`SELECT id, kind::text, hard, pattern FROM zeusi.wall_denylist ORDER BY id`)).rows,
    (await db.query(`SELECT tablename, policyname, roles::text, qual FROM pg_policies WHERE schemaname = 'zeusi' ORDER BY 1, 2`)).rows,
  ]);
  const before = await snap();
  await rolledBack(async () => {
    await db.exec(readFileSync(join(MIGRATIONS_DIR, M0010), 'utf8'));
    assert.equal(await snap(), before);
  });
});

test('0010 TS seeds: SEED_RULES = legacy minus lifted (0010, 0011) plus the 0010 and 0011 regexes; legacySeedWall is the 0009 wall (dry run only)', () => {
  const key = (r: { kind: string; pattern: string }) => `${r.kind} ${r.pattern}`;
  const lifted = new Set([...LIFTED_0010, ...LIFTED_0011].map(key));
  assert.deepEqual(
    SEED_RULES.map(key),
    [...LEGACY_SEED_RULES.filter((r) => !lifted.has(key(r))).map(key), `regex ${PROTECTED_SPELLING_REGEX}`, `regex ${PROTECTED_VARIANTS_REGEX}`],
  );
  assert.ok(legacySeedWall().checkUri('vault:ClientCo/x.md').blocked);
  assert.ok(!seedWall().checkUri('vault:ClientCo/x.md').blocked);
  for (const w of [legacySeedWall(), seedWall()]) {
    for (const u of ['vault:ClientCo/plankiva/x.md', 'file:~/PlankivaVault/requests/x.md', 'vault:Work/%50lankiva.md']) assert.ok(w.checkUri(u).blocked, u);
  }
});

test('0010 config: a clientco source is valid; Plankiva spellings with separators / leetspeak are refused in any config string', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-0010-cfg-'));
  try {
    const cfg = (extra: string) => parseToml(`
[[source]]
name = "vault-client"
kind = "vault_note"
scope = "client"
root = "~/KnowledgeVault"
include = ["ClientCo/**/*.md"]
${extra}`);
    const ok = validateSources(cfg(''), seedWall(), { home });
    assert.equal(ok.sources[0]!.scope, 'client');
    for (const bad of ['P-l-a-n-k-i-v-a', 'pl4nkiva', 'p.l.a.n.k.i.v.a', 'Plan_kiva', 'ｐｌ４ｎｋｉｖａ']) {
      assert.ok(mentionsProtectedName(bad), bad);
      assert.throws(() => validateSources(cfg(`exclude = ["ClientCo/${bad}/**"]`), seedWall(), { home }), /plankiva/, bad);
    }
    for (const fine of ['plan', 'kiva', 'plankton', 'ClientCo/clientco-erp', 'northbank']) assert.ok(!mentionsProtectedName(fine), fine);
    // A ClientCo github repo is no longer refused; an plankiva one still is.
    const gh = (repo: string) => parseToml(`[github]\norg = "example-org"\nrepos = ["${repo}"]\n`);
    assert.doesNotThrow(() => validateSources(gh('clientco-hedging-engine'), seedWall(), { home }));
    assert.throws(() => validateSources(gh('clientco-plankiva-tools'), seedWall(), { home }), /plankiva/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
