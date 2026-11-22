// C6 §7 item 1, write half (docs/plans/2026-11-19-c6-write-path.md Verification; parent plan §7 item 1): a canary
// written through the real workspace write path (commit: markdown + a headed decision with Links: + rule and
// focus entries; sync: an HQ note and a deletion) into a born-`on` workspace and into a `verified` one is
// found in NO column of any base table (as text and as UTF-8 hex, so plain text in a bytea column is caught
// too), in no pg_stats value after ANALYZE, and no index of the five content tables covers a plain content
// column. The same writes into a flag-off workspace DO show the canary (the scan bites). PGlite, test DEK only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { HNSW_INDEX, OVERLAY_SPEC, OVERLAY_TABLES, PLAIN_UNIQUES, TARGET_URI_INDEX, TSV_INDEX } from '../src/tenant-overlay.ts';
import { c6Fixture, callerOf, commitDocs, counts, decisionEntry, decisionLog, factEntry, hqItem, newWorkspace, type C6Fixture } from './helpers/c6-fixture.ts';
import { asOwner } from './helpers/tenant-fixture.ts';

/** One lexical token, no private term. */
const CANARY = 'c6itemonecanarybilby';
const HEX = Buffer.from(CANARY, 'utf8').toString('hex');

let f: C6Fixture;
before(async () => {
  f = await c6Fixture();
});
after(async () => {
  await f.close();
});

async function writeCanary(t: string): Promise<void> {
  const c = callerOf(t);
  const r = await commitDocs(f, c, [
    { kind: 'markdown', title: `Plan ${CANARY}`, text: `---\ntitle: ${CANARY} title\ntags: ${CANARY}\n---\n# ${CANARY} heading\n\nbody ${CANARY}\n\n## second ${CANARY}\n\nmore ${CANARY}\n` },
    decisionLog(decisionEntry(`decide ${CANARY}`, { links: [`vault:notes/${CANARY}.md`, `gh:Org/${CANARY}#4`], applies: [CANARY] })
      + '\n' + factEntry('rule', `${CANARY}subject`, `rule ${CANARY}`) + '\n' + factEntry('focus', `${CANARY}focus`, `focus ${CANARY}`, '2026-11-19T08:00:00+01:00')),
  ]);
  assert.equal(r.notes.errors, 0);
  assert.deepEqual([r.decisions, r.rules, r.focus], [1, 1, 1]);
  const s = await f.ww.sync(c, [
    hqItem('journal', `2026-11-19-${CANARY}.md`, `${CANARY} day`, `## ${CANARY}\n\nsync ${CANARY}`),
    hqItem('journal', '2026-11-19-gone.md', 'Gone', `## gone\n\nto delete ${CANARY}`),
  ], []);
  assert.equal(s.counts.inserted, 2);
  assert.equal((await f.ww.sync(c, [], ['journal/2026-11-19-gone.md'])).counts.deleted, 1);
  const n = await counts(f.db, t);
  assert.ok(n['notes']! >= 4 && n['chunks']! >= 4 && n['facts'] === 2 && n['decisions'] === 1 && n['decision_links'] === 2, JSON.stringify(n));
}

/** Tables (and pg_stats columns) whose text holds the canary or its hex, as the schema owner. */
async function scan(t: string): Promise<{ rows: string[]; stats: string[] }> {
  return asOwner(f.db, async () => {
    const rels = (await f.db.query<{ r: string }>(
      `SELECT c.relname::text AS r FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind IN ('r', 'p') ORDER BY 1`, [t])).rows.map((x) => x.r);
    assert.ok(rels.length > 15, 'every base table of the schema');
    const rows: string[] = [];
    for (const r of rels) {
      const all = (await f.db.query<{ j: string }>(`SELECT to_jsonb(x)::text AS j FROM "${t}"."${r}" x`)).rows.map((x) => x.j.toLowerCase()).join('\n');
      if (all.includes(CANARY)) rows.push(`${r}:text`);
      if (all.includes(HEX)) rows.push(`${r}:hex`);
      await f.db.exec(`ANALYZE "${t}"."${r}"`);
    }
    const stats: string[] = [];
    for (const s of (await f.db.query<{ tbl: string; col: string; v: string | null }>(
      `SELECT tablename::text AS tbl, attname::text AS col,
              concat_ws(' ', most_common_vals::text, histogram_bounds::text, most_common_elems::text) AS v
         FROM pg_stats WHERE schemaname = $1`, [t])).rows) {
      const v = (s.v ?? '').toLowerCase();
      if (v.includes(CANARY) || v.includes(HEX)) stats.push(`${s.tbl}.${s.col}`);
    }
    return { rows, stats };
  });
}

/** Indexes of the five content tables that cover a plain content (or derived) column. */
async function plainIndexes(t: string): Promise<string[]> {
  return asOwner(f.db, async () => {
    const out: string[] = [];
    for (const r of (await f.db.query<{ tbl: string; idx: string; def: string }>(
      `SELECT c.relname::text AS tbl, ic.relname::text AS idx, pg_get_indexdef(i.indexrelid) AS def
         FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid JOIN pg_class ic ON ic.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relname = ANY($2::text[])`, [t, [...OVERLAY_TABLES]])).rows) {
      const spec = OVERLAY_SPEC.find((s) => s.table === r.tbl)!;
      const plain = [...spec.columns.map((c) => c.plain), ...spec.derived, ...(r.tbl === 'chunks' ? ['tsv'] : [])];
      const cols = /\((.*)\)/.exec(r.def)?.[1] ?? '';
      if (plain.some((p) => new RegExp(`\\b${p}\\b`).test(cols))) out.push(r.idx);
    }
    return out.sort();
  });
}

test('item 1: a canary through commit (markdown + headed decision with Links:) and sync is in no column, no pg_stats value and no index of a sealed workspace', async () => {
  const on = await newWorkspace(f, 'on');
  const verified = await newWorkspace(f, 'verified');
  const off = await newWorkspace(f, 'off');
  for (const t of [on, verified, off]) await writeCanary(t);

  // Control: the plain workspace shows the canary in rows and in pg_stats (the scan can see it).
  const plain = await scan(off);
  assert.ok(plain.rows.some((x) => x.startsWith('notes:')) && plain.rows.some((x) => x.startsWith('decisions:')), JSON.stringify(plain));
  assert.ok(plain.stats.length > 0, 'pg_stats holds plain values on the off path');

  for (const t of [on, verified]) {
    const s = await scan(t);
    assert.deepEqual(s.rows, [], `${t === on ? 'on' : 'verified'}: no row holds the canary or its hex`);
    assert.deepEqual(s.stats, [], `${t === on ? 'on' : 'verified'}: no pg_stats value holds it`);
  }

  // Indexes. A flipped workspace keeps two the team indexes on a plain column that C5's flip does not drop
  // (0002: chunks_text_sha on text_sha256, facts_subject on subject). On a sealed row both columns are NULL
  // (C5 KTD3, and the flip CHECK on `on`), so they index nothing: pinned below. A `verified` workspace also
  // still has the indexes C5's flip drops (tsv / HNSW / plain UNIQUEs / target index), again over NULLs only.
  const TEAM_PLAIN_INDEXES = ['chunks_text_sha', 'facts_subject'];
  assert.deepEqual(await plainIndexes(on), TEAM_PLAIN_INDEXES);
  const flipDropped = [...PLAIN_UNIQUES.map((u) => u.name), TSV_INDEX, HNSW_INDEX, TARGET_URI_INDEX];
  const pre = await plainIndexes(verified);
  assert.ok(pre.every((x) => flipDropped.includes(x) || TEAM_PLAIN_INDEXES.includes(x)), JSON.stringify(pre));
  for (const t of [on, verified]) {
    await asOwner(f.db, async () => {
      for (const s of OVERLAY_SPEC) {
        const cols = [...s.columns.map((c) => c.plain), ...s.derived];
        const n = (await f.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}".${s.table} WHERE num_nonnulls(${cols.join(', ')}) > 0`)).rows[0]!.n;
        assert.equal(n, 0, `${s.table}: no plain value for a plain-column index to hold`);
      }
    });
  }
  assert.equal((await f.dir.overlayStep(verified, 'flip', { dryRun: false })).outcome, 'applied');
  assert.deepEqual(await plainIndexes(verified), TEAM_PLAIN_INDEXES);
  const after0 = await scan(verified);
  assert.deepEqual([after0.rows, after0.stats], [[], []]);
});
