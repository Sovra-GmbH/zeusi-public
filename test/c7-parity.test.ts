// C7 parity (docs/plans/2026-11-19-c7-read-path.md KTD9, "Parity"): the same synthetic corpus, written through the
// real write route into P (off), S (born on), V (prepared, verified) and D (on, relaxed to decrypting, every even
// id decrypted by a decrypt-shaped UPDATE), gives the SAME tool output on every read tool, compared after
// deleting query_id and generated_at only. P runs today's SQL (the PGlite oracle: real websearch_to_tsquery,
// ts_rank_cd); S, V and D run the sealed route (the app lexer over the B1 index). Scores are compared exactly.
// Mutants (each turns a case red): rank with BM25 or any other function (search order / score differs); drop the
// phrase fallback (a phrase decision is missing); skip negation in the query parser ('launch -pricing' differs);
// lock notes from the index ignoring the DB status (the deleted sync note's lock is served); candidateMatch
// without a_hit (a task matched only by applies_to is missing); facts focus without the opened subject (focus
// dedupe differs); note_locks counted without the btrim rule (onboarding differs).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { noteLockItemCount } from '../src/onboarding.ts';
import { C7_QUERIES, C7_TASKS, mcpHarness, normalised, readCalls, stable } from './helpers/c7-fixture.ts';
import { toTsvector } from '../src/b1-lexer.ts';
import { c7World, decryptingWorkspace, filledWorkspace, routedDeps, type C7World } from './helpers/c7-sealed.ts';

let w: C7World;
const ws: Record<'P' | 'S' | 'V' | 'D', string> = { P: '', S: '', V: '', D: '' };
const out: Record<string, unknown[]> = {};

before(async () => {
  w = await c7World();
  ws.P = await filledWorkspace(w, 'off');
  ws.S = await filledWorkspace(w, 'on');
  ws.V = await filledWorkspace(w, 'verified');
  ws.D = await decryptingWorkspace(w);
  for (const [name, t] of Object.entries(ws)) {
    const h = await mcpHarness(routedDeps(w, t));
    out[name] = [];
    for (const [tool, args] of readCalls()) {
      const r = await h.call(tool, args);
      out[name]!.push({ tool, args, isError: r.isError, out: stable(normalised(r.json)) ?? r.text });
    }
  }
});
after(async () => {
  await w.f.close();
});

const calls = readCalls();
const idxOf = (pred: (c: [string, Record<string, unknown>]) => boolean) => calls.map((c, i) => (pred(c) ? i : -1)).filter((i) => i >= 0);

function sameAs(name: 'S' | 'V' | 'D', which: number[]): void {
  for (const i of which) {
    const p = out['P']![i] as { tool: string; args: unknown; isError: boolean; out: unknown };
    const x = out[name]![i] as typeof p;
    assert.equal(p.isError, false, `P ${p.tool} ${JSON.stringify(p.args)}: ${JSON.stringify(p.out).slice(0, 300)}`);
    assert.deepEqual(x, p, `${name}: ${p.tool} ${JSON.stringify(p.args)}`);
  }
}

for (const name of ['S', 'V', 'D'] as const) {
  test(`parity ${name}: zeusi_search gives the same hits (uri, text, heading, order, exact score), decisions and about list as P for every corpus query`, () => {
    sameAs(name, idxOf(([t]) => t === 'zeusi_search'));
    // The corpus exercises what the parity claims: hits, phrase decisions, negation, about entries.
    const s = out['P']!.filter((x) => (x as { tool: string }).tool === 'zeusi_search') as Array<{ out: { hits: unknown[]; decisions: Array<{ match: string }>; about: unknown[] } }>;
    assert.ok(s.filter((x) => x.out.hits.length > 0).length >= C7_QUERIES.length / 2, 'most queries have hits');
    assert.ok(s.some((x) => x.out.decisions.some((d) => d.match === 'phrase')), 'a phrase decision');
    assert.ok(s.some((x) => x.out.about.length > 0), 'an about entry');
  });

  test(`parity ${name}: zeusi_startup (rules, remainder, focus, decisions with links and source_note, withheld, messages) equals P`, () => {
    sameAs(name, idxOf(([t]) => t === 'zeusi_startup'));
    const st = (out['P']![0] as { out: { rules: unknown[]; focus: unknown[]; decisions: unknown[]; focus_older_same_subject?: number } }).out;
    assert.ok(st.rules.length >= 2 && st.focus.length >= 2 && st.decisions.length >= 5, 'startup has rules, focus and decisions');
    assert.equal(st.focus_older_same_subject, 1, 'the older focus of the same subject is counted, not served');
  });

  test(`parity ${name}: zeusi_context_for_task items, history and conflicts equal P for every corpus task`, () => {
    sameAs(name, idxOf(([t]) => t === 'zeusi_context_for_task'));
    const ctx = out['P']!.filter((x) => (x as { tool: string }).tool === 'zeusi_context_for_task') as Array<{ out: { items: unknown[]; history?: unknown[] } }>;
    assert.ok(ctx.filter((x) => x.out.items.length > 0).length >= C7_TASKS.length / 2, 'most tasks have items');
    assert.ok(ctx.some((x) => (x.out.history ?? []).length > 0), 'a superseded / expired lock in history');
  });

  test(`parity ${name}: zeusi_onboarding_status counts (note_locks included) equal P`, () => {
    sameAs(name, idxOf(([t]) => t === 'zeusi_onboarding_status'));
  });
}

test('note_locks rule in memory = the SQL rule (array / string / other; null and space-only items do not count; btrim trims spaces only)', () => {
  assert.equal(noteLockItemCount(['a', '', '  ', null, 5, { x: 1 }, '\tz']), 4);
  assert.equal(noteLockItemCount('one'), 1);
  assert.equal(noteLockItemCount('  '), 0);
  assert.equal(noteLockItemCount({ a: 1 }), 0);
  assert.equal(noteLockItemCount(undefined), 0);
});

test('divergence (KTD9, stated, open decision 2): a query word inside a date token (the ISO heading of a decision-log note) ranks by the app lexer, not the Postgres parser: same hits, a different score; mutant: emit Postgres signed-number tokens -> P and S equal, red', async () => {
  const q = { query: 'q3 2026' };
  const p = (await (await mcpHarness(routedDeps(w, ws.P))).call('zeusi_search', q)).json as { hits: Array<{ source_uri: string; score: number }> };
  const s = (await (await mcpHarness(routedDeps(w, ws.S))).call('zeusi_search', q)).json as typeof p;
  assert.deepEqual(s.hits.map((h) => h.source_uri).sort(), p.hits.map((h) => h.source_uri).sort(), 'the same chunks match');
  assert.notDeepEqual(s.hits.map((h) => h.score), p.hits.map((h) => h.score), 'their scores differ (stated divergence)');
  // The cause, pinned: Postgres keeps '-11' as a signed integer token; the app splits on the '-'.
  assert.deepEqual(toTsvector('2026-11-17T10:00').map(([w]) => w), ['00', '11', '17t10', '2026']);
});
