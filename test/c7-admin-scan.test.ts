// C7 §7 item 1, read half (docs/plans/2026-11-19-c7-read-path.md "§7.1"): on a born-on workspace, after search,
// startup, context_for_task and onboarding with a canary query, a canary task and a canary note, (1) the owner scan
// finds the canary (text, and UTF-8 hex inside any bytea) in no column of any table of the workspace (b1_index
// included), no pg_stats value and no index definition; (2) no statement text or parameter the sealed route sent
// contains the canary query, task or note words. The same reads on an `off` workspace DO send the query (the
// control that shows the check bites). PGlite, real roles, a FIXED test DEK. No network.
// Mutants: index objects sealed as identity (plain bytes) -> the hex scan finds the canary in b1_index.blob_ct, red;
// the hook writes a plain term list -> red; run searchAbout / the plain search SQL on the sealed route -> the
// parameter check finds the canary query, red.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { callerOf, commitDocs, decisionEntry, decisionLog, newWorkspace } from './helpers/c6-fixture.ts';
import { mcpHarness, recordingDb, type Recorded } from './helpers/c7-fixture.ts';
import { c7World, routedDeps, type C7World } from './helpers/c7-sealed.ts';
import { asOwner } from './helpers/tenant-fixture.ts';

const CANARY = 'c7readcanarynumbat';
const QUERY = 'c7querycanaryquokka';
const TASK = 'c7taskcanarybilby';

let w: C7World;
before(async () => {
  w = await c7World();
});
after(async () => {
  await w.f.close();
});

async function scan(t: string): Promise<string[]> {
  return asOwner(w.f.db, async () => {
    await w.f.db.exec(`ANALYZE`);
    const hits: string[] = [];
    const rels = (await w.f.db.query<{ r: string }>(`SELECT c.relname::text AS r FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind = 'r'`, [t])).rows.map((x) => x.r);
    assert.ok(rels.includes('b1_index') && rels.includes('notes'));
    for (const word of [CANARY, QUERY, TASK]) {
      const hex = Buffer.from(word, 'utf8').toString('hex');
      for (const r of rels) {
        const n = (await w.f.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}"."${r}" x WHERE strpos(lower(to_jsonb(x)::text), $1) > 0 OR strpos(to_jsonb(x)::text, $2) > 0`, [word, hex])).rows[0]!.n;
        if (n > 0) hits.push(`${r}:${word}`);
      }
      const st = (await w.f.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_stats s WHERE s.schemaname = $1 AND (strpos(lower(to_jsonb(s)::text), $2) > 0 OR strpos(to_jsonb(s)::text, $3) > 0)`, [t, word, hex])).rows[0]!.n;
      if (st > 0) hits.push(`pg_stats:${word}`);
      const ix = (await w.f.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_indexes WHERE schemaname = $1 AND strpos(lower(indexdef), $2) > 0`, [t, word])).rows[0]!.n;
      if (ix > 0) hits.push(`pg_indexes:${word}`);
    }
    return hits;
  });
}

async function readAll(t: string, log: Recorded[]): Promise<void> {
  const h = await mcpHarness(routedDeps(w, t, { tenantRead: async () => recordingDb(await w.f.router.open(t), log) }));
  for (const [tool, args] of [
    ['zeusi_search', { query: QUERY }], ['zeusi_search', { query: CANARY }], ['zeusi_search', { query: `"${CANARY} words"` }],
    ['zeusi_startup', {}], ['zeusi_context_for_task', { task: `work on ${TASK} and ${CANARY}` }], ['zeusi_onboarding_status', {}],
  ] as const) {
    const r = await h.call(tool, args);
    assert.equal(r.isError, false, `${tool}: ${r.text.slice(0, 200)}`);
  }
}

const sentText = (log: Recorded[], word: string) => log.filter((s) => s.sql.toLowerCase().includes(word) || JSON.stringify(s.params, (_k, v) => (v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v)).toLowerCase().includes(word));

test('§7.1 (reads): after every read tool with a canary query, task and note, the owner scan finds no canary in any column (b1_index included), pg_stats or index definition; the sealed route sent none of them to Postgres', async () => {
  const t = await newWorkspace(w.f, 'on');
  await commitDocs(w.f, callerOf(t), [
    { kind: 'markdown', title: `Plan ${CANARY}`, text: `# ${CANARY}\n\n${CANARY} words in the body.\n` },
    decisionLog(decisionEntry(`decide ${CANARY} now`, { applies: [CANARY] })),
  ]);
  const log: Recorded[] = [];
  await readAll(t, log);
  assert.ok(log.length > 10, 'statements were recorded');
  assert.ok(w.cache.list().some((e) => e.tenant === t), 'the reads used the B1 index');
  assert.deepEqual(await scan(t), [], 'no canary at rest');
  for (const word of [QUERY, TASK, CANARY]) assert.deepEqual(sentText(log, word).map((s) => s.sql.slice(0, 80)), [], `${word}: never in a statement or parameter`);
});

test('§7.1 control: the same reads on an off workspace DO send the query to Postgres (so the parameter check above bites)', async () => {
  const t = await newWorkspace(w.f, 'off');
  await commitDocs(w.f, callerOf(t), [{ kind: 'markdown', title: 'Plain', text: '# Plain\n\nplain words.\n' }]);
  const log: Recorded[] = [];
  await readAll(t, log);
  assert.ok(sentText(log, QUERY).length > 0, 'websearch_to_tsquery($1) gets the query on the plain route');
  assert.ok(sentText(log, TASK).length > 0, 'queryCandidates gets the task terms on the plain route');
});
