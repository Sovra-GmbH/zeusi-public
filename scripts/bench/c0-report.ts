// C0 report: turns docs/bench/2026-11-18-c0-raw.jsonl (written by c0-run.ts) into the markdown tables of
// docs/plans/2026-11-18-c0-results.md. Every figure printed here is MEASURED on the bench host; the results
// doc labels projections separately as [estimate]. Also strips local temp paths from the raw file.
//
//   node scripts/bench/c0-report.ts [raw.jsonl] > tables.md
import { readFileSync, writeFileSync } from 'node:fs';

const file = process.argv[2] ?? 'docs/bench/2026-11-18-c0-raw.jsonl';
const clean = readFileSync(file, 'utf8').replace(/\/(?:var|private|tmp)\/[^"\s]*zeusi-c0-idx-[^/"\s]+\//g, '<tmp>/');
writeFileSync(file, clean);
type R = Record<string, any>;
const rows: R[] = clean.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as R);
const MiB = 1048576;
const mb = (b: number) => (b / MiB).toFixed(1);
const f1 = (x: number) => (Math.round(x * 10) / 10).toString();
const sh = (s: number) => (s === 0 ? 'blob' : String(s));
const p = (s: string) => process.stdout.write(`${s}\n`);
const table = (head: string[], body: Array<Array<string | number>>) => {
  p(`| ${head.join(' | ')} |`);
  p(`|${head.map(() => '---').join('|')}|`);
  for (const r of body) p(`| ${r.join(' | ')} |`);
  p('');
};
const by = (cmd: string, cpu?: string) => rows.filter((r) => r['cmd'] === cmd && (!cpu || r['cpu'] === cpu));
const failed = rows.filter((r) => r['exit'] !== 0);

p('### Baseline (hosted server modules loaded, after GC), cpu p');
table(['run', 'RSS before import MiB', 'RSS after MiB', 'heapUsed after MiB', 'peak RSS (time -l) MiB'],
  by('baseline').map((r, i) => [i + 1, mb(r.before.rss), mb(r.after.rss), mb(r.after.heapUsed), r.maxRssMiB]));

for (const cpu of ['p', 'e']) {
  p(`### B1 index build (cpu ${cpu})`);
  table(['MiB', 'notes', 'chunks', 'text MiB', 'shard', 'deflate', 'shards', 'index plain MiB', 'index enc MiB', 'largest shard KiB', 'build ms', 'tokenize ms', 'serialize ms', 'seal ms', 'peak RSS MiB'],
    by('index', cpu).map((r) => [r.mib, r.notes, r.chunks, mb(r.textBytes), sh(r.shard), r.deflate ? 'yes' : 'no', r.shards, mb(r.indexPlainBytes), mb(r.indexEncBytes), Math.round(r.largestShardEncBytes / 1024), f1(r.buildWallMs), f1(r.tokenizeMs), f1(r.serializeMs), f1(r.sealMs), r.maxRssMiB]));
}

for (const cpu of ['p', 'e']) {
  p(`### Cache: decrypt (load) and query (cpu ${cpu})`);
  table(['MiB', 'shard', 'deflate', 'form', 'copies', 'load ms per copy', 'cold 1st query ms', 'warm p50 ms', 'warm p95 ms', 'RSS delta per copy MiB', 'heap+AB delta per copy MiB', 'peak RSS MiB', 'exit'],
    by('cache', cpu).map((r) => r['exit'] === 0
      ? [r.mib, sh(r.shard), r.deflate ? 'yes' : 'no', r.form, r.copies, r.loadMsPerCopy.join(' / '), r.coldFirstQueryMs, r.warmQueryMs.p50, r.warmQueryMs.p95, r.rssDeltaPerCopyMiB.join(' / '), r.heapPlusAbDeltaPerCopyMiB.join(' / '), r.maxRssMiB, 0]
      : ['', '', '', String(r.args).replace(/^cache /, ''), '', '', '', '', '', '', '', r.maxRssMiB, `${r.exit} ${r.error ?? ''}`]));
}

for (const d of [false, true]) {
  p(d ? '### Write cost, delta variant (appends to tail shard; updates to a delta shard + tombstones; then compaction), cpu p'
    : '### Write cost per commit / sync batch, in-place shard patch (PGlite, Postgres WAL), cpu p');
  const wal: Array<Array<string | number>> = [];
  for (const r of by('wal').filter((x) => Boolean(x['delta']) === d || (x['exit'] !== 0 && String(x['args']).includes('--delta 1') === d))) {
    if (r['exit'] !== 0) { wal.push([String(r.args), '', '', '', '', '', '', '', '', '', '', `exit ${r.exit} ${r.error ?? ''}`]); continue; }
    for (const s of r.results) wal.push([r.mib, sh(r.shard), s.scenario, s.notesWritten, mb(s.textBytes), `${s.shardsTouched}/${s.shardsTotal}`, mb(s.indexBytesWritten), mb(s.indexWalBytes), mb(s.dataWalBytes), mb(s.indexRelGrowthBytes), f1(s.indexPatchCpuMs + s.indexSealCpuMs), d ? `${mb(s.deltaPlainBytes)} / ${s.tombstones}` : '']);
  }
  table(['MiB', 'shard', 'scenario', 'notes', 'text MiB', 'shards touched', 'index bytes MiB', 'index WAL MiB', 'data WAL MiB (notes+chunks ct)', 'index rel growth MiB', 'index CPU ms (patch+seal)', 'delta MiB / tombstones'], wal);
}
p('WAL and encrypt runs hold PGlite (a WASM Postgres) in the same process with a 2048 MiB heap flag; their peak RSS is the bench process including the database and is NOT app memory.');
p('');

p('### Encrypt tool: one call = batches until 20 s, 50 MiB workspace (PGlite in-process)');
table(['cpu', 'batch cap', 'shard', 'done', 'calls', 'total s', 'rows', 'plain MiB (notes+chunks)', 'median call: rows', 'median call: MiB', 'median call: batches', 'median call: app ms', 'median call: db ms', 'batch p95 ms', 'batch median ms sel/crypto/upd/rb/verify/index/shardw', 'peak RSS MiB'],
  by('encrypt').map((r) => r['exit'] === 0
    ? [r.cpu, `${r.batchBytes / 1024} KiB`, sh(r.shard), r.done ? 'yes' : 'no', r.calls, f1(r.totalWallMs / 1000), r.notes + r.chunks, mb(r.plainBytes), r.perCallMedian.rows, mb(r.perCallMedian.bytes), r.perCallMedian.batches, f1(r.perCallMedian.appMs), f1(r.perCallMedian.dbMs), f1(r.batchP95TotalMs), Object.values(r.batchMedianMs).join(' / '), r.maxRssMiB]
    : [r.cpu, String(r.args), '', '', '', '', '', '', '', '', '', '', '', '', `exit ${r.exit} ${r.error ?? ''}`, r.maxRssMiB]));

p(`Runs: ${rows.length}; non-zero exits: ${failed.length}${failed.length ? ` (${failed.map((r) => `${r.cpu} ${r.args}: ${r.error ?? r.exit}`).join('; ')})` : ''}.`);
const lim = (c: string) => [...new Set(rows.filter((r) => r['cmd'] === c).map((r) => r['heapLimitMiB']))].join('/');
p(`Node ${rows[0]?.node}. V8 heap limit in children: baseline/index/cache ${lim('index')} MiB (--max-old-space-size=256, the 512 MB model); wal/encrypt ${lim('wal')} MiB (--max-old-space-size=2048, PGlite in process).`);
