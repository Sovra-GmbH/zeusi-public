// C7 KTD6 size gate (docs/plans/2026-11-19-c7-read-path.md "Size gate"): the REAL packed B1 index (src/b1-index.ts,
// lexemes WITH positions, src/b1-lexer.ts) over C0's synthetic corpus (same generator and seeds as
// scripts/bench/c0-measure.ts: ~10 KiB notes, Zipf vocabulary of 60k words, 1% unique identifiers), at --mib N.
// A BENCH ONLY: no database, no key, nothing written. Prints ONE JSON line:
//   build_ms (tokenize + encode + pack), packed_bytes (Packed.bytes), accounted_bytes (x1.25, the cache's charge),
//   heap_delta (heapUsed + arrayBuffers after pack, gc'd, minus before), query p50 / p95 ms (200 two-word queries).
// Run: node --expose-gc scripts/bench/c7-measure.ts --mib 50
import { performance } from 'node:perf_hooks';
import { websearchToTsquery, toTsvector } from '../../src/b1-lexer.ts';
import { encodeVector, Merged, pack } from '../../src/b1-index.ts';
import { chunkMarkdown } from '../../src/chunking.ts';
import { rankChunks } from '../../src/sealed-read.ts';

const argv = process.argv.slice(2);
const mibArg = argv.indexOf('--mib');
const MIB = mibArg >= 0 ? Number(argv[mibArg + 1]) : 1;
const MiB = 1024 * 1024;
const gc = (): void => { const g = (globalThis as { gc?: () => void }).gc; if (g) { g(); g(); } };
const mem = () => { const m = process.memoryUsage(); return m.heapUsed + m.arrayBuffers; };

// ---- C0's corpus generator (scripts/bench/c0-measure.ts:55-122), copied: same seeds, same notes.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const VOCAB_SIZE = 60_000;
const LETTERS = 'abcdefghijklmnopqrstuvwxyz';
const VOCAB: string[] = (() => {
  const rnd = mulberry32(42);
  const seen = new Set<string>();
  const v: string[] = [];
  while (v.length < VOCAB_SIZE) {
    const len = 2 + Math.floor(rnd() * 9) + (v.length > 1000 ? 2 : 0);
    let w = '';
    for (let i = 0; i < len; i++) w += LETTERS[Math.floor(rnd() * 26)];
    if (!seen.has(w)) { seen.add(w); v.push(w); }
  }
  return v;
})();
const ZIPF_CDF: Float64Array = (() => {
  const c = new Float64Array(VOCAB_SIZE);
  let s = 0;
  for (let i = 0; i < VOCAB_SIZE; i++) { s += 1 / (i + 1); c[i] = s; }
  for (let i = 0; i < VOCAB_SIZE; i++) c[i]! /= s;
  return c;
})();
function zipfWord(rnd: () => number): string {
  const u = rnd();
  let lo = 0, hi = VOCAB_SIZE - 1;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (ZIPF_CDF[mid]! < u) lo = mid + 1; else hi = mid; }
  return VOCAB[lo]!;
}
function word(rnd: () => number): string {
  if (rnd() < 0.01) return `${LETTERS[Math.floor(rnd() * 26)]}${Math.floor(rnd() * 2 ** 31).toString(36)}`;
  return zipfWord(rnd);
}
const NOTE_BYTES = 10 * 1024;
function genNote(id: number): { id: number; title: string; body: string } {
  const rnd = mulberry32(id * 7919 + 104729);
  const target = Math.round(NOTE_BYTES * (0.4 + rnd() * 1.2)) - 1100;
  const tw = 4 + Math.floor(rnd() * 5);
  const titleWords: string[] = [];
  for (let i = 0; i < tw; i++) titleWords.push(word(rnd));
  const parts: string[] = [];
  let len = 0;
  while (len < target) {
    const h: string[] = [];
    for (let i = 0; i < 3; i++) h.push(word(rnd));
    const sec: string[] = [`## ${h.join(' ')}`, ''];
    const words = 150 + Math.floor(rnd() * 250);
    let line: string[] = [];
    for (let i = 0; i < words; i++) {
      line.push(word(rnd));
      if (rnd() < 0.07) { sec.push(`${line.join(' ')}.`); line = []; if (rnd() < 0.3) sec.push(''); }
    }
    if (line.length) sec.push(`${line.join(' ')}.`);
    const s = sec.join('\n');
    parts.push(s);
    len += s.length + 2;
  }
  return { id, title: titleWords.join(' '), body: parts.join('\n\n') };
}

// ---- build the index exactly as entriesFromRows does (minus the database and the open)
gc();
const before = mem();
const t0 = performance.now();
const m = new Merged();
const notes = Math.min(5000, Math.round((MIB * MiB) / NOTE_BYTES));
let textBytes = 0;
let chunkId = 0;
for (let id = 1; id <= notes; id++) {
  const n = genNote(id);
  textBytes += Buffer.byteLength(n.body);
  m.notes.set(id, { id, title: n.title, vaultPath: `hq:notes/n${id}.md`, sourceUri: `hq:notes/n${id}.md`, fm: null });
  for (const c of chunkMarkdown(n.body)) {
    chunkId++;
    m.chunks.set(chunkId, { id: chunkId, noteId: id, vec: encodeVector(toTsvector(`${c.headingPath ?? ''} ${c.text}`)) } as never);
  }
}
const packed = pack(m, 1);
const buildMs = performance.now() - t0;
m.chunks.clear();
m.notes.clear();
gc();
const heapDelta = mem() - before;

const rnd = mulberry32(7);
const times: number[] = [];
for (let i = 0; i < 200; i++) {
  const q = `${zipfWord(rnd)} ${zipfWord(rnd)}`;
  const s = performance.now();
  rankChunks(packed, websearchToTsquery(q));
  times.push(performance.now() - s);
}
times.sort((a, b) => a - b);
const pct = (p: number) => Number(times[Math.min(times.length - 1, Math.floor(p * times.length))]!.toFixed(3));
process.stdout.write(`${JSON.stringify({
  mib: MIB, notes, chunks: chunkId, text_bytes: textBytes, build_ms: Math.round(buildMs), packed_bytes: packed.bytes,
  accounted_bytes: Math.ceil(packed.bytes * 1.25), heap_delta_bytes: heapDelta, query_p50_ms: pct(0.5), query_p95_ms: pct(0.95),
})}\n`);
