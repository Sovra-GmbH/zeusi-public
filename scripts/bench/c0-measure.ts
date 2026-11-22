// C0 measure (docs/plans/2026-11-18-c0-measure.md; parent plan docs/plans/2026-11-18-zeusi-workspace-encryption.md
// §3B, §5.2b, §8.2 row C0). A BENCH ONLY. The B1 prototype below (AES-256-GCM, inverted index, shards,
// in-memory cache) lives in this script and is never imported by src/ or the server request path.
//
// Every workspace here is synthetic (seeded PRNG). Nothing reads or writes a real workspace, Neon or Fly.
// The write-cost and encrypt benches use PGlite in a throwaway temp dir.
//
// Subcommands (each prints ONE JSON line on stdout; run each in its own child, see c0-run.sh):
//   baseline                                   RSS after loading the hosted server modules
//   index   --mib N --shard S --deflate 0|1 --out DIR   build + serialize + encrypt; writes shards to DIR
//   cache   --dir DIR --copies K --form packed|map       decrypt K copies (one per grant), query
//   wal     --mib N --shard S --deflate 0|1               WAL + relation growth per commit / sync batch
//   encrypt --mib N --batch-bytes B --shard S             encrypt-tool batches against a 20 s budget
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { getHeapStatistics } from 'node:v8';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { chunkMarkdown } from '../../src/chunking.ts';
import { safeMkdtemp } from '../../test/helpers/safe-tmp.ts';

// ---------------------------------------------------------------- args, util

const argv = process.argv.slice(2);
const cmd = argv[0] ?? '';
function arg(name: string, def?: string): string {
  const i = argv.indexOf(`--${name}`);
  if (i >= 0 && argv[i + 1] !== undefined) return argv[i + 1]!;
  if (def === undefined) throw new Error(`missing --${name}`);
  return def;
}
const num = (name: string, def?: number) => Number(arg(name, def === undefined ? undefined : String(def)));
const MiB = 1024 * 1024;
const gc = (): void => { const g = (globalThis as { gc?: () => void }).gc; if (g) { g(); g(); } };
function mem() {
  const m = process.memoryUsage();
  return { rss: m.rss, heapUsed: m.heapUsed, external: m.external, arrayBuffers: m.arrayBuffers };
}
let peakRss = 0;
const sampler = setInterval(() => { peakRss = Math.max(peakRss, process.memoryUsage().rss); }, 20);
sampler.unref();
const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] ?? 0;
};
const r2 = (x: number) => Math.round(x * 100) / 100;
function out(o: Record<string, unknown>): void {
  peakRss = Math.max(peakRss, process.memoryUsage().rss);
  process.stdout.write(`${JSON.stringify({ cmd, node: process.version, heapLimitMiB: heapLimit(), inProcessPeakRss: peakRss, ...o })}\n`);
}
function heapLimit(): number { return Math.round(getHeapStatistics().heap_size_limit / MiB); }

// ---------------------------------------------------------------- synthetic workspace

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
const ZIPF_S = 1.0;
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
  for (let i = 0; i < VOCAB_SIZE; i++) { s += 1 / Math.pow(i + 1, ZIPF_S); c[i] = s; }
  for (let i = 0; i < VOCAB_SIZE; i++) c[i]! /= s;
  return c;
})();
function zipfWord(rnd: () => number): string {
  const u = rnd();
  let lo = 0, hi = VOCAB_SIZE - 1;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (ZIPF_CDF[mid]! < u) lo = mid + 1; else hi = mid; }
  return VOCAB[lo]!;
}
/** ~1% of words are unique identifiers (ids, numbers, names): they inflate the term dictionary on purpose. */
function word(rnd: () => number): string {
  if (rnd() < 0.01) return `${LETTERS[Math.floor(rnd() * 26)]}${Math.floor(rnd() * 2 ** 31).toString(36)}`;
  return zipfWord(rnd);
}

const NOTE_BYTES = 10 * 1024;
export interface Note { id: number; path: string; title: string; body: string }
/** Deterministic note `id` (version `v` for a sync update). About NOTE_BYTES of markdown with H2 sections. */
function genNote(id: number, v = 1): Note {
  const rnd = mulberry32(id * 7919 + v * 104729);
  const target = Math.round(NOTE_BYTES * (0.4 + rnd() * 1.2)) - 1100;
  const tw = 4 + Math.floor(rnd() * 5);
  const titleWords: string[] = [];
  for (let i = 0; i < tw; i++) titleWords.push(word(rnd));
  const title = titleWords.join(' ');
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
  return { id, path: `hq:notes/2026-11-18-n${id}.md`, title, body: parts.join('\n\n') };
}
function noteCount(mib: number): number { return Math.min(5000, Math.round((mib * MiB) / NOTE_BYTES)); }

const TOKEN_RE = /[\p{L}\p{N}]+/gu;
function tokens(s: string): string[] { return s.toLowerCase().match(TOKEN_RE) ?? []; }

// ---------------------------------------------------------------- B1 shard (prototype)

interface ChunkRef { noteId: number; chunkIdx: number; docLen: number }
/** A shard under construction or patching: chunks plus term -> [chunkLocal, tf, chunkLocal, tf, ...]. */
class ShardBuilder {
  chunks: ChunkRef[] = [];
  post = new Map<string, number[]>();
  addNote(n: Note): number {
    const cs = chunkMarkdown(n.body);
    // the title is indexed as chunk text of chunk 0, like heading_path + text today
    let bytes = 0;
    cs.forEach((c, i) => {
      const toks = tokens(`${i === 0 ? `${n.title} ` : ''}${c.headingPath ?? ''} ${c.text}`);
      bytes += c.text.length;
      const local = this.chunks.length;
      this.chunks.push({ noteId: n.id, chunkIdx: c.index, docLen: toks.length });
      const tf = new Map<string, number>();
      for (const t of toks) tf.set(t, (tf.get(t) ?? 0) + 1);
      for (const [t, f] of tf) {
        let p = this.post.get(t);
        if (!p) { p = []; this.post.set(t, p); }
        p.push(local, f);
      }
    });
    return cs.length;
  }
  /** Drop every chunk of these notes and renumber the rest (a sync update or a delete). */
  removeNotes(ids: Set<number>): void {
    const remap = new Int32Array(this.chunks.length).fill(-1);
    const kept: ChunkRef[] = [];
    this.chunks.forEach((c, i) => { if (!ids.has(c.noteId)) { remap[i] = kept.length; kept.push(c); } });
    this.chunks = kept;
    for (const [t, p] of this.post) {
      const q: number[] = [];
      for (let i = 0; i < p.length; i += 2) { const m = remap[p[i]!]!; if (m >= 0) q.push(m, p[i + 1]!); }
      if (q.length) this.post.set(t, q); else this.post.delete(t);
    }
  }
  noteIds(): Set<number> { return new Set(this.chunks.map((c) => c.noteId)); }
}

function putVarint(b: number[], v: number): void { while (v >= 0x80) { b.push((v & 0x7f) | 0x80); v >>>= 7; } b.push(v); }
/** Binary shard: header | chunk table | termOff | postOff | termBytes | postBytes. Terms sorted by bytes. */
function serialize(sb: ShardBuilder): Buffer {
  const terms = [...sb.post.keys()].map((t) => Buffer.from(t, 'utf8')).sort(Buffer.compare);
  const nT = terms.length, nC = sb.chunks.length;
  const termBytes = Buffer.concat(terms);
  const post: number[] = [];
  const postOff = new Uint32Array(nT + 1);
  const termOff = new Uint32Array(nT + 1);
  let to = 0;
  terms.forEach((tb, i) => {
    termOff[i] = to; to += tb.length;
    postOff[i] = post.length;
    const p = sb.post.get(tb.toString('utf8'))!;
    putVarint(post, p.length / 2);
    let prev = 0;
    for (let j = 0; j < p.length; j += 2) { putVarint(post, p[j]! - prev); prev = p[j]!; putVarint(post, p[j + 1]!); }
  });
  termOff[nT] = to; postOff[nT] = post.length;
  const head = Buffer.alloc(24);
  head.write('ZB1S', 0); head.writeUInt32LE(1, 4); head.writeUInt32LE(nC, 8); head.writeUInt32LE(nT, 12);
  head.writeUInt32LE(termBytes.length, 16); head.writeUInt32LE(post.length, 20);
  const ct = Buffer.alloc(nC * 12);
  sb.chunks.forEach((c, i) => { ct.writeUInt32LE(c.noteId, i * 12); ct.writeUInt32LE(c.chunkIdx, i * 12 + 4); ct.writeUInt32LE(c.docLen, i * 12 + 8); });
  return Buffer.concat([head, ct, Buffer.from(termOff.buffer), Buffer.from(postOff.buffer), termBytes, Buffer.from(post)]);
}
/** Back to a builder (the in-memory patch path of a write: decrypted shard -> patch -> re-serialize). */
function deserialize(buf: Buffer): ShardBuilder {
  const v = view(buf);
  const sb = new ShardBuilder();
  for (let i = 0; i < v.nC; i++) sb.chunks.push({ noteId: buf.readUInt32LE(v.cOff + i * 12), chunkIdx: buf.readUInt32LE(v.cOff + i * 12 + 4), docLen: buf.readUInt32LE(v.cOff + i * 12 + 8) });
  for (let i = 0; i < v.nT; i++) sb.post.set(buf.toString('utf8', v.tb + v.termOff[i]!, v.tb + v.termOff[i + 1]!), Array.from(decodePostings(buf, v.pb + v.postOff[i]!)));
  return sb;
}
interface View { nC: number; nT: number; cOff: number; termOff: Uint32Array; postOff: Uint32Array; tb: number; pb: number }
function view(buf: Buffer): View {
  if (buf.toString('latin1', 0, 4) !== 'ZB1S') throw new Error('bad shard');
  const nC = buf.readUInt32LE(8), nT = buf.readUInt32LE(12), tLen = buf.readUInt32LE(16);
  const cOff = 24, oOff = cOff + nC * 12;
  // copy the offset tables to aligned arrays
  const termOff = new Uint32Array(nT + 1), postOff = new Uint32Array(nT + 1);
  for (let i = 0; i <= nT; i++) { termOff[i] = buf.readUInt32LE(oOff + i * 4); postOff[i] = buf.readUInt32LE(oOff + (nT + 1) * 4 + i * 4); }
  const tb = oOff + 2 * (nT + 1) * 4;
  return { nC, nT, cOff, termOff, postOff, tb, pb: tb + tLen };
}
function decodePostings(buf: Buffer, at: number): Uint32Array {
  let p = at;
  const rd = () => { let x = 0, s = 0, b: number; do { b = buf[p++]!; x |= (b & 0x7f) << s; s += 7; } while (b & 0x80); return x >>> 0; };
  const n = rd();
  const o = new Uint32Array(n * 2);
  let prev = 0;
  for (let i = 0; i < n; i++) { prev += rd(); o[i * 2] = prev; o[i * 2 + 1] = rd(); }
  return o;
}

// ---------------------------------------------------------------- AES-256-GCM envelope (bench copy)

function aad(parts: string[]): Buffer {
  return Buffer.concat(parts.map((p) => { const b = Buffer.from(p, 'utf8'); const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]); }));
}
function seal(key: Buffer, plain: Buffer, ad: Buffer): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(ad);
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]);
}
function open(key: Buffer, box: Buffer, ad: Buffer): Buffer {
  const d = createDecipheriv('aes-256-gcm', key, box.subarray(0, 12));
  d.setAAD(ad);
  d.setAuthTag(box.subarray(12, 28));
  return Buffer.concat([d.update(box.subarray(28)), d.final()]);
}
const TENANT = 'zt_benchbenchbenchbenchbenchb';
const shardAad = (shard: number) => aad(['zeusi-b1-v1', TENANT, 'shard', String(shard), 'kv1']);
function sealShard(key: Buffer, shard: number, plain: Buffer, deflate: boolean): Buffer {
  return seal(key, deflate ? deflateRawSync(plain, { level: 1 }) : plain, shardAad(shard));
}
function openShard(key: Buffer, shard: number, box: Buffer, deflate: boolean): Buffer {
  const p = open(key, box, shardAad(shard));
  return deflate ? inflateRawSync(p) : p;
}

// ---------------------------------------------------------------- cache forms and query

interface Shard { nC: number; docLen: Uint32Array; noteId: Uint32Array; lookup(term: string): Uint32Array | null }
function packedShard(buf: Buffer): Shard {
  const v = view(buf);
  const docLen = new Uint32Array(v.nC), noteId = new Uint32Array(v.nC);
  for (let i = 0; i < v.nC; i++) { noteId[i] = buf.readUInt32LE(v.cOff + i * 12); docLen[i] = buf.readUInt32LE(v.cOff + i * 12 + 8); }
  return {
    nC: v.nC, docLen, noteId,
    lookup(term) {
      const t = Buffer.from(term, 'utf8');
      let lo = 0, hi = v.nT - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const c = buf.compare(t, 0, t.length, v.tb + v.termOff[mid]!, v.tb + v.termOff[mid + 1]!);
        if (c === 0) return decodePostings(buf, v.pb + v.postOff[mid]!);
        if (c < 0) lo = mid + 1; else hi = mid - 1;
      }
      return null;
    },
  };
}
function mapShard(buf: Buffer): Shard {
  const v = view(buf);
  const docLen = new Uint32Array(v.nC), noteId = new Uint32Array(v.nC);
  for (let i = 0; i < v.nC; i++) { noteId[i] = buf.readUInt32LE(v.cOff + i * 12); docLen[i] = buf.readUInt32LE(v.cOff + i * 12 + 8); }
  const m = new Map<string, Uint32Array>();
  for (let i = 0; i < v.nT; i++) m.set(buf.toString('utf8', v.tb + v.termOff[i]!, v.tb + v.termOff[i + 1]!), decodePostings(buf, v.pb + v.postOff[i]!));
  return { nC: v.nC, docLen, noteId, lookup: (t) => m.get(t) ?? null };
}
/** BM25 over every chunk of every shard, OR of the query terms, top k. */
function query(shards: Shard[], terms: string[], k = 20): Array<{ shard: number; chunk: number; score: number }> {
  let N = 0, totalLen = 0;
  for (const s of shards) { N += s.nC; for (let i = 0; i < s.nC; i++) totalLen += s.docLen[i]!; }
  const avgdl = totalLen / Math.max(1, N);
  const k1 = 1.2, b = 0.75;
  const lists = terms.map((t) => shards.map((s) => s.lookup(t)));
  const scores = new Map<number, number>();
  lists.forEach((perShard) => {
    let df = 0;
    for (const p of perShard) if (p) df += p.length / 2;
    if (!df) return;
    const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));
    perShard.forEach((p, si) => {
      if (!p) return;
      const s = shards[si]!;
      for (let i = 0; i < p.length; i += 2) {
        const c = p[i]!, tf = p[i + 1]!;
        const sc = idf * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * s.docLen[c]! / avgdl));
        const key = si * 1_000_000 + c;
        scores.set(key, (scores.get(key) ?? 0) + sc);
      }
    });
  });
  const top: Array<{ shard: number; chunk: number; score: number }> = [];
  for (const [key, score] of scores) {
    if (top.length < k || score > top[top.length - 1]!.score) {
      top.push({ shard: Math.floor(key / 1_000_000), chunk: key % 1_000_000, score });
      top.sort((a, b2) => b2.score - a.score);
      if (top.length > k) top.pop();
    }
  }
  return top;
}
function queries(n: number): string[][] {
  const rnd = mulberry32(777);
  const q: string[][] = [];
  for (let i = 0; i < n; i++) {
    const a = VOCAB[100 + Math.floor(rnd() * 4900)]!, b = VOCAB[100 + Math.floor(rnd() * 4900)]!, c = VOCAB[5000 + Math.floor(rnd() * 55000)]!;
    q.push([a, b, c]);
  }
  return q;
}

// ---------------------------------------------------------------- build helper

interface Built { shards: Buffer[]; plainBytes: number; textBytes: number; chunks: number; notes: number; terms: number; tokenizeMs: number; serializeMs: number; sealMs: number }
function buildAll(nNotes: number, shardSize: number, key: Buffer, deflate: boolean): Built {
  const per = shardSize > 0 ? shardSize : nNotes;
  const shards: Buffer[] = [];
  let plainBytes = 0, textBytes = 0, chunks = 0, terms = 0, tokenizeMs = 0, serializeMs = 0, sealMs = 0;
  for (let s = 0; s * per < nNotes; s++) {
    const sb = new ShardBuilder();
    for (let id = s * per; id < Math.min(nNotes, (s + 1) * per); id++) {
      const n = genNote(id);
      textBytes += Buffer.byteLength(n.body) + Buffer.byteLength(n.title);
      const t0 = performance.now();
      chunks += sb.addNote(n);
      tokenizeMs += performance.now() - t0;
    }
    terms += sb.post.size;
    const t1 = performance.now();
    const plain = serialize(sb);
    const t2 = performance.now();
    plainBytes += plain.length;
    shards.push(sealShard(key, s, plain, deflate));
    const t3 = performance.now();
    serializeMs += t2 - t1; sealMs += t3 - t2;
  }
  return { shards, plainBytes, textBytes, chunks, notes: nNotes, terms, tokenizeMs, serializeMs, sealMs };
}

// ---------------------------------------------------------------- subcommands

async function cmdBaseline(): Promise<void> {
  gc();
  const before = mem();
  await import('../../src/mcp-hosted.ts');
  await import('../../src/mcp-server.ts');
  await import('../../src/workspace-write.ts');
  await import('../../src/tenants.ts');
  await import('pg');
  gc();
  out({ before, after: mem() });
}

function cmdIndex(): void {
  const mib = num('mib'), shard = num('shard'), deflate = num('deflate', 0) === 1, dir = arg('out');
  const key = randomBytes(32);
  const nNotes = noteCount(mib);
  gc();
  const m0 = mem();
  const t0 = performance.now();
  const b = buildAll(nNotes, shard, key, deflate);
  const buildWallMs = performance.now() - t0;
  const m1 = mem();
  mkdirSync(dir, { recursive: true });
  b.shards.forEach((s, i) => writeFileSync(join(dir, `s${String(i).padStart(5, '0')}.bin`), s));
  writeFileSync(join(dir, 'meta.json'), JSON.stringify({ key: key.toString('base64'), deflate, mib, shard, notes: nNotes }));
  const encBytes = b.shards.reduce((a, s) => a + s.length, 0);
  out({
    mib, shard, deflate, notes: b.notes, chunks: b.chunks, textBytes: b.textBytes, shards: b.shards.length,
    termsSumOverShards: b.terms, indexPlainBytes: b.plainBytes, indexEncBytes: encBytes,
    largestShardEncBytes: Math.max(...b.shards.map((s) => s.length)),
    buildWallMs: r2(buildWallMs), tokenizeMs: r2(b.tokenizeMs), serializeMs: r2(b.serializeMs), sealMs: r2(b.sealMs),
    memBefore: m0, memAfterBuild: m1,
  });
}

function cmdCache(): void {
  const dir = arg('dir'), copies = num('copies'), form = arg('form', 'packed');
  const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')) as { key: string; deflate: boolean; mib: number; shard: number; notes: number };
  const key = Buffer.from(meta.key, 'base64');
  const files = readdirSync(dir).filter((f) => f.endsWith('.bin')).sort();
  gc();
  const m0 = mem();
  const loads: number[] = [];
  const cache: Shard[][] = [];
  const perCopy: Array<ReturnType<typeof mem>> = [];
  let firstQueryMs = 0;
  for (let c = 0; c < copies; c++) {
    // the ciphertext comes from the DB per load (one row per shard); it is garbage after decrypt
    const t0 = performance.now();
    const shards: Shard[] = files.map((f, i) => {
      const plain = openShard(key, i, readFileSync(join(dir, f)), meta.deflate);
      return form === 'map' ? mapShard(plain) : packedShard(plain);
    });
    const tq = performance.now();
    query(shards, queries(1)[0]!);
    const t1 = performance.now();
    loads.push(tq - t0);
    if (c === 0) firstQueryMs = t1 - tq;
    cache.push(shards);
    gc();
    perCopy.push(mem());
  }
  const qs = queries(200);
  const times: number[] = [];
  let hits = 0;
  for (const q of qs) { const t = performance.now(); hits += query(cache[0]!, q).length; times.push(performance.now() - t); }
  gc();
  const m1 = mem();
  out({
    mib: meta.mib, shard: meta.shard, deflate: meta.deflate, notes: meta.notes, shards: files.length, form, copies,
    loadMsPerCopy: loads.map(r2), coldFirstQueryMs: r2(firstQueryMs),
    warmQueryMs: { p50: r2(pct(times, 50)), p95: r2(pct(times, 95)), max: r2(Math.max(...times)) }, avgHits: r2(hits / qs.length),
    memBefore: m0, memPerCopy: perCopy, memAfter: m1,
    rssDeltaPerCopyMiB: perCopy.map((m, i) => r2((m.rss - (i ? perCopy[i - 1]!.rss : m0.rss)) / MiB)),
    heapPlusAbDeltaPerCopyMiB: perCopy.map((m, i) => { const p = i ? perCopy[i - 1]! : m0; return r2((m.heapUsed + m.arrayBuffers - p.heapUsed - p.arrayBuffers) / MiB); }),
    keepAlive: cache.length,
  });
}

async function pglite(dir: string) {
  const { PGlite } = await import('@electric-sql/pglite');
  return PGlite.create(dir);
}
type PG = Awaited<ReturnType<typeof pglite>>;
async function lsn(db: PG): Promise<string> { return (await db.query<{ l: string }>('SELECT pg_current_wal_insert_lsn()::text AS l')).rows[0]!.l; }
async function walSince(db: PG, from: string): Promise<number> {
  return Number((await db.query<{ d: string }>(`SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(), $1::pg_lsn)::text AS d`, [from])).rows[0]!.d);
}
async function relSize(db: PG, rel: string): Promise<number> {
  return Number((await db.query<{ s: string }>(`SELECT pg_total_relation_size($1)::text AS s`, [rel])).rows[0]!.s);
}

/** Write cost: B1 shard rows + manifest vs the note/chunk ciphertext rows the same write stores anyway. */
async function cmdWal(): Promise<void> {
  const mib = num('mib'), shard = num('shard'), deflate = num('deflate', 0) === 1;
  // --delta 1: new notes still go to the tail shard; an UPDATE of an existing note goes to one small delta
  // shard (patched in place) and the old note id goes on a tombstone list in the manifest; a later
  // compaction folds the delta into the base shards (scenario compact_delta).
  const delta = num('delta', 0) === 1;
  const DELTA_ID = 1_000_000;
  let deltaPlain: Buffer | null = null;
  const tomb = new Set<number>();
  const key = randomBytes(32);
  const nNotes = noteCount(mib);
  const per = shard > 0 ? shard : Number.MAX_SAFE_INTEGER;
  const tmp = safeMkdtemp(join(tmpdir(), 'zeusi-c0-wal-'));
  const db = await pglite(join(tmp, 'pg'));
  try {
    await db.exec(`
      CREATE TABLE b1_shards (shard int PRIMARY KEY, key_version int NOT NULL, ct bytea NOT NULL);
      ALTER TABLE b1_shards ALTER COLUMN ct SET STORAGE EXTERNAL;
      CREATE TABLE b1_manifest (id int PRIMARY KEY, ct bytea NOT NULL);
      ALTER TABLE b1_manifest ALTER COLUMN ct SET STORAGE EXTERNAL;
      CREATE TABLE notes_ct (id bigint PRIMARY KEY, path_hmac bytea NOT NULL, title_ct bytea NOT NULL, body_ct bytea NOT NULL, uri_ct bytea NOT NULL);
      CREATE TABLE chunks_ct (id bigserial PRIMARY KEY, note_id bigint NOT NULL, idx int NOT NULL, text_ct bytea NOT NULL);`);
    // The decrypted cache holds each shard in packed (serialized) form, as the cache bench does. A write
    // deserializes only the shards it touches, patches them, re-serializes and seals them.
    const plains: Buffer[] = [];
    const nChunks = (b: Buffer | undefined) => (b ? b.readUInt32LE(8) : 0);
    const shardOf = (id: number) => (shard > 0 ? Math.floor(id / per) : 0);
    const writeNotes = async (notes: Note[]) => {
      const ids: number[] = [], hm: Buffer[] = [], ti: Buffer[] = [], bo: Buffer[] = [], ur: Buffer[] = [];
      const cn: number[] = [], ci: number[] = [], ct: Buffer[] = [];
      for (const n of notes) {
        ids.push(n.id); hm.push(createHmac('sha256', key).update(n.path).digest());
        const a = (col: string) => aad(['zeusi-v1', TENANT, 'notes', col, String(n.id), 'kv1']);
        ti.push(seal(key, Buffer.from(n.title), a('title'))); bo.push(seal(key, Buffer.from(n.body), a('body'))); ur.push(seal(key, Buffer.from(n.path), a('source_uri')));
        for (const c of chunkMarkdown(n.body)) { cn.push(n.id); ci.push(c.index); ct.push(seal(key, Buffer.from(c.text), aad(['zeusi-v1', TENANT, 'chunks', 'text', `${n.id}:${c.index}`, 'kv1']))); }
      }
      await db.query(`DELETE FROM chunks_ct WHERE note_id = ANY($1::bigint[])`, [ids]);
      await db.query(`INSERT INTO notes_ct SELECT * FROM unnest($1::bigint[], $2::bytea[], $3::bytea[], $4::bytea[], $5::bytea[])
                      ON CONFLICT (id) DO UPDATE SET path_hmac = EXCLUDED.path_hmac, title_ct = EXCLUDED.title_ct, body_ct = EXCLUDED.body_ct, uri_ct = EXCLUDED.uri_ct`, [ids, hm, ti, bo, ur]);
      await db.query(`INSERT INTO chunks_ct (note_id, idx, text_ct) SELECT * FROM unnest($1::bigint[], $2::int[], $3::bytea[])`, [cn, ci, ct]);
    };
    const writeShards = async (touched: Set<number>) => {
      let bytes = 0;
      const t0 = performance.now();
      const rows: Array<[number, Buffer]> = [];
      for (const s of touched) { const box = sealShard(key, s, s === DELTA_ID ? deltaPlain! : plains[s]!, deflate); rows.push([s, box]); bytes += box.length; }
      const manifest = seal(key, Buffer.from(JSON.stringify({ v: 1, shards: plains.map((b, i) => ({ i, chunks: nChunks(b) })), delta: nChunks(deltaPlain ?? undefined), tombstones: [...tomb] })), aad(['zeusi-b1-v1', TENANT, 'manifest', 'kv1']));
      bytes += manifest.length;
      const cpuMs = performance.now() - t0;
      await db.query(`SELECT pg_advisory_xact_lock(hashtext('workspace-index:' || $1))`, [TENANT]);
      await db.query(`INSERT INTO b1_shards SELECT s, 1, c FROM unnest($1::int[], $2::bytea[]) AS u(s, c) ON CONFLICT (shard) DO UPDATE SET ct = EXCLUDED.ct`, [rows.map((r) => r[0]), rows.map((r) => r[1])]);
      await db.query(`INSERT INTO b1_manifest VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET ct = EXCLUDED.ct`, [manifest]);
      return { bytes, cpuMs };
    };
    // initial load in chunks of 250 notes (not measured)
    let open: { s: number; sb: ShardBuilder } | null = null;
    for (let i = 0; i < nNotes; i += 250) {
      const ns: Note[] = [];
      for (let id = i; id < Math.min(nNotes, i + 250); id++) {
        const n = genNote(id); ns.push(n);
        const s = shardOf(id);
        if (!open || open.s !== s) { if (open) plains[open.s] = serialize(open.sb); open = { s, sb: new ShardBuilder() }; }
        open.sb.addNote(n);
      }
      await db.exec('BEGIN'); await writeNotes(ns); await db.exec('COMMIT');
    }
    if (open) plains[open.s] = serialize(open.sb);
    open = null;
    await db.exec('BEGIN'); await writeShards(new Set(plains.map((_, i) => i))); await db.exec('COMMIT');
    await db.exec('VACUUM'); await db.exec('CHECKPOINT');
    let nextId = nNotes;
    const rnd = mulberry32(99);
    const scenarios: Array<{ name: string; make: () => { add: Note[]; upd: Note[] } }> = [
      { name: 'sync_update_10', make: () => ({ add: [], upd: Array.from({ length: 10 }, () => genNote(Math.floor(rnd() * nNotes), 2)) }) },
      { name: 'sync_update_100', make: () => ({ add: [], upd: Array.from({ length: 100 }, () => genNote(Math.floor(rnd() * nNotes), 3)) }) },
      { name: 'commit_append_20', make: () => ({ add: Array.from({ length: 20 }, () => genNote(nextId++)), upd: [] }) },
      { name: 'commit_append_1000', make: () => ({ add: Array.from({ length: 1000 }, () => genNote(nextId++)), upd: [] }) },
      ...(delta ? [{ name: 'compact_delta', make: () => ({ add: [] as Note[], upd: [] as Note[] }) }] : []),
    ];
    const results: Record<string, unknown>[] = [];
    for (const sc of scenarios) {
      const { add, upd } = sc.make();
      const all = [...upd, ...add];
      const uniq = new Map(all.map((n) => [n.id, n]));
      const textBytes = [...uniq.values()].reduce((a, n) => a + Buffer.byteLength(n.body) + Buffer.byteLength(n.title), 0);
      const size0 = { shards: await relSize(db, 'b1_shards'), manifest: await relSize(db, 'b1_manifest'), notes: await relSize(db, 'notes_ct') + await relSize(db, 'chunks_ct') };
      const tw = performance.now();
      await db.exec('BEGIN');
      const l0 = await lsn(db);
      await writeNotes([...uniq.values()]);
      const dataWal = await walSince(db, l0);
      // index patch (in memory, from the decrypted cache) then seal and write touched shards + manifest
      const tp = performance.now();
      const touched = new Set<number>();
      const bySh = new Map<number, Note[]>();
      const isUpdate = (id: number) => id < nNotes;
      if (sc.name === 'compact_delta' && deltaPlain) {
        // fold the delta into the base shards: drop tombstoned chunks there, add the delta's chunks
        const d = deserialize(deltaPlain);
        const dIds = d.noteIds();
        const byBase = new Map<number, Set<number>>();
        for (const id of tomb) { const s = shardOf(id); (byBase.get(s) ?? byBase.set(s, new Set()).get(s)!).add(id); }
        for (const [s, ids] of byBase) {
          const b = deserialize(plains[s]!);
          b.removeNotes(ids);
          // re-add the current version of these notes from the delta's postings
          const keep = new Set([...ids].filter((id) => dIds.has(id)));
          const other = new Set([...dIds].filter((id) => !keep.has(id)));
          const part = deserialize(deltaPlain); part.removeNotes(other);
          const base = b.chunks.length;
          b.chunks.push(...part.chunks);
          for (const [t, p] of part.post) { let q = b.post.get(t); if (!q) { q = []; b.post.set(t, q); } for (let i = 0; i < p.length; i += 2) q.push(p[i]! + base, p[i + 1]!); }
          plains[s] = serialize(b);
          touched.add(s);
        }
        tomb.clear();
        deltaPlain = serialize(new ShardBuilder());
        touched.add(DELTA_ID);
      }
      for (const n of uniq.values()) {
        if (delta && isUpdate(n.id)) { tomb.add(n.id); touched.add(DELTA_ID); continue; }
        const s = shardOf(n.id); touched.add(s); (bySh.get(s) ?? bySh.set(s, []).get(s)!).push(n);
      }
      if (delta) {
        const ups = [...uniq.values()].filter((n) => isUpdate(n.id));
        if (ups.length) {
          const d = deltaPlain ? deserialize(deltaPlain) : new ShardBuilder();
          d.removeNotes(new Set(ups.map((n) => n.id)));
          for (const n of ups) d.addNote(n);
          deltaPlain = serialize(d);
        }
      }
      for (const [s, ns] of bySh) {
        const b = plains[s] ? deserialize(plains[s]) : new ShardBuilder();
        b.removeNotes(new Set(ns.map((n) => n.id)));
        for (const n of ns) b.addNote(n);
        plains[s] = serialize(b);
      }
      const patchMs = performance.now() - tp;
      const l1 = await lsn(db);
      const ws = await writeShards(touched);
      const indexWal = await walSince(db, l1);
      await db.exec('COMMIT');
      const wallMs = performance.now() - tw;
      const size1 = { shards: await relSize(db, 'b1_shards'), manifest: await relSize(db, 'b1_manifest'), notes: await relSize(db, 'notes_ct') + await relSize(db, 'chunks_ct') };
      results.push({
        scenario: sc.name, delta, deltaPlainBytes: deltaPlain ? deltaPlain.length : 0, tombstones: tomb.size, notesWritten: uniq.size, textBytes, shardsTouched: touched.size, shardsTotal: plains.length,
        indexBytesWritten: ws.bytes, indexWalBytes: indexWal, dataWalBytes: dataWal,
        indexRelGrowthBytes: size1.shards + size1.manifest - size0.shards - size0.manifest, dataRelGrowthBytes: size1.notes - size0.notes,
        indexPatchCpuMs: r2(patchMs), indexSealCpuMs: r2(ws.cpuMs), wallMs: r2(wallMs),
      });
      await db.exec('VACUUM');
    }
    out({ mib, shard, deflate, delta, notes: nNotes, results });
  } finally {
    await db.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * The encrypt tool (§5.2b, faithful bench): each batch is one transaction with the three advisory locks,
 * byte-capped selection, AES-256-GCM of notes.title/body/source_uri and chunks.text with length-prefixed
 * AAD, HMAC of vault_path, one UPDATE per table that writes ct and NULLs the plain text, read-back,
 * decrypt and compare, then the B1 shards the batch touched and the manifest, and the cursor row.
 * Calls run batches back to back until 20 s are spent.
 */
async function cmdEncrypt(): Promise<void> {
  const mib = num('mib'), batchBytes = num('batch-bytes'), shard = num('shard', 250), maxRows = num('max-rows', 2000);
  const budgetMs = num('budget-ms', 20_000), maxCalls = num('max-calls', 1000);
  const key = randomBytes(32);
  const nNotes = noteCount(mib);
  const tmp = safeMkdtemp(join(tmpdir(), 'zeusi-c0-enc-'));
  const db = await pglite(join(tmp, 'pg'));
  try {
    await db.exec(`
      CREATE TABLE notes (id bigint PRIMARY KEY, vault_path text, title text, body text, source_uri text,
        vault_path_hmac bytea, title_ct bytea, body_ct bytea, source_uri_ct bytea);
      CREATE TABLE chunks (id bigserial PRIMARY KEY, note_id bigint NOT NULL, chunk_index int NOT NULL, heading_path text, text text,
        heading_path_ct bytea, text_ct bytea);
      CREATE INDEX ON chunks (note_id);
      CREATE TABLE enc_progress (id int PRIMARY KEY, cursor bigint NOT NULL, rows bigint NOT NULL);
      INSERT INTO enc_progress VALUES (1, -1, 0);
      CREATE TABLE b1_shards (shard int PRIMARY KEY, key_version int NOT NULL, ct bytea NOT NULL);
      ALTER TABLE b1_shards ALTER COLUMN ct SET STORAGE EXTERNAL;
      CREATE TABLE b1_manifest (id int PRIMARY KEY, ct bytea NOT NULL);`);
    for (let i = 0; i < nNotes; i += 250) {
      const ns: Note[] = [];
      for (let id = i; id < Math.min(nNotes, i + 250); id++) ns.push(genNote(id));
      await db.query(`INSERT INTO notes (id, vault_path, title, body, source_uri) SELECT * FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[])`,
        [ns.map((n) => n.id), ns.map((n) => n.path), ns.map((n) => n.title), ns.map((n) => n.body), ns.map((n) => n.path)]);
      const cn: number[] = [], ci: number[] = [], ch: (string | null)[] = [], ct: string[] = [];
      for (const n of ns) for (const c of chunkMarkdown(n.body)) { cn.push(n.id); ci.push(c.index); ch.push(c.headingPath); ct.push(c.text); }
      await db.query(`INSERT INTO chunks (note_id, chunk_index, heading_path, text) SELECT * FROM unnest($1::bigint[], $2::int[], $3::text[], $4::text[])`, [cn, ci, ch, ct]);
    }
    const totals = (await db.query<{ n: number; c: number; b: string }>(`SELECT (SELECT count(*)::int FROM notes) n, (SELECT count(*)::int FROM chunks) c,
      ((SELECT sum(octet_length(title) + octet_length(body) + octet_length(source_uri)) FROM notes) + (SELECT sum(octet_length(text) + coalesce(octet_length(heading_path),0)) FROM chunks))::text b`)).rows[0]!;
    // packed shards, plus at most the shards the current batch touches as builders (notes go in id order)
    const plains: Buffer[] = [];
    const calls: Array<Record<string, number>> = [];
    let cursor = -1, done = false;
    const batchStats: Array<Record<string, number>> = [];
    const cpu0 = process.cpuUsage();
    const wall0 = performance.now();
    while (!done && calls.length < maxCalls) {
      const c0 = performance.now();
      const cpuC = process.cpuUsage();
      let rows = 0, bytes = 0, batches = 0, appMs = 0, dbMs = 0;
      while (performance.now() - c0 < budgetMs) {
        const t = { sel: 0, crypto: 0, upd: 0, rb: 0, verify: 0, index: 0, shardw: 0 };
        let m = performance.now();
        const lap = (k: keyof typeof t) => { const n = performance.now(); t[k] += n - m; m = n; };
        await db.exec('BEGIN');
        for (const k of ['workspace-import:', 'workspace-sync:', 'workspace-index:']) await db.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [k + TENANT]);
        // byte-first selection: notes in id order with their chunks, cumulative bytes <= batchBytes, rows <= maxRows
        const pick = await db.query<{ id: number }>(`
          WITH w AS (SELECT n.id, octet_length(n.title) + octet_length(n.body) + octet_length(n.source_uri)
                       + coalesce((SELECT sum(octet_length(c.text)) FROM chunks c WHERE c.note_id = n.id), 0) AS b,
                       1 + (SELECT count(*) FROM chunks c WHERE c.note_id = n.id) AS r
                     FROM notes n WHERE n.id > $1 ORDER BY n.id LIMIT 2000),
               s AS (SELECT id, sum(b) OVER (ORDER BY id) cb, sum(r) OVER (ORDER BY id) cr, row_number() OVER (ORDER BY id) rn FROM w)
          SELECT id::int FROM s WHERE (cb <= $2 AND cr <= $3) OR rn = 1 ORDER BY id`, [cursor, batchBytes, maxRows]);
        if (!pick.rows.length) { await db.exec('ROLLBACK'); done = true; break; }
        const ids = pick.rows.map((r) => r.id);
        const ns = (await db.query<{ id: number; vault_path: string; title: string; body: string; source_uri: string }>(`SELECT id::int, vault_path, title, body, source_uri FROM notes WHERE id = ANY($1::bigint[]) ORDER BY id`, [ids])).rows;
        const cs = (await db.query<{ id: number; note_id: number; chunk_index: number; heading_path: string | null; text: string }>(`SELECT id::int, note_id::int, chunk_index, heading_path, text FROM chunks WHERE note_id = ANY($1::bigint[]) ORDER BY id`, [ids])).rows;
        lap('sel');
        const nA = (id: number, col: string) => aad(['zeusi-v1', TENANT, 'notes', col, String(id), 'kv1']);
        const cA = (id: number, col: string) => aad(['zeusi-v1', TENANT, 'chunks', col, String(id), 'kv1']);
        const nh = ns.map((n) => createHmac('sha256', key).update(n.vault_path).digest());
        const nt = ns.map((n) => seal(key, Buffer.from(n.title), nA(n.id, 'title')));
        const nb = ns.map((n) => seal(key, Buffer.from(n.body), nA(n.id, 'body')));
        const nu = ns.map((n) => seal(key, Buffer.from(n.source_uri), nA(n.id, 'source_uri')));
        const ct = cs.map((c) => seal(key, Buffer.from(c.text), cA(c.id, 'text')));
        const chp = cs.map((c) => (c.heading_path === null ? null : seal(key, Buffer.from(c.heading_path), cA(c.id, 'heading_path'))));
        lap('crypto');
        await db.query(`UPDATE notes SET vault_path_hmac = u.h, title_ct = u.t, body_ct = u.b, source_uri_ct = u.s, vault_path = NULL, title = NULL, body = NULL, source_uri = NULL
                        FROM unnest($1::bigint[], $2::bytea[], $3::bytea[], $4::bytea[], $5::bytea[]) AS u(id, h, t, b, s) WHERE notes.id = u.id`, [ns.map((n) => n.id), nh, nt, nb, nu]);
        await db.query(`UPDATE chunks SET text_ct = u.t, heading_path_ct = u.h, text = NULL, heading_path = NULL
                        FROM unnest($1::bigint[], $2::bytea[], $3::bytea[]) AS u(id, t, h) WHERE chunks.id = u.id`, [cs.map((c) => c.id), ct, chp]);
        lap('upd');
        const rbN = (await db.query<{ id: number; title_ct: Uint8Array; body_ct: Uint8Array; source_uri_ct: Uint8Array }>(`SELECT id::int, title_ct, body_ct, source_uri_ct FROM notes WHERE id = ANY($1::bigint[]) ORDER BY id`, [ids])).rows;
        const rbC = (await db.query<{ id: number; text_ct: Uint8Array }>(`SELECT id::int, text_ct FROM chunks WHERE note_id = ANY($1::bigint[]) ORDER BY id`, [ids])).rows;
        lap('rb');
        rbN.forEach((r, i) => {
          const n = ns[i]!;
          if (r.id !== n.id || open(key, Buffer.from(r.body_ct), nA(n.id, 'body')).toString() !== n.body
            || open(key, Buffer.from(r.title_ct), nA(n.id, 'title')).toString() !== n.title
            || open(key, Buffer.from(r.source_uri_ct), nA(n.id, 'source_uri')).toString() !== n.source_uri) throw new Error('read-back mismatch');
        });
        rbC.forEach((r, i) => { if (open(key, Buffer.from(r.text_ct), cA(r.id, 'text')).toString() !== cs[i]!.text) throw new Error('chunk read-back mismatch'); });
        lap('verify');
        const work = new Map<number, ShardBuilder>();
        for (const n of ns) {
          const s = shard > 0 ? Math.floor(n.id / shard) : 0;
          let b = work.get(s);
          if (!b) { b = plains[s] ? deserialize(plains[s]) : new ShardBuilder(); work.set(s, b); }
          b.addNote({ id: n.id, path: n.vault_path, title: n.title, body: n.body });
        }
        for (const [s, b] of work) plains[s] = serialize(b);
        const touched = new Set(work.keys());
        work.clear();
        const boxes = [...touched].map((s) => sealShard(key, s, plains[s]!, false));
        const manifest = seal(key, Buffer.from(JSON.stringify({ v: 1, shards: plains.length })), aad(['zeusi-b1-v1', TENANT, 'manifest', 'kv1']));
        lap('index');
        await db.query(`INSERT INTO b1_shards SELECT s, 1, c FROM unnest($1::int[], $2::bytea[]) AS u(s, c) ON CONFLICT (shard) DO UPDATE SET ct = EXCLUDED.ct`, [[...touched], boxes]);
        await db.query(`INSERT INTO b1_manifest VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET ct = EXCLUDED.ct`, [manifest]);
        cursor = ids[ids.length - 1]!;
        await db.query(`UPDATE enc_progress SET cursor = $1, rows = rows + $2 WHERE id = 1`, [cursor, ns.length + cs.length]);
        await db.exec('COMMIT');
        lap('shardw');
        const bBytes = ns.reduce((a, n) => a + Buffer.byteLength(n.title) + Buffer.byteLength(n.body) + Buffer.byteLength(n.source_uri), 0) + cs.reduce((a, c) => a + Buffer.byteLength(c.text) + (c.heading_path ? Buffer.byteLength(c.heading_path) : 0), 0);
        rows += ns.length + cs.length; bytes += bBytes; batches++;
        appMs += t.crypto + t.verify + t.index; dbMs += t.sel + t.upd + t.rb + t.shardw;
        batchStats.push({ rows: ns.length + cs.length, bytes: bBytes, ...Object.fromEntries(Object.entries(t).map(([k, v]) => [k, r2(v)])) });
      }
      const cu = process.cpuUsage(cpuC);
      if (batches) calls.push({ wallMs: r2(performance.now() - c0), batches, rows, bytes, appMs: r2(appMs), dbMs: r2(dbMs), cpuMs: r2((cu.user + cu.system) / 1000) });
    }
    const cpu = process.cpuUsage(cpu0);
    const per = (k: string) => batchStats.map((b) => b[k]!);
    out({
      mib, batchBytes, maxRows, shard, budgetMs, notes: totals.n, chunks: totals.c, plainBytes: Number(totals.b), done,
      calls: calls.length, totalWallMs: r2(performance.now() - wall0), totalCpuMs: r2((cpu.user + cpu.system) / 1000),
      firstCall: calls[0], lastFullCall: calls.length > 1 ? calls[calls.length - 2] : calls[0],
      perCallMedian: { rows: pct(calls.map((c) => c.rows!), 50), bytes: pct(calls.map((c) => c.bytes!), 50), batches: pct(calls.map((c) => c.batches!), 50), appMs: pct(calls.map((c) => c.appMs!), 50), dbMs: pct(calls.map((c) => c.dbMs!), 50) },
      batchMedianMs: Object.fromEntries(['sel', 'crypto', 'upd', 'rb', 'verify', 'index', 'shardw'].map((k) => [k, r2(pct(per(k), 50))])),
      batchP95TotalMs: r2(pct(batchStats.map((b) => b['sel']! + b['crypto']! + b['upd']! + b['rb']! + b['verify']! + b['index']! + b['shardw']!), 95)),
      batches: batchStats.length, medianBatchRows: pct(per('rows'), 50), medianBatchBytes: pct(per('bytes'), 50),
    });
  } finally {
    await db.close();
    rmSync(tmp, { recursive: true, force: true });
  }
}

const run: Record<string, () => void | Promise<void>> = { baseline: cmdBaseline, index: cmdIndex, cache: cmdCache, wal: cmdWal, encrypt: cmdEncrypt };
const f = run[cmd];
if (!f) { process.stderr.write(`usage: c0-measure.ts ${Object.keys(run).join('|')} [--opts]\n`); process.exit(2); }
await f();
