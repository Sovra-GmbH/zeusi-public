// The B1 index of an encrypted workspace (C7a, docs/plans/2026-11-19-c7-read-path.md KTD5, KTD6, KTD8; parent
// plan docs/plans/2026-11-18-zeusi-workspace-encryption.md §2.2, §3B; C0 docs/plans/2026-11-18-c0-results.md §2).
//
// What it holds, built ONLY from opened rows (openedRow, src/workspace-seal.ts; one rule for both row shapes):
//   note      id, title, vault_path, source_uri and the lifecycle frontmatter keys (src/lock-lifecycle.ts
//             LIFECYCLE_KEYS + standing_locks), nothing of the body;
//   chunk     id, note id and the lexemes of coalesce(heading_path,'') || ' ' || text WITH positions
//             (src/b1-lexer.ts), never the chunk text (snippets come from opening the served rows);
//   fact      id, subject, text, source_uri;   decision  id, exact_words, applies_to, source_uri, linked_repo;
//   link      id, decision id, target kind, target uri.
// Visibility (note status, chunk scope, decisions_current / facts_current, expiry) is NEVER taken from here:
// the read path asks the database for it in the request (KTD7).
//
// Storage: tenant table <schema>.b1_index (src/tenant-overlay.ts b1IndexStatements), one key_version at a time:
//   manifest  (shard_no 0)  sealed JSON: generation, coverage (per table: row count, max id, sum of ids), the
//                           listed base shards and segments with their generation and plain size;
//   base      (shard_no n)  notes + chunks of note ids [500n, 500n+500); facts / decisions / links in their own
//                           number ranges (RECORD_SHARD_BASE);
//   segment   (shard_no n)  ONE per sealed write transaction: that transaction's entries plus tombstones.
// Every object is sealed under C1's index AAD (tenant, kind, object number, key_version) by WorkspaceKey.sealIndex,
// and carries a plain header (kind, number, generation, key_version) checked against its row and the manifest
// after opening, so a copied, renumbered, replayed or foreign object never loads (the read path rebuilds).
// Compaction (more than COMPACT_SEGMENTS segments or COMPACT_BYTES of segment plaintext) merges the segments
// into the base shards they touch, in the same transaction, under the same lock.
//
// Write side (KTD8): b1IndexHook(key) is the IndexHook of the sealed write route (an IndexHookFactory). The C6
// call sites tell it which ids a transaction wrote / removed; at beforeCommit (index lock held, src/write-route.ts
// sealedTx) it reads those rows back, opens them, and appends one segment, after checking that the stored
// coverage plus this transaction's delta equals the database's (one aggregate statement). A mismatch (a writer
// that bypassed the hook) or a missing / unopenable manifest rebuilds the whole index from rows instead.
//
// Read side: loadPacked() opens the manifest and every listed object, checks coverage against the database and
// packs the result; anything that does not open or does not match -> buildPacked() from rows (read role, SELECT
// only, nothing written). The packed form is Buffers and typed arrays only (C0: never a JS Map of terms).
//
// Never logs, returns in an error, or renders a key, a term, an id list or a value.

import type { Db } from './db.ts';
import { LIFECYCLE_KEYS, STANDING_MARKER_KEY } from './lock-lifecycle.ts';
import { B1_INDEX_TABLE } from './tenant-ddl.ts';
import { openedRow, type B1Object, type WorkspaceKey } from './workspace-seal.ts';
import type { IndexHook } from './write-route.ts';
import { toTsvector, type TsVector } from './b1-lexer.ts';

export const NOTE_SHARD_SIZE = 500;
export const RECORD_SHARD_SIZE = 2000;
/** Base shard numbers of the record tables (notes + chunks use 0 .. RECORD_SHARD_BASE.facts - 1). */
export const RECORD_SHARD_BASE = { facts: 1_000_000, decisions: 2_000_000, decision_links: 3_000_000 } as const;
/** Compaction thresholds: segment count [estimate, plan KTD6] and plain segment bytes (C0: 1 MiB delta). */
export const COMPACT_SEGMENTS = 64;
export const COMPACT_BYTES = 1024 * 1024;
/** Rows read per statement by a build from rows. */
export const BUILD_BATCH = 1000;
const LAYER_MAGIC = Buffer.from('B1L1', 'ascii');
const INDEX_TABLES = ['notes', 'chunks', 'facts', 'decisions', 'decision_links'] as const;
export type IndexTable = (typeof INDEX_TABLES)[number];
/** The frontmatter keys the index keeps (the lock lifecycle's, plus the standing marker). */
export const INDEX_FM_KEYS: readonly string[] = [...LIFECYCLE_KEYS, STANDING_MARKER_KEY];

export interface NoteEntry { id: number; title: string; vaultPath: string; sourceUri: string; fm: Record<string, unknown> | null }
export interface FactEntry { id: number; subject: string | null; text: string; sourceUri: string }
export interface DecisionEntry { id: number; exactWords: string; appliesTo: string[]; sourceUri: string; linkedRepo: string | null }
export interface LinkEntry { id: number; decisionId: number; targetKind: string; targetUri: string }
/** A chunk's lexemes, encoded (see encodeVector); kept as bytes until the index is packed. */
interface ChunkEntry { id: number; noteId: number; vec: Buffer }

export interface TableCoverage { n: number; max: number; sum: string }
export type Coverage = Record<IndexTable, TableCoverage>;

/** A chunk removed by a transaction: its id and its note (the base shard it lives in). */
export interface ChunkTomb { id: number; note: number }

interface LayerHeader {
  v: 1;
  kind: 'base' | 'segment';
  no: number;
  generation: number;
  keyVersion: number;
  notes: NoteEntry[];
  facts: FactEntry[];
  decisions: DecisionEntry[];
  links: LinkEntry[];
  tomb: { chunks: ChunkTomb[] };
  nChunks: number;
}

interface ListedObject { no: number; generation: number; bytes: number }
export interface Manifest {
  v: 1;
  kind: 'manifest';
  generation: number;
  keyVersion: number;
  coverage: Coverage;
  base: ListedObject[];
  segments: ListedObject[];
  nextSegment: number;
}

/** The index could not be used (missing, does not open, does not match the rows): rebuild from rows. */
export class IndexStale extends Error {
  override name = 'IndexStale';
}

// ---------------------------------------------------------------------------
// Encoding

/** One chunk's vector as bytes: u32 nTerms, then per term u16 byte length, UTF-8 bytes, u16 nPos, u16 positions. */
export function encodeVector(v: TsVector): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(4);
  head.writeUInt32LE(v.length);
  parts.push(head);
  for (const [w, pos] of v) {
    const wb = Buffer.from(w, 'utf8');
    if (wb.length > 0xffff || pos.length > 0xffff) throw new IndexStale('lexeme too long');
    const b = Buffer.alloc(4 + wb.length + 2 * pos.length);
    b.writeUInt16LE(wb.length, 0);
    wb.copy(b, 2);
    b.writeUInt16LE(pos.length, 2 + wb.length);
    pos.forEach((p, i) => b.writeUInt16LE(p, 4 + wb.length + 2 * i));
    parts.push(b);
  }
  return Buffer.concat(parts);
}

/** Visit each term of an encoded vector: (term bytes, positions offset in `b`, count). */
function eachTerm(b: Buffer, fn: (term: Buffer, posAt: number, nPos: number) => void): void {
  const n = b.readUInt32LE(0);
  let o = 4;
  for (let i = 0; i < n; i++) {
    const len = b.readUInt16LE(o);
    const term = b.subarray(o + 2, o + 2 + len);
    const nPos = b.readUInt16LE(o + 2 + len);
    fn(term, o + 4 + len, nPos);
    o += 4 + len + 2 * nPos;
  }
  if (o !== b.length) throw new IndexStale('vector does not parse');
}

function encodeLayer(h: LayerHeader, chunks: readonly ChunkEntry[]): Buffer {
  const header = Buffer.from(JSON.stringify({ ...h, nChunks: chunks.length }), 'utf8');
  const parts: Buffer[] = [LAYER_MAGIC, Buffer.alloc(4), header];
  parts[1]!.writeUInt32LE(header.length);
  for (const c of chunks) {
    const b = Buffer.alloc(20);
    b.writeDoubleLE(c.id, 0);
    b.writeDoubleLE(c.noteId, 8);
    b.writeUInt32LE(c.vec.length, 16);
    parts.push(b, c.vec);
  }
  return Buffer.concat(parts);
}

function decodeLayer(b: Buffer): { h: LayerHeader; chunks: ChunkEntry[] } {
  if (b.length < 8 || !b.subarray(0, 4).equals(LAYER_MAGIC)) throw new IndexStale('not an index layer');
  const hl = b.readUInt32LE(4);
  const h = JSON.parse(b.subarray(8, 8 + hl).toString('utf8')) as LayerHeader;
  const chunks: ChunkEntry[] = [];
  let o = 8 + hl;
  for (let i = 0; i < h.nChunks; i++) {
    const id = b.readDoubleLE(o);
    const noteId = b.readDoubleLE(o + 8);
    const len = b.readUInt32LE(o + 16);
    chunks.push({ id, noteId, vec: b.subarray(o + 20, o + 20 + len) });
    o += 20 + len;
  }
  if (o !== b.length) throw new IndexStale('layer does not parse');
  return { h, chunks };
}

// ---------------------------------------------------------------------------
// The merged state (load, compaction, build): plain values in memory, keyed by row id.

export class Merged {
  readonly notes = new Map<number, NoteEntry>();
  readonly chunks = new Map<number, ChunkEntry>();
  readonly facts = new Map<number, FactEntry>();
  readonly decisions = new Map<number, DecisionEntry>();
  readonly links = new Map<number, LinkEntry>();

  apply(h: Pick<LayerHeader, 'notes' | 'facts' | 'decisions' | 'links' | 'tomb'>, chunks: readonly ChunkEntry[]): void {
    for (const t of h.tomb.chunks) this.chunks.delete(t.id);
    for (const n of h.notes) this.notes.set(n.id, n);
    for (const c of chunks) this.chunks.set(c.id, c);
    for (const f of h.facts) this.facts.set(f.id, f);
    for (const d of h.decisions) this.decisions.set(d.id, d);
    for (const l of h.links) this.links.set(l.id, l);
  }

  coverage(): Coverage {
    const cov = (ids: Iterable<number>): TableCoverage => {
      let n = 0;
      let max = 0;
      let sum = 0n;
      for (const id of ids) {
        n++;
        if (id > max) max = id;
        sum += BigInt(id);
      }
      return { n, max, sum: sum.toString() };
    };
    return {
      notes: cov(this.notes.keys()), chunks: cov(this.chunks.keys()), facts: cov(this.facts.keys()),
      decisions: cov(this.decisions.keys()), decision_links: cov(this.links.keys()),
    };
  }
}

export function sameCoverage(a: Coverage, b: Coverage): boolean {
  return INDEX_TABLES.every((t) => a[t].n === b[t].n && a[t].max === b[t].max && a[t].sum === b[t].sum);
}

const noteShard = (noteId: number) => Math.floor(noteId / NOTE_SHARD_SIZE);
const recordShard = (table: 'facts' | 'decisions' | 'decision_links', id: number) => RECORD_SHARD_BASE[table] + Math.floor(id / RECORD_SHARD_SIZE);

// ---------------------------------------------------------------------------
// Rows -> entries (the ONE rule; the hook and the build both use it)

const num = (v: unknown) => Number(v);
const str = (v: unknown) => (v === null || v === undefined ? null : String(v));

/** The lifecycle frontmatter keys of one note (absent keys stay absent: `?|` tests presence). */
function fmOf(v: unknown): Record<string, unknown> | null {
  if (v === null || v === undefined || typeof v !== 'object' || Array.isArray(v)) return null;
  const out: Record<string, unknown> = {};
  for (const k of INDEX_FM_KEYS) if (Object.prototype.hasOwnProperty.call(v, k)) out[k] = (v as Record<string, unknown>)[k];
  return Object.keys(out).length > 0 ? out : null;
}

type Sel = readonly number[] | 'all';
const where = (sel: Sel, after: number) => (sel === 'all' ? { sql: 'id > $1', params: [after] as unknown[] } : { sql: 'id = ANY($1::bigint[]) AND id > $2', params: [[...sel], after] as unknown[] });

async function batched(db: Db, sel: Sel, sql: (w: string) => string, each: (r: Record<string, unknown>) => void): Promise<void> {
  if (sel !== 'all' && sel.length === 0) return;
  let after = 0;
  for (;;) {
    const w = where(sel, after);
    const rows = (await db.query<Record<string, unknown>>(`${sql(w.sql)} ORDER BY id LIMIT ${BUILD_BATCH}`, w.params)).rows;
    for (const r of rows) each(r);
    if (rows.length < BUILD_BATCH) return;
    after = num(rows[rows.length - 1]!['id']);
  }
}

/** Read the selected rows of both shapes (SELECT only), open them with `key` and add them to `m`. */
export async function entriesFromRows(db: Db, key: WorkspaceKey, sel: Partial<Record<IndexTable, Sel>>, m: Merged = new Merged()): Promise<Merged> {
  const both = (cols: readonly string[]) => [...cols, ...cols.map((c) => `${c}_ct`)].join(', ');
  if (sel.notes) {
    const cols = ['title', 'vault_path', 'source_uri', 'frontmatter'];
    await batched(db, sel.notes, (w) => `SELECT id::bigint AS id, key_version, ${both(cols)} FROM zeusi.notes WHERE ${w}`, (r) => {
      const o = openedRow(key, 'notes', r, cols);
      m.notes.set(num(r['id']), { id: num(r['id']), title: String(o['title']), vaultPath: String(o['vault_path']), sourceUri: String(o['source_uri']), fm: fmOf(o['frontmatter']) });
    });
  }
  if (sel.chunks) {
    const cols = ['heading_path', 'text'];
    await batched(db, sel.chunks, (w) => `SELECT id::bigint AS id, note_id::bigint AS note_id, key_version, ${both(cols)} FROM zeusi.chunks WHERE ${w}`, (r) => {
      const o = openedRow(key, 'chunks', r, cols);
      // Exactly the tsv expression of migrations/0001_core.sql:242-243 (coalesce(heading_path,'') || ' ' || text).
      const vec = encodeVector(toTsvector(`${str(o['heading_path']) ?? ''} ${String(o['text'])}`));
      m.chunks.set(num(r['id']), { id: num(r['id']), noteId: num(r['note_id']), vec });
    });
  }
  if (sel.facts) {
    const cols = ['subject', 'text', 'source_uri'];
    await batched(db, sel.facts, (w) => `SELECT id::bigint AS id, key_version, ${both(cols)} FROM zeusi.facts WHERE ${w}`, (r) => {
      const o = openedRow(key, 'facts', r, cols);
      m.facts.set(num(r['id']), { id: num(r['id']), subject: str(o['subject']), text: String(o['text']), sourceUri: String(o['source_uri']) });
    });
  }
  if (sel.decisions) {
    const cols = ['exact_words', 'applies_to', 'source_uri', 'linked_repo'];
    await batched(db, sel.decisions, (w) => `SELECT id::bigint AS id, key_version, ${both(cols)} FROM zeusi.decisions WHERE ${w}`, (r) => {
      const o = openedRow(key, 'decisions', r, cols);
      const a = o['applies_to'];
      m.decisions.set(num(r['id']), {
        id: num(r['id']), exactWords: String(o['exact_words']), appliesTo: Array.isArray(a) ? a.map(String) : [], sourceUri: String(o['source_uri']), linkedRepo: str(o['linked_repo']),
      });
    });
  }
  if (sel.decision_links) {
    const cols = ['target_uri'];
    const has = (await db.query<{ ok: boolean }>(`SELECT to_regclass('zeusi.decision_links') IS NOT NULL AS ok`)).rows[0]?.ok === true;
    if (has) {
      await batched(db, sel.decision_links, (w) => `SELECT id::bigint AS id, decision_id::bigint AS decision_id, target_kind::text AS target_kind, key_version, ${both(cols)} FROM zeusi.decision_links WHERE ${w}`, (r) => {
        const o = openedRow(key, 'decision_links', r, cols);
        m.links.set(num(r['id']), { id: num(r['id']), decisionId: num(r['decision_id']), targetKind: String(r['target_kind']), targetUri: String(o['target_uri']) });
      });
    }
  }
  return m;
}

/** Every row of the five tables (both shapes), opened: the full index. */
export function buildFromRows(db: Db, key: WorkspaceKey): Promise<Merged> {
  return entriesFromRows(db, key, { notes: 'all', chunks: 'all', facts: 'all', decisions: 'all', decision_links: 'all' });
}

/**
 * The database's coverage of the five tables (row count, max id, sum of ids) and the number of rows of
 * ANOTHER key_version than `kv` (a rotation this session predates). Ids and counts only.
 */
export async function dbCoverage(db: Db, kv: number): Promise<{ coverage: Coverage; otherKeyVersion: number }> {
  const hasLinks = (await db.query<{ ok: boolean }>(`SELECT to_regclass('zeusi.decision_links') IS NOT NULL AS ok`)).rows[0]?.ok === true;
  const tables = INDEX_TABLES.filter((t) => t !== 'decision_links' || hasLinks);
  const r = (await db.query<Record<string, string>>(
    `SELECT ${tables.map((t) => `(SELECT count(*)::text FROM zeusi.${t}) AS ${t}_n, (SELECT coalesce(max(id), 0)::text FROM zeusi.${t}) AS ${t}_max,
            (SELECT coalesce(sum(id), 0)::text FROM zeusi.${t}) AS ${t}_sum`).join(', ')},
            (${tables.map((t) => `(SELECT count(*) FROM zeusi.${t} WHERE key_version IS NOT NULL AND key_version <> $1::smallint)`).join(' + ')})::int AS other_kv`,
    [kv])).rows[0]!;
  const z: TableCoverage = { n: 0, max: 0, sum: '0' };
  const coverage = Object.fromEntries(INDEX_TABLES.map((t) => [t, tables.includes(t) ? { n: Number(r[`${t}_n`]), max: Number(r[`${t}_max`]), sum: String(r[`${t}_sum`]) } : z])) as Coverage;
  return { coverage, otherKeyVersion: Number(r['other_kv']) };
}

// ---------------------------------------------------------------------------
// Sealed objects on b1_index

export async function hasIndexTable(db: Db): Promise<boolean> {
  return (await db.query<{ ok: boolean }>(`SELECT to_regclass('zeusi.${B1_INDEX_TABLE}') IS NOT NULL AS ok`)).rows[0]?.ok === true;
}

function sealLayer(key: WorkspaceKey, h: LayerHeader, chunks: readonly ChunkEntry[]): { blob: Buffer; bytes: number } {
  const plain = encodeLayer(h, chunks);
  try {
    return { blob: key.sealIndex({ kind: h.kind, no: h.no }, plain), bytes: plain.length };
  } finally {
    plain.fill(0);
  }
}

function openLayer(key: WorkspaceKey, obj: { kind: 'base' | 'segment'; no: number }, blob: Uint8Array, expect: ListedObject): { h: LayerHeader; chunks: ChunkEntry[] } {
  let plain: Buffer;
  try {
    plain = key.openIndex(obj, blob);
  } catch {
    throw new IndexStale('an index object does not open');
  }
  const l = decodeLayer(plain);
  if (l.h.v !== 1 || l.h.kind !== obj.kind || l.h.no !== obj.no || l.h.generation !== expect.generation || l.h.keyVersion !== key.keyVersion) {
    throw new IndexStale('an index object does not match its manifest');
  }
  return l;
}

/** The manifest of `key`'s key_version, opened and checked against its row, or null when there is none. */
export async function readManifest(db: Db, key: WorkspaceKey): Promise<{ manifest: Manifest | null; rowGeneration: number }> {
  const r = (await db.query<{ generation: string; blob_ct: Uint8Array }>(
    `SELECT generation::text AS generation, blob_ct FROM zeusi.${B1_INDEX_TABLE} WHERE key_version = $1 AND kind = 'manifest' AND shard_no = 0`, [key.keyVersion])).rows[0];
  if (!r) return { manifest: null, rowGeneration: 0 };
  const gen = Number(r.generation);
  try {
    const m = JSON.parse(key.openIndex({ kind: 'manifest' }, r.blob_ct).toString('utf8')) as Manifest;
    if (m.v !== 1 || m.kind !== 'manifest' || m.generation !== gen || m.keyVersion !== key.keyVersion) return { manifest: null, rowGeneration: gen };
    return { manifest: m, rowGeneration: gen };
  } catch {
    return { manifest: null, rowGeneration: gen };
  }
}

/** Open every object the manifest lists and merge them (base shards, then segments in order). Throws IndexStale. */
export async function loadMerged(db: Db, key: WorkspaceKey, m: Manifest): Promise<Merged> {
  const rows = (await db.query<{ kind: 'base' | 'segment'; shard_no: number; generation: string; blob_ct: Uint8Array }>(
    `SELECT kind, shard_no, generation::text AS generation, blob_ct FROM zeusi.${B1_INDEX_TABLE} WHERE key_version = $1 AND kind IN ('base', 'segment')`,
    [key.keyVersion])).rows;
  const byKey = new Map(rows.map((r) => [`${r.kind}:${r.shard_no}`, r]));
  const merged = new Merged();
  const one = (kind: 'base' | 'segment', o: ListedObject) => {
    const r = byKey.get(`${kind}:${o.no}`);
    if (!r || Number(r.generation) !== o.generation) throw new IndexStale('a listed index object is missing');
    const l = openLayer(key, { kind, no: o.no }, r.blob_ct, o);
    merged.apply(l.h, l.chunks);
  };
  for (const o of m.base) one('base', o);
  for (const o of [...m.segments].sort((a, b) => a.no - b.no)) one('segment', o);
  if (!sameCoverage(merged.coverage(), m.coverage)) throw new IndexStale('the index does not match its manifest');
  return merged;
}

/** The base-shard layers of a merged state, restricted to `only` (undefined: every shard). */
function baseLayers(m: Merged, generation: number, keyVersion: number, only?: ReadonlySet<number>): Array<{ h: LayerHeader; chunks: ChunkEntry[] }> {
  const shards = new Map<number, { h: LayerHeader; chunks: ChunkEntry[] }>();
  const at = (no: number) => {
    let s = shards.get(no);
    if (!s) {
      s = { h: { v: 1, kind: 'base', no, generation, keyVersion, notes: [], facts: [], decisions: [], links: [], tomb: { chunks: [] }, nChunks: 0 }, chunks: [] };
      shards.set(no, s);
    }
    return s;
  };
  for (const n of m.notes.values()) at(noteShard(n.id)).h.notes.push(n);
  for (const c of m.chunks.values()) at(noteShard(c.noteId)).chunks.push(c);
  for (const f of m.facts.values()) at(recordShard('facts', f.id)).h.facts.push(f);
  for (const d of m.decisions.values()) at(recordShard('decisions', d.id)).h.decisions.push(d);
  for (const l of m.links.values()) at(recordShard('decision_links', l.id)).h.links.push(l);
  if (only) for (const no of only) at(no); // a touched shard that is now empty is rewritten empty
  return [...shards.values()].filter((s) => !only || only.has(s.h.no)).sort((a, b) => a.h.no - b.h.no);
}

async function putObject(db: Db, kv: number, kind: 'base' | 'segment' | 'manifest', no: number, generation: number, blob: Buffer): Promise<void> {
  await db.query(
    `INSERT INTO zeusi.${B1_INDEX_TABLE} (key_version, kind, shard_no, generation, blob_ct) VALUES ($1, $2, $3, $4, $5::bytea)
     ON CONFLICT (key_version, kind, shard_no) DO UPDATE SET generation = EXCLUDED.generation, blob_ct = EXCLUDED.blob_ct, updated_at = now()`,
    [kv, kind, no, generation, blob]);
}

function sealManifest(key: WorkspaceKey, m: Manifest): Buffer {
  const plain = Buffer.from(JSON.stringify(m), 'utf8');
  try {
    return key.sealIndex({ kind: 'manifest' }, plain);
  } finally {
    plain.fill(0);
  }
}

/** Replace the whole index of key.keyVersion with `merged` as base shards (a build, or a repair). */
export async function persistFull(db: Db, key: WorkspaceKey, merged: Merged, generation: number): Promise<Manifest> {
  const kv = key.keyVersion;
  await db.query(`DELETE FROM zeusi.${B1_INDEX_TABLE} WHERE key_version = $1`, [kv]);
  const base: ListedObject[] = [];
  for (const l of baseLayers(merged, generation, kv)) {
    const s = sealLayer(key, l.h, l.chunks);
    await putObject(db, kv, 'base', l.h.no, generation, s.blob);
    base.push({ no: l.h.no, generation, bytes: s.bytes });
  }
  const m: Manifest = { v: 1, kind: 'manifest', generation, keyVersion: kv, coverage: merged.coverage(), base, segments: [], nextSegment: 0 };
  await putObject(db, kv, 'manifest', 0, generation, sealManifest(key, m));
  return m;
}

// ---------------------------------------------------------------------------
// The write hook (KTD8)

/** What one sealed transaction changed, as the C6 call sites report it. */
interface Pending {
  notes: Set<number>;
  chunks: Set<number>;
  tomb: Map<number, number>;
  facts: Set<number>;
  decisions: Set<number>;
  links: Set<number>;
  unknown: boolean;
}
const emptyPending = (): Pending => ({ notes: new Set(), chunks: new Set(), tomb: new Map(), facts: new Set(), decisions: new Set(), links: new Set(), unknown: false });

/** Observable counts for tests and the PR's figures (never ids or values). */
export interface HookStats { segments: number; rebuilds: number; compactions: number; skippedNoTable: number }

/**
 * The real IndexHook of the sealed write route, bound to that route's session key (an IndexHookFactory for
 * src/workspace-write.ts). Stages ids during the transaction; writes at beforeCommit (lock held).
 */
export function b1IndexHook(key: WorkspaceKey, stats?: HookStats): IndexHook {
  let p = emptyPending();
  return {
    onNoteWritten: async (_tx, n) => {
      p.notes.add(n.noteId);
      for (const c of n.chunks) p.chunks.add(c.id);
      for (const id of n.removedChunkIds) p.tomb.set(id, n.noteId);
    },
    onNoteRemoved: async (_tx, noteId, removed) => {
      p.notes.add(noteId);
      if (removed === undefined) p.unknown = true;
      else for (const id of removed) p.tomb.set(id, noteId);
    },
    onRecordWritten: async (_tx, r) => {
      (r.table === 'facts' ? p.facts : r.table === 'decisions' ? p.decisions : p.links).add(r.id);
    },
    afterRollback: () => {
      p = emptyPending();
    },
    beforeCommit: async (tx) => {
      const staged = p;
      p = emptyPending();
      if (!staged.unknown && staged.notes.size + staged.chunks.size + staged.tomb.size + staged.facts.size + staged.decisions.size + staged.links.size === 0) return;
      if (!(await hasIndexTable(tx))) {
        // A workspace prepared before C7 that has not converged yet (writerIn creates the table at sign-in):
        // nothing to persist into; the read path builds the index from rows.
        if (stats) stats.skippedNoTable++;
        return;
      }
      await persistSegment(tx, key, staged, stats);
    },
  };
}

/** Coverage after this transaction, from the manifest's and the staged ids (ids come from nextval under the lock). */
function expectedCoverage(before: Coverage, p: Pending): Coverage {
  const out = structuredClone(before);
  const add = (t: IndexTable, id: number) => {
    out[t].n++;
    out[t].max = Math.max(out[t].max, id);
    out[t].sum = (BigInt(out[t].sum) + BigInt(id)).toString();
  };
  const drop = (t: IndexTable, id: number) => {
    out[t].n--;
    out[t].sum = (BigInt(out[t].sum) - BigInt(id)).toString();
  };
  // A note id above the stored max is a new row; at or below it is an update of an existing row.
  for (const id of p.notes) if (id > before.notes.max) add('notes', id);
  for (const id of p.tomb.keys()) if (!p.chunks.has(id)) drop('chunks', id);
  for (const id of p.chunks) if (!p.tomb.has(id)) add('chunks', id);
  for (const id of p.facts) add('facts', id);
  for (const id of p.decisions) add('decisions', id);
  for (const id of p.links) add('decision_links', id);
  // max after removals: only recomputable from the rows; a removal of the max chunk is caught by the DB compare.
  return out;
}

async function persistSegment(tx: Db, key: WorkspaceKey, p: Pending, stats?: HookStats): Promise<void> {
  const kv = key.keyVersion;
  const { manifest, rowGeneration } = await readManifest(tx, key);
  const actual = (await dbCoverage(tx, kv)).coverage;
  const rebuild = async () => {
    const merged = await buildFromRows(tx, key);
    await persistFull(tx, key, merged, rowGeneration + 1);
    if (stats) stats.rebuilds++;
  };
  if (!manifest || p.unknown) return rebuild();
  const expected = expectedCoverage(manifest.coverage, p);
  // max ids cannot shrink by a removal in `expected`; compare counts and sums, and max only when no chunk left.
  const covOk = INDEX_TABLES.every((t) => expected[t].n === actual[t].n && expected[t].sum === actual[t].sum
    && (t === 'chunks' && p.tomb.size > 0 ? true : expected[t].max === actual[t].max));
  if (!covOk) return rebuild();
  const delta = await entriesFromRows(tx, key, {
    notes: [...p.notes], chunks: [...p.chunks].filter((id) => !p.tomb.has(id)), facts: [...p.facts], decisions: [...p.decisions], decision_links: [...p.links],
  });
  const generation = manifest.generation + 1;
  const no = manifest.nextSegment;
  const h: LayerHeader = {
    v: 1, kind: 'segment', no, generation, keyVersion: kv, notes: [...delta.notes.values()], facts: [...delta.facts.values()],
    decisions: [...delta.decisions.values()], links: [...delta.links.values()], tomb: { chunks: [...p.tomb].map(([id, note]) => ({ id, note })) }, nChunks: 0,
  };
  const s = sealLayer(key, h, [...delta.chunks.values()]);
  await putObject(tx, kv, 'segment', no, generation, s.blob);
  const next: Manifest = { ...manifest, generation, coverage: actual, segments: [...manifest.segments, { no, generation, bytes: s.bytes }], nextSegment: no + 1 };
  if (stats) stats.segments++;
  if (next.segments.length > COMPACT_SEGMENTS || next.segments.reduce((a, x) => a + x.bytes, 0) > COMPACT_BYTES) {
    await compact(tx, key, next);
    if (stats) stats.compactions++;
    return;
  }
  await putObject(tx, kv, 'manifest', 0, generation, sealManifest(key, next));
}

/** Merge every segment into the base shards it touches; rewrite only those; delete the segments. */
async function compact(tx: Db, key: WorkspaceKey, m: Manifest): Promise<void> {
  const kv = key.keyVersion;
  const merged = await loadMerged(tx, key, m);
  const touched = new Set<number>();
  const segRows = (await tx.query<{ shard_no: number; generation: string; blob_ct: Uint8Array }>(
    `SELECT shard_no, generation::text AS generation, blob_ct FROM zeusi.${B1_INDEX_TABLE} WHERE key_version = $1 AND kind = 'segment'`, [kv])).rows;
  for (const r of segRows) {
    const listed = m.segments.find((s) => s.no === r.shard_no);
    if (!listed) continue;
    const l = openLayer(key, { kind: 'segment', no: r.shard_no }, r.blob_ct, listed);
    for (const n of l.h.notes) touched.add(noteShard(n.id));
    for (const c of l.chunks) touched.add(noteShard(c.noteId));
    for (const t of l.h.tomb.chunks) touched.add(noteShard(t.note));
    for (const f of l.h.facts) touched.add(recordShard('facts', f.id));
    for (const d of l.h.decisions) touched.add(recordShard('decisions', d.id));
    for (const x of l.h.links) touched.add(recordShard('decision_links', x.id));
  }
  const generation = m.generation;
  const base = new Map(m.base.map((b) => [b.no, b]));
  for (const l of baseLayers(merged, generation, kv, touched)) {
    const s = sealLayer(key, l.h, l.chunks);
    await putObject(tx, kv, 'base', l.h.no, generation, s.blob);
    base.set(l.h.no, { no: l.h.no, generation, bytes: s.bytes });
  }
  await tx.query(`DELETE FROM zeusi.${B1_INDEX_TABLE} WHERE key_version = $1 AND kind = 'segment'`, [kv]);
  const next: Manifest = { ...m, base: [...base.values()].sort((a, b) => a.no - b.no), segments: [], nextSegment: m.nextSegment };
  await putObject(tx, kv, 'manifest', 0, generation, sealManifest(key, next));
}

// ---------------------------------------------------------------------------
// The packed form (the B1 cache value): Buffers and typed arrays only.

export interface IndexRecords { notes: NoteEntry[]; facts: FactEntry[]; decisions: DecisionEntry[]; links: LinkEntry[] }

export interface Packed {
  /** The manifest generation this copy matches (0: no persisted manifest). */
  readonly generation: number;
  readonly coverage: Coverage;
  /** Chunk ids ascending, and each chunk's note id. */
  readonly chunkIds: Float64Array;
  readonly chunkNotes: Float64Array;
  /** Distinct lexemes, UTF-8, sorted bytewise; termOff has n+1 offsets. */
  readonly terms: Buffer;
  readonly termOff: Uint32Array;
  /**
   * Postings of term t: postStart[t] .. postStart[t+1]; posting g = chunk ordinal postChunk[g] (16-bit while the
   * workspace has <= 65535 chunks) with postNPos[g] positions (<= 255: the tsvector cap). Positions are laid out in
   * posting order; the offset of posting g = postPosSample[g >> 6] + the counts of the postings before g in its
   * block of 64 (a sampled prefix sum: about 1.06 bytes per posting instead of 4).
   */
  readonly postStart: Uint32Array;
  readonly postChunk: Uint16Array | Uint32Array;
  readonly postNPos: Uint8Array;
  readonly postPosSample: Uint32Array;
  readonly positions: Uint16Array;
  /** notes / facts / decisions / links as UTF-8 JSON. */
  readonly records: Buffer;
  /** Plain bytes of all the above (the cache accounts bytes x 1.25). */
  readonly bytes: number;
}

/** Pack a merged state (transient term interning; the result holds no Map). */
export function pack(m: Merged, generation: number): Packed {
  const chunks = [...m.chunks.values()].sort((a, b) => a.id - b.id);
  const chunkIds = new Float64Array(chunks.length);
  const chunkNotes = new Float64Array(chunks.length);
  const intern = new Map<string, number>();
  const termBytes: Buffer[] = [];
  const nPost: number[] = [];
  const nPos: number[] = [];
  chunks.forEach((c, i) => {
    chunkIds[i] = c.id;
    chunkNotes[i] = c.noteId;
    eachTerm(c.vec, (term, _at, np) => {
      const k = term.toString('latin1');
      let t = intern.get(k);
      if (t === undefined) {
        t = termBytes.length;
        intern.set(k, t);
        termBytes.push(Buffer.from(term));
        nPost.push(0);
        nPos.push(0);
      }
      nPost[t]!++;
      nPos[t]! += np;
    });
  });
  const order = termBytes.map((_, i) => i).sort((a, b) => Buffer.compare(termBytes[a]!, termBytes[b]!));
  const rank = new Uint32Array(order.length);
  order.forEach((t, r) => { rank[t] = r; });
  const termOff = new Uint32Array(order.length + 1);
  const postStart = new Uint32Array(order.length + 1);
  const posOfTerm = new Uint32Array(order.length + 1);
  order.forEach((t, r) => {
    termOff[r + 1] = termOff[r]! + termBytes[t]!.length;
    postStart[r + 1] = postStart[r]! + nPost[t]!;
    posOfTerm[r + 1] = posOfTerm[r]! + nPos[t]!;
  });
  const terms = Buffer.alloc(termOff[order.length]!);
  order.forEach((t, r) => termBytes[t]!.copy(terms, termOff[r]!));
  const totalPost = postStart[order.length]!;
  const postChunk = chunks.length <= 0xffff ? new Uint16Array(totalPost) : new Uint32Array(totalPost);
  const postNPos = new Uint8Array(totalPost);
  const positions = new Uint16Array(posOfTerm[order.length]!);
  const postCur = postStart.slice(0, order.length);
  const posCur = posOfTerm.slice(0, order.length);
  chunks.forEach((c, i) => {
    eachTerm(c.vec, (term, at, np) => {
      if (np > 0xff) throw new IndexStale('more positions than the tsvector cap');
      const r = rank[intern.get(term.toString('latin1'))!]!;
      const slot = postCur[r]!++;
      postChunk[slot] = i;
      postNPos[slot] = np;
      for (let j = 0; j < np; j++) positions[posCur[r]! + j] = c.vec.readUInt16LE(at + 2 * j);
      posCur[r]! += np;
    });
  });
  // Postings and their positions are both in term-major order, so one running sum gives every block start.
  const postPosSample = new Uint32Array((totalPost >> 6) + 1);
  for (let g = 0, off = 0; g < totalPost; g++) {
    if ((g & 63) === 0) postPosSample[g >> 6] = off;
    off += postNPos[g]!;
  }
  intern.clear();
  const records = Buffer.from(JSON.stringify({
    notes: [...m.notes.values()].sort((a, b) => a.id - b.id), facts: [...m.facts.values()].sort((a, b) => a.id - b.id),
    decisions: [...m.decisions.values()].sort((a, b) => a.id - b.id), links: [...m.links.values()].sort((a, b) => a.id - b.id),
  } satisfies IndexRecords), 'utf8');
  const bytes = chunkIds.byteLength + chunkNotes.byteLength + terms.length + termOff.byteLength + postStart.byteLength + postChunk.byteLength
    + postNPos.byteLength + postPosSample.byteLength + positions.byteLength + records.length;
  return { generation, coverage: m.coverage(), chunkIds, chunkNotes, terms, termOff, postStart, postChunk, postNPos, postPosSample, positions, records, bytes };
}

/** Zero every buffer of a packed copy (eviction; best effort, parent §4.3 step 3). */
export function wipePacked(p: Packed): void {
  for (const b of [p.chunkIds, p.chunkNotes, p.terms, p.termOff, p.postStart, p.postChunk, p.postNPos, p.postPosSample, p.positions, p.records]) b.fill(0);
}

/** The term index of `word`, or -1. */
export function termIndex(p: Packed, word: string): number {
  const w = Buffer.from(word, 'utf8');
  let lo = 0;
  let hi = p.termOff.length - 2;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const c = Buffer.compare(p.terms.subarray(p.termOff[mid]!, p.termOff[mid + 1]!), w);
    if (c === 0) return mid;
    if (c < 0) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/** Positions of term `t` in the chunk with ordinal `ord`, or undefined. */
export function positionsOf(p: Packed, t: number, ord: number): number[] | undefined {
  let lo = p.postStart[t]!;
  let hi = p.postStart[t + 1]! - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const c = p.postChunk[mid]!;
    if (c === ord) {
      let off = p.postPosSample[mid >> 6]!;
      for (let g = mid & ~63; g < mid; g++) off += p.postNPos[g]!;
      return Array.from(p.positions.subarray(off, off + p.postNPos[mid]!));
    }
    if (c < ord) lo = mid + 1;
    else hi = mid - 1;
  }
  return undefined;
}

/** Chunk ordinals that hold term `t`. */
export function chunksOf(p: Packed, t: number): Uint16Array | Uint32Array {
  return p.postChunk.subarray(p.postStart[t]!, p.postStart[t + 1]!);
}

/** The records (decoded per request; never kept beside the packed copy). */
export function recordsOf(p: Packed): IndexRecords {
  return JSON.parse(p.records.toString('utf8')) as IndexRecords;
}

// ---------------------------------------------------------------------------
// Read side: the persisted index, or a build from rows

export interface LoadOutcome { packed: Packed; rebuilt: boolean }

/**
 * The packed index of key.keyVersion for a read: the persisted one when its manifest opens, every listed
 * object opens and matches, and its coverage equals `dbCov`; otherwise a build from rows (nothing written).
 */
export async function loadPacked(db: Db, key: WorkspaceKey, dbCov: Coverage): Promise<LoadOutcome> {
  if (await hasIndexTable(db)) {
    const { manifest, rowGeneration } = await readManifest(db, key);
    if (manifest && sameCoverage(manifest.coverage, dbCov)) {
      try {
        return { packed: pack(await loadMerged(db, key, manifest), manifest.generation), rebuilt: false };
      } catch (e) {
        if (!(e instanceof IndexStale)) throw e;
      }
    }
    return { packed: pack(await buildFromRows(db, key), rowGeneration), rebuilt: true };
  }
  return { packed: pack(await buildFromRows(db, key), 0), rebuilt: true };
}

/** The manifest row's generation (0 when none): the cache freshness key, read in the request (still sealed). */
export async function manifestGeneration(db: Db, kv: number): Promise<number> {
  if (!(await hasIndexTable(db))) return 0;
  const r = (await db.query<{ g: string }>(`SELECT generation::text AS g FROM zeusi.${B1_INDEX_TABLE} WHERE key_version = $1 AND kind = 'manifest' AND shard_no = 0`, [kv])).rows[0];
  return r ? Number(r.g) : 0;
}
