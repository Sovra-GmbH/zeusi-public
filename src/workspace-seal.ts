// Sealing workspace rows on the write path (C6, docs/plans/2026-11-19-c6-write-path.md KTD4-KTD7, KTD11;
// parent plan docs/plans/2026-11-18-zeusi-workspace-encryption.md §4.1, §4.1a).
//
// The only value-crypto importer of the C1 envelope (src/crypto-envelope.ts) besides src/workspace-keys.ts
// (test/crypto-envelope.test.ts pins both import lists). Used only on the SEALED route (enc_state
// verified or on, src/write-route.ts); the plain (`off`) path never reaches this file.
//
//   WorkspaceKey  the session DEK of one request, turned into K_enc / K_idx / K_hash at once (the DEK
//                 buffer is zeroed in fromUnlocked) and zeroed again by dispose(); any use after dispose
//                 throws. It carries the per-key_version EncryptionCounter (KTD11): every seal adds 1
//                 first, so at ROTATE_AT no further value is sealed (SealRefused stops the call).
//   sealRow       KTD6: walks OVERLAY_SPEC for one table and returns every `_ct`, `_hmac`, `key_version`,
//                 and every plain content / derived column as NULL. A spec column it was not given
//                 throws, so a column added to the spec later can never be left plain by mistake.
//   AAD           (tenant = schema id, table, PLAIN column name, row id as decimal, key_version).
//   Encodings     text: UTF-8; notes.frontmatter: the JSON.stringify text the path builds; decisions.applies_to:
//                 a JSON array of strings; an optional NULL value: plain and `_ct` both NULL.
//   HMACs (KTD5)  vault_path -> indexHmac('vault_path'); every source_uri / target_uri -> indexHmac('uri');
//                 chunks.text_hmac -> keyedDigest('text', sha256(UTF-8 text)); stored source_sha256 ->
//                 keyedDigest('source_sha256', plain digest); quarantine source_uri -> 'hmac:' +
//                 hex(indexHmac('quarantine-uri', uri)).
//
// C7 (docs/plans/2026-11-19-c7-read-path.md KTD2, KTD6, KTD7) adds, on the same key:
//   sealIndex / openIndex  one B1 index object (base shard, per-transaction segment, manifest) under C1's
//                 index AAD (tenant, b1-main-shard | b1-delta-shard | b1-manifest, object no, key_version).
//                 Each index seal counts 1 under the `notes` row of enc_progress (C7 open decision 3).
//   cacheCheck    indexHmac('b1-cache-check', tenant): the B1 cache entry's check value (memory only).
//   openedRow     the read rule for one row of an overlay table, either shape (one-rule): key_version
//                 NULL -> the plain columns; else every `_ct` opened under the row's AAD; a row of another
//                 key_version -> RowKeyVersionMismatch; a tag failure throws (the caller fails closed).
//
// C8-0 (docs/plans/2026-11-21-c8-refresh.md KTD-A) adds, on the same key:
//   sealDigest    the sealed copy of a row's PLAIN source digest (64 lowercase hex characters, UTF-8) under AAD
//                 (tenant, table, column 'source_sha256', row id, key_version), for notes, facts, decisions and
//                 decision_links; counted by seal like every value. sealedInsertSql / sealedUpdateSql refuse a row
//                 that sets source_sha256 without it (the one owner of that rule).
//   digestCopyMatches  the one check a later rotate or decrypt must pass before trusting a copy (a stale copy
//                 left by a reverted image's UPDATE is false). No runtime caller in C8-0.
//
// Never logs, returns in an error, or renders a key, a plaintext value or a plain digest.

import { createHash, timingSafeEqual } from 'node:crypto';
import {
  deriveSubkeys, EncryptionCounter, EnvelopeError, indexHmac, KEY_BYTES, keyedDigest, MAX_KEY_VERSION, openIndexObject, openValue, sealIndexObject, sealValue,
  type DigestPurpose, type IndexHmacPurpose, type Subkeys,
} from './crypto-envelope.ts';
import type { Db } from './db.ts';
import { assertTenantId, ENC_PROGRESS_TABLE } from './tenant-ddl.ts';
import { OVERLAY_SPEC, OVERLAY_TABLES, SEALED_DIGEST_COLUMN, SEALED_DIGEST_TABLES, SEALED_MIN_BYTES } from './tenant-overlay.ts';

/** The call must stop: the key_version's seal budget is used up (rotate first), or the counter was not started. */
export class SealRefused extends Error {
  override name = 'SealRefused';
}

/** A DEK as unwrapped from a C4 wrap (src/workspace-keys.ts UnlockedDek). */
export interface UnlockedKey {
  dek: Buffer;
  keyVersion: number;
}

export class WorkspaceKey {
  readonly tenantId: string;
  readonly keyVersion: number;
  #sub: Subkeys | null;
  #counter: EncryptionCounter | null = null;
  readonly #pending = new Map<string, number>();

  private constructor(tenantId: string, keyVersion: number, sub: Subkeys) {
    this.tenantId = tenantId;
    this.keyVersion = keyVersion;
    this.#sub = sub;
  }

  /** Subkeys from an unwrapped DEK; the DEK buffer is zeroed here, whatever happens. */
  static fromUnlocked(u: UnlockedKey, tenantId: string): WorkspaceKey {
    try {
      assertTenantId(tenantId);
      if (!Number.isInteger(u.keyVersion) || u.keyVersion < 1 || u.keyVersion > MAX_KEY_VERSION) throw new EnvelopeError('key_version out of range');
      if (!(u.dek instanceof Uint8Array) || u.dek.length !== KEY_BYTES) throw new EnvelopeError('DEK must be 32 bytes');
      return new WorkspaceKey(tenantId, u.keyVersion, deriveSubkeys(u.dek));
    } finally {
      if (u.dek instanceof Uint8Array) u.dek.fill(0);
    }
  }

  get disposed(): boolean {
    return this.#sub === null;
  }

  /** Zero the subkeys. Idempotent. Every later use throws. */
  dispose(): void {
    const s = this.#sub;
    this.#sub = null;
    if (s) {
      s.enc.fill(0);
      s.idx.fill(0);
      s.hash.fill(0);
    }
  }

  private sub(): Subkeys {
    if (!this.#sub) throw new EnvelopeError('workspace key was disposed');
    return this.#sub;
  }

  /** Start the in-memory counter at the durable sum of enc_progress.values_sealed for this key_version (KTD11). */
  startCounter(sealedSoFar: number | bigint | string): void {
    this.sub();
    this.#counter = new EncryptionCounter(this.keyVersion, sealedSoFar);
  }

  /** True once the key_version reached ROTATE_AT (the call is refused before any seal). */
  get mustRotate(): boolean {
    return this.#counter?.mustRotate ?? true;
  }

  /** Seal one value of one row (AAD: tenant, table, plain column, row id, key_version). Counts it first. */
  seal(table: string, column: string, rowId: number | string | bigint, plaintext: string): Buffer {
    const s = this.sub();
    if (!this.#counter) throw new SealRefused('seal counter not started');
    try {
      this.#counter.add(1);
    } catch {
      throw new SealRefused('the seal budget of this key_version is used up; rotate first');
    }
    this.#pending.set(table, (this.#pending.get(table) ?? 0) + 1);
    return sealValue(s.enc, this.keyVersion, { tenant: this.tenantId, table, column, rowId }, plaintext);
  }

  /** Open one value; throws on any mismatch (key, tenant, table, column, row id, key_version) or bad UTF-8. */
  open(table: string, column: string, rowId: number | string | bigint, sealed: Uint8Array): string {
    const b = openValue(this.sub().enc, this.keyVersion, { tenant: this.tenantId, table, column, rowId }, sealed);
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(b);
    } finally {
      b.fill(0);
    }
  }

  indexHmac(purpose: IndexHmacPurpose, value: string): Buffer {
    return indexHmac(this.sub().idx, purpose, value);
  }

  /** The keyed form of a plain SHA-256 (hex) for `purpose`. */
  keyedSha(purpose: DigestPurpose, plainHex: string): Buffer {
    if (!/^[0-9a-f]{64}$/i.test(plainHex)) throw new EnvelopeError('digest must be 64 hex characters');
    return keyedDigest(this.sub().hash, purpose, Buffer.from(plainHex, 'hex'));
  }

  /**
   * C8-0 KTD-A: the sealed copy of one row's plain source digest, as the pair to append to the row's SealedColumns.
   * The plaintext is exactly the 64 LOWERCASE hex characters the importers compute (digest('hex')); anything else
   * is refused, so open(copy) can go straight into keyedSha. Sealed through seal: it counts 1 like any value.
   */
  sealDigest(table: string, rowId: number | string | bigint, plainHex: string): [string, Buffer] {
    if (!SEALED_DIGEST_TABLES.includes(table)) throw new EnvelopeError('sealDigest: not a sealed digest table');
    if (typeof plainHex !== 'string' || !/^[0-9a-f]{64}$/.test(plainHex)) throw new EnvelopeError('digest must be 64 lowercase hex characters');
    return [SEALED_DIGEST_COLUMN, this.seal(table, 'source_sha256', rowId, plainHex)];
  }

  /** chunks.text_hmac: keyedDigest('text', sha256(UTF-8 text)). */
  textHmac(text: string): Buffer {
    return keyedDigest(this.sub().hash, 'text', createHash('sha256').update(text, 'utf8').digest());
  }

  /** quarantine.source_uri on the sealed route (C6 KTD12): no plain uri, not linkable to stored rows. */
  quarantineRef(uri: string): string {
    return `hmac:${this.indexHmac('quarantine-uri', uri).toString('hex')}`;
  }

  /** C7 KTD6: seal one B1 index object; counts 1 under `notes` (the budget sums every table per key_version). */
  sealIndex(obj: B1Object, packed: Uint8Array): Buffer {
    const s = this.sub();
    if (!this.#counter) throw new SealRefused('seal counter not started');
    try {
      this.#counter.add(1);
    } catch {
      throw new SealRefused('the seal budget of this key_version is used up; rotate first');
    }
    this.#pending.set('notes', (this.#pending.get('notes') ?? 0) + 1);
    return sealIndexObject(s.enc, this.keyVersion, b1Ref(this.tenantId, obj), packed);
  }

  /** Open one B1 index object; throws on any mismatch (tenant, kind, object no, key_version) or a bad tag. */
  openIndex(obj: B1Object, sealed: Uint8Array): Buffer {
    return openIndexObject(this.sub().enc, this.keyVersion, b1Ref(this.tenantId, obj), sealed);
  }

  /** C7 KTD2: the B1 cache check value of this (workspace, key_version): indexHmac('b1-cache-check', tenant). */
  cacheCheck(): Buffer {
    return indexHmac(this.sub().idx, 'b1-cache-check', this.tenantId);
  }

  /** Values sealed since the last call, per table (flushed into enc_progress inside the write transaction). */
  takePending(): Array<[string, number]> {
    const out = [...this.#pending.entries()].filter(([, n]) => n > 0).sort(([a], [b]) => (a < b ? -1 : 1));
    this.#pending.clear();
    return out;
  }
}

/** One B1 index object (C7 KTD6): a base shard, a per-transaction segment, or the manifest of one key_version. */
export type B1Object = { kind: 'base'; no: number } | { kind: 'segment'; no: number } | { kind: 'manifest' };

function b1Ref(tenant: string, o: B1Object) {
  if (o.kind !== 'manifest' && (!Number.isSafeInteger(o.no) || o.no < 0)) throw new EnvelopeError('index object number out of range');
  return o.kind === 'base' ? { kind: 'main-shard' as const, tenant, shardId: o.no }
    : o.kind === 'segment' ? { kind: 'delta-shard' as const, tenant, shardId: o.no }
      : { kind: 'manifest' as const, tenant };
}

/** A row of another key_version than the session's (a rotation this session predates): the read is refused. */
export class RowKeyVersionMismatch extends Error {
  override name = 'RowKeyVersionMismatch';
  constructor() {
    super('row key_version differs from the session key');
  }
}

/** Plain columns whose stored text is JSON on a sealed row (C6 KTD6 encodings). */
const JSON_COLUMNS: Readonly<Record<string, readonly string[]>> = { notes: ['frontmatter'], decisions: ['applies_to'] };

/**
 * C7 KTD7 (`rowValue`, one rule for both row shapes): the plain values of `columns` of one overlay-table row.
 * key_version NULL: the plain columns as selected. Otherwise every `<column>_ct` is opened under the row's AAD
 * (table, plain column, row.id, the key's key_version): frontmatter and applies_to are JSON-decoded (C6 KTD6),
 * a NULL `_ct` is NULL. A row of another key_version throws RowKeyVersionMismatch; a tag failure throws
 * EnvelopeError: the caller fails closed, never a partial or substituted value.
 */
export function openedRow(key: WorkspaceKey, table: string, row: Readonly<Record<string, unknown>>, columns: readonly string[]): Record<string, unknown> {
  const t = OVERLAY_SPEC.find((x) => x.table === table);
  if (!t) throw new EnvelopeError('openedRow: not an overlay table');
  const kv = row['key_version'];
  const out: Record<string, unknown> = {};
  if (kv === null || kv === undefined) {
    for (const c of columns) out[c] = row[c] ?? null;
    return out;
  }
  if (Number(kv) !== key.keyVersion) throw new RowKeyVersionMismatch();
  const id = row['id'];
  if (typeof id !== 'number' && typeof id !== 'string' && typeof id !== 'bigint') throw new EnvelopeError('openedRow: the row id is missing');
  for (const c of columns) {
    if (!t.columns.some((x) => x.plain === c)) throw new EnvelopeError(`openedRow: ${table}.${c} is not an overlay column`);
    const ct = row[`${c}_ct`];
    if (ct === null || ct === undefined) {
      out[c] = null;
      continue;
    }
    if (!(ct instanceof Uint8Array)) throw new EnvelopeError('openedRow: a sealed value is not bytes');
    const v = key.open(table, c, typeof id === 'bigint' ? id : String(id), ct);
    out[c] = (JSON_COLUMNS[table] ?? []).includes(c) ? JSON.parse(v) as unknown : v;
  }
  return out;
}

/**
 * C8-0 KTD-A "Consistency" (review r1 P2-2): may a later rotate or decrypt trust this row's sealed digest copy? True
 * only when the copy is present, opens under its own row's AAD (table, 'source_sha256', row.id) to 64 lowercase hex
 * characters, and keyedSha('source_sha256', that) equals the stored source_sha256 byte for byte. Every other case
 * (NULL, a copy moved from another row, a broken ciphertext, a stale copy whose keyed digest was rewritten) is
 * false; it never throws.
 */
export function digestCopyMatches(key: WorkspaceKey, table: string, row: Readonly<Record<string, unknown>>): boolean {
  try {
    if (!SEALED_DIGEST_TABLES.includes(table)) return false;
    const copy = row[SEALED_DIGEST_COLUMN];
    const stored = row['source_sha256'];
    const id = row['id'];
    if (!(copy instanceof Uint8Array) || !(stored instanceof Uint8Array)) return false;
    if (typeof id !== 'number' && typeof id !== 'string' && typeof id !== 'bigint') return false;
    const hex = key.open(table, 'source_sha256', typeof id === 'bigint' ? id : String(id), copy);
    if (!/^[0-9a-f]{64}$/.test(hex)) return false;
    const want = key.keyedSha('source_sha256', hex);
    return want.length === stored.length && timingSafeEqual(want, stored);
  } catch {
    return false;
  }
}

/** The stored HMAC of one overlay column (KTD5). */
function hmacFor(key: WorkspaceKey, table: string, column: string, value: string): Buffer {
  if (column === 'vault_path') return key.indexHmac('vault_path', value);
  if (column === 'source_uri' || column === 'target_uri') return key.indexHmac('uri', value);
  if (table === 'chunks' && column === 'text') return key.textHmac(value);
  throw new EnvelopeError(`no HMAC rule for ${table}.${column}`);
}

/** Column -> value pairs for one sealed row: key_version, every _ct and _hmac, every plain / derived column NULL. */
export type SealedColumns = Array<[string, Buffer | number | null]>;

/**
 * KTD6: the sealed form of one row of an overlay table. `values` must name EVERY plain column of the
 * table's OVERLAY_SPEC entry (an optional column as null) and nothing else.
 */
export function sealRow(key: WorkspaceKey, table: string, rowId: number | string | bigint, values: Readonly<Record<string, string | null>>): SealedColumns {
  const t = OVERLAY_SPEC.find((x) => x.table === table);
  if (!t) throw new EnvelopeError('sealRow: not an overlay table');
  for (const k of Object.keys(values)) {
    if (!t.columns.some((c) => c.plain === k)) throw new EnvelopeError(`sealRow: ${table}.${k} is not an overlay column`);
  }
  const out: SealedColumns = [['key_version', key.keyVersion]];
  for (const c of t.columns) {
    if (!Object.prototype.hasOwnProperty.call(values, c.plain)) throw new EnvelopeError(`sealRow: ${table}.${c.plain} was not given`);
    const v = values[c.plain];
    if (v === null || v === undefined) {
      if (c.required) throw new EnvelopeError(`sealRow: ${table}.${c.plain} is required`);
      out.push([`${c.plain}_ct`, null]);
    } else {
      if (typeof v !== 'string') throw new EnvelopeError(`sealRow: ${table}.${c.plain} must be text`);
      out.push([`${c.plain}_ct`, key.seal(table, c.plain, rowId, v)]);
      if (c.hmac) out.push([`${c.plain}_hmac`, hmacFor(key, table, c.plain, v)]);
    }
    out.push([c.plain, null]);
  }
  for (const d of t.derived) out.push([d, null]);
  return out;
}

/** One SQL value: `[column, value, cast]` (cast without `::`, e.g. 'zeusi.scope'). */
export type SqlCol = [string, unknown, string?];

function castOf(col: string, v: unknown, cast?: string): string {
  if (cast) return cast;
  if (col === 'key_version') return 'smallint';
  if (Buffer.isBuffer(v) || v instanceof Uint8Array || col.endsWith('_ct') || col.endsWith('_hmac')) return 'bytea';
  return '';
}

/**
 * C8-0 KTD-A "App rule" (review r1 P1-2), owned here only: a sealed row of notes, facts, decisions or decision_links
 * that sets source_sha256 also carries its sealed copy (sealDigest). Refused before any SQL exists. A statement that
 * does not set source_sha256 (chunks, a metadata-only UPDATE) is not affected.
 */
function assertDigestCopy(table: string, meta: readonly SqlCol[], sealed: SealedColumns): void {
  if (!SEALED_DIGEST_TABLES.includes(table)) return;
  if (!meta.some(([c]) => c === 'source_sha256')) return;
  if (!sealed.some(([c, v]) => c === SEALED_DIGEST_COLUMN && Buffer.isBuffer(v))) throw new EnvelopeError('source_sha256 without its sealed copy');
}

/** INSERT INTO zeusi.<table> (meta..., sealed...) VALUES (...) [suffix]. Values are parameters only. */
export function sealedInsertSql(table: string, meta: readonly SqlCol[], sealed: SealedColumns, suffix = ''): { sql: string; params: unknown[] } {
  if (!OVERLAY_TABLES.includes(table)) throw new EnvelopeError('not an overlay table');
  assertDigestCopy(table, meta, sealed);
  const cols = [...meta, ...sealed.map(([c, v]) => [c, v] as SqlCol)];
  const params = cols.map(([, v]) => v);
  const ph = cols.map(([c, v, cast], i) => {
    const t = castOf(c, v, cast);
    return t ? `$${i + 1}::${t}` : `$${i + 1}`;
  });
  return { sql: `INSERT INTO zeusi.${table} (${cols.map(([c]) => c).join(', ')}) VALUES (${ph.join(', ')})${suffix ? ` ${suffix}` : ''}`, params };
}

/** UPDATE zeusi.<table> SET (meta..., sealed...) WHERE id = <id>. */
export function sealedUpdateSql(table: string, id: number, meta: readonly SqlCol[], sealed: SealedColumns, suffix = ''): { sql: string; params: unknown[] } {
  if (!OVERLAY_TABLES.includes(table)) throw new EnvelopeError('not an overlay table');
  assertDigestCopy(table, meta, sealed);
  const cols = [...meta, ...sealed.map(([c, v]) => [c, v] as SqlCol)];
  const params: unknown[] = [...cols.map(([, v]) => v), id];
  const set = cols.map(([c, v, cast], i) => {
    const t = castOf(c, v, cast);
    return `${c} = ${t ? `$${i + 1}::${t}` : `$${i + 1}`}`;
  });
  return { sql: `UPDATE zeusi.${table} SET ${set.join(', ')} WHERE id = $${cols.length + 1}${suffix ? ` ${suffix}` : ''}`, params };
}

/** One id from the table's own sequence (§4.1a: the AAD needs the id before the INSERT). */
export async function nextId(db: Db, table: string, n = 1): Promise<number[]> {
  if (!OVERLAY_TABLES.includes(table)) throw new EnvelopeError('not an overlay table');
  if (n <= 0) return [];
  const r = await db.query<{ id: string }>(
    `SELECT nextval(pg_get_serial_sequence('zeusi.${table}', 'id'))::text AS id FROM generate_series(1, $1::int)`, [n]);
  return r.rows.map((x) => Number(x.id));
}

/** KTD11: the durable sum of values sealed under this key_version (all tables). */
export async function sealedSoFar(db: Db, keyVersion: number): Promise<string> {
  const r = await db.query<{ n: string }>(`SELECT coalesce(sum(values_sealed), 0)::text AS n FROM zeusi.${ENC_PROGRESS_TABLE} WHERE key_version = $1`, [keyVersion]);
  return r.rows[0]?.n ?? '0';
}

/** KTD11: add the values sealed since the last flush to enc_progress (never phase, cursor or row counts). */
export async function flushProgress(db: Db, key: WorkspaceKey): Promise<void> {
  for (const [table, n] of key.takePending()) {
    await db.query(
      `INSERT INTO zeusi.${ENC_PROGRESS_TABLE} (key_version, table_name, values_sealed) VALUES ($1, $2, $3)
       ON CONFLICT (key_version, table_name) DO UPDATE SET values_sealed = ${ENC_PROGRESS_TABLE}.values_sealed + EXCLUDED.values_sealed, updated_at = now()`,
      [key.keyVersion, table, n]);
  }
}

/**
 * KTD9 mixed-shape guard: does any row of the five tables have a key_version other than `kv` (a plain
 * row left in verified, or a row of another key_version after a rotation this session predates)?
 */
export async function mixedShape(db: Db, kv: number): Promise<boolean> {
  const r = await db.query<{ mixed: boolean }>(
    `SELECT (${OVERLAY_TABLES.map((t) => `EXISTS (SELECT 1 FROM zeusi.${t} WHERE key_version IS DISTINCT FROM $1::smallint)`).join(' OR ')}) AS mixed`, [kv]);
  return r.rows[0]?.mixed !== false;
}

/** KTD9 usage bytes: the plain body, else the ciphertext length minus the sealed overhead (29). */
export const SEALED_BODY_BYTES_SQL = `coalesce(octet_length(body), octet_length(body_ct) - ${SEALED_MIN_BYTES}, 0)`;
