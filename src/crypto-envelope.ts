// Envelope crypto for workspace encryption, option B (docs/plans/2026-11-18-zeusi-workspace-encryption.md
// §4.1, §4.1a; chip plan docs/plans/2026-11-18-c1-crypto-envelope.md).
//
// WIRED ONLY THROUGH TWO FILES (a test pins the import lists): src/workspace-keys.ts (C4: DEK wrap /
// unwrap, KEKs) and src/workspace-seal.ts (C6: value seal / open and the keyed HMACs of the workspace
// write path, docs/plans/2026-11-19-c6-write-path.md KTD4-KTD6). Nothing else imports it. It does not
// mean any workspace is encrypted: that needs ZEUSI_WORKSPACE_ENCRYPTION=on (or enroll) and a
// workspace in state verified or on. The self-hosted default is off. C2's preview staging seal
// (src/preview-seal.ts) is separate and stays as it is.
//
// What it pins:
//   * AES-256-GCM (Node built-in), one seal per field value, a random 96-bit nonce per seal, 128-bit tag.
//     Sealed blob = 0x01 (format) || nonce (12) || ciphertext || tag (16).
//   * HKDF-SHA256 subkeys from the per-workspace DEK: K_enc (AEAD), K_idx (index HMAC), K_hash (keyed
//     content hashes).
//   * AAD v1: "zeusi-aad-v1", then each field as (u16 big-endian length, UTF-8 bytes). Never joined text.
//       data value : (tenant, table, column, row id as decimal string, key_version)
//       wrap       : (tenant, wrap_id, key_version)
//       B1 index   : (tenant, type tag, object id, key_version); tags b1-main-shard, b1-delta-shard,
//                    b1-manifest (the tombstone list lives inside the manifest).
//   * KEKs: passkey HKDF(PRF output, salt = wrap_id, "zeusi-kek-v1"); recovery code (128 bits)
//     HKDF(code, salt = wrap_id, "zeusi-recovery-v1"); session HKDF(token, salt = grant id,
//     "zeusi-session-access-v1" | "zeusi-session-refresh-v1").
//   * Keyed hashes (C6 KTD5): HMAC-SHA256 over "zeusi-hmac-v1", then (u16 big-endian length, bytes) for
//     the purpose and the value. indexHmac(K_idx, purpose, UTF-8 value): purposes vault_path, uri,
//     quarantine-uri, b1-cache-check (C7). keyedDigest(K_hash, purpose, 32-byte SHA-256): purposes source_sha256, text.
//   * Per-version encryption counter: at 2^30 values sealed under one key_version, the next write
//     must rotate the DEK. The durable counter row is enc_progress (chip C5a); this file is pure.
//
// key_version contract (r3 review R3-1): key_version is an explicit argument of every seal, open, wrap
// and unwrap and is always inside the AAD, so a ciphertext opened under another key_version fails its
// tag. The per-row `key_version smallint` column (NULL = plain) and the stamp_provenance comparison of
// OLD/NEW key_version are DDL for chip C5a; callers pass the row's column value here.
//
// B1 index (C7, docs/plans/2026-11-19-c7-read-path.md KTD5, KTD6): src/workspace-seal.ts is the one caller of
// the index-object seal / open below (base shard = main-shard, per-transaction segment = delta-shard, manifest).
// This module seals and opens opaque, packed shard bytes only. It offers no unpacked
// JavaScript-Map form of the index, and C6/C7 must keep the index packed (C0 measured the map form at
// 244 MiB heap per 50 MiB copy: docs/plans/2026-11-18-c0-results.md l.41). The B1 cache is chip C7:
// one unlocked packed copy per (tenant, key_version), used only after the request proves it holds
// that grant's session wrap (the owner, 2026-11-18, 20:36 Zurich, D13). This module does not implement it.
//
// Errors never carry key bytes, plaintext, AAD fields, tokens or codes.

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto';

export const AEAD_ALGORITHM = 'aes-256-gcm';
export const AAD_LABEL_V1 = 'zeusi-aad-v1';
export const FORMAT_V1 = 0x01;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const KEY_BYTES = 32;
export const RECOVERY_CODE_BYTES = 16;
export const MIN_PRF_BYTES = 32;
export const MIN_TOKEN_BYTES = 32;
export const MAX_KEY_VERSION = 32767; // fits the smallint column R3-1 proposes (C5a)
/** Once this many values were sealed under one key_version, the next write must rotate the DEK. */
export const ROTATE_AT = 2 ** 30;
/** Random 96-bit nonces under one key are safe up to about 2^32 seals (plan §4.1); no write may pass it. */
export const NONCE_HARD_LIMIT = 2 ** 32;

export const INFO_K_ENC = 'zeusi-k-enc-v1';
export const INFO_K_IDX = 'zeusi-k-idx-v1';
export const INFO_K_HASH = 'zeusi-k-hash-v1';
export const INFO_KEK_PASSKEY = 'zeusi-kek-v1';
export const INFO_KEK_RECOVERY = 'zeusi-recovery-v1';
export const INFO_KEK_SESSION_ACCESS = 'zeusi-session-access-v1';
export const INFO_KEK_SESSION_REFRESH = 'zeusi-session-refresh-v1';

export const HMAC_LABEL_V1 = 'zeusi-hmac-v1';
export const HMAC_OUT_BYTES = 32;
export const SHA256_BYTES = 32;
/**
 * indexHmac purposes (C6 KTD5): one `uri` purpose for every source_uri / target_uri, so C7 can join on it.
 * C7 KTD2 adds `b1-cache-check`: the per-(workspace, key_version) check value of the B1 cache (memory only).
 */
export const INDEX_HMAC_PURPOSES = ['vault_path', 'uri', 'quarantine-uri', 'b1-cache-check'] as const;
export type IndexHmacPurpose = (typeof INDEX_HMAC_PURPOSES)[number];
/** keyedDigest purposes (C6 KTD5). */
export const DIGEST_PURPOSES = ['source_sha256', 'text'] as const;
export type DigestPurpose = (typeof DIGEST_PURPOSES)[number];

export const INDEX_TAG = {
  'main-shard': 'b1-main-shard',
  'delta-shard': 'b1-delta-shard',
  manifest: 'b1-manifest',
} as const;
const MANIFEST_OBJECT_ID = 'manifest';

// Copy of TENANT_ID_RE (src/tenant-ddl.ts:36), so this module depends on node:crypto only; a test pins
// the copy. the team's workspace ('work') is out of scope for workspace encryption.
const TENANT_RE = /^zt_[a-z2-7]{26}$/;
const IDENT_RE = /^[a-z_][a-z0-9_]{0,62}$/;
const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;
const MAX_BIGINT = (1n << 63n) - 1n;
const MAX_ID_BYTES = 255;

export class EnvelopeError extends Error {
  override name = 'EnvelopeError';
}

export type Bytes = Uint8Array;
export type IntegerId = bigint | number | string;

/** A field value of one table row (parent plan §4.1). */
export interface ValueRef {
  readonly tenant: string;
  readonly table: string;
  readonly column: string;
  /** The row's id, known before INSERT (§4.1a: ids are pre-allocated with nextval()). */
  readonly rowId: IntegerId;
}

/** A wrapped DEK (catalog key_wraps row, or a session wrap beside an OAuth grant). */
export interface WrapRef {
  readonly tenant: string;
  readonly wrapId: string;
}

export type IndexObjectKind = keyof typeof INDEX_TAG;

export type IndexRef =
  | { readonly kind: 'main-shard'; readonly tenant: string; readonly shardId: IntegerId }
  | { readonly kind: 'delta-shard'; readonly tenant: string; readonly shardId: IntegerId }
  | { readonly kind: 'manifest'; readonly tenant: string };

export interface Subkeys {
  /** AEAD key for values and index objects. */
  readonly enc: Buffer;
  /** HMAC key for blind-index style lookups. */
  readonly idx: Buffer;
  /** HMAC key for keyed content hashes (e.g. *_hmac columns). */
  readonly hash: Buffer;
}

export type SessionTokenKind = 'access' | 'refresh';

// ---------------------------------------------------------------- validation

function fail(msg: string): never {
  throw new EnvelopeError(msg);
}

function asBytes(v: unknown, what: string): Buffer {
  if (v instanceof Uint8Array) return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
  return fail(`${what} must be bytes`);
}

function key32(v: unknown, what: string): Buffer {
  const b = asBytes(v, what);
  if (b.length !== KEY_BYTES) fail(`${what} must be ${KEY_BYTES} bytes`);
  return b;
}

function checkKeyVersion(kv: unknown): string {
  if (typeof kv !== 'number' || !Number.isInteger(kv) || kv < 1 || kv > MAX_KEY_VERSION) {
    fail(`key_version must be an integer from 1 to ${MAX_KEY_VERSION}`);
  }
  return String(kv);
}

function checkTenant(t: unknown): string {
  if (typeof t !== 'string' || !TENANT_RE.test(t)) fail('tenant must be a personal workspace id');
  return t;
}

function checkIdent(v: unknown, what: string): string {
  if (typeof v !== 'string' || !IDENT_RE.test(v)) fail(`${what} must be a lower-case SQL identifier`);
  return v;
}

function checkIntegerId(v: unknown, what: string): string {
  let s: string;
  if (typeof v === 'bigint') s = v.toString();
  else if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) fail(`${what} must be a non-negative integer`);
    s = String(v);
  } else if (typeof v === 'string') s = v;
  else return fail(`${what} must be a non-negative integer`);
  if (!DECIMAL_RE.test(s) || BigInt(s) > MAX_BIGINT) fail(`${what} must be a non-negative integer`);
  return s;
}

function checkOpaqueId(v: unknown, what: string): string {
  if (typeof v !== 'string' || v.length === 0) fail(`${what} must be a non-empty string`);
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) fail(`${what} must not contain control characters`);
  // Lone UTF-16 surrogates would all encode to U+FFFD, so two different ids could share one AAD / KEK.
  if (Buffer.from(v, 'utf8').toString('utf8') !== v) fail(`${what} must be well-formed text`);
  if (Buffer.byteLength(v, 'utf8') > MAX_ID_BYTES) fail(`${what} is too long`);
  return v;
}

// ---------------------------------------------------------------- AAD v1

/** "zeusi-aad-v1" || for each field: u16 big-endian byte length || UTF-8 bytes. Injective over lists. */
function encodeAadV1(fields: readonly string[]): Buffer {
  const parts: Buffer[] = [Buffer.from(AAD_LABEL_V1, 'utf8')];
  for (const f of fields) {
    const b = Buffer.from(f, 'utf8');
    if (b.length > 0xffff) fail('AAD field too long');
    const len = Buffer.alloc(2);
    len.writeUInt16BE(b.length);
    parts.push(len, b);
  }
  return Buffer.concat(parts);
}

/** AAD of one field value: (tenant, table, column, row id, key_version). */
export function valueAad(ref: ValueRef, keyVersion: number): Buffer {
  return encodeAadV1([
    checkTenant(ref.tenant),
    checkIdent(ref.table, 'table'),
    checkIdent(ref.column, 'column'),
    checkIntegerId(ref.rowId, 'row id'),
    checkKeyVersion(keyVersion),
  ]);
}

/** AAD of a wrapped DEK: (tenant, wrap_id, key_version). */
export function wrapAad(ref: WrapRef, keyVersion: number): Buffer {
  return encodeAadV1([checkTenant(ref.tenant), checkOpaqueId(ref.wrapId, 'wrap id'), checkKeyVersion(keyVersion)]);
}

/** AAD of a B1 main (base) shard: (tenant, "b1-main-shard", shard id, key_version). */
export function mainShardAad(tenant: string, shardId: IntegerId, keyVersion: number): Buffer {
  return encodeAadV1([checkTenant(tenant), INDEX_TAG['main-shard'], checkIntegerId(shardId, 'shard id'), checkKeyVersion(keyVersion)]);
}

/** AAD of a B1 delta shard: (tenant, "b1-delta-shard", shard id, key_version). */
export function deltaShardAad(tenant: string, shardId: IntegerId, keyVersion: number): Buffer {
  return encodeAadV1([checkTenant(tenant), INDEX_TAG['delta-shard'], checkIntegerId(shardId, 'shard id'), checkKeyVersion(keyVersion)]);
}

/** AAD of the B1 manifest (which also holds the tombstone list): (tenant, "b1-manifest", "manifest", key_version). */
export function manifestAad(tenant: string, keyVersion: number): Buffer {
  return encodeAadV1([checkTenant(tenant), INDEX_TAG.manifest, MANIFEST_OBJECT_ID, checkKeyVersion(keyVersion)]);
}

function indexAad(ref: IndexRef, keyVersion: number): Buffer {
  switch (ref.kind) {
    case 'main-shard':
      return mainShardAad(ref.tenant, ref.shardId, keyVersion);
    case 'delta-shard':
      return deltaShardAad(ref.tenant, ref.shardId, keyVersion);
    case 'manifest':
      return manifestAad(ref.tenant, keyVersion);
    default:
      return fail('unknown index object kind');
  }
}

// ---------------------------------------------------------------- AEAD core (not exported)

function aeadSeal(key: Buffer, aad: Buffer, plaintext: Buffer): Buffer {
  const nonce = randomBytes(NONCE_BYTES);
  const c = createCipheriv(AEAD_ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([Buffer.of(FORMAT_V1), nonce, ct, c.getAuthTag()]);
}

function aeadOpen(key: Buffer, aad: Buffer, sealed: Buffer): Buffer {
  if (sealed.length < 1 + NONCE_BYTES + TAG_BYTES) fail('sealed value too short');
  if (sealed[0] !== FORMAT_V1) fail('unknown sealed format');
  const nonce = sealed.subarray(1, 1 + NONCE_BYTES);
  const tag = sealed.subarray(sealed.length - TAG_BYTES);
  const ct = sealed.subarray(1 + NONCE_BYTES, sealed.length - TAG_BYTES);
  const d = createDecipheriv(AEAD_ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
  d.setAAD(aad);
  d.setAuthTag(tag);
  try {
    return Buffer.concat([d.update(ct), d.final()]);
  } catch {
    return fail('authentication failed');
  }
}

function plainBytes(p: unknown): Buffer {
  if (typeof p === 'string') return Buffer.from(p, 'utf8');
  return asBytes(p, 'plaintext');
}

// ---------------------------------------------------------------- keyed hashes (C6 KTD5)

/** "zeusi-hmac-v1" || u16 len || purpose || u16 len || value (the AAD v1 field encoding, another label). */
function hmacV1(key: Buffer, purpose: string, value: Buffer): Buffer {
  const p = Buffer.from(purpose, 'utf8');
  if (value.length > 0xffff) fail('HMAC value too long');
  const lp = Buffer.alloc(2);
  lp.writeUInt16BE(p.length);
  const lv = Buffer.alloc(2);
  lv.writeUInt16BE(value.length);
  return createHmac('sha256', key).update(Buffer.from(HMAC_LABEL_V1, 'utf8')).update(lp).update(p).update(lv).update(value).digest();
}

/** Deterministic HMAC of a lookup value (vault path, uri) under K_idx: equality and joins without the value. */
export function indexHmac(kIdx: Bytes, purpose: IndexHmacPurpose, value: string): Buffer {
  if (!(INDEX_HMAC_PURPOSES as readonly string[]).includes(purpose)) fail('unknown index HMAC purpose');
  if (typeof value !== 'string') fail('HMAC value must be text');
  if (Buffer.from(value, 'utf8').toString('utf8') !== value) fail('HMAC value must be well-formed text');
  return hmacV1(key32(kIdx, 'K_idx'), purpose, Buffer.from(value, 'utf8'));
}

/** Keyed form of a plain SHA-256 digest under K_hash: what a sealed row stores instead of the digest. */
export function keyedDigest(kHash: Bytes, purpose: DigestPurpose, sha256: Bytes): Buffer {
  if (!(DIGEST_PURPOSES as readonly string[]).includes(purpose)) fail('unknown digest purpose');
  const d = asBytes(sha256, 'digest');
  if (d.length !== SHA256_BYTES) fail(`digest must be ${SHA256_BYTES} bytes`);
  return hmacV1(key32(kHash, 'K_hash'), purpose, d);
}

// ---------------------------------------------------------------- keys

/** A fresh 256-bit DEK for one key_version of one workspace. */
export function generateDek(): Buffer {
  return randomBytes(KEY_BYTES);
}

/** A fresh 128-bit recovery code (raw bytes; its text form for display and entry is chip C4). */
export function generateRecoveryCode(): Buffer {
  return randomBytes(RECOVERY_CODE_BYTES);
}

/** HKDF-SHA256 (RFC 5869). */
export function hkdfSha256(ikm: Bytes, salt: Bytes, info: Bytes | string, length: number): Buffer {
  const i = typeof info === 'string' ? Buffer.from(info, 'utf8') : asBytes(info, 'info');
  return Buffer.from(hkdfSync('sha256', asBytes(ikm, 'ikm'), asBytes(salt, 'salt'), i, length));
}

/** K_enc, K_idx and K_hash from one DEK (distinct HKDF info labels, empty salt). */
export function deriveSubkeys(dek: Bytes): Subkeys {
  const d = key32(dek, 'DEK');
  const empty = Buffer.alloc(0);
  return {
    enc: hkdfSha256(d, empty, INFO_K_ENC, KEY_BYTES),
    idx: hkdfSha256(d, empty, INFO_K_IDX, KEY_BYTES),
    hash: hkdfSha256(d, empty, INFO_K_HASH, KEY_BYTES),
  };
}

/** KEK from a WebAuthn PRF output. The raw PRF output is never used as the KEK itself. */
export function passkeyKek(prfOutput: Bytes, wrapId: string): Buffer {
  const prf = asBytes(prfOutput, 'PRF output');
  if (prf.length < MIN_PRF_BYTES) fail(`PRF output must be at least ${MIN_PRF_BYTES} bytes`);
  return hkdfSha256(prf, Buffer.from(checkOpaqueId(wrapId, 'wrap id'), 'utf8'), INFO_KEK_PASSKEY, KEY_BYTES);
}

/** KEK from a 128-bit recovery code (raw bytes). A fast KDF is enough for 128 random bits. */
export function recoveryKek(code: Bytes, wrapId: string): Buffer {
  const c = asBytes(code, 'recovery code');
  if (c.length !== RECOVERY_CODE_BYTES) fail(`recovery code must be ${RECOVERY_CODE_BYTES} bytes`);
  return hkdfSha256(c, Buffer.from(checkOpaqueId(wrapId, 'wrap id'), 'utf8'), INFO_KEK_RECOVERY, KEY_BYTES);
}

/**
 * KEK of a session wrap from an OAuth access or refresh token (the bearer string or its bytes) and the
 * grant id. Domain-separated from the OAuth store's token HMAC (src/mcp-oauth-store.ts:150).
 */
export function sessionKek(token: string | Bytes, grantId: string, kind: SessionTokenKind): Buffer {
  const t = typeof token === 'string' ? Buffer.from(token, 'utf8') : asBytes(token, 'token');
  if (t.length < MIN_TOKEN_BYTES) fail(`token must be at least ${MIN_TOKEN_BYTES} bytes`);
  const info = kind === 'access' ? INFO_KEK_SESSION_ACCESS : kind === 'refresh' ? INFO_KEK_SESSION_REFRESH : fail('unknown session token kind');
  return hkdfSha256(t, Buffer.from(checkOpaqueId(grantId, 'grant id'), 'utf8'), info, KEY_BYTES);
}

// ---------------------------------------------------------------- values, index objects, wraps

/** Seal one field value under K_enc, bound to its row, column, workspace and key_version. */
export function sealValue(kEnc: Bytes, keyVersion: number, ref: ValueRef, plaintext: string | Bytes): Buffer {
  return aeadSeal(key32(kEnc, 'K_enc'), valueAad(ref, keyVersion), plainBytes(plaintext));
}

/** Open one field value; fails unless key, row, column, workspace and key_version all match. */
export function openValue(kEnc: Bytes, keyVersion: number, ref: ValueRef, sealed: Bytes): Buffer {
  return aeadOpen(key32(kEnc, 'K_enc'), valueAad(ref, keyVersion), asBytes(sealed, 'sealed value'));
}

/** Seal one packed B1 index object (main shard, delta shard or manifest). */
export function sealIndexObject(kEnc: Bytes, keyVersion: number, ref: IndexRef, packed: Bytes): Buffer {
  return aeadSeal(key32(kEnc, 'K_enc'), indexAad(ref, keyVersion), asBytes(packed, 'index object'));
}

/** Open one packed B1 index object; a main shard never opens as a delta shard or a manifest. */
export function openIndexObject(kEnc: Bytes, keyVersion: number, ref: IndexRef, sealed: Bytes): Buffer {
  return aeadOpen(key32(kEnc, 'K_enc'), indexAad(ref, keyVersion), asBytes(sealed, 'sealed index object'));
}

/** Wrap a DEK under a KEK, bound to (tenant, wrap_id, key_version). */
export function wrapDek(kek: Bytes, keyVersion: number, ref: WrapRef, dek: Bytes): Buffer {
  return aeadSeal(key32(kek, 'KEK'), wrapAad(ref, keyVersion), key32(dek, 'DEK'));
}

/** Unwrap a DEK; fails without the right KEK, tenant, wrap_id and key_version. */
export function unwrapDek(kek: Bytes, keyVersion: number, ref: WrapRef, wrapped: Bytes): Buffer {
  const dek = aeadOpen(key32(kek, 'KEK'), wrapAad(ref, keyVersion), asBytes(wrapped, 'wrapped DEK'));
  if (dek.length !== KEY_BYTES) fail('wrapped DEK has the wrong length');
  return dek;
}

// ---------------------------------------------------------------- per-version encryption counter

function checkCount(v: unknown, what: string): number {
  let n: number;
  if (typeof v === 'number') n = v;
  else if (typeof v === 'bigint') n = Number(v);
  else if (typeof v === 'string' && DECIMAL_RE.test(v)) n = Number(v);
  else return fail(`${what} must be a non-negative integer`);
  if (!Number.isSafeInteger(n) || n < 0) fail(`${what} must be a non-negative integer`);
  return n;
}

/** True once ROTATE_AT values were sealed under one key_version: the next write must rotate the DEK. */
export function mustRotate(sealedSoFar: number | bigint | string): boolean {
  return checkCount(sealedSoFar, 'count') >= ROTATE_AT;
}

/**
 * Throws before a write when the key_version's counter has reached ROTATE_AT, or when the write of
 * `toSeal` values would take it past NONCE_HARD_LIMIT.
 */
export function assertEncryptionBudget(sealedSoFar: number | bigint | string, toSeal: number = 0): void {
  if (mustRotate(sealedSoFar)) fail('DEK rotation required before the next write');
  if (checkCount(sealedSoFar, 'count') + checkCount(toSeal, 'n') > NONCE_HARD_LIMIT) fail('write too large for one key_version');
}

/** In-memory mirror of one key_version's counter (the durable row is enc_progress, chip C5a). */
export class EncryptionCounter {
  readonly keyVersion: number;
  #count: number;

  constructor(keyVersion: number, start: number | bigint | string = 0) {
    checkKeyVersion(keyVersion);
    this.keyVersion = keyVersion;
    this.#count = checkCount(start, 'start');
  }

  get count(): number {
    return this.#count;
  }

  get mustRotate(): boolean {
    return this.#count >= ROTATE_AT;
  }

  /**
   * Record n values sealed in one write. Refuses a write that starts at or above ROTATE_AT, or that
   * would end above NONCE_HARD_LIMIT.
   */
  add(n: number): void {
    const k = checkCount(n, 'n');
    assertEncryptionBudget(this.#count, k);
    this.#count += k;
  }
}
