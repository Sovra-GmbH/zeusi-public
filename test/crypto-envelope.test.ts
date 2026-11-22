// C1 (docs/plans/2026-11-18-c1-crypto-envelope.md): envelope crypto module, not wired. Hermetic: no DB.
// Every key, PRF output, recovery code and token below is a TEST value (fixed byte patterns), never a
// production secret.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHmac, hkdfSync } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  AAD_LABEL_V1,
  HMAC_LABEL_V1,
  indexHmac,
  keyedDigest,
  assertEncryptionBudget,
  deltaShardAad,
  deriveSubkeys,
  EncryptionCounter,
  EnvelopeError,
  FORMAT_V1,
  generateDek,
  generateRecoveryCode,
  hkdfSha256,
  INFO_K_ENC,
  INFO_K_HASH,
  INFO_K_IDX,
  mainShardAad,
  manifestAad,
  MAX_KEY_VERSION,
  mustRotate,
  NONCE_HARD_LIMIT,
  NONCE_BYTES,
  openIndexObject,
  openValue,
  passkeyKek,
  recoveryKek,
  ROTATE_AT,
  sealIndexObject,
  sealValue,
  sessionKek,
  TAG_BYTES,
  unwrapDek,
  valueAad,
  wrapAad,
  wrapDek,
  type IndexRef,
  type ValueRef,
} from '../src/crypto-envelope.ts';
import { TENANT_ID_RE } from '../src/tenant-ddl.ts';

// ---- test-only material
const T1 = 'zt_' + 'a'.repeat(26);
const T2 = 'zt_' + 'b'.repeat(26);
const TEST_DEK = Buffer.alloc(32, 0x01);
const TEST_KEY = Buffer.alloc(32, 0x11);
const OTHER_KEY = Buffer.alloc(32, 0x12);
const TEST_PRF = Buffer.alloc(32, 0x33);
const TEST_CODE = Buffer.alloc(16, 0x44);
const TEST_TOKEN = 't'.repeat(40);

const hex = (s: string) => Buffer.from(s, 'hex');
const authFail = (fn: () => unknown) => assert.throws(fn, (e: unknown) => e instanceof EnvelopeError && e.message === 'authentication failed');
const ref = (over: Partial<ValueRef> = {}): ValueRef => ({ tenant: T1, table: 'notes', column: 'title', rowId: 42, ...over });

function flip(b: Buffer, i: number): Buffer {
  const c = Buffer.from(b);
  c[i] = (c[i] ?? 0) ^ 0x01;
  return c;
}

// ------------------------------------------------------------------ vectors

test('vector: NIST GCM test case 16 (AES-256, 96-bit IV, AAD) through Node aes-256-gcm', () => {
  // McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", test case 16.
  const K = hex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
  const IV = hex('cafebabefacedbaddecaf888');
  const A = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  const P = hex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
  const C = '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662';
  const Tg = '76fc6ece0f4e1768cddf8853bb2d551b';
  const e = createCipheriv('aes-256-gcm', K, IV);
  e.setAAD(A);
  const ct = Buffer.concat([e.update(P), e.final()]);
  assert.equal(ct.toString('hex'), C);
  assert.equal(e.getAuthTag().toString('hex'), Tg);
});

test('vector: RFC 5869 test case 1 (HKDF-SHA256) through hkdfSha256', () => {
  const okm = hkdfSha256(Buffer.alloc(22, 0x0b), hex('000102030405060708090a0b0c'), hex('f0f1f2f3f4f5f6f7f8f9'), 42);
  assert.equal(okm.toString('hex'), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

test('vector: AAD v1 bytes for a data value are the length-prefixed encoding (hand-built)', () => {
  const expected =
    '7a657573692d6161642d7631' + // "zeusi-aad-v1"
    '001d' + Buffer.from(T1).toString('hex') + // tenant (29 bytes)
    '0005' + Buffer.from('notes').toString('hex') +
    '0005' + Buffer.from('title').toString('hex') +
    '0002' + Buffer.from('42').toString('hex') + // row id as decimal string
    '0001' + Buffer.from('1').toString('hex'); // key_version
  assert.equal(valueAad(ref(), 1).toString('hex'), expected);
  assert.equal(AAD_LABEL_V1, 'zeusi-aad-v1');
});

test('vector: checked-in sealed blob (fixed test key and nonce) opens; layout is 0x01 || nonce || ct || tag', () => {
  // Built once with raw node:crypto under the hand-built AAD above: key 0x11*32, nonce 0x22*12, "hello zeusi".
  const blob = hex('012222222222222222222222227f926b25afefe53a904cb7b3f0689cc20505d40552890cde2e5715');
  assert.equal(openValue(TEST_KEY, 1, ref(), blob).toString('utf8'), 'hello zeusi');
  assert.equal(blob[0], FORMAT_V1);
  // Independent decrypt of the same layout with raw node:crypto.
  const d = createDecipheriv('aes-256-gcm', TEST_KEY, blob.subarray(1, 1 + NONCE_BYTES));
  d.setAAD(valueAad(ref(), 1));
  d.setAuthTag(blob.subarray(blob.length - TAG_BYTES));
  assert.equal(Buffer.concat([d.update(blob.subarray(1 + NONCE_BYTES, blob.length - TAG_BYTES)), d.final()]).toString('utf8'), 'hello zeusi');
});

test('vector: subkeys are HKDF-SHA256(DEK, empty salt, distinct labels) and pinned', () => {
  const s = deriveSubkeys(TEST_DEK);
  const ind = (info: string) => Buffer.from(hkdfSync('sha256', TEST_DEK, Buffer.alloc(0), Buffer.from(info), 32)).toString('hex');
  assert.equal(s.enc.toString('hex'), ind(INFO_K_ENC));
  assert.equal(s.idx.toString('hex'), ind(INFO_K_IDX));
  assert.equal(s.hash.toString('hex'), ind(INFO_K_HASH));
  assert.equal(s.enc.toString('hex'), 'f969e3a1fa6c67878c1dfdcaedc20e22b73cb9387be330eafced3aab203e64c0');
  assert.equal(s.idx.toString('hex'), '4c6c63348bfde3c6056b73da01f55209b0d5e8bf408e1d01c308cda3f4fd3bf2');
  assert.equal(s.hash.toString('hex'), 'f57af0329d408c56d4e000ce52cbcef11ea1d1f7c5b0f6d0e50ca7b3363b1eae');
  assert.equal(new Set([s.enc.toString('hex'), s.idx.toString('hex'), s.hash.toString('hex'), TEST_DEK.toString('hex')]).size, 4);
});

test('vector: KEK derivations match the plan formulas and are pinned', () => {
  const ind = (ikm: Buffer, salt: string, info: string) => Buffer.from(hkdfSync('sha256', ikm, Buffer.from(salt), Buffer.from(info), 32)).toString('hex');
  assert.equal(passkeyKek(TEST_PRF, 'wrap-1').toString('hex'), ind(TEST_PRF, 'wrap-1', 'zeusi-kek-v1'));
  assert.equal(recoveryKek(TEST_CODE, 'wrap-2').toString('hex'), ind(TEST_CODE, 'wrap-2', 'zeusi-recovery-v1'));
  assert.equal(passkeyKek(TEST_PRF, 'wrap-1').toString('hex'), 'c58b987f8bdc015ebc09a3fb543706a7a3b32981c4e751fdbc23bd86aded7f81');
  assert.equal(recoveryKek(TEST_CODE, 'wrap-2').toString('hex'), '7768749384e5b36bb9e01225fc5701f2833280b37726680410601561c544c4b4');
  assert.equal(sessionKek(TEST_TOKEN, 'grant-1', 'access').toString('hex'), 'c3fb81c854d0450aec7379bc1492dbf3e017a37e2f18c09482fd022c775862f1');
  assert.equal(sessionKek(TEST_TOKEN, 'grant-1', 'refresh').toString('hex'), '957dfcce1f5a690fbc99bb4870a2e220035709af514262b1ca9e928433760470');
  // The raw PRF output is never the KEK.
  assert.notEqual(passkeyKek(TEST_PRF, 'wrap-1').toString('hex'), TEST_PRF.toString('hex'));
});

// ------------------------------------------------------------------ round trip, tamper, wrong key

test('round trip: string and bytes values', () => {
  const { enc } = deriveSubkeys(TEST_DEK);
  assert.equal(openValue(enc, 1, ref(), sealValue(enc, 1, ref(), 'Grüße, ✓')).toString('utf8'), 'Grüße, ✓');
  const bytes = Buffer.from([0, 1, 2, 255]);
  assert.deepEqual(openValue(enc, 1, ref(), sealValue(enc, 1, ref(), bytes)), bytes);
  assert.equal(openValue(enc, 1, ref(), sealValue(enc, 1, ref(), '')).length, 0);
});

test('tamper: flipping any byte of nonce, ciphertext or tag fails; unknown format byte is refused', () => {
  const sealed = sealValue(TEST_KEY, 1, ref(), 'tamper me');
  for (let i = 1; i < sealed.length; i++) authFail(() => openValue(TEST_KEY, 1, ref(), flip(sealed, i)));
  assert.throws(() => openValue(TEST_KEY, 1, ref(), flip(sealed, 0)), /unknown sealed format/);
  assert.throws(() => openValue(TEST_KEY, 1, ref(), sealed.subarray(0, 1 + NONCE_BYTES + TAG_BYTES - 1)), /too short/);
  authFail(() => openValue(TEST_KEY, 1, ref(), sealed.subarray(0, sealed.length - 1)));
});

test('wrong key: another K_enc, or K_idx / K_hash / the DEK itself, fails', () => {
  const s = deriveSubkeys(TEST_DEK);
  const sealed = sealValue(s.enc, 1, ref(), 'secret');
  authFail(() => openValue(OTHER_KEY, 1, ref(), sealed));
  authFail(() => openValue(s.idx, 1, ref(), sealed));
  authFail(() => openValue(s.hash, 1, ref(), sealed));
  authFail(() => openValue(TEST_DEK, 1, ref(), sealed));
  authFail(() => openValue(deriveSubkeys(generateDek()).enc, 1, ref(), sealed));
});

test('wrong key_version: a value sealed under v1 does not open as v2 (R3-1: key_version is in the AAD)', () => {
  const sealed = sealValue(TEST_KEY, 1, ref(), 'v1 value');
  authFail(() => openValue(TEST_KEY, 2, ref(), sealed));
  const v7 = sealValue(TEST_KEY, 7, ref(), 'v7 value');
  authFail(() => openValue(TEST_KEY, 1, ref(), v7));
  assert.equal(openValue(TEST_KEY, 7, ref(), v7).toString('utf8'), 'v7 value');
  // key_version is a required, explicit argument everywhere.
  assert.notDeepEqual(valueAad(ref(), 1), valueAad(ref(), 2));
  assert.notDeepEqual(wrapAad({ tenant: T1, wrapId: 'w' }, 1), wrapAad({ tenant: T1, wrapId: 'w' }, 2));
  assert.notDeepEqual(mainShardAad(T1, 0, 1), mainShardAad(T1, 0, 2));
});

// ------------------------------------------------------------------ AAD binding

test('wrong AAD: a value moved to another row, column, table or workspace fails', () => {
  const sealed = sealValue(TEST_KEY, 1, ref(), 'bound');
  authFail(() => openValue(TEST_KEY, 1, ref({ rowId: 43 }), sealed));
  authFail(() => openValue(TEST_KEY, 1, ref({ column: 'body' }), sealed));
  authFail(() => openValue(TEST_KEY, 1, ref({ table: 'facts' }), sealed));
  authFail(() => openValue(TEST_KEY, 1, ref({ tenant: T2 }), sealed));
  // Row id forms are canonical: 42, 42n and "42" are the same row.
  assert.equal(openValue(TEST_KEY, 1, ref({ rowId: 42n }), sealed).toString('utf8'), 'bound');
  assert.equal(openValue(TEST_KEY, 1, ref({ rowId: '42' }), sealed).toString('utf8'), 'bound');
});

test('AAD swap: two sealed values of one row cannot trade columns', () => {
  const title = sealValue(TEST_KEY, 1, ref({ column: 'title' }), 'title');
  const body = sealValue(TEST_KEY, 1, ref({ column: 'body' }), 'body');
  authFail(() => openValue(TEST_KEY, 1, ref({ column: 'body' }), title));
  authFail(() => openValue(TEST_KEY, 1, ref({ column: 'title' }), body));
});

test('AAD separator ambiguity: field lists that collide when |-joined give different AADs and do not open each other', () => {
  // 1) Plain concatenation collisions: ("ab","c") vs ("a","bc"), and (row 11, kv 1) vs (row 1, kv 11).
  const r11 = ref({ rowId: 11 });
  const r1 = ref({ rowId: 1 });
  assert.equal(`${r11.rowId}${1}`, `${r1.rowId}${11}`);
  assert.notDeepEqual(valueAad(r11, 1), valueAad(r1, 11));
  authFail(() => openValue(TEST_KEY, 11, r1, sealValue(TEST_KEY, 1, r11, 'x')));
  const a = ref({ table: 'ab', column: 'c' });
  const b = ref({ table: 'a', column: 'bc' });
  assert.equal(`${a.table}${a.column}`, `${b.table}${b.column}`); // would collide with plain concatenation
  assert.notDeepEqual(valueAad(a, 1), valueAad(b, 1));
  authFail(() => openValue(TEST_KEY, 1, b, sealValue(TEST_KEY, 1, a, 'x')));
  authFail(() => openValue(TEST_KEY, 1, a, sealValue(TEST_KEY, 1, b, 'x')));

  // 2) |-joined collisions: a wrap id may contain '|', so a wrap list and a data or index list can
  //    join to the same text. The length-prefixed AADs differ and nothing opens across them.
  const joined = (fields: string[]) => fields.join('|');
  const data = ref(); // (T1, notes, title, 42, 1)
  const wrapLikeData = { tenant: T1, wrapId: 'notes|title|42' };
  assert.equal(joined([T1, 'notes', 'title', '42', '1']), joined([T1, wrapLikeData.wrapId, '1']));
  assert.notDeepEqual(valueAad(data, 1), wrapAad(wrapLikeData, 1));
  authFail(() => unwrapDek(TEST_KEY, 1, wrapLikeData, sealValue(TEST_KEY, 1, data, TEST_DEK)));
  authFail(() => openValue(TEST_KEY, 1, data, wrapDek(TEST_KEY, 1, wrapLikeData, TEST_DEK)));
  const wrapLikeShard = { tenant: T1, wrapId: 'b1-main-shard|0' };
  assert.equal(joined([T1, 'b1-main-shard', '0', '1']), joined([T1, wrapLikeShard.wrapId, '1']));
  assert.notDeepEqual(mainShardAad(T1, 0, 1), wrapAad(wrapLikeShard, 1));
  const shard = sealIndexObject(TEST_KEY, 1, { kind: 'main-shard', tenant: T1, shardId: 0 }, TEST_DEK);
  authFail(() => unwrapDek(TEST_KEY, 1, wrapLikeShard, shard));
  const w = wrapDek(TEST_KEY, 1, wrapLikeShard, TEST_DEK);
  authFail(() => openIndexObject(TEST_KEY, 1, { kind: 'main-shard', tenant: T1, shardId: 0 }, w));
  assert.deepEqual(unwrapDek(TEST_KEY, 1, wrapLikeShard, w), TEST_DEK);
});

test('chunk vs parent: a parent note source_uri ciphertext does not open under the chunk AAD (§4.1a)', () => {
  const uri = 'hq:project/2026-11-18-some-note.md';
  const parent = ref({ table: 'notes', column: 'source_uri', rowId: 10 });
  const chunk = ref({ table: 'chunks', column: 'source_uri', rowId: 10 });
  const parentCt = sealValue(TEST_KEY, 1, parent, uri);
  authFail(() => openValue(TEST_KEY, 1, chunk, parentCt));
  // The chunk gets its own ciphertext of the same URI under its own AAD.
  const chunkCt = sealValue(TEST_KEY, 1, chunk, uri);
  assert.equal(openValue(TEST_KEY, 1, chunk, chunkCt).toString('utf8'), uri);
  authFail(() => openValue(TEST_KEY, 1, parent, chunkCt));
});

// ------------------------------------------------------------------ B1 index objects

test('B1: main shard, delta shard and manifest AADs are distinct and not interchangeable', () => {
  const kinds: IndexRef[] = [
    { kind: 'main-shard', tenant: T1, shardId: 0 },
    { kind: 'delta-shard', tenant: T1, shardId: 0 },
    { kind: 'manifest', tenant: T1 },
  ];
  const aads = [mainShardAad(T1, 0, 1), deltaShardAad(T1, 0, 1), manifestAad(T1, 1)].map((b) => b.toString('hex'));
  assert.equal(new Set(aads).size, 3);
  const packed = Buffer.from('packed shard bytes');
  for (const from of kinds) {
    const sealed = sealIndexObject(TEST_KEY, 1, from, packed);
    for (const to of kinds) {
      if (to === from) assert.deepEqual(openIndexObject(TEST_KEY, 1, to, sealed), packed);
      else authFail(() => openIndexObject(TEST_KEY, 1, to, sealed));
    }
  }
});

test('B1: a shard is bound to its workspace, shard id and key_version', () => {
  const sealed = sealIndexObject(TEST_KEY, 3, { kind: 'main-shard', tenant: T1, shardId: 5 }, Buffer.from('s5'));
  authFail(() => openIndexObject(TEST_KEY, 3, { kind: 'main-shard', tenant: T1, shardId: 6 }, sealed));
  authFail(() => openIndexObject(TEST_KEY, 3, { kind: 'main-shard', tenant: T2, shardId: 5 }, sealed));
  authFail(() => openIndexObject(TEST_KEY, 4, { kind: 'main-shard', tenant: T1, shardId: 5 }, sealed));
  const m = sealIndexObject(TEST_KEY, 3, { kind: 'manifest', tenant: T1 }, Buffer.from('manifest+tombstones'));
  authFail(() => openIndexObject(TEST_KEY, 3, { kind: 'manifest', tenant: T2 }, m));
  authFail(() => openIndexObject(TEST_KEY, 4, { kind: 'manifest', tenant: T1 }, m));
});

test('AAD kinds never collide: data (5 fields), index (4) and wrap (3) encodings differ for look-alike inputs', () => {
  // A wrap whose id looks like an index tag, and a data value, all under the same tenant and version.
  const all = [
    valueAad(ref({ rowId: 0 }), 1),
    mainShardAad(T1, 0, 1),
    deltaShardAad(T1, 0, 1),
    manifestAad(T1, 1),
    wrapAad({ tenant: T1, wrapId: 'b1-manifest' }, 1),
    wrapAad({ tenant: T1, wrapId: 'manifest' }, 1),
  ].map((b) => b.toString('hex'));
  assert.equal(new Set(all).size, all.length);
  // A value sealed as a data field never opens as an index object, and the reverse.
  const v = sealValue(TEST_KEY, 1, ref({ rowId: 0 }), 'v');
  authFail(() => openIndexObject(TEST_KEY, 1, { kind: 'main-shard', tenant: T1, shardId: 0 }, v));
  const s = sealIndexObject(TEST_KEY, 1, { kind: 'main-shard', tenant: T1, shardId: 0 }, Buffer.from('v'));
  authFail(() => openValue(TEST_KEY, 1, ref({ rowId: 0 }), s));
});

// ------------------------------------------------------------------ nonces

test('nonce uniqueness: same plaintext, key and AAD give different 96-bit nonces and ciphertexts', () => {
  const a = sealValue(TEST_KEY, 1, ref(), 'same');
  const b = sealValue(TEST_KEY, 1, ref(), 'same');
  assert.notDeepEqual(a, b);
  assert.notDeepEqual(a.subarray(1, 1 + NONCE_BYTES), b.subarray(1, 1 + NONCE_BYTES));
  assert.equal(NONCE_BYTES, 12);
  assert.equal(a.length, 1 + 12 + Buffer.byteLength('same') + 16);
  const seen = new Set<string>();
  for (let i = 0; i < 5000; i++) seen.add(sealValue(TEST_KEY, 1, ref(), 'same').subarray(1, 13).toString('hex'));
  assert.equal(seen.size, 5000);
});

// ------------------------------------------------------------------ wraps

test('wrap/unwrap: passkey, recovery and session wraps round-trip and are useless without the secret', () => {
  const dek = generateDek();
  const pref = { tenant: T1, wrapId: 'wrap-passkey-1' };
  const rref = { tenant: T1, wrapId: 'wrap-recovery-1' };
  const sref = { tenant: T1, wrapId: 'grant-1:access' };
  const pk = wrapDek(passkeyKek(TEST_PRF, pref.wrapId), 1, pref, dek);
  const rc = wrapDek(recoveryKek(TEST_CODE, rref.wrapId), 1, rref, dek);
  const ss = wrapDek(sessionKek(TEST_TOKEN, 'grant-1', 'access'), 1, sref, dek);
  assert.deepEqual(unwrapDek(passkeyKek(TEST_PRF, pref.wrapId), 1, pref, pk), dek);
  assert.deepEqual(unwrapDek(recoveryKek(TEST_CODE, rref.wrapId), 1, rref, rc), dek);
  assert.deepEqual(unwrapDek(sessionKek(TEST_TOKEN, 'grant-1', 'access'), 1, sref, ss), dek);
  // Wrong secret.
  authFail(() => unwrapDek(passkeyKek(Buffer.alloc(32, 0x34), pref.wrapId), 1, pref, pk));
  authFail(() => unwrapDek(recoveryKek(Buffer.alloc(16, 0x45), rref.wrapId), 1, rref, rc));
  authFail(() => unwrapDek(sessionKek('u'.repeat(40), 'grant-1', 'access'), 1, sref, ss));
  // Right secret, wrong salt (wrap id / grant id) or wrong token kind.
  authFail(() => unwrapDek(passkeyKek(TEST_PRF, 'wrap-passkey-2'), 1, pref, pk));
  authFail(() => unwrapDek(sessionKek(TEST_TOKEN, 'grant-2', 'access'), 1, sref, ss));
  authFail(() => unwrapDek(sessionKek(TEST_TOKEN, 'grant-1', 'refresh'), 1, sref, ss));
  // A raw PRF output used directly as the KEK does not unwrap.
  authFail(() => unwrapDek(TEST_PRF, 1, pref, pk));
  // The wrapped bytes do not contain the DEK.
  assert.equal(pk.includes(dek), false);
});

test('wrap/unwrap: a wrap copied to another tenant, wrap id or key_version fails', () => {
  const kek = passkeyKek(TEST_PRF, 'wrap-1');
  const wrapped = wrapDek(kek, 2, { tenant: T1, wrapId: 'wrap-1' }, TEST_DEK);
  authFail(() => unwrapDek(kek, 2, { tenant: T2, wrapId: 'wrap-1' }, wrapped));
  authFail(() => unwrapDek(kek, 2, { tenant: T1, wrapId: 'wrap-9' }, wrapped));
  authFail(() => unwrapDek(kek, 1, { tenant: T1, wrapId: 'wrap-1' }, wrapped));
  for (let i = 1; i < wrapped.length; i++) authFail(() => unwrapDek(kek, 2, { tenant: T1, wrapId: 'wrap-1' }, flip(wrapped, i)));
});

test('wrap/unwrap: a sealed data value is not accepted as a wrap (AAD kind and DEK length)', () => {
  const v = sealValue(TEST_KEY, 1, ref(), TEST_DEK);
  authFail(() => unwrapDek(TEST_KEY, 1, { tenant: T1, wrapId: 'w' }, v));
  assert.throws(() => wrapDek(TEST_KEY, 1, { tenant: T1, wrapId: 'w' }, Buffer.alloc(16)), /DEK must be 32 bytes/);
  // An authentic wrap of a payload that is not 32 bytes (built with raw node:crypto) is refused after opening.
  const nonce = Buffer.alloc(NONCE_BYTES, 0x55);
  const c = createCipheriv('aes-256-gcm', TEST_KEY, nonce);
  c.setAAD(wrapAad({ tenant: T1, wrapId: 'w' }, 1));
  const ct = Buffer.concat([c.update(Buffer.alloc(16, 0x66)), c.final()]);
  const shortWrap = Buffer.concat([Buffer.of(FORMAT_V1), nonce, ct, c.getAuthTag()]);
  assert.throws(() => unwrapDek(TEST_KEY, 1, { tenant: T1, wrapId: 'w' }, shortWrap), /wrong length/);
});

// ------------------------------------------------------------------ counter

test('counter: ROTATE_AT is 2^30; reaching it forces the rotation signal', () => {
  assert.equal(ROTATE_AT, 1073741824);
  assert.equal(mustRotate(0), false);
  assert.equal(mustRotate(ROTATE_AT - 1), false);
  assert.equal(mustRotate(ROTATE_AT), true);
  assert.equal(mustRotate(ROTATE_AT + 1), true);
  assert.equal(mustRotate(BigInt(ROTATE_AT)), true);
  assert.equal(mustRotate(String(ROTATE_AT - 1)), false); // pg returns bigint as text
  assert.doesNotThrow(() => assertEncryptionBudget(ROTATE_AT - 1));
  assert.throws(() => assertEncryptionBudget(ROTATE_AT), /DEK rotation required/);
  assert.throws(() => mustRotate(-1), EnvelopeError);
  assert.throws(() => mustRotate('1e9'), EnvelopeError);
});

test('counter: EncryptionCounter tracks one key_version and refuses the write after the threshold', () => {
  const c = new EncryptionCounter(1);
  c.add(10);
  assert.equal(c.count, 10);
  assert.equal(c.mustRotate, false);
  const near = new EncryptionCounter(3, ROTATE_AT - 5);
  near.add(100); // a write that starts below the threshold is allowed; it crosses it
  assert.equal(near.count, ROTATE_AT + 95);
  assert.equal(near.mustRotate, true);
  assert.throws(() => near.add(1), /DEK rotation required/);
  assert.equal(near.count, ROTATE_AT + 95);
  assert.equal(near.keyVersion, 3);
  assert.throws(() => new EncryptionCounter(0), EnvelopeError);
  assert.throws(() => c.add(-1), EnvelopeError);
  assert.throws(() => c.add(1.5), EnvelopeError);
  // One write can never carry a key_version past the ~2^32 random-nonce bound.
  assert.equal(NONCE_HARD_LIMIT, 2 ** 32);
  const big = new EncryptionCounter(1, ROTATE_AT - 1);
  assert.throws(() => big.add(2 ** 40), /write too large/);
  assert.equal(big.count, ROTATE_AT - 1);
  assert.throws(() => assertEncryptionBudget(0, NONCE_HARD_LIMIT + 1), /write too large/);
  assert.doesNotThrow(() => assertEncryptionBudget(0, 1000));
});

// ------------------------------------------------------------------ validation

test('validation: tenant must be a personal workspace id (copy of TENANT_ID_RE); the team is refused', () => {
  assert.equal(TENANT_ID_RE.source, '^zt_[a-z2-7]{26}$');
  assert.ok(TENANT_ID_RE.test(T1) && TENANT_ID_RE.test(T2));
  for (const t of ['work', 'zt_short', 'ZT_' + 'a'.repeat(26), 'zt_' + 'a'.repeat(25) + '1', '', T1 + ' ']) {
    assert.throws(() => valueAad(ref({ tenant: t }), 1), EnvelopeError);
    assert.throws(() => wrapAad({ tenant: t, wrapId: 'w' }, 1), EnvelopeError);
    assert.throws(() => manifestAad(t, 1), EnvelopeError);
  }
});

test('validation: key_version, identifiers, ids, key and secret sizes', () => {
  for (const kv of [0, -1, MAX_KEY_VERSION + 1, 1.5, Number.NaN]) assert.throws(() => valueAad(ref(), kv), /key_version/);
  assert.doesNotThrow(() => valueAad(ref(), MAX_KEY_VERSION));
  assert.equal(MAX_KEY_VERSION, 32767);
  for (const id of ['Notes', 'no-tes', '1notes', '', 'a'.repeat(64), 'notes|x']) {
    assert.throws(() => valueAad(ref({ table: id }), 1), /table/);
    assert.throws(() => valueAad(ref({ column: id }), 1), /column/);
  }
  for (const rowId of [-1, 1.5, '01', '1e3', ' 1', '', 2 ** 53, (1n << 63n), -1n]) assert.throws(() => valueAad(ref({ rowId }), 1), /row id/);
  assert.doesNotThrow(() => valueAad(ref({ rowId: (1n << 63n) - 1n }), 1));
  for (const w of ['', 'a\nb', 'x'.repeat(256), 'w\uD800', 'w\uDC00x']) assert.throws(() => wrapAad({ tenant: T1, wrapId: w }, 1), /wrap id/);
  // Lone surrogates would collapse to U+FFFD and let two ids share one AAD and KEK; they are refused.
  assert.throws(() => passkeyKek(TEST_PRF, 'w\uD800'), /wrap id/);
  assert.throws(() => sessionKek(TEST_TOKEN, 'g\uD800', 'access'), /grant id/);
  assert.doesNotThrow(() => wrapAad({ tenant: T1, wrapId: 'w\uFFFD' }, 1));
  assert.throws(() => sealValue(Buffer.alloc(16), 1, ref(), 'x'), /K_enc must be 32 bytes/);
  assert.throws(() => deriveSubkeys(Buffer.alloc(31)), /DEK must be 32 bytes/);
  assert.throws(() => passkeyKek(Buffer.alloc(16), 'w'), /PRF output/);
  assert.throws(() => recoveryKek(Buffer.alloc(32), 'w'), /recovery code/);
  assert.throws(() => sessionKek('short', 'g', 'access'), /token/);
  assert.throws(() => sessionKek(TEST_TOKEN, 'g', 'other' as 'access'), /session token kind/);
  assert.equal(generateRecoveryCode().length, 16);
  assert.equal(generateDek().length, 32);
  assert.notDeepEqual(generateDek(), generateDek());
});

test('errors carry no secret or plaintext', () => {
  const sealed = sealValue(TEST_KEY, 1, ref(), 'kestrelenvelopecanary');
  try {
    openValue(OTHER_KEY, 1, ref(), sealed);
    assert.fail('should throw');
  } catch (e) {
    const msg = String((e as Error).message);
    const all = msg + String((e as Error).stack);
    assert.equal(msg, 'authentication failed');
    for (const needle of ['kestrelenvelopecanary', OTHER_KEY.toString('hex'), TEST_KEY.toString('hex'), T1]) {
      assert.equal(all.includes(needle), false);
    }
  }
});

// ------------------------------------------------------------------ keyed hashes (C6 KTD5)

test('C6 KTD5 vectors: indexHmac / keyedDigest = HMAC-SHA256("zeusi-hmac-v1" || u16 len purpose || u16 len value); purposes separate', () => {
  const K = Buffer.alloc(32, 0x11);
  const field = (b: Buffer) => Buffer.concat([Buffer.from([b.length >> 8, b.length & 0xff]), b]);
  const ref = (purpose: string, v: Buffer) => createHmac('sha256', K).update(Buffer.concat([Buffer.from(HMAC_LABEL_V1), field(Buffer.from(purpose)), field(v)])).digest('hex');
  // Pinned vectors (any change of label, encoding or purpose turns these red).
  const V = {
    vault: '5784b20a67d863e9ae1ebda67156825bcfed25cd975c0fa7c7c1f86301e6227e',
    uri: 'd5b76c85c4a649c5b5529222e31e21b8ebdbb02f788a6b1f207095c094dc9f3b',
    quarantine: 'f9ae6750ca9f83888110f70ecae3eb8465db06fcf2465e8a5f8ffe06851f8e0b',
    sha: '034272ca313652d1dfcb0c31e1365119e229af71d226a1bfcb99a6478162fad1',
    text: '447359cea694164e355e0444fc0550856135f45ffa509a515f6de9c1bdc6aab8',
  };
  assert.equal(indexHmac(K, 'vault_path', 'hq:proj/2026-11-19-a.md').toString('hex'), V.vault);
  assert.equal(indexHmac(K, 'uri', 'import:notes/a.md').toString('hex'), V.uri);
  assert.equal(indexHmac(K, 'quarantine-uri', 'import:notes/a.md').toString('hex'), V.quarantine);
  assert.equal(keyedDigest(K, 'source_sha256', Buffer.alloc(32, 0xab)).toString('hex'), V.sha);
  assert.equal(keyedDigest(K, 'text', Buffer.alloc(32, 0xab)).toString('hex'), V.text);
  // The same values by a second, independent encoding.
  assert.equal(ref('vault_path', Buffer.from('hq:proj/2026-11-19-a.md')), V.vault);
  assert.equal(ref('source_sha256', Buffer.alloc(32, 0xab)), V.sha);
  // Domain separation: purpose and key both matter; the digest is not the plain input.
  assert.notEqual(V.uri, V.quarantine);
  assert.notEqual(V.sha, V.text);
  assert.notEqual(indexHmac(OTHER_KEY, 'uri', 'import:notes/a.md').toString('hex'), V.uri);
  assert.notEqual(V.sha, 'ab'.repeat(32));
  // C7 KTD2: the B1 cache check purpose (pinned vector; separate from every other purpose).
  const check = indexHmac(K, 'b1-cache-check', 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa').toString('hex');
  assert.equal(check, ref('b1-cache-check', Buffer.from('zt_aaaaaaaaaaaaaaaaaaaaaaaaaa')));
  assert.equal(check, '6281f6b7beb0ff4cb157f616cc1127b51d8062127a0df80036cd627903e00929');
  assert.notEqual(check, indexHmac(K, 'uri', 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa').toString('hex'));
  assert.throws(() => indexHmac(K, 'other' as never, 'x'), EnvelopeError);
  assert.throws(() => keyedDigest(K, 'text', Buffer.alloc(31)), EnvelopeError);
  assert.throws(() => indexHmac(Buffer.alloc(31), 'uri', 'x'), EnvelopeError);
  assert.throws(() => indexHmac(K, 'uri', 'x'.repeat(0x10000)), EnvelopeError);
});

// ------------------------------------------------------------------ not wired

// C4 (docs/plans/2026-11-18-c4-enroll.md KTD16): the guard is tightened, not dropped. src/workspace-keys.ts may
// import only the key-wrap names below (DEK wrap / unwrap, KEKs).
// C6 (docs/plans/2026-11-19-c6-write-path.md KTD4), changed on purpose: exactly ONE more file,
// src/workspace-seal.ts, may import value seal / open, the subkeys, the counter and the two HMACs. Every
// other file under src/, scripts/ and site/ is still refused; nothing may touch the B1 index objects (C7).
const ENVELOPE_IMPORTERS: Readonly<Record<string, readonly string[]>> = {
  'src/workspace-keys.ts': [
    'EnvelopeError', 'generateDek', 'generateRecoveryCode', 'KEY_BYTES', 'MAX_KEY_VERSION', 'passkeyKek', 'RECOVERY_CODE_BYTES',
    'recoveryKek', 'sessionKek', 'unwrapDek', 'wrapDek',
  ],
  'src/workspace-seal.ts': [
    'deriveSubkeys', 'EncryptionCounter', 'EnvelopeError', 'indexHmac', 'KEY_BYTES', 'keyedDigest', 'MAX_KEY_VERSION', 'openValue', 'sealValue',
    'DigestPurpose', 'IndexHmacPurpose', 'Subkeys',
    // C7 (docs/plans/2026-11-19-c7-read-path.md KTD6), changed on purpose: the B1 index objects, sealed / opened here only.
    'openIndexObject', 'sealIndexObject',
  ],
};
const VALUE_CRYPTO = ['sealValue', 'openValue', 'sealIndexObject', 'openIndexObject', 'deriveSubkeys', 'valueAad', 'mainShardAad', 'deltaShardAad', 'manifestAad'];
/** C6: the one file that seals / opens workspace values; C7: and the B1 index objects (KTD6). */
const VALUE_SEALERS: Readonly<Record<string, readonly string[]>> = { 'src/workspace-seal.ts': ['sealValue', 'openValue', 'deriveSubkeys', 'sealIndexObject', 'openIndexObject'] };

function sourceFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const n of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, n.name);
      if (n.isDirectory()) {
        if (n.name !== 'node_modules' && !n.name.startsWith('.')) walk(p);
      } else if (/\.(ts|tsx|js|jsx|mjs|cjs|html)$/.test(n.name) && n.name !== 'crypto-envelope.ts') out.push(p);
    }
  };
  walk('src');
  walk('scripts');
  walk('site');
  return out;
}

test('not wired (C4-tightened, C6): only src/workspace-keys.ts (key-wrap names) and src/workspace-seal.ts (value names) import crypto-envelope', () => {
  const offenders: string[] = [];
  for (const p of sourceFiles()) {
    const text = readFileSync(p, 'utf8');
    if (!text.includes('crypto-envelope')) continue;
    const allowed = ENVELOPE_IMPORTERS[p];
    if (!allowed) {
      offenders.push(p);
      continue;
    }
    const m = /import\s*\{([^}]*)\}\s*from\s*'\.\/crypto-envelope\.ts'/.exec(text);
    assert.ok(m, `${p} imports crypto-envelope with named imports only`);
    assert.equal((text.match(/crypto-envelope\.ts'/g) ?? []).length, 1, `${p}: one import statement`);
    const names = m[1]!.split(',').map((x) => x.trim()).filter(Boolean).map((x) => x.replace(/^type\s+/, ''));
    assert.deepEqual(names.filter((x) => !allowed.includes(x)), [], `${p} imports only key-wrap names`);
  }
  assert.deepEqual(offenders, []);
});

test('not wired (C4, C6, C7): no file under src/, scripts/ or site/ but src/workspace-seal.ts seals or opens a workspace value or a B1 index object', () => {
  const hits: string[] = [];
  for (const p of sourceFiles()) {
    const text = readFileSync(p, 'utf8');
    for (const fn of VALUE_CRYPTO) if (new RegExp(`\\b${fn}\\b`).test(text) && !(VALUE_SEALERS[p] ?? []).includes(fn)) hits.push(`${p}:${fn}`);
  }
  assert.deepEqual(hits, []);
});

test('not wired (C4): the guard itself bites (an unlisted importer and a value seal are both caught)', () => {
  const unlisted = "import { wrapDek } from './crypto-envelope.ts';";
  assert.ok(unlisted.includes('crypto-envelope') && ENVELOPE_IMPORTERS['src/mcp-oauth.ts'] === undefined);
  const sneaky = "import { sealValue, wrapDek } from './crypto-envelope.ts';";
  const names = /import\s*\{([^}]*)\}/.exec(sneaky)![1]!.split(',').map((x) => x.trim());
  assert.deepEqual(names.filter((x) => !ENVELOPE_IMPORTERS['src/workspace-keys.ts']!.includes(x)), ['sealValue']);
});
