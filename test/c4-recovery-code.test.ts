// C4 KTD2 (docs/plans/2026-11-18-c4-enroll.md): recovery-code text form. Crockford Base32 + mod-37 check
// symbol. Every single typo and adjacent transposition is refused by the pure parser, i.e. before any KDF
// or unwrap. Hermetic; every code below is a TEST byte pattern.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  CROCKFORD, CROCKFORD_CHECK_EXTRA, formatRecoveryCode, MAX_RECOVERY_ENTRY_CHARS, parseRecoveryCode, RECOVERY_TEXT_SYMBOLS,
} from '../src/workspace-keys.ts';

const CODE = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const symbols = (s: string) => s.replace(/-/g, '');

test('C4 recovery code: 27 Crockford symbols grouped by 4, no I L O U in the data, round trip for edge and random values', () => {
  const s = formatRecoveryCode(CODE);
  assert.match(s, /^[0-9A-Z*~$=]{4}(-[0-9A-Z*~$=]{4}){5}-[0-9A-Z*~$=]{3}$/);
  assert.equal(symbols(s).length, RECOVERY_TEXT_SYMBOLS);
  assert.doesNotMatch(symbols(s).slice(0, 26), /[ILOU]/);
  assert.deepEqual(parseRecoveryCode(s), CODE);
  for (const b of [Buffer.alloc(16, 0), Buffer.alloc(16, 0xff), Buffer.from('80'.padEnd(32, '0'), 'hex')]) {
    assert.deepEqual(parseRecoveryCode(formatRecoveryCode(b)), b);
    assert.match(symbols(formatRecoveryCode(b))[0]!, /[0-7]/, 'the first symbol carries only 3 bits');
  }
  for (let i = 0; i < 200; i++) {
    const b = randomBytes(16);
    assert.deepEqual(parseRecoveryCode(formatRecoveryCode(b)), b);
  }
  assert.throws(() => formatRecoveryCode(Buffer.alloc(15)));
});

test('C4 recovery code: entry ignores case, hyphens and white space; O->0 and I/L->1 (Crockford decoding)', () => {
  const s = formatRecoveryCode(CODE);
  assert.deepEqual(parseRecoveryCode(s.toLowerCase()), CODE);
  assert.deepEqual(parseRecoveryCode(symbols(s)), CODE);
  assert.deepEqual(parseRecoveryCode(` ${s.replace(/-/g, ' ')}\n`), CODE);
  assert.deepEqual(parseRecoveryCode(s.replace(/-/g, ' - ')), CODE);
  const withAliases = symbols(s).slice(0, 26).replace(/0/g, 'O').replace(/1/g, 'l') + symbols(s)[26];
  assert.deepEqual(parseRecoveryCode(withAliases), CODE);
});

test('C4 recovery code: EVERY single-symbol substitution fails closed (exhaustive over one code)', () => {
  const s = symbols(formatRecoveryCode(CODE));
  let tried = 0;
  for (let i = 0; i < s.length; i++) {
    const alphabet = i < 26 ? CROCKFORD : CROCKFORD + CROCKFORD_CHECK_EXTRA;
    for (const c of alphabet) {
      if (c === s[i]) continue;
      tried++;
      assert.equal(parseRecoveryCode(s.slice(0, i) + c + s.slice(i + 1)), null, `position ${i}`);
    }
  }
  assert.ok(tried > 26 * 31);
});

test('C4 recovery code: EVERY adjacent transposition of two different symbols fails closed, check symbol included', () => {
  for (const code of [CODE, Buffer.from('0f1e2d3c4b5a69788796a5b4c3d2e1f0', 'hex'), randomBytes(16)]) {
    const s = symbols(formatRecoveryCode(code));
    for (let i = 0; i + 1 < s.length; i++) {
      if (s[i] === s[i + 1]) continue;
      const t = s.slice(0, i) + s[i + 1] + s[i] + s.slice(i + 2);
      assert.equal(parseRecoveryCode(t), null, `swap ${i}/${i + 1}`);
    }
  }
});

test('C4 recovery code: wrong length, foreign symbols, overflow and oversize input are refused unread', () => {
  const s = symbols(formatRecoveryCode(CODE));
  for (const bad of ['', s.slice(1), `${s}0`, `${s.slice(0, 5)}U${s.slice(6)}`, `${s.slice(0, 26)}#`, `8${s.slice(1)}`, `Z${s.slice(1)}`, 'é'.repeat(27), `${s}${'-'.repeat(MAX_RECOVERY_ENTRY_CHARS)}`]) {
    assert.equal(parseRecoveryCode(bad), null, JSON.stringify(bad.slice(0, 8)));
  }
  for (const v of [null, undefined, 42, Buffer.from(s)]) assert.equal(parseRecoveryCode(v), null);
});
