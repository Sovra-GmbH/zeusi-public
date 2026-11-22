// Workspace keys for enrollment and unlock (C4, docs/plans/2026-11-18-c4-enroll.md; parent plan
// docs/plans/2026-11-18-zeusi-workspace-encryption.md §4.1, §4.3, §4.5).
//
// The ONLY importer of the envelope module (src/crypto-envelope.ts), and only for DEK wrap / unwrap
// and KEK derivation (test/crypto-envelope.test.ts pins the import list). Nothing here seals or opens a
// workspace value: no workspace row is encrypted by C4.
//
//   flag          ZEUSI_WORKSPACE_ENCRYPTION=off|enroll|on, default off (KTD6; `on` is C5 KTD13: enroll
//                 on the consent page plus new workspaces born encrypted). Anything else is off.
//   recovery      16 random bytes. Text form: Crockford Base32 of the 128-bit big-endian integer
//                 (26 symbols, the first 0-7) plus one Crockford check symbol (value mod 37), grouped
//                 by 4 with '-'. Entry ignores case, '-' and white space and maps O->0, I/L->1. Every
//                 single substitution and adjacent transposition fails the check, so a typo is refused
//                 before any KDF or unwrap (KTD2). The KEK takes the raw bytes, never the text.
//   catalog wraps passkey wrap_id 'pk:' + base64url(sha256(credential id)); recovery 'rc:' + 20 random
//                 base32 symbols; key_version 1 at enrollment (KTD12).
//   session wraps wrap_id 'sess:access:<grant_id>' / 'sess:refresh:<grant_id>', AAD
//                 wrapAad({ tenant, wrapId }, key_version), KEK sessionKek(token, grant_id, kind) (KTD3).
//
// Never logs, returns in an error, or renders a DEK, PRF output, recovery code or token. Callers drop
// DEK references (and zero the buffers they own) as soon as they are wrapped.

import { createHash, randomBytes } from 'node:crypto';
import {
  EnvelopeError, generateDek, generateRecoveryCode, KEY_BYTES, MAX_KEY_VERSION, passkeyKek, RECOVERY_CODE_BYTES, recoveryKek, sessionKek,
  unwrapDek, wrapDek,
} from './crypto-envelope.ts';
import type { PasskeyWrapRow, RecoveryWrapRow, StoredWrap } from './tenants.ts';

export const ENCRYPTION_FLAG_ENV = 'ZEUSI_WORKSPACE_ENCRYPTION';
export type EncryptionMode = 'off' | 'enroll' | 'on';
/** key_version of the first DEK of a workspace. */
export const ENROLL_KEY_VERSION = 1;
/** A WebAuthn PRF output is 32 bytes; anything else is refused. */
export const PRF_BYTES = 32;
export const PRF_SALT_BYTES = 32;
export const MAX_CREDENTIAL_ID_BYTES = 1023;

/**
 * The flag (KTD6). Only the exact values `off`, `enroll` and `on` are understood; unset is off. Anything
 * else is off with a loud line that names the variable, never its value. `on` (C5 KTD13) = `enroll` on
 * the consent page, and provisioning applies the prepare + flip overlays to NEW workspaces. C6 (encrypted
 * writes, #47) and C7 (encrypted reads, #48) have shipped. The self-hosted default is off.
 * Wired in src/mcp.ts tenantSignupSetup (test/born-encrypted-wiring.test.ts).
 */
export function encryptionMode(env: NodeJS.ProcessEnv): { mode: EncryptionMode; log?: string } {
  const v = env[ENCRYPTION_FLAG_ENV];
  if (v === undefined || v === '' || v === 'off') return { mode: 'off' };
  if (v === 'enroll') return { mode: 'enroll' };
  if (v === 'on') return { mode: 'on' };
  return { mode: 'off', log: `zeusi-mcp: WORKSPACE KEYS OFF: ${ENCRYPTION_FLAG_ENV} is not off, enroll or on; treated as off.` };
}

// ---------------------------------------------------------------- recovery code text form

export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/** Crockford check symbols for the values 32..36. */
export const CROCKFORD_CHECK_EXTRA = '*~$=U';
export const RECOVERY_DATA_SYMBOLS = 26;
export const RECOVERY_TEXT_SYMBOLS = RECOVERY_DATA_SYMBOLS + 1;
/** Longest entry looked at (27 symbols plus generous separators); longer is refused unread. */
export const MAX_RECOVERY_ENTRY_CHARS = 64;
const CHECK_ALPHABET = CROCKFORD + CROCKFORD_CHECK_EXTRA;
const DECODE_ALIAS: Readonly<Record<string, string>> = { O: '0', I: '1', L: '1' };

/** Display form of a 16-byte recovery code: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX (27 symbols). */
export function formatRecoveryCode(code: Uint8Array): string {
  if (!(code instanceof Uint8Array) || code.length !== RECOVERY_CODE_BYTES) throw new EnvelopeError(`recovery code must be ${RECOVERY_CODE_BYTES} bytes`);
  const n = BigInt(`0x${Buffer.from(code).toString('hex')}`);
  let rest = n;
  const sym: string[] = new Array<string>(RECOVERY_DATA_SYMBOLS);
  for (let i = RECOVERY_DATA_SYMBOLS - 1; i >= 0; i--) {
    sym[i] = CROCKFORD[Number(rest & 31n)]!;
    rest >>= 5n;
  }
  sym.push(CHECK_ALPHABET[Number(n % 37n)]!);
  const s = sym.join('');
  return s.match(/.{1,4}/g)!.join('-');
}

/**
 * The 16 bytes behind a typed recovery code, or null when it is not one (wrong length, a symbol
 * outside the alphabet, an overflow, or a failed check symbol). Pure; no KDF, no I/O.
 */
export function parseRecoveryCode(text: unknown): Buffer | null {
  if (typeof text !== 'string' || text.length === 0 || text.length > MAX_RECOVERY_ENTRY_CHARS) return null;
  const s = text.toUpperCase().replace(/[\s-]/g, '');
  if (s.length !== RECOVERY_TEXT_SYMBOLS) return null;
  let n = 0n;
  for (let i = 0; i < RECOVERY_DATA_SYMBOLS; i++) {
    const c = DECODE_ALIAS[s[i]!] ?? s[i]!;
    const v = CROCKFORD.indexOf(c);
    if (v < 0) return null;
    if (i === 0 && v > 7) return null; // 26 symbols carry 130 bits; the code is 128 (first symbol: 3 bits)
    n = (n << 5n) | BigInt(v);
  }
  const last = s[RECOVERY_DATA_SYMBOLS]!;
  const check = CHECK_ALPHABET.indexOf(DECODE_ALIAS[last] ?? last);
  if (check < 0 || BigInt(check) !== n % 37n) return null;
  return Buffer.from(n.toString(16).padStart(RECOVERY_CODE_BYTES * 2, '0'), 'hex');
}

// ---------------------------------------------------------------- ids

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

export function passkeyWrapId(credentialId: Uint8Array): string {
  return `pk:${createHash('sha256').update(credentialId).digest('base64url')}`;
}

export function newRecoveryWrapId(): string {
  return `rc:${[...randomBytes(20)].map((b) => BASE32[b & 31]).join('')}`;
}

export type SessionKind = 'access' | 'refresh';

export function sessionWrapId(kind: SessionKind, grantId: string): string {
  return `sess:${kind}:${grantId}`;
}

// ---------------------------------------------------------------- enroll and unlock

export interface Enrollment {
  /** The new DEK (memory only; the caller zeroes it after the session wraps are made). */
  dek: Buffer;
  keyVersion: number;
  /** Raw recovery code bytes (shown once in text form, then dropped). */
  recoveryCode: Buffer;
  passkey: PasskeyWrapRow;
  recovery: RecoveryWrapRow;
}

/** A COPY of min..max bytes (for values that are stored: credential id, salt). */
function bytesOf(v: unknown, min: number, max: number): Buffer | null {
  return v instanceof Uint8Array && v.length >= min && v.length <= max ? Buffer.from(v) : null;
}

/** A VIEW (no copy) of exactly n secret bytes, so the caller's fill(0) wipes the only copy (review P3-1). */
function secretView(v: unknown, n: number): Buffer | null {
  return v instanceof Uint8Array && v.length === n ? Buffer.from(v.buffer, v.byteOffset, v.byteLength) : null;
}

/** Run fn with a derived key, then zero the key. */
function withKey<T>(key: Buffer, fn: (k: Buffer) => T): T {
  try {
    return fn(key);
  } finally {
    key.fill(0);
  }
}

/**
 * A fresh DEK wrapped under the passkey PRF output (HKDF, never the raw output) and under a fresh
 * recovery code. Throws EnvelopeError on a malformed input (wrong PRF length, team tenant, ...).
 */
export function enrollmentWraps(o: {
  tenant: string; prfOutput: Uint8Array; credentialId: Uint8Array; prfSalt: Uint8Array; newDek?: (() => Buffer) | undefined;
}): Enrollment {
  const prf = secretView(o.prfOutput, PRF_BYTES);
  const cred = bytesOf(o.credentialId, 1, MAX_CREDENTIAL_ID_BYTES);
  const salt = bytesOf(o.prfSalt, PRF_SALT_BYTES, PRF_SALT_BYTES);
  if (!prf || !cred || !salt) throw new EnvelopeError('enrollment input is malformed');
  const dek = (o.newDek ?? generateDek)();
  if (!(dek instanceof Uint8Array) || dek.length !== KEY_BYTES) throw new EnvelopeError('DEK must be 32 bytes');
  const keyVersion = ENROLL_KEY_VERSION;
  const pkId = passkeyWrapId(cred);
  const recoveryCode = generateRecoveryCode();
  const rcId = newRecoveryWrapId();
  const passkey: PasskeyWrapRow = {
    wrapId: pkId, keyVersion, credentialId: cred, prfSalt: salt,
    sealedDek: withKey(passkeyKek(prf, pkId), (k) => wrapDek(k, keyVersion, { tenant: o.tenant, wrapId: pkId }, dek)),
  };
  const recovery: RecoveryWrapRow = {
    wrapId: rcId, keyVersion, sealedDek: withKey(recoveryKek(recoveryCode, rcId), (k) => wrapDek(k, keyVersion, { tenant: o.tenant, wrapId: rcId }, dek)),
  };
  return { dek, keyVersion, recoveryCode, passkey, recovery };
}

export interface UnlockedDek {
  dek: Buffer;
  keyVersion: number;
}

function tryUnwrap(kek: () => Buffer, tenant: string, w: Pick<StoredWrap, 'wrapId' | 'keyVersion' | 'sealedDek'>): UnlockedDek | null {
  try {
    if (!Number.isInteger(w.keyVersion) || w.keyVersion < 1 || w.keyVersion > MAX_KEY_VERSION) return null;
    return { dek: withKey(kek(), (k) => unwrapDek(k, w.keyVersion, { tenant, wrapId: w.wrapId }, w.sealedDek)), keyVersion: w.keyVersion };
  } catch {
    return null;
  }
}

/** The passkey wrap of `credentialId` among `wraps` (exact bytes), or null. */
export function wrapForCredential(wraps: readonly StoredWrap[], credentialId: Uint8Array): StoredWrap | null {
  const id = Buffer.from(credentialId);
  return wraps.find((w) => w.kind === 'passkey' && w.credentialId !== null && w.credentialId.equals(id)) ?? null;
}

/** Unwrap with a passkey PRF output; null on any failure (wrong secret, moved wrap, malformed). */
export function unlockWithPasskey(tenant: string, wrap: StoredWrap, prfOutput: Uint8Array): UnlockedDek | null {
  const prf = secretView(prfOutput, PRF_BYTES);
  if (!prf || wrap.kind !== 'passkey') return null;
  return tryUnwrap(() => passkeyKek(prf, wrap.wrapId), tenant, wrap);
}

/** Unwrap with the raw 16 recovery-code bytes (already parsed); null when no recovery wrap opens. */
export function unlockWithRecovery(tenant: string, wraps: readonly StoredWrap[], code: Uint8Array): UnlockedDek | null {
  const c = secretView(code, RECOVERY_CODE_BYTES);
  if (!c) return null;
  for (const w of wraps) {
    if (w.kind !== 'recovery') continue;
    const r = tryUnwrap(() => recoveryKek(c, w.wrapId), tenant, w);
    if (r) return r;
  }
  return null;
}

// ---------------------------------------------------------------- session wraps (OAuth store)

/** As stored beside the grant (src/mcp-oauth-store.ts): base64url of two 61-byte C1 wraps. */
export interface SessionWraps {
  key_version: number;
  access: string;
  refresh: string;
}

function sealOne(tenant: string, grantId: string, kind: SessionKind, token: string, dek: Uint8Array, keyVersion: number): string {
  const wrapId = sessionWrapId(kind, grantId);
  return withKey(sessionKek(token, grantId, kind), (k) => wrapDek(k, keyVersion, { tenant, wrapId }, dek)).toString('base64url');
}

/** The DEK wrapped under a new access token and a new refresh token of one grant. */
export function sealSessionWraps(tenant: string, grantId: string, accessToken: string, refreshToken: string, dek: Uint8Array, keyVersion: number): SessionWraps {
  return {
    key_version: keyVersion,
    access: sealOne(tenant, grantId, 'access', accessToken, dek, keyVersion),
    refresh: sealOne(tenant, grantId, 'refresh', refreshToken, dek, keyVersion),
  };
}

/** Open one session wrap with its token; null on any failure (wrong token, grant, kind or tenant). */
export function openSessionWrap(tenant: string, grantId: string, kind: SessionKind, token: string, wraps: SessionWraps): UnlockedDek | null {
  const sealed = kind === 'access' ? wraps.access : wraps.refresh;
  return tryUnwrap(() => sessionKek(token, grantId, kind), tenant, {
    wrapId: sessionWrapId(kind, grantId), keyVersion: wraps.key_version, sealedDek: Buffer.from(sealed, 'base64url'),
  });
}

/**
 * Refresh (§4.3 step 4): unwrap with the OLD refresh token, rewrap under the new pair. null when the
 * old wrap does not open (the caller then drops the wraps: fail closed). The DEK is zeroed here.
 */
export function rewrapSession(tenant: string, grantId: string, oldRefresh: string, newAccess: string, newRefresh: string, wraps: SessionWraps): SessionWraps | null {
  const u = openSessionWrap(tenant, grantId, 'refresh', oldRefresh, wraps);
  if (!u) return null;
  try {
    return sealSessionWraps(tenant, grantId, newAccess, newRefresh, u.dek, u.keyVersion);
  } catch {
    return null;
  } finally {
    u.dek.fill(0);
  }
}

/**
 * The session DEK of a live access token (for C6/C7; unused on /mcp in C4): the grant must be live,
 * the access token unexpired and the wrap must open. The caller zeroes `dek` after the request.
 */
export function openSessionDek(
  store: { sessionWrapsFor(accessToken: string): { grantId: string; tenant: string; wraps: SessionWraps } | null }, accessToken: string,
): { tenant: string; grantId: string; dek: Buffer; keyVersion: number } | null {
  const s = store.sessionWrapsFor(accessToken);
  if (!s) return null;
  const u = openSessionWrap(s.tenant, s.grantId, 'access', accessToken, s.wraps);
  return u ? { tenant: s.tenant, grantId: s.grantId, dek: u.dek, keyVersion: u.keyVersion } : null;
}
