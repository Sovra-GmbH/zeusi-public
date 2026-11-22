// Server-side WebAuthn verification for the C4 consent page (docs/plans/2026-11-19-c4-webauthn-verify.md
// KTD1, KTD2). Registration (WebAuthn L3 §7.1) and authentication (§7.2) with node:crypto only: a strict,
// bounded CBOR subset decoder; COSE keys ES256 (P-256), RS256 (2048..4096 bit) and EdDSA (Ed25519);
// attestation formats `none` and `packed` (self or x5c leaf; attestation trust is NOT evaluated).
//
// Every function here is pure: it gets the server's expectations (challenge, origin, rpId, stored key and
// counter) and the client's bytes, and returns a typed result or a refusal reason. A reason is a constant
// code, never a value from the input. Nothing here sees a PRF output, a DEK or a recovery code.

import { createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify, X509Certificate, type KeyObject } from 'node:crypto';

export const WEBAUTHN_CHALLENGE_BYTES = 32;
/** A WebAuthn challenge lives at most this long (shorter than the 10-minute sign-in transaction). */
export const WEBAUTHN_CHALLENGE_TTL_MS = 5 * 60_000;
export const MAX_CLIENT_DATA_BYTES = 1024;
export const MAX_ATTESTATION_BYTES = 4096;
export const MAX_ASSERTION_AUTH_DATA_BYTES = 512;
export const MAX_SIGNATURE_BYTES = 512;
export const MAX_COSE_KEY_BYTES = 1024;
export const MAX_WEBAUTHN_CREDENTIAL_ID_BYTES = 1023;
export const MAX_SIGN_COUNT = 0xffff_ffff;

/** COSE algorithm ids accepted (and offered by the consent script, in this order). */
export const COSE_ALG = { EdDSA: -8, ES256: -7, RS256: -257 } as const;
export const ACCEPTED_ALGS: readonly number[] = [COSE_ALG.EdDSA, COSE_ALG.ES256, COSE_ALG.RS256];

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

export type WebAuthnRefusal =
  | 'malformed' | 'too_large' | 'client_data' | 'type' | 'challenge' | 'origin' | 'cross_origin'
  | 'rp_id' | 'user_present' | 'user_verified' | 'flags' | 'credential' | 'key' | 'alg' | 'format'
  | 'attestation' | 'signature' | 'counter';

export type Verified<T> = { ok: true; value: T } | { ok: false; reason: WebAuthnRefusal };
const no = <T>(reason: WebAuthnRefusal): Verified<T> => ({ ok: false, reason });

// ---------------------------------------------------------------------------------------------- CBOR

export type Cbor = number | string | boolean | null | Buffer | Cbor[] | Map<number | string, Cbor>;

export const CBOR_MAX_DEPTH = 4;
export const CBOR_MAX_ITEMS = 64;

class CborError extends Error {}

/**
 * Decode ONE CBOR item from `buf` at `start` (RFC 8949 subset): unsigned / negative integers within
 * Number.MAX_SAFE_INTEGER, byte and text strings (strict UTF-8), arrays, maps with integer or text keys
 * (no duplicates), true / false / null. Definite lengths only; no tags, floats, undefined or other simple
 * values; depth ≤ CBOR_MAX_DEPTH, ≤ CBOR_MAX_ITEMS per container. Throws on anything else. Returns the
 * value and the offset just after it (the caller decides whether trailing bytes are allowed).
 */
export function cborDecode(buf: Buffer, start = 0): { value: Cbor; end: number } {
  let p = start;
  const need = (n: number) => {
    if (n < 0 || p + n > buf.length) throw new CborError('truncated');
  };
  const arg = (info: number): number => {
    if (info < 24) return info;
    if (info === 24) { need(1); return buf[p++]!; }
    if (info === 25) { need(2); const v = buf.readUInt16BE(p); p += 2; return v; }
    if (info === 26) { need(4); const v = buf.readUInt32BE(p); p += 4; return v; }
    if (info === 27) {
      need(8);
      const v = buf.readBigUInt64BE(p);
      p += 8;
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError('integer too large');
      return Number(v);
    }
    throw new CborError('indefinite or reserved length');
  };
  const item = (depth: number): Cbor => {
    if (depth > CBOR_MAX_DEPTH) throw new CborError('too deep');
    need(1);
    const ib = buf[p++]!;
    const major = ib >> 5;
    const info = ib & 0x1f;
    switch (major) {
      case 0: return arg(info);
      case 1: return -1 - arg(info);
      case 2: { const n = arg(info); need(n); const v = Buffer.from(buf.subarray(p, p + n)); p += n; return v; }
      case 3: {
        const n = arg(info);
        need(n);
        let s: string;
        try {
          s = new TextDecoder('utf-8', { fatal: true }).decode(buf.subarray(p, p + n));
        } catch {
          throw new CborError('bad utf-8');
        }
        p += n;
        return s;
      }
      case 4: {
        const n = arg(info);
        if (n > CBOR_MAX_ITEMS) throw new CborError('too many items');
        const out: Cbor[] = [];
        for (let i = 0; i < n; i++) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        const n = arg(info);
        if (n > CBOR_MAX_ITEMS) throw new CborError('too many items');
        const out = new Map<number | string, Cbor>();
        for (let i = 0; i < n; i++) {
          const k = item(depth + 1);
          if (typeof k !== 'number' && typeof k !== 'string') throw new CborError('bad map key');
          if (out.has(k)) throw new CborError('duplicate map key');
          out.set(k, item(depth + 1));
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new CborError('unsupported simple or float');
      default:
        throw new CborError('tags are not accepted');
    }
  };
  const value = item(0);
  return { value, end: p };
}

/** Exactly one CBOR item filling the whole buffer, or a throw. */
function cborWhole(buf: Buffer): Cbor {
  const { value, end } = cborDecode(buf, 0);
  if (end !== buf.length) throw new CborError('trailing bytes');
  return value;
}

const isMap = (v: Cbor | undefined): v is Map<number | string, Cbor> => v instanceof Map;
const isBytes = (v: Cbor | undefined): v is Buffer => Buffer.isBuffer(v);

// ---------------------------------------------------------------------------------------------- COSE

export interface CoseKey {
  alg: number;
  key: KeyObject;
}

/** A COSE_Key (RFC 9053) of an accepted algorithm as a node KeyObject; throws on anything else. */
export function coseToKey(cose: Buffer): CoseKey {
  if (cose.length === 0 || cose.length > MAX_COSE_KEY_BYTES) throw new CborError('cose key size');
  const m = cborWhole(cose);
  if (!isMap(m)) throw new CborError('cose key is not a map');
  const kty = m.get(1);
  const alg = m.get(3);
  if (typeof alg !== 'number' || !ACCEPTED_ALGS.includes(alg)) throw new CborError('alg');
  let jwk: Record<string, string>;
  if (alg === COSE_ALG.ES256) {
    const x = m.get(-2);
    const y = m.get(-3);
    if (kty !== 2 || m.get(-1) !== 1 || !isBytes(x) || !isBytes(y) || x.length !== 32 || y.length !== 32) throw new CborError('ec2 key');
    jwk = { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') };
  } else if (alg === COSE_ALG.RS256) {
    const n = m.get(-1);
    const e = m.get(-2);
    if (kty !== 3 || !isBytes(n) || !isBytes(e) || n.length < 256 || n.length > 512 || n[0] === 0 || e.length < 1 || e.length > 8) throw new CborError('rsa key');
    jwk = { kty: 'RSA', n: n.toString('base64url'), e: e.toString('base64url') };
  } else {
    const x = m.get(-2);
    if (kty !== 1 || m.get(-1) !== 6 || !isBytes(x) || x.length !== 32) throw new CborError('okp key');
    jwk = { kty: 'OKP', crv: 'Ed25519', x: x.toString('base64url') };
  }
  return { alg, key: createPublicKey({ key: jwk, format: 'jwk' }) };
}

function verifySig(alg: number, key: KeyObject, data: Buffer, sig: Buffer): boolean {
  if (sig.length === 0 || sig.length > MAX_SIGNATURE_BYTES) return false;
  try {
    if (alg === COSE_ALG.ES256) {
      if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return false;
      return cryptoVerify('sha256', data, { key, dsaEncoding: 'der' }, sig);
    }
    if (alg === COSE_ALG.RS256) {
      if (key.asymmetricKeyType !== 'rsa') return false;
      return cryptoVerify('sha256', data, key, sig);
    }
    if (alg === COSE_ALG.EdDSA) {
      if (key.asymmetricKeyType !== 'ed25519') return false;
      return cryptoVerify(null, data, key, sig);
    }
  } catch {
    return false;
  }
  return false;
}

// ---------------------------------------------------------------------------------------- client data

export interface Expected {
  /** The server-issued challenge, base64url (unpadded). */
  challenge: string;
  /** The issuer origin, e.g. https://mcp.zeusi.dev. */
  origin: string;
  /** The RP id, the issuer hostname. */
  rpId: string;
}

function sameString(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

function checkClientData(cdj: Buffer, type: 'webauthn.create' | 'webauthn.get', exp: Expected): WebAuthnRefusal | null {
  if (cdj.length === 0 || cdj.length > MAX_CLIENT_DATA_BYTES) return 'too_large';
  let c: unknown;
  try {
    c = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(cdj));
  } catch {
    return 'client_data';
  }
  if (typeof c !== 'object' || c === null || Array.isArray(c)) return 'client_data';
  const o = c as Record<string, unknown>;
  if (o['type'] !== type) return 'type';
  if (typeof o['challenge'] !== 'string' || !sameString(o['challenge'], exp.challenge)) return 'challenge';
  if (typeof o['origin'] !== 'string' || o['origin'] !== exp.origin) return 'origin';
  if (o['crossOrigin'] !== undefined && o['crossOrigin'] !== false) return 'cross_origin';
  if (o['topOrigin'] !== undefined) return 'cross_origin';
  return null;
}

// ---------------------------------------------------------------------------------- authenticator data

interface AuthData {
  flags: number;
  signCount: number;
  credentialId: Buffer | null;
  cose: Buffer | null;
}

function parseAuthData(ad: Buffer, exp: Expected, attested: boolean): Verified<AuthData> {
  if (ad.length < 37) return no('malformed');
  const rpIdHash = createHash('sha256').update(exp.rpId, 'utf8').digest();
  if (!timingSafeEqual(ad.subarray(0, 32), rpIdHash)) return no('rp_id');
  const flags = ad[32]!;
  if ((flags & FLAG_UP) === 0) return no('user_present');
  if ((flags & FLAG_UV) === 0) return no('user_verified');
  if ((flags & FLAG_BS) !== 0 && (flags & FLAG_BE) === 0) return no('flags');
  if (((flags & FLAG_AT) !== 0) !== attested) return no('flags');
  const signCount = ad.readUInt32BE(33);
  let p = 37;
  let credentialId: Buffer | null = null;
  let cose: Buffer | null = null;
  try {
    if (attested) {
      if (ad.length < p + 18) return no('malformed');
      p += 16; // AAGUID: not evaluated (no attestation trust, KTD2)
      const n = ad.readUInt16BE(p);
      p += 2;
      if (n < 1 || n > MAX_WEBAUTHN_CREDENTIAL_ID_BYTES || p + n > ad.length) return no('malformed');
      credentialId = Buffer.from(ad.subarray(p, p + n));
      p += n;
      const k = cborDecode(ad, p);
      cose = Buffer.from(ad.subarray(p, k.end));
      p = k.end;
    }
    if ((flags & FLAG_ED) !== 0) {
      const e = cborDecode(ad, p);
      if (!isMap(e.value)) return no('malformed');
      p = e.end;
    }
  } catch {
    return no('malformed');
  }
  if (p !== ad.length) return no('malformed');
  return { ok: true, value: { flags, signCount, credentialId, cose } };
}

// ------------------------------------------------------------------------------------- registration

export interface Registration {
  credentialId: Buffer;
  /** The COSE key exactly as attested (stored in key_wraps.webauthn_public_key). */
  publicKey: Buffer;
  alg: number;
  signCount: number;
}

/**
 * WebAuthn L3 §7.1 for this RP: clientDataJSON (type webauthn.create, challenge, origin, not cross-origin),
 * attestationObject {fmt, attStmt, authData} (nothing else, nothing after), rpIdHash, UP + UV + AT, the
 * attested credential id equal to `credentialId` (the id the client posted), an accepted COSE key, and the
 * attestation statement: `none` (empty) or `packed` (signature verified with the credential key or the x5c
 * leaf; no trust path). Returns the credential to store.
 */
export function verifyRegistration(o: { clientDataJSON: Buffer; attestationObject: Buffer; credentialId: Buffer; expected: Expected }): Verified<Registration> {
  const cd = checkClientData(o.clientDataJSON, 'webauthn.create', o.expected);
  if (cd) return no(cd);
  if (o.attestationObject.length === 0 || o.attestationObject.length > MAX_ATTESTATION_BYTES) return no('too_large');
  let att: Cbor;
  try {
    att = cborWhole(o.attestationObject);
  } catch {
    return no('malformed');
  }
  if (!isMap(att) || att.size !== 3) return no('malformed');
  const fmt = att.get('fmt');
  const stmt = att.get('attStmt');
  const authData = att.get('authData');
  if (typeof fmt !== 'string' || !isMap(stmt) || !isBytes(authData)) return no('malformed');
  const pa = parseAuthData(authData, o.expected, true);
  if (!pa.ok) return pa;
  const { credentialId, cose, signCount } = pa.value;
  if (!credentialId || !cose || credentialId.length !== o.credentialId.length || !timingSafeEqual(credentialId, o.credentialId)) return no('credential');
  let key: CoseKey;
  try {
    key = coseToKey(cose);
  } catch {
    return no('key');
  }
  const signed = Buffer.concat([authData, createHash('sha256').update(o.clientDataJSON).digest()]);
  if (fmt === 'none') {
    if (stmt.size !== 0) return no('attestation');
  } else if (fmt === 'packed') {
    const alg = stmt.get('alg');
    const sig = stmt.get('sig');
    const x5c = stmt.get('x5c');
    if (typeof alg !== 'number' || !isBytes(sig)) return no('attestation');
    if (x5c === undefined) {
      if (stmt.size !== 2 || alg !== key.alg) return no('attestation');
      if (!verifySig(alg, key.key, signed, sig)) return no('attestation');
    } else {
      if (stmt.size !== 3 || !Array.isArray(x5c) || x5c.length < 1 || !isBytes(x5c[0]) || !ACCEPTED_ALGS.includes(alg)) return no('attestation');
      let leaf: KeyObject;
      try {
        leaf = new X509Certificate(x5c[0]).publicKey;
      } catch {
        return no('attestation');
      }
      if (!verifySig(alg, leaf, signed, sig)) return no('attestation');
    }
  } else {
    return no('format');
  }
  return { ok: true, value: { credentialId, publicKey: cose, alg: key.alg, signCount } };
}

// ----------------------------------------------------------------------------------- authentication

/**
 * WebAuthn L3 §7.2 for this RP: clientDataJSON (type webauthn.get, challenge, origin, not cross-origin),
 * authenticatorData (≤ 512 bytes; rpIdHash, UP + UV, no AT, extensions consumed exactly), the signature
 * over authenticatorData || SHA-256(clientDataJSON) with the STORED COSE key, and the signature counter:
 * when either the stored or the new count is non-zero the new one must be greater (§6.1.1: otherwise a
 * cloned authenticator or a replay; refused). Returns the new count to store.
 */
export function verifyAssertion(o: {
  clientDataJSON: Buffer; authenticatorData: Buffer; signature: Buffer; publicKey: Buffer; storedSignCount: number; expected: Expected;
}): Verified<{ signCount: number }> {
  const cd = checkClientData(o.clientDataJSON, 'webauthn.get', o.expected);
  if (cd) return no(cd);
  if (o.authenticatorData.length > MAX_ASSERTION_AUTH_DATA_BYTES || o.signature.length > MAX_SIGNATURE_BYTES) return no('too_large');
  const pa = parseAuthData(o.authenticatorData, o.expected, false);
  if (!pa.ok) return pa;
  let key: CoseKey;
  try {
    key = coseToKey(o.publicKey);
  } catch {
    return no('key');
  }
  const signed = Buffer.concat([o.authenticatorData, createHash('sha256').update(o.clientDataJSON).digest()]);
  if (!verifySig(key.alg, key.key, signed, o.signature)) return no('signature');
  const n = pa.value.signCount;
  if (!Number.isSafeInteger(o.storedSignCount) || o.storedSignCount < 0 || o.storedSignCount > MAX_SIGN_COUNT) return no('counter');
  if ((n !== 0 || o.storedSignCount !== 0) && n <= o.storedSignCount) return no('counter');
  return { ok: true, value: { signCount: n } };
}
