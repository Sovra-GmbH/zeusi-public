// A software WebAuthn authenticator + browser for tests (docs/plans/2026-11-19-c4-webauthn-verify.md "Tests"):
// real key pairs (ES256 P-256, RS256 2048-bit, EdDSA Ed25519), real CBOR attestation objects (fmt none or
// packed self) and assertions, a PRF derived as HMAC(test secret, credential id, salt) like the C4 fake. It
// reads the consent page's data attributes and returns the form fields CONSENT_SCRIPT would post. Every knob
// in `Tweak` exists to build ONE negative test. All keys and PRF secrets are TEST values, made per run.
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign as cryptoSign, type KeyObject } from 'node:crypto';

export type Alg = -7 | -257 | -8;

// ------------------------------------------------------------------------------------------ CBOR encode

export type CborIn = number | string | boolean | null | Buffer | CborIn[] | Map<number | string, CborIn>;

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.of((major << 5) | n);
  if (n < 0x100) return Buffer.of((major << 5) | 24, n);
  if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  if (n < 0x1_0000_0000) { const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b; }
  const b = Buffer.alloc(9); b[0] = (major << 5) | 27; b.writeBigUInt64BE(BigInt(n), 1); return b;
}

export function cbor(v: CborIn): Buffer {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') { const b = Buffer.from(v, 'utf8'); return Buffer.concat([head(3, b.length), b]); }
  if (typeof v === 'boolean') return Buffer.of(v ? 0xf5 : 0xf4);
  if (v === null) return Buffer.of(0xf6);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
}

// ----------------------------------------------------------------------------------------- keys / COSE

export interface KeyPair { alg: Alg; priv: KeyObject; cose: Buffer }

export function keyPair(alg: Alg): KeyPair {
  if (alg === -7) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const j = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    return { alg, priv: privateKey, cose: cbor(new Map<number, CborIn>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(j.x, 'base64url')], [-3, Buffer.from(j.y, 'base64url')]])) };
  }
  if (alg === -257) {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const j = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    return { alg, priv: privateKey, cose: cbor(new Map<number, CborIn>([[1, 3], [3, -257], [-1, Buffer.from(j.n, 'base64url')], [-2, Buffer.from(j.e, 'base64url')]])) };
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const j = publicKey.export({ format: 'jwk' }) as { x: string };
  return { alg, priv: privateKey, cose: cbor(new Map<number, CborIn>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(j.x, 'base64url')]])) };
}

export function signWith(k: KeyPair, data: Buffer): Buffer {
  if (k.alg === -7) return cryptoSign('sha256', data, { key: k.priv, dsaEncoding: 'der' });
  if (k.alg === -257) return cryptoSign('sha256', data, k.priv);
  return cryptoSign(null, data, k.priv);
}

// -------------------------------------------------------------------------------------------- tweaks

/** Every way a test can bend one response. Unset: a correct response. */
export interface Tweak {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
  topOrigin?: string;
  rpId?: string;
  /** Raw flags byte (default UP|UV, plus AT at create, plus ED when `extensions`). */
  flags?: number;
  /** Sign with this key instead of the credential's own. */
  signer?: KeyPair;
  /** Flip one bit of the signature after signing. */
  corruptSig?: boolean;
  /** The counter written into authenticatorData (default: the authenticator's next value). */
  counter?: number;
  /** Bytes appended after authenticatorData (inside the signed data). */
  trailing?: Buffer;
  /** Append a CBOR extensions map (sets ED). */
  extensions?: Map<string, CborIn>;
  /** Attestation format (default 'none'); 'packed' = self attestation with the credential key. */
  fmt?: string;
  /** The attested credential id, when it must differ from the posted one. */
  attestedId?: Buffer;
  /** Replace the attestationObject bytes entirely. */
  rawAttestation?: Buffer;
  /** Replace the clientDataJSON bytes entirely. */
  rawClientData?: Buffer;
  /** Replace the authenticatorData bytes entirely (assertion). */
  rawAuthData?: Buffer;
}

const UP = 0x01;
const UV = 0x04;
const AT = 0x40;
const ED = 0x80;

function clientData(type: string, challenge: string, origin: string, t: Tweak): Buffer {
  if (t.rawClientData) return t.rawClientData;
  const o: Record<string, unknown> = { type: t.type ?? type, challenge: t.challenge ?? challenge, origin: t.origin ?? origin };
  if (t.crossOrigin !== undefined) o['crossOrigin'] = t.crossOrigin;
  if (t.topOrigin !== undefined) o['topOrigin'] = t.topOrigin;
  return Buffer.from(JSON.stringify(o), 'utf8');
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
}

// ------------------------------------------------------------------------------------- authenticator

export class SoftAuthenticator {
  readonly key: KeyPair;
  readonly credentialId: Buffer;
  /** The counter of the NEXT operation is counter + step (step 0: an authenticator without a counter). */
  counter: number;
  readonly step: number;
  private readonly prfSecret: Buffer;

  constructor(o: { alg?: Alg; step?: number; credentialId?: Buffer } = {}) {
    this.key = keyPair(o.alg ?? -7);
    this.credentialId = o.credentialId ?? randomBytes(16);
    this.step = o.step ?? 1;
    this.counter = 0;
    this.prfSecret = randomBytes(32);
  }

  prf(salt: Buffer, cred: Buffer = this.credentialId): Buffer {
    return createHmac('sha256', this.prfSecret).update(cred).update(salt).digest();
  }

  private next(t: Tweak): number {
    if (t.counter !== undefined) return t.counter;
    this.counter += this.step;
    return this.counter;
  }

  /** navigator.credentials.create(): { cdj, att } for this RP. */
  create(o: { rpId: string; origin: string; challenge: string }, t: Tweak = {}): { cdj: Buffer; att: Buffer } {
    const cdj = clientData('webauthn.create', o.challenge, o.origin, t);
    if (t.rawAttestation) return { cdj, att: t.rawAttestation };
    const id = t.attestedId ?? this.credentialId;
    const len = Buffer.alloc(2);
    len.writeUInt16BE(id.length);
    const ext = t.extensions ? cbor(t.extensions) : Buffer.alloc(0);
    const flags = t.flags ?? (UP | UV | AT | (t.extensions ? ED : 0));
    const authData = Buffer.concat([
      createHash('sha256').update(t.rpId ?? o.rpId, 'utf8').digest(), Buffer.of(flags), u32(this.next(t)),
      Buffer.alloc(16), len, id, this.key.cose, ext, t.trailing ?? Buffer.alloc(0),
    ]);
    const fmt = t.fmt ?? 'none';
    let stmt = new Map<string, CborIn>();
    if (fmt === 'packed') {
      const signed = Buffer.concat([authData, createHash('sha256').update(cdj).digest()]);
      let sig = signWith(t.signer ?? this.key, signed);
      if (t.corruptSig) sig = Buffer.concat([sig.subarray(0, -1), Buffer.of(sig[sig.length - 1]! ^ 1)]);
      stmt = new Map<string, CborIn>([['alg', (t.signer ?? this.key).alg], ['sig', sig]]);
    }
    return { cdj, att: cbor(new Map<string, CborIn>([['fmt', fmt], ['attStmt', stmt], ['authData', authData]])) };
  }

  /** navigator.credentials.get(): { acdj, ad, sig } for this RP. */
  get(o: { rpId: string; origin: string; challenge: string }, t: Tweak = {}): { acdj: Buffer; ad: Buffer; sig: Buffer } {
    const acdj = clientData('webauthn.get', o.challenge, o.origin, t);
    const ext = t.extensions ? cbor(t.extensions) : Buffer.alloc(0);
    const flags = t.flags ?? (UP | UV | (t.extensions ? ED : 0));
    const ad = t.rawAuthData ?? Buffer.concat([
      createHash('sha256').update(t.rpId ?? o.rpId, 'utf8').digest(), Buffer.of(flags), u32(this.next(t)), ext, t.trailing ?? Buffer.alloc(0),
    ]);
    let sig = signWith(t.signer ?? this.key, Buffer.concat([ad, createHash('sha256').update(acdj).digest()]));
    if (t.corruptSig) sig = Buffer.concat([sig.subarray(0, -1), Buffer.of(sig[sig.length - 1]! ^ 1)]);
    return { acdj, ad, sig };
  }
}

// ------------------------------------------------------------------------------------ consent "browser"

export const FLAGS = { UP, UV, AT, ED } as const;

const attrOf = (html: string, name: string) => new RegExp(` ${name}="([^"]*)"`).exec(html)?.[1];

/** What the consent page's #zeusi-keys block says (the script's inputs). */
export function keysOf(html: string): { mode: string; rpId: string; challenge: string; challenge2: string | undefined; salt: string | undefined; creds: Array<{ id: string; salt: string }>; required: boolean } {
  return {
    mode: attrOf(html, 'data-mode')!, rpId: attrOf(html, 'data-rp')!, challenge: attrOf(html, 'data-challenge')!,
    challenge2: attrOf(html, 'data-challenge2'), salt: attrOf(html, 'data-salt'), required: attrOf(html, 'data-required') === 'yes',
    creds: (attrOf(html, 'data-creds') ?? '').split(' ').filter(Boolean).map((x) => { const [id, salt] = x.split('.'); return { id: id!, salt: salt! }; }),
  };
}

const b64u = (b: Buffer) => b.toString('base64url');

/**
 * The form fields CONSENT_SCRIPT posts for an enroll on `html`. `via: 'get'`: create() gave no PRF, so the PRF
 * and an assertion come from get() with challenge2. `create` / `get` bend the respective response.
 */
export function enrollFields(a: SoftAuthenticator, html: string, origin: string, o: { via?: 'create' | 'get'; create?: Tweak; get?: Tweak; prf?: Buffer; cred?: Buffer } = {}): Record<string, string> {
  const k = keysOf(html);
  const salt = Buffer.from(k.salt!, 'base64url');
  const reg = a.create({ rpId: k.rpId, origin, challenge: k.challenge }, o.create);
  const out: Record<string, string> = {
    enc: 'enroll', cred: b64u(o.cred ?? a.credentialId), prf: b64u(o.prf ?? a.prf(salt)), att: b64u(reg.att), cdj: b64u(reg.cdj), acdj: '', ad: '', sig: '',
  };
  if (o.via === 'get') {
    const g = a.get({ rpId: k.rpId, origin, challenge: k.challenge2! }, o.get);
    Object.assign(out, { acdj: b64u(g.acdj), ad: b64u(g.ad), sig: b64u(g.sig) });
  }
  return out;
}

/** The form fields CONSENT_SCRIPT posts for an unlock on `html` (the salt of this authenticator's credential). */
export function unlockFields(a: SoftAuthenticator, html: string, origin: string, o: { get?: Tweak; prf?: Buffer; cred?: Buffer } = {}): Record<string, string> {
  const k = keysOf(html);
  const mine = k.creds.find((c) => c.id === b64u(a.credentialId));
  const salt = Buffer.from(mine?.salt ?? k.creds[0]?.salt ?? '', 'base64url');
  const g = a.get({ rpId: k.rpId, origin, challenge: k.challenge }, o.get);
  return {
    enc: 'unlock', cred: b64u(o.cred ?? a.credentialId), prf: b64u(o.prf ?? a.prf(salt)), att: '', cdj: '', acdj: b64u(g.acdj), ad: b64u(g.ad), sig: b64u(g.sig),
  };
}
