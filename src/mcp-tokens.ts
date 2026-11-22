// Hosted MCP bearer tokens (docs/hosting.md): the token format, the slow hashes and the
// tokens file on the Fly volume. Used by the hosted auth layer (src/mcp-auth.ts) and the
// offline admin CLI (src/mcp-token-admin.ts, `zeusi mcp-token`).
//
//   token      zeusi_<token_id>_<secret>; token_id = 12 chars [a-z2-7] (no "_", safe to log),
//              secret = 32 random bytes, base64url (43 chars, may contain "_" and "-").
//   hash       argon2id (m=19456 KiB, t=2, p=1, dkLen 32, 16-byte salt) over
//              "<token_id>:<secret>", so a row's hash is bound to its id. scrypt rows
//              (N=2^15, r=8, p=1) also verify, as an operator fallback. One slow hash at a time.
//   file       { "version": 1, "tokens": [row, ...] }, file 0600, dir 0700, owned by the
//              process user. Anything else (missing, unreadable, invalid, looser modes, other
//              owner) loads as "unconfigured": the hosted server then answers 503 (fail closed).
//
// The file holds no plaintext token, no Neon password and no OpenAI key. Errors carry a code,
// never a token or a secret.

import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import {
  chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { z } from 'zod';

export const TOKEN_RE = /^zeusi_([a-z2-7]{12})_([A-Za-z0-9_-]{43})$/;
export const TOKEN_ID_RE = /^[a-z2-7]{12}$/;
export const TOKEN_CLASSES = ['read', 'write'] as const;
export type TokenClass = (typeof TOKEN_CLASSES)[number];
/** Assistant label: short, lowercase, safe to log. */
export const LABEL_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
export const TOKENS_PATH_ENV = 'ZEUSI_MCP_TOKENS_PATH';
export const DEFAULT_TOKENS_PATH = '/data/mcp-tokens.json';
export const MAX_EXPIRES_DAYS = 90;

export const ARGON2ID_DEFAULTS = { m: 19456, t: 2, p: 1, dkLen: 32 } as const;
export const SCRYPT_DEFAULTS = { N: 2 ** 15, r: 8, p: 1, dkLen: 32 } as const;
const SALT_BYTES = 16;
const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

export class TokenFileError extends Error {
  override name = 'TokenFileError';
  readonly code: 'locked' | 'invalid' | 'io';
  constructor(code: 'locked' | 'invalid' | 'io', message: string) {
    super(message);
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Format

export function generateToken(): { tokenId: string; secret: string; token: string } {
  // 256 % 32 == 0: masking a byte to 5 bits is unbiased.
  const tokenId = [...randomBytes(12)].map((b) => BASE32[b & 31]).join('');
  const secret = randomBytes(32).toString('base64url');
  return { tokenId, secret, token: `zeusi_${tokenId}_${secret}` };
}

/** The exact token pattern, or null. The id has no "_", so the split is at the first two. */
export function parseToken(s: string): { tokenId: string; secret: string } | null {
  const m = TOKEN_RE.exec(s);
  return m ? { tokenId: m[1]!, secret: m[2]! } : null;
}

/** SHA-256 of a full presented token (the success cache keys on this, never on the token). */
export function tokenDigest(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

// ---------------------------------------------------------------------------
// Hashing

const b64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/);
const ArgonHash = z.strictObject({
  alg: z.literal('argon2id'), m: z.number().int().min(8).max(262144), t: z.number().int().min(1).max(10),
  p: z.number().int().min(1).max(4), dkLen: z.number().int().min(16).max(64), salt: b64, digest: b64,
});
const ScryptHash = z.strictObject({
  alg: z.literal('scrypt'), N: z.number().int().min(1024).max(2 ** 20), r: z.number().int().min(1).max(32),
  p: z.number().int().min(1).max(4), dkLen: z.number().int().min(16).max(64), salt: b64, digest: b64,
});
const HashSpec = z.discriminatedUnion('alg', [ArgonHash, ScryptHash]);
export type HashSpec = z.infer<typeof HashSpec>;
type HashParams = HashSpec extends infer H ? (H extends HashSpec ? Omit<H, 'digest'> : never) : never;

export type HashChoice =
  | { alg: 'argon2id'; params?: { m: number; t: number; p: number; dkLen: number } }
  | { alg: 'scrypt'; params?: { N: number; r: number; p: number; dkLen: number } };

/** One slow hash at a time (bounds memory on the 512 MB machine). */
let slot: Promise<unknown> = Promise.resolve();
function queued<T>(fn: () => Promise<T>): Promise<T> {
  const run = slot.then(fn, fn);
  slot = run.catch(() => undefined);
  return run;
}

function derive(spec: HashParams, input: string): Promise<Buffer> {
  const salt = Buffer.from(spec.salt, 'base64');
  if (salt.length < 8) return Promise.reject(new Error('salt too short'));
  if (spec.alg === 'argon2id') {
    return queued(async () => Buffer.from(await argon2idAsync(input, salt, { m: spec.m, t: spec.t, p: spec.p, dkLen: spec.dkLen })));
  }
  const maxmem = 256 * spec.N * spec.r + 1024 * 1024;
  return queued(() => new Promise<Buffer>((res, rej) => {
    scryptCb(input, salt, spec.dkLen, { N: spec.N, r: spec.r, p: spec.p, maxmem }, (e, k) => (e ? rej(e) : res(k)));
  }));
}

const bound = (tokenId: string, secret: string) => `${tokenId}:${secret}`;

export async function hashSecret(tokenId: string, secret: string, choice: HashChoice = { alg: 'argon2id' }): Promise<HashSpec> {
  const salt = randomBytes(SALT_BYTES).toString('base64');
  const base = choice.alg === 'argon2id'
    ? { alg: 'argon2id' as const, ...(choice.params ?? ARGON2ID_DEFAULTS), salt }
    : { alg: 'scrypt' as const, ...(choice.params ?? SCRYPT_DEFAULTS), salt };
  const digest = (await derive(base, bound(tokenId, secret))).toString('base64');
  return { ...base, digest } as HashSpec;
}

/** Re-hash with the row's own salt and parameters; constant-time compare. Never throws. */
export async function verifySecret(row: Pick<TokenRow, 'token_id' | 'hash'>, secret: string): Promise<boolean> {
  try {
    const want = Buffer.from(row.hash.digest, 'base64');
    const got = await derive(row.hash, bound(row.token_id, secret));
    return want.length === got.length && timingSafeEqual(want, got);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// File

const isoTs = z.iso.datetime({ offset: true });
const TokenRowSchema = z.strictObject({
  token_id: z.string().regex(TOKEN_ID_RE),
  assistant: z.string().regex(LABEL_RE),
  class: z.enum(TOKEN_CLASSES),
  hash: HashSpec,
  issued_at: isoTs,
  expires_at: isoTs,
  revoked_at: isoTs.nullable(),
});
const TokenFileSchema = z.strictObject({ version: z.literal(1), tokens: z.array(TokenRowSchema) });
export type TokenRow = z.infer<typeof TokenRowSchema>;
export type TokenFile = z.infer<typeof TokenFileSchema>;

export function emptyTokenFile(): TokenFile {
  return { version: 1, tokens: [] };
}

export type TokenStore =
  | { state: 'unconfigured'; reason: string }
  | { state: 'loaded'; rows: TokenRow[]; byId: Map<string, TokenRow> };

/** Rows that can authenticate at `now` (not revoked, not expired). */
export function usableRows(rows: readonly TokenRow[], now: number): TokenRow[] {
  return rows.filter((r) => isUsable(r, now));
}

export function isUsable(r: TokenRow, now: number): boolean {
  return r.revoked_at === null && Date.parse(r.expires_at) > now;
}

/** Cheap change signature of the tokens file (and its directory's mode), or null when unreadable. */
export function storeSignature(path: string): string | null {
  try {
    const f = statSync(path);
    const d = statSync(dirname(path));
    return [f.ino, f.size, f.mtimeMs, f.ctimeMs, f.mode, f.uid, d.mode, d.uid].join(':');
  } catch {
    return null;
  }
}

function parseFile(text: string): TokenFile | null {
  let j: unknown;
  try {
    j = JSON.parse(text);
  } catch {
    return null;
  }
  const r = TokenFileSchema.safeParse(j);
  if (!r.success) return null;
  const ids = new Set<string>();
  for (const t of r.data.tokens) {
    if (ids.has(t.token_id)) return null;
    ids.add(t.token_id);
  }
  return r.data;
}

/**
 * Load and validate the tokens file. Fail closed: any problem is `unconfigured` (with a reason
 * code for the operator log, never a path or content).
 */
export function loadTokenStore(path: string, opts: { uid?: number | undefined } = {}): TokenStore {
  const uid = opts.uid ?? process.getuid?.();
  try {
    const d = statSync(dirname(path));
    if (!d.isDirectory() || (d.mode & 0o077) !== 0) return { state: 'unconfigured', reason: 'dir_mode' };
    if (uid !== undefined && d.uid !== uid) return { state: 'unconfigured', reason: 'dir_owner' };
    const f = lstatSync(path);
    if (!f.isFile()) return { state: 'unconfigured', reason: 'not_a_file' };
    if ((f.mode & 0o077) !== 0) return { state: 'unconfigured', reason: 'file_mode' };
    if (uid !== undefined && f.uid !== uid) return { state: 'unconfigured', reason: 'file_owner' };
    const doc = parseFile(readFileSync(path, 'utf8'));
    if (!doc) return { state: 'unconfigured', reason: 'invalid' };
    return { state: 'loaded', rows: doc.tokens, byId: new Map(doc.tokens.map((t) => [t.token_id, t])) };
  } catch {
    return { state: 'unconfigured', reason: 'unreadable' };
  }
}

function errCode(e: unknown): string {
  return String((e as { code?: unknown })?.code ?? 'unknown').replace(/[^A-Z0-9_]/g, '') || 'unknown';
}

/** Read and validate the tokens file for the admin CLI (no mode checks; throws TokenFileError). */
export function readTokenFile(path: string): TokenFile {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new TokenFileError('io', errCode(e) === 'ENOENT' ? 'tokens file not found' : `tokens file not readable (${errCode(e)})`);
  }
  const doc = parseFile(text);
  if (!doc) throw new TokenFileError('invalid', 'tokens file does not validate');
  return doc;
}

/**
 * Read-modify-write the tokens file under an O_EXCL lock file. The new content goes to a
 * 0600 temp file in the same directory, is fsynced and renamed over the old file. A missing
 * directory is created 0700; an existing one must already be 0700 (it is never chmodded).
 * A file that exists but does not validate is never overwritten.
 */
export async function withTokenFile<T extends TokenFile>(path: string, fn: (doc: TokenFile) => T | Promise<T>): Promise<T> {
  const dir = dirname(path);
  let created: string | undefined;
  try {
    created = mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (e) {
    throw new TokenFileError('io', `tokens directory not usable (${errCode(e)})`);
  }
  if (created !== undefined) {
    // Only a directory this call created is chmodded (to undo a umask that might differ).
    try {
      chmodSync(dir, 0o700);
    } catch (e) {
      throw new TokenFileError('io', `tokens directory not usable (${errCode(e)})`);
    }
  } else {
    // An existing directory is never chmodded: it may be $HOME, a repo or a system directory.
    // The server needs 0700 anyway, so a looser one is refused with nothing written.
    const d = statSync(dir);
    if ((d.mode & 0o1000) !== 0 || (d.mode & 0o002) !== 0) {
      throw new TokenFileError('io', 'tokens file must live in a dedicated directory (this one is shared: sticky or world-writable); nothing written');
    }
    if ((d.mode & 0o077) !== 0) {
      throw new TokenFileError('io', 'tokens dir must be 0700 (it is looser; this tool never chmods an existing directory). Use a dedicated directory or chmod 700 it yourself; nothing written');
    }
  }
  const lock = `${path}.lock`;
  let lockFd: number;
  try {
    lockFd = openSync(lock, 'wx', 0o600);
  } catch (e) {
    if (errCode(e) === 'EEXIST') throw new TokenFileError('locked', 'tokens file is locked by another writer (stale? remove the .lock file after checking)');
    throw new TokenFileError('io', `tokens lock not created (${errCode(e)})`);
  }
  try {
    let current: TokenFile;
    let text: string | null = null;
    try {
      text = readFileSync(path, 'utf8');
    } catch (e) {
      if (errCode(e) !== 'ENOENT') throw new TokenFileError('io', `tokens file not readable (${errCode(e)})`);
    }
    if (text === null) current = emptyTokenFile();
    else {
      const parsed = parseFile(text);
      if (!parsed) throw new TokenFileError('invalid', 'tokens file exists but does not validate; refusing to overwrite it');
      current = parsed;
    }
    const next = await fn(current);
    const valid = TokenFileSchema.parse(next);
    const tmp = `${path}.tmp-${randomBytes(6).toString('hex')}`;
    try {
      const fd = openSync(tmp, 'wx', 0o600);
      try {
        writeSync(fd, `${JSON.stringify(valid, null, 2)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      chmodSync(tmp, 0o600);
      renameSync(tmp, path);
    } catch (e) {
      try { unlinkSync(tmp); } catch { /* already gone */ }
      throw new TokenFileError('io', `tokens file not written (${errCode(e)})`);
    }
    try {
      const dfd = openSync(dir, 'r');
      try { fsyncSync(dfd); } finally { closeSync(dfd); }
    } catch { /* directory fsync is best effort (not supported everywhere) */ }
    return next;
  } finally {
    closeSync(lockFd);
    try { unlinkSync(lock); } catch { /* already gone */ }
  }
}
