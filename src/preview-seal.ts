// Sealed import-preview staging (docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD3). EPHEMERAL STAGING
// HYGIENE ONLY: this is not workspace encryption and says nothing about how a workspace is stored.
//
// A kept preview (src/workspace-write.ts) waits up to 30 minutes for the user's yes. During that time
// its prepared run (the filtered notes the commit will import) stays on the work disk. sealRun() turns
// every file of that run into an AES-256-GCM sealed file under a neutral name (`sealed/000001`, ...):
//   * one random 256-bit key per preview, held only in this process's memory (never written, never
//     logged); destroySealed() zero-fills it, and a restart loses it (the work root is also wiped at
//     start), so a leftover sealed file can never be opened again;
//   * a random 96-bit nonce per file; file bytes = nonce (12) || tag (16) || ciphertext;
//   * AAD = "zeusi-preview-v1" || u16 length || relative path, so a sealed file put in another file's
//     place fails its tag;
//   * the relative paths (which name the notes) live only in memory, beside the key.
// readSealed() opens one file in memory (the preview's title / first line); unsealRun() writes the run
// back into a fresh private directory only for the commit call, which removes it in `finally`.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { gatedRunDir } from './run-dir.ts';

const AAD_LABEL = 'zeusi-preview-v1';
const NONCE = 12;
const TAG = 16;
export const SEALED_DIR = 'sealed';

export interface SealedRun {
  /** The run directory: it holds only `sealed/` once sealRun() returns. */
  readonly dir: string;
  /** Relative path (inside the original run) -> neutral sealed file name. In memory only. */
  readonly entries: ReadonlyMap<string, string>;
  /** The per-preview key; null once destroyed. */
  key: Buffer | null;
}

export class SealError extends Error {
  override name = 'SealError';
}

function aad(rel: string): Buffer {
  const r = Buffer.from(rel, 'utf8');
  if (r.length > 0xffff) throw new SealError('sealed path too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(r.length);
  return Buffer.concat([Buffer.from(AAD_LABEL, 'utf8'), len, r]);
}

function seal(key: Buffer, rel: string, plain: Buffer): Buffer {
  const nonce = randomBytes(NONCE);
  const c = createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(aad(rel));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([nonce, c.getAuthTag(), ct]);
}

function open(key: Buffer, rel: string, sealed: Buffer): Buffer {
  if (sealed.length < NONCE + TAG) throw new SealError('sealed file too short');
  const d = createDecipheriv('aes-256-gcm', key, sealed.subarray(0, NONCE));
  d.setAAD(aad(rel));
  d.setAuthTag(sealed.subarray(NONCE, NONCE + TAG));
  try {
    return Buffer.concat([d.update(sealed.subarray(NONCE + TAG)), d.final()]);
  } catch {
    throw new SealError('sealed file does not open');
  }
}

/** Regular files below `dir` (relative, `/`-separated), never through a symlink. */
function filesOf(dir: string): string[] {
  const out: string[] = [];
  const walk = (abs: string) => {
    for (const name of readdirSync(abs).sort()) {
      const p = join(abs, name);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) throw new SealError('unexpected link in a preview run');
      if (st.isDirectory()) walk(p);
      else if (st.isFile()) out.push(relative(dir, p).split(sep).join('/'));
      else throw new SealError('unexpected entry in a preview run');
    }
  };
  walk(dir);
  return out;
}

/**
 * Seal every file of the run directory `dir` in place: afterwards `dir` holds only `sealed/<ordinal>`
 * files (0600, dir 0700). On any error everything below `dir` is removed and the error rethrown.
 */
export function sealRun(dir: string): SealedRun {
  const key = randomBytes(32);
  const entries = new Map<string, string>();
  try {
    const files = filesOf(dir);
    if (files.includes(SEALED_DIR) || files.some((f) => f.startsWith(`${SEALED_DIR}/`))) throw new SealError('a preview run already holds sealed files');
    const out = join(dir, SEALED_DIR);
    mkdirSync(out, { mode: 0o700 });
    files.forEach((rel, i) => {
      const name = String(i + 1).padStart(6, '0');
      writeFileSync(join(out, name), seal(key, rel, readFileSync(join(dir, rel))), { mode: 0o600, flag: 'wx' });
      entries.set(rel, name);
    });
    // Only the sealed copies stay: every original entry (files and their directories) goes.
    for (const name of readdirSync(dir)) if (name !== SEALED_DIR) rmSync(join(dir, name), { recursive: true, force: true });
    return { dir, entries, key };
  } catch (e) {
    key.fill(0);
    for (const name of safeList(dir)) rmSync(join(dir, name), { recursive: true, force: true });
    throw e;
  }
}

function safeList(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

function liveKey(s: SealedRun): Buffer {
  if (!s.key) throw new SealError('the preview key is gone');
  return s.key;
}

/** One file of the sealed run, opened in memory (null when the run has no such file). */
export function readSealed(s: SealedRun, rel: string): Buffer | null {
  const name = s.entries.get(rel);
  if (name === undefined) return null;
  return open(liveKey(s), rel, readFileSync(join(s.dir, SEALED_DIR, name)));
}

/**
 * Write the run back (original relative paths) into a fresh private directory under `parent`
 * (`run-*`, 0700; files 0600) for the duration of one commit. The caller removes it with cleanup(),
 * in `finally`; on error here it is removed before the error is rethrown.
 */
export function unsealRun(s: SealedRun, parent: string, accept: (dir: string) => boolean, name?: () => string): { workDir: string; cleanup: () => void } {
  const key = liveKey(s);
  // The run dir's random name must pass the path gate the importer applies to it (src/run-dir.ts; #55 CI).
  const workDir = gatedRunDir(parent, 'run-', accept, name);
  const cleanup = () => rmSync(workDir, { recursive: true, force: true });
  try {
    for (const [rel, name] of s.entries) {
      const target = join(workDir, ...rel.split('/'));
      if (relative(workDir, target).startsWith('..')) throw new SealError('sealed path escapes the run');
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      writeFileSync(target, open(key, rel, readFileSync(join(s.dir, SEALED_DIR, name))), { mode: 0o600, flag: 'wx' });
    }
    return { workDir, cleanup };
  } catch (e) {
    cleanup();
    throw e;
  }
}

/** Forget the key (zero-filled) and remove the sealed files. Idempotent. */
export function destroySealed(s: SealedRun): void {
  s.key?.fill(0);
  s.key = null;
  rmSync(s.dir, { recursive: true, force: true });
}
