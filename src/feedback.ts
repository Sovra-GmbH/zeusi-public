// "Did this answer it?" ledger for zeusi_search hits (docs/mcp.md). LOCAL file on the
// machine that runs the MCP server, like the query-embed ledger (src/search.ts): no DB
// row, so no migration and no write role. ~/.zeusi/search-feedback.jsonl, dir 0700 (an
// existing looser dir is tightened on every write), file 0600, one JSON line per answer:
// ts, query_id, source_uri, useful, optional short reason.
// Never the query text, never chunk text, never secrets, never walled content (the MCP
// server refuses such input before calling record()).
//
// Personal workspaces (C2, docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD1, KTD2): their ledger
// (src/mcp-hosted.ts workspaceFeedbackPath) never holds the hit's source_uri (a synced path carries
// the note's file name) nor a free-text reason. A line is: ts, query_id, uri_hmac
// (HMAC-SHA256(K_hash, uri), hex), uri_key (the key id), useful. For C2, K_hash is a random 256-bit
// key in a 0600 file beside that workspace's ledger. Honest limit: whoever can read the data volume
// (root on the machine, the host, a volume snapshot) has that key, and the operator holds every
// source_uri in the database, so they can recompute the HMAC and match lines. It keeps paths out of
// casual reads, greps and log scraping of the ledger only. Later chips derive K_hash from the
// workspace key instead (uri_key "dek-v<n>"); the C2 key file can then be deleted. the team's own
// ledger is unchanged (D4).

import { createHmac, randomBytes } from 'node:crypto';
import {
  appendFileSync, chmodSync, closeSync, constants as fsc, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, rmSync, writeSync,
} from 'node:fs';
import type { Stats } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const FEEDBACK_REASON_MAX = 200;

export function defaultFeedbackPath(home: string = homedir()): string {
  return join(home, '.zeusi', 'search-feedback.jsonl');
}

export interface FeedbackEntry {
  queryId: string;
  sourceUri: string;
  useful: boolean;
  reason?: string | undefined;
}

export function recordFeedback(path: string, e: FeedbackEntry, now: Date = new Date()): void {
  appendLine(path, JSON.stringify({
    ts: now.toISOString(), query_id: e.queryId, source_uri: e.sourceUri, useful: e.useful,
    ...(e.reason !== undefined && e.reason !== '' ? { reason: e.reason } : {}),
  }));
}

function privateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700); // mkdir's mode applies only on create: tighten an existing looser dir
}

function appendLine(path: string, line: string): void {
  privateDir(dirname(path));
  appendFileSync(path, `${line}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** Key id of the C2 per-workspace file key (KTD1). */
export const WORKSPACE_URI_KEY_ID = 'c2-file-v1';
/** The key file, beside the workspace's ledger. */
export const WORKSPACE_URI_KEY_FILE = 'feedback-uri.key';
const URI_HMAC_LABEL = 'zeusi-feedback-uri-v1';

export class FeedbackKeyError extends Error {
  override name = 'FeedbackKeyError';
}

/** TEST seam for the durable key-file write: what is fsynced, and when. */
export interface UriKeyIo {
  fsync?: ((fd: number, what: 'file' | 'dir') => void) | undefined;
}

const notFound = (e: unknown) => (e as NodeJS.ErrnoException).code === 'ENOENT';

/**
 * The workspace's C2 URI key: read from `<dir>/feedback-uri.key`, or created there once (32 random
 * bytes, 0600). Created durably: written whole to a private temp file, the temp file fsynced, linked
 * into place (link never replaces an existing entry), then the directory fsynced, so neither a
 * process crash nor a host crash can leave a short key file after the key was first used.
 * Recovery (review C2R1-3): a 0-byte regular file owned by this user is what an older, unsynced
 * create can leave after a host crash; no ledger line can depend on it (an empty key was always
 * refused), so it is removed and the key is created again. Refused (nothing recorded) when the entry
 * is anything else that is not a regular file of exactly 32 bytes owned by this user, e.g. a symlink
 * or a short non-empty file.
 */
export function workspaceUriKey(dir: string, io: UriKeyIo = {}): Buffer {
  const sync = io.fsync ?? ((fd: number) => fsyncSync(fd));
  privateDir(dir);
  const path = join(dir, WORKSPACE_URI_KEY_FILE);
  const ownedByMe = (uid: number) => typeof process.getuid !== 'function' || uid === process.getuid();
  let st = lstatOrNull(path);
  if (st && st.isFile() && st.size === 0 && ownedByMe(st.uid)) {
    try {
      rmSync(path, { force: true });
    } catch {
      throw new FeedbackKeyError('feedback key is not usable; nothing recorded');
    }
    st = null;
  }
  if (!st) {
    const tmp = join(dir, `.${WORKSPACE_URI_KEY_FILE}.${randomBytes(8).toString('hex')}.tmp`);
    try {
      const fd = openSync(tmp, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | (fsc.O_NOFOLLOW ?? 0), 0o600);
      try {
        const key = randomBytes(32);
        try {
          if (writeSync(fd, key) !== 32) throw new Error('short write');
        } finally {
          key.fill(0);
        }
        sync(fd, 'file');
      } finally {
        closeSync(fd);
      }
      let linked = true;
      try {
        linkSync(tmp, path);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e; // another request created it first
        linked = false;
      }
      if (linked) {
        const dfd = openSync(dir, fsc.O_RDONLY | (fsc.O_DIRECTORY ?? 0));
        try {
          sync(dfd, 'dir');
        } finally {
          closeSync(dfd);
        }
      }
    } catch {
      throw new FeedbackKeyError('feedback key could not be created; nothing recorded');
    } finally {
      rmSync(tmp, { force: true });
    }
    st = lstatOrNull(path);
  }
  if (!st || !st.isFile() || st.size !== 32 || !ownedByMe(st.uid)) {
    throw new FeedbackKeyError('feedback key is not usable; nothing recorded');
  }
  chmodSync(path, 0o600);
  const key = readFileSync(path);
  if (key.length !== 32) throw new FeedbackKeyError('feedback key is not usable; nothing recorded');
  return key;
}

function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch (e) {
    if (notFound(e)) return null;
    throw new FeedbackKeyError('feedback key is not usable; nothing recorded');
  }
}

/** HMAC-SHA256(key, label || 0x00 || uri), hex. */
export function uriHmac(key: Buffer, uri: string): string {
  return createHmac('sha256', key).update(`${URI_HMAC_LABEL}\0${uri}`, 'utf8').digest('hex');
}

/**
 * A personal workspace's feedback line (KTD1, KTD2): the hit as a keyed hash, no reason. `path` is the
 * workspace's own ledger (src/mcp-hosted.ts workspaceFeedbackPath); the key lives beside it.
 */
export function recordWorkspaceFeedback(path: string, e: Omit<FeedbackEntry, 'reason'>, now: Date = new Date()): void {
  const key = workspaceUriKey(dirname(path));
  try {
    appendLine(path, JSON.stringify({
      ts: now.toISOString(), query_id: e.queryId, uri_hmac: uriHmac(key, e.sourceUri), uri_key: WORKSPACE_URI_KEY_ID, useful: e.useful,
    }));
  } finally {
    key.fill(0);
  }
}

const squash = (s: string) => s.replace(/\s+/g, ' ').trim().toLowerCase();

/** True when `reason` copies a run of >= `window` characters from any of the texts. */
export function copiesText(reason: string, texts: readonly string[], window = 32): boolean {
  const r = squash(reason);
  if (r.length < window) return texts.some((t) => r.length >= 16 && squash(t).includes(r));
  const hay = texts.map(squash);
  for (let i = 0; i + window <= r.length; i++) {
    const w = r.slice(i, i + window);
    if (hay.some((h) => h.includes(w))) return true;
  }
  return false;
}
