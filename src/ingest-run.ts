// Importer run bookkeeping (PLAN.md "Idempotency and runs", KTD13).
// Every importer run opens one zeusi.ingest_runs row and closes it with status and
// counts (numbers only: no paths, no content). Incremental runs key off the last ok
// run; a full re-hash is due when the last ok FULL run is older than a week.

import { createHash } from 'node:crypto';
import type { Db } from './db.ts';
import { closeRun, openRun, type RunInput } from './facts.ts';

export { closeRun, openRun, type RunInput };

export const WEEKLY_FULL_MS = 7 * 24 * 3600 * 1000;

export interface VaultCounts {
  /** Notes written for the first time (dry run: would be written). */
  inserted: number;
  /** Existing notes rewritten (content, scope, or deleted -> active). */
  updated: number;
  /** Unchanged notes (same sha, scope, active) and, in incremental runs, files not opened. */
  skipped: number;
  /** Items refused by the wall: path-gated files/dirs plus notes with a blocked note or chunk row. */
  quarantined: number;
  /** Active notes whose file is gone: status -> deleted, chunks removed. */
  deleted: number;
  /** Per-file errors (non-UTF-8, too large, changed while read, hard link, unexpected DB error). Never content. */
  errors: number;
  /** Of errors: regular files with more than one link (nlink > 1); refused unopened (a hard link can alias a walled file). */
  hardlinks: number;
  /** Of quarantined: refused by the path gates before any open. */
  path_gated: number;
  /** Of quarantined: caught by the DB trigger (ZW001) after the pre-check passed. */
  backstop: number;
  /** quarantine rows written (a note can add a note row and chunk rows). */
  quarantine_rows: number;
  /** Previously active notes whose new version is quarantined: their chunks are removed from search. */
  retracted: number;
  chunks_written: number;
  /** New chunks that kept the vector of an old chunk with the same text sha. */
  vectors_reused: number;
  /** Admitted notes whose text had at least one secret redacted at ingest (src/secrets.ts). */
  notes_redacted: number;
  /** Secrets replaced by [REDACTED:<kind>] at ingest (count only, never the text). */
  secrets_redacted: number;
  /** Symlinked directories (never followed). */
  symlink_dirs_skipped: number;
  /** Admitted notes (inserted + updated + skipped-unchanged) by scope. */
  by_scope: Record<string, number>;
  /** Quarantined items by first-hit wall rule id ("none" when no rule applies, e.g. a symlink leaving the vault). */
  by_rule: Record<string, number>;
}

export function emptyCounts(): VaultCounts {
  return {
    inserted: 0, updated: 0, skipped: 0, quarantined: 0, deleted: 0, errors: 0, hardlinks: 0,
    path_gated: 0, backstop: 0, quarantine_rows: 0, retracted: 0, chunks_written: 0, vectors_reused: 0, notes_redacted: 0, secrets_redacted: 0,
    symlink_dirs_skipped: 0, by_scope: {}, by_rule: {},
  };
}

export function bump(m: Record<string, number>, k: string, n = 1): void {
  m[k] = (m[k] ?? 0) + n;
}

/** Start time of the last ok run of this importer (any mode), or null. */
export async function lastOkRunStart(db: Db, importer: string, mode?: 'full'): Promise<Date | null> {
  const r = await db.query<{ t: Date | null }>(
    `SELECT max(started_at) AS t FROM zeusi.ingest_runs
     WHERE importer = $1 AND status = 'ok' AND ($2::text IS NULL OR mode = $2::text)`,
    [importer, mode ?? null],
  );
  const t = r.rows[0]?.t;
  return t ? new Date(t) : null;
}

/** 'full' when asked, or when no ok full run started within the last week. */
export async function resolveMode(db: Db, importer: string, wanted: 'full' | 'incremental', now: Date): Promise<'full' | 'incremental'> {
  if (wanted === 'full') return 'full';
  const lastFull = await lastOkRunStart(db, importer, 'full');
  return lastFull && now.getTime() - lastFull.getTime() < WEEKLY_FULL_MS ? 'incremental' : 'full';
}

/**
 * Session advisory lock key for one importer (63-bit, from sha256 of the name), so two
 * concurrent runs of the same importer cannot interleave (review r1 MINOR-5).
 */
export function importerLockKey(importer: string): string {
  return BigInt(`0x${createHash('sha256').update(`zeusi-ingest:${importer}`, 'utf8').digest('hex').slice(0, 15)}`).toString();
}

/** pg_try_advisory_lock for the importer; false when another session holds it. Call before openRun. */
export async function tryLockImporter(db: Db, importer: string): Promise<boolean> {
  const r = await db.query<{ ok: boolean }>(`SELECT pg_try_advisory_lock($1::bigint) AS ok`, [importerLockKey(importer)]);
  return r.rows[0]?.ok === true;
}

export async function unlockImporter(db: Db, importer: string): Promise<void> {
  await db.query(`SELECT pg_advisory_unlock($1::bigint)`, [importerLockKey(importer)]);
}
