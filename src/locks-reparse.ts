// `zeusi ingest vault --reparse-frontmatter` (lock-lifecycle addendum K5; docs/note-locks.md).
//
// The vault importer skips a file whose sha is unchanged, so a parser fix never reaches frontmatter
// that is already stored. This runs the importer's own walk and gates in reparse mode
// (importVault({ reparse })): unchanged files only, the stored frontmatter compared with a fresh
// parse (redacted exactly as at ingest), and on --real ONLY notes.frontmatter is updated.
//
//   * DRY RUN (default): everything inside one BEGIN READ ONLY transaction; zero writes; counts.
//   * REAL: the vault importer's advisory lock; one transaction per note; the UPDATE is guarded by
//     id + status active + the same source_sha256; the wall trigger and the provenance trigger run
//     (the stamp is kept: the sha does not change). No chunk, body, title, embedding,
//     quarantine or ingest_runs row is written; nothing is inserted or deleted.
//   * The caller (cli) refuses an owner-privileged session (assertIngestReady), requires the DIRECT
//     endpoint and the main-branch guard for --real.
//
// Output: counts only (notes, frontmatter changed, lock items and current / superseded / expired
// before and after). Never a path, a title or lock text.

import type { Db } from './db.ts';
import { importVault, type VaultImportResult, type VaultScope } from './importers/vault.ts';
import type { SourcesConfig } from './sources.ts';
import { loadLockNotes, resolveLockLifecycle, type LifecycleCounts, type LockNoteInput } from './lock-lifecycle.ts';
import type { VaultFs } from './importers/vault.ts';

export interface ReparseOptions {
  db: Db;
  config: SourcesConfig;
  real: boolean;
  scope?: VaultScope;
  now?: Date;
  home?: string;
  fs?: VaultFs;
}

export interface ReparseResult {
  status: VaultImportResult['status'];
  real: boolean;
  error?: string;
  notes_scanned: number;
  frontmatter_unchanged: number;
  frontmatter_changed: number;
  frontmatter_updated: number;
  file_changed: number;
  not_stored: number;
  blocked: number;
  write_errors: number;
  locks_before: LifecycleCounts;
  locks_after: LifecycleCounts;
}

const LIFECYCLE_FIELDS: ReadonlyArray<[keyof LockNoteInput, string]> = [['locks', 'locks'], ['supersedes', 'supersedes'], ['lockUntil', 'lock_until'], ['until', 'until']];

export async function runReparse(o: ReparseOptions): Promise<ReparseResult> {
  const now = o.now ?? new Date();
  const db = o.db;
  if (!o.real) await db.exec('BEGIN READ ONLY');
  try {
    const before = (await loadLockNotes(db)).notes;
    const r = await importVault({
      db, config: o.config, mode: 'full', reparse: { real: o.real, ...(o.scope ? { scope: o.scope } : {}) },
      ...(o.home ? { home: o.home } : {}), ...(o.fs ? { fs: o.fs } : {}), logPaths: false,
    });
    const rc = r.reparse?.counts;
    const changes = r.reparse?.changes ?? [];
    // After = the stored lifecycle input with the re-parsed frontmatter of the changed notes.
    const byId = new Map(before.map((n) => [n.noteId, n]));
    const missing = changes.filter((c) => !byId.has(c.id)).map((c) => c.id);
    if (missing.length) {
      const extra = (await db.query<Record<string, unknown>>(
        `SELECT id::int AS note_id, vault_path, title, scope::text AS scope, source_uri, source_ts FROM zeusi.notes WHERE id = ANY($1::bigint[]) AND status = 'active'`,
        [missing])).rows;
      for (const x of extra) {
        byId.set(Number(x['note_id']), {
          noteId: Number(x['note_id']), vaultPath: String(x['vault_path']), title: String(x['title']), scope: String(x['scope']),
          sourceUri: String(x['source_uri']), sourceTs: new Date(x['source_ts'] as string).toISOString(), locks: null, supersedes: null, lockUntil: null, until: null,
        });
      }
    }
    const after = new Map(byId);
    for (const c of changes) {
      const base = after.get(c.id);
      if (!base) continue;
      const next = { ...base };
      for (const [field, key] of LIFECYCLE_FIELDS) (next as Record<string, unknown>)[field] = c.after[key] ?? null;
      after.set(c.id, next);
    }
    const lb = resolveLockLifecycle(before, now).counts;
    const la = resolveLockLifecycle([...after.values()], now).counts;
    return {
      status: r.status, real: o.real, ...(r.error ? { error: r.error } : {}),
      notes_scanned: rc?.scanned ?? 0, frontmatter_unchanged: rc?.unchanged ?? 0, frontmatter_changed: rc?.changed ?? 0,
      frontmatter_updated: rc?.updated ?? 0, file_changed: rc?.file_changed ?? 0, not_stored: rc?.not_stored ?? 0, blocked: rc?.blocked ?? 0,
      write_errors: rc?.write_errors ?? 0, locks_before: lb, locks_after: la,
    };
  } finally {
    if (!o.real) await db.exec('ROLLBACK').catch(() => {});
  }
}

/** Counts only. */
export function formatReparse(r: ReparseResult): string {
  const l = (c: LifecycleCounts) => `${c.items} item(s) in ${c.notes} note(s): current ${c.current}, superseded ${c.superseded}, expired ${c.expired}`;
  const lines = [
    `vault frontmatter reparse (${r.real ? 'REAL: notes.frontmatter only' : 'dry run: READ ONLY, nothing written'}): status ${r.status}`,
  ];
  if (r.status === 'locked' || r.status === 'failed') {
    lines.push(`  ${r.error ?? r.status}`);
    if (r.status === 'locked') return lines.join('\n');
  }
  lines.push(`  notes scanned (unchanged files, stored): ${r.notes_scanned}`);
  lines.push(`  frontmatter changed: ${r.frontmatter_changed}${r.real ? `, updated: ${r.frontmatter_updated}, write errors: ${r.write_errors}` : ' (would update)'}; unchanged: ${r.frontmatter_unchanged}`);
  lines.push(`  left to \`ingest vault\`: file changed ${r.file_changed}, not stored ${r.not_stored}; content wall blocks now: ${r.blocked} (left untouched)`);
  lines.push(`  lock items before: ${l(r.locks_before)}`);
  lines.push(`  lock items after:  ${l(r.locks_after)}`);
  lines.push(`  lifecycle claims after: supersede applied ${r.locks_after.supersede_applied}, unresolved ${r.locks_after.supersede_unresolved}, invalid ${r.locks_after.supersede_invalid}; until set ${r.locks_after.until_set}, invalid ${r.locks_after.until_invalid}`);
  return lines.join('\n');
}
