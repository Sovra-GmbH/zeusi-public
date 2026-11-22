// `zeusi rescrub` (security P0, 17 Nov 2026): re-scrub rows that were ingested before the
// shared credential detector (src/secrets.ts) existed.
//
// Role: the ingest service (zeusi_ingest, DIRECT endpoint), like every other write command
// of the importer. No new role, no migration.
//
//   dry run (default): one READ ONLY transaction. Scans zeusi.notes (title, body,
//     frontmatter), zeusi.chunks (heading_path, text), zeusi.facts (subject, text) and
//     zeusi.decisions (exact_words, applies_to, expires_rule, linked_job) and reports COUNTS
//     ONLY (rows scanned / matched, secrets by kind). Writes zero rows.
//   real (--real): holds the vault and hq-sync importer locks (no ingest interleaves), opens
//     one ingest_runs row (importer rescrub, mode manual), then per row, in its own
//     transaction: notes get the redacted title / body / frontmatter; chunks get the
//     redacted heading_path / text (text_sha256 and token_count recomputed) and their
//     embedding cleared (embedding, embed_model, embedded_at = NULL) so `embed` re-embeds
//     them. Chunks of a note whose title changed are cleared too (the title is part of the
//     embedded string). source_sha256 is NOT changed: it stays the sha of the source file, so
//     an unchanged file is skipped by the next incremental ingest and its redacted row stays.
//     Facts and decisions are insert-only for zeusi_ingest (0004): they are counted and
//     listed by id for the owner (supersede with a redacted copy); the serve-time guard
//     withholds them from every MCP response meanwhile.
//   Idempotent: redacted text never matches again, so a second run changes nothing.
//
// Output: counts, kinds and row ids only. Never text, titles, paths or the matched characters.

import { estimateTokens } from './chunking.ts';
import type { Db } from './db.ts';
import { asPgError } from './db.ts';
import { closeRun, openRun } from './facts.ts';
import { tryLockImporter, unlockImporter } from './ingest-run.ts';
import { addCounts, formatKinds, redactDeep as redactDeep0, redactSecrets as redactSecrets0, STORAGE_SKIP, type SecretKind } from './secrets.ts';

// Stored data: the same rules as ingest (one-time codes are not rewritten, see STORAGE_SKIP).
const redactSecrets = (s: string) => redactSecrets0(s, { skip: STORAGE_SKIP });
const redactDeep = <T>(v: T) => redactDeep0(v, { skip: STORAGE_SKIP });

export const RESCRUB_IMPORTER = 'rescrub';
/** Importers whose runs must not interleave with a real rescrub. */
const LOCKS = ['vault', 'hq-sync', RESCRUB_IMPORTER] as const;
const PAGE = 500;

export class RescrubRefused extends Error {
  override name = 'RescrubRefused';
}

type Table = 'notes' | 'chunks' | 'facts' | 'decisions';

export interface RescrubCounts {
  scanned: Record<Table, number>;
  matched: Record<Table, number>;
  /** Secrets found, by kind (all tables). */
  by_kind: Partial<Record<SecretKind, number>>;
  /** Real run only. */
  notes_rewritten: number;
  chunks_rewritten: number;
  /** Chunks whose embedding was cleared (re-embed through `embed`). */
  chunks_flagged_reembed: number;
  /** Rows a per-row write refused (wall trigger, RLS, ...): error class only. */
  write_errors: number;
  /** Fact / decision ids that need the owner (insert-only for the ingest role). */
  owner_followup: { facts: number[]; decisions: number[] };
}

export interface RescrubResult {
  status: 'ok' | 'locked' | 'failed';
  real: boolean;
  runId: number | null;
  counts: RescrubCounts;
  error?: string;
}

export interface RescrubOptions {
  db: Db;
  real: boolean;
  /** ingest_runs.host (default 'mini'). */
  host?: string;
  log?: (line: string) => void;
}

function emptyCounts(): RescrubCounts {
  const z = () => ({ notes: 0, chunks: 0, facts: 0, decisions: 0 });
  return {
    scanned: z(), matched: z(), by_kind: {}, notes_rewritten: 0, chunks_rewritten: 0, chunks_flagged_reembed: 0, write_errors: 0,
    owner_followup: { facts: [], decisions: [] },
  };
}

/** Keyset pages over one table (id order). */
async function* pages<T extends { id: number }>(db: Db, sql: string): AsyncGenerator<T[]> {
  let after = 0;
  for (;;) {
    const rows = (await db.query<T>(sql, [after, PAGE])).rows;
    if (rows.length === 0) return;
    yield rows;
    after = Number(rows[rows.length - 1]!.id);
  }
}

/** One row update in its own transaction; a refusal is counted (error class only), never thrown. */
async function writeRow(db: Db, counts: RescrubCounts, fn: () => Promise<void>): Promise<boolean> {
  try {
    await db.exec('BEGIN');
    await fn();
    await db.exec('COMMIT');
    return true;
  } catch {
    await db.exec('ROLLBACK').catch(() => {});
    counts.write_errors++;
    return false;
  }
}

export async function runRescrub(opts: RescrubOptions): Promise<RescrubResult> {
  const { db, real } = opts;
  const counts = emptyCounts();
  const held: string[] = [];
  let runId: number | null = null;

  // The caller refuses an owner-privileged session first (cli: assertIngestReady, as for ingest).
  try {
    if (real) {
      for (const l of LOCKS) {
        if (!(await tryLockImporter(db, l))) {
          return { status: 'locked', real, runId, counts, error: `another ${l} run holds its lock; nothing was changed` };
        }
        held.push(l);
      }
      runId = await openRun(db, { importer: RESCRUB_IMPORTER, host: opts.host ?? 'mini', mode: 'manual' });
    } else {
      await db.exec('BEGIN READ ONLY');
    }

    // ---- notes
    const retitled = new Set<number>();
    for await (const rows of pages<{ id: number; title: string; body: string; frontmatter: unknown }>(db,
      `SELECT id::int AS id, title, body, frontmatter FROM zeusi.notes WHERE id > $1 ORDER BY id LIMIT $2`)) {
      for (const r of rows) {
        counts.scanned.notes++;
        const t = redactSecrets(r.title);
        const b = redactSecrets(r.body);
        const f = redactDeep(r.frontmatter);
        const n = t.count + b.count + f.count;
        if (n === 0) continue;
        counts.matched.notes++;
        addCounts(counts.by_kind, t.byKind);
        addCounts(counts.by_kind, b.byKind);
        addCounts(counts.by_kind, f.byKind);
        if (!real) continue;
        const ok = await writeRow(db, counts, async () => {
          await db.query(`UPDATE zeusi.notes SET title = $2, body = $3, frontmatter = $4::jsonb WHERE id = $1`,
            [r.id, t.text, b.text, JSON.stringify(f.value)]);
        });
        if (ok) {
          counts.notes_rewritten++;
          if (t.count > 0) retitled.add(Number(r.id));
        }
      }
    }

    // ---- chunks
    for await (const rows of pages<{ id: number; note_id: number | null; heading_path: string | null; text: string; embedded: boolean }>(db,
      `SELECT id::int AS id, note_id::int AS note_id, heading_path, text, embedding IS NOT NULL AS embedded
       FROM zeusi.chunks WHERE id > $1 ORDER BY id LIMIT $2`)) {
      for (const r of rows) {
        counts.scanned.chunks++;
        const h = r.heading_path === null ? { text: null, count: 0, byKind: {} } : redactSecrets(r.heading_path);
        const x = redactSecrets(r.text);
        const n = h.count + x.count;
        const staleTitle = r.note_id !== null && retitled.has(Number(r.note_id)) && r.embedded;
        if (n === 0 && !staleTitle) continue;
        if (n > 0) {
          counts.matched.chunks++;
          addCounts(counts.by_kind, h.byKind);
          addCounts(counts.by_kind, x.byKind);
        }
        if (!real) continue;
        const ok = await writeRow(db, counts, async () => {
          await db.query(
            `UPDATE zeusi.chunks SET heading_path = $2, text = $3::text, text_sha256 = sha256(convert_to($3::text, 'UTF8')),
                    token_count = $4, embedding = NULL, embed_model = NULL, embedded_at = NULL
             WHERE id = $1`,
            [r.id, h.text, x.text, estimateTokens(x.text)]);
        });
        if (ok) {
          if (n > 0) counts.chunks_rewritten++;
          counts.chunks_flagged_reembed++;
        }
      }
    }

    // ---- facts / decisions: counted; insert-only for the ingest role (owner follow-up by id)
    for await (const rows of pages<{ id: number; subject: string | null; text: string }>(db,
      `SELECT id::int AS id, subject, text FROM zeusi.facts WHERE id > $1 ORDER BY id LIMIT $2`)) {
      for (const r of rows) {
        counts.scanned.facts++;
        const d = redactDeep([r.subject, r.text]);
        if (d.count === 0) continue;
        counts.matched.facts++;
        addCounts(counts.by_kind, d.byKind);
        counts.owner_followup.facts.push(Number(r.id));
      }
    }
    for await (const rows of pages<{ id: number; exact_words: string; applies_to: string[]; expires_rule: string | null; linked_job: string | null }>(db,
      `SELECT id::int AS id, exact_words, applies_to, expires_rule, linked_job FROM zeusi.decisions WHERE id > $1 ORDER BY id LIMIT $2`)) {
      for (const r of rows) {
        counts.scanned.decisions++;
        const d = redactDeep([r.exact_words, r.applies_to, r.expires_rule, r.linked_job]);
        if (d.count === 0) continue;
        counts.matched.decisions++;
        addCounts(counts.by_kind, d.byKind);
        counts.owner_followup.decisions.push(Number(r.id));
      }
    }

    if (real) await closeRun(db, runId!, counts.write_errors > 0 ? 'ok_partial' : 'ok', summary(counts));
    return { status: 'ok', real, runId, counts };
  } catch (e) {
    const msg = `rescrub failed (${asPgError(e).code ?? (e instanceof Error ? e.name : 'error')})`;
    if (real && runId !== null) await closeRun(db, runId, 'failed', { ...summary(counts), failure: msg }).catch(() => {});
    return { status: 'failed', real, runId, counts, error: msg };
  } finally {
    if (!real) await db.exec('ROLLBACK').catch(() => {});
    for (const l of held.reverse()) await unlockImporter(db, l).catch(() => {});
  }
}

/** Counts for ingest_runs.counts (numbers and kinds only). */
function summary(c: RescrubCounts): Record<string, unknown> {
  return {
    scanned: c.scanned, matched: c.matched, by_kind: c.by_kind, notes_rewritten: c.notes_rewritten, chunks_rewritten: c.chunks_rewritten,
    chunks_flagged_reembed: c.chunks_flagged_reembed, write_errors: c.write_errors,
    owner_followup: { facts: c.owner_followup.facts.length, decisions: c.owner_followup.decisions.length },
  };
}

/** Counts, kinds and ids only. */
export function formatRescrub(r: RescrubResult): string {
  const c = r.counts;
  const t = (k: Table) => `${k} ${c.matched[k]}/${c.scanned[k]}`;
  const lines = [`rescrub (${r.real ? `REAL, run ${r.runId ?? '?'}` : 'dry run: read-only, zero rows written'}): status ${r.status}`];
  if (r.status === 'locked') {
    lines.push(`  ${r.error ?? 'locked'}`);
    return lines.join('\n');
  }
  lines.push(`  rows matched/scanned: ${t('notes')}, ${t('chunks')}, ${t('facts')}, ${t('decisions')}`);
  lines.push(`  secrets by kind: ${formatKinds(c.by_kind)}`);
  if (r.real) {
    lines.push(`  rewritten: notes ${c.notes_rewritten}, chunks ${c.chunks_rewritten}; chunks flagged for re-embed: ${c.chunks_flagged_reembed}; write errors: ${c.write_errors}`);
  } else {
    lines.push(`  would rewrite: notes ${c.matched.notes}, chunks ${c.matched.chunks} (and clear their embeddings for re-embed)`);
  }
  const f = c.owner_followup;
  if (f.facts.length || f.decisions.length) {
    lines.push(`  owner follow-up (insert-only for the ingest role; withheld at serve meanwhile): facts [${f.facts.join(', ')}], decisions [${f.decisions.join(', ')}]`);
  }
  if (r.error) lines.push(`  FAILED: ${r.error}`);
  return lines.join('\n');
}
