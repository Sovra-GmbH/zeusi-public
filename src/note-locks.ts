// Rules from note locks, derived at READ time (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md,
// Fix PR A, A1/A2, and the "Lock lifecycle" addendum; root cause: lanes/zeusi-v2-prime/
// DIG-startup-links.md D1-rules). The vault importer stores every note's `locks:` frontmatter list
// in zeusi.notes.frontmatter (scoped, wall-gated, upserted and deleted with the note). The readers
// take the lock items from there, through ONE resolver (src/lock-lifecycle.ts):
//
//   * active notes only; `locks` as a list, or a single string (one item); blank items skipped;
//     the item text is returned VERBATIM (the note's own words);
//   * each item is current, superseded (an explicit, newer `supersedes:` claim) or expired
//     (`lock_until:` / `until:` in the past); only CURRENT items are served as rules or task
//     items; superseded / expired matches of a task go to a separate `history` list;
//   * `who` is always null: a note lock has no recorded speaker, and none is invented;
//   * the queries run inside the caller's BEGIN READ ONLY transaction as the caller's read-only
//     role, so RLS (never personal) applies; nothing here writes;
//   * zeusi_startup serves the STANDING set (STANDING_LOCK_PREFIXES, or a `standing_locks:`
//     marker) with facts_current kind rule: every one is served in compact form within a token
//     budget or listed in rules_remainder (src/startup-rules.ts); zeusi_onboarding_status counts
//     the same set; zeusi_context_for_task matches all notes by the task terms (taskTerms,
//     compared in JS: no tsquery, regex or SQL text is built from the task) against the lock text
//     and the note title.
//
// Why not copy locks into facts at ingest: zeusi_ingest cannot supersede facts, so an edited or
// deleted lock note would leave a stale current rule (see the dig). Reading from notes inherits the
// importer's lifecycle for free.

import { KIND_WEIGHT, RECENCY_DAYS, RECENCY_WEIGHT, taskTerms, tokens } from './context-for-task.ts';
import type { LockRef, ResolvedLock } from './lock-lifecycle.ts';
import { lockRuleId, type StartupRule } from './startup-rules.ts';

/** vault_path prefixes of the "standing" notes whose locks zeusi_startup lists (case-sensitive). */
export const STANDING_LOCK_PREFIXES: readonly string[] = ['Work/ops/', 'Work/handbook/'];

export function isStandingPath(vaultPath: string): boolean {
  return STANDING_LOCK_PREFIXES.some((p) => vaultPath.startsWith(p));
}

/** One lock item of one active note (RLS-visible to the caller), with its lifecycle status. */
export type LockRow = ResolvedLock;

/**
 * A lock item is standing when its note lives under STANDING_LOCK_PREFIXES, or when its note's
 * `standing_locks` frontmatter lists its ordinal (the explicit marker; src/lock-lifecycle.ts
 * STANDING_MARKER_KEY, proposed for Northbank by src/locks-classify.ts). Nothing else promotes a lock.
 */
export function isStandingLock(l: Pick<ResolvedLock, 'vaultPath' | 'standingMarked'>): boolean {
  return l.standingMarked || isStandingPath(l.vaultPath);
}

/** The standing, CURRENT lock items, newest note first, in-note order kept (the startup rule set). */
export function currentStandingLocks(locks: readonly ResolvedLock[]): ResolvedLock[] {
  return locks.filter((l) => l.status === 'current' && isStandingLock(l));
}

/** The startup rule input of a current standing lock (src/startup-rules.ts ranks, budgets and compacts it). */
export function lockStartupRule(r: ResolvedLock): StartupRule {
  return {
    origin: 'note_lock', id: lockRuleId(r.sourceUri, r.ord), subject: r.title, text: r.text, scope: r.scope, source_uri: r.sourceUri, source_ts: r.sourceTs,
    expires_at: r.until, supersedes: r.supersedes.map((x) => (x.ord !== null ? lockRuleId(x.source_uri, x.ord) : x.source_uri)),
  };
}

const supersedesJson = (r: ResolvedLock) => (r.supersedes.length ? { supersedes: r.supersedes } : {});
const refCite = (x: LockRef) => `${x.source_uri} @ ${x.source_ts}${x.ord !== null ? ` (lock ${x.ord} of "${x.note_title}")` : ` ("${x.note_title}")`}`;

/** The startup rule shape of a current lock item. */
export function lockRuleJson(r: ResolvedLock) {
  return {
    origin: 'note_lock' as const, subject: r.title, ord: r.ord, text: r.text, who: null, scope: r.scope, source_uri: r.sourceUri, source_ts: r.sourceTs,
    expires_at: r.until, ...supersedesJson(r),
    cite: `${r.sourceUri} @ ${r.sourceTs}`,
  };
}

export interface RankedLock extends ResolvedLock {
  score: number;
}

/** Pure: distinct task terms found as whole words in title + text, + the lock kind weight, + recency on source_ts. */
export function rankLocksForTask(rows: readonly ResolvedLock[], task: string, now: Date): RankedLock[] {
  const terms = taskTerms(task);
  const out: RankedLock[] = [];
  for (const r of rows) {
    const body = new Set(tokens(`${r.title} ${r.text}`));
    const hits = terms.filter((t) => body.has(t)).length;
    if (hits === 0) continue;
    const ageDays = Math.max(0, (now.getTime() - new Date(r.sourceTs).getTime()) / 86_400_000);
    const score = hits + (KIND_WEIGHT['lock'] ?? 0) + RECENCY_WEIGHT * Math.exp(-ageDays / RECENCY_DAYS);
    out.push({ ...r, score: Math.round(score * 1e6) / 1e6 });
  }
  return out.sort((a, b) => b.score - a.score || b.sourceTs.localeCompare(a.sourceTs) || b.noteId - a.noteId || a.ord - b.ord);
}

/**
 * The context_for_task wire shape of a CURRENT lock item: the decision item's fields, honestly
 * filled. id and who are null (a note lock is not a decision row and has no recorded speaker),
 * said_at is null, exact_words_verbatim is null (the note's own words, not a quote of a person).
 */
export function lockItemJson(r: RankedLock) {
  return {
    type: 'lock' as const, origin: 'note_lock' as const, id: null, kind: 'lock' as const, who: null, status: 'current' as const,
    date: { said_at: null, source_ts: r.sourceTs }, exact_words: r.text, exact_words_verbatim: null, note_title: r.title, ord: r.ord,
    applies_to: [] as string[], expires_at: r.until, ...supersedesJson(r), scope: r.scope, source_uri: r.sourceUri, source_ts: r.sourceTs, score: r.score,
    cite: `${r.sourceUri} @ ${r.sourceTs} (note lock in "${r.title}", who not recorded)`,
  };
}

export type LockItem = ReturnType<typeof lockItemJson>;

/**
 * The `history` wire shape: a superseded or expired lock that matches the task. Not binding; it
 * says what replaced it (superseded_by, with its own cite) or when it lapsed (expired_at).
 */
export function lockHistoryJson(r: RankedLock) {
  return {
    type: 'lock' as const, origin: 'note_lock' as const, status: r.status as 'superseded' | 'expired', who: null,
    exact_words: r.text, note_title: r.title, ord: r.ord, scope: r.scope, source_uri: r.sourceUri, source_ts: r.sourceTs, score: r.score,
    ...(r.status === 'superseded' && r.supersededBy ? { superseded_by: { ...r.supersededBy, cite: refCite(r.supersededBy) } } : {}),
    ...(r.status === 'expired' ? { expired_at: r.until } : {}),
    cite: `${r.sourceUri} @ ${r.sourceTs} (note lock in "${r.title}", ${r.status}; not binding)`,
  };
}

export type LockHistoryItem = ReturnType<typeof lockHistoryJson>;
