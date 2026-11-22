// `zeusi locks lint --vault <root> [--all] [--json]` (lock-lifecycle addendum K5; docs/note-locks.md).
//
// OFFLINE and READ-ONLY: no database, no network. Walks the standing folders (or, with --all,
// every folder under Work/), never a dot entry, never a symlink, never a path that names the
// walled person (plankiva / plankiva, any case) or that a seed wall rule refuses; files are opened
// O_RDONLY | O_NOFOLLOW, hard links and files over 8 MiB are skipped. For every note it parses the
// frontmatter with the OLD (frozen) and the NEW parser and reports:
//   * counts (files, lock notes, lock items old / new, changed items);
//   * every changed item as `vault_path:ord` with the old and the new text (the owner's own
//     words: printed locally only; credentials are redacted first);
//   * the lifecycle resolution of the NEW parse (current / superseded / expired, claim counts);
//   * CANDIDATES for a human to confirm, never applied: same-subject pairs (standing folders,
//     newer vs older, shared distinctive terms) and locks with time-box language but no until.

import { createHash } from 'node:crypto';
import { constants, closeSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { frontmatterBlock, MAX_FILE_BYTES, parseFrontmatter, parseNoteDate } from './importers/vault.ts';
import { parseFrontmatterLegacy } from './importers/frontmatter-legacy.ts';
import { lockItemsOf, resolveLockLifecycle, type LifecycleCounts, type LockNoteInput, type ResolvedLock } from './lock-lifecycle.ts';
import { isStandingLock, STANDING_LOCK_PREFIXES } from './note-locks.ts';
import { redactSecrets } from './secrets.ts';
import { mentionsProtectedName } from './sources.ts';
import { seedWall } from './wall.ts';
import { STOPWORDS, tokens } from './context-for-task.ts';

/** A term counts for same-subject candidates when at most this many current standing locks contain it. */
export const DISTINCTIVE_DF = 16;
/** Minimum sum of ln(N / df) over the shared distinctive terms (>= 2 terms) for a candidate pair. */
export const MIN_PAIR_SCORE = 9;
export const MAX_PAIRS = 25;
/** Printed in place of any text that names the walled person (the item is counted, never shown). */
export const WITHHELD_TEXT = '[withheld: wall]';

/** Never walked or opened, whatever the flags (case-insensitive, also inside a word). */
const WALLED_NAME = /plankiva/i;

export interface LintOptions {
  root: string;
  /** Every folder under Work/ instead of the standing folders only. */
  all?: boolean;
  now?: Date;
}

export interface LintItemDiff {
  ref: string;
  old: string | null;
  new: string | null;
}

export interface LintCandidatePair {
  newer: string;
  older: string;
  shared_terms: string[];
  /** Sum of ln(N / df) over the shared terms (higher = more specific overlap). */
  score: number;
}

export interface LintTimebox {
  ref: string;
  text: string;
  phrase: string;
}

export interface LintResult {
  scanned_prefixes: string[];
  files: number;
  files_skipped: number;
  lock_notes: { old: number; new: number };
  lock_items: { old: number; new: number };
  items_changed: number;
  notes_changed: number;
  changed: LintItemDiff[];
  lifecycle: LifecycleCounts;
  superseded: Array<{ ref: string; by: string | null }>;
  expired: Array<{ ref: string; until: string | null }>;
  candidates_same_subject: LintCandidatePair[];
  candidates_timebox: LintTimebox[];
}

/** Local output still keeps the wall: a text naming the walled person is withheld; credentials are redacted. */
const walled = (s: string) => WALLED_NAME.test(s) || mentionsProtectedName(s);
const safe = (s: string | null) => (s === null ? null : walled(s) ? WITHHELD_TEXT : redactSecrets(s).text);

/** One parsed vault note (offline walk). `fm` is the NEW parser's frontmatter; `sha256` the file bytes' hash. */
export interface ParsedVaultNote {
  rel: string;
  oldLocks: Array<{ ord: number; text: string }>;
  newLocks: Array<{ ord: number; text: string }>;
  input: LockNoteInput;
  fm: Record<string, unknown>;
  sha256: string;
}
type Parsed = ParsedVaultNote;

/**
 * Offline, read-only walk of `<root>/<prefix>` for each prefix (shared by `locks lint` and
 * `locks classify`): dot entries, symlinks, walled names and seed-wall paths are never opened;
 * files are opened O_RDONLY | O_NOFOLLOW; hard links and files over 8 MiB are skipped.
 */
export function walkVaultNotes(root: string, prefixes: readonly string[]): { notes: ParsedVaultNote[]; files: number; skipped: number } {
  const notes: ParsedVaultNote[] = [];
  const counts = { files: 0, skipped: 0 };
  for (const p of prefixes) walk(root, p.replace(/\/$/, ''), notes, counts);
  return { notes, ...counts };
}

function walk(root: string, rel: string, out: Parsed[], counts: { files: number; skipped: number }, wall = seedWall()): void {
  let entries;
  try {
    entries = readdirSync(join(root, rel), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  } catch {
    counts.skipped++;
    return;
  }
  for (const e of entries) {
    const r = `${rel}/${e.name}`;
    if (e.name.startsWith('.') || WALLED_NAME.test(r) || mentionsProtectedName(r)) continue;
    if (wall.checkUri(`vault:${r}`).blocked || wall.checkUri(`vault:${r}/`).blocked) continue;
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      walk(root, r, out, counts, wall);
      continue;
    }
    if (!e.isFile() || !e.name.toLowerCase().endsWith('.md')) continue;
    const abs = join(root, r);
    let text: string;
    let mtime: number;
    let sha256: string;
    try {
      const st0 = lstatSync(abs);
      if (!st0.isFile() || st0.nlink > 1 || st0.size > MAX_FILE_BYTES) {
        counts.skipped++;
        continue;
      }
      const fd = openSync(abs, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const st = fstatSync(fd);
        if (st.ino !== st0.ino || st.nlink > 1) {
          counts.skipped++;
          continue;
        }
        const bytes = readFileSync(fd);
        sha256 = createHash('sha256').update(bytes).digest('hex');
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        mtime = st.mtimeMs;
      } finally {
        closeSync(fd);
      }
    } catch {
      counts.skipped++;
      continue;
    }
    counts.files++;
    const block = frontmatterBlock(text);
    if (block === null) continue;
    const fo = parseFrontmatterLegacy(block);
    const fn = parseFrontmatter(block);
    const date = parseNoteDate(fn['date']);
    const title = typeof fn['title'] === 'string' && fn['title'].trim() !== '' ? fn['title'].trim() : e.name.replace(/\.md$/i, '');
    out.push({
      rel: r, oldLocks: lockItemsOf(fo['locks']), newLocks: lockItemsOf(fn['locks']),
      input: {
        noteId: out.length + 1, vaultPath: r, title, scope: 'work', sourceUri: `vault:${r}`,
        sourceTs: (date ? date.ts : new Date(mtime)).toISOString(),
        locks: fn['locks'] ?? null, supersedes: fn['supersedes'] ?? null, lockUntil: fn['lock_until'] ?? null, until: fn['until'] ?? null,
        standingLocks: fn['standing_locks'] ?? null,
      },
      fm: fn, sha256,
    });
  }
}

/** Time-box language in a lock text (candidates only). */
export const TIMEBOX = new RegExp([
  String.raw`\b(?:through|thru|until|till|up to)\s+(?:(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*\.?\s+)?(?:\d{1,2}(?:st|nd|rd|th)?\s+[a-z]{3,9}|[a-z]{3,9}\s+\d{1,2}|\d{4}-\d{2}-\d{2}|(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*|end of [a-z]+|tomorrow|tonight)`,
  String.raw`\bduring the [a-z-]+`,
  String.raw`\bfor (?:the next )?\d+\s+(?:days?|weeks?|hours?|months?)\b`,
  String.raw`\b(?:this|next) (?:week|weekend|month)\b`,
  String.raw`\bresumes?\s+(?:on\s+)?(?:mon|tue|wed|thu|fri|sat|sun)`,
].join('|'), 'i');

const refOf = (l: ResolvedLock) => `${l.vaultPath}:${l.ord}`;

export function lintVault(o: LintOptions): LintResult {
  const now = o.now ?? new Date();
  const prefixes = o.all ? ['Work'] : STANDING_LOCK_PREFIXES.map((p) => p.replace(/\/$/, ''));
  const parsed: Parsed[] = [];
  const counts = { files: 0, skipped: 0 };
  for (const p of prefixes) walk(o.root, p, parsed, counts);

  const changed: LintItemDiff[] = [];
  let notesChanged = 0;
  for (const p of parsed) {
    const max = Math.max(...p.oldLocks.map((x) => x.ord), ...p.newLocks.map((x) => x.ord), 0);
    let any = false;
    for (let ord = 1; ord <= max; ord++) {
      const a = p.oldLocks.find((x) => x.ord === ord)?.text ?? null;
      const b = p.newLocks.find((x) => x.ord === ord)?.text ?? null;
      if (a === b) continue;
      any = true;
      changed.push({ ref: `${p.rel}:${ord}`, old: safe(a), new: safe(b) });
    }
    if (any) notesChanged++;
  }

  const { locks, counts: lc } = resolveLockLifecycle(parsed.map((p) => p.input), now);
  const superseded = locks.filter((l) => l.status === 'superseded').map((l) => ({
    ref: refOf(l), by: l.supersededBy ? `${l.supersededBy.source_uri.replace(/^vault:/, '')}${l.supersededBy.ord !== null ? `:${l.supersededBy.ord}` : ''}` : null,
  }));
  const expired = locks.filter((l) => l.status === 'expired').map((l) => ({ ref: refOf(l), until: l.until }));

  // Time-box candidates: current locks with time-box words and no until of their own.
  const timebox: LintTimebox[] = [];
  for (const l of locks) {
    if (l.status !== 'current' || l.until !== null) continue;
    const m = TIMEBOX.exec(l.text);
    if (m) timebox.push({ ref: refOf(l), text: safe(l.text)!, phrase: m[0] });
  }

  // Same-subject candidates: current standing locks of different notes sharing >= 2 distinctive terms.
  const standing = locks.filter((l) => l.status === 'current' && isStandingLock(l));
  const termsOf = (l: ResolvedLock) => (walled(l.text) ? [] : [...new Set(tokens(l.text).filter((t) => [...t].length >= 4 && !STOPWORDS.has(t) && !/^\d+$/.test(t)))]);
  const df = new Map<string, number>();
  const terms = new Map<ResolvedLock, string[]>();
  for (const l of standing) {
    const ts = termsOf(l);
    terms.set(l, ts);
    for (const t of ts) df.set(t, (df.get(t) ?? 0) + 1);
  }
  const pairs: Array<LintCandidatePair & { score: number }> = [];
  const idf = (t: string) => Math.log(standing.length / (df.get(t) ?? 1));
  for (let i = 0; i < standing.length; i++) {
    for (let j = 0; j < standing.length; j++) {
      const a = standing[i]!;
      const b = standing[j]!;
      if (a.noteId === b.noteId || !(a.sourceTs > b.sourceTs)) continue;
      const bt = new Set(terms.get(b));
      const shared = terms.get(a)!.filter((t) => bt.has(t) && (df.get(t) ?? 0) <= DISTINCTIVE_DF);
      const score = shared.reduce((n, t) => n + idf(t), 0);
      if (shared.length >= 2 && score >= MIN_PAIR_SCORE) pairs.push({ newer: refOf(a), older: refOf(b), shared_terms: shared.sort(), score: Math.round(score * 100) / 100 });
    }
  }
  pairs.sort((x, y) => y.score - x.score || x.newer.localeCompare(y.newer) || x.older.localeCompare(y.older));

  return {
    scanned_prefixes: prefixes.map((p) => `${p}/`), files: counts.files, files_skipped: counts.skipped,
    lock_notes: { old: parsed.filter((p) => p.oldLocks.length > 0).length, new: parsed.filter((p) => p.newLocks.length > 0).length },
    lock_items: { old: parsed.reduce((n, p) => n + p.oldLocks.length, 0), new: parsed.reduce((n, p) => n + p.newLocks.length, 0) },
    items_changed: changed.length, notes_changed: notesChanged, changed, lifecycle: lc, superseded, expired,
    candidates_same_subject: pairs.slice(0, MAX_PAIRS), candidates_timebox: timebox,
  };
}

export function formatLint(r: LintResult): string {
  const q = (s: string | null) => (s === null ? '(none)' : JSON.stringify(s));
  const L = r.lifecycle;
  const lines = [
    `locks lint (offline, read-only): ${r.scanned_prefixes.join(', ')}`,
    `  files: ${r.files} (skipped: ${r.files_skipped})`,
    `  lock notes: old ${r.lock_notes.old}, new ${r.lock_notes.new}`,
    `  lock items: old ${r.lock_items.old}, new ${r.lock_items.new}`,
    `  changed items: ${r.items_changed} in ${r.notes_changed} note(s)`,
    `  lifecycle (new parse): current ${L.current}, superseded ${L.superseded}, expired ${L.expired}; supersede claims ${L.supersede_claims} (applied ${L.supersede_applied}, unresolved ${L.supersede_unresolved}, invalid ${L.supersede_invalid}); until set ${L.until_set}, invalid ${L.until_invalid}`,
  ];
  if (r.changed.length) {
    lines.push('', 'changed items (vault_path:ord):');
    for (const c of r.changed) lines.push(`  ${c.ref}`, `    old: ${q(c.old)}`, `    new: ${q(c.new)}`);
  }
  if (r.superseded.length) {
    lines.push('', 'superseded:');
    for (const s of r.superseded) lines.push(`  ${s.ref}  <- ${s.by ?? '?'}`);
  }
  if (r.expired.length) {
    lines.push('', 'expired:');
    for (const s of r.expired) lines.push(`  ${s.ref}  until ${s.until}`);
  }
  lines.push('', `CANDIDATES (not applied; a human confirms): same-subject pairs ${r.candidates_same_subject.length}, time-box language without until ${r.candidates_timebox.length}`);
  for (const p of r.candidates_same_subject) lines.push(`  same subject? ${p.newer}  newer than  ${p.older}  [${p.shared_terms.join(', ')}] score ${p.score}`);
  for (const t of r.candidates_timebox) lines.push(`  time-box? ${t.ref}  ${q(t.phrase)}`);
  return lines.join('\n');
}
