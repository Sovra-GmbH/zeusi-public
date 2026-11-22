// `zeusi locks classify --vault <root> [--json] [--show-text] [--save-preview <f>] | --real --from <f>` (session-start gaps U4;
// docs/locks-classifier.md). Proposes which Northbank product locks are DURABLE standing rules, so
// that zeusi_startup serves them, and leaves one-off PR / staging / approval decisions alone.
//
// OFFLINE. No database, no network. The preview (default) opens vault files read-only through the
// `locks lint` walker (src/locks-lint.ts walkVaultNotes: no dot entries, no symlinks, no walled
// names, seed-wall path check, O_NOFOLLOW, 8 MiB cap). The write (--real, an operator step) adds
// ONLY a `standing_locks: [<ordinals>]` line to the frontmatter of the notes it promotes; the
// normal `zeusi ingest vault` then carries that marker into notes.frontmatter, and the read side
// (src/lock-lifecycle.ts STANDING_MARKER_KEY) makes those locks standing. Preview and write share
// classifyVault(): the write marks exactly the previewed promote set (test/locks-classify.test.ts).
//
// Rules, first match wins (invent=NO: a lock is promoted only on explicit, testable signals;
// anything ambiguous is skipped with its reason and stays available via zeusi_context_for_task):
//   1. not current (superseded / expired)                    -> skip  not_current
//   2. already standing (standing folder or marker)           -> keep  already_standing
//   3. note `status:` not exactly locked / lock               -> skip  note_status
//   4. one-off, time-bound or instance-specific wording       -> skip  one_off:<class>
//      (ONE_OFF_PATTERNS: dated, timebox, pr_or_merge, event, go, open, staging, scoped_to_now,
//      sequence, specific (IPs, ids of 4+ digits, decimals, amounts), cross_scope (names ClientCo:
//      ClientCo work stays in scope clientco))
//   5. durable wording (DURABLE_PATTERNS)                     -> PROMOTE durable:<signal>
//   6. otherwise                                              -> skip  no_standing_signal

import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { frontmatterBlock, parseFrontmatter, PRODUCT_PATH_PREFIXES } from './importers/vault.ts';
import { parseStandingMarker, resolveLockLifecycle, STANDING_MARKER_KEY, type ResolvedLock } from './lock-lifecycle.ts';
import { TIMEBOX, walkVaultNotes, WITHHELD_TEXT, type ParsedVaultNote } from './locks-lint.ts';
import { isStandingLock } from './note-locks.ts';
import { redactSecrets } from './secrets.ts';
import { mentionsProtectedName } from './sources.ts';

/** Folders whose locks are classified (the vault-northbank-product source, src/importers/vault.ts). */
export const CLASSIFY_PREFIXES: readonly string[] = PRODUCT_PATH_PREFIXES;
/** Folder walked for the lifecycle (so a supersession from any Work note is seen). */
export const LIFECYCLE_ROOT_PREFIX = 'Work/';
/** Note statuses whose locks may be promoted (exact, case-insensitive, trimmed). */
export const PROMOTABLE_NOTE_STATUSES: readonly string[] = ['locked', 'lock'];

const MONTH = '(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\\.?';

/** One-off / time-bound wording, by class. Any match skips the lock (precision over recall). */
export const ONE_OFF_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ['dated', new RegExp(`\\b\\d{4}-\\d{2}-\\d{2}\\b|\\b\\d{1,2}\\s+${MONTH}(?=\\W|$)|\\b${MONTH}\\s+\\d{1,2}\\b|\\b(?:mon|tues|wednes|thurs|fri|satur|sun)day\\b|\\b\\d{1,2}:\\d{2}\\b`, 'i')],
  ['timebox', TIMEBOX],
  ['timebox', /\b(?:until|till|today|tonight|tomorrow|yesterday|for now|for the moment|temporar\w*|interim|pilot|later|this (?:week|weekend|month|sprint|session|round)|next (?:week|month|session|round)|waits? for)\b/i],
  ['pr_or_merge', /#\d+|\bPRs?\b|\bpull request|\bmerge[sd]?\b|\bbranch(?:es)?\b|\bdraft\b|\brevert(?:ed)?\b|\bcommit(?:ted)?\b|\bv\d+(?:\.\d+)+\b|\bv\d+\b/i],
  ['event', /\b(?:approved|greenlit|decided|deployed|shipped|removed|deleted|created|added|fixed|merged|done|completed|landed|reverted|signed off|agreed|confirmed|chosen|picked|selected|replaced|moved|renamed|launched|released|paused|resumed|kept|restated|revised|updated)\b/i],
  ['go', /\bGO(?:'d|’d)?\b|\bgo-?ahead\b/],
  ['open', /\?|\b(?:tbd|to settle|to decide|open question|pending|proposal|proposed|idea|maybe|consider|might|could)\b/i],
  ['staging', /\bstaging\b/i],
  ['scoped_to_now', /\bfor this \w+|\b(?:already|currently|right now|as of)\b/i],
  ['sequence', /^\s*(?:then|next|first|second|after that|afterwards)\b/i],
  ['specific', /\b\d{1,3}(?:\.\d{1,3}){3}\b|\b\d{4,}\b(?![-:]\d)|\b\d+\.\d+\b|[$€£]\s?\d|\b(?:USD|EUR|CHF|GBP|JPY)\s?\d/],
  ['cross_scope', /clientco/i],
];

/** Durable, normative wording. At least one is required to promote. */
export const DURABLE_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ['never_always', /\b(?:never|always)\b/i],
  ['every_each', /\b(?:every|each)\b/i],
  ['must_only', /\b(?:must|only|mandatory|required|forbidden|prohibited)\b/i],
  ['prohibition', /\b(?:do not|don't|does not|doesn't|may not|cannot|can't|no one)\b|^\s*no\s/i],
  ['source_of_truth', /\bsource of truth\b/i],
];

export type ClassifyDecision = 'promote' | 'skip' | 'already_standing';

export interface ClassifyInput {
  noteStatus: string | null;
  text: string;
  lockStatus: ResolvedLock['status'];
  standing: boolean;
}

/** Pure: one lock -> decision + reason (rules 1-6 above). */
export function classifyLock(i: ClassifyInput): { decision: ClassifyDecision; reason: string } {
  if (i.lockStatus !== 'current') return { decision: 'skip', reason: `not_current:${i.lockStatus}` };
  if (i.standing) return { decision: 'already_standing', reason: 'already_standing' };
  const st = (i.noteStatus ?? '').trim().toLowerCase();
  if (!PROMOTABLE_NOTE_STATUSES.includes(st)) return { decision: 'skip', reason: `note_status:${st === '' ? '(none)' : st.length > 40 ? 'other' : st}` };
  const oneOff = [...new Set(ONE_OFF_PATTERNS.filter(([, re]) => re.test(i.text)).map(([c]) => c))];
  if (oneOff.length) return { decision: 'skip', reason: `one_off:${oneOff.join('+')}` };
  const durable = DURABLE_PATTERNS.find(([, re]) => re.test(i.text));
  if (durable) return { decision: 'promote', reason: `durable:${durable[0]}` };
  return { decision: 'skip', reason: 'no_standing_signal' };
}

export interface ClassifiedLock {
  /** `<vault_path>:<ord>` (the `locks lint` ref). */
  ref: string;
  vaultPath: string;
  ord: number;
  decision: ClassifyDecision;
  reason: string;
  /** Local display only (redacted; the walled person's name withheld). */
  text: string;
}

export interface ClassifyResult {
  scanned_prefixes: string[];
  files: number;
  files_skipped: number;
  lock_notes: number;
  lock_items: number;
  counts: { promote: number; skip: number; already_standing: number };
  by_reason: Record<string, number>;
  /** The promote set, sorted: exactly what --real writes. */
  promote: string[];
  items: ClassifiedLock[];
  /** Per note to write: vault_path -> { sha256 read, ordinals to mark }. Internal to applyStandingMarkers. */
  plan: Map<string, { sha256: string; ords: number[] }>;
}

const safe = (s: string) => (mentionsProtectedName(s) ? WITHHELD_TEXT : redactSecrets(s).text);
const inPrefixes = (p: string) => CLASSIFY_PREFIXES.some((x) => p.startsWith(x));

/** Offline classification of the Northbank locks under <root> (the preview; nothing is written). */
export function classifyVault(o: { root: string; now?: Date }): ClassifyResult {
  const now = o.now ?? new Date();
  const walk = walkVaultNotes(o.root, [LIFECYCLE_ROOT_PREFIX]);
  const byPath = new Map<string, ParsedVaultNote>(walk.notes.map((n) => [n.rel, n]));
  const { locks } = resolveLockLifecycle(walk.notes.map((n) => n.input), now);
  const items: ClassifiedLock[] = [];
  for (const l of locks) {
    if (!inPrefixes(l.vaultPath)) continue;
    const note = byPath.get(l.vaultPath)!;
    const st = note.fm['status'];
    const { decision, reason } = classifyLock({ noteStatus: typeof st === 'string' ? st : null, text: l.text, lockStatus: l.status, standing: isStandingLock(l) });
    items.push({ ref: `${l.vaultPath}:${l.ord}`, vaultPath: l.vaultPath, ord: l.ord, decision, reason, text: safe(l.text) });
  }
  items.sort((a, b) => (a.vaultPath < b.vaultPath ? -1 : a.vaultPath > b.vaultPath ? 1 : a.ord - b.ord));
  const by_reason: Record<string, number> = {};
  const counts = { promote: 0, skip: 0, already_standing: 0 };
  const plan = new Map<string, { sha256: string; ords: number[] }>();
  for (const it of items) {
    counts[it.decision]++;
    by_reason[it.reason] = (by_reason[it.reason] ?? 0) + 1;
    if (it.decision !== 'promote') continue;
    const p = plan.get(it.vaultPath) ?? { sha256: byPath.get(it.vaultPath)!.sha256, ords: [] };
    p.ords.push(it.ord);
    plan.set(it.vaultPath, p);
  }
  const tapeNotes = walk.notes.filter((n) => inPrefixes(n.rel) && n.newLocks.length > 0);
  return {
    scanned_prefixes: [...CLASSIFY_PREFIXES], files: walk.files, files_skipped: walk.skipped,
    lock_notes: tapeNotes.length, lock_items: items.length, counts,
    by_reason: Object.fromEntries(Object.entries(by_reason).sort(([a], [b]) => (a < b ? -1 : 1))),
    promote: items.filter((i) => i.decision === 'promote').map((i) => i.ref), items, plan,
  };
}

/** The saved dry-run preview (`--save-preview`): what the owner reviewed, and what `--real --from` must match. */
export interface SavedPreview {
  version: 1;
  promote: string[];
  files: Array<{ vault_path: string; sha256: string; ords: number[] }>;
}

export function savedPreview(r: ClassifyResult): SavedPreview {
  return { version: 1, promote: [...r.promote], files: [...r.plan].sort(([a], [b]) => (a < b ? -1 : 1)).map(([vault_path, p]) => ({ vault_path, sha256: p.sha256, ords: [...p.ords] })) };
}

/**
 * Differences between a fresh classification and the saved preview ([] = identical). --real writes
 * only when this is empty: a note edited, added or re-resolved since the dry run refuses the whole run.
 */
export function previewDifferences(r: ClassifyResult, saved: unknown): string[] {
  const s = saved as Partial<SavedPreview> | null;
  if (!s || s.version !== 1 || !Array.isArray(s.promote) || !Array.isArray(s.files)) return ['the saved preview is not a locks classify preview (version 1)'];
  const now = savedPreview(r);
  const out: string[] = [];
  const a = new Set(now.promote);
  const b = new Set(s.promote);
  for (const x of a) if (!b.has(x)) out.push(`would now promote ${x}, not in the saved preview`);
  for (const x of b) if (!a.has(x)) out.push(`saved preview promotes ${x}, a fresh classification does not`);
  const files = new Map(s.files.map((f) => [f?.vault_path, f]));
  for (const f of now.files) {
    const o = files.get(f.vault_path);
    if (!o || o.sha256 !== f.sha256) out.push(`${f.vault_path} changed since the saved preview`);
  }
  return out;
}

const KEY_LINE = new RegExp(`^${STANDING_MARKER_KEY}\\s*:`);

/**
 * The note text with `standing_locks: [<existing ∪ ords>]` in its frontmatter, every other byte
 * kept. An existing top-level `standing_locks:` (and its block lines) is replaced in place; else
 * the line goes right before the closing `---`. Returns null when the text has no frontmatter, or
 * its existing marker holds a non-ordinal entry (refused, never silently dropped).
 */
export function withStandingMarker(text: string, ords: readonly number[]): string | null {
  const m = /^(---[ \t]*(\r?\n))([\s\S]*?)(\r?\n---[ \t]*(?:\r?\n|$))/.exec(text);
  if (!m) return null;
  const nl = m[2]!;
  const lines = m[3]!.split(/\r?\n/);
  const parsedExisting = parseStandingMarker(parseFrontmatter(m[3]!)[STANDING_MARKER_KEY]);
  // An existing marker with a non-ordinal entry is the owner's to fix: never rewritten (it would be dropped).
  if (parsedExisting.some((x) => x === null)) return null;
  const existing = parsedExisting.filter((x): x is number => x !== null);
  const all = [...new Set([...existing, ...ords])].sort((a, b) => a - b);
  const line = `${STANDING_MARKER_KEY}: [${all.join(', ')}]`;
  const at = lines.findIndex((l) => KEY_LINE.test(l));
  if (at === -1) lines.push(line);
  else {
    let end = at + 1;
    while (end < lines.length && (/^\s+\S/.test(lines[end]!) || /^-\s/.test(lines[end]!))) end++;
    lines.splice(at, end - at, line);
  }
  return `${m[1]}${lines.join(nl)}${m[4]}${text.slice(m[0].length)}`;
}

export interface ApplyResult {
  /** `<vault_path>:<ord>` refs now marked, sorted (== the preview's promote set when nothing was refused). */
  written: string[];
  files_changed: number;
  /** Notes not written: the file changed since the preview, is a link, or the edit did not verify. */
  refused: Array<{ vault_path: string; why: string }>;
}

/**
 * The --real write: mark exactly `r.plan` (the CLI first checks it equals the saved dry-run preview:
 * previewDifferences). Each file is re-opened O_RDONLY|O_NOFOLLOW, its bytes must hash to the
 * preview's sha256, the new frontmatter must parse back to the marked ordinals, and only then is it
 * replaced atomically (a new file in the same folder, fully written, then renamed over the note).
 * Nothing else in the vault is touched.
 */
export function applyStandingMarkers(root: string, r: ClassifyResult): ApplyResult {
  const written: string[] = [];
  const refused: ApplyResult['refused'] = [];
  let files = 0;
  for (const [rel, p] of [...r.plan].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const abs = join(root, rel);
    try {
      const st0 = lstatSync(abs);
      if (!st0.isFile() || st0.nlink > 1) {
        refused.push({ vault_path: rel, why: 'not a plain file' });
        continue;
      }
      const fd = openSync(abs, constants.O_RDONLY | constants.O_NOFOLLOW);
      let next: string | null = null;
      try {
        const st = fstatSync(fd);
        if (st.ino !== st0.ino || st.nlink > 1) {
          refused.push({ vault_path: rel, why: 'file changed under us' });
          continue;
        }
        const bytes = readFileSync(fd);
        if (createHash('sha256').update(bytes).digest('hex') !== p.sha256) {
          refused.push({ vault_path: rel, why: 'file changed since the preview: run the preview again' });
          continue;
        }
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        next = withStandingMarker(text, p.ords);
        const block = next === null ? null : frontmatterBlock(next);
        const marked = block === null ? [] : parseStandingMarker(parseFrontmatter(block)[STANDING_MARKER_KEY]);
        const oldFm = parseFrontmatter(frontmatterBlock(text) ?? '');
        const newFm = block === null ? {} : parseFrontmatter(block);
        delete (oldFm as Record<string, unknown>)[STANDING_MARKER_KEY];
        delete (newFm as Record<string, unknown>)[STANDING_MARKER_KEY];
        if (next === null || !p.ords.every((o) => marked.includes(o)) || JSON.stringify(oldFm) !== JSON.stringify(newFm)) {
          refused.push({ vault_path: rel, why: 'the edit did not verify' });
          continue;
        }
        if (next === text) next = null;
      } finally {
        closeSync(fd);
      }
      if (next !== null) {
        const out = Buffer.from(next, 'utf8');
        const tmp = join(dirname(abs), `.${rel.slice(rel.lastIndexOf('/') + 1)}.zeusi-classify-${process.pid}.tmp`);
        const wfd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, st0.mode & 0o777);
        try {
          let off = 0;
          while (off < out.length) off += writeSync(wfd, out, off, out.length - off);
        } catch (e) {
          closeSync(wfd);
          rmSync(tmp, { force: true });
          throw e;
        }
        closeSync(wfd);
        renameSync(tmp, abs);
        files++;
      }
      for (const o of p.ords) written.push(`${rel}:${o}`);
    } catch (e) {
      refused.push({ vault_path: rel, why: `filesystem error (${(e as NodeJS.ErrnoException).code ?? 'unknown'})` });
    }
  }
  const byRef = (a: string, b: string) => {
    const [pa, oa] = [a.slice(0, a.lastIndexOf(':')), Number(a.slice(a.lastIndexOf(':') + 1))];
    const [pb, ob] = [b.slice(0, b.lastIndexOf(':')), Number(b.slice(b.lastIndexOf(':') + 1))];
    return pa < pb ? -1 : pa > pb ? 1 : oa - ob;
  };
  return { written: written.sort(byRef), files_changed: files, refused };
}

export function formatClassify(r: ClassifyResult, o: { showText?: boolean; real?: ApplyResult } = {}): string {
  const lines = [
    `locks classify (offline): ${r.scanned_prefixes.join(', ')}${o.real ? ' -- REAL: standing_locks written' : ' -- DRY RUN: nothing written'}`,
    `  files: ${r.files} (skipped: ${r.files_skipped}); Northbank lock notes: ${r.lock_notes}; lock items: ${r.lock_items}`,
    `  promote ${r.counts.promote} / skip ${r.counts.skip} / already standing ${r.counts.already_standing}`,
    '  by reason:',
    ...Object.entries(r.by_reason).map(([k, v]) => `    ${k}: ${v}`),
    `  ${o.real ? 'promoted' : 'would promote'} (${r.promote.length}):`,
    ...r.items.filter((i) => i.decision === 'promote').map((i) => `    ${i.ref}  ${i.reason}${o.showText ? `  ${JSON.stringify(i.text)}` : ''}`),
  ];
  if (o.showText) {
    lines.push('  skipped:');
    for (const i of r.items.filter((x) => x.decision === 'skip')) lines.push(`    ${i.ref}  ${i.reason}  ${JSON.stringify(i.text)}`);
  }
  if (o.real) {
    lines.push(`  written: ${o.real.written.length} lock(s) in ${o.real.files_changed} file(s); refused notes: ${o.real.refused.length}`);
    for (const x of o.real.refused) lines.push(`    refused ${x.vault_path}: ${x.why}`);
    lines.push('  next: zeusi ingest vault (dry run first) carries the marker into Zeusi; nothing was written to any database.');
  } else {
    lines.push('  write: save this preview (--save-preview <file>), review it, then --real --from <file> (operator, owner GO): it writes only if the vault still matches the saved preview exactly; then zeusi ingest vault (dry run first).');
  }
  return lines.join('\n');
}
