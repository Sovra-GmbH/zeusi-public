// zeusi_startup rule set (docs/plans/2026-11-18-session-start-gaps-plan.md, U2; docs/note-locks.md
// "What each tool reports"). Pure: no database, no I/O.
//
// Every current standing rule the caller can see (after the output wall) ends up in exactly ONE of
// two lists, never in neither:
//
//   * `served`    - compact one-line form { id, origin, scope, text, source_uri, source_ts, cite }
//                   (+ expires_at /
//                   supersedes ids when set), the longest prefix of the ranking that fits the
//                   token budget;
//   * `remainder` - { id, origin, scope, subject, source_uri, source_ts, cite, reason } for every other rule, in rank
//                   order, so a client can look each one up (zeusi_context_for_task with the
//                   subject, or zeusi_search with the file name in the id). Beyond REMAINDER_MAX
//                   entries the rest is COUNTED in `unlisted` and said in rules_note (never silent).
//
// Ranking (stable): fact rules first (typed, explicit), then scope (team, product, clientco,
// then any other scope alphabetically), then source_ts newest first; ties keep the input order
// (newest note first, in-note lock order). The budget is an estimate: ceil(JSON chars / 4) per
// served item. Text is whitespace-collapsed only, never cut: a text over COMPACT_TEXT_MAX_CHARS
// goes to the remainder (reason too_long) with its pointer instead of being truncated.

/** Served-rules budget in estimated tokens (ceil(JSON characters / 4) per compact item). */
export const STARTUP_RULES_BUDGET_TOKENS = 16_000;
/** A rule text longer than this (after whitespace collapse) is listed, not served, so it is never cut. */
export const COMPACT_TEXT_MAX_CHARS = 600;
/** At most this many remainder entries are listed; any beyond are counted in `unlisted`. */
export const REMAINDER_MAX = 2_000;
/** Scope rank for ordering; any other scope sorts after these, alphabetically. */
export const SCOPE_ORDER: readonly string[] = ['work', 'product', 'client'];
export const BUDGET_ESTIMATE = 'ceil(JSON characters / 4) per served rule';

/** One current standing rule in full (before the wall and the budget). */
export interface StartupRule {
  origin: 'fact' | 'note_lock';
  /** `<source_uri>#lock-<ord>` or `<source_uri>#fact-<id>`. */
  id: string;
  /** Note title (lock) or fact subject; the lookup term for zeusi_context_for_task. */
  subject: string | null;
  text: string;
  scope: string;
  source_uri: string;
  source_ts: string;
  expires_at?: string | null;
  /** ids of the locks this one replaces. */
  supersedes?: string[];
}

export interface CompactRule {
  id: string;
  origin: 'fact' | 'note_lock';
  scope: string;
  text: string;
  source_uri: string;
  source_ts: string;
  cite: string;
  expires_at?: string;
  supersedes?: string[];
}

export type RemainderReason = 'budget' | 'too_long';

export interface RemainderEntry {
  id: string;
  origin: 'fact' | 'note_lock';
  scope: string;
  subject: string | null;
  source_uri: string;
  source_ts: string;
  cite: string;
  reason: RemainderReason;
}

export interface StartupRulesPlan {
  served: CompactRule[];
  remainder: RemainderEntry[];
  /** Rules in neither list because the remainder hit REMAINDER_MAX (counted, said in the note). */
  unlisted: number;
  budget_used: number;
}

export const lockRuleId = (sourceUri: string, ord: number) => `${sourceUri}#lock-${ord}`;
export const factRuleId = (sourceUri: string, id: number | string) => `${sourceUri}#fact-${id}`;

export function oneLine(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

export function estimateTokens(v: unknown): number {
  return Math.ceil(JSON.stringify(v).length / 4);
}

const cite = (r: StartupRule) => `${r.source_uri} @ ${r.source_ts}`;

function scopeRank(s: string): [number, string] {
  const i = SCOPE_ORDER.indexOf(s);
  return [i === -1 ? SCOPE_ORDER.length : i, i === -1 ? s : ''];
}

/** Rank comparator (stable sort keeps the input order on ties). */
export function compareRules(a: StartupRule, b: StartupRule): number {
  if (a.origin !== b.origin) return a.origin === 'fact' ? -1 : 1;
  const [ra, na] = scopeRank(a.scope);
  const [rb, nb] = scopeRank(b.scope);
  if (ra !== rb) return ra - rb;
  if (na !== nb) return na < nb ? -1 : 1;
  return a.source_ts === b.source_ts ? 0 : a.source_ts < b.source_ts ? 1 : -1;
}

export function compactRule(r: StartupRule): CompactRule {
  return {
    id: r.id, origin: r.origin, scope: r.scope, text: oneLine(r.text), source_uri: r.source_uri, source_ts: r.source_ts, cite: cite(r),
    ...(r.expires_at ? { expires_at: r.expires_at } : {}),
    ...(r.supersedes && r.supersedes.length ? { supersedes: r.supersedes } : {}),
  };
}

export function remainderEntry(r: StartupRule, reason: RemainderReason): RemainderEntry {
  return { id: r.id, origin: r.origin, scope: r.scope, subject: r.subject, source_uri: r.source_uri, source_ts: r.source_ts, cite: cite(r), reason };
}

/**
 * Rank, then serve the longest ranked prefix that fits the budget (too_long items are listed and
 * skipped over); everything else goes to the remainder in rank order.
 */
export function planStartupRules(rules: readonly StartupRule[], budget: number = STARTUP_RULES_BUDGET_TOKENS, remainderMax: number = REMAINDER_MAX): StartupRulesPlan {
  const ranked = [...rules].sort(compareRules);
  const served: CompactRule[] = [];
  const rest: RemainderEntry[] = [];
  let used = 0;
  let full = false;
  for (const r of ranked) {
    if (oneLine(r.text).length > COMPACT_TEXT_MAX_CHARS) {
      rest.push(remainderEntry(r, 'too_long'));
      continue;
    }
    if (!full) {
      const c = compactRule(r);
      const cost = estimateTokens(c);
      if (used + cost <= budget) {
        served.push(c);
        used += cost;
        continue;
      }
      full = true;
    }
    rest.push(remainderEntry(r, 'budget'));
  }
  return { served, remainder: rest.slice(0, remainderMax), unlisted: Math.max(0, rest.length - remainderMax), budget_used: used };
}

/** rules_note: what was served, what was listed, how to look the rest up. */
export function rulesNote(p: StartupRulesPlan, total: number, capped: boolean, budget: number = STARTUP_RULES_BUDGET_TOKENS): string {
  const order = `ranked fact rules first, then scope (${SCOPE_ORDER.join(', ')}, others), newest first`;
  const parts: string[] = [];
  if (p.remainder.length === 0 && p.unlisted === 0) {
    parts.push(`All ${p.served.length} current standing rules are served in compact form (${order}; ~${p.budget_used} of ${budget} estimated tokens).`);
  } else {
    parts.push(`Served ${p.served.length} of ${total} current standing rules in compact form within a ${budget}-token budget (${order}). `
      + `The other ${p.remainder.length + p.unlisted} are NOT dropped: ${p.remainder.length} are listed in rules_remainder with id, subject and cite `
      + '(reason budget, or too_long: never truncated); they bind like served rules. Look one up with zeusi_context_for_task (its subject) or zeusi_search (the file name in its id).');
    if (p.unlisted > 0) parts.push(` ${p.unlisted} more are counted but not listed (the remainder list holds at most ${REMAINDER_MAX}); zeusi_context_for_task finds them by task.`);
  }
  if (capped) parts.push(' The rule total is capped (more lock notes or fact rules exist than one call reads).');
  return parts.join('');
}
