// zeusi_context_for_task core (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md U2, KTD4, KTD5):
// "Zeusi speaks up first". Given a short task description, return the owner's CURRENT
// decisions, locks and parked items that apply, ranked, cited, with conflicts flagged.
//
//   * Source: zeusi.decisions_current only (not superseded, not expired). Supersession and
//     expiry are NOT reimplemented here; the view decides.
//   * Matching (lexical, no embeddings, no OpenAI spend): the task is reduced to at most
//     MAX_TERMS terms (NFKC, lower-case, letters and digits only, 2..64 characters, stopwords
//     dropped). A row qualifies when a term equals one of its tokens (exact_words + applies_to
//     split on non-alphanumerics), or an applies_to element is a whole word / phrase of the
//     task. Terms reach SQL only as a text[] parameter compared with `=`: no tsquery, regex or
//     SQL text is ever built from them. Implementation note (deviation from KTD4's OR-tsquery):
//     token-array equality is used instead of to_tsquery so the SQL filter and the JS relevance
//     score tokenise the same way (the 'simple' parser keeps e.g. "london/ny" as one lexeme).
//   * Runs inside the caller's BEGIN READ ONLY transaction, as the caller's read-only role, so
//     RLS (never personal) and the scope filter apply.
//   * Ranking and conflicts are pure functions (rankForTask, findConflicts).

import type { Db } from './db.ts';
import { fetchDecisionLinks, LINK_COLS, linksOf, NO_LINKS, sourceNoteJoin, type DecisionLinks } from './decision-links.ts';

export const MAX_TERMS = 32;
export const MAX_CANDIDATES = 200;
export const TERM_MIN = 2;
export const TERM_MAX = 64;
export const DEFAULT_CONTEXT_LIMIT = 10;
export const MAX_CONTEXT_LIMIT = 50;
export const MAX_TASK_CHARS = 4000;

/** Small fixed English + German stopword list (task phrasing, not content). */
export const STOPWORDS: ReadonlySet<string> = new Set([
  // English
  'a', 'an', 'the', 'and', 'or', 'but', 'to', 'of', 'in', 'on', 'at', 'for', 'with', 'by', 'from', 'as', 'into', 'onto', 'about',
  'over', 'under', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'am', 'it', 'its', 'this', 'that', 'these', 'those', 'i', 'we',
  'you', 'he', 'she', 'they', 'them', 'me', 'my', 'our', 'your', 'his', 'her', 'their', 'do', 'does', 'did', 'done', 'doing', 'can',
  'could', 'should', 'would', 'will', 'shall', 'may', 'might', 'must', 'not', 'no', 'yes', 'so', 'if', 'then', 'than', 'up', 'out',
  'all', 'any', 'some', 'what', 'when', 'where', 'which', 'who', 'whom', 'how', 'why', 'there', 'here', 'have', 'has', 'had', 'just',
  'also', 'now', 'please', 'pls', 'let', 'lets', 'us', 'get', 'got', 'make', 'need', 'needs', 'want', 'go', 'going', 'task', 'work',
  'job', 'start', 'starting', 'next', 'via', 'per', 'etc', 'new',
  // German
  'der', 'die', 'das', 'den', 'dem', 'des', 'ein', 'eine', 'einen', 'einem', 'einer', 'und', 'oder', 'aber', 'zu', 'zum', 'zur',
  'mit', 'von', 'vom', 'fuer', 'für', 'auf', 'aus', 'bei', 'nach', 'ist', 'sind', 'war', 'nicht', 'kein', 'keine', 'im', 'es', 'ich',
  'wir', 'du', 'sie', 'er', 'bitte', 'auch', 'noch', 'wie', 'was', 'wo', 'mal', 'jetzt', 'dann', 'dass', 'damit', 'machen', 'soll',
]);

const TOKEN_RE = /[\p{L}\p{N}]+/gu;

/** NFKC + lower-case tokens of letters and digits (same tokeniser for task, rows and relevance). */
export function tokens(s: string): string[] {
  return s.normalize('NFKC').toLowerCase().match(TOKEN_RE) ?? [];
}

/** The searchable terms of a task: deduped, stopwords dropped, 2..64 characters, at most MAX_TERMS. */
export function taskTerms(task: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const t of tokens(task)) {
    const n = [...t].length;
    if (n < TERM_MIN || n > TERM_MAX || STOPWORDS.has(t) || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
    if (out.length >= MAX_TERMS) break;
  }
  return out;
}

/** A candidate row from decisions_current (RLS-visible to the caller). */
export interface CandidateRow {
  id: number;
  kind: string;
  who: string | null;
  saidAt: string;
  exactWords: string;
  exactWordsVerbatim: boolean;
  appliesTo: string[];
  expiresAt: string | null;
  scope: string;
  sourceUri: string;
  sourceTs: string;
  /** linked_repo, linked_pr, linked_pr_uri, source_note (src/decision-links.ts). */
  links?: DecisionLinks;
}

const iso = (v: unknown): string | null => (v === null || v === undefined ? null : new Date(v as string).toISOString());

/**
 * Up to MAX_CANDIDATES current decisions that share a whole word with the task terms, or whose
 * applies_to element appears in the task. Must run inside the caller's read-only transaction.
 */
export async function queryCandidates(db: Db, terms: readonly string[], task: string, scope: string | null): Promise<CandidateRow[]> {
  if (terms.length === 0) return [];
  const normTask = tokens(task).join(' ');
  const rows = (await db.query<Record<string, unknown>>(
    `WITH d AS (
       SELECT d.*, regexp_split_to_array(lower(d.exact_words || ' ' || array_to_string(d.applies_to, ' ')), '[^[:alnum:]]+') AS toks
       FROM zeusi.decisions_current d
       WHERE ($3::text IS NULL OR d.scope::text = $3::text)
     ), m AS (
       SELECT d.*,
              (SELECT count(DISTINCT t)::int FROM unnest($1::text[]) t WHERE t = ANY (d.toks)) AS n_terms,
              EXISTS (SELECT 1 FROM unnest(d.applies_to) a,
                             LATERAL (SELECT btrim(regexp_replace(lower(a), '[^[:alnum:]]+', ' ', 'g')) AS na) x
                      WHERE length(x.na) >= ${TERM_MIN} AND strpos(' ' || $2::text || ' ', ' ' || x.na || ' ') > 0) AS a_hit
       FROM d
     )
     SELECT d.id::int AS id, d.kind::text AS kind, p.handle AS who, d.said_at, d.exact_words, d.exact_words_verbatim,
            d.applies_to, d.expires_at, d.scope::text AS scope, d.source_uri, d.source_ts, ${LINK_COLS}
     FROM m AS d LEFT JOIN zeusi.people p ON p.id = d.who_id
     ${sourceNoteJoin('d')}
     WHERE d.n_terms > 0 OR d.a_hit
     ORDER BY d.n_terms DESC, d.said_at DESC, d.id DESC
     LIMIT ${MAX_CANDIDATES}`,
    [terms, normTask, scope],
  )).rows;
  const links = await fetchDecisionLinks(db, rows.map((r) => Number(r['id'])));
  return rows.map((r) => ({
    id: Number(r['id']), kind: String(r['kind']), who: (r['who'] as string | null) ?? null, saidAt: iso(r['said_at'])!,
    exactWords: String(r['exact_words']), exactWordsVerbatim: Boolean(r['exact_words_verbatim']),
    appliesTo: (r['applies_to'] as string[] | null) ?? [], expiresAt: iso(r['expires_at']), scope: String(r['scope']),
    sourceUri: String(r['source_uri']), sourceTs: iso(r['source_ts'])!, links: linksOf(r, links.get(Number(r['id']))),
  }));
}

/** Kind weight: binding constraints first (lock, stop), then parked, then rulings and GOs. */
export const KIND_WEIGHT: Readonly<Record<string, number>> = { lock: 0.6, stop: 0.6, park: 0.4, ruling: 0.2, go: 0.2 };
const APPLIES_BONUS = 1.5;
export const RECENCY_WEIGHT = 0.3;
export const RECENCY_DAYS = 90;

export interface RankedRow extends CandidateRow {
  score: number;
  /** applies_to elements that matched the task (original spelling). */
  matchedAppliesTo: string[];
}

/** Whole-word / whole-phrase test over normalised token strings. */
function containsPhrase(hay: string, needle: string): boolean {
  return needle !== '' && ` ${hay} `.includes(` ${needle} `);
}

/**
 * Pure ranking: relevance (distinct task terms found as whole words + an applies_to bonus), then
 * kind weight, then recency decay on said_at. Rows with no relevance at all are dropped.
 */
export function rankForTask(rows: readonly CandidateRow[], task: string, now: Date): RankedRow[] {
  const terms = taskTerms(task);
  const taskNorm = tokens(task).join(' ');
  const out: RankedRow[] = [];
  for (const r of rows) {
    const body = new Set(tokens(`${r.exactWords} ${r.appliesTo.join(' ')}`));
    const termHits = terms.filter((t) => body.has(t)).length;
    const matchedAppliesTo = r.appliesTo.filter((a) => {
      const n = tokens(a).join(' ');
      return [...n].length >= TERM_MIN && (containsPhrase(taskNorm, n) || terms.includes(n));
    });
    if (termHits === 0 && matchedAppliesTo.length === 0) continue;
    const ageDays = Math.max(0, (now.getTime() - new Date(r.saidAt).getTime()) / 86_400_000);
    const score = termHits + APPLIES_BONUS * matchedAppliesTo.length + (KIND_WEIGHT[r.kind] ?? 0) + RECENCY_WEIGHT * Math.exp(-ageDays / RECENCY_DAYS);
    out.push({ ...r, score: Math.round(score * 1e6) / 1e6, matchedAppliesTo });
  }
  return out.sort((a, b) => b.score - a.score || b.saidAt.localeCompare(a.saidAt) || b.id - a.id);
}

export interface Conflict {
  ids: [number, number];
  kinds: [string, string];
  /** Shared applies_to targets (lower-case). */
  applies_to: string[];
}

const BLOCKING = new Set(['stop', 'lock', 'park']);

/**
 * Pure: two current items conflict when they share at least one applies_to target
 * (case-insensitive) and one is a go while the other is a stop, lock or park.
 */
export function findConflicts(items: ReadonlyArray<{ id: number; kind: string; applies_to: readonly string[] }>): Conflict[] {
  const out: Conflict[] = [];
  for (let i = 0; i < items.length; i++) {
    for (let j = i + 1; j < items.length; j++) {
      const a = items[i]!;
      const b = items[j]!;
      const opposed = (a.kind === 'go' && BLOCKING.has(b.kind)) || (b.kind === 'go' && BLOCKING.has(a.kind));
      if (!opposed) continue;
      const bt = new Set(b.applies_to.map((x) => x.toLowerCase()));
      const shared = [...new Set(a.applies_to.map((x) => x.toLowerCase()))].filter((x) => bt.has(x));
      if (shared.length > 0) out.push({ ids: [a.id, b.id], kinds: [a.kind, b.kind], applies_to: shared });
    }
  }
  return out;
}

/** The wire shape of one item (R6). cite carries the decision id, who and date too. */
export function contextItemJson(r: RankedRow) {
  return {
    type: 'decision' as const, origin: 'decision' as const, id: r.id, kind: r.kind, who: r.who, date: { said_at: r.saidAt, source_ts: r.sourceTs },
    exact_words: r.exactWords, exact_words_verbatim: r.exactWordsVerbatim, applies_to: r.appliesTo, expires_at: r.expiresAt,
    scope: r.scope, source_uri: r.sourceUri, source_ts: r.sourceTs, ...(r.links ?? NO_LINKS), score: r.score,
    cite: `${r.sourceUri} @ ${r.sourceTs} (decision ${r.id}, ${r.who ?? 'who unknown'}, said ${r.saidAt})`,
  };
}

export type ContextItem = ReturnType<typeof contextItemJson>;

export const NOTHING_FOUND =
  'No current decision, lock or parked item in Zeusi matches this task. Nothing was invented. Proceed with the usual rules, and ask the owner if a decision is needed.';
export const CONFLICT_HINT = 'These current items disagree on a shared target. Do not pick one yourself: ask the owner which applies.';
