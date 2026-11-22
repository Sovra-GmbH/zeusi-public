// `zeusi search` (PLAN.md U10 slice, R6, R7; KTD2, KTD6, KTD16). Role: zeusi_box_ro
// (service zeusi_ro, pooled endpoint) or zeusi_cloud_ro. READ-ONLY by construction:
//
//   * refuses a session that is superuser or holds ANY write privilege on a zeusi table
//     (so it never runs as zeusi_box_rw, zeusi_ingest, zeusi_backup or the owner);
//   * every query runs inside BEGIN READ ONLY ... ROLLBACK (the role default
//     default_transaction_read_only=on from 0004 is a second layer);
//   * RLS (read_allowed_scopes: 0005, clientco added in 0010) limits zeusi_read to scopes
//     team, product and clientco (never personal); --scope only narrows it; quarantined
//     content is never stored (R10), and the reader roles cannot read the quarantine.
//
// Modes:
//   vector   ORDER BY embedding <=> $q filtered by embed_model (partial HNSW index),
//            SET LOCAL hnsw.ef_search = 100, hnsw.iterative_scan = relaxed_order (0002).
//   hybrid   vector top 50 + full-text top 50 (tsv, 'simple', websearch_to_tsquery),
//            fused with reciprocal rank fusion, k = 60 (KTD6).
//   lexical  full text only: no ZEUSI_OPENAI_API_KEY (cloud agents until MCP, KTD16),
//            a query-spend cap reached, or a failed query embedding. Always with a notice.
//
// Query-embedding spend cannot go to zeusi.embed_usage (the role is read-only). It is
// tracked best-effort in a LOCAL ledger file on the machine that runs the search
// (~/.zeusi/query-embed-ledger.json, mode 0600, month -> requests/tokens/usd, never the
// query text), and bounded by a per-process cap and a local monthly cap. Results cite
// source_uri, source_ts, scope and heading_path, and carry at most the chunk text.
//
// Decisions (searchDecisions): every mode also searches zeusi.decisions_current (the view
// zeusi_startup uses: not superseded, not expired) in the SAME read-only transaction, so the
// same role, RLS (never personal) and --scope apply. Decisions have no tsv and no embedding
// column, so they are always matched lexically, even in vector / hybrid mode:
//   full text  to_tsvector('simple', exact_words + applies_to) @@ websearch_to_tsquery('simple', q)
//   phrase     whitespace-normalised, case-insensitive substring of exact_words or an applies_to
//              element (queries of >= PHRASE_MIN_CHARS characters); ranks above full-text-only.
// They are returned in their own `decisions` list (never fused into the chunk hits): their
// scores are not comparable with cosine / RRF scores, and the chunk hits stay unchanged.
// Each decision also carries linked_repo, linked_pr, linked_pr_uri and source_note (the decision's
// own active source note: uri, title, source_ts; never the body), read under the same role and RLS
// (src/decision-links.ts).

import { redactDeep } from './secrets.ts';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { Db } from './db.ts';
import { EMBED_MODEL_LABEL, usdForTokens, worstCaseTokens } from './embed.ts';
import type { EmbeddingsClient } from './embeddings.ts';
import { fetchDecisionLinks, LINK_COLS, linksOf, NO_LINKS, sourceNoteJoin, type DecisionLinks } from './decision-links.ts';
import { EMBED_DIMS } from './facts.ts';

export const SEARCH_SCOPES = ['work', 'product', 'client'] as const;
export const RRF_K = 60;
export const HYBRID_DEPTH = 50;
export const HNSW_EF_SEARCH = 100;
export const MAX_LIMIT = 50;

/** Query-embedding caps for one process / one machine (no DB row: the search role is read-only). */
export const QUERY_CAPS = {
  maxRequestsPerProcess: 20,
  maxWorstTokensPerProcess: 20_000,
  /** Local monthly cap per machine, USD (best effort: a local file). */
  localMonthlyUsd: 0.5,
  /** Longer queries are not embedded (lexical instead). */
  maxQueryChars: 2_000,
};

export const LEXICAL_ONLY_NOTICE =
  'notice: no ZEUSI_OPENAI_API_KEY here, so this is a lexical-only (full-text) search; semantic search needs the key (KTD16).';

export class SearchRefused extends Error {
  override name = 'SearchRefused';
}

export interface SearchHit {
  chunkId: number;
  sourceUri: string;
  /** ISO timestamp. */
  sourceTs: string;
  scope: string;
  headingPath: string | null;
  /** The chunk text (never more). */
  text: string;
  score: number;
  /** 1-based rank in each list the hit came from. */
  ranks: { vector?: number; lexical?: number };
}

/** A current decision (zeusi.decisions_current) that matched the query lexically. */
export interface DecisionHit {
  type: 'decision';
  decisionId: number;
  kind: string;
  /** people.handle; null when the person row is not visible to this role. */
  who: string | null;
  /** ISO timestamp. */
  saidAt: string;
  exactWords: string;
  exactWordsVerbatim: boolean;
  appliesTo: string[];
  scope: string;
  sourceUri: string;
  /** ISO timestamp. */
  sourceTs: string;
  /** ts_rank_cd of the full-text match, + 1 for a phrase (substring) match. */
  score: number;
  match: 'phrase' | 'fulltext';
  /** linked_repo, linked_pr, linked_pr_uri, source_note (src/decision-links.ts). Optional for injected search functions. */
  links?: DecisionLinks;
}

export interface SearchResult {
  mode: 'vector' | 'hybrid' | 'lexical';
  hits: SearchHit[];
  /** Matching current decisions (always lexical). Optional so injected search functions may omit it. */
  decisions?: DecisionHit[];
  notice?: string;
}

/** The phrase (substring) fallback runs only for queries at least this long. */
export const PHRASE_MIN_CHARS = 3;

// ---------------------------------------------------------------------------
// Local query-spend ledger

interface LedgerMonth {
  requests: number;
  tokens: number;
  usd: number;
}

export function defaultLedgerPath(home: string = homedir()): string {
  return join(home, '.zeusi', 'query-embed-ledger.json');
}

/** One instance per process: it also holds the per-process counters. */
export class QueryLedger {
  readonly path: string;
  requests = 0;
  worstTokens = 0;

  constructor(path: string = defaultLedgerPath()) {
    this.path = path;
  }

  private read(): Record<string, LedgerMonth> {
    if (!existsSync(this.path)) return {};
    const j = JSON.parse(readFileSync(this.path, 'utf8')) as unknown;
    if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('ledger is not an object');
    return j as Record<string, LedgerMonth>;
  }

  /** null when the query may be embedded; else the reason (the caller falls back to lexical). */
  check(worst: number, month: string): string | null {
    if (this.requests + 1 > QUERY_CAPS.maxRequestsPerProcess || this.worstTokens + worst > QUERY_CAPS.maxWorstTokensPerProcess) {
      return `per-process query-embedding cap reached (${QUERY_CAPS.maxRequestsPerProcess} requests / ${QUERY_CAPS.maxWorstTokensPerProcess} worst-case tokens)`;
    }
    let m: LedgerMonth | undefined;
    try {
      m = this.read()[month];
    } catch {
      return `query-embedding ledger ${this.path} is unreadable; not embedding (fail closed)`;
    }
    const usd = Number(m?.usd ?? 0);
    if (!Number.isFinite(usd) || usd + usdForTokens(worst) > QUERY_CAPS.localMonthlyUsd) {
      return `local monthly query-embedding cap ($${QUERY_CAPS.localMonthlyUsd.toFixed(2)}) reached on this machine`;
    }
    return null;
  }

  /** Record one request. Returns false when the file could not be written (best effort). */
  record(tokens: number, worst: number, month: string): boolean {
    this.requests++;
    this.worstTokens += worst;
    try {
      const all = this.read();
      const m = all[month] ?? { requests: 0, tokens: 0, usd: 0 };
      m.requests += 1;
      m.tokens += tokens;
      m.usd = usdForTokens(m.tokens);
      all[month] = m;
      mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
      const tmp = `${this.path}.tmp-${process.pid}`;
      writeFileSync(tmp, `${JSON.stringify(all, null, 2)}\n`, { mode: 0o600 });
      chmodSync(tmp, 0o600);
      renameSync(tmp, this.path);
      return true;
    } catch {
      return false;
    }
  }
}

// ---------------------------------------------------------------------------

/** Reciprocal rank fusion: score = sum 1 / (k + rank), ranks 1-based; ties by chunk id. */
export function rrfFuse(vector: SearchHit[], lexical: SearchHit[], k = RRF_K): SearchHit[] {
  const by = new Map<number, SearchHit>();
  const add = (list: SearchHit[], which: 'vector' | 'lexical') => {
    list.forEach((h, i) => {
      const cur = by.get(h.chunkId) ?? { ...h, score: 0, ranks: {} };
      cur.score += 1 / (k + i + 1);
      cur.ranks = { ...cur.ranks, [which]: i + 1 };
      by.set(h.chunkId, cur);
    });
  };
  add(vector, 'vector');
  add(lexical, 'lexical');
  return [...by.values()].sort((a, b) => b.score - a.score || a.chunkId - b.chunkId);
}

/** Refuse unless the session is a plain reader (no superuser, no write privilege on any zeusi table). */
export async function assertReadOnlySession(db: Db): Promise<void> {
  const r = (await db.query<{ su: boolean; can_write: boolean }>(
    `SELECT coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false) AS su,
            EXISTS (SELECT 1 FROM pg_tables t WHERE t.schemaname = 'zeusi' AND (
                      has_table_privilege(format('%I.%I', t.schemaname, t.tablename), 'INSERT')
                   OR has_table_privilege(format('%I.%I', t.schemaname, t.tablename), 'UPDATE')
                   OR has_table_privilege(format('%I.%I', t.schemaname, t.tablename), 'DELETE')
                   OR has_table_privilege(format('%I.%I', t.schemaname, t.tablename), 'TRUNCATE'))) AS can_write`,
  )).rows[0]!;
  if (r.su || r.can_write) {
    throw new SearchRefused('search runs only as a read-only role (zeusi_box_ro via service zeusi_ro, or zeusi_cloud_ro); this session can write');
  }
}

interface Row {
  id: number;
  source_uri: string;
  source_ts: Date | string;
  scope: string;
  heading_path: string | null;
  text: string;
  s: number;
}

const toHit = (r: Row, score: number): SearchHit => ({
  chunkId: Number(r.id), sourceUri: r.source_uri, sourceTs: new Date(r.source_ts).toISOString(), scope: r.scope,
  headingPath: r.heading_path, text: r.text, score, ranks: {},
});

const COLS = `c.id::int AS id, c.source_uri, c.source_ts, c.scope::text AS scope, c.heading_path, c.text`;

interface DecisionRow {
  id: number;
  kind: string;
  who: string | null;
  said_at: Date | string;
  exact_words: string;
  exact_words_verbatim: boolean;
  applies_to: string[] | null;
  scope: string;
  source_uri: string;
  source_ts: Date | string;
  phrase: boolean;
  s: number;
  [link: string]: unknown;
}

/** The whitespace-normalised, lower-cased phrase of a query (the LIKE pattern's text; the C7 sealed search's substring). */
export function phraseText(query: string): string {
  return query.toLowerCase().replace(/\s+/g, ' ').trim();
}

/** LIKE pattern for a whitespace-normalised, lower-cased substring match (%, _ and \ escaped). */
export function phrasePattern(query: string): string {
  const norm = phraseText(query);
  return `%${norm.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

/**
 * Current decisions matching the query (full text on exact_words + applies_to, plus the phrase
 * fallback). Runs inside the caller's read-only transaction, as the caller's role (RLS applies).
 */
export async function searchDecisions(db: Db, query: string, scope: string | null, limit: number): Promise<DecisionHit[]> {
  const phrase = [...query.trim()].length >= PHRASE_MIN_CHARS ? phrasePattern(query) : null;
  const rows = (await db.query<DecisionRow>(
    `WITH d AS (
       SELECT d.*, to_tsvector('simple', d.exact_words || ' ' || array_to_string(d.applies_to, ' ')) AS dtsv
       FROM zeusi.decisions_current d
       WHERE ($2::text IS NULL OR d.scope::text = $2::text)
     ), m AS (
       SELECT d.*,
              ($3::text IS NOT NULL AND (
                 regexp_replace(lower(d.exact_words), '\\s+', ' ', 'g') LIKE $3::text
                 OR EXISTS (SELECT 1 FROM unnest(d.applies_to) a WHERE regexp_replace(lower(a), '\\s+', ' ', 'g') LIKE $3::text)
              )) AS phrase,
              coalesce(ts_rank_cd(d.dtsv, q), 0)::float8 AS fts,
              (d.dtsv @@ q) AS fmatch
       FROM d, websearch_to_tsquery('simple', $1) AS q
     )
     SELECT d.id::int AS id, d.kind::text AS kind, p.handle AS who, d.said_at, d.exact_words, d.exact_words_verbatim,
            d.applies_to, d.scope::text AS scope, d.source_uri, d.source_ts, d.phrase,
            (d.fts + CASE WHEN d.phrase THEN 1 ELSE 0 END)::float8 AS s, ${LINK_COLS}
     FROM m AS d LEFT JOIN zeusi.people p ON p.id = d.who_id
     ${sourceNoteJoin('d')}
     WHERE d.phrase OR coalesce(d.fmatch, false)
     ORDER BY s DESC, d.said_at DESC, d.id DESC
     LIMIT $4`,
    [query, scope, phrase, limit],
  )).rows;
  const links = await fetchDecisionLinks(db, rows.map((r) => Number(r.id)));
  return rows.map((r) => ({
    type: 'decision', decisionId: Number(r.id), kind: r.kind, who: r.who ?? null, saidAt: new Date(r.said_at).toISOString(),
    exactWords: r.exact_words, exactWordsVerbatim: Boolean(r.exact_words_verbatim), appliesTo: r.applies_to ?? [],
    scope: r.scope, sourceUri: r.source_uri, sourceTs: new Date(r.source_ts).toISOString(), score: Number(r.s),
    match: r.phrase ? 'phrase' : 'fulltext', links: linksOf(r, links.get(Number(r.id))),
  }));
}

export interface SearchOptions {
  db: Db;
  query: string;
  limit?: number;
  scope?: string;
  hybrid?: boolean;
  /** null: no key on this machine -> lexical only. */
  client: EmbeddingsClient | null;
  ledger: QueryLedger;
  now?: () => Date;
}

/** The argument rule of every search (search() and the C7 sealed search): trimmed query, limit and scope. */
export function searchArgs(opts: Pick<SearchOptions, 'query' | 'limit' | 'scope'>): { query: string; limit: number; scope: string | null } {
  const query = opts.query.trim();
  if (query === '') throw new SearchRefused('empty query');
  const limit = opts.limit ?? 10;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) throw new SearchRefused(`--limit must be 1..${MAX_LIMIT}`);
  const scope = opts.scope ?? null;
  if (scope !== null && !(SEARCH_SCOPES as readonly string[]).includes(scope)) {
    throw new SearchRefused(`--scope must be one of ${SEARCH_SCOPES.join('|')}`);
  }
  return { query, limit, scope };
}

export async function search(opts: SearchOptions): Promise<SearchResult> {
  const { db } = opts;
  const { query, limit, scope } = searchArgs(opts);
  await assertReadOnlySession(db);

  // Query vector first (no DB transaction is open during the network call).
  let vec: string | null = null;
  let notice: string | undefined;
  if (opts.client === null) notice = LEXICAL_ONLY_NOTICE;
  else if ([...query].length > QUERY_CAPS.maxQueryChars) notice = `notice: query longer than ${QUERY_CAPS.maxQueryChars} characters is not embedded; lexical-only search.`;
  else {
    const month = (opts.now?.() ?? new Date()).toISOString().slice(0, 7);
    const worst = worstCaseTokens(query);
    const why = opts.ledger.check(worst, month);
    if (why) notice = `notice: ${why}; lexical-only search.`;
    else {
      try {
        const out = await opts.client.embed([query]);
        const v = out.vectors[0];
        if (!v || v.length !== EMBED_DIMS || !v.every(Number.isFinite)) throw new Error('bad vector');
        if (!opts.ledger.record(out.totalTokens ?? worst, worst, month)) notice = `notice: query-embedding ledger ${opts.ledger.path} could not be written (spend not recorded locally).`;
        vec = `[${v.join(',')}]`;
      } catch (e) {
        opts.ledger.record(worst, worst, month); // may have been billed: count the worst case
        notice = `notice: query embedding failed (${e instanceof Error ? e.message : 'error'}); lexical-only search.`;
      }
    }
  }

  const mode: SearchResult['mode'] = vec === null ? 'lexical' : opts.hybrid ? 'hybrid' : 'vector';
  await db.exec('BEGIN READ ONLY');
  try {
    await db.exec(`SET LOCAL hnsw.ef_search = ${HNSW_EF_SEARCH}`);
    await db.exec('SET LOCAL hnsw.iterative_scan = relaxed_order');
    const depth = mode === 'hybrid' ? HYBRID_DEPTH : limit;
    let vHits: SearchHit[] = [];
    let lHits: SearchHit[] = [];
    if (vec !== null) {
      // Model label inlined as a constant so the planner matches the partial HNSW index predicate.
      vHits = (await db.query<Row>(
        `SELECT ${COLS}, (c.embedding <=> $1::halfvec(${EMBED_DIMS}))::float8 AS s
         FROM zeusi.chunks c
         WHERE c.embed_model = '${EMBED_MODEL_LABEL}' AND ($2::text IS NULL OR c.scope::text = $2::text)
         ORDER BY c.embedding <=> $1::halfvec(${EMBED_DIMS})
         LIMIT $3`,
        [vec, scope, depth],
      )).rows.map((r) => toHit(r, 1 - Number(r.s)));
    }
    if (mode !== 'vector') {
      lHits = (await db.query<Row>(
        `SELECT ${COLS}, ts_rank_cd(c.tsv, q)::float8 AS s
         FROM zeusi.chunks c, websearch_to_tsquery('simple', $1) AS q
         WHERE c.tsv @@ q AND ($2::text IS NULL OR c.scope::text = $2::text)
         ORDER BY s DESC, c.id
         LIMIT $3`,
        [query, scope, mode === 'hybrid' ? HYBRID_DEPTH : limit],
      )).rows.map((r) => toHit(r, Number(r.s)));
    }
    let hits: SearchHit[];
    if (mode === 'hybrid') hits = rrfFuse(vHits, lHits).slice(0, limit);
    else if (mode === 'vector') hits = vHits.map((h, i) => ({ ...h, ranks: { vector: i + 1 } }));
    else hits = lHits.map((h, i) => ({ ...h, ranks: { lexical: i + 1 } }));
    // Decisions: always lexical (no embedding column), same transaction, same role and RLS.
    const decisions = await searchDecisions(db, query, scope, limit);
    return notice === undefined ? { mode, hits, decisions } : { mode, hits, decisions, notice };
  } finally {
    await db.exec('ROLLBACK').catch(() => {});
  }
}

const SNIPPET = 240;

export function formatSearch(r0: SearchResult, opts: { json?: boolean } = {}): string {
  // Serve-time secret guard for the CLI (src/secrets.ts): every hit, decision and notice is
  // redacted before it is printed. Fail closed: nothing is printed if the guard throws.
  let r: SearchResult;
  try {
    r = redactDeep(r0).value;
  } catch {
    return 'search: output withheld (the secret guard failed; nothing printed)';
  }
  if (opts.json) {
    return JSON.stringify({
      mode: r.mode,
      ...(r.notice ? { notice: r.notice } : {}),
      hits: r.hits.map((h) => ({
        chunk_id: h.chunkId, source_uri: h.sourceUri, source_ts: h.sourceTs, scope: h.scope,
        heading_path: h.headingPath, score: h.score, ranks: h.ranks, text: h.text,
      })),
      decisions: (r.decisions ?? []).map(decisionJson),
    }, null, 2);
  }
  const lines: string[] = [];
  if (r.notice) lines.push(r.notice);
  lines.push(`search (${r.mode}): ${r.hits.length} hit(s)`);
  r.hits.forEach((h, i) => {
    const snip = h.text.replace(/\s+/g, ' ').trim();
    lines.push(`${String(i + 1).padStart(2)}. ${h.sourceUri} @ ${h.sourceTs} [${h.scope}]${h.headingPath ? ` ${h.headingPath.slice(0, 80)}` : ''} score=${h.score.toFixed(4)}`);
    lines.push(`    ${[...snip].length > SNIPPET ? `${[...snip].slice(0, SNIPPET).join('')}…` : snip}`);
  });
  const ds = r.decisions ?? [];
  if (ds.length > 0) {
    lines.push(`decisions (lexical, current only): ${ds.length} hit(s)`);
    ds.forEach((d, i) => {
      const words = d.exactWords.replace(/\s+/g, ' ').trim();
      lines.push(`${String(i + 1).padStart(2)}. ${d.sourceUri} @ ${d.sourceTs} [${d.scope}] ${d.kind} by ${d.who ?? '?'} at ${d.saidAt}${d.appliesTo.length ? ` applies_to=${d.appliesTo.join(',').slice(0, 80)}` : ''} score=${d.score.toFixed(4)}`);
      lines.push(`    ${[...words].length > SNIPPET ? `${[...words].slice(0, SNIPPET).join('')}…` : words}`);
    });
  }
  return lines.join('\n');
}

/** The wire shape of a decision hit (MCP and --json). cite is `<source_uri> @ <source_ts>`. */
export function decisionJson(d: DecisionHit) {
  return {
    type: 'decision' as const, kind: d.kind, who: d.who, said_at: d.saidAt, exact_words: d.exactWords,
    exact_words_verbatim: d.exactWordsVerbatim, applies_to: d.appliesTo, scope: d.scope, source_uri: d.sourceUri,
    source_ts: d.sourceTs, cite: `${d.sourceUri} @ ${d.sourceTs}`, score: d.score, match: d.match,
    ...(d.links ?? NO_LINKS),
  };
}
