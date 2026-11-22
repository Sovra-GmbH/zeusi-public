// Workspace READ routing (C7, docs/plans/2026-11-19-c7-read-path.md KTD1, KTD10, KTD13).
//
// ONE rule decides how a personal workspace is read, from its catalog enc_state (TenantRouter.encState, read
// once per request by the hosted handler, src/mcp-hosted.ts):
//
//   off, enrolled                                       plain   (offPathAllowed, C5 KTD12): today's SQL, unchanged
//   encrypting, verified, on, decrypting, decrypted     sealed  (values opened in the app; both row shapes)
//   anything else (or a state that cannot be read)      refused before any workspace SQL
//
// `encrypting` is sealed (open decision 1, default): during a C8a run the schema holds plain and sealed rows; the
// plain route would serve a sealed row's NULL text as "null" or miss it, and refusing would block startup for
// the whole run. The sealed route handles both shapes (src/workspace-seal.ts openedRow).
//
// ReadSource (KTD10): the row source of the four read tools. sqlReadSource is today's code with the SAME SQL
// text and parameters (moved, not rewritten; test/c7-off-golden.test.ts pins every statement). The sealed one
// is src/sealed-read.ts. Everything after the row source (lock lifecycle resolution, startup rules, ranking,
// conflicts, links, the serve wall and the secret guard on the served strings) is shared and unchanged.
// the team and the stdio / --http servers never route: they have no readRoute and run sqlReadSource.

import type { AboutHit, AboutSection } from './about.ts';
import { searchAbout } from './about.ts';
import type { B1Cache, WrapProof } from './b1-cache.ts';
import { queryCandidates, type CandidateRow } from './context-for-task.ts';
import type { Db } from './db.ts';
import { fetchDecisionLinks, LINK_COLS, sourceNoteJoin, type DecisionLinkItem } from './decision-links.ts';
import { lockLifecycle, type LifecycleCounts, type ResolvedLock } from './lock-lifecycle.ts';
import { emptinessCounts, onboardingCounts, type Emptiness, type OnboardingStatus } from './onboarding.ts';
import type { SearchOptions, SearchResult } from './search.ts';
import { offPathAllowed } from './tenant-overlay.ts';
import { WORKSPACE_PERSON_HANDLE, type EncState } from './tenants.ts';

/** KTD13: the sealed route has no session key for this request (no or another session wrap). Served; no claim. */
export const WORKSPACE_READ_LOCKED =
  'This connection cannot open your workspace right now. Sign in to Zeusi again from your assistant, then retry.';
/** KTD13: the workspace is in a state the read path does not serve (or its key changed under the request). */
export const WORKSPACE_READ_CHANGING =
  'Your workspace is in the middle of a change you started. Try again in a few minutes.';

/** The states read on the sealed route (KTD1). Not exported: src/read-route.ts exports only served copy and code (test/helpers/overclaim.ts). */
const SEALED_READ_STATES: readonly EncState[] = ['encrypting', 'verified', 'on', 'decrypting', 'decrypted'];

export class ReadRouteRefused extends Error {
  override name = 'ReadRouteRefused';
  readonly reason: 'locked' | 'changing';
  constructor(reason: 'locked' | 'changing') {
    super(reason === 'locked' ? WORKSPACE_READ_LOCKED : WORKSPACE_READ_CHANGING);
    this.reason = reason;
  }
}

/** KTD1: plain exactly when offPathAllowed; sealed for the five states above; anything else is refused (changing). */
export function readRouteFor(state: unknown): 'plain' | 'sealed' {
  if (typeof state === 'string' && offPathAllowed(state as EncState)) return 'plain';
  if (typeof state === 'string' && (SEALED_READ_STATES as readonly string[]).includes(state)) return 'sealed';
  throw new ReadRouteRefused('changing');
}

/** The route of one request: plain, or sealed with this request's proof and the process cache. */
export type ReadRoute =
  | { readonly kind: 'plain' }
  | { readonly kind: 'sealed'; readonly proof: WrapProof; readonly cache: B1Cache };

export const PLAIN_READ: ReadRoute = Object.freeze({ kind: 'plain' as const });

type Row = Record<string, unknown>;

/** Does the workspace know its own person `me`? One statement for both routes (people is never sealed). */
export const WORKSPACE_PERSON_HANDLE_SQL = { sql: 'SELECT count(*)::int AS n FROM zeusi.people WHERE handle = $1', params: [WORKSPACE_PERSON_HANDLE] } as const;

/** The rows the read tools consume; each returns exactly what today's SQL returns (KTD10). */
export interface ReadSource {
  /** Open the tool's read-only transaction (plain: BEGIN READ ONLY). */
  begin(): Promise<void>;
  /** End it (ROLLBACK; never throws). */
  end(): Promise<void>;
  /** zeusi_startup: fact rules of facts_current, newest first (id as text, subject, text, scope, source_uri, source_ts). */
  factRules(cap: number): Promise<Row[]>;
  /** zeusi_startup: facts_current of one kind, newest first (subject, text, scope, source_uri, source_ts). */
  facts(kind: string, cap: number): Promise<Row[]>;
  /** The note-lock lifecycle (src/lock-lifecycle.ts) over the visible lifecycle notes. */
  lockLifecycle(now: Date): Promise<{ locks: ResolvedLock[]; counts: LifecycleCounts; capped: boolean }>;
  /** zeusi_startup: decisions_current of the last `days` days with LINK_COLS. */
  recentDecisions(days: number, cap: number): Promise<Row[]>;
  /** The 0013 links of these decisions (src/decision-links.ts fetchDecisionLinks). */
  decisionLinks(ids: readonly number[]): Promise<Map<number, DecisionLinkItem[]>>;
  /** The one emptiness rule (src/onboarding.ts emptinessCounts). */
  emptiness(scope: string | null): Promise<Emptiness>;
  /** Does the workspace know its own person `me`? */
  knowsPerson(): Promise<boolean>;
  /** zeusi_search chunk hits + decisions (the whole search, its own transaction). */
  search(o: SearchOptions): Promise<SearchResult>;
  /** The built-in about entries matching the query. */
  about(query: string, limit: number, sections: readonly AboutSection[]): Promise<AboutHit[]>;
  /** zeusi_context_for_task candidates (src/context-for-task.ts queryCandidates). */
  taskCandidates(terms: readonly string[], task: string, scope: string | null): Promise<CandidateRow[]>;
  /** zeusi_onboarding_status counts (src/onboarding.ts onboardingCounts). */
  onboarding(scope: string | null, now: Date): Promise<OnboardingStatus>;
}

/** Today's read path, byte-identical SQL (moved from src/mcp-server.ts; the rest are the existing functions). */
export function sqlReadSource(db: Db, searchFn: (o: SearchOptions) => Promise<SearchResult>): ReadSource {
  return {
    begin: () => db.exec('BEGIN READ ONLY'),
    end: async () => {
      await db.exec('ROLLBACK').catch(() => {});
    },
    factRules: async (cap) => (await db.query<Row>(
      `SELECT id::bigint::text AS id, subject, text, scope::text AS scope, source_uri, source_ts FROM zeusi.facts_current
             WHERE kind = 'rule' ORDER BY source_ts DESC, id DESC LIMIT $1`, [cap])).rows,
    facts: async (kind, cap) => (await db.query<Row>(
      `SELECT subject, text, scope::text AS scope, source_uri, source_ts FROM zeusi.facts_current
             WHERE kind = $1 ORDER BY source_ts DESC, id DESC LIMIT $2`, [kind, cap])).rows,
    lockLifecycle: (now) => lockLifecycle(db, now),
    recentDecisions: async (days, cap) => (await db.query<Row>(
      `SELECT d.id::int AS id, d.kind::text AS kind, p.handle AS who, d.said_at, d.exact_words, d.exact_words_verbatim, d.applies_to,
                    d.expires_at, d.scope::text AS scope, d.source_uri, d.source_ts, ${LINK_COLS}
             FROM zeusi.decisions_current d LEFT JOIN zeusi.people p ON p.id = d.who_id
             ${sourceNoteJoin('d')}
             WHERE d.said_at >= now() - make_interval(days => $1::int)
             ORDER BY d.said_at DESC, d.id DESC LIMIT $2`, [days, cap])).rows,
    decisionLinks: (ids) => fetchDecisionLinks(db, ids),
    emptiness: (scope) => emptinessCounts(db, scope),
    knowsPerson: async () => (await db.query<{ n: number }>(WORKSPACE_PERSON_HANDLE_SQL.sql, [...WORKSPACE_PERSON_HANDLE_SQL.params])).rows[0]?.n === 1,
    search: (o) => searchFn({ ...o, db }),
    about: (query, limit, sections) => searchAbout(db, query, limit, sections),
    taskCandidates: (terms, task, scope) => queryCandidates(db, terms, task, scope),
    onboarding: (scope, now) => onboardingCounts(db, scope, undefined, now),
  };
}
