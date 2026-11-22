// The sealed read source (C7b + C7c, docs/plans/2026-11-19-c7-read-path.md KTD7, KTD9, KTD11): the ReadSource of a
// workspace on the sealed read route (src/read-route.ts). ONE algorithm for every read tool:
//
//   1. the tool's transaction: BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY (one snapshot for the coverage
//      check, the visibility metadata and the served rows), as the workspace read role (SELECT only);
//   2. the database's coverage of the five tables and the manifest generation (numbers only); a row of another
//      key_version than this request's proof refuses the call (WORKSPACE_READ_CHANGING);
//   3. the B1 cache (src/b1-cache.ts) with this request's wrap proof; on a miss the persisted index is opened, or
//      built from rows (both shapes) when it is missing, does not open or does not match;
//   4. visibility from the database, metadata only: decisions_current / facts_current ids with their plain
//      metadata, active note ids, chunk scope; the 0001 views stay the one owner of "current";
//   5. the answer in memory: the lexer (src/b1-lexer.ts, Postgres `simple` parity) over the index; the same
//      ordering, ties and limits as the SQL; one in-memory rule for "this note is the source of that uri" (both
//      row shapes; the database gets note ids only);
//   6. the served chunk rows are fetched by id and opened (openedRow; a tag failure fails the call closed).
//
// No query, task, term, uri or other user text is ever a statement text or parameter here: parameters are
// ids, scopes, kinds, caps, `days` and key_version. Nothing is written (no INSERT / UPDATE / DELETE, no nextval,
// no index persist: a rebuilt index lives in the cache until the next sealed write persists it). No embeddings
// client is ever called (personal workspaces are lexical only).

import { aboutHit, type AboutHit, type AboutSection } from './about.ts';
import { CacheVersionChanged } from './b1-cache.ts';
import {
  chunksOf, dbCoverage, loadPacked, manifestGeneration, positionsOf, recordsOf, termIndex,
  type DecisionEntry, type FactEntry, type IndexRecords, type LinkEntry, type NoteEntry, type Packed,
} from './b1-index.ts';
import { lookupOf, queryLexemes, toTsvector, tsMatch, tsRankCd, websearchToTsquery, type TsQuery } from './b1-lexer.ts';
import { MAX_CANDIDATES, TERM_MIN, tokens, type CandidateRow } from './context-for-task.ts';
import type { Db } from './db.ts';
import { hasDecisionLinks, linksOf, MAX_LINKS, type DecisionLinkItem, type LinkTargetKind } from './decision-links.ts';
import { LIFECYCLE_KEYS, LOCK_NOTES_CAP, resolveLockLifecycle, type LockNoteInput } from './lock-lifecycle.ts';
import { emptinessCounts, noteLockItemCount, onboardingCounts } from './onboarding.ts';
import { ReadRouteRefused, WORKSPACE_PERSON_HANDLE_SQL, type ReadRoute, type ReadSource } from './read-route.ts';
import {
  assertReadOnlySession, LEXICAL_ONLY_NOTICE, PHRASE_MIN_CHARS, phraseText, searchArgs, type DecisionHit, type SearchHit, type SearchResult,
} from './search.ts';
import { openedRow, RowKeyVersionMismatch } from './workspace-seal.ts';

type Row = Record<string, unknown>;
type SealedRoute = Extract<ReadRoute, { kind: 'sealed' }>;

const iso = (v: unknown): string | null => (v === null || v === undefined ? null : new Date(v as string).toISOString());
const ms = (v: unknown): number => new Date(v as string).getTime();

/** Postgres `\s` (ASCII white space) runs to one space, after lower(): the phrase fallback's haystack. */
function phraseHay(s: string): string {
  return s.toLowerCase().replace(/[ \t\n\v\f\r]+/g, ' ');
}
/** regexp_split_to_array(lower(x), '[^[:alnum:]]+') (context_for_task, parity class: ASCII). */
function alnumSplit(s: string): string[] {
  return s.toLowerCase().split(/[^\p{L}\p{N}]+/u);
}
/** btrim(regexp_replace(lower(a), '[^[:alnum:]]+', ' ', 'g')). */
function alnumNorm(s: string): string {
  return s.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').replace(/^ +| +$/g, '');
}
/** split_part(uri, '#', 1). */
const uriBase = (u: string) => u.split('#')[0]!;
/** substr(x, 7) in characters. */
const substr7 = (x: string) => [...x].slice(6).join('');

/** Map any failure of the sealed route to its served class: a key_version change -> changing; else the error. */
function classify(e: unknown): never {
  if (e instanceof RowKeyVersionMismatch || e instanceof CacheVersionChanged) throw new ReadRouteRefused('changing');
  throw e;
}

/** Rank chunks of the packed index for a query: every matching chunk ordinal with its ts_rank_cd, best first, ties by id. */
export function rankChunks(p: Packed, q: TsQuery): Array<{ id: number; score: number }> {
  if (q === null) return [];
  const words = queryLexemes(q);
  const tix = new Map(words.map((w) => [w, termIndex(p, w)] as const));
  const lookupAt = (ord: number) => (w: string) => {
    const t = tix.get(w);
    return t === undefined || t < 0 ? undefined : positionsOf(p, t, ord);
  };
  const cands = new Set<number>();
  if (tsMatch(() => undefined, q)) for (let i = 0; i < p.chunkIds.length; i++) cands.add(i);
  else for (const t of tix.values()) if (t >= 0) for (const ord of chunksOf(p, t)) cands.add(ord);
  const out: Array<{ id: number; score: number }> = [];
  for (const ord of cands) {
    const lk = lookupAt(ord);
    if (tsMatch(lk, q)) out.push({ id: p.chunkIds[ord]!, score: tsRankCd(lk, q) });
  }
  return out.sort((a, b) => b.score - a.score || a.id - b.id);
}

/** The ReadSource of one tool call on the sealed route (one per call: its index lease ends with the proof). */
export function sealedReadSource(db: Db, route: SealedRoute): ReadSource {
  const { proof, cache } = route;
  let index: Promise<{ packed: Packed }> | null = null;
  let recs: { all: IndexRecords; notes: Map<number, NoteEntry>; facts: Map<number, FactEntry>; decisions: Map<number, DecisionEntry> } | null = null;

  /** Steps 2-3: the coverage check and the cached (or loaded) index of this request's key_version. */
  const ensure = () => {
    index ??= (async () => {
      const kv = proof.keyVersion;
      const { coverage, otherKeyVersion } = await dbCoverage(db, kv);
      if (otherKeyVersion > 0) throw new ReadRouteRefused('changing');
      const generation = await manifestGeneration(db, kv);
      const packed = await cache.use(proof, { generation, coverage }, (key) => loadPacked(db, key, coverage)).catch(classify);
      return { packed };
    })();
    return index;
  };
  const records = async () => {
    if (!recs) {
      const all = recordsOf((await ensure()).packed);
      recs = {
        all, notes: new Map(all.notes.map((n) => [n.id, n])), facts: new Map(all.facts.map((f) => [f.id, f])),
        decisions: new Map(all.decisions.map((d) => [d.id, d])),
      };
    }
    return recs;
  };
  const need = <T>(v: T | undefined): T => {
    if (v === undefined) throw new Error('the workspace index does not cover a visible row');
    return v;
  };

  /**
   * KTD11, one rule for both row shapes: the ACTIVE note whose source_uri equals the uri without its #fragment
   * and whose vault_path is that uri or the uri minus its 6-character scheme (sourceNoteJoin), highest id.
   * The database is asked for note ids only.
   */
  const notesForUris = async (uris: readonly string[]): Promise<Map<string, { note: NoteEntry; sourceTs: string } | null>> => {
    const r = await records();
    const out = new Map<string, { note: NoteEntry; sourceTs: string } | null>();
    const want = new Map<string, NoteEntry[]>();
    for (const u of uris) {
      const base = uriBase(u);
      if (want.has(base)) continue;
      want.set(base, r.all.notes.filter((n) => n.sourceUri === base && (n.vaultPath === base || n.vaultPath === substr7(base))));
    }
    const ids = [...new Set([...want.values()].flat().map((n) => n.id))];
    const active = new Map<number, unknown>();
    if (ids.length > 0) {
      for (const row of (await db.query<{ id: number; source_ts: unknown }>(
        `SELECT n.id::int AS id, n.source_ts FROM zeusi.notes n WHERE n.status = 'active' AND n.id = ANY($1::bigint[])`, [ids])).rows) active.set(Number(row.id), row.source_ts);
    }
    for (const [base, cands] of want) {
      const best = cands.filter((n) => active.has(n.id)).sort((a, b) => b.id - a.id)[0];
      out.set(base, best ? { note: best, sourceTs: iso(active.get(best.id))! } : null);
    }
    return out;
  };

  /** LINK_COLS of one decision (linked_repo from the index, linked_pr plain, the source note). */
  const linkCols = (d: DecisionEntry, linkedPr: unknown, sn: { note: NoteEntry; sourceTs: string } | null | undefined): Row => ({
    linked_repo: d.linkedRepo, linked_pr: linkedPr ?? null,
    ...(sn ? { sn_uri: sn.note.sourceUri, sn_title: sn.note.title, sn_ts: sn.sourceTs } : { sn_uri: null, sn_title: null, sn_ts: null }),
  });

  const decisionLinks = async (ids: readonly number[]): Promise<Map<number, DecisionLinkItem[]>> => {
    const out = new Map<number, DecisionLinkItem[]>();
    if (ids.length === 0 || !(await hasDecisionLinks(db))) return out;
    const r = await records();
    const want = new Set(ids.map(Number));
    const per = new Map<number, LinkEntry[]>();
    for (const l of r.all.links) if (want.has(l.decisionId)) per.set(l.decisionId, [...(per.get(l.decisionId) ?? []), l]);
    const chosen = [...per.entries()].sort(([a], [b]) => a - b).flatMap(([, ls]) => ls.sort((a, b) => a.id - b.id).slice(0, MAX_LINKS));
    const notes = await notesForUris(chosen.filter((l) => l.targetKind === 'note').map((l) => l.targetUri));
    for (const l of chosen) {
      const sn = l.targetKind === 'note' ? notes.get(uriBase(l.targetUri)) : null;
      const item: DecisionLinkItem = sn
        ? { target_kind: l.targetKind as LinkTargetKind, target_uri: l.targetUri, resolved: true, title: sn.note.title }
        : { target_kind: l.targetKind as LinkTargetKind, target_uri: l.targetUri, resolved: false };
      out.set(l.decisionId, [...(out.get(l.decisionId) ?? []), item]);
    }
    return out;
  };

  /** The current decisions (metadata from decisions_current, content from the index), optionally of one scope. */
  const currentDecisions = async (scope: string | null, extra = '', params: unknown[] = []) => {
    const r = await records();
    const rows = (await db.query<Row>(
      `SELECT d.id::int AS id, d.kind::text AS kind, p.handle AS who, d.said_at, d.exact_words_verbatim, d.expires_at, d.scope::text AS scope,
              d.source_ts, d.linked_pr
       FROM zeusi.decisions_current d LEFT JOIN zeusi.people p ON p.id = d.who_id
       WHERE ($1::text IS NULL OR d.scope::text = $1::text)${extra}`, [scope, ...params])).rows;
    return rows.map((m) => ({ m, d: need(r.decisions.get(Number(m['id']))) }));
  };

  const lockLifecycle = async (now: Date) => {
    const r = await records();
    const cands = r.all.notes.filter((n) => n.fm !== null && LIFECYCLE_KEYS.some((k) => Object.prototype.hasOwnProperty.call(n.fm, k)));
    const rows = cands.length === 0 ? [] : (await db.query<{ id: number; scope: string; source_ts: unknown }>(
      `SELECT n.id::int AS id, n.scope::text AS scope, n.source_ts FROM zeusi.notes n
       WHERE n.status = 'active' AND n.id = ANY($1::bigint[]) ORDER BY n.source_ts DESC, n.id DESC LIMIT $2`,
      [cands.map((n) => n.id), LOCK_NOTES_CAP + 1])).rows;
    const capped = rows.length > LOCK_NOTES_CAP;
    const notes: LockNoteInput[] = rows.slice(0, LOCK_NOTES_CAP).map((x) => {
      const n = need(r.notes.get(Number(x.id)));
      const fm = n.fm ?? {};
      return {
        noteId: n.id, vaultPath: n.vaultPath, title: n.title, scope: String(x.scope), sourceUri: n.sourceUri, sourceTs: iso(x.source_ts)!,
        locks: fm['locks'] ?? null, supersedes: fm['supersedes'] ?? null, lockUntil: fm['lock_until'] ?? null, until: fm['until'] ?? null,
        standingLocks: fm['standing_locks'] ?? null,
      };
    });
    return { ...resolveLockLifecycle(notes, now), capped };
  };

  const factRows = async (kind: string, cap: number, withId: boolean) => {
    const r = await records();
    const rows = (await db.query<Row>(
      `SELECT f.id::bigint::text AS id, f.scope::text AS scope, f.source_ts FROM zeusi.facts_current f
       WHERE f.kind = $1 ORDER BY f.source_ts DESC, f.id DESC LIMIT $2`, [kind, cap])).rows;
    return rows.map((m) => {
      const f = need(r.facts.get(Number(m['id'])));
      return { ...(withId ? { id: m['id'] } : {}), subject: f.subject, text: f.text, scope: m['scope'], source_uri: f.sourceUri, source_ts: m['source_ts'] };
    });
  };

  const decisionMatch = (query: string) => {
    const phrase = [...query.trim()].length >= PHRASE_MIN_CHARS ? phraseText(query) : null;
    const q = websearchToTsquery(query);
    return (d: DecisionEntry) => {
      const v = lookupOf(toTsvector(`${d.exactWords} ${d.appliesTo.join(' ')}`));
      const ph = phrase !== null && (phraseHay(d.exactWords).includes(phrase) || d.appliesTo.some((a) => phraseHay(a).includes(phrase)));
      return { phrase: ph, fmatch: tsMatch(v, q), fts: tsRankCd(v, q) };
    };
  };

  const source: ReadSource = {
    begin: () => db.exec('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'),
    end: async () => {
      await db.exec('ROLLBACK').catch(() => {});
    },
    factRules: (cap) => factRows('rule', cap, true),
    facts: (kind, cap) => factRows(kind, cap, false),
    lockLifecycle,
    recentDecisions: async (days, cap) => {
      const rows = (await currentDecisions(null, ` AND d.said_at >= now() - make_interval(days => $2::int)`, [days]))
        .sort((a, b) => ms(b.m['said_at']) - ms(a.m['said_at']) || Number(b.m['id']) - Number(a.m['id'])).slice(0, cap);
      const sn = await notesForUris(rows.map((x) => x.d.sourceUri));
      return rows.map(({ m, d }) => ({
        ...m, exact_words: d.exactWords, applies_to: d.appliesTo, source_uri: d.sourceUri, ...linkCols(d, m['linked_pr'], sn.get(uriBase(d.sourceUri))),
      }));
    },
    decisionLinks,
    emptiness: (scope) => emptinessCounts(db, scope),
    knowsPerson: async () => (await db.query<{ n: number }>(WORKSPACE_PERSON_HANDLE_SQL.sql, [...WORKSPACE_PERSON_HANDLE_SQL.params])).rows[0]?.n === 1,

    search: async (o): Promise<SearchResult> => {
      const { query, limit, scope } = searchArgs(o);
      await assertReadOnlySession(db);
      await db.exec('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      try {
        const { packed } = await ensure();
        const key = proof.key;
        const ranked = rankChunks(packed, websearchToTsquery(query));
        const hits: SearchHit[] = [];
        const batch = Math.max(limit, 50);
        for (let i = 0; i < ranked.length && hits.length < limit; i += batch) {
          const slice = ranked.slice(i, i + batch);
          const rows = new Map((await db.query<Row>(
            `SELECT c.id::bigint AS id, c.scope::text AS scope, c.source_ts, c.key_version, c.heading_path, c.text, c.source_uri,
                    c.heading_path_ct, c.text_ct, c.source_uri_ct
             FROM zeusi.chunks c WHERE c.id = ANY($1::bigint[]) AND ($2::text IS NULL OR c.scope::text = $2::text)`,
            [slice.map((h) => h.id), scope])).rows.map((r) => [Number(r['id']), r]));
          for (const h of slice) {
            const r = rows.get(h.id);
            if (!r) continue; // another scope (or gone under this snapshot)
            let v: Row;
            try {
              v = openedRow(key, 'chunks', r, ['heading_path', 'text', 'source_uri']);
            } catch (e) {
              classify(e);
            }
            hits.push({
              chunkId: h.id, sourceUri: String(v['source_uri']), sourceTs: iso(r['source_ts'])!, scope: String(r['scope']),
              headingPath: (v['heading_path'] as string | null) ?? null, text: String(v['text']), score: h.score, ranks: { lexical: hits.length + 1 },
            });
            if (hits.length >= limit) break;
          }
        }
        const match = decisionMatch(query);
        const scored = (await currentDecisions(scope)).map((x) => ({ ...x, ...match(x.d) })).filter((x) => x.phrase || x.fmatch)
          .map((x) => ({ ...x, s: x.fts + (x.phrase ? 1 : 0) }))
          .sort((a, b) => b.s - a.s || ms(b.m['said_at']) - ms(a.m['said_at']) || Number(b.m['id']) - Number(a.m['id'])).slice(0, limit);
        const links = await decisionLinks(scored.map((x) => Number(x.m['id'])));
        const sn = await notesForUris(scored.map((x) => x.d.sourceUri));
        const decisions: DecisionHit[] = scored.map(({ m, d, s, phrase }) => ({
          type: 'decision', decisionId: Number(m['id']), kind: String(m['kind']), who: (m['who'] as string | null) ?? null, saidAt: iso(m['said_at'])!,
          exactWords: d.exactWords, exactWordsVerbatim: Boolean(m['exact_words_verbatim']), appliesTo: d.appliesTo, scope: String(m['scope']),
          sourceUri: d.sourceUri, sourceTs: iso(m['source_ts'])!, score: s, match: phrase ? 'phrase' : 'fulltext',
          links: linksOf(linkCols(d, m['linked_pr'], sn.get(uriBase(d.sourceUri))), links.get(Number(m['id']))),
        }));
        // Personal workspaces are lexical only (no embeddings client is ever called on this route).
        return { mode: 'lexical', hits, decisions, notice: LEXICAL_ONLY_NOTICE };
      } finally {
        await db.exec('ROLLBACK').catch(() => {});
      }
    },

    about: async (query, limit, sections) => sealedAbout(query, limit, sections),

    taskCandidates: async (terms, task, scope): Promise<CandidateRow[]> => {
      if (terms.length === 0) return [];
      const normTask = tokens(task).join(' ');
      const pad = ` ${normTask} `;
      const rows = (await currentDecisions(scope)).map((x) => {
        const toks = new Set(alnumSplit(`${x.d.exactWords} ${x.d.appliesTo.join(' ')}`));
        const nTerms = new Set(terms.filter((t) => toks.has(t))).size;
        const aHit = x.d.appliesTo.some((a) => {
          const na = alnumNorm(a);
          return [...na].length >= TERM_MIN && pad.includes(` ${na} `);
        });
        return { ...x, nTerms, aHit };
      }).filter((x) => x.nTerms > 0 || x.aHit)
        .sort((a, b) => b.nTerms - a.nTerms || ms(b.m['said_at']) - ms(a.m['said_at']) || Number(b.m['id']) - Number(a.m['id'])).slice(0, MAX_CANDIDATES);
      const links = await decisionLinks(rows.map((x) => Number(x.m['id'])));
      const sn = await notesForUris(rows.map((x) => x.d.sourceUri));
      return rows.map(({ m, d }) => ({
        id: Number(m['id']), kind: String(m['kind']), who: (m['who'] as string | null) ?? null, saidAt: iso(m['said_at'])!,
        exactWords: d.exactWords, exactWordsVerbatim: Boolean(m['exact_words_verbatim']), appliesTo: d.appliesTo, expiresAt: iso(m['expires_at']),
        scope: String(m['scope']), sourceUri: d.sourceUri, sourceTs: iso(m['source_ts'])!,
        links: linksOf(linkCols(d, m['linked_pr'], sn.get(uriBase(d.sourceUri))), links.get(Number(m['id']))),
      }));
    },

    onboarding: (scope, now) => onboardingCounts(db, scope, undefined, now, {
      lockLifecycle,
      noteLockItems: async (sc, cap) => {
        const r = await records();
        const cands = r.all.notes.filter((n) => n.fm !== null && Object.prototype.hasOwnProperty.call(n.fm, 'locks'));
        const active = cands.length === 0 ? [] : (await db.query<{ id: number }>(
          `SELECT n.id::int AS id FROM zeusi.notes n WHERE n.status = 'active' AND n.id = ANY($1::bigint[]) AND ($2::text IS NULL OR n.scope::text = $2::text)`,
          [cands.map((n) => n.id), sc])).rows;
        const total = active.reduce((a, x) => a + noteLockItemCount(need(r.notes.get(Number(x.id))).fm?.['locks']), 0);
        const n = Math.min(total, cap + 1);
        return { n: Math.min(n, cap), capped: n > cap };
      },
    }),
  };
  // Every entry point maps a key_version change to the served refusal (CHANGING); anything else fails closed.
  const guarded = {} as ReadSource;
  for (const [k, fn] of Object.entries(source) as Array<[keyof ReadSource, (...a: unknown[]) => Promise<unknown>]>) {
    (guarded as unknown as Record<string, unknown>)[k] = (...a: unknown[]) => fn(...a).catch(classify);
  }
  return guarded;
}

/**
 * zeusi_search `about` on the sealed route: src/about.ts searchAbout's rule in memory (the query never reaches
 * Postgres): to_tsvector(heading \n body) @@ websearch_to_tsquery, or the whitespace-normalised lower-case
 * substring (>= 3 characters); ordered by (phrase ? 1 : 0) + ts_rank_cd, then section order.
 */
export function sealedAbout(query: string, limit: number, sections: readonly AboutSection[]): AboutHit[] {
  const q = query.trim();
  if (q === '') return [];
  const phrase = [...q].length >= 3 ? q.toLowerCase().replace(/\s+/g, ' ') : null;
  const tq = websearchToTsquery(q);
  const out: Array<{ i: number; s: number }> = [];
  sections.forEach((sec, i) => {
    const doc = `${sec.heading}\n${sec.body}`;
    const v = lookupOf(toTsvector(doc));
    const like = phrase !== null && phraseHay(doc).includes(phrase);
    if (tsMatch(v, tq) || like) out.push({ i, s: (like ? 1 : 0) + tsRankCd(v, tq) });
  });
  return out.sort((a, b) => b.s - a.s || a.i - b.i).slice(0, limit).map((x) => aboutHit(sections[x.i]!));
}
