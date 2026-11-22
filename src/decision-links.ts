// Decision links on the read paths (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md, Fix PR A,
// A3). No migration: the columns already exist (migrations/0001_core.sql decisions.linked_repo,
// linked_pr), they were just never returned. Every reader (searchDecisions, zeusi_startup,
// zeusi_context_for_task) adds the same four fields:
//
//   linked_repo    the stored text, or null
//   linked_pr      the stored PR number, or null
//   linked_pr_uri  `gh:<linked_repo>#<linked_pr>` when both are stored; built from the stored
//                  values only (no org or repo is added or guessed); else null. PR state is not
//                  resolved here (no github importer fills zeusi.prs yet).
//   source_note    { source_uri, title, source_ts } of the ACTIVE note whose source_uri equals the
//                  decision's source_uri without its #fragment, else null. Read in the caller's
//                  read-only transaction as the caller's role, so RLS decides visibility. Never the
//                  body. The whole item (these fields included) still passes the output wall.
//
// Migration 0013 (zeusi.decision_links, DESIGN, not applied on Neon) adds a fifth field:
//
//   links          [{ target_kind, target_uri, resolved, title? }] (<= MAX_LINKS per decision, in
//                  insert order). A `note` link is resolved to the title of the ACTIVE note with that
//                  source_uri (fragment dropped) that the caller can see under RLS; never the body.
//                  PRs, repos, jobs and lanes are returned as stored with resolved: false. Without
//                  0013 (to_regclass is NULL) it is [] and nothing errors.
//
// Each link passes the serve guard on its own (serveWithLinks): a walled or secret-bearing link
// is dropped and counted in the response's `withheld`; the decision itself is then guarded whole.
// Writers: insertDecisionLinks (zeusi_log_decision, structured imports / hq-sync).

import { createHash } from 'node:crypto';
import { asPgError, type Db } from './db.ts';
import { parseWallError } from './facts.ts';
import { wallFilter, type ServeCheck } from './mcp-wall.ts';
import { recordQuarantine, type Wall } from './wall.ts';
import { PLAIN_ROUTE, type WriteRoute } from './write-route.ts';
import { nextId, sealedInsertSql, sealRow } from './workspace-seal.ts';

/** Columns to add to a decision SELECT whose decisions alias is `d` and that joins SOURCE_NOTE_JOIN('d'). */
export const LINK_COLS = 'd.linked_repo, d.linked_pr, sn.source_uri AS sn_uri, sn.title AS sn_title, sn.source_ts AS sn_ts';

/**
 * LEFT JOIN LATERAL to the decision's own source note (alias `sn`). The vault_path IN (...) term
 * lets the planner use the UNIQUE vault_path index (vault notes store `<rel>` with uri `vault:<rel>`;
 * hq notes store `hq:<rel>` with the same uri); the source_uri equality is the real condition.
 */
export function sourceNoteJoin(alias: string): string {
  const base = `split_part(${alias}.source_uri, '#', 1)`;
  return `LEFT JOIN LATERAL (
       SELECT n.source_uri, n.title, n.source_ts FROM zeusi.notes n
       WHERE n.status = 'active' AND n.vault_path IN (${base}, substr(${base}, 7)) AND n.source_uri = ${base}
       ORDER BY n.id DESC LIMIT 1) sn ON true`;
}

export interface SourceNote {
  source_uri: string;
  title: string;
  source_ts: string;
}

export interface DecisionLinks {
  linked_repo: string | null;
  linked_pr: number | null;
  linked_pr_uri: string | null;
  source_note: SourceNote | null;
  /** zeusi.decision_links rows (0013), [] without the table. */
  links: DecisionLinkItem[];
}

/** The fields of a decision row with no link (and for injected rows that carry none). */
export const NO_LINKS: DecisionLinks = Object.freeze({ linked_repo: null, linked_pr: null, linked_pr_uri: null, source_note: null, links: [] as DecisionLinkItem[] });

const isoOf = (v: unknown): string => new Date(v as string).toISOString();

/** The link fields from a row selected with LINK_COLS (plus its decision_links items, if fetched). */
export function linksOf(r: Record<string, unknown>, items: DecisionLinkItem[] = []): DecisionLinks {
  const repo = typeof r['linked_repo'] === 'string' && r['linked_repo'] !== '' ? r['linked_repo'] : null;
  const pr = r['linked_pr'] === null || r['linked_pr'] === undefined ? null : Number(r['linked_pr']);
  const uri = r['sn_uri'];
  return {
    linked_repo: repo,
    linked_pr: pr,
    linked_pr_uri: repo !== null && pr !== null ? `gh:${repo}#${pr}` : null,
    source_note: typeof uri === 'string' ? { source_uri: uri, title: String(r['sn_title']), source_ts: isoOf(r['sn_ts']) } : null,
    links: items,
  };
}

// ---------------------------------------------------------------------------
// 0013 decision_links

export const LINK_TARGET_KINDS = ['pr', 'note', 'repo', 'job', 'uri'] as const;
export type LinkTargetKind = (typeof LINK_TARGET_KINDS)[number];
/** Links per decision: accepted on write (zeusi_log_decision, a Links: header) and returned on read. */
export const MAX_LINKS = 20;
export const MIN_LINK_URI = 5;
export const MAX_LINK_URI = 500;

/** Mirrors the CHECK decision_links_target_uri_shape of migrations/0013_decision_links.sql (per kind). */
export const LINK_TARGET_RES: Readonly<Record<LinkTargetKind, RegExp>> = Object.freeze({
  pr: /^gh:[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}#[1-9][0-9]{0,8}$/u,
  repo: /^gh:[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/u,
  note: /^(vault|hq|import):[^#/ ][^#]*[^# ](#[^#]*[^# ])?$/u,
  job: /^job:[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$/u,
  uri: /^lane:[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/u,
});
/** Human-readable allowlist (tool descriptions and refusals; never echoes a value). */
export const LINK_TARGET_SHAPES = 'gh:<owner>/<repo>#<n>, gh:<owner>/<repo>, vault:<path>, hq:<path>, import:<path>, job:<name>, lane:<name>';
/** No whitespace but a plain space, no control or format characters (stricter than the SQL CHECK). */
const BAD_CHARS_RE = /[^\S ]|[\p{Cc}\p{Cf}]/u;
/** A `.` or `..` path segment. */
const DOT_SEGMENT_RE = /(^[a-z]+:|\/)\.\.?(\/|#|$)/;

/**
 * The app-side form of the CHECK decision_links_target_uri_shape (0013): length 5..500 in code points,
 * the whitespace / control rule (stricter: no format characters either), the `.` / `..` segment rule
 * and the per-kind regex; null when the uri is not on the allowlist. Lengths are counted in code
 * points and the regexes run with the `u` flag, as Postgres counts characters (security review M1: an
 * astral character is one character on both sides).
 *
 * C6 R3-4 (docs/plans/2026-11-19-c6-write-path.md KTD13): on a sealed workspace target_uri is NULL, so
 * the SQL CHECK passes every row; this function is then the only shape gate, run before sealing.
 */
export function linkShape(uri: string): { kind: LinkTargetKind } | null {
  if (typeof uri !== 'string') return null;
  const n = [...uri].length;
  if (n < MIN_LINK_URI || n > MAX_LINK_URI) return null;
  if (BAD_CHARS_RE.test(uri) || DOT_SEGMENT_RE.test(uri)) return null;
  for (const k of LINK_TARGET_KINDS) if (LINK_TARGET_RES[k].test(uri)) return { kind: k };
  return null;
}

/** The kind of an allowed link target uri, or null (one rule: linkShape). */
export function linkTargetKind(uri: string): LinkTargetKind | null {
  return linkShape(uri)?.kind ?? null;
}

export interface DecisionLinkItem {
  target_kind: LinkTargetKind;
  target_uri: string;
  /** true only for a note link whose active note the caller can see. */
  resolved: boolean;
  /** The resolved note's title (never its body). */
  title?: string;
}

/**
 * Is migration 0013 applied, and does this session hold `privilege` on zeusi.decision_links? Never
 * errors for a missing table (the oid form of has_table_privilege after to_regclass).
 */
export async function hasDecisionLinks(db: Db, privilege: 'SELECT' | 'INSERT' = 'SELECT'): Promise<boolean> {
  const r = await db.query<{ ok: boolean }>(
    `SELECT CASE WHEN to_regclass('zeusi.decision_links') IS NULL THEN false
                 ELSE has_table_privilege(to_regclass('zeusi.decision_links')::oid, $1) END AS ok`, [privilege]);
  return r.rows[0]?.ok === true;
}

/**
 * The links of these decisions, as the caller's role (RLS on decision_links and notes), at most
 * MAX_LINKS per decision in insert order. Run inside the caller's read-only transaction. Empty when
 * 0013 is not applied or this role has no SELECT on the table (links: [], nothing errors).
 */
export async function fetchDecisionLinks(db: Db, ids: readonly number[]): Promise<Map<number, DecisionLinkItem[]>> {
  const out = new Map<number, DecisionLinkItem[]>();
  if (ids.length === 0 || !(await hasDecisionLinks(db))) return out;
  const rows = (await db.query<{ decision_id: number; target_kind: LinkTargetKind; target_uri: string; title: string | null }>(
    `SELECT l.decision_id::int AS decision_id, l.target_kind::text AS target_kind, l.target_uri, n.title
     FROM (SELECT x.id, x.decision_id, x.target_kind, x.target_uri,
                  row_number() OVER (PARTITION BY x.decision_id ORDER BY x.id) AS rn
           FROM zeusi.decision_links x WHERE x.decision_id = ANY($1::bigint[])) l
     LEFT JOIN LATERAL (
       SELECT n.title FROM zeusi.notes n
       WHERE l.target_kind = 'note' AND n.status = 'active'
         AND n.vault_path IN (split_part(l.target_uri, '#', 1), substr(split_part(l.target_uri, '#', 1), 7))
         AND n.source_uri = split_part(l.target_uri, '#', 1)
       ORDER BY n.id DESC LIMIT 1) n ON true
     WHERE l.rn <= $2
     ORDER BY l.decision_id, l.id`,
    [ids.map(Number), MAX_LINKS],
  )).rows;
  for (const r of rows) {
    const item: DecisionLinkItem = typeof r.title === 'string'
      ? { target_kind: r.target_kind, target_uri: r.target_uri, resolved: true, title: r.title }
      : { target_kind: r.target_kind, target_uri: r.target_uri, resolved: false };
    const id = Number(r.decision_id);
    out.set(id, [...(out.get(id) ?? []), item]);
  }
  return out;
}

/**
 * The serve guard for items that may carry `links` (decisions): each link is guarded on its own
 * (a walled / secret-bearing link is dropped and counted), then the item is guarded whole with the
 * links that remain. Items without a links array go through wallFilter unchanged. Same result
 * shape as wallFilter; a link dropped from an item that is then withheld whole is not counted twice.
 */
export function serveWithLinks<T>(items: readonly T[], check?: ServeCheck): { kept: T[]; withheld: number; secretWithheld: number } {
  const kept: T[] = [];
  let withheld = 0;
  let secretWithheld = 0;
  for (const it of items) {
    const links = (it as { links?: unknown }).links;
    let candidate = it;
    let lw = 0;
    let ls = 0;
    if (Array.isArray(links)) {
      const L = wallFilter(links, check);
      candidate = { ...it, links: L.kept };
      lw = L.withheld;
      ls = L.secretWithheld;
    }
    const V = wallFilter([candidate], check);
    if (V.kept.length === 1) {
      kept.push(V.kept[0]!);
      withheld += lw;
      secretWithheld += ls;
    } else {
      withheld += V.withheld;
      secretWithheld += V.secretWithheld;
    }
  }
  return { kept, withheld, secretWithheld };
}

/** sha256 (hex) of one link statement: the decision's source and the target. */
export function linkSha256(sourceUri: string, targetUri: string): string {
  return createHash('sha256').update(`${sourceUri}\n${targetUri}`, 'utf8').digest('hex');
}

/**
 * The decision-shaped wall probes of a link, exactly as zeusi.decision_link_wall_check() (0013)
 * builds them: the target in the uri and words slots, then under the link's own source_uri.
 */
export function linkWallProbes(sourceUri: string, targetUri: string): Array<Record<string, unknown>> {
  return [
    { source_uri: targetUri, exact_words: targetUri },
    { source_uri: sourceUri, exact_words: targetUri },
  ];
}

/** The TypeScript pre-check of one link (same verdict as the trigger, src/wall.ts parity). */
export function linkWallVerdict(wall: Wall, sourceUri: string, targetUri: string): { blocked: boolean; ruleId: number | null; contentSha256: string } {
  for (const p of linkWallProbes(sourceUri, targetUri)) {
    const v = wall.check('decisions', p);
    if (v.blocked) return { blocked: true, ruleId: v.ruleId, contentSha256: v.contentSha256 };
  }
  return { blocked: false, ruleId: null, contentSha256: '' };
}

export interface LinkWriteInput {
  decisionId: number;
  scope: string;
  sourceKind: string;
  /** Where the link was stated (the decision's own source_uri for log_decision and Links: headers). */
  sourceUri: string;
  sourceTs: string;
  runId: number;
  /** Validated target uris (linkTargetKind non-null); duplicates are ignored. */
  targets: readonly string[];
  /** Optional TypeScript pre-check (importers); the zeusi_90_wall trigger is always the backstop. */
  wall?: Wall | undefined;
  /**
   * The caller runs inside a transaction: each insert is wrapped in a SAVEPOINT so a wall
   * rejection does not abort the outer transaction.
   */
  inTransaction?: boolean;
  /**
   * C6 (KTD7, KTD13): default PLAIN_ROUTE (unchanged). Sealed: the caller's sealed transaction
   * (inTransaction required); a target linkShape refuses is counted invalid (no row, no quarantine);
   * pre-allocated id, sealed target_uri / source_uri, ON CONFLICT (decision_id, target_uri_hmac) DO
   * NOTHING (never rebinds an existing row's ciphertext), quarantine by HMAC.
   */
  route?: WriteRoute;
}

export interface LinkWriteCounts {
  inserted: number;
  /** Already stored for this decision (UNIQUE (decision_id, target_uri)). */
  deduped: number;
  /** Rejected by the wall (pre-check or trigger); recorded by uri and hash only. */
  quarantined: number;
  /**
   * Refused by a CHECK (23514: allowlist shape, or the decision's scope differs from the link's).
   * Counted, never thrown, so one bad header cannot fail every later run (security review M1 / L3).
   */
  invalid: number;
}

/**
 * Insert links for one decision (0013 must be applied: callers check hasDecisionLinks first).
 * Never UPDATE; ON CONFLICT DO NOTHING on (decision_id, target_uri). A wall rejection is recorded
 * in zeusi.quarantine (uri + hashes, target_table decision_links) and counted; any other error
 * is thrown.
 */
export async function insertDecisionLinks(db: Db, o: LinkWriteInput): Promise<LinkWriteCounts> {
  const c: LinkWriteCounts = { inserted: 0, deduped: 0, quarantined: 0, invalid: 0 };
  const route = o.route ?? PLAIN_ROUTE;
  const sealed = route.kind === 'sealed' ? route : null;
  if (sealed && !o.inTransaction) throw new Error('sealed decision links are written inside the record\'s sealed transaction');
  const seen = new Set<string>();
  for (const target of o.targets) {
    if (seen.has(target)) continue;
    seen.add(target);
    const shape = linkShape(target);
    if (shape === null) {
      // R3-4: the DB CHECK is blind on a sealed row (NULL target_uri); the app refuses the shape here.
      if (sealed) {
        c.invalid++;
        continue;
      }
      throw new Error('decision link target is not on the allowlist (validate before insert)');
    }
    const kind = shape.kind;
    const sha = linkSha256(o.sourceUri, target);
    const quarantine = (ruleId: number | null, contentSha: string | null) => recordQuarantine(db, {
      sourceKind: o.sourceKind, sourceUri: o.sourceUri, sourceSha256: sha, ruleId, ingestRunId: o.runId, table: 'decision_links', contentSha256: contentSha,
    }, route);
    if (o.wall) {
      const v = linkWallVerdict(o.wall, o.sourceUri, target);
      if (v.blocked) {
        await quarantine(v.ruleId, v.contentSha256);
        c.quarantined++;
        continue;
      }
    }
    if (o.inTransaction) await db.exec('SAVEPOINT zeusi_link');
    try {
      if (sealed) {
        const id = (await nextId(db, 'decision_links'))[0]!;
        const ins = sealedInsertSql('decision_links', [
          ['id', id, 'bigint'], ['decision_id', o.decisionId, 'bigint'], ['target_kind', kind, 'zeusi.link_target_kind'], ['scope', o.scope, 'zeusi.scope'],
          ['source_kind', o.sourceKind, 'zeusi.source_kind'], ['source_ts', o.sourceTs, 'timestamptz'],
          ['source_sha256', sealed.key.keyedSha('source_sha256', sha), 'bytea'], ['ingest_run_id', o.runId, 'bigint'],
        ], [...sealRow(sealed.key, 'decision_links', id, { target_uri: target, source_uri: o.sourceUri }), sealed.key.sealDigest('decision_links', id, sha)], // C8-0 KTD-A
        'ON CONFLICT (decision_id, target_uri_hmac) DO NOTHING RETURNING id::int AS id');
        const r = await db.query<{ id: number }>(ins.sql, ins.params);
        if (r.rows.length > 0) await sealed.index.onRecordWritten(db, { table: 'decision_links', id });
        await db.exec('RELEASE SAVEPOINT zeusi_link');
        if (r.rows.length > 0) c.inserted++;
        else c.deduped++;
        continue;
      }
      const r = await db.query<{ id: number }>(
        `INSERT INTO zeusi.decision_links (decision_id, target_kind, target_uri, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ($1, $2::zeusi.link_target_kind, $3, $4::zeusi.scope, $5::zeusi.source_kind, $6, $7::timestamptz, decode($8, 'hex'), $9)
         ON CONFLICT (decision_id, target_uri) DO NOTHING
         RETURNING id::int AS id`,
        [o.decisionId, kind, target, o.scope, o.sourceKind, o.sourceUri, o.sourceTs, sha, o.runId],
      );
      if (o.inTransaction) await db.exec('RELEASE SAVEPOINT zeusi_link');
      if (r.rows.length > 0) c.inserted++;
      else c.deduped++;
    } catch (e) {
      if (o.inTransaction) await db.exec('ROLLBACK TO SAVEPOINT zeusi_link').catch(() => {});
      if (asPgError(e).code === '23514') {
        c.invalid++;
        continue;
      }
      const w = parseWallError(e);
      if (!w) throw e;
      await quarantine(w.ruleId, w.contentSha256);
      c.quarantined++;
    }
  }
  return c;
}

/** Can this session insert links (0013 applied and INSERT granted)? Never throws for a missing table. */
export async function canInsertLinks(db: Db): Promise<boolean> {
  return hasDecisionLinks(db, 'INSERT');
}
