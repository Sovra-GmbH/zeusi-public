// Sourced decision writes into the EXISTING zeusi.decisions table (0001; no migration).
// Used by the MCP tool zeusi_log_decision as zeusi_box_decision (group zeusi_decision_write,
// migrations/0012, not applied yet: INSERT on decisions + ingest_runs only, the ingest-run close
// columns, SELECT on people through zeusi_read, supersede_decision, quarantine_record), or as the
// transitional zeusi_box_rw (group zeusi_agent_write) until 0012 is applied. Needs only the
// grants 0012 gives: openRun / closeRun (ingest_runs INSERT + UPDATE (finished_at, status, counts)),
// the people lookup (SELECT), the decisions INSERT and quarantine_record.
// Modelled on insertFact (src/facts.ts): one ingest run per write, source_kind agent_write,
// the wall trigger zeusi_90_wall as the backstop (a ZW001 rejection is recorded by uri and
// hashes only, never the text). invent=NO: who, when, the words and the source are required.

import { createHash } from 'node:crypto';
import { asPgError, type Db } from './db.ts';
import { closeRun, defaultHost, openRun, parseWallError, ValidationError } from './facts.ts';
import { insertDecisionLinks, type LinkWriteCounts } from './decision-links.ts';
import { recordQuarantine } from './wall.ts';

/** zeusi.people handle pattern: the decision tool's `who` and `zeusi people add --handle`. */
export const WHO_HANDLE_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;

export const DECISION_KINDS = ['go', 'lock', 'ruling', 'stop', 'park'] as const;
/** Writable scopes (personal is reserved; RLS write_not_personal refuses it too). */
export const DECISION_SCOPES = ['work', 'product', 'client'] as const;

export interface DecisionInput {
  kind: (typeof DECISION_KINDS)[number];
  /** zeusi.people handle (must exist). */
  who: string;
  saidAt: string;
  saidAtPrecision: 'minute' | 'day';
  exactWords: string;
  exactWordsVerbatim: boolean;
  appliesTo: string[];
  scope: (typeof DECISION_SCOPES)[number];
  sourceUri: string;
  sourceTs: string;
  expiresAt?: string | undefined;
  linkedRepo?: string | undefined;
  linkedPr?: number | undefined;
  /**
   * 0013 decision_links targets (validated with linkTargetKind, <= MAX_LINKS). Inserted in the SAME
   * transaction as the decision, under the same run; the caller must have checked canInsertLinks.
   * Not part of decisionSha256 (each link has its own sha).
   */
  links?: readonly string[] | undefined;
}

export type InsertDecisionResult =
  | { status: 'inserted'; id: number; runId: number; links?: LinkWriteCounts }
  | { status: 'quarantined'; runId: number; ruleId: number | null };

/** sha256 of the canonical decision content (the "source item" an agent write records). */
export function decisionSha256(d: DecisionInput): string {
  const canonical = JSON.stringify([d.kind, d.who, d.saidAt, d.saidAtPrecision, d.exactWords, d.exactWordsVerbatim,
    [...d.appliesTo], d.scope, d.sourceUri, d.sourceTs, d.expiresAt ?? null, d.linkedRepo ?? null, d.linkedPr ?? null]);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export async function insertDecision(db: Db, d: DecisionInput): Promise<InsertDecisionResult> {
  const who = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.people WHERE handle = $1`, [d.who])).rows[0];
  if (!who) throw new ValidationError('unknown person handle (zeusi.people); nothing written (invent=NO)');
  const sha = decisionSha256(d);
  const runId = await openRun(db, { importer: 'mcp', host: defaultHost(), mode: 'agent' });
  const links = d.links ?? [];
  const tx = links.length > 0;
  try {
    if (tx) await db.exec('BEGIN');
    const r = await db.query<{ id: number }>(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to,
                                    expires_at, linked_repo, linked_pr, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1::zeusi.decision_kind, $2, $3::timestamptz, $4, $5, $6, $7::text[], $8::timestamptz, $9, $10, $11::zeusi.scope,
               'agent_write', $12, $13::timestamptz, decode($14, 'hex'), $15)
       RETURNING id::int AS id`,
      [d.kind, who.id, d.saidAt, d.saidAtPrecision, d.exactWords, d.exactWordsVerbatim, d.appliesTo, d.expiresAt ?? null,
        d.linkedRepo ?? null, d.linkedPr ?? null, d.scope, d.sourceUri, d.sourceTs, sha, runId],
    );
    const id = Number(r.rows[0]!.id);
    let lc: LinkWriteCounts | undefined;
    if (tx) {
      // A walled link is quarantined and counted inside insertDecisionLinks (SAVEPOINT); any other
      // error rolls the decision back too (all or nothing).
      lc = await insertDecisionLinks(db, {
        decisionId: id, scope: d.scope, sourceKind: 'agent_write', sourceUri: d.sourceUri, sourceTs: d.sourceTs, runId,
        targets: links, inTransaction: true,
      });
      await db.exec('COMMIT');
    }
    await closeRun(db, runId, 'ok', lc
      ? { inserted: 1, links_inserted: lc.inserted, links_deduped: lc.deduped, links_quarantined: lc.quarantined, links_invalid: lc.invalid }
      : { inserted: 1 });
    return lc ? { status: 'inserted', id, runId, links: lc } : { status: 'inserted', id, runId };
  } catch (e) {
    if (tx) await db.exec('ROLLBACK').catch(() => {});
    const wall = parseWallError(e);
    if (!wall) {
      await closeRun(db, runId, 'failed', { error_code: asPgError(e).code ?? 'unknown' }).catch(() => {});
      throw e;
    }
    await recordQuarantine(db, {
      sourceKind: 'agent_write', sourceUri: d.sourceUri, sourceSha256: sha, ruleId: wall.ruleId, ingestRunId: runId, table: 'decisions', contentSha256: wall.contentSha256,
    });
    await closeRun(db, runId, 'ok', { quarantined: 1 });
    return { status: 'quarantined', runId, ruleId: wall.ruleId };
  }
}
