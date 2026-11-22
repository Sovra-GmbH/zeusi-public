// `zeusi wall report | allow | audit` (PLAN.md U4). Nothing here reads or prints content:
// quarantine holds uri + hashes only, and the audit returns row references and rule ids.

import type { Db } from './db.ts';
import { loadWall } from './wall.ts';

export class WallAdminError extends Error {
  override name = 'WallAdminError';
}

export interface ReportRow {
  id: number;
  detected_at: Date;
  source_kind: string;
  source_uri: string;
  target_table: string | null;
  rule_id: number | null;
  rule_kind: string | null;
  hard: boolean | null;
  content_sha256: string | null;
}

/** Quarantined items by uri and rule id (weekly digest for the operator). */
export async function wallReport(db: Db, opts: { sinceDays?: number } = {}): Promise<ReportRow[]> {
  const r = await db.query<ReportRow>(
    `SELECT q.id::int AS id, q.detected_at, q.source_kind::text AS source_kind, q.source_uri, q.target_table,
            q.rule_id, d.kind::text AS rule_kind, d.hard, encode(q.content_sha256, 'hex') AS content_sha256
     FROM zeusi.quarantine q LEFT JOIN zeusi.wall_denylist d ON d.id = q.rule_id
     WHERE $1::int IS NULL OR q.detected_at > now() - make_interval(days => $1::int)
     ORDER BY q.detected_at DESC, q.id DESC`,
    [opts.sinceDays ?? null],
  );
  return r.rows;
}

export function formatReport(rows: ReportRow[]): string {
  if (rows.length === 0) return 'quarantine: empty';
  const lines = [`quarantine: ${rows.length} item(s) (uri + hash only; no content is stored)`];
  for (const r of rows) {
    const rule = r.rule_id === null ? 'rule ?' : `rule ${r.rule_id} ${r.rule_kind}${r.hard ? ' HARD' : ''}`;
    const sha = r.content_sha256 ? ` content_sha256=${r.content_sha256}` : '';
    lines.push(`  #${r.id} ${new Date(r.detected_at).toISOString()} ${r.source_kind} ${r.source_uri} -> ${r.target_table ?? '?'} [${rule}]${sha}`);
  }
  return lines.join('\n');
}

export interface AllowResult {
  sourceUri: string;
  contentSha256: string;
  ruleId: number;
}

/**
 * Pin one exact content hash for one soft (content) rule. Owner only (the owner).
 * Refused for hard rules, for uris that hit a hard rule, and without a matching
 * quarantine row unless --rule is given. The DB guard (ZW002) is the backstop.
 */
export async function wallAllow(db: Db, sourceUri: string, contentSha256Hex: string, ruleId?: number): Promise<AllowResult> {
  const sha = contentSha256Hex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sha)) throw new WallAdminError('content sha256 must be 64 hex characters');
  if (!sourceUri.trim()) throw new WallAdminError('source uri is required');

  const wall = await loadWall(db);
  const uriHit = wall.checkUri(sourceUri);
  if (uriHit.blocked) {
    throw new WallAdminError(`refused: ${sourceUri} hits hard rule ${uriHit.ruleId} (${uriHit.kind}); hard rules cannot be allowed`);
  }

  let rid = ruleId;
  if (rid === undefined) {
    const q = await db.query<{ rule_id: number | null }>(
      `SELECT rule_id FROM zeusi.quarantine WHERE source_uri = $1 AND content_sha256 = decode($2, 'hex')
       ORDER BY detected_at DESC LIMIT 1`,
      [sourceUri, sha],
    );
    if (!q.rows[0]) throw new WallAdminError(`no quarantine row for ${sourceUri} at that content sha; pass --rule <id> to allow explicitly`);
    if (q.rows[0].rule_id === null) throw new WallAdminError('the quarantine row has no rule id; pass --rule <id>');
    rid = Number(q.rows[0].rule_id);
  }
  const rule = wall.rules.find((r) => r.id === rid);
  if (!rule) throw new WallAdminError(`wall rule ${rid} does not exist`);
  if (rule.hard) throw new WallAdminError(`refused: rule ${rid} (${rule.kind}) is hard and cannot be allowed`);

  const priv = await db.query<{ ok: boolean }>(`SELECT has_table_privilege('zeusi.wall_allow', 'INSERT') AS ok`);
  if (!priv.rows[0]?.ok) throw new WallAdminError('refused: wall allow is owner-only (connect with the owner URL; the operator runs this)');

  await db.query(
    `INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ($1, decode($2, 'hex'), $3)
     ON CONFLICT (source_uri, content_sha256, rule_id) DO NOTHING`,
    [sourceUri, sha, rid],
  );
  return { sourceUri, contentSha256: sha, ruleId: rid };
}

export interface AuditRow {
  table_name: string;
  row_ref: string;
  source_uri: string;
  problem: string;
}

/**
 * zeusi.wall_audit() plus, once 0013 is applied, zeusi.decision_links_wall_audit() (stored links
 * re-checked against today's rules; wall_audit() itself is unchanged). Must be empty.
 */
export async function wallAudit(db: Db): Promise<AuditRow[]> {
  const links = (await db.query<{ ok: boolean }>(
    `SELECT to_regprocedure('zeusi.decision_links_wall_audit()') IS NOT NULL AS ok`)).rows[0]?.ok === true;
  const r = await db.query<AuditRow>(links
    ? `SELECT table_name, row_ref, source_uri, problem FROM zeusi.wall_audit()
       UNION ALL SELECT table_name, row_ref, source_uri, problem FROM zeusi.decision_links_wall_audit() ORDER BY 1, 2`
    : `SELECT table_name, row_ref, source_uri, problem FROM zeusi.wall_audit() ORDER BY 1, 2`);
  return r.rows;
}

/**
 * Table, row id and problem only. The uri is not printed: a vault uri is a path, and a
 * row flagged by a rule added later may carry the walled word in its path (review r1).
 */
export function formatAudit(rows: AuditRow[]): string {
  if (rows.length === 0) return 'wall audit: 0 rows (clean)';
  return [`wall audit: ${rows.length} row(s) — WALL BREACH, pause ingest and tell the owner`, ...rows.map((r) => `  ${r.table_name} ${r.row_ref}: ${r.problem}`)].join('\n');
}

/** Loud one-liner for the end of an ingest run when the audit is not clean (counts by table, no uri, no text). */
/** Exit code of `ingest vault --real`: 1 unless the run finished ok AND the wall audit is empty. */
export function realIngestExitCode(status: string, audit: readonly AuditRow[]): 0 | 1 {
  return status === 'ok' && audit.length === 0 ? 0 : 1;
}

export function ownerActionLine(rows: AuditRow[]): string | null {
  if (rows.length === 0) return null;
  const by: Record<string, number> = {};
  for (const r of rows) by[r.table_name] = (by[r.table_name] ?? 0) + 1;
  const tables = Object.entries(by).sort().map(([t, n]) => `${t} ${n}`).join(', ');
  return `OWNER ACTION NEEDED: wall audit found ${rows.length} row(s) (${tables}) still readable after this run. ` +
    'Pause ingest; the owner reviews `zeusi wall audit` and deletes or re-pins the rows (no text is printed here).';
}
