// Sourced fact writes and reads, wall handling, and the dummy-vector probe.

import { redactSecrets, STORAGE_SKIP } from './secrets.ts';
import { hostname } from 'node:os';
import { asPgError, type Db } from './db.ts';
import { loadWall, recordQuarantine, seedWall, type Wall } from './wall.ts';
import { mentionsProtectedName } from './sources.ts';

/** 0010 adds clientco (owner rule). personal is reserved and never written in v1. */
export const SCOPES = ['work', 'product', 'client', 'personal'] as const;
export const SOURCE_KINDS = [
  'vault_note', 'lane_md', 'review_ledger', 'github_api', 'runner_log',
  'assistant_memory', 'zeus_memory', 'agent_write', 'manual',
] as const;
export const FACT_KINDS = ['rule', 'preference', 'state', 'config', 'identity', 'other'] as const;

export type Scope = (typeof SCOPES)[number];
export type SourceKind = (typeof SOURCE_KINDS)[number];
export type FactKind = (typeof FACT_KINDS)[number];

/** SQLSTATE raised by zeusi.wall_check() (row rejected) and the wall guards. */
export const WALL_REJECTED = 'ZW001';
export const WALL_GUARD = 'ZW002';

/** Embedding model label the HNSW partial index covers (0002_search.sql). */
export const INDEXED_EMBED_MODEL = 'openai/text-embedding-3-small@1536';
export const EMBED_DIMS = 1536;

export interface FactInput {
  kind: FactKind;
  subject?: string | undefined;
  text: string;
  scope: Scope;
  sourceKind: SourceKind;
  sourceUri: string;
  /** ISO timestamp: when the source said it. */
  sourceTs: string;
  /** Hex sha256 of the source item. */
  sourceSha256: string;
}

export interface RunInput {
  importer: string;
  host: string;
  mode: 'full' | 'incremental' | 'agent' | 'manual';
}

export type InsertFactResult =
  | { status: 'inserted'; id: number; runId: number }
  | { status: 'quarantined'; runId: number; ruleId: number | null; quarantineId: number; contentSha256: string | null };

export interface FactRow {
  id: number;
  kind: string;
  subject: string | null;
  text: string;
  scope: string;
  source_kind: string;
  source_uri: string;
  source_ts: Date;
  source_sha256_hex: string;
  ingest_run_id: number;
  ingested_at: Date;
  ingested_by: string;
  superseded_by: number | null;
}

export class ValidationError extends Error {
  override name = 'ValidationError';
}

/** invent=NO, client side. The database enforces the same rules. */
export function validateFact(f: Partial<FactInput>): FactInput {
  const missing: string[] = [];
  for (const k of ['kind', 'text', 'scope', 'sourceKind', 'sourceUri', 'sourceTs', 'sourceSha256'] as const) {
    const v = f[k];
    if (typeof v !== 'string' || v.trim() === '') missing.push(k);
  }
  if (missing.length) throw new ValidationError(`Missing required field(s): ${missing.join(', ')} (invent=NO).`);
  if (!FACT_KINDS.includes(f.kind as FactKind)) throw new ValidationError(`kind must be one of ${FACT_KINDS.join('|')}`);
  if (!SCOPES.includes(f.scope as Scope)) throw new ValidationError(`scope must be one of ${SCOPES.join('|')}`);
  if (f.scope === 'personal') throw new ValidationError('scope personal is reserved and not writable in v1');
  if (!SOURCE_KINDS.includes(f.sourceKind as SourceKind)) {
    throw new ValidationError(`source kind must be one of ${SOURCE_KINDS.join('|')}`);
  }
  if (!/^[0-9a-f]{64}$/i.test(f.sourceSha256!)) throw new ValidationError('source sha256 must be 64 hex characters');
  if (Number.isNaN(Date.parse(f.sourceTs!))) throw new ValidationError('source ts must be an ISO timestamp');
  return f as FactInput;
}

export function defaultHost(): string {
  return process.env['ZEUSI_HOST'] ?? (/mini/i.test(hostname()) ? 'mini' : hostname().split('.')[0] ?? 'unknown');
}

export async function openRun(db: Db, run: RunInput): Promise<number> {
  const r = await db.query<{ id: string }>(
    'INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ($1, $2, $3) RETURNING id',
    [run.importer, run.host, run.mode],
  );
  return Number(r.rows[0]!.id);
}

export async function closeRun(db: Db, runId: number, status: 'ok' | 'ok_partial' | 'failed', counts: object): Promise<void> {
  await db.query('UPDATE zeusi.ingest_runs SET finished_at = now(), status = $2, counts = $3::jsonb WHERE id = $1', [
    runId,
    status,
    JSON.stringify(counts),
  ]);
}

export interface WallRejection {
  ruleId: number | null;
  hard: boolean;
  contentSha256: string | null;
}

export function parseWallError(e: unknown): WallRejection | undefined {
  const pe = asPgError(e);
  if (pe.code !== WALL_REJECTED) return undefined;
  const detail = pe.detail ?? '';
  const rule = /rule_id=(\d+)/.exec(detail);
  const sha = /content_sha256=([0-9a-f]{64})/.exec(detail);
  return {
    ruleId: rule ? Number(rule[1]) : null,
    hard: /hard=true/.test(detail),
    contentSha256: sha ? sha[1]! : null,
  };
}

export async function insertFactInRun(db: Db, runId: number, f: FactInput): Promise<number> {
  const r = await db.query<{ id: string }>(
    `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, $2, $3, $4::zeusi.scope, $5::zeusi.source_kind, $6, $7::timestamptz, decode($8, 'hex'), $9)
     RETURNING id`,
    [f.kind, f.subject ?? null, f.text, f.scope, f.sourceKind, f.sourceUri, f.sourceTs, f.sourceSha256.toLowerCase(), runId],
  );
  return Number(r.rows[0]!.id);
}

/**
 * Insert one sourced fact in its own ingest run. A wall rejection is recorded in
 * zeusi.quarantine by uri and hashes only (never the text) and returned, not thrown.
 */
/** Live wall rules for the pre-check, or null when this role cannot read them (box roles). */
async function tryLoadWall(db: Db): Promise<Wall | null> {
  try {
    return await loadWall(db);
  } catch (e) {
    if (asPgError(e).code === '42501') return null; // no SELECT on wall tables: the trigger is the only check
    throw e;
  }
}

export async function insertFact(db: Db, input: Partial<FactInput>, run?: Partial<RunInput>): Promise<InsertFactResult> {
  const v0 = validateFact(input);
  // Secrets (src/secrets.ts): redacted in place before the INSERT (the wall pre-check sees both).
  const f: FactInput = { ...v0, text: redactSecrets(v0.text, { skip: STORAGE_SKIP }).text, ...(v0.subject != null ? { subject: redactSecrets(v0.subject, { skip: STORAGE_SKIP }).text } : {}) };
  const runId = await openRun(db, { importer: run?.importer ?? 'cli', host: run?.host ?? defaultHost(), mode: run?.mode ?? 'manual' });
  // Pre-check with src/wall.ts (same verdict as the trigger) and quarantine BEFORE
  // the text is sent. The trigger below stays the backstop.
  // The wall checks the ORIGINAL text first, then the redacted text (review r1 P1-1):
  // redaction must never remove the wall's own signal (a walled name inside a `token=...`
  // value) and let the fact through.
  const row = (x: FactInput) => ({
    kind: x.kind, subject: x.subject ?? null, text: x.text, scope: x.scope, source_kind: x.sourceKind,
    source_uri: x.sourceUri, source_ts: x.sourceTs, source_sha256: x.sourceSha256, ingest_run_id: runId,
  });
  const wall = await tryLoadWall(db);
  if (!wall && (f.text !== v0.text || f.subject !== v0.subject)) {
    // Box roles cannot read the wall tables, so the DB trigger is their only check, and it
    // only sees the REDACTED text. When redaction changed the fact, the code-shipped seed
    // wall and the Plankiva signal check the ORIGINAL here (security review of fix round 1):
    // a walled name inside a redacted value is quarantined, never stored redacted.
    const seed = seedWall();
    const raw = seed.check('facts', row(v0));
    const hit = raw.blocked || mentionsProtectedName(v0.text) || (v0.subject != null && mentionsProtectedName(v0.subject));
    if (hit) {
      const red = seed.check('facts', row(f));
      const ruleId = raw.blocked ? raw.ruleId : (seed.rules.find((r) => r.hard && r.kind === 'term' && /plankiva/i.test(r.pattern))?.id ?? null);
      const qid = await recordQuarantine(db, {
        sourceKind: f.sourceKind, sourceUri: f.sourceUri, sourceSha256: f.sourceSha256, ruleId, ingestRunId: runId, table: 'facts', contentSha256: red.contentSha256,
      });
      await closeRun(db, runId, 'ok', { quarantined: 1, precheck: 1 });
      return { status: 'quarantined', runId, ruleId, quarantineId: qid, contentSha256: red.contentSha256 };
    }
  }
  if (wall) {
    const raw = wall.check('facts', row(v0));
    const red = wall.check('facts', row(f));
    // Quarantine records the hash of the redacted text (what would have been stored), never one of a secret-bearing text.
    const v = raw.blocked ? { ...raw, contentSha256: red.contentSha256 } : red;
    if (v.blocked) {
      const qid = await recordQuarantine(db, {
        sourceKind: f.sourceKind, sourceUri: f.sourceUri, sourceSha256: f.sourceSha256, ruleId: v.ruleId,
        ingestRunId: runId, table: 'facts', contentSha256: v.contentSha256,
      });
      await closeRun(db, runId, 'ok', { quarantined: 1, precheck: 1 });
      return { status: 'quarantined', runId, ruleId: v.ruleId, quarantineId: qid, contentSha256: v.contentSha256 };
    }
  }
  try {
    const id = await insertFactInRun(db, runId, f);
    await closeRun(db, runId, 'ok', { inserted: 1 });
    return { status: 'inserted', id, runId };
  } catch (e) {
    const wall = parseWallError(e);
    if (!wall) {
      await closeRun(db, runId, 'failed', { error_code: asPgError(e).code ?? 'unknown' }).catch(() => {});
      throw e;
    }
    const qid = await recordQuarantine(db, {
      sourceKind: f.sourceKind, sourceUri: f.sourceUri, sourceSha256: f.sourceSha256, ruleId: wall.ruleId, ingestRunId: runId, table: 'facts', contentSha256: wall.contentSha256,
    });
    await closeRun(db, runId, 'ok', { quarantined: 1 });
    return { status: 'quarantined', runId, ruleId: wall.ruleId, quarantineId: qid, contentSha256: wall.contentSha256 };
  }
}

export async function getFact(db: Db, id: number): Promise<FactRow | undefined> {
  const r = await db.query<FactRow>(
    `SELECT id::int AS id, kind, subject, text, scope::text AS scope, source_kind::text AS source_kind, source_uri,
            source_ts, encode(source_sha256, 'hex') AS source_sha256_hex, ingest_run_id::int AS ingest_run_id,
            ingested_at, ingested_by, superseded_by::int AS superseded_by
     FROM zeusi.facts WHERE id = $1`,
    [id],
  );
  return r.rows[0];
}

/** Deterministic dummy vector literal (no embedding provider involved). */
export function dummyVector(seed = 0, dims = EMBED_DIMS): string {
  const v = new Array<number>(dims).fill(0);
  v[Math.abs(seed) % dims] = 1;
  v[(Math.abs(seed) + 1) % dims] = 0.5;
  return `[${v.join(',')}]`;
}

export interface HnswIndexInfo {
  exists: boolean;
  method: string | null;
  opclass: string | null;
  options: string[];
  predicate: string | null;
}

export async function hnswIndexInfo(db: Db): Promise<HnswIndexInfo> {
  const r = await db.query<{ method: string; opclass: string; options: string[] | null; predicate: string | null }>(
    `SELECT am.amname AS method, opc.opcname AS opclass, c.reloptions AS options,
            pg_get_expr(i.indpred, i.indrelid) AS predicate
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_index i ON i.indexrelid = c.oid
     JOIN pg_am am ON am.oid = c.relam
     JOIN pg_opclass opc ON opc.oid = i.indclass[0]
     WHERE n.nspname = 'zeusi' AND c.relname = 'chunks_hnsw_te3s'`,
  );
  const row = r.rows[0];
  if (!row) return { exists: false, method: null, opclass: null, options: [], predicate: null };
  return { exists: true, method: row.method, opclass: row.opclass, options: row.options ?? [], predicate: row.predicate };
}

export interface VectorHit {
  id: number;
  source_uri: string;
  source_ts: Date;
  distance: number;
}

/** Nearest chunks to a dummy vector over the indexed model. Always returns source_uri/source_ts (R7). */
export async function vectorQuery(db: Db, vec: string, k = 5): Promise<VectorHit[]> {
  // Model label is a constant inlined so the planner can match the partial index predicate.
  const r = await db.query<VectorHit>(
    `SELECT id::int AS id, source_uri, source_ts, (embedding <=> $1::halfvec(${EMBED_DIMS}))::float8 AS distance
     FROM zeusi.chunks
     WHERE embed_model = '${INDEXED_EMBED_MODEL}'
     ORDER BY embedding <=> $1::halfvec(${EMBED_DIMS})
     LIMIT $2`,
    [vec, k],
  );
  return r.rows;
}

/** EXPLAIN the vector query with seq scans disabled; true when the HNSW index is chosen. */
export async function vectorQueryUsesHnsw(db: Db, vec: string): Promise<{ used: boolean; plan: string }> {
  await db.exec('BEGIN');
  try {
    await db.exec('SET LOCAL enable_seqscan = off');
    await db.exec('SET LOCAL hnsw.ef_search = 100');
    const r = await db.query<{ 'QUERY PLAN': string }>(
      `EXPLAIN SELECT id FROM zeusi.chunks
       WHERE embed_model = '${INDEXED_EMBED_MODEL}'
       ORDER BY embedding <=> $1::halfvec(${EMBED_DIMS}) LIMIT 5`,
      [vec],
    );
    const plan = r.rows.map((x) => x['QUERY PLAN']).join('\n');
    return { used: plan.includes('chunks_hnsw_te3s'), plan };
  } finally {
    await db.exec('ROLLBACK');
  }
}
