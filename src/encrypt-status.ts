// `zeusi workspaces encrypt-status --tenant <id>`: the operator's dry run before encrypting one
// workspace (docs/plans/2026-11-18-zeusi-workspace-encryption.md §5.2 step 2, §11 wall_allow;
// C3 docs/plans/2026-11-18-c3-catalog-enc-state.md KTD8, KTD9).
//
//   who      the provisioner login zeusi_tenant_admin, which owns the catalog and every workspace
//            schema: no new grant. Two short READ ONLY transactions (catalog, then workspace counts),
//            both rolled back; the catalog ensure path
//            (which writes DDL) is NOT run, so a catalog without 0014 is reported, never fixed.
//   what     enc_state, the number of wraps per kind, and per table the row count and the count of
//            non-NULL values of every content and content-derived column of plan §2.1. Before C5
//            there are no ciphertext columns, so every non-NULL value counted is plain text (the
//            output says so). After C5 this counts the plain column against its _ct overlay.
//   never    a value: no body, title, path, URI, hash, wrap blob, credential id or salt. Every token
//            of the output is a constant label, a number, the validated workspace id or a validated
//            enc_state (test/c3-encrypt-status.test.ts plants canaries and checks the output).
//
// `zeusi workspaces encrypt-status --all [--expect-no-plain]` (C8-0 U2, docs/plans/2026-11-21-c8-refresh.md KTD-B):
// every personal workspace, COUNTS ONLY (no id, no title, no value). One short READ ONLY catalog transaction (counts
// per enc_state, workspaces with 0 wraps, the active ids, held in memory and never printed), then one READ ONLY
// transaction per workspace that touches no zeusi_tenants table: digest_column_missing (a prepared workspace whose
// schema lacks the sealed digest copy column or its CHECKs) and digest_missing (sealed rows of the four tables with
// no copy). A schema gone between the two steps counts as skipped. With --expect-no-plain the exit code is 3 when any
// workspace is off or enrolled (the C10 trigger), else 0.
//
// No key, no unwrap: this file does not use the C1 envelope module.

import type { Db } from './db.ts';
import { assertTenantId, TENANT_ID_RE } from './tenant-ddl.ts';
import { PREPARE_MARKER, SEALED_DIGEST_COLUMN, sealedDigestPresence } from './tenant-overlay.ts';
import { CONTROL_SCHEMA, ENC_STATES, KEY_WRAP_KINDS, type TenantDirectory } from './tenants.ts';

/**
 * Columns counted per workspace table (plan §2.1 "Content" and "Content-derived"; people, ingest_runs,
 * embed_usage and backup_runs hold none). quarantine holds plain-text URIs and hashes (deleted at
 * flip, §5.2a); wall_allow is counted by rows (§11). test/c3-encrypt-status.test.ts pins that every
 * name exists in a freshly provisioned workspace.
 */
export const PLAIN_COLUMNS: ReadonlyArray<{ readonly table: string; readonly columns: readonly string[] }> = [
  { table: 'notes', columns: ['title', 'body', 'frontmatter', 'vault_path', 'source_uri', 'source_sha256'] },
  { table: 'chunks', columns: ['heading_path', 'text', 'text_sha256', 'tsv', 'embedding', 'source_uri'] },
  { table: 'facts', columns: ['subject', 'text', 'source_uri', 'source_sha256'] },
  { table: 'decisions', columns: ['exact_words', 'applies_to', 'expires_rule', 'linked_repo', 'linked_job', 'source_uri', 'source_sha256'] },
  { table: 'decision_links', columns: ['target_uri', 'source_uri', 'source_sha256'] },
  { table: 'episodes', columns: ['actor', 'summary', 'links', 'source_uri', 'source_sha256'] },
  { table: 'prs', columns: ['title', 'author_login', 'base_ref', 'head_ref', 'source_uri', 'source_sha256'] },
  { table: 'pr_reviews', columns: ['reviewer', 'review_ref', 'source_uri', 'source_sha256'] },
  { table: 'routine_runs', columns: ['run_key', 'login_label', 'log_ref', 'source_uri', 'source_sha256'] },
  { table: 'quarantine', columns: ['source_uri', 'source_sha256', 'content_sha256'] },
];
/** Counted by rows only (plan §11: should be empty; deleted at flip like quarantine if not). */
export const ROW_ONLY_TABLES: readonly string[] = ['wall_allow'];

/** A refusal the CLI prints as is (exit 1). Never carries a value from the database. */
export class EncryptStatusRefused extends Error {
  override name = 'EncryptStatusRefused';
}

export interface EncryptStatusTable {
  table: string;
  /** null: the table is absent in this workspace. */
  rows: number | null;
  /** Non-NULL values per column; null: the column is absent in this workspace. */
  plain: Array<{ column: string; count: number | null }>;
}

export interface EncryptStatus {
  tenantId: string;
  encState: (typeof ENC_STATES)[number] | 'unknown';
  wraps: { passkey: number; recovery: number; total: number };
  tables: EncryptStatusTable[];
  rowOnly: Array<{ table: string; rows: number | null }>;
  plainTotal: number;
}

const qi = (ident: string) => `"${ident.replace(/"/g, '""')}"`;
const n = (v: unknown): number => {
  const x = Number(v);
  if (!Number.isSafeInteger(x) || x < 0) throw new EncryptStatusRefused('a count was not a number');
  return x;
};

export type CatalogStatus = Pick<EncryptStatus, 'tenantId' | 'encState' | 'wraps'>;
export type WorkspaceCounts = Pick<EncryptStatus, 'tables' | 'rowOnly' | 'plainTotal'>;

/**
 * The catalog part (enc_state, wraps per kind) of one workspace on `db` (the caller holds a READ ONLY
 * transaction as the catalog owner). Refuses a malformed id before any query, a catalog without 0014,
 * and an unknown workspace.
 */
export async function readCatalogStatus(db: Db, tenantId: string): Promise<CatalogStatus> {
  assertTenantId(tenantId);
  const cat = (await db.query<{ col: boolean; wraps: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace s ON s.oid = c.relnamespace
                     WHERE s.nspname = $1 AND c.relname = 'tenants' AND a.attname = 'enc_state' AND NOT a.attisdropped) AS col,
            EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace
                     WHERE s.nspname = $1 AND c.relname = 'key_wraps' AND c.relkind = 'r') AS wraps`, [CONTROL_SCHEMA])).rows[0];
  if (!cat?.col || !cat.wraps) {
    throw new EncryptStatusRefused('catalog not migrated: zeusi_tenants has no enc_state / key_wraps yet (migration 0014 pending); nothing changed');
  }
  const st = (await db.query<{ enc_state: string }>(`SELECT enc_state FROM ${CONTROL_SCHEMA}.tenants WHERE tenant_id = $1`, [tenantId])).rows[0];
  if (!st) throw new EncryptStatusRefused('no such workspace in the catalog');
  const encState = (ENC_STATES as readonly string[]).includes(st.enc_state) ? (st.enc_state as EncryptStatus['encState']) : 'unknown';

  const wraps = { passkey: 0, recovery: 0, total: 0 };
  for (const r of (await db.query<{ kind: string; c: string }>(
    `SELECT kind, count(*)::bigint AS c FROM ${CONTROL_SCHEMA}.key_wraps WHERE tenant_id = $1 GROUP BY kind`, [tenantId])).rows) {
    const c = n(r.c);
    wraps.total += c;
    if ((KEY_WRAP_KINDS as readonly string[]).includes(r.kind)) wraps[r.kind as 'passkey' | 'recovery'] += c;
  }
  return { tenantId, encState, wraps };
}

/**
 * The plain-text counts of one workspace schema on `db` (READ ONLY transaction, as the schema owner).
 * Touches no catalog table, so a long count never holds a lock on zeusi_tenants.
 */
export async function readWorkspaceCounts(db: Db, tenantId: string): Promise<WorkspaceCounts> {
  assertTenantId(tenantId);
  if ((await db.query<{ c: number }>('SELECT count(*)::int AS c FROM pg_namespace WHERE nspname = $1', [tenantId])).rows[0]?.c !== 1) {
    throw new EncryptStatusRefused('the workspace schema does not exist');
  }
  const present = new Map<string, Set<string>>();
  for (const r of (await db.query<{ t: string; a: string }>(
    `SELECT c.relname::text AS t, a.attname::text AS a FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace
       JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
      WHERE s.nspname = $1 AND c.relkind = 'r'`, [tenantId])).rows) {
    if (!present.has(r.t)) present.set(r.t, new Set());
    present.get(r.t)!.add(r.a);
  }

  const s = qi(tenantId);
  let plainTotal = 0;
  const tables: EncryptStatusTable[] = [];
  for (const spec of PLAIN_COLUMNS) {
    const cols = present.get(spec.table);
    if (!cols) {
      tables.push({ table: spec.table, rows: null, plain: spec.columns.map((column) => ({ column, count: null })) });
      continue;
    }
    const have = spec.columns.filter((c) => cols.has(c));
    const r = (await db.query<Record<string, string>>(
      `SELECT count(*)::bigint AS r${have.map((c, i) => `, count(${qi(c)})::bigint AS c${i}`).join('')} FROM ${s}.${qi(spec.table)}`)).rows[0] ?? {};
    const plain = spec.columns.map((column) => {
      const i = have.indexOf(column);
      if (i < 0) return { column, count: null };
      const count = n(r[`c${i}`]);
      plainTotal += count;
      return { column, count };
    });
    tables.push({ table: spec.table, rows: n(r.r), plain });
  }
  const rowOnly: EncryptStatus['rowOnly'] = [];
  for (const t of ROW_ONLY_TABLES) {
    if (!present.has(t)) {
      rowOnly.push({ table: t, rows: null });
      continue;
    }
    const rows = n((await db.query<{ r: string }>(`SELECT count(*)::bigint AS r FROM ${s}.${qi(t)}`)).rows[0]?.r);
    rowOnly.push({ table: t, rows });
  }
  return { tables, rowOnly, plainTotal };
}

/** Both parts on one `db` (one READ ONLY transaction held by the caller). */
export async function readEncryptStatus(db: Db, tenantId: string): Promise<EncryptStatus> {
  const cat = await readCatalogStatus(db, tenantId);
  return { ...cat, ...(await readWorkspaceCounts(db, tenantId)) };
}

/**
 * The status of one workspace, as the provisioner. Two short READ ONLY transactions, both rolled
 * back: the catalog first (released at once, so DDL on zeusi_tenants and the router never queue behind
 * a long count; C3 review P3-2), then the workspace counts.
 */
export async function encryptStatus(dir: TenantDirectory, tenantId: string): Promise<EncryptStatus> {
  assertTenantId(tenantId);
  const cat = await dir.readOnly((db) => readCatalogStatus(db, tenantId));
  return { ...cat, ...(await dir.readOnly((db) => readWorkspaceCounts(db, tenantId))) };
}

/** Output lines: constant labels, numbers, the validated id and enc_state. Nothing else. */
export function formatEncryptStatus(s: EncryptStatus): string[] {
  const id = TENANT_ID_RE.test(s.tenantId) ? s.tenantId : 'invalid';
  const v = (x: number | null) => (x === null ? 'absent' : String(x));
  return [
    'workspaces encrypt-status (dry run, counts only, nothing changed)',
    `workspace ${id}: enc_state ${s.encState}; key wraps ${s.wraps.total} (passkey ${s.wraps.passkey}, recovery ${s.wraps.recovery})`,
    'plain text: no ciphertext columns exist before the C5 overlay, so every non-NULL value counted below is plain text',
    ...s.tables.map((t) => `  ${t.table}: rows ${v(t.rows)}; ${t.plain.map((p) => `${p.column} ${v(p.count)}`).join(', ')}`),
    ...s.rowOnly.map((t) => `  ${t.table}: rows ${v(t.rows)}`),
    `plain values total ${s.plainTotal}`,
  ];
}

// ---------------------------------------------------------------------------
// C8-0 U2: `encrypt-status --all` (KTD-B)

export interface EncryptStatusAll {
  /** Personal workspaces in the catalog (any status). */
  workspaces: number;
  /** Per enc_state (every state listed, 0 included); `unknown` for a value outside ENC_STATES. */
  byState: Record<(typeof ENC_STATES)[number] | 'unknown', number>;
  /** Workspaces with no key_wraps row. */
  zeroWraps: number;
  /** Active workspaces read in step 2. */
  active: number;
  /** Prepared workspaces whose schema lacks the sealed digest copy column or one of its two CHECKs. */
  digestColumnMissing: number;
  /** Sealed rows (key_version set) of notes, facts, decisions and decision_links with no sealed digest copy. */
  digestMissing: number;
  /** Active workspaces whose schema was gone at step 2 (a concurrent delete). */
  skipped: number;
}

/** Step 1, on `db` (READ ONLY, as the catalog owner): the counts and the active ids. The ids never leave this module. */
async function readCatalogAll(db: Db): Promise<{ counts: Pick<EncryptStatusAll, 'workspaces' | 'byState' | 'zeroWraps'>; ids: string[] }> {
  const cat = (await db.query<{ col: boolean; wraps: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace s ON s.oid = c.relnamespace
                     WHERE s.nspname = $1 AND c.relname = 'tenants' AND a.attname = 'enc_state' AND NOT a.attisdropped) AS col,
            EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace
                     WHERE s.nspname = $1 AND c.relname = 'key_wraps' AND c.relkind = 'r') AS wraps`, [CONTROL_SCHEMA])).rows[0];
  if (!cat?.col || !cat.wraps) {
    throw new EncryptStatusRefused('catalog not migrated: zeusi_tenants has no enc_state / key_wraps yet (migration 0014 pending); nothing changed');
  }
  const byState = Object.fromEntries([...ENC_STATES, 'unknown'].map((k) => [k, 0])) as EncryptStatusAll['byState'];
  let workspaces = 0;
  for (const r of (await db.query<{ s: string; c: string }>(`SELECT enc_state AS s, count(*)::bigint AS c FROM ${CONTROL_SCHEMA}.tenants GROUP BY enc_state`)).rows) {
    const c = n(r.c);
    workspaces += c;
    byState[(ENC_STATES as readonly string[]).includes(r.s) ? (r.s as (typeof ENC_STATES)[number]) : 'unknown'] += c;
  }
  const zeroWraps = n((await db.query<{ c: string }>(
    `SELECT count(*)::bigint AS c FROM ${CONTROL_SCHEMA}.tenants t WHERE NOT EXISTS (SELECT 1 FROM ${CONTROL_SCHEMA}.key_wraps k WHERE k.tenant_id = t.tenant_id)`)).rows[0]?.c);
  const ids = (await db.query<{ id: string }>(`SELECT tenant_id AS id FROM ${CONTROL_SCHEMA}.tenants WHERE status = 'active' ORDER BY tenant_id`)).rows
    .map((r) => r.id).filter((id) => TENANT_ID_RE.test(id));
  return { counts: { workspaces, byState, zeroWraps }, ids };
}

/**
 * Step 2, on `db` (READ ONLY, as the schema owner): the digest counts of ONE workspace. Touches no zeusi_tenants
 * table. `gone`: the schema no longer exists. Reads catalog facts and counts only, never a value.
 */
export async function readWorkspaceDigest(db: Db, tenantId: string): Promise<{ gone: boolean; prepared: boolean; columnMissing: boolean; missing: number }> {
  assertTenantId(tenantId);
  if ((await db.query<{ c: number }>('SELECT count(*)::int AS c FROM pg_namespace WHERE nspname = $1', [tenantId])).rows[0]?.c !== 1) {
    return { gone: true, prepared: false, columnMissing: false, missing: 0 };
  }
  const s = qi(tenantId);
  const prepared = (await db.query<{ p: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM ${s}.schema_migrations WHERE filename = $1) AS p`, [PREPARE_MARKER])).rows[0]?.p === true;
  if (!prepared) return { gone: false, prepared: false, columnMissing: false, missing: 0 };
  const presence = await sealedDigestPresence(db, tenantId);
  let missing = 0;
  for (const p of presence) {
    // Where the column is absent every sealed row lacks its copy; never name a missing column.
    const where = p.column ? `key_version IS NOT NULL AND ${SEALED_DIGEST_COLUMN} IS NULL` : 'key_version IS NOT NULL';
    missing += n((await db.query<{ c: string }>(`SELECT count(*)::bigint AS c FROM ${s}.${qi(p.table)} WHERE ${where}`)).rows[0]?.c);
  }
  return { gone: false, prepared: true, columnMissing: !presence.every((p) => p.column && p.format && p.plain), missing };
}

/** KTD-B: one short READ ONLY catalog transaction, then one READ ONLY transaction per active workspace. Counts only. */
export async function encryptStatusAll(dir: TenantDirectory): Promise<EncryptStatusAll> {
  const cat = await dir.readOnly((db) => readCatalogAll(db));
  const out: EncryptStatusAll = { ...cat.counts, active: cat.ids.length, digestColumnMissing: 0, digestMissing: 0, skipped: 0 };
  for (const id of cat.ids) {
    const d = await dir.readOnly((db) => readWorkspaceDigest(db, id));
    if (d.gone) {
      out.skipped++;
      continue;
    }
    if (d.columnMissing) out.digestColumnMissing++;
    out.digestMissing += d.missing;
  }
  return out;
}

/** `off` + `enrolled`: personal workspaces that write plain text (the C8a / C10 trigger). */
export const plainWorkspaces = (s: EncryptStatusAll): number => s.byState.off + s.byState.enrolled;

/** Output lines of --all: constant labels and numbers only (no id, no title, no value). */
export function formatEncryptStatusAll(s: EncryptStatusAll): string[] {
  return [
    'workspaces encrypt-status --all (dry run, counts only, nothing changed)',
    `personal workspaces ${s.workspaces}: ${[...ENC_STATES, 'unknown' as const].map((k) => `${k} ${s.byState[k]}`).join(', ')}`,
    `plain-text workspaces (off + enrolled) ${plainWorkspaces(s)}`,
    `workspaces with 0 key wraps ${s.zeroWraps}`,
    `active workspaces read ${s.active}; skipped ${s.skipped} (schema gone between the two reads)`,
    `digest_column_missing ${s.digestColumnMissing} (active prepared workspaces without the sealed digest copy column or its checks)`,
    `digest_missing ${s.digestMissing} (sealed rows of notes, facts, decisions and decision_links of active workspaces without a sealed digest copy)`,
  ];
}

/** The CLI body of --all: print the lines; exit 3 under --expect-no-plain when any workspace is off or enrolled, else 0. */
export async function runEncryptStatusAll(dir: TenantDirectory, o: { expectNoPlain: boolean }, print: (line: string) => void): Promise<number> {
  const s = await encryptStatusAll(dir);
  for (const line of formatEncryptStatusAll(s)) print(line);
  return o.expectNoPlain && plainWorkspaces(s) > 0 ? 3 : 0;
}
