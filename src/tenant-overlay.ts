// Tenant schema overlay for workspace encryption (C5; chip plan docs/plans/2026-11-19-c5-tenant-ddl.md,
// parent plan docs/plans/2026-11-18-zeusi-workspace-encryption.md §4.6, §5.1, §5.2a, §8.1).
//
// A personal workspace schema is "the team migrations + overlay" (src/tenant-ddl.ts:1-30). The overlay is
// owner-run SQL that needs no key and reads no content. It applies to `zt_*` schemas only: every builder
// asserts TENANT_ID_RE, so it can never target `zeusi`, and nothing here adds a migration file.
//
//   prepare (C5a)  nullable *_ct / *_hmac / key_version columns; num_nonnulls(plain, ct) = 1 in place of
//                  every NOT NULL of plan §2.1; one <table>_enc_shape CHECK (a row is wholly plain or
//                  wholly encrypted); HMAC UNIQUEs; replacement chunks_inherit() and stamp_provenance();
//                  the enc_progress table (numbers only, RLS off) and its writer grant; a marker row in
//                  <schema>.schema_migrations. Every existing plain row stays valid.
//   flip (C5b)     <table>_enc_flipped CHECKs (NOT VALID, then VALIDATE: fails loudly while any plain
//                  value is left); drop tsv + GIN, HNSW, the plain UNIQUEs and decision_links_target_uri_idx;
//                  delete every quarantine and wall_allow row; ANALYZE.
//   relax (C5b)    drop the <table>_enc_flipped CHECKs (the decrypt run needs plain text allowed again).
//   unflip (C5b)   re-add tsv, GIN, HNSW, the plain UNIQUEs (a duplicate fails loudly) and the index;
//                  delete every quarantine row; ANALYZE. The prepare overlay stays.
//
// State moves and their guards live in TenantDirectory.overlayStep (src/tenants.ts); this module only
// builds SQL and reads counts. It never imports the C1 envelope module (the C1 "not wired" test allows
// one importer only): the sealed-value format byte, minimum length and MAX_KEY_VERSION are literals
// that test/c5-overlay.test.ts pins equal to C1.

import { createHash } from 'node:crypto';
import type { Db } from './db.ts';
import {
  assertTenantId, B1_INDEX_READER_PRIVS, B1_INDEX_TABLE, B1_INDEX_WRITER_PRIVS, ENC_PROGRESS_TABLE, ENC_PROGRESS_WRITER_PRIVS, tenantRole, tenantWriterRole,
} from './tenant-ddl.ts';
import type { EncState } from './tenants.ts';

/** C1 sealed blob: 0x01 || nonce (12) || ciphertext || tag (16) (chip C1). */
export const SEALED_FORMAT_BYTE = 0x01;
/** The shortest sealed value: format byte + nonce + empty ciphertext + tag. */
export const SEALED_MIN_BYTES = 1 + 12 + 16;
/** HMAC-SHA256 output. */
export const HMAC_BYTES = 32;
/** = MAX_KEY_VERSION of the C1 envelope module (the smallint maximum). */
export const OVERLAY_MAX_KEY_VERSION = 32767;
/** The marker row prepare writes into <schema>.schema_migrations. */
export const PREPARE_MARKER = 'overlay:c5a_prepare';

export interface OverlayColumn {
  /** The plain-text column (plan §2.1 "Content", plus source_uri / vault_path / target_uri). */
  plain: string;
  /** NOT NULL today: replaced by num_nonnulls(plain, plain_ct) = 1. */
  required: boolean;
  /** Has a deterministic `<plain>_hmac` column (equality, joins, uniqueness). */
  hmac?: boolean;
  /** Has a DEFAULT today that prepare drops (an encrypted INSERT must not get a plain default). */
  dropDefault?: boolean;
}
export interface OverlayTable {
  table: string;
  columns: readonly OverlayColumn[];
  /** Content-derived plain columns that must be NULL on an encrypted row and after flip. */
  derived: readonly string[];
}

/** Plan §2.1 / §5.2a step 1, per table. The one source for prepare, flip, relax, unflip and the counts. */
export const OVERLAY_SPEC: readonly OverlayTable[] = [
  {
    table: 'notes',
    columns: [
      { plain: 'title', required: true }, { plain: 'body', required: true }, { plain: 'frontmatter', required: true, dropDefault: true },
      { plain: 'vault_path', required: true, hmac: true }, { plain: 'source_uri', required: true, hmac: true },
    ],
    derived: [],
  },
  {
    table: 'chunks',
    columns: [{ plain: 'heading_path', required: false }, { plain: 'text', required: true, hmac: true }, { plain: 'source_uri', required: true, hmac: true }],
    // text_sha256 = sha256(text) and the embedding are plain-text derived (plan §2.1).
    derived: ['text_sha256', 'embedding'],
  },
  {
    table: 'facts',
    columns: [{ plain: 'subject', required: false }, { plain: 'text', required: true }, { plain: 'source_uri', required: true, hmac: true }],
    derived: [],
  },
  {
    table: 'decisions',
    columns: [
      { plain: 'exact_words', required: true }, { plain: 'applies_to', required: true, dropDefault: true },
      { plain: 'expires_rule', required: false }, { plain: 'linked_repo', required: false }, { plain: 'linked_job', required: false },
      { plain: 'source_uri', required: true, hmac: true },
    ],
    derived: [],
  },
  {
    table: 'decision_links',
    columns: [{ plain: 'target_uri', required: true, hmac: true }, { plain: 'source_uri', required: true, hmac: true }],
    derived: [],
  },
];
export const OVERLAY_TABLES: readonly string[] = OVERLAY_SPEC.map((t) => t.table);
/**
 * Content tables the workspace writer can never write (src/tenant-ddl.ts TENANT_WRITE_TABLES): they get
 * no overlay columns, and flip refuses unless they are empty.
 */
export const OVERLAY_MUST_BE_EMPTY: readonly string[] = ['episodes', 'prs', 'pr_reviews', 'routine_runs'];

/** Plain UNIQUE constraints dropped at flip, re-added at unflip (PostgreSQL's default names, 0001 / 0013). */
export const PLAIN_UNIQUES: ReadonlyArray<{ table: string; name: string; columns: string }> = [
  { table: 'notes', name: 'notes_vault_path_key', columns: 'vault_path' },
  { table: 'facts', name: 'facts_source_uri_source_sha256_key', columns: 'source_uri, source_sha256' },
  { table: 'decisions', name: 'decisions_source_uri_source_sha256_key', columns: 'source_uri, source_sha256' },
  { table: 'decision_links', name: 'decision_links_decision_id_target_uri_key', columns: 'decision_id, target_uri' },
];
/** HMAC UNIQUEs added at prepare (NULL-tolerant: plain rows are unaffected). */
export const HMAC_UNIQUES: ReadonlyArray<{ table: string; name: string; columns: string }> = [
  { table: 'notes', name: 'notes_vault_path_hmac_key', columns: 'vault_path_hmac' },
  { table: 'facts', name: 'facts_source_uri_hmac_source_sha256_key', columns: 'source_uri_hmac, source_sha256' },
  { table: 'decisions', name: 'decisions_source_uri_hmac_source_sha256_key', columns: 'source_uri_hmac, source_sha256' },
  { table: 'decision_links', name: 'decision_links_decision_id_target_uri_hmac_key', columns: 'decision_id, target_uri_hmac' },
];
/** Exactly 0001_core.sql:242-243 and 0002_search.sql:7-12 (re-added at unflip). */
export const TSV_EXPR = `to_tsvector('simple'::regconfig, coalesce(heading_path, '') || ' ' || text)`;
export const HNSW_INDEX = 'chunks_hnsw_te3s';
export const TSV_INDEX = 'chunks_tsv';
export const TARGET_URI_INDEX = 'decision_links_target_uri_idx';

/**
 * May the plain (`off`) read and write paths run on a workspace in this state? Only while no row can be
 * ciphertext and the schema is not flipped: `off` and `enrolled`. C6 / C7 route through this; in
 * `decrypting` and `decrypted` the encrypted path (or a refusal) applies until unflip ends in `off`.
 */
export function offPathAllowed(state: EncState): boolean {
  return state === 'off' || state === 'enrolled';
}

const q = (ident: string) => `"${ident.replace(/"/g, '""')}"`;
const ct = (c: string) => `${c}_ct`;
const hm = (c: string) => `${c}_hmac`;
const and = (xs: string[]) => (xs.length === 0 ? 'true' : xs.join(' AND '));

function plainNullList(t: OverlayTable): string[] {
  return [...t.columns.map((c) => c.plain), ...t.derived];
}
function ctList(t: OverlayTable): string[] {
  return t.columns.map((c) => ct(c.plain));
}
function hmacList(t: OverlayTable): string[] {
  return [...t.columns.filter((c) => c.hmac).map((c) => hm(c.plain))];
}

/** The SQL of the enc_progress writer grant (R3-5). One rule for prepare and writerIn. */
export function encProgressGrantSql(schema: string): string {
  assertTenantId(schema);
  return `GRANT ${ENC_PROGRESS_WRITER_PRIVS.join(', ')} ON ${q(schema)}.${q(ENC_PROGRESS_TABLE)} TO ${q(tenantWriterRole(schema))}`;
}

/**
 * C7 KTD5 (docs/plans/2026-11-19-c7-read-path.md): the B1 index table of one workspace, idempotently (CREATE
 * ... IF NOT EXISTS, REVOKE, GRANT: safe to repeat). Sealed objects only: key_version, kind, object number,
 * generation and the ciphertext; no term, id list or content in clear. The read role gets SELECT only.
 * Run (as the schema owner) by born-encrypted provisioning, by the prepare step, and by writerIn whenever
 * the workspace is prepared (enc_progress exists), so a workspace prepared before C7 converges at its next
 * sign-in. NOT part of the prepare template: PREPARE_SHA256 (the marker of every prepared workspace) is unchanged.
 */
export function b1IndexStatements(schema: string): string[] {
  assertTenantId(schema);
  const s = q(schema);
  const T = `${s}.${q(B1_INDEX_TABLE)}`;
  return [
    `CREATE TABLE IF NOT EXISTS ${T} (
      key_version smallint NOT NULL CHECK (key_version BETWEEN 1 AND ${OVERLAY_MAX_KEY_VERSION}),
      kind        text     NOT NULL CHECK (kind IN ('manifest', 'base', 'segment')),
      shard_no    integer  NOT NULL CHECK (shard_no >= 0),
      generation  bigint   NOT NULL CHECK (generation >= 1),
      blob_ct     bytea    NOT NULL CHECK (octet_length(blob_ct) >= ${SEALED_MIN_BYTES} AND get_byte(blob_ct, 0) = ${SEALED_FORMAT_BYTE}),
      updated_at  timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (key_version, kind, shard_no))`,
    `REVOKE ALL ON ${T} FROM PUBLIC`,
    `GRANT ${B1_INDEX_READER_PRIVS.join(', ')} ON ${T} TO ${q(tenantRole(schema))}`,
  ];
}

// ---------------------------------------------------------------------------
// C8-0 U1 (docs/plans/2026-11-21-c8-refresh.md KTD-A): the sealed copy of the plain source digest.
//
// A sealed row stores source_sha256 = keyedDigest('source_sha256', plain digest) (src/workspace-seal.ts). A later
// rotate or decrypt must recompute it from the PLAIN digest, so every sealed row of notes, facts, decisions and
// decision_links also carries source_sha256_ct = seal(plain digest as 64 lowercase hex characters) under AAD
// (tenant, table, column 'source_sha256', row id, key_version). Chunks get none (they inherit the parent's digest).
//
//   DDL        ensureSealedDigest: check, then alter. One catalog read; an ALTER only for the missing parts, under a
//              transaction-local lock_timeout; the steady state issues no ALTER (no ACCESS EXCLUSIVE). Additive: one
//              nullable bytea column and two named CHECKs per table. NOT part of the prepare template, so
//              PREPARE_SHA256 is unchanged. Run as the schema owner by born-encrypted provisioning, by prepare and by
//              writerIn whenever enc_progress exists (every sign-in, backfill-writers), all under PROVISION_LOCK.
//   App rule   the copy is never skipped: sealedInsertSql / sealedUpdateSql refuse a sealed row that sets
//              source_sha256 without source_sha256_ct (src/workspace-seal.ts, the one owner of that rule).
//   Presence   sealedDigestPresence is the one reader of "is it there": readOverlayState counts the column only where
//              it exists; the sealed write route refuses (WORKSPACE_CHANGING) unless every table is ready, so a
//              workspace prepared before C8-0 never sees a 42703.
//
// Rollback: revert the image. The old code never names the column; the plain-side CHECK holds for it, and the sealed
// side has no NOT NULL, so its sealed writes still pass. A row it INSERTs has no copy (encrypt-status --all counts
// it as digest_missing). A row it UPDATEs keeps a STALE copy (keyed digest new, copy old) that no count can see:
// a later rotate or decrypt must trust a copy only when digestCopyMatches (src/workspace-seal.ts) says so. A
// revert also removes the CLI refusal of `overlay relax|rollback-start --real` (src/cli.ts), so the operator rule
// "never relax a born-on workspace" applies again. The column may stay. To drop it (owner, Neon snapshot first,
// per workspace and per table of SEALED_DIGEST_TABLES): sealedDigestDropSql.

/** The tables whose sealed rows carry the sealed digest copy (chunks inherit the parent's digest). */
export const SEALED_DIGEST_TABLES: readonly string[] = ['notes', 'facts', 'decisions', 'decision_links'];
/** The column of the sealed copy; its AAD column name is the plain column, 'source_sha256'. */
export const SEALED_DIGEST_COLUMN = 'source_sha256_ct';
export const sealedDigestFormatConstraint = (table: string) => `${table}_source_sha256_ct_format`;
export const sealedDigestPlainConstraint = (table: string) => `${table}_source_sha256_ct_plain`;

/** Per table: is the column there, and each of its two named CHECKs. */
export interface SealedDigestPresence {
  table: string;
  column: boolean;
  format: boolean;
  plain: boolean;
}

/**
 * The one presence read (KTD-A "Presence"; review r2 P3-1): per table of SEALED_DIGEST_TABLES, the column
 * (pg_attribute, not dropped) and the two named CHECKs (pg_constraint). Catalog only, bind parameters only, so it
 * runs unchanged on a provisioner session and on a workspace writer session.
 */
export async function sealedDigestPresence(db: Db, schema: string): Promise<SealedDigestPresence[]> {
  assertTenantId(schema);
  const r = (await db.query<{ t: string; col: boolean; fmt: boolean; pln: boolean }>(
    `SELECT t.t::text AS t,
            EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = $1 AND c.relname = t.t AND a.attname = $3 AND a.attnum > 0 AND NOT a.attisdropped) AS col,
            EXISTS (SELECT 1 FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = $1 AND c.relname = t.t AND k.contype = 'c' AND k.conname = t.t || '_source_sha256_ct_format') AS fmt,
            EXISTS (SELECT 1 FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = $1 AND c.relname = t.t AND k.contype = 'c' AND k.conname = t.t || '_source_sha256_ct_plain') AS pln
       FROM unnest($2::text[]) AS t(t)`, [schema, [...SEALED_DIGEST_TABLES], SEALED_DIGEST_COLUMN])).rows;
  return SEALED_DIGEST_TABLES.map((table) => {
    const x = r.find((y) => y.t === table);
    return { table, column: x?.col === true, format: x?.fmt === true, plain: x?.pln === true };
  });
}

/** Every table has the column and both CHECKs: the sealed write route may run (KTD-A "Presence"). */
export async function sealedDigestReady(db: Db, schema: string): Promise<boolean> {
  return (await sealedDigestPresence(db, schema)).every((p) => p.column && p.format && p.plain);
}

/** The ALTERs that add exactly the missing parts (pure; empty when every part is present). */
export function sealedDigestAlterStatements(schema: string, presence: readonly SealedDigestPresence[]): string[] {
  assertTenantId(schema);
  const s = q(schema);
  const c = SEALED_DIGEST_COLUMN;
  const out: string[] = [];
  for (const p of presence) {
    if (!SEALED_DIGEST_TABLES.includes(p.table)) throw new Error('overlay: not a sealed digest table');
    const parts = [
      ...(p.column ? [] : [`ADD COLUMN IF NOT EXISTS ${c} bytea`]),
      ...(p.format ? [] : [`ADD CONSTRAINT ${sealedDigestFormatConstraint(p.table)} CHECK (${c} IS NULL OR (octet_length(${c}) >= ${SEALED_MIN_BYTES} AND get_byte(${c}, 0) = ${SEALED_FORMAT_BYTE}))`]),
      ...(p.plain ? [] : [`ADD CONSTRAINT ${sealedDigestPlainConstraint(p.table)} CHECK (key_version IS NOT NULL OR ${c} IS NULL)`]),
    ];
    if (parts.length > 0) out.push(`ALTER TABLE ${s}.${q(p.table)} ${parts.join(', ')}`);
  }
  return out;
}

const LOCK_TIMEOUT_RE = /^[1-9][0-9]{0,5}(ms|s)$/;

/**
 * KTD-A "DDL": converge one prepared workspace schema (inside the caller's transaction, as the schema owner). Check,
 * then alter: when every part is present, no further statement runs. Otherwise lock_timeout is set
 * transaction-locally to `lockTimeout` (the callers pass ENC_STATE_LOCK_TIMEOUT, src/tenants.ts), the missing parts
 * are added, and the previous lock_timeout is restored. Returns the number of ALTER statements issued.
 */
export async function ensureSealedDigest(db: Db, schema: string, lockTimeout: string): Promise<number> {
  assertTenantId(schema);
  if (!LOCK_TIMEOUT_RE.test(lockTimeout)) throw new Error('overlay: lock_timeout must look like 5s or 500ms');
  const stmts = sealedDigestAlterStatements(schema, await sealedDigestPresence(db, schema));
  if (stmts.length === 0) return 0;
  const prev = (await db.query<{ lt: string }>(`SELECT current_setting('lock_timeout') AS lt`)).rows[0]?.lt ?? '0';
  await db.query(`SELECT set_config('lock_timeout', '${lockTimeout}', true)`);
  for (const stmt of stmts) await db.exec(stmt);
  await db.query(`SELECT set_config('lock_timeout', $1, true)`, [prev]);
  return stmts.length;
}

/** The documented rollback of U1 for one table (owner, Neon snapshot first): both named CHECKs, then the column. */
export function sealedDigestDropSql(schema: string, table: string): string {
  assertTenantId(schema);
  if (!SEALED_DIGEST_TABLES.includes(table)) throw new Error('overlay: not a sealed digest table');
  return `ALTER TABLE ${q(schema)}.${q(table)} DROP CONSTRAINT IF EXISTS ${sealedDigestFormatConstraint(table)}, `
    + `DROP CONSTRAINT IF EXISTS ${sealedDigestPlainConstraint(table)}, DROP COLUMN IF EXISTS ${SEALED_DIGEST_COLUMN}`;
}

/** The SQL of the b1_index writer grant (C7 KTD5). One rule for prepare, provisioning and writerIn. */
export function b1IndexGrantSql(schema: string): string {
  assertTenantId(schema);
  return `GRANT ${B1_INDEX_WRITER_PRIVS.join(', ')} ON ${q(schema)}.${q(B1_INDEX_TABLE)} TO ${q(tenantWriterRole(schema))}`;
}

/** The replacement chunks_inherit() (plan §4.1a, §5.2a step 4). */
function chunksInheritSql(s: string): string {
  const parent = (table: string, hmac: boolean) =>
    `SELECT scope, source_kind, source_uri, ${hmac ? 'source_uri_hmac' : 'NULL::bytea'}, source_ts, source_sha256, ingest_run_id
      INTO p_scope, p_kind, p_uri, p_uri_hmac, p_ts, p_sha, p_run FROM ${s}.${table}`;
  return `CREATE OR REPLACE FUNCTION ${s}.chunks_inherit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ${s} AS $$
DECLARE
  p_scope ${s}.scope; p_kind ${s}.source_kind; p_uri text; p_uri_hmac bytea;
  p_ts timestamptz; p_sha bytea; p_run bigint; enc boolean;
BEGIN
  -- C5 overlay (docs/plans/2026-11-19-c5-tenant-ddl.md KTD5). An encrypted-shape chunk carries its own
  -- source_uri ciphertext (bound to the chunk's AAD); only metadata and the HMACs are inherited.
  enc := NEW.key_version IS NOT NULL OR NEW.text_ct IS NOT NULL;
  IF enc AND NEW.source_uri_ct IS NULL THEN
    RAISE EXCEPTION 'zeusi: an encrypted chunk needs its own source_uri_ct' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.note_id IS NOT NULL THEN
    ${parent('notes', true)} WHERE id = NEW.note_id;
  ELSIF NEW.fact_id IS NOT NULL THEN
    ${parent('facts', true)} WHERE id = NEW.fact_id;
  ELSIF NEW.decision_id IS NOT NULL THEN
    ${parent('decisions', true)} WHERE id = NEW.decision_id;
  ELSIF NEW.episode_id IS NOT NULL THEN
    ${parent('episodes', false)} WHERE id = NEW.episode_id;
  END IF;
  IF p_scope IS NULL THEN
    RETURN NEW;  -- no parent found: the FK / num_nonnulls checks reject the row
  END IF;
  IF NEW.scope IS NOT NULL AND NEW.scope <> p_scope THEN
    RAISE EXCEPTION 'zeusi: chunk scope % differs from parent scope %', NEW.scope, p_scope
      USING ERRCODE = 'check_violation';
  END IF;
  NEW.scope         := p_scope;
  NEW.source_kind   := coalesce(NEW.source_kind, p_kind);
  NEW.source_ts     := coalesce(NEW.source_ts, p_ts);
  NEW.source_sha256 := coalesce(NEW.source_sha256, p_sha);
  NEW.ingest_run_id := coalesce(NEW.ingest_run_id, p_run);
  IF enc THEN
    NEW.source_uri_hmac := coalesce(NEW.source_uri_hmac, p_uri_hmac);
    NEW.text_sha256     := NULL;
  ELSE
    NEW.source_uri  := coalesce(NEW.source_uri, p_uri);
    NEW.text_sha256 := sha256(convert_to(NEW.text, 'UTF8'));
  END IF;
  RETURN NEW;
END $$`;
}

/** The replacement stamp_provenance() (N2-11, R3-1): a representation-only change keeps the stamp. */
function stampProvenanceSql(s: string): string {
  return `CREATE OR REPLACE FUNCTION ${s}.stamp_provenance() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ${s} AS $$
DECLARE keep boolean := false;
BEGIN
  -- On UPDATE, keep the original stamp unless the source content changed (0001_core.sql:279-292).
  -- C5 overlay (docs/plans/2026-11-19-c5-tenant-ddl.md KTD6): an UPDATE that changes key_version
  -- (encrypt NULL->v, decrypt v->NULL, rotate v1->v2) only changes representation and keeps it too.
  IF TG_OP = 'UPDATE' THEN
    keep := NEW.source_sha256 IS NOT DISTINCT FROM OLD.source_sha256;
    IF NOT keep AND TG_TABLE_NAME IN (${OVERLAY_TABLES.map((t) => `'${t}'`).join(', ')}) THEN
      keep := NEW.key_version IS DISTINCT FROM OLD.key_version;
    END IF;
  END IF;
  IF keep THEN
    NEW.ingested_at := OLD.ingested_at;
    NEW.ingested_by := OLD.ingested_by;
  ELSE
    NEW.ingested_at := now();
    NEW.ingested_by := session_user;
  END IF;
  RETURN NEW;
END $$`;
}

function prepareTemplate(schema: string): string[] {
  const s = q(schema);
  const out: string[] = [];
  for (const t of OVERLAY_SPEC) {
    const T = `${s}.${q(t.table)}`;
    // 1. Columns (nullable, no default: no table rewrite) and the NOT NULLs / defaults they replace.
    const cols = [
      'ADD COLUMN key_version smallint',
      ...t.columns.map((c) => `ADD COLUMN ${ct(c.plain)} bytea`),
      ...t.columns.filter((c) => c.hmac).map((c) => `ADD COLUMN ${hm(c.plain)} bytea`),
      ...t.columns.filter((c) => c.required).map((c) => `ALTER COLUMN ${c.plain} DROP NOT NULL`),
      ...t.columns.filter((c) => c.dropDefault).map((c) => `ALTER COLUMN ${c.plain} DROP DEFAULT`),
      ...(t.table === 'chunks' ? ['ALTER COLUMN text_sha256 DROP NOT NULL'] : []),
    ];
    out.push(`ALTER TABLE ${T} ${cols.join(', ')}`);
    // 2. "The value is present" still holds: exactly one of plain or ciphertext.
    const plainNull = plainNullList(t).map((c) => `${c} IS NULL`);
    const cts = ctList(t);
    const hmacs = hmacList(t);
    const checks = [
      `ADD CONSTRAINT ${t.table}_key_version_range CHECK (key_version IS NULL OR key_version BETWEEN 1 AND ${OVERLAY_MAX_KEY_VERSION})`,
      ...t.columns.filter((c) => c.required).map((c) => `ADD CONSTRAINT ${t.table}_${c.plain}_present CHECK (num_nonnulls(${c.plain}, ${ct(c.plain)}) = 1)`),
      ...(t.table === 'chunks' ? ['ADD CONSTRAINT chunks_text_sha256_present CHECK (num_nonnulls(text_sha256, text_hmac) = 1)'] : []),
      ...cts.map((c) => `ADD CONSTRAINT ${t.table}_${c}_format CHECK (${c} IS NULL OR (octet_length(${c}) >= ${SEALED_MIN_BYTES} AND get_byte(${c}, 0) = ${SEALED_FORMAT_BYTE}))`),
      ...hmacs.map((c) => `ADD CONSTRAINT ${t.table}_${c}_format CHECK (${c} IS NULL OR octet_length(${c}) = ${HMAC_BYTES})`),
      // 3. A row is wholly plain or wholly encrypted (R3-1, R3-3).
      `ADD CONSTRAINT ${t.table}_enc_shape CHECK (
         (key_version IS NULL AND ${and([...cts, ...hmacs].map((c) => `${c} IS NULL`))})
         OR (key_version IS NOT NULL AND ${and([...plainNull, ...hmacs.map((c) => `${c} IS NOT NULL`)])}))`,
    ];
    out.push(`ALTER TABLE ${T} ${checks.join(', ')}`);
  }
  // 4. HMAC uniqueness (NULL-tolerant).
  for (const u of HMAC_UNIQUES) out.push(`ALTER TABLE ${s}.${q(u.table)} ADD CONSTRAINT ${u.name} UNIQUE (${u.columns})`);
  // 5. Replacement triggers (same function oids: CREATE OR REPLACE keeps the triggers and the ACL).
  out.push(chunksInheritSql(s), stampProvenanceSql(s));
  // 6. enc_progress: cursor, counts, phase and the per-key_version sealed-value counter. Numbers only.
  out.push(`CREATE TABLE ${s}.${q(ENC_PROGRESS_TABLE)} (
    key_version     smallint NOT NULL CHECK (key_version BETWEEN 1 AND ${OVERLAY_MAX_KEY_VERSION}),
    table_name      text NOT NULL CHECK (table_name IN ('all', ${OVERLAY_TABLES.map((x) => `'${x}'`).join(', ')})),
    phase           text NOT NULL DEFAULT 'idle' CHECK (phase IN ('idle', 'encrypt', 'verify', 'decrypt', 'rotate', 'done', 'stopped')),
    cursor_id       bigint NOT NULL DEFAULT 0 CHECK (cursor_id >= 0),
    rows_done       bigint NOT NULL DEFAULT 0 CHECK (rows_done >= 0),
    rows_skipped    bigint NOT NULL DEFAULT 0 CHECK (rows_skipped >= 0),
    rows_mismatched bigint NOT NULL DEFAULT 0 CHECK (rows_mismatched >= 0),
    values_sealed   bigint NOT NULL DEFAULT 0 CHECK (values_sealed >= 0),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (key_version, table_name))`);
  out.push(`REVOKE ALL ON ${s}.${q(ENC_PROGRESS_TABLE)} FROM PUBLIC`);
  return out;
}

/** Fingerprint of the prepare overlay (schema-independent), stored with the marker row. */
export const PREPARE_SHA256 = createHash('sha256').update(prepareTemplate(`zt_${'a'.repeat(26)}`).join(';\n').split(`zt_${'a'.repeat(26)}`).join('<schema>'), 'utf8').digest('hex');

/**
 * C5a prepare, in order, for one workspace schema. The caller runs it as the schema owner inside one
 * transaction, then grants enc_progress to the writer when that role exists (encProgressGrantSql).
 */
export function prepareStatements(schema: string): string[] {
  assertTenantId(schema);
  return [
    ...prepareTemplate(schema),
    `INSERT INTO ${q(schema)}.schema_migrations (filename, sha256) VALUES ('${PREPARE_MARKER}', '${PREPARE_SHA256}')`,
  ];
}

/** The <table>_enc_flipped CHECK body: no plain value and a key_version on every row. */
function flipCheck(t: OverlayTable): string {
  return and(['key_version IS NOT NULL', ...plainNullList(t).map((c) => `${c} IS NULL`)]);
}
export const flipConstraint = (table: string) => `${table}_enc_flipped`;

/**
 * C5b flip (plan §5.2a). Guards (state verified, prepared, no plain row) are the caller's; VALIDATE is
 * the backstop that fails loudly on any plain value even without them.
 */
export function flipStatements(schema: string): string[] {
  assertTenantId(schema);
  const s = q(schema);
  return [
    ...OVERLAY_SPEC.map((t) => `ALTER TABLE ${s}.${q(t.table)} ADD CONSTRAINT ${flipConstraint(t.table)} CHECK (${flipCheck(t)}) NOT VALID`),
    ...OVERLAY_SPEC.map((t) => `ALTER TABLE ${s}.${q(t.table)} VALIDATE CONSTRAINT ${flipConstraint(t.table)}`),
    `DROP INDEX ${s}.${HNSW_INDEX}`,
    `ALTER TABLE ${s}.chunks DROP COLUMN tsv`,
    ...PLAIN_UNIQUES.map((u) => `ALTER TABLE ${s}.${q(u.table)} DROP CONSTRAINT ${u.name}`),
    `DROP INDEX ${s}.${TARGET_URI_INDEX}`,
    `DELETE FROM ${s}.quarantine`,
    `DELETE FROM ${s}.wall_allow`,
    ...analyzeStatements(schema),
  ];
}

/** C5b relax: only the content-NULL CHECKs go; tsv and the plain UNIQUEs stay absent. */
export function relaxStatements(schema: string): string[] {
  assertTenantId(schema);
  return OVERLAY_SPEC.map((t) => `ALTER TABLE ${q(schema)}.${q(t.table)} DROP CONSTRAINT ${flipConstraint(t.table)}`);
}

export interface UnflipShape {
  tsv: boolean;
  tsvIndex: boolean;
  hnsw: boolean;
  uniques: readonly string[];
  targetUriIndex: boolean;
}

/**
 * C5b unflip: re-add what flip dropped (each only when missing), delete every quarantine row, ANALYZE.
 * After a pre-flip rollback everything is present, so only the quarantine delete and ANALYZE run.
 */
export function unflipStatements(schema: string, has: UnflipShape): string[] {
  assertTenantId(schema);
  const s = q(schema);
  return [
    `DELETE FROM ${s}.quarantine`,
    ...(has.tsv ? [] : [`ALTER TABLE ${s}.chunks ADD COLUMN tsv tsvector GENERATED ALWAYS AS (${TSV_EXPR}) STORED`]),
    ...(has.tsvIndex ? [] : [`CREATE INDEX ${TSV_INDEX} ON ${s}.chunks USING gin (tsv)`]),
    ...(has.hnsw ? [] : [`CREATE INDEX ${HNSW_INDEX} ON ${s}.chunks
      USING hnsw (embedding halfvec_cosine_ops) WITH (m = 16, ef_construction = 64)
      WHERE embed_model = 'openai/text-embedding-3-small@1536'`]),
    ...PLAIN_UNIQUES.filter((u) => !has.uniques.includes(u.name)).map((u) => `ALTER TABLE ${s}.${q(u.table)} ADD CONSTRAINT ${u.name} UNIQUE (${u.columns})`),
    ...(has.targetUriIndex ? [] : [`CREATE INDEX ${TARGET_URI_INDEX} ON ${s}.decision_links (target_uri)`]),
    ...analyzeStatements(schema),
  ];
}

/** ANALYZE every base table of the workspace (pg_statistic is replaced only by a new ANALYZE, §5.2 step 7). */
function analyzeStatements(schema: string): string[] {
  return [`DO $an$ DECLARE r record; BEGIN
     FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = '${schema}' AND c.relkind = 'r' ORDER BY 1 LOOP
       EXECUTE format('ANALYZE %I.%I', '${schema}', r.relname);
     END LOOP; END $an$`];
}

// ---------------------------------------------------------------------------
// Reading the overlay state (counts and catalog facts only, never a value)

export interface OverlayTableCounts {
  table: string;
  rows: number;
  /** Rows with key_version NULL (plain). Equals rows before prepare. */
  plainRows: number;
  /** Rows with key_version set (encrypted). 0 before prepare. */
  encryptedRows: number;
  /** Non-NULL *_ct values across the table. 0 before prepare. */
  ctValues: number;
}
export interface OverlayState {
  schemaExists: boolean;
  prepared: boolean;
  encProgress: boolean;
  /** How many of the five <table>_enc_flipped CHECKs exist. */
  flipChecks: number;
  shape: UnflipShape;
  tables: OverlayTableCounts[];
  /** Rows in OVERLAY_MUST_BE_EMPTY tables (flip refuses unless 0). */
  otherRows: number;
  quarantineRows: number;
  wallAllowRows: number;
}

const num = (v: unknown): number => {
  const x = Number(v);
  if (!Number.isSafeInteger(x) || x < 0) throw new Error('overlay: a count was not a number');
  return x;
};

/** The overlay state of one workspace on `db` (the caller is the schema owner, in a transaction). */
export async function readOverlayState(db: Db, schema: string): Promise<OverlayState> {
  assertTenantId(schema);
  const empty: OverlayState = {
    schemaExists: false, prepared: false, encProgress: false, flipChecks: 0,
    shape: { tsv: false, tsvIndex: false, hnsw: false, uniques: [], targetUriIndex: false },
    tables: [], otherRows: 0, quarantineRows: 0, wallAllowRows: 0,
  };
  if ((await db.query<{ n: number }>('SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = $1', [schema])).rows[0]?.n !== 1) return empty;
  const s = q(schema);
  const f = (await db.query<{ marker: boolean; ep: boolean; flips: number; tsv: boolean; tsvi: boolean; hnsw: boolean; tui: boolean; uq: string[] | null }>(
    `SELECT EXISTS (SELECT 1 FROM ${s}.schema_migrations WHERE filename = $2) AS marker,
            to_regclass(format('%I.%I', $1::text, $3::text)) IS NOT NULL AS ep,
            (SELECT count(*)::int FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = $1 AND k.contype = 'c' AND k.conname = c.relname || '_enc_flipped') AS flips,
            EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = to_regclass(format('%I.chunks', $1::text)) AND a.attname = 'tsv' AND NOT a.attisdropped) AS tsv,
            to_regclass(format('%I.%I', $1::text, $4::text)) IS NOT NULL AS tsvi,
            to_regclass(format('%I.%I', $1::text, $5::text)) IS NOT NULL AS hnsw,
            to_regclass(format('%I.%I', $1::text, $6::text)) IS NOT NULL AS tui,
            ARRAY(SELECT k.conname::text FROM pg_constraint k JOIN pg_namespace n ON n.oid = k.connamespace
                   WHERE n.nspname = $1 AND k.contype = 'u' AND k.conname = ANY ($7::text[]) ORDER BY 1) AS uq`,
    [schema, PREPARE_MARKER, ENC_PROGRESS_TABLE, TSV_INDEX, HNSW_INDEX, TARGET_URI_INDEX, PLAIN_UNIQUES.map((u) => u.name)])).rows[0]!;
  const tables: OverlayTableCounts[] = [];
  // C8-0 KTD-A "Presence": the sealed digest copy counts as a ciphertext value only where its column exists, so a
  // workspace prepared before C8-0 (not converged yet) is read without naming a missing column.
  const digestCol = f.marker
    ? new Set((await sealedDigestPresence(db, schema)).filter((p) => p.column).map((p) => p.table))
    : new Set<string>();
  for (const t of OVERLAY_SPEC) {
    const cts = [...ctList(t), ...(digestCol.has(t.table) ? [SEALED_DIGEST_COLUMN] : [])];
    const r = f.marker
      ? (await db.query<{ r: string; p: string; e: string; c: string }>(
        `SELECT count(*)::bigint AS r, count(*) FILTER (WHERE key_version IS NULL)::bigint AS p, count(key_version)::bigint AS e,
                (${cts.map((c) => `count(${c})`).join(' + ')})::bigint AS c FROM ${s}.${q(t.table)}`)).rows[0]!
      : (await db.query<{ r: string; p: string; e: string; c: string }>(
        `SELECT count(*)::bigint AS r, count(*)::bigint AS p, 0::bigint AS e, 0::bigint AS c FROM ${s}.${q(t.table)}`)).rows[0]!;
    tables.push({ table: t.table, rows: num(r.r), plainRows: num(r.p), encryptedRows: num(r.e), ctValues: num(r.c) });
  }
  const o = (await db.query<{ other: string; qr: string; wa: string }>(
    `SELECT (${OVERLAY_MUST_BE_EMPTY.map((t) => `(SELECT count(*) FROM ${s}.${q(t)})`).join(' + ')})::bigint AS other,
            (SELECT count(*) FROM ${s}.quarantine)::bigint AS qr, (SELECT count(*) FROM ${s}.wall_allow)::bigint AS wa`)).rows[0]!;
  return {
    schemaExists: true, prepared: f.marker, encProgress: f.ep, flipChecks: num(f.flips),
    shape: { tsv: f.tsv, tsvIndex: f.tsvi, hnsw: f.hnsw, uniques: f.uq ?? [], targetUriIndex: f.tui },
    tables, otherRows: num(o.other), quarantineRows: num(o.qr), wallAllowRows: num(o.wa),
  };
}

/** Rows with key_version set plus non-NULL *_ct values in the workspace (0: no ciphertext at all). */
export async function ciphertextCount(db: Db, schema: string): Promise<number> {
  const st = await readOverlayState(db, schema);
  return st.tables.reduce((a, t) => a + t.encryptedRows + t.ctValues, 0);
}

/**
 * CLI lines for one overlay step (C5 KTD14): the validated id, the step, the states, constant reasons
 * and numbers. Never a value from a row.
 */
export function formatOverlayStep(
  tenantId: string,
  r: { step: string; outcome: string; reason?: string | undefined; from: string | null; to: string | null; state: OverlayState },
): string[] {
  assertTenantId(tenantId);
  const st = r.state;
  const head = r.outcome === 'applied' ? `applied: enc_state ${r.from ?? '-'} -> ${r.to ?? '-'}`
    : r.outcome === 'would_apply' ? `dry run, nothing changed: would apply (enc_state ${r.from ?? '-'} -> ${r.to ?? '-'})`
      : `refused, nothing changed: ${r.reason ?? 'refused'}`;
  return [
    `workspace ${tenantId}: overlay ${r.step}: ${head}`,
    `  prepared ${st.prepared ? 'yes' : 'no'}; enc_progress ${st.encProgress ? 'yes' : 'no'}; flip checks ${st.flipChecks} of ${OVERLAY_TABLES.length}; `
      + `tsv ${st.shape.tsv ? 'yes' : 'no'}; plain uniques ${st.shape.uniques.length} of ${PLAIN_UNIQUES.length}`,
    ...st.tables.map((t) => `  ${t.table}: rows ${t.rows}, plain ${t.plainRows}, encrypted ${t.encryptedRows}, ciphertext values ${t.ctValues}`),
    `  other content rows ${st.otherRows}; quarantine rows ${st.quarantineRows}; wall_allow rows ${st.wallAllowRows}`,
  ];
}
