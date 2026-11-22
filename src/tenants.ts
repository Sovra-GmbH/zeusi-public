// Personal workspaces (tenants) for open GitHub sign-up
// (docs/plans/2026-11-18-open-signup-workspaces-plan.md U2, KTD2, KTD4, KTD5, KTD6, KTD9).
//
//   catalog     schema zeusi_tenants, owned by zeusi_tenant_admin, bootstrapped idempotently by the
//               provisioner: tenants (tenant_id, status, created_at) and members (subject
//               'github:<id>' PRIMARY KEY, tenant_id, created_at). Durable, in the same database
//               as the workspaces, so a workspace and its catalog rows commit together.
//   provision   ONE transaction as zeusi_tenant_admin, under one advisory lock: re-check the
//               subject, enforce the total cap, CREATE ROLE <id>_r (NOLOGIN), GRANT it to
//               zeusi_tenant_rt WITH INHERIT FALSE, SET TRUE, CREATE SCHEMA <id>, the workspace DDL
//               (src/tenant-ddl.ts), the ACL audit (any violation aborts), the catalog rows.
//               A race for the same subject reuses; nothing half-built can commit.
//   writer      (docs/plans/2026-11-18-workspace-write-import-plan.md KTD3, KTD4) provision and
//               ensureWriter create the NOLOGIN role <id>_w (own schema only, tenantWriterGrants) and
//               GRANT it to zeusi_tenant_wr WITH INHERIT FALSE, SET TRUE when that login exists.
//               TenantWriter.open: catalog check through the router, then as zeusi_tenant_wr the same
//               hygiene, SET ROLE <id>_w, search_path, and a fail-closed check (exactly that role and
//               login, no power, USAGE on its own schema only, no write privilege outside it).
//   person      provision (and only the operator backfill `zeusi workspaces backfill-people` for older
//               workspaces, never sign-in) adds the workspace's own person `me` as the provisioner
//               (WORKSPACE_PERSON_*), so a decision written as `me` is stored. No grant changes.
//   router      per request, as zeusi_tenant_rt: the workspace must be 'active' in the catalog,
//               then SET ROLE <id>_r, search_path, read-only, and a fail-closed session check
//               (expected current_user and session_user, not superuser / BYPASSRLS, USAGE on its own
//               schema only: none on zeusi, zeusi_tenants or any other zt_* schema, no write
//               privilege). The Db it returns rewrites `zeusi.` to the workspace schema (KTD4).
//   hygiene     every workspace-login session (runtime and provisioner) is RESET (role, search_path,
//               read-only default) right after connect and checked to be exactly its login
//               (current_user = session_user), and is RESET again before every close, on every
//               path (docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md U1). A session
//               left dirty by anyone (a pooled server connection) can neither serve another
//               workspace nor break the catalog check. Transaction poolers are still refused at
//               startup (src/mcp.ts hostedTenantPreflight): session state cannot work through them.
//
// Plain PostgreSQL 16+ and pgvector only: no Neon API, no neon_superuser, no CREATEDB, no
// @neondatabase/serverless. Connections come from injected factories (src/mcp.ts uses
// connectService: TCP, TLS verify-full, SCRAM channel binding). No identifier is ever built from
// caller text: workspace ids are generated here and match TENANT_ID_RE before any use.

import { createHash, randomBytes } from 'node:crypto';
import type { Db } from './db.ts';
import { listMigrations, type MigrationFile } from './migrate.ts';
import {
  assertTenantId, ENC_PROGRESS_TABLE, QUALIFIER_RE, TENANT_ACL_AUDIT_SQL, TENANT_ID_RE, tenantDdl, tenantRole, tenantWriterGrants, tenantWriterRole,
} from './tenant-ddl.ts';
import {
  b1IndexGrantSql, b1IndexStatements, encProgressGrantSql, ensureSealedDigest, flipStatements, OVERLAY_TABLES, prepareStatements, readOverlayState, relaxStatements,
  unflipStatements, type OverlayState,
} from './tenant-overlay.ts';

export const TENANT_ADMIN_ROLE = 'zeusi_tenant_admin';
export const TENANT_RT_ROLE = 'zeusi_tenant_rt';
/**
 * The writer login (docs/plans/2026-11-18-workspace-write-import-plan.md KTD3, KTD4): NOINHERIT, it
 * may SET ROLE to a workspace's `<id>_w` and nothing else. Created by the operator
 * (scripts/owner-sql/tenant-writer-role.sql); until then workspace writes stay off.
 */
export const TENANT_WR_ROLE = 'zeusi_tenant_wr';
export const CONTROL_SCHEMA = 'zeusi_tenants';
/** Total personal workspaces this server will ever create (KTD9) [estimate]. */
export const MAX_TENANTS = 200;
export const MIN_SERVER_VERSION_NUM = 160000;
/** How long an 'active' answer of TenantRouter.check() is reused. */
export const TENANT_CHECK_CACHE_MS = 30_000;
const CHECK_CACHE_MAX = 1024;
const SUBJECT_RE = /^github:[0-9]{1,20}$/;
const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
const PROVISION_LOCK = `hashtext('zeusi.tenants.provision')`;

/**
 * The workspace's own person (docs/hosting.md "The workspace person"): ONE people row per
 * workspace, handle `me`, so a headed decision / `Type: rule|focus` entry written as `me` is stored
 * (src/importers/structured.ts writeStructured resolves `who` against people; the writer role may only
 * SELECT people, TENANT_WRITER_READ_TABLES). Created by the provisioning login, which owns the
 * workspace schema: at provision (new workspaces) and by `zeusi workspaces backfill-people` (existing
 * ones, an explicit operator step). Never at sign-in. No new privilege, no DDL, no migration.
 *
 * Every column is a constant, never caller text (invent=NO):
 *   handle 'me', display_name 'me'  the handle the documented examples use (src/about.ts DECISION_EXAMPLE_*);
 *                                   no GitHub login and no name are stored (the catalog holds only a numeric subject).
 *   kind 'human'                    the person who signed in with GitHub and owns the workspace.
 *   org 'work', scope 'work'      inside a workspace these mean "this workspace" (src/workspace-write.ts WS_SCOPE, OD2);
 *                                   the CHECK allows only team | vendor.
 *   source_kind 'manual'            provenance = the provisioning step itself: source_uri WORKSPACE_PERSON_SOURCE_URI,
 *                                   source_ts now(), source_sha256 = sha256(WORKSPACE_PERSON_SOURCE_TEXT), and one
 *                                   ingest_runs row (importer WORKSPACE_PERSON_IMPORTER, host WORKSPACE_PERSON_HOST,
 *                                   mode manual, status ok). ingested_by / started_by = session_user (zeusi_tenant_admin).
 * The wall trigger on people still runs (a refusal aborts the transaction, nothing half-made).
 */
export const WORKSPACE_PERSON_HANDLE = 'me';
export const WORKSPACE_PERSON_IMPORTER = 'workspace-provision:person';
/** ingest_runs.host: the step that wrote the row (the provisioner login), not a machine name. */
export const WORKSPACE_PERSON_HOST = 'provisioner';
export const WORKSPACE_PERSON_SOURCE_URI = 'zeusi:workspace-provision/person/me';
export const WORKSPACE_PERSON_SOURCE_TEXT =
  'Workspace person `me`: the person who owns this personal workspace, created by the Zeusi workspace provisioner.';

/** Infrastructure failure (connection, catalog, DDL): the caller answers 503. Never carries a value. */
export class TenantError extends Error {
  override name = 'TenantError';
}
/** The session is not a clean workspace session, or the workspace is not active: the caller refuses. */
export class TenantRefused extends Error {
  override name = 'TenantRefused';
}
/** A workspace delete that waited too long for a lock (lock_timeout, deadlock): rolled back; retry. */
export class TenantBusy extends TenantError {
  override name = 'TenantBusy';
}
/** A workspace delete whose COMMIT did not complete: the database may or may not have committed it. */
export class TenantCommitUnknown extends TenantError {
  override name = 'TenantCommitUnknown';
}

export type TenantStatus = 'active' | 'disabled';
export type ProvisionResult =
  | { kind: 'existing'; tenantId: string; status: TenantStatus }
  | { kind: 'created'; tenantId: string; status: 'active' }
  | { kind: 'cap_reached' };

export function newTenantId(): string {
  return `zt_${[...randomBytes(26)].map((b) => BASE32[b & 31]).join('')}`;
}

const qi = (ident: string) => `"${ident.replace(/"/g, '""')}"`;

/**
 * Workspace encryption state (docs/plans/2026-11-18-zeusi-workspace-encryption.md §5.2 step 2,
 * §5.2a, §5.2b; C3 docs/plans/2026-11-18-c3-catalog-enc-state.md KTD2). One column on the catalog
 * row, default 'off'. C3 only stores it: C4 enrolls, C8 moves encrypting / verified / decrypting /
 * decrypted, the operator flip sets on / off. No transition is enforced here.
 */
export const ENC_STATES = ['off', 'enrolled', 'encrypting', 'verified', 'on', 'decrypting', 'decrypted'] as const;
export type EncState = (typeof ENC_STATES)[number];
/** Kinds of a catalog wrap (C3 KTD3). Session wraps never live here: they stay beside the grant in the OAuth store. */
export const KEY_WRAP_KINDS = ['passkey', 'recovery'] as const;
export type KeyWrapKind = (typeof KEY_WRAP_KINDS)[number];

/** A passkey wrap row as C4 writes it (C4 U1). sealedDek is a C1 wrapped DEK; the rest is not secret. */
export interface PasskeyWrapRow {
  wrapId: string;
  keyVersion: number;
  sealedDek: Buffer;
  credentialId: Buffer;
  prfSalt: Buffer;
  /**
   * The verified WebAuthn credential (docs/plans/2026-11-19-c4-webauthn-verify.md KTD5): its COSE public key
   * as attested and its signature counter. The consent page always sets it; a row without it can never
   * unlock by passkey (KTD6).
   */
  webauthn?: { publicKey: Buffer; signCount: number } | undefined;
}
export interface RecoveryWrapRow {
  wrapId: string;
  keyVersion: number;
  sealedDek: Buffer;
}
export interface StoredWrap {
  wrapId: string;
  kind: KeyWrapKind;
  keyVersion: number;
  sealedDek: Buffer;
  credentialId: Buffer | null;
  prfSalt: Buffer | null;
  /** WebAuthn COSE public key and counter (KTD5); null on a recovery row and on a pre-0017 passkey row (KTD6). */
  webauthnPublicKey: Buffer | null;
  webauthnSignCount: number | null;
}
/** The consent page's view of one workspace (C4): never a sealed DEK. */
export interface EncryptionView {
  encState: EncState;
  passkeys: Array<{ credentialId: Buffer; prfSalt: Buffer }>;
  recovery: number;
}
/**
 * Upper bound of key_wraps.key_version: MAX_KEY_VERSION of the C1 envelope module (32767, the
 * smallint maximum). A literal on purpose: the catalog does not import that module (C3 KTD10);
 * test/c3-catalog.test.ts pins the two equal.
 */
export const KEY_WRAP_MAX_KEY_VERSION = 32767;
/** A C1 wrapped DEK: format byte 0x01, 12-byte nonce, 32-byte DEK ciphertext, 16-byte tag. */
export const KEY_WRAP_SEALED_BYTES = 61;

/**
 * The one-time ADD COLUMN takes ACCESS EXCLUSIVE on tenants (and scans it once for the CHECK). It
 * waits at most this long for that lock, then fails cleanly instead of queueing every router check
 * behind it (C3 review P3-1); the next ensure retries.
 */
export const ENC_STATE_LOCK_TIMEOUT = '5s';
/**
 * C4 KTD1 (docs/plans/2026-11-18-c4-enroll.md): one live wrap row per (workspace, passkey credential).
 * Recovery rows carry NULL credential_id and are not constrained. Same index in
 * migrations/0015_key_wraps_credential_unique.sql; the ensure path creates it only when missing (no lock
 * on a converged catalog), i.e. on the FIRST catalog ensure after deploy (any sign-in, flag on or off,
 * like C3's enc_state), waiting at most ENC_STATE_LOCK_TIMEOUT for the lock.
 */
export const KEY_WRAP_CREDENTIAL_INDEX = 'key_wraps_tenant_credential_key';
/** Upper bound of key_wraps.webauthn_public_key (MAX_COSE_KEY_BYTES of src/webauthn.ts; test/c4-webauthn.test.ts pins the two equal). */
export const KEY_WRAP_MAX_COSE_BYTES = 1024;
/**
 * docs/plans/2026-11-19-c4-webauthn-verify.md KTD5: the verified WebAuthn credential of a passkey wrap. ONE
 * statement shared by the ensure path (CONTROL_DDL, guarded: only while the column is missing, bounded lock
 * wait) and migrations/0017_key_wraps_webauthn.sql (same text): two nullable columns + one CHECK.
 */
export const KEY_WRAP_WEBAUTHN_ALTER = `ALTER TABLE ${CONTROL_SCHEMA}.key_wraps
    ADD COLUMN webauthn_public_key bytea,
    ADD COLUMN webauthn_sign_count bigint,
    ADD CONSTRAINT key_wraps_webauthn_check CHECK (
      (webauthn_public_key IS NULL AND webauthn_sign_count IS NULL)
      OR (kind = 'passkey' AND webauthn_public_key IS NOT NULL AND webauthn_sign_count IS NOT NULL
          AND octet_length(webauthn_public_key) BETWEEN 1 AND ${KEY_WRAP_MAX_COSE_BYTES}
          AND webauthn_sign_count BETWEEN 0 AND 4294967295))`;
/** The catalog columns the runtime login may SELECT (C6 KTD2 added enc_state; test/c3-catalog.test.ts pins the ACL). */
export const TENANT_RT_COLUMNS: readonly string[] = ['tenant_id', 'status', 'enc_state'];
const ENC_STATE_CHECK = `CONSTRAINT tenants_enc_state_check CHECK (enc_state IN (${ENC_STATES.map((s) => `'${s}'`).join(', ')}))`;

/**
 * The catalog (C3 KTD1). Every statement converges a new AND an existing catalog: CREATE ... IF NOT
 * EXISTS for the tables, and a guarded ADD COLUMN for enc_state (a pre-C3 tenants table has none).
 * The guard keeps a converged catalog from taking ALTER TABLE's ACCESS EXCLUSIVE lock on every call,
 * and the one upgrade waits at most ENC_STATE_LOCK_TIMEOUT for it (KTD7). migrations/0014_catalog_key_wraps.sql is the same change for the recorded operator apply;
 * test/c3-catalog.test.ts pins the two paths to the same catalog.
 *
 * key_wraps (C3 KTD3, KTD4): tenant_id, wrap_id and key_version are stored exactly as the envelope's
 * wrap AAD takes them, never transformed. Nothing but the owner has any privilege on it (KTD5): the
 * runtime login keeps SELECT (tenant_id, status) on tenants and nothing on key_wraps.
 *
 * C6 (docs/plans/2026-11-19-c6-write-path.md KTD2): the runtime login also reads enc_state, a deliberate
 * column grant (migrations/0016_catalog_rt_enc_state.sql is the same change for the recorded operator
 * apply). TenantRouter.encState is its one reader (C6 write routing now, C7 reads later). Still nothing
 * on key_wraps, members, created_at.
 */
const CONTROL_DDL = `
CREATE SCHEMA IF NOT EXISTS ${CONTROL_SCHEMA};
CREATE TABLE IF NOT EXISTS ${CONTROL_SCHEMA}.tenants (
  tenant_id  text PRIMARY KEY CHECK (tenant_id ~ '^zt_[a-z2-7]{26}$'),
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  enc_state  text NOT NULL DEFAULT 'off' ${ENC_STATE_CHECK}
);
DO $c3$
DECLARE prev text := current_setting('lock_timeout');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = '${CONTROL_SCHEMA}.tenants'::regclass AND attname = 'enc_state' AND NOT attisdropped) THEN
    PERFORM set_config('lock_timeout', '${ENC_STATE_LOCK_TIMEOUT}', true);
    ALTER TABLE ${CONTROL_SCHEMA}.tenants ADD COLUMN IF NOT EXISTS enc_state text NOT NULL DEFAULT 'off' ${ENC_STATE_CHECK};
    PERFORM set_config('lock_timeout', prev, true);
  END IF;
END
$c3$;
CREATE TABLE IF NOT EXISTS ${CONTROL_SCHEMA}.members (
  subject    text PRIMARY KEY CHECK (subject ~ '^github:[0-9]{1,20}$'),
  tenant_id  text NOT NULL UNIQUE REFERENCES ${CONTROL_SCHEMA}.tenants(tenant_id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ${CONTROL_SCHEMA}.key_wraps (
  tenant_id     text NOT NULL REFERENCES ${CONTROL_SCHEMA}.tenants(tenant_id),
  wrap_id       text NOT NULL CONSTRAINT key_wraps_wrap_id_check CHECK (octet_length(wrap_id) BETWEEN 1 AND 255 AND wrap_id !~ '[\\x01-\\x1f\\x7f]'),
  kind          text NOT NULL CONSTRAINT key_wraps_kind_check CHECK (kind IN (${KEY_WRAP_KINDS.map((k) => `'${k}'`).join(', ')})),
  key_version   smallint NOT NULL CONSTRAINT key_wraps_key_version_check CHECK (key_version BETWEEN 1 AND ${KEY_WRAP_MAX_KEY_VERSION}),
  sealed_dek    bytea NOT NULL CONSTRAINT key_wraps_sealed_dek_check CHECK (octet_length(sealed_dek) = ${KEY_WRAP_SEALED_BYTES} AND substring(sealed_dek FROM 1 FOR 1) = '\\x01'::bytea),
  credential_id bytea,
  prf_salt      bytea,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT key_wraps_pkey PRIMARY KEY (tenant_id, wrap_id),
  CONSTRAINT key_wraps_shape_check CHECK (
    (kind = 'passkey' AND credential_id IS NOT NULL AND prf_salt IS NOT NULL
     AND octet_length(credential_id) BETWEEN 1 AND 1023 AND octet_length(prf_salt) = 32)
    OR (kind = 'recovery' AND credential_id IS NULL AND prf_salt IS NULL))
);
DO $c4$
DECLARE prev text := current_setting('lock_timeout');
BEGIN
  IF to_regclass('${CONTROL_SCHEMA}.${KEY_WRAP_CREDENTIAL_INDEX}') IS NULL THEN
    PERFORM set_config('lock_timeout', '${ENC_STATE_LOCK_TIMEOUT}', true);
    CREATE UNIQUE INDEX IF NOT EXISTS ${KEY_WRAP_CREDENTIAL_INDEX} ON ${CONTROL_SCHEMA}.key_wraps (tenant_id, credential_id) WHERE credential_id IS NOT NULL;
    PERFORM set_config('lock_timeout', prev, true);
  END IF;
END
$c4$;
DO $c17$
DECLARE prev text := current_setting('lock_timeout');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = '${CONTROL_SCHEMA}.key_wraps'::regclass AND attname = 'webauthn_public_key' AND NOT attisdropped) THEN
    PERFORM set_config('lock_timeout', '${ENC_STATE_LOCK_TIMEOUT}', true);
    ${KEY_WRAP_WEBAUTHN_ALTER};
    PERFORM set_config('lock_timeout', prev, true);
  END IF;
END
$c17$;
REVOKE ALL ON SCHEMA ${CONTROL_SCHEMA} FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ${CONTROL_SCHEMA} FROM PUBLIC;
REVOKE ALL ON ${CONTROL_SCHEMA}.key_wraps FROM PUBLIC;
GRANT USAGE ON SCHEMA ${CONTROL_SCHEMA} TO ${TENANT_RT_ROLE};
GRANT SELECT (${TENANT_RT_COLUMNS.join(', ')}) ON ${CONTROL_SCHEMA}.tenants TO ${TENANT_RT_ROLE};
`;

async function closeQuietly(db: Db): Promise<void> {
  await db.close().catch(() => {});
}

/**
 * Session hygiene (docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md U1, KTD1). Exactly
 * the session state the router sets (role, search_path, read-only default) goes back to the login's
 * defaults. RESET, not DISCARD ALL: works outside and on PGlite, keeps prepared statements. Neither
 * workspace login is superuser, so SET SESSION AUTHORIZATION can never have changed session_user.
 */
export const SESSION_RESET_SQL = 'RESET ROLE; RESET search_path; RESET default_transaction_read_only';

/**
 * Close a workspace-login session WITHOUT leaving state behind for whoever gets the server connection
 * next: best-effort ROLLBACK (an aborted transaction would make RESET fail), the resets, then close.
 * Never throws, so it can never mask the error a caller is already handling.
 */
export async function closeClean(db: Db, rollback = false): Promise<void> {
  if (rollback) await db.exec('ROLLBACK').catch(() => {});
  await db.exec(SESSION_RESET_SQL).catch(() => {});
  await closeQuietly(db);
}

/**
 * Acquire hygiene: reset whatever a previous user of this server connection left (a pooled leak),
 * then require current_user = session_user = `login`. Any failure closes the session and throws
 * TenantError: fail closed, nothing is read.
 */
async function resetAndAssertLogin(db: Db, login: string, what: string): Promise<void> {
  try {
    await db.exec(SESSION_RESET_SQL);
    const r = (await db.query<{ cu: string; su: string }>('SELECT current_user::text AS cu, session_user::text AS su')).rows[0];
    if (!r || r.cu !== login || r.su !== login) throw new TenantError(`${what} session refused (not a clean ${login} session after reset)`);
  } catch (e) {
    await closeClean(db);
    throw e instanceof TenantError ? e : new TenantError(`${what} session reset failed`);
  }
}

// ---------------------------------------------------------------------------
// Directory: lookup and provisioning (sign-up path only)

export interface TenantDirectoryOptions {
  /** A fresh session as zeusi_tenant_admin (closed by the directory after each operation). */
  connectAdmin: () => Promise<Db>;
  /** Expected login of that session (default zeusi_tenant_admin). */
  adminLogin?: string | undefined;
  maxTenants?: number | undefined;
  /**
   * ZEUSI_WORKSPACE_ENCRYPTION=on (C5 KTD11, KTD13): a NEW workspace is provisioned with the prepare and
   * flip overlays (src/tenant-overlay.ts) in the same transaction, before the ACL audit, and its catalog
   * row starts at enc_state 'on' with no wrap. Default false: provisioning is exactly as before C5.
   */
  bornEncrypted?: boolean | undefined;
  /** TEST seams. */
  files?: MigrationFile[] | undefined;
  newId?: (() => string) | undefined;
}

export class TenantDirectory {
  private readonly o: TenantDirectoryOptions;
  private files: MigrationFile[] | undefined;

  constructor(o: TenantDirectoryOptions) {
    this.o = o;
  }

  private migrationFiles(): MigrationFile[] {
    this.files ??= this.o.files ?? listMigrations();
    return this.files;
  }

  /** Open an admin session and check it is the provisioner and nothing more (fail closed). */
  private async admin(): Promise<Db> {
    let db: Db;
    try {
      db = await this.o.connectAdmin();
    } catch {
      throw new TenantError('workspace directory not reachable');
    }
    const login = this.o.adminLogin ?? TENANT_ADMIN_ROLE;
    await resetAndAssertLogin(db, login, 'workspace provisioner');
    try {
      const r = (await db.query<{ u: string; v: number; power: boolean; team: boolean }>(
        `SELECT session_user::text AS u, current_setting('server_version_num')::int AS v,
                coalesce((SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user), true) AS power,
                CASE WHEN to_regnamespace('zeusi') IS NULL THEN false ELSE has_schema_privilege('zeusi', 'USAGE') END AS team`)).rows[0];
      if (!r || r.u !== login || r.power || r.team) {
        throw new TenantError('workspace provisioner session refused (wrong login, too much power, or access to the zeusi schema)');
      }
      if (Number(r.v) < MIN_SERVER_VERSION_NUM) throw new TenantError('workspaces need PostgreSQL 16 or later');
      return db;
    } catch (e) {
      await closeClean(db);
      throw e instanceof TenantError ? e : new TenantError('workspace provisioner session check failed');
    }
  }

  private async ensureControl(db: Db): Promise<void> {
    await db.exec(CONTROL_DDL);
  }

  /**
   * Operator inspection (C3 `workspaces encrypt-status`): run `fn` as the provisioner (same session
   * checks as every other operation) inside a READ ONLY transaction that is always rolled back.
   * Does NOT run the catalog ensure path, so nothing at all is written. Errors other than
   * TenantError pass through unchanged (they carry no value: the callers throw constant messages).
   */
  async readOnly<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    const db = await this.admin();
    try {
      await db.exec('BEGIN TRANSACTION READ ONLY');
      return await fn(db);
    } finally {
      await closeClean(db, true);
    }
  }

  // -------------------------------------------------------------------------
  // Key wraps (C4, docs/plans/2026-11-18-c4-enroll.md U1, KTD1, KTD5). Rows hold wrapped DEKs only:
  // nothing here can unwrap (this module never imports the envelope code). Every method runs as the
  // provisioner with SET LOCAL ROLE zeusi_tenant_admin inside its own transaction; no grant changes.

  /** One transaction as zeusi_tenant_admin (SET LOCAL ROLE, then checked). Rolled back on any error. */
  private async wrapTxn<T>(write: boolean, what: string, fn: (db: Db) => Promise<T>): Promise<T> {
    const db = await this.admin();
    try {
      await db.exec(write ? 'BEGIN' : 'BEGIN TRANSACTION READ ONLY');
      await db.exec(`SET LOCAL ROLE ${TENANT_ADMIN_ROLE}`);
      const cu = (await db.query<{ cu: string }>('SELECT current_user::text AS cu')).rows[0]?.cu;
      if (cu !== TENANT_ADMIN_ROLE) throw new TenantError(`${what}: not running as ${TENANT_ADMIN_ROLE}`);
      if (write) {
        await db.query(`SELECT pg_advisory_xact_lock(${PROVISION_LOCK})`);
        await this.ensureControl(db);
      }
      const out = await fn(db);
      await db.exec(write ? 'COMMIT' : 'ROLLBACK');
      return out;
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw e instanceof TenantError || e instanceof TenantRefused ? e : new TenantError(`${what} failed`);
    } finally {
      await closeClean(db);
    }
  }

  /** The tenant row (locked FOR UPDATE when `lock`), or null when unknown or not active. */
  private async activeEncState(db: Db, tenantId: string, lock: boolean): Promise<EncState | null> {
    const r = (await db.query<{ status: string; enc_state: string }>(
      `SELECT status, enc_state FROM ${CONTROL_SCHEMA}.tenants WHERE tenant_id = $1${lock ? ' FOR UPDATE' : ''}`, [tenantId])).rows[0];
    if (!r || r.status !== 'active') return null;
    if (!(ENC_STATES as readonly string[]).includes(r.enc_state)) throw new TenantError('catalog holds an unknown enc_state');
    return r.enc_state as EncState;
  }

  /**
   * What the consent page needs (C4 U1): enc_state, the passkey credential ids and PRF salts (not
   * secret), and how many recovery wraps exist. null: unknown or disabled workspace. Never a sealed DEK.
   */
  async encryptionView(tenantId: string): Promise<EncryptionView | null> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) return null;
    return this.wrapTxn(false, 'workspace key view', async (db) => {
      const encState = await this.activeEncState(db, tenantId, false);
      if (encState === null) return null;
      const passkeys = (await db.query<{ credential_id: Uint8Array; prf_salt: Uint8Array }>(
        `SELECT credential_id, prf_salt FROM ${CONTROL_SCHEMA}.key_wraps WHERE tenant_id = $1 AND kind = 'passkey' ORDER BY created_at, wrap_id`,
        [tenantId])).rows.map((r) => ({ credentialId: Buffer.from(r.credential_id), prfSalt: Buffer.from(r.prf_salt) }));
      const recovery = (await db.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM ${CONTROL_SCHEMA}.key_wraps WHERE tenant_id = $1 AND kind = 'recovery'`, [tenantId])).rows[0]?.n ?? 0;
      return { encState, passkeys, recovery: Number(recovery) };
    });
  }

  /** The stored wraps of one kind of an ACTIVE workspace (sealed DEKs; useless without the user's secret). */
  async wrapsFor(tenantId: string, kind: KeyWrapKind): Promise<StoredWrap[]> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId) || !(KEY_WRAP_KINDS as readonly string[]).includes(kind)) return [];
    return this.wrapTxn(false, 'workspace key read', async (db) => {
      if ((await this.activeEncState(db, tenantId, false)) === null) return [];
      return (await db.query<{
        wrap_id: string; key_version: number; sealed_dek: Uint8Array; credential_id: Uint8Array | null; prf_salt: Uint8Array | null;
        webauthn_public_key: Uint8Array | null; webauthn_sign_count: string | number | null;
      }>(
        `SELECT wrap_id, key_version::int AS key_version, sealed_dek, credential_id, prf_salt, webauthn_public_key, webauthn_sign_count::text AS webauthn_sign_count
           FROM ${CONTROL_SCHEMA}.key_wraps WHERE tenant_id = $1 AND kind = $2 ORDER BY created_at, wrap_id`, [tenantId, kind])).rows.map((r) => ({
        wrapId: r.wrap_id, kind, keyVersion: Number(r.key_version), sealedDek: Buffer.from(r.sealed_dek),
        credentialId: r.credential_id === null ? null : Buffer.from(r.credential_id), prfSalt: r.prf_salt === null ? null : Buffer.from(r.prf_salt),
        webauthnPublicKey: r.webauthn_public_key === null ? null : Buffer.from(r.webauthn_public_key),
        webauthnSignCount: r.webauthn_sign_count === null ? null : Number(r.webauthn_sign_count),
      }));
    });
  }

  /**
   * First enrollment (C4 U1): in ONE transaction, with the tenant row locked, insert the first passkey
   * wrap and the recovery wrap and move enc_state off -> enrolled. Any failure rolls everything back
   * (enc_state stays off, no wrap row). 'already': the workspace is not off or already holds wraps.
   *
   * C5 KTD11 (born encrypted, flag `on`): a workspace provisioned in the flipped shape starts at 'on'
   * with no wrap. Its first enrollment inserts the same two wraps and LEAVES 'on'. Allowed only while it
   * holds no wrap, is prepared and flipped, and no row of its schema holds ciphertext, so a workspace
   * that once held ciphertext can never be given a fresh DEK by this path.
   */
  async enroll(tenantId: string, rows: { passkey: PasskeyWrapRow; recovery: RecoveryWrapRow }): Promise<'enrolled' | 'already' | 'unknown'> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) return 'unknown';
    return this.wrapTxn(true, 'workspace enrollment', async (db) => {
      const st = await this.activeEncState(db, tenantId, true);
      if (st === null) return 'unknown';
      const n = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${CONTROL_SCHEMA}.key_wraps WHERE tenant_id = $1`, [tenantId])).rows[0]?.n ?? 0;
      if ((st !== 'off' && st !== 'on') || Number(n) > 0) return 'already';
      if (st === 'on' && !bornEncryptedAndEmpty(await readOverlayState(db, tenantId))) return 'already';
      const p = rows.passkey;
      await db.query(
        `INSERT INTO ${CONTROL_SCHEMA}.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek, credential_id, prf_salt, webauthn_public_key, webauthn_sign_count)
         VALUES ($1, $2, 'passkey', $3, $4, $5, $6, $7, $8)`,
        [tenantId, p.wrapId, p.keyVersion, p.sealedDek, p.credentialId, p.prfSalt, p.webauthn?.publicKey ?? null, p.webauthn?.signCount ?? null]);
      const r = rows.recovery;
      await db.query(
        `INSERT INTO ${CONTROL_SCHEMA}.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek) VALUES ($1, $2, 'recovery', $3, $4)`,
        [tenantId, r.wrapId, r.keyVersion, r.sealedDek]);
      if (st === 'on') return 'enrolled'; // born encrypted: the state stays 'on' (C5 KTD11)
      const moved = await db.query<{ tenant_id: string }>(
        `UPDATE ${CONTROL_SCHEMA}.tenants SET enc_state = 'enrolled' WHERE tenant_id = $1 AND enc_state = 'off' RETURNING tenant_id`, [tenantId]);
      if (moved.rows.length !== 1) throw new TenantError('workspace enrollment lost its state');
      return 'enrolled';
    });
  }

  /**
   * Add or replace the passkey wrap of one credential of an ENROLLED workspace (C4 KTD1): the UNIQUE
   * (tenant_id, credential_id) makes a re-enroll of the same credential an UPDATE of its row in this
   * one transaction, never a second live row. 'not_enrolled' while enc_state is off or the workspace
   * holds no wrap yet (a born-encrypted workspace is 'on' before its first enrollment, C5 KTD11).
   */
  async putPasskeyWrap(tenantId: string, row: PasskeyWrapRow): Promise<'inserted' | 'updated' | 'not_enrolled' | 'unknown'> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) return 'unknown';
    return this.wrapTxn(true, 'workspace passkey wrap', async (db) => {
      const st = await this.activeEncState(db, tenantId, true);
      if (st === null) return 'unknown';
      if (st === 'off') return 'not_enrolled';
      const n = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${CONTROL_SCHEMA}.key_wraps WHERE tenant_id = $1`, [tenantId])).rows[0]?.n ?? 0;
      if (Number(n) === 0) return 'not_enrolled';
      const r = (await db.query<{ inserted: boolean }>(
        `INSERT INTO ${CONTROL_SCHEMA}.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek, credential_id, prf_salt, webauthn_public_key, webauthn_sign_count)
         VALUES ($1, $2, 'passkey', $3, $4, $5, $6, $7, $8)
         ON CONFLICT (tenant_id, credential_id) WHERE credential_id IS NOT NULL
         DO UPDATE SET wrap_id = EXCLUDED.wrap_id, key_version = EXCLUDED.key_version, sealed_dek = EXCLUDED.sealed_dek,
                       prf_salt = EXCLUDED.prf_salt, webauthn_public_key = EXCLUDED.webauthn_public_key,
                       webauthn_sign_count = EXCLUDED.webauthn_sign_count, created_at = now()
         RETURNING (xmax = 0) AS inserted`,
        [tenantId, row.wrapId, row.keyVersion, row.sealedDek, row.credentialId, row.prfSalt, row.webauthn?.publicKey ?? null, row.webauthn?.signCount ?? null])).rows[0];
      return r?.inserted ? 'inserted' : 'updated';
    });
  }

  /**
   * Advance the WebAuthn signature counter of one passkey wrap from `from` to `to` (KTD2), compare-and-swap:
   * true only when exactly that row of an ACTIVE workspace still held `from` (and a stored key). A
   * concurrent unlock that already moved it makes this false, and the caller refuses. 0 -> 0 (an authenticator
   * without a counter) is allowed and still requires the row and its stored key.
   */
  async advanceSignCount(tenantId: string, credentialId: Buffer, from: number, to: number): Promise<boolean> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) return false;
    if (![from, to].every((n) => Number.isSafeInteger(n) && n >= 0 && n <= 0xffff_ffff) || (to <= from && !(to === 0 && from === 0))) return false;
    return this.wrapTxn(true, 'workspace passkey counter', async (db) => {
      if ((await this.activeEncState(db, tenantId, false)) === null) return false;
      const r = await db.query<{ wrap_id: string }>(
        `UPDATE ${CONTROL_SCHEMA}.key_wraps SET webauthn_sign_count = $4
          WHERE tenant_id = $1 AND kind = 'passkey' AND credential_id = $2 AND webauthn_public_key IS NOT NULL AND webauthn_sign_count = $3
          RETURNING wrap_id`, [tenantId, credentialId, from, to]);
      return r.rows.length === 1;
    });
  }

  /** The workspace of a subject, or null. Never creates anything but the (empty) catalog. */
  async lookup(subject: string): Promise<{ tenantId: string; status: TenantStatus } | null> {
    if (!SUBJECT_RE.test(subject)) throw new TenantRefused('not a GitHub subject');
    const db = await this.admin();
    try {
      await db.exec('BEGIN');
      await db.query(`SELECT pg_advisory_xact_lock(${PROVISION_LOCK})`);
      await this.ensureControl(db);
      const r = await this.memberOf(db, subject);
      await db.exec('COMMIT');
      return r;
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw e instanceof TenantError || e instanceof TenantRefused ? e : new TenantError('workspace lookup failed');
    } finally {
      await closeClean(db);
    }
  }

  private async memberOf(db: Db, subject: string): Promise<{ tenantId: string; status: TenantStatus } | null> {
    const r = (await db.query<{ tenant_id: string; status: TenantStatus }>(
      `SELECT t.tenant_id, t.status FROM ${CONTROL_SCHEMA}.members m JOIN ${CONTROL_SCHEMA}.tenants t USING (tenant_id) WHERE m.subject = $1`,
      [subject])).rows[0];
    if (!r) return null;
    if (!TENANT_ID_RE.test(r.tenant_id)) throw new TenantError('catalog holds a malformed workspace id');
    return { tenantId: r.tenant_id, status: r.status === 'active' ? 'active' : 'disabled' };
  }

  /**
   * The writer role of one workspace, idempotently (inside the caller's transaction, as the
   * provisioner): create `<id>_w` if missing, its grants, the missing tenant_write policies, and its
   * membership in the writer login when that login exists. Returns whether the login holds it now.
   */
  private async writerIn(db: Db, tenantId: string): Promise<boolean> {
    assertTenantId(tenantId);
    const w = tenantWriterRole(tenantId);
    const has = (await db.query<{ n: number }>('SELECT count(*)::int AS n FROM pg_roles WHERE rolname = $1', [w])).rows[0]?.n === 1;
    if (!has) await db.exec(`CREATE ROLE ${qi(w)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT`);
    const g = tenantWriterGrants(tenantId);
    for (const sql of g.grants) await db.exec(sql);
    const present = new Set((await db.query<{ t: string }>(
      `SELECT c.relname::text AS t FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND p.polname = 'tenant_write'`, [tenantId])).rows.map((r) => r.t));
    for (const p of g.policies) if (!present.has(p.table)) await db.exec(p.sql);
    // R3-5 (C5 KTD8): a prepared workspace has enc_progress; its writer grant is restored here whenever
    // the table exists (a re-created writer role, a backfill). Absent table (flag off): nothing extra.
    const ep = (await db.query<{ ok: boolean }>(`SELECT to_regclass(format('%I.%I', $1::text, $2::text)) IS NOT NULL AS ok`, [tenantId, ENC_PROGRESS_TABLE])).rows[0]?.ok;
    if (ep) {
      await db.exec(encProgressGrantSql(tenantId));
      // C7 KTD5: a prepared workspace has the B1 index table (created here if it was prepared before C7) and
      // its grants; idempotent. Absent enc_progress (flag off, never prepared): nothing extra.
      for (const stmt of b1IndexStatements(tenantId)) await db.exec(stmt);
      await db.exec(b1IndexGrantSql(tenantId));
      // C8-0 KTD-A: the sealed digest copy column and its CHECKs, check-then-alter (no ALTER once converged), so a
      // workspace prepared before C8-0 converges at its next sign-in or at backfill-writers --real.
      await ensureSealedDigest(db, tenantId, ENC_STATE_LOCK_TIMEOUT);
    }
    const login = (await db.query<{ n: number }>('SELECT count(*)::int AS n FROM pg_roles WHERE rolname = $1', [TENANT_WR_ROLE])).rows[0]?.n === 1;
    if (!login) return false;
    const member = (await db.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
        WHERE r.rolname = $1 AND u.rolname = $2`, [w, TENANT_WR_ROLE])).rows[0]?.n === 1;
    if (!member) await db.exec(`GRANT ${qi(w)} TO ${TENANT_WR_ROLE} WITH INHERIT FALSE, SET TRUE`);
    await this.assertWriterRole(db, w);
    return true;
  }

  /**
   * The writer role is exactly what writerIn makes, whoever created it: no attribute, a member of no
   * role, held only by zeusi_tenant_wr (SET TRUE, INHERIT FALSE). Anything else aborts (TenantError).
   */
  private async assertWriterRole(db: Db, w: string): Promise<void> {
    const r = (await db.query<{ bad_attr: boolean; member_of: number; holders: number }>(
      `SELECT (rolcanlogin OR rolsuper OR rolinherit OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls) AS bad_attr,
              (SELECT count(*)::int FROM pg_auth_members m WHERE m.member = r.oid) AS member_of,
              (SELECT count(*)::int FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member
                WHERE m.roleid = r.oid AND NOT (u.rolname = $2 AND m.set_option AND NOT m.inherit_option)
                  AND u.rolname <> current_user) AS holders
         FROM pg_roles r WHERE r.rolname = $1`, [w, TENANT_WR_ROLE])).rows[0];
    if (!r || r.bad_attr || Number(r.member_of) > 0 || Number(r.holders) > 0) {
      throw new TenantError('workspace writer role is not as provisioned (attributes or memberships); refusing');
    }
  }

  /**
   * Ensure the writer role of one ACTIVE workspace (sign-in path: a returning user re-consents and
   * gets a writer role if an older provisioning had none). One transaction, the ACL audit re-run.
   * Returns 'ready' (granted to the writer login), 'no_login' (role ready, login not created yet),
   * or 'unknown' (no such active workspace). Throws TenantError on infra.
   */
  async ensureWriter(tenantId: string): Promise<'ready' | 'no_login' | 'unknown'> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) return 'unknown';
    const db = await this.admin();
    try {
      await db.exec('BEGIN');
      await db.query(`SELECT pg_advisory_xact_lock(${PROVISION_LOCK})`);
      await this.ensureControl(db);
      const st = (await db.query<{ status: string }>(`SELECT status FROM ${CONTROL_SCHEMA}.tenants WHERE tenant_id = $1`, [tenantId])).rows[0]?.status;
      if (st !== 'active' || (await db.query<{ n: number }>('SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = $1', [tenantId])).rows[0]?.n !== 1) {
        await db.exec('ROLLBACK');
        return 'unknown';
      }
      const granted = await this.writerIn(db, tenantId);
      const bad = (await db.query<{ kind: string }>(TENANT_ACL_AUDIT_SQL, [tenantId, tenantRole(tenantId)])).rows;
      if (bad.length > 0) throw new TenantError(`workspace ACL audit failed (${bad.length} object(s) granted beyond the workspace roles)`);
      await db.exec('COMMIT');
      return granted ? 'ready' : 'no_login';
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw e instanceof TenantError || e instanceof TenantRefused ? e : new TenantError('workspace writer setup failed');
    } finally {
      await closeClean(db);
    }
  }

  /**
   * Backfill (operator: `zeusi workspaces backfill-writers`): ensureWriter for every active workspace
   * in the catalog. dryRun: counts only, nothing changed. Counts only leave this method.
   */
  async backfillWriters(o: { dryRun: boolean }): Promise<{ active: number; ready: number; no_login: number; failed: number; missing_role: number }> {
    const db = await this.admin();
    let ids: string[];
    let missing = 0;
    try {
      await this.ensureControl(db);
      ids = (await db.query<{ tenant_id: string }>(`SELECT tenant_id FROM ${CONTROL_SCHEMA}.tenants WHERE status = 'active' ORDER BY tenant_id`)).rows
        .map((r) => r.tenant_id).filter((t) => TENANT_ID_RE.test(t));
      missing = (await db.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM unnest($1::text[]) AS t(id) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = t.id || '_w')`, [ids])).rows[0]?.n ?? 0;
    } catch (e) {
      throw e instanceof TenantError ? e : new TenantError('workspace backfill listing failed');
    } finally {
      await closeClean(db);
    }
    const out = { active: ids.length, ready: 0, no_login: 0, failed: 0, missing_role: missing };
    if (o.dryRun) return out;
    for (const id of ids) {
      try {
        const r = await this.ensureWriter(id);
        if (r === 'ready') out.ready++;
        else if (r === 'no_login') out.no_login++;
      } catch {
        out.failed++;
      }
    }
    return out;
  }

  /**
   * The workspace person (WORKSPACE_PERSON_HANDLE), idempotently, inside the caller's transaction as
   * the provisioner (the schema owner). Touches only `<tenantId>.ingest_runs` and `<tenantId>.people`.
   */
  private async personIn(db: Db, tenantId: string): Promise<'created' | 'exists'> {
    assertTenantId(tenantId);
    const s = qi(tenantId);
    const has = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${s}.people WHERE handle = $1`, [WORKSPACE_PERSON_HANDLE])).rows[0]?.n === 1;
    if (has) return 'exists';
    const run = (await db.query<{ id: number }>(
      `INSERT INTO ${s}.ingest_runs (importer, host, mode, status, finished_at, counts)
       VALUES ($1, $2, 'manual', 'ok', now(), $3::jsonb) RETURNING id::int AS id`,
      [WORKSPACE_PERSON_IMPORTER, WORKSPACE_PERSON_HOST, JSON.stringify({ inserted: 1 })])).rows[0]!.id;
    const sha = createHash('sha256').update(WORKSPACE_PERSON_SOURCE_TEXT, 'utf8').digest('hex');
    await db.query(
      `INSERT INTO ${s}.people (handle, display_name, kind, org, github_login, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1, $1, 'human', 'work', NULL, 'work', 'manual', $2, now(), decode($3, 'hex'), $4)`,
      [WORKSPACE_PERSON_HANDLE, WORKSPACE_PERSON_SOURCE_URI, sha, run]);
    return 'created';
  }

  /**
   * Ensure the workspace person of one ACTIVE workspace (operator backfill only; never called at
   * sign-in). One transaction under the provisioning lock. 'created', 'exists', or 'unknown' (no such
   * active workspace). Throws TenantError on infra.
   */
  async ensurePerson(tenantId: string): Promise<'created' | 'exists' | 'unknown'> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) return 'unknown';
    const db = await this.admin();
    try {
      await db.exec('BEGIN');
      await db.query(`SELECT pg_advisory_xact_lock(${PROVISION_LOCK})`);
      await this.ensureControl(db);
      const st = (await db.query<{ status: string }>(`SELECT status FROM ${CONTROL_SCHEMA}.tenants WHERE tenant_id = $1`, [tenantId])).rows[0]?.status;
      if (st !== 'active' || (await db.query<{ n: number }>('SELECT count(*)::int AS n FROM pg_namespace WHERE nspname = $1', [tenantId])).rows[0]?.n !== 1) {
        await db.exec('ROLLBACK');
        return 'unknown';
      }
      const r = await this.personIn(db, tenantId);
      await db.exec('COMMIT');
      return r;
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw e instanceof TenantError || e instanceof TenantRefused ? e : new TenantError('workspace person setup failed');
    } finally {
      await closeClean(db);
    }
  }

  /**
   * Backfill (operator: `zeusi workspaces backfill-people`): ensurePerson for every active workspace
   * whose person is missing. dryRun: counts only, nothing changed. Counts only leave this method.
   */
  async backfillPeople(o: { dryRun: boolean }): Promise<{ active: number; missing_person: number; ready: number; failed: number }> {
    const db = await this.admin();
    const missing: string[] = [];
    let active = 0;
    try {
      await this.ensureControl(db);
      const ids = (await db.query<{ tenant_id: string }>(`SELECT tenant_id FROM ${CONTROL_SCHEMA}.tenants WHERE status = 'active' ORDER BY tenant_id`)).rows
        .map((r) => r.tenant_id).filter((t) => TENANT_ID_RE.test(t));
      active = ids.length;
      for (const id of ids) {
        const schema = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = $1 AND c.relname = 'people' AND c.relkind = 'r'`, [id])).rows[0]?.n === 1;
        const has = schema && (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${qi(id)}.people WHERE handle = $1`, [WORKSPACE_PERSON_HANDLE])).rows[0]?.n === 1;
        if (!has) missing.push(id);
      }
    } catch (e) {
      throw e instanceof TenantError ? e : new TenantError('workspace backfill listing failed');
    } finally {
      await closeClean(db);
    }
    // ready: workspaces that hold their person after this run (created now, or by a concurrent provision).
    const out = { active, missing_person: missing.length, ready: 0, failed: 0 };
    if (o.dryRun) return out;
    for (const id of missing) {
      try {
        const r = await this.ensurePerson(id);
        if (r === 'unknown') out.failed++;
        else out.ready++;
      } catch {
        out.failed++;
      }
    }
    return out;
  }

  /** Create-or-reuse the workspace of `subject` (one transaction; see the header). */
  async provision(subject: string): Promise<ProvisionResult> {
    if (!SUBJECT_RE.test(subject)) throw new TenantRefused('not a GitHub subject');
    const db = await this.admin();
    try {
      await db.exec('BEGIN');
      await db.query(`SELECT pg_advisory_xact_lock(${PROVISION_LOCK})`);
      await this.ensureControl(db);
      const existing = await this.memberOf(db, subject);
      if (existing) {
        await db.exec('COMMIT');
        return { kind: 'existing', ...existing };
      }
      const n = Number((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${CONTROL_SCHEMA}.tenants`)).rows[0]?.n ?? 0);
      if (n >= (this.o.maxTenants ?? MAX_TENANTS)) {
        await db.exec('ROLLBACK');
        return { kind: 'cap_reached' };
      }
      const tenantId = (this.o.newId ?? newTenantId)();
      assertTenantId(tenantId);
      const role = tenantRole(tenantId);
      // The workspace role: no login, no attributes. The runtime login may SET ROLE to it but never
      // inherits its privileges implicitly. PostgreSQL 16+ gives the creator ADMIN on it, nothing more.
      await db.exec(`CREATE ROLE ${qi(role)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT`);
      await db.exec(`GRANT ${qi(role)} TO ${TENANT_RT_ROLE} WITH INHERIT FALSE, SET TRUE`);
      await db.exec(`CREATE SCHEMA ${qi(tenantId)}`);
      // Unqualified names in the DDL resolve to the workspace schema first (pgvector types: public).
      await db.exec(`SET LOCAL search_path = ${qi(tenantId)}, public`);
      const ddl = tenantDdl(tenantId, this.migrationFiles());
      await db.exec(ddl.statements.join(';\n'));
      // Flag `on` (C5 KTD11): born in the encrypted shape. The workspace is empty, so flip's VALIDATE
      // passes; writerIn below grants enc_progress (R3-5) and adds the C8-0 sealed digest copy (it runs
      // ensureSealedDigest whenever enc_progress exists: the one call site for this path); the ACL audit runs after both.
      if (this.o.bornEncrypted) await db.exec([...prepareStatements(tenantId), ...flipStatements(tenantId), ...b1IndexStatements(tenantId)].join(';\n'));
      await this.writerIn(db, tenantId);
      // The workspace's own person (`me`), so a decision written as `me` is stored, not kept as a note.
      await this.personIn(db, tenantId);
      const bad = (await db.query<{ kind: string; name: string }>(TENANT_ACL_AUDIT_SQL, [tenantId, role])).rows;
      if (bad.length > 0) throw new TenantError(`workspace ACL audit failed (${bad.length} object(s) granted beyond the workspace role)`);
      await db.query(`INSERT INTO ${CONTROL_SCHEMA}.tenants (tenant_id, status, enc_state) VALUES ($1, 'active', $2)`,
        [tenantId, this.o.bornEncrypted ? 'on' : 'off']);
      await db.query(`INSERT INTO ${CONTROL_SCHEMA}.members (subject, tenant_id) VALUES ($1, $2)`, [subject, tenantId]);
      await db.exec('COMMIT');
      return { kind: 'created', tenantId, status: 'active' };
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw e instanceof TenantError || e instanceof TenantRefused ? e : new TenantError('workspace provisioning failed');
    } finally {
      await closeClean(db);
    }
  }

  /**
   * Operator overlay step on ONE workspace (C5 KTD9, KTD10, KTD14; CLI `zeusi workspaces overlay`). No
   * key, no content: the result carries the state, the counts and a constant reason. dryRun: one READ
   * ONLY transaction, always rolled back, nothing written (not even the catalog ensure). Real: ONE
   * transaction as zeusi_tenant_admin under the provisioning lock with the tenant row locked and
   * lock_timeout 5s: guard, the step's SQL, the ACL audit, the enc_state move. Any failure (a VALIDATE
   * that finds plain text, a duplicate for a re-added UNIQUE, a lock timeout) rolls everything back and
   * throws TenantError naming the step and SQLSTATE only: the state does not move.
   */
  async overlayStep(tenantId: string, step: OverlayStep, o: { dryRun: boolean }): Promise<OverlayStepResult> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) throw new TenantRefused('not a workspace id');
    if (!(OVERLAY_STEPS as readonly string[]).includes(step)) throw new TenantRefused('not an overlay step');
    const db = await this.admin();
    try {
      await db.exec(o.dryRun ? 'BEGIN TRANSACTION READ ONLY' : 'BEGIN');
      if (!o.dryRun) {
        await db.query(`SELECT pg_advisory_xact_lock(${PROVISION_LOCK})`);
        await this.ensureControl(db);
        await db.exec(`SET LOCAL lock_timeout = '${ENC_STATE_LOCK_TIMEOUT}'`);
      }
      await db.exec(`SET LOCAL search_path = ${qi(tenantId)}, public`);
      const from = await this.activeEncState(db, tenantId, !o.dryRun);
      const before = await readOverlayState(db, tenantId);
      const reason = from === null ? 'no such active workspace' : !before.schemaExists ? 'the workspace schema does not exist' : overlayGuard(step, from, before);
      if (reason !== null || o.dryRun) {
        await db.exec('ROLLBACK');
        return { step, outcome: reason !== null ? 'refused' : 'would_apply', ...(reason !== null ? { reason } : {}), from, to: reason !== null ? from : OVERLAY_STEP_TO[step] ?? from, state: before };
      }
      const sql = step === 'prepare' ? prepareStatements(tenantId)
        : step === 'flip' ? flipStatements(tenantId)
          : step === 'relax' ? relaxStatements(tenantId)
            : step === 'unflip' ? unflipStatements(tenantId, before.shape)
              : [];
      try {
        for (const stmt of sql) await db.exec(stmt);
        if (step === 'prepare') {
          for (const stmt of b1IndexStatements(tenantId)) await db.exec(stmt); // C7 KTD5
          await ensureSealedDigest(db, tenantId, ENC_STATE_LOCK_TIMEOUT); // C8-0 KTD-A
          const w = (await db.query<{ n: number }>('SELECT count(*)::int AS n FROM pg_roles WHERE rolname = $1', [tenantWriterRole(tenantId)])).rows[0]?.n === 1;
          if (w) {
            await db.exec(encProgressGrantSql(tenantId));
            await db.exec(b1IndexGrantSql(tenantId));
          }
        }
      } catch (e) {
        throw new TenantError(`workspace overlay ${step} failed${sqlStateTail(e)}; rolled back, nothing changed`);
      }
      const bad = (await db.query<{ kind: string }>(TENANT_ACL_AUDIT_SQL, [tenantId, tenantRole(tenantId)])).rows;
      if (bad.length > 0) throw new TenantError(`workspace ACL audit failed (${bad.length} object(s) granted beyond the workspace roles)`);
      const to = OVERLAY_STEP_TO[step] ?? from!;
      if (to !== from) {
        const moved = await db.query<{ tenant_id: string }>(
          `UPDATE ${CONTROL_SCHEMA}.tenants SET enc_state = $2 WHERE tenant_id = $1 AND enc_state = $3 RETURNING tenant_id`, [tenantId, to, from]);
        if (moved.rows.length !== 1) throw new TenantError(`workspace overlay ${step} lost its state`);
      }
      const after = await readOverlayState(db, tenantId);
      await db.exec('COMMIT');
      return { step, outcome: 'applied', from, to, state: after };
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw e instanceof TenantError || e instanceof TenantRefused ? e : new TenantError(`workspace overlay ${step} failed`);
    } finally {
      await closeClean(db);
    }
  }

  /**
   * Operator delete of ONE personal workspace (CLI `zeusi workspaces delete`; docs/plans/2026-11-20-workspaces-delete.md
   * KTD1-KTD6). Anything but a workspace id (`team`, `zeusi` and every other name) is refused BEFORE a connection;
   * every identifier below is derived from that validated id only, every value is a bind parameter. As the provisioner
   * (admin(): not superuser, not BYPASSRLS, no USAGE on `zeusi`), which created every object removed here.
   *   dryRun  one READ ONLY transaction, always rolled back: the state only (no advisory lock, no catalog ensure).
   *   apply   ONE transaction, in this order: lock_timeout 5s, provisioning advisory lock, catalog ensure; the state;
   *           the outside fingerprint F0; DELETE the key_wraps, members and tenants rows of the id; DROP SCHEMA IF EXISTS
   *           <id> CASCADE (its tables, functions, privileges and policies); DROP ROLE IF EXISTS <id>_r, <id>_w (their
   *           memberships go with them); F1 must equal F0 (CASCADE reached nothing outside the schema, KTD5); nothing of
   *           the id may be left (rows, schema, roles, memberships, shared dependencies); COMMIT. Any failure rolls
   *           everything back and throws TenantError (TenantBusy for a lock wait; TenantCommitUnknown when COMMIT itself
   *           did not complete): a constant text and the SQLSTATE only.
   * The OAuth grants are not here (a file, not Postgres): src/workspace-delete.ts revokes them before and after (KTD4).
   * Idempotent: a second run, or a well-formed id that never existed, removes nothing and reports zeros.
   */
  async deleteWorkspace(tenantId: string, o: { dryRun: boolean }): Promise<WorkspaceDeleteResult> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) throw new TenantRefused('not a workspace id');
    const what = o.dryRun ? 'workspace delete dry run' : 'workspace delete';
    const db = await this.admin();
    try {
      await db.exec(o.dryRun ? 'BEGIN TRANSACTION READ ONLY' : 'BEGIN');
      // First, so every wait below is bounded, the provisioning lock and the catalog ensure included (TenantBusy).
      await db.exec(`SET LOCAL lock_timeout = '${ENC_STATE_LOCK_TIMEOUT}'`);
      if (!o.dryRun) {
        await db.query(`SELECT pg_advisory_xact_lock(${PROVISION_LOCK})`);
        await this.ensureControl(db);
      }
      await db.exec(`SET LOCAL search_path = pg_catalog, pg_temp`);
      const before = await this.deleteState(db, tenantId);
      if (o.dryRun) {
        await db.exec('ROLLBACK');
        return { tenantId, dryRun: true, before: before.state, removed: { tenants: 0, members: 0, keyWraps: 0, schemas: 0, roles: 0, rows: 0 } };
      }
      const f0 = await outsideFingerprint(db, tenantId);
      const del = async (table: 'key_wraps' | 'members' | 'tenants') =>
        (await db.query(`DELETE FROM ${CONTROL_SCHEMA}.${table} WHERE tenant_id = $1 RETURNING 1 AS gone`, [tenantId])).rows.length;
      // The two foreign keys point at tenants: its row goes last.
      const keyWraps = await del('key_wraps');
      const members = await del('members');
      const tenants = await del('tenants');
      await db.exec(`DROP SCHEMA IF EXISTS ${qi(tenantId)} CASCADE`);
      await db.exec(`DROP ROLE IF EXISTS ${qi(tenantRole(tenantId))}`);
      await db.exec(`DROP ROLE IF EXISTS ${qi(tenantWriterRole(tenantId))}`);
      const changed = fingerprintChanges(f0, await outsideFingerprint(db, tenantId));
      if (changed.length > 0) {
        throw new TenantError(`workspace delete would also remove objects outside the workspace schema (${changed.join(', ')}); rolled back, nothing changed`);
      }
      if (await this.deleteLeftovers(db, tenantId, before)) throw new TenantError('workspace delete left part of the workspace behind; rolled back, nothing changed');
      try {
        await db.exec('COMMIT');
      } catch (e) {
        throw new TenantCommitUnknown(`workspace delete: COMMIT did not complete${sqlStateTail(e)}; the outcome is unknown: run the dry run to see what is left`);
      }
      // The catalog counts are what the DELETEs removed; the rest is what the state held (the drops removed all of it).
      return { tenantId, dryRun: false, before: before.state, removed: { ...deleteCountsOf(before.state), tenants, members, keyWraps } };
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw deleteError(e, what);
    } finally {
      await closeClean(db);
    }
  }

  /**
   * One workspace as the provisioner sees it, inside the caller's transaction: its catalog rows (the catalog may not exist
   * yet: a dry run never creates it), its schema with every table's row count, and its two roles. Never reads a value.
   */
  private async deleteState(db: Db, tenantId: string): Promise<DeleteStateRead> {
    assertTenantId(tenantId);
    const cat = (await db.query<{ t: boolean; m: boolean; k: boolean }>(
      `SELECT to_regclass('${CONTROL_SCHEMA}.tenants') IS NOT NULL AS t, to_regclass('${CONTROL_SCHEMA}.members') IS NOT NULL AS m,
              to_regclass('${CONTROL_SCHEMA}.key_wraps') IS NOT NULL AS k`)).rows[0];
    const rowsOf = async (present: boolean | undefined, table: 'tenants' | 'members' | 'key_wraps') => (present
      ? Number((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${CONTROL_SCHEMA}.${table} WHERE tenant_id = $1`, [tenantId])).rows[0]?.n ?? 0)
      : 0);
    const tenants = await rowsOf(cat?.t, 'tenants');
    const members = await rowsOf(cat?.m, 'members');
    const keyWraps = await rowsOf(cat?.k, 'key_wraps');
    const ns = (await db.query<{ oid: string; usage: boolean }>(
      `SELECT oid::int8::text AS oid, has_schema_privilege(oid, 'USAGE') AS usage FROM pg_namespace WHERE nspname = $1`, [tenantId])).rows[0];
    const tables: WorkspaceDbState['tables'] = [];
    let rows = 0;
    if (ns) {
      const rels = (await db.query<{ t: string; readable: boolean }>(
        `SELECT c.relname::text AS t, has_table_privilege(c.oid, 'SELECT') AS readable FROM pg_class c
          WHERE c.relnamespace = $1::int8::oid AND c.relkind IN ('r', 'p') AND NOT c.relispartition ORDER BY 1`, [ns.oid])).rows;
      for (const r of rels) {
        const n = ns.usage && r.readable ? Number((await db.query<{ n: string }>(`SELECT count(*)::text AS n FROM ${qi(tenantId)}.${qi(r.t)}`)).rows[0]?.n ?? 0) : null;
        if (n !== null) rows += n;
        tables.push({ table: SAFE_TABLE_RE.test(r.t) ? r.t : TABLE_NAME_HIDDEN, rows: n });
      }
    }
    const roles: WorkspaceRoleState[] = [];
    const roleOids: number[] = [];
    for (const [role, login] of [[tenantRole(tenantId), TENANT_RT_ROLE], [tenantWriterRole(tenantId), TENANT_WR_ROLE]] as const) {
      const r = (await db.query<{ oid: string; admin: boolean; held: boolean; other: number }>(
        `SELECT r.oid::int8::text AS oid,
                EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE m.roleid = r.oid AND u.rolname = current_user AND m.admin_option) AS admin,
                EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE m.roleid = r.oid AND u.rolname = $2) AS held,
                (SELECT count(*)::int FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE m.roleid = r.oid AND u.rolname NOT IN ($2, current_user))
                  + (SELECT count(*)::int FROM pg_auth_members m WHERE m.member = r.oid) AS other
           FROM pg_roles r WHERE r.rolname = $1`, [role, login])).rows[0];
      if (r) roleOids.push(Number(r.oid));
      roles.push({ role, exists: r !== undefined, admin: r?.admin === true, held: r?.held === true, otherMemberships: Number(r?.other ?? 0) });
    }
    return { state: { tenants, members, keyWraps, schema: ns !== undefined, roles, tables, rows }, nsOid: ns ? Number(ns.oid) : null, roleOids };
  }

  /**
   * After the drops (KTD3 step 8): true when anything of the workspace is still there (a catalog row, the schema, a role)
   * or still points at what was dropped (a membership, a shared dependency of the old role oids, a dependency on the old
   * schema oid). The caller then rolls back: fail closed.
   */
  private async deleteLeftovers(db: Db, tenantId: string, before: DeleteStateRead): Promise<boolean> {
    const s = (await this.deleteState(db, tenantId)).state;
    if (s.tenants + s.members + s.keyWraps > 0 || s.schema || s.roles.some((r) => r.exists)) return true;
    const n = (await db.query<{ n: number }>(
      `SELECT (SELECT count(*)::int FROM pg_auth_members
                WHERE roleid::int8 = ANY ($1::int8[]) OR member::int8 = ANY ($1::int8[]) OR grantor::int8 = ANY ($1::int8[]))
            + (SELECT count(*)::int FROM pg_shdepend WHERE refclassid = 'pg_authid'::regclass AND refobjid::int8 = ANY ($1::int8[]))
            + (SELECT count(*)::int FROM pg_depend WHERE $2::int8 IS NOT NULL AND refclassid = 'pg_namespace'::regclass AND refobjid::int8 = $2::int8) AS n`,
      [before.roleOids, before.nsOid])).rows[0]?.n;
    return n === undefined || Number(n) > 0;
  }
}

// ---------------------------------------------------------------------------
// Overlay steps (C5, docs/plans/2026-11-19-c5-tenant-ddl.md KTD9-KTD11, KTD14)

export const OVERLAY_STEPS = ['prepare', 'flip', 'relax', 'rollback-start', 'unflip'] as const;
export type OverlayStep = (typeof OVERLAY_STEPS)[number];
/** The enc_state each operator step may start from (plan §4.6). The C8 tool's moves are not here. */
export const OVERLAY_STEP_FROM: Readonly<Record<OverlayStep, readonly EncState[]>> = {
  prepare: ['off', 'enrolled'],
  flip: ['verified'],
  relax: ['on'],
  'rollback-start': ['encrypting', 'verified'],
  unflip: ['decrypted'],
};
/** The enc_state after the step (null: prepare does not move the state). */
export const OVERLAY_STEP_TO: Readonly<Record<OverlayStep, EncState | null>> = {
  prepare: null, flip: 'on', relax: 'decrypting', 'rollback-start': 'decrypting', unflip: 'off',
};

export interface OverlayStepResult {
  step: OverlayStep;
  outcome: 'applied' | 'would_apply' | 'refused';
  /** A constant reason with counts only; set when refused. */
  reason?: string;
  from: EncState | null;
  to: EncState | null;
  state: OverlayState;
}

const counted = (st: OverlayState, pick: (t: OverlayState['tables'][number]) => number) =>
  st.tables.filter((t) => pick(t) > 0).map((t) => `${t.table} ${pick(t)}`).join(', ');

/** Why `step` may not run now (a constant reason with counts), or null. Pure: test/c5-overlay.test.ts. */
export function overlayGuard(step: OverlayStep, from: EncState, st: OverlayState): string | null {
  if (!OVERLAY_STEP_FROM[step].includes(from)) return `enc_state is ${from}; ${step} needs ${OVERLAY_STEP_FROM[step].join(' or ')}`;
  const all = OVERLAY_TABLES.length;
  if (step === 'prepare') {
    if (st.prepared) return 'already prepared; nothing to do';
    if (st.encProgress) return 'enc_progress exists without the prepare marker; refusing';
    return null;
  }
  if (!st.prepared) return 'not prepared (run prepare first)';
  if (step === 'flip') {
    if (st.flipChecks > 0) return 'already flipped';
    const plain = st.tables.reduce((a, t) => a + t.plainRows, 0);
    if (plain > 0) return `plain-text rows left (${counted(st, (t) => t.plainRows)}); flip needs every row encrypted`;
    if (st.otherRows > 0) return `rows in tables the overlay does not cover (${st.otherRows}); flip refuses`;
    return null;
  }
  if (step === 'relax') return st.flipChecks === all ? null : `not flipped (${st.flipChecks} of ${all} flip checks)`;
  if (step === 'rollback-start') return st.flipChecks === 0 ? null : 'flipped; run relax instead';
  // unflip (R3-2): no flip check left, and 0 ciphertext rows and 0 *_ct values.
  if (st.flipChecks > 0) return `flip checks still present (${st.flipChecks}); run relax first`;
  const enc = st.tables.reduce((a, t) => a + t.encryptedRows + t.ctValues, 0);
  if (enc > 0) return `ciphertext left (${counted(st, (t) => t.encryptedRows + t.ctValues)}); unflip needs 0`;
  return null;
}

/** C5 KTD11: a born-encrypted workspace before its first enrollment (prepared, flipped, no row at all). */
function bornEncryptedAndEmpty(st: OverlayState): boolean {
  return st.prepared && st.flipChecks === OVERLAY_TABLES.length && st.tables.every((t) => t.rows === 0 && t.ctValues === 0);
}

// ---------------------------------------------------------------------------
// Workspace delete (TenantDirectory.deleteWorkspace; docs/plans/2026-11-20-workspaces-delete.md KTD3, KTD5, KTD6)

/** One workspace role as a delete sees it: its name (derived from the validated id) and facts, never another role's name. */
export interface WorkspaceRoleState {
  role: string;
  exists: boolean;
  /** The provisioner holds ADMIN OPTION on it. DROP ROLE needs that (PostgreSQL 16+); without it the delete fails (42501). */
  admin: boolean;
  /** Its login holds it: zeusi_tenant_rt for `<id>_r`, zeusi_tenant_wr for `<id>_w`. */
  held: boolean;
  /** Every other membership of or in the role (DROP ROLE removes those too). */
  otherMemberships: number;
}

/** What one workspace holds in the database: names and numbers only, never a value. */
export interface WorkspaceDbState {
  /** Its rows in zeusi_tenants.tenants / members / key_wraps. */
  tenants: number;
  members: number;
  keyWraps: number;
  schema: boolean;
  /** `<id>_r`, then `<id>_w`. */
  roles: WorkspaceRoleState[];
  /** Every table of the schema with its row count (null: the provisioner cannot read it). A name off SAFE_TABLE_RE reads TABLE_NAME_HIDDEN. */
  tables: Array<{ table: string; rows: number | null }>;
  /** All rows of the readable tables. */
  rows: number;
}

export interface WorkspaceDeleteCounts {
  tenants: number;
  members: number;
  keyWraps: number;
  schemas: number;
  roles: number;
  rows: number;
}

export interface WorkspaceDeleteResult {
  tenantId: string;
  dryRun: boolean;
  /** Read inside the transaction before anything was removed (for a dry run: what a delete would remove). */
  before: WorkspaceDbState;
  /** What the committed transaction removed; all 0 for a dry run. */
  removed: WorkspaceDeleteCounts;
}

/** What a delete of a workspace in state `st` removes: the dry run's "would remove" and the apply's result (one rule). */
export function deleteCountsOf(st: WorkspaceDbState): WorkspaceDeleteCounts {
  return { tenants: st.tenants, members: st.members, keyWraps: st.keyWraps, schemas: st.schema ? 1 : 0, roles: st.roles.filter((r) => r.exists).length, rows: st.rows };
}

interface DeleteStateRead {
  state: WorkspaceDbState;
  /** Internal only (the leftover check after the drops); never printed. */
  nsOid: number | null;
  roleOids: number[];
}

const SAFE_TABLE_RE = /^[a-z_][a-z0-9_]*$/;
export const TABLE_NAME_HIDDEN = '(name not shown)';

/**
 * KTD5: every catalog object OUTSIDE the workspace schema ($1), one row per catalog: (cat, n, h), h = md5 of the sorted
 * object ids. DROP SCHEMA ... CASCADE also drops, with no privilege check on them, objects elsewhere that depend on the
 * schema: a view in `zeusi` or `public`, a column of a workspace row type, a foreign key, a default, a function, trigger,
 * policy, rule, cast or operator. deleteWorkspace takes this before and after its drops and rolls back on any difference
 * (a concurrent DDL elsewhere trips it too: fail closed, retry). pg_toast and temporary namespaces are left out: their
 * objects come and go with the tables and sessions of every schema.
 */
const OUTSIDE_FINGERPRINT_SQL = `
WITH skip AS (SELECT oid FROM pg_namespace
               WHERE nspname = $1::text OR nspname = 'pg_toast' OR nspname LIKE 'pg\\_temp\\_%' OR nspname LIKE 'pg\\_toast\\_temp\\_%'),
     rel AS (SELECT oid FROM pg_class WHERE relnamespace NOT IN (SELECT oid FROM skip)),
     typ AS (SELECT oid FROM pg_type WHERE typnamespace NOT IN (SELECT oid FROM skip)),
     fam AS (SELECT oid FROM pg_opfamily WHERE opfnamespace NOT IN (SELECT oid FROM skip)),
     ids (cat, id) AS (
       SELECT 'pg_namespace', oid::text FROM pg_namespace WHERE oid NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_class', oid::text FROM rel
       UNION ALL SELECT 'pg_attribute', attrelid::text || '.' || attnum::text FROM pg_attribute
                  WHERE attnum > 0 AND NOT attisdropped AND attrelid IN (SELECT oid FROM rel)
       UNION ALL SELECT 'pg_type', oid::text FROM typ
       UNION ALL SELECT 'pg_proc', oid::text FROM pg_proc WHERE pronamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_constraint', oid::text FROM pg_constraint WHERE connamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_trigger', oid::text FROM pg_trigger WHERE tgrelid IN (SELECT oid FROM rel)
       UNION ALL SELECT 'pg_policy', oid::text FROM pg_policy WHERE polrelid IN (SELECT oid FROM rel)
       UNION ALL SELECT 'pg_rewrite', oid::text FROM pg_rewrite WHERE ev_class IN (SELECT oid FROM rel)
       UNION ALL SELECT 'pg_attrdef', oid::text FROM pg_attrdef WHERE adrelid IN (SELECT oid FROM rel)
       UNION ALL SELECT 'pg_cast', oid::text FROM pg_cast WHERE castsource IN (SELECT oid FROM typ) AND casttarget IN (SELECT oid FROM typ)
       UNION ALL SELECT 'pg_operator', oid::text FROM pg_operator WHERE oprnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_opclass', oid::text FROM pg_opclass WHERE opcnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_opfamily', oid::text FROM fam
       UNION ALL SELECT 'pg_amop', oid::text FROM pg_amop WHERE amopfamily IN (SELECT oid FROM fam)
       UNION ALL SELECT 'pg_amproc', oid::text FROM pg_amproc WHERE amprocfamily IN (SELECT oid FROM fam)
       UNION ALL SELECT 'pg_collation', oid::text FROM pg_collation WHERE collnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_conversion', oid::text FROM pg_conversion WHERE connamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_extension', oid::text FROM pg_extension WHERE extnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_event_trigger', oid::text FROM pg_event_trigger
       UNION ALL SELECT 'pg_publication_rel', oid::text FROM pg_publication_rel WHERE prrelid IN (SELECT oid FROM rel)
       UNION ALL SELECT 'pg_publication_namespace', oid::text FROM pg_publication_namespace WHERE pnnspid NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_statistic_ext', oid::text FROM pg_statistic_ext WHERE stxnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_default_acl', oid::text FROM pg_default_acl WHERE defaclnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_language', oid::text FROM pg_language
       UNION ALL SELECT 'pg_foreign_data_wrapper', oid::text FROM pg_foreign_data_wrapper
       UNION ALL SELECT 'pg_foreign_server', oid::text FROM pg_foreign_server
       UNION ALL SELECT 'pg_am', oid::text FROM pg_am
       UNION ALL SELECT 'pg_transform', oid::text FROM pg_transform WHERE trftype IN (SELECT oid FROM typ)
       UNION ALL SELECT 'pg_ts_config', oid::text FROM pg_ts_config WHERE cfgnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_ts_dict', oid::text FROM pg_ts_dict WHERE dictnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_ts_parser', oid::text FROM pg_ts_parser WHERE prsnamespace NOT IN (SELECT oid FROM skip)
       UNION ALL SELECT 'pg_ts_template', oid::text FROM pg_ts_template WHERE tmplnamespace NOT IN (SELECT oid FROM skip))
SELECT cat, count(*)::int AS n, md5(string_agg(id, ',' ORDER BY id)) AS h FROM ids GROUP BY cat`;

type Fingerprint = Map<string, { n: number; h: string }>;

async function outsideFingerprint(db: Db, schema: string): Promise<Fingerprint> {
  assertTenantId(schema);
  const rows = (await db.query<{ cat: string; n: number; h: string }>(OUTSIDE_FINGERPRINT_SQL, [schema])).rows;
  return new Map(rows.map((r) => [r.cat, { n: Number(r.n), h: String(r.h) }]));
}

/** The catalogs whose outside objects differ, as `pg_class -1` (one fewer) / `+1` / `changed`: catalog names and numbers only. */
function fingerprintChanges(a: Fingerprint, b: Fingerprint): string[] {
  const out: string[] = [];
  for (const cat of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    const x = a.get(cat) ?? { n: 0, h: '' };
    const y = b.get(cat) ?? { n: 0, h: '' };
    if (x.n === y.n && x.h === y.h) continue;
    const d = y.n - x.n;
    out.push(`${/^pg_[a-z_]+$/.test(cat) ? cat : 'catalog'} ${d === 0 ? 'changed' : d > 0 ? `+${d}` : String(d)}`);
  }
  return out;
}

/**
 * lock_timeout (55P03), deadlock (40P01), serialization (40001): the delete lost a race and rolled back (TenantBusy).
 * Not 57014: a statement timeout or a cancel is not a lock wait, and a retry would hit it again.
 */
const BUSY_SQLSTATES: ReadonlySet<string> = new Set(['55P03', '40P01', '40001']);

/** The SQLSTATE of a database error when it has the 5-character shape, else null (never the server's message). */
function sqlStateOf(e: unknown): string | null {
  const code = (e as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code) ? code : null;
}

/** ` (SQLSTATE xxxxx)` or nothing: the one rule for naming a database error in a TenantError (overlay and delete). */
function sqlStateTail(e: unknown): string {
  const code = sqlStateOf(e);
  return code ? ` (SQLSTATE ${code})` : '';
}

/** A delete failure as a constant text plus the SQLSTATE only (never the server's message: it can name objects). */
function deleteError(e: unknown, what: string): TenantError {
  if (e instanceof TenantError) return e;
  const code = sqlStateOf(e);
  const tail = `${sqlStateTail(e)}; rolled back, nothing changed`;
  return code !== null && BUSY_SQLSTATES.has(code) ? new TenantBusy(`${what} waited too long for a lock${tail}`) : new TenantError(`${what} failed${tail}`);
}

// ---------------------------------------------------------------------------
// Router: one fail-closed read session per tool call (request path)

/** Rewrite the zeusi schema to the workspace schema in one SQL text (KTD4). */
export function translateSql(sql: string, schema: string): string {
  assertTenantId(schema);
  return sql.replace(QUALIFIER_RE, `${schema}.`).replace(/'zeusi'/g, `'${schema}'`);
}

/** A Db whose every statement reads the workspace schema instead of `zeusi`. */
export function schemaTranslatingDb(db: Db, schema: string): Db {
  assertTenantId(schema);
  return {
    label: 'personal workspace session',
    ...(db.transport ? { transport: db.transport } : {}),
    query: (sql, params) => db.query(translateSql(sql, schema), params),
    exec: (sql) => db.exec(translateSql(sql, schema)),
    close: () => db.close(),
  };
}

export interface TenantRouterOptions {
  /** A fresh session as zeusi_tenant_rt. */
  connectRuntime: () => Promise<Db>;
  /** Expected session_user of that session (default zeusi_tenant_rt). */
  runtimeLogin?: string | undefined;
  cacheMs?: number | undefined;
  now?: (() => number) | undefined;
}

export class TenantRouter {
  private readonly o: TenantRouterOptions;
  private readonly now: () => number;
  private readonly cache = new Map<string, number>();

  constructor(o: TenantRouterOptions) {
    this.o = o;
    this.now = o.now ?? Date.now;
  }

  /** The same router without the 'active' cache: workspace writes re-check the catalog every time. */
  uncached(): TenantRouter {
    return new TenantRouter({ ...this.o, cacheMs: 0 });
  }

  /** A runtime session, reset and checked to be exactly the runtime login (U1: a pooled leak never survives). */
  private async connect(): Promise<Db> {
    let db: Db;
    try {
      db = await this.o.connectRuntime();
    } catch {
      throw new TenantError('workspace runtime not reachable');
    }
    await resetAndAssertLogin(db, this.o.runtimeLogin ?? TENANT_RT_ROLE, 'workspace runtime');
    return db;
  }

  private async statusOf(db: Db, tenantId: string): Promise<'active' | 'unknown'> {
    const r = (await db.query<{ status: string }>(`SELECT status FROM ${CONTROL_SCHEMA}.tenants WHERE tenant_id = $1`, [tenantId])).rows[0];
    return r?.status === 'active' ? 'active' : 'unknown';
  }

  /** Is this workspace active? 'unknown' for a malformed, missing or disabled id. Throws TenantError on infra. */
  async check(tenantId: string): Promise<'active' | 'unknown'> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) return 'unknown';
    const t = this.now();
    const hit = this.cache.get(tenantId);
    if (hit !== undefined && hit > t) return 'active';
    const db = await this.connect();
    try {
      const st = await this.statusOf(db, tenantId);
      if (st === 'active') {
        this.cache.delete(tenantId);
        this.cache.set(tenantId, t + (this.o.cacheMs ?? TENANT_CHECK_CACHE_MS));
        while (this.cache.size > CHECK_CACHE_MAX) this.cache.delete(this.cache.keys().next().value!);
      } else {
        this.cache.delete(tenantId);
      }
      return st;
    } catch {
      throw new TenantError('workspace check failed');
    } finally {
      await closeClean(db);
    }
  }

  /**
   * C6 KTD2: the workspace's status and enc_state, uncached, as the runtime login (one SELECT on the two
   * granted columns). The one reader of enc_state for the request path (C6 writes, C7 reads). Throws
   * TenantError on ANY failure (no grant yet = 42501 before 0016, unreachable, malformed id, unknown
   * row, a value outside ENC_STATES): the caller refuses the write (fail closed).
   */
  async encState(tenantId: string): Promise<{ status: TenantStatus; encState: EncState }> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) throw new TenantError('not a workspace id');
    const db = await this.connect();
    try {
      const r = (await db.query<{ status: string; enc_state: string }>(
        `SELECT status, enc_state FROM ${CONTROL_SCHEMA}.tenants WHERE tenant_id = $1`, [tenantId])).rows[0];
      if (!r || (r.status !== 'active' && r.status !== 'disabled') || !(ENC_STATES as readonly string[]).includes(r.enc_state)) {
        throw new TenantError('workspace state not readable');
      }
      return { status: r.status, encState: r.enc_state as EncState };
    } catch {
      throw new TenantError('workspace state not readable');
    } finally {
      await closeClean(db);
    }
  }

  /**
   * A read session bound to exactly this workspace, checked (header), returning a translating Db.
   * Throws TenantRefused (refuse, no data) or TenantError (infra). The caller closes the Db.
   */
  async open(tenantId: string): Promise<Db> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) throw new TenantRefused('not a workspace id');
    const role = tenantRole(tenantId);
    const db = await this.connect();
    try {
      if ((await this.statusOf(db, tenantId)) !== 'active') throw new TenantRefused('workspace not available');
      await db.exec(`SET ROLE ${qi(role)}`);
      await db.exec(`SET search_path = ${qi(tenantId)}, public`);
      await db.exec('SET default_transaction_read_only = on');
      const v = (await db.query<{
        cu: string; su: string; power: boolean; own: boolean; team: boolean; ctl: boolean; other: boolean; can_write: boolean;
      }>(
        `SELECT current_user::text AS cu, session_user::text AS su,
                coalesce((SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user), true) AS power,
                has_schema_privilege($1::text, 'USAGE') AS own,
                CASE WHEN to_regnamespace('zeusi') IS NULL THEN false ELSE has_schema_privilege('zeusi', 'USAGE') END AS team,
                CASE WHEN to_regnamespace('${CONTROL_SCHEMA}') IS NULL THEN false ELSE has_schema_privilege('${CONTROL_SCHEMA}', 'USAGE') END AS ctl,
                EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname LIKE 'zt\\_%' AND n.nspname <> $1::text AND has_schema_privilege(n.oid, 'USAGE')) AS other,
                EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                         WHERE n.nspname = $1::text AND c.relkind IN ('r', 'p')
                           AND (has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE')
                             OR has_table_privilege(c.oid, 'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE'))) AS can_write`,
        [tenantId])).rows[0];
      if (!v || v.cu !== role || v.su !== (this.o.runtimeLogin ?? TENANT_RT_ROLE) || v.power || !v.own || v.team || v.ctl || v.other || v.can_write) {
        throw new TenantRefused('workspace session refused (it is not exactly this workspace, read-only)');
      }
      // The caller's close() rolls back and resets before it closes: the workspace role and
      // search_path never outlive this tool call on the server connection.
      return schemaTranslatingDb({
        label: db.label, ...(db.transport ? { transport: db.transport } : {}),
        query: (sql, params) => db.query(sql, params), exec: (sql) => db.exec(sql), close: () => closeClean(db, true),
      }, tenantId);
    } catch (e) {
      await closeClean(db, true);
      throw e instanceof TenantRefused || e instanceof TenantError ? e : new TenantError('workspace session failed');
    }
  }
}

// ---------------------------------------------------------------------------
// Writer: one fail-closed WRITE session into exactly one workspace
// (docs/plans/2026-11-18-workspace-write-import-plan.md KTD4)

export interface TenantWriterOptions {
  /** A fresh session as zeusi_tenant_wr. */
  connectWriter: () => Promise<Db>;
  /** The catalog check (the runtime router's check(): the writer login has no catalog access). */
  check: (tenantId: string) => Promise<'active' | 'unknown'>;
  /** Expected session_user of that session (default zeusi_tenant_wr). */
  writerLogin?: string | undefined;
}

export class TenantWriter {
  private readonly o: TenantWriterOptions;

  constructor(o: TenantWriterOptions) {
    this.o = o;
  }

  /**
   * A write session bound to exactly this workspace (`zeusi.` rewritten to its schema). Throws
   * TenantRefused (refuse, nothing written) or TenantError (infra). The caller closes the Db; close
   * rolls back anything open and resets the session before it closes.
   */
  async open(tenantId: string): Promise<Db> {
    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) throw new TenantRefused('not a workspace id');
    let st: 'active' | 'unknown';
    try {
      st = await this.o.check(tenantId);
    } catch {
      throw new TenantError('workspace check failed');
    }
    if (st !== 'active') throw new TenantRefused('workspace not available');
    const login = this.o.writerLogin ?? TENANT_WR_ROLE;
    const role = tenantWriterRole(tenantId);
    let db: Db;
    try {
      db = await this.o.connectWriter();
    } catch {
      throw new TenantError('workspace writer not reachable');
    }
    await resetAndAssertLogin(db, login, 'workspace writer');
    try {
      await db.exec(`SET ROLE ${qi(role)}`);
      await db.exec(`SET search_path = ${qi(tenantId)}, public`);
      const v = (await db.query<{
        cu: string; su: string; power: boolean; own: boolean; team: boolean; ctl: boolean; other: boolean; outside: boolean;
      }>(
        `SELECT current_user::text AS cu, session_user::text AS su,
                coalesce((SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user), true) AS power,
                has_schema_privilege($1::text, 'USAGE') AS own,
                CASE WHEN to_regnamespace('zeusi') IS NULL THEN false ELSE has_schema_privilege('zeusi', 'USAGE') END AS team,
                CASE WHEN to_regnamespace('${CONTROL_SCHEMA}') IS NULL THEN false ELSE has_schema_privilege('${CONTROL_SCHEMA}', 'USAGE') END AS ctl,
                EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname LIKE 'zt\\_%' AND n.nspname <> $1::text AND has_schema_privilege(n.oid, 'USAGE')) AS other,
                EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                         WHERE n.nspname <> $1::text AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\\_%'
                           AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                           AND (has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE')
                             OR has_table_privilege(c.oid, 'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE')))
                OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                            WHERE p.prosecdef AND n.nspname <> $1::text AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                              AND has_schema_privilege(n.oid, 'USAGE') AND has_function_privilege(p.oid, 'EXECUTE')) AS outside`,
        [tenantId])).rows[0];
      if (!v || v.cu !== role || v.su !== login || v.power || !v.own || v.team || v.ctl || v.other || v.outside) {
        throw new TenantRefused('workspace write session refused (it is not exactly this workspace)');
      }
      return schemaTranslatingDb({
        label: db.label, ...(db.transport ? { transport: db.transport } : {}),
        query: (sql, params) => db.query(sql, params), exec: (sql) => db.exec(sql), close: () => closeClean(db, true),
      }, tenantId);
    } catch (e) {
      await closeClean(db, true);
      throw e instanceof TenantRefused || e instanceof TenantError ? e : new TenantError('workspace write session failed');
    }
  }
}
