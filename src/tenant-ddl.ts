// Workspace (tenant) DDL derived from the same migration files as the zeusi schema
// (docs/plans/2026-11-18-open-signup-workspaces-plan.md U1, KTD1, KTD3).
//
// A personal workspace is one Postgres schema `zt_<26 base32>` next to `zeusi`, read through its own
// NOLOGIN role `<schema>_r`. Its tables, views, functions, triggers and wall seed rules are those of
// migrations/0001..NNNN with the schema renamed, minus everything that binds a ROLE:
//
//   files dropped      0004_roles.sql, 0005_rls.sql, 0012_decision_write_role.sql (the shared roles,
//                      the work-scope RLS, the shared write role). They are role bindings, not shape.
//                      0014_catalog_key_wraps.sql (C3): catalog DDL for zeusi_tenants, not shape.
//   statements dropped GRANT, REVOKE, CREATE / ALTER / DROP POLICY, CREATE / ALTER / DROP ROLE,
//                      CREATE EXTENSION, ALTER DEFAULT PRIVILEGES, SET / RESET ROLE,
//                      SET SESSION AUTHORIZATION, anything with OWNER TO, and DO blocks that create
//                      roles or policies or grant / revoke (0010's work-scope read policy).
//   renamed            every `zeusi.` qualifier (also inside function bodies and format() strings),
//                      `CREATE SCHEMA IF NOT EXISTS zeusi` and `search_path = pg_catalog, zeusi`.
//                      Any other bare `zeusi` identifier left in code refuses the whole DDL.
//   epilogue           nothing to PUBLIC; USAGE + SELECT on TENANT_READ_TABLES to the workspace role
//                      only; RLS on its base tables with one `USING (true)` read policy for that role;
//                      schema_migrations rows for the files applied.
//   writer             (src/tenants.ts provision / ensureWriter, tenantWriterGrants) the NOLOGIN role
//                      `<schema>_w`: USAGE, SELECT/INSERT/UPDATE/DELETE on TENANT_WRITE_TABLES, SELECT on
//                      TENANT_WRITER_READ_TABLES, the schema's sequences, TENANT_WRITER_FUNCTIONS, and a
//                      `tenant_write` policy on its RLS tables. Its own schema only.
//
// No shared-schema row is copied: the only rows a new workspace gets are the wall seed rules the migration
// files themselves insert (code), in tables the workspace role cannot read.
//
// TENANT_ACL_AUDIT_SQL runs in the provisioning transaction after the DDL (src/tenants.ts): any
// grantee other than the owner and the workspace role on the schema, a table, a view, a sequence or
// a function, or a policy for any other role, aborts the transaction. That audit, not this filter,
// is the backstop: a role-bound statement that slips through cannot commit.

import { listMigrations, type MigrationFile } from './migrate.ts';

/** A workspace id is also its schema name: zt_ + 26 lowercase base32 characters (130 random bits). */
export const TENANT_ID_RE = /^zt_[a-z2-7]{26}$/;
/** The team workspace: the existing schema `zeusi` and its roles. Never a TENANT_ID_RE value. */
export const WORK_TENANT = 'work';
/** A tenant reference on a grant or a principal: `work` or a workspace id. */
export const TENANT_REF_RE = /^(work|zt_[a-z2-7]{26})$/;
export type TenantRef = string;

/** The NOLOGIN read role of a workspace. */
export function tenantRole(tenantId: string): string {
  assertTenantId(tenantId);
  return `${tenantId}_r`;
}

/**
 * The NOLOGIN writer role of a workspace (docs/plans/2026-11-18-workspace-write-import-plan.md KTD3):
 * granted only to the writer login zeusi_tenant_wr (SET TRUE, INHERIT FALSE), privileges on its own
 * schema only (tenantWriterGrants). Never granted to the runtime login.
 */
export function tenantWriterRole(tenantId: string): string {
  assertTenantId(tenantId);
  return `${tenantId}_w`;
}

export function assertTenantId(tenantId: string): void {
  if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) throw new Error('not a workspace id');
}

/**
 * Migration files that are never part of a workspace: those that only bind the shared roles or the work scope
 * RLS, and 0014, which is catalog DDL for zeusi_tenants (C3, docs/plans/2026-11-18-c3-catalog-enc-state.md).
 */
export const TENANT_EXCLUDED_FILES: readonly string[] = ['0004_roles.sql', '0005_rls.sql', '0012_decision_write_role.sql', '0014_catalog_key_wraps.sql', '0015_key_wraps_credential_unique.sql', '0016_catalog_rt_enc_state.sql', '0017_key_wraps_webauthn.sql'];

/**
 * What the workspace role may SELECT: exactly what zeusi_read may SELECT in `zeusi`
 * (0004 + 0013; test/tenant-ddl.test.ts pins the two lists together). Not the wall tables, not
 * quarantine, not schema_migrations.
 */
export const TENANT_READ_TABLES: readonly string[] = [
  'people', 'facts', 'decisions', 'prs', 'pr_reviews', 'episodes', 'routine_runs', 'notes', 'chunks',
  'facts_current', 'decisions_current', 'pr_status', 'ingest_runs', 'backup_runs', 'embed_usage', 'decision_links',
];
/** The views among TENANT_READ_TABLES (security_invoker, 0001): no RLS of their own. */
export const TENANT_READ_VIEWS: readonly string[] = ['facts_current', 'decisions_current', 'pr_status'];

/**
 * What the workspace WRITER role may SELECT, INSERT, UPDATE and DELETE: exactly the tables the
 * import / sync pipeline writes (src/import-run.ts executeImport, src/importers/vault.ts importVault,
 * src/importers/structured.ts writeStructured, src/facts.ts openRun / closeRun). Nothing else.
 */
export const TENANT_WRITE_TABLES: readonly string[] = ['ingest_runs', 'notes', 'chunks', 'facts', 'decisions', 'decision_links'];
/**
 * The tenant encryption progress table (C5a, docs/plans/2026-11-19-c5-tenant-ddl.md KTD7, KTD8). NOT in
 * TENANT_WRITE_TABLES (plan N2-5): only a prepared workspace has it. src/tenant-overlay.ts creates it and
 * grants the writer ENC_PROGRESS_WRITER_PRIVS (encProgressGrantSql, also run by writerIn whenever the
 * table exists, R3-5). The ACL audit allows exactly those privileges; inert where the table is absent.
 */
export const ENC_PROGRESS_TABLE = 'enc_progress';
export const ENC_PROGRESS_WRITER_PRIVS: readonly string[] = ['SELECT', 'INSERT', 'UPDATE'];
/**
 * The B1 index table (C7, docs/plans/2026-11-19-c7-read-path.md KTD5): sealed index objects only (numbers,
 * kinds and ciphertext). NOT in TENANT_WRITE_TABLES / TENANT_READ_TABLES: only a prepared (or born-encrypted)
 * workspace has it. src/tenant-overlay.ts creates it (b1IndexStatements) and grants the writer
 * B1_INDEX_WRITER_PRIVS (b1IndexGrantSql, also run by writerIn whenever the table exists) and the read role
 * B1_INDEX_READER_PRIVS. RLS off (like enc_progress). The ACL audit allows exactly those writer privileges.
 */
export const B1_INDEX_TABLE = 'b1_index';
export const B1_INDEX_WRITER_PRIVS: readonly string[] = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];
/** The read role may only SELECT it: TenantRouter.open refuses a read session that can write any table. */
export const B1_INDEX_READER_PRIVS: readonly string[] = ['SELECT'];
/** Read-only for the writer: the people it resolves handles against, the wall rules it gates with. */
export const TENANT_WRITER_READ_TABLES: readonly string[] = ['people', 'wall_denylist', 'wall_allow'];
/** Functions the pipeline calls directly (blocked rows are recorded by uri + hash only). */
export const TENANT_WRITER_FUNCTIONS: readonly string[] = [
  'quarantine_record(zeusi.source_kind, text, bytea, integer, bigint, text, bytea)',
];

/**
 * Grants for the writer role of one workspace (provision and the idempotent backfill; every
 * statement is safe to repeat except CREATE POLICY, which the caller runs only when missing).
 * `policies`: the base tables that need a tenant_write policy (RLS is on for them).
 */
export function tenantWriterGrants(schema: string): { grants: string[]; policies: Array<{ table: string; sql: string }> } {
  const w = q(tenantWriterRole(schema));
  const s = q(schema);
  const rls = TENANT_READ_TABLES.filter((t) => !TENANT_READ_VIEWS.includes(t));
  return {
    grants: [
      `GRANT USAGE ON SCHEMA ${s} TO ${w}`,
      `GRANT SELECT, INSERT, UPDATE, DELETE ON ${TENANT_WRITE_TABLES.map((t) => `${s}.${q(t)}`).join(', ')} TO ${w}`,
      `GRANT SELECT ON ${TENANT_WRITER_READ_TABLES.map((t) => `${s}.${q(t)}`).join(', ')} TO ${w}`,
      `GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${s} TO ${w}`,
      ...TENANT_WRITER_FUNCTIONS.map((f) => `GRANT EXECUTE ON FUNCTION ${s}.${f.replace(/\bzeusi\./g, `${s}.`)} TO ${w}`),
    ],
    policies: [...TENANT_WRITE_TABLES, ...TENANT_WRITER_READ_TABLES].filter((t) => rls.includes(t)).map((t) => ({
      table: t, sql: `CREATE POLICY tenant_write ON ${s}.${q(t)} FOR ALL TO ${w} USING (true) WITH CHECK (true)`,
    })),
  };
}

export class TenantDdlError extends Error {
  override name = 'TenantDdlError';
}

// ---------------------------------------------------------------------------
// Lexer: code, quoted strings, dollar-quoted bodies and comments, so a `;` or a `zeusi` inside a
// string or a comment is never mistaken for code.

export type Segment =
  | { kind: 'code'; text: string }
  | { kind: 'string'; text: string }
  | { kind: 'dollar'; text: string; tag: string; body: string }
  | { kind: 'comment'; text: string };

const DOLLAR_TAG_RE = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/;

/** Split SQL text into segments. Throws on an unterminated string, comment or dollar quote. */
export function lex(sql: string): Segment[] {
  const out: Segment[] = [];
  let code = '';
  const flush = () => {
    if (code !== '') out.push({ kind: 'code', text: code });
    code = '';
  };
  let i = 0;
  while (i < sql.length) {
    const c = sql[i]!;
    const next = sql[i + 1];
    if (c === '-' && next === '-') {
      const end = sql.indexOf('\n', i);
      const stop = end === -1 ? sql.length : end;
      flush();
      out.push({ kind: 'comment', text: sql.slice(i, stop) });
      i = stop;
      continue;
    }
    if (c === '/' && next === '*') {
      let depth = 1;
      let j = i + 2;
      while (j < sql.length && depth > 0) {
        if (sql[j] === '/' && sql[j + 1] === '*') { depth++; j += 2; continue; }
        if (sql[j] === '*' && sql[j + 1] === '/') { depth--; j += 2; continue; }
        j++;
      }
      if (depth > 0) throw new TenantDdlError('unterminated block comment');
      flush();
      out.push({ kind: 'comment', text: sql.slice(i, j) });
      i = j;
      continue;
    }
    if (c === "'") {
      // E'...' strings take backslash escapes; plain strings only double the quote.
      const prev = code.length > 0 ? code[code.length - 1]! : '';
      const prev2 = code.length > 1 ? code[code.length - 2]! : '';
      const escapes = (prev === 'E' || prev === 'e') && !/[A-Za-z0-9_$]/.test(prev2);
      let j = i + 1;
      for (;;) {
        if (j >= sql.length) throw new TenantDdlError('unterminated string literal');
        if (escapes && sql[j] === '\\') { j += 2; continue; }
        if (sql[j] === "'") {
          if (sql[j + 1] === "'") { j += 2; continue; }
          break;
        }
        j++;
      }
      flush();
      out.push({ kind: 'string', text: sql.slice(i, j + 1) });
      i = j + 1;
      continue;
    }
    if (c === '$') {
      const prev = code.length > 0 ? code[code.length - 1]! : '';
      const m = /[A-Za-z0-9_]/.test(prev) ? null : DOLLAR_TAG_RE.exec(sql.slice(i));
      if (m) {
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        if (end === -1) throw new TenantDdlError('unterminated dollar quote');
        flush();
        out.push({ kind: 'dollar', tag, body: sql.slice(i + tag.length, end), text: sql.slice(i, end + tag.length) });
        i = end + tag.length;
        continue;
      }
    }
    code += c;
    i++;
  }
  flush();
  return out;
}

/** Top-level statements (comments kept, the terminating `;` dropped, blank ones skipped). */
export function splitStatements(sql: string): string[] {
  const stmts: string[] = [];
  let cur = '';
  for (const s of lex(sql)) {
    if (s.kind !== 'code') {
      cur += s.text;
      continue;
    }
    const parts = s.text.split(';');
    cur += parts[0]!;
    for (const p of parts.slice(1)) {
      stmts.push(cur);
      cur = p;
    }
  }
  stmts.push(cur);
  return stmts.filter((x) => codeOf(x).trim() !== '');
}

/** The code of a statement with comments removed and strings / dollar bodies kept (for classification). */
function codeOf(stmt: string): string {
  return lex(stmt).filter((s) => s.kind !== 'comment').map((s) => s.text).join('');
}

/** Code-only text (no strings, no comments); dollar bodies are lexed again, recursively. */
function codeOnly(sql: string): string {
  return lex(sql).map((s) => (s.kind === 'code' ? s.text : s.kind === 'dollar' ? ` ${codeOnly(s.body)} ` : ' ')).join('');
}

// ---------------------------------------------------------------------------
// Classification and rename

const ROLE_BOUND = [
  /^GRANT\b/i, /^REVOKE\b/i,
  /^(CREATE|ALTER|DROP)\s+POLICY\b/i,
  /^(CREATE|ALTER|DROP)\s+(ROLE|USER|GROUP)\b/i,
  /^CREATE\s+EXTENSION\b/i,
  /^ALTER\s+DEFAULT\s+PRIVILEGES\b/i,
  /^(SET|RESET)\s+(LOCAL\s+|SESSION\s+)?ROLE\b/i,
  /^SET\s+SESSION\s+AUTHORIZATION\b/i,
  /^RESET\s+SESSION\s+AUTHORIZATION\b/i,
];
const DO_ROLE_BOUND = /\b(CREATE|ALTER|DROP)\s+(POLICY|ROLE|USER|GROUP)\b|\bGRANT\b|\bREVOKE\b|\bOWNER\s+TO\b|\bSET\s+ROLE\b|\bSESSION\s+AUTHORIZATION\b/i;

export type Classification = { keep: true } | { keep: false; why: string };

/** Keep a statement in a workspace, or drop it because it binds a role (KTD3). */
export function classifyStatement(stmt: string): Classification {
  const code = codeOf(stmt).trim();
  for (const re of ROLE_BOUND) if (re.test(code)) return { keep: false, why: re.source };
  if (/\bOWNER\s+TO\b/i.test(codeOnly(stmt))) return { keep: false, why: 'OWNER TO' };
  if (/^DO\b/i.test(code)) {
    // The body is a string (dollar-quoted); look at the code inside it, and at format() strings too.
    const body = lex(stmt).filter((s) => s.kind === 'dollar').map((s) => s.body).join('\n');
    if (DO_ROLE_BOUND.test(body)) return { keep: false, why: 'DO block binds a role' };
  }
  return { keep: true };
}

// `zeusi.` followed by an identifier start, a quote or a format() placeholder; not part of a longer
// name (my_zeusi.x), a dotted path (a.zeusi.x) or a $-identifier.
export const QUALIFIER_RE = /(?<![\w.$])zeusi\.(?=[A-Za-z_"%])/g;
const CREATE_SCHEMA_RE = /\bCREATE\s+SCHEMA\s+IF\s+NOT\s+EXISTS\s+zeusi(?![\w.])/gi;
const SEARCH_PATH_RE = /(\bsearch_path\s*=\s*pg_catalog\s*,\s*)zeusi(?![\w.])/gi;
const BARE_RE = /(?<![\w.$])zeusi(?![\w$])/;

/** Rename the zeusi schema to `schema` in one statement (code, strings and function bodies). */
export function renameSchema(stmt: string, schema: string): string {
  assertTenantId(schema);
  return stmt
    .replace(QUALIFIER_RE, `${schema}.`)
    .replace(CREATE_SCHEMA_RE, `CREATE SCHEMA IF NOT EXISTS ${schema}`)
    .replace(SEARCH_PATH_RE, `$1${schema}`);
}

/** A bare `zeusi` identifier left in code (not in a string or comment). Throws if one is found. */
export function assertNoBareSchema(stmt: string, where: string): void {
  if (BARE_RE.test(codeOnly(stmt))) throw new TenantDdlError(`${where}: a bare zeusi schema reference is left after the rename`);
}

// ---------------------------------------------------------------------------
// The workspace DDL

export interface TenantDdlFile {
  name: string;
  sha256: string;
  statements: string[];
  dropped: number;
}

/** The migration files of a workspace, each with its kept, renamed statements. Throws on any leftover. */
export function tenantStatements(schema: string, files: MigrationFile[] = listMigrations()): TenantDdlFile[] {
  assertTenantId(schema);
  const out: TenantDdlFile[] = [];
  for (const f of files) {
    if (TENANT_EXCLUDED_FILES.includes(f.name)) continue;
    let dropped = 0;
    const statements: string[] = [];
    for (const stmt of splitStatements(f.sql)) {
      if (!classifyStatement(stmt).keep) {
        dropped++;
        continue;
      }
      const renamed = renameSchema(stmt, schema);
      assertNoBareSchema(renamed, f.name);
      statements.push(renamed);
    }
    out.push({ name: f.name, sha256: f.sha256, statements, dropped });
  }
  return out;
}

const q = (ident: string) => `"${ident.replace(/"/g, '""')}"`;

/**
 * The epilogue: nothing to PUBLIC, the workspace role reads TENANT_READ_TABLES, RLS with one read
 * policy for that role on every base table it reads, and the schema_migrations rows.
 */
export function tenantEpilogue(schema: string, applied: Array<{ name: string; sha256: string }>): string[] {
  const role = tenantRole(schema);
  const s = q(schema);
  const r = q(role);
  const base = TENANT_READ_TABLES.filter((t) => !TENANT_READ_VIEWS.includes(t));
  const lit = (v: string) => `'${v.replace(/'/g, "''")}'`;
  return [
    `REVOKE ALL ON SCHEMA ${s} FROM PUBLIC`,
    `REVOKE ALL ON ALL TABLES IN SCHEMA ${s} FROM PUBLIC`,
    `REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${s} FROM PUBLIC`,
    `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ${s} FROM PUBLIC`,
    `GRANT USAGE ON SCHEMA ${s} TO ${r}`,
    `GRANT SELECT ON ${TENANT_READ_TABLES.map((t) => `${s}.${q(t)}`).join(', ')} TO ${r}`,
    ...base.flatMap((t) => [
      `ALTER TABLE ${s}.${q(t)} ENABLE ROW LEVEL SECURITY`,
      `CREATE POLICY tenant_read ON ${s}.${q(t)} FOR SELECT TO ${r} USING (true)`,
    ]),
    `CREATE TABLE ${s}.schema_migrations (
       filename   text PRIMARY KEY,
       sha256     text NOT NULL,
       applied_at timestamptz NOT NULL DEFAULT now(),
       applied_by text NOT NULL DEFAULT session_user)`,
    `REVOKE ALL ON ${s}.schema_migrations FROM PUBLIC`,
    ...(applied.length > 0
      ? [`INSERT INTO ${s}.schema_migrations (filename, sha256) VALUES ${applied.map((a) => `(${lit(a.name)}, ${lit(a.sha256)})`).join(', ')}`]
      : []),
  ];
}

/**
 * Every statement that builds one workspace schema, in order, AFTER the caller created the schema
 * and the workspace role (src/tenants.ts). Runs inside one transaction as the provisioner.
 */
export function tenantDdl(schema: string, files: MigrationFile[] = listMigrations()): { statements: string[]; applied: Array<{ name: string; sha256: string }> } {
  const per = tenantStatements(schema, files);
  const applied = per.map((f) => ({ name: f.name, sha256: f.sha256 }));
  return { statements: [...per.flatMap((f) => f.statements), ...tenantEpilogue(schema, applied)], applied };
}

const sqlLit = (v: string) => `'${v.replace(/'/g, "''")}'`;

/** The writer role's exact table privileges (tenantWriterGrants), as SQL VALUES rows (relname, privilege). */
const WRITER_REL_PRIVS: ReadonlyArray<readonly [string, string]> = [
  ...TENANT_WRITE_TABLES.flatMap((t) => ['SELECT', 'INSERT', 'UPDATE', 'DELETE'].map((p) => [t, p] as const)),
  ...TENANT_WRITER_READ_TABLES.map((t) => [t, 'SELECT'] as const),
  ...ENC_PROGRESS_WRITER_PRIVS.map((p) => [ENC_PROGRESS_TABLE, p] as const),
  ...B1_INDEX_WRITER_PRIVS.map((p) => [B1_INDEX_TABLE, p] as const),
];
/** The writer's EXECUTE functions (tenantWriterGrants), resolved in the workspace schema ($1). */
const WRITER_FN_OIDS = TENANT_WRITER_FUNCTIONS.map((f) => {
  const n = (f.match(/\bzeusi\./g) ?? []).length;
  return `to_regprocedure(format(${sqlLit(`%I.${f.replace(/\bzeusi\./g, '%I.')}`)}, ${Array.from({ length: n + 1 }, () => '$1::text').join(', ')}))`;
});

/**
 * ACL post-condition for one workspace ($1 = schema, $2 = workspace role). Returns one row per
 * violation (object kind + name, never data). Grantees allowed: the object owner and the workspace
 * role; the workspace writer role `<schema>_w` (tenantWriterRole) only with EXACTLY the privileges
 * tenantWriterGrants gives it (USAGE on the schema, SELECT/INSERT/UPDATE/DELETE on
 * TENANT_WRITE_TABLES, SELECT on TENANT_WRITER_READ_TABLES, ENC_PROGRESS_WRITER_PRIVS on enc_progress and B1_INDEX_WRITER_PRIVS on b1_index where they exist (C5, C7), USAGE on the sequences, EXECUTE on
 * TENANT_WRITER_FUNCTIONS), never WITH GRANT OPTION: anything more (e.g. a write on the wall tables,
 * quarantine or schema_migrations) is a violation. PUBLIC (grantee 0) is never allowed. Policies must
 * name only the workspace role or its writer role. Types keep PostgreSQL's default PUBLIC USAGE (a
 * type carries no rows).
 */
export const TENANT_ACL_AUDIT_SQL = `
WITH ns AS (SELECT oid, nspowner FROM pg_namespace WHERE nspname = $1::text),
     allowed AS (SELECT oid FROM pg_roles WHERE rolname = $2::text),
     wr AS (SELECT oid FROM pg_roles WHERE rolname = $1::text || '_w'),
     wr_rel (relname, priv) AS (VALUES ${WRITER_REL_PRIVS.map(([t, p]) => `(${sqlLit(t)}, ${sqlLit(p)})`).join(', ')}),
     wr_fn (oid) AS (VALUES ${WRITER_FN_OIDS.map((o) => `(${o}::oid)`).join(', ')})
SELECT 'schema' AS kind, $1::text AS name
  FROM ns, aclexplode(coalesce((SELECT nspacl FROM pg_namespace WHERE oid = ns.oid), acldefault('n'::"char", ns.nspowner))) a
 WHERE a.grantee <> ns.nspowner AND a.grantee NOT IN (SELECT oid FROM allowed)
   AND NOT (a.grantee IN (SELECT oid FROM wr) AND a.privilege_type = 'USAGE' AND NOT a.is_grantable)
UNION ALL
SELECT 'relation', c.relname::text
  FROM pg_class c JOIN ns ON c.relnamespace = ns.oid,
       aclexplode(coalesce(c.relacl, acldefault((CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END)::"char", c.relowner))) a
 WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND a.grantee <> c.relowner AND a.grantee NOT IN (SELECT oid FROM allowed)
   AND NOT (a.grantee IN (SELECT oid FROM wr) AND NOT a.is_grantable
            AND CASE WHEN c.relkind = 'S' THEN a.privilege_type = 'USAGE'
                     ELSE (c.relname::text, a.privilege_type) IN (SELECT relname, priv FROM wr_rel) END)
UNION ALL
SELECT 'function', p.proname::text
  FROM pg_proc p JOIN ns ON p.pronamespace = ns.oid, aclexplode(coalesce(p.proacl, acldefault('f'::"char", p.proowner))) a
 WHERE a.grantee <> p.proowner AND a.grantee NOT IN (SELECT oid FROM allowed)
   AND NOT (a.grantee IN (SELECT oid FROM wr) AND a.privilege_type = 'EXECUTE' AND NOT a.is_grantable AND p.oid IN (SELECT oid FROM wr_fn))
UNION ALL
SELECT 'policy', c.relname::text || '.' || pol.polname::text
  FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid JOIN ns ON c.relnamespace = ns.oid
 WHERE NOT (pol.polroles <@ ARRAY(SELECT oid FROM allowed UNION ALL SELECT oid FROM wr) AND array_length(pol.polroles, 1) >= 1)
`;
