#!/usr/bin/env node
// `your-zeusi-mcp` (node dist/mcp.js): the Zeusi MCP connector (docs/mcp.md).
//
//   zeusi-mcp                                  stdio (default; what MCP clients spawn)
//   zeusi-mcp --write-service zeusi_decision   also enables zeusi_log_decision (zeusi_box_decision;
//                                              transitional: a zeusi_box_rw service such as zeusi_rw)
//   zeusi-mcp --http [--host 127.0.0.1] [--port 8787]
//                                              streamable HTTP, stateless, LOOPBACK ONLY
//                                              (127.0.0.1, ::1, localhost), DNS-rebinding protection on
//   zeusi-mcp --hosted [--bind 0.0.0.0|::] [--port 8080] [--public-host <h>]... [--data-dir /data]
//             [--tokens-file <f>]             AUTHENTICATED streamable HTTP for the Fly machine
//                                              (src/mcp-hosted.ts, docs/hosting.md): Bearer tokens,
//                                              fail closed (503 without a valid tokens file), scopes,
//                                              limits, HSTS, allowlisted logs. Never combined with --http.
//                                              OAuth for MCP clients (src/mcp-oauth.ts) on the same origin
//                                              when ZEUSI_GITHUB_CLIENT_ID, ZEUSI_GITHUB_CLIENT_SECRET and
//                                              ZEUSI_OAUTH_SIGNING_KEY are set; issuer https://<first
//                                              --public-host>. Read-only grants. Never on --http.
//             [--tenant-service zeusi_tenant_rt --tenant-admin-service zeusi_tenant_admin]
//                                              open sign-up: personal workspaces for every non-operator
//                                              GitHub identity (src/tenants.ts), plain pg over TCP, the
//                                              passwords from PGPASSFILE (scripts/fly-entrypoint.sh). Both
//                                              or neither; any startup miss (incl. a -pooler host: they
//                                              need the DIRECT endpoint) turns sign-up off with one
//                                              WORKSPACE SIGN-UP OFF: line (the team sign-in and bearer
//                                              tokens unaffected).
//
// stdout belongs to the MCP protocol on stdio; diagnostics go to stderr and never carry
// a secret, a hostname or a connection string. ZEUSI_TRANSPORT=serverless applies to the
// read tools only (src/mcp-server.ts); the write tool refuses it.

import { existsSync, lstatSync, mkdirSync, realpathSync, statfsSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { basename, dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ConfigError } from './config.ts';
import { connectService, type Db } from './db.ts';
import { runMain } from './fatal.ts';
import { Authenticator } from './mcp-auth.ts';
import { createHostedHandler } from './mcp-hosted.ts';
import { OAUTH_ENV_VARS, oauthFromEnv } from './mcp-oauth.ts';
import { enrollAuditSink } from './enroll-audit.ts';
import { encryptionMode } from './workspace-keys.ts';
import { PGPASSFILE_ENV, readPgpass } from './keychain.ts';
import { createMcpState, createZeusiMcpServer, DEFAULT_DECISION_DAYS, MAX_DECISION_DAYS, purgeQueries, WRITE_ROLE, WRITE_SERVICE_ENV, type McpDeps, type McpState } from './mcp-server.ts';
import { B1Cache } from './b1-cache.ts';
import { b1IndexHook } from './b1-index.ts';
import { TOKENS_PATH_ENV } from './mcp-tokens.ts';
import { resolveService, SEARCH_SERVICE } from './service.ts';
import { auditSink } from './signin-audit.ts';
import { TENANT_ADMIN_ROLE, TENANT_RT_ROLE, TENANT_WR_ROLE, TenantDirectory, TenantRouter, TenantWriter } from './tenants.ts';
import { wsAuditSink } from './workspace-audit.ts';
import { WorkspaceWrites } from './workspace-write.ts';
import { resolveTransport, SERVERLESS_VALUE, TRANSPORT_ENV } from './transport.ts';

export const LOOPBACK_HOSTS = ['127.0.0.1', '::1', 'localhost'] as const;
export const DEFAULT_HTTP_PORT = 8787;
/** --hosted binds the Fly-internal address: all IPv4 (default) or all IPv6 interfaces. */
export const HOSTED_BINDS = ['0.0.0.0', '::'] as const;
export const DEFAULT_HOSTED_PORT = 8080;
export const DEFAULT_PUBLIC_HOSTS = ['mcp.zeusi.dev'] as const;
export const DEFAULT_DATA_DIR = '/data';
/**
 * --hosted preview work root (review P1-1 of #32): on the machine's root disk, never on the data
 * volume (OAuth store, ledgers) and never on tmpfs (RAM on a 512 MB machine). /var/tmp is disk-backed
 * by convention (FHS) and world-writable with the sticky bit, so the server user creates its own 0700
 * parent there. Wiped at startup (previews are memory-only).
 */
export const DEFAULT_WORKSPACE_IMPORT_DIR = '/var/tmp/zeusi-mcp/workspace-import';
/** statfs f_type of tmpfs (Linux). */
export const TMPFS_MAGIC = 0x01021994;

export class McpArgsError extends Error {
  override name = 'McpArgsError';
}

export interface McpArgs {
  transport: 'stdio' | 'http' | 'hosted';
  host?: string;
  port?: number;
  /** --hosted only. */
  bind?: (typeof HOSTED_BINDS)[number];
  publicHosts?: string[];
  dataDir?: string;
  tokensPath?: string;
  /** --hosted only: the preview work root (DEFAULT_WORKSPACE_IMPORT_DIR); must be named workspace-import. */
  workspaceImportDir?: string;
  /** --hosted only, both or neither: the personal-workspace runtime and provisioner services. */
  tenantService?: string;
  tenantAdminService?: string;
  /** --hosted only, needs the two above: the own-workspace writer service (user zeusi_tenant_wr). */
  tenantWriterService?: string;
  readService: string;
  writeService?: string;
  days: number;
}

export const MCP_HELP = `zeusi-mcp: Zeusi MCP connector (docs/mcp.md)

  zeusi-mcp [--read-service <name>] [--write-service <name>] [--days <n>]
  zeusi-mcp --http [--host 127.0.0.1|::1|localhost] [--port <n>] [...]
  zeusi-mcp --hosted [--bind 0.0.0.0|::] [--port <n>] [--public-host <h>]... [--data-dir <d>] [--tokens-file <f>] [...]

  --read-service   service for zeusi_startup / zeusi_search (default ${SEARCH_SERVICE}; user must be zeusi_box_ro or zeusi_cloud_ro)
  --write-service  service for zeusi_log_decision (user must be zeusi_box_decision, or transitional zeusi_box_rw; or ${WRITE_SERVICE_ENV}). Unset: read-only connector
  --days           default zeusi_startup decision window (default ${DEFAULT_DECISION_DAYS}, max ${MAX_DECISION_DAYS})
  --http           streamable HTTP on a loopback address instead of stdio (default port ${DEFAULT_HTTP_PORT}).
                   Loopback only, no authentication: a local tool, never exposed.
  --hosted         authenticated streamable HTTP for the Fly machine (docs/hosting.md): every request
                   needs Authorization: Bearer <token> (zeusi mcp-token mint). Fails closed: HTTP 503 until a
                   valid tokens file exists, 401 for any bad token. Excludes --http. Default port ${DEFAULT_HOSTED_PORT}.
  --bind           --hosted listen address: 0.0.0.0 (default) or ::
  --public-host    --hosted Host header to accept (repeatable; default ${DEFAULT_PUBLIC_HOSTS.join(', ')})
  --data-dir       --hosted data directory (default ${DEFAULT_DATA_DIR}): tokens file and the .zeusi ledgers
  --tokens-file    --hosted tokens file (default ${TOKENS_PATH_ENV}, else <data-dir>/mcp-tokens.json)
  --workspace-import-dir
                   --hosted preview work dir for workspace writes (default ${DEFAULT_WORKSPACE_IMPORT_DIR});
                   absolute, named workspace-import, wiped at startup. It must be on another filesystem
                   than --data-dir and not on tmpfs, else workspace writes are refused at startup
  --tenant-service / --tenant-admin-service
                   --hosted open sign-up (both or neither): services whose user= is ${TENANT_RT_ROLE} /
                   ${TENANT_ADMIN_ROLE}; passwords from PGPASSFILE. Unset or refused: sign-up off
  --tenant-writer-service
                   --hosted own-workspace writes (import preview/commit, nightly sync; needs the two above):
                   service whose user= is ${TENANT_WR_ROLE} on the DIRECT host (no -pooler). Unset or
                   refused: workspace writes off (friendly message), reads unaffected
`;

export function parseMcpArgs(argv: string[], env: NodeJS.ProcessEnv = {}): McpArgs {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv, allowPositionals: false, strict: true,
      options: {
        http: { type: 'boolean', default: false },
        hosted: { type: 'boolean', default: false },
        bind: { type: 'string' },
        'public-host': { type: 'string', multiple: true },
        'data-dir': { type: 'string' },
        'tokens-file': { type: 'string' },
        'workspace-import-dir': { type: 'string' },
        'tenant-service': { type: 'string' },
        'tenant-admin-service': { type: 'string' },
        'tenant-writer-service': { type: 'string' },
        host: { type: 'string' },
        port: { type: 'string' },
        'read-service': { type: 'string' },
        'write-service': { type: 'string' },
        days: { type: 'string' },
        help: { type: 'boolean', default: false },
      },
    }));
  } catch {
    throw new McpArgsError('unknown or malformed option (see --help)');
  }
  const days = values.days === undefined ? DEFAULT_DECISION_DAYS : Number(values.days);
  if (!Number.isInteger(days) || days < 1 || days > MAX_DECISION_DAYS) throw new McpArgsError(`--days must be 1..${MAX_DECISION_DAYS}`);
  const svcName = /^[A-Za-z0-9_-]{1,64}$/;
  const readService = values['read-service'] ?? SEARCH_SERVICE;
  const writeService = values['write-service'] ?? (env[WRITE_SERVICE_ENV] || undefined);
  for (const s of [readService, writeService, values['tenant-service'], values['tenant-admin-service'], values['tenant-writer-service']]) {
    if (s !== undefined && !svcName.test(s)) throw new McpArgsError('service names are letters, digits, _ and - only');
  }
  const base = { readService, ...(writeService !== undefined ? { writeService } : {}), days };
  const hostedOnly = [values.bind, values['public-host'], values['data-dir'], values['tokens-file'], values['workspace-import-dir'], values['tenant-service'], values['tenant-admin-service'], values['tenant-writer-service']].some((v) => v !== undefined);
  if (values.hosted) {
    if (values.http) throw new McpArgsError('--hosted and --http exclude each other (--http stays loopback-only and unauthenticated)');
    if (values.host !== undefined) throw new McpArgsError('--hosted uses --bind, not --host');
    const bind = values.bind ?? HOSTED_BINDS[0];
    if (!(HOSTED_BINDS as readonly string[]).includes(bind)) throw new McpArgsError(`--bind must be one of ${HOSTED_BINDS.join(', ')}`);
    const port = values.port === undefined ? DEFAULT_HOSTED_PORT : Number(values.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new McpArgsError('--port must be 1..65535');
    const publicHosts = values['public-host'] ?? [...DEFAULT_PUBLIC_HOSTS];
    const hostName = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$/;
    for (const h of publicHosts) if (!hostName.test(h)) throw new McpArgsError('--public-host must be a lowercase host name (optionally :port)');
    const dataDir = values['data-dir'] ?? DEFAULT_DATA_DIR;
    if (!dataDir.startsWith('/')) throw new McpArgsError('--data-dir must be an absolute path');
    const tokensPath = values['tokens-file'] ?? (env[TOKENS_PATH_ENV] || undefined) ?? join(dataDir, 'mcp-tokens.json');
    const workspaceImportDir = values['workspace-import-dir'] ?? DEFAULT_WORKSPACE_IMPORT_DIR;
    if (!workspaceImportDir.startsWith('/') || basename(workspaceImportDir) !== 'workspace-import' || dirname(workspaceImportDir) === '/') {
      throw new McpArgsError('--workspace-import-dir must be an absolute path ending in /workspace-import, below a parent directory (it is wiped at startup)');
    }
    const tenantService = values['tenant-service'];
    const tenantAdminService = values['tenant-admin-service'];
    if ((tenantService === undefined) !== (tenantAdminService === undefined)) throw new McpArgsError('--tenant-service and --tenant-admin-service go together');
    const tenantWriterService = values['tenant-writer-service'];
    if (tenantWriterService !== undefined && tenantService === undefined) throw new McpArgsError('--tenant-writer-service needs --tenant-service and --tenant-admin-service');
    return {
      transport: 'hosted', bind: bind as (typeof HOSTED_BINDS)[number], port, publicHosts, dataDir, tokensPath, workspaceImportDir,
      ...(tenantService !== undefined && tenantAdminService !== undefined ? { tenantService, tenantAdminService } : {}),
      ...(tenantWriterService !== undefined ? { tenantWriterService } : {}), ...base,
    };
  }
  if (hostedOnly) throw new McpArgsError('--bind / --public-host / --data-dir / --tokens-file / --workspace-import-dir / --tenant-service / --tenant-admin-service / --tenant-writer-service need --hosted');
  if (!values.http) {
    if (values.host !== undefined || values.port !== undefined) throw new McpArgsError('--host / --port need --http');
    return { transport: 'stdio', ...base };
  }
  const host = values.host ?? '127.0.0.1';
  if (!(LOOPBACK_HOSTS as readonly string[]).includes(host)) throw new McpArgsError(`--host must be a loopback address (${LOOPBACK_HOSTS.join(', ')})`);
  const port = values.port === undefined ? DEFAULT_HTTP_PORT : Number(values.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new McpArgsError('--port must be 1..65535');
  return { transport: 'http', host, port, ...base };
}

export type WritePreflight = { ok: true } | { ok: false; reason: string };

/**
 * --hosted startup check for the write service (offline; docs/hosting.md "Write service").
 * The hosted server writes ONLY as zeusi_box_decision (no transitional zeusi_box_rw), over TCP,
 * with the password from the PGPASSFILE the Fly entrypoint wrote. Any miss: the caller logs the
 * reason and serves read-only (fail closed for writes, reads stay up). Reasons name services,
 * roles and env var names, never a value, host or password. The pgpass lookup only checks that
 * a matching line exists; the password is not kept.
 */
export function hostedWritePreflight(service: string, env: NodeJS.ProcessEnv, home?: string): WritePreflight {
  if (env[TRANSPORT_ENV] === SERVERLESS_VALUE) return { ok: false, reason: `${TRANSPORT_ENV}=${SERVERLESS_VALUE} is for read-only roles; writes need TCP` };
  let svc;
  try {
    svc = resolveService(service, { env, ...(home ? { home } : {}) });
  } catch (e) {
    return { ok: false, reason: (e instanceof Error ? e.message : 'service not resolvable').split('\n')[0]! };
  }
  if (svc.user !== WRITE_ROLE) return { ok: false, reason: `service ${service} logs in as ${svc.user}; the hosted write service runs only ${WRITE_ROLE}` };
  const file = env[PGPASSFILE_ENV];
  if (!file || file.trim() === '') return { ok: false, reason: `${PGPASSFILE_ENV} is not set (the entrypoint sets it from ZEUSI_DECISION_PGPASS)` };
  if (!existsSync(file)) return { ok: false, reason: `${PGPASSFILE_ENV} names a file that does not exist` };
  let found: boolean;
  try {
    found = readPgpass(file, { host: svc.host, port: svc.port, dbname: svc.dbname, user: svc.user }) !== undefined;
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : 'password file not readable' };
  }
  if (!found) return { ok: false, reason: `no line in ${PGPASSFILE_ENV} matches service ${service} (host, port, dbname, user ${WRITE_ROLE})` };
  return { ok: true };
}

/** A connection-pooler host (Neon names its PgBouncer endpoint `<endpoint>-pooler.<region>...`). */
export const POOLER_HOST_RE = /-pooler/i;
/** Names the service and the marker only, never the host. */
export const poolerReason = (service: string) =>
  `service ${service} points at a connection pooler (-pooler); personal workspaces need the direct endpoint because SET ROLE leaks across pooled connections`;

/**
 * --hosted startup check for one personal-workspace login (offline; docs/hosting.md
 * "Workspaces"): the service resolves, its user= is exactly `login`, its host is NOT a connection
 * pooler (the router's session-level SET ROLE / search_path would leak to the next client of a
 * pooled server connection: docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md U2), and
 * PGPASSFILE has a matching line. Any miss: the caller turns sign-up off (the team unaffected). Reasons
 * name services, logins and env var names, never a value, host or password. The password is not kept.
 * Only the two workspace logins get the pooler check: the team read and decision services keep
 * working on the pooler (they never change session state).
 */
export function hostedTenantPreflight(service: string, login: string, env: NodeJS.ProcessEnv, home?: string): WritePreflight {
  let svc;
  try {
    svc = resolveService(service, { env, ...(home ? { home } : {}) });
  } catch (e) {
    return { ok: false, reason: (e instanceof Error ? e.message : 'service not resolvable').split('\n')[0]! };
  }
  if (svc.user !== login) return { ok: false, reason: `service ${service} logs in as ${svc.user}; it must be ${login}` };
  if (POOLER_HOST_RE.test(svc.host)) return { ok: false, reason: poolerReason(service) };
  const file = env[PGPASSFILE_ENV];
  if (!file || file.trim() === '') return { ok: false, reason: `${PGPASSFILE_ENV} is not set (the entrypoint sets it from the tenant secrets)` };
  if (!existsSync(file)) return { ok: false, reason: `${PGPASSFILE_ENV} names a file that does not exist` };
  let found: boolean;
  try {
    found = readPgpass(file, { host: svc.host, port: svc.port, dbname: svc.dbname, user: svc.user }) !== undefined;
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : 'password file not readable' };
  }
  if (!found) return { ok: false, reason: `no line in ${PGPASSFILE_ENV} matches service ${service} (host, port, dbname, user ${login})` };
  return { ok: true };
}

export interface TenantSignupSetup {
  /** Set only when both workspace logins passed their startup check. */
  tenants?: { dir: TenantDirectory; router: TenantRouter } | undefined;
  /** The `sign-up ...` part of the startup line. */
  signup: string;
  /** One loud stderr line when sign-up was asked for but refused (starts WORKSPACE SIGN-UP OFF:). No host, no value. */
  log?: string | undefined;
}

/**
 * --hosted: decide personal-workspace sign-up at startup (offline; nothing connects here). Both
 * workspace services must pass hostedTenantPreflight (incl. the pooler refusal), else sign-up and
 * workspace routing stay OFF with one loud line; the team sign-in, bearer tokens and the team
 * read / decision services are unaffected either way.
 */
export function tenantSignupSetup(
  a: Pick<McpArgs, 'tenantService' | 'tenantAdminService'>, env: NodeJS.ProcessEnv, connect: (service: string) => Promise<Db>, home?: string,
): TenantSignupSetup {
  if (!a.tenantService || !a.tenantAdminService) return { signup: 'off (no --tenant-service)' };
  const rt = hostedTenantPreflight(a.tenantService, TENANT_RT_ROLE, env, home);
  const admin = hostedTenantPreflight(a.tenantAdminService, TENANT_ADMIN_ROLE, env, home);
  if (!rt.ok || !admin.ok) {
    const reason = !rt.ok ? rt.reason : !admin.ok ? admin.reason : '';
    return {
      signup: 'off (refused at startup)',
      log: `zeusi-mcp: WORKSPACE SIGN-UP OFF: refused at startup: ${reason}. Personal workspaces are not served; the team sign-in unaffected.`,
    };
  }
  const rtService = a.tenantService;
  const adminService = a.tenantAdminService;
  return {
    tenants: {
      // C5 KTD13: with ZEUSI_WORKSPACE_ENCRYPTION=on a NEW workspace is born encrypted (prepare + flip).
      dir: new TenantDirectory({ connectAdmin: () => connect(adminService), bornEncrypted: encryptionMode(env).mode === 'on' }),
      router: new TenantRouter({ connectRuntime: () => connect(rtService) }),
    },
    signup: 'on (personal workspaces)',
  };
}

/**
 * C7 KTD4 + KTD12 (D13): the OAuth store's session-end hook of the hosted server. Every ended session (revoke, client
 * revoke, revokeAll, revokeTenant, a reused refresh, an offline revoke picked up at the next re-read) evicts every
 * cached copy of that workspace at once and drops the grant's feedback memo. Exported so the test harness wires the
 * same function (test/helpers/hosted-tenants.ts).
 */
export function sessionEndHook(cache: B1Cache, state: McpState): (e: { grantId: string; tenant: string }) => void {
  return (e) => {
    cache.evictTenant(e.tenant);
    purgeQueries(state, e.grantId);
  };
}

export interface WorkspaceWriteSetup {
  /** Set only when the writer login passed its startup check and sign-up is on. */
  writes?: WorkspaceWrites | undefined;
  /** The `workspace writes ...` part of the startup line. */
  status: string;
  /** One loud stderr line when writes were asked for but refused (starts WORKSPACE WRITES OFF:). No host, no value. */
  log?: string | undefined;
}

export interface WorkspaceWorkDir {
  /** The preview work root (a directory named workspace-import; wiped by WorkspaceWrites). */
  root: string;
  /** Directories previews must never share a filesystem with: the data dir (OAuth store, ledgers) and the tokens file's dir. */
  protect: readonly string[];
}

/**
 * Why the preview work root is not usable, or null (review P1-1 of #32). Creates its parent (0700)
 * if missing, then requires: a real directory owned by this user and closed to others; not tmpfs;
 * and a different filesystem (st_dev) from every protected directory, so preview files can never
 * fill the volume that holds mcp-oauth.json and the ledgers. Reasons never name a path.
 */
export function workDirProblem(w: WorkspaceWorkDir, statfs: (p: string) => { type: number | bigint } = statfsSync): string | null {
  if (!w.root.startsWith('/') || basename(w.root) !== 'workspace-import') return 'the workspace import dir must be an absolute path named workspace-import';
  const parent = dirname(w.root);
  let dev: number;
  try {
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    const st = lstatSync(parent);
    if (st.isSymbolicLink() || !st.isDirectory()) return 'the workspace import dir\'s parent is not a real directory';
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) return 'the workspace import dir\'s parent is not owned by the server user';
    if ((st.mode & 0o077) !== 0) return 'the workspace import dir\'s parent is open to other users (it must be 0700)';
    if (Number(statfs(parent).type) === TMPFS_MAGIC) return 'the workspace import dir is on tmpfs (memory); it must be on a disk';
    dev = st.dev;
  } catch {
    return 'the workspace import dir could not be created or checked';
  }
  for (const d of w.protect) {
    let pd: number;
    try {
      pd = statSync(d).dev;
    } catch {
      return 'the data directory could not be checked against the workspace import dir';
    }
    if (pd === dev) {
      return 'the workspace import dir is on the same filesystem as the data volume (OAuth store, ledgers); previews could fill it. Use --workspace-import-dir on the root disk';
    }
  }
  return null;
}

/**
 * --hosted: decide own-workspace writes at startup (offline; nothing connects here;
 * docs/plans/2026-11-18-workspace-write-import-plan.md KTD3). The writer service must pass the same
 * check as the other workspace logins (login, NOT a -pooler host, a PGPASSFILE line), and sign-up must
 * be on (the writer's catalog check is the router's). Any miss: writes OFF with one loud line; reads,
 * sign-up and the team are unaffected.
 */
export function workspaceWriteSetup(
  a: Pick<McpArgs, 'tenantWriterService'>, env: NodeJS.ProcessEnv, connect: (service: string) => Promise<Db>,
  router: TenantRouter | undefined, work: WorkspaceWorkDir, audit?: ReturnType<typeof wsAuditSink>, home?: string,
): WorkspaceWriteSetup {
  if (!a.tenantWriterService) return { status: 'off (no --tenant-writer-service)' };
  if (!router) {
    return { status: 'off (sign-up off)', log: 'zeusi-mcp: WORKSPACE WRITES OFF: personal workspaces are not served, so there is nothing to write into. Reads unaffected.' };
  }
  const pf = hostedTenantPreflight(a.tenantWriterService, TENANT_WR_ROLE, env, home);
  if (!pf.ok) {
    return {
      status: 'off (refused at startup)',
      log: `zeusi-mcp: WORKSPACE WRITES OFF: refused at startup: ${pf.reason}. Personal workspaces stay read-only; the team unaffected.`,
    };
  }
  const wd = workDirProblem(work);
  if (wd) {
    return {
      status: 'off (refused at startup)',
      log: `zeusi-mcp: WORKSPACE WRITES OFF: refused at startup: ${wd}. Personal workspaces stay read-only; the team unaffected.`,
    };
  }
  let writes: WorkspaceWrites;
  const service = a.tenantWriterService;
  // The writer's catalog check is never served from the router's 30 s cache: a workspace disabled a
  // moment ago is refused at once for writes (reads keep the cached check).
  const fresh = router.uncached();
  const writer = new TenantWriter({ connectWriter: () => connect(service), check: (t) => fresh.check(t) });
  try {
    // C6 KTD2: the write route reads enc_state with the same uncached runtime router (one reader).
    // C7 KTD8: the real B1 index hook of the sealed write route (a factory bound to each call's session key).
    writes = new WorkspaceWrites({ workRoot: work.root, openWrite: (t) => writer.open(t), encState: (t) => fresh.encState(t), audit, indexHook: (key) => b1IndexHook(key) });
  } catch {
    return {
      status: 'off (refused at startup)',
      log: 'zeusi-mcp: WORKSPACE WRITES OFF: refused at startup: the workspace import dir could not be prepared. Personal workspaces stay read-only; the team unaffected.',
    };
  }
  return { writes, status: 'on (own workspace, preview first)' };
}

async function main(argv: string[]): Promise<void> {
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(MCP_HELP);
    return;
  }
  const a = parseMcpArgs(argv, process.env);
  resolveTransport(process.env); // refuse an invalid ZEUSI_TRANSPORT at startup
  const deps: McpDeps = { env: process.env, readService: a.readService, writeService: a.writeService, defaultDays: a.days };
  const state = createMcpState();

  if (a.transport === 'stdio') {
    const server = createZeusiMcpServer(deps, state);
    await server.connect(new StdioServerTransport());
    process.stderr.write(`zeusi-mcp: stdio ready (${a.writeService ? 'read + log_decision' : 'read-only'})\n`);
    return;
  }

  if (a.transport === 'hosted') {
    let writeService = a.writeService;
    if (writeService) {
      const pf = hostedWritePreflight(writeService, process.env);
      if (!pf.ok) {
        process.stderr.write(`zeusi-mcp: write service REFUSED at startup: ${pf.reason}. Serving read-only.\n`);
        writeService = undefined;
      }
    }
    const ledgers = join(a.dataDir!, '.zeusi');
    const hostedDeps: McpDeps = {
      ...deps, writeService, feedbackPath: join(ledgers, 'search-feedback.jsonl'), queryLedgerPath: join(ledgers, 'query-embed-ledger.json'),
    };
    // Open sign-up: personal workspaces only when both workspace logins pass their startup check.
    const ts = tenantSignupSetup(a, process.env, (service) => connectService(service, { env: process.env }));
    if (ts.log) process.stderr.write(`${ts.log}\n`);
    const tenants = ts.tenants;
    const signup = ts.signup;
    const audit = auditSink({ file: join(ledgers, 'signin-audit.jsonl') });
    const wsAudit = wsAuditSink({ file: join(ledgers, 'workspace-write-audit.jsonl') });
    const connect = (service: string) => connectService(service, { env: process.env });
    // Previews live off the data volume (review P1-1 of #32): refused at startup if they would share its filesystem.
    const wws = workspaceWriteSetup(a, process.env, connect, tenants?.router, {
      root: a.workspaceImportDir!, protect: [a.dataDir!, dirname(a.tokensPath!)],
    }, wsAudit);
    if (wws.log) process.stderr.write(`${wws.log}\n`);
    // C4 workspace keys (docs/plans/2026-11-18-c4-enroll.md KTD6): only with ZEUSI_WORKSPACE_ENCRYPTION=enroll
    // or on (C5 KTD13) AND personal workspaces on. Default off: the consent page and every flow are unchanged.
    const enc = encryptionMode(process.env);
    if (enc.log) process.stderr.write(`${enc.log}\n`);
    const keysOn = enc.mode !== 'off' && tenants !== undefined;
    if (enc.mode !== 'off' && !tenants) process.stderr.write(`zeusi-mcp: WORKSPACE KEYS OFF: ${enc.mode} needs personal workspaces (--tenant-service).\n`);
    // C7 KTD3 + KTD4 (D13): ONE B1 cache per process; every ended session (revoke, client revoke, revokeAll,
    // revokeTenant, a reused refresh, an offline revoke) evicts its workspace and drops its feedback memo.
    const cache = new B1Cache();
    const oauth = oauthFromEnv(process.env, {
      issuer: `https://${a.publicHosts![0]!}`, dataDir: a.dataDir!, tenants: tenants?.dir, audit, workspaceWrite: wws.writes !== undefined,
      encryption: keysOn && enc.mode !== 'off' ? { mode: enc.mode, catalog: tenants!.dir, audit: enrollAuditSink({ file: join(ledgers, 'enroll-audit.jsonl') }) } : undefined,
      onSessionEnded: sessionEndHook(cache, state),
    });
    // An offline revoke is picked up at the next request (every cache use re-reads the store first) and at the
    // latest within 60 s here; the same timer applies the cache's idle TTL.
    setInterval(() => {
      if (oauth.state === 'enabled') oauth.server.syncStore();
      cache.sweep();
    }, 60_000).unref();
    // The secrets now live only inside the OAuth server; nothing later in this process (or a
    // child) can read them from the environment.
    for (const k of OAUTH_ENV_VARS) delete process.env[k];
    const authenticator = new Authenticator({ tokensPath: a.tokensPath!, oauth: oauth.state === 'enabled' ? oauth.server : undefined });
    const allowedHosts = a.publicHosts!.flatMap((h) => (h.includes(':') ? [h] : [h, `${h}:443`]));
    const http = createServer(createHostedHandler({
      deps: hostedDeps, state, authenticator, allowedHosts, oauth, tenants: tenants?.router, writes: wws.writes, wsAudit, cache,
    }));
    const tokens = authenticator.refresh().state === 'loaded' ? 'configured' : 'not_configured (static tokens answer 503)';
    const oauthStatus = oauth.state === 'enabled' ? (wws.writes ? 'on (read; personal grants also write their own workspace)' : 'on (read-only grants)') : `off (${oauth.reason}; OAuth routes answer 503)`;
    // Mode and status only: no host, no path, no secret.
    http.listen(a.port!, a.bind!, () => process.stderr.write(
      `zeusi-mcp: hosted streamable HTTP on port ${a.port} (${writeService ? 'read + log_decision' : 'read-only'}); tokens ${tokens}; oauth ${oauthStatus}; sign-up ${signup}; workspace writes ${wws.status}; workspace keys ${keysOn ? (enc.mode === 'on' ? 'on (new workspaces born encrypted)' : 'enroll') : 'off'}\n`));
    return;
  }

  const host = a.host!;
  const port = a.port!;
  const hostHeader = host.includes(':') ? `[${host}]` : host;
  const allowedHosts = [`${hostHeader}:${port}`, `localhost:${port}`, `127.0.0.1:${port}`];
  const http = createServer((req, res) => {
    if ((req.url ?? '').split('?')[0] !== '/mcp') {
      res.writeHead(404).end();
      return;
    }
    // Stateless (no sessionIdGenerator): one server + transport per request; query ids for feedback live in `state`.
    const server = createZeusiMcpServer(deps, state);
    const transport = new StreamableHTTPServerTransport({ enableDnsRebindingProtection: true, allowedHosts });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    server.connect(transport)
      .then(() => transport.handleRequest(req, res))
      .catch(() => {
        if (!res.headersSent) res.writeHead(500).end();
      });
  });
  http.listen(port, host, () => process.stderr.write(`zeusi-mcp: streamable HTTP on http://${hostHeader}:${port}/mcp (loopback only)\n`));
}

/**
 * C2 KTD6: may a failed start print its message? Only McpArgsError and the ConfigError family
 * (TransportRefused, PooledEndpointRefused, MainBranchRefused): see the note at the entry below.
 * Exported so the boundary is pinned (test/fatal.test.ts), not only the wiring.
 */
export function startErrorKeepsMessage(e: unknown): boolean {
  return e instanceof McpArgsError || e instanceof ConfigError;
}

const isMain = (() => {
  try {
    return !!process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
})();

if (isMain) {
  // C2 KTD6: uncaught exceptions and unhandled rejections print the error class only. A failed start
  // keeps its message only for McpArgsError and the ConfigError family (TransportRefused,
  // PooledEndpointRefused, MainBranchRefused): they exist to tell the operator what to fix and may name
  // operator config (a service file path, section names, a URL scheme), never workspace data or a
  // secret value; anything else prints its class.
  runMain('zeusi-mcp', () => main(process.argv.slice(2)), { safeMessage: startErrorKeepsMessage });
}
