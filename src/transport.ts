// HTTPS serverless transport for `zeusi search` and read-only `zeusi doctor` (box egress).
//
// Why: the box's egress does not complete a Postgres session on TCP 5432, but HTTPS 443
// to the same Neon pooled host works. @neondatabase/serverless speaks the Postgres wire
// protocol inside a secure WebSocket (wss://<host>/v2, port 443) to Neon's proxy.
//
// Default OFF. TCP 5432 via connectService() (src/db.ts) stays the default and is not
// changed: sslmode=verify-full, sslrootcert=system, channel_binding=require
// (SCRAM-SHA-256-PLUS) remain mandatory there, with no switch to turn them off.
//
// Gate: the env var ZEUSI_TRANSPORT. Unset or empty -> tcp. Exactly "serverless" ->
// this transport. Any other value is refused (a typo never silently falls back to TCP).
// There is deliberately NO pg_service.conf key: libpq/psql reject unknown keywords, so
// a Zeusi-only key would break that section for psql; src/service.ts still refuses
// unknown keys.
//
// With the gate on:
//   * only `search` and `doctor` run (assertTransportAllowed, called first in the CLI);
//     ingest, embed, migrate, prove, embed-smoke, wall, fact, vector-probe, export-filter
//     are refused and keep their TCP / owner paths;
//   * only the read-only logins zeusi_box_ro and zeusi_cloud_ro connect (matched on the
//     service section's user=). Every other user (zeusi_box_rw, zeusi_mini_ingest,
//     zeusi_mini_backup, the owner, anything else) is refused after the offline service
//     parse, BEFORE any password is read and BEFORE a client is constructed.
//
// AUTH EXCEPTION (deliberate, narrow; docs/roles.md, docs/neon.md): Neon serverless auth
// is the role password sent over a verified TLS (wss) connection to Neon's proxy. It is
// NOT Postgres SCRAM-SHA-256-PLUS channel binding. This exception holds only on this
// transport, only for zeusi_box_ro / zeusi_cloud_ro, and only with ZEUSI_TRANSPORT=serverless.
// TLS certificate verification is still required: wss only (useSecureWebSocket, and the
// socket constructor refuses any other scheme), Neon's default proxy address (no wsProxy
// override), no experimental pure-JS TLS, and NODE_TLS_REJECT_UNAUTHORIZED=0 is refused.
// The runtime's WebSocket verifies the server certificate and hostname against Node's
// trust store. The password comes from ZEUSI_NEON_BOX_RO_PASSWORD (zeusi_box_ro only,
// the existing U6 rule) or the Keychain / ~/.pgpass; it is a driver config field, never
// part of a URL, never printed, logged or written, and redacted from connect errors.
//
// One transaction: the Db returned here wraps ONE WebSocket Client (one server session).
// search() sends BEGIN READ ONLY, SET LOCAL hnsw.ef_search, SET LOCAL hnsw.iterative_scan,
// its queries and ROLLBACK through that Db, so the SET LOCALs apply to the queries. The
// HTTP one-shot API (neon(), Pool with poolQueryViaFetch) is never used: each HTTP request
// is its own transaction and would silently drop the SET LOCALs. Only Client is imported.

import { Client } from '@neondatabase/serverless';
import { ConfigError } from './config.ts';
import { connectService, ConnectError, envPasswordFor, redact, type Db } from './db.ts';
import { readRolePassword, type SecurityRunner } from './keychain.ts';
import { resolveService, type ResolveOptions } from './service.ts';

export const TRANSPORT_ENV = 'ZEUSI_TRANSPORT';
export const SERVERLESS_VALUE = 'serverless';
export type Transport = 'tcp' | 'serverless';

/** Commands that may run with ZEUSI_TRANSPORT=serverless. Everything else is refused. */
export const SERVERLESS_COMMANDS = ['search', 'doctor'] as const;

/** The only logins this transport connects as (service section user=). Read-only by grant and role default. */
export const SERVERLESS_ROLES = ['zeusi_box_ro', 'zeusi_cloud_ro'] as const;

const HELP_COMMANDS = new Set([undefined, 'help', '--help', '-h']);

export class TransportRefused extends ConfigError {
  override name = 'TransportRefused';
}

/** Read the gate. Throws (naming the variable, never echoing its value) on anything but unset, empty, or "serverless". */
export function resolveTransport(env: NodeJS.ProcessEnv = process.env): Transport {
  const v = env[TRANSPORT_ENV];
  if (v === undefined || v === '') return 'tcp';
  if (v === SERVERLESS_VALUE) return 'serverless';
  throw new TransportRefused(
    `${TRANSPORT_ENV} may only be "${SERVERLESS_VALUE}" (or unset for the default TCP transport); another value is refused. No connection made.`,
  );
}

/** CLI gate, before any other work. Returns the transport for the command. */
export function assertTransportAllowed(cmd: string | undefined, env: NodeJS.ProcessEnv = process.env): Transport {
  if (HELP_COMMANDS.has(cmd)) return 'tcp';
  const t = resolveTransport(env);
  if (t === 'serverless' && !(SERVERLESS_COMMANDS as readonly string[]).includes(cmd ?? '')) {
    throw new TransportRefused(
      `${TRANSPORT_ENV}=${SERVERLESS_VALUE} is only for ${SERVERLESS_COMMANDS.join(' and ')} (read-only roles ${SERVERLESS_ROLES.join(', ')}); ` +
        `"${cmd}" keeps the TCP path: unset ${TRANSPORT_ENV}. No connection made.`,
    );
  }
  return t;
}

/** WebSocket that only opens wss:// URLs (certificate + hostname verified by the runtime). */
export class WssOnlyWebSocket extends WebSocket {
  constructor(url: string | URL, protocols?: string | string[]) {
    if (!String(url).startsWith('wss://')) throw new TransportRefused('serverless transport: refused a non-wss WebSocket URL (TLS is required).');
    super(url, protocols);
  }
}

/** The connection fields handed to the serverless Client. No URL, no TLS knobs. */
export interface ServerlessClientConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  application_name: string;
  connectionTimeoutMillis: number;
}

/** The part of @neondatabase/serverless Client this module uses (tests inject a fake). */
export interface ServerlessClientLike {
  readonly neonConfig: object;
  connect(): Promise<void>;
  query(sql: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
  end(): Promise<void>;
}

export type ServerlessClientFactory = (config: ServerlessClientConfig) => ServerlessClientLike;

const defaultFactory: ServerlessClientFactory = (config) => new Client(config) as unknown as ServerlessClientLike;

export interface ServerlessConnectOptions extends ResolveOptions {
  runSecurity?: SecurityRunner;
  /** TEST ONLY: replaces `new Client(config)` from @neondatabase/serverless. */
  serverlessClient?: ServerlessClientFactory;
}

/** Wrap one connected serverless Client as a Db. One client = one session, so a BEGIN..ROLLBACK spans every call. */
export function serverlessDb(client: ServerlessClientLike, name: string): Db {
  return {
    label: `service ${name} (serverless wss)`,
    transport: { tls: true, channelBinding: false, kind: 'serverless' },
    async query<T>(sql: string, params?: unknown[]) {
      const r = await client.query(sql, params);
      return { rows: r.rows as T[] };
    },
    async exec(sql: string) {
      await client.query(sql);
    },
    async close() {
      await client.end();
    },
  };
}

/**
 * Read-only role connection over the serverless transport. Order matters: gate, TLS env,
 * offline service parse, role allow-list, THEN password, THEN client. Nothing before the
 * role check reads a secret or touches the network.
 */
export async function connectServerless(name: string, opts: ServerlessConnectOptions = {}): Promise<Db> {
  const env = opts.env ?? process.env;
  if (resolveTransport(env) !== 'serverless') {
    throw new TransportRefused(`serverless transport needs ${TRANSPORT_ENV}=${SERVERLESS_VALUE}. No connection made.`);
  }
  if (process.env['NODE_TLS_REJECT_UNAUTHORIZED'] === '0' || env['NODE_TLS_REJECT_UNAUTHORIZED'] === '0') {
    throw new TransportRefused('NODE_TLS_REJECT_UNAUTHORIZED=0 disables certificate verification; the serverless transport refuses to run with it. No connection made.');
  }
  // Same validation as TCP (verify-full / system roots / channel_binding=require lines must be present).
  const svc = resolveService(name, opts);
  if (!(SERVERLESS_ROLES as readonly string[]).includes(svc.user)) {
    throw new TransportRefused(
      `service ${name}: user ${svc.user} refused on the serverless transport: only the read-only roles ${SERVERLESS_ROLES.join(', ')} may use it. No password read, no connection made.`,
    );
  }
  const pwOpts = { host: svc.host, port: svc.port, dbname: svc.dbname, env, ...(opts.home ? { home: opts.home } : {}), ...(opts.runSecurity ? { runSecurity: opts.runSecurity } : {}) };
  const password = envPasswordFor(svc.user, env) ?? await readRolePassword(svc.user, pwOpts);
  const client = (opts.serverlessClient ?? defaultFactory)({
    host: svc.host,
    port: 443,
    database: svc.dbname,
    user: svc.user,
    password,
    application_name: 'zeusi-cli',
    connectionTimeoutMillis: 15_000,
  });
  // Per-client settings (override any global neonConfig). wsProxy, subtls and rootCerts are left at Neon's defaults.
  Object.assign(client.neonConfig, {
    useSecureWebSocket: true,
    forceDisablePgSSL: true, // no Postgres-level TLS inside the tunnel: the wss layer is the verified TLS
    webSocketConstructor: WssOnlyWebSocket,
    pipelineConnect: false, // send the password only when the server asks for it
  });
  try {
    await client.connect();
  } catch (e) {
    await client.end().catch(() => {});
    const msg = e instanceof Error ? e.message : String(e);
    throw new ConnectError(`service ${name} (serverless): connection failed: ${redact(msg, [svc.host, svc.host.replace('-pooler', ''), password])}`);
  }
  return serverlessDb(client, name);
}

export interface ReadOnlyConnectOptions extends ServerlessConnectOptions {
  /** TEST ONLY: replaces the TCP path (default: connectService from src/db.ts, unchanged). */
  tcp?: (name: string) => Promise<Db>;
}

/** `search` / `doctor`: TCP unless ZEUSI_TRANSPORT=serverless. */
export async function connectReadOnly(name: string, opts: ReadOnlyConnectOptions = {}): Promise<Db> {
  if (resolveTransport(opts.env ?? process.env) === 'serverless') return connectServerless(name, opts);
  return (opts.tcp ?? ((n: string) => connectService(n, opts)))(name);
}
