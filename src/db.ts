// Minimal database seam. The CLI uses node-postgres (`pg`) over TLS; tests can
// plug in any client with the same two methods (e.g. PGlite in test/).
//
// Two ways in:
//   connectService(name)  role connections (doctor, fact, wall report/audit, ...):
//                         pg_service.conf section + Keychain / ~/.pgpass password.
//   connectOwner(kind)    OWNER URL from .env.local — owner-only commands the operator runs
//                         (migrate, prove, embed-smoke, wall allow). Nothing else.

import { TLSSocket } from 'node:tls';
import pg from 'pg';
import { ConfigError, prepareUrl, resolveUrl, type ResolvedUrl, type UrlKind } from './config.ts';
import { readRolePassword, type SecurityRunner } from './keychain.ts';
import { resolveService, type ResolveOptions } from './service.ts';

export interface QueryResult<T> {
  rows: T[];
}

export interface Db {
  /** One statement, optional $n parameters. */
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<QueryResult<T>>;
  /** Multi-statement script, no parameters (migrations). */
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
  /** Safe-to-print description: URL kind and env var NAME only (no host, no credentials). */
  readonly label: string;
  /**
   * Set for network connections: TLS verified, and SCRAM-SHA-256-PLUS used. `kind` is
   * absent (= TCP, src/db.ts connectService) or 'serverless' (src/transport.ts: wss/443,
   * password over verified TLS, channelBinding always false).
   */
  readonly transport?: { tls: boolean; channelBinding: boolean; kind?: 'serverless' };
}

/** Postgres error shape shared by pg and PGlite. */
export interface PgErrorLike {
  code?: string;
  message: string;
  detail?: string;
}

export function asPgError(e: unknown): PgErrorLike {
  if (e && typeof e === 'object' && 'message' in e) {
    const o = e as { code?: unknown; message: unknown; detail?: unknown };
    const out: PgErrorLike = { message: String(o.message) };
    if (typeof o.code === 'string') out.code = o.code;
    if (typeof o.detail === 'string') out.detail = o.detail;
    return out;
  }
  return { message: String(e) };
}

export const INSECURE_NO_CB_FLAG = '--insecure-no-channel-binding';

export interface OwnerConnectOptions {
  /**
   * Local debugging only: allow SCRAM without channel binding. Needs the explicit
   * CLI flag; ZEUSI_CHANNEL_BINDING=off alone is refused (review r1 MINOR-7).
   */
  insecureNoChannelBinding?: boolean;
  warn?: (line: string) => void;
}

/** Decide channel binding for the owner path. Throws before any connection. */
export function ownerChannelBinding(env: NodeJS.ProcessEnv, opts: OwnerConnectOptions = {}): boolean {
  const v = env['ZEUSI_CHANNEL_BINDING'];
  if (v !== undefined && v.trim() !== '' && v.trim() !== 'off') {
    throw new ConfigError(`ZEUSI_CHANNEL_BINDING may only be "off" (got another value); channel binding is on by default.`);
  }
  if (v?.trim() === 'off' && !opts.insecureNoChannelBinding) {
    throw new ConfigError(
      `ZEUSI_CHANNEL_BINDING=off is not honoured on its own. Channel binding stays required unless you also pass ${INSECURE_NO_CB_FLAG} (local debugging only). No connection made.`,
    );
  }
  if (opts.insecureNoChannelBinding) {
    (opts.warn ?? ((l: string) => process.stderr.write(`${l}\n`)))(
      `WARNING: ${INSECURE_NO_CB_FLAG}: SCRAM channel binding is OFF for this owner connection (MITM protection reduced). Local debugging only.`,
    );
    return false;
  }
  return true;
}

/** OWNER connection from the env URL names (.env.local). Owner-only commands only. */
export async function connectOwner(kind: UrlKind, env: NodeJS.ProcessEnv = process.env, opts: OwnerConnectOptions = {}): Promise<Db> {
  const channelBinding = ownerChannelBinding(env, opts);
  const resolved: ResolvedUrl = resolveUrl(kind, env);
  const client = new pg.Client({
    connectionString: prepareUrl(resolved.url),
    // TLS required and verified against the system CA store (verify-full equivalent).
    ssl: { rejectUnauthorized: true },
    // SCRAM-SHA-256-PLUS when the server offers it (Neon does). Off only with
    // --insecure-no-channel-binding (see ownerChannelBinding).
    enableChannelBinding: channelBinding,
    application_name: 'zeusi-cli',
    connectionTimeoutMillis: 15_000,
  });
  await client.connect();
  const label = `${kind} URL via ${resolved.sourceName}`;
  return {
    label,
    async query<T>(sql: string, params?: unknown[]) {
      const r = await client.query(sql, params as unknown[] | undefined);
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

export class ConnectError extends Error {
  override name = 'ConnectError';
}

/** Replace every given secret-ish string (host, user, password) in a message. */
export function redact(message: string, secrets: Array<string | undefined>): string {
  let out = message;
  for (const s of secrets) if (s && s.length >= 3) out = out.split(s).join('<redacted>');
  return out.replace(/[A-Za-z0-9.-]+\.neon\.tech/g, '<host>').replace(/postgres(ql)?:\/\/\S+/g, '<url>');
}

/**
 * DELIBERATE, NARROW EXCEPTION to "no DB credentials from the environment" (U6, KTD16):
 * the read-only search login zeusi_box_ro, and ONLY that login (matched on the service
 * file's user=, not on the service name), may take its password from this env var on
 * the box, so a sandboxed agent can search without a ~/.pgpass. It is read only here,
 * inside connectService(), passed to the driver as a config field (never in a URL),
 * never printed, logged or written to disk, and redacted from connection errors. Every
 * other role ignores it (and every other env password). See docs/roles.md.
 */
export const RO_PASSWORD_ENV = 'ZEUSI_NEON_BOX_RO_PASSWORD';
export const RO_ENV_PASSWORD_ROLE = 'zeusi_box_ro';

export function envPasswordFor(user: string, env: NodeJS.ProcessEnv): string | undefined {
  if (user !== RO_ENV_PASSWORD_ROLE) return undefined;
  const v = env[RO_PASSWORD_ENV];
  return v !== undefined && v !== '' ? v : undefined;
}

/** pg client constructor seam (tests inject a client that never touches the network). */
export type PgClientFactory = (config: pg.ClientConfig) => pg.Client;

export interface ServiceConnectOptions extends ResolveOptions {
  runSecurity?: SecurityRunner;
  /** TEST ONLY: replaces `new pg.Client(config)`. */
  pgClient?: PgClientFactory;
}

type PgClientInternals = {
  _handleAuthSASL: (msg: { mechanisms: string[] }) => void;
  _handleAuthCleartextPassword: (msg: unknown) => void;
  _handleAuthMD5Password: (msg: unknown) => void;
  connection: { stream: unknown; emit: (ev: string, err: Error) => void };
};

/**
 * Role connection through a pg_service.conf section. TLS verify-full against the
 * trusted root store (sslrootcert=system), and channel_binding=require: anything
 * but SCRAM-SHA-256-PLUS is refused BEFORE the password is sent.
 */
export async function connectService(name: string, opts: ServiceConnectOptions = {}): Promise<Db> {
  const svc = resolveService(name, opts);
  const pwOpts = { host: svc.host, port: svc.port, dbname: svc.dbname, env: opts.env ?? process.env, ...(opts.home ? { home: opts.home } : {}), ...(opts.runSecurity ? { runSecurity: opts.runSecurity } : {}) };
  const password = envPasswordFor(svc.user, opts.env ?? process.env) ?? await readRolePassword(svc.user, pwOpts);
  const client = (opts.pgClient ?? ((c: pg.ClientConfig) => new pg.Client(c)))({
    host: svc.host,
    port: svc.port,
    database: svc.dbname,
    user: svc.user,
    password,
    ssl: { rejectUnauthorized: true, servername: svc.host },
    enableChannelBinding: true,
    application_name: 'zeusi-cli',
    connectionTimeoutMillis: 15_000,
  });
  let usedPlus = false;
  const internals = client as unknown as PgClientInternals;
  const refuse = (why: string) => internals.connection.emit('error', new ConnectError(`refused: ${why} (channel_binding=require)`));
  const origSasl = internals._handleAuthSASL.bind(client);
  internals._handleAuthSASL = (msg) => {
    if (!msg.mechanisms.includes('SCRAM-SHA-256-PLUS')) return refuse('server did not offer SCRAM-SHA-256-PLUS');
    usedPlus = true;
    return origSasl(msg);
  };
  internals._handleAuthCleartextPassword = () => refuse('server asked for a cleartext password');
  internals._handleAuthMD5Password = () => refuse('server asked for an MD5 password');

  try {
    await client.connect();
  } catch (e) {
    await client.end().catch(() => {});
    const msg = e instanceof Error ? e.message : String(e);
    throw new ConnectError(`service ${name}: connection failed: ${redact(msg, [svc.host, svc.host.replace('-pooler', ''), password])}`);
  }
  const stream = internals.connection.stream;
  const tls = stream instanceof TLSSocket && stream.encrypted === true && stream.authorized === true;
  if (!tls || !usedPlus) {
    await client.end().catch(() => {});
    throw new ConnectError(`service ${name}: refused: TLS verified=${tls ? 'yes' : 'no'}, channel binding=${usedPlus ? 'yes' : 'no'}`);
  }
  return {
    label: `service ${name}`,
    transport: { tls, channelBinding: usedPlus },
    async query<T>(sql: string, params?: unknown[]) {
      const r = await client.query(sql, params as unknown[] | undefined);
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

export { ConfigError };
