// r2 MINOR-1: endpoint guard for importers.
//
// The vault importer serialises runs with a SESSION-level pg_try_advisory_lock. Over
// Neon's pooled endpoint (PgBouncer, transaction mode) consecutive statements can land
// on different server backends, so the lock neither excludes a second run nor reliably
// unlocks. Importers must therefore use the DIRECT endpoint (the pooled host without
// "-pooler"). This guard runs offline, after the service file is parsed and validated
// (TLS / channel binding checks unchanged) and BEFORE any password is read or any
// connection is opened. Errors name the service and file, never the host.

import { ConfigError } from './config.ts';
import { connectService, type Db } from './db.ts';
import { resolveService, type ResolveOptions, type ServiceConfig } from './service.ts';

export class PooledEndpointRefused extends ConfigError {
  constructor(name: string, file: string) {
    super(
      `Service "${name}" in ${file} points at a pooled endpoint (host contains "-pooler"); refused, no connection made. ` +
        'The importer holds a session advisory lock, which does not hold over the pooler (transaction mode). ' +
        `Set host= in [${name}] to the DIRECT endpoint (the same host without "-pooler"); see docs/neon.md.`,
    );
    this.name = 'PooledEndpointRefused';
  }
}

/** Neon convention: the pooled host has "-pooler" appended to the endpoint id. */
export function isPooledHost(host: string): boolean {
  return host.toLowerCase().includes('-pooler');
}

/** Resolve + validate a service and refuse a pooled host. Offline; never prints the host. */
export function requireDirectEndpoint(name: string, opts: ResolveOptions = {}): ServiceConfig {
  return checkDirect(resolveService(name, opts));
}

function checkDirect(svc: ServiceConfig): ServiceConfig {
  if (isPooledHost(svc.host)) throw new PooledEndpointRefused(svc.name, svc.file);
  return svc;
}

export interface DirectConnectDeps {
  resolve: (name: string) => ServiceConfig;
  /** Reads the role password (Keychain / ~/.pgpass) and connects. Never reached for a pooled host. */
  connect: (name: string) => Promise<Db>;
}

const DEFAULT_DEPS: DirectConnectDeps = { resolve: (n) => resolveService(n), connect: (n) => connectService(n) };

/** Guard, then connect. Used by `ingest vault --real`. */
export async function connectDirectService(name: string, deps: DirectConnectDeps = DEFAULT_DEPS): Promise<Db> {
  checkDirect(deps.resolve(name));
  return deps.connect(name);
}
