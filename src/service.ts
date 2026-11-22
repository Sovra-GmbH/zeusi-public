// libpq-style connection services (PLAN.md KTD11, U1).
//
// Role connections are described by a pg_service.conf section (outside every repo):
//   ~/.pg_service.conf, or the file named by PGSERVICEFILE.
// The section holds host, port, dbname, user and the TLS settings. It must NOT hold
// a password: the password comes from the macOS Keychain item zeusi-neon-<user>
// (account <user>), or ~/.pgpass (0600) (or the file named by PGPASSFILE,
// a path, as libpq; the hosted Fly entrypoint uses it). See src/keychain.ts.
//
// Zeusi refuses a service unless it has sslmode=verify-full, sslrootcert=system and
// channel_binding=require. Errors name the service and file, never a value.
// Inherited PG* / DATABASE_URL env vars are ignored for role connections
// (never take DB credentials from the environment), except the two
// PATHS PGSERVICEFILE and PGPASSFILE, which name files as in libpq.
//
// ONE deliberate, narrow exception (U6, KTD16): the read-only search login
// zeusi_box_ro (service zeusi_ro, pooled endpoint) may take its password from
// ZEUSI_NEON_BOX_RO_PASSWORD on the box. It is read only inside connectService()
// (src/db.ts), only when the section's user= is zeusi_box_ro, never printed, logged,
// put in a URL or written to disk. Every other role ignores it. Else ~/.pgpass as today.

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { ConfigError } from './config.ts';
import { assertNotRealCredentialFile } from './keychain.ts';

/**
 * Which service each login role uses. Mini: ingest and backup (both DIRECT: the importer holds a
 * session advisory lock, see src/endpoint-guard.ts; pg_dump must not use the pooler). Box: rw, ro, decision (pooled).
 */
export const SERVICE_FOR_ROLE = {
  zeusi_mini_ingest: 'zeusi_ingest',
  zeusi_mini_backup: 'zeusi_backup',
  zeusi_box_rw: 'zeusi_rw',
  zeusi_box_ro: 'zeusi_ro',
  /** migrations/0012 (NOT applied yet): the narrow decision-write login for zeusi_log_decision. */
  zeusi_box_decision: 'zeusi_decision',
} as const;

export const DEFAULT_SERVICE = 'zeusi_ingest';
/** `zeusi search` default: the read-only box login on the pooled endpoint. */
export const SEARCH_SERVICE = 'zeusi_ro';
export const ROLES_SERVICE = 'zeusi_backup';

export interface ServiceConfig {
  name: string;
  host: string;
  port: number;
  dbname: string;
  user: string;
  sslmode: 'verify-full';
  sslrootcert: 'system';
  channelBinding: 'require';
  /** Path of the service file (safe to print). */
  file: string;
}

const KNOWN_KEYS = new Set([
  'host', 'hostaddr', 'port', 'dbname', 'user', 'sslmode', 'sslrootcert', 'channel_binding',
  'application_name', 'connect_timeout', 'sslnegotiation', 'target_session_attrs', 'options',
]);

export function serviceFilePath(env: NodeJS.ProcessEnv = process.env, home: string = homedir()): string {
  const f = env['PGSERVICEFILE'];
  return f && f.trim() !== '' ? f : join(home, '.pg_service.conf');
}

/** Parse a pg_service.conf (INI: [section], key=value, # or ; comments). */
export function parseServiceFile(text: string): Map<string, Record<string, string>> {
  const out = new Map<string, Record<string, string>>();
  let cur: Record<string, string> | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith(';')) continue;
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) {
      cur = {};
      out.set(sec[1]!.trim(), cur);
      continue;
    }
    const eq = line.indexOf('=');
    if (eq <= 0 || !cur) continue; // libpq ignores junk outside sections; so do we
    cur[line.slice(0, eq).trim().toLowerCase()] = line.slice(eq + 1).trim();
  }
  return out;
}

export interface ResolveOptions {
  env?: NodeJS.ProcessEnv;
  home?: string;
}

/** Resolve and validate one service. Throws ConfigError naming the service, never a value. */
export function resolveService(name: string, opts: ResolveOptions = {}): ServiceConfig {
  const file = serviceFilePath(opts.env ?? process.env, opts.home ?? homedir());
  assertNotRealCredentialFile(file);
  if (!existsSync(file)) {
    throw new ConfigError(
      `Service "${name}" not found: service file ${file} does not exist. ` +
        'the operator places it outside the repo (template: config/pg_service.example.conf).',
    );
  }
  const sections = parseServiceFile(readFileSync(file, 'utf8'));
  const s = sections.get(name);
  if (!s) throw new ConfigError(`Service "${name}" not found in ${file} (sections present: ${[...sections.keys()].join(', ') || 'none'}).`);

  const problems: string[] = [];
  if ('password' in s) problems.push('password= is not allowed in a service file (use the Keychain item or ~/.pgpass)');
  if ('passfile' in s) problems.push('passfile= is not supported (Zeusi reads ~/.pgpass / PGPASSFILE or the Keychain)');
  for (const k of Object.keys(s)) if (!KNOWN_KEYS.has(k) && k !== 'password' && k !== 'passfile') problems.push(`unknown key ${k}=`);
  for (const k of ['host', 'dbname', 'user']) if (!s[k]) problems.push(`${k}= is required`);
  if (s['sslmode'] !== 'verify-full') {
    problems.push(`sslmode=${s['sslmode'] ?? '(unset)'} refused: Zeusi requires sslmode=verify-full (and channel_binding=require)`);
  }
  if (s['channel_binding'] !== 'require') {
    problems.push(`channel_binding=${s['channel_binding'] ?? '(unset)'} refused: Zeusi requires channel_binding=require (SCRAM-SHA-256-PLUS)`);
  }
  if (s['sslrootcert'] !== 'system') {
    problems.push('sslrootcert must be sslrootcert=system (verify against the trusted root store)');
  }
  const port = s['port'] === undefined ? 5432 : Number(s['port']);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) problems.push('port= must be a TCP port number');
  if (problems.length) throw new ConfigError(`Service "${name}" in ${file} is refused:\n  - ${problems.join('\n  - ')}`);

  return {
    name,
    host: s['host']!,
    port,
    dbname: s['dbname']!,
    user: s['user']!,
    sslmode: 'verify-full',
    sslrootcert: 'system',
    channelBinding: 'require',
    file,
  };
}
