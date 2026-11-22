// Secret loading (PLAN.md KTD11, R15). Never prints, logs, or echoes a value.
//
// * Neon role passwords (Mini): macOS Keychain generic password
//     service = zeusi-neon-<role>, account = <role>
//   read with `/usr/bin/security find-generic-password -s .. -a .. -w`. The value
//   travels only over the child's stdout pipe (never argv, never a tty).
// * Fallback / box: ~/.pgpass, or the file named by PGPASSFILE (libpq semantics: a PATH,
//   never a password; the hosted Fly entrypoint writes one), which must be mode 0600 or stricter.
// * OpenAI key (embed-smoke): scripts/keychain.py (Security framework), unchanged.

import { execFile } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const HELPER = fileURLToPath(new URL('../scripts/keychain.py', import.meta.url));
const SECURITY = '/usr/bin/security';
const ERR_ITEM_NOT_FOUND = 44; // security(1) exit code for errSecItemNotFound

export class KeychainError extends Error {
  override name = 'KeychainError';
}

// Test hermeticity guard. Under `node --test` (NODE_TEST_CONTEXT is set in every test file's
// process) or with ZEUSI_TEST_NO_REAL_CREDS=1 (npm test sets it, and test-spawned CLIs inherit
// it), the REAL credential stores refuse to open: the default `security` runner, the
// keychain.py helper, and the invoking user's real ~/.pgpass / ~/.pg_service.conf all throw.
// Tests must inject a fake runner and temp files. Always read from process.env (never from an
// injected env), so a test cannot switch the guard off by accident.
export const NO_REAL_CREDS_ENV = 'ZEUSI_TEST_NO_REAL_CREDS';

export function realCredentialStoresBlocked(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[NO_REAL_CREDS_ENV] === '1' || (env['NODE_TEST_CONTEXT'] ?? '') !== '';
}

function refuse(what: string): never {
  throw new KeychainError(`test mode (NODE_TEST_CONTEXT / ${NO_REAL_CREDS_ENV}=1): refusing to read the real ${what}; inject a fake`);
}

/** The invoking user's real home from the passwd database (ignores a test-overridden HOME). */
function realHome(): string | undefined {
  try {
    return userInfo().homedir;
  } catch {
    return undefined;
  }
}

/** Throws in test mode when `path` is the real user's ~/.pgpass or ~/.pg_service.conf. */
export function assertNotRealCredentialFile(path: string): void {
  if (!realCredentialStoresBlocked()) return;
  const home = realHome();
  if (home === undefined) return;
  const p = resolve(path);
  if (p === resolve(home, '.pgpass') || p === resolve(home, '.pg_service.conf')) refuse(`credential file ${path}`);
}

/** Runs `security` with args; returns exit code and stdout. Injectable for tests. */
export type SecurityRunner = (args: string[]) => Promise<{ code: number; stdout: string }>;

export const defaultSecurityRunner: SecurityRunner = async (args) => {
  if (realCredentialStoresBlocked()) refuse('macOS Keychain (/usr/bin/security)');
  try {
    const { stdout } = await execFileAsync(SECURITY, args, { encoding: 'utf8', timeout: 15_000, maxBuffer: 64 * 1024 });
    return { code: 0, stdout };
  } catch (e) {
    const err = e as { code?: unknown };
    return { code: typeof err.code === 'number' ? err.code : 1, stdout: '' }; // stdout/stderr deliberately dropped
  }
};

export function keychainServiceFor(role: string): string {
  return `zeusi-neon-${role}`;
}

export interface RolePasswordOptions {
  platform?: NodeJS.Platform;
  home?: string;
  runSecurity?: SecurityRunner;
  /** PGPASSFILE (a path) replaces ~/.pgpass when set and non-empty (libpq semantics). */
  env?: NodeJS.ProcessEnv;
  /** For ~/.pgpass matching. */
  host?: string;
  port?: number;
  dbname?: string;
}

export const PGPASSFILE_ENV = 'PGPASSFILE';

/** The pgpass file: PGPASSFILE when set and non-empty, else ~/.pgpass (as libpq). */
export function pgpassFilePath(env: NodeJS.ProcessEnv = {}, home: string = homedir()): string {
  const f = env[PGPASSFILE_ENV];
  return f && f.trim() !== '' ? f : join(home, '.pgpass');
}

/** Password for a login role: Keychain (darwin) first, then PGPASSFILE / ~/.pgpass. */
export async function readRolePassword(role: string, opts: RolePasswordOptions = {}): Promise<string> {
  const platform = opts.platform ?? process.platform;
  const item = keychainServiceFor(role);
  const tried: string[] = [];
  if (platform === 'darwin') {
    const r = await (opts.runSecurity ?? defaultSecurityRunner)(['find-generic-password', '-s', item, '-a', role, '-w']);
    if (r.code === 0) {
      const v = r.stdout.endsWith('\n') ? r.stdout.slice(0, -1) : r.stdout;
      if (v.length === 0) throw new KeychainError(`Keychain item ${item} (account ${role}) is empty`);
      return v;
    }
    tried.push(r.code === ERR_ITEM_NOT_FOUND
      ? `Keychain item ${item} (account ${role}) not found`
      : `Keychain item ${item} (account ${role}) not readable (security exit ${r.code})`);
  }
  const pgpassPath = pgpassFilePath(opts.env ?? {}, opts.home ?? homedir());
  const fromFile = readPgpass(pgpassPath, { host: opts.host ?? '', port: opts.port ?? 5432, dbname: opts.dbname ?? '', user: role });
  if (fromFile !== undefined) return fromFile;
  tried.push(`no matching entry in ${pgpassPath}`);
  throw new KeychainError(`No password for role ${role}: ${tried.join('; ')}.`);
}

export function readPgpass(path: string, key: PgpassKey): string | undefined {
  assertNotRealCredentialFile(path);
  let st;
  try {
    st = statSync(path);
  } catch {
    return undefined;
  }
  if ((st.mode & 0o077) !== 0) {
    throw new KeychainError(`${path} must be mode 0600 or stricter (it is ${(st.mode & 0o777).toString(8)}); refusing to read it`);
  }
  return lookupPgpass(readFileSync(path, 'utf8'), key);
}

export interface PgpassKey {
  host: string;
  port: number;
  dbname: string;
  user: string;
}

/** libpq .pgpass lookup: host:port:database:username:password, * wildcards, \: and \\ escapes. */
export function lookupPgpass(text: string, key: PgpassKey): string | undefined {
  for (const line of text.split(/\r?\n/)) {
    if (line === '' || line.startsWith('#')) continue;
    const fields: string[] = [];
    let cur = '';
    for (let i = 0; i < line.length; i++) {
      const c = line[i]!;
      if (c === '\\' && i + 1 < line.length) {
        cur += line[++i];
      } else if (c === ':' && fields.length < 4) {
        fields.push(cur);
        cur = '';
      } else {
        cur += c;
      }
    }
    fields.push(cur);
    if (fields.length !== 5) continue;
    const [h, p, d, u, pw] = fields as [string, string, string, string, string];
    const m = (pat: string, v: string) => pat === '*' || pat === v;
    if (m(h, key.host) && m(p, String(key.port)) && m(d, key.dbname) && m(u, key.user)) return pw;
  }
  return undefined;
}

/** Read a generic password via scripts/keychain.py (used for the OpenAI key). Never prints the value. */
export async function readKeychainPassword(service: string, account = process.env['USER'] ?? 'owner'): Promise<string> {
  if (realCredentialStoresBlocked()) refuse(`macOS Keychain (item ${service} via keychain.py)`);
  try {
    const { stdout } = await execFileAsync(
      'python3',
      [HELPER, 'emit', '--service', service, '--account', account],
      { encoding: 'utf8', env: { ...process.env, ZEUSI_KEYCHAIN_EMIT: '1' } },
    );
    if (!stdout) throw new KeychainError(`Keychain item ${service} is empty`);
    return stdout;
  } catch (e) {
    if (e instanceof KeychainError) throw e;
    const msg = e instanceof Error ? e.message : 'unknown error';
    throw new KeychainError(`Keychain item ${service} is not readable (${msg.split('\n')[0]})`);
  }
}
