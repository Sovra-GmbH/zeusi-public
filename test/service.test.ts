// U1: libpq-style service resolution + Keychain/pgpass secret loading (KTD11).
// No network, no real Keychain: `security` is replaced by a fake runner.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseServiceFile, resolveService, serviceFilePath, SERVICE_FOR_ROLE } from '../src/service.ts';
import { keychainServiceFor, readRolePassword, lookupPgpass, type SecurityRunner } from '../src/keychain.ts';
import { redactError, formatDoctor } from '../src/doctor.ts';
import { ConfigError } from '../src/config.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { assertRejectsRedacted, assertSecretEqual, assertThrowsRedacted } from './redact.ts';

// Fake values assembled at runtime; never real.
const FAKE_HOST = ['ep-fake-000', '-pooler.eu-central-1.aws.neon.tech'].join('');
const SECRET = ['s3cr3t', '-never-print-', 'me'].join('');

const good = (extra = '') => `
# comment
[zeusi_ingest]
host=${FAKE_HOST}
port=5432
dbname=zeusi
user=zeusi_mini_ingest
sslmode=verify-full
sslrootcert=system
channel_binding=require
${extra}
[zeusi_backup]
host=${FAKE_HOST.replace('-pooler', '')}
dbname=zeusi
user=zeusi_mini_backup
sslmode=verify-full
sslrootcert=system
channel_binding=require
`;

function svcFile(text: string): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-svc-'));
  const p = join(dir, 'pg_service.conf');
  writeFileSync(p, text);
  return p;
}

test('service file path: PGSERVICEFILE wins, else ~/.pg_service.conf', () => {
  assert.equal(serviceFilePath({ PGSERVICEFILE: '/x/y.conf' }, '/home/u'), '/x/y.conf');
  assert.equal(serviceFilePath({}, '/home/u'), '/home/u/.pg_service.conf');
});

test('service file parses sections and key=value pairs', () => {
  const m = parseServiceFile(good());
  assert.deepEqual([...m.keys()], ['zeusi_ingest', 'zeusi_backup']);
  assert.equal(m.get('zeusi_ingest')!['user'], 'zeusi_mini_ingest');
});

test('a valid service resolves (defaults port 5432)', () => {
  const s = resolveService('zeusi_backup', { env: { PGSERVICEFILE: svcFile(good()) } });
  assert.equal(s.user, 'zeusi_mini_backup');
  assert.equal(s.port, 5432);
  assert.equal(s.sslmode, 'verify-full');
});

test('sslmode=require (no verify-full) is refused with a clear error', () => {
  const f = svcFile(good().replace('sslmode=verify-full', 'sslmode=require'));
  assert.throws(() => resolveService('zeusi_ingest', { env: { PGSERVICEFILE: f } }),
    (e: Error) => e instanceof ConfigError && /zeusi_ingest/.test(e.message) && /sslmode=require/.test(e.message) && /verify-full/.test(e.message));
});

test('channel_binding other than require is refused; missing is refused', () => {
  const f1 = svcFile(good().replace('channel_binding=require', 'channel_binding=prefer'));
  assert.throws(() => resolveService('zeusi_ingest', { env: { PGSERVICEFILE: f1 } }), /channel_binding=require/);
  const f2 = svcFile(good().replace(/channel_binding=require\n(?=\n?\[zeusi_backup\])/, ''));
  assert.throws(() => resolveService('zeusi_ingest', { env: { PGSERVICEFILE: f2 } }), /channel_binding=require/);
});

test('sslrootcert must be system', () => {
  const f = svcFile(good().replace('sslrootcert=system', 'sslrootcert=/tmp/x.pem'));
  assert.throws(() => resolveService('zeusi_ingest', { env: { PGSERVICEFILE: f } }), /sslrootcert=system/);
});

test('a password in the service file is refused and never echoed', () => {
  const f = svcFile(good(`password=${SECRET}`));
  assertThrowsRedacted(() => resolveService('zeusi_ingest', { env: { PGSERVICEFILE: f } }),
    (e) => /password/.test(e.message), [SECRET]);
});

test('a missing service names the service (and file), never a password or host', () => {
  const f = svcFile(good());
  assertThrowsRedacted(() => resolveService('zeusi_rw', { env: { PGSERVICEFILE: f } }),
    (e) => /zeusi_rw/.test(e.message) && !e.message.includes(FAKE_HOST), [SECRET]);
  assert.throws(() => resolveService('zeusi_ingest', { env: { PGSERVICEFILE: '/nonexistent/pg_service.conf' } }), /zeusi_ingest.*not found|not found.*zeusi_ingest/);
});

test('DB credentials are never taken from inherited env vars for role connections', () => {
  const f = svcFile(good());
  const s = resolveService('zeusi_ingest', { env: { PGSERVICEFILE: f, PGPASSWORD: SECRET, DATABASE_URL: 'x', PGHOST: 'evil', PGUSER: 'neondb_owner' } });
  assert.equal(s.host, FAKE_HOST);
  assert.equal(s.user, 'zeusi_mini_ingest');
  assert.ok(!JSON.stringify(s).includes(SECRET));
});

test('role → service mapping covers the Mini and box roles', () => {
  assert.equal(SERVICE_FOR_ROLE.zeusi_mini_ingest, 'zeusi_ingest');
  assert.equal(SERVICE_FOR_ROLE.zeusi_mini_backup, 'zeusi_backup');
  assert.equal(SERVICE_FOR_ROLE.zeusi_box_rw, 'zeusi_rw');
  assert.equal(SERVICE_FOR_ROLE.zeusi_box_ro, 'zeusi_ro');
});

test('Keychain read uses security with service zeusi-neon-<role>, account=<role>; the value is never logged', async () => {
  const calls: string[][] = [];
  const runner: SecurityRunner = async (args) => {
    calls.push(args);
    return { code: 0, stdout: `${SECRET}\n` };
  };
  const seen: string[] = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, write: process.stdout.write.bind(process.stdout), ewrite: process.stderr.write.bind(process.stderr) };
  console.log = (...a: unknown[]) => void seen.push(a.join(' '));
  console.error = (...a: unknown[]) => void seen.push(a.join(' '));
  console.warn = (...a: unknown[]) => void seen.push(a.join(' '));
  process.stdout.write = ((s: string) => (seen.push(String(s)), true)) as typeof process.stdout.write;
  process.stderr.write = ((s: string) => (seen.push(String(s)), true)) as typeof process.stderr.write;
  let pw: string;
  try {
    pw = await readRolePassword('zeusi_mini_ingest', { platform: 'darwin', runSecurity: runner, home: '/nonexistent' });
  } finally {
    console.log = orig.log; console.error = orig.error; console.warn = orig.warn;
    process.stdout.write = orig.write; process.stderr.write = orig.ewrite;
  }
  assertSecretEqual(pw, SECRET, 'Keychain password');
  assert.equal(keychainServiceFor('zeusi_mini_ingest'), 'zeusi-neon-zeusi_mini_ingest');
  assert.deepEqual(calls, [['find-generic-password', '-s', 'zeusi-neon-zeusi_mini_ingest', '-a', 'zeusi_mini_ingest', '-w']]);
  assert.ok(!seen.join('').includes(SECRET), 'nothing printed the secret');
});

test('Keychain miss → error names the Keychain item, not a value; pgpass fallback works', async () => {
  const miss: SecurityRunner = async () => ({ code: 44, stdout: '' });
  await assert.rejects(readRolePassword('zeusi_mini_backup', { platform: 'darwin', runSecurity: miss, home: '/nonexistent' }),
    (e: Error) => /zeusi-neon-zeusi_mini_backup/.test(e.message) && /\.pgpass/.test(e.message));
  // A failing runner that echoes a secret on stdout must not leak it into the error.
  const leaky: SecurityRunner = async () => ({ code: 1, stdout: SECRET });
  await assertRejectsRedacted(readRolePassword('zeusi_mini_backup', { platform: 'darwin', runSecurity: leaky, home: '/nonexistent' }),
    () => true, [SECRET]);

  const home = safeMkdtemp(join(tmpdir(), 'zeusi-home-'));
  const pgpass = join(home, '.pgpass');
  writeFileSync(pgpass, `# c\n*:*:zeusi:zeusi_box_ro:${SECRET}\nother:5432:db:u:x\n`);
  chmodSync(pgpass, 0o600);
  const pw = await readRolePassword('zeusi_box_ro', { platform: 'linux', home, host: FAKE_HOST, port: 5432, dbname: 'zeusi' });
  assertSecretEqual(pw, SECRET, '~/.pgpass password');
  chmodSync(pgpass, 0o644);
  await assert.rejects(readRolePassword('zeusi_box_ro', { platform: 'linux', home, host: FAKE_HOST, port: 5432, dbname: 'zeusi' }), /0600/);
});

test('pgpass: escapes and wildcards', () => {
  assert.equal(lookupPgpass('h\\:x:5432:d:u:p\\:w\\\\', { host: 'h:x', port: 5432, dbname: 'd', user: 'u' }), 'p:w\\');
  assert.equal(lookupPgpass('*:*:*:u:pw', { host: 'any', port: 1, dbname: 'x', user: 'u' }), 'pw');
  assert.equal(lookupPgpass('*:*:*:other:pw', { host: 'any', port: 1, dbname: 'x', user: 'u' }), undefined);
});

test('connection errors are redacted of host, user, and password', () => {
  const e = new Error(`getaddrinfo ENOTFOUND ${FAKE_HOST} for zeusi_mini_ingest with ${SECRET}`);
  const r = redactError(e, [FAKE_HOST, SECRET]);
  assert.ok(!r.includes(FAKE_HOST) && !r.includes(SECRET));
  assert.match(r, /<host>|<redacted>/);
});

test('doctor output shows TLS, server major, pgvector — never host or credentials', () => {
  const out = formatDoctor({ service: 'zeusi_ingest', role: 'zeusi_mini_ingest', tls: true, channelBinding: true, serverMajor: 18, serverVersion: '18.7', pgvector: '0.8.7', migrations: ['0001_core.sql'] });
  assert.match(out, /TLS: yes/);
  assert.match(out, /server major: 18/);
  assert.match(out, /pgvector: present \(0\.8\.7\)/);
  assert.doesNotMatch(out, /neon\.tech|postgres(ql)?:\/\/|password/i);
});
