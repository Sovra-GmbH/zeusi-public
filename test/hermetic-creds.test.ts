// Tests never touch a real credential store (incident: a test resolved a real Keychain password on
// the Mini and an assert printed it). The hard guard in src/keychain.ts refuses, in test mode
// (NODE_TEST_CONTEXT under node --test, or ZEUSI_TEST_NO_REAL_CREDS=1 set by `npm test`), the
// real `security` binary, the keychain.py helper, and the real user's ~/.pgpass /
// ~/.pg_service.conf. Each case below is a lookup with NO injection: it must throw, not read.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertNotRealCredentialFile, defaultSecurityRunner, KeychainError, NO_REAL_CREDS_ENV, readKeychainPassword, readPgpass,
  readRolePassword, realCredentialStoresBlocked,
} from '../src/keychain.ts';
import { resolveService } from '../src/service.ts';
import { connectService } from '../src/db.ts';

const TEST_MODE = /test mode \(NODE_TEST_CONTEXT \/ ZEUSI_TEST_NO_REAL_CREDS=1\): refusing to read the real/;
const REAL_HOME = userInfo().homedir;
// Role names that cannot exist anywhere; even so, nothing below may reach a real store.
const ROLE = 'zeusi_hermetic_probe_nonexistent';

const isRefusal = (e: unknown) => e instanceof KeychainError && TEST_MODE.test(e.message);

test('test mode is on in every test process (node --test sets NODE_TEST_CONTEXT)', () => {
  assert.ok((process.env['NODE_TEST_CONTEXT'] ?? '') !== '', 'NODE_TEST_CONTEXT is set by the node test runner');
  assert.equal(realCredentialStoresBlocked(), true);
  assert.equal(realCredentialStoresBlocked({}), false, 'outside tests the guard is off');
  assert.equal(realCredentialStoresBlocked({ [NO_REAL_CREDS_ENV]: '1' }), true);
  assert.equal(realCredentialStoresBlocked({ NODE_TEST_CONTEXT: 'child-v8' }), true);
});

test('the default `security` runner throws in test mode (never spawns /usr/bin/security)', async () => {
  await assert.rejects(defaultSecurityRunner(['find-generic-password', '-s', `zeusi-neon-${ROLE}`, '-a', ROLE, '-w']), isRefusal);
});

test('readRolePassword on darwin with no injected runner throws instead of asking the real Keychain', async () => {
  await assert.rejects(readRolePassword(ROLE, { platform: 'darwin', home: '/nonexistent', env: {} }), isRefusal);
});

test('connectService with no injected runner throws instead of asking the real Keychain (the incident path)', async () => {
  // Same shape as the incident: a service file + a pgpass file, but no runSecurity. On darwin the
  // Keychain is tried first, so the guard must fire; elsewhere only the temp pgpass is read.
  if (process.platform !== 'darwin') return;
  const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
  const svc = join(dir, 'hermetic-pg_service.conf');
  await assert.rejects(
    connectService('zeusi_hermetic', { env: { PGSERVICEFILE: svc, PGPASSFILE: '/nonexistent/pgpass' }, home: '/nonexistent', pgClient: () => { throw new Error('must not connect'); } }),
    isRefusal,
  );
});

test('readKeychainPassword (keychain.py helper) throws in test mode', async () => {
  await assert.rejects(readKeychainPassword('zeusi-hermetic-probe-nonexistent', ROLE), isRefusal);
});

test('scripts/keychain.py refuses to open the Keychain under ZEUSI_TEST_NO_REAL_CREDS=1 or NODE_TEST_CONTEXT', () => {
  const py = spawnSync('python3', ['-c', 'pass'], { encoding: 'utf8' });
  if (py.error || py.status !== 0) return; // no python3 on this host
  const helper = fileURLToPath(new URL('../scripts/keychain.py', import.meta.url));
  for (const env of [{ [NO_REAL_CREDS_ENV]: '1' }, { NODE_TEST_CONTEXT: 'child' }]) {
    const r = spawnSync('python3', ['-I', helper, 'present', '--service', 'zeusi-hermetic-probe-nonexistent', '--account', ROLE], {
      encoding: 'utf8', env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ...env },
    });
    assert.notEqual(r.status, 0, JSON.stringify(env));
    assert.match(r.stderr, /test mode .*refusing to open the real Keychain/, JSON.stringify(env));
    assert.doesNotMatch(r.stdout, /present|absent/, 'never reached the Keychain');
  }
});

test('the real ~/.pgpass and ~/.pg_service.conf are refused in test mode (even when passed explicitly)', () => {
  const key = { host: 'h', port: 5432, dbname: 'd', user: ROLE };
  assert.throws(() => readPgpass(join(REAL_HOME, '.pgpass'), key), isRefusal);
  assert.throws(() => assertNotRealCredentialFile(join(REAL_HOME, '.pg_service.conf')), isRefusal);
  assert.throws(() => resolveService(ROLE, { env: {}, home: REAL_HOME }), isRefusal);
  assert.throws(() => resolveService(ROLE, { env: { PGSERVICEFILE: join(REAL_HOME, '.pg_service.conf') } }), isRefusal);
  // a temp path is fine (no throw from the guard; the file just isn't there)
  assert.doesNotThrow(() => assertNotRealCredentialFile('/nonexistent/.pgpass'));
  assert.equal(readPgpass('/nonexistent/.pgpass', key), undefined);
});

test('readRolePassword falling back to the real ~/.pgpass throws instead of reading it', async () => {
  await assert.rejects(readRolePassword(ROLE, { platform: 'linux', home: REAL_HOME, env: {} }), isRefusal);
});

test('npm test runs with HOME in a temp dir, the guard flag set, and no credential env', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { scripts: Record<string, string> };
  assert.equal(pkg.scripts['test'], 'node scripts/test-hermetic.ts');
  if (process.env[NO_REAL_CREDS_ENV] !== '1') return; // run directly with node --test, not via npm test
  assert.notEqual(process.env['HOME'], REAL_HOME, 'HOME is a temp dir, so ~/.pgpass cannot leak in');
  for (const k of Object.keys(process.env)) {
    assert.ok(!/^(PG|DATABASE_URL)|PASSWORD|PASSWD|SECRET|TOKEN|API_KEY/i.test(k), `credential env ${k} was scrubbed`);
  }
});
