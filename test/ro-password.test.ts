// U6d: the read-only role's narrow env-password exception (ZEUSI_NEON_BOX_RO_PASSWORD).
// No network: connectService gets an injected pg client factory whose connect() fails
// (or succeeds without TLS) offline; the password the factory receives is inspected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, chmodSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { connectService, ConnectError, RO_PASSWORD_ENV, RO_ENV_PASSWORD_ROLE, type PgClientFactory } from '../src/db.ts';
import { SEARCH_SERVICE, SERVICE_FOR_ROLE } from '../src/service.ts';
import type { SecurityRunner } from '../src/keychain.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { assertRejectsRedacted, assertSecretEqual, assertSecretsEqual } from './redact.ts';
import { withPlatform } from './helpers/platform.ts';

const FAKE_HOST = ['ep-fake-111', '-pooler.eu-central-1.aws.neon.tech'].join('');
const ENV_PW = ['ro-env-', 'pw-never-', 'print-42'].join('');
const KC_PW = ['keychain-', 'pw-', 'zzz'].join('');

function setup(user: string, service: string) {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-ro-'));
  const file = join(home, 'pg_service.conf');
  writeFileSync(file, `[${service}]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
  return { home, file };
}

/** Factory that records the password and fails connect() with an error that echoes it (worst case). */
function failing(seen: string[]): PgClientFactory {
  return (cfg) => {
    const c = new pg.Client(cfg);
    seen.push(String(cfg.password));
    c.connect = (async () => { throw new Error(`password authentication failed for user with password "${String(cfg.password)}" at ${FAKE_HOST}`); }) as typeof c.connect;
    c.end = (async () => {}) as typeof c.end;
    return c;
  };
}

const keychain: SecurityRunner = async () => ({ code: 0, stdout: `${KC_PW}\n` });
const noKeychain: SecurityRunner = async () => ({ code: 44, stdout: '' });

test('zeusi_box_ro via service zeusi_ro takes ZEUSI_NEON_BOX_RO_PASSWORD; the error never contains it', async () => {
  assert.equal(SEARCH_SERVICE, 'zeusi_ro');
  assert.equal(SERVICE_FOR_ROLE.zeusi_box_ro, SEARCH_SERVICE);
  assert.equal(RO_ENV_PASSWORD_ROLE, 'zeusi_box_ro');
  const { home, file } = setup('zeusi_box_ro', 'zeusi_ro');
  const seen: string[] = [];
  let caught: unknown;
  try {
    await connectService('zeusi_ro', { env: { PGSERVICEFILE: file, [RO_PASSWORD_ENV]: ENV_PW }, home, runSecurity: noKeychain, pgClient: failing(seen) });
  } catch (e) {
    caught = e;
  }
  assertSecretsEqual(seen, [ENV_PW], 'env password used for zeusi_box_ro');
  assert.ok(caught instanceof ConnectError);
  const all = [String(caught), (caught as Error).message, (caught as Error).stack ?? '', JSON.stringify(caught)].join('\n');
  assert.ok(!all.includes(ENV_PW), 'password redacted');
  assert.ok(!all.includes(FAKE_HOST), 'host redacted');
  // never written to disk: nothing new in the temp home except the service file
  assert.deepEqual(readdirSync(home), ['pg_service.conf']);
  assert.ok(!readFileSync(file, 'utf8').includes(ENV_PW));
});

test('zeusi_box_ro without the env var falls back to the Keychain / ~/.pgpass as before', () => withPlatform('darwin', async () => {
  const { home, file } = setup('zeusi_box_ro', 'zeusi_ro');
  const seen: string[] = [];
  await assert.rejects(connectService('zeusi_ro', { env: { PGSERVICEFILE: file }, home, runSecurity: keychain, pgClient: failing(seen) }), ConnectError);
  assertSecretsEqual(seen, [KC_PW], 'Keychain password');
  const pgpass = join(home, '.pgpass');
  writeFileSync(pgpass, `*:*:zeusi:zeusi_box_ro:${KC_PW}-file\n`);
  chmodSync(pgpass, 0o600);
  await assert.rejects(connectService('zeusi_ro', { env: { PGSERVICEFILE: file, [RO_PASSWORD_ENV]: '' }, home, runSecurity: noKeychain, pgClient: failing(seen) }), ConnectError);
  assertSecretEqual(seen.at(-1), `${KC_PW}-file`, 'an empty env var is ignored');
}));

test('no other role honours an env password (ro var, or any look-alike var)', () => withPlatform('darwin', async () => {
  const roles: Array<[string, string]> = [
    ['zeusi_mini_ingest', 'zeusi_ingest'], ['zeusi_mini_backup', 'zeusi_backup'], ['zeusi_box_rw', 'zeusi_rw'], ['zeusi_cloud_ro', 'zeusi_cloud'],
    ['zeusi_box_decision', 'zeusi_decision'], // 0012 (not applied): no env-password exception either
  ];
  for (const [user, service] of roles) {
    const { home, file } = setup(user, service);
    const env: NodeJS.ProcessEnv = {
      PGSERVICEFILE: file, [RO_PASSWORD_ENV]: ENV_PW, PGPASSWORD: ENV_PW,
      [`ZEUSI_NEON_${user.toUpperCase()}_PASSWORD`]: ENV_PW, ZEUSI_NEON_BOX_RW_PASSWORD: ENV_PW, ZEUSI_NEON_PASSWORD: ENV_PW,
    };
    const seen: string[] = [];
    await assert.rejects(connectService(service, { env, home, runSecurity: keychain, pgClient: failing(seen) }), ConnectError);
    assertSecretsEqual(seen, [KC_PW], `${user} ignores every env password`);
    // and with no Keychain / pgpass entry it fails without a password, naming no value
    await assertRejectsRedacted(connectService(service, { env, home, runSecurity: noKeychain, pgClient: failing(seen) }),
      (e) => /No password for role/.test(e.message), [ENV_PW]);
  }
}));

test('the env password is honoured by USER, not by service name (a renamed section for another role gets nothing)', () => withPlatform('darwin', async () => {
  const { home, file } = setup('zeusi_box_rw', 'zeusi_ro');
  const seen: string[] = [];
  await assert.rejects(connectService('zeusi_ro', { env: { PGSERVICEFILE: file, [RO_PASSWORD_ENV]: ENV_PW }, home, runSecurity: keychain, pgClient: failing(seen) }), ConnectError);
  assertSecretsEqual(seen, [KC_PW], 'Keychain password');
}));

test('ro connections keep verify-full + channel_binding=require (pg client config)', async () => {
  const { home, file } = setup('zeusi_box_ro', 'zeusi_ro');
  let cfgSeen: pg.ClientConfig | undefined;
  const f: PgClientFactory = (cfg) => {
    cfgSeen = cfg;
    return failing([])(cfg);
  };
  await assert.rejects(connectService('zeusi_ro', { env: { PGSERVICEFILE: file, [RO_PASSWORD_ENV]: ENV_PW }, home, pgClient: f }), ConnectError);
  assert.equal(cfgSeen!.enableChannelBinding, true);
  assert.deepEqual(cfgSeen!.ssl, { rejectUnauthorized: true, servername: FAKE_HOST });
  assert.ok(!('connectionString' in cfgSeen!), 'no URL string that could be logged');
});
