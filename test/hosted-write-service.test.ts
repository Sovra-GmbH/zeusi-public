// Hosted write service (docs/hosting.md "Write service"): PGPASSFILE support in the role
// password reader (a PATH, libpq semantics, same 0600 rule) and the --hosted startup preflight
// (src/mcp.ts hostedWritePreflight). Temp files only; nothing connects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync } from 'node:fs';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connectService, RO_PASSWORD_ENV } from '../src/db.ts';
import { pgpassFilePath, readRolePassword, type SecurityRunner } from '../src/keychain.ts';
import { hostedWritePreflight } from '../src/mcp.ts';
import { TRANSPORT_ENV } from '../src/transport.ts';
import { assertRejectsRedacted, assertSecretEqual } from './redact.ts';

const HOST = ['ep-fake-555', '-pooler.eu-central-1.aws.neon.tech'].join('');
const PW = ['Synthetic', 'HostedWritePw', '9Kd'].join('-');

const svc = (name: string, user: string, host = HOST) =>
  `[${name}]\nhost=${host}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;

function setup(o: { pgpass?: string; mode?: number; services?: string } = {}): { home: string; env: NodeJS.ProcessEnv; pgpass: string } {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-hws-'));
  const run = safeMkdtemp(join(tmpdir(), 'zeusi-hws-run-'));
  const services = join(run, 'pg_service.conf');
  writeFileSync(services, o.services ?? [svc('zeusi_ro', 'zeusi_box_ro'), svc('zeusi_decision', 'zeusi_box_decision'), svc('zeusi_rw', 'zeusi_box_rw')].join('\n'));
  const pgpass = join(run, 'pgpass');
  writeFileSync(pgpass, o.pgpass ?? `${HOST}:5432:zeusi:zeusi_box_decision:${PW}\n`);
  chmodSync(pgpass, o.mode ?? 0o600);
  return { home, pgpass, env: { HOME: home, PGSERVICEFILE: services, PGPASSFILE: pgpass } };
}

test('PGPASSFILE: names the pgpass file when set and non-empty, else ~/.pgpass', () => {
  assert.equal(pgpassFilePath({ PGPASSFILE: '/run/zeusi/pgpass' }, '/home/x'), '/run/zeusi/pgpass');
  assert.equal(pgpassFilePath({ PGPASSFILE: ' ' }, '/home/x'), '/home/x/.pgpass');
  assert.equal(pgpassFilePath({}, '/home/x'), '/home/x/.pgpass');
});

test('PGPASSFILE: readRolePassword reads it (0600 only), matching host/port/dbname/user like ~/.pgpass', async () => {
  const { env, home, pgpass } = setup();
  const key = { platform: 'linux' as const, home, env, host: HOST, port: 5432, dbname: 'zeusi' };
  assertSecretEqual(await readRolePassword('zeusi_box_decision', key), PW, 'decision password from PGPASSFILE');
  await assertRejectsRedacted(readRolePassword('zeusi_box_rw', key), (e) => /No password for role zeusi_box_rw/.test(e.message), [PW]);
  await assert.rejects(readRolePassword('zeusi_box_decision', { ...key, host: 'other.example.invalid' }), /No password/);
  chmodSync(pgpass, 0o644);
  await assertRejectsRedacted(readRolePassword('zeusi_box_decision', key), (e) => /must be mode 0600/.test(e.message), [PW]);
});

test('PGPASSFILE: connectService hands the decision login its file password; the ro env password is still never used for it', async () => {
  const { env, home } = setup();
  // Hermetic: a fake Keychain that has no item, so the PGPASSFILE is the only source. Without
  // this, darwin would ask the REAL login Keychain first (the incident this guards against).
  const securityCalls: string[][] = [];
  const noKeychain: SecurityRunner = async (a) => { securityCalls.push(a); return { code: 44, stdout: '' }; };
  let seen: { user?: string | undefined; password?: unknown } = {};
  const stop = new Error('stop before connect');
  await assert.rejects(connectService('zeusi_decision', {
    env: { ...env, [RO_PASSWORD_ENV]: 'fake-ro-env-pw' }, home, runSecurity: noKeychain,
    pgClient: (c) => { seen = { user: c.user, password: c.password }; throw stop; },
  }), (e: unknown) => e === stop);
  assert.equal(seen.user, 'zeusi_box_decision');
  assertSecretEqual(seen.password, PW, 'decision login password');
  if (process.platform === 'darwin') assert.equal(securityCalls.length, 1, 'the injected fake, not /usr/bin/security, was asked');
});

test('hosted preflight: zeusi_decision with a matching PGPASSFILE line passes', () => {
  const { env, home } = setup();
  assert.deepEqual(hostedWritePreflight('zeusi_decision', env, home), { ok: true });
});

test('hosted preflight: every misconfiguration is refused with a reason naming no password and no host', () => {
  const cases: Array<[string, () => ReturnType<typeof hostedWritePreflight>, RegExp]> = [
    ['missing section', () => { const s = setup(); return hostedWritePreflight('zeusi_nope', s.env, s.home); }, /Service "zeusi_nope" not found/],
    ['ro login', () => { const s = setup(); return hostedWritePreflight('zeusi_ro', s.env, s.home); }, /logs in as zeusi_box_ro; the hosted write service runs only zeusi_box_decision/],
    ['transitional rw', () => { const s = setup(); return hostedWritePreflight('zeusi_rw', s.env, s.home); }, /logs in as zeusi_box_rw/],
    ['no PGPASSFILE', () => { const s = setup(); const { PGPASSFILE: _drop, ...env } = s.env; return hostedWritePreflight('zeusi_decision', env, s.home); }, /PGPASSFILE is not set/],
    ['file gone', () => { const s = setup(); return hostedWritePreflight('zeusi_decision', { ...s.env, PGPASSFILE: join(s.home, 'nope') }, s.home); }, /does not exist/],
    ['loose mode', () => { const s = setup({ mode: 0o640 }); return hostedWritePreflight('zeusi_decision', s.env, s.home); }, /must be mode 0600/],
    ['wrong host line', () => { const s = setup({ pgpass: `other.example.invalid:5432:zeusi:zeusi_box_decision:${PW}\n` }); return hostedWritePreflight('zeusi_decision', s.env, s.home); }, /no line in PGPASSFILE matches service zeusi_decision/],
    ['serverless', () => { const s = setup(); return hostedWritePreflight('zeusi_decision', { ...s.env, [TRANSPORT_ENV]: 'serverless' }, s.home); }, /read-only roles; writes need TCP/],
  ];
  for (const [label, run, re] of cases) {
    const r = run();
    assert.equal(r.ok, false, label);
    if (r.ok) continue;
    assert.match(r.reason, re, label);
    assert.ok(!r.reason.includes(PW) && !r.reason.includes(HOST), `${label}: no value in the reason`);
  }
});
