// U6 (docs/plans/2026-11-18-open-signup-workspaces-plan.md KTD12): the --hosted flags and the startup
// preflight for the two personal-workspace logins. Temp files only; nothing connects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hostedTenantPreflight, hostedWritePreflight, McpArgsError, parseMcpArgs, poolerReason, tenantSignupSetup } from '../src/mcp.ts';
import { TENANT_ADMIN_ROLE, TENANT_RT_ROLE } from '../src/tenants.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const HOST = ['ep-fake-777', '.example.invalid'].join('');
const PW = ['Synthetic', 'TenantPw', '4Zr'].join('-');
const svc = (name: string, user: string, host = HOST) =>
  `[${name}]\nhost=${host}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;
/** A Neon-style pooler host (synthetic, never resolvable). */
const POOLER = ['ep-fake-777', '-pooler', '.example.invalid'].join('');

function setup(o: { lines?: string; mode?: number; rtHost?: string; adminHost?: string; teamHost?: string } = {}): NodeJS.ProcessEnv {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-hts-'));
  const run = safeMkdtemp(join(tmpdir(), 'zeusi-hts-run-'));
  const services = join(run, 'pg_service.conf');
  const rtHost = o.rtHost ?? HOST;
  const adminHost = o.adminHost ?? HOST;
  const teamHost = o.teamHost ?? HOST;
  writeFileSync(services, [
    svc('zeusi_tenant_rt', TENANT_RT_ROLE, rtHost), svc('zeusi_tenant_admin', TENANT_ADMIN_ROLE, adminHost),
    svc('zeusi_ro', 'zeusi_box_ro', teamHost), svc('zeusi_decision', 'zeusi_box_decision', teamHost),
  ].join('\n'));
  const pgpass = join(run, 'pgpass');
  writeFileSync(pgpass, o.lines ?? [
    `${rtHost}:5432:zeusi:${TENANT_RT_ROLE}:${PW}`, `${adminHost}:5432:zeusi:${TENANT_ADMIN_ROLE}:${PW}x`, `${teamHost}:5432:zeusi:zeusi_box_decision:${PW}y`, '',
  ].join('\n'));
  chmodSync(pgpass, o.mode ?? 0o600);
  return { HOME: home, PGSERVICEFILE: services, PGPASSFILE: pgpass };
}

test('hosted flags: --tenant-service and --tenant-admin-service go together, need --hosted, and are service names', () => {
  const a = parseMcpArgs(['--hosted', '--tenant-service', 'zeusi_tenant_rt', '--tenant-admin-service', 'zeusi_tenant_admin']);
  assert.equal(a.tenantService, 'zeusi_tenant_rt');
  assert.equal(a.tenantAdminService, 'zeusi_tenant_admin');
  const none = parseMcpArgs(['--hosted']);
  assert.equal(none.tenantService, undefined);
  assert.equal(none.tenantAdminService, undefined);
  assert.throws(() => parseMcpArgs(['--hosted', '--tenant-service', 'zeusi_tenant_rt']), /go together/);
  assert.throws(() => parseMcpArgs(['--hosted', '--tenant-admin-service', 'zeusi_tenant_admin']), /go together/);
  assert.throws(() => parseMcpArgs(['--tenant-service', 'a', '--tenant-admin-service', 'b']), /need --hosted/);
  assert.throws(() => parseMcpArgs(['--http', '--tenant-service', 'a', '--tenant-admin-service', 'b']), McpArgsError);
  assert.throws(() => parseMcpArgs(['--hosted', '--tenant-service', 'a b', '--tenant-admin-service', 'x']), /service names/);
  assert.throws(() => parseMcpArgs(['--hosted', '--tenant-service', '$(id)', '--tenant-admin-service', 'x']), /service names/);
});

test('tenant preflight: both logins pass with their own service and a matching PGPASSFILE line', () => {
  const env = setup();
  assert.deepEqual(hostedTenantPreflight('zeusi_tenant_rt', TENANT_RT_ROLE, env), { ok: true });
  assert.deepEqual(hostedTenantPreflight('zeusi_tenant_admin', TENANT_ADMIN_ROLE, env), { ok: true });
});

test('tenant preflight: a service of another login, a missing PGPASSFILE or line, or a loose file refuses; no value in any reason', () => {
  const env = setup();
  const cases: Array<[NodeJS.ProcessEnv, string, string, RegExp]> = [
    [env, 'zeusi_ro', TENANT_RT_ROLE, /logs in as zeusi_box_ro; it must be zeusi_tenant_rt/],
    [env, 'zeusi_tenant_admin', TENANT_RT_ROLE, /it must be zeusi_tenant_rt/],
    [env, 'zeusi_tenant_rt', TENANT_ADMIN_ROLE, /it must be zeusi_tenant_admin/],
    [env, 'no_such_service', TENANT_RT_ROLE, /no_such_service/],
    [{ ...env, PGPASSFILE: '' }, 'zeusi_tenant_rt', TENANT_RT_ROLE, /PGPASSFILE is not set/],
    [{ ...env, PGPASSFILE: join(tmpdir(), 'zeusi-no-such-pgpass-file') }, 'zeusi_tenant_rt', TENANT_RT_ROLE, /does not exist/],
    [setup({ lines: `${HOST}:5432:zeusi:${TENANT_ADMIN_ROLE}:${PW}\n` }), 'zeusi_tenant_rt', TENANT_RT_ROLE, /no line in PGPASSFILE matches service zeusi_tenant_rt/],
    [setup({ mode: 0o644 }), 'zeusi_tenant_rt', TENANT_RT_ROLE, /0600/],
  ];
  for (const [e, service, login, re] of cases) {
    const r = hostedTenantPreflight(service, login, e);
    assert.equal(r.ok, false, `${service} as ${login}`);
    if (!r.ok) {
      assert.match(r.reason, re);
      assert.ok(!r.reason.includes(PW) && !r.reason.includes(HOST), 'no password or host in a reason');
    }
  }
});

test('tenant preflight (U2): a -pooler host for either workspace service is refused with the exact reason, in any case; no host in it', () => {
  const expected = (name: string) => `service ${name} points at a connection pooler (-pooler); personal workspaces need the direct endpoint because SET ROLE leaks across pooled connections`;
  assert.equal(poolerReason('zeusi_tenant_rt'), expected('zeusi_tenant_rt'));
  for (const host of [POOLER, POOLER.toUpperCase(), POOLER.replace('-pooler', '-Pooler')]) {
    const rt = hostedTenantPreflight('zeusi_tenant_rt', TENANT_RT_ROLE, setup({ rtHost: host }));
    assert.deepEqual(rt, { ok: false, reason: expected('zeusi_tenant_rt') }, host);
    const admin = hostedTenantPreflight('zeusi_tenant_admin', TENANT_ADMIN_ROLE, setup({ adminHost: host }));
    assert.deepEqual(admin, { ok: false, reason: expected('zeusi_tenant_admin') }, host);
    for (const r of [rt, admin]) if (!r.ok) assert.ok(!r.reason.toLowerCase().includes('ep-fake') && !r.reason.includes(PW));
  }
  // The direct endpoint passes (same pgpass, same services).
  assert.deepEqual(hostedTenantPreflight('zeusi_tenant_rt', TENANT_RT_ROLE, setup()), { ok: true });
  assert.deepEqual(hostedTenantPreflight('zeusi_tenant_admin', TENANT_ADMIN_ROLE, setup()), { ok: true });
});

test('tenant preflight (U2): the team read and decision services on the pooler stay allowed (the check is for workspace logins only)', () => {
  const env = setup({ teamHost: POOLER });
  assert.deepEqual(hostedWritePreflight('zeusi_decision', env), { ok: true }, 'decision service on the pooler still passes');
  // The read service has no hosted preflight at all; its user= check (src/mcp-server.ts) never looks at the host.
  assert.deepEqual(hostedTenantPreflight('zeusi_tenant_rt', TENANT_RT_ROLE, env), { ok: true }, 'workspace services on the direct host still pass');
});

test('tenant startup (U2): a pooler host keeps sign-up OFF with one loud WORKSPACE SIGN-UP OFF: line and no router; direct hosts turn it on; nothing connects', async () => {
  const connected: string[] = [];
  const connect = async (s: string) => {
    connected.push(s);
    throw new Error('must not connect at startup');
  };
  const args = { tenantService: 'zeusi_tenant_rt', tenantAdminService: 'zeusi_tenant_admin' };
  for (const env of [setup({ rtHost: POOLER }), setup({ adminHost: POOLER })]) {
    const r = tenantSignupSetup(args, env, connect);
    assert.equal(r.tenants, undefined, 'no directory, no router: personal workspaces are not routed');
    assert.equal(r.signup, 'off (refused at startup)');
    assert.match(r.log ?? '', /^zeusi-mcp: WORKSPACE SIGN-UP OFF: refused at startup: service zeusi_tenant_(rt|admin) points at a connection pooler \(-pooler\);/);
    assert.equal((r.log ?? '').split('\n').length, 1, 'one line');
    assert.match(r.log ?? '', /the team sign-in unaffected/);
    assert.ok(!(r.log ?? '').toLowerCase().includes('ep-fake') && !(r.log ?? '').includes(PW), 'no host or value in the log');
  }
  const on = tenantSignupSetup(args, setup(), connect);
  assert.equal(on.signup, 'on (personal workspaces)');
  assert.equal(on.log, undefined);
  assert.ok(on.tenants?.dir && on.tenants.router);
  assert.deepEqual(tenantSignupSetup({}, setup(), connect), { signup: 'off (no --tenant-service)' });
  assert.deepEqual(connected, [], 'startup never connects');
});
