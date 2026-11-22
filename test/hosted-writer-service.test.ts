// U6 (docs/plans/2026-11-18-workspace-write-import-plan.md KTD3): the --tenant-writer-service flag
// and its startup preflight (direct host only, the writer login, a PGPASSFILE line). Temp files only;
// nothing connects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DEFAULT_WORKSPACE_IMPORT_DIR, McpArgsError, parseMcpArgs, poolerReason, TMPFS_MAGIC, workDirProblem, workspaceWriteSetup,
} from '../src/mcp.ts';
import { TENANT_RT_ROLE, TENANT_WR_ROLE, TenantRouter } from '../src/tenants.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const HOST = ['ep-fake-778', '.example.invalid'].join('');
const POOLER = ['ep-fake-778', '-POOLER', '.example.invalid'].join('');
const PW = ['Synthetic', 'WriterPw', '6Tn'].join('-');
const svc = (name: string, user: string, host = HOST) =>
  `[${name}]\nhost=${host}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;

function setup(o: { wrHost?: string; wrUser?: string; line?: boolean } = {}): { env: NodeJS.ProcessEnv; root: string } {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-hws-'));
  const run = safeMkdtemp(join(tmpdir(), 'zeusi-hws-run-'));
  const services = join(run, 'pg_service.conf');
  const wrHost = o.wrHost ?? HOST;
  writeFileSync(services, [svc('zeusi_tenant_rt', TENANT_RT_ROLE), svc('zeusi_tenant_wr', o.wrUser ?? TENANT_WR_ROLE, wrHost)].join('\n'));
  const pgpass = join(run, 'pgpass');
  writeFileSync(pgpass, [`${HOST}:5432:zeusi:${TENANT_RT_ROLE}:${PW}`, ...(o.line === false ? [] : [`${wrHost}:5432:zeusi:${o.wrUser ?? TENANT_WR_ROLE}:${PW}w`]), ''].join('\n'));
  chmodSync(pgpass, 0o600);
  return { env: { HOME: home, PGSERVICEFILE: services, PGPASSFILE: pgpass }, root: join(run, 'workspace-import') };
}

const router = new TenantRouter({ connectRuntime: async () => { throw new Error('never connects'); } });
const never = async () => { throw new Error('never connects'); };

test('flag: --tenant-writer-service needs --hosted and the two workspace services; a service name only', () => {
  const a = parseMcpArgs(['--hosted', '--tenant-service', 'zeusi_tenant_rt', '--tenant-admin-service', 'zeusi_tenant_admin', '--tenant-writer-service', 'zeusi_tenant_wr']);
  assert.equal(a.tenantWriterService, 'zeusi_tenant_wr');
  assert.equal(parseMcpArgs(['--hosted']).tenantWriterService, undefined);
  assert.throws(() => parseMcpArgs(['--hosted', '--tenant-writer-service', 'zeusi_tenant_wr']), /needs --tenant-service/);
  assert.throws(() => parseMcpArgs(['--tenant-writer-service', 'zeusi_tenant_wr']), /need --hosted/);
  assert.throws(() => parseMcpArgs(['--hosted', '--tenant-service', 'a', '--tenant-admin-service', 'b', '--tenant-writer-service', 'x;y']), McpArgsError);
});

test('setup: a direct host + the writer login + a pgpass line -> writes on; nothing connects', () => {
  const { env, root } = setup();
  // /dev is its own filesystem (devfs / devtmpfs) on macOS and Linux: a protected dir elsewhere passes.
  const s = workspaceWriteSetup({ tenantWriterService: 'zeusi_tenant_wr' }, env, never, router, { root, protect: ['/dev'] });
  assert.ok(s.writes);
  assert.equal(s.log, undefined);
  assert.match(s.status, /^on/);
  s.writes!.close();
});

test('setup: a -pooler host (any case), another login, no pgpass line, sign-up off, or no flag -> writes OFF with one loud line; no host or value in it', () => {
  const cases: Array<[ReturnType<typeof setup>, TenantRouter | undefined, RegExp]> = [
    [setup({ wrHost: POOLER }), router, new RegExp(poolerReason('zeusi_tenant_wr').replace(/[()]/g, '\\$&'))],
    [setup({ wrUser: TENANT_RT_ROLE }), router, /logs in as zeusi_tenant_rt; it must be zeusi_tenant_wr/],
    [setup({ line: false }), router, /no line in PGPASSFILE matches service zeusi_tenant_wr/],
    [setup(), undefined, /personal workspaces are not served/],
  ];
  for (const [{ env, root }, r, re] of cases) {
    const s = workspaceWriteSetup({ tenantWriterService: 'zeusi_tenant_wr' }, env, never, r, { root, protect: [] });
    assert.equal(s.writes, undefined);
    assert.match(s.log ?? '', /^zeusi-mcp: WORKSPACE WRITES OFF: /);
    assert.match(s.log ?? '', re);
    for (const leak of [HOST, POOLER.toLowerCase(), PW]) assert.ok(!(s.log ?? '').toLowerCase().includes(leak.toLowerCase()), leak);
  }
  const off = workspaceWriteSetup({}, setup().env, never, router, { root: setup().root, protect: [] });
  assert.deepEqual(off, { status: 'off (no --tenant-writer-service)' });
});

// Review P1-1 of #32: preview files live off the data volume that holds mcp-oauth.json and the ledgers.
test('review P1-1: --workspace-import-dir defaults off /data (root disk), must be absolute and named workspace-import; hosted only', () => {
  const a = parseMcpArgs(['--hosted']);
  assert.equal(a.workspaceImportDir, DEFAULT_WORKSPACE_IMPORT_DIR);
  assert.ok(!a.workspaceImportDir!.startsWith(`${a.dataDir}/`), 'the default is not under the data dir');
  assert.ok(!DEFAULT_WORKSPACE_IMPORT_DIR.startsWith('/dev/shm') && !DEFAULT_WORKSPACE_IMPORT_DIR.startsWith('/run/'), 'not a tmpfs path');
  assert.equal(parseMcpArgs(['--hosted', '--workspace-import-dir', '/srv/scratch/workspace-import']).workspaceImportDir, '/srv/scratch/workspace-import');
  for (const bad of ['rel/workspace-import', '/srv/scratch', '/workspace-import', '/srv/workspace-import/x']) {
    assert.throws(() => parseMcpArgs(['--hosted', '--workspace-import-dir', bad]), McpArgsError, bad);
  }
  assert.throws(() => parseMcpArgs(['--workspace-import-dir', '/srv/scratch/workspace-import']), /need --hosted/);
});

test('review P1-1: a work dir on the same filesystem as the OAuth store / data dir -> writes OFF at startup, one loud line, no path, nothing wiped', () => {
  const { env, root } = setup();
  // The "data volume" here: another dir on the same filesystem as the work dir (both under tmpdir).
  const dataDir = safeMkdtemp(join(tmpdir(), 'zeusi-hws-data-'));
  writeFileSync(join(dataDir, 'mcp-oauth.json'), '{}');
  const s = workspaceWriteSetup({ tenantWriterService: 'zeusi_tenant_wr' }, env, never, router, { root, protect: ['/dev', dataDir] });
  assert.equal(s.writes, undefined);
  assert.equal(s.status, 'off (refused at startup)');
  assert.match(s.log ?? '', /^zeusi-mcp: WORKSPACE WRITES OFF: refused at startup: the workspace import dir is on the same filesystem as the data volume \(OAuth store, ledgers\)/);
  for (const leak of [root, dataDir, tmpdir()]) assert.ok(!(s.log ?? '').includes(leak), 'no path in the log line');
  assert.ok(!existsSync(root), 'no work root was created');
  assert.ok(existsSync(join(dataDir, 'mcp-oauth.json')), 'the OAuth store is untouched');
  // A data dir that cannot be checked also refuses (fail closed).
  assert.match(workDirProblem({ root, protect: [join(dataDir, 'missing')] }) ?? '', /could not be checked/);
});

test('review P1-1: a tmpfs work dir, a parent open to others or not a real dir -> refused (writes off)', () => {
  const { root } = setup();
  assert.equal(workDirProblem({ root, protect: ['/dev'] }, () => ({ type: 0 })), null);
  assert.match(workDirProblem({ root, protect: ['/dev'] }, () => ({ type: TMPFS_MAGIC })) ?? '', /on tmpfs \(memory\)/);
  const open = join(safeMkdtemp(join(tmpdir(), 'zeusi-hws-open-')), 'shared');
  mkdirSync(open, { mode: 0o755 });
  chmodSync(open, 0o755);
  assert.match(workDirProblem({ root: join(open, 'workspace-import'), protect: [] }) ?? '', /open to other users/);
  const notDir = join(safeMkdtemp(join(tmpdir(), 'zeusi-hws-file-')), 'f');
  writeFileSync(notDir, 'x');
  assert.match(workDirProblem({ root: join(notDir, 'workspace-import'), protect: [] }) ?? '', /could not be created|not a real directory/);
  assert.match(workDirProblem({ root: join(tmpdir(), 'elsewhere'), protect: [] }) ?? '', /named workspace-import/);
});
