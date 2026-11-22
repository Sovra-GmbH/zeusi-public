// scripts/fly-entrypoint.sh behaviour (docs/hosting.md "Write service"). The script runs
// under `sh` with its two fixed paths (/data, /run/zeusi) rewritten to temp dirs and fake
// `mountpoint`, `chown` and `setpriv` on PATH. The fake setpriv prints its argv and which
// env vars node would see (never a secret value). Nothing runs as root, nothing connects.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { redact } from './redact.ts';

const SCRIPT = fileURLToPath(new URL('../scripts/fly-entrypoint.sh', import.meta.url));
const PW = ['Synthetic', 'DecisionPw', '7Qx'].join('-');
const LINE = `ep-fake-pooler.example.invalid:5432:zeusi:zeusi_box_decision:${PW}`;
const TPW = ['Synthetic', 'TenantRtPw', '2Hm'].join('-');
const APW = ['Synthetic', 'TenantAdminPw', '8Lc'].join('-');
const RT_LINE = `ep-fake-pooler.example.invalid:5432:zeusi:zeusi_tenant_rt:${TPW}`;
const ADMIN_LINE = `ep-fake-pooler.example.invalid:5432:zeusi:zeusi_tenant_admin:${APW}`;
const TENANT_ARGS = ['--tenant-service', 'zeusi_tenant_rt', '--tenant-admin-service', 'zeusi_tenant_admin'];
// PR 2 (own-workspace writes): the writer login's secret.
const WPW = ['Synthetic', 'TenantWrPw', '5Kd'].join('-');
const WR_LINE = `ep-fake.example.invalid:5432:zeusi:zeusi_tenant_wr:${WPW}`;

interface Run {
  code: number | null;
  /** stdout+stderr with PW (and the secret env value) redacted: safe in any assert message. */
  out: string;
  /** Whether the RAW output, args or env lines contained PW or the secret env value. */
  leaked: boolean;
  args: string[];
  env: Record<string, string>;
  dataDir: string;
  runDir: string;
  chowns: string[];
}

/** The image's /bin/sh is dash (Debian); run under the local sh and, when installed, dash too. */
const SHELLS = ['sh', ...(['/bin/dash', '/usr/bin/dash'].some((p) => existsSync(p)) ? ['dash'] : [])];

function run(env: Record<string, string>, o: { mounted?: boolean; shell?: string } = {}): Run {
  const root = safeMkdtemp(join(tmpdir(), 'zeusi-entry-'));
  const dataDir = join(root, 'data');
  const runDir = join(root, 'run', 'zeusi');
  const bin = join(root, 'bin');
  mkdirSync(dataDir);
  mkdirSync(join(root, 'run'));
  mkdirSync(bin);
  const script = readFileSync(SCRIPT, 'utf8');
  assert.match(script, /^DATA_DIR=\/data$/m);
  assert.match(script, /^RUN_DIR=\/run\/zeusi$/m);
  const patched = join(root, 'entry.sh');
  writeFileSync(patched, script.replace(/^DATA_DIR=\/data$/m, `DATA_DIR=${dataDir}`).replace(/^RUN_DIR=\/run\/zeusi$/m, `RUN_DIR=${runDir}`));
  const fake = (name: string, body: string) => {
    writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(bin, name), 0o755);
  };
  fake('mountpoint', o.mounted === false ? 'exit 1' : 'exit 0');
  fake('chown', `echo "$*" >> "${join(root, 'chowns')}"`);
  fake('setpriv', [
    'for a in "$@"; do printf "ARG %s\\n" "$a"; done',
    'for k in PGPASSFILE PGSERVICEFILE ZEUSI_MCP_WRITE_SERVICE; do eval "v=\\${$k-<unset>}"; printf "ENV %s=%s\\n" "$k" "$v"; done',
    'if [ -n "${ZEUSI_DECISION_PGPASS+x}" ]; then echo "ENV ZEUSI_DECISION_PGPASS=present"; else echo "ENV ZEUSI_DECISION_PGPASS=<unset>"; fi',
    'for k in ZEUSI_TENANT_RT_PGPASS ZEUSI_TENANT_ADMIN_PGPASS ZEUSI_TENANT_WR_PGPASS; do eval "p=\\${$k+x}"; if [ -n "$p" ]; then echo "ENV $k=present"; else echo "ENV $k=<unset>"; fi; done',
  ].join('\n'));
  const r = spawnSync(o.shell ?? 'sh', [patched], { env: { PATH: `${bin}:/usr/bin:/bin`, ...env }, encoding: 'utf8' });
  const raw = `${r.stdout}${r.stderr}`;
  const secrets = [PW, TPW, APW, WPW, env['ZEUSI_DECISION_PGPASS'] ?? '', env['ZEUSI_TENANT_RT_PGPASS'] ?? '', env['ZEUSI_TENANT_ADMIN_PGPASS'] ?? '', env['ZEUSI_TENANT_WR_PGPASS'] ?? ''].filter((s) => s.length >= 6);
  const leaked = secrets.some((s) => raw.includes(s));
  const out = redact(raw, secrets);
  const args: string[] = [];
  const childEnv: Record<string, string> = {};
  for (const l of r.stdout.split('\n')) {
    if (l.startsWith('ARG ')) args.push(redact(l.slice(4), secrets));
    const m = /^ENV ([A-Z_]+)=(.*)$/.exec(l);
    if (m) childEnv[m[1]!] = redact(m[2]!, secrets);
  }
  const chowns = existsSync(join(root, 'chowns')) ? readFileSync(join(root, 'chowns'), 'utf8').trim().split('\n') : [];
  return { code: r.status, out, leaked, args, env: childEnv, dataDir, runDir, chowns };
}

const readOnlyArgs = (d: string) => ['--reuid=node', '--regid=node', '--init-groups', '--', 'node', '/app/dist/mcp.js', '--hosted', '--data-dir', d];

for (const shell of SHELLS) {
  test(`[${shell}] entrypoint: write vars unset -> exactly today's read-only command, no PGPASSFILE, no password file`, () => {
    const r = run({}, { shell });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.args, readOnlyArgs(r.dataDir));
    assert.equal(r.env['PGPASSFILE'], '<unset>');
    assert.equal(r.env['ZEUSI_MCP_WRITE_SERVICE'], '<unset>');
    assert.ok(!existsSync(join(r.runDir, 'pgpass')));
    assert.equal(statSync(r.dataDir).mode & 0o777, 0o700);
    assert.ok(r.chowns.includes(`node:node ${r.dataDir}`));
    assert.match(r.out, /write service off \(read-only\)/);
  });

  test(`[${shell}] entrypoint: service + secret -> --write-service, PGPASSFILE to a node-owned 0600 file in a 0700 run dir, secret gone from env and output`, () => {
    const r = run({ ZEUSI_MCP_WRITE_SERVICE: 'zeusi_decision', ZEUSI_DECISION_PGPASS: LINE }, { shell });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.args, [...readOnlyArgs(r.dataDir), '--write-service', 'zeusi_decision']);
    const file = join(r.runDir, 'pgpass');
    assert.equal(r.env['PGPASSFILE'], file);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(statSync(r.runDir).mode & 0o777, 0o700);
    assert.equal(readFileSync(file, 'utf8'), `${LINE}\n`);
    assert.ok(r.chowns.includes(`-R node:node ${r.runDir}`), r.chowns.join('|'));
    assert.ok(r.env['ZEUSI_DECISION_PGPASS'] === '<unset>', 'node never sees the password in its environment');
    assert.ok(!r.leaked, 'the password never reaches stdout/stderr');
    assert.match(r.out, /write service ON: --write-service zeusi_decision/);
    assert.ok(!r.dataDir.startsWith(r.runDir) && !file.startsWith(r.dataDir), 'never on the volume');
  });

  test(`[${shell}] entrypoint: service set, secret missing -> read-only, loud refusal, the env fallback is removed too`, () => {
    const r = run({ ZEUSI_MCP_WRITE_SERVICE: 'zeusi_decision' }, { shell });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.args, readOnlyArgs(r.dataDir));
    assert.equal(r.env['ZEUSI_MCP_WRITE_SERVICE'], '<unset>', 'node must not pick the service up from the env (parseMcpArgs fallback)');
    assert.equal(r.env['PGPASSFILE'], '<unset>');
    assert.ok(!existsSync(join(r.runDir, 'pgpass')));
    assert.match(r.out, /write service REFUSED: .*ZEUSI_DECISION_PGPASS secret is missing; starting read-only/);
  });

  test(`[${shell}] entrypoint: malformed secrets are refused (read-only), and no value is ever printed`, () => {
    const bad = [
      `ep-fake.example.invalid:5432:zeusi:zeusi_box_ro:${PW}`, // wrong login (the ro role)
      `ep-fake.example.invalid:5432:zeusi:zeusi_box_rw:${PW}`, // transitional role is not the hosted writer
      `ep-fake.example.invalid:5432:zeusi:zeusi_box_decision:`, // empty password
      `ep-fake.example.invalid:5432:zeusi_box_decision:${PW}`, // a field missing
      `${PW}`, // a bare password
      `${LINE}\n*:*:*:zeusi_mini_backup:${PW}`, // two lines
      `${LINE}\r`, // CR
      `:5432:zeusi:zeusi_box_decision:${PW}`, // empty host
      `h\\:x:5432:zeusi:zeusi_box_decision:${PW}`, // escapes in the key fields
    ];
    for (const secret of bad) {
      const r = run({ ZEUSI_MCP_WRITE_SERVICE: 'zeusi_decision', ZEUSI_DECISION_PGPASS: secret }, { shell });
      assert.equal(r.code, 0, r.out);
      assert.deepEqual(r.args, readOnlyArgs(r.dataDir), secret.length.toString());
      assert.ok(r.env['ZEUSI_DECISION_PGPASS'] === '<unset>', 'ZEUSI_DECISION_PGPASS is unset for node');
      assert.equal(r.env['ZEUSI_MCP_WRITE_SERVICE'], '<unset>');
      assert.ok(!existsSync(join(r.runDir, 'pgpass')));
      assert.match(r.out, /write service REFUSED: ZEUSI_DECISION_PGPASS is not one pgpass line .*\(value not shown\); starting read-only/);
      assert.ok(!r.leaked, 'no value printed');
    }
  });

  test(`[${shell}] entrypoint: a password containing colons and backslashes is accepted as is`, () => {
    const line = `*:5432:zeusi:zeusi_box_decision:${PW}\\:with:colons\\\\`;
    const r = run({ ZEUSI_MCP_WRITE_SERVICE: 'zeusi_decision', ZEUSI_DECISION_PGPASS: line }, { shell });
    assert.equal(r.args.at(-1), 'zeusi_decision');
    assert.equal(readFileSync(join(r.runDir, 'pgpass'), 'utf8'), `${line}\n`);
    assert.ok(!r.leaked);
  });

  test(`[${shell}] entrypoint: a bad service name is refused (read-only), the secret alone enables nothing`, () => {
    for (const svc of ['zeusi decision', 'zeusi;rm', 'x'.repeat(65), '$(id)']) {
      const r = run({ ZEUSI_MCP_WRITE_SERVICE: svc, ZEUSI_DECISION_PGPASS: LINE }, { shell });
      assert.deepEqual(r.args, readOnlyArgs(r.dataDir));
      assert.match(r.out, /ZEUSI_MCP_WRITE_SERVICE is not a service name/);
      assert.ok(!r.leaked);
    }
    const only = run({ ZEUSI_DECISION_PGPASS: LINE }, { shell });
    assert.deepEqual(only.args, readOnlyArgs(only.dataDir));
    assert.ok(only.env['ZEUSI_DECISION_PGPASS'] === '<unset>', 'ZEUSI_DECISION_PGPASS is unset for node');
    assert.ok(!existsSync(join(only.runDir, 'pgpass')));
    assert.ok(!only.leaked);
  });

  test(`[${shell}] entrypoint: PGSERVICEFILE content is materialised to a 0600 file; a path is passed through untouched`, () => {
    const content = '[zeusi_ro]\nhost=ep-fake.example.invalid\nuser=zeusi_box_ro\n\n[zeusi_decision]\nhost=ep-fake.example.invalid\nuser=zeusi_box_decision';
    const r = run({ PGSERVICEFILE: content }, { shell });
    const file = join(r.runDir, 'pg_service.conf');
    assert.equal(r.env['PGSERVICEFILE'], file);
    assert.equal(readFileSync(file, 'utf8'), `${content}\n`);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.ok(!r.out.includes('ep-fake'), 'content not shown');
    const p = run({ PGSERVICEFILE: '/etc/zeusi/pg_service.conf' }, { shell });
    assert.equal(p.env['PGSERVICEFILE'], '/etc/zeusi/pg_service.conf');
    assert.ok(!existsSync(join(p.runDir, 'pg_service.conf')));
  });

  test(`[${shell}] entrypoint (open sign-up): no tenant secrets -> no tenant flags, sign-up off, nothing written`, () => {
    const r = run({}, { shell });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.args, readOnlyArgs(r.dataDir));
    assert.match(r.out, /workspace sign-up off \(no tenant secrets\)/);
    assert.ok(!existsSync(join(r.runDir, 'pgpass')));
  });

  test(`[${shell}] entrypoint (open sign-up): both tenant secrets -> tenant flags, both lines in the 0600 run-dir pgpass, secrets gone from env and output`, () => {
    const r = run({ ZEUSI_TENANT_RT_PGPASS: RT_LINE, ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE }, { shell });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.args, [...readOnlyArgs(r.dataDir), ...TENANT_ARGS]);
    const file = join(r.runDir, 'pgpass');
    assert.equal(r.env['PGPASSFILE'], file);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(readFileSync(file, 'utf8'), `${RT_LINE}\n${ADMIN_LINE}\n`);
    assert.equal(r.env['ZEUSI_TENANT_RT_PGPASS'], '<unset>');
    assert.equal(r.env['ZEUSI_TENANT_ADMIN_PGPASS'], '<unset>');
    assert.equal(r.env['ZEUSI_MCP_WRITE_SERVICE'], '<unset>', 'sign-up never turns the write service on');
    assert.ok(!r.leaked, 'no tenant password in the output');
    assert.match(r.out, /workspace sign-up ON: --tenant-service zeusi_tenant_rt --tenant-admin-service zeusi_tenant_admin/);
    assert.match(r.out, /write service off \(read-only\)/);
  });

  test(`[${shell}] entrypoint (open sign-up): write service and tenants together -> both flags, three lines, decision line first`, () => {
    const r = run({ ZEUSI_MCP_WRITE_SERVICE: 'zeusi_decision', ZEUSI_DECISION_PGPASS: LINE, ZEUSI_TENANT_RT_PGPASS: RT_LINE, ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE }, { shell });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.args, [...readOnlyArgs(r.dataDir), '--write-service', 'zeusi_decision', ...TENANT_ARGS]);
    assert.equal(readFileSync(join(r.runDir, 'pgpass'), 'utf8'), `${LINE}\n${RT_LINE}\n${ADMIN_LINE}\n`);
    assert.ok(!r.leaked);
  });

  test(`[${shell}] entrypoint (open sign-up): one secret missing or a malformed / swapped line -> sign-up off, loud refusal, no value printed`, () => {
    const bad: Array<[Record<string, string>, RegExp]> = [
      [{ ZEUSI_TENANT_RT_PGPASS: RT_LINE }, /set both ZEUSI_TENANT_RT_PGPASS and ZEUSI_TENANT_ADMIN_PGPASS/],
      [{ ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE }, /set both/],
      [{ ZEUSI_TENANT_RT_PGPASS: ADMIN_LINE, ZEUSI_TENANT_ADMIN_PGPASS: RT_LINE }, /must each be one pgpass line/],
      [{ ZEUSI_TENANT_RT_PGPASS: `${RT_LINE}\n${ADMIN_LINE}`, ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE }, /must each be one pgpass line/],
      [{ ZEUSI_TENANT_RT_PGPASS: 'ep-fake.example.invalid:5432:zeusi:zeusi_tenant_rt:', ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE }, /must each be one pgpass line/],
      [{ ZEUSI_TENANT_RT_PGPASS: RT_LINE, ZEUSI_TENANT_ADMIN_PGPASS: `ep-fake.example.invalid:5432:zeusi:zeusi_box_decision:${APW}` }, /must each be one pgpass line/],
      [{ ZEUSI_TENANT_RT_PGPASS: `${RT_LINE}\r`, ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE }, /must each be one pgpass line/],
    ];
    for (const [env, re] of bad) {
      const r = run(env, { shell });
      assert.equal(r.code, 0, r.out);
      assert.deepEqual(r.args, readOnlyArgs(r.dataDir));
      assert.match(r.out, re);
      assert.equal(r.env['PGPASSFILE'], '<unset>');
      assert.equal(r.env['ZEUSI_TENANT_RT_PGPASS'], '<unset>');
      assert.equal(r.env['ZEUSI_TENANT_ADMIN_PGPASS'], '<unset>');
      assert.ok(!existsSync(join(r.runDir, 'pgpass')));
      assert.ok(!r.leaked, 'no value printed');
    }
  });

  test(`[${shell}] entrypoint (workspace writes): sign-up + writer secret -> --tenant-writer-service, line appended 0600, secret gone`, () => {
    const r = run({ ZEUSI_TENANT_RT_PGPASS: RT_LINE, ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE, ZEUSI_TENANT_WR_PGPASS: WR_LINE }, { shell });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.args, [...readOnlyArgs(r.dataDir), ...TENANT_ARGS, '--tenant-writer-service', 'zeusi_tenant_wr']);
    const file = join(r.runDir, 'pgpass');
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(readFileSync(file, 'utf8'), `${RT_LINE}\n${ADMIN_LINE}\n${WR_LINE}\n`);
    assert.equal(r.env['ZEUSI_TENANT_WR_PGPASS'], '<unset>');
    assert.ok(!r.leaked);
    assert.match(r.out, /workspace writes ON: --tenant-writer-service zeusi_tenant_wr/);
  });

  test(`[${shell}] entrypoint (workspace writes): no secret, sign-up off, or a malformed / wrong-login line -> writes off, loud, no value`, () => {
    const none = run({ ZEUSI_TENANT_RT_PGPASS: RT_LINE, ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE }, { shell });
    assert.deepEqual(none.args, [...readOnlyArgs(none.dataDir), ...TENANT_ARGS]);
    assert.match(none.out, /workspace writes off \(no writer secret\)/);
    const bad: Array<[Record<string, string>, RegExp, string[]]> = [
      [{ ZEUSI_TENANT_WR_PGPASS: WR_LINE }, /writer secret.*|sign-up is off/, []],
      [{ ZEUSI_TENANT_RT_PGPASS: RT_LINE, ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE, ZEUSI_TENANT_WR_PGPASS: RT_LINE }, /must be one pgpass line for zeusi_tenant_wr/, TENANT_ARGS],
      [{ ZEUSI_TENANT_RT_PGPASS: RT_LINE, ZEUSI_TENANT_ADMIN_PGPASS: ADMIN_LINE, ZEUSI_TENANT_WR_PGPASS: `${WR_LINE}\r` }, /must be one pgpass line/, TENANT_ARGS],
    ];
    for (const [env, re, extra] of bad) {
      const r = run(env, { shell });
      assert.equal(r.code, 0, r.out);
      assert.deepEqual(r.args, [...readOnlyArgs(r.dataDir), ...extra]);
      assert.match(r.out, re);
      assert.equal(r.env['ZEUSI_TENANT_WR_PGPASS'], '<unset>');
      assert.ok(!r.leaked, 'no value printed');
      if (existsSync(join(r.runDir, 'pgpass'))) assert.ok(!readFileSync(join(r.runDir, 'pgpass'), 'utf8').includes('zeusi_tenant_wr'));
    }
  });

  test(`[${shell}] entrypoint: without the /data mount it refuses to start, write vars or not`, () => {
    const r = run({ ZEUSI_MCP_WRITE_SERVICE: 'zeusi_decision', ZEUSI_DECISION_PGPASS: LINE }, { mounted: false, shell });
    assert.equal(r.code, 1);
    assert.deepEqual(r.args, []);
    assert.match(r.out, /not a mount point/);
    assert.ok(!r.leaked);
  });
}
