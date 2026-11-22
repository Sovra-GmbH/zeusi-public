// C8-0 U2-U4 (docs/plans/2026-11-21-c8-refresh.md KTD-B, KTD-C, KTD-D, §5): `encrypt-status --all` (counts only,
// read-only, two-step), the offline refusal of `overlay relax|rollback-start --real`, and the pins (every enc_state
// writer in the code, the overlay step targets, the write tool list). PGlite with the real roles; the CLI runs as a
// subprocess with no service file (so a refusal that comes first never connects). No network, no Neon, no key.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Db } from '../src/db.ts';
import { encryptStatusAll, formatEncryptStatusAll, runEncryptStatusAll } from '../src/encrypt-status.ts';
import { WORKSPACE_WRITE_TOOL_NAMES } from '../src/mcp-server.ts';
import { OVERLAY_STEP_FROM, OVERLAY_STEP_TO, OVERLAY_STEPS, TenantDirectory, type EncState } from '../src/tenants.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { dcrClient, LIST, mcpPost, serviceHome, startTenantHosted } from './helpers/hosted-tenants.ts';
import { asLogin, asOwner, plantInWorkspace, tenantTestDb } from './helpers/tenant-fixture.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const SRC = fileURLToPath(new URL('../src/', import.meta.url));
const CANARY = 'c80holdcanarywallaby';
/** What the CLI prints when it reaches the admin service lookup and there is no service file (exit 2). */
const NO_SERVICE = /Service "zeusi_tenant_admin" not found/;

let db: Db;
let dir: TenantDirectory;
let dirOn: TenantDirectory;
before(async () => {
  db = await tenantTestDb({ writer: true });
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  dirOn = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin'), bornEncrypted: true });
});
after(async () => {
  await db.close();
});

const run = (args: string[]) => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-c80-cli-'));
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: home, encoding: 'utf8', timeout: 20_000,
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: home, PGSERVICEFILE: join(home, 'missing.conf') },
  });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
};
const setState = (t: string, s: EncState) => asOwner(db, async () => {
  await db.query(`UPDATE zeusi_tenants.tenants SET enc_state = $2 WHERE tenant_id = $1`, [t, s]);
});
let seq = 8800;
const provision = async (d: TenantDirectory) => ((await d.provision(`github:${seq++}`)) as { tenantId: string }).tenantId;

/** A directory whose admin sessions record every statement; `rewrite` may answer a statement instead of the DB. */
function recordingDir(log: string[], rewrite?: (sql: string, params: unknown[] | undefined) => { rows: unknown[] } | null): TenantDirectory {
  const base = asLogin(db, 'zeusi_tenant_admin');
  return new TenantDirectory({
    connectAdmin: async () => {
      const d = await base();
      log.push('<session>');
      return {
        label: d.label,
        query: (sql, params) => {
          log.push(sql);
          const r = rewrite?.(sql, params);
          return r ? Promise.resolve(r as never) : d.query(sql, params);
        },
        exec: (sql) => { log.push(sql); return d.exec(sql); },
        close: () => d.close(),
      } satisfies Db;
    },
  });
}

/** Statements grouped per READ ONLY transaction (BEGIN ... ROLLBACK). */
function transactions(log: string[]): string[][] {
  const out: string[][] = [];
  let cur: string[] | null = null;
  for (const s of log) {
    if (/^BEGIN/i.test(s)) {
      cur = [s];
      out.push(cur);
    } else if (s === 'ROLLBACK') {
      cur = null;
    } else if (cur) cur.push(s);
  }
  return out;
}

// ---------------------------------------------------------------------------
// U2: encrypt-status --all

test('no operator unlock: --all reads one READ ONLY catalog transaction, then one READ ONLY transaction per workspace that names no zeusi_tenants table; no INSERT, UPDATE, DELETE or DDL; the output has no id, title or canary', async () => {
  // Mutants: drop READ ONLY -> the BEGIN assertion turns red; print an id -> the output assertion turns red; count the
  // workspaces inside the catalog transaction -> the transaction count / "no zeusi_tenants" assertions turn red.
  const on = await provision(dirOn);
  const off = await provision(dir);
  await plantInWorkspace(db, off, CANARY);
  const log: string[] = [];
  const s = await encryptStatusAll(recordingDir(log));
  const txs = transactions(log);
  const active = (await asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi_tenants.tenants WHERE status = 'active'`)).rows[0]!.n));
  assert.equal(s.active, active);
  assert.equal(txs.length, 1 + active, 'one catalog transaction, then one per workspace');
  for (const tx of txs) assert.equal(tx[0], 'BEGIN TRANSACTION READ ONLY');
  assert.ok(txs[0]!.some((x) => x.includes('zeusi_tenants.tenants')), 'the catalog step reads the catalog');
  for (const tx of txs.slice(1)) assert.ok(!tx.some((x) => x.includes('zeusi_tenants')), 'a workspace step names no catalog table');
  for (const x of log) assert.doesNotMatch(x, /^\s*(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|GRANT|REVOKE|TRUNCATE)\b/i, x.slice(0, 60));
  assert.ok(!log.some((x) => /enc_state\s*=/.test(x) && /UPDATE/i.test(x)), 'no enc_state write');
  const out = formatEncryptStatusAll(s).join('\n');
  assert.doesNotMatch(out, /zt_[a-z2-7]{26}/, 'no workspace id');
  for (const t of [on, off]) assert.ok(!out.includes(t));
  assert.ok(!out.toLowerCase().includes(CANARY), 'no content');
  assert.match(out, /^workspaces encrypt-status --all \(dry run, counts only, nothing changed\)$/m);
  assert.match(out, /^digest_column_missing \d+ /m);
  assert.match(out, /^digest_missing \d+ /m);
  // Every token is a constant label or a number.
  for (const line of formatEncryptStatusAll(s)) assert.match(line, /^[a-z0-9_ ,:;()+\-.]+$/i, line);
});

test('no operator unlock (source scan): encrypt-status and the overlay module import none of crypto-envelope, workspace-keys or workspace-seal, directly or through any import', () => {
  // Mutant: import workspace-seal (or anything that does) from src/encrypt-status.ts -> red.
  const banned = ['crypto-envelope.ts', 'workspace-keys.ts', 'workspace-seal.ts'];
  const importsOf = (file: string): string[] => [...readFileSync(file, 'utf8').matchAll(/^\s*import\s+(?!type\b)[^;]*?from\s+'(\.[^']+)'/gm)]
    .map((m) => resolve(dirname(file), m[1]!));
  for (const root of ['encrypt-status.ts', 'tenant-overlay.ts']) {
    const seen = new Set<string>();
    const todo = [join(SRC, root)];
    while (todo.length) {
      const f = todo.pop()!;
      if (seen.has(f)) continue;
      seen.add(f);
      todo.push(...importsOf(f).filter((x) => x.startsWith(SRC)));
    }
    const hit = [...seen].map((x) => x.slice(SRC.length)).filter((x) => banned.some((b) => x.endsWith(b)));
    assert.deepEqual(hit, [], `${root} reaches no key module`);
  }
});

test('skipped (r2 P3-5): a workspace whose schema vanished between the two steps counts as skipped, exit 0', async () => {
  const gone = await provision(dir);
  const log: string[] = [];
  const d = recordingDir(log, (sql, params) => (/FROM pg_namespace WHERE nspname = \$1/.test(sql) && params?.[0] === gone ? { rows: [{ c: 0 }] } : null));
  const lines: string[] = [];
  assert.equal(await runEncryptStatusAll(d, { expectNoPlain: false }, (l) => lines.push(l)), 0);
  const s = await encryptStatusAll(recordingDir([], (sql, params) => (/FROM pg_namespace WHERE nspname = \$1/.test(sql) && params?.[0] === gone ? { rows: [{ c: 0 }] } : null)));
  assert.equal(s.skipped, 1);
  assert.match(lines.join('\n'), /skipped 1 /);
});

test('--expect-no-plain (r1 P2-3): exit 3 when one enrolled (and, separately, one off) workspace exists, 0 when every workspace is on; without the flag 0 in every case', async () => {
  // Mutants: always return 0 -> the exit-3 cases turn red; count only `off` -> the enrolled case turns red.
  const quiet = () => {};
  const code = (expectNoPlain: boolean) => runEncryptStatusAll(dir, { expectNoPlain }, quiet);
  // Make every existing workspace `on` first (owner SQL), so the cases below are exact.
  await asOwner(db, () => db.query(`UPDATE zeusi_tenants.tenants SET enc_state = 'on'`));
  await provision(dirOn);
  assert.equal(await code(true), 0, 'all on');
  const w = await provision(dir);
  assert.equal((await encryptStatusAll(dir)).byState.off, 1);
  assert.equal(await code(true), 3, 'one off');
  assert.equal(await code(false), 0);
  await setState(w, 'enrolled');
  assert.equal((await encryptStatusAll(dir)).byState.enrolled, 1);
  assert.equal(await code(true), 3, 'one enrolled');
  assert.equal(await code(false), 0);
  await setState(w, 'on');
  assert.equal(await code(true), 0, 'all on again');
});

test('CLI encrypt-status: --all with --tenant, --expect-no-plain without --all, --all --real and --all on a backfill are usage errors before any connection', () => {
  // Mutant: accept both flags -> the command goes on to the (missing) service and the message differs, red.
  const T = `zt_${'e'.repeat(26)}`;
  const both = run(['workspaces', 'encrypt-status', '--all', '--tenant', T]);
  assert.equal(both.code, 2);
  assert.match(both.out, /--all and --tenant are exclusive/);
  const lone = run(['workspaces', 'encrypt-status', '--tenant', T, '--expect-no-plain']);
  assert.equal(lone.code, 2);
  assert.match(lone.out, /--expect-no-plain goes with --all/);
  assert.equal(run(['workspaces', 'encrypt-status', '--all', '--real']).code, 2);
  assert.equal(run(['workspaces', 'backfill-writers', '--all']).code, 2);
  assert.equal(run(['workspaces', 'backfill-writers', '--expect-no-plain']).code, 2);
  const ok = run(['workspaces', 'encrypt-status', '--all']);
  assert.match(ok.out, NO_SERVICE, 'a valid --all goes on to the admin service (none here)');
  assert.doesNotMatch(ok.out, /usage:|exclusive|goes with/);
  for (const r of [both, lone]) assert.doesNotMatch(r.out, NO_SERVICE, 'refused before the service lookup');
  assert.match(run(['help']).out, /workspaces encrypt-status --all \[--expect-no-plain\]/);
});

// ---------------------------------------------------------------------------
// U3: the relax / rollback-start refusal (P5)

test('relax refusal (P5): overlay relax / rollback-start --real --i-took-a-snapshot are refused before any connection; their dry runs and the other steps still go on to the admin service', () => {
  // Mutant: delete the refusal -> the --real runs go on to the (missing) admin service: the message differs, red.
  const T = `zt_${'f'.repeat(26)}`;
  for (const step of ['relax', 'rollback-start']) {
    for (const extra of [['--real', '--i-took-a-snapshot'], ['--real']]) {
      const r = run(['workspaces', 'overlay', step, '--tenant', T, ...extra]);
      assert.equal(r.code, 1, `${step} ${extra.join(' ')}`);
      assert.match(r.out, /would leave the workspace unable to save: no decrypt run exists on this server yet; nothing changed/);
      assert.doesNotMatch(r.out, NO_SERVICE, 'never reached the service lookup');
    }
    const dry = run(['workspaces', 'overlay', step, '--tenant', T]);
    assert.match(dry.out, NO_SERVICE, 'the dry run goes on to the admin service (none here)');
    assert.doesNotMatch(dry.out, /unable to save/, 'the dry run is not refused');
  }
  const flip = run(['workspaces', 'overlay', 'flip', '--tenant', T, '--real', '--i-took-a-snapshot']);
  assert.doesNotMatch(flip.out, /unable to save/, 'flip --real is not refused by C8-0');
  assert.match(flip.out, NO_SERVICE);
});

// ---------------------------------------------------------------------------
// U4: pins (KTD-D)

/** Every SQL statement shape in a source file that writes enc_state: UPDATE ... SET ... enc_state =, INSERT INTO ... (... enc_state ...), DO UPDATE SET ... enc_state =. */
function encStateWriters(file: string): string[] {
  const src = readFileSync(file, 'utf8');
  return [
    ...src.matchAll(/\bUPDATE\s+[^\s;`'(]+\s+SET\s[^;`]*?\benc_state\s*=/gi),
    ...src.matchAll(/\bINSERT\s+INTO\s+[^\s;`'(]+\s*\([^)]*\benc_state\b[^)]*\)/gi),
    ...src.matchAll(/\bDO\s+UPDATE\s+SET\s[^;`]*?\benc_state\s*=/gi),
  ].map((m) => m[0].replace(/\s+/g, ' '));
}
const walk = (d: string): string[] => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]));

test('§7 item 18: the only enc_state writers in src/, scripts/ and migrations/ are enroll off->enrolled, provision on/off and overlayStep; the overlay step targets are pinned (no step sets on except flip, off except unflip)', () => {
  // Mutant: add `UPDATE ... SET enc_state = 'off'` (or any enc_state write) anywhere -> the scan turns red.
  const root = fileURLToPath(new URL('..', import.meta.url));
  const found: string[] = [];
  for (const d of ['src', 'scripts', 'migrations']) {
    for (const f of walk(join(root, d)).filter((x) => /\.(ts|sql)$/.test(x))) for (const s of encStateWriters(f)) found.push(`${f.slice(root.length)}: ${s}`);
  }
  assert.deepEqual(found.sort(), [
    'src/tenants.ts: INSERT INTO ${CONTROL_SCHEMA}.tenants (tenant_id, status, enc_state)',
    'src/tenants.ts: UPDATE ${CONTROL_SCHEMA}.tenants SET enc_state =',
    'src/tenants.ts: UPDATE ${CONTROL_SCHEMA}.tenants SET enc_state =',
  ]);
  // Which three: enroll moves off -> enrolled only; provision inserts on or off from bornEncrypted; overlayStep moves
  // from OVERLAY_STEP_FROM to OVERLAY_STEP_TO (pinned below).
  const ten = readFileSync(join(root, 'src/tenants.ts'), 'utf8');
  assert.match(ten, /SET enc_state = 'enrolled' WHERE tenant_id = \$1 AND enc_state = 'off' RETURNING/);
  assert.match(ten, /VALUES \(\$1, 'active', \$2\)`,\s*\[tenantId, this\.o\.bornEncrypted \? 'on' : 'off'\]/);
  assert.match(ten, /SET enc_state = \$2 WHERE tenant_id = \$1 AND enc_state = \$3 RETURNING tenant_id`, \[tenantId, to, from\]/);
  assert.deepEqual({ ...OVERLAY_STEP_TO }, { prepare: null, flip: 'on', relax: 'decrypting', 'rollback-start': 'decrypting', unflip: 'off' });
  assert.deepEqual([...OVERLAY_STEPS], ['prepare', 'flip', 'relax', 'rollback-start', 'unflip']);
  assert.deepEqual(Object.fromEntries(Object.entries(OVERLAY_STEP_FROM).map(([k, v]) => [k, [...v]])),
    { prepare: ['off', 'enrolled'], flip: ['verified'], relax: ['on'], 'rollback-start': ['encrypting', 'verified'], unflip: ['decrypted'] });
});

test('§7 item 18: with bornEncrypted no provision writes off (born on); without it, off', async () => {
  // Mutant: ignore bornEncrypted in provision -> the born workspace reads off, red.
  const state = async (t: string) => asOwner(db, async () => (await db.query<{ s: string }>(`SELECT enc_state AS s FROM zeusi_tenants.tenants WHERE tenant_id = $1`, [t])).rows[0]!.s);
  assert.equal(await state(await provision(dirOn)), 'on');
  assert.equal(await state(await provision(dir)), 'off');
});

test('tenant isolation: WORKSPACE_WRITE_TOOL_NAMES is exactly preview, commit and sync; on a flag-on server a personal write grant\'s tools/list differs from a read grant\'s by exactly those three', async () => {
  // Mutant: add a tool name (to the list or as a new write tool on the grant) -> red.
  assert.deepEqual([...WORKSPACE_WRITE_TOOL_NAMES], ['zeusi_import_preview', 'zeusi_import_commit', 'zeusi_sync_batch']);
  const hdb = await tenantTestDb({ writer: true });
  const h = await startTenantHosted({ db: hdb, home: serviceHome(), writer: 'on', flagOn: { newDek: () => Buffer.alloc(32, 0x5a) }, routerCacheMs: 0 });
  try {
    const t = ((await h.dir!.provision('github:8899')) as { tenantId: string }).tenantId;
    assert.equal((await h.router!.encState(t)).encState, 'on', 'flag on: born on');
    const clientId = await dcrClient(h);
    const write = h.store.createGrant({ clientId, subject: 'github:8899', login: 'c80-write', tenant: t, workspaceWrite: true }).accessToken;
    const read = h.store.createGrant({ clientId, subject: 'github:8899', login: 'c80-read', tenant: t }).accessToken;
    const tools = async (tok: string) => ((JSON.parse((await mcpPost(h.port, tok, LIST)).body) as { result: { tools: Array<{ name: string }> } }).result.tools).map((x) => x.name);
    const w = await tools(write);
    const r = await tools(read);
    assert.deepEqual(w.filter((x) => !r.includes(x)).sort(), [...WORKSPACE_WRITE_TOOL_NAMES].sort());
    assert.deepEqual(r.filter((x) => !w.includes(x)), []);
  } finally {
    await h.close();
    await hdb.close();
  }
});
