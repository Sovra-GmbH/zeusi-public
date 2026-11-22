// CLI `zeusi onboard` / `zeusi import` (plan U9; PR2 P2, P4, P5). Spawns src/cli.ts with a temp
// HOME that has NO service file and no credentials: any connection attempt would fail loudly, so
// a dry run that exits 0 provably made none. Planted values are built at runtime. No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const TOKEN = ['gh', 'p_', 'Q'.repeat(36)].join('');
const WALL_TERM = ['Plan', 'kiva'].join('');

function sandbox() {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-import-cli-'));
  const home = join(dir, 'home');
  mkdirSync(home);
  const notes = join(dir, 'sample notes');
  mkdirSync(notes);
  writeFileSync(join(notes, 'clean.md'), '---\ntitle: Clean title marker-c1\ndate: 2026-11-10\nlocks:\n  - SYNTHETIC lock marker-l1\n---\nclean body marker-b1\n');
  writeFileSync(join(notes, 'token.md'), `---\ndate: 2026-11-10\n---\nkey ${TOKEN}\n`);
  writeFileSync(join(notes, 'wall.md'), `---\ndate: 2026-11-10\n---\nabout ${WALL_TERM}\n`);
  const log = join(dir, 'decisions.jsonl');
  writeFileSync(log, JSON.stringify({ kind: 'lock', who: 'synthetic-owner', said_at: '2026-11-12T08:00:00Z', said_at_precision: 'minute', exact_words: 'SYNTHETIC words marker-w1' }) + '\n');
  const env: NodeJS.ProcessEnv = { PATH: process.env['PATH'] ?? '', HOME: home, ZEUSI_TEST_NO_REAL_CREDS: '1' };
  const run = (args: string[], extra: NodeJS.ProcessEnv = {}) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', env: { ...env, ...extra }, timeout: 60_000 });
  return { dir, home, notes, log, run };
}

const MARKERS = ['marker-c1', 'marker-l1', 'marker-b1', 'marker-w1', TOKEN, WALL_TERM];

test('cli onboard: preview + the exact next import command; no connection (no service file exists); counts only; work dir cleaned', () => {
  const s = sandbox();
  const r = s.run(['onboard', '--markdown', s.notes, '--decision-log', s.log, '--scope', 'work']);
  assert.equal(r.status, 0, r.stderr);
  const out = `${r.stdout}${r.stderr}`;
  assert.match(r.stdout, /import preview \(dry run: offline, no database connection, nothing written\): scope work/);
  assert.match(r.stdout, /input #1 markdown: items 3, notes staged 3/);
  assert.match(r.stdout, /input #2 decision-log: items 1, notes staged 1/);
  assert.match(r.stdout, /withheld \(export filter, same as nightly\): entries 2 \(plankiva-class 1, requests 0, credential 1\)/);
  assert.match(r.stdout, /rules 0 \(\+ note lock items 1, read as rules\), focus 0, decisions 1 \(lock 1\)/);
  assert.match(r.stdout, /people handle\(s\)/);
  assert.ok(r.stdout.includes(`zeusi import --markdown '${s.notes}' --decision-log ${s.log} --scope work --real`), 'the exact next command (paths quoted)');
  for (const m of MARKERS) assert.ok(!out.includes(m), `output holds ${m.slice(0, 10)}`);
  assert.ok(!/\.md\b/.test(out.replace(s.notes, '')), 'no file below an input is named');
  assert.deepEqual(readdirSync(join(s.home, '.zeusi', 'onboard')), [], 'private work dir removed');
});

test('cli import without --real is the same dry run; --json has only counts and the next command', () => {
  const s = sandbox();
  const r = s.run(['import', '--markdown', s.notes, '--scope', 'product', '--json']);
  assert.equal(r.status, 0, r.stderr);
  const j = JSON.parse(r.stdout) as Record<string, unknown>;
  assert.equal(j['dry_run'], true);
  assert.equal(j['scope'], 'product');
  assert.equal(j['project'], 'northbank');
  assert.match(String(j['next_command']), /--scope product --real$/);
  const flat = JSON.stringify({ ...j, next_command: '' });
  for (const m of [...MARKERS, s.notes, s.dir]) assert.ok(!flat.includes(m), `json holds ${m.slice(0, 10)}`);
});

test('cli: usage errors exit 2 before any read (no inputs, unknown scope, missing scope, onboard --real, --service without --real, unknown flag)', () => {
  const s = sandbox();
  const cases: string[][] = [
    ['import', '--scope', 'work'],
    ['import', '--markdown', s.notes, '--scope', 'personal'],
    ['import', '--markdown', s.notes, '--real'],
    ['onboard', '--markdown', s.notes, '--scope', 'work', '--real'],
    ['import', '--markdown', s.notes, '--scope', 'work', '--service', 'zeusi_ingest'],
    ['import', '--markdown', s.notes, '--scope', 'work', '--path-to-evil', 'x'],
    ['import', '--markdown', join(s.dir, 'does-not-exist'), '--scope', 'work'],
  ];
  for (const a of cases) {
    const r = s.run(a);
    assert.equal(r.status, 2, `${a.join(' ')}: ${r.stderr}`);
    assert.equal(r.stdout, '', 'nothing printed to stdout');
    assert.ok(!r.stderr.includes(s.dir), 'no path in the error');
  }
  assert.equal(existsSync(join(s.home, '.zeusi', 'onboard')) ? readdirSync(join(s.home, '.zeusi', 'onboard')).length : 0, 0);
});

test('cli import --real: preview first, then refused offline by the service / main-branch guards (no service file, no endpoint id): exit 2, no connection', () => {
  const s = sandbox();
  const r = s.run(['import', '--markdown', s.notes, '--scope', 'work', '--real']);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stdout, /import preview \(dry run/);
  assert.match(r.stderr, /Service "zeusi_ingest" not found/);
  for (const m of MARKERS) assert.ok(!`${r.stdout}${r.stderr}`.includes(m));
  // With a direct service but no ZEUSI_MAIN_ENDPOINT_ID: the main-branch guard refuses offline.
  const host = ['ep-synthetic-cli-1', '.eu-central-1.aws.neon.tech'].join('');
  writeFileSync(join(s.home, '.pg_service.conf'), `[zeusi_ingest]\nhost=${host}\nport=5432\ndbname=zeusi\nuser=zeusi_mini_ingest\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
  const g = s.run(['import', '--markdown', s.notes, '--scope', 'work', '--real']);
  assert.equal(g.status, 2, g.stderr);
  assert.match(g.stderr, /cannot tell whether the target is Neon main/);
  assert.ok(!g.stderr.includes('ep-synthetic') && !g.stderr.includes('neon.tech'));
  const same = s.run(['import', '--markdown', s.notes, '--scope', 'work', '--real'], { ZEUSI_MAIN_ENDPOINT_ID: 'ep-synthetic-cli-1' });
  assert.equal(same.status, 2);
  assert.match(same.stderr, /targets the default branch \(main\) endpoint/);
});

test('cli: ZEUSI_TRANSPORT=serverless refuses import and onboard like every other write command', () => {
  const s = sandbox();
  for (const cmd of ['import', 'onboard']) {
    const r = s.run([cmd, '--markdown', s.notes, '--scope', 'work', ...(cmd === 'import' ? ['--real'] : [])], { ZEUSI_TRANSPORT: 'serverless' });
    assert.equal(r.status, 2, r.stderr);
    assert.doesNotMatch(r.stdout, /import preview/);
  }
});

test('cli help lists onboard and import', () => {
  const s = sandbox();
  const r = s.run(['help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^ {2}onboard <inputs> --scope/m);
  assert.match(r.stdout, /^ {2}import <inputs> --scope/m);
});
