// U1: the pre-commit secret scan (gitleaks) flags a fake Postgres URL with credentials.
// The fixture string is assembled at runtime, so the repo itself never contains it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateToken } from '../src/mcp-tokens.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const HOOK = fileURLToPath(new URL('../scripts/git-hooks/pre-commit', import.meta.url));
// gitleaks from $GITLEAKS, PATH, or the usual install paths. These tests never skip: a skipped test cannot
// fail (scripts/test-hermetic.ts fails the run on any skip), and the pre-commit hook fails closed without it.
const GITLEAKS = [process.env['GITLEAKS'], ...(process.env['PATH'] ?? '').split(':').map((d) => d && join(d, 'gitleaks')),
  '/opt/homebrew/bin/gitleaks', '/usr/local/bin/gitleaks', '/usr/bin/gitleaks'].find((p): p is string => !!p && existsSync(p));
const needGitleaks = () => assert.ok(GITLEAKS, 'gitleaks not found ($GITLEAKS, PATH, /opt/homebrew/bin, /usr/local/bin, /usr/bin): install it (CI pins 8.30.1)');

function tempRepo(): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-leak-'));
  execFileSync('git', ['init', '-q', dir]);
  return dir;
}

function runHook(dir: string) {
  return spawnSync('sh', [HOOK], { cwd: dir, encoding: 'utf8', env: { ...process.env, ...(GITLEAKS ? { GITLEAKS } : {}) } });
}

test('pre-commit hook blocks a staged fake postgres URL with user:password', () => {
  needGitleaks();
  const dir = tempRepo();
  const fake = ['postgresql', '://', 'user', ':', 'pass', 'w0rdFake', '@', 'db.example.invalid', '/zeusi'].join('');
  writeFileSync(join(dir, 'leak.txt'), `DATABASE_URL=${fake}\n`);
  execFileSync('git', ['add', 'leak.txt'], { cwd: dir });
  const r = runHook(dir);
  assert.notEqual(r.status, 0, `hook should fail; output: ${r.stdout}${r.stderr}`);
  // Redacted: the hook output never echoes the fake password.
  assert.ok(!`${r.stdout}${r.stderr}`.includes('passw0rdFake'));
});

test('pre-commit hook blocks the bare plan-shaped fake (user:pass@)', () => {
  needGitleaks();
  const dir = tempRepo();
  writeFileSync(join(dir, 'leak.md'), `see ${['postgresql://', 'user:pass', '@host/db'].join('')}\n`);
  execFileSync('git', ['add', 'leak.md'], { cwd: dir });
  assert.notEqual(runHook(dir).status, 0);
});

test('pre-commit hook blocks a staged hosted MCP token (zeusi_<12>_<43>, generated at runtime)', () => {
  needGitleaks();
  const dir = tempRepo();
  const { token, secret } = generateToken();
  writeFileSync(join(dir, 'client.json'), `{"headers":{"Authorization":"Bearer ${token}"}}\n`);
  execFileSync('git', ['add', 'client.json'], { cwd: dir });
  const r = runHook(dir);
  assert.notEqual(r.status, 0, `hook should fail; output: ${r.stdout}${r.stderr}`);
  assert.match(`${r.stdout}${r.stderr}`, /zeusi-mcp-token|generic-api-key/);
  assert.ok(!`${r.stdout}${r.stderr}`.includes(secret), 'redacted');
});

test('the zeusi-mcp-token rule itself fires on a bare token (not only via the generic rules)', () => {
  needGitleaks();
  const dir = tempRepo();
  writeFileSync(join(dir, 'note.txt'), `${generateToken().token}\n`);
  execFileSync('git', ['add', 'note.txt'], { cwd: dir });
  const r = runHook(dir);
  assert.notEqual(r.status, 0);
  assert.match(`${r.stdout}${r.stderr}`, /zeusi-mcp-token/);
});

test('the zeusi-oauth-token rule fires on OAuth access/refresh tokens and codes (generated at runtime, redacted)', () => {
  needGitleaks();
  for (const kind of ['at', 'rt', 'ac']) {
    const dir = tempRepo();
    const secret = randomBytes(32).toString('base64url');
    writeFileSync(join(dir, 'note.txt'), `${['zeusi', kind, secret].join('_')}\n`);
    execFileSync('git', ['add', 'note.txt'], { cwd: dir });
    const r = runHook(dir);
    assert.notEqual(r.status, 0, kind);
    assert.match(`${r.stdout}${r.stderr}`, /zeusi-oauth-token/);
    assert.ok(!`${r.stdout}${r.stderr}`.includes(secret), 'redacted');
  }
});

test('pre-commit hook passes a clean staged file', () => {
  needGitleaks();
  const dir = tempRepo();
  writeFileSync(join(dir, 'ok.txt'), 'service=zeusi_ingest\nno credentials here\n');
  execFileSync('git', ['add', 'ok.txt'], { cwd: dir });
  const r = runHook(dir);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
});

test('pre-commit hook fails closed when gitleaks is missing', () => {
  const dir = tempRepo();
  const r = spawnSync('sh', [HOOK], { cwd: dir, encoding: 'utf8', env: { PATH: '/usr/bin:/bin', GITLEAKS: '/nonexistent/gitleaks' } });
  assert.notEqual(r.status, 0);
  assert.match(`${r.stdout}${r.stderr}`, /gitleaks/);
});

// Security P0 (17 Nov 2026): partial / masked provider keys (the default rules need the full key).
test('pre-commit hook blocks a staged PARTIAL and a MASKED provider key fragment (built at runtime)', () => {
  needGitleaks();
  const prefix = ['AI', 'za'].join('');
  const cases: Array<[string, RegExp]> = [
    [`gemini: ${prefix}SyQ7m2Kp`, /zeusi-partial-provider-key/],
    [`key in use: \`${prefix}…Q7m2K\``, /zeusi-masked-provider-key/],
    [`token ${['gh', 'p_'].join('')}****9Kx2`, /zeusi-masked-provider-key/],
    // review r1 P2-1: single asterisk, spaced ellipsis, a split over a line break
    [`key ${prefix}*Q7m2K`, /zeusi-weak-masked-provider-key/],
    [`key ${prefix} … Q7m2K`, /zeusi-weak-masked-provider-key/],
    [`key ${prefix}Sy\nQ7m2KpQ7m2KpQ7m2Kp`, /zeusi-split-provider-key/],
  ];
  for (const [line, rule] of cases) {
    const dir = tempRepo();
    writeFileSync(join(dir, 'note.md'), `${line}\n`);
    execFileSync('git', ['add', 'note.md'], { cwd: dir });
    const r = runHook(dir);
    assert.notEqual(r.status, 0, `hook should fail; output: ${r.stdout}${r.stderr}`);
    assert.match(`${r.stdout}${r.stderr}`, rule);
  }
  // A prefix alone (documentation) is not a finding.
  const dir = tempRepo();
  writeFileSync(join(dir, 'doc.md'), `Google keys start with ${prefix} and look like ${prefix}…\nor ${prefix} ... and so on, *${prefix}* in bold, ${prefix}\nand more prose\n`);
  execFileSync('git', ['add', 'doc.md'], { cwd: dir });
  assert.equal(runHook(dir).status, 0);
});
