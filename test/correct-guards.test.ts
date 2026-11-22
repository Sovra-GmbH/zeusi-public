// The repo guards (scripts/guards/, `npm run guards`, part of `npm run check`): the exception and
// allowlist rules every guard shares, and, per guard, RED on the real past mistake (historical content
// in test/fixtures/correct/, each headed by its source sha:path:lines) and GREEN on the fixed form.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { safeTmpDir } from './helpers/safe-tmp.ts';
import { inlineException, loadAllowlist, settle, type AllowEntry, type Violation } from '../scripts/guards/lib.ts';
import * as safeTmp from '../scripts/guards/safe-tmp.ts';
import * as secretAssert from '../scripts/guards/secret-assert.ts';
import * as hermeticNpmTest from '../scripts/guards/hermetic-npm-test.ts';
import { hermeticEnv, scrubbedName } from '../scripts/hermetic-env.ts';
import { DIRECT_URL_NAMES, POOLED_URL_NAMES } from '../src/config.ts';

const TODAY = '2026-11-19';
const ALLOW = 'correct-' + 'allow:'; // assembled so this file carries no live exception
const hit = (path: string, line: number, text: string, rule = 'demo'): Violation & { text: string } => ({ rule, path, line, text, message: `demo hit ${text}` });

/** Historical content captured from git (header lines start with '#'). */
function fixture(name: string): string {
  return readFileSync(new URL(`./fixtures/correct/${name}`, import.meta.url), 'utf8').split('\n').filter((l) => !l.startsWith('#')).join('\n');
}

test('inline exception: needs reason, expires and a human approved-by; a past expiry or a bot approver fails', () => {
  const at = (l: string) => inlineException([l], 0, 'demo', TODAY);
  assert.equal(at(`x(); // ${ALLOW} demo reason=fixture-needs-it expires=2026-12-31 approved-by=octocat`), 'ok');
  assert.equal(at(`x(); // ${ALLOW} other reason=r expires=2026-12-31 approved-by=octocat`), null, 'another rule id does not count');
  assert.equal(at('x();'), null);
  assert.match(at(`x(); // ${ALLOW} demo expires=2026-12-31 approved-by=octocat`) as string, /missing reason/);
  assert.match(at(`x(); // ${ALLOW} demo reason=r approved-by=octocat`) as string, /missing expires/);
  assert.match(at(`x(); // ${ALLOW} demo reason=r expires=2026-12-31`) as string, /missing approved-by/);
  assert.match(at(`x(); // ${ALLOW} demo reason=r expires=31.12.2026 approved-by=octocat`) as string, /not a YYYY-MM-DD/);
  assert.match(at(`x(); // ${ALLOW} demo reason=r expires=2026-11-18 approved-by=octocat`) as string, /expired on 2026-11-18/);
  for (const bot of ['claude', 'claude-code', 'github-actions[bot]', 'dependabot', 'agent-7']) {
    assert.match(at(`x(); // ${ALLOW} demo reason=r expires=2026-12-31 approved-by=${bot}`) as string, /human GitHub login/, bot);
  }
  assert.equal(inlineException(['// ' + `${ALLOW} demo reason=r expires=2026-12-31 approved-by=octocat`, 'x();'], 1, 'demo', TODAY), 'ok', 'the line above counts');
});

test('settle: an invalid inline exception is itself the violation; a valid one clears the hit', () => {
  const files = new Map([['a.ts', [`x(); // ${ALLOW} demo reason=r expires=2026-01-01 approved-by=octocat`, `y(); // ${ALLOW} demo reason=r expires=2027-01-01 approved-by=octocat`]]]);
  const out = settle([hit('a.ts', 1, 'x();'), hit('a.ts', 2, 'y();')], files, [], null, ['demo'], TODAY);
  assert.deepEqual(out.map((v) => [v.line, /expired/.test(v.message)]), [[1, true]]);
});

test('allowlist: only shrinks (stale entry fails, entry missing from the base fails, bootstrap without a base allowlist passes)', () => {
  const e = (text: string): AllowEntry => ({ rule: 'demo', path: 'a.ts', text, why: 'pre-existing' });
  const files = new Map([['a.ts', ['old();', 'new();']]]);
  const old = hit('a.ts', 1, 'old();');
  // listed and in the base: allowed
  assert.deepEqual(settle([old], files, [e('old();')], [e('old();')], ['demo'], TODAY), []);
  // bootstrap: the base has no allowlist yet
  assert.deepEqual(settle([old], files, [e('old();')], null, ['demo'], TODAY), []);
  // not listed: the hit stands, with its message
  assert.deepEqual(settle([hit('a.ts', 2, 'new();')], files, [e('old();')], [e('old();')], ['demo'], TODAY).map((v) => v.line), [2, 0]);
  // added to the list after the base: refused
  const grown = settle([old, hit('a.ts', 2, 'new();')], files, [e('old();'), e('new();')], [e('old();')], ['demo'], TODAY);
  assert.equal(grown.length, 1);
  assert.match(grown[0]!.message, /not in the base revision; the list only shrinks/);
  // the line was fixed but the entry stayed: refused (delete it)
  const stale = settle([], files, [e('old();')], [e('old();')], ['demo'], TODAY);
  assert.match(stale[0]!.message, /stale allowlist entry/);
});

// ---- safe-tmp (class: random / walled temp names; #12, #16, #44) ----

const tmpHits = (path: string, text: string) => safeTmp.check([{ path, text }]).map((v) => v.line);

test('safe-tmp: RED on the real past mistakes (38dbec5 hq-sync-import, 15403da search-decisions, b52fde9 test-hermetic HOME)', () => {
  assert.deepEqual(tmpHits('test/hq-sync-import.test.ts', fixture('38dbec5-hq-sync-import.txt')), [1, 2, 3]);
  assert.deepEqual(tmpHits('test/search-decisions.test.ts', fixture('15403da-search-decisions.txt')), [1]);
  assert.deepEqual(tmpHits('scripts/test-hermetic.ts', fixture('b52fde9-test-hermetic.txt')), [1]);
  const v = safeTmp.check([{ path: 'test/x.test.ts', text: fixture('15403da-search-decisions.txt') }])[0]!;
  assert.match(v.message, /safeMkdtemp\(prefix\) or safeTmpDir\(name\) from test\/helpers\/safe-tmp\.ts/, 'the message names the helper');
});

test('safe-tmp: GREEN on the fixes (17564c7, 1ad358b) and on this branch\'s scripts/test-hermetic.ts', () => {
  assert.deepEqual(tmpHits('test/hq-sync-import.test.ts', fixture('17564c7-hq-sync-import.txt')), []);
  assert.deepEqual(tmpHits('test/search-decisions.test.ts', fixture('1ad358b-search-decisions.txt')), []);
  assert.deepEqual(tmpHits('scripts/test-hermetic.ts', readFileSync(new URL('../scripts/test-hermetic.ts', import.meta.url), 'utf8')), []);
});

test('safe-tmp: aliased imports and fs.* calls are caught (#12 review P3); comments and the helper itself are not', () => {
  const mk = 'mkdtemp' + 'Sync';
  assert.deepEqual(tmpHits('test/helpers/new.ts', `import { ${mk} as mk } from 'node:fs';`), [1]);
  assert.deepEqual(tmpHits('test/a.test.ts', `const { ${mk}: mk } = fs;`), [1]);
  assert.deepEqual(tmpHits('test/a.test.ts', `fs.${mk}(p);`), [1]);
  assert.deepEqual(tmpHits('test/a.test.ts', `await fsp.${'mkdtemp'}(p);`), [1]);
  assert.deepEqual(tmpHits('test/a.test.ts', `// ${mk}(p) is banned\n/* ${mk}(p) */ x();`), []);
  // A glob or URL string must not open a comment: the first version missed 38dbec5 lines 65 and 295 this way.
  assert.deepEqual(tmpHits('test/a.test.ts', `const inc = ['team/*.md'];\nconst d = ${mk}(p);\nconst u = 'https://x/*';\nconst e = ${mk}(q); // */`), [2, 4]);
  assert.equal(safeTmp.keep('test/helpers/safe-tmp.ts'), false, 'the owner of the supported way is exempt');
  assert.equal(safeTmp.keep('test/helpers/other.ts'), true, 'test/helpers is scanned');
});

// ---- secret-assert (class: secrets reaching output; #14 printed a real password through node:assert) ----

const credHits = (text: string) => secretAssert.check([{ path: 'test/x.test.ts', text }]).map((v) => v.line);

test('secret-assert: RED on the #14 incident lines (77b63d4:test/hosted-write-service.test.ts:40,56)', () => {
  assert.deepEqual(credHits(fixture('77b63d4-hosted-write-service.txt')), [1, 2]);
  const v = secretAssert.check([{ path: 'test/x.test.ts', text: fixture('77b63d4-hosted-write-service.txt') }]);
  assert.match(v[0]!.message, /readRolePassword/);
  assert.match(v[1]!.message, /"password".*assertSecretEqual \/ assertSecretsEqual/, 'the message names the helpers');
});

test('secret-assert: RED on 14 of the 16 credential compares #14 had to remove (b15f177); GREEN on the redacted replacements it added', () => {
  // The two misses are known limits: an env var compared with '<unset>' and `seen.at(-1)` vs a template literal.
  assert.deepEqual(credHits(fixture('b15f177-removed-credential-asserts.txt')), [1, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16]);
  assert.deepEqual(credHits(fixture('b15f177-added-redacted-asserts.txt')), []);
});

test('secret-assert: names where a credential word is only a modifier, predicates, and count compares stay GREEN', () => {
  const ok = [
    "assert.deepEqual(secretProblems(t), []);",
    "assert.equal(j.token_endpoint_auth_method, 'none');",
    "assert.equal(r.tokenCount, x.tokenCount);",
    "assert.equal(verifySecret(rec, s), true);",
    "assert.equal(p.counts.secret, 2, 'counted');",
    "assert.equal(r.secretWithheld, other.secretWithheld);",
    "assert.match(OFFER, /^Want me to fill your memory now\\? I'll show a preview first\\./);",
  ];
  for (const l of ok) assert.deepEqual(credHits(l), [], l);
  const A = 'assert' + '.'; // assembled: this file must not itself trip the guard
  const bad = [
    A + "equal(j.client_secret, undefined);",
    A + "notEqual(t2.refreshToken, t1.refreshToken);",
    A + "deepEqual(seen, [ENV_PW]);",
    A + "equal(headers['Authorization'], expected);",
    A + "strictEqual(await resolveApiKey(env), KEY);",
  ];
  for (const l of bad) assert.deepEqual(credHits(l), [1], l);
});

// ---- hermetic (class: tests touching real host state; #14) ----

test('hermetic-npm-test: RED on 77b63d4:package.json (plain node --test), GREEN on b15f177:package.json and on this tree', () => {
  const red = hermeticNpmTest.check([{ path: 'package.json', text: fixture('77b63d4-package.json.txt') }]);
  assert.deepEqual(red.map((v) => [v.line, v.text]), [[7, '"test": "node --test test/*.test.ts",']]);
  assert.match(red[0]!.message, /must be "node scripts\/test-hermetic\.ts"/);
  assert.deepEqual(hermeticNpmTest.check([{ path: 'package.json', text: fixture('b15f177-package.json.txt') }]), []);
  assert.deepEqual(hermeticNpmTest.check([{ path: 'package.json', text: readFileSync(new URL('../package.json', import.meta.url), 'utf8') }]), []);
  const side = JSON.stringify({ scripts: { test: 'node scripts/test-hermetic.ts', 'test:one': 'node --test test/a.test.ts' } }, null, 2);
  assert.match(hermeticNpmTest.check([{ path: 'package.json', text: side }])[0]!.message, /"test:one" runs node --test outside the hermetic runner/);
});

test('hermetic env: every owner URL name src/config.ts reads is scrubbed (the b52fde9 regex kept 7 of them)', () => {
  const urlNames = [...POOLED_URL_NAMES, ...DIRECT_URL_NAMES];
  const old = /const SCRUB = \/(.+)\/([a-z]*);/.exec(fixture('b52fde9-test-hermetic-scrub.txt'))!;
  const oldRe = new RegExp(old[1]!, old[2]);
  assert.deepEqual(urlNames.filter((n) => !oldRe.test(n)).sort(), ['DIRECT_URL', 'NEON_DATABASE_URL', 'NEON_DATABASE_URL_UNPOOLED', 'POSTGRES_URL',
    'POSTGRES_URL_NON_POOLING', 'ZEUSI_DATABASE_URL', 'ZEUSI_DIRECT_URL'], 'RED: the b52fde9 scrub passes these owner URLs through');
  for (const n of [...urlNames, 'PGPASSWORD', 'PGHOST', 'OPENAI_API_KEY', 'OPENAI_KEY', 'AWS_ACCESS_KEY_ID', 'ZEUSI_MCP_TOKEN', 'SOME_SECRET', 'GH_TOKEN']) assert.ok(scrubbedName(n), n);
  for (const n of ['PATH', 'NODE_OPTIONS', 'LANG', 'TMPDIR', 'CI', 'GITHUB_BASE_REF', 'ZEUSI_TRANSPORT']) assert.ok(!scrubbedName(n), n);
  assert.deepEqual(Object.keys(hermeticEnv({ PATH: '/bin', ZEUSI_DATABASE_URL: 'x', NEON_DATABASE_URL_UNPOOLED: 'x' })), ['PATH']);
});

// ---- no-skip (class: tests that cannot fail) ----

const RUNNER = fileURLToPath(new URL('../scripts/test-hermetic.ts', import.meta.url));

function runHermetic(body: string): { status: number | null; out: string } {
  const dir = safeTmpDir('zeusi-noskip-');
  try {
    const file = join(dir, 'probe.test.ts');
    writeFileSync(file, body);
    const env = { ...process.env };
    delete env['NODE_TEST_CONTEXT']; // a nested runner must report as a top-level run
    const r = spawnSync(process.execPath, [RUNNER, file], { encoding: 'utf8', env, cwd: tmpdir() });
    return { status: r.status, out: `${r.stdout}${r.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('no-skip: RED on the b52fde9 secret-scan shape (gitleaks missing -> the hook test skipped and could not fail); GREEN without the skip', () => {
  const skipOpt = /(\{ skip: GITLEAKS \? false : 'gitleaks not installed' \})/.exec(fixture('b52fde9-secret-scan-skip.txt'))![1]!;
  const head = "import { test } from 'node:test';\nconst GITLEAKS: string | undefined = undefined;\n";
  const red = runHermetic(`${head}test('pre-commit hook blocks a staged fake', ${skipOpt}, () => {});\n`);
  assert.equal(red.status, 1, red.out);
  assert.match(red.out, /1 skipped and 0 todo test\(s\), 1 SKIP\/TODO directive\(s\) .*\. A test that skips cannot fail/);
  const todo = runHermetic(`${head}test.todo('later');\n`);
  assert.equal(todo.status, 1, todo.out);
  const green = runHermetic(`${head}test('pre-commit hook blocks a staged fake', () => {});\n`);
  assert.equal(green.status, 0, green.out);
  const failing = runHermetic(`${head}test('fails', () => { throw new Error('x'); });\n`);
  assert.equal(failing.status, 1, 'a failing test still fails the run');
});

test('no-skip: RED on a skipped or todo suite (describe.skip, describe(name, {skip|todo}), it.skip inside); the summary counters miss describe.skip (#45 review r1 P2-1)', () => {
  const head = "import { describe, it, test } from 'node:test';\ntest('ok', () => {});\n";
  for (const suite of [
    "describe.skip('s', () => { it('a', () => {}); });",
    "describe('s', { skip: true }, () => { it('a', () => {}); });",
    "describe('s', { skip: 'not here' }, () => { it('a', () => {}); });",
    "describe('s', { todo: true }, () => { it('a', () => {}); });",
    "describe.todo('s', () => { it('a', () => {}); });",
    "describe('s', () => { it.skip('a', () => {}); it('b', () => {}); });",
  ]) {
    const r = runHermetic(`${head}${suite}\n`);
    assert.equal(r.status, 1, `${suite}\n${r.out}`);
    assert.match(r.out, /A test that skips cannot fail/, suite);
  }
  const green = runHermetic(`${head}describe('s', () => { it('a', () => {}); });\n`);
  assert.equal(green.status, 0, green.out);
  const named = runHermetic(`${head}test('a name with # SKIP and # TODO in it', () => {});\n`);
  assert.equal(named.status, 0, `a '#' in a test name is escaped in TAP and is not a directive\n${named.out}`);
});

test('allowlist: an entry covers one occurrence; a second identical copy of an allowlisted line in the same file is RED (#45 review r1 P2-2)', () => {
  // A synthetic file and entry: the real src/ entries are gone since src/run-dir.ts replaced those calls (#55 fix r1).
  const path = 'src/example-run.ts';
  const line = 'return mkdtemp' + "Sync(join(root, 'run-'));"; // assembled so this file carries no raw call
  const real = ['export function workDir(root: string): string {', `  ${line}`, '}', ''].join('\n');
  const allow = loadAllowlist(JSON.stringify({ entries: [{ rule: safeTmp.RULE, path, text: line, why: 'fixture' }] }));
  assert.equal(allow.length, 1);
  const run = (text: string) => {
    const hits = safeTmp.check([{ path, text }]).map((v) => ({ ...v, text: text.split('\n')[v.line - 1]!.trim() }));
    return settle(hits, new Map([[path, text.split('\n')]]), allow, allow, [safeTmp.RULE], TODAY);
  };
  assert.deepEqual(run(real), [], 'the tree as it is: the one allowlisted line passes');
  const lines = real.split('\n');
  const at = lines.findIndex((l) => l.trim() === line);
  assert.ok(at >= 0, 'fixture still carries the allowlisted line');
  const copy = [...lines.slice(0, at + 1), lines[at]!, ...lines.slice(at + 1)].join('\n'); // the D1 mutant: an identical second call site
  const out = run(copy);
  assert.equal(out.length, 1, JSON.stringify(out));
  assert.equal(out[0]!.line, at + 2, 'the extra occurrence is the violation');
  assert.match(out[0]!.message, /allowlist covers 1 occurrence\(s\)/);
  // two entries for the same line cover two copies (an entry is one occurrence, not a pattern)
  assert.deepEqual(settle(safeTmp.check([{ path, text: copy }]).map((v) => ({ ...v, text: copy.split('\n')[v.line - 1]!.trim() })), new Map([[path, copy.split('\n')]]), [...allow, ...allow], [...allow, ...allow], [safeTmp.RULE], TODAY), []);
});

// ---- check: push runs cover the whole pushed range and are not cancelled (#45 review r1 P3-5) ----
// The official public tree is a single initial commit, so this test uses a self-contained
// temporary repo (GUARD_ROOT) rather than the package checkout's history.

const REPO = fileURLToPath(new URL('../', import.meta.url));

function gitAt(cwd: string, ...a: string[]): string {
  const r = spawnSync('git', a, {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, GIT_AUTHOR_NAME: 'Test', GIT_AUTHOR_EMAIL: 'test@example.com', GIT_COMMITTER_NAME: 'Test', GIT_COMMITTER_EMAIL: 'test@example.com' },
  });
  if (r.status !== 0) throw new Error(`git ${a.join(' ')}\n${r.stdout}\n${r.stderr}`);
  return r.stdout.trim();
}

/** A throwaway repo with an empty allowlist, a hermetic package.json, and `commits` commits on main. */
function historyRepo(commits: number): { dir: string; shas: string[] } {
  const dir = safeTmpDir('zeusi-guard-git-');
  mkdirSync(join(dir, 'scripts', 'guards'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), `${JSON.stringify({ scripts: { test: 'node scripts/test-hermetic.ts' } }, null, 2)}\n`);
  writeFileSync(join(dir, 'scripts', 'guards', 'allowlist.json'), `${JSON.stringify({ entries: [] }, null, 2)}\n`);
  gitAt(dir, 'init', '-b', 'main');
  gitAt(dir, 'add', 'package.json', 'scripts/guards/allowlist.json');
  const shas: string[] = [];
  for (let i = 1; i <= commits; i++) {
    writeFileSync(join(dir, 'REV'), `${i}\n`);
    gitAt(dir, 'add', 'REV');
    gitAt(dir, 'commit', '-m', `c${i}`);
    shas.push(gitAt(dir, 'rev-parse', 'HEAD'));
  }
  return { dir, shas };
}

function guardsAsPush(root: string, before: string | null): string {
  const dir = safeTmpDir('zeusi-push-event-');
  try {
    const env: NodeJS.ProcessEnv = {
      PATH: process.env['PATH'], HOME: process.env['HOME'], CI: '1',
      GITHUB_EVENT_NAME: 'push', GUARD_ROOT: root,
    };
    if (before !== null) {
      env['GITHUB_EVENT_PATH'] = join(dir, 'event.json');
      writeFileSync(env['GITHUB_EVENT_PATH'], JSON.stringify({ before, after: gitAt(root, 'rev-parse', 'HEAD') }));
    }
    const r = spawnSync(process.execPath, [join(REPO, 'scripts/guards/run.ts')], { cwd: root, encoding: 'utf8', env });
    return `${r.stdout}${r.stderr}`;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('check: a push run diffs the allowlist against github.event.before (a multi-commit push is fully covered), else HEAD^1', () => {
  const { dir, shas } = historyRepo(3);
  try {
    const before = shas[0]!;
    const parent = shas[1]!;
    assert.match(before, /^[0-9a-f]{40}$/);
    assert.match(guardsAsPush(dir, before), new RegExp(`base ${before.slice(0, 12)}`), 'event.before is the base');
    assert.match(guardsAsPush(dir, '0'.repeat(40)), new RegExp(`base ${parent.slice(0, 12)}`), 'a new branch (all-zero before) falls back to HEAD^1');
    assert.match(guardsAsPush(dir, 'f'.repeat(40)), new RegExp(`base ${parent.slice(0, 12)}`), 'an unknown commit falls back to HEAD^1');
    assert.match(guardsAsPush(dir, null), new RegExp(`base ${parent.slice(0, 12)}`), 'no event file falls back to HEAD^1');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check: an initial commit in CI has no HEAD^1, so the allowlist addition check is skipped', () => {
  const { dir } = historyRepo(1);
  try {
    assert.match(guardsAsPush(dir, '0'.repeat(40)), /base: none \(initial commit; addition check skipped\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('check: ci.yml cancels superseded pull_request runs only (a main push run always completes) and runs exactly `npm run check`', () => {
  const ci = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  assert.match(ci, /^\s*cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}\s*$/m);
  const runs = [...ci.matchAll(/^\s*-?\s*run: (.+)$/gm)].map((m) => m[1]!.trim());
  assert.deepEqual(runs.filter((r) => r !== '|'), ['npm ci', 'npm run check']);
});
