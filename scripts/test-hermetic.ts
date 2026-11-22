// `npm test`: run node --test with NO path to a real credential store.
//   * HOME (and USERPROFILE) point at a fresh wall-safe temp dir (safeMkdtemp: a random suffix
//     that spells a walled term made path-gated tests fail at random; #12, #44 review P3-5), so ~/.pgpass, ~/.pg_service.conf and any
//     other dotfile resolve inside it; it is deleted afterwards.
//   * ZEUSI_TEST_NO_REAL_CREDS=1: src/keychain.ts and scripts/keychain.py refuse the real
//     Keychain and the real user's ~/.pgpass / ~/.pg_service.conf (hard guard; see
//     realCredentialStoresBlocked). node --test also sets NODE_TEST_CONTEXT in each test process.
//   * libpq/credential env (PG*, *PASSWORD*, *SECRET*, *TOKEN*, *API_KEY*, *_KEY, and every owner URL
//     name src/config.ts reads) is dropped so the developer's shell cannot leak a real value into a
//     test (scripts/hermetic-env.ts).
//   * A skipped or todo test fails the run: it cannot fail, so it proves nothing (the 7 gitleaks
//     tests in test/secret-scan.test.ts used to skip on any host without gitleaks, e.g. a fresh CI
//     runner). The counts and the per-line SKIP/TODO directives (a skipped suite too) come from a TAP
//     copy of the run.
// Extra args are passed through (default: every test file).
import { spawnSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { safeMkdtemp } from '../test/helpers/safe-tmp.ts';
import { hermeticEnv } from './hermetic-env.ts';

const home = safeMkdtemp(join(tmpdir(), 'zeusi-test-home-'));
const env = hermeticEnv(process.env);
Object.assign(env, { HOME: home, USERPROFILE: home, ZEUSI_TEST_NO_REAL_CREDS: '1' });

const args = process.argv.slice(2);
const tap = join(home, 'run.tap');
const reporters = ['--test-reporter=spec', '--test-reporter-destination=stdout', '--test-reporter=tap', `--test-reporter-destination=${tap}`];
const r = spawnSync(process.execPath, ['--test', ...reporters, ...(args.length ? args : ['test/*.test.ts'])], { stdio: 'inherit', env });
let summary = '';
try {
  summary = readFileSync(tap, 'utf8');
} catch { /* no TAP: the run itself failed; its status says so */ }
rmSync(home, { recursive: true, force: true });
if (r.error) throw r.error;
const count = (k: string) => Number(new RegExp(`^# ${k} (\\d+)$`, 'm').exec(summary)?.[1] ?? 0);
// The summary counters miss a skipped suite (describe.skip / describe(name, {skip}) is counted under
// `# suites` and its tests never run), so also fail on every TAP `# SKIP` / `# TODO` directive line,
// at any nesting depth, for a test or a suite. A '#' inside a test name is escaped (`\#`) in TAP.
const directives = [...summary.matchAll(/^\s*(?:not )?ok \d+ - (.*) # (SKIP|TODO)\b/gm)].map((m) => `${m[2]}: ${m[1]}`);
if (r.status === 0 && (count('skipped') + count('todo') > 0 || directives.length > 0)) {
  console.error(`npm test: ${count('skipped')} skipped and ${count('todo')} todo test(s), ${directives.length} SKIP/TODO directive(s)${directives.length ? ` (${directives.slice(0, 10).join('; ')})` : ''}. A test that skips cannot fail: make it run (install what it needs) or delete it.`);
  process.exit(1);
}
process.exit(r.status ?? 1);
