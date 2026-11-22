// `npm run check`: every gate, in one command. CI (.github/workflows/ci.yml) runs exactly this after
// setup (Node, npm ci, gitleaks); there is no CI-only step. Each gate runs even when an earlier one
// failed, so one run shows every failure. Exit 1 when any gate fails.
//
//   typecheck    tsc over src/, test/, scripts/ (tsconfig.test.json)
//   build        tsc emit (tsconfig.json)
//   test         scripts/test-hermetic.ts (temp HOME, scrubbed env, no real credential store)
//   secret-scan  gitleaks over the whole git history (.gitleaks.toml)
//   guards       scripts/guards/run.ts (repeated-mistake guards; see AGENTS.md)
import { spawnSync } from 'node:child_process';

const GATES: ReadonlyArray<readonly [string, string[]]> = [
  ['typecheck', ['run', 'typecheck']],
  ['build', ['run', 'build']],
  ['test', ['test']],
  ['secret-scan', ['run', 'secret-scan']],
  ['guards', ['run', 'guards']],
];

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const results: Array<[string, number | null, number]> = [];
for (const [name, args] of GATES) {
  console.log(`\n=== check: ${name} (npm ${args.join(' ')}) ===`);
  const t0 = Date.now();
  const r = spawnSync(npm, args, { stdio: 'inherit', env: process.env });
  results.push([name, r.error ? null : r.status, Date.now() - t0]);
}
console.log('\n=== check summary ===');
for (const [name, status, ms] of results) console.log(`${status === 0 ? 'PASS' : 'FAIL'}  ${name.padEnd(12)} exit=${status ?? 'spawn-error'}  ${(ms / 1000).toFixed(1)}s`);
const failed = results.filter(([, s]) => s !== 0).map(([n]) => n);
console.log(failed.length ? `check: FAILED (${failed.join(', ')})` : 'check: all gates passed');
process.exit(failed.length ? 1 : 0);
