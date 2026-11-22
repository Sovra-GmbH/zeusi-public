// `npm run guards`: run every repo guard (scripts/guards/*.ts) over the working tree.
//
//   node scripts/guards/run.ts [--base <git ref>]
//
// Exit 1 with `file:line [rule] message` lines when any guard finds a violation, 0 otherwise.
// The allowlist (scripts/guards/allowlist.json) may only shrink; it is compared with the allowlist at
// the base revision: --base, else GUARD_BASE, else on GitHub pull_request origin/$GITHUB_BASE_REF,
// on push github.event.before (GITHUB_EVENT_PATH) when it is a known commit, else HEAD^1, locally `git merge-base HEAD origin/main`. In CI an unresolvable base is an error.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { ALLOWLIST_PATH, format, gitShow, loadAllowlist, readSources, ROOT, settle, type SourceFile, type Violation } from './lib.ts';
import { GUARDS } from './registry.ts';

function git(args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
}

/**
 * github.event.before of a push (read from the event payload GitHub writes to GITHUB_EVENT_PATH) when it
 * is a commit this checkout has, so a multi-commit push (fast-forward, rebase-merge) is checked as one
 * range. Null for a new branch (all-zero sha), an unknown commit or no payload: the caller uses HEAD^1.
 */
function pushBefore(env: NodeJS.ProcessEnv): string | null {
  let before: unknown;
  try {
    before = (JSON.parse(readFileSync(env['GITHUB_EVENT_PATH'] ?? '', 'utf8')) as { before?: unknown }).before;
  } catch {
    return null;
  }
  if (typeof before !== 'string' || !/^[0-9a-f]{40}$/.test(before) || /^0+$/.test(before)) return null;
  return git(['rev-parse', '--verify', '--quiet', `${before}^{commit}`]);
}

function resolveBase(explicit: string | undefined, env: NodeJS.ProcessEnv): string | null {
  const want = explicit ?? env['GUARD_BASE']
    ?? (env['GITHUB_EVENT_NAME'] === 'pull_request' && env['GITHUB_BASE_REF'] ? `origin/${env['GITHUB_BASE_REF']}` : undefined)
    ?? (env['GITHUB_EVENT_NAME'] === 'push' ? pushBefore(env) ?? 'HEAD^1' : undefined);
  if (want !== undefined) return git(['rev-parse', '--verify', '--quiet', `${want}^{commit}`]);
  return git(['merge-base', 'HEAD', 'origin/main']);
}

const { values } = parseArgs({ options: { base: { type: 'string' } } });
const base = resolveBase(values.base, process.env);
const initialCommit = !!(git(['rev-parse', '--verify', '--quiet', 'HEAD']) && !git(['rev-parse', '--verify', '--quiet', 'HEAD^1']));
if (base === null && (process.env['CI'] || values.base || process.env['GUARD_BASE']) && !initialCommit) {
  console.error(`guards: cannot resolve the base revision (${values.base ?? process.env['GUARD_BASE'] ?? process.env['GITHUB_BASE_REF'] ?? 'HEAD^1'}); the allowlist addition check needs it (fetch-depth: 0 in CI)`);
  process.exit(2);
}

const allow = loadAllowlist(readFileSync(join(ROOT, ALLOWLIST_PATH), 'utf8'));
const baseAllow = base === null ? null : (() => {
  const t = gitShow(base, ALLOWLIST_PATH);
  return t === null ? null : loadAllowlist(t);
})();

const hits: Array<Violation & { text: string }> = [];
const lines = new Map<string, string[]>();
let scanned = 0;
for (const g of GUARDS) {
  const files: SourceFile[] = readSources(g.files());
  scanned += files.length;
  for (const f of files) lines.set(f.path, f.text.split('\n'));
  hits.push(...g.check(files));
}
const out = settle(hits, lines, allow, baseAllow, GUARDS.map((g) => g.RULE));
for (const v of out) console.error(format(v));
const baseNote = base === null ? (initialCommit ? 'base: none (initial commit; addition check skipped)' : 'base: none (local, no origin/main; addition check skipped)') : baseAllow === null ? `base ${base.slice(0, 12)} has no allowlist (bootstrap)` : `base ${base.slice(0, 12)}`;
if (out.length) {
  console.error(`guards: ${out.length} violation(s) [${GUARDS.map((g) => g.RULE).join(', ')}]; ${baseNote}. See AGENTS.md for each rule and the helper to use.`);
  process.exit(1);
}
console.log(`guards: ok (${GUARDS.length} rules: ${GUARDS.map((g) => g.RULE).join(', ')}; ${scanned} files; ${allow.length} allowlisted lines; ${baseNote})`);
