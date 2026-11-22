// Shared plumbing for the repo guards (scripts/guards/*.ts, run by `npm run guards` and `npm run check`).
//
// A guard is a pure function over file contents, so a test can feed it historical content
// (test/correct-guards.test.ts replays real past mistakes). Two escape hatches, both narrow:
//   * an inline exception on the offending line (or the line above it):
//       // correct-allow: <rule-id> reason=<why> expires=<YYYY-MM-DD> approved-by=<human GitHub login>
//     A missing field, a malformed or past expiry, or a bot/agent approver is itself a violation.
//   * scripts/guards/allowlist.json: lines that already existed when the guard landed. Each entry covers
//     one occurrence (rule+path+text, counted), so an identical copy of a listed line is a new hit. It
//     may only shrink: an entry that no longer matches anything, or an entry that the base revision did
//     not have (by count), is a violation.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

function resolveRoot(): string {
  const override = process.env['GUARD_ROOT'];
  if (override) {
    if (!isAbsolute(override)) throw new Error('GUARD_ROOT must be an absolute path');
    return override;
  }
  return fileURLToPath(new URL('../../', import.meta.url));
}
export const ROOT = resolveRoot();
export const ALLOWLIST_PATH = 'scripts/guards/allowlist.json';

export interface SourceFile { path: string; text: string }
export interface Violation { rule: string; path: string; line: number; message: string }
export interface AllowEntry { rule: string; path: string; text: string; why: string }

/** Repo-relative, '/'-separated paths of every file under `dirs` whose name passes `keep`. */
export function listFiles(dirs: readonly string[], keep: (p: string) => boolean, root = ROOT): string[] {
  const out: string[] = [];
  const walk = (abs: string) => {
    for (const name of readdirSync(abs)) {
      if (name === 'node_modules' || name === 'dist' || name.startsWith('.')) continue;
      const p = join(abs, name);
      if (statSync(p).isDirectory()) walk(p);
      else {
        const rel = relative(root, p).split(sep).join('/');
        if (keep(rel)) out.push(rel);
      }
    }
  };
  for (const d of dirs) {
    try {
      if (statSync(join(root, d)).isDirectory()) walk(join(root, d));
    } catch { /* missing dir: nothing to scan */ }
  }
  return out.sort();
}

export function readSources(paths: readonly string[], root = ROOT): SourceFile[] {
  return paths.map((path) => ({ path, text: readFileSync(join(root, path), 'utf8') }));
}

const ALLOW_RE = /correct-allow:\s*([a-z0-9-]+)(.*)$/;
const BOT_APPROVER = /(\[bot\]|^bot$|^claude|^codex|^copilot|^agent|^github-actions|^dependabot)/i;

/**
 * The inline exception for `rule` on `lines[i]` or `lines[i-1]`: 'ok', or a violation message when an
 * exception is present but invalid, or null when there is none.
 */
export function inlineException(lines: readonly string[], i: number, rule: string, today: string): 'ok' | string | null {
  for (const j of [i, i - 1]) {
    const m = j >= 0 ? ALLOW_RE.exec(lines[j] ?? '') : null;
    if (!m || m[1] !== rule) continue;
    const fields = Object.fromEntries([...m[2]!.matchAll(/(reason|expires|approved-by)=(\S+)/g)].map((x) => [x[1], x[2]]));
    const missing = ['reason', 'expires', 'approved-by'].filter((k) => !fields[k]);
    if (missing.length) return `correct-allow for ${rule} is missing ${missing.join(', ')} (needs reason=, expires=YYYY-MM-DD, approved-by=<human GitHub login>)`;
    const exp = fields['expires']!;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(exp) || Number.isNaN(Date.parse(exp))) return `correct-allow for ${rule}: expires=${exp} is not a YYYY-MM-DD date`;
    if (exp < today) return `correct-allow for ${rule} expired on ${exp}; fix the line or get a new human approval`;
    if (BOT_APPROVER.test(fields['approved-by']!)) return `correct-allow for ${rule}: approved-by must be a human GitHub login, not ${fields['approved-by']}`;
    return 'ok';
  }
  return null;
}

export const todayUtc = (): string => new Date().toISOString().slice(0, 10);

export function loadAllowlist(text: string | null): AllowEntry[] {
  if (text === null) return [];
  const v = JSON.parse(text) as { entries?: AllowEntry[] };
  return v.entries ?? [];
}

const key = (e: Pick<AllowEntry, 'rule' | 'path' | 'text'>) => `${e.rule}\u0000${e.path}\u0000${e.text}`;

/** How many times each rule+path+text key occurs: an allowlist entry covers ONE occurrence, not a pattern. */
function tally(entries: readonly AllowEntry[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const e of entries) m.set(key(e), (m.get(key(e)) ?? 0) + 1);
  return m;
}

/**
 * Apply inline exceptions and the allowlist to raw hits. `hits` carry the trimmed offending line text.
 * `base` is the allowlist at the base revision (null when the base has no allowlist yet: bootstrap).
 * Entries are counted: N identical entries cover N identical lines in that file, so a second copy of an
 * allowlisted line is a new hit (#45 review r1 P2-2), and the base must already have had N of them.
 */
export function settle(
  hits: ReadonlyArray<Violation & { text: string }>,
  files: ReadonlyMap<string, readonly string[]>,
  allow: readonly AllowEntry[],
  base: readonly AllowEntry[] | null,
  rules: readonly string[],
  today = todayUtc(),
): Violation[] {
  const out: Violation[] = [];
  const allowed = tally(allow);
  const used = new Map<string, number>();
  for (const h of hits) {
    const ex = inlineException(files.get(h.path) ?? [], h.line - 1, h.rule, today);
    if (ex === 'ok') continue;
    if (ex !== null) {
      out.push({ rule: h.rule, path: h.path, line: h.line, message: ex });
      continue;
    }
    const k = key(h);
    const n = used.get(k) ?? 0;
    if (n < (allowed.get(k) ?? 0)) {
      used.set(k, n + 1);
      continue;
    }
    const covers = allowed.get(k) ?? 0;
    out.push({ rule: h.rule, path: h.path, line: h.line, message: covers ? `${h.message} (this line is allowlisted, but the allowlist covers ${covers} occurrence(s) of it in ${h.path} and this is one more; the list only shrinks)` : h.message });
  }
  const baseCount = base === null ? null : tally(base);
  const seen = new Map<string, number>();
  for (const e of allow) {
    if (!rules.includes(e.rule)) continue;
    const k = key(e);
    const i = (seen.get(k) ?? 0) + 1; // this is the i-th entry with this key
    seen.set(k, i);
    if (i > (used.get(k) ?? 0)) {
      out.push({ rule: e.rule, path: ALLOWLIST_PATH, line: 0, message: `stale allowlist entry (${e.path}: ${e.text.slice(0, 80)}) no longer matches; delete it (the list only shrinks)` });
    } else if (baseCount !== null && i > (baseCount.get(k) ?? 0)) {
      out.push({ rule: e.rule, path: ALLOWLIST_PATH, line: 0, message: `new allowlist entry (${e.path}: ${e.text.slice(0, 80)}) is not in the base revision; the list only shrinks: fix the line, or use an inline correct-allow with a human approval` });
    }
  }
  return out;
}

/** Content of `path` at git revision `rev`, or null when the revision or path does not exist. */
export function gitShow(rev: string, path: string, root = ROOT): string | null {
  try {
    return execFileSync('git', ['show', `${rev}:${path}`], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return null;
  }
}

export function format(v: Violation): string {
  return `${v.path}:${v.line} [${v.rule}] ${v.message}`;
}
