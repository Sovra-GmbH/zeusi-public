// Importer source config (PLAN.md U1, "Ingestion sources"). The real file is
// config/sources.toml on the Mini (gitignored); config/sources.example.toml is the
// template. Validation runs at load time and refuses any hard-walled path or repo
// (the same rules as the DB wall, via src/wall.ts), and ANY string containing
// "plankiva" (the owner, 14 Nov 2026 14:17 Zurich: no Plankiva content, requests/ included).
// 0010 (owner rule): ClientCo is no longer walled; a clientco source
// (scope = "client") reads ClientCo content from its own vault folder.
//
// Review r1 MINOR-2: every path is judged on its logical form AND, when it exists,
// its real path (symlinks resolved), after percent-decoding and wall normalisation.
// sourcePathGate() is the importer's per-file gate; validateSources() applies the
// same to roots and to the literal prefix of every include.

import { readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { ConfigError } from './config.ts';
import { PROTECTED_VARIANTS_REGEX, PROTECTED_SPELLING_REGEX, pctDecode, pgRegexToJs, seedWall, wallNorm, type Wall } from './wall.ts';
import { HQ_PROJECT_RE } from './importers/profile.ts';

export const SOURCES_EXAMPLE = 'config/sources.example.toml';
export const SOURCE_KINDS = ['vault_note', 'lane_md', 'review_ledger', 'runner_log', 'assistant_memory', 'zeus_memory'] as const;
export const SOURCE_SCOPES = ['work', 'product', 'client'] as const;

export interface SourceSpec {
  name: string;
  /**
   * `manual` exists only in the in-memory spec `zeusi import` builds (src/import-run.ts); a
   * sources.toml can never declare it (validateSources accepts SOURCE_KINDS only).
   */
  kind: (typeof SOURCE_KINDS)[number] | 'manual';
  scope: (typeof SOURCE_SCOPES)[number];
  root: string;
  include: string[];
  exclude: string[];
  parse?: string;
  mode?: string;
  contentScan?: boolean;
  /**
   * zeus_memory (HQ export) sources only: the project folder this source covers
   * (docs/hq-sync.md). Every include must sit under `<project>/`; the importer
   * checks the note's frontmatter `project` against it.
   */
  project?: string;
}

export interface GithubSpec {
  org: string;
  repos: string[];
  northbankRepos: string[];
}

export interface HqExportSpec {
  /**
   * Project folders that are configured but disabled (fix round 1, m3): `export-filter`
   * counts their staged notes and leaves them in staging, never writes or deletes them.
   * Generic (none in the example config): `clientco` was held until 0010, now it is an
   * enabled scope clientco source (docs/hq-sync.md).
   */
  held: string[];
}

export interface SourcesConfig {
  sources: SourceSpec[];
  github: GithubSpec;
  /** `[hq_export]` (optional). */
  hqExport?: HqExportSpec;
}

// ---------------------------------------------------------------------------
// Minimal TOML subset: [table], [[array.of.tables]] (bare names), key = value with
// "basic" / 'literal' strings, true/false, integers, arrays (multi-line, trailing
// comma). Anything else fails loudly ("unsupported").

type TomlValue = string | number | boolean | TomlValue[];
type TomlTable = Record<string, TomlValue | Record<string, TomlValue> | Array<Record<string, TomlValue>>>;

export function parseToml(text: string): TomlTable {
  let i = 0;
  let line = 1;
  const root: TomlTable = {};
  let cur: Record<string, unknown> = root;
  const fail = (msg: string): never => {
    throw new ConfigError(`sources config line ${line}: ${msg}`);
  };
  const peek = (o = 0) => text[i + o];
  const skipSpaces = () => {
    while (peek() === ' ' || peek() === '\t') i++;
  };
  const skipComment = () => {
    if (peek() === '#') while (i < text.length && peek() !== '\n') i++;
  };
  const skipWsNl = () => {
    for (;;) {
      skipSpaces();
      skipComment();
      if (peek() === '\r') i++;
      if (peek() === '\n') {
        i++;
        line++;
        continue;
      }
      break;
    }
  };
  const endOfLine = () => {
    skipSpaces();
    skipComment();
    if (peek() === '\r') i++;
    if (i < text.length && peek() !== '\n') fail('unexpected text after value');
  };
  const bareKey = (): string => {
    const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i));
    if (!m) fail('expected a bare key (unsupported key syntax)');
    i += m![0].length;
    if (peek() === '.') fail('unsupported dotted key');
    return m![0];
  };
  const parseString = (): string => {
    const q = peek();
    if (text.startsWith(q!.repeat(3), i)) fail('unsupported multi-line string');
    i++;
    let out = '';
    while (i < text.length && peek() !== q) {
      const c = text[i++]!;
      if (c === '\n') fail('newline in string');
      if (q === '"' && c === '\\') {
        const e = text[i++];
        if (e === '"' || e === '\\') out += e;
        else if (e === 'n') out += '\n';
        else if (e === 't') out += '\t';
        else if (e === 'u') {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) fail('bad \\u escape');
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else fail(`unsupported escape \\${e}`);
      } else out += c;
    }
    if (peek() !== q) fail('unterminated string');
    i++;
    return out;
  };
  const parseValue = (): TomlValue => {
    const c = peek();
    if (c === '"' || c === "'") return parseString();
    if (c === '[') {
      i++;
      const arr: TomlValue[] = [];
      for (;;) {
        skipWsNl();
        if (peek() === ']') {
          i++;
          return arr;
        }
        arr.push(parseValue());
        skipWsNl();
        if (peek() === ',') {
          i++;
          continue;
        }
        if (peek() === ']') {
          i++;
          return arr;
        }
        fail('expected , or ] in array');
      }
    }
    if (c === '{') fail('unsupported inline table');
    const rest = text.slice(i);
    const b = /^(true|false)(?![A-Za-z0-9_])/.exec(rest);
    if (b) {
      i += b[0].length;
      return b[1] === 'true';
    }
    const n = /^[+-]?\d+(?![\d.eE:_-])/.exec(rest);
    if (n) {
      i += n[0].length;
      return Number(n[0]);
    }
    return fail('unsupported value');
  };

  for (;;) {
    skipWsNl();
    if (i >= text.length) break;
    if (peek() === '[') {
      const arrayTable = peek(1) === '[';
      i += arrayTable ? 2 : 1;
      skipSpaces();
      const name = bareKey();
      skipSpaces();
      if (!text.startsWith(arrayTable ? ']]' : ']', i)) fail('unterminated table header');
      i += arrayTable ? 2 : 1;
      endOfLine();
      if (arrayTable) {
        const existing = root[name];
        if (existing !== undefined && !Array.isArray(existing)) fail(`duplicate key ${name}`);
        const arr = (existing as Array<Record<string, TomlValue>> | undefined) ?? [];
        root[name] = arr;
        const t: Record<string, TomlValue> = {};
        arr.push(t);
        cur = t;
      } else {
        if (root[name] !== undefined) fail(`duplicate table ${name}`);
        const t: Record<string, TomlValue> = {};
        root[name] = t;
        cur = t;
      }
      continue;
    }
    const key = bareKey();
    skipSpaces();
    if (peek() !== '=') fail('expected =');
    i++;
    skipSpaces();
    const v = parseValue();
    if (key in cur) fail(`duplicate key ${key}`);
    cur[key] = v;
    endOfLine();
  }
  return root;
}

// ---------------------------------------------------------------------------

function strings(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.flatMap(strings);
  if (v && typeof v === 'object') return Object.values(v).flatMap(strings);
  return [];
}

const joinPath = (root: string, rel: string) => `${root.replace(/\/+$/, '')}/${rel.replace(/^\/+/, '')}`;

const PLANKIVA_SPELLING = pgRegexToJs(PROTECTED_SPELLING_REGEX);
const PLANKIVA_VARIANTS = pgRegexToJs(PROTECTED_VARIANTS_REGEX);

/**
 * "plankiva" in the string, its percent-decoded form, or either normalised (look-alikes,
 * zero-width); since 0010 also spelled with separators or leetspeak (the same hard
 * regex the wall seeds, PROTECTED_SPELLING_REGEX); since 0011 also "plankiva" and every
 * variant of PROTECTED_VARIANTS_REGEX (the owner: Plankiva IS Plankiva).
 */
export function mentionsProtectedName(s: string): boolean {
  return [s, pctDecode(s)].some((x) => {
    const n = wallNorm(x);
    return /plankiva/i.test(x) || n.includes('plankiva') || PLANKIVA_SPELLING.test(x) || PLANKIVA_SPELLING.test(n)
      || PLANKIVA_VARIANTS.test(x) || PLANKIVA_VARIANTS.test(n);
  });
}

export interface PathGateOptions {
  wall?: Wall;
  /** Expands a leading ~ (default: os.homedir()). */
  home?: string;
}

export type PathGateResult = { ok: true } | { ok: false; reason: string };

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  return p.startsWith('~/') ? join(home, p.slice(2)) : p;
}

function pathHit(p: string, wall: Wall): string | null {
  if (mentionsProtectedName(p)) return 'contains "plankiva" or a variant such as "plankiva" (the owner hard rules 2026-11-14 and 2026-11-15; requests/ included)';
  const v = wall.checkUri(`file:${p}`);
  if (!v.blocked) return null;
  const r = wall.rules.find((x) => x.id === v.ruleId);
  return `hits hard wall rule ${v.ruleId} (${v.kind} ${JSON.stringify(r?.pattern ?? '')})`;
}

/** realpath of an existing path, or null (missing / unreadable). Never reads file content. */
function realOrNull(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

/**
 * Importer path gate: the logical path, and the real path when it exists, must both
 * clear the hard wall and the Plankiva rule. A symlink from an allowed tree into
 * ~/PlankivaVault (or any hard-walled path) is refused.
 */
export function sourcePathGate(path: string, opts: PathGateOptions = {}): PathGateResult {
  const wall = opts.wall ?? seedWall();
  const home = opts.home ?? homedir();
  const logical = pathHit(path, wall);
  if (logical) return { ok: false, reason: `logical path ${logical}` };
  const expanded = expandHome(path, home);
  const real = realOrNull(expanded);
  if (real !== null && real !== expanded) {
    const hit = pathHit(real, wall);
    if (hit) return { ok: false, reason: `real path (symlink target) ${hit}` };
  }
  return { ok: true };
}

/** The part of an include pattern before its first glob segment. */
function literalPrefix(p: string): string {
  const segs = p.split('/');
  const i = segs.findIndex((x) => /[*?[\]{}]/.test(x));
  return (i === -1 ? segs : segs.slice(0, i)).join('/');
}

/** Validate a parsed config. Throws one ConfigError listing every problem. */
export function validateSources(t: TomlTable, wall: Wall = seedWall(), opts: { home?: string } = {}): SourcesConfig {
  const problems: string[] = [];
  const home = opts.home ?? homedir();

  // the owner's Plankiva rule applies to every string in the file, not just paths
  // (also percent-encoded, zero-width or look-alike spellings).
  for (const s of strings(t)) {
    if (mentionsProtectedName(s)) problems.push(`"${s}" contains "plankiva" or a variant such as "plankiva": Zeusi holds no Plankiva content (the owner hard rules 2026-11-14 and 2026-11-15; requests/ included)`);
  }

  const pathProblem = (where: string, p: string, scheme: string) => {
    const v = wall.checkUri(`${scheme}:${p}`);
    if (v.blocked) {
      const r = wall.rules.find((x) => x.id === v.ruleId);
      problems.push(`${where}: path "${p}" hits hard wall rule ${v.ruleId} (${v.kind} ${JSON.stringify(r?.pattern ?? '')})`);
    }
  };
  // Existing roots / literal include prefixes: the real path must clear the wall too.
  const realProblem = (where: string, p: string) => {
    const g = sourcePathGate(p, { wall, home });
    if (!g.ok && g.reason.startsWith('real path')) problems.push(`${where}: "${p}" ${g.reason}`);
  };

  const sources: SourceSpec[] = [];
  const raw = t['source'];
  const list = raw === undefined ? [] : Array.isArray(raw) ? raw : null;
  if (list === null) problems.push('[[source]] must be an array of tables');
  const names = new Set<string>();
  for (const [n, s] of (list ?? []).entries()) {
    if (!s || typeof s !== 'object' || Array.isArray(s)) {
      problems.push(`source #${n + 1} is not a table`);
      continue;
    }
    const o = s as Record<string, unknown>;
    const name = typeof o['name'] === 'string' ? o['name'] : '';
    const where = `source "${name || `#${n + 1}`}"`;
    if (!name) problems.push(`${where}: name is required`);
    else if (names.has(name)) problems.push(`${where}: duplicate name`);
    names.add(name);
    const kind = o['kind'];
    if (!(SOURCE_KINDS as readonly unknown[]).includes(kind)) problems.push(`${where}: kind must be one of ${SOURCE_KINDS.join('|')}`);
    const scope = o['scope'] ?? 'work';
    if (scope === 'personal') problems.push(`${where}: scope personal is reserved and not ingested in v1`);
    else if (!(SOURCE_SCOPES as readonly unknown[]).includes(scope)) problems.push(`${where}: scope must be one of ${SOURCE_SCOPES.join('|')}`);
    const root = typeof o['root'] === 'string' ? o['root'] : '';
    if (!root) problems.push(`${where}: root is required`);
    const include = Array.isArray(o['include']) ? o['include'] : [];
    const exclude = Array.isArray(o['exclude']) ? o['exclude'] : o['exclude'] === undefined ? [] : null;
    if (include.length === 0 || !include.every((x) => typeof x === 'string')) problems.push(`${where}: include must be a non-empty list of strings`);
    if (exclude === null || !exclude.every((x) => typeof x === 'string')) problems.push(`${where}: exclude must be a list of strings`);
    if (root) {
      pathProblem(where, root, 'file');
      realProblem(where, root);
    }
    for (const inc of include.filter((x): x is string => typeof x === 'string')) {
      pathProblem(where, inc, 'vault'); // relative to a vault root
      if (root) {
        pathProblem(where, joinPath(root, inc), 'file');
        const prefix = literalPrefix(joinPath(root, inc));
        if (prefix && prefix !== root) realProblem(where, prefix);
      }
    }
    const spec: SourceSpec = {
      name, kind: kind as SourceSpec['kind'], scope: scope as SourceSpec['scope'], root,
      include: include as string[], exclude: (exclude ?? []) as string[],
    };
    if (typeof o['parse'] === 'string') spec.parse = o['parse'];
    if (typeof o['mode'] === 'string') spec.mode = o['mode'];
    if (typeof o['content_scan'] === 'boolean') spec.contentScan = o['content_scan'];
    if (o['project'] !== undefined) {
      const project = o['project'];
      if (kind !== 'zeus_memory') problems.push(`${where}: project is only valid for kind zeus_memory`);
      else if (typeof project !== 'string' || !HQ_PROJECT_RE.test(project)) problems.push(`${where}: project must be a lower-case slug`);
      else {
        if (!include.every((x) => typeof x === 'string' && x.startsWith(`${project}/`))) problems.push(`${where}: every include must sit under "${project}/"`);
        pathProblem(where, `${project}/`, 'hq');
        spec.project = project;
      }
    }
    // ClientCo in the HQ export (the owner: ClientCo goes into Zeusi with its own scope):
    // the clientco folder is one source with scope clientco, and scope clientco is for that folder only.
    if (kind === 'zeus_memory') {
      if (spec.project === 'clientco' && scope !== 'client') problems.push(`${where}: project "clientco" needs scope "client"`);
      if (scope === 'client' && spec.project !== 'clientco') problems.push(`${where}: scope "client" is only for project "clientco"`);
    }
    sources.push(spec);
  }

  const gh = (t['github'] ?? {}) as Record<string, unknown>;
  const org = typeof gh['org'] === 'string' ? gh['org'] : 'example-org';
  const repos = Array.isArray(gh['repos']) ? (gh['repos'] as unknown[]).filter((x): x is string => typeof x === 'string') : [];
  const northbankRepos = Array.isArray(gh['northbank_repos']) ? (gh['northbank_repos'] as unknown[]).filter((x): x is string => typeof x === 'string') : [];
  for (const r of repos) {
    const full = r.includes('/') ? r : `${org}/${r}`;
    const v = wall.check('prs', { repo: full, source_uri: `gh:${full}`, title: null, author_login: null, head_ref: null, base_ref: null });
    if (v.blocked && v.hard) problems.push(`github: repo "${r}" hits hard wall rule ${v.ruleId} (${v.kind})`);
  }
  for (const r of northbankRepos) if (!repos.includes(r)) problems.push(`github: northbank repo "${r}" is not in repos`);

  const hx = (t['hq_export'] ?? {}) as Record<string, unknown>;
  const held: string[] = [];
  if (hx['held'] !== undefined) {
    const enabled = new Set(sources.filter((x) => x.kind === 'zeus_memory' && x.project !== undefined).map((x) => x.project!));
    if (!Array.isArray(hx['held'])) problems.push('hq_export: held must be an array of project folder names');
    else {
      for (const h of hx['held'] as unknown[]) {
        if (typeof h !== 'string' || !HQ_PROJECT_RE.test(h)) problems.push('hq_export: every held project must be a lower-case slug');
        else if (enabled.has(h)) problems.push(`hq_export: held project "${h}" is also an enabled zeus_memory project`);
        else if (!held.includes(h)) held.push(h);
      }
    }
  }

  if (problems.length) throw new ConfigError(problems.join('\n'));
  return { sources, github: { org, repos, northbankRepos }, ...(hx['held'] !== undefined ? { hqExport: { held } } : {}) };
}

export function loadSources(path: string): SourcesConfig {
  return validateSources(parseToml(readFileSync(path, 'utf8')));
}
