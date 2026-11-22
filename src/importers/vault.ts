// Vault importer (PLAN.md U5; "Ingestion sources", "Idempotency and runs", KTD7;
// R1 R2 R7 R10 R11). Mirrors allowed KnowledgeVault notes into zeusi.notes and
// zeusi.chunks.
//
// READ-ONLY on the vault: files are opened with O_RDONLY only, through the
// injectable VaultFs (tests spy on it); nothing is ever written back.
//
// Two gates, in this order:
//   1. Path gate, BEFORE a directory is listed or a file is opened:
//      sourcePathGate() on the absolute path (logical + realpath, symlink-safe,
//      Plankiva rule) AND the wall's hard rules on the vault-relative path
//      ("vault:<rel>", and the real path's vault-relative form for symlinks).
//      A path that hits a SOFT rule too (no allows) is refused the same way: the
//      path is the note uri and the default title (r1). Symlinks that leave the
//      vault are refused; symlinked directories are never followed; symlinked files
//      are re-gated right before the open. Files are opened O_RDONLY|O_NOFOLLOW;
//      hard-linked files (nlink > 1) are refused unopened. A refused item is
//      quarantined as `vault-path-sha256:<sha256(relpath)>`: its name is never stored.
//      Chunk uris are `vault:<rel>#c<index>`, never heading text (r1 MAJOR-1).
//   2. Content gate, BEFORE any insert: the note row and every chunk row are
//      checked with the live wall (loadWall). A note is atomic: one blocked row
//      and nothing of the note is written; every blocked row is quarantined by
//      (uri, sha, content sha, rule) — never text (R10). Northbank product notes
//      (OD5) are checked with NO wall_allow pins: only a clean scan admits them.
//   The DB trigger (zeusi_90_wall) is the backstop: a ZW001 rejection rolls the
//   note's transaction back and is quarantined from the error DETAIL.
//
// Logs carry counts and the relative paths of non-quarantined files only.

import { constants, closeSync, fstatSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync, openSync, type Dirent, type Stats } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { basename, join, relative, sep } from 'node:path';
import { asPgError, type Db } from '../db.ts';
import { chunkMarkdown, embedText, estimateTokens, type Chunk } from '../chunking.ts';
import { parseWallError } from '../facts.ts';
import {
  bump, closeRun, emptyCounts, lastOkRunStart, openRun, resolveMode, tryLockImporter, unlockImporter, type VaultCounts,
} from '../ingest-run.ts';
import { redactDeep, redactSecrets, STORAGE_SKIP } from '../secrets.ts';
import { mentionsProtectedName, sourcePathGate, type SourcesConfig, type SourceSpec } from '../sources.ts';
import { HQ_PROFILE, IMPORT_PROFILE, VAULT_PROFILE, type ImportProfile } from './profile.ts';
import { PLAIN_ROUTE, sealedTx, type IndexedChunk, type SealedRoute, type WriteRoute } from '../write-route.ts';
import { nextId, SealRefused, sealedInsertSql, sealedUpdateSql, sealRow, type SqlCol } from '../workspace-seal.ts';
import {
  compileWall, globToRegex, loadWall, recordQuarantine, seedWall, sha256Hex, wallReadiness,
  type Row, type Verdict, type Wall,
} from '../wall.ts';

export const IMPORTER = 'vault';
export const MAX_FILE_BYTES = 8 * 1024 * 1024;
/** Folders whose notes are Northbank product notes (scope product, OD5). Matched case-insensitively (APFS). */
export const PRODUCT_PATH_PREFIXES = ['Work/product/', 'Work/products/product/'];
/**
 * 0010 (owner rule): ClientCo content lives in its own vault folder
 * and is stored with scope clientco. Matched case-insensitively (APFS). Checked before Northbank.
 */
export const ClientCo_PREFIXES = ['ClientCo/'];
export type VaultScope = 'work' | 'product' | 'client';
/** Deletion guard: refuse to mark more than max(MIN, FRACTION x active) notes deleted in one run. */
export const DELETE_GUARD = { min: 20, fraction: 0.25 };

// ---------------------------------------------------------------------------
// Read-only filesystem seam.

export interface VaultFs {
  readdir(path: string): Dirent[];
  lstat(path: string): Stats;
  stat(path: string): Stats;
  realpath(path: string): string;
  open(path: string, flags: number): number;
  fstat(fd: number): Stats;
  readAll(fd: number): Buffer;
  close(fd: number): void;
}

export const nodeVaultFs: VaultFs = {
  readdir: (p) => readdirSync(p, { withFileTypes: true }),
  lstat: (p) => lstatSync(p),
  stat: (p) => statSync(p),
  realpath: (p) => realpathSync(p),
  open: (p, flags) => openSync(p, flags),
  fstat: (fd) => fstatSync(fd),
  readAll: (fd) => readFileSync(fd),
  close: (fd) => closeSync(fd),
};

// ---------------------------------------------------------------------------
// Frontmatter (YAML subset used by the vault: scalars, quoted strings, inline and
// block lists, block scalars). Anything nested is kept as its raw text.

export type Frontmatter = Record<string, string | string[]>;

/**
 * Strip a trailing comment from an UNQUOTED value. Deliberate deviation from strict YAML for the
 * vault (docs/note-locks.md): `#` starts a comment only at the start of the value or after
 * whitespace, AND only when whitespace or the end of the line follows it (`# comment`). So the
 * vault's plain-text issue refs (`Close #1157`), tags (`#tag`) and `C#` stay text.
 */
export function stripComment(v: string): string {
  return v.replace(/(?:^|\s)#(?:\s.*)?$/, '').trim();
}

/** A whole quoted scalar (`"..."` with backslash escapes, or `'...'` with `''`), then optional space. */
const QUOTED = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*')(\s.*)?$/;

/** Drop a trailing comment: after a closing quote (`"a" # c`), or per stripComment for an unquoted value. */
function dropComment(v: string): string {
  const s = v.trim();
  const q = QUOTED.exec(s);
  if (q) return q[2] === undefined || /^\s+#(\s.*)?$/.test(q[2]) || q[2].trim() === '' ? q[1]! : s;
  return stripComment(s);
}

function unquote(v: string): string {
  const s = dropComment(v);
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1).replace(/\\(["\\])/g, '$1');
  if (s.length >= 2 && s.startsWith("'") && s.endsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
  return s;
}

function inlineList(v: string): string[] {
  const inner = v.trim().slice(1, -1);
  const out: string[] = [];
  let cur = '';
  let q: string | null = null;
  for (const c of inner) {
    if (q) {
      if (c === q) q = null;
      cur += c;
    } else if (c === '"' || c === "'") {
      q = c;
      cur += c;
    } else if (c === ',') {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out.map(unquote).filter((x) => x !== '');
}

/** A comment-only line inside a block (`# ...` or a lone `#`). `#1157 ...` is NOT a comment. */
const COMMENT_LINE = /^\s*#(\s|$)/;
const ITEM_LINE = /^(\s*)-(\s|$)/;

/**
 * Block list items. Each `- ` line starts an item; a non-empty, non-comment line indented deeper
 * than the item's dash continues it (joined with one space, YAML plain-scalar folding). Returns
 * null when the block is not a list (its first content line is not an item).
 */
function blockList(block: string[]): string[] | null {
  const items: string[] = [];
  let dashIndent = -1;
  for (const l of block) {
    if (l.trim() === '' || COMMENT_LINE.test(l)) continue;
    const m = ITEM_LINE.exec(l);
    if (m) {
      dashIndent = m[1]!.length;
      items.push(l.replace(/^\s*-\s*/, ''));
      continue;
    }
    const indent = /^\s*/.exec(l)![0].length;
    if (items.length === 0 || indent <= dashIndent) return null;
    items[items.length - 1] = `${items[items.length - 1]!.trimEnd()} ${l.trim()}`.trim();
  }
  return items.map(unquote);
}

export function parseFrontmatter(raw: string): Frontmatter {
  const fm: Frontmatter = {};
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*(#|$)/.test(line)) continue;
    const kv = /^([A-Za-z0-9_][A-Za-z0-9_ -]*?)\s*:(?:\s+(.*))?$/.exec(line);
    if (!kv) continue;
    const key = kv[1]!;
    // A trailing `# comment` (quote-aware, see stripComment) never becomes part of the value.
    const val = dropComment(kv[2] ?? '');
    const block: string[] = [];
    while (i + 1 < lines.length && (/^\s+\S/.test(lines[i + 1]!) || /^-\s/.test(lines[i + 1]!) || lines[i + 1] === '')) {
      if (lines[i + 1] === '' && !(i + 2 < lines.length && /^\s+\S/.test(lines[i + 2]!))) break;
      block.push(lines[++i]!);
    }
    if (val === '|' || val === '>' || /^[|>][+-]?$/.test(val)) {
      const body = block.map((l) => l.replace(/^\s+/, ''));
      fm[key] = val.startsWith('|') ? body.join('\n') : body.join(' ');
    } else if (val.startsWith('[') && val.endsWith(']')) {
      fm[key] = inlineList(val);
    } else if (val !== '') {
      fm[key] = unquote(val);
    } else if (block.length) {
      fm[key] = blockList(block) ?? block.join('\n');
    } else fm[key] = '';
  }
  return fm;
}

const FM_BLOCK = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/;

/** The raw frontmatter block of a note (between the leading `---` lines), or null. */
export function frontmatterBlock(text: string): string | null {
  return FM_BLOCK.exec(text)?.[1] ?? null;
}

export function splitNote(text: string): { fm: Frontmatter | null; body: string } {
  const m = FM_BLOCK.exec(text);
  if (!m) return { fm: null, body: text };
  return { fm: parseFrontmatter(m[1]!), body: text.slice(m[0].length) };
}

const WIKILINK = /!?\[\[([^\]\n]+?)\]\]/g;

/** [[target]], [[target|alias]], [[target#heading]], ![[embed]] -> unique targets, in order. */
export function wikilinks(...texts: string[]): string[] {
  const out: string[] = [];
  for (const t of texts) {
    for (const m of t.matchAll(WIKILINK)) {
      const target = m[1]!.split('|')[0]!.split('#')[0]!.trim();
      if (target && !out.includes(target)) out.push(target);
    }
  }
  return out;
}

/** frontmatter date -> { noteDate, ts } or null when absent / not a real date. */
export function parseNoteDate(v: unknown): { noteDate: string; ts: Date } | null {
  if (typeof v !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)\s*(Z|[+-]\d{2}:?\d{2})?)?$/.exec(v.trim());
  if (!m) return null;
  const day = `${m[1]}-${m[2]}-${m[3]}`;
  const check = new Date(`${day}T00:00:00Z`);
  if (Number.isNaN(check.getTime()) || check.toISOString().slice(0, 10) !== day) return null;
  if (!m[4]) return { noteDate: day, ts: check };
  const tz = m[5] ? (m[5] === 'Z' ? 'Z' : m[5].replace(/^([+-]\d{2})(\d{2})$/, '$1:$2')) : 'Z';
  const ts = new Date(`${day}T${m[4].length === 5 ? `${m[4]}:00` : m[4]}${tz}`);
  return Number.isNaN(ts.getTime()) ? { noteDate: day, ts: check } : { noteDate: day, ts };
}

// ---------------------------------------------------------------------------
// Path helpers.

const posix = (p: string) => p.split(sep).join('/');

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  return p.startsWith('~/') ? join(home, p.slice(2)) : p;
}

/** Quarantine uri for a path-gated item: the relative path's hash, never the name. */
export function pathQuarantineUri(rel: string, profile: ImportProfile = VAULT_PROFILE): string {
  return `${profile.scheme}-path-sha256:${sha256Hex(rel)}`;
}

/** Vault globs match case-insensitively: APFS is case-insensitive, so `Work/Northbank/` is `Work/product/`. */
function segRegex(seg: string): RegExp {
  return new RegExp(globToRegex(seg), 'i');
}

/** Chunk uri: the note uri plus the chunk index. Never derived from heading text (r1 MAJOR-1, R10). */
export function chunkUri(noteUri: string, index: number): string {
  return `${noteUri}#c${index}`;
}

/** Could a file under directory `dirRel` match include glob `inc`? (Prunes the walk.) */
function couldMatchUnder(dirRel: string, inc: string): boolean {
  const ds = dirRel.split('/');
  const is = inc.split('/');
  for (let i = 0; i < ds.length; i++) {
    const g = is[i];
    if (g === undefined) return false;
    if (g.includes('**')) return true;
    if (!segRegex(g).test(ds[i]!)) return false;
  }
  return is.length > ds.length;
}

interface Matcher {
  spec: SourceSpec;
  include: RegExp[];
  exclude: RegExp[];
}

// ---------------------------------------------------------------------------

export interface VaultImportOptions {
  config: SourcesConfig;
  mode: 'full' | 'incremental';
  /** No database: walk, gate, parse, chunk, count. Uses the seed wall. */
  dryRun?: boolean;
  /** Required unless dryRun. Connect as zeusi_ingest (real mode) or PGlite (tests). */
  db?: Db;
  home?: string;
  /** ingest_runs.host (default 'mini'). */
  host?: string;
  fs?: VaultFs;
  log?: (line: string) => void;
  /** Log relative paths of non-quarantined files (inserted/updated/errors). Default: !dryRun. */
  logPaths?: boolean;
  verbose?: boolean;
  now?: () => Date;
  /**
   * TEST ONLY: replaces the content pre-check (gate 2) to prove the trigger backstop.
   * The path gate (gate 1) is never replaced.
   */
  testOnlyContentWall?: Wall;
  /**
   * DRY RUN ONLY (refused otherwise): the wall for both gates instead of the seed wall.
   * scripts/wall-dryrun.ts --compare-old runs the importer's own pipeline offline with
   * the 0009 wall (legacySeedWall) and the current one. Also used by the U6 cost
   * estimate (embed --estimate). Real runs always load the live rules.
   */
  dryRunWall?: Wall;
  /**
   * DRY RUN ONLY (refused otherwise): called once per gated item, in memory. The caller
   * must print counts only (never rel, rows or text).
   */
  dryRunObserve?: (o: VaultDryRunObservation) => void;
  /**
   * DRY RUN ONLY (U6 cost estimate): called once per admitted note with NUMBERS ONLY
   * (estimated and worst-case tokens of each chunk's embedded string). Never a path,
   * a title or text. Refused in real mode.
   */
  dryRunObserver?: (o: { chunks: Array<{ estTokens: number; worstTokens: number }> }) => void;
  /**
   * Which source family to import (default: the vault). HQ_PROFILE imports the
   * Zeus HQ export folder (docs/hq-sync.md) through the SAME gates.
   */
  profile?: ImportProfile;
  /**
   * Re-parse frontmatter of UNCHANGED notes (lock-lifecycle addendum K5; docs/note-locks.md).
   * Same walk, path gate, content wall and redaction; nothing is inserted, deleted, quarantined
   * or retracted, no chunk / body / embedding is touched, no ingest_runs row. `real: false` only
   * reads (the caller wraps it in BEGIN READ ONLY); `real: true` updates notes.frontmatter of the
   * notes whose stored frontmatter differs, one transaction each, under the importer's lock.
   * Requires db. `scope` narrows it to one scope.
   */
  reparse?: { real: boolean; scope?: VaultScope };
  /**
   * C6 (docs/plans/2026-11-19-c6-write-path.md KTD8): the write route, default PLAIN_ROUTE (today's SQL,
   * unchanged). The sealed route (a workspace in verified / on, src/write-route.ts) seals every note
   * and chunk in the app, writes no plain content, no plain digest and no embedding, and refuses
   * dryRun, reparse and a deletion pass.
   */
  route?: WriteRoute;
  /**
   * TEST ONLY (C6 §7.16): runs inside the sealed note transaction after the id lookup and before the
   * write (stages a racing insert on PGlite's one connection).
   */
  testOnlySealedBeforeWrite?: (db: Db, at: { vaultPathHmac: Buffer; found: boolean }) => Promise<void>;
}

/** One note whose stored frontmatter differs from a re-parse of its unchanged file. */
export interface ReparseChange {
  id: number;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

export interface ReparseCounts {
  /** Stored, active notes whose file is unchanged (sha + scope): compared. */
  scanned: number;
  unchanged: number;
  changed: number;
  /** Real run: frontmatter rows updated. */
  updated: number;
  /** The file changed since the last ingest (sha / scope): left to `ingest vault`. */
  file_changed: number;
  /** No active stored note for the file: left to `ingest vault`. */
  not_stored: number;
  /** The content wall blocks the note now: left untouched (wall audit / ingest decide). */
  blocked: number;
  /** Real run: an update failed (trigger refusal or database error); rolled back. */
  write_errors: number;
}

export { HQ_PROFILE, IMPORT_PROFILE, VAULT_PROFILE, type ImportProfile };

/** One dry-run outcome: a path-gated entry (file or directory), a quarantined note, an admitted note, or a file error. */
export type VaultDryRunObservation =
  | { outcome: 'path_gated'; rel: string; ruleId: number | null }
  | { outcome: 'content'; rel: string; scope: VaultScope; ruleIds: Array<number | null>; hard: boolean }
  | { outcome: 'admitted'; rel: string; scope: VaultScope; note: Row; chunks: Row[] }
  | { outcome: 'error'; rel: string };

export interface VaultImportResult {
  runId: number | null;
  mode: 'full' | 'incremental';
  /** 'locked': another run of this importer holds the advisory lock; nothing was read or written. */
  status: 'ok' | 'failed' | 'locked';
  counts: VaultCounts;
  /** Safe message (no paths, no content) when status is failed or locked. */
  error?: string;
  /** Reparse mode only: counts, and the changed rows in memory (never printed). */
  reparse?: { counts: ReparseCounts; changes: ReparseChange[] };
}

export class VaultRunError extends Error {
  override name = 'VaultRunError';
}

interface Candidate {
  rel: string;
  abs: string;
  /** stat of the file the open must land on (target of a symlink). */
  st: Stats;
  /** A symlink entry: gate 1 is re-run on its real path right before the open. */
  link: boolean;
  scope: VaultScope;
  /** The `project` of the first matching source that sets one (HQ profile). */
  project: string | null;
}

interface Existing {
  id: number;
  status: string;
  scope: string;
  sha: string;
  mtimeMs: number;
}

interface Blocked {
  table: 'notes' | 'chunks';
  uri: string;
  verdict: Verdict;
}

/** Rule id for a refused path (first hard rule that matches any of its forms; the Plankiva term rule for the extra Plankiva check). */
function pathRuleId(wall: Wall, forms: string[]): number | null {
  for (const f of forms) {
    const v = wall.checkUri(f);
    if (v.blocked) return v.ruleId;
  }
  if (forms.some((f) => mentionsProtectedName(f))) return wall.rules.find((r) => r.kind === 'term' && r.pattern === 'plankiva')?.id ?? null;
  return null;
}

export async function importVault(opts: VaultImportOptions): Promise<VaultImportResult> {
  const dry = opts.dryRun === true;
  const db = opts.db;
  const reparse = opts.reparse;
  const route = opts.route ?? PLAIN_ROUTE;
  const sealed = route.kind === 'sealed' ? route : null;
  if (reparse && (dry || !db)) throw new VaultRunError('importVault: reparse needs a database and is not a dry run');
  const rc: ReparseCounts = { scanned: 0, unchanged: 0, changed: 0, updated: 0, file_changed: 0, not_stored: 0, blocked: 0, write_errors: 0 };
  const changes: ReparseChange[] = [];
  const profile = opts.profile ?? VAULT_PROFILE;
  if (sealed && (dry || reparse || profile.deletes !== false)) throw new VaultRunError('importVault: the sealed route takes no dry run, reparse or deletion pass');
  const IMPORTER = profile.importer;
  const scheme = profile.scheme;
  if (!dry && !db) throw new VaultRunError('importVault: db is required unless dryRun');
  if (!dry && (opts.dryRunWall || opts.dryRunObserve)) throw new VaultRunError('importVault: dryRunWall / dryRunObserve are for dry runs only');
  if (!dry && opts.dryRunObserver) throw new VaultRunError('importVault: dryRunWall / dryRunObserver are for a dry run only');
  const observe = opts.dryRunObserve ?? (() => {});
  const fs = opts.fs ?? nodeVaultFs;
  const home = opts.home ?? homedir();
  const log = opts.log ?? (() => {});
  const logPaths = opts.logPaths ?? (!dry && !reparse);
  const now = opts.now ?? (() => new Date());
  const counts = emptyCounts();

  const specs = opts.config.sources.filter((s) => s.kind === profile.sourceKind);
  if (specs.length === 0) throw new VaultRunError(`no ${profile.sourceKind} sources in the config`);
  const roots = [...new Set(specs.map((s) => expandHome(s.root, home).replace(/\/+$/, '')))];
  if (roots.length !== 1) throw new VaultRunError(`all ${profile.sourceKind} sources must share one root (vault_path is relative to it)`);
  const root = roots[0]!;
  const matchers: Matcher[] = specs.map((spec) => ({
    spec,
    include: spec.include.map((g) => new RegExp(globToRegex(g), 'i')),
    exclude: spec.exclude.map((g) => new RegExp(globToRegex(g), 'i')),
  }));
  const includes = specs.flatMap((s) => s.include);

  const wall = dry ? (opts.dryRunWall ?? seedWall()) : await loadWall(db!);
  const contentWall = opts.testOnlyContentWall ?? wall;
  const noAllows = compileWall(wall.rules, []);
  const strictWall = opts.testOnlyContentWall ?? noAllows; // OD5: no allows for product
  /**
   * Gate 1 also refuses a vault-relative path that hits ANY rule, soft ones included
   * (no allows): the path becomes the note uri and the default title, so a walled
   * file or folder name would otherwise be stored in quarantine.source_uri (r1).
   */
  const softPathHit = (rel: string): Verdict | null => {
    const v = noAllows.check('facts', { source_uri: `${scheme}:${rel}`, kind: 'other', subject: null, text: rel });
    return v.blocked ? v : null;
  };

  let mode: 'full' | 'incremental' = opts.mode;
  let since: Date | null = null;
  let runId: number | null = null;
  let locked = false;
  if (reparse) {
    // Reparse: full walk, no run row. The real run holds the vault importer's lock (no ingest interleaves).
    mode = 'full';
    if (reparse.real) {
      if (!(await tryLockImporter(db!, IMPORTER))) {
        return { runId: null, mode, status: 'locked', counts, error: `another ${profile.label} ingest run holds the lock; nothing read or written` };
      }
      locked = true;
    }
  } else if (!dry) {
    // One vault run at a time (r1 MINOR-5): a second run exits before any read or write.
    if (!(await tryLockImporter(db!, IMPORTER))) {
      return { runId: null, mode, status: 'locked', counts, error: `another ${profile.label} ingest run holds the lock; nothing read or written` };
    }
    locked = true;
    try {
      mode = await resolveMode(db!, IMPORTER, opts.mode, now());
      since = mode === 'incremental' ? await lastOkRunStart(db!, IMPORTER) : null;
      runId = await openRun(db!, { importer: IMPORTER, host: opts.host ?? 'mini', mode });
    } catch (e) {
      await unlockImporter(db!, IMPORTER).catch(() => {});
      throw e;
    }
  } else if (opts.mode === 'incremental') {
    mode = 'full'; // no run history without a database
  }

  const quarantine = async (q: { uri: string; sha: string; ruleId: number | null; table: string; contentSha: string | null }) => {
    counts.quarantine_rows++;
    if (dry || reparse) return; // reparse never writes quarantine rows
    await recordQuarantine(db!, {
      sourceKind: profile.sourceKind, sourceUri: q.uri, sourceSha256: q.sha, ruleId: q.ruleId,
      ingestRunId: runId!, table: q.table, contentSha256: q.contentSha,
    }, route);
  };
  const pathQuarantine = async (rel: string, ruleId: number | null) => {
    observe({ outcome: 'path_gated', rel, ruleId });
    counts.quarantined++;
    counts.path_gated++;
    bump(counts.by_rule, ruleId === null ? 'none' : String(ruleId));
    await quarantine({ uri: pathQuarantineUri(rel, profile), sha: sha256Hex(rel), ruleId, table: 'notes', contentSha: null });
  };

  try {
    // ---- 1. Walk + path gate ---------------------------------------------------
    let rootReal: string;
    try {
      if (!fs.stat(root).isDirectory()) throw new Error('not a directory');
      rootReal = fs.realpath(root);
    } catch {
      throw new VaultRunError(`${profile.label} root is missing or not a directory (nothing read, nothing deleted)`);
    }
    const rootGate = sourcePathGate(root, { wall, home });
    if (!rootGate.ok) throw new VaultRunError(`${profile.label} root is refused by the path gate`);

    /** Gate 1 for one entry. Returns the real path when it passes. */
    const gate = (rel: string, abs: string): { ok: true; real: string } | { ok: false; ruleId: number | null } => {
      const forms = [`${scheme}:${rel}`, `file:${abs}`];
      const g = sourcePathGate(abs, { wall, home });
      let real: string;
      try {
        real = fs.realpath(abs);
      } catch {
        return { ok: false, ruleId: pathRuleId(wall, forms) }; // dangling symlink: refuse
      }
      const realRel = posix(relative(rootReal, real));
      const inside = realRel !== '' && !realRel.startsWith('../') && realRel !== '..';
      forms.push(`file:${real}`);
      if (inside) forms.push(`${scheme}:${realRel}`);
      // Directory forms too: "Work/intake/**" must refuse the directory Work/intake itself, before it is listed.
      forms.push(...forms.map((f) => `${f}/`));
      const hard = !g.ok || forms.some((f) => wall.checkUri(f).blocked) || mentionsProtectedName(rel);
      if (hard) return { ok: false, ruleId: pathRuleId(wall, forms) };
      if (!inside) return { ok: false, ruleId: null }; // symlink leaving the vault
      const soft = softPathHit(rel);
      if (soft) return { ok: false, ruleId: soft.ruleId };
      return { ok: true, real };
    };

    const candidates = new Map<string, Candidate>();
    const matchSpecs = (rel: string) => matchers.filter((m) => m.include.some((r) => r.test(rel)) && !m.exclude.some((r) => r.test(rel)));

    /** Directories that could not be listed: notes under them are not treated as deleted. */
    const unreadable: string[] = [];
    const walk = async (dirAbs: string, dirRel: string): Promise<void> => {
      let listing: Dirent[];
      try {
        listing = fs.readdir(dirAbs);
      } catch (e) {
        if (dirRel === '') throw e;
        unreadable.push(dirRel);
        counts.errors++;
        if (logPaths) log(`skipped (directory not readable): ${dirRel}`);
        return;
      }
      const entries = listing.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      for (const e of entries) {
        if (e.name.startsWith('.')) continue; // dot folders/files (.obsidian, .trash, .git) are never read
        const rel = dirRel ? `${dirRel}/${e.name}` : e.name;
        const abs = join(dirAbs, e.name);
        if (e.isSymbolicLink()) {
          const g = gate(rel, abs);
          if (!g.ok) {
            await pathQuarantine(rel, g.ruleId);
            continue;
          }
          const st = fs.stat(abs);
          if (st.isDirectory()) {
            counts.symlink_dirs_skipped++;
            continue;
          }
          if (!st.isFile()) continue;
          const ms = matchSpecs(rel);
          if (ms.length) candidates.set(rel, { rel, abs, st, link: true, scope: scopeFor(rel, ms), project: projectFor(ms) });
        } else if (e.isDirectory()) {
          if (!includes.some((inc) => couldMatchUnder(rel, inc))) continue;
          const g = gate(rel, abs);
          if (!g.ok) {
            await pathQuarantine(rel, g.ruleId);
            continue;
          }
          await walk(abs, rel);
        } else if (e.isFile()) {
          const ms = matchSpecs(rel);
          if (!ms.length) continue;
          const g = gate(rel, abs);
          if (!g.ok) {
            await pathQuarantine(rel, g.ruleId);
            continue;
          }
          candidates.set(rel, { rel, abs, st: fs.lstat(abs), link: false, scope: scopeFor(rel, ms), project: projectFor(ms) });
        }
      }
    };
    await walk(root, '');

    // ---- 2. Existing notes + deletion guard (before any write) ------------------
    const existing = new Map<string, Existing>();
    const storedFm = new Map<number, Record<string, unknown>>();
    if (sealed) {
      // C6 KTD8: the stored path is sealed. Every note of this source kind, its vault_path opened in the
      // app (bound to the row id: a moved ciphertext fails here and the run fails) and filtered by prefix.
      const r = await db!.query<{ id: number; vp: Uint8Array | null; status: string; scope: string; sha: string; mtime: Date }>(
        `SELECT id::int AS id, vault_path_ct AS vp, status, scope::text AS scope, encode(source_sha256, 'hex') AS sha, file_mtime AS mtime
         FROM zeusi.notes WHERE source_kind = $1::zeusi.source_kind`, [profile.sourceKind]);
      for (const x of r.rows) {
        if (!x.vp) throw new VaultRunError('a note without a sealed path in a sealed workspace');
        const vp = sealed.key.open('notes', 'vault_path', x.id, x.vp);
        if (!vp.startsWith(profile.storedPrefix)) continue;
        existing.set(vp.slice(profile.storedPrefix.length), { id: Number(x.id), status: x.status, scope: x.scope, sha: x.sha, mtimeMs: new Date(x.mtime).getTime() });
      }
    } else if (!dry) {
      // Only this profile's rows (source_kind + stored prefix): the vault and the HQ export never delete each other's notes.
      const r = await db!.query<{ id: number; vault_path: string; status: string; scope: string; sha: string; mtime: Date; fm: unknown }>(
        `SELECT id::int AS id, vault_path, status, scope::text AS scope, encode(source_sha256, 'hex') AS sha, file_mtime AS mtime,
                ${reparse ? 'frontmatter' : 'NULL::jsonb'} AS fm
         FROM zeusi.notes WHERE source_kind = $1::zeusi.source_kind AND left(vault_path, $2) = $3`,
        [profile.sourceKind, profile.storedPrefix.length, profile.storedPrefix],
      );
      for (const x of r.rows) {
        existing.set(x.vault_path.slice(profile.storedPrefix.length), { id: Number(x.id), status: x.status, scope: x.scope, sha: x.sha, mtimeMs: new Date(x.mtime).getTime() });
        if (reparse && x.fm && typeof x.fm === 'object') storedFm.set(Number(x.id), x.fm as Record<string, unknown>);
      }
    }
    const active = [...existing.entries()].filter(([, x]) => x.status === 'active');
    // Imports (IMPORT_PROFILE, deletes: false) only add: no deletion pass and no deletion guard. Reparse never deletes.
    const deletes = profile.deletes !== false && !reparse;
    const gone = deletes ? active.filter(([p]) => !candidates.has(p) && !unreadable.some((d) => p.startsWith(`${d}/`))) : [];
    if (deletes && active.length > 0 && candidates.size === 0) {
      throw new VaultRunError(`deletion guard: no files found but ${active.length} active notes exist (${profile.label} unmounted or config wrong?); nothing deleted`);
    }
    const limit = Math.max(DELETE_GUARD.min, Math.floor(active.length * DELETE_GUARD.fraction));
    if (gone.length > limit) {
      throw new VaultRunError(`deletion guard: ${gone.length} of ${active.length} active notes would be marked deleted (limit ${limit}); nothing deleted`);
    }

    // ---- 3. Each candidate: open read-only, parse, gate, write -----------------
    for (const c of [...candidates.values()].sort((a, b) => (a.rel < b.rel ? -1 : 1))) {
      const ex = existing.get(c.rel);
      const mtimeMs = Math.floor(c.st.mtimeMs);
      const fileErr = (why: string) => {
        observe({ outcome: 'error', rel: c.rel });
        counts.errors++;
        if (logPaths) log(`skipped (${why}): ${c.rel}`);
      };
      // Profile scope check before the file is opened (HQ: clientco/ only via its scope clientco source).
      const scopeProblem = profile.scopeProblem?.(c.rel, c.scope, matchSpecs(c.rel).map((m) => m.spec.scope)) ?? null;
      if (scopeProblem) {
        fileErr(scopeProblem);
        continue;
      }
      // A hard link can alias a walled file under a clean name: refuse unopened (r1 MINOR-4).
      if (c.st.nlink > 1) {
        counts.hardlinks++;
        fileErr('hard link');
        continue;
      }
      if (reparse?.scope !== undefined && c.scope !== reparse.scope) continue;
      if (reparse && !(ex && ex.status === 'active')) {
        rc.not_stored++; // a new file is ingest's job, not reparse's (checked before the open)
        continue;
      }
      if (mode === 'incremental' && since && ex && ex.status === 'active' && ex.mtimeMs === mtimeMs && mtimeMs < since.getTime()) {
        counts.skipped++;
        bump(counts.by_scope, ex.scope);
        continue;
      }

      // Read-only open, never through a symlink (r1 MINOR-3). A symlink entry is re-resolved
      // and re-gated immediately before the open, and its gated real path is opened. The fd
      // must still be the file the gate approved (ino/dev), with a single link.
      let target = c.abs;
      if (c.link) {
        const g = gate(c.rel, c.abs);
        if (!g.ok) {
          await pathQuarantine(c.rel, g.ruleId);
          continue;
        }
        target = g.real;
      }
      let bytes: Buffer;
      let fd: number;
      try {
        fd = fs.open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
      } catch {
        fileErr('not readable');
        continue;
      }
      try {
        const st = fs.fstat(fd);
        if (st.ino !== c.st.ino || st.dev !== c.st.dev) {
          fileErr('changed while reading');
          continue;
        }
        if (st.nlink > 1) {
          counts.hardlinks++;
          fileErr('hard link');
          continue;
        }
        if (st.size > MAX_FILE_BYTES) {
          fileErr('larger than 8 MiB');
          continue;
        }
        bytes = fs.readAll(fd);
      } finally {
        fs.close(fd);
      }

      let text: string;
      try {
        text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
      } catch {
        fileErr('not UTF-8');
        continue;
      }
      // Secrets (src/secrets.ts): every full, partial or masked credential is replaced by
      // [REDACTED:<kind>] in what is STORED: the parsed frontmatter values (title included),
      // the body and so the chunks. The rest of the note is kept. The wall gate below still
      // sees the file as written (its verdicts do not change because of redaction); an
      // admitted note is then rebuilt from the redacted parts. source_sha256 stays the sha of
      // the file bytes (provenance). Fail closed: a detector error skips the file.
      // Every file is redacted below (not gated on a text signal, review r2: a frontmatter FIELD
      // named like a credential, `db_password:` with a block-scalar value, only shows in the
      // parsed values). Fail closed there too: a detector error skips the file.
      const sha = createHash('sha256').update(bytes).digest('hex'); // whole file: frontmatter edits count
      // What the stored row holds for that digest: the digest (plain) or its keyed form (sealed, C6 KTD5).
      const storedSha = sealed ? sealed.key.keyedSha('source_sha256', sha).toString('hex') : sha;
      const { fm, body: body0 } = splitNote(text);
      let body = body0;
      // Profile format check (HQ export: layout + frontmatter). Never logs content.
      const formatProblem = profile.formatProblem?.(c.rel, fm, c.project) ?? null;
      if (formatProblem) {
        fileErr(formatProblem);
        continue;
      }
      const fmRows = (f: typeof fm, b: string) => {
        const links = wikilinks(...Object.values(f ?? {}).flat(), b);
        return {
          frontmatter: { ...(f ?? {}), links } as Record<string, unknown>,
          title: typeof f?.['title'] === 'string' && f['title'].trim() !== '' ? f['title'].trim() : basename(c.rel, '.md'),
        };
      };
      let { frontmatter, title } = fmRows(fm, body);
      const date = parseNoteDate(fm?.['date']);
      const sourceTs = date ? date.ts : new Date(mtimeMs);
      const uri = `${scheme}:${c.rel}`;
      const storedPath = `${profile.storedPrefix}${c.rel}`;
      let noteRow: Row = {
        vault_path: storedPath, title, body, frontmatter, scope: c.scope, source_kind: profile.sourceKind, source_uri: uri,
      };
      let chunks = chunkMarkdown(body);
      const kUri = (k: Chunk) => chunkUri(uri, k.index);

      // Gate 2: content pre-check (note + every chunk).
      const w = c.scope === 'product' ? strictWall : contentWall;
      const blocked: Blocked[] = [];
      const chunkRow = (k: Chunk): Row => ({ heading_path: k.headingPath, text: k.text, scope: c.scope, source_kind: profile.sourceKind, source_uri: kUri(k) });
      const nv = w.check('notes', noteRow);
      if (nv.blocked) blocked.push({ table: 'notes', uri, verdict: nv });
      if (!(nv.blocked && nv.hard)) {
        for (const k of chunks) {
          const v = w.check('chunks', chunkRow(k));
          if (v.blocked) blocked.push({ table: 'chunks', uri: kUri(k), verdict: v });
        }
      }
      const retract = async () => {
        if (dry || !ex || ex.status !== 'active') return;
        if (sealed) {
          // C6 KTD10: a sealed write takes the index lock and tells the index (the note leaves search).
          const n = await sealedTx(db!, sealed, async () => {
            const del = await db!.query<{ id: number | string }>(`DELETE FROM zeusi.chunks WHERE note_id = $1 RETURNING id`, [ex.id]);
            await sealed.index.onNoteRemoved(db!, ex.id, del.rows.map((r) => Number(r.id)));
            return del.rows.length;
          });
          if (n) counts.retracted++;
          return;
        }
        const del = await db!.query(`DELETE FROM zeusi.chunks WHERE note_id = $1 RETURNING id`, [ex.id]);
        if (del.rows.length) counts.retracted++;
      };
      if (blocked.length && reparse) {
        rc.blocked++; // reparse never quarantines or retracts: the note is left exactly as stored
        continue;
      }
      if (blocked.length) {
        observe({ outcome: 'content', rel: c.rel, scope: c.scope, ruleIds: blocked.map((b) => b.verdict.ruleId), hard: blocked.some((b) => b.verdict.hard) });
        counts.quarantined++;
        bump(counts.by_rule, String(blocked[0]!.verdict.ruleId));
        for (const b of blocked) await quarantine({ uri: b.uri, sha, ruleId: b.verdict.ruleId, table: b.table, contentSha: b.verdict.contentSha256 });
        await retract();
        continue;
      }

      {
        // Admitted: store the redacted note (frontmatter values and body; chunks rebuilt from it).
        let rb: ReturnType<typeof redactSecrets>;
        let rf: ReturnType<typeof redactDeep<typeof fm>>;
        try {
          rb = redactSecrets(body, { skip: STORAGE_SKIP });
          rf = redactDeep(fm, { skip: STORAGE_SKIP });
        } catch {
          fileErr('secret scan failed');
          continue;
        }
        if (rb.count + rf.count > 0) {
          body = rb.text;
          ({ frontmatter, title } = fmRows(rf.value, body));
          noteRow = { ...noteRow, title, body, frontmatter };
          chunks = chunkMarkdown(body);
          counts.notes_redacted++;
          counts.secrets_redacted += rb.count + rf.count;
        }
      }
      if (reparse) {
        if (!(ex && ex.sha === sha && ex.scope === c.scope)) {
          rc.file_changed++;
          continue;
        }
        rc.scanned++;
        const before = storedFm.get(ex.id) ?? {};
        if (canonicalJson(before) === canonicalJson(frontmatter)) {
          rc.unchanged++;
          continue;
        }
        rc.changed++;
        changes.push({ id: ex.id, before, after: frontmatter });
        if (!reparse.real) continue;
        try {
          await db!.exec('BEGIN');
          // ONLY the frontmatter, and only if the row is still the file we parsed (sha, active).
          const u = await db!.query(
            `UPDATE zeusi.notes SET frontmatter = $2::jsonb
             WHERE id = $1 AND status = 'active' AND source_sha256 = decode($3, 'hex') RETURNING id`,
            [ex.id, JSON.stringify(frontmatter), sha]);
          await db!.exec('COMMIT');
          if (u.rows.length) rc.updated++;
        } catch {
          await db!.exec('ROLLBACK').catch(() => {});
          rc.write_errors++;
        }
        continue;
      }
      if (ex && ex.status === 'active' && ex.sha === storedSha && ex.scope === c.scope) {
        counts.skipped++;
        bump(counts.by_scope, c.scope);
        continue;
      }
      if (dry) {
        observe({ outcome: 'admitted', rel: c.rel, scope: c.scope, note: noteRow, chunks: chunks.map(chunkRow) });
        if (opts.dryRunObserver) {
          opts.dryRunObserver({
            chunks: chunks.map((k) => {
              const e = embedText(title, k.headingPath, k.text);
              return { estTokens: estimateTokens(e), worstTokens: Buffer.byteLength(e, 'utf8') };
            }),
          });
        }
        counts.inserted++;
        counts.chunks_written += chunks.length;
        bump(counts.by_scope, c.scope);
        continue;
      }

      if (sealed) {
        // C6 KTD8: one sealed transaction per note; no vector reuse (no embedding on a sealed chunk).
        try {
          const w = await writeSealedNote(db!, sealed, {
            storedPath, uri, title, noteDate: date?.noteDate ?? null, frontmatter: JSON.stringify(frontmatter), body,
            mtimeIso: new Date(mtimeMs).toISOString(), scope: c.scope, sourceKind: profile.sourceKind, sourceTsIso: sourceTs.toISOString(), sha, runId: runId!,
            chunks: chunks.map((k) => ({ index: k.index, headingPath: k.headingPath, text: k.text, tokenCount: k.tokenCount, uri: kUri(k) })),
          }, opts.testOnlySealedBeforeWrite);
          if (w.updated) counts.updated++;
          else counts.inserted++;
          counts.chunks_written += chunks.length;
          bump(counts.by_scope, c.scope);
          if (logPaths && opts.verbose) log(`${w.updated ? 'updated' : 'inserted'}: ${c.rel} (${chunks.length} chunks)`);
        } catch (e) {
          if (e instanceof SealRefused) throw e; // the seal budget is used up: the whole call stops
          fileErr(`database error ${asPgError(e).code ?? 'unknown'}`);
        }
        continue;
      }

      // One transaction per note: upsert, new chunks (vectors reused by embedded-text sha), drop old chunks.
      try {
        await db!.exec('BEGIN');
        // Vector reuse key (r1 MINOR-6): sha256 of the text U6 embeds (title > heading path + chunk),
        // computed with the OLD title before the upsert. A title or heading rename drops the vector.
        const reuse = new Map<string, number>();
        if (ex) {
          const old = await db!.query<{ id: number; title: string; heading_path: string | null; text: string }>(
            `SELECT c.id::int AS id, n.title, c.heading_path, c.text FROM zeusi.chunks c JOIN zeusi.notes n ON n.id = c.note_id
             WHERE c.note_id = $1 AND c.embedding IS NOT NULL ORDER BY c.embedded_at DESC NULLS LAST, c.id DESC`, [ex.id],
          );
          for (const o of old.rows) {
            const k = sha256Hex(embedText(o.title, o.heading_path, o.text));
            if (!reuse.has(k)) reuse.set(k, Number(o.id));
          }
        }
        const id = Number((await db!.query<{ id: number }>(
          `INSERT INTO zeusi.notes (vault_path, title, note_date, frontmatter, body, file_mtime, status, deleted_seen_at,
                                    scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
           VALUES ($1, $2, $3::date, $4::jsonb, $5, $6::timestamptz, 'active', NULL,
                   $7::zeusi.scope, $12::zeusi.source_kind, $8, $9::timestamptz, decode($10, 'hex'), $11)
           ON CONFLICT (vault_path) DO UPDATE SET
             title = EXCLUDED.title, note_date = EXCLUDED.note_date, frontmatter = EXCLUDED.frontmatter,
             body = EXCLUDED.body, file_mtime = EXCLUDED.file_mtime, status = 'active', deleted_seen_at = NULL,
             scope = EXCLUDED.scope, source_kind = EXCLUDED.source_kind, source_uri = EXCLUDED.source_uri,
             source_ts = EXCLUDED.source_ts, source_sha256 = EXCLUDED.source_sha256, ingest_run_id = EXCLUDED.ingest_run_id
           RETURNING id::int AS id`,
          [storedPath, title, date?.noteDate ?? null, JSON.stringify(frontmatter), body, new Date(mtimeMs).toISOString(),
            c.scope, uri, sourceTs.toISOString(), sha, runId, profile.sourceKind],
        )).rows[0]!.id);
        const oldIds = (await db!.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.chunks WHERE note_id = $1`, [id])).rows.map((x) => Number(x.id));
        let reused = 0;
        for (const k of chunks) {
          const r = await db!.query<{ reused: boolean }>(
            `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, scope, source_kind,
                                       source_uri, embed_model, embedding, embedded_at)
             SELECT $1, $2, $3, $4::text, sha256(convert_to($4::text, 'UTF8')), $5, $6::zeusi.scope, $10::zeusi.source_kind,
                    $7, o.embed_model, o.embedding, o.embedded_at
             FROM (SELECT 1) AS one
             LEFT JOIN LATERAL (
               SELECT embed_model, embedding, embedded_at FROM zeusi.chunks
               WHERE id = $8::bigint AND id = ANY($9::bigint[]) AND embedding IS NOT NULL) AS o ON true
             RETURNING embedding IS NOT NULL AS reused`,
            [id, k.index, k.headingPath, k.text, k.tokenCount, c.scope, kUri(k),
              reuse.get(sha256Hex(embedText(title, k.headingPath, k.text))) ?? null, oldIds, profile.sourceKind],
          );
          if (r.rows[0]?.reused) reused++;
        }
        if (oldIds.length) await db!.query(`DELETE FROM zeusi.chunks WHERE id = ANY($1::bigint[])`, [oldIds]);
        await db!.exec('COMMIT');
        if (ex) counts.updated++;
        else counts.inserted++;
        counts.chunks_written += chunks.length;
        counts.vectors_reused += reused;
        bump(counts.by_scope, c.scope);
        if (logPaths && opts.verbose) log(`${ex ? 'updated' : 'inserted'}: ${c.rel} (${chunks.length} chunks)`);
      } catch (e) {
        await db!.exec('ROLLBACK').catch(() => {});
        const wr = parseWallError(e);
        if (!wr) {
          fileErr(`database error ${asPgError(e).code ?? 'unknown'}`);
          continue;
        }
        // Backstop: the trigger refused a row the pre-check passed. uri + hashes only.
        const pe = asPgError(e);
        const table = /zeusi wall: (notes|chunks) row/.exec(pe.message)?.[1] ?? 'notes';
        // Only a uri the importer itself built is accepted from DETAIL (note uri or note uri #c<n>).
        const dUri = /source_uri=(.*?);content_sha256=/.exec(pe.detail ?? '')?.[1];
        const rUri = dUri !== undefined && (dUri === uri || (dUri.startsWith(`${uri}#c`) && /^\d+$/.test(dUri.slice(uri.length + 2)))) ? dUri : uri;
        counts.quarantined++;
        counts.backstop++;
        bump(counts.by_rule, String(wr.ruleId));
        await quarantine({ uri: rUri, sha, ruleId: wr.ruleId, table, contentSha: wr.contentSha256 });
        await retract();
      }
    }

    // ---- 4. Deletions: status only, chunks removed from search -----------------
    if (!dry) {
      for (const [, x] of gone) {
        if (sealed) {
          // C7 KTD8 (a C6 gap): on the sealed route a deletion also takes the index lock and tells the B1
          // index which chunks left, in one sealed transaction (the plain branch below is unchanged).
          try {
            await sealedTx(db!, sealed, async () => {
              await db!.query(`UPDATE zeusi.notes SET status = 'deleted', deleted_seen_at = now() WHERE id = $1`, [x.id]);
              const del = await db!.query<{ id: number | string }>(`DELETE FROM zeusi.chunks WHERE note_id = $1 RETURNING id`, [x.id]);
              await sealed.index.onNoteRemoved(db!, x.id, del.rows.map((r) => Number(r.id)));
            });
            counts.deleted++;
          } catch (e) {
            if (e instanceof SealRefused) throw e;
            counts.errors++;
            if (logPaths) log(`could not mark note ${x.id} deleted (${asPgError(e).code ?? 'error'})`);
          }
          continue;
        }
        try {
          await db!.exec('BEGIN');
          await db!.query(`UPDATE zeusi.notes SET status = 'deleted', deleted_seen_at = now() WHERE id = $1`, [x.id]);
          await db!.query(`DELETE FROM zeusi.chunks WHERE note_id = $1`, [x.id]);
          await db!.exec('COMMIT');
          counts.deleted++;
        } catch (e) {
          await db!.exec('ROLLBACK').catch(() => {});
          // The old row now fails the wall (rules changed): still pull its chunks; wall audit shows the row.
          await db!.query(`DELETE FROM zeusi.chunks WHERE note_id = $1`, [x.id]);
          counts.errors++;
          if (logPaths) log(`could not mark note ${x.id} deleted (${asPgError(e).code ?? 'error'}); its chunks were removed`);
        }
      }
    }

    if (reparse) return { runId: null, mode, status: 'ok', counts, reparse: { counts: rc, changes } };
    if (!dry) await closeRun(db!, runId!, 'ok', counts);
    return { runId, mode, status: 'ok', counts };
  } catch (e) {
    const msg = e instanceof VaultRunError ? e.message : `run failed (${asPgError(e).code ?? (e instanceof Error ? e.name : 'error')})`;
    if (reparse) return { runId: null, mode, status: 'failed', counts, error: msg, reparse: { counts: rc, changes } };
    if (!dry && runId !== null) {
      await db!.exec('ROLLBACK').catch(() => {});
      await closeRun(db!, runId, 'failed', { ...counts, failure: msg }).catch(() => {});
    }
    return { runId, mode, status: 'failed', counts, error: msg };
  } finally {
    if (locked) await unlockImporter(db!, IMPORTER).catch(() => {});
  }
}

interface SealedNoteInput {
  storedPath: string;
  uri: string;
  title: string;
  noteDate: string | null;
  /** The JSON.stringify text the plain path stores as jsonb (C6 KTD6 encoding). */
  frontmatter: string;
  body: string;
  mtimeIso: string;
  scope: string;
  sourceKind: string;
  sourceTsIso: string;
  /** Plain SHA-256 hex of the file bytes (stored keyed). */
  sha: string;
  runId: number;
  chunks: Array<{ index: number; headingPath: string | null; text: string; tokenCount: number; uri: string }>;
}

/**
 * C6 KTD7 + KTD8: one note in one sealed transaction (sealedTx: BEGIN, index lock, ..., enc_progress,
 * COMMIT). The id is looked up by vault_path_hmac FOR UPDATE, or pre-allocated; the note is sealed under
 * that id and written by one INSERT or UPDATE; new chunks get pre-allocated ids, their own
 * source_uri_ct / source_uri_hmac, text_ct / heading_path_ct / text_hmac and no embedding; old chunks
 * go; the title is read back and opened; the index hook runs. A concurrent insert of the same path
 * hits UNIQUE (vault_path_hmac): the transaction rolls back (an error, never a mis-bound row).
 */
async function writeSealedNote(
  db: Db, route: SealedRoute, n: SealedNoteInput, seam?: (db: Db, at: { vaultPathHmac: Buffer; found: boolean }) => Promise<void>,
): Promise<{ updated: boolean }> {
  const key = route.key;
  const vph = key.indexHmac('vault_path', n.storedPath);
  return sealedTx(db, route, async () => {
    const found = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.notes WHERE vault_path_hmac = $1::bytea FOR UPDATE`, [vph])).rows[0];
    if (seam) await seam(db, { vaultPathHmac: vph, found: found !== undefined });
    const id = found ? Number(found.id) : (await nextId(db, 'notes'))[0]!;
    const meta: SqlCol[] = [
      ['note_date', n.noteDate, 'date'], ['file_mtime', n.mtimeIso, 'timestamptz'], ['status', 'active'], ['deleted_seen_at', null, 'timestamptz'],
      ['scope', n.scope, 'zeusi.scope'], ['source_kind', n.sourceKind, 'zeusi.source_kind'], ['source_ts', n.sourceTsIso, 'timestamptz'],
      ['source_sha256', key.keyedSha('source_sha256', n.sha), 'bytea'], ['ingest_run_id', n.runId, 'bigint'],
    ];
    const cols = [
      ...sealRow(key, 'notes', id, { title: n.title, body: n.body, frontmatter: n.frontmatter, vault_path: n.storedPath, source_uri: n.uri }),
      key.sealDigest('notes', id, n.sha), // C8-0 KTD-A: the sealed copy of the plain digest
    ];
    const w = found ? sealedUpdateSql('notes', id, meta, cols) : sealedInsertSql('notes', [['id', id, 'bigint'], ...meta], cols);
    await db.query(w.sql, w.params);
    const oldIds = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.chunks WHERE note_id = $1`, [id])).rows.map((x) => Number(x.id));
    const ids = await nextId(db, 'chunks', n.chunks.length);
    const written: IndexedChunk[] = [];
    for (const [i, k] of n.chunks.entries()) {
      const cid = ids[i]!;
      // The chunk's own uri (<note uri>#c<n>) under the chunk's own AAD (§4.1a), never the note's.
      const cc = sealRow(key, 'chunks', cid, { heading_path: k.headingPath, text: k.text, source_uri: k.uri });
      const ci = sealedInsertSql('chunks', [
        ['id', cid, 'bigint'], ['note_id', id, 'bigint'], ['chunk_index', k.index, 'int'], ['token_count', k.tokenCount, 'int'],
        ['scope', n.scope, 'zeusi.scope'], ['source_kind', n.sourceKind, 'zeusi.source_kind'],
      ], cc);
      await db.query(ci.sql, ci.params);
      written.push({ id: cid, headingPath: k.headingPath, text: k.text });
    }
    if (oldIds.length) await db.query(`DELETE FROM zeusi.chunks WHERE id = ANY($1::bigint[])`, [oldIds]);
    // Read-back (KTD7): the stored title opens under this id and equals what was sealed.
    const rb = (await db.query<{ ct: Uint8Array | null }>(`SELECT title_ct AS ct FROM zeusi.notes WHERE id = $1`, [id])).rows[0];
    if (!rb?.ct || key.open('notes', 'title', id, rb.ct) !== n.title) throw new Error('sealed note read-back failed');
    await route.index.onNoteWritten(db, { noteId: id, title: n.title, chunks: written, removedChunkIds: oldIds });
    return { updated: found !== undefined };
  });
}

/** JSON with object keys sorted (jsonb does not keep key order): equality of stored vs parsed frontmatter. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`).join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

function projectFor(ms: Matcher[]): string | null {
  return ms.find((m) => m.spec.project !== undefined)?.spec.project ?? null;
}

/** Path-to-scope mapping: the ClientCo folder (or a clientco source) → clientco; Northbank folders (or a northbank source) → product; else team. */
export function scopeFor(rel: string, ms: Array<{ spec: Pick<SourceSpec, 'scope'> }>): VaultScope {
  const lower = rel.toLowerCase();
  if (ClientCo_PREFIXES.some((p) => lower.startsWith(p.toLowerCase())) || ms.some((m) => m.spec.scope === 'client')) return 'client';
  if (PRODUCT_PATH_PREFIXES.some((p) => lower.startsWith(p.toLowerCase())) || ms.some((m) => m.spec.scope === 'product')) return 'product';
  return 'work';
}

// ---------------------------------------------------------------------------
// Real-mode precondition (checked over the zeusi_ingest connection before a run).

export class IngestNotReady extends Error {
  override name = 'IngestNotReady';
}

/**
 * Refuse unless (a) the session is NOT owner-privileged (superuser, or can write
 * wall_allow), and (b) the wall is ready (wall.ts wallReadiness, shared with `embed`):
 * wall migrations 0006-0011 applied and every current seed rule present as seeded
 * (SEED_RULES: includes the 0010 and 0011 Plankiva regexes).
 */
export async function assertIngestReady(db: Db): Promise<void> {
  const r = await wallReadiness(db);
  const problems: string[] = [];
  if (r.ownerPrivileged) problems.push('the session is owner-privileged; ingest runs as zeusi_ingest (service zeusi_ingest), never as the owner');
  problems.push(...r.problems);
  if (problems.length) throw new IngestNotReady(`real ingest refused:\n  - ${problems.join('\n  - ')}`);
}

// ---------------------------------------------------------------------------
// Output: counts only. No paths, no titles, no text (rule ids/kinds/patterns are wall config).

export function formatVaultResult(r: VaultImportResult, rules: Wall['rules'], dryRun: boolean, profile: ImportProfile = VAULT_PROFILE): string {
  const label0 = profile.label;
  const c = r.counts;
  const scopes = Object.entries(c.by_scope).sort().map(([k, v]) => `${k} ${v}`).join(', ') || 'none';
  const head = dryRun
    ? `${label0} ingest (dry run, no database; seed wall rules only): mode ${r.mode}`
    : `${label0} ingest run ${r.runId ?? '?'}: mode ${r.mode}, status ${r.status}`;
  const lines = [head];
  if (r.status === 'locked') {
    lines.push(`  ${r.error ?? 'locked'}`);
    return lines.join('\n');
  }
  if (dryRun) lines.push(`  would insert: ${c.inserted} note(s), ${c.chunks_written} chunk(s)`);
  else {
    lines.push(`  inserted: ${c.inserted}, updated: ${c.updated}, skipped: ${c.skipped}, deleted: ${c.deleted}`);
    lines.push(`  chunks written: ${c.chunks_written} (vectors reused: ${c.vectors_reused}; embeddings are U6)`);
  }
  lines.push(`  admitted by scope: ${scopes}`);
  lines.push(`  quarantined: ${c.quarantined} (path-gated: ${c.path_gated}, content: ${c.quarantined - c.path_gated}${dryRun ? '' : `, trigger backstop: ${c.backstop}, quarantine rows: ${c.quarantine_rows}, retracted: ${c.retracted}`})`);
  const label = (k: string) => {
    const rule = rules.find((x) => String(x.id) === k);
    return rule ? `rule ${rule.id} ${rule.kind}${rule.hard ? ' (hard)' : ' (soft)'} ${JSON.stringify(rule.pattern)}` : k === 'none' ? 'no rule (symlink leaving the vault / dangling)' : `rule ${k}`;
  };
  for (const [k, v] of Object.entries(c.by_rule).sort((a, b) => Number(a[0]) - Number(b[0]))) lines.push(`    ${label(k)}: ${v}`);
  lines.push(`  errors: ${c.errors}${c.hardlinks ? ` (hard links refused: ${c.hardlinks})` : ''}${dryRun ? ' (non-UTF-8 / unreadable; paths not printed in a dry run)' : ''}`);
  lines.push(`  secrets redacted at ingest: ${c.secrets_redacted} in ${c.notes_redacted} note(s) (kept as [REDACTED:<kind>]; counts only)`);
  if (c.symlink_dirs_skipped) lines.push(`  symlinked directories not followed: ${c.symlink_dirs_skipped}`);
  if (r.error) lines.push(`  FAILED: ${r.error}`);
  return lines.join('\n');
}
