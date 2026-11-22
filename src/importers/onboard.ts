// First-run import adapters (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md U7, KTD10, KTD12,
// KTD13, KTD15; PR2 amendments P1, P5). Each input kind becomes staging notes in the Zeus HQ
// export layout, `<staging>/<project>/YYYY-MM-DD-<kind>-<hash8>.md`, with the HQ frontmatter
// (project, kind, date, title, source) and one H2 entry per message / commit / decision, so the
// UNCHANGED nightly filter (runExportFilter) and importer (importVault) take it from there.
//
//   claude-export   Claude conversations.json        -> kind chat, one note per conversation
//   chatgpt-export  ChatGPT conversations.json       -> kind chat, one note per conversation
//   markdown        markdown / Obsidian folder        -> kind memory, one note per file; the
//                                                       original `locks:` and `related:` frontmatter
//                                                       is carried through (Fix PR A rules read it);
//                                                       a strictly valid `standing_locks:` too, only for
//                                                       the personal-workspace import (carriedStandingLocks)
//   git             local git repository             -> kind decision, one note per day of
//                                                       decision-like / PR-merge commits (notes only)
//   decision-log    markdown or JSONL decision log   -> kind decision, one note per day; JSONL uses the
//                                                       zeusi_log_decision field names and is rendered
//                                                       with the structured header (src/importers/structured.ts)
//
// Safety (counts only leave this module; never a path below an input, a title or text):
//   * every input root: lstat (a symlink root is refused), the wall's path gate (sourcePathGate);
//   * markdown walk: dot entries, symlinks and hard links are skipped (counted), files are opened
//     O_RDONLY|O_NOFOLLOW and must still be the file that was listed (ino/dev), size caps;
//   * JSON exports: size cap before parsing, permissive zod (unknown fields allowed, missing
//     essentials refuse the WHOLE export with a safe message, never half-imported);
//   * git: execFile (no shell) with fixed arguments only (the repo is the cwd, never an argument),
//     hooks, fsmonitor, signatures, textconv and external diff off, no pager, a fixed format and
//     --max-count; no diff is read; author names and emails are never read;
//   * lines in imported text that look like an H2 are escaped, so text can never forge an entry;
//   * caps: notes staged, files walked, commits, JSONL lines.
//
// Content-addressed names: <hash8> = sha256 of (kind, date, body). The same content from two
// inputs stages once (counted deduped); the same input twice gives the same names and bytes.

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, join, resolve, sep } from 'node:path';
import { z } from 'zod';
import { DECISION_KINDS, WHO_HANDLE_RE } from '../decisions.ts';
import { requestsSignal } from '../hq-export.ts';
import { lockItemsOf, parseStandingMarker, STANDING_MARKER_KEY } from '../lock-lifecycle.ts';
import { serveSecretSignal } from '../mcp-wall.ts';
import { mentionsProtectedName, sourcePathGate } from '../sources.ts';
import { compileWall, seedWall, type Wall } from '../wall.ts';
import { HQ_FILE_RE, HQ_PROJECT_RE } from './profile.ts';
import { MAX_FILE_BYTES, parseNoteDate, splitNote, ClientCo_PREFIXES, type Frontmatter } from './vault.ts';

export const INPUT_KINDS = ['claude-export', 'chatgpt-export', 'markdown', 'git', 'decision-log'] as const;
export type InputKind = (typeof INPUT_KINDS)[number];

export interface ImportInput {
  kind: InputKind;
  path: string;
  /**
   * Markdown only: logical names of top-level files (physical name -> name). The hosted preview
   * (src/workspace-write.ts) writes its inbox under neutral names (`001.md`) and keeps the former
   * name here, in memory, so the title fallback, the path wall and the component checks see exactly
   * the name they saw before (docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD5).
   */
  names?: ReadonlyMap<string, string> | undefined;
}

/** Caps (P5). Beyond them an input is refused with a safe message, or the item is skipped and counted. */
export const IMPORT_CAPS = {
  /** One JSON export file. */
  jsonExportBytes: 64 * 1024 * 1024,
  /** One markdown note / decision log file (same as the importer). */
  fileBytes: MAX_FILE_BYTES,
  /** A staged note: split a long conversation below this. */
  stagedNoteBytes: 4 * 1024 * 1024,
  /** Notes staged per run (all inputs). */
  stagedNotes: 20_000,
  /** Files listed per markdown folder. */
  walkedFiles: 50_000,
  /** Commits read per repository. */
  commits: 20_000,
  /** JSONL lines per decision log. */
  jsonlLines: 50_000,
  /** Inputs per run. */
  inputs: 20,
} as const;

/** Input problem (exit 2). Safe text: never a path, a title or content. */
export class ImportInputError extends Error {
  override name = 'ImportInputError';
}

/** More notes staged than the run's note cap (IMPORT_CAPS.stagedNotes, or a smaller caller cap). */
export class ImportNotesCapError extends ImportInputError {
  override name = 'ImportNotesCapError';
  readonly cap: number;
  constructor(cap: number) {
    super(`import refused: more than ${cap} notes in one run; split the input`);
    this.cap = cap;
  }
}

export type SkipReason = 'unsupported' | 'too_large' | 'symlink' | 'hard_link' | 'dot' | 'unreadable' | 'malformed' | 'no_date' | 'empty' | 'path_gated' | 'scope_mismatch';

export interface InputCounts {
  kind: InputKind;
  /** Conversations, files, decision-like commits or decision-log entries seen. */
  items_seen: number;
  notes_staged: number;
  /** Notes whose content another input (or this one) already staged in this run. */
  deduped: number;
  skipped: Record<SkipReason, number>;
}

export function emptyInputCounts(kind: InputKind): InputCounts {
  return {
    kind, items_seen: 0, notes_staged: 0, deduped: 0,
    skipped: { unsupported: 0, too_large: 0, symlink: 0, hard_link: 0, dot: 0, unreadable: 0, malformed: 0, no_date: 0, empty: 0, path_gated: 0, scope_mismatch: 0 },
  };
}

/** Where a staged note came from (the pipeline extracts structured records only from markdown / decision-log notes). */
export type StagedOrigin = InputKind;

export interface StagedNote {
  /** `<project>/<file>` relative to the staging dir. */
  rel: string;
  origin: StagedOrigin;
}

/** HQ kinds a staged note uses. */
type StageKind = 'chat' | 'memory' | 'decision';

export interface Stager {
  readonly dir: string;
  readonly project: string;
  readonly notes: StagedNote[];
  stage(c: InputCounts, n: { kind: StageKind; date: string; title: string; source: string; body: string; extra?: Frontmatter }): void;
}

// ---------------------------------------------------------------------------
// Text helpers

/**
 * Escape lines that would start a markdown heading of level 1-2 or a code fence, so imported text
 * can never forge an entry, a note title, or swallow the next entries into an unclosed fence.
 */
export function escapeHeadings(text: string): string {
  return text.replace(/\r\n?/g, '\n').split('\n').map((l) => (/^ {0,3}(?:#{1,2}(?:[ \t]|$)|`{3,}|~{3,})/.test(l) ? `\\${l.trimStart()}` : l)).join('\n');
}

/** One-line, length-capped scalar (titles, labels). */
function oneLine(s: string, max = 200): string {
  const t = s.replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max).trim() : t;
}

/** A double-quoted YAML scalar that parseFrontmatter (src/importers/vault.ts unquote) reads back exactly. */
export function yamlQuote(s: string): string {
  return `"${oneLine(s, 2000).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

const realDay = (s: string): boolean => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
};

/** YYYY-MM-DD (UTC) of a date, or null. */
export function dayOf(d: Date | null | undefined): string | null {
  if (!d || Number.isNaN(d.getTime())) return null;
  const s = d.toISOString().slice(0, 10);
  return realDay(s) && s >= '1990-01-01' ? s : null;
}

const within = (a: string, b: string) => a === b || a.startsWith(b.endsWith(sep) ? b : b + sep);

// ---------------------------------------------------------------------------
// Staging

/**
 * The HQ-layout writer for one run: `<dir>/<project>/YYYY-MM-DD-<kind>-<hash8>.md`, mode 0600,
 * never through an existing entry (`wx`). Frontmatter keys: project, kind, date, title, source,
 * plus `locks` / `related` lists when carried through.
 */
export function createStager(dir: string, project: string, maxNotes: number = IMPORT_CAPS.stagedNotes): Stager {
  if (!Number.isInteger(maxNotes) || maxNotes < 1 || maxNotes > IMPORT_CAPS.stagedNotes) throw new ImportInputError('import: internal note cap error');
  if (!HQ_PROJECT_RE.test(project)) throw new ImportInputError('import: the project folder is not a slug');
  const pdir = join(dir, project);
  mkdirSync(pdir, { recursive: true, mode: 0o700 });
  const notes: StagedNote[] = [];
  const names = new Set<string>();
  let total = 0;
  return {
    dir, project, notes,
    stage(c, n) {
      if (!realDay(n.date)) {
        c.skipped.no_date++;
        return;
      }
      const body = n.body.replace(/\r\n?/g, '\n').replace(/\s+$/, '') + '\n';
      if (body.trim() === '') {
        c.skipped.empty++;
        return;
      }
      // Carried frontmatter (locks, related) is part of the identity: two notes with the same body but
      // different locks never dedupe into one (the second note's locks would be lost).
      const hash = createHash('sha256').update(JSON.stringify([n.kind, n.date, body, n.extra ?? {}]), 'utf8').digest('hex').slice(0, 8);
      const file = `${n.date}-${n.kind}-${hash}.md`;
      if (!HQ_FILE_RE.test(file)) throw new ImportInputError('import: internal staging name error');
      if (names.has(file)) {
        c.deduped++;
        return;
      }
      // Checked before the file is written: staging stops at the cap (a capped run never holds more files).
      if (++total > maxNotes) throw new ImportNotesCapError(maxNotes);
      const fm = [
        '---', `project: ${project}`, `kind: ${n.kind}`, `date: ${n.date}`, `title: ${yamlQuote(n.title || 'Imported note')}`, `source: ${yamlQuote(n.source)}`,
      ];
      for (const [k, v] of Object.entries(n.extra ?? {})) {
        const items = (Array.isArray(v) ? v : [v]).map((x) => oneLine(String(x), 2000)).filter((x) => x !== '');
        if (items.length === 0) continue;
        fm.push(`${k}:`, ...items.map((x) => `  - ${yamlQuote(x)}`));
      }
      fm.push('---', '');
      const text = fm.join('\n') + body;
      if (Buffer.byteLength(text, 'utf8') > MAX_FILE_BYTES) {
        c.skipped.too_large++;
        return;
      }
      writeFileSync(join(pdir, file), text, { mode: 0o600, flag: 'wx' });
      names.add(file);
      notes.push({ rel: `${project}/${file}`, origin: c.kind });
      c.notes_staged++;
    },
  };
}

// ---------------------------------------------------------------------------
// Input roots and safe reads

/**
 * Resolve and check an input root. Refused (safe message, no path): missing, wrong type, a
 * symlink, refused by the wall's path gate, or overlapping the private work dir.
 */
export function checkInputRoot(path: string, want: 'file' | 'dir', workDir: string, scope = 'work'): string {
  if (typeof path !== 'string' || path.trim() === '' || path.includes('\0')) throw new ImportInputError('import: an input path is empty or invalid');
  const abs = resolve(path);
  let st;
  try {
    st = lstatSync(abs);
  } catch {
    throw new ImportInputError(`import: an input (${want}) is missing or not readable`);
  }
  if (st.isSymbolicLink()) throw new ImportInputError('import: an input is a symlink; pass the real path');
  if (want === 'dir' ? !st.isDirectory() : !st.isFile()) throw new ImportInputError(`import: an input is not a ${want === 'dir' ? 'folder' : 'regular file'}`);
  if (want === 'file' && st.nlink > 1) throw new ImportInputError('import: an input file is a hard link; pass a plain copy');
  const real = realpathSync(abs);
  if (!sourcePathGate(real).ok || !sourcePathGate(abs).ok) throw new ImportInputError('import: an input is refused by the wall path gate');
  for (const p of [abs, real]) {
    const why = componentRefused(p, scope);
    if (why === 'path_gated') throw new ImportInputError('import: an input lies in a walled folder (a hard wall folder name is part of its path)');
    if (why === 'scope_mismatch') throw new ImportInputError('import: an input lies in a ClientCo folder; import it with --scope clientco');
  }
  const work = resolve(workDir);
  let workReal = work;
  try {
    workReal = realpathSync(work);
  } catch { /* not created yet */ }
  if (within(real, workReal) || within(workReal, real)) throw new ImportInputError('import: an input overlaps the private work dir');
  return real;
}

/** Read one regular single-link file (O_NOFOLLOW), the same file that was listed. null = refused (reason set). */
function readListed(abs: string, max: number, listed?: { ino: number; dev: number }): { bytes: Buffer } | { skip: SkipReason } {
  let fd: number;
  try {
    const st = lstatSync(abs);
    if (st.isSymbolicLink()) return { skip: 'symlink' };
    if (!st.isFile()) return { skip: 'unsupported' };
    if (st.nlink > 1) return { skip: 'hard_link' };
    if (st.size > max) return { skip: 'too_large' };
    fd = openSync(abs, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    return { skip: 'unreadable' };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { skip: 'unsupported' };
    if (st.nlink > 1) return { skip: 'hard_link' };
    if (listed && (st.ino !== listed.ino || st.dev !== listed.dev)) return { skip: 'unreadable' };
    if (st.size > max) return { skip: 'too_large' };
    return { bytes: readFileSync(fd) };
  } catch {
    return { skip: 'unreadable' };
  } finally {
    closeSync(fd);
  }
}

function utf8(b: Buffer): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(b);
  } catch {
    return null;
  }
}

/** Read a whole input file (root already checked). Refuses (safe message) instead of skipping. */
function readInputFile(real: string, max: number, what: string): string {
  const r = readListed(real, max);
  if ('skip' in r) throw new ImportInputError(r.skip === 'too_large' ? `import: the ${what} is larger than the cap (${Math.round(max / 1024 / 1024)} MiB)` : `import: the ${what} could not be read safely (${r.skip})`);
  const t = utf8(r.bytes);
  if (t === null) throw new ImportInputError(`import: the ${what} is not UTF-8`);
  return t;
}

// ---------------------------------------------------------------------------
// Chat exports

const tsOf = (v: unknown): Date | null => {
  if (typeof v === 'number' && Number.isFinite(v)) return new Date(v < 1e12 ? v * 1000 : v);
  if (typeof v === 'string' && v.trim() !== '') {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
};

const ClaudeMessage = z.looseObject({
  sender: z.string().max(64),
  text: z.string().max(IMPORT_CAPS.jsonExportBytes).optional(),
  created_at: z.string().max(64).optional(),
  content: z.array(z.looseObject({ type: z.string().max(64).optional(), text: z.string().max(IMPORT_CAPS.jsonExportBytes).optional() })).max(100_000).optional(),
});
const ClaudeConversation = z.looseObject({
  name: z.string().max(10_000).nullish(),
  created_at: z.string().min(1).max(64),
  chat_messages: z.array(ClaudeMessage).max(100_000),
});
const ClaudeExport = z.array(ClaudeConversation).max(100_000);

const GptNode = z.looseObject({
  message: z.looseObject({
    author: z.looseObject({ role: z.string().max(64) }),
    create_time: z.number().nullish(),
    content: z.looseObject({ content_type: z.string().max(64).optional(), parts: z.array(z.unknown()).max(10_000).optional() }).optional(),
  }).nullish(),
});
const GptConversation = z.looseObject({
  title: z.string().max(10_000).nullish(),
  create_time: z.number(),
  mapping: z.record(z.string().max(200), GptNode),
});
const GptExport = z.array(GptConversation).max(100_000);

interface ChatMsg { role: string; at: Date | null; text: string }

/** Stage one conversation: H2 per message `## <ts> (<role>)` (never a handle shape), parts below the size cap. */
function stageConversation(st: Stager, c: InputCounts, source: string, title: string, date: string, msgs: ChatMsg[]): void {
  const parts: string[][] = [[]];
  let bytes = 0;
  for (const m of msgs) {
    const text = escapeHeadings(m.text.trim());
    if (text === '') continue;
    const role = /^[a-z_]{1,32}$/.test(m.role) ? m.role : 'other';
    const entry = `## ${m.at ? m.at.toISOString() : 'undated'} (${role})\n\n${text}\n`;
    const b = Buffer.byteLength(entry, 'utf8');
    if (b > IMPORT_CAPS.stagedNoteBytes) {
      c.skipped.too_large++;
      continue;
    }
    if (bytes + b > IMPORT_CAPS.stagedNoteBytes && parts[parts.length - 1]!.length > 0) {
      parts.push([]);
      bytes = 0;
    }
    parts[parts.length - 1]!.push(entry);
    bytes += b;
  }
  const real = parts.filter((p) => p.length > 0);
  if (real.length === 0) {
    c.skipped.empty++;
    return;
  }
  real.forEach((p, i) => st.stage(c, {
    kind: 'chat', date, source, title: real.length > 1 ? `${title} (part ${i + 1} of ${real.length})` : title, body: p.join('\n'),
  }));
}

function parseJsonExport(text: string, what: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ImportInputError(`import: the ${what} is not valid JSON`);
  }
}

export function importClaudeExport(real: string, st: Stager, c: InputCounts): void {
  const parsed = ClaudeExport.safeParse(parseJsonExport(readInputFile(real, IMPORT_CAPS.jsonExportBytes, 'Claude export'), 'Claude export'));
  if (!parsed.success) throw new ImportInputError('import: the Claude export does not have the expected shape (conversations with created_at and chat_messages); nothing imported from it');
  for (const conv of parsed.data) {
    c.items_seen++;
    const date = dayOf(tsOf(conv.created_at));
    if (!date) {
      c.skipped.no_date++;
      continue;
    }
    const msgs: ChatMsg[] = conv.chat_messages.map((m) => ({
      role: m.sender === 'human' ? 'user' : m.sender,
      at: tsOf(m.created_at),
      text: m.text && m.text.trim() !== '' ? m.text : (m.content ?? []).map((x) => (x.type === undefined || x.type === 'text' ? x.text ?? '' : '')).join('\n'),
    }));
    stageConversation(st, c, 'claude-export', oneLine(conv.name ?? '') || 'Claude conversation', date, msgs);
  }
}

export function importChatgptExport(real: string, st: Stager, c: InputCounts): void {
  const parsed = GptExport.safeParse(parseJsonExport(readInputFile(real, IMPORT_CAPS.jsonExportBytes, 'ChatGPT export'), 'ChatGPT export'));
  if (!parsed.success) throw new ImportInputError('import: the ChatGPT export does not have the expected shape (conversations with create_time and mapping); nothing imported from it');
  for (const conv of parsed.data) {
    c.items_seen++;
    const date = dayOf(tsOf(conv.create_time));
    if (!date) {
      c.skipped.no_date++;
      continue;
    }
    const msgs: ChatMsg[] = [];
    for (const node of Object.values(conv.mapping)) {
      const m = node.message;
      if (!m) continue;
      const role = m.author.role;
      if (role !== 'user' && role !== 'assistant') continue; // system / tool messages are not imported
      const text = (m.content?.parts ?? []).filter((p): p is string => typeof p === 'string').join('\n');
      msgs.push({ role, at: tsOf(m.create_time ?? null), text });
    }
    msgs.sort((a, b) => (a.at?.getTime() ?? 0) - (b.at?.getTime() ?? 0));
    stageConversation(st, c, 'chatgpt-export', oneLine(conv.title ?? '') || 'ChatGPT conversation', date, msgs);
  }
}

// ---------------------------------------------------------------------------
// Path gate below an input root (security review r1, finding 2)

/**
 * The wall's path rules for an entry BELOW an input root, applied before it is listed or opened.
 * Staged names are content hashes, so the export filter and the importer never see the original
 * folder names: every rule that keys on them must fire here. Same checks the vault importer's
 * gate 1 applies: the path gate on the absolute path, every hard uri rule on the relative path
 * (file and directory forms, e.g. plankiva/**, personal/**, raw/**), the Plankiva check, the
 * requests/ family, and the soft rules on the path text (no allows).
 */
export function belowRootRefused(rel: string, abs: string, wall: Wall = seedWall()): boolean {
  if (!sourcePathGate(abs).ok) return true;
  const forms = [`vault:${rel}`, `vault:${rel}/`, `hq:${rel}`, `file:${abs}`, `file:${abs}/`];
  if (forms.some((f) => wall.checkUri(f).blocked)) return true;
  if (mentionsProtectedName(rel) || requestsSignal(`${rel}/`) || /(^|\/)requests(\/|$)/i.test(rel)) return true;
  const soft = compileWall(wall.rules, []).check('facts', { source_uri: `vault:${rel}`, kind: 'other', subject: null, text: rel });
  return soft.blocked;
}

/** Folder names of the wall's root-anchored hard rules (`<name>/**`: plankiva, personal, raw, ...), lower-case. */
export function hardFolderNames(wall: Wall = seedWall()): Set<string> {
  const out = new Set<string>();
  for (const r of wall.rules) {
    const m = r.hard && r.kind === 'path_glob' ? /^([^/*?[\]{}]+)\/\*\*$/.exec(r.pattern) : null;
    if (m) out.add(m[1]!.toLowerCase());
  }
  return out;
}

const ClientCo_FOLDERS = new Set(ClientCo_PREFIXES.map((p) => p.replace(/\/+$/, '').toLowerCase()));

/**
 * Security review r1 (re-check): the vault's root-anchored folder rules must hold whatever root the
 * user passes (the folder itself, a parent of the vault, or a nested copy). Every component of the
 * ABSOLUTE path is checked: a hard folder name refuses (path_gated); a ClientCo folder under a non-clientco
 * scope refuses (scope_mismatch). Fail closed: an unrelated folder of the same name refuses too.
 */
export function componentRefused(absPath: string, scope: string, names: ReadonlySet<string> = hardFolderNames()): 'path_gated' | 'scope_mismatch' | null {
  const parts = absPath.split(/[\\/]+/).filter(Boolean).map((x) => x.toLowerCase());
  if (parts.some((x) => names.has(x))) return 'path_gated';
  if (scope !== 'client' && parts.some((x) => ClientCo_FOLDERS.has(x))) return 'scope_mismatch';
  return null;
}

// ---------------------------------------------------------------------------
// Markdown / Obsidian folder

/** Frontmatter keys carried through from an original note (Fix PR A reads `locks`). */
export const CARRIED_KEYS = ['locks', 'related'] as const;

/** Adapter options. */
export interface AdapterOptions {
  /**
   * Carry a strictly valid `standing_locks:` (carriedStandingLocks). Set only by the hosted
   * personal-workspace import (src/workspace-write.ts); the CLI import into the work tenant leaves it off, so an
   * import can never make a team standing rule.
   */
  standingLocks?: boolean;
  /** Logical names of top-level files (ImportInput.names). */
  names?: ReadonlyMap<string, string> | undefined;
}

/**
 * `standing_locks` of an imported markdown note, carried STRICTLY (the H1 rule stands: nothing of the
 * original frontmatter is carried unless it is listed here, and frontmatterRefused has already checked
 * the WHOLE frontmatter, the marker included). Carried only when:
 *   * the note carries `locks:` too, and the marker parses with the readers' own parser
 *     (src/lock-lifecycle.ts parseStandingMarker) into at least one entry, EVERY entry an ordinal of a
 *     non-blank lock item of THIS note (lockItemsOf). One bad entry drops the whole marker: the locks
 *     stay ordinary locks, never a guess.
 * The ordinals are renumbered to the staged `locks:` list (the stager drops blank items), so the marker
 * names exactly the lock it named in the original and never another one (and never another note's:
 * a marker only ever applies to its own note's locks, src/lock-lifecycle.ts resolveLockLifecycle).
 * Returns the staged ordinals (sorted, unique, as strings), or null (not carried).
 */
export function carriedStandingLocks(fm: Frontmatter): string[] | null {
  const raw = fm[STANDING_MARKER_KEY];
  const locks = fm['locks'];
  if (raw === undefined || raw === null || raw === '' || locks === undefined || locks === '') return null;
  const items = Array.isArray(locks) ? locks : [locks];
  // The stager's rule for list items (stage(): oneLine, blank dropped): the staged ordinal of each original item.
  let n = 0;
  const staged = items.map((x) => (oneLine(String(x), 2000) !== '' ? ++n : null));
  const live = new Set(lockItemsOf(locks).map((l) => l.ord));
  const ords = parseStandingMarker(raw);
  if (ords.length === 0) return null;
  const out = new Set<number>();
  for (const o of ords) {
    const m = o === null || !live.has(o) ? null : staged[o - 1] ?? null;
    if (m === null) return null;
    out.add(m);
  }
  return [...out].sort((a, b) => a - b).map(String);
}

export function importMarkdownFolder(real: string, st: Stager, c: InputCounts, scope: string, o: AdapterOptions = {}): void {
  const wall = seedWall();
  const names = hardFolderNames(wall);
  let walked = 0;
  const walk = (dir: string, depth: number, dirRel: string): void => {
    if (depth > 64) {
      c.skipped.unsupported++;
      return;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    } catch {
      c.skipped.unreadable++;
      return;
    }
    for (const e of entries) {
      if (++walked > IMPORT_CAPS.walkedFiles) throw new ImportInputError(`import refused: a markdown folder has more than ${IMPORT_CAPS.walkedFiles} entries`);
      // The name every check and the title fallback see (a logical name only for top-level files).
      const name = (depth === 0 ? o.names?.get(e.name) : undefined) ?? e.name;
      if (name.startsWith('.')) {
        c.skipped.dot++; // .obsidian, .trash, .git: never read
        continue;
      }
      const abs = join(dir, e.name);
      const named = join(dir, name);
      const rel = dirRel ? `${dirRel}/${name}` : name;
      if (e.isSymbolicLink()) {
        c.skipped.symlink++;
        continue;
      }
      // Wall path rules on the relative path, before a folder is listed or a file opened.
      if (belowRootRefused(rel, named, wall)) {
        c.skipped.path_gated++;
        continue;
      }
      const comp = componentRefused(named, scope, names);
      if (comp) {
        c.skipped[comp]++;
        continue;
      }
      if (e.isDirectory()) {
        walk(abs, depth + 1, rel);
        continue;
      }
      if (!e.isFile() || !/\.md$/i.test(name)) {
        if (e.isFile()) c.skipped.unsupported++;
        continue;
      }
      c.items_seen++;
      let listed;
      try {
        listed = lstatSync(abs);
      } catch {
        c.skipped.unreadable++;
        continue;
      }
      const r = readListed(abs, IMPORT_CAPS.fileBytes, { ino: listed.ino, dev: listed.dev });
      if ('skip' in r) {
        c.skipped[r.skip]++;
        continue;
      }
      const text = utf8(r.bytes);
      if (text === null) {
        c.skipped.unreadable++;
        continue;
      }
      const { fm, body } = splitNote(text);
      // Security review (PR2 update 3, H1): only title / date / locks / related are carried, so the
      // export filter and the importer never see the rest of the original frontmatter (tags,
      // aliases, ...). Check the WHOLE original frontmatter here with the same signals (walled
      // person, requests family, the shared secret detector, the seed wall incl. tag rules);
      // a hit skips the note (counted path_gated), never stages it.
      if (fm && frontmatterRefused(fm)) {
        c.skipped.path_gated++;
        continue;
      }
      const fmTitle = typeof fm?.['title'] === 'string' ? fm['title'] : '';
      const title = oneLine(fmTitle) || oneLine(basename(name, '.md')) || 'Imported note';
      const date = parseNoteDate(fm?.['date'])?.noteDate ?? dayOf(listed.mtime);
      if (!date) {
        c.skipped.no_date++;
        continue;
      }
      const extra: Frontmatter = {};
      for (const k of CARRIED_KEYS) {
        const v = fm?.[k];
        if (v !== undefined && v !== '') extra[k] = v;
      }
      const standing = o.standingLocks === true && fm ? carriedStandingLocks(fm) : null;
      if (standing) extra[STANDING_MARKER_KEY] = standing;
      // Body kept as written: its own H2 entries stay entries (a timestamped, headed one can become a structured record).
      st.stage(c, { kind: 'memory', date, title, source: 'markdown', body, extra });
    }
  };
  walk(real, 0, '');
}

/** True when the original frontmatter of a markdown note must not be imported (any key, any value). */
export function frontmatterRefused(fm: Frontmatter, wall: Wall = seedWall()): boolean {
  try {
    const raw = JSON.stringify(fm);
    if (mentionsProtectedName(raw) || requestsSignal(raw) || serveSecretSignal(raw)) return true;
    const title = typeof fm['title'] === 'string' ? fm['title'] : '';
    return wall.check('notes', { title, body: '', frontmatter: fm, source_uri: 'import:frontmatter-check' }).blocked;
  } catch {
    return true; // fail closed
  }
}

// ---------------------------------------------------------------------------
// Git repository (local history only; notes only, never structured)

/** Fixed git arguments (P5): nothing user-controlled is ever an argument; the repo is the cwd. */
export const GIT_LOG_ARGS: readonly string[] = [
  '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'log.showSignature=false', '-c', 'core.pager=cat',
  '-c', 'diff.external=', '-c', 'protocol.allow=never', '-c', 'protocol.ext.allow=never', '-c', 'protocol.file.allow=never',
  // Security review r1, finding 1: a mailmap blob missing from a partial clone triggers a lazy fetch
  // from the promisor remote (e.g. an ext:: command). Mailmap off; lazy fetch off (env below).
  '-c', 'log.mailmap=false', '-c', 'mailmap.file=', '-c', 'mailmap.blob=',
  '--no-pager', 'log', '--no-textconv', '--no-ext-diff', '--no-color', '--no-show-signature', '--no-notes', '--no-mailmap', `--max-count=${IMPORT_CAPS.commits}`,
  // %H sha, %cI committer date ISO, %P parents, %s subject, %b body. Never author name / email.
  '--format=%x1e%H%x1f%cI%x1f%P%x1f%s%x1f%b', 'HEAD', '--',
];

/** Subject or body words that make a commit "decision-like" (fixed list). */
export const DECISION_LIKE_RE = /\b(decide[ds]?|decision|lock(?:ed|s)?|park(?:ed)?|revert(?:s|ed)?|polic(?:y|ies)|rules?|adr|breaking(?:[ -]change)?)\b/i;
const PR_MERGE_RE = /^Merge pull request #\d+\b|\(#\d+\)\s*$/;

/** Environment for git: no inherited GIT_* overrides, no prompts, no system config, no optional locks. */
function gitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const k of ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR']) if (process.env[k] !== undefined) env[k] = process.env[k];
  return {
    ...env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_OPTIONAL_LOCKS: '0', GIT_PAGER: 'cat', PAGER: 'cat',
    GIT_NO_LAZY_FETCH: '1', GIT_PROTOCOL_FROM_USER: '0', GIT_ALLOW_PROTOCOL: '',
  };
}

export function runGitLog(repoReal: string): Promise<string> {
  return new Promise((res, rej) => {
    execFile('git', [...GIT_LOG_ARGS], { cwd: repoReal, env: gitEnv(), maxBuffer: 256 * 1024 * 1024, timeout: 120_000, windowsHide: true, shell: false }, (err, stdout) => {
      if (err) rej(new ImportInputError('import: the git input is not a readable git repository with commits (git log failed; nothing imported from it)'));
      else res(stdout);
    });
  });
}

/** Fixed arguments for reading the repo's remote urls (same hardening as GIT_LOG_ARGS). */
export const GIT_REMOTES_ARGS: readonly string[] = [
  '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.pager=cat', '--no-pager',
  'config', '--local', '--get-regexp', '^remote\\..*\\.url$',
];

/** The repo's remote urls (git config exit 1 = none). Any other failure refuses the input. */
export function runGitRemotes(repoReal: string): Promise<string[]> {
  return new Promise((res, rej) => {
    execFile('git', [...GIT_REMOTES_ARGS], { cwd: repoReal, env: gitEnv(), maxBuffer: 1024 * 1024, timeout: 30_000, windowsHide: true, shell: false }, (err, stdout) => {
      if (err && (err as { code?: unknown }).code === 1) res([]);
      else if (err) rej(new ImportInputError('import: the git input is not a readable git repository (git config failed; nothing imported from it)'));
      else res(stdout.split('\n').map((l) => l.trim().split(/\s+/)[1] ?? '').filter((u) => u !== ''));
    });
  });
}

/** owner/repo of a remote url (https, ssh, scp-like); null when it has no two path parts. */
export function remoteRepo(url: string): string | null {
  const m = /[:/]([^/:\s]+)\/([^/\s]+?)(?:\.git)?\/?$/.exec(url.trim());
  return m ? `${m[1]}/${m[2]}` : null;
}

/**
 * Security review (PR2 update 3, M1): the wall's hard `repo` rules (ClientCo repos, agent config
 * backups, ...) apply to a local clone too: its folder name and every remote's owner/repo.
 */
export function gitRepoRefused(folderName: string, remotes: readonly string[], wall: Wall = seedWall()): boolean {
  const names = [folderName, ...remotes.map((u) => remoteRepo(u) ?? u)];
  return names.some((n) => n === '' || wall.checkUri(`gh:${n.includes('/') ? n : `example-org/${n}`}`).blocked || wall.checkUri(`gh:${n}`).blocked);
}

export async function importGitRepo(real: string, st: Stager, c: InputCounts, git: (repo: string) => Promise<string> = runGitLog,
  remotes: (repo: string) => Promise<string[]> = runGitRemotes): Promise<void> {
  // L1: the root itself must be a repository (.git dir or worktree file), never a subfolder of a parent repo.
  try {
    lstatSync(join(real, '.git'));
  } catch {
    throw new ImportInputError('import: the git input must be the top folder of a repository (it has no .git); nothing imported from it');
  }
  if (gitRepoRefused(basename(real), await remotes(real))) {
    throw new ImportInputError('import: the git input is refused by the wall (a walled repository name or remote)');
  }
  const out = await git(real);
  const label = oneLine(basename(real), 80).replace(/[^A-Za-z0-9._-]/g, '-') || 'repo';
  const byDay = new Map<string, string[]>();
  for (const rec of out.split('\x1e')) {
    if (rec.trim() === '') continue;
    const [sha, at, , subject, body] = rec.replace(/^\n/, '').split('\x1f') as [string, string?, string?, string?, string?];
    if (!/^[0-9a-f]{40,64}$/.test(sha ?? '')) {
      c.skipped.malformed++;
      continue;
    }
    const subj = oneLine(subject ?? '', 300);
    const msg = (body ?? '').trim();
    // Decision-like words, or a PR merge / squash-merge subject ("Merge pull request #n", "... (#n)").
    if (!(DECISION_LIKE_RE.test(subj) || DECISION_LIKE_RE.test(msg) || PR_MERGE_RE.test(subj))) continue;
    c.items_seen++;
    const when = tsOf(at);
    const day = dayOf(when);
    if (!day || !when) {
      c.skipped.no_date++;
      continue;
    }
    const entry = `## ${when.toISOString()} commit ${sha.slice(0, 12)}: ${subj || '(no subject)'}\n${msg ? `\n${escapeHeadings(msg)}\n` : ''}`;
    (byDay.get(day) ?? byDay.set(day, []).get(day)!).push(entry);
  }
  for (const [day, entries] of [...byDay.entries()].sort()) {
    st.stage(c, { kind: 'decision', date: day, title: `${label} decision-like commits ${day}`, source: `git:${label}`, body: entries.join('\n') });
  }
}

// ---------------------------------------------------------------------------
// Decision log (markdown or JSONL)

/** One JSONL line: the zeusi_log_decision field names (scope / source_* come from the import itself). */
export const DecisionLine = z.object({
  kind: z.enum(DECISION_KINDS),
  who: z.string().regex(WHO_HANDLE_RE),
  said_at: z.iso.datetime({ offset: true }),
  said_at_precision: z.enum(['minute', 'day']).optional(),
  exact_words: z.string().trim().min(1).max(4000),
  exact_words_verbatim: z.boolean().optional(),
  applies_to: z.array(z.string().trim().min(1).max(200).regex(/^[^,\n\r]+$/)).max(20).optional(),
  expires_at: z.iso.datetime({ offset: true }).optional(),
  linked_repo: z.string().regex(/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/).optional(),
  linked_pr: z.number().int().positive().max(999_999_999).optional(),
}).loose();

/** Render one JSONL decision as a structured entry. A missing said_at_precision is left out (the entry then stays a note: invent=NO). */
export function renderDecisionLine(d: z.infer<typeof DecisionLine>): string {
  const h = [`## ${d.said_at} ${d.who}`, `Decision: ${d.kind}`];
  if (d.said_at_precision) h.push(`Said-at-precision: ${d.said_at_precision}`);
  if (d.exact_words_verbatim !== undefined) h.push(`Verbatim: ${d.exact_words_verbatim ? 'yes' : 'no'}`);
  if (d.applies_to?.length) h.push(`Applies-to: ${d.applies_to.map((x) => oneLine(x)).join(', ')}`);
  if (d.linked_repo && d.linked_pr) h.push(`Links: gh:${d.linked_repo}#${d.linked_pr}`);
  if (d.expires_at) h.push(`Expires: ${d.expires_at}`);
  return `${h.join('\n')}\n\n${escapeHeadings(d.exact_words.trim())}\n`;
}

const H2_TS_RE = /^ {0,3}##[ \t]+(\d{4}-\d{2}-\d{2})T/;

export function importDecisionLog(real: string, st: Stager, c: InputCounts, mtime: Date): void {
  const text = readInputFile(real, IMPORT_CAPS.fileBytes, 'decision log');
  const byDay = new Map<string, string[]>();
  const add = (day: string, entry: string) => (byDay.get(day) ?? byDay.set(day, []).get(day)!).push(entry);
  if (/\.jsonl$/i.test(real)) {
    const lines = text.split(/\r?\n/);
    if (lines.length > IMPORT_CAPS.jsonlLines) throw new ImportInputError(`import refused: the decision log has more than ${IMPORT_CAPS.jsonlLines} lines`);
    for (const line of lines) {
      if (line.trim() === '') continue;
      c.items_seen++;
      let obj: unknown;
      try {
        obj = JSON.parse(line) as unknown;
      } catch {
        c.skipped.malformed++;
        continue;
      }
      const p = DecisionLine.safeParse(obj);
      if (!p.success) {
        c.skipped.malformed++;
        continue;
      }
      const day = dayOf(new Date(p.data.said_at));
      if (!day) {
        c.skipped.no_date++;
        continue;
      }
      add(day, renderDecisionLine(p.data));
    }
  } else {
    // Markdown: entries with a timestamped H2 go to that day (kept as written, header included);
    // everything else (list items, plain H2 sections) stays one note dated by its frontmatter or mtime.
    const { fm, body } = splitNote(text);
    const fallback = parseNoteDate(fm?.['date'])?.noteDate ?? dayOf(mtime);
    const rest: string[] = [];
    let cur: string[] | null = null;
    let curDay: string | null = null;
    const flush = () => {
      if (cur && curDay) add(curDay, cur.join('\n'));
      else if (cur) rest.push(cur.join('\n'));
      cur = null;
      curDay = null;
    };
    let fence: string | null = null;
    for (const line of body.replace(/\r\n?/g, '\n').split('\n')) {
      const f = /^ {0,3}(`{3,}|~{3,})/.exec(line);
      if (f) fence = fence === null ? f[1]! : (f[1]![0] === fence[0] && f[1]!.length >= fence.length ? null : fence);
      if (fence === null && /^ {0,3}##[ \t]/.test(line)) {
        flush();
        c.items_seen++;
        cur = [line];
        curDay = H2_TS_RE.exec(line)?.[1] ?? null;
        if (curDay && !realDay(curDay)) curDay = null;
        continue;
      }
      if (cur) cur.push(line);
      else rest.push(line);
    }
    flush();
    const restText = rest.join('\n').trim();
    if (restText !== '') {
      if (fallback) add(fallback, restText);
      else c.skipped.no_date++;
    }
  }
  for (const [day, entries] of [...byDay.entries()].sort()) {
    st.stage(c, { kind: 'decision', date: day, title: `Decision log ${day}`, source: 'decision-log', body: entries.join('\n') });
  }
}

/** Run one input's adapter (root checked first). Returns its counts. */
export async function runAdapter(input: ImportInput, st: Stager, workDir: string, git?: (repo: string) => Promise<string>, scope = 'work',
  gitRemotes?: (repo: string) => Promise<string[]>, o: AdapterOptions = {}): Promise<InputCounts> {
  const c = emptyInputCounts(input.kind);
  if (mentionsProtectedName(input.path) || /(^|[\\/])requests([\\/]|$)/i.test(input.path)) throw new ImportInputError('import: an input path is refused by the wall');
  switch (input.kind) {
    case 'claude-export':
      importClaudeExport(checkInputRoot(input.path, 'file', workDir, scope), st, c);
      break;
    case 'chatgpt-export':
      importChatgptExport(checkInputRoot(input.path, 'file', workDir, scope), st, c);
      break;
    case 'markdown':
      importMarkdownFolder(checkInputRoot(input.path, 'dir', workDir, scope), st, c, scope, { ...o, names: input.names });
      break;
    case 'git':
      await importGitRepo(checkInputRoot(input.path, 'dir', workDir, scope), st, c, git, gitRemotes);
      break;
    case 'decision-log': {
      const real = checkInputRoot(input.path, 'file', workDir, scope);
      importDecisionLog(real, st, c, lstatSync(real).mtime);
      break;
    }
  }
  return c;
}
