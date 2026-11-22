// `zeusi export-filter` (docs/hq-sync.md): the deterministic, offline source-side
// filter for the nightly Zeus HQ export (HQ chat, project histories, journal, Zeus memory).
//
// Input: a staging dir `<in>/<project>/YYYY-MM-DD-<slug>.md` written by the HQ routine.
// Output: the Zeusi source folder `<out>/<project>/...`, read by `zeusi ingest hq-sync`.
//
// No LLM, no database, no network. READ-ONLY on --in (O_RDONLY|O_NOFOLLOW; symlinks and
// hard links refused unopened). Per note:
//   * whole-note drop when the path (project folder, file name), the frontmatter (title,
//     tags, any value) or the layout trips: Plankiva signals (the wall's own Plankiva-class
//     rules via compileWall + mentionsProtectedName: raw, percent-decoded, normalised, look-alikes,
//     inline/frontmatter tags), the `requests/` family, a credential pattern, or a bad
//     layout; the earlier output of the same name is removed;
//   * otherwise per ENTRY (one H2 section; text before the first H2 is the preamble entry):
//     an entry that trips any signal is replaced by WITHHELD_MARKER and nothing else (no
//     reason, no count of what matched, no heading).
// Then the output gate: every output file is re-read and checked exactly as the importer
// builds its rows (note row + chunkMarkdown chunks) against the Plankiva-class wall plus the
// extra signals. Any hit removes every file this run wrote and the run is refused.
//
// ClientCo and Northbank content is NOT filtered here (owner rule). The soft wall rules
// (account numbers, IBAN; currency and P&L lines were lifted by 0011) are not applied here either: they still
// quarantine at ingest. The report's "ingest preview" counts how often they would fire.
//
// Output: counts only. Never a path below --in/--out, a title, or entry text.

import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { chunkMarkdown } from './chunking.ts';
import { HQ_FILE_RE, HQ_PROJECT_RE, hqFormatProblem } from './importers/profile.ts';
import { MAX_FILE_BYTES, splitNote, wikilinks } from './importers/vault.ts';
import { strictCredentialSignal as credentialSignal } from './secrets.ts';
import { mentionsProtectedName, sourcePathGate } from './sources.ts';
import { PROTECTED_VARIANTS_REGEX, PROTECTED_SPELLING_REGEX, compileWall, pctDecode, seedWall, wallNorm, WALL_UNDECODED_TERM, type Row, type Wall } from './wall.ts';

/** The only thing left where a withheld entry was. Content-free on purpose. */
export const WITHHELD_MARKER = '<!-- withheld: 1 entry -->';

export type Signal = 'plankiva' | 'requests' | 'credential';

/** Usage / folder problem (exit 2). Messages are safe: never a path below --in/--out. */
export class ExportFilterError extends Error {
  override name = 'ExportFilterError';
}

/** A filesystem / IO error (EACCES, ENOSPC, ENOTDIR, ...) during the run (exit 3). Code only, never a path. */
export class ExportFilterIoError extends ExportFilterError {
  override name = 'ExportFilterIoError';
}

/** The --in / --out tree is unsafe (overlap, a symlink or non-directory below --out): refused before any write (exit 4). */
export class ExportFilterUnsafeError extends ExportFilterError {
  override name = 'ExportFilterUnsafeError';
}

// ---------------------------------------------------------------------------
// Signals

/** The hard Plankiva regex rules of 0010 (spelling) and 0011 ("Plankiva" variants). */
const PLANKIVA_REGEXES: readonly string[] = [PROTECTED_SPELLING_REGEX, PROTECTED_VARIANTS_REGEX];

/**
 * The wall restricted to its Plankiva class: every rule whose normalised pattern names
 * plankiva (path / lane / repo globs, the tag rule, the term rule), the hard Plankiva
 * regex rules (0010 separators / leetspeak, 0011 "Plankiva" and its variants), plus the
 * hard undecoded-percent-escape rule. Built from the wall's own rules (default: the seed
 * rules), compiled by the wall's own compiler: same normalisation, decoding and matching.
 */
export function plankivaWall(base: Wall = seedWall()): Wall {
  const rules = base.rules.filter((r) => r.hard && (wallNorm(r.pattern).includes('plankiva') || PLANKIVA_REGEXES.includes(r.pattern) || r.pattern === WALL_UNDECODED_TERM));
  if (!rules.some((r) => r.kind === 'term') || !rules.some((r) => r.kind === 'tag')) {
    throw new ExportFilterError('the wall has no Plankiva term/tag rule; refusing to filter');
  }
  return compileWall(rules, []);
}

/** `requests/` in the text, its percent-decoded form, or either normalised. */
export function requestsSignal(s: string): boolean {
  return [s, pctDecode(s)].some((x) => /requests\//i.test(x) || /requests\//.test(wallNorm(x)));
}

/**
 * Credential shapes: the ONE shared detector (src/secrets.ts), also used by ingest, the MCP
 * output guard and `zeusi rescrub`. Full and partial / masked provider keys, JWTs, private
 * keys, URL passwords, bearer tokens, keyword=value forms and 2FA codes. Here a hit
 * withholds the whole entry (counted only): an HQ entry carrying a credential means the
 * routine broke its rules, so nothing of that entry is kept.
 */
export { strictCredentialSignal as credentialSignal } from './secrets.ts';

/** First signal an entry's text trips (Plankiva first), or null. */
export function entrySignal(text: string, aw: Wall): Signal | null {
  const v = aw.check('chunks', { heading_path: null, text, source_uri: 'hq:entry' });
  if (v.blocked || mentionsProtectedName(text)) return 'plankiva';
  if (requestsSignal(text)) return 'requests';
  if (credentialSignal(text)) return 'credential';
  return null;
}

/** Path signal for `<project>` or `<project>/<file>` (as the importer would see it). */
function pathSignal(rel: string, aw: Wall): Signal | null {
  if (mentionsProtectedName(rel) || aw.checkUri(`hq:${rel}`).blocked || aw.checkUri(`hq:${rel}/`).blocked) return 'plankiva';
  if (requestsSignal(`${rel}/`) || /(^|\/)requests(\/|$)/i.test(wallNorm(pctDecode(rel)))) return 'requests';
  if (credentialSignal(rel)) return 'credential';
  return null;
}

// ---------------------------------------------------------------------------
// Entries

export interface Entry {
  /** Raw lines (split on \n; a trailing \r stays on its line). */
  lines: string[];
  /** true for the H2 entries, false for the preamble. */
  heading: boolean;
}

const H2 = /^ {0,3}##[ \t]/;
const FENCE = /^ {0,3}(`{3,}|~{3,})/; // same fence rule as src/chunking.ts

/** Split a note body into the preamble and one entry per H2 (outside fenced code). Lossless. */
export function splitEntries(body: string): Entry[] {
  const out: Entry[] = [{ lines: [], heading: false }];
  let fence: string | null = null;
  for (const line of body.split('\n')) {
    const f = FENCE.exec(line);
    if (f) {
      const mark = f[1]!;
      if (fence === null) fence = mark;
      else if (mark[0] === fence[0] && mark.length >= fence.length) fence = null;
    } else if (fence === null && H2.test(line)) {
      out.push({ lines: [line], heading: true });
      continue;
    }
    out[out.length - 1]!.lines.push(line);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The run

export interface ExportCounts {
  files_seen: number;
  files_kept: number;
  /** Of kept: the output already had these exact bytes (not rewritten). */
  files_unchanged: number;
  files_dropped: number;
  dropped_by_reason: { signal: number; layout: number; unsafe: number };
  /** Earlier outputs removed because the same-name input is now dropped. */
  files_removed: number;
  /** Project folders refused unlisted (signal, not a slug, or not a configured project). */
  folders_dropped: number;
  /**
   * Configured-but-disabled ("held") project folders (fix round 1, m3): counted, left in
   * staging, never written to --out, never deleted. Not part of files_seen.
   */
  held: { folders: number; files: number; entries: number };
  entries_kept: number;
  entries_withheld: number;
  withheld_by_signal: Record<Signal, number>;
  /** Output-gate hits (0 unless the filter itself is broken). */
  gate_hits: number;
  by_project: Record<string, { files_kept: number; entries_kept: number; entries_withheld: number }>;
}

export interface IngestPreview {
  /** Output notes the importer would admit with the seed wall (no allows). */
  would_pass: number;
  would_quarantine: number;
  /** First blocking rule per quarantined note, by rule id. */
  by_rule: Record<string, number>;
}

export interface ExportFilterOptions {
  inDir: string;
  outDir: string;
  /** Allowed project folders (from the zeus_memory sources' `project` keys). Default: any slug. */
  projects?: readonly string[];
  /** Held project folders (`[hq_export] held`): counted, kept in staging, never written. */
  held?: readonly string[];
  /** Wall to take the Plankiva-class rules and the preview from (default: seed rules). */
  wall?: Wall;
  /** TEST ONLY: keep every entry, to prove the output gate refuses. */
  testOnlyKeepAllEntries?: boolean;
}

export interface ExportFilterResult {
  status: 'ok' | 'refused';
  counts: ExportCounts;
  preview: IngestPreview;
  /** Safe text (no paths, no content). */
  error?: string;
}

function emptyCounts(): ExportCounts {
  return {
    files_seen: 0, files_kept: 0, files_unchanged: 0, files_dropped: 0,
    dropped_by_reason: { signal: 0, layout: 0, unsafe: 0 }, files_removed: 0, folders_dropped: 0, held: { folders: 0, files: 0, entries: 0 },
    entries_kept: 0, entries_withheld: 0, withheld_by_signal: { plankiva: 0, requests: 0, credential: 0 },
    gate_hits: 0, by_project: {},
  };
}

/** realpath of p, or of its nearest existing ancestor plus the rest (p may not exist yet). */
function realish(p: string): string {
  const abs = resolve(p);
  const rest: string[] = [];
  let cur = abs;
  for (;;) {
    try {
      return join(realpathSync(cur), ...rest.reverse());
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return abs;
      rest.push(basename(cur));
      cur = parent;
    }
  }
}

const within = (a: string, b: string) => a === b || a.startsWith(b.endsWith(sep) ? b : b + sep);

const UNSAFE_OUT = 'refused; nothing is written or removed through it';

/**
 * Fix round 1 (M1): --out must be a plain tree. Every non-dot entry directly below --out
 * is a real directory (never a symlink), dot entries are regular files, and nothing below a
 * project folder is a symlink. Checked BEFORE the first write; the project folder and
 * the target file are re-checked at every write, removal and re-read (see outDir/outFile).
 */
function assertOutTree(outReal: string): void {
  for (const top of readdirSync(outReal)) {
    const p = join(outReal, top);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) throw new ExportFilterUnsafeError(`--out: an entry directly below --out is a symlink; ${UNSAFE_OUT}`);
    if (!st.isDirectory()) {
      if (top.startsWith('.') && st.isFile()) continue;
      throw new ExportFilterUnsafeError(`--out: an entry directly below --out is not a real directory; ${UNSAFE_OUT}`);
    }
    for (const f of readdirSync(p)) {
      const fst = lstatSync(join(p, f));
      if (fst.isSymbolicLink() || !(fst.isFile() || fst.isDirectory())) {
        throw new ExportFilterUnsafeError(`--out: an entry in a project folder is a symlink or not a regular file; ${UNSAFE_OUT}`);
      }
    }
  }
}

/** Read a regular, single-link file without following symlinks. null = unsafe / unreadable. */
function readSafe(abs: string): Buffer | null {
  let fd: number;
  try {
    const st = lstatSync(abs);
    if (!st.isFile() || st.nlink > 1 || st.size > MAX_FILE_BYTES) return null;
    fd = openSync(abs, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink > 1 || st.size > MAX_FILE_BYTES) return null;
    return readFileSync(fd);
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

function decodeUtf8(b: Buffer): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(b);
  } catch {
    return null;
  }
}

/** Rows exactly as the importer builds them (HQ profile), for the gate and the preview. */
function importerRows(rel: string, text: string): { note: Row; chunks: Row[] } {
  const { fm, body } = splitNote(text);
  const links = wikilinks(...Object.values(fm ?? {}).flat(), body);
  const title = typeof fm?.['title'] === 'string' && fm['title'].trim() !== '' ? fm['title'].trim() : basename(rel, '.md');
  const uri = `hq:${rel}`;
  const note: Row = { vault_path: uri, title, body, frontmatter: { ...(fm ?? {}), links }, scope: 'work', source_kind: 'zeus_memory', source_uri: uri };
  const chunks = chunkMarkdown(body).map((k) => ({ heading_path: k.headingPath, text: k.text, scope: 'work', source_kind: 'zeus_memory', source_uri: `${uri}#c${k.index}` }));
  return { note, chunks };
}

/** Output gate for one written file: the importer's rows through the Plankiva-class wall, plus the extra signals. */
function gateHit(rel: string, text: string, aw: Wall): boolean {
  const { note, chunks } = importerRows(rel, text);
  if (aw.check('notes', note).blocked || chunks.some((c) => aw.check('chunks', c).blocked)) return true;
  return pathSignal(rel, aw) !== null || mentionsProtectedName(text) || requestsSignal(text) || credentialSignal(text);
}

/**
 * Any non-ExportFilterError (a Node fs error: EACCES, ENOSPC, ENOTDIR, ...) becomes an
 * ExportFilterIoError carrying the error code only: Node's message holds an absolute path
 * below --in/--out, which is never printed (fix round 1, m4). Outputs already written
 * stay (each one was filtered); no output gate ran, so the routine must not treat it as one.
 */
export function runExportFilter(opts: ExportFilterOptions): ExportFilterResult {
  try {
    return runExportFilterUnsafe(opts);
  } catch (e) {
    if (e instanceof ExportFilterError) throw e;
    const code = (e as { code?: unknown } | null)?.code;
    const what = typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? `filesystem error (${code})` : 'internal error';
    throw new ExportFilterIoError(`${what} during export-filter; no path printed; outputs already written were each filtered, no output gate ran`);
  }
}

function runExportFilterUnsafe(opts: ExportFilterOptions): ExportFilterResult {
  const base = opts.wall ?? seedWall();
  const aw = plankivaWall(base);
  const counts = emptyCounts();
  const preview: IngestPreview = { would_pass: 0, would_quarantine: 0, by_rule: {} };

  // ---- Folders: --in must exist; --in and --out must not overlap (never write the input).
  let inReal: string;
  try {
    inReal = realpathSync(opts.inDir);
    if (!lstatSync(inReal).isDirectory()) throw new Error('not a directory');
  } catch {
    throw new ExportFilterError('--in is missing or not a directory');
  }
  const outReal0 = realish(opts.outDir);
  if (within(outReal0, inReal) || within(inReal, outReal0)) throw new ExportFilterUnsafeError('--in and --out overlap; refusing (the input is never written)');
  for (const [flag, p] of [['--in', opts.inDir], ['--out', opts.outDir]] as const) {
    if (!sourcePathGate(p).ok) throw new ExportFilterError(`${flag} is refused by the path gate`);
  }
  mkdirSync(opts.outDir, { recursive: true, mode: 0o700 });
  const outReal = realpathSync(opts.outDir);
  if (within(outReal, inReal) || within(inReal, outReal)) throw new ExportFilterUnsafeError('--in and --out overlap; refusing (the input is never written)');
  assertOutTree(outReal);

  /** out/<project>, re-checked: a real directory directly below --out (created 0700 if missing), never a symlink. */
  const outDir = (project: string, create: boolean): string | null => {
    const d = join(outReal, project);
    let st = lstatSync(d, { throwIfNoEntry: false });
    if (st === undefined) {
      if (!create) return null;
      mkdirSync(d, { mode: 0o700 });
      st = lstatSync(d);
    }
    if (st.isSymbolicLink() || !st.isDirectory()) throw new ExportFilterUnsafeError(`--out: a project folder is a symlink or not a real directory; ${UNSAFE_OUT}`);
    return d;
  };
  /** out/<project>/<file>: absent, or a regular file (never a symlink). */
  const outFile = (project: string, file: string, create: boolean): { abs: string; exists: boolean } | null => {
    const d = outDir(project, create);
    if (d === null) return null;
    const abs = join(d, file);
    const st = lstatSync(abs, { throwIfNoEntry: false });
    if (st !== undefined && (st.isSymbolicLink() || !st.isFile())) throw new ExportFilterUnsafeError(`--out: an output file is a symlink or not a regular file; ${UNSAFE_OUT}`);
    return { abs, exists: st !== undefined };
  };
  const readOut = (rel: string): string | null => {
    const [project, file] = rel.split('/') as [string, string];
    const f = outFile(project, file, false);
    if (f === null || !f.exists) return null;
    const b = readSafe(f.abs);
    return b === null ? null : decodeUtf8(b);
  };

  const written: string[] = [];
  const kept: string[] = [];
  const removeStale = (rel: string) => {
    const [project, file] = rel.split('/') as [string, string];
    const f = outFile(project, file, false);
    if (f?.exists) {
      unlinkSync(f.abs);
      counts.files_removed++;
    }
  };
  const drop = (rel: string | null, reason: keyof ExportCounts['dropped_by_reason']) => {
    counts.files_dropped++;
    counts.dropped_by_reason[reason]++;
    if (rel) removeStale(rel);
  };

  const sortNames = (xs: string[]) => xs.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const top = sortNames(readdirSync(inReal).filter((n) => !n.startsWith('.')));
  for (const project of top) {
    const pAbs = join(inReal, project);
    const st = lstatSync(pAbs);
    if (!st.isDirectory()) {
      counts.files_seen++;
      drop(null, st.isFile() ? 'layout' : 'unsafe');
      continue;
    }
    // Held folders (m3): counted (files, H2 entries), read-only, nothing written or removed.
    if (opts.held?.includes(project) && HQ_PROJECT_RE.test(project) && pathSignal(project, aw) === null && !opts.projects?.includes(project)) {
      counts.held.folders++;
      for (const file of readdirSync(pAbs).filter((n) => !n.startsWith('.'))) {
        const abs = join(pAbs, file);
        if (!lstatSync(abs).isFile()) continue;
        counts.held.files++;
        const b = readSafe(abs);
        const text = b === null ? null : decodeUtf8(b);
        if (text !== null) counts.held.entries += splitEntries(splitNote(text).body).filter((x) => x.heading).length;
      }
      continue;
    }
    // Refused folders are never listed: their files are not counted one by one.
    if (pathSignal(project, aw) !== null || !HQ_PROJECT_RE.test(project) || (opts.projects && !opts.projects.includes(project))) {
      counts.folders_dropped++;
      continue;
    }
    for (const file of sortNames(readdirSync(pAbs).filter((n) => !n.startsWith('.')))) {
      const rel = `${project}/${file}`;
      const abs = join(pAbs, file);
      counts.files_seen++;
      const lst = lstatSync(abs);
      if (lst.isDirectory()) {
        drop(null, 'layout'); // sub-folders are not part of the layout; never listed
        continue;
      }
      if (pathSignal(rel, aw) !== null) {
        drop(rel, 'signal');
        continue;
      }
      if (!HQ_FILE_RE.test(file)) {
        drop(rel, 'layout');
        continue;
      }
      const bytes = readSafe(abs);
      if (bytes === null) {
        drop(rel, 'unsafe');
        continue;
      }
      const text = decodeUtf8(bytes);
      if (text === null) {
        drop(rel, 'unsafe');
        continue;
      }
      const { fm, body } = splitNote(text);
      const fmRaw = text.slice(0, text.length - body.length);
      // Whole-note signals: frontmatter (title, tags, every value) + the note-level wall row.
      const noteRow: Row = { vault_path: `hq:${rel}`, title: typeof fm?.['title'] === 'string' ? fm['title'] : '', body: '', frontmatter: fm ?? {}, source_uri: `hq:${rel}` };
      if (aw.check('notes', noteRow).blocked || mentionsProtectedName(fmRaw) || requestsSignal(fmRaw) || credentialSignal(fmRaw)) {
        drop(rel, 'signal');
        continue;
      }
      if (hqFormatProblem(rel, fm, null) !== null) {
        drop(rel, 'layout');
        continue;
      }

      // Entries.
      const entries = splitEntries(body);
      const parts: string[] = [];
      let k = 0;
      let w = 0;
      for (const e of entries) {
        const t = e.lines.join('\n');
        const isEmptyPreamble = !e.heading && t.trim() === '';
        const sig = isEmptyPreamble || opts.testOnlyKeepAllEntries ? null : entrySignal(t, aw);
        if (sig === null) {
          parts.push(t);
          k++;
        } else {
          parts.push([WITHHELD_MARKER, ...(e.lines[e.lines.length - 1] === '' ? [''] : [])].join('\n'));
          w++;
          counts.withheld_by_signal[sig]++;
        }
      }
      const outText = fmRaw + parts.join('\n');
      const target = outFile(project, file, true)!;
      const outAbs = target.abs;
      const same = target.exists && readOut(rel) === outText;
      if (same) counts.files_unchanged++;
      else {
        const tmp = join(dirname(outAbs), `.${file}.tmp-${process.pid}`);
        if (lstatSync(tmp, { throwIfNoEntry: false })?.isFile()) unlinkSync(tmp); // a crashed earlier run's leftover
        writeFileSync(tmp, outText, { mode: 0o600, flag: 'wx' }); // wx: never through an existing entry (symlink included)
        renameSync(tmp, outAbs); // atomic: the importer never sees a half-written note
        written.push(outAbs);
      }
      kept.push(rel);
      counts.files_kept++;
      counts.entries_kept += k;
      counts.entries_withheld += w;
      const bp = (counts.by_project[project] ??= { files_kept: 0, entries_kept: 0, entries_withheld: 0 });
      bp.files_kept++;
      bp.entries_kept += k;
      bp.entries_withheld += w;
    }
  }

  // ---- Output gate: re-read every kept output as the importer would. Fail closed.
  const texts = new Map<string, string>();
  for (const rel of kept) {
    const text = readOut(rel); // O_NOFOLLOW, single link; unreadable counts as a hit (fail closed)
    if (text === null || gateHit(rel, text, aw)) counts.gate_hits++;
    else texts.set(rel, text);
  }
  if (counts.gate_hits > 0) {
    for (const rel of kept) {
      const [project, file] = rel.split('/') as [string, string];
      const f = outFile(project, file, false);
      if (f?.exists) unlinkSync(f.abs);
    }
    return { status: 'refused', counts, preview, error: `output gate: ${counts.gate_hits} file(s) still carry a signal; every output of this run was removed` };
  }

  // ---- Ingest preview with the full wall (no allows): how often the importer quarantines.
  const full = compileWall(base.rules, []);
  for (const rel of kept) {
    const { note, chunks } = importerRows(rel, texts.get(rel)!);
    const pathV = full.check('facts', { source_uri: `hq:${rel}`, kind: 'other', subject: null, text: rel });
    const v = [pathV, full.check('notes', note), ...chunks.map((c) => full.check('chunks', c))].find((x) => x.blocked);
    if (v) {
      preview.would_quarantine++;
      preview.by_rule[String(v.ruleId)] = (preview.by_rule[String(v.ruleId)] ?? 0) + 1;
    } else preview.would_pass++;
  }
  return { status: 'ok', counts, preview };
}

/** Counts only. `report` adds per-project, per-signal and the ingest preview. */
export function formatExportResult(r: ExportFilterResult, report: boolean, rules: Wall['rules'] = seedWall().rules): string {
  const c = r.counts;
  const lines = [`export-filter: status ${r.status}`];
  lines.push(`  files: seen ${c.files_seen}, kept ${c.files_kept} (unchanged ${c.files_unchanged}), dropped ${c.files_dropped}, earlier outputs removed ${c.files_removed}, folders refused ${c.folders_dropped}`);
  lines.push(`  entries: kept ${c.entries_kept}, withheld ${c.entries_withheld}`);
  lines.push(`  held (project disabled): folders ${c.held.folders}, files ${c.held.files}, entries ${c.held.entries} (left in staging, not written)`);
  lines.push(`  output gate: ${c.gate_hits} hit(s)`);
  if (report) {
    const d = c.dropped_by_reason;
    lines.push(`  dropped files by reason: signal ${d.signal}, layout ${d.layout}, unsafe ${d.unsafe}`);
    const s = c.withheld_by_signal;
    lines.push(`  withheld entries by signal: plankiva-class ${s.plankiva}, requests ${s.requests}, credential ${s.credential}`);
    for (const [p, v] of Object.entries(c.by_project).sort()) lines.push(`  project ${p}: files ${v.files_kept}, entries kept ${v.entries_kept}, withheld ${v.entries_withheld}`);
    if (r.status === 'ok') {
      lines.push(`  ingest preview (seed wall, no allows): would pass ${r.preview.would_pass}, would quarantine ${r.preview.would_quarantine}`);
      for (const [k, v] of Object.entries(r.preview.by_rule).sort((a, b) => Number(a[0]) - Number(b[0]))) {
        const rule = rules.find((x) => String(x.id) === k);
        lines.push(`    rule ${k}${rule ? ` ${rule.kind} (${rule.hard ? 'hard' : 'soft'})` : ''}: ${v}`);
      }
    }
  }
  if (r.error) lines.push(`  REFUSED: ${r.error}`);
  return lines.join('\n');
}
