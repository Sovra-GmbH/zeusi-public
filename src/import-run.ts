// `zeusi import` / `zeusi onboard` pipeline (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md U8,
// KTD10-KTD15; PR2 amendments P1-P4).
//
//   inputs -> adapters (src/importers/onboard.ts) -> private staging dir, HQ layout
//          -> runExportFilter (src/hq-export.ts, UNCHANGED: Plankiva excluded entirely,
//             requests/, credential and 2FA scrub, output gate) -> private filtered dir
//          -> importVault with IMPORT_PROFILE (path gate, content gate incl. the soft IBAN /
//             account-number rules, the zeusi_90_wall trigger, quarantine by uri + hash only)
//          -> structured entries (src/importers/structured.ts) of ADMITTED markdown / decision-log
//             notes only -> zeusi.decisions / zeusi.facts (rule, state)
//
// prepareImport() runs everything up to the preview OFFLINE: no database connection, the seed wall,
// zero writes. The preview is always produced (and printed by the CLI) before any write.
// executeImport() is the real write and needs a Db that the caller opened as zeusi_ingest after
// the --scope, transport and main-branch guards (src/cli.ts). The work dir is private
// (~/.zeusi/onboard/<random>, 0700) and is removed by cleanup(), also after an error.
//
// Counts only leave this module: never an input path, a title or text.

import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { Db } from './db.ts';
import { defaultHost, openRun, closeRun } from './facts.ts';
import { runExportFilter, type ExportCounts } from './hq-export.ts';
import type { VaultCounts } from './ingest-run.ts';
import {
  createStager, ImportInputError, IMPORT_CAPS, runAdapter, type ImportInput, type InputCounts, type StagedNote,
} from './importers/onboard.ts';
import {
  emptyParseCounts, emptyWriteCounts, parseStructuredBody, recordRow, recordSha256, recordUri, writeStructured,
  type KeptAsNoteReason, type StructuredParseCounts, type StructuredRecord, type StructuredWriteCounts,
} from './importers/structured.ts';
import { IMPORT_PROFILE, importVault, splitNote } from './importers/vault.ts';
import type { ImportProfile } from './importers/profile.ts';
import { gatedRunDir, isRunName, runDirGate } from './run-dir.ts';
import type { SourcesConfig } from './sources.ts';
import { compileWall, loadWall, seedWall } from './wall.ts';
import { PLAIN_ROUTE, type WriteRoute } from './write-route.ts';

export const IMPORT_SCOPES = ['work', 'product', 'client'] as const;
export type ImportScope = (typeof IMPORT_SCOPES)[number];

/** KTD12: the project folder of a scope (fixed map; hqScopeProblem keeps client in its own scope). */
export const SCOPE_PROJECT: Readonly<Record<ImportScope, string>> = { work: 'team', product: 'northbank', client: 'clientco' };

/** source_uri prefix of every imported note and structured row. */
export const IMPORT_URI_PREFIX = 'import:';
/** ingest_runs.importer of the structured rows (the notes run is IMPORT_PROFILE.importer). */
export const STRUCTURED_IMPORTER = 'onboard-import-structured';

/** Inputs whose notes may carry structured entries. Chat exports and git never do (notes only). */
const STRUCTURED_ORIGINS: ReadonlySet<string> = new Set(['markdown', 'decision-log']);

export interface TargetCounts {
  notes: number;
  chunks: number;
  /** Non-blank `locks:` items of admitted notes (rules at read time: zeusi_startup / context_for_task). */
  note_locks: number;
  rules: number;
  focus: number;
  decisions: number;
  decisions_by_kind: Record<string, number>;
}

export interface ImportPreview {
  scope: ImportScope;
  project: string;
  inputs: InputCounts[];
  filter: {
    status: 'ok' | 'refused';
    files_seen: number;
    files_kept: number;
    files_dropped: number;
    entries_kept: number;
    entries_withheld: number;
    withheld_by_signal: ExportCounts['withheld_by_signal'];
    gate_hits: number;
  };
  importer: { would_insert: number; quarantined: number; path_gated: number; errors: number; by_rule: Record<string, number> };
  /** What the run would add (dry run, offline: dedupe against the database is not known yet). */
  targets: TargetCounts;
  /** duplicate_in_run: the same record (uri + sha) reached through two inputs / notes; counted once. */
  structured: StructuredParseCounts & {
    would_quarantine: number; handles_named: number; duplicate_in_run: number;
    /** Headed entries that stay notes, by the first rule they broke (src/importers/structured.ts KEPT_AS_NOTE_REASONS). */
    kept_as_note: Partial<Record<KeptAsNoteReason, number>>;
  };
  error?: string;
}

export interface PreparedImport {
  preview: ImportPreview;
  /** The private work dir (removed by cleanup). */
  readonly workDir: string;
  /** Filtered folder read by importVault. */
  readonly filteredDir: string;
  readonly staged: readonly StagedNote[];
  /**
   * Relative paths (`<project>/<file>`) the dry importer pass ADMITTED, in staging order. In memory
   * only: the hosted workspace preview (src/workspace-write.ts) reads their filtered title and first
   * line; the CLI never prints them.
   */
  readonly admitted: readonly string[];
  /**
   * Structured records the run would write, per `who` handle (after the wall pre-check and in-run
   * dedupe). In memory only: the hosted workspace preview checks them against its people
   * (src/workspace-write.ts) to say in advance which entries would stay notes.
   */
  readonly handles: ReadonlyMap<string, number>;
  cleanup(): void;
}

export interface ImportRealResult {
  status: 'ok' | 'ok_partial' | 'failed' | 'locked';
  runId: number | null;
  structuredRunId: number | null;
  notes: Pick<VaultCounts, 'inserted' | 'updated' | 'skipped' | 'quarantined' | 'errors' | 'chunks_written' | 'backstop'>;
  targets: TargetCounts;
  structured: StructuredWriteCounts;
  error?: string;
}

export interface PrepareOptions {
  inputs: readonly ImportInput[];
  scope: string;
  /** Parent of the private work dirs (default ~/.zeusi/onboard). */
  workRoot?: string;
  home?: string;
  /**
   * Notes staged per run, at most IMPORT_CAPS.stagedNotes (the default). The hosted workspace preview
   * passes its smaller per-preview cap so staging stops early (ImportNotesCapError; the work dir is removed).
   */
  stagedNotes?: number;
  /**
   * Carry a strictly valid `standing_locks:` of a markdown note (src/importers/onboard.ts
   * carriedStandingLocks). Only the hosted personal-workspace import sets it; the CLI import into
   * the work tenant never does, so no import can make a work-tenant standing rule.
   */
  standingLocks?: boolean;
  /** TEST seam: replaces `git log` (the real runner is the hardened execFile in onboard.ts). */
  git?: (repo: string) => Promise<string>;
  /** TEST seam: replaces the remote-url read (`git config --get-regexp`). */
  gitRemotes?: (repo: string) => Promise<string[]>;
  /** TEST seam: the work dir's random name (src/run-dir.ts), so a test can force a walled name first. */
  runName?: () => string;
}

/** The sub-dirs of a run's work dir; the path gates check them (export filter, dry importer). */
export const STAGING_DIR = 'staging';
export const FILTERED_DIR = 'filtered';

export function assertScope(scope: unknown): ImportScope {
  if (typeof scope !== 'string' || !(IMPORT_SCOPES as readonly string[]).includes(scope)) {
    throw new ImportInputError(`import: --scope must be one of ${IMPORT_SCOPES.join('|')}`);
  }
  return scope as ImportScope;
}

function emptyTargets(): TargetCounts {
  return { notes: 0, chunks: 0, note_locks: 0, rules: 0, focus: 0, decisions: 0, decisions_by_kind: {} };
}

/**
 * A private 0700 dir directly under `root` (created 0700 if missing; never through a symlink) whose random name
 * passes the gates this run applies under it (src/run-dir.ts): the export filter's on staging/ and filtered/ and
 * the dry importer's on filtered/, all with the seed wall.
 */
function privateWorkDir(root: string, home: string, name?: () => string): string {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const st = lstatSync(root);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new ImportInputError('import: the work dir parent is not a real directory');
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw new ImportInputError('import: the work dir parent is not owned by this user');
  sweepStaleRuns(root);
  return gatedRunDir(root, 'run-', runDirGate([seedWall()], home, [STAGING_DIR, FILTERED_DIR]), name);
}

/** A run dir older than this is from an interrupted run (Ctrl-C, kill): removed at the next start. */
export const STALE_RUN_MS = 6 * 3600 * 1000;

/**
 * Security review (PR2 update 3, M2): an interrupted run can leave its private work dir behind.
 * Remove this user's stale `run-*` dirs (real dirs only, never through a symlink). Best effort.
 */
export function sweepStaleRuns(root: string, now = Date.now()): number {
  let n = 0;
  for (const name of readdirSync(root)) {
    if (!name.startsWith('run-') || !isRunName(name.slice('run-'.length))) continue;
    try {
      const st = lstatSync(join(root, name));
      if (st.isSymbolicLink() || !st.isDirectory()) continue;
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) continue;
      if (now - st.mtimeMs < STALE_RUN_MS) continue;
      rmSync(join(root, name), { recursive: true, force: true });
      n++;
    } catch { /* best effort */ }
  }
  return n;
}

const lockItems = (fm: Record<string, unknown> | null | undefined): number => {
  const v = fm?.['locks'];
  const items = Array.isArray(v) ? v : typeof v === 'string' ? [v] : [];
  return items.filter((x) => typeof x === 'string' && x.trim() !== '').length;
};

/** Structured records of one filtered note (markdown / decision-log origins only). */
function recordsOf(filteredDir: string, rel: string): {
  records: StructuredRecord[]; counts: StructuredParseCounts; keptAsNote: Partial<Record<KeptAsNoteReason, number>>; locks: number;
} {
  const text = readFileSync(join(filteredDir, rel), 'utf8');
  const { fm, body } = splitNote(text);
  const { records, counts, keptAsNote } = parseStructuredBody(body);
  return { records, counts, keptAsNote, locks: lockItems(fm) };
}

function addParse(a: StructuredParseCounts, b: StructuredParseCounts): void {
  a.entries += b.entries;
  a.unstructured += b.unstructured;
  a.invalid += b.invalid;
  a.secret += b.secret;
}

function countRecord(t: TargetCounts, r: StructuredRecord): void {
  if (r.type === 'decision') {
    t.decisions++;
    t.decisions_by_kind[r.kind] = (t.decisions_by_kind[r.kind] ?? 0) + 1;
  } else if (r.factKind === 'rule') t.rules++;
  else t.focus++;
}

function inMemoryConfig(root: string, scope: ImportScope, project: string): SourcesConfig {
  return {
    sources: [{ name: 'onboard-import', kind: 'manual', scope, root, include: [`${project}/*.md`], exclude: [], project }],
    github: { org: '', repos: [], northbankRepos: [] },
  };
}

/**
 * Offline: adapters, the nightly filter and a dry importer pass (seed wall). No database, zero
 * writes. On any error the work dir is removed and the error rethrown.
 */
export async function prepareImport(o: PrepareOptions): Promise<PreparedImport> {
  const scope = assertScope(o.scope);
  if (o.inputs.length === 0) throw new ImportInputError('import: give at least one input (--markdown, --decision-log, --claude-export, --chatgpt-export, --git)');
  if (o.inputs.length > IMPORT_CAPS.inputs) throw new ImportInputError(`import: at most ${IMPORT_CAPS.inputs} inputs per run`);
  const home = o.home ?? homedir();
  const project = SCOPE_PROJECT[scope];
  const workDir = privateWorkDir(o.workRoot ?? join(home, '.zeusi', 'onboard'), home, o.runName);
  const cleanup = () => rmSync(workDir, { recursive: true, force: true });
  try {
    const stagingDir = join(workDir, STAGING_DIR);
    const filteredDir = join(workDir, FILTERED_DIR);
    const st = createStager(stagingDir, project, o.stagedNotes);
    const inputs: InputCounts[] = [];
    for (const input of o.inputs) inputs.push(await runAdapter(input, st, workDir, o.git, scope, o.gitRemotes, { standingLocks: o.standingLocks === true }));

    const f = runExportFilter({ inDir: stagingDir, outDir: filteredDir, projects: [project] });
    // M2: the raw (unfiltered) staging copies are not needed after the filter: removed at once,
    // so only filtered text is ever left on disk while the run continues.
    rmSync(stagingDir, { recursive: true, force: true });
    const preview: ImportPreview = {
      scope, project, inputs,
      filter: {
        status: f.status, files_seen: f.counts.files_seen, files_kept: f.counts.files_kept, files_dropped: f.counts.files_dropped,
        entries_kept: f.counts.entries_kept, entries_withheld: f.counts.entries_withheld, withheld_by_signal: { ...f.counts.withheld_by_signal },
        gate_hits: f.counts.gate_hits,
      },
      importer: { would_insert: 0, quarantined: 0, path_gated: 0, errors: 0, by_rule: {} },
      targets: emptyTargets(),
      structured: { ...emptyParseCounts(), would_quarantine: 0, handles_named: 0, duplicate_in_run: 0, kept_as_note: {} },
    };
    if (f.status !== 'ok') {
      preview.error = f.error ?? 'export filter refused the run';
      return { preview, workDir, filteredDir, staged: st.notes, admitted: [], handles: new Map(), cleanup };
    }

    // Dry importer pass (seed wall, no database): exactly what a real run would admit.
    const admitted = new Map<string, number>();
    const r = await importVault({
      config: inMemoryConfig(filteredDir, scope, project), mode: 'full', dryRun: true, profile: IMPORT_PROFILE, home, logPaths: false,
      dryRunObserve: (ob) => { if (ob.outcome === 'admitted') admitted.set(ob.rel, ob.chunks.length); },
    });
    preview.importer = {
      would_insert: r.counts.inserted, quarantined: r.counts.quarantined, path_gated: r.counts.path_gated, errors: r.counts.errors, by_rule: { ...r.counts.by_rule },
    };
    if (r.status !== 'ok') preview.error = r.error ?? 'dry importer pass failed';
    preview.targets.notes = r.counts.inserted;
    preview.targets.chunks = r.counts.chunks_written;

    const wall = seedWall();
    const handles = new Map<string, number>();
    const seen = new Set<string>();
    for (const s of st.notes) {
      if (!admitted.has(s.rel)) continue;
      const x = recordsOf(filteredDir, s.rel);
      preview.targets.note_locks += x.locks;
      if (!STRUCTURED_ORIGINS.has(s.origin)) continue;
      addParse(preview.structured, x.counts);
      for (const [k, n] of Object.entries(x.keptAsNote) as Array<[KeptAsNoteReason, number]>) {
        preview.structured.kept_as_note[k] = (preview.structured.kept_as_note[k] ?? 0) + n;
      }
      for (const rec of x.records) {
        const uri = recordUri(IMPORT_URI_PREFIX, project, rec);
        const sha = recordSha256(rec);
        if (seen.has(`${uri} ${sha}`)) {
          preview.structured.duplicate_in_run++;
          continue;
        }
        seen.add(`${uri} ${sha}`);
        const v = wall.check(rec.type === 'decision' ? 'decisions' : 'facts', recordRow(rec, uri, scope, 'manual', sha));
        if (v.blocked) {
          preview.structured.would_quarantine++;
          continue;
        }
        handles.set(rec.who, (handles.get(rec.who) ?? 0) + 1);
        countRecord(preview.targets, rec);
      }
    }
    preview.structured.handles_named = handles.size;
    return { preview, workDir, filteredDir, staged: st.notes, admitted: st.notes.map((x) => x.rel).filter((rel) => admitted.has(rel)), handles, cleanup };
  } catch (e) {
    cleanup();
    throw e;
  }
}

export interface ExecuteOptions {
  /** ingest_runs.host (default: this machine's label). */
  host?: string;
  home?: string;
  /**
   * The note profile (default IMPORT_PROFILE). The hosted workspace import passes IMPORT_PROFILE with
   * only its importer name changed (own advisory lock and ingest_runs rows per workspace); every
   * gate, the uri scheme, the stored prefix and `deletes: false` stay those of IMPORT_PROFILE.
   */
  profile?: ImportProfile;
  /**
   * C6 (docs/plans/2026-11-19-c6-write-path.md KTD9): the write route, default PLAIN_ROUTE (unchanged).
   * The sealed route seals notes, chunks and structured records, and checks the active notes by
   * vault_path_hmac and keyed digest.
   */
  route?: WriteRoute;
}

/**
 * The real write (caller: --real, --scope, transport and main-branch guards passed, then a
 * zeusi_ingest connection with assertIngestReady). importVault holds the importer's advisory lock
 * and writes one ingest_runs row; structured rows get their own ingest_runs row.
 */
export async function executeImport(p: PreparedImport, db: Db, o: ExecuteOptions = {}): Promise<ImportRealResult> {
  const { scope, project } = p.preview;
  const targets = emptyTargets();
  const structured = emptyWriteCounts();
  if (p.preview.filter.status !== 'ok') {
    return { status: 'failed', runId: null, structuredRunId: null, notes: { inserted: 0, updated: 0, skipped: 0, quarantined: 0, errors: 0, chunks_written: 0, backstop: 0 }, targets, structured, error: p.preview.error ?? 'export filter refused' };
  }
  const route = o.route ?? PLAIN_ROUTE;
  const r = await importVault({
    db, config: inMemoryConfig(p.filteredDir, scope, project), mode: 'full', profile: o.profile ?? IMPORT_PROFILE, home: o.home ?? homedir(),
    host: o.host ?? defaultHost(), logPaths: false, ...(route.kind === 'sealed' ? { route } : {}),
  });
  const notes = {
    inserted: r.counts.inserted, updated: r.counts.updated, skipped: r.counts.skipped, quarantined: r.counts.quarantined,
    errors: r.counts.errors, chunks_written: r.counts.chunks_written, backstop: r.counts.backstop,
  };
  targets.notes = r.counts.inserted + r.counts.updated;
  targets.chunks = r.counts.chunks_written;
  if (r.status !== 'ok') return { status: r.status, runId: r.runId, structuredRunId: null, notes, targets, structured, ...(r.error ? { error: r.error } : {}) };

  // Admitted = the note is active with exactly the filtered bytes (inserted now, or by an earlier run).
  const files = new Map<string, string>();
  for (const s of p.staged) {
    try {
      files.set(s.rel, createHash('sha256').update(readFileSync(join(p.filteredDir, s.rel))).digest('hex'));
    } catch { /* dropped by the export filter */ }
  }
  const paths = [...files.keys()].map((rel) => `${IMPORT_PROFILE.storedPrefix}${rel}`);
  const active = new Set<string>();
  if (paths.length && route.kind === 'sealed') {
    // C6 KTD9: the path is sealed; match by vault_path_hmac and compare keyed digests.
    const k = route.key;
    const byHmac = new Map(paths.map((x) => [k.indexHmac('vault_path', x).toString('hex'), x.slice(IMPORT_PROFILE.storedPrefix.length)]));
    const rows = (await db.query<{ h: string; sha: string }>(
      `SELECT encode(vault_path_hmac, 'hex') AS h, encode(source_sha256, 'hex') AS sha FROM zeusi.notes
       WHERE status = 'active' AND source_kind = 'manual'::zeusi.source_kind
         AND vault_path_hmac IN (SELECT decode(x, 'hex') FROM unnest($1::text[]) AS x)`, [[...byHmac.keys()]])).rows;
    for (const x of rows) {
      const rel = byHmac.get(x.h);
      const plain = rel === undefined ? undefined : files.get(rel);
      if (rel !== undefined && plain !== undefined && k.keyedSha('source_sha256', plain).toString('hex') === x.sha) active.add(rel);
    }
  } else if (paths.length) {
    const rows = (await db.query<{ vault_path: string; sha: string }>(
      `SELECT vault_path, encode(source_sha256, 'hex') AS sha FROM zeusi.notes
       WHERE status = 'active' AND source_kind = 'manual'::zeusi.source_kind AND vault_path = ANY($1::text[])`, [paths])).rows;
    for (const x of rows) {
      const rel = x.vault_path.slice(IMPORT_PROFILE.storedPrefix.length);
      if (files.get(rel) === x.sha) active.add(rel);
    }
  }
  const items: Array<{ record: StructuredRecord; project: string }> = [];
  const seen = new Set<string>();
  for (const s of p.staged) {
    if (!active.has(s.rel)) continue;
    const x = recordsOf(p.filteredDir, s.rel);
    targets.note_locks += x.locks;
    if (!STRUCTURED_ORIGINS.has(s.origin)) continue;
    for (const rec of x.records) {
      const k = `${recordUri(IMPORT_URI_PREFIX, project, rec)} ${recordSha256(rec)}`;
      if (seen.has(k)) continue; // the same record through two inputs: written once
      seen.add(k);
      items.push({ record: rec, project });
    }
  }
  let structuredRunId: number | null = null;
  if (items.length) {
    structuredRunId = await openRun(db, { importer: STRUCTURED_IMPORTER, host: o.host ?? defaultHost(), mode: 'manual' });
    try {
      const w = await writeStructured(db, items, { scope, sourceKind: 'manual', uriPrefix: IMPORT_URI_PREFIX, runId: structuredRunId, route,
        // OD5: Northbank product records only by a clean scan, never through wall_allow pins (as its notes).
        wall: scope === 'product' ? compileWall((await loadWall(db)).rules, []) : await loadWall(db) });
      Object.assign(structured, w);
      await closeRun(db, structuredRunId, w.conflict > 0 || w.unknown_person > 0 ? 'ok_partial' : 'ok', w);
    } catch {
      await closeRun(db, structuredRunId, 'failed', { ...structured, failure: 'structured write failed' }).catch(() => {});
      return { status: 'failed', runId: r.runId, structuredRunId, notes, targets, structured, error: 'structured write failed (database error); notes were imported, re-run to resume' };
    }
  }
  targets.decisions = structured.decisions_inserted;
  targets.rules = structured.rules_inserted;
  targets.focus = structured.focus_inserted;
  const partial = structured.conflict > 0 || structured.unknown_person > 0;
  return { status: partial ? 'ok_partial' : 'ok', runId: r.runId, structuredRunId, notes, targets, structured };
}

// ---------------------------------------------------------------------------
// Output: counts and placeholders only.

const kinds = (m: Record<string, number>) => Object.entries(m).sort().map(([k, v]) => `${k} ${v}`).join(' / ') || 'none';
const skipLine = (s: InputCounts['skipped']) => Object.entries(s).filter(([, v]) => v > 0).map(([k, v]) => `${k} ${v}`).join(', ') || 'none';

export function formatPreview(p: ImportPreview): string {
  const L = [`import preview (dry run: offline, no database connection, nothing written): scope ${p.scope}, project folder ${p.project}`];
  p.inputs.forEach((c, i) => L.push(`  input #${i + 1} ${c.kind}: items ${c.items_seen}, notes staged ${c.notes_staged}, deduped ${c.deduped}, skipped ${skipLine(c.skipped)}`));
  const f = p.filter;
  L.push(`  withheld (export filter, same as nightly): entries ${f.entries_withheld} (plankiva-class ${f.withheld_by_signal.plankiva}, requests ${f.withheld_by_signal.requests}, credential ${f.withheld_by_signal.credential}), files dropped ${f.files_dropped}, output gate hits ${f.gate_hits}`);
  L.push(`  quarantined (importer wall: secrets, credentials, IBAN / account numbers, walled terms): notes ${p.importer.quarantined} (path-gated ${p.importer.path_gated}), structured entries ${p.structured.would_quarantine}, headed entries withheld by the secret detector ${p.structured.secret} (notes only, redacted)`);
  L.push(`  errors: ${p.importer.errors}`);
  const t = p.targets;
  L.push(`  would insert: notes ${t.notes}, chunks ${t.chunks}, rules ${t.rules} (+ note lock items ${t.note_locks}, read as rules), focus ${t.focus}, decisions ${t.decisions} (${kinds(t.decisions_by_kind)})`);
  const s = p.structured;
  L.push(`  structured entries: H2 entries ${s.entries} (of them without a header, notes only ${s.unstructured}; invalid header, notes only ${s.invalid}), same record via two inputs ${s.duplicate_in_run} (counted once), people handles named ${s.handles_named}`);
  L.push('  deduped / unknown_person / conflict against the database: checked on the real run only (the dry run makes no connection)');
  if (p.error) L.push(`  REFUSED: ${p.error}`);
  return L.join('\n');
}

export function formatRealResult(r: ImportRealResult): string {
  const n = r.notes;
  const s = r.structured;
  const t = r.targets;
  const L = [`import: status ${r.status}${r.runId !== null ? ` (ingest run ${r.runId}${r.structuredRunId !== null ? `, structured run ${r.structuredRunId}` : ''})` : ''}`];
  L.push(`  notes: inserted ${n.inserted}, updated ${n.updated}, resumed / unchanged ${n.skipped}, quarantined ${n.quarantined} (trigger backstop ${n.backstop}), errors ${n.errors}, chunks ${n.chunks_written}`);
  L.push(`  note lock items now readable as rules: ${t.note_locks}`);
  L.push(`  inserted: decisions ${s.decisions_inserted}, rules ${s.rules_inserted}, focus ${s.focus_inserted}`);
  L.push(`  deduped ${s.deduped}, unknown_person ${s.unknown_person} (skipped; add the person first: zeusi people add ...), conflict ${s.conflict} (an edited entry; refused, nothing updated), quarantined ${s.quarantined}, secret withheld ${s.secret_withheld}`);
  L.push(`  decision links (0013): inserted ${s.links_inserted}, quarantined ${s.links_quarantined}, skipped ${s.links_skipped} (0013 not applied), invalid ${s.links_invalid}`);
  if (r.error) L.push(`  ERROR: ${r.error}`);
  return L.join('\n');
}

/** Machine-readable preview: counts only (the same numbers as formatPreview). */
export function previewJson(p: ImportPreview) {
  return { dry_run: true, ...p };
}

export { ImportInputError };
