// Fix PR B (lanes DIG-startup-links.md D1-focus / D1-decisions, "2. Decisions and focus from the
// HQ export"): `ingest hq-sync` extracts explicitly headed entries of HQ export notes into
// zeusi.decisions and zeusi.facts (rule / state) with the SAME parser and writer as onboarding
// (src/importers/structured.ts). No second copy of the header grammar lives here.
//
// Order (unchanged gates first): the routine's output went through `zeusi export-filter`
// (secret / credential scrub, the Plankiva exclusion, quarantine); importVault with
// HQ_PROFILE then admitted the note (path gate, content wall, zeusi_90_wall trigger). Only an
// ADMITTED note is read here:
//   * dry run: the importer's in-memory 'admitted' observations (no database, zero writes);
//   * real run: the active hq: notes as stored (the body the wall admitted), read as zeusi_ingest.
// Every record is checked again with the live wall before its insert, and the trigger is the
// backstop; a blocked record is quarantined by uri and hash only.
//
// Note kind decides the record type: a `decision` note yields decision rows only, a `memory` note
// yields fact rows only (`Type: rule` -> rule, `Type: focus` -> state); a record of the other type
// is counted invalid. chat / journal notes are never parsed (notes only). invent=NO: an entry
// without the header block stays a note (counted unstructured); nothing is classified from text.
//
// Scope: the note's scope, which comes from the source config (sources.toml) and the folder
// mapping only. No header key can set or widen a scope.
//
// Retirement (`Type: retire`, or superseding an older focus / rule) is NOT done: zeusi_ingest has
// no EXECUTE on zeusi.supersede_fact. That needs migration 0013-a (one GRANT), owner GO; until
// then a newer focus is inserted next to the older one and startup lists the newest first.
//
// Counts only leave this module: never a path, a title, a handle or text.

import type { Db } from '../db.ts';
import { closeRun, openRun } from '../facts.ts';
import { tryLockImporter, unlockImporter } from '../ingest-run.ts';
import { compileWall, loadWall, type Wall } from '../wall.ts';
import type { VaultDryRunObservation } from './vault.ts';
import {
  emptyParseCounts, emptyWriteCounts, parseStructuredBody, recordRow, recordSha256, recordUri, writeStructured,
  type StructuredParseCounts, type StructuredRecord, type StructuredWriteCounts,
} from './structured.ts';

/** ingest_runs.importer (and advisory-lock key) of the structured rows of hq-sync. */
export const HQ_STRUCTURED_IMPORTER = 'hq-sync-structured';
/** source_uri prefix: `hq:<project>/entry/<16 hex>` (recordUri). */
export const HQ_STRUCTURED_URI_PREFIX = 'hq:';
export const HQ_STRUCTURED_SOURCE_KIND = 'zeus_memory' as const;
const SCOPES = ['work', 'product', 'client'] as const;
type Scope = (typeof SCOPES)[number];

/** Note kinds that may carry headed entries, and the record type each one may yield. */
const KIND_TYPE: Readonly<Record<string, StructuredRecord['type']>> = { decision: 'decision', memory: 'fact' };

export interface HqStructuredCounts extends StructuredParseCounts {
  /** decision + memory notes read. */
  notes: number;
  decisions: number;
  decisions_by_kind: Record<string, number>;
  rules: number;
  focus: number;
  /** The same record (uri + sha) in two notes of one run: counted once. */
  duplicate_in_run: number;
  /** Distinct `who` handles of the would-insert records (dry run: the people that must exist). */
  handles_named: number;
}

function emptyCounts(): HqStructuredCounts {
  return { ...emptyParseCounts(), notes: 0, decisions: 0, decisions_by_kind: {}, rules: 0, focus: 0, duplicate_in_run: 0, handles_named: 0 };
}

export interface HqNoteInput {
  /** `<project>/<file>` (the HQ layout already checked by hqFormatProblem). */
  rel: string;
  scope: string;
  kind: string | null;
  body: string;
}

interface Item {
  record: StructuredRecord;
  project: string;
  scope: Scope;
}

/** Parse the admitted decision / memory notes; records of the wrong type for the note kind count invalid. */
export function collectHqRecords(notes: readonly HqNoteInput[]): { items: Item[]; counts: HqStructuredCounts } {
  const counts = emptyCounts();
  const items: Item[] = [];
  const seen = new Set<string>();
  for (const n of [...notes].sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0))) {
    const want = n.kind === null ? undefined : KIND_TYPE[n.kind];
    if (want === undefined) continue; // chat / journal: notes only
    if (!(SCOPES as readonly string[]).includes(n.scope)) continue; // never personal
    const project = n.rel.split('/')[0] ?? '';
    if (project === '' || n.rel.split('/').length !== 2) continue;
    counts.notes++;
    const p = parseStructuredBody(n.body);
    counts.entries += p.counts.entries;
    counts.unstructured += p.counts.unstructured;
    counts.invalid += p.counts.invalid;
    counts.secret += p.counts.secret;
    for (const record of p.records) {
      if (record.type !== want) {
        counts.invalid++;
        continue;
      }
      const k = `${recordUri(HQ_STRUCTURED_URI_PREFIX, project, record)} ${recordSha256(record)}`;
      if (seen.has(k)) {
        counts.duplicate_in_run++;
        continue;
      }
      seen.add(k);
      items.push({ record, project, scope: n.scope as Scope });
    }
  }
  return { items, counts };
}

function countRecord(c: HqStructuredCounts, r: StructuredRecord): void {
  if (r.type === 'decision') {
    c.decisions++;
    c.decisions_by_kind[r.kind] = (c.decisions_by_kind[r.kind] ?? 0) + 1;
  } else if (r.factKind === 'rule') c.rules++;
  else c.focus++;
}

/** The note inputs of a dry run, from importVault's in-memory 'admitted' observations. */
export function hqNoteFromObservation(o: VaultDryRunObservation): HqNoteInput | null {
  if (o.outcome !== 'admitted') return null;
  const fm = o.note['frontmatter'] as Record<string, unknown> | undefined;
  const kind = typeof fm?.['kind'] === 'string' ? fm['kind'] : null;
  const body = typeof o.note['body'] === 'string' ? o.note['body'] : '';
  return { rel: o.rel, scope: o.scope, kind, body };
}

export interface HqStructuredPreview {
  counts: HqStructuredCounts;
  /** Records the (seed) wall would quarantine. */
  would_quarantine: number;
}

/** Dry run: counts only, offline (no database). */
export function previewHqStructured(notes: readonly HqNoteInput[], wall: Wall): HqStructuredPreview {
  const { items, counts } = collectHqRecords(notes);
  let would_quarantine = 0;
  const handles = new Set<string>();
  for (const it of items) {
    const uri = recordUri(HQ_STRUCTURED_URI_PREFIX, it.project, it.record);
    const sha = recordSha256(it.record);
    const v = wall.check(it.record.type === 'decision' ? 'decisions' : 'facts', recordRow(it.record, uri, it.scope, HQ_STRUCTURED_SOURCE_KIND, sha));
    if (v.blocked) {
      would_quarantine++;
      continue;
    }
    handles.add(it.record.who);
    countRecord(counts, it.record);
  }
  counts.handles_named = handles.size;
  return { counts, would_quarantine };
}

export interface HqStructuredResult {
  status: 'ok' | 'ok_partial' | 'failed' | 'locked';
  runId: number | null;
  parse: HqStructuredCounts;
  write: StructuredWriteCounts;
  error?: string;
}

/** The active hq: decision / memory notes as stored (the bodies the wall admitted). */
export async function readAdmittedHqNotes(db: Db): Promise<HqNoteInput[]> {
  const rows = (await db.query<{ vault_path: string; scope: string; kind: string | null; body: string }>(
    `SELECT vault_path, scope::text AS scope, frontmatter->>'kind' AS kind, body FROM zeusi.notes
     WHERE source_kind = 'zeus_memory'::zeusi.source_kind AND status = 'active' AND left(vault_path, 3) = 'hq:'
       AND frontmatter->>'kind' IN ('decision', 'memory')
     ORDER BY vault_path`)).rows;
  return rows.map((r) => ({ rel: r.vault_path.slice(3), scope: r.scope, kind: r.kind, body: r.body }));
}

/**
 * Real run (after a successful importVault with HQ_PROFILE, same zeusi_ingest connection):
 * insert the headed records of every active hq: decision / memory note. Idempotent (dedupe on
 * (source_uri, source_sha256)); resumable (a skipped unknown_person entry is written on a later
 * run once the person exists). Never UPDATE, never creates people.
 */
export async function extractHqStructured(db: Db, o: { mode: 'full' | 'incremental'; host: string }): Promise<HqStructuredResult> {
  const write = emptyWriteCounts();
  if (!(await tryLockImporter(db, HQ_STRUCTURED_IMPORTER))) {
    return { status: 'locked', runId: null, parse: emptyCounts(), write, error: 'another hq-sync structured run holds the lock; nothing written' };
  }
  let runId: number | null = null;
  try {
    const { items, counts } = collectHqRecords(await readAdmittedHqNotes(db));
    if (items.length === 0) return { status: 'ok', runId: null, parse: counts, write };
    runId = await openRun(db, { importer: HQ_STRUCTURED_IMPORTER, host: o.host, mode: o.mode });
    const wall = await loadWall(db);
    for (const scope of SCOPES) {
      const mine = items.filter((it) => it.scope === scope);
      if (mine.length === 0) continue;
      // OD5: Northbank product content is admitted only by a clean scan, never through wall_allow pins (as its notes).
      const w = await writeStructured(db, mine, {
        scope, sourceKind: HQ_STRUCTURED_SOURCE_KIND, uriPrefix: HQ_STRUCTURED_URI_PREFIX, runId,
        wall: scope === 'product' ? compileWall(wall.rules, []) : wall,
      });
      for (const k of Object.keys(write) as Array<keyof StructuredWriteCounts>) write[k] += w[k];
    }
    const status = write.conflict > 0 || write.unknown_person > 0 ? 'ok_partial' : 'ok';
    await closeRun(db, runId, status, { ...counts, ...write });
    return { status, runId, parse: counts, write };
  } catch {
    if (runId !== null) await closeRun(db, runId, 'failed', { ...write, failure: 'structured write failed' }).catch(() => {});
    return { status: 'failed', runId, parse: emptyCounts(), write, error: 'structured write failed (database error); notes were ingested, re-run to resume' };
  } finally {
    await unlockImporter(db, HQ_STRUCTURED_IMPORTER).catch(() => {});
  }
}

const byKind = (m: Record<string, number>): string => Object.entries(m).sort().map(([k, v]) => `${k} ${v}`).join(' / ') || 'none';

/** Dry-run preview lines (counts only). */
export function formatHqStructuredPreview(p: HqStructuredPreview): string {
  const c = p.counts;
  return [
    `  structured entries (decision / memory notes ${c.notes}, H2 entries ${c.entries}):`,
    `    would insert: decisions ${c.decisions} (${byKind(c.decisions_by_kind)}), facts rule ${c.rules} / state (focus) ${c.focus}`,
    `    unstructured ${c.unstructured} (no header: notes only), invalid ${c.invalid} (bad header: notes only), would quarantine ${p.would_quarantine}, secret ${c.secret} (secret detector: notes only), same record twice ${c.duplicate_in_run}`,
    `    people handles named ${c.handles_named} (each must exist in zeusi.people; else unknown_person on the real run)`,
    '    deduped / unknown_person / conflict: checked on the real run only (the dry run makes no connection)',
  ].join('\n');
}

/** Real-run lines (counts only). */
export function formatHqStructuredResult(r: HqStructuredResult): string {
  const w = r.write;
  const c = r.parse;
  const L = [`hq-sync structured: status ${r.status}${r.runId !== null ? ` (ingest run ${r.runId})` : ''}`];
  if (r.status === 'locked') {
    L.push(`  ${r.error ?? 'locked'}`);
    return L.join('\n');
  }
  L.push(`  notes read ${c.notes}, H2 entries ${c.entries}, unstructured ${c.unstructured}, invalid ${c.invalid}, secret ${c.secret} (secret detector: notes only)`);
  L.push(`  inserted: decisions ${w.decisions_inserted}, facts rule ${w.rules_inserted} / state (focus) ${w.focus_inserted}`);
  L.push(`  deduped ${w.deduped}, unknown_person ${w.unknown_person} (skipped; zeusi people add first), conflict ${w.conflict} (an edited entry; refused, nothing updated), quarantined ${w.quarantined}, secret withheld ${w.secret_withheld}`);
  L.push(`  decision links (0013): inserted ${w.links_inserted}, quarantined ${w.links_quarantined}, skipped ${w.links_skipped} (0013 not applied), invalid ${w.links_invalid}`);
  if (r.error) L.push(`  FAILED: ${r.error}`);
  return L.join('\n');
}
