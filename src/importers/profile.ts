// Import profiles for the note importer (src/importers/vault.ts).
//
// One importer, two source families, the SAME gates (path gate, content gate, trigger
// backstop, deletion guard, advisory lock, ingest_runs):
//   * VAULT_PROFILE: KnowledgeVault notes (U5). Unchanged behaviour.
//   * HQ_PROFILE: the Zeus HQ export folder (docs/hq-sync.md): HQ chat, project
//     histories, journal and Zeus memory, written nightly as dated markdown notes and
//     cleaned by `zeusi export-filter`. source_kind zeus_memory (0001; no migration),
//     uri scheme `hq:`, vault_path `hq:<project>/<file>` (the UNIQUE column is shared
//     with vault notes; VAULT_PROFILE refuses a vault path starting with `hq:`), its own
//     importer name `hq-sync` (own lock, own ingest_runs rows: KTD13 freshness per importer).
//     The `clientco/` folder is admitted only through its own scope client source (hqScopeProblem).
//   * IMPORT_PROFILE: first-run onboarding (`zeusi import`, src/import-run.ts). The staged and
//     export-filtered HQ layout, source_kind manual (0001; no migration), uri scheme `import:`,
//     its own importer name `onboard-import`, and `deletes: false`: one import never marks the
//     notes of an earlier import deleted.

import type { Frontmatter } from './vault.ts';

export interface ImportProfile {
  /** ingest_runs.importer and the advisory-lock key. */
  importer: string;
  /** Human label for messages (never a path). */
  label: string;
  sourceKind: 'vault_note' | 'zeus_memory' | 'manual';
  /** source_uri scheme: `<scheme>:<rel>`, chunks `<scheme>:<rel>#c<n>`. */
  scheme: 'vault' | 'hq' | 'import';
  /** Prefix of zeusi.notes.vault_path for this profile ('' for the vault). */
  storedPrefix: string;
  /** A format problem (safe text: no content, no path) or null. */
  formatProblem?: (rel: string, fm: Frontmatter | null, project: string | null) => string | null;
  /**
   * A scope problem (safe text) or null, checked before the file is opened. `sourceScopes`
   * are the scopes of the sources whose globs match the file.
   */
  scopeProblem?: (rel: string, scope: string, sourceScopes: readonly string[]) => string | null;
  /**
   * Mark this profile's notes that are no longer in the source deleted (and run the deletion
   * guard). Default true (vault, hq-sync: unchanged). false for imports: each run adds, never removes.
   */
  deletes?: boolean;
}

/**
 * vault_path prefixes other profiles store under (fix round 1, m7). A vault file whose
 * relative path starts with one (a folder named `hq:x`, legal on APFS) is a per-file
 * error, so it can never hit ON CONFLICT (vault_path) on another profile's row.
 */
export const RESERVED_VAULT_PREFIXES = ['hq:', 'import:'] as const;

export function vaultFormatProblem(rel: string): string | null {
  const lower = rel.toLowerCase();
  return RESERVED_VAULT_PREFIXES.some((p) => lower.startsWith(p)) ? `vault: relative path starts with a reserved prefix (${RESERVED_VAULT_PREFIXES.join(', ')})` : null;
}

export const VAULT_PROFILE: ImportProfile = {
  importer: 'vault', label: 'vault', sourceKind: 'vault_note', scheme: 'vault', storedPrefix: '',
  formatProblem: (rel) => vaultFormatProblem(rel),
};

/** Entry kinds of an HQ export note (frontmatter `kind`). */
export const HQ_KINDS = ['chat', 'journal', 'memory', 'decision'] as const;
export type HqKind = (typeof HQ_KINDS)[number];
/** Project folder names: lower-case slug. */
export const HQ_PROJECT_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
/** Export file names: YYYY-MM-DD-<slug>.md. */
export const HQ_FILE_RE = /^(\d{4}-\d{2}-\d{2})-([a-z0-9]+(?:-[a-z0-9]+)*)\.md$/;

function realDay(s: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null);

/**
 * HQ export layout check: `<project>/YYYY-MM-DD-<slug>.md`, frontmatter with
 * `project` == folder (== the source's `project` when set), `kind` in HQ_KINDS,
 * `date` == the file-name date, a `source` and a `title`. Returns a safe reason.
 */
export function hqFormatProblem(rel: string, fm: Frontmatter | null, project: string | null): string | null {
  const parts = rel.split('/');
  if (parts.length !== 2) return 'hq export: not <project>/<file>';
  const [folder, file] = parts as [string, string];
  if (!HQ_PROJECT_RE.test(folder)) return 'hq export: project folder is not a slug';
  const m = HQ_FILE_RE.exec(file);
  if (!m || !realDay(m[1]!)) return 'hq export: file name is not YYYY-MM-DD-<slug>.md';
  if (project !== null && project !== folder) return 'hq export: folder differs from the source project';
  if (fm === null) return 'hq export: no frontmatter';
  if (str(fm['project']) !== folder) return 'hq export: frontmatter project differs from the folder';
  const kind = str(fm['kind']);
  if (kind === null || !(HQ_KINDS as readonly string[]).includes(kind)) return 'hq export: kind is not chat|journal|memory|decision';
  if (str(fm['date']) !== m[1]) return 'hq export: frontmatter date differs from the file name';
  if (str(fm['title']) === null) return 'hq export: title missing';
  if (str(fm['source']) === null) return 'hq export: source missing';
  return null;
}

/**
 * ClientCo (the owner: ClientCo goes into Zeusi with its own scope): an HQ note of the
 * `clientco/` folder is admitted ONLY through a configured scope "client" source, and only with scope
 * client; a clientco/ note matched by any other source (a wide glob) is refused, never stored under
 * team or product. The Plankiva exclusion and every hard wall rule still apply after this.
 */
export function hqScopeProblem(rel: string, scope: string, sourceScopes: readonly string[]): string | null {
  const clientcoFolder = (rel.split('/')[0] ?? '').toLowerCase() === 'clientco';
  if (!clientcoFolder && scope !== 'client') return null;
  if (clientcoFolder && scope === 'client' && sourceScopes.includes('client')) return null;
  return 'hq export: the clientco folder is admitted only through its own scope client source';
}

export const HQ_PROFILE: ImportProfile = {
  importer: 'hq-sync', label: 'hq-sync', sourceKind: 'zeus_memory', scheme: 'hq', storedPrefix: 'hq:',
  formatProblem: hqFormatProblem,
  scopeProblem: hqScopeProblem,
};

/** First-run onboarding imports (`zeusi import`): the HQ layout and gates, source_kind manual, never deletes. */
export const IMPORT_PROFILE: ImportProfile = {
  importer: 'onboard-import', label: 'import', sourceKind: 'manual', scheme: 'import', storedPrefix: 'import:',
  formatProblem: hqFormatProblem,
  scopeProblem: hqScopeProblem,
  deletes: false,
};
