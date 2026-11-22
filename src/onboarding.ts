// First-run onboarding status (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md U6, KTD9; counts
// made consistent with zeusi_startup by the "Lock lifecycle" addendum, K3).
//
// ONE definition of "rule" (rulesDefinition below, shared with zeusi_startup): fact rules
// (facts_current kind rule) plus the CURRENT lock items of the standing notes (after explicit
// supersession and expiry, src/lock-lifecycle.ts). `rules_by_origin` splits the two. `note_locks`
// stays every lock item of every active note; note_locks_current / _superseded / _expired
// partition it.
//
// zeusi_onboarding_status (alias onboarding_status) is READ-ONLY. It counts, as the caller's
// read-only login inside BEGIN READ ONLY (so RLS decides what is visible), how many current
// facts (and of them rules and focus), active notes, note lock items, chunks and current
// decisions exist, optionally narrowed to one scope. Each count runs over a LIMIT CAP+1 subquery,
// so it never scans more than CAP+1 rows and reports `capped` when the real number is larger.
// It returns no row text, no title and no source_uri of a content row. The built-in about entry
// (src/about.ts) is code, not a row, so it is never counted.
//
// A connector cannot run the import for the user: `next` lists the CLI commands (dry run first)
// the user runs locally (src/import-run.ts, `zeusi onboard` / `zeusi import`).

import type { Db } from './db.ts';
import { lockLifecycle } from './lock-lifecycle.ts';
import { currentStandingLocks } from './note-locks.ts';
import { ABOUT_URI, fillMemoryLine, RECONNECT_TO_FILL, SOURCES_OF_RULES_FACTS_FOCUS } from './about.ts';

/** Every count stops at this many (reported as CAP with capped[key] = true). */
export const ONBOARDING_COUNT_CAP = 10_000;

export const ONBOARDING_COUNT_KEYS = [
  'facts', 'rules', 'focus', 'notes', 'note_locks', 'note_locks_current', 'note_locks_superseded', 'note_locks_expired', 'chunks', 'decisions',
] as const;
/** Counted with a LIMIT CAP+1 subquery each. The rest come from the lock resolver (LOCK_NOTES_CAP notes). */
const SQL_COUNT_KEYS = ['facts', 'focus', 'notes', 'note_locks', 'chunks', 'decisions'] as const;
export type OnboardingCountKey = (typeof ONBOARDING_COUNT_KEYS)[number];

/** The one honest sentence every onboarding surface carries (tool, prompt, instructions, docs). */
export const CANNOT_RUN_IT =
  'A connector cannot force a model to run anything, and Zeusi cannot run the import for you: to onboard, the user runs `zeusi onboard` locally.';

/** The commands a user runs locally, dry run (preview) first. Placeholders only, never a real path. */
export const ONBOARDING_COMMANDS: readonly string[] = [
  'zeusi onboard --markdown <notes-folder> --scope work',
  'zeusi onboard --decision-log <decisions.md|decisions.jsonl> --scope work',
  'zeusi onboard --claude-export <conversations.json> --chatgpt-export <conversations.json> --git <repo> --scope work',
];

export const ONBOARDING_NEXT = {
  commands: ONBOARDING_COMMANDS,
  then: '`zeusi onboard` only previews (counts, no database connection, nothing written) and prints the exact `zeusi import ... --real` command to run next, after review.',
  filters: 'Every input passes the same filters as the nightly export: secrets, credentials and 2FA codes are withheld, the walled person is excluded entirely, IBAN and account numbers are quarantined. Names, emails and phone numbers are NOT detected: review your input first.',
  honesty: CANNOT_RUN_IT,
} as const;

/** One count expression per key. `$1` is the optional scope (NULL = every scope the caller can see). */
const COUNT_SQL: Record<(typeof SQL_COUNT_KEYS)[number] | 'fact_rules', string> = {
  facts: `SELECT 1 FROM zeusi.facts_current WHERE ($1::text IS NULL OR scope::text = $1::text)`,
  fact_rules: `SELECT 1 FROM zeusi.facts_current WHERE kind = 'rule' AND ($1::text IS NULL OR scope::text = $1::text)`,
  focus: `SELECT 1 FROM zeusi.facts_current WHERE kind = 'state' AND ($1::text IS NULL OR scope::text = $1::text)`,
  notes: `SELECT 1 FROM zeusi.notes WHERE status = 'active' AND ($1::text IS NULL OR scope::text = $1::text)`,
  note_locks: `SELECT 1 FROM zeusi.notes n CROSS JOIN LATERAL jsonb_array_elements_text(
                 CASE jsonb_typeof(n.frontmatter->'locks') WHEN 'array' THEN n.frontmatter->'locks'
                      WHEN 'string' THEN jsonb_build_array(n.frontmatter->'locks') ELSE '[]'::jsonb END) AS l(item)
               WHERE n.status = 'active' AND n.frontmatter ? 'locks' AND btrim(l.item) <> ''
                 AND ($1::text IS NULL OR n.scope::text = $1::text)`,
  chunks: `SELECT 1 FROM zeusi.chunks WHERE ($1::text IS NULL OR scope::text = $1::text)`,
  decisions: `SELECT 1 FROM zeusi.decisions_current WHERE ($1::text IS NULL OR scope::text = $1::text)`,
};

export interface OnboardingStatus {
  empty: boolean;
  scope: string | null;
  counts: Record<OnboardingCountKey, number>;
  capped: Record<OnboardingCountKey, boolean>;
  /** rules = fact + note_lock (the set zeusi_startup serves, before its cap). */
  rulesByOrigin: { fact: number; note_lock: number };
  cap: number;
}

/**
 * The ONE emptiness rule (zeusi_onboarding_status `empty` and zeusi_startup's personal `empty`):
 * nothing a model could cite, i.e. no current fact, active note, chunk or current decision (note
 * locks live in notes; rules and focus are facts or note locks). Both surfaces call emptinessCounts,
 * so they can never disagree again (live finding 2026-11-18: startup ignored imported notes).
 */
export const EMPTINESS_KEYS = ['facts', 'notes', 'chunks', 'decisions'] as const;
export type EmptinessKey = (typeof EMPTINESS_KEYS)[number];
export interface Emptiness {
  empty: boolean;
  counts: Record<EmptinessKey, number>;
  capped: Record<EmptinessKey, boolean>;
}

/** One capped count (LIMIT cap+1 subquery): never scans more than cap+1 rows. */
async function cappedCount(db: Db, sql: string, scope: string | null, cap: number): Promise<{ n: number; capped: boolean }> {
  const r = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM (${sql} LIMIT $2::int) AS x`, [scope, cap + 1]);
  const n = Number(r.rows[0]?.n ?? 0);
  return { n: Math.min(n, cap), capped: n > cap };
}

/** The emptiness counts, inside the caller's read-only transaction (RLS decides what is visible). */
export async function emptinessCounts(db: Db, scope: string | null, cap: number = ONBOARDING_COUNT_CAP): Promise<Emptiness> {
  const counts = {} as Record<EmptinessKey, number>;
  const capped = {} as Record<EmptinessKey, boolean>;
  for (const key of EMPTINESS_KEYS) {
    const c = await cappedCount(db, COUNT_SQL[key], scope, cap);
    counts[key] = c.n;
    capped[key] = c.capped;
  }
  return { empty: EMPTINESS_KEYS.every((k) => counts[k] === 0), counts, capped };
}

/**
 * The note_locks count rule on in-memory values (C7 sealed route, docs/plans/2026-11-19-c7-read-path.md KTD10):
 * exactly COUNT_SQL.note_locks for one note's `locks` frontmatter value (an array: its elements; a string: one
 * item; anything else: none; an element counts unless it is JSON null or a string that is blank after
 * btrim's space-only trim). The SQL stays the plain route's rule; test/c7-parity.test.ts pins the two equal.
 */
export function noteLockItemCount(locks: unknown): number {
  const items = Array.isArray(locks) ? locks : typeof locks === 'string' ? [locks] : [];
  return items.filter((x) => x !== null && !(typeof x === 'string' && x.replace(/^ +| +$/g, '') === '')).length;
}

/** C7: what the sealed route supplies instead of the two content reads (the counts stay this function's). */
export interface OnboardingContentSource {
  /** COUNT_SQL.note_locks, capped like cappedCount (n = min(count, cap), capped = count > cap). */
  noteLockItems: (scope: string | null, cap: number) => Promise<{ n: number; capped: boolean }>;
  lockLifecycle: (now: Date) => ReturnType<typeof lockLifecycle>;
}

/**
 * Counts only, inside the caller's read-only transaction (the caller opens BEGIN READ ONLY and
 * checks the session). `cap` is a test seam (default ONBOARDING_COUNT_CAP); `now` decides expiry.
 * `content` (C7 sealed route only): the note_locks count and the lock lifecycle from opened values; every
 * other count is the same metadata SQL on both routes. Omitted: today's SQL, unchanged.
 */
export async function onboardingCounts(
  db: Db, scope: string | null, cap: number = ONBOARDING_COUNT_CAP, now: Date = new Date(), content?: OnboardingContentSource,
): Promise<OnboardingStatus> {
  const counts = {} as Record<OnboardingCountKey, number>;
  const capped = {} as Record<OnboardingCountKey, boolean>;
  const sqlCount = (sql: string) => cappedCount(db, sql, scope, cap);
  const e = await emptinessCounts(db, scope, cap);
  for (const key of SQL_COUNT_KEYS) {
    const c = (EMPTINESS_KEYS as readonly string[]).includes(key)
      ? { n: e.counts[key as EmptinessKey], capped: e.capped[key as EmptinessKey] }
      : key === 'note_locks' && content ? await content.noteLockItems(scope, cap)
        : await sqlCount(COUNT_SQL[key]);
    counts[key] = c.n;
    capped[key] = c.capped;
  }
  const factRules = await sqlCount(COUNT_SQL.fact_rules);
  // Lock items through the one resolver (RLS-visible notes; supersession and expiry applied).
  const lc = content ? await content.lockLifecycle(now) : await lockLifecycle(db, now);
  const inScope = lc.locks.filter((l) => scope === null || l.scope === scope);
  const by = (st: string) => inScope.filter((l) => l.status === st).length;
  const standing = currentStandingLocks(inScope).length;
  const clamp = (k: OnboardingCountKey, n: number, extraCapped = false) => {
    counts[k] = Math.min(n, cap);
    capped[k] = n > cap || extraCapped || lc.capped;
  };
  clamp('note_locks_current', by('current'));
  clamp('note_locks_superseded', by('superseded'));
  clamp('note_locks_expired', by('expired'));
  const rulesByOrigin = { fact: factRules.n, note_lock: Math.min(standing, cap) };
  clamp('rules', factRules.n + standing, factRules.capped);
  // Empty = nothing a model could cite (EMPTINESS_KEYS; the same rule zeusi_startup uses).
  const empty = e.empty;
  const ordered = <T>(m: Record<OnboardingCountKey, T>) => Object.fromEntries(ONBOARDING_COUNT_KEYS.map((k) => [k, m[k]])) as Record<OnboardingCountKey, T>;
  return { empty, scope, counts: ordered(counts), capped: ordered(capped), rulesByOrigin, cap };
}

/** The one definition of "rule" every surface uses (zeusi_startup serves exactly this set, capped). */
export const RULES_DEFINITION =
  'rules = fact rules (facts_current kind rule) + the CURRENT lock items of the standing notes (Work/ops/, Work/handbook/, or a lock its note '
  + 'marks with standing_locks:), after explicit supersession and expiry. zeusi_startup returns every one: served (compact, ranked, within a token '
  + 'budget) or listed in rules_remainder with id, subject and cite. '
  + 'note_locks counts every lock item of every active note; note_locks_current + note_locks_superseded + note_locks_expired = note_locks.';

/** Why focus is empty (said, never filled in). */
export const FOCUS_EMPTY_WHY =
  'No current focus recorded in Zeusi for this connection. Focus comes only from typed focus entries (Type: focus): the HQ sync, once its routine '
  + 'exports the typed Focus block and that export is ingested, or a `zeusi import` of headed entries. None has been ingested, so focus is empty. '
  + 'That does not mean there is no focus: ask the owner what the current focus is if it matters for the work.';

/**
 * Said on every personal-workspace onboarding surface (open sign-up, docs/plans/2026-11-18-open-signup-workspaces-plan.md
 * R17): what the workspace is, that it starts empty, and that importing into it is not available yet.
 */
/** The same note when filling IS available on this connection (KTD9). */
export const PERSONAL_WORKSPACE_NOTE_FILL =
  'This connection reads one personal workspace. It is separate from every other Zeusi workspace (no other workspace\'s rules, notes or decisions are visible here) and it starts empty. '
  + 'You can fill it from here: zeusi_import_preview shows what would be saved (nothing is saved), and only after the user says yes does zeusi_import_commit save exactly that preview.';
/** Fill-your-memory steps for the assistant (form B surfaces). */
export const FILL_STEPS =
  'To fill it: ask the user for their notes (pasted text, a decision log, or a Claude / ChatGPT export), call zeusi_import_preview, show the user the counts and items, '
  + 'and call zeusi_import_commit with that preview_id and confirm: true only after they clearly say yes. For a nightly sync, their routine calls zeusi_sync_batch.';

export const PERSONAL_WORKSPACE_NOTE =
  'This connection reads one personal workspace. It is separate from every other Zeusi workspace (no other workspace\'s rules, notes or decisions are visible here) and it starts empty. '
  + 'Importing into a hosted personal workspace is not available yet: the zeusi CLI imports into a database the user runs, not into this workspace.';

/** The tool's wire shape: counts, flags and the fixed guidance. No row content of any kind. */
/**
 * `fill`: 'on' = filling is available on this connection (form B); 'reconnect' = this server can fill
 * workspaces but this grant is read-only (upgrade by signing in again); 'off' (default) = form A.
 */
export function onboardingJson(s: OnboardingStatus, workspace: 'team' | 'personal' = 'team', fill: 'on' | 'reconnect' | 'off' = 'off') {
  if (workspace === 'personal') {
    const canFill = fill === 'on';
    return {
      workspace: 'personal' as const, empty: s.empty, scope: s.scope ?? 'all visible', counts: s.counts, rules_by_origin: s.rulesByOrigin, capped: s.capped, cap: s.cap,
      rules_definition: RULES_DEFINITION, sources: SOURCES_OF_RULES_FACTS_FOCUS,
      ...(s.counts.focus === 0 ? { focus_message: FOCUS_EMPTY_WHY } : {}),
      message: s.empty
        ? 'This personal workspace is empty: no rules, locks, focus, decisions or notes yet, so Zeusi has nothing to cite. That is normal for a new workspace. Say so; never invent rules, focus or decisions.'
        : 'This personal workspace holds items this connection can see.',
      ...(s.empty
        ? { next: canFill
          ? `${fillMemoryLine(true)} ${FILL_STEPS}`
          : `${fillMemoryLine(false)}${fill === 'reconnect' ? ` ${RECONNECT_TO_FILL}` : ''} Meanwhile, ask "What can Zeusi do?" (resource ${ABOUT_URI}).` }
        : canFill ? { next: `Adding more is optional. ${FILL_STEPS}` } : {}),
      workspace_note: canFill ? PERSONAL_WORKSPACE_NOTE_FILL : PERSONAL_WORKSPACE_NOTE,
    };
  }
  return {
    empty: s.empty, scope: s.scope ?? 'all visible', counts: s.counts, rules_by_origin: s.rulesByOrigin, capped: s.capped, cap: s.cap,
    rules_definition: RULES_DEFINITION, sources: SOURCES_OF_RULES_FACTS_FOCUS,
    ...(s.counts.focus === 0 ? { focus_message: FOCUS_EMPTY_WHY } : {}),
    ...(s.empty
      ? { message: 'Zeusi has nothing this connection can see yet. Offer the onboarding prompt: the user imports their history with the zeusi CLI.', next: ONBOARDING_NEXT }
      : { message: 'Zeusi already holds items this connection can see. Importing more is optional (zeusi onboard, dry run first).', honesty: CANNOT_RUN_IT }),
  };
}
