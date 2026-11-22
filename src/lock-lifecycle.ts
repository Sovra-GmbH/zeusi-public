// Lock lifecycle (docs/note-locks.md; plan addendum "Lock lifecycle", K1/K2): explicit, lock-level
// supersession and expiry for the `locks:` items of notes, resolved at READ time from frontmatter.
// No migration, no stored status: the newest note says what it replaces, a lock says until when it
// holds, and every reader (zeusi_startup, zeusi_context_for_task, zeusi_onboarding_status, the
// reparse counts and `zeusi locks lint`) runs the same pure resolver over the same input.
//
// Grammar (flat-parser friendly; one item per list entry):
//
//   supersedes:                                   # list, or one string
//     - "[[<target note>]] lock 2"                # lock 2 of that note
//     - "[[<target note>]]"                       # every lock of that note
//     - "1: [[<target note>]] lock 2"             # ... replaced by MY lock 1 (else: by the note)
//   lock_until:                                   # list, or one string
//     - "1: 2026-10-25T00:00+02:00"               # ISO timestamp WITH offset, end-exclusive
//     - "2: 2026-10-24"                           # a date = end of that day, Europe/Zurich
//   until: 2026-10-24                             # every lock of the note (lock_until wins)
//
// Rules (never guessed, invent=NO):
//   * a target resolves to exactly ONE visible lock note: its vault_path (with or without .md), its
//     file name without .md, or its title, case-insensitive. 0 or >1 matches: supersede_unresolved;
//     so is a `lock N` the target does not have;
//   * the superseding note must be strictly newer (source_ts) than the target, else
//     supersede_invalid (also: malformed item, self reference, an own-ordinal it does not have);
//   * visibility is the caller's: the input is what the caller can read under RLS, so a superseding
//     note the caller cannot see does not exist for it and the old lock stays current;
//   * status precedence: superseded > expired > current; the three partition every lock item;
//   * a lock is expired when now >= until (end-exclusive); an offset-less timestamp is until_invalid.

import type { Db } from './db.ts';

export const LIFECYCLE_KEYS = ['locks', 'supersedes', 'lock_until', 'until'] as const;
/**
 * Explicit standing marker (docs/note-locks.md "Standing marker"): `standing_locks:` lists the
 * ordinals of this note's locks that are standing rules wherever the note lives. Proposed for
 * Northbank notes by `zeusi locks classify` (src/locks-classify.ts), written only by its --real run
 * or by hand. Read with the lifecycle keys; never guessed.
 */
export const STANDING_MARKER_KEY = 'standing_locks';
/** At most this many lifecycle-bearing notes are read per call (newest first); more is reported as capped. */
export const LOCK_NOTES_CAP = 5000;
export const LIFECYCLE_TZ = 'Europe/Zurich';

/** One active note with any lifecycle key, as the caller can see it. */
export interface LockNoteInput {
  noteId: number;
  vaultPath: string;
  title: string;
  scope: string;
  sourceUri: string;
  /** ISO timestamp. */
  sourceTs: string;
  locks: unknown;
  supersedes: unknown;
  lockUntil: unknown;
  until: unknown;
  /** `standing_locks` frontmatter (list of ordinals, or one string); absent = none marked. */
  standingLocks?: unknown;
}

export type LockStatus = 'current' | 'superseded' | 'expired';

/** A compact reference to another lock (the chain is followable both ways). */
export interface LockRef {
  note_title: string;
  /** null: a note-level claim by a note that has no locks of its own. */
  ord: number | null;
  text: string | null;
  source_uri: string;
  source_ts: string;
}

export interface ResolvedLock {
  noteId: number;
  ord: number;
  title: string;
  text: string;
  scope: string;
  sourceUri: string;
  sourceTs: string;
  vaultPath: string;
  status: LockStatus;
  /** Locks this one replaces (direct claims only, oldest first). */
  supersedes: LockRef[];
  /** The newest lock (or note's first lock, for a note-level claim) that replaces this one. */
  supersededBy: LockRef | null;
  /** The lock's until bound (ISO), when one is set and valid. */
  until: string | null;
  /** Its ordinal is listed in the note's `standing_locks` marker. */
  standingMarked: boolean;
}

export interface LifecycleCounts {
  notes: number;
  items: number;
  current: number;
  superseded: number;
  expired: number;
  supersede_claims: number;
  supersede_applied: number;
  supersede_unresolved: number;
  supersede_invalid: number;
  until_set: number;
  until_invalid: number;
  /** Lock items listed in a `standing_locks` marker (any status). */
  standing_marked: number;
  /** `standing_locks` entries that are not an ordinal of the note's locks. */
  standing_marker_invalid: number;
}

export function emptyLifecycleCounts(): LifecycleCounts {
  return {
    notes: 0, items: 0, current: 0, superseded: 0, expired: 0, supersede_claims: 0, supersede_applied: 0, supersede_unresolved: 0,
    supersede_invalid: 0, until_set: 0, until_invalid: 0, standing_marked: 0, standing_marker_invalid: 0,
  };
}

// ---------------------------------------------------------------------------
// Parsing (pure)

/** `locks` as stored: a list (1-based position kept, blanks skipped) or one string (one item). */
export function lockItemsOf(locks: unknown): Array<{ ord: number; text: string }> {
  const arr = Array.isArray(locks) ? locks : typeof locks === 'string' ? [locks] : [];
  const out: Array<{ ord: number; text: string }> = [];
  arr.forEach((v, i) => {
    const t = typeof v === 'string' ? v : v === null || v === undefined ? '' : JSON.stringify(v);
    if (t.trim() !== '') out.push({ ord: i + 1, text: t });
  });
  return out;
}

/** A list or a single string, as strings; anything else none. */
function stringsOf(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => (typeof x === 'string' ? x : JSON.stringify(x)));
  return typeof v === 'string' && v.trim() !== '' ? [v] : [];
}

export interface SupersedeClaim {
  /** The superseding note's own lock ordinal, or null (the note as a whole). */
  ownOrd: number | null;
  /** The wikilink target (no alias, no heading). */
  target: string;
  /** The target lock ordinal, or null (every lock of the target). */
  ord: number | null;
}

const SUPERSEDE_RE = /^\s*(?:(\d{1,4})\s*:\s*)?\[\[([^\]\n]+?)\]\](?:\s+locks?\s+(\d{1,4}))?\s*$/i;

/** One `supersedes` item, or null when malformed. */
export function parseSupersede(s: string): SupersedeClaim | null {
  const m = SUPERSEDE_RE.exec(s);
  if (!m) return null;
  const target = m[2]!.split('|')[0]!.split('#')[0]!.trim();
  if (target === '') return null;
  const ownOrd = m[1] === undefined ? null : Number(m[1]);
  const ord = m[3] === undefined ? null : Number(m[3]);
  if (ownOrd === 0 || ord === 0) return null;
  return { ownOrd, target, ord };
}

/** UTC offset (minutes) of Europe/Zurich at an instant. */
function zurichOffsetMin(at: Date): number {
  const s = new Intl.DateTimeFormat('en-US', { timeZone: LIFECYCLE_TZ, timeZoneName: 'longOffset' }).format(at);
  const m = /GMT([+-])(\d{2}):(\d{2})/.exec(s);
  if (!m) return 0; // "GMT" = +00:00
  return (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3]));
}

/** 00:00 Europe/Zurich of a calendar day (y, m 1-12, d), as an instant. */
export function zurichMidnight(y: number, m: number, d: number): Date {
  const utcMidnight = Date.UTC(y, m - 1, d);
  // Midnight is never inside a Zurich DST gap (02:00/03:00), so two passes settle it.
  let t = utcMidnight - zurichOffsetMin(new Date(utcMidnight)) * 60_000;
  t = utcMidnight - zurichOffsetMin(new Date(t)) * 60_000;
  return new Date(t);
}

const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;
const TS_WITH_OFFSET = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * An until bound: an ISO timestamp WITH offset (as is), or a date (end of that day in
 * Europe/Zurich = 00:00 of the next day there). Anything else (no offset, not a real date): null.
 */
export function parseUntil(s: string): Date | null {
  const v = s.trim();
  const d = DATE_ONLY.exec(v);
  if (d) {
    const y = Number(d[1]);
    const mo = Number(d[2]);
    const da = Number(d[3]);
    const check = new Date(Date.UTC(y, mo - 1, da));
    if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== da) return null;
    const next = new Date(Date.UTC(y, mo - 1, da + 1));
    return zurichMidnight(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate());
  }
  if (!TS_WITH_OFFSET.test(v)) return null;
  const t = new Date(v);
  return Number.isNaN(t.getTime()) ? null : t;
}

/** One `lock_until` item `"<ord>: <until>"`, or null when malformed. */
export function parseLockUntil(s: string): { ord: number; until: Date } | null {
  const m = /^\s*(\d{1,4})\s*:\s*(\S.*?)\s*$/.exec(s);
  if (!m || Number(m[1]) === 0) return null;
  const until = parseUntil(m[2]!);
  return until ? { ord: Number(m[1]), until } : null;
}

/**
 * `standing_locks` as stored: a list (`[1, 3]` or a block list) or one string (`"1, 3"`). Each
 * entry is a positive integer ordinal, or null when it is not one (counted invalid, never guessed).
 */
export function parseStandingMarker(v: unknown): Array<number | null> {
  const raw = Array.isArray(v) ? v : typeof v === 'string' ? v.split(/[\s,]+/) : typeof v === 'number' ? [v] : [];
  const out: Array<number | null> = [];
  for (const x of raw) {
    const t = typeof x === 'number' ? String(x) : typeof x === 'string' ? x.trim() : '';
    if (t === '') continue;
    out.push(/^[1-9]\d{0,3}$/.test(t) ? Number(t) : null);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Resolution (pure)

const lc = (s: string) => s.normalize('NFC').toLowerCase().trim();
const noMd = (s: string) => s.replace(/\.md$/i, '');
const baseName = (p: string) => p.slice(p.lastIndexOf('/') + 1);

/** Lookup keys of a note for a wikilink target. */
function noteKeys(n: LockNoteInput): string[] {
  // The stored path may carry a profile prefix (hq:, import:): match without it too.
  const path = n.vaultPath.replace(/^[a-z]+:/, '');
  return [...new Set([lc(path), lc(noMd(path)), lc(noMd(baseName(path))), lc(n.title)])];
}

const refOf = (n: LockNoteInput, ord: number, text: string): LockRef => ({ note_title: n.title, ord, text, source_uri: n.sourceUri, source_ts: n.sourceTs });

/**
 * Resolve every lock item of the given notes to current / superseded / expired. Input order does
 * not matter. Output: newest note first (source_ts, then note id), in-note order kept.
 */
export function resolveLockLifecycle(notes: readonly LockNoteInput[], now: Date): { locks: ResolvedLock[]; counts: LifecycleCounts } {
  const counts = emptyLifecycleCounts();
  const byKey = new Map<string, Set<number>>();
  const byId = new Map<number, LockNoteInput>();
  const items = new Map<number, Array<{ ord: number; text: string }>>();
  for (const n of notes) {
    byId.set(n.noteId, n);
    items.set(n.noteId, lockItemsOf(n.locks));
    for (const k of noteKeys(n)) {
      if (!byKey.has(k)) byKey.set(k, new Set());
      byKey.get(k)!.add(n.noteId);
    }
  }
  const key = (noteId: number, ord: number) => `${noteId}:${ord}`;
  const out = new Map<string, ResolvedLock>();
  for (const n of notes) {
    const its = items.get(n.noteId)!;
    if (its.length) counts.notes++;
    for (const it of its) {
      out.set(key(n.noteId, it.ord), {
        noteId: n.noteId, ord: it.ord, title: n.title, text: it.text, scope: n.scope, sourceUri: n.sourceUri, sourceTs: n.sourceTs,
        vaultPath: n.vaultPath, status: 'current', supersedes: [], supersededBy: null, until: null, standingMarked: false,
      });
    }
  }

  // Standing marker: `standing_locks` ordinals (a list, or one string of comma/space separated ordinals).
  for (const n of notes) {
    for (const ord of parseStandingMarker(n.standingLocks)) {
      const l = typeof ord === 'number' ? out.get(key(n.noteId, ord)) : undefined;
      if (!l) {
        counts.standing_marker_invalid++;
        continue;
      }
      if (!l.standingMarked) counts.standing_marked++;
      l.standingMarked = true;
    }
  }

  // Expiry: note-level until, then per-lock lock_until (wins).
  for (const n of notes) {
    const its = items.get(n.noteId)!;
    const untilByOrd = new Map<number, Date>();
    const noteUntil = stringsOf(n.until);
    if (noteUntil.length) {
      const u = noteUntil.length === 1 ? parseUntil(noteUntil[0]!) : null;
      if (!u) counts.until_invalid++;
      else for (const it of its) untilByOrd.set(it.ord, u);
    }
    for (const s of stringsOf(n.lockUntil)) {
      const p = parseLockUntil(s);
      if (!p || !its.some((it) => it.ord === p.ord)) {
        counts.until_invalid++;
        continue;
      }
      untilByOrd.set(p.ord, p.until);
    }
    for (const [ord, u] of untilByOrd) {
      const l = out.get(key(n.noteId, ord))!;
      l.until = u.toISOString();
      counts.until_set++;
    }
  }

  // Supersession: claims of every visible note, oldest claimant first (so the newest wins superseded_by).
  const claimants = [...notes].sort((a, b) => a.sourceTs.localeCompare(b.sourceTs) || a.noteId - b.noteId);
  for (const n of claimants) {
    const own = items.get(n.noteId)!;
    for (const s of stringsOf(n.supersedes)) {
      counts.supersede_claims++;
      const c = parseSupersede(s);
      if (!c || (c.ownOrd !== null && !own.some((it) => it.ord === c.ownOrd))) {
        counts.supersede_invalid++;
        continue;
      }
      const t = lc(c.target);
      const hits = new Set([...(byKey.get(t) ?? []), ...(byKey.get(lc(noMd(c.target))) ?? [])]);
      if (hits.size !== 1) {
        counts.supersede_unresolved++;
        continue;
      }
      const target = byId.get([...hits][0]!)!;
      if (target.noteId === n.noteId || !(n.sourceTs > target.sourceTs)) {
        counts.supersede_invalid++;
        continue;
      }
      const tItems = items.get(target.noteId)!;
      const victims = c.ord === null ? tItems : tItems.filter((it) => it.ord === c.ord);
      if (victims.length === 0) {
        counts.supersede_unresolved++;
        continue;
      }
      counts.supersede_applied++;
      const by = c.ownOrd !== null ? [own.find((it) => it.ord === c.ownOrd)!] : own;
      for (const v of victims) {
        const victim = out.get(key(target.noteId, v.ord))!;
        victim.status = 'superseded';
        // superseded_by: the claiming lock, or (note-level claim) the note's first lock; a note without locks is cited by title.
        const first = by[0];
        victim.supersededBy = first ? refOf(n, first.ord, first.text) : { note_title: n.title, ord: null, text: null, source_uri: n.sourceUri, source_ts: n.sourceTs };
        for (const b of by) out.get(key(n.noteId, b.ord))!.supersedes.push(refOf(target, v.ord, v.text));
      }
    }
  }

  const locks = [...out.values()].sort((a, b) => b.sourceTs.localeCompare(a.sourceTs) || b.noteId - a.noteId || a.ord - b.ord);
  for (const l of locks) {
    if (l.status !== 'superseded' && l.until !== null && now.getTime() >= Date.parse(l.until)) l.status = 'expired';
    counts.items++;
    counts[l.status]++;
  }
  return { locks, counts };
}

// ---------------------------------------------------------------------------
// Loading (inside the caller's BEGIN READ ONLY transaction, as the caller's read role: RLS applies)

export async function loadLockNotes(db: Db, cap: number = LOCK_NOTES_CAP): Promise<{ notes: LockNoteInput[]; capped: boolean }> {
  const rows = (await db.query<Record<string, unknown>>(
    `SELECT n.id::int AS note_id, n.vault_path, n.title, n.scope::text AS scope, n.source_uri, n.source_ts,
            n.frontmatter->'locks' AS locks, n.frontmatter->'supersedes' AS supersedes,
            n.frontmatter->'lock_until' AS lock_until, n.frontmatter->'until' AS until,
            n.frontmatter->'standing_locks' AS standing_locks
     FROM zeusi.notes n
     WHERE n.status = 'active' AND n.frontmatter ?| $1::text[]
     ORDER BY n.source_ts DESC, n.id DESC
     LIMIT $2`,
    [[...LIFECYCLE_KEYS], cap + 1],
  )).rows;
  const capped = rows.length > cap;
  return {
    capped,
    notes: rows.slice(0, cap).map((r) => ({
      noteId: Number(r['note_id']), vaultPath: String(r['vault_path']), title: String(r['title']), scope: String(r['scope']),
      sourceUri: String(r['source_uri']), sourceTs: new Date(r['source_ts'] as string).toISOString(),
      locks: r['locks'] ?? null, supersedes: r['supersedes'] ?? null, lockUntil: r['lock_until'] ?? null, until: r['until'] ?? null,
      standingLocks: r['standing_locks'] ?? null,
    })),
  };
}

/** Load (RLS) + resolve. */
export async function lockLifecycle(db: Db, now: Date, cap: number = LOCK_NOTES_CAP): Promise<{ locks: ResolvedLock[]; counts: LifecycleCounts; capped: boolean }> {
  const { notes, capped } = await loadLockNotes(db, cap);
  return { ...resolveLockLifecycle(notes, now), capped };
}
