// Output (and input) wall for the MCP connector (docs/mcp.md). Every item a tool would
// return (a standing rule, a focus fact, a decision, a search hit, a notice) and every
// string a write/feedback tool receives is checked here. An item that trips any check is
// OMITTED and counted (never paraphrased, never echoed):
//
//   * the Plankiva signal used everywhere else (mentionsProtectedName: raw, percent-decoded,
//     normalised, 0010 spelling + 0011 variants regexes);
//   * the wall's hard Plankiva class, compiled by the wall's own compiler (plankivaWall);
//   * the seed wall's hard uri rules for any string that looks like a source uri;
//   * credential shapes (strictCredentialSignal: the shared detector plus the pre-detector
//     floor, the same check the export filter uses);
//   * database hostnames and connection strings.
//
// This is a second layer: rows were already walled by the DB trigger when written, and
// RLS hides personal. It catches rows that predate a rule and anything a writer slipped by.
//
// SERVE-TIME SECRET GUARD (security P0, 17 Nov 2026; final design of PR #23): WITHHOLD,
// never redact-and-serve. In this order, per item:
//   1. the WALL on the item (wallSignal: Plankiva, the compiled Plankiva class, seed uri
//      rules, hosts / connection strings);
//   2. the SECRET check (serveSecretSignal) on every string of the item: the shared detector
//      (any rule, src/secrets.ts strictCredentialSignal = detector + withhold floor), the
//      verbatim origin/main credential patterns (src/secrets-main-floor.ts, so serve-time
//      strictness is never below main by construction), and ANY `[REDACTED:` marker (text
//      that was redacted at ingest / rescrub is never served, so no residue next to a marker
//      can leak, whatever its shape);
//   3. fail closed: if a check throws, the item is withheld.
// Nothing is rewritten at serve time: an item is returned byte-for-byte or not at all. The
// count of items withheld by step 2 is reported to the hosted request log as redacted_count
// (count only, never the text); withheld_count counts every omitted item.

import { plankivaWall } from './hq-export.ts';
import { REDACTED_PREFIX, strictCredentialSignal } from './secrets.ts';
import { mainCredentialSignal } from './secrets-main-floor.ts';
import { mentionsProtectedName } from './sources.ts';
import { seedWall, type Wall } from './wall.ts';
import { redact } from './db.ts';

const HOST_OR_URL: readonly RegExp[] = [
  /[A-Za-z0-9.-]+\.neon\.tech\b/i,
  /\bpostgres(?:ql)?:\/\//i,
  /\b(?:host|hostaddr)\s*=\s*\S+/i,
];

let cached: { plankiva: Wall; seed: Wall } | undefined;
function walls(): { plankiva: Wall; seed: Wall } {
  cached ??= { plankiva: plankivaWall(), seed: seedWall() };
  return cached;
}

/**
 * The wall's non-credential checks (Plankiva, the compiled Plankiva class, seed uri
 * rules, hosts). Run on the ORIGINAL strings, before any redaction.
 */
export function wallSignal(strings: ReadonlyArray<string | null | undefined>, o: { hosts?: boolean } = {}): boolean {
  const { plankiva, seed } = walls();
  for (const s of strings) {
    if (s === null || s === undefined || s === '') continue;
    if (mentionsProtectedName(s)) return true;
    if (plankiva.check('chunks', { heading_path: null, text: s, source_uri: 'mcp:item' }).blocked) return true;
    if (/^[a-z][a-z0-9+.-]*:/i.test(s) && seed.checkUri(s).blocked) return true;
    if (o.hosts !== false && HOST_OR_URL.some((re) => re.test(s))) return true;
  }
  return false;
}

/** Which parts of the serve-time secret check run (TEST seam: a mutant drops one). */
export interface ServeCheckParts {
  detector?: boolean;
  mainFloor?: boolean;
  marker?: boolean;
}

/**
 * The serve-time SECRET check for one string: true = must not be served. The shared detector
 * (any rule, plus its withhold floor), origin/main's credential patterns (verbatim), or any
 * `[REDACTED:` marker. Boolean only.
 */
export function serveSecretSignal(s: string, parts: ServeCheckParts = {}): boolean {
  if (typeof s !== 'string' || s === '') return false;
  if (parts.marker !== false && s.includes(REDACTED_PREFIX)) return true;
  if (parts.detector !== false && strictCredentialSignal(s)) return true;
  if (parts.mainFloor !== false && mainCredentialSignal(s)) return true;
  return false;
}

/** The serve-time secret check over one string (TEST seam: a mutant / a throwing check is injected here). */
export type ServeCheck = (s: string) => boolean;
export const defaultServeCheck: ServeCheck = (s) => serveSecretSignal(s);

/** True when any of the strings must not cross the MCP boundary (wall OR secret signal). Used for MCP input too. */
export function withheld(strings: ReadonlyArray<string | null | undefined>, check: ServeCheck = defaultServeCheck): boolean {
  if (wallSignal(strings)) return true;
  return strings.some((s) => typeof s === 'string' && s !== '' && check(s));
}

/** Every string inside a value (keys and values), for withheld() over a whole item. */
export function stringsOf(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.flatMap(stringsOf);
  if (v && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => [k, ...stringsOf(x)]);
  return [];
}

type Verdict = 'serve' | 'wall' | 'secret' | 'error';

/** One item through the guard: the wall first, then the secret check; any throw withholds. */
function verdict(v: unknown, check: ServeCheck): Verdict {
  try {
    const strings = stringsOf(v);
    if (wallSignal(strings)) return 'wall';
    if (strings.some((s) => s !== '' && check(s))) return 'secret';
    return 'serve';
  } catch {
    return 'error'; // fail closed: an item the guard could not scan is never served
  }
}

/**
 * The serve-time guard for a list of items. Items are returned unchanged or omitted.
 * `withheld` counts every omitted item (wall, secret, guard error); `secretWithheld` counts
 * the ones the secret check (or a guard error) omitted. Counts only, never text.
 */
export function wallFilter<T>(items: readonly T[], check: ServeCheck = defaultServeCheck): { kept: T[]; withheld: number; secretWithheld: number } {
  const kept: T[] = [];
  let n = 0;
  let secret = 0;
  for (const it of items) {
    const v = verdict(it, check);
    if (v === 'serve') kept.push(it);
    else {
      n++;
      if (v !== 'wall') secret++;
    }
  }
  return { kept, withheld: n, secretWithheld: secret };
}

/** One string through the guard: the string unchanged, or null when it must be withheld (wall, secret, guard error). */
export function guardString(s: string, check: ServeCheck = defaultServeCheck): { text: string | null; secretWithheld: number } {
  const v = verdict(s, check);
  return v === 'serve' ? { text: s, secretWithheld: 0 } : { text: null, secretWithheld: v === 'wall' ? 0 : 1 };
}

/** An error message safe to hand to an MCP client: known secrets / hosts masked, and replaced entirely if it trips the wall or the secret check. */
export function safeMessage(message: string, secrets: Array<string | undefined> = [], check: ServeCheck = defaultServeCheck): string {
  const refused = 'refused (details withheld by the wall)';
  try {
    const known = redact(message, secrets);
    // The wall on the raw message (Plankiva / seed uri), everything (hosts too) on the message
    // with its known hosts / secrets masked (a known host is masked as <host>, the rest kept).
    if (wallSignal([message], { hosts: false }) || wallSignal([known])) return refused;
    // The secret check on what would be served (as origin/main: its credential patterns ran on
    // the masked message; the detector and the marker check run there too). Never rewritten.
    return check(known) ? refused : known;
  } catch {
    return refused;
  }
}
