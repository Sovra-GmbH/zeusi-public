// Chinese wall pre-check in TypeScript (PLAN.md KTD7, U4).
//
// IDENTICAL semantics to the SQL verdict function zeusi.wall_eval() (0007), which
// the zeusi_90_wall trigger calls. Importers run this first and quarantine a blocked
// item (uri + hashes only) before anything is sent; the trigger is the backstop.
// test/wall.test.ts holds the parity test (wall.ts == wall_eval() == trigger).
//
// Evaluation order (first hit wins, the same in SQL):
//   1. hard path_glob / lane / repo rules, by id
//   2. hard tag rules, by id (frontmatter tags/tag + inline #tags)
//   3. hard regex / term rules, by id, over content + uri + paths + lanes + repos
//   4. soft regex / term rules, by id, over content; skipped only when a wall_allow
//      row pins (source_uri, content_sha256, rule_id)
//
// 0008 (review r1): the hard tag / term / regex rules also match the normalised text
// (wallNorm == zeusi.wall_norm: NFKC, ignorables and combining marks stripped,
// Cyrillic/Greek look-alikes folded), and path / lane / repo candidates include the
// percent-decoded (pctDecode == zeusi.pct_decode) and normalised forms.
// 0009 (review r2): Cherokee / Lisu look-alikes join the fold list, and a decoded
// uri / path that still holds a %XX escape is a hard block (WALL_UNDECODED_TERM).
// 0010 (owner rule): the ClientCo-name hard rules are deleted
// (LIFTED_0010) and one hard Plankiva spelling regex is seeded (PROTECTED_SPELLING_REGEX).
// The verdict function, its order and the normalisation are unchanged.
// 0011 (the owner: "Plankiva" IS Plankiva; lift the soft currency and P&L
// rules): one hard regex for the name and its variants (PROTECTED_VARIANTS_REGEX) and the
// two soft rules deleted (LIFTED_0011). Verdict function and normalisation unchanged.
//
// Known parity limits (documented in docs/wall.md): non-ASCII case folding and
// non-ASCII "word" characters for \m / \M may differ between JS and the server
// locale; NFKC/NFKD tables follow each side's Unicode version (Node ICU vs the
// server), which only differ for code points added in the newest Unicode releases.
// Seeded rules and the Plankiva rules are ASCII.

import { createHash } from 'node:crypto';
import type { Db } from './db.ts';
// Types only (no runtime import): wall.ts sits under facts.ts / sources.ts, and write-route.ts imports them.
import type { WriteRoute } from './write-route.ts';

export const WALL_TABLES = [
  'facts', 'decisions', 'episodes', 'notes', 'chunks', 'prs', 'pr_reviews', 'routine_runs', 'people',
] as const;
export type WallTable = (typeof WALL_TABLES)[number];
export type RuleKind = 'path_glob' | 'lane' | 'repo' | 'tag' | 'regex' | 'term';
export type Row = Record<string, unknown>;

export interface WallRule {
  id: number;
  kind: RuleKind;
  hard: boolean;
  pattern: string;
}

export interface WallAllowRow {
  sourceUri: string;
  /** hex */
  contentSha256: string;
  ruleId: number;
}

export interface Verdict {
  blocked: boolean;
  ruleId: number | null;
  kind: RuleKind | null;
  hard: boolean;
  /** hex sha256 of wallContent(table, row): what wall_allow pins. */
  contentSha256: string;
}

export class WallRuleError extends Error {
  override name = 'WallRuleError';
}

export type SeedRule = Omit<WallRule, 'id'> & { reason: string };

/**
 * The seed rules of 0003, 0007 and 0009, in id order (a fresh database gives them ids
 * 1..n). This is the wall BEFORE 0010. It is used only for the count-only comparison
 * in scripts/wall-dryrun.ts (--compare-old) and in tests. SEED_RULES is the current wall.
 */
export const LEGACY_SEED_RULES: ReadonlyArray<SeedRule> = [
  { kind: 'path_glob', hard: true, pattern: 'ClientCo/**', reason: 'ClientCo vault area' },
  { kind: 'path_glob', hard: true, pattern: 'plankiva/**', reason: 'Plankiva vault area' },
  { kind: 'path_glob', hard: true, pattern: 'bot-staged/**', reason: 'deferred: bot-staged' },
  { kind: 'path_glob', hard: true, pattern: 'raw/**', reason: 'deferred: raw meetings' },
  { kind: 'path_glob', hard: true, pattern: 'personal/**', reason: 'personal area' },
  { kind: 'path_glob', hard: true, pattern: 'canvas/**', reason: 'not ingested' },
  { kind: 'path_glob', hard: true, pattern: 'bases/**', reason: 'not ingested' },
  { kind: 'path_glob', hard: true, pattern: '.obsidian/**', reason: 'Obsidian config' },
  { kind: 'path_glob', hard: true, pattern: 'Work/ops/attic/**', reason: 'archived ops notes' },
  { kind: 'path_glob', hard: true, pattern: 'Work/intake/**', reason: 'unreviewed inbox' },
  { kind: 'path_glob', hard: true, pattern: '**clientco**', reason: 'name contains clientco' },
  { kind: 'path_glob', hard: true, pattern: '**plankiva**', reason: 'name contains plankiva' },
  { kind: 'path_glob', hard: true, pattern: '**pnl**', reason: 'name contains pnl (desk P&L)' },
  { kind: 'path_glob', hard: true, pattern: '**p&l**', reason: 'name contains p&l (desk P&L)' },
  { kind: 'path_glob', hard: true, pattern: '~/PlankivaVault/**', reason: 'PlankivaVault' },
  { kind: 'path_glob', hard: true, pattern: '**/PlankivaVault/**', reason: 'PlankivaVault (absolute path)' },
  { kind: 'path_glob', hard: true, pattern: '~/KnowledgeVault-staging/**', reason: 'staging copy' },
  { kind: 'path_glob', hard: true, pattern: '**/KnowledgeVault-staging/**', reason: 'staging copy (absolute)' },
  { kind: 'path_glob', hard: true, pattern: '~/.assistant/memory/plankiva*', reason: 'Plankiva assistant memory' },
  { kind: 'path_glob', hard: true, pattern: '**/.assistant/memory/plankiva*', reason: 'Plankiva assistant memory (absolute)' },
  { kind: 'path_glob', hard: true, pattern: '**/lanes/desk-pnl/**', reason: 'desk P&L lane' },
  { kind: 'path_glob', hard: true, pattern: '**/lanes/session-pnl/**', reason: 'desk P&L lane' },
  { kind: 'lane', hard: true, pattern: 'desk-pnl', reason: 'desk P&L lane, hard-denied unread' },
  { kind: 'lane', hard: true, pattern: 'session-pnl', reason: 'desk P&L lane, hard-denied unread' },
  { kind: 'lane', hard: true, pattern: '*pnl*', reason: 'lane name contains pnl' },
  { kind: 'lane', hard: true, pattern: '*clientco*', reason: 'lane name contains clientco' },
  { kind: 'lane', hard: true, pattern: '*plankiva*', reason: 'lane name contains plankiva' },
  { kind: 'repo', hard: true, pattern: 'example-org/clientco-*', reason: 'ClientCo repos' },
  { kind: 'repo', hard: true, pattern: 'example-org/*clientco*', reason: 'ClientCo repos' },
  { kind: 'repo', hard: true, pattern: 'example-org/agent-config-backup*', reason: 'agent config backups (client-walled)' },
  { kind: 'repo', hard: true, pattern: '*plankiva*', reason: 'repo name contains plankiva' },
  { kind: 'repo', hard: true, pattern: '*/*clientco*', reason: 'repo name contains clientco (any owner)' },
  { kind: 'regex', hard: false, pattern: '(USD|EUR|CHF|GBP|JPY)[ ]?[0-9]|\\$[ ]?[0-9]', reason: 'currency amount' },
  { kind: 'regex', hard: false, pattern: '\\m(login|account|acct)\\M[^0-9\\n]{0,4}[0-9]{5,}', reason: 'trading account or login number' },
  { kind: 'regex', hard: false, pattern: '(?c)\\m[A-Z]{2}[0-9]{2}[ ]?([A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\\M', reason: 'IBAN pattern' },
  { kind: 'regex', hard: false, pattern: '(p&l|\\mpnl\\M|\\mbook\\M)[^\\n]*[0-9]', reason: 'P&L / PnL / book line with digits' },
  // 0007_wall_protected_name.sql — owner hard rule.
  { kind: 'tag', hard: true, pattern: 'plankiva', reason: 'Plankiva tag (owner hard rule); no wall_allow' },
  { kind: 'term', hard: true, pattern: 'plankiva', reason: 'the word plankiva anywhere in checked text (owner hard rule); no wall_allow' },
  // 0009_wall_r2.sql — review r2 MINOR-B.
  { kind: 'term', hard: true, pattern: 'zeusi-wall:undecoded-percent-escape', reason: 'a uri or path still holds a %XX escape after the bounded percent-decoding (review r2); no wall_allow' },
];

/**
 * 0010_wall_client_admit.sql (owner rule: ClientCo and Northbank
 * go INTO Zeusi, only Plankiva stays out): the hard rules that blocked on the ClientCo name,
 * deleted by (kind, pattern). Repo 'example-org/agent-config-backup*' is kept.
 */
export const LIFTED_0010: ReadonlyArray<Pick<WallRule, 'kind' | 'pattern'>> = [
  { kind: 'path_glob', pattern: 'ClientCo/**' },
  { kind: 'path_glob', pattern: '**clientco**' },
  { kind: 'lane', pattern: '*clientco*' },
  { kind: 'repo', pattern: 'example-org/clientco-*' },
  { kind: 'repo', pattern: 'example-org/*clientco*' },
  { kind: 'repo', pattern: '*/*clientco*' },
];

/**
 * 0010 Plankiva hardening (hard regex, never allowable): the word with up to 3
 * non-alphanumeric, non-space characters between its letters ("Plan-kiva", "P.l.a.n.k.i.v.a",
 * "**Plan**kiva"), or with 1-3 non-alphanumeric characters (spaces allowed) between EVERY
 * pair of letters ("P l a n k i v a"); a/i also as leetspeak (4 @ / 1 ! |). Matched over the
 * hard text, raw and wall_norm()ed, like every hard regex. Vault dry run: 0 false positives.
 */
const SEP = '[^a-z0-9 \\t\\n\\r\\f\\v]{0,3}';
const GAP = '[^a-z0-9]{1,3}';
export const PROTECTED_SPELLING_REGEX =
  `p${SEP}l${SEP}[a4@]${SEP}n${SEP}k${SEP}[i1!|]${SEP}v${SEP}[a4@]|p${GAP}l${GAP}[a4@]${GAP}n${GAP}k${GAP}[i1!|]${GAP}v${GAP}[a4@]`;

const ADDED_0010: ReadonlyArray<SeedRule> = [
  { kind: 'regex', hard: true, pattern: PROTECTED_SPELLING_REGEX, reason: 'the word plankiva spelled with separators or leetspeak (owner hard rule, kept by owner-rule); no wall_allow' },
];

/**
 * 0011_wall_name_variants_soft_lift.sql (the owner Zurich: lift the soft
 * currency and P&L rules so ClientCo / Northbank content is admitted): deleted by (kind, pattern)
 * while soft. The account / login-number and IBAN soft rules stay.
 */
export const LIFTED_0011: ReadonlyArray<Pick<WallRule, 'kind' | 'pattern'>> = [
  { kind: 'regex', pattern: '(USD|EUR|CHF|GBP|JPY)[ ]?[0-9]|\\$[ ]?[0-9]' },
  { kind: 'regex', pattern: '(p&l|\\mpnl\\M|\\mbook\\M)[^\\n]*[0-9]' },
];

/**
 * 0011 (the owner Zurich: "Plankiva" IS Plankiva), hard regex, never allowable:
 * the letters of the protected name, each written 1-3 times (Plankiva, Plaankiva, Plankkiva,
 * Plannnkiva, ...), a as 4 / @, i as 1 / ! / |, with the 0010 separator forms (alternative 1:
 * 0-3 non-alphanumeric non-space characters between letters; alternative 2: 1-3
 * non-alphanumeric characters, spaces allowed, between EVERY pair). No start anchor: the
 * letters inside a longer token block too. Matched over the hard text, raw and
 * wall_norm()ed (look-alikes, fullwidth, zero-width fold in). Every quantifier is bounded:
 * linear time. A superset of PROTECTED_SPELLING_REGEX.
 */
const PROTECTED_LETTERS = ['p', 'l', '[a4@]', 'n', 'k', '[i1!|]', 'v', '[a4@]'];
const repeated = (letter: string, sep: string) => `${letter}(?:${sep}${letter}){0,2}`;
export const PROTECTED_VARIANTS_REGEX =
  `${PROTECTED_LETTERS.map((l) => repeated(l, SEP)).join(SEP)}|${PROTECTED_LETTERS.map((l) => repeated(l, GAP)).join(GAP)}`;

const ADDED_0011: ReadonlyArray<SeedRule> = [
  { kind: 'regex', hard: true, pattern: PROTECTED_VARIANTS_REGEX, reason: 'the name plankiva / plankiva and its variants (repeated letters, separators, leetspeak, look-alikes; the owner hard rule 2026-11-15 01:09: Plankiva IS Plankiva); no wall_allow' },
];

const ruleKey = (r: Pick<WallRule, 'kind' | 'pattern'>) => `${r.kind}\u0000${r.pattern}`;
const LIFTED_KEYS = new Set(LIFTED_0010.map(ruleKey));
const LIFTED_KEYS_0011 = new Set([...LIFTED_0010, ...LIFTED_0011].map(ruleKey));

/**
 * The current seed rules (after 0011), in id order: LEGACY_SEED_RULES without
 * LIFTED_0010 and LIFTED_0011, then the 0010 and 0011 additions. A test asserts equality
 * with the migrated DB. Used offline (config validation, count-only dry runs); importers
 * load the live rules with loadWall().
 */
export const SEED_RULES: ReadonlyArray<SeedRule> = [
  ...LEGACY_SEED_RULES.filter((r) => !LIFTED_KEYS_0011.has(ruleKey(r))),
  ...ADDED_0010,
  ...ADDED_0011,
];

/**
 * 0009 (r2 MINOR-B): when a percent-decoded uri / path still contains a %XX escape
 * (more than PCT_DECODE_MAX_ROUNDS levels, %00, or bytes that are not UTF-8), this
 * marker is appended to the hard text, so the hard term rule with the same pattern
 * blocks the row. Same marker and test in 0009's wall_eval().
 */
export const WALL_UNDECODED_TERM = 'zeusi-wall:undecoded-percent-escape';
const LEFTOVER_ESCAPE = /%[0-9A-Fa-f]{2}/;

/** LEGACY_SEED_RULES with the ids a fresh database assigned them (1..n): the 0009 wall. */
export function legacySeedRulesWithIds(): WallRule[] {
  return LEGACY_SEED_RULES.map((r, i) => ({ id: i + 1, kind: r.kind, hard: r.hard, pattern: r.pattern }));
}

/** The 0010 wall (head of PR #3 before 0011), with fresh-database ids. Offline comparison only. */
export function seed0010RulesWithIds(): WallRule[] {
  const kept = legacySeedRulesWithIds().filter((r) => !LIFTED_KEYS.has(ruleKey(r)));
  const added = ADDED_0010.map((r, j) => ({ id: LEGACY_SEED_RULES.length + j + 1, kind: r.kind, hard: r.hard, pattern: r.pattern }));
  return [...kept, ...added];
}

/**
 * SEED_RULES with the ids a fresh database assigns: a kept legacy rule keeps its id
 * (a deleted serial id is never reused), the 0010 then the 0011 additions follow the
 * legacy ids.
 */
export function seedRulesWithIds(): WallRule[] {
  const kept = legacySeedRulesWithIds().filter((r) => !LIFTED_KEYS_0011.has(ruleKey(r)));
  const added = [...ADDED_0010, ...ADDED_0011].map((r, j) => ({ id: LEGACY_SEED_RULES.length + j + 1, kind: r.kind, hard: r.hard, pattern: r.pattern }));
  return [...kept, ...added];
}

// ---------------------------------------------------------------------------
// Value rendering: mirrors Postgres jsonb text output and the ->> operator.

function quoteJson(s: string): string {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c < 0x20) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return `${out}"`;
}

/** Postgres numeric text for a JSON number (no exponent notation). */
function numericText(n: number): string {
  if (!Number.isFinite(n)) throw new WallRuleError('non-finite number cannot be stored as jsonb');
  const s = JSON.stringify(n);
  const m = /^(-?)(\d+)(?:\.(\d+))?e([+-]\d+)$/i.exec(s);
  if (!m) return s;
  const [, sign, int, frac = '', expS] = m;
  const exp = Number(expS);
  const digits = int! + frac;
  const point = int!.length + exp;
  let out: string;
  if (point <= 0) out = `0.${'0'.repeat(-point)}${digits}`;
  else if (point >= digits.length) out = digits + '0'.repeat(point - digits.length);
  else out = `${digits.slice(0, point)}.${digits.slice(point)}`;
  out = out.replace(/^0+(?=\d)/, '');
  return `${sign}${out}`;
}

function keyOrder(a: string, b: string): number {
  const la = Buffer.byteLength(a), lb = Buffer.byteLength(b);
  if (la !== lb) return la - lb;
  return Buffer.compare(Buffer.from(a), Buffer.from(b));
}

/** Text of a value as Postgres prints `$1::jsonb::text` for JSON.stringify(value). */
export function jsonbText(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return quoteJson(v);
  if (typeof v === 'number') return numericText(v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (Array.isArray(v)) return `[${v.map((x) => (x === undefined ? 'null' : jsonbText(x))).join(', ')}]`;
  if (typeof v === 'object') {
    const keys = Object.keys(v as object).filter((k) => (v as Record<string, unknown>)[k] !== undefined).sort(keyOrder);
    return `{${keys.map((k) => `${quoteJson(k)}: ${jsonbText((v as Record<string, unknown>)[k])}`).join(', ')}}`;
  }
  throw new WallRuleError(`unsupported value type ${typeof v}`);
}

/** r->>'key' */
function txt(row: Row, key: string): string | null {
  const v = row[key];
  if (v === undefined || v === null) return null;
  return typeof v === 'string' ? v : jsonbText(v);
}

/** jsonb_array_elements_text element */
function elemText(e: unknown): string | null {
  if (e === null || e === undefined) return null;
  return typeof e === 'string' ? e : jsonbText(e);
}

/** Column defaults that change what the wall sees (the trigger sees NEW with defaults). */
export function withDefaults(table: WallTable, row: Row): Row {
  const r = { ...row };
  if (table === 'notes' && r['frontmatter'] === undefined) r['frontmatter'] = {};
  if (table === 'episodes' && r['links'] === undefined) r['links'] = [];
  if (table === 'decisions' && r['applies_to'] === undefined) r['applies_to'] = [];
  return r;
}

const CONTENT_COLUMNS: Record<WallTable, string[]> = {
  facts: ['subject', 'text'],
  decisions: ['exact_words', 'expires_rule', 'linked_job'],
  episodes: ['actor', 'summary', 'links'],
  notes: ['title', 'body', 'frontmatter'],
  chunks: ['heading_path', 'text'],
  prs: ['title', 'author_login', 'head_ref', 'base_ref'],
  pr_reviews: ['reviewer', 'review_ref'],
  routine_runs: ['routine', 'login_label', 'log_ref'],
  people: ['handle', 'display_name', 'github_login'],
};

function assertTable(table: string): asserts table is WallTable {
  if (!(WALL_TABLES as readonly string[]).includes(table)) throw new WallRuleError(`zeusi wall: unknown table ${table}`);
}

/** zeusi.wall_content(tbl, r): the exact text the content rules see (and wall_allow pins). */
export function wallContent(table: string, row: Row): string {
  assertTable(table);
  const r = withDefaults(table, row);
  return CONTENT_COLUMNS[table].map((c) => txt(r, c)).filter((x): x is string => x !== null).join('\n');
}

export function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

export function contentSha256(table: string, row: Row): string {
  return sha256Hex(wallContent(table, row));
}

// ---------------------------------------------------------------------------
// Helpers mirroring 0003 SQL functions.

/** zeusi.glob_to_regex */
export function globToRegex(glob: string, starCrossesSlash = false): string {
  let out = '^';
  let i = 0;
  while (i < glob.length) {
    const c = glob[i]!;
    if (c === '*' && glob[i + 1] === '*') {
      if (glob[i + 2] === '/') {
        out += '(.*/)?';
        i += 3;
      } else {
        out += '.*';
        i += 2;
      }
      continue;
    } else if (c === '*') {
      out += starCrossesSlash ? '.*' : '[^/]*';
    } else if (c === '?') {
      out += '[^/]';
    } else if ('.^$+()[]{}|\\'.includes(c)) {
      out += `\\${c}`;
    } else {
      out += c;
    }
    i += 1;
  }
  return `${out}$`;
}

// ---------------------------------------------------------------------------
// 0008: normalisation (zeusi.wall_norm) and percent-decoding (zeusi.pct_decode).
// The hard tag / term / regex rules and the path / lane / repo candidates are also
// matched on the normalised form. wall_content() is NOT normalised (allow pins stay).

/** Default_Ignorable_Code_Point ∪ General_Category=Cf (Unicode 16). Same list in 0008. */
export const WALL_IGNORABLE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00ad, 0x00ad], [0x034f, 0x034f], [0x0600, 0x0605], [0x061c, 0x061c], [0x06dd, 0x06dd], [0x070f, 0x070f],
  [0x0890, 0x0891], [0x08e2, 0x08e2], [0x115f, 0x1160], [0x17b4, 0x17b5], [0x180b, 0x180f], [0x200b, 0x200f],
  [0x202a, 0x202e], [0x2060, 0x206f], [0x3164, 0x3164], [0xfe00, 0xfe0f], [0xfeff, 0xfeff], [0xffa0, 0xffa0],
  [0xfff0, 0xfffb], [0x110bd, 0x110bd], [0x110cd, 0x110cd], [0x13430, 0x1343f], [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a], [0xe0000, 0xe0fff],
];

/** Combining marks stripped after NFKD (accents: Ä → A). Same list in 0008. */
export const WALL_MARK_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0300, 0x036f], [0x1ab0, 0x1aff], [0x1dc0, 0x1dff], [0x20d0, 0x20ff], [0xfe20, 0xfe2f],
];

/**
 * Confusable folds for letters used by the seed hard terms → ASCII. Same source/target
 * pairs as the translate() lists in the latest wall_norm (0009; 0008 had the list
 * without Cherokee/Lisu). Pair alignment matters; list order does not. Cherokee small
 * letters are listed too: wall_norm does no non-ASCII case folding.
 */
export const WALL_CONFUSABLES: ReadonlyMap<string, string> = new Map([
  // a
  ['а', 'a'], ['А', 'a'], ['α', 'a'], ['Α', 'a'], ['ɑ', 'a'], ['ᴀ', 'a'],
  // c
  ['с', 'c'], ['С', 'c'], ['ϲ', 'c'], ['Ϲ', 'c'], ['ᴄ', 'c'],
  // g
  ['ɡ', 'g'], ['ɢ', 'g'], ['ԍ', 'g'], ['Ԍ', 'g'],
  // i (palochka looks like I / l; it folds to i so "plankiva" is caught)
  ['і', 'i'], ['І', 'i'], ['ι', 'i'], ['Ι', 'i'], ['ı', 'i'], ['ɪ', 'i'], ['ӏ', 'i'], ['Ӏ', 'i'],
  // k
  ['к', 'k'], ['К', 'k'], ['κ', 'k'], ['Κ', 'k'], ['ϰ', 'k'], ['ᴋ', 'k'],
  // l
  ['ʟ', 'l'], ['ᴌ', 'l'],
  // n
  ['п', 'n'], ['Ν', 'n'], ['η', 'n'], ['ɴ', 'n'], ['ո', 'n'], ['ռ', 'n'],
  // p
  ['р', 'p'], ['Р', 'p'], ['ρ', 'p'], ['Ρ', 'p'], ['ᴘ', 'p'],
  // v
  ['ν', 'v'], ['ѵ', 'v'], ['Ѵ', 'v'], ['ᴠ', 'v'],
  // 0009 (r2 MINOR-B): Cherokee capital + small letter (Unicode 8 small forms)
  ['\u13AA', 'a'], ['\uAB7A', 'a'], // GO
  ['\u13DF', 'c'], ['\uABAF', 'c'], // TLI
  ['\u13C0', 'g'], ['\uAB90', 'g'], // NAH
  ['\u13A5', 'i'], ['\uAB75', 'i'], // V
  ['\u13E6', 'k'], ['\uABB6', 'k'], // TSO
  ['\u13DE', 'l'], ['\uABAE', 'l'], // TLE
  ['\u13E2', 'p'], ['\uABB2', 'p'], // TLV
  ['\u13D9', 'v'], ['\uABA9', 'v'], // DO
  // 0009: Lisu (no case); same pairs as the 0009 translate list
  ['\uA4EE', 'a'], ['\uA4DA', 'c'], ['\uA4D6', 'g'], ['\uA4F2', 'i'], ['\uA4D7', 'k'],
  ['\uA4E1', 'l'], ['\uA4E0', 'n'], ['\uA4D1', 'p'], ['\uA4E6', 'v'],
]);

const rangeClass = (ranges: ReadonlyArray<readonly [number, number]>) =>
  ranges.map(([lo, hi]) => (lo === hi ? `\\u{${lo.toString(16)}}` : `\\u{${lo.toString(16)}}-\\u{${hi.toString(16)}}`)).join('');
const IGNORABLE_RE = new RegExp(`[${rangeClass(WALL_IGNORABLE_RANGES)}]`, 'gu');
const IGNORABLE_OR_MARK_RE = new RegExp(`[${rangeClass(WALL_IGNORABLE_RANGES)}${rangeClass(WALL_MARK_RANGES)}]`, 'gu');

/**
 * zeusi.wall_norm: strip ignorables → NFKD → strip ignorables + combining marks →
 * NFKC → strip ignorables → fold look-alikes → ASCII lower-case. Matching only.
 */
export function wallNorm(t: string): string {
  let s = t.replace(IGNORABLE_RE, '').normalize('NFKD').replace(IGNORABLE_OR_MARK_RE, '').normalize('NFKC').replace(IGNORABLE_RE, '');
  let out = '';
  for (const ch of s) out += WALL_CONFUSABLES.get(ch) ?? ch;
  s = out.replace(/[A-Z]/g, (c) => c.toLowerCase());
  return s;
}

const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * One pass of zeusi.pct_decode: every %XX (except %00) becomes its byte. If the
 * result is not valid UTF-8, only the ASCII escapes (%01–%7F) are decoded.
 */
function pctDecodeOnce(s: string): string {
  const bytes: number[] = [];
  let ascii = '';
  for (let i = 0; i < s.length;) {
    const h = s.slice(i + 1, i + 3);
    if (s[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(h) && h !== '00') {
      const v = parseInt(h, 16);
      bytes.push(v);
      ascii += v < 128 ? String.fromCharCode(v) : `%${h}`;
      i += 3;
    } else {
      const ch = String.fromCodePoint(s.codePointAt(i)!);
      for (const b of utf8.encode(ch)) bytes.push(b);
      ascii += ch;
      i += ch.length;
    }
  }
  try {
    return strictUtf8.decode(Uint8Array.from(bytes));
  } catch {
    return ascii;
  }
}

export const PCT_DECODE_MAX_ROUNDS = 8;

/** zeusi.pct_decode: repeat until stable, at most PCT_DECODE_MAX_ROUNDS passes. */
export function pctDecode(s: string): string {
  let cur = s;
  for (let n = 0; n < PCT_DECODE_MAX_ROUNDS; n++) {
    const next = pctDecodeOnce(cur);
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

/** zeusi.uri_path */
export function uriPath(uri: string): string {
  return uri.replace(/#[\s\S]*$/, '').replace(/^[a-z][a-z0-9+.-]*:/, '').replace(/^(\.\/|\/)+/, '');
}

const btrim = (s: string) => s.replace(/^ +| +$/g, '');

/** zeusi.norm_repo */
export function normRepo(repo: string): string {
  const t = btrim(repo);
  return t.includes('/') ? t : `example-org/${t}`;
}

const INLINE_TAG = /(?:^|[ \t\n\r\f\v])#([A-Za-z0-9_/-]+)/g;

/** Tags the wall checks: frontmatter `tags` / `tag` (list or string) + inline #tags in the checked text. */
export function rowTags(table: string, row: Row): string[] {
  assertTable(table);
  const r = withDefaults(table, row);
  const tags: string[] = [];
  const fm = r['frontmatter'];
  if (fm !== null && typeof fm === 'object' && !Array.isArray(fm)) {
    for (const k of ['tags', 'tag']) {
      const v = (fm as Record<string, unknown>)[k];
      if (v === undefined || v === null) continue;
      if (Array.isArray(v)) {
        for (const e of v) if (e !== null && e !== undefined) tags.push(typeof e === 'string' ? e : jsonbText(e));
      } else if (typeof v === 'string') {
        tags.push(v);
      } else {
        tags.push(jsonbText(v));
      }
    }
  }
  for (const m of wallContent(table, r).matchAll(INLINE_TAG)) tags.push(m[1]!);
  return tags;
}

// ---------------------------------------------------------------------------
// Postgres ARE (the subset Zeusi rules may use) → JS RegExp. Fails closed.

const WORD = 'A-Za-z0-9_';

export function pgRegexToJs(pattern: string): RegExp {
  let p = pattern;
  let ci = true; // rules are matched with ~* (case-insensitive) unless (?c)
  const opt = /^\(\?([a-z]+)\)/.exec(p);
  if (opt) {
    for (const ch of opt[1]!) {
      if (ch === 'c') ci = false;
      else if (ch === 'i') ci = true;
      else throw new WallRuleError(`unsupported regex option (?${ch}) in wall rule`);
    }
    p = p.slice(opt[0].length);
  }
  if (p.startsWith('***')) throw new WallRuleError('unsupported regex director *** in wall rule');
  let out = '';
  let inBracket = false;
  let bracketStart = -1;
  for (let i = 0; i < p.length; i++) {
    const c = p[i]!;
    if (c === '\\') {
      const n = p[i + 1];
      if (n === undefined) throw new WallRuleError('unsupported trailing backslash in wall rule');
      if (n === 'm' || n === 'M') {
        if (inBracket) throw new WallRuleError('unsupported \\m/\\M inside brackets in wall rule');
        out += n === 'm' ? `(?<![${WORD}])(?=[${WORD}])` : `(?<=[${WORD}])(?![${WORD}])`;
      } else if ('yYAZ<>'.includes(n) || /[0-9]/.test(n)) {
        throw new WallRuleError(`unsupported regex escape \\${n} in wall rule`);
      } else {
        out += `\\${n}`;
      }
      i += 1;
      continue;
    }
    if (inBracket) {
      if (c === '[' && /[:.=]/.test(p[i + 1] ?? '')) throw new WallRuleError('unsupported POSIX bracket class in wall rule');
      if (c === ']' && i > bracketStart) {
        inBracket = false;
        out += c;
        continue;
      }
      if (c === ']') {
        out += '\\]'; // ']' first in a bracket is literal in Postgres
        continue;
      }
      out += c;
      continue;
    }
    if (c === '[') {
      inBracket = true;
      out += c;
      if (p[i + 1] === '^') {
        out += '^';
        i += 1;
      }
      bracketStart = i + 1; // index of the first member
      if (p[i + 1] === ']') {
        out += '\\]';
        i += 1;
      }
      continue;
    }
    if (c === '(' && p[i + 1] === '?') {
      const rest = p.slice(i + 2);
      const ok = ['?:', '?=', '?!', '?<=', '?<!'].find((x) => `?${rest}`.startsWith(x));
      if (!ok) throw new WallRuleError('unsupported (? group in wall rule');
      out += `(${ok}`;
      i += ok.length;
      continue;
    }
    out += c;
  }
  if (inBracket) throw new WallRuleError('unsupported unterminated bracket in wall rule');
  try {
    return new RegExp(out, ci ? 'is' : 's');
  } catch {
    throw new WallRuleError('unsupported regex (does not compile in JS) in wall rule');
  }
}

// ---------------------------------------------------------------------------
// The verdict.

interface Compiled {
  rule: WallRule;
  re?: RegExp;
  lower?: string;
  /** wall_norm(pattern); null when it normalises to '' (never matches on the normalised side). */
  norm?: string | null;
}

export interface Wall {
  check(table: string, row: Row): Verdict;
  /** Hard-rule check for a bare uri or path (config validation, `wall allow` refusal). */
  checkUri(uri: string): Verdict;
  readonly rules: readonly WallRule[];
}

export function compileWall(rules: readonly WallRule[], allows: readonly WallAllowRow[]): Wall {
  const sorted = [...rules].sort((a, b) => a.id - b.id);
  const compiled: Compiled[] = sorted.map((rule) => {
    switch (rule.kind) {
      case 'path_glob':
      case 'lane':
      case 'repo':
        return { rule, re: new RegExp(globToRegex(rule.pattern, rule.kind === 'repo'), 'is') };
      case 'regex':
        return { rule, re: pgRegexToJs(rule.pattern) };
      case 'tag':
      case 'term':
        return { rule, lower: rule.pattern.toLowerCase(), norm: wallNorm(rule.pattern) || null };
      default:
        throw new WallRuleError(`unsupported wall rule kind ${String((rule as WallRule).kind)}`);
    }
  });
  const allowSet = new Set(allows.map((a) => `${a.sourceUri}\u0000${a.contentSha256.toLowerCase()}\u0000${a.ruleId}`));
  const stage1 = compiled.filter((c) => ['path_glob', 'lane', 'repo'].includes(c.rule.kind));
  const stage2 = compiled.filter((c) => c.rule.kind === 'tag');
  const stage3 = compiled.filter((c) => (c.rule.kind === 'regex' || c.rule.kind === 'term') && c.rule.hard);
  const stage4 = compiled.filter((c) => (c.rule.kind === 'regex' || c.rule.kind === 'term') && !c.rule.hard);

  const textHit = (c: Compiled, text: string) =>
    c.re ? c.re.test(text) : text.toLowerCase().includes(c.lower!);

  function check(table: string, input: Row): Verdict {
    assertTable(table);
    const row = withDefaults(table, input);
    const content = wallContent(table, row);
    const csha = sha256Hex(content);
    const uri = txt(row, 'source_uri');
    const uriD = uri === null ? null : pctDecode(uri);
    const pd = (x: string | null) => (x === null ? null : pctDecode(x));
    const nonNull = (xs: Array<string | null>) => xs.filter((x): x is string => x !== null);
    const withNorm = (xs: string[]) => [...xs, ...xs.map(wallNorm)];

    // Candidates: raw, percent-decoded, then the normalised form of each (0008).
    const vaultPath = txt(row, 'vault_path'), reviewRef = txt(row, 'review_ref'), logRef = txt(row, 'log_ref');
    const paths = withNorm(nonNull([
      uri === null ? null : uriPath(uri), uriD === null ? null : uriPath(uriD),
      vaultPath, pd(vaultPath), reviewRef, pd(reviewRef), logRef, pd(logRef),
    ]));
    const lanes: Array<string | null> = [
      txt(row, 'lane'),
      uri === null ? null : (/^lane:([^/#]+)/.exec(uri)?.[1] ?? null),
      uri === null ? null : (/lanes\/([^/#]+)/.exec(uri)?.[1] ?? null),
      uriD === null ? null : (/^lane:([^/#]+)/.exec(uriD)?.[1] ?? null),
      uriD === null ? null : (/lanes\/([^/#]+)/.exec(uriD)?.[1] ?? null),
    ];
    const repos: Array<string | null> = [
      txt(row, 'repo'), txt(row, 'linked_repo'),
      uri !== null && uri.startsWith('gh:') ? uriPath(uri) : null,
      uriD !== null && uriD.startsWith('gh:') ? uriPath(uriD) : null,
    ];
    const applies = row['applies_to'];
    if (Array.isArray(applies)) {
      for (const e of applies) {
        lanes.push(elemText(e));
        repos.push(elemText(e));
      }
    }
    const laneList = withNorm(nonNull(lanes));
    const repoList = withNorm(nonNull(repos)).filter((x) => btrim(x) !== '').map(normRepo);

    const hit = (c: Compiled): Verdict => ({ blocked: true, ruleId: c.rule.id, kind: c.rule.kind, hard: c.rule.hard, contentSha256: csha });

    for (const c of stage1) {
      const cands = c.rule.kind === 'path_glob' ? paths : c.rule.kind === 'lane' ? laneList : repoList;
      if (cands.some((x) => c.re!.test(x))) return hit(c);
    }
    if (stage2.length) {
      const raw = rowTags(table, row);
      const normInline = [...wallNorm(content).matchAll(INLINE_TAG)].map((m) => m[1]!);
      const lowered = raw.map((t) => t.toLowerCase());
      const normed = [...raw, ...normInline].map(wallNorm);
      for (const c of stage2) {
        if (lowered.some((t) => t.includes(c.lower!)) || (c.norm != null && normed.some((t) => t.includes(c.norm!)))) return hit(c);
      }
    }
    if (stage3.length) {
      // Free-text columns outside wall_content (r1 MINOR-3): prs.merged_to,
      // routine_runs.run_key, chunks.embed_model. Hard rules only.
      // 0009: a decoded uri / path that still holds a %XX escape adds the marker.
      const undecoded = nonNull([uriD, pd(vaultPath), pd(reviewRef), pd(logRef)]).some((x) => LEFTOVER_ESCAPE.test(x));
      const hardText = nonNull([
        content, uri, uriD, txt(row, 'merged_to'), txt(row, 'run_key'), txt(row, 'embed_model'),
        paths.join('\n'), laneList.join('\n'), repoList.join('\n'), undecoded ? WALL_UNDECODED_TERM : null,
      ]).join('\n');
      const normText = wallNorm(hardText);
      for (const c of stage3) {
        if (c.re ? c.re.test(hardText) || c.re.test(normText) : hardText.toLowerCase().includes(c.lower!) || (c.norm != null && normText.includes(c.norm))) return hit(c);
      }
    }
    for (const c of stage4) {
      if (textHit(c, content) && !(uri !== null && allowSet.has(`${uri}\u0000${csha}\u0000${c.rule.id}`))) return hit(c);
    }
    return { blocked: false, ruleId: null, kind: null, hard: false, contentSha256: csha };
  }

  function checkUri(uri: string): Verdict {
    const v = check('facts', { source_uri: uri, kind: 'other', text: '', subject: null });
    return v.blocked && v.hard ? v : { blocked: false, ruleId: null, kind: null, hard: false, contentSha256: v.contentSha256 };
  }

  return { check, checkUri, rules: sorted };
}

/** The wall compiled from the seed rules (offline use only). */
export function seedWall(): Wall {
  return compileWall(seedRulesWithIds(), []);
}

/** The 0009 wall (before the 0010 ClientCo lift). Offline comparison only (wall-dryrun --compare-old). */
export function legacySeedWall(): Wall {
  return compileWall(legacySeedRulesWithIds(), []);
}

/** The 0010 wall (before 0011: no Plankiva rule, soft currency / P&L rules). Offline comparison only. */
export function wall0010SeedWall(): Wall {
  return compileWall(seed0010RulesWithIds(), []);
}

/** Load the live rules and allows (zeusi_ingest has SELECT on both). */
export async function loadWall(db: Db): Promise<Wall> {
  const rules = await db.query<{ id: number; kind: RuleKind; hard: boolean; pattern: string }>(
    `SELECT id::int AS id, kind::text AS kind, hard, pattern FROM zeusi.wall_denylist ORDER BY id`,
  );
  const allows = await db.query<{ source_uri: string; sha: string; rule_id: number }>(
    `SELECT source_uri, encode(content_sha256, 'hex') AS sha, rule_id::int AS rule_id FROM zeusi.wall_allow`,
  );
  return compileWall(
    rules.rows.map((r) => ({ id: Number(r.id), kind: r.kind, hard: r.hard, pattern: r.pattern })),
    allows.rows.map((a) => ({ sourceUri: a.source_uri, contentSha256: a.sha, ruleId: Number(a.rule_id) })),
  );
}

export interface WallReadiness {
  /** Superuser, or can write wall_allow. Callers word their own refusal for this. */
  ownerPrivileged: boolean;
  /** Missing wall migrations 0006-0011 / missing or softened seed rules, one line each. Empty = ready. */
  problems: string[];
}

/**
 * The wall readiness shared by real ingest (importers/vault.ts assertIngestReady) and
 * `embed` (embed.ts runEmbed): wall migrations 0006-0011 applied ('tag' rule kind
 * (0006), wall_eval (0007), wall_norm + pct_decode (0008), the hard
 * undecoded-percent-escape rule (0009), the clientco scope (0010), the hard Plankiva variants
 * rule with the soft currency / P&L rules gone (0011)) and every current seed rule
 * present as seeded (SEED_RULES). Reads catalog + wall config only, never chunk text.
 */
export async function wallReadiness(db: Db): Promise<WallReadiness> {
  const r = (await db.query<{ su: boolean; owner_like: boolean; m0006: boolean; m0007: boolean; m0008: boolean; m0009: boolean; m0010: boolean; m0011: boolean }>(
    `SELECT coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false) AS su,
            has_table_privilege('zeusi.wall_allow', 'INSERT') AS owner_like,
            EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid JOIN pg_namespace n ON n.oid = t.typnamespace
                    WHERE n.nspname = 'zeusi' AND t.typname = 'wall_rule_kind' AND e.enumlabel = 'tag') AS m0006,
            to_regprocedure('zeusi.wall_eval(text,jsonb)') IS NOT NULL AS m0007,
            to_regprocedure('zeusi.wall_norm(text)') IS NOT NULL AND to_regprocedure('zeusi.pct_decode(text)') IS NOT NULL AS m0008,
            EXISTS (SELECT 1 FROM zeusi.wall_denylist WHERE kind::text = 'term' AND pattern = $1 AND hard) AS m0009,
            EXISTS (SELECT 1 FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid JOIN pg_namespace n ON n.oid = t.typnamespace
                    WHERE n.nspname = 'zeusi' AND t.typname = 'scope' AND e.enumlabel = 'client') AS m0010,
            EXISTS (SELECT 1 FROM zeusi.wall_denylist WHERE kind::text = 'regex' AND pattern = $2 AND hard)
              AND NOT EXISTS (SELECT 1 FROM zeusi.wall_denylist WHERE kind::text = 'regex' AND NOT hard AND pattern = ANY($3::text[])) AS m0011`,
    [WALL_UNDECODED_TERM, PROTECTED_VARIANTS_REGEX, LIFTED_0011.map((r) => r.pattern)],
  )).rows[0]!;
  const problems: string[] = [];
  if (!r.m0006) problems.push('migration 0006 (wall tag kind) is not applied');
  if (!r.m0007) problems.push('migration 0007 (wall_eval / Plankiva rules) is not applied');
  if (!r.m0008) problems.push('migration 0008 (wall_norm / pct_decode) is not applied');
  if (!r.m0009) problems.push('migration 0009 (undecoded-percent-escape hard rule) is not applied');
  if (!r.m0010) problems.push('migration 0010 (clientco scope, ClientCo lift, Plankiva spelling rule) is not applied');
  if (!r.m0011) problems.push('migration 0011 (Plankiva variants hard rule, soft currency / P&L lift) is not applied');
  if (r.m0006) {
    const wall = await loadWall(db);
    const missing = SEED_RULES.filter((s) => !wall.rules.some((x) => x.kind === s.kind && x.pattern === s.pattern && x.hard === s.hard));
    if (missing.length) problems.push(`${missing.length} seeded wall rule(s) missing or softened`);
  }
  return { ownerPrivileged: r.su || r.owner_like, problems };
}

export interface GateInput {
  table: WallTable;
  row: Row;
  ingestRunId: number;
}

export type GateResult =
  | { status: 'pass'; verdict: Verdict }
  | { status: 'quarantined'; verdict: Verdict; quarantineId: number };

/**
 * Importer gate: pre-check a row with wall.ts and, when blocked, record it in
 * zeusi.quarantine (uri + hashes only — never text) before anything is sent.
 */
export async function wallGate(db: Db, wall: Wall, input: GateInput): Promise<GateResult> {
  const verdict = wall.check(input.table, input.row);
  if (!verdict.blocked) return { status: 'pass', verdict };
  const q = await recordQuarantine(db, {
    sourceKind: String(input.row['source_kind'] ?? 'manual'),
    sourceUri: String(input.row['source_uri']),
    sourceSha256: String(input.row['source_sha256']),
    ruleId: verdict.ruleId,
    ingestRunId: input.ingestRunId,
    table: input.table,
    contentSha256: verdict.contentSha256,
  });
  return { status: 'quarantined', verdict, quarantineId: q };
}

/**
 * The one caller of quarantine_record (test/c6b-write-structured.test.ts pins that by a source scan).
 * Plain route: the uri and hashes as given (the team, flag-off workspaces). Sealed route (C6 KTD12):
 * source_uri = 'hmac:' + hex(indexHmac('quarantine-uri', uri)), source_sha256 = the keyed digest of the
 * plain digest, content_sha256 = NULL (it only fed plain-uri wall_allow pins, which flip deletes).
 */
export async function recordQuarantine(
  db: Db,
  q: { sourceKind: string; sourceUri: string; sourceSha256: string; ruleId: number | null; ingestRunId: number; table: string; contentSha256: string | null },
  route?: WriteRoute,
): Promise<number> {
  const v = route?.kind === 'sealed'
    ? { ...q, sourceUri: route.key.quarantineRef(q.sourceUri), sourceSha256: route.key.keyedSha('source_sha256', q.sourceSha256).toString('hex'), contentSha256: null }
    : q;
  const r = await db.query<{ id: string }>(
    `SELECT zeusi.quarantine_record($1::zeusi.source_kind, $2, decode($3, 'hex'), $4, $5, $6,
                                    CASE WHEN $7::text IS NULL THEN NULL ELSE decode($7, 'hex') END) AS id`,
    [v.sourceKind, v.sourceUri, v.sourceSha256.toLowerCase(), v.ruleId, v.ingestRunId, v.table, v.contentSha256],
  );
  return Number(r.rows[0]!.id);
}
