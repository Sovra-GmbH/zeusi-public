// The ONE credential detector (security P0, 17 Nov 2026: a partial key was served by zeusi_search).
//
// Used by every path that can carry text into, through or out of Zeusi:
//   * ingest: the vault / hq-sync importer redacts each file's text before it parses, chunks
//     and writes it (src/importers/vault.ts); `fact add` redacts the fact text (src/facts.ts);
//   * the nightly HQ export filter withholds an entry that trips it (src/hq-export.ts,
//     credentialSignal), and its output gate re-checks every file;
//   * serve time: every MCP tool result (search hits, decisions, startup rules / focus /
//     decisions, notices, error messages) is WITHHELD, never redacted, when this detector,
//     origin/main's patterns or a [REDACTED: marker fires (src/mcp-wall.ts); the CLI search
//     output (local operator) is redacted (src/search.ts formatSearch);
//   * `zeusi rescrub` re-scrubs rows that were ingested before this detector existed
//     (src/rescrub.ts).
//
// What it catches (kind in brackets; the replacement is `[REDACTED:<kind>]`):
//   * provider key prefixes, full OR truncated (prefix + at least 6 key characters): Google
//     `AIza` [google_api_key], OpenAI `sk-` / `sk-proj-` / `sk-svcacct-` [openai_key],
//     Anthropic `sk-ant-` [anthropic_key], GitHub `gh[pousr]_` / `github_pat_` [github_token],
//     Slack `xox[abposr]-` [slack_token], AWS `AKIA` / `ASIA` [aws_key_id], Stripe
//     `sk_live_` / `rk_live_` / `*_test_` [stripe_key], Fly `fo1_` / `FlyV1 fm2_...` / `fm2_`
//     [fly_token], Neon `npg_` [neon_password];
//   * MASKED fragments of those keys: a real prefix, then an ellipsis (`…` or `...`),
//     asterisks or bullets, with key characters around the mask, when the prefix plus the
//     visible key characters are at least 6 and at least 2 of them are not the prefix
//     (`<prefix>…<tail>`, `<prefix>****<tail>`, `<prefix><head>...<tail>`) [masked_<kind>];
//     a single `*` / bullet or a spaced mask (`<prefix> … <tail>`) too, when the visible key
//     characters hold a digit (review r1 P2-1);
//   * SPLIT keys: prefix + head, a line break or markdown (backtick, `*`, `~~`), the rest
//     (head + rest a valid body with a digit) [<kind>] (review r1 P2-1);
//   * JWTs [jwt], PEM / OpenSSH / PGP private key blocks [private_key] (BEGIN to the END line,
//     or to the end of the text; never to a blank line), URLs with an inline password
//     [url_password] (the password, to the LAST `@` of the authority), `Bearer <token>`
//     [bearer] (a token68 start, then to the next whitespace or quote): every delimiter-bounded
//     value is replaced whole, never leaving a residue (fix round 2 finish);
//   * keyword = value forms (`GEMINI_API_KEY=...`, `password: ...`, `client_secret: ...`):
//     everything from the value start to the end of the line is redacted, quoted or not (on a
//     markdown table row: to the next ` |` cell bar; a YAML block scalar: the indented lines
//     below), the keyword kept [keyword_value]; one keyword
//     definition (KEYWORD_HEAD) shared with the withhold floor and redactDeep's field names;
//   * 2FA / one-time codes after a code keyword [otp_code] (same shapes as before, fix
//     round 1 m1/m2 of the export filter; docs/hq-sync.md).
//
// False positives are bounded: prefixes are matched case-sensitively and only at a token
// start (no letter or digit right before), short generic prefixes need a digit in the
// key part, AWS needs a digit (or the full 16 characters), a prefix alone (`AIza…`, `sk-...`)
// is NOT a secret, placeholders (`<your key>`, `${VAR}`, `process.env.X`, an existing
// `[REDACTED:...]`) are NOT a value. Redaction is idempotent: redacted text never trips again.
//
// Nothing here logs, prints or returns the matched characters: findSecrets returns kinds and
// offsets, redactSecrets returns the redacted text and counts by kind.

export const SECRET_KINDS = [
  'google_api_key', 'openai_key', 'anthropic_key', 'github_token', 'slack_token', 'aws_key_id', 'stripe_key', 'fly_token',
  'neon_password', 'jwt', 'private_key', 'url_password', 'bearer', 'keyword_value', 'otp_code',
] as const;
export type ProviderKind = 'google_api_key' | 'openai_key' | 'anthropic_key' | 'github_token' | 'slack_token' | 'aws_key_id' | 'stripe_key' | 'fly_token' | 'neon_password';
export type SecretKind = (typeof SECRET_KINDS)[number] | `masked_${ProviderKind}`;

export interface SecretMatch {
  kind: SecretKind;
  /** Offsets of the part that is replaced (the value only, for keyword=value / URL / bearer / otp). */
  start: number;
  end: number;
}

export interface RedactResult {
  text: string;
  /** Total secrets replaced. */
  count: number;
  byKind: Partial<Record<SecretKind, number>>;
}

export const REDACTED_PREFIX = '[REDACTED:';
export const redactedMarker = (kind: SecretKind): string => `${REDACTED_PREFIX}${kind}]`;

/** Characters a key body is made of (base64url + the dot JWT / Fly tokens use is handled per rule). */
const BODY = String.raw`[A-Za-z0-9_-]`;
/** Token start: no letter or digit right before (an underscore may be markdown emphasis: `_key_`). */
const START = String.raw`(?<![A-Za-z0-9])`;
/** Masks people use when they show part of a key (a single `*` / bullet too; one space or NBSP may sit on either side). */
const MASK = String.raw`[ \u00a0]?(?:\u2026|\.{2,}|\*+|\u2022+|\u00b7{2,})[ \u00a0]?`;
/** A weak mask (one `*` or bullet, or a mask with a space around it) could be prose or markdown: the visible key characters must then hold a digit. */
const WEAK_MASK = /^(?:[ \u00a0].*|.*[ \u00a0]|[*\u2022])$/s;
/**
 * A STRONG mask (no space, not a single `*` / bullet): after the first mask, the tail runs on
 * across further strong masks (`<prefix><head>…<k1>…<k2>`), so no visible piece of the key is
 * left after the marker (fix round 2 finish: whole credential span, never residue). Only strong
 * masks chain: a chain then stops at the next weak-masked prefix, which keeps the scan linear.
 */
const STRONG_MASK = String.raw`(?:\u2026|\.{2,}|\*{2,}|\u2022{2,}|\u00b7{2,})`;
/** Mask characters inside a chained tail (not key characters). */
const MASK_CHARS = /[\u2026.*\u2022\u00b7]/g;
/**
 * Where a key is SPLIT without a mask (review r1 P2-1): a line break (with indentation or a
 * `>` quote marker on the next line), or markdown around part of it (a backtick, `*` / `**`, `~~`).
 */
/**
 * Longest key head before a mask or a split (bounds the work per start position: linear time
 * on long unbroken runs, review r1 P2-3). A longer head is caught by the unmasked rule.
 */
const HEAD_MAX = 256;
const SPLIT = String.raw`(?:[ \t]*\r?\n[ \t>]*|\x60{1,3}|\*{1,2}|~~)`;
/**
 * A key or token hard-wrapped over MORE lines (self-review fix2e, storage side): any number of
 * further lines that hold ONLY key characters (8 or more, optional indentation or `>` before,
 * whitespace after) continue the span. A line with anything else on it ends the chain, so prose
 * after a key is never swallowed. Each segment starts at a line break: linear time.
 */
const wrapped = (body: string) => String.raw`(?:[ \t]*\r?\n[ \t>]*${body}{8,}(?=[ \t]*\r?(?:\n|$)))*`;
/** Line breaks, indentation and `>` inside a wrapped tail (not key characters). */
const WRAP_CHARS = /[\s>]/g;

interface Provider {
  kind: ProviderKind;
  /** Regex source of the prefix (case-sensitive). */
  prefix: string;
  /** Body character class (default BODY). */
  body?: string;
  /** Minimum body length for an UNMASKED (full or truncated) match. */
  min: number;
  /** Extra check on the unmasked body (bounded false positives). */
  accept?: (body: string) => boolean;
}

const hasDigit = (b: string) => /\d/.test(b);

// Order matters: the longer, more specific prefix first (sk-ant- before sk-).
const PROVIDERS: readonly Provider[] = [
  { kind: 'google_api_key', prefix: 'AIza', min: 6 },
  { kind: 'anthropic_key', prefix: 'sk-ant-', min: 6 },
  { kind: 'openai_key', prefix: 'sk-(?:proj|svcacct|admin)-', min: 6 },
  { kind: 'stripe_key', prefix: '(?:sk|rk)_(?:live|test)_', min: 6, accept: (b) => hasDigit(b) || b.length >= 16 },
  { kind: 'openai_key', prefix: 'sk-', min: 6, accept: (b) => hasDigit(b) || b.length >= 20 },
  { kind: 'github_token', prefix: 'github_pat_', min: 6 },
  { kind: 'github_token', prefix: 'gh[pousr]_', min: 6, accept: (b) => hasDigit(b) || b.length >= 20 },
  { kind: 'slack_token', prefix: 'xox[abposr]-', body: '[A-Za-z0-9-]', min: 6, accept: hasDigit },
  { kind: 'aws_key_id', prefix: '(?:AKIA|ASIA)', body: '[A-Z0-9]', min: 8, accept: (b) => b.length >= 16 || (hasDigit(b) && /[A-Z]/.test(b)) },
  { kind: 'fly_token', prefix: 'fo1_', min: 6 },
  { kind: 'fly_token', prefix: String.raw`FlyV1\s+fm[12]_`, body: '[A-Za-z0-9_+/=,-]', min: 6 },
  { kind: 'fly_token', prefix: 'fm[12]_', body: '[A-Za-z0-9_+/=,-]', min: 20 },
  { kind: 'neon_password', prefix: 'npg_', body: '[A-Za-z0-9]', min: 12 },
];

type Rule = {
  kind: SecretKind | ((m: RegExpExecArray) => SecretKind | null);
  re: RegExp;
  /** Named group(s) holding the part to replace (the first that took part; default: the whole match). */
  group?: string | readonly string[];
  /**
   * On a rejected match, resume AFTER it, not one character later. Safe for the unmasked
   * provider rules: the body class holds the prefix characters, so any later start inside
   * the match has a body that is a suffix of this one, and every accept check (minimum
   * length, a digit, AWS length / digit + capital) is monotone: a suffix of a rejected body
   * is rejected too. Keeps the scan linear on long runs of repeated prefixes.
   */
  skipOnReject?: boolean;
  /**
   * Full control over an accepted match (instead of kind + group): the kind and the span to
   * replace, and where the scan resumes; null = rejected (retry one character further).
   */
  resolve?: (m: RegExpExecArray, ctx: ScanContext) => (SecretMatch & { resume: number }) | null;
};

/** Per-scan helpers (line boundaries found once, amortised linear as the scan moves forward). */
interface ScanContext {
  /** Start of the line holding offset i. */
  lineStart(i: number): number;
  /** End of the line holding offset i (the `\n`, or the text length; a `\r` before it is inside). */
  lineEnd(i: number): number;
}

function scanContext(s: string): ScanContext {
  // Newline positions, built once per scan (linear); lookups by binary search.
  const nl: number[] = [];
  for (let i = s.indexOf('\n'); i !== -1; i = s.indexOf('\n', i + 1)) nl.push(i);
  const after = (i: number) => {
    let lo = 0;
    let hi = nl.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (nl[mid]! < i) lo = mid + 1;
      else hi = mid;
    }
    return lo; // index of the first newline at or after i
  };
  return {
    lineStart: (i) => { const k = after(i); return k === 0 ? 0 : nl[k - 1]! + 1; },
    lineEnd: (i) => { const k = after(i); return k === nl.length ? s.length : nl[k]!; },
  };
}

/** A markdown table row: optional whitespace, then `|` (sticky, tested at a line start). */
const TABLE_ROW = /[ \t]*\|/y;
function isTableRow(s: string, lineStart: number): boolean {
  TABLE_ROW.lastIndex = lineStart;
  return TABLE_ROW.test(s);
}

const MASKED_RULES: Rule[] = PROVIDERS.map((p) => {
  const body = p.body ?? BODY;
  return {
    kind: (m: RegExpExecArray) => {
      const head = m.groups!['head']!.length;
      const tailRaw = m.groups!['tail']!;
      const mask = m.groups!['mask']!;
      const prefixLen = m[0].length - head - tailRaw.length - mask.length;
      const tailText = tailRaw.replace(MASK_CHARS, '');
      const tail = tailText.length;
      if (WEAK_MASK.test(mask) && !hasDigit(m.groups!['head']! + tailText)) return null;
      return head + tail >= 2 && prefixLen + head + tail >= 6 ? (`masked_${p.kind}` as SecretKind) : null;
    },
    re: new RegExp(`${START}${p.prefix}(?<head>${body}{0,${HEAD_MAX}}?)(?<mask>${MASK})(?<tail>${body}*(?:${STRONG_MASK}${body}+)*)`, 'g'),
  };
});

/**
 * A key split over a line break or by markdown, with no mask: prefix + head, the split, then
 * the rest. Accepted when head + rest is a valid unmasked body for that provider AND holds a
 * digit (a prefix at the end of a line followed by an ordinary word is prose, not a key).
 */
const SPLIT_RULES: Rule[] = PROVIDERS.map((p) => {
  const body = p.body ?? BODY;
  return {
    kind: (m: RegExpExecArray) => {
      const b = m.groups!['head']! + m.groups!['tail']!.replace(WRAP_CHARS, '');
      return b.length >= p.min && hasDigit(b) && (p.accept?.(b) ?? true) ? p.kind : null;
    },
    re: new RegExp(`${START}${p.prefix}(?<head>${body}{0,${HEAD_MAX}})${SPLIT}(?<tail>${body}+${wrapped(body)})`, 'g'),
  };
});

const UNMASKED_RULES: Rule[] = PROVIDERS.map((p) => ({
  kind: (m: RegExpExecArray) => {
    const b = m.groups!['b']!;
    return b.length >= p.min && (p.accept?.(b) ?? true) ? p.kind : null;
  },
  re: new RegExp(`${START}${p.prefix}(?<b>${p.body ?? BODY}+)`, 'g'),
  skipOnReject: true,
}));

/**
 * A placeholder, a reference or an already-redacted value: not a secret. A placeholder must
 * span the WHOLE value (`<your-token>`, `${VAR}`, `$ALL_CAPS_VAR`, `{{name}}`): a real value
 * that merely starts with `$`, `<` or `{{` (generated passwords do) is still a secret
 * (security review, 17 Nov 2026: a first-character exclusion let such values through).
 */
// Case-sensitive on purpose (the keyword rule is /i): `$ALL_CAPS` is an env reference,
// `$Mixed9...` is a value. Trailing sentence punctuation is allowed after a placeholder.
const PLACEHOLDER_RE = /^(?:<[^<>\s]+>|\$\{[A-Za-z_][A-Za-z0-9_.:-]*\}|\$[A-Z_][A-Z0-9_]*|\{\{[^{}\s]+\}\})[.,;:)\]]*$/;
const KEYWORD = String.raw`(?:password|passwd|pwd|passphrase|secret|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|token)`;
/**
 * THE credential keyword (review r2 P1-1 / P2-1: ONE definition, used by the detector's
 * keyword rule AND by the withhold floor, so the places that redact, withhold, export and
 * store all agree): a KEYWORD at the start of a word run, optionally with a prefix
 * (`DB_PASSWORD`, `GEMINI_API_KEY`, `refresh_token`, `my-secret`), and not followed by a
 * letter or digit (`tokenizer`, `passwords` are not keywords). Used case-insensitively.
 * Starting only at the start of a run keeps it linear on long `a_a_a_...` runs.
 */
export const KEYWORD_HEAD = String.raw`(?<![A-Za-z0-9_-])(?:[A-Za-z0-9]*[_-])*${KEYWORD}(?![A-Za-z0-9])`;
/** The assignment after a keyword: an optional closing quote of a JSON / YAML key, then `:`, `=`, `:=` or `=>` (at most one line break before the value). */
const KEYWORD_ASSIGN = String.raw`["']?[ \t]*(?::=|=>|[:=])[ \t]*(?:\r?\n[ \t]*)?`;
/** A value that is only a redaction marker (any kind): already clean, so redaction is idempotent. */
const ONLY_MARKER = /^\[REDACTED:[a-z_]+\]$/;
/** Masks and references that are not a value (the whole value). */
const NOT_A_VALUE_RE = /^(?:\*+|x{6,}|X{6,}|(?:process\.env|os\.environ|os\.getenv|env\()\S*)$/;
/** A field name that is a credential keyword (the same KEYWORD_HEAD, the whole name). */
const KEYWORD_FIELD = new RegExp(String.raw`^${KEYWORD_HEAD}$`, 'i');
/** A keyword field's value (an object field, not text): a secret unless short, a marker, a mask or a placeholder. */
function keywordFieldValue(raw: string): boolean {
  const v = raw.trim();
  if (v.replace(/\s+/g, '').length < 6) return false;
  return !(ONLY_MARKER.test(v) || NOT_A_VALUE_RE.test(v) || PLACEHOLDER_RE.test(v));
}
/**
 * The value span of a keyword in text, as resolveKeyword cut it: a secret unless it is exactly
 * one redaction marker, or (once a trailing `,` / `;` and one pair of enclosing quotes are set
 * aside) short, a mask or a placeholder (`"<your-token>",`, `'${DB_PW}'`). A quoted marker
 * (`"[REDACTED:...]"`, the shape older heads stored) IS rewritten, to the bare marker: the
 * withhold floor accepts only whitespace after a marker on a non-table line.
 */
function keywordSpanValue(raw: string): boolean {
  let v = raw.trim();
  if (ONLY_MARKER.test(v)) return false;
  v = v.replace(/[,;]$/, '');
  const q = v[0];
  if ((q === '"' || q === "'" || q === '`') && v.length >= 2 && v.endsWith(q)) v = v.slice(1, -1);
  if (ONLY_MARKER.test(v.trim())) return true;
  return keywordFieldValue(v);
}

/** The end of a table cell: a `|` with whitespace before it, or the line end (searched from a value start). */
const CELL_END = /[ \t]\||\n/g;

/**
 * THE VALUE SPAN RULE (fix round 2, simplified): when a keyword is assigned (`kw:`, `kw=`,
 * `kw :=`, `kw =>`, a quoted key), EVERYTHING from the first non-space character of the value
 * to the end of that line is the value, quoted or not, whatever it holds (quotes, doubled or
 * escaped quotes, shell quote-joining, `+` concatenation, `|`, `, `, `; `, more words, a
 * trailing comment, a following setting). One exception: on a markdown table row (a line that
 * starts with optional whitespace then `|`) the value ends at the next `|` that has whitespace
 * before it (the cell bar), or at the line end; the other cells stay readable. A table cell
 * that starts with `|` is empty (no value). Trailing whitespace stays outside the span. The
 * scan resumes after the span, so a later cell on a table row is checked too. Linear: the
 * regex captures one character; the end is the line end or one forward search to it.
 */
function resolveKeyword(m: RegExpExecArray, ctx: ScanContext): (SecretMatch & { resume: number }) | null {
  const s = m.input;
  const start = m.indices!.groups!['v']![0];
  let end = ctx.lineEnd(start);
  // A YAML block scalar: the indented lines below. No such line (or only a placeholder there):
  // the line-end rule below still applies to the header line (`| # <text>` on a flattened line).
  if (BLOCK_HEADER.test(s.slice(start, end))) {
    const block = resolveBlock(s, ctx, m.index, start, end);
    if (block !== null) return block;
  }
  if (isTableRow(s, ctx.lineStart(start))) {
    if (s[start] === '|') return null;
    CELL_END.lastIndex = start;
    const c = CELL_END.exec(s);
    if (c !== null && c.index < end) end = c.index;
  }
  while (end > start && /\s/.test(s[end - 1]!)) end--;
  return keywordSpanValue(s.slice(start, end)) ? { kind: 'keyword_value', start, end, resume: end } : null;
}

/** A YAML block scalar header as the whole rest of the line: `|` or `>`, chomping / indent indicators, an optional comment. */
const BLOCK_HEADER = /^[|>](?:[+-]?[1-9]?|[1-9][+-])[ \t]*(?:#.*)?\r?$/;
/**
 * A keyword whose value is a YAML block scalar (`password: |` / `private_key: >-`, then the
 * value on the following, more indented lines): the span runs from the header to the end of the
 * last line indented deeper than the keyword's line (blank lines inside are part of it), so no
 * line of a multi-line value is left (fix round 2 finish). Linear: each line is visited once and
 * the scan resumes after the block.
 */
function resolveBlock(s: string, ctx: ScanContext, kwAt: number, start: number, headerEnd: number): (SecretMatch & { resume: number }) | null {
  const ls = ctx.lineStart(kwAt);
  const indentOf = (from: number) => { let i = from; while (s[i] === ' ' || s[i] === '\t') i++; return i - from; };
  const kwIndent = indentOf(ls);
  let end = headerEnd;
  const parts: string[] = [];
  for (let pos = headerEnd + 1; headerEnd < s.length && pos <= s.length; ) {
    const le = ctx.lineEnd(pos);
    const line = s.slice(pos, le);
    if (line.trim() !== '') {
      if (indentOf(pos) <= kwIndent) break;
      parts.push(line.trim());
      end = le;
    }
    if (le >= s.length) break;
    pos = le + 1;
  }
  while (end > start && /\s/.test(s[end - 1]!)) end--;
  if (parts.length === 0) return null;
  return keywordFieldValue(parts.join(' ')) ? { kind: 'keyword_value', start, end, resume: end } : null;
}

/**
 * A CODE: 6-8 digits, or two groups of 3-4 digits split by one space or "-". Not part of a
 * longer number or word (no letter, digit or "_" right before, no digit + [.,:/ -] before or
 * after, no digit right after), not a compact date YYYYMMDD (19xx/20xx, real month and day
 * range), and not followed by a time / size / rate unit.
 */
function otpCode(): string {
  const date = String.raw`(?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?!\d)`;
  const unit = String.raw`\s*(?:%|(?:ms|msec|µs|us|ns|s|secs?|seconds?|mins?|minutes?|h|hrs?|hours?|days?|[kmgt]i?b|bytes?|px|rps|qps|tokens?|rows?|lines?|chars?)\b)`;
  return String.raw`(?<v>(?<![A-Za-z0-9_])(?<!\d[.,:/ -])(?!${date})(?:\d{6,8}|\d{3,4}[ -]\d{3,4})(?!\d)(?![.,:/ -]\d)(?!${unit}))`;
}

const OTHER_RULES: Rule[] = [
  // PEM / OpenSSH / PGP private key: the whole block, from BEGIN up to its END line, or to the
  // end of the text when there is no END line. NEVER to a blank line: PGP armor and encrypted
  // PEM have a blank line between the headers and the key body (self-review fix2d, Vuln 1).
  { kind: 'private_key', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|$)/g },
  { kind: 'jwt', re: /(?<![A-Za-z0-9_])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  // URL userinfo password: from after `<user>:` to the LAST `@` of the authority (the WHATWG URL
  // parser and urlsplit end the userinfo there), so a password holding `@` is replaced whole
  // (self-review fix2d, Vuln 2). The user may be empty (`redis://:<pw>@host`). A value that is
  // only a marker is clean (idempotent); a legacy partial `[REDACTED:url_password]@<rest>@host`
  // is a value and is redacted whole on the next pass.
  {
    kind: (m) => (ONLY_MARKER.test(m.groups!['v']!) ? null : 'url_password'),
    re: /(?<![A-Za-z0-9+.-])[a-z0-9+.-]+:\/\/[^\s:/@'"`]*:(?<v>[^\s/'"`]+)@/gi,
    group: 'v',
  },
  // Bearer token: a token68 run of 20+ characters starts it; the span runs on to the next
  // whitespace or quote, so a token with a character outside token68 (`%`, `,`, `!`) leaves no
  // tail, and on over further lines made only of token characters (a wrapped header, fix2e).
  { kind: 'bearer', re: new RegExp(String.raw`\bbearer\s+(?<v>[A-Za-z0-9._~+/-]{20,}=*[^\s"'\x60]*` + wrapped('[A-Za-z0-9._~+/=-]') + ')', 'gi'), group: 'v' },
  // keyword = value: everything from the value start to the line end (on a table row: to the
  // cell bar) is replaced, quoted or not (resolveKeyword). A legacy row redacted only in part
  // (`kw: [REDACTED:keyword_value] w2`, `kw: "[REDACTED:keyword_value]"x`) is a value too:
  // the rest is redacted on the next pass (rescrub). A value that is only a marker is clean.
  {
    kind: 'keyword_value',
    re: new RegExp(KEYWORD_HEAD + KEYWORD_ASSIGN + String.raw`(?<v>\S)`, 'gi'),
    resolve: resolveKeyword,
  },
  // 2FA / one-time codes (fix round 1, m1/m2; docs/hq-sync.md mirrors this exactly):
  //   a strong keyword, then at most 32 characters on the same line, then a CODE; or
  { kind: 'otp_code', re: new RegExp(String.raw`\b(?:2fa|mfa|otp|totp|one[- ]time|verification|verify|security|sign[- ]?in|log[- ]?in|auth(?:entication|enticator)?|passcode|recovery)\b[^\n]{0,32}?` + otpCode(), 'gi'), group: 'v' },
  //   the word "code", then optionally ":", "=", "#", "is" or "was", then a CODE.
  { kind: 'otp_code', re: new RegExp(String.raw`\bcode\b\s*(?:[:=#]|is\b|was\b)?\s*` + otpCode(), 'gi'), group: 'v' },
];

/** Every rule, most specific first (masked provider fragments, full/partial provider keys, the rest). */
const RULES: readonly Rule[] = [...MASKED_RULES, ...SPLIT_RULES, ...UNMASKED_RULES, ...OTHER_RULES].map((r) => ({
  ...r, re: r.re.flags.includes('d') ? r.re : new RegExp(r.re.source, r.re.flags + 'd'),
}));

/** Invisible characters someone may have pasted into a key (zero-width, soft hyphen, BOM). */
const INVISIBLE = /[\u00ad\u200b-\u200d\u2060\ufeff]/g;

/**
 * Kinds NOT rewritten in stored data (ingest, rescrub): one-time codes expire, and that rule
 * (built as a withhold backstop for the HQ export) also fires on plain counts next to
 * "login" / "security", which must not be rewritten in a note. Serve time and the export
 * filter still apply it (an item is redacted / an entry withheld).
 */
export const STORAGE_SKIP: readonly SecretKind[] = ['otp_code'];

export interface ScanOptions {
  /** Rule kinds to ignore (static-kind rules only; provider kinds are never skipped). */
  skip?: readonly SecretKind[];
}

function scan(s: string, o: ScanOptions = {}): SecretMatch[] {
  const found: SecretMatch[] = [];
  let ctx: ScanContext | undefined;
  for (const r of RULES) {
    if (o.skip && typeof r.kind === 'string' && o.skip.includes(r.kind)) continue;
    r.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = r.re.exec(s)) !== null) {
      if (m[0].length === 0) {
        r.re.lastIndex++;
        continue;
      }
      if (r.resolve) {
        const x = r.resolve(m, (ctx ??= scanContext(s)));
        if (x === null) {
          r.re.lastIndex = m.index + 1;
          continue;
        }
        found.push({ kind: x.kind, start: x.start, end: x.end });
        r.re.lastIndex = Math.max(x.resume, m.index + 1);
        continue;
      }
      const kind = typeof r.kind === 'function' ? r.kind(m) : r.kind;
      if (kind === null) {
        // Not accepted at this start: retry one character further (a later, valid match may overlap).
        r.re.lastIndex = r.skipOnReject ? m.index + m[0].length : m.index + 1;
        continue;
      }
      let start = m.index;
      let end = m.index + m[0].length;
      const names = r.group === undefined ? [] : typeof r.group === 'string' ? [r.group] : r.group;
      const g = names.map((n) => m!.indices?.groups?.[n]).find((x) => x !== undefined);
      if (g) [start, end] = g;
      found.push({ kind, start, end });
    }
  }
  return merge(found);
}

/** Earliest first; at the same start the longest; drop matches inside an earlier one, widen overlaps. */
function merge(found: SecretMatch[]): SecretMatch[] {
  found.sort((a, b) => a.start - b.start || b.end - a.end);
  const out: SecretMatch[] = [];
  for (const f of found) {
    const last = out[out.length - 1];
    if (last && f.start < last.end) {
      if (f.end > last.end) last.end = f.end; // overlapping: widen, keep the first (more specific) kind
      continue;
    }
    out.push({ ...f });
  }
  return out;
}

/** The secrets in s: kinds and offsets only (into s itself). Never the characters. */
export function findSecrets(s: string): SecretMatch[] {
  if (typeof s !== 'string' || s === '') return [];
  return scan(s);
}

/** True when s carries any secret shape (including one hidden by invisible characters). */
export function credentialSignal(s: string): boolean {
  if (typeof s !== 'string' || s === '') return false;
  if (scan(s).length > 0) return true;
  const visible = s.replace(INVISIBLE, '');
  return visible !== s && scan(visible).length > 0;
}

/**
 * The WITHHOLD floor (review r1 P2-4): the credential patterns the nightly export filter and
 * the MCP output wall used before the shared detector, kept verbatim except that an existing
 * `[REDACTED:...]` marker is not a value. strictCredentialSignal = the shared detector OR
 * this floor, so the places that WITHHOLD (export filter, output wall, MCP input checks) are
 * never looser than before: whole-value placeholders after a keyword (`token: <x>`,
 * `${VAR}`, `$ALL_CAPS`, `process.env.X`), a JWT right after `-`, a digit-free Slack token
 * and a keyword value with a backtick in it are still withheld there. Redaction (stored
 * text, served items) uses the shared detector alone: a placeholder is not rewritten.
 */
const WITHHOLD_FLOOR: readonly RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\bnpg_[A-Za-z0-9]{12,}/,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /(?<![a-z0-9+.-])[a-z0-9+.-]+:\/\/[^\s:/@'"`]+:(?!\[REDACTED:)[^\s/@'"`]+@/i,
  // Fix round 2 finish (whole span, never residue), defence in depth over the detector:
  //   * a URL password marker followed by anything other than `@<host>` and the end of the
  //     authority (`://u:[REDACTED:url_password]@<rest of the password>@host`);
  /:\/\/[^\s:/@'"`]*:\[REDACTED:url_password\](?!@[^\s@/'"`]*(?:[\s/'"`]|$))/i,
  //   * an END line of a private key (its BEGIN line was cut off or redacted apart from it);
  /-----END [A-Z0-9 ]*PRIVATE KEY/,
  //   * any marker with a key character right after it (a span that ended inside a credential).
  /\[REDACTED:[a-z_]+\][A-Za-z0-9+/=]/,
  // The old keyword rule: a keyword (THE single definition, KEYWORD_HEAD, so every prefixed
  // or compound form the detector knows: review r2 P1-1) then 6+ characters that are not a
  // marker. Withholds whole-value placeholders after a keyword, which redaction keeps.
  new RegExp(String.raw`${KEYWORD_HEAD}["']?\s*[:=]\s*["']?(?!\[REDACTED:)[^\s"']{6,}`, 'i'),
  /\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*/i,
];

/**
 * The WITHHOLD check: the shared detector, or the pre-detector floor (never looser than
 * before). Used where a hit omits the whole item / entry: the HQ export filter and the MCP
 * output wall + input checks. Booleans only.
 */
export function strictCredentialSignal(s: string): boolean {
  if (typeof s !== 'string' || s === '') return false;
  return credentialSignal(s) || withholdFloor(s);
}

/** The pre-detector floor alone (defence in depth; exported so tests can pin it on its own). Boolean only. */
export function withholdFloor(s: string): boolean {
  if (typeof s !== 'string' || s === '') return false;
  return WITHHOLD_FLOOR.some((re) => re.test(s)) || markerResidue(s);
}

/**
 * Defence in depth (fix round 2, simplified; the same KEYWORD_HEAD and assignment as the
 * detector): a keyword assigned a `[REDACTED:...]` marker (bare, or after an opening quote:
 * the detector never writes a quoted marker, so its closing quote counts as residue), then
 *   * on a line that is NOT a markdown table row: anything but whitespace up to the line end;
 *   * on a table row: anything but whitespace before the next cell bar (`|` with whitespace
 *     before it) or the line end.
 * The detector replaces the value to exactly that point, so anything there is a value of which
 * only part was redacted (a legacy row not yet rescrubbed, a span that ended too early). Withheld.
 */
const MARKER_AFTER_KEYWORD = new RegExp(String.raw`${KEYWORD_HEAD}${KEYWORD_ASSIGN}["'\x60]?\[REDACTED:[a-z_]+\]`, 'gi');
const CLEAN_TO_LINE_END = /[ \t]*\r?(?:\n|$)/y;
const CLEAN_TO_CELL_END = /[ \t]+\||[ \t]*\r?(?:\n|$)/y;
function markerResidue(s: string): boolean {
  if (!s.includes(REDACTED_PREFIX)) return false;
  let ctx: ScanContext | undefined;
  MARKER_AFTER_KEYWORD.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MARKER_AFTER_KEYWORD.exec(s)) !== null) {
    const after = m.index + m[0].length;
    ctx ??= scanContext(s);
    const clean = isTableRow(s, ctx.lineStart(after - 1)) ? CLEAN_TO_CELL_END : CLEAN_TO_LINE_END;
    clean.lastIndex = after;
    if (!clean.test(s)) return true;
  }
  return false;
}

/**
 * Replace every secret with `[REDACTED:<kind>]`. The rest of the text is kept as is. When the
 * text holds invisible characters (zero-width, soft hyphen, BOM) the scan ALWAYS runs on the
 * text without them, and if that finds anything they are removed from the whole text before
 * the redaction: a key hidden by zero-width characters is redacted even when a visible secret
 * sits in the same text (review r1 P2-2). Idempotent: redactSecrets(redactSecrets(s).text).count === 0.
 */
export function redactSecrets(s: string, o: ScanOptions = {}): RedactResult {
  if (typeof s !== 'string' || s === '') return { text: s, count: 0, byKind: {} };
  let text = s;
  let hits = scan(s, o);
  const visible = s.replace(INVISIBLE, '');
  if (visible !== s) {
    // Both views, in the coordinates of the text without invisibles: the hidden keys (found
    // only there) AND the visible ones (a visible hit can stop matching once an invisible
    // character before it is removed and it touches a letter). Union, merged.
    const hidden = scan(visible, o);
    if (hidden.length > 0) {
      const toVisible = invisibleOffsets(s);
      hits = merge([...hidden, ...hits.map((h) => ({ kind: h.kind, start: toVisible(h.start), end: toVisible(h.end) }))]);
      text = visible;
    }
  }
  if (hits.length === 0) return { text, count: 0, byKind: {} };
  const byKind: Partial<Record<SecretKind, number>> = {};
  let out = '';
  let at = 0;
  for (const h of hits) {
    out += text.slice(at, h.start) + redactedMarker(h.kind);
    at = h.end;
    byKind[h.kind] = (byKind[h.kind] ?? 0) + 1;
  }
  out += text.slice(at);
  // A replacement can join two halves into a new shape: run again until stable (bounded).
  let count = hits.length;
  for (let i = 0; i < 3; i++) {
    const again = scan(out, o);
    if (again.length === 0) break;
    let o2 = '';
    let a2 = 0;
    for (const h of again) {
      o2 += out.slice(a2, h.start) + redactedMarker(h.kind);
      a2 = h.end;
      byKind[h.kind] = (byKind[h.kind] ?? 0) + 1;
      count++;
    }
    out = o2 + out.slice(a2);
  }
  return { text: out, count, byKind };
}

/** Maps an offset in s to the offset in s without its invisible characters. */
function invisibleOffsets(s: string): (i: number) => number {
  const removedBefore = new Array<number>(s.length + 1);
  let n = 0;
  for (let i = 0; i <= s.length; i++) {
    removedBefore[i] = n;
    if (i < s.length && /[\u00ad\u200b-\u200d\u2060\ufeff]/.test(s[i]!)) n++;
  }
  return (i) => i - removedBefore[i]!;
}

/** Add b's counts into a. */
export function addCounts(a: Partial<Record<SecretKind, number>>, b: Partial<Record<SecretKind, number>>): void {
  for (const [k, v] of Object.entries(b) as Array<[SecretKind, number]>) a[k] = (a[k] ?? 0) + v;
}

/**
 * Redact every string inside a JSON-like value (object keys are kept: they are field names).
 * Returns a NEW value and the number of secrets replaced. Throws only on a cycle (caller fails closed).
 */
export function redactDeep<T>(v: T, o: ScanOptions = {}): { value: T; count: number; byKind: Partial<Record<SecretKind, number>> } {
  const seen = new Set<object>();
  const byKind: Partial<Record<SecretKind, number>> = {};
  let count = 0;
  const walk = (x: unknown): unknown => {
    if (typeof x === 'string') {
      const r = redactSecrets(x, o);
      count += r.count;
      addCounts(byKind, r.byKind);
      return r.text;
    }
    if (x === null || typeof x !== 'object') return x;
    if (x instanceof Date) return x;
    if (seen.has(x)) throw new Error('redactDeep: cycle');
    seen.add(x);
    try {
      if (Array.isArray(x)) return x.map(walk);
      const o: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(x)) {
        // A field NAMED like a credential (parsed YAML frontmatter `db_password: four random
        // words`, JSON `{"api_key": "..."}`): its whole value is the secret, the same keyword
        // definition and value checks as `kw: value` in text (review r2 P1-1 / P2-1).
        if (KEYWORD_FIELD.test(k) && (typeof val === 'string' || typeof val === 'number') && keywordFieldValue(String(val))) {
          o[k] = redactedMarker('keyword_value');
          count++;
          byKind.keyword_value = (byKind.keyword_value ?? 0) + 1;
          continue;
        }
        // The same for a list of values under such a name (`passwords:` is not a keyword, but
        // `api_key: [a, b]` is): every scalar entry that is a value is replaced whole.
        if (KEYWORD_FIELD.test(k) && Array.isArray(val)) {
          o[k] = val.map((e) => {
            if ((typeof e === 'string' || typeof e === 'number') && keywordFieldValue(String(e))) {
              count++;
              byKind.keyword_value = (byKind.keyword_value ?? 0) + 1;
              return redactedMarker('keyword_value');
            }
            return walk(e);
          });
          continue;
        }
        o[k] = walk(val);
      }
      return o;
    } finally {
      seen.delete(x);
    }
  };
  return { value: walk(v) as T, count, byKind };
}

/** Counts by kind, safe to print (kind names and numbers only). */
export function formatKinds(byKind: Partial<Record<SecretKind, number>>): string {
  const e = Object.entries(byKind).filter(([, n]) => (n ?? 0) > 0).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return e.length === 0 ? 'none' : e.map(([k, n]) => `${k} ${n}`).join(', ');
}
