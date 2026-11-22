// C7 app-side full-text search: an in-memory re-implementation of the Postgres pieces Zeusi's
// lexical search uses, so an encrypted workspace (whose text the database never sees) can be
// searched in the app with the same results the database would give for plaintext.
//
// Mirrors (Postgres 18, `simple` text search configuration, oracle = PGlite in test/c7-lexer.test.ts):
//   - to_tsvector('simple', text)          -> toTsvector
//   - websearch_to_tsquery('simple', q)    -> websearchToTsquery (+ tsqueryText = the ::text output)
//   - tsvector @@ tsquery                  -> tsMatch            (tsvector_op.c TS_execute / TS_phrase_execute)
//   - ts_rank_cd(tsvector, tsquery)        -> tsRankCd           (tsrank.c calc_rank_cd, default weights,
//                                                                 normalization 0, float4 result)
//
// Parity class (pinned exactly against the oracle by test/c7-lexer.test.ts): text made of ASCII
// letters and digits, any mix of case, ASCII whitespace, the punctuation , ; : ! ? ( ) ' _ and a
// '.' that ends a sentence (followed by whitespace). Inside that class the app and Postgres agree
// on lexemes, positions (including the 16383 position cap and the 255-positions-per-lexeme cap),
// dropped over-long words (2047+ bytes, no position consumed), digit-e-digit "scientific" tokens
// ('12e3abc' -> '12e3', 'abc'), query parse trees and their text, @@, and ts_rank_cd bit for bit.
// websearchToTsquery also mirrors Postgres's "tsquery stack too small" error (33+ pending
// operators, e.g. 33 leading '-'): it throws where Postgres raises.
//
// Divergences (outside the parity class; the app rule is: tokens are maximal runs of Unicode
// letters/digits \p{L}\p{N}, lower-cased with String.prototype.toLowerCase, everything else is a
// separator that does not consume a position). Each is pinned by the divergence test, which also
// asserts that Postgres still differs, so this list can only shrink:
//   - hyphenated words       'foo-bar'      app: foo, bar          pg: foo-bar, foo, bar
//   - signed numbers         '-5'           app: 5                 pg: -5
//   - decimals / versions    '1.5', '1.2.3' app: 1, 5 / 1, 2, 3    pg: 1.5 / 1.2.3
//   - host names             'example.com'  app: example, com      pg: example.com
//   - email addresses        'a@b.com'      app: a, b, com         pg: a@b.com
//   - URLs with protocol     'http://x.org/a' app: http, x, org, a pg: x.org/a, x.org, /a
//   - file paths             '/usr/bin'     app: usr, bin          pg: /usr/bin
//   - HTML/XML tags, entities '<b>x</b>', '&amp;' app: b, x, b / amp  pg: x / (nothing)
//   - non-ASCII text         'cafe\u0301' (decomposed accent), 'x²', 'İ': app splits at combining
//     marks, keeps \p{N} like '²', and lower-cases with JS rules; Postgres follows the database's
//     ctype (PGlite: C.UTF-8), so results depend on the database locale.
// Words of 2047+ bytes are NOT a divergence: they are dropped exactly like Postgres does.

export type TsVector = ReadonlyArray<readonly [lexeme: string, positions: readonly number[]]>;

export type QNode =
  | { readonly op: 'val'; readonly word: string }
  | { readonly op: 'not'; readonly arg: QNode }
  | { readonly op: 'and' | 'or'; readonly l: QNode; readonly r: QNode }
  | { readonly op: 'phrase'; readonly l: QNode; readonly r: QNode; readonly distance: number };

/** null = the empty query: matches nothing, ranks 0. */
export type TsQuery = null | QNode;

export type PositionLookup = (lexeme: string) => readonly number[] | undefined;

// ---- constants from the Postgres sources -------------------------------------------------------
const MAXSTRLEN = (1 << 11) - 1; // ts_type.h: a token this long (bytes) or longer is dropped
const MAXENTRYPOS = 1 << 14; // positions are capped at MAXENTRYPOS - 1 = 16383
const MAXNUMPOS = 256; // at most MAXNUMPOS - 1 = 255 positions per lexeme
const STACKDEPTH = 32; // tsquery.c operator stack
const WEIGHT_D = Math.fround(0.1); // tsrank.c: static const float weights[] = {0.1f, ...}; all to_tsvector positions are D

const limitPos = (p: number): number => (p >= MAXENTRYPOS ? MAXENTRYPOS - 1 : p);

/** Postgres orders lexemes with memcmp over UTF-8 bytes, shorter first on a common prefix. */
export function compareLexemes(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(i);
    if (x === y) continue;
    // UTF-16 code-unit order equals code-point (= UTF-8 byte) order except surrogates vs U+E000..U+FFFF
    const xs = x >= 0xd800 && x <= 0xdfff;
    const ys = y >= 0xd800 && y <= 0xdfff;
    if (xs === ys) return x < y ? -1 : 1;
    return xs ? 1 : -1;
  }
  return a.length - b.length;
}

function utf8Len(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

// ---- lexer -------------------------------------------------------------------------------------
const RUN = /[\p{L}\p{N}]+/gu;
// default parser: an ASCII-digit run followed by e/E and digits is an "sfloat" token on its own
// (TPS_InUnsignedInt -> TPS_InMantissaFirst -> TPS_InMantissa); the rest of the run is a new token
const SFLOAT = /^[0-9]+[eE][0-9]+/;

/** The lexemes of `text` in order, one per position (the `simple` dictionary keeps every token). */
function lexemes(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(RUN)) {
    const run = m[0];
    const sf = SFLOAT.exec(run);
    const tokens = sf && sf[0].length < run.length ? [sf[0], run.slice(sf[0].length)] : [run];
    for (const t of tokens) {
      if (utf8Len(t) >= MAXSTRLEN) continue; // ts_parse.c parsetext: "word is too long", no position
      out.push(t.toLowerCase());
    }
  }
  return out;
}

export function toTsvector(text: string): TsVector {
  const map = new Map<string, number[]>();
  let pos = 0;
  for (const lx of lexemes(text)) {
    const p = limitPos(++pos);
    const ps = map.get(lx);
    if (!ps) {
      map.set(lx, [p]);
      continue;
    }
    // to_tsany.c uniqueWORD: keep < MAXNUMPOS - 1 positions, stop after the capped one, no duplicates
    const last = ps[ps.length - 1];
    if (ps.length < MAXNUMPOS - 1 && last !== MAXENTRYPOS - 1 && last !== p) ps.push(p);
  }
  return [...map.entries()].sort((a, b) => compareLexemes(a[0], b[0]));
}

export function lookupOf(v: TsVector): PositionLookup {
  const m = new Map<string, readonly number[]>();
  for (const [lx, ps] of v) m.set(lx, ps);
  return (lx) => m.get(lx);
}

// ---- websearch_to_tsquery ----------------------------------------------------------------------
type PItem =
  | { readonly t: 'val'; readonly word: string }
  | { readonly t: 'stop' }
  | { readonly t: 'op'; readonly op: 'and' | 'or' | 'not' | 'phrase'; readonly distance: number };

const PRIORITY = { not: 4, phrase: 3, and: 2, or: 1 } as const;
type OpName = keyof typeof PRIORITY;

const isSpace = (c: string | undefined): boolean =>
  c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\v' || c === '\f';
const isQOperator = (c: string | undefined): boolean =>
  c === '!' || c === '&' || c === '|' || c === '(' || c === ')' || c === '<';
const isAsciiAlnum = (c: string | undefined): boolean => c !== undefined && /^[A-Za-z0-9]$/.test(c);
// t_isalnum on a multibyte char follows the locale; the app treats \p{L}\p{N} as alnum
const isAlnum = (c: string | undefined): boolean => c !== undefined && (isAsciiAlnum(c) || /^[\p{L}\p{N}]$/u.test(c));

/**
 * websearch_to_tsquery('simple', q). Mirrors tsquery.c gettoken_query_websearch, makepol,
 * pushval_morph (OP_PHRASE between the lexemes of one operand) and cleanup_tsquery_stopwords.
 * Throws "tsquery stack too small" exactly where Postgres does.
 */
export function websearchToTsquery(q: string): TsQuery {
  const s = Array.from(q); // one element per code point, like pg_mblen stepping
  let i = 0;
  let state: 'first' | 'operand' | 'operator' = 'first';
  const polish: PItem[] = [];
  const opstack: OpName[] = [];

  const pushval = (text: string): void => {
    const lx = lexemes(text);
    if (lx.length === 0) {
      polish.push({ t: 'stop' });
      return;
    }
    lx.forEach((w, k) => {
      polish.push({ t: 'val', word: w });
      if (k > 0) polish.push({ t: 'op', op: 'phrase', distance: 1 });
    });
  };
  const cleanOpStack = (op: OpName): void => {
    const pr = PRIORITY[op];
    while (opstack.length > 0) {
      const top = opstack[opstack.length - 1] as OpName;
      if ((op !== 'not' && pr > PRIORITY[top]) || (op === 'not' && pr >= PRIORITY[top])) break;
      opstack.pop();
      polish.push({ t: 'op', op: top, distance: 0 });
    }
  };
  const operator = (op: OpName): void => {
    cleanOpStack(op);
    if (opstack.length === STACKDEPTH) throw new Error('tsquery stack too small');
    opstack.push(op);
  };
  const parseOr = (): boolean => {
    const a = s[i];
    const b = s[i + 1];
    if (a === undefined || b === undefined || a.toLowerCase() !== 'o' || b.toLowerCase() !== 'r') return false;
    let p = i + 2;
    const c = s[p];
    if (c === undefined) return false;
    if (c === '-' || c === '_' || isAlnum(c)) return false;
    for (;;) {
      p++;
      if (p >= s.length) return false;
      if (!isSpace(s[p])) break;
    }
    i += 2;
    return true;
  };

  for (;;) {
    const c = s[i];
    if (state === 'first' || state === 'operand') {
      if (c === '-') {
        i++;
        state = 'operand';
        operator('not');
        continue;
      }
      if (c === '"') {
        i++;
        const start = i;
        while (i < s.length && s[i] !== '"') i++;
        const text = s.slice(start, i).join('');
        if (i < s.length) i++;
        state = 'operator';
        pushval(text);
        continue;
      }
      if (isQOperator(c)) {
        i++;
        state = 'operand';
        continue;
      }
      if (c === undefined) {
        // gettoken_tsvector found no word: the end. A pending operator gets a stop-word operand.
        if (state === 'operand') polish.push({ t: 'stop' });
        break;
      }
      if (!isSpace(c)) {
        // tsvector_parser.c (websearch mode): the first char is always taken (so a ':' is a word of
        // its own); the word then runs to whitespace, an operator char, '"' or ':'
        const start = i;
        i++;
        while (i < s.length) {
          const d = s[i];
          if (isSpace(d) || isQOperator(d) || d === '"' || d === ':') break;
          i++;
        }
        state = 'operator';
        pushval(s.slice(start, i).join(''));
        continue;
      }
      i++;
    } else {
      if (c === '"') {
        state = 'operand';
        operator('and');
        continue;
      }
      if (parseOr()) {
        state = 'operand';
        operator('or');
        continue;
      }
      if (c === undefined) break;
      if (!isSpace(c)) {
        operator('and');
        state = 'operand';
        continue;
      }
      i++;
    }
  }
  cleanOpStack('or');
  return cleanStopwords(fromPolish(polish));
}

type RawNode =
  | { op: 'val'; word: string }
  | { op: 'stop' }
  | { op: 'not'; arg: RawNode }
  | { op: 'and' | 'or'; l: RawNode; r: RawNode }
  | { op: 'phrase'; l: RawNode; r: RawNode; distance: number };

function fromPolish(items: readonly PItem[]): RawNode | null {
  const st: RawNode[] = [];
  for (const it of items) {
    if (it.t === 'val') st.push({ op: 'val', word: it.word });
    else if (it.t === 'stop') st.push({ op: 'stop' });
    else if (it.op === 'not') st.push({ op: 'not', arg: st.pop() as RawNode });
    else {
      const r = st.pop() as RawNode;
      const l = st.pop() as RawNode;
      st.push(it.op === 'phrase' ? { op: 'phrase', l, r, distance: it.distance } : { op: it.op, l, r });
    }
  }
  return st.length > 0 ? (st[st.length - 1] as RawNode) : null;
}

/**
 * tsquery_cleanup.c clean_stopword_intree. Its phrase-distance corrections are ported for fidelity
 * but unreachable with `simple` (no stop words, so a stop placeholder is always a whole AND/OR/NOT
 * operand, never a phrase member); no test pins them.
 */
function cleanStopwords(root: RawNode | null): TsQuery {
  if (!root) return null;
  const rec = (n: RawNode): { node: QNode | null; ladd: number; radd: number } => {
    if (n.op === 'val') return { node: { op: 'val', word: n.word }, ladd: 0, radd: 0 };
    if (n.op === 'stop') return { node: null, ladd: 0, radd: 0 };
    if (n.op === 'not') {
      const c = rec(n.arg);
      return c.node ? { node: { op: 'not', arg: c.node }, ladd: c.ladd, radd: c.radd } : { node: null, ladd: c.ladd, radd: c.radd };
    }
    const L = rec(n.l);
    const R = rec(n.r);
    const isphrase = n.op === 'phrase';
    const nd = n.op === 'phrase' ? n.distance : 0;
    if (!L.node && !R.node) {
      const add = isphrase ? L.ladd + nd + R.ladd : Math.max(L.ladd, R.ladd);
      return { node: null, ladd: add, radd: add };
    }
    if (!L.node) return isphrase ? { node: R.node, ladd: L.ladd + nd + R.ladd, radd: R.radd } : { node: R.node, ladd: R.ladd, radd: R.radd };
    if (!R.node) return isphrase ? { node: L.node, ladd: L.ladd, radd: L.radd + nd + R.radd } : { node: L.node, ladd: L.ladd, radd: L.radd };
    if (n.op === 'phrase') {
      return { node: { op: 'phrase', l: L.node, r: R.node, distance: n.distance + L.radd + R.ladd }, ladd: L.ladd, radd: R.radd };
    }
    return { node: { op: n.op, l: L.node, r: R.node }, ladd: 0, radd: 0 };
  };
  return rec(root).node;
}

/** Postgres's tsquery ::text output (tsquery.c infix). The empty query prints as ''. */
export function tsqueryText(q: TsQuery): string {
  if (!q) return '';
  const rec = (n: QNode, parentPriority: number, rightPhraseOp: boolean): string => {
    if (n.op === 'val') return `'${n.word.replace(/['\\]/g, (c) => c + c)}'`;
    const pr = PRIORITY[n.op];
    if (n.op === 'not') {
      const inner = '!' + rec(n.arg, pr, false);
      return pr < parentPriority ? `( ${inner} )` : inner;
    }
    const paren = pr < parentPriority || (n.op === 'phrase' && rightPhraseOp);
    const right = rec(n.r, pr, n.op === 'phrase');
    const left = rec(n.l, pr, false);
    const sym = n.op !== 'phrase' ? (n.op === 'or' ? '|' : '&') : n.distance !== 1 ? `<${String(n.distance)}>` : '<->';
    const body = `${left} ${sym} ${right}`;
    return paren ? `( ${body} )` : body;
  };
  return rec(q, -1, false);
}

/** Distinct operand words of the query, in first-occurrence order (left to right). */
export function queryLexemes(q: TsQuery): string[] {
  const seen = new Set<string>();
  const walk = (n: QNode): void => {
    if (n.op === 'val') seen.add(n.word);
    else if (n.op === 'not') walk(n.arg);
    else {
      walk(n.l);
      walk(n.r);
    }
  };
  if (q) walk(q);
  return [...seen];
}

// ---- evaluation (tsvector_op.c TS_execute / TS_phrase_execute) --------------------------------
/** Positions of one operand occurrence, ascending; undefined = the operand does not occur. */
type Check = (v: QNode & { op: 'val' }) => readonly number[] | undefined;

interface PhraseData {
  pos: number[] | readonly number[];
  negate: boolean;
  width: number;
}
const TSPO_L_ONLY = 1;
const TSPO_R_ONLY = 2;
const TSPO_BOTH = 4;

function phraseOutput(data: PhraseData | null, L: PhraseData, R: PhraseData, emit: number, Loffset: number, Roffset: number): boolean {
  let li = 0;
  let ri = 0;
  const out: number[] = [];
  while (li < L.pos.length || ri < R.pos.length) {
    let lp: number;
    let rp: number;
    if (li < L.pos.length) lp = (L.pos[li] as number) + Loffset;
    else {
      if (!(emit & TSPO_R_ONLY)) break;
      lp = Number.MAX_SAFE_INTEGER;
    }
    if (ri < R.pos.length) rp = (R.pos[ri] as number) + Roffset;
    else {
      if (!(emit & TSPO_L_ONLY)) break;
      rp = Number.MAX_SAFE_INTEGER;
    }
    let o = 0;
    if (lp < rp) {
      if (emit & TSPO_L_ONLY) o = lp;
      li++;
    } else if (lp === rp) {
      if (emit & TSPO_BOTH) o = rp;
      li++;
      ri++;
    } else {
      if (emit & TSPO_R_ONLY) o = rp;
      ri++;
    }
    if (o > 0) {
      if (!data) return true;
      out.push(o);
    }
  }
  if (data) {
    data.pos = out;
    return out.length > 0;
  }
  return false;
}

function phraseExec(n: QNode, check: Check, data: PhraseData | null): boolean {
  if (n.op === 'val') {
    const ps = check(n);
    if (!ps) return false;
    if (data) data.pos = ps;
    return true;
  }
  if (n.op === 'not') {
    const d = data as PhraseData; // a NOT inside a phrase always has an output slot
    if (!phraseExec(n.arg, check, d)) {
      d.negate = true;
      return true;
    }
    if (d.pos.length > 0) {
      d.negate = !d.negate;
      return true;
    }
    if (d.negate) {
      d.negate = false;
      return false;
    }
    return false;
  }
  const L: PhraseData = { pos: [], negate: false, width: 0 };
  const R: PhraseData = { pos: [], negate: false, width: 0 };
  if (n.op === 'phrase' || n.op === 'and') {
    if (!phraseExec(n.l, check, L)) return false;
    if (!phraseExec(n.r, check, R)) return false;
    let Loffset: number;
    let Roffset: number;
    if (n.op === 'phrase') {
      Loffset = n.distance + R.width;
      Roffset = 0;
      if (data) data.width = n.distance + L.width + R.width;
    } else {
      const maxwidth = Math.max(L.width, R.width);
      Loffset = maxwidth - L.width;
      Roffset = maxwidth - R.width;
      if (data) data.width = maxwidth;
    }
    if (L.negate && R.negate) {
      phraseOutput(data, L, R, TSPO_BOTH | TSPO_L_ONLY | TSPO_R_ONLY, Loffset, Roffset);
      if (data) data.negate = true;
      return true;
    }
    if (L.negate) return phraseOutput(data, L, R, TSPO_R_ONLY, Loffset, Roffset);
    if (R.negate) return phraseOutput(data, L, R, TSPO_L_ONLY, Loffset, Roffset);
    return phraseOutput(data, L, R, TSPO_BOTH, Loffset, Roffset);
  }
  // OR
  const lm = phraseExec(n.l, check, L);
  const rm = phraseExec(n.r, check, R);
  if (!lm && !rm) return false;
  if (!lm) L.width = 0;
  if (!rm) R.width = 0;
  const maxwidth = Math.max(L.width, R.width);
  const Loffset = maxwidth - L.width;
  const Roffset = maxwidth - R.width;
  const d = data as PhraseData; // OR is evaluated here only below a phrase/AND that passes a slot
  d.width = maxwidth;
  if (L.negate && R.negate) {
    phraseOutput(d, L, R, TSPO_BOTH, Loffset, Roffset);
    d.negate = true;
    return true;
  }
  if (L.negate) {
    phraseOutput(d, L, R, TSPO_L_ONLY, Loffset, Roffset);
    d.negate = true;
    return true;
  }
  if (R.negate) {
    phraseOutput(d, L, R, TSPO_R_ONLY, Loffset, Roffset);
    d.negate = true;
    return true;
  }
  return phraseOutput(d, L, R, TSPO_BOTH | TSPO_L_ONLY | TSPO_R_ONLY, Loffset, Roffset);
}

function execute(n: QNode, check: Check): boolean {
  switch (n.op) {
    case 'val':
      return check(n) !== undefined;
    case 'not':
      return !execute(n.arg, check);
    case 'and':
      return execute(n.l, check) && execute(n.r, check);
    case 'or':
      return execute(n.l, check) || execute(n.r, check);
    case 'phrase':
      return phraseExec(n, check, null);
  }
}

/** Positions per distinct query word, asking the lookup only for query words, once each. */
function resolve(doc: PositionLookup, q: QNode): Map<string, readonly number[]> {
  const m = new Map<string, readonly number[]>();
  for (const w of queryLexemes(q)) {
    const ps = doc(w);
    if (ps && ps.length > 0) m.set(w, ps);
  }
  return m;
}

/** tsvector @@ tsquery. */
export function tsMatch(doc: PositionLookup, q: TsQuery): boolean {
  if (!q) return false;
  const m = resolve(doc, q);
  return execute(q, (v) => m.get(v.word));
}

// ---- ts_rank_cd (tsrank.c) ---------------------------------------------------------------------
interface DocRep {
  pos: number;
  word: string;
  items: number[]; // indexes of the query operand occurrences at this (pos, lexeme)
}

/** ts_rank_cd(tsvector, tsquery): default weights, normalization 0, float4 result. */
export function tsRankCd(doc: PositionLookup, q: TsQuery): number {
  if (!q) return 0;
  const vals: (QNode & { op: 'val' })[] = [];
  const collect = (n: QNode): void => {
    if (n.op === 'val') vals.push(n);
    else if (n.op === 'not') collect(n.arg);
    else {
      collect(n.l);
      collect(n.r);
    }
  };
  collect(q);
  const index = new Map<QNode, number>(vals.map((v, k) => [v, k]));
  const m = resolve(doc, q);

  // get_docrep: one entry per (position, lexeme), joining every operand occurrence of that lexeme
  const reps: DocRep[] = [];
  const byWord = new Map<string, number[]>();
  vals.forEach((v, k) => {
    const list = byWord.get(v.word);
    if (list) list.push(k);
    else byWord.set(v.word, [k]);
  });
  for (const [w, items] of byWord) {
    const ps = m.get(w);
    if (!ps) continue;
    for (const p of ps) reps.push({ pos: p, word: w, items });
  }
  if (reps.length === 0) return 0;
  reps.sort((a, b) => (a.pos !== b.pos ? a.pos - b.pos : compareLexemes(a.word, b.word)));

  // QueryRepresentation: per operand occurrence, existence + ascending positions
  const exists: boolean[] = new Array<boolean>(vals.length).fill(false);
  const qpos: number[][] = vals.map(() => []);
  const reset = (): void => {
    for (let k = 0; k < vals.length; k++) {
      exists[k] = false;
      qpos[k] = [];
    }
  };
  // fillQueryRepresentationData: forward pass appends, backward pass prepends; skip a repeat of the
  // last position (ported; unreachable here, as one operand never sees the same position twice)
  const fill = (r: DocRep, reverse: boolean): void => {
    for (const k of r.items) {
      exists[k] = true;
      const ps = qpos[k] as number[];
      if (ps.length === 0) ps.push(r.pos);
      else if (reverse) {
        if (ps[0] !== r.pos) ps.unshift(r.pos);
      } else if (ps[ps.length - 1] !== r.pos) ps.push(r.pos);
    }
  };
  const check: Check = (v) => {
    const k = index.get(v) as number;
    return exists[k] ? (qpos[k] as number[]) : undefined;
  };

  const invD = 1.0 / WEIGHT_D;
  let Wdoc = 0.0;
  let extPos = 0;
  const len = reps.length;
  // Cover(), with its tail recursion as a loop
  for (;;) {
    reset();
    let p = Number.MAX_SAFE_INTEGER;
    let qq = 0;
    let end = -1;
    let begin = -1;
    let lastpos = extPos;
    let found = false;
    for (let k = extPos; k < len; k++) {
      const r = reps[k] as DocRep;
      fill(r, false);
      if (execute(q, check)) {
        if (r.pos > qq) {
          qq = r.pos;
          end = k;
          lastpos = k;
          found = true;
        }
        break;
      }
    }
    if (!found) break;
    reset();
    let k = lastpos;
    for (; k >= extPos; k--) {
      const r = reps[k] as DocRep;
      fill(r, true);
      if (execute(q, check)) {
        if (r.pos < p) {
          begin = k;
          p = r.pos;
        }
        break;
      }
    }
    if (p <= qq) {
      extPos = k + 1;
      // calc_rank_cd body for this cover
      let InvSum = 0.0;
      for (let j = begin; j <= end; j++) InvSum += invD;
      const Cpos = (end - begin + 1) / InvSum;
      let nNoise = qq - p - (end - begin);
      if (nNoise < 0) nNoise = Math.trunc((end - begin) / 2);
      Wdoc += Cpos / (1 + nNoise);
      continue;
    }
    extPos++;
  }
  return Math.fround(Wdoc);
}
