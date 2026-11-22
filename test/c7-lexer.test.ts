// C7 app-side full-text search parity (src/b1-lexer.ts) against Postgres itself (PGlite, the
// `simple` configuration). Every assertion compares the app with the oracle on the same input:
// to_tsvector lexemes + positions, websearch_to_tsquery ::text, @@ and ts_rank_cd::float8 (===).
// No network, no real credentials; the corpus is synthetic words only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import {
  toTsvector, websearchToTsquery, tsqueryText, lookupOf, queryLexemes, tsMatch, tsRankCd, compareLexemes,
  type TsVector, type PositionLookup,
} from '../src/b1-lexer.ts';

let db: Db;
before(async () => {
  db = await pgliteDb();
});
after(async () => {
  await db.close();
});

// ---- corpus (parity class: ASCII letters/digits, whitespace, , ; : ! ? ( ) ' _ and ". ") ------
function prng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const VOCAB = [
  'alpha', 'beta', 'gamma', 'delta', 'Alpha', 'BETA', 'kappa', 'lambda', 'omega', 'sigma',
  'x9', '42', '007', '3d', '12e3abc', '1e5', '1E5x', '1e', 'abc123def', 'or', 'OR', 'a', 'b', 'q2',
];
const SEPS = [' ', ' ', ' ', '  ', '\n', '\t', ', ', '; ', ': ', '! ', '? ', ' (', ') ', '. ', "'", '_', ' _', "' "];
const pick = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;

function randomDoc(r: () => number, n: number): string {
  let s = pick(r, VOCAB);
  for (let i = 1; i < n; i++) s += pick(r, SEPS) + pick(r, VOCAB);
  return s;
}

function randomQuery(r: () => number): string {
  const parts: string[] = [];
  const n = 1 + Math.floor(r() * 4);
  for (let i = 0; i < n; i++) {
    const k = r();
    if (k < 0.2) parts.push(`"${pick(r, VOCAB)} ${pick(r, VOCAB)}${r() < 0.4 ? ' ' + pick(r, VOCAB) : ''}"`);
    else if (k < 0.32) parts.push('-' + pick(r, VOCAB));
    else if (k < 0.37) parts.push(`-"${pick(r, VOCAB)} ${pick(r, VOCAB)}"`);
    else parts.push(pick(r, VOCAB));
    if (i < n - 1 && r() < 0.3) parts.push(pick(r, ['or', 'OR', 'Or']));
  }
  return parts.join(r() < 0.2 ? '  ' : ' ');
}

const HAND_DOCS = [
  '',
  ',,, ;; !!',
  'alpha',
  'Alpha beta gamma',
  'alpha beta alpha beta alpha',
  'The quick brown fox jumps over the lazy dog. The dog sleeps.',
  "don't stop_me now. OK? (yes) no; maybe: never!",
  'gamma\tdelta\nepsilon\n\nzeta',
  '3d 12e3abc 1e5 1E5x 1e 5. x abc123def 007 0e0',
  'a b c a b c a b c d a b',
  'beta alpha beta alpha gamma beta',
  'x y z x y z x x x y',
  'alpha beta gamma delta alpha gamma beta delta',
  "it's a dog's life: dogs' lives_matter",
  'ONE two THREE four ONE two',
  'sigma (omega) sigma; omega! sigma? omega',
  'alpha alpha alpha alpha alpha beta',
  'p ' + 'a'.repeat(2046) + ' q ' + 'b'.repeat(2047) + ' r ' + 'c'.repeat(3000) + ' s',
  Array(300).fill('alpha').join(' ') + ' beta gamma',
  Array(400).fill('alpha beta').join(', ') + '. omega',
  (() => {
    const w: string[] = [];
    for (let i = 0; i < 16500; i++) w.push(i % 3 === 0 ? 'alpha' : i % 3 === 1 ? 'beta' : 'w' + (i % 50));
    w.push('gamma', 'delta', 'gamma', 'omega', 'alpha', 'omega');
    return w.join(' ');
  })(),
  (() => {
    const w: string[] = [];
    for (let i = 0; i < 16380; i++) w.push('filler' + (i % 400));
    w.push('kappa', 'lambda', 'kappa', 'lambda', 'sigma');
    return w.join(' ');
  })(),
];
const rd = prng(0xc7d0c);
const RANDOM_DOCS = Array.from({ length: 48 }, (_, i) => randomDoc(rd, 3 + Math.floor(rd() * (i < 40 ? 40 : 600))));
const DOCS = [...HAND_DOCS, ...RANDOM_DOCS];

const HAND_QUERIES = [
  '', '   ', ',', '!?', '""', '"', 'alpha', 'ALPHA', 'alpha beta', 'alpha or beta', 'alpha OR beta Or gamma',
  '"alpha beta"', '"beta alpha"', '"alpha beta gamma"', '"alpha alpha"', '"a b a"', 'alpha -beta', '-alpha',
  '--alpha', '-alpha -beta', 'alpha -alpha', '-"alpha beta"', '"alpha beta" -"beta gamma"', 'alpha or -beta',
  '-alpha or beta', '-alpha or -beta', 'alpha beta or gamma delta', 'alpha or', 'or alpha', 'alpha or or beta',
  'alpha or, beta', 'alpha , beta', 'alpha -', 'alpha "beta', "don't", "dog's life", 'stop_me', 'or_b', 'a:b',
  'a::b', "'alpha'", 'alpha!beta', '(alpha or beta) gamma', 'alpha <-> beta', 'alpha | beta & gamma',
  'alpha orb', 'alpha alpha', 'alpha alpha alpha', '12e3abc', '1E5x 3d', '007 or 42', 'x y z', '"x y" "y z"',
  '"x x x"', '-x y', 'dog -cat', '"quick brown" fox -cat', '"a b c d"', 'a b c d', 'omega sigma',
  '"alpha"', '"alpha beta" or "gamma delta"', 'kappa lambda', '"kappa lambda"', 'filler1 kappa', 'gamma delta',
  '"gamma delta" or omega', 'w1 -alpha', '"alpha beta alpha"', '"beta alpha beta"', '-gamma',
];
const rq = prng(0x5eed7);
const RANDOM_QUERIES = Array.from({ length: 60 }, () => randomQuery(rq));
const QUERIES = [...HAND_QUERIES, ...RANDOM_QUERIES];

type Pos = { lexeme: string; positions: number[]; i: number };

async function pgVectors(texts: readonly string[]): Promise<TsVector[]> {
  const { rows } = await db.query<Pos>(
    `SELECT d.i::int AS i, u.lexeme, u.positions::int[] AS positions
       FROM unnest($1::text[]) WITH ORDINALITY d(t, i),
            unnest(to_tsvector('simple', d.t)) WITH ORDINALITY u(lexeme, positions, weights, k)
      ORDER BY d.i, u.k`, [texts]);
  const out: [string, number[]][][] = texts.map(() => []);
  for (const r of rows) (out[r.i - 1] as [string, number[]][]).push([r.lexeme, r.positions]);
  return out;
}

async function pgQueryTexts(qs: readonly string[]): Promise<string[]> {
  const { rows } = await db.query<{ t: string }>(
    `SELECT websearch_to_tsquery('simple', q.t)::text AS t FROM unnest($1::text[]) WITH ORDINALITY q(t, j) ORDER BY q.j`, [qs]);
  return rows.map((r) => r.t);
}

/** Plain arrays, for small deepEqual comparisons. */
const plain = (v: TsVector) => v.map(([l, p]) => [l, [...p]]);

/** The first differing entry of two vectors, or null. Keeps failure output small for 16k-word docs. */
function vectorDiff(app: TsVector, pg: TsVector): string | null {
  for (let i = 0; i < Math.max(app.length, pg.length); i++) {
    const a = JSON.stringify(app[i] ?? null);
    const b = JSON.stringify(pg[i] ?? null);
    if (a !== b) return `entry ${i}: app ${a.slice(0, 200)} pg ${b.slice(0, 200)}`;
  }
  return null;
}

test('to_tsvector parity on the corpus: lexemes, order, positions, both caps (mutant: no position cap -> red; mutant: no 255-per-lexeme cap -> red; mutant: keep 2047+ byte words -> red)', async () => {
  assert.ok(DOCS.length >= 60, `corpus has ${DOCS.length} documents`);
  const pg = await pgVectors(DOCS);
  DOCS.forEach((d, k) => {
    const diff = vectorDiff(toTsvector(d), pg[k] as TsVector);
    assert.equal(diff, null, `doc #${k}: ${JSON.stringify(d.slice(0, 80))}`);
  });
  // the caps are really exercised by the corpus (so the mutants above have something to break)
  const big = toTsvector(HAND_DOCS[20] as string);
  const omega = big.find(([l]) => l === 'omega');
  assert.deepEqual(omega?.[1], [16383], 'positions past 16383 collapse to one 16383');
  const alpha = toTsvector(HAND_DOCS[18] as string).find(([l]) => l === 'alpha');
  assert.equal(alpha?.[1].length, 255, '300 repeats keep the first 255 positions');
  assert.deepEqual(alpha?.[1].slice(-2), [254, 255]);
  const long = toTsvector(HAND_DOCS[17] as string);
  assert.deepEqual(plain(long).map(([l, p]) => [typeof l === 'string' ? l.length : l, p]), [[2046, [2]], [1, [1]], [1, [3]], [1, [4]], [1, [5]]]);
});

test('websearch_to_tsquery ::text parity on the query corpus (mutant: drop the NOT handling in the parser -> red; mutant: AND instead of <-> inside quotes -> red; mutant: "or" as a word -> red)', async () => {
  assert.ok(QUERIES.length >= 60, `corpus has ${QUERIES.length} queries`);
  const pg = await pgQueryTexts(QUERIES);
  QUERIES.forEach((q, k) => {
    assert.equal(tsqueryText(websearchToTsquery(q)), pg[k], `query #${k}: ${JSON.stringify(q)}`);
  });
  // the corpus contains each operator kind, so each parser mutant has a red case
  const all = pg.join(' ');
  for (const tok of ['!', '<->', ' | ', ' & ', '( ']) assert.ok(all.includes(tok), `oracle output contains ${tok}`);
});

test('@@ and ts_rank_cd::float8 parity on every (doc, query) pair, bit for bit (mutant: rank with BM25 -> red; mutant: ts_rank instead of ts_rank_cd -> red; mutant: ignore phrase positions -> red; mutant: NOT as true in Cover -> red; mutant: no float4 rounding -> red)', async () => {
  const { rows } = await db.query<{ i: number; j: number; m: boolean; r: number }>(
    `WITH d AS MATERIALIZED (SELECT i::int AS i, to_tsvector('simple', t) AS v FROM unnest($1::text[]) WITH ORDINALITY x(t, i)),
          q AS MATERIALIZED (SELECT j::int AS j, websearch_to_tsquery('simple', t) AS w FROM unnest($2::text[]) WITH ORDINALITY y(t, j))
     SELECT d.i, q.j, d.v @@ q.w AS m, ts_rank_cd(d.v, q.w)::float8 AS r FROM d CROSS JOIN q ORDER BY d.i, q.j`,
    [DOCS, QUERIES]);
  assert.equal(rows.length, DOCS.length * QUERIES.length);
  const lookups = DOCS.map((d) => lookupOf(toTsvector(d)));
  const queries = QUERIES.map((q) => websearchToTsquery(q));
  let matched = 0;
  let ranked = 0;
  let phraseOrNotRanked = 0;
  for (const row of rows) {
    const look = lookups[row.i - 1] as PositionLookup;
    const q = queries[row.j - 1] ?? null;
    const where = `doc #${row.i - 1} ${JSON.stringify((DOCS[row.i - 1] as string).slice(0, 60))} @@ ${JSON.stringify(QUERIES[row.j - 1])}`;
    assert.equal(tsMatch(look, q), row.m, `match: ${where}`);
    const rank = tsRankCd(look, q);
    assert.ok(Object.is(rank, row.r), `rank: ${where}: app ${rank} pg ${row.r}`);
    if (row.m) matched++;
    if (row.r > 0) {
      ranked++;
      if (/<->|!/.test(tsqueryText(q))) phraseOrNotRanked++;
    }
  }
  // the corpus is not degenerate: plenty of matches, non-zero ranks, phrase/NOT queries that rank
  assert.ok(matched > 500 && ranked > 500 && phraseOrNotRanked > 100, `matched ${matched}, ranked ${ranked}, phrase/NOT ranked ${phraseOrNotRanked}`);
});

test('match and rank ask the lookup only for query words, once each (mutant: scan the whole vector -> red)', () => {
  const v = toTsvector('alpha beta gamma delta alpha beta');
  const base = lookupOf(v);
  const asked: string[] = [];
  const spy: PositionLookup = (w) => {
    asked.push(w);
    return base(w);
  };
  const q = websearchToTsquery('"alpha beta" -omega alpha or gamma');
  assert.deepEqual(queryLexemes(q), ['alpha', 'beta', 'omega', 'gamma']);
  assert.equal(tsMatch(spy, q), true);
  assert.deepEqual(asked.sort(), ['alpha', 'beta', 'gamma', 'omega']);
  asked.length = 0;
  assert.ok(tsRankCd(spy, q) > 0);
  assert.deepEqual(asked.sort(), ['alpha', 'beta', 'gamma', 'omega']);
  assert.deepEqual(queryLexemes(null), []);
  assert.equal(tsMatch(spy, null), false);
  assert.equal(tsRankCd(spy, null), 0);
});

test('the operator-stack limit errors where Postgres errors (mutant: drop the STACKDEPTH check -> red)', async () => {
  for (const [q, errs] of [['-'.repeat(32) + 'alpha', false], ['-'.repeat(33) + 'alpha', true], ['alpha or '.repeat(40) + 'beta', false]] as const) {
    let pgErr = false;
    try {
      await db.query(`SELECT websearch_to_tsquery('simple', $1)::text`, [q]);
    } catch {
      pgErr = true;
    }
    assert.equal(pgErr, errs, `postgres on ${q.length}-char query`);
    if (errs) assert.throws(() => websearchToTsquery(q), /tsquery stack too small/);
    else assert.equal(tsqueryText(websearchToTsquery(q)), (await pgQueryTexts([q]))[0]);
  }
});

test('lexeme order is Postgres byte order, shorter first (mutant: sort lexemes with localeCompare -> red)', async () => {
  // precomposed accented / Greek letters are only here to tell byte order from collation order;
  // they are not a parity claim (see the non-ASCII divergence rows)
  const words = ['b', 'B', 'a1', 'a', 'ab', 'a0', '10', '9', 'z', 'zz', '_', '\u00e9a', 'ea', 'za', '\u03c9a'];
  const app = toTsvector(words.join(' ')).map(([l]) => l);
  const pg = (await pgVectors([words.join(' ')]))[0]?.map(([l]) => l);
  assert.deepEqual(app, pg);
  assert.ok(compareLexemes('é', 'z') > 0 && compareLexemes('\u{1F600}', '�') > 0 && compareLexemes('ab', 'a') > 0);
});

// ---- divergences: the app rule (\p{L}\p{N} runs, toLowerCase, no position for separators) vs the
// default parser. Each row states the app output and asserts Postgres differs, so a row whose
// difference disappears fails here and must be deleted (the list can only shrink).
const DIVERGENCES: ReadonlyArray<readonly [cls: string, text: string, app: ReadonlyArray<readonly [string, readonly number[]]>]> = [
  ['hyphenated word', 'foo-bar', [['bar', [2]], ['foo', [1]]]],
  ['signed number', 'x -5', [['5', [2]], ['x', [1]]]],
  ['decimal number', '1.5', [['1', [1]], ['5', [2]]]],
  ['version number', '1.2.3', [['1', [1]], ['2', [2]], ['3', [3]]]],
  ['host name', 'example.com', [['com', [2]], ['example', [1]]]],
  ['email address', 'a@b.com', [['a', [1]], ['b', [2]], ['com', [3]]]],
  ['URL with protocol', 'http://x.org/a', [['a', [4]], ['http', [1]], ['org', [3]], ['x', [2]]]],
  ['file path', '/usr/bin', [['bin', [2]], ['usr', [1]]]],
  ['HTML tag', '<b>x</b>', [['b', [1, 3]], ['x', [2]]]],
  ['HTML entity', 'a &amp; b', [['a', [1]], ['amp', [2]], ['b', [3]]]],
  ['non-ASCII: decomposed accent', 'café', [['cafe', [1]]]],
  ['non-ASCII: superscript digit', 'x²', [['x²', [1]]]],
  ['non-ASCII: dotted capital I', 'İx', [['i̇x', [1]]]],
];

test('divergence list: app output pinned, Postgres still differs (mutant: route a divergent class through a Postgres-style tokenizer -> red here, so delete the row)', async () => {
  const pg = await pgVectors(DIVERGENCES.map(([, t]) => t));
  DIVERGENCES.forEach(([cls, text, app], k) => {
    assert.deepEqual(plain(toTsvector(text)), plain(app), `${cls}: app output`);
    assert.notDeepEqual(plain(pg[k] as TsVector), plain(app), `${cls}: Postgres now agrees with the app; remove this divergence row`);
  });
  // the query side follows the same lexer: a hyphenated word is a <-> chain of its parts in the app
  assert.equal(tsqueryText(websearchToTsquery('foo-bar')), "'foo' <-> 'bar'");
  assert.notEqual((await pgQueryTexts(['foo-bar']))[0], "'foo' <-> 'bar'");
});
