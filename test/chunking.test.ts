// U5 chunker (PLAN.md "Chunking"). Pure functions, synthetic text only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CHUNK, chunkMarkdown, embedText, estimateTokens } from '../src/chunking.ts';

const words = (n: number, seed = 'w') => Array.from({ length: n }, (_, i) => `${seed}${i % 97}`).join(' ');

test('token estimator: ceil(code points / 4), documented constants', () => {
  assert.equal(estimateTokens(''), 0);
  assert.equal(estimateTokens('abcd'), 1);
  assert.equal(estimateTokens('abcde'), 2);
  assert.equal(estimateTokens('äöüß'), 1, 'code points, not UTF-16 units or bytes');
  assert.equal(estimateTokens('😀😀😀😀'), 1);
  assert.deepEqual(CHUNK, { targetMin: 400, targetMax: 600, max: 800, overlap: 60 });
});

test('splits on H1-H3 only; H4+ stays inside its section; heading lines are not in text', () => {
  const md = [
    'intro line',
    '# Top',
    'top body',
    '## Sub A',
    'a body',
    '#### deep heading stays',
    'still a',
    '### Sub A.1',
    'a1 body',
    '## Sub B',
    'b body',
  ].join('\n');
  const c = chunkMarkdown(md);
  assert.deepEqual(c.map((x) => x.headingPath), [null, 'Top', 'Top > Sub A', 'Top > Sub A > Sub A.1', 'Top > Sub B']);
  assert.ok(c.every((x) => !('fragment' in x)), 'no heading-derived uri fragment (r1 MAJOR-1): uris use #c<index>');
  assert.match(c[2]!.text, /#### deep heading stays/);
  assert.ok(c.every((x) => !/^#{1,3} /m.test(x.text)), 'H1-H3 lines live in heading_path, not text');
  assert.deepEqual(c.map((x) => x.index), [0, 1, 2, 3, 4]);
});

test('headings inside code fences do not split; empty sections are dropped', () => {
  const md = ['# A', '```sh', '# not a heading', '```', '# Empty', '', '# B', 'b'].join('\n');
  const c = chunkMarkdown(md);
  assert.deepEqual(c.map((x) => x.headingPath), ['A', 'B']);
  assert.match(c[0]!.text, /# not a heading/);
});

test('repeated headings: chunk indexes stay unique (the uri is #c<index>)', () => {
  const md = ['# Notes', 'one', '# Notes', 'two'].join('\n');
  assert.deepEqual(chunkMarkdown(md).map((x) => [x.index, x.headingPath]), [[0, 'Notes'], [1, 'Notes']]);
});

test('a heading-less ~3,000-token note splits into chunks of at most 800 tokens with 60-token overlap', () => {
  const paras = Array.from({ length: 30 }, (_, i) => words(80, `p${i}x`)).join('\n\n');
  assert.ok(estimateTokens(paras) >= 3000, `fixture is ${estimateTokens(paras)} tokens`);
  const c = chunkMarkdown(paras);
  assert.ok(c.length >= 5, `${c.length} chunks`);
  for (const x of c) {
    assert.ok(x.tokenCount <= CHUNK.max, `chunk ${x.index} has ${x.tokenCount} tokens`);
    assert.equal(x.tokenCount, estimateTokens(x.text));
    assert.equal(x.headingPath, null);
  }
  for (let i = 1; i < c.length; i++) {
    // chunk i opens with (about) the last 60 tokens of chunk i-1
    const head = c[i]!.text.slice(0, 40);
    const prevTail = c[i - 1]!.text.slice(-(CHUNK.overlap * 4 + 8));
    assert.ok(prevTail.includes(head), `chunk ${i} starts with the tail of chunk ${i - 1}`);
  }
  assert.deepEqual(c.map((x) => x.index), c.map((_, i) => i));
  // Every word of the source survives in some chunk.
  const all = c.map((x) => x.text).join(' ');
  for (const w of new Set(paras.split(/\s+/))) assert.ok(all.includes(w), w);
});

test('one huge paragraph (no blank lines) is still cut at word boundaries under the max', () => {
  const c = chunkMarkdown(`# Big\n${words(2500)}`);
  assert.ok(c.length >= 3);
  for (const x of c) {
    assert.ok(x.tokenCount <= CHUNK.max);
    assert.equal(x.headingPath, 'Big');
    assert.doesNotMatch(x.text, /^\s|\s$/);
  }
});

test('short sections are not split and carry no overlap', () => {
  const md = `# A\n${words(100)}\n# B\n${words(100, 'q')}`;
  const c = chunkMarkdown(md);
  assert.equal(c.length, 2);
  assert.ok(!c[1]!.text.includes('w1 '), 'no text from section A leaks into B');
});

test('embedded text is "title > heading path" plus the chunk; stored text is the chunk only', () => {
  assert.equal(embedText('Note', 'A > B', 'body'), 'Note > A > B\n\nbody');
  assert.equal(embedText('Note', null, 'body'), 'Note\n\nbody');
});

test('CRLF input is handled like LF', () => {
  const c = chunkMarkdown('# A\r\nline one\r\n## B\r\nline two\r\n');
  assert.deepEqual(c.map((x) => [x.headingPath, x.text]), [['A', 'line one'], ['A > B', 'line two']]);
});
