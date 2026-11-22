// Lock-lifecycle addendum K4: frontmatter parser. `#` starts a comment only at the start of a value
// or after whitespace AND before whitespace / end of line (deliberate deviation from strict YAML for
// the vault: plain-text issue refs like `#1157` stay text). Multi-line list items join into one item.
// The frozen legacy parser keeps the old behaviour for `zeusi locks lint`. Synthetic fixtures only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFrontmatter, stripComment } from '../src/importers/vault.ts';
import { parseFrontmatterLegacy } from '../src/importers/frontmatter-legacy.ts';

test('parser: `#1157` in a list item stays text (the old parser stored "Close"); `# comment` is stripped', () => {
  const raw = [
    'locks:',
    '  - Close #1157; set Dependabot to weekly with a PR limit',
    '  - Keep fixing #1057, #1059 and #1060 — do not park them',
    '  - Ship it # owner said so',
    '  - C# and F# tooling stays',
    '  - tagged #ops-only',
  ].join('\n');
  assert.deepEqual(parseFrontmatter(raw)['locks'], [
    'Close #1157; set Dependabot to weekly with a PR limit',
    'Keep fixing #1057, #1059 and #1060 — do not park them',
    'Ship it',
    'C# and F# tooling stays',
    'tagged #ops-only',
  ]);
  assert.deepEqual(parseFrontmatterLegacy(raw)['locks'], ['Close', 'Keep fixing', 'Ship it', 'C# and F# tooling stays', 'tagged']);
});

test('parser: plain scalars follow the same rule; a value that is only a comment is empty; `#` at value start before a digit is text', () => {
  const fm = parseFrontmatter(['title: Fix #42 in the C# client # trailing note', 'a: x #', 'b: # just a comment', 'c: #1157', 'd: a#b'].join('\n'));
  assert.equal(fm['title'], 'Fix #42 in the C# client');
  assert.equal(fm['a'], 'x');
  assert.equal(fm['b'], '');
  assert.equal(fm['c'], '#1157');
  assert.equal(fm['d'], 'a#b');
  assert.equal(stripComment('x\t# tab comment'), 'x');
  assert.equal(stripComment('#'), '');
});

test('parser: quoted strings are unchanged (a `#` inside quotes is text; a comment after the closing quote is dropped)', () => {
  const fm = parseFrontmatter([
    'a: "keep # this"',
    "b: 'and #this # too'",
    'c: "quoted" # comment after',
    'locks:',
    '  - "Close #1157 # not a comment inside quotes"',
    "  - 'it''s #fine'",
    '  - "esc \\"q\\" #1" # gone',
  ].join('\n'));
  assert.equal(fm['a'], 'keep # this');
  assert.equal(fm['b'], 'and #this # too');
  assert.equal(fm['c'], 'quoted');
  assert.deepEqual(fm['locks'], ['Close #1157 # not a comment inside quotes', "it's #fine", 'esc "q" #1']);
});

test('parser: a multi-line list item (indented continuation lines) joins into ONE item; the old parser fell back to a raw string', () => {
  const raw = [
    'locks:',
    '  - After hardened gates ops-console',
    '    may auto-merge #88 once green',
    '  - Second lock on one line',
    '  - "Quoted item that',
    '    continues"',
    '  # a comment line between items',
    '  - Last',
    'status: locked',
  ].join('\n');
  const fm = parseFrontmatter(raw);
  assert.deepEqual(fm['locks'], ['After hardened gates ops-console may auto-merge #88 once green', 'Second lock on one line', 'Quoted item that continues', 'Last']);
  assert.equal(fm['status'], 'locked');
  assert.equal(typeof parseFrontmatterLegacy(raw)['locks'], 'string', 'legacy: raw block string');
});

test('parser: top-level (unindented) dash items with an indented continuation; nested non-list blocks stay raw', () => {
  const fm = parseFrontmatter(['locks:', '- first item', '  continued', '- second', 'meta:', '  key: v', '  other: w'].join('\n'));
  assert.deepEqual(fm['locks'], ['first item continued', 'second']);
  assert.equal(fm['meta'], '  key: v\n  other: w');
});

test('parser: inline lists keep `#ref` text, and a trailing comment after the list is dropped', () => {
  const fm = parseFrontmatter(['locks: [Close #1157, "Keep #1057, #1059", tagged #x] # trailing', 'tags: [ops, lock]'].join('\n'));
  assert.deepEqual(fm['locks'], ['Close #1157', 'Keep #1057, #1059', 'tagged #x']);
  assert.deepEqual(fm['tags'], ['ops', 'lock']);
  assert.deepEqual(parseFrontmatterLegacy('locks: [Close #1157, b]')['locks'], ['Close', 'b']);
});

test('parser: block scalars are untouched by comment stripping; unchanged notes without `#` parse the same as before', () => {
  const raw = ['body: |', '  line one # stays', '  line #2', 'title: Plain title', 'related:', '  - "[[a-note]]"', '  - "[[b-note]]"', 'tags:', '  - ops', '  - lock'].join('\n');
  const fm = parseFrontmatter(raw);
  assert.equal(fm['body'], 'line one # stays\nline #2');
  assert.deepEqual(fm, parseFrontmatterLegacy(raw));
});
