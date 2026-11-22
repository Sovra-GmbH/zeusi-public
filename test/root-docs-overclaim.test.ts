// The over-claim ban (test/helpers/overclaim.ts) for the public root docs that GitHub shows on the repo page:
// README.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md and the .github templates. Review r1 P0 of
// zeusi-public PR #1: the README said more about encryption than the code makes true, and only site/ was scanned.
// AGENTS.md and CLAUDE.md are rule files that name the ban itself, so they are not public copy and are not scanned.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ADMIN_LOGIN_SENTENCE, OWNER_ENCRYPTION_LINE, SIGNED_IN_SENTENCE, siteOverclaims } from './helpers/overclaim.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const TEMPLATES = '.github/ISSUE_TEMPLATE/';
const PUBLIC_DOCS = [
  'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md', '.github/PULL_REQUEST_TEMPLATE.md',
  ...readdirSync(`${ROOT}${TEMPLATES}`).map((f) => `${TEMPLATES}${f}`),
];
// The setting's name is a variable name, not a claim: it is the only "encrypt" removed before the scan.
const FLAG = /`ZEUSI_WORKSPACE_ENCRYPTION`/g;
const read = (f: string) => readFileSync(`${ROOT}${f}`, 'utf8');
const escapeRe = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// In markdown a line start is a sentence start (the site's equivalent is "right after a tag"). The exact owner line is
// removed only there or after sentence punctuation, the same rule as siteOverclaims; nothing else is removed.
const OWNER_AT_LINE_START = new RegExp(String.raw`(^|[.!?]\s+)${escapeRe(OWNER_ENCRYPTION_LINE)}(?=\s|$)`, 'gm');
/** Blockquote markers and emphasis removed, the owner line removed at a line start, then lines joined with spaces
 * (so a phrase wrapped over two lines is still caught). */
const plain = (t: string) => t.replace(/^>[ \t]?/gm, '').replace(/\*\*|__/g, '').replace(FLAG, 'the setting')
  .replace(OWNER_AT_LINE_START, '$1 ').replace(/\s*\n\s*/g, ' ');

test('root docs: no encryption or operator-blindness claim beyond the owner line and the allowed sentences', () => {
  for (const f of PUBLIC_DOCS) assert.deepEqual(siteOverclaims(plain(read(f))), [], f);
});

test('root docs: the README keeps the security-page bundle word for word, and none of the removed claims', () => {
  const raw = read('README.md');
  assert.equal(raw.split(OWNER_ENCRYPTION_LINE).length - 1, 1, 'the owner line once');
  const r = raw.replace(/^>[ \t]?/gm, '').replace(/\s*\n\s*/g, ' ');
  for (const s of [SIGNED_IN_SENTENCE, ADMIN_LOGIN_SENTENCE, 'Your workspace is not end-to-end encrypted.']) assert.ok(r.includes(s), s);
  assert.doesNotMatch(r, /encrypted from sign-up|New personal workspaces are encrypted|born encrypted|unlocks it/i);
});

test('root docs: every `wall <sub>` the README names is a real CLI subcommand', () => {
  const cli = read('src/cli.ts');
  const real = new Set([...cli.matchAll(/sub === '([a-z-]+)'/g)].map((m) => m[1]));
  const named = [...read('README.md').matchAll(/`(?:npm start -- |node dist\/cli\.js )?wall ([a-z][a-z-]*)/g)].map((m) => m[1]!);
  assert.ok(named.length > 0, 'the README names wall subcommands');
  for (const n of named) assert.ok(real.has(n), `wall ${n} is not a CLI subcommand`);
});
