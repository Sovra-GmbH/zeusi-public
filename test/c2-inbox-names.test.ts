// C2 (docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD5, review C2R1-2): a preview's raw inbox uses
// neutral names on disk. The inbox lives only inside the preview call (it is removed before the call
// returns), so the post-call disk scans of test/c2-canary.test.ts cannot see it; this pins the names
// the inbox writer puts on disk, and that a note's title survives only as the in-memory logical name.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { writeInbox } from '../src/workspace-write.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const CANARY = 'osprey-inbox-canary-5519';

function allEntries(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, n.name);
      out.push(relative(dir, p));
      if (n.isDirectory()) walk(p);
    }
  };
  walk(dir);
  return out.sort();
}

test('writeInbox: on-disk names are neutral (no title, no canary); the title-bearing name stays in memory only', () => {
  const root = safeMkdtemp(join(tmpdir(), 'zeusi-inbox-'));
  const inputs = writeInbox(root, [
    { kind: 'markdown', title: `Plan ${CANARY}`, text: `# Plan ${CANARY}\n\nbody` },
    { kind: 'markdown', text: 'untitled body' },
    { kind: 'decision-log', format: 'jsonl', text: '{}\n' },
    { kind: 'claude-export', text: '[]' },
  ]);

  const entries = allEntries(root);
  assert.deepEqual(entries, ['claude-export-4.json', 'decision-log-3.jsonl', 'notes', 'notes/001.md', 'notes/002.md']);
  for (const e of entries) {
    assert.ok(!e.toLowerCase().includes('osprey') && !e.toLowerCase().includes('plan'), `a title reached a name on disk: ${e}`);
    if (e !== 'notes') assert.equal(statSync(join(root, e)).mode & 0o777, 0o600, e);
  }
  assert.equal(statSync(join(root, 'notes')).mode & 0o777, 0o700);
  assert.ok(readFileSync(join(root, 'notes', '001.md'), 'utf8').includes(CANARY), 'the content was written (the scan is not vacuous)');

  // The logical names (in memory) keep the title, so titles and path gates are unchanged.
  const md = inputs.find((i) => i.kind === 'markdown');
  assert.ok(md && 'names' in md && md.names instanceof Map, 'the markdown input carries its logical-name map');
  assert.deepEqual([...md.names!.entries()], [['001.md', `001-plan-${CANARY}.md`], ['002.md', '002-note.md']]);
  assert.deepEqual(inputs.map((i) => [i.kind, relative(root, i.path)]), [
    ['markdown', 'notes'], ['decision-log', 'decision-log-3.jsonl'], ['claude-export', 'claude-export-4.json'],
  ]);
});

test('the preview call writes its inbox through writeInbox (the pin above covers the real path)', () => {
  const src = readFileSync(new URL('../src/workspace-write.ts', import.meta.url), 'utf8');
  const preview = src.slice(src.indexOf('async preview('), src.indexOf('prepareImport({', src.indexOf('async preview(')));
  assert.match(preview, /const inputs = writeInbox\(inbox, docs\);/);
  assert.doesNotMatch(preview, /writeFileSync/, 'no other inbox write inside preview');
});
