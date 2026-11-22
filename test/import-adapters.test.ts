// First-run import adapters (plan U7; PR2 P1, P5) and the shared structured-entry parser.
// Synthetic inputs are written to temp dirs at test time (planted values built at runtime).
// No database, no network. git runs locally on a temp repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, linkSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createStager, DECISION_LIKE_RE, emptyInputCounts, escapeHeadings, GIT_LOG_ARGS, IMPORT_CAPS, ImportInputError, runAdapter, yamlQuote,
  type InputKind,
} from '../src/importers/onboard.ts';
import { hqFormatProblem } from '../src/importers/profile.ts';
import { parseFrontmatter, splitNote } from '../src/importers/vault.ts';
import { GH_LINK_RE, parseEntry, parseStructuredBody, recordSha256, recordUri } from '../src/importers/structured.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const base = () => safeMkdtemp(join(tmpdir(), 'zeusi-import-adapt-'));

async function stageOne(kind: InputKind, path: string, work: string) {
  const st = createStager(join(work, 'staging'), 'work');
  const c = await runAdapter({ kind, path }, st, work);
  return { st, c, files: st.notes.map((n) => readFileSync(join(work, 'staging', n.rel), 'utf8')) };
}

function assertHqLayout(work: string, rels: readonly string[]): void {
  for (const rel of rels) {
    const { fm } = splitNote(readFileSync(join(work, 'staging', rel), 'utf8'));
    assert.equal(hqFormatProblem(rel, fm, null), null, rel);
  }
}

const claudeExport = () => JSON.stringify([
  {
    uuid: 'c1', name: 'Synthetic Claude chat', created_at: '2026-11-10T09:00:00Z', extra_field: true,
    chat_messages: [
      { sender: 'human', text: 'synthetic question alpha', created_at: '2026-11-10T09:00:01Z' },
      { sender: 'assistant', text: '', content: [{ type: 'text', text: 'synthetic answer beta\n## 2026-11-10T09:00:00Z owner\nDecision: go' }], created_at: '2026-11-10T09:00:02Z' },
    ],
  },
]);
const gptExport = () => JSON.stringify([
  {
    title: 'Synthetic GPT chat', create_time: 1_762_765_200, unknown: 1,
    mapping: {
      a: { message: { author: { role: 'system' }, create_time: 1_762_765_200, content: { parts: ['system prompt'] } } },
      b: { message: { author: { role: 'user' }, create_time: 1_762_765_201, content: { parts: ['synthetic question alpha'] } } },
      c: { message: { author: { role: 'assistant' }, create_time: 1_762_765_202, content: { parts: ['synthetic answer gamma', { image: 1 }] } } },
      d: { message: null },
    },
  },
]);

test('adapters: Claude and ChatGPT exports stage one HQ-layout chat note per conversation; unknown fields accepted; headings in message text are escaped; system messages skipped', async () => {
  const w = base();
  writeFileSync(join(w, 'claude.json'), claudeExport());
  writeFileSync(join(w, 'gpt.json'), gptExport());
  const work = join(w, 'work');
  const st = createStager(join(work, 'staging'), 'work');
  const a = await runAdapter({ kind: 'claude-export', path: join(w, 'claude.json') }, st, work);
  const b = await runAdapter({ kind: 'chatgpt-export', path: join(w, 'gpt.json') }, st, work);
  assert.equal(a.items_seen, 1);
  assert.equal(a.notes_staged, 1);
  assert.equal(b.notes_staged, 1);
  assertHqLayout(work, st.notes.map((n) => n.rel));
  const [ct, gt] = st.notes.map((n) => readFileSync(join(work, 'staging', n.rel), 'utf8'));
  assert.match(ct!, /^kind: chat$/m);
  assert.match(ct!, /^## 2026-11-10T09:00:01\.000Z \(user\)$/m);
  assert.match(ct!, /^\\## 2026-11-10T09:00:00Z owner$/m, 'an H2 inside message text is escaped');
  assert.equal(parseStructuredBody(splitNote(ct!).body).records.length, 0, 'a chat never yields a structured record');
  assert.doesNotMatch(gt!, /system prompt/);
  assert.match(gt!, /synthetic answer gamma/);
  assert.deepEqual(st.notes.map((n) => n.origin), ['claude-export', 'chatgpt-export']);
});

test('adapters: an export with a missing essential field, invalid JSON or over the size cap is refused whole with a safe message (no path)', async () => {
  const w = base();
  const work = join(w, 'work');
  const bad = join(w, 'bad.json');
  writeFileSync(bad, JSON.stringify([{ name: 'x', chat_messages: [] }]));
  for (const [kind, text] of [['claude-export', JSON.stringify([{ name: 'x', chat_messages: [] }])], ['chatgpt-export', JSON.stringify([{ title: 'x' }])], ['claude-export', '{not json']] as const) {
    writeFileSync(bad, text);
    await assert.rejects(runAdapter({ kind, path: bad }, createStager(join(work, `s-${Math.random()}`), 'work'), work), (e: Error) => {
      assert.ok(e instanceof ImportInputError);
      assert.ok(!e.message.includes(w), 'no path in the message');
      return true;
    });
  }
  // Over the cap: refused before parsing (a sparse file of cap+1 bytes).
  const big = join(w, 'big.json');
  writeFileSync(big, '');
  execFileSync('truncate', ['-s', String(IMPORT_CAPS.jsonExportBytes + 1), big]);
  await assert.rejects(runAdapter({ kind: 'claude-export', path: big }, createStager(join(work, 's-big'), 'work'), work), /larger than the cap/);
});

test('adapters: two inputs with identical content stage one note (deduped 1); the same input twice gives the same names and bytes', async () => {
  const w = base();
  writeFileSync(join(w, 'c1.json'), claudeExport());
  writeFileSync(join(w, 'c2.json'), claudeExport());
  const work = join(w, 'work');
  const st = createStager(join(work, 'staging'), 'work');
  await runAdapter({ kind: 'claude-export', path: join(w, 'c1.json') }, st, work);
  const second = await runAdapter({ kind: 'claude-export', path: join(w, 'c2.json') }, st, work);
  assert.equal(second.deduped, 1);
  assert.equal(st.notes.length, 1);
  const again = await stageOne('claude-export', join(w, 'c1.json'), join(w, 'work2'));
  assert.equal(again.st.notes[0]!.rel, st.notes[0]!.rel);
  assert.equal(again.files[0], readFileSync(join(work, 'staging', st.notes[0]!.rel), 'utf8'));
});

test('adapters: markdown walk carries locks / related through, skips .obsidian, symlinked file and folder, hard link (each counted), refuses a symlink root', async () => {
  const w = base();
  const notes = join(w, 'notes');
  mkdirSync(join(notes, '.obsidian'), { recursive: true });
  mkdirSync(join(notes, 'sub'), { recursive: true });
  writeFileSync(join(notes, '.obsidian', 'app.md'), 'never read');
  writeFileSync(join(notes, 'Ops rules.md'), '---\ntitle: "Ops: rules \\"quoted\\""\ndate: 2026-11-12\nstatus: locked\nlocks:\n  - no prod deploys on Fridays\n  - "keep #channel quiet"\nrelated: [[Other note]]\n---\n# Heading\n\n## Section\nbody text\n');
  writeFileSync(join(notes, 'sub', 'plain.md'), 'no frontmatter, just text\n');
  writeFileSync(join(notes, 'image.png'), 'x');
  writeFileSync(join(w, 'outside.md'), 'outside the folder');
  symlinkSync(join(w, 'outside.md'), join(notes, 'link.md'));
  symlinkSync(w, join(notes, 'linkdir'));
  writeFileSync(join(w, 'hard-src.md'), 'hard linked');
  linkSync(join(w, 'hard-src.md'), join(notes, 'hard.md'));
  const work = join(w, 'work');
  const { st, c, files } = await stageOne('markdown', notes, work);
  assert.equal(c.notes_staged, 2);
  assert.equal(c.skipped.dot, 1);
  assert.equal(c.skipped.symlink, 2);
  assert.equal(c.skipped.hard_link, 1);
  assert.equal(c.skipped.unsupported, 1);
  assertHqLayout(work, st.notes.map((n) => n.rel));
  const ops = files.find((f) => f.includes('no prod deploys'))!;
  const fm = splitNote(ops).fm!;
  assert.deepEqual(fm['locks'], ['no prod deploys on Fridays', 'keep #channel quiet']);
  assert.deepEqual(fm['related'], ['[Other note]'], 'carried exactly as the vault frontmatter parser reads it');
  assert.equal(fm['title'], 'Ops: rules "quoted"');
  assert.equal(fm['date'], '2026-11-12');
  assert.equal(fm['kind'], 'memory');
  assert.equal(fm['status'], undefined, 'only locks and related are carried');
  for (const f of files) assert.ok(!f.includes('outside the folder') && !f.includes('hard linked') && !f.includes('never read'));
  // A symlink as the input root is refused.
  symlinkSync(notes, join(w, 'notes-link'));
  await assert.rejects(runAdapter({ kind: 'markdown', path: join(w, 'notes-link') }, createStager(join(work, 's2'), 'work'), work), /symlink/);
  // An input overlapping the private work dir is refused.
  await assert.rejects(runAdapter({ kind: 'markdown', path: w }, createStager(join(work, 's3'), 'work'), work), /overlaps the private work dir/);
});

function git(repo: string, ...args: string[]): string {
  return execFileSync('git', args, {
    cwd: repo, encoding: 'utf8',
    env: { PATH: process.env['PATH'] ?? '', HOME: repo, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 'Synthetic', GIT_AUTHOR_EMAIL: 'synthetic@example.invalid', GIT_COMMITTER_NAME: 'Synthetic', GIT_COMMITTER_EMAIL: 'synthetic@example.invalid' },
  });
}

test('adapters: git stages decision-like commits and PR merges (one note per day), never author emails; hooks, fsmonitor and gpg config in the repo never run; a non-repo is refused safely', async () => {
  const w = base();
  const repo = join(w, 'repo');
  mkdirSync(repo);
  git(repo, 'init', '-q', '-b', 'main');
  const at = (d: string) => ({ GIT_AUTHOR_DATE: d, GIT_COMMITTER_DATE: d });
  const commit = (msg: string, d: string) => execFileSync('git', ['commit', '-q', '--allow-empty', '-m', msg], {
    cwd: repo, env: { PATH: process.env['PATH'] ?? '', HOME: repo, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 'Synthetic', GIT_AUTHOR_EMAIL: 'synthetic@example.invalid', GIT_COMMITTER_NAME: 'Synthetic', GIT_COMMITTER_EMAIL: 'synthetic@example.invalid', ...at(d) },
  });
  commit('chore: plain commit', '2026-11-10T10:00:00Z');
  commit('feat: lock the release train (decision)\n\nDecision: lock\nSaid-at-precision: minute', '2026-11-11T10:00:00Z');
  commit('Merge pull request #12 from synthetic/branch', '2026-11-11T11:00:00Z');
  commit('fix: typo', '2026-11-12T10:00:00Z');
  // Hostile repo config: every one of these must stay inert.
  const marker = join(w, 'marker');
  const script = join(w, 'evil.sh');
  writeFileSync(script, `#!/bin/sh\ntouch '${marker}'\n`);
  chmodSync(script, 0o755);
  mkdirSync(join(repo, 'hooks'));
  for (const h of ['post-checkout', 'pre-commit', 'post-index-change', 'reference-transaction']) {
    writeFileSync(join(repo, 'hooks', h), `#!/bin/sh\ntouch '${marker}'\n`);
    chmodSync(join(repo, 'hooks', h), 0o755);
  }
  git(repo, 'config', 'core.fsmonitor', script);
  git(repo, 'config', 'core.hooksPath', join(repo, 'hooks'));
  git(repo, 'config', 'log.showSignature', 'true');
  git(repo, 'config', 'gpg.program', script);
  git(repo, 'config', 'core.pager', script);
  const work = join(w, 'work');
  const { st, c, files } = await stageOne('git', repo, work);
  assert.equal(existsSync(marker), false, 'no hook / fsmonitor / gpg / pager ran');
  assert.equal(c.items_seen, 2);
  assert.equal(st.notes.length, 1);
  assertHqLayout(work, st.notes.map((n) => n.rel));
  const t = files[0]!;
  assert.match(t, /^kind: decision$/m);
  assert.match(t, /^source: "git:repo"$/m);
  assert.equal((t.match(/^## /gm) ?? []).length, 2);
  assert.match(t, /commit [0-9a-f]{12}: feat: lock the release train/);
  assert.ok(!t.includes('synthetic@example.invalid') && !t.includes('Synthetic\n'));
  assert.equal(parseStructuredBody(splitNote(t).body).records.length, 0, 'git never yields structured records (the H2 is not a handle line)');
  // Fixed arguments only: no option comes from the input; the repo is the cwd.
  assert.ok(GIT_LOG_ARGS.includes('--') && GIT_LOG_ARGS.includes('core.hooksPath=/dev/null') && GIT_LOG_ARGS.includes('--no-show-signature'));
  assert.ok(DECISION_LIKE_RE.test('Revert "x"') && !DECISION_LIKE_RE.test('fix: typo'));
  mkdirSync(join(w, 'not-a-repo'));
  await assert.rejects(runAdapter({ kind: 'git', path: join(w, 'not-a-repo') }, createStager(join(work, 's2'), 'work'), work), (e: Error) => {
    assert.ok(e instanceof ImportInputError);
    assert.ok(!e.message.includes(w));
    return true;
  });
});

test('adapters: a JSONL decision log renders the structured header per line; a malformed line is skipped and counted; missing precision leaves the entry without it', async () => {
  const w = base();
  const log = join(w, 'decisions.jsonl');
  writeFileSync(log, [
    JSON.stringify({ kind: 'lock', who: 'synthetic-owner', said_at: '2026-11-12T08:00:00+01:00', said_at_precision: 'minute', exact_words: 'SYNTHETIC no Friday deploys', exact_words_verbatim: true, applies_to: ['deploy', 'prod'], linked_repo: 'Synthetic-Org/repo', linked_pr: 7 }),
    '{broken',
    JSON.stringify({ kind: 'go', who: 'synthetic-owner', said_at: '2026-11-13T09:00:00Z', exact_words: 'SYNTHETIC go without precision' }),
    JSON.stringify({ kind: 'nope', who: 'x', said_at: 'yesterday', exact_words: 'x' }),
    '',
  ].join('\n'));
  const work = join(w, 'work');
  const { st, c, files } = await stageOne('decision-log', log, work);
  assert.equal(c.items_seen, 4);
  assert.equal(c.skipped.malformed, 2);
  assert.equal(st.notes.length, 2, 'one note per day');
  assertHqLayout(work, st.notes.map((n) => n.rel));
  const all = files.join('\n');
  const parsed = files.map((f) => parseStructuredBody(splitNote(f).body));
  const records = parsed.flatMap((p) => p.records);
  assert.equal(records.length, 1);
  assert.deepEqual(records[0], {
    type: 'decision', who: 'synthetic-owner', saidAt: '2026-11-12T07:00:00.000Z', saidAtPrecision: 'minute', kind: 'lock', verbatim: true,
    appliesTo: ['deploy', 'prod'], linkedRepo: 'Synthetic-Org/repo', linkedPr: 7, expiresAt: null, expiresRule: null, text: 'SYNTHETIC no Friday deploys',
    links: ['gh:Synthetic-Org/repo#7'], // 0013: every allowlisted Links: item (not part of recordSha256)
  });
  assert.equal(parsed.reduce((n, p) => n + p.counts.invalid, 0), 1, 'the go without Said-at-precision is invalid (stays a note: invent=NO)');
  assert.match(all, /SYNTHETIC go without precision/);
});

test('adapters: a markdown decision log keeps timestamped H2 entries per day and the rest as one dated note', async () => {
  const w = base();
  const log = join(w, 'log.md');
  writeFileSync(log, '---\ndate: 2026-11-01\n---\n- an undated list decision\n\n## 2026-11-14T10:00:00+01:00 synthetic-owner\nDecision: park\nSaid-at-precision: day\n\nSYNTHETIC park the newsletter\n\n## Plain section\nnot structured\n');
  const work = join(w, 'work');
  const { st, files } = await stageOne('decision-log', log, work);
  assert.deepEqual(st.notes.map((n) => n.rel.split('/')[1]!.slice(0, 10)).sort(), ['2026-11-01', '2026-11-14']);
  const recs = files.flatMap((f) => parseStructuredBody(splitNote(f).body).records);
  assert.deepEqual(recs.map((r) => [r.type, r.type === 'decision' ? r.kind : '', r.text]), [['decision', 'park', 'SYNTHETIC park the newsletter']]);
});

test('structured parser: required fields, invent=NO refusals, facts, links, expires, mixing refused', () => {
  const e = (s: string) => parseEntry(s.split('\n'));
  const ok = e('## 2026-11-16T20:27:00+01:00 owner\nDecision: go\nSaid-at-precision: minute\nApplies-to: zeusi, oss\nLinks: vault:x.md, gh:example-org/zeusi#11\nExpires: after #13 merges\n\nSYNTHETIC text');
  assert.ok('record' in ok);
  const r = ok.record;
  assert.equal(r.type, 'decision');
  if (r.type === 'decision') {
    assert.deepEqual([r.linkedRepo, r.linkedPr, r.expiresRule, r.expiresAt, r.verbatim], ['example-org/zeusi', 11, 'after #13 merges', null, false]);
    assert.deepEqual(r.appliesTo, ['zeusi', 'oss']);
  }
  const fact = e('## 2026-11-16T20:27:00Z zeus\nType: focus\nSubject: northbank-release\n\nSYNTHETIC focus text');
  assert.ok('record' in fact && fact.record.type === 'fact' && fact.record.factKind === 'state');
  for (const [s, why] of [
    ['## 2026-11-16T20:27:00Z owner\n\nplain entry text', 'unstructured'],
    ['## Some heading\nDecision: go\n\nx', 'unstructured'],
    ['## 2026-11-16T20:27:00Z owner\nDecision: go\n\nmissing precision', 'invalid'],
    ['## 2026-11-16T20:27:00Z owner\nDecision: maybe\nSaid-at-precision: minute\n\nx', 'invalid'],
    ['## 2026-11-16T20:27:00Z owner\nDecision: go\nSaid-at-precision: minute\nType: rule\n\nx', 'invalid'],
    ['## 2026-11-16T20:27:00Z owner\nDecision: go\nSaid-at-precision: minute\nColour: red\n\nx', 'invalid'],
    ['## 2026-11-16T20:27:00Z owner\nDecision: go\nSaid-at-precision: minute\n\n', 'invalid'],
    ['## 2026-11-16T20:27:00Z owner\nType: retire\nSubject: x\n\nx', 'invalid'],
    ['## 2026-11-16T20:27:00Z owner\nType: rule\n\nno subject', 'invalid'],
    ['## 2026-11-16 owner\nDecision: go\nSaid-at-precision: day\n\nno time', 'unstructured'],
    ['## 2026-11-16T20:27:00Z the owner Smith\nDecision: go\nSaid-at-precision: day\n\nnot a handle', 'unstructured'],
  ] as const) {
    const x = e(s);
    assert.ok('skip' in x && x.skip === why, `${why}: ${s.split('\n')[0]}`);
  }
  assert.ok(GH_LINK_RE.test('gh:example-org/zeusi#11') && !GH_LINK_RE.test('gh:x#0') && !GH_LINK_RE.test('https://github.com/x/y/pull/1'));
  // uri ignores the text (an edit keeps the uri); sha changes with any field.
  const a = e('## 2026-11-16T20:27:00Z owner\nDecision: go\nSaid-at-precision: minute\n\none');
  const b = e('## 2026-11-16T20:27:00Z owner\nDecision: go\nSaid-at-precision: minute\n\ntwo');
  assert.ok('record' in a && 'record' in b);
  assert.equal(recordUri('import:', 'work', a.record), recordUri('import:', 'work', b.record));
  assert.notEqual(recordSha256(a.record), recordSha256(b.record));
  assert.match(recordUri('import:', 'work', a.record), /^import:work\/entry\/[0-9a-f]{16}$/);
});

test('helpers: escapeHeadings and yamlQuote round-trip through the frontmatter parser', () => {
  assert.equal(escapeHeadings('# a\n## b\n### c\n   ## d'), '\\# a\n\\## b\n### c\n\\## d');
  for (const s of ['plain', 'with "quotes" and \\ backslash', 'colon: and # hash', 'multi\nline']) {
    const fm = parseFrontmatter(`t: ${yamlQuote(s)}`);
    assert.equal(fm['t'], s.replace(/\n/g, ' '));
  }
  const c = emptyInputCounts('markdown');
  const st = createStager(join(base(), 'staging'), 'work');
  st.stage(c, { kind: 'memory', date: '2026-02-30', title: 't', source: 's', body: 'x' });
  st.stage(c, { kind: 'memory', date: '2026-02-03', title: 't', source: 's', body: '   ' });
  assert.deepEqual([c.skipped.no_date, c.skipped.empty, c.notes_staged], [1, 1, 0]);
  assert.equal(readdirSync(join(st.dir, 'work')).length, 0);
});

test('security r1 #1: a partial-clone repo whose missing mailmap blob would lazy-fetch from an ext:: promisor remote runs nothing', async () => {
  const w = base();
  const repo = join(w, 'repo');
  mkdirSync(repo);
  git(repo, 'init', '-q', '-b', 'main');
  execFileSync('git', ['commit', '-q', '--allow-empty', '-m', 'decision: lock the train'], {
    cwd: repo, env: { PATH: process.env['PATH'] ?? '', HOME: repo, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 'S', GIT_AUTHOR_EMAIL: 's@example.invalid', GIT_COMMITTER_NAME: 'S', GIT_COMMITTER_EMAIL: 's@example.invalid' },
  });
  const marker = join(w, 'PWNED');
  git(repo, 'config', 'core.repositoryformatversion', '1');
  git(repo, 'config', 'extensions.partialClone', 'origin');
  git(repo, 'config', 'remote.origin.promisor', 'true');
  git(repo, 'config', 'remote.origin.url', `ext::sh -c touch% ${marker}`);
  git(repo, 'config', 'protocol.ext.allow', 'always');
  git(repo, 'config', 'mailmap.blob', '0123456789abcdef0123456789abcdef01234567');
  git(repo, 'config', 'log.mailmap', 'true');
  const work = join(w, 'work');
  await stageOne('git', repo, work).catch(() => undefined);
  assert.equal(existsSync(marker), false, 'no lazy fetch, no ext:: command');
  assert.ok(GIT_LOG_ARGS.includes('log.mailmap=false') && GIT_LOG_ARGS.includes('--no-mailmap'));
});

test('security r1 #2: the markdown walk applies the wall path rules below the root (plankiva/, requests/, personal/, raw/) and keeps ClientCo/ out of a non-clientco scope', async () => {
  const w = base();
  const notes = join(w, 'vault');
  for (const d of [['plan', 'kiva'].join(''), 'requests', 'personal', 'raw', 'ClientCo', 'ok']) {
    mkdirSync(join(notes, d), { recursive: true });
    writeFileSync(join(notes, d, 'note.md'), `---\ndate: 2026-11-10\n---\nplain synthetic text in ${d === 'ok' ? 'ok' : 'gated'} folder\n`);
  }
  const work = join(w, 'work');
  const st = createStager(join(work, 'staging'), 'work');
  const c = await runAdapter({ kind: 'markdown', path: notes }, st, work, undefined, 'work');
  assert.equal(c.notes_staged, 1, 'only ok/note.md');
  assert.ok(c.skipped.path_gated >= 4, `path_gated ${c.skipped.path_gated}`);
  assert.equal(c.skipped.path_gated + c.skipped.scope_mismatch, 5);
  for (const n of st.notes) assert.doesNotMatch(readFileSync(join(work, 'staging', n.rel), 'utf8'), /gated folder/);
  // An input path inside a requests/ folder is refused outright.
  mkdirSync(join(w, 'requests'));
  writeFileSync(join(w, 'requests', 'log.md'), 'x\n');
  await assert.rejects(runAdapter({ kind: 'decision-log', path: join(w, 'requests', 'log.md') }, createStager(join(work, 's2'), 'work'), work), /refused by the wall/);
});

test('review r1 (low): fences in imported text are escaped; same body with different locks stages two notes', () => {
  assert.equal(escapeHeadings('```\nx\n~~~'), '\\```\nx\n\\~~~');
  const c = emptyInputCounts('markdown');
  const st = createStager(join(base(), 'staging'), 'work');
  st.stage(c, { kind: 'memory', date: '2026-02-03', title: 't', source: 's', body: 'same', extra: { locks: ['a'] } });
  st.stage(c, { kind: 'memory', date: '2026-02-03', title: 't', source: 's', body: 'same', extra: { locks: ['b'] } });
  assert.deepEqual([c.notes_staged, c.deduped], [2, 0]);
});

test('security r1 re-check: root-anchored wall folders hold for any root (the folder itself, a parent of the vault, nested copies); ClientCo needs --scope clientco', async () => {
  const w = base();
  const vault = join(w, 'parent', 'Vault');
  for (const d of ['ClientCo', 'personal', 'raw', 'a/ClientCo', 'a/personal', 'Bases', 'ok']) {
    mkdirSync(join(vault, d), { recursive: true });
    writeFileSync(join(vault, d, 'n.md'), `---\ndate: 2026-11-10\n---\nsynthetic ${d === 'ok' ? 'kept' : 'gated'} note\n`);
  }
  const work = join(w, 'work');
  let i = 0;
  const run = (path: string, scope: string) => runAdapter({ kind: 'markdown', path }, createStager(join(work, `s${i++}`), SCOPE_PROJECT_TEST[scope]!), work, undefined, scope);
  for (const root of [join(w, 'parent'), vault]) {
    const c = await run(root, 'work');
    assert.equal(c.notes_staged, 1, `root ${root === vault ? 'vault' : 'parent'}: only ok/n.md`);
  }
  await assert.rejects(run(join(vault, 'ClientCo'), 'work'), /import it with --scope client/);
  await assert.rejects(run(join(vault, 'personal'), 'work'), /walled folder/);
  await assert.rejects(run(join(vault, 'a', 'personal'), 'client'), /walled folder/);
  const v = await run(join(vault, 'ClientCo'), 'client');
  assert.equal(v.notes_staged, 1, 'ClientCo with --scope clientco is admitted');
});

const SCOPE_PROJECT_TEST: Record<string, string> = { work: 'work', client: 'client' };
