// `zeusi export-filter` (docs/hq-sync.md): the deterministic source-side filter for
// the nightly Zeus HQ export. Offline: no database, no network. Every "plankiva" string
// below is an obviously synthetic exclusion probe. Credential-shaped probes are built by
// concatenation at run time so the secret scanner never sees a token-shaped literal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, linkSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  plankivaWall, credentialSignal, entrySignal, ExportFilterIoError, ExportFilterUnsafeError, formatExportResult, runExportFilter, splitEntries, WITHHELD_MARKER, type ExportFilterOptions,
} from '../src/hq-export.ts';
import { mentionsProtectedName, parseToml, validateSources } from '../src/sources.ts';
import { PROTECTED_VARIANTS_REGEX, PROTECTED_SPELLING_REGEX, seedWall, wallNorm } from '../src/wall.ts';
import { hqNote } from './hq-fixtures.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

// Credential-shaped probes (fake; assembled at run time).
const FAKE_GH = ['gh', 'p_', 'Zz9'.repeat(12)].join('');
const FAKE_AWS = ['AK', 'IA', 'QQQQ', 'WWWW', 'EEEE', 'RRRR'].join('');
const FAKE_PW = ['pass', 'word', ': ', 'not-a-real-', 'pw-77'].join('');
const FAKE_2FA = ['Your 2FA ', 'code is ', '48', '29', '13'].join('');
const FAKE_KEY = ['-----BEGIN ', 'OPENSSH PRIVATE', ' KEY-----'].join('');
const FAKE_URL = ['postgresql://', 'u', ':', 'fakepw', '@', 'db.invalid/x'].join('');

interface Env {
  dir: string;
  inDir: string;
  outDir: string;
  write(rel: string, text: string): void;
  run(o?: Partial<ExportFilterOptions>): ReturnType<typeof runExportFilter>;
  out(rel: string): string;
  outFiles(): string[];
  close(): void;
}

function fresh(): Env {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-xf-'));
  const inDir = join(dir, 'staging');
  const outDir = join(dir, 'zeus-hq');
  mkdirSync(inDir, { recursive: true });
  const env: Env = {
    dir, inDir, outDir,
    write(rel, text) {
      mkdirSync(join(inDir, rel, '..'), { recursive: true });
      writeFileSync(join(inDir, rel), text);
    },
    run(o = {}) {
      return runExportFilter({ inDir, outDir, ...o });
    },
    out(rel) {
      return readFileSync(join(outDir, rel), 'utf8');
    },
    outFiles() {
      try {
        return readdirSync(outDir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => relative(outDir, join(e.parentPath, e.name))).sort();
      } catch {
        return [];
      }
    },
    close() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return env;
}

function treeHash(root: string): string {
  const h = createHash('sha256');
  for (const e of readdirSync(root, { recursive: true, withFileTypes: true }).sort((a, b) => join(a.parentPath, a.name).localeCompare(join(b.parentPath, b.name)))) {
    const p = join(e.parentPath, e.name);
    const st = statSync(p, { throwIfNoEntry: false });
    h.update(`${relative(root, p)}|${e.isFile() ? readFileSync(p).toString('base64') : 'dir'}|${st?.mtimeMs ?? ''}\n`);
  }
  return h.digest('hex');
}

/** Zero Plankiva signal by every layer: wall (Plankiva-class rules, incl. look-alike/encoded), mentionsProtectedName, requests/. */
function assertNoPlankivaSignal(text: string) {
  assert.ok(!mentionsProtectedName(text), 'mentionsProtectedName');
  assert.doesNotMatch(wallNorm(text), /plankiva/);
  assert.doesNotMatch(text, /requests\//i);
  const v = plankivaWall().check('notes', { vault_path: 'hq:x/y.md', title: 'x', body: text, frontmatter: {}, source_uri: 'hq:x/y.md' });
  assert.equal(v.blocked, false);
}

const MIXED: Array<[string, string]> = [
  ['2026-11-13T09:00:00+01:00 owner', 'K1 synthetic clean turn one.'],
  ['2026-11-13T09:01:00+01:00 zeus', 'W1-marker synthetic exclusion probe: Plankiva.'],
  ['2026-11-13T09:02:00+01:00 owner', 'K2 synthetic clean turn two (ClientCo desk sync, CHF 120 invoice: not filtered here).'],
  ['2026-11-13T09:03:00+01:00 zeus', 'W2-marker synthetic look-alike probe: plаnκіva.'],
  ['2026-11-13T09:04:00+01:00 owner', 'W3-marker synthetic zero-width probe: pla​nkiva.'],
  ['2026-11-13T09:05:00+01:00 zeus', 'W4-marker synthetic encoded probe: %70lankiva and %2570lankiva.'],
  ['2026-11-13T09:06:00+01:00 owner', 'W5-marker synthetic tag probe #plankiva-probe'],
  ['2026-11-13T09:07:00+01:00 zeus', 'K3 synthetic clean turn three (Northbank coverage).'],
  ['2026-11-13T09:08:00+01:00 owner', 'W6-marker synthetic path probe: see requests/form-7.md'],
  ['2026-11-13T09:09:00+01:00 zeus', 'W7-marker synthetic full-width probe: ｐｌａｎｋｉｖａ.'],
  ['2026-11-13T09:10:00+01:00 owner', 'K4 synthetic clean turn four.'],
];

test('mixed note: Plankiva-signal entries are withheld (marker only), clean entries kept in order, ClientCo/Northbank/currency text untouched', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-hq-chat.md', hqNote({ project: 'team' }, MIXED));
    const r = e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.files_kept, 1);
    assert.equal(r.counts.entries_kept, 4 + 1, 'four clean turns + the empty preamble');
    assert.equal(r.counts.entries_withheld, 7);
    assert.equal(r.counts.withheld_by_signal.plankiva, 6);
    assert.equal(r.counts.withheld_by_signal.requests, 1);
    const out = e.out('team/2026-11-13-hq-chat.md');
    const k = ['K1', 'K2', 'K3', 'K4'].map((x) => out.indexOf(x));
    assert.ok(k.every((i, n) => i > 0 && (n === 0 || i > k[n - 1]!)), 'kept entries in input order');
    assert.equal(out.split(WITHHELD_MARKER).length - 1, 7);
    assert.doesNotMatch(out, /W\d-marker/);
    assert.match(out, /ClientCo desk sync, CHF 120/);
    assertNoPlankivaSignal(out);
    // The marker sits where the entry was: K1, marker, K2.
    assert.ok(out.indexOf(WITHHELD_MARKER) > k[0]! && out.indexOf(WITHHELD_MARKER) < k[1]!);
    // Frontmatter is byte-identical.
    assert.ok(out.startsWith(hqNote({ project: 'team' }, []).split('\n').slice(0, 10).join('\n')));
  } finally {
    e.close();
  }
});

test('whole-note drop: title, tags, any frontmatter value, file name or project folder name with an Plankiva signal', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-title.md', hqNote({ project: 'team', title: 'synthetic Plаnkiva probe' }, [['t', 'D1-marker']]));
    e.write('team/2026-11-13-tags.md', hqNote({ project: 'team', tags: ['ops', 'plankiva-probe'] }, [['t', 'D2-marker']]));
    e.write('team/2026-11-13-thread.md', hqNote({ project: 'team', thread: '%70lankiva-probe' }, [['t', 'D3-marker']]));
    e.write('team/2026-11-13-plankiva-probe.md', hqNote({ project: 'team' }, [['t', 'D4-marker']]));
    e.write('plankiva-probe/2026-11-13-x.md', hqNote({ project: 'plankiva-probe' }, [['t', 'D5-marker']]));
    e.write('team/2026-11-13-req.md', hqNote({ project: 'team', thread: 'requests/form-1' }, [['t', 'D6-marker']]));
    e.write('team/2026-11-13-ok.md', hqNote({ project: 'team' }, [['t', 'K-ok']]));
    const r = e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.deepEqual(e.outFiles(), ['team/2026-11-13-ok.md']);
    assert.equal(r.counts.files_dropped, 5);
    assert.equal(r.counts.folders_dropped, 1);
    const report = formatExportResult(r, true);
    assert.doesNotMatch(report, /D\d-marker|plankiva-probe|2026-11-13-/i);
  } finally {
    e.close();
  }
});

test('credential scrub: token / password / private key / URL password / 2FA code entries are withheld, counted only', () => {
  const e = fresh();
  try {
    const turns: Array<[string, string]> = [
      ['t0', 'K0 clean'],
      ['t1', `C1 ${FAKE_GH}`],
      ['t2', `C2 ${FAKE_AWS}`],
      ['t3', `C3 ${FAKE_PW}`],
      ['t4', `C4 ${FAKE_2FA}`],
      ['t5', `C5\n${FAKE_KEY}\nabc\n`],
      ['t6', `C6 ${FAKE_URL}`],
      ['t7', 'K7 clean: the password lives in 1Password, ask the owner.'],
    ];
    e.write('zeusi/2026-11-13-creds.md', hqNote({ project: 'zeusi' }, turns));
    const r = e.run();
    assert.equal(r.counts.withheld_by_signal.credential, 6);
    const out = e.out('zeusi/2026-11-13-creds.md');
    assert.doesNotMatch(out, /C[1-6] /);
    assert.match(out, /K0 clean/);
    assert.match(out, /K7 clean/);
    for (const s of [FAKE_GH, FAKE_AWS, FAKE_PW, FAKE_2FA, FAKE_KEY, FAKE_URL]) {
      assert.ok(credentialSignal(s), s.slice(0, 4));
      assert.ok(!out.includes(s));
    }
    assert.equal(credentialSignal('we rotated the password yesterday'), false);
    assert.equal(credentialSignal('PR #1188 merged at 10:42'), false);
  } finally {
    e.close();
  }
});

test('input is never written; output is idempotent (same bytes, files not rewritten); --out inside --in (or the reverse) is refused', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-hq-chat.md', hqNote({ project: 'team' }, MIXED));
    e.write('northbank/2026-11-13-standup.md', hqNote({ project: 'northbank', kind: 'decision' }, [['t', 'K northbank']]));
    const before = treeHash(e.inDir);
    const r1 = e.run();
    assert.equal(treeHash(e.inDir), before, 'input untouched (bytes and mtimes)');
    const out1 = treeHash(e.outDir);
    const r2 = e.run();
    assert.equal(treeHash(e.outDir), out1, 'same bytes, same mtimes: nothing rewritten');
    assert.equal(r2.counts.files_unchanged, 2);
    assert.deepEqual({ ...r1.counts, files_unchanged: 0 }, { ...r2.counts, files_unchanged: 0 });
    assert.equal(treeHash(e.inDir), before);
    assert.throws(() => runExportFilter({ inDir: e.inDir, outDir: join(e.inDir, 'out') }), /overlap/);
    assert.throws(() => runExportFilter({ inDir: e.inDir, outDir: e.inDir }), /overlap/);
    assert.throws(() => runExportFilter({ inDir: join(e.outDir, 'team'), outDir: e.outDir }), /overlap/);
    symlinkSync(e.inDir, join(e.dir, 'in-link'));
    assert.throws(() => runExportFilter({ inDir: e.inDir, outDir: join(e.dir, 'in-link', 'x') }), /overlap/);
    assert.equal(treeHash(e.inDir), before);
  } finally {
    e.close();
  }
});

test('re-export after an edit: a now-dropped note removes its earlier clean output; an edited entry is re-filtered', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K clean']]));
    e.write('team/2026-11-13-b.md', hqNote({ project: 'team' }, [['t1', 'K clean b']]));
    e.run();
    assert.deepEqual(e.outFiles(), ['team/2026-11-13-a.md', 'team/2026-11-13-b.md']);
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team', tags: ['plankiva-probe'] }, [['t1', 'K clean']]));
    e.write('team/2026-11-13-b.md', hqNote({ project: 'team' }, [['t1', 'K clean b'], ['t2', 'synthetic exclusion probe plankiva']]));
    const r = e.run();
    assert.equal(r.counts.files_removed, 1);
    assert.deepEqual(e.outFiles(), ['team/2026-11-13-b.md']);
    assert.equal(e.out('team/2026-11-13-b.md').split(WITHHELD_MARKER).length - 1, 1);
  } finally {
    e.close();
  }
});

test('layout and unsafe files: bad names, no frontmatter, sub-folders, symlinks and hard links are dropped (counted), never followed', () => {
  const e = fresh();
  try {
    e.write('team/notes.md', '# x\n');
    e.write('team/2026-11-13-nofm.md', '## t\n\nx\n');
    e.write('team/sub/2026-11-13-deep.md', hqNote({ project: 'team' }, [['t', 'x']]));
    e.write('top-level.md', 'x\n');
    e.write('team/2026-11-13-ok.md', hqNote({ project: 'team' }, [['t', 'K']]));
    writeFileSync(join(e.dir, 'outside.md'), hqNote({ project: 'team' }, [['t', 'S-marker outside']]));
    symlinkSync(join(e.dir, 'outside.md'), join(e.inDir, 'team/2026-11-13-link.md'));
    linkSync(join(e.dir, 'outside.md'), join(e.inDir, 'team/2026-11-13-hard.md'));
    const r = e.run();
    assert.deepEqual(e.outFiles(), ['team/2026-11-13-ok.md']);
    assert.equal(r.counts.dropped_by_reason.layout, 4);
    assert.equal(r.counts.dropped_by_reason.unsafe, 2);
  } finally {
    e.close();
  }
});

test('splitEntries: H2 outside fences only; a ## line in a code block stays in its entry; round trip is byte-exact', () => {
  const body = 'pre\n\n## a\n\nx\n```\n## not a heading\n```\n\n## b\r\n\r\ny\n';
  const es = splitEntries(body);
  assert.equal(es.length, 3);
  assert.equal(es.map((x) => x.lines.join('\n')).join('\n'), body);
  assert.match(es[1]!.lines.join('\n'), /not a heading/);
  assert.equal(entrySignal('plain text', plankivaWall()), null);
  assert.equal(entrySignal('synthetic probe PLANKIVA', plankivaWall()), 'plankiva');
});

test('output gate: if the entry filter is bypassed (test only), the wall re-check refuses and removes the run\'s outputs', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K ok']]));
    e.write('team/2026-11-13-b.md', hqNote({ project: 'team' }, [['t1', 'synthetic exclusion probe plankiva']]));
    const r = e.run({ testOnlyKeepAllEntries: true });
    assert.equal(r.status, 'refused');
    assert.equal(r.counts.gate_hits, 1);
    assert.deepEqual(e.outFiles(), [], 'nothing from the refused run stays in the source folder');
  } finally {
    e.close();
  }
});

test('--config projects: a folder that is not a configured project is dropped unlisted', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K']]));
    e.write('other/2026-11-13-a.md', hqNote({ project: 'other' }, [['t1', 'K']]));
    const r = e.run({ projects: ['team', 'hq'] });
    assert.deepEqual(e.outFiles(), ['team/2026-11-13-a.md']);
    assert.equal(r.counts.folders_dropped, 1);
  } finally {
    e.close();
  }
});

test('report: counts only; the ingest preview counts soft-rule hits by rule id (the wall is not weakened)', () => {
  const e = fresh();
  try {
    e.write('clientco/2026-11-13-desk.md', hqNote({ project: 'clientco' }, [['t1', 'synthetic ClientCo desk note']]));
    e.write('team/2026-11-13-money.md', hqNote({ project: 'team' }, [['t1', 'synthetic invoice CHF 120']]));
    e.write('team/2026-11-13-acct.md', hqNote({ project: 'team' }, [['t1', 'synthetic account 1234567']]));
    e.write('team/2026-11-13-clean.md', hqNote({ project: 'team' }, [['t1', 'synthetic clean'], ['t2', 'synthetic exclusion probe plankiva']]));
    const r = e.run();
    assert.equal(r.counts.files_kept, 4, 'ClientCo, currency and account-number notes are not filtered at the source');
    // The account-number note is quarantined by soft rule 34 at ingest. The currency rule was
    // lifted by 0011 and the ClientCo hard rules by 0010, so those notes would pass.
    assert.equal(r.preview.would_pass + r.preview.would_quarantine, 4);
    assert.equal(r.preview.by_rule['33'] ?? 0, 0, 'rule 33 (currency) is gone since 0011');
    assert.ok((r.preview.by_rule['34'] ?? 0) >= 1);
    assert.equal(r.preview.would_quarantine, 1);
    assert.equal(r.preview.would_pass, 3);
    const text = formatExportResult(r, true);
    assert.match(text, /entries: kept \d+, withheld 1/);
    assert.match(text, /ingest preview/);
    assert.match(text, /rule 34 regex \(soft\)/);
    assert.doesNotMatch(text, /synthetic|2026-11-13-|CHF 120|1234567/);
  } finally {
    e.close();
  }
});

test('CLI: zeusi export-filter --in --out --report (offline, clean env), counts only; usage errors exit 2', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-hq-chat.md', hqNote({ project: 'team' }, MIXED));
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: safeMkdtemp(join(tmpdir(), 'zeusi-xf-home-')) };
    const r = spawnSync(process.execPath, [CLI, 'export-filter', '--in', e.inDir, '--out', e.outDir, '--report'], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /export-filter: status ok/);
    assert.match(r.stdout, /files: seen 1, kept 1/);
    assert.match(r.stdout, /entries: kept 5, withheld 7/);
    assert.doesNotMatch(`${r.stdout}${r.stderr}`, /W\d-marker|K\d synthetic|hq-chat|\/staging|\/zeus-hq/);
    const bad = spawnSync(process.execPath, [CLI, 'export-filter', '--in', e.inDir], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
    assert.equal(bad.status, 2);
    rmSync(env.HOME, { recursive: true, force: true });
  } finally {
    e.close();
  }
});

test('scripts/hq-soft-wall-sample.ts: deterministic, counts only (no sample text printed)', () => {
  const script = fileURLToPath(new URL('../scripts/hq-soft-wall-sample.ts', import.meta.url));
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: tmpdir() };
  const a = spawnSync(process.execPath, [script], { encoding: 'utf8', env, timeout: 20_000 });
  const b = spawnSync(process.execPath, [script], { encoding: 'utf8', env, timeout: 20_000 });
  assert.equal(a.status, 0, a.stderr);
  assert.equal(a.stdout, b.stdout);
  assert.match(a.stdout, /one note per thread per day: \d+ of 150/);
  assert.doesNotMatch(a.stdout, /Invoice|login 5|Neon compute/);
});

// ---------------------------------------------------------------------------
// Fix round 1, M1: never follow a symlink below --out (or leave --in through one).

test('M1: out/<project> symlinked to in/<project> is refused before any write: the input is never overwritten', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K clean'], ['t2', 'synthetic exclusion probe plankiva']]));
    mkdirSync(e.outDir, { recursive: true });
    symlinkSync(join(e.inDir, 'team'), join(e.outDir, 'team'));
    const before = treeHash(e.inDir);
    assert.throws(() => e.run(), (err: Error) => err instanceof ExportFilterUnsafeError && /symlink|real director/i.test(err.message) && !err.message.includes(e.dir));
    assert.equal(treeHash(e.inDir), before, 'input bytes and mtimes unchanged');
  } finally {
    e.close();
  }
});

test('M1: out/<project> symlinked to in/<project> with a whole-note drop: the input file is never deleted', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team', tags: ['plankiva-probe'] }, [['t1', 'K']]));
    mkdirSync(e.outDir, { recursive: true });
    symlinkSync(join(e.inDir, 'team'), join(e.outDir, 'team'));
    const before = treeHash(e.inDir);
    assert.throws(() => e.run(), ExportFilterUnsafeError);
    assert.equal(treeHash(e.inDir), before);
    assert.ok(statSync(join(e.inDir, 'team/2026-11-13-a.md')).isFile());
  } finally {
    e.close();
  }
});

test('M1: out/<project> symlinked anywhere else (or a non-directory) is refused; nothing is written or deleted there', () => {
  for (const kind of ['dir-link', 'file', 'other-project-link'] as const) {
    const e = fresh();
    try {
      e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K']]));
      e.write('team/2026-11-13-b.md', hqNote({ project: 'team', tags: ['plankiva-probe'] }, [['t1', 'K']]));
      const elsewhere = join(e.dir, 'elsewhere');
      mkdirSync(elsewhere);
      writeFileSync(join(elsewhere, '2026-11-13-b.md'), 'unrelated');
      mkdirSync(e.outDir, { recursive: true });
      if (kind === 'dir-link') symlinkSync(elsewhere, join(e.outDir, 'team'));
      else if (kind === 'file') writeFileSync(join(e.outDir, 'team'), 'x');
      else symlinkSync(elsewhere, join(e.outDir, 'hq')); // a project this run does not even touch
      const before = treeHash(elsewhere);
      assert.throws(() => e.run(), ExportFilterUnsafeError, kind);
      assert.equal(treeHash(elsewhere), before, kind);
      assert.deepEqual(readdirSync(elsewhere), ['2026-11-13-b.md'], kind);
    } finally {
      e.close();
    }
  }
});

test('M1: a file-level symlink below --out is refused (never read, replaced or unlinked through)', () => {
  const e = fresh();
  try {
    const body = hqNote({ project: 'team' }, [['t1', 'K']]);
    e.write('team/2026-11-13-a.md', body);
    const target = join(e.dir, 'target.md');
    writeFileSync(target, body); // same bytes: the "unchanged" shortcut must not read through it
    mkdirSync(join(e.outDir, 'team'), { recursive: true });
    symlinkSync(target, join(e.outDir, 'team/2026-11-13-a.md'));
    assert.throws(() => e.run(), ExportFilterUnsafeError);
    assert.equal(readFileSync(target, 'utf8'), body);
  } finally {
    e.close();
  }
});

test('M1 (--in): a symlinked project folder or file that leaves --in is dropped unread; --in is never written', () => {
  const e = fresh();
  try {
    const outside = join(e.dir, 'outside');
    mkdirSync(outside);
    writeFileSync(join(outside, '2026-11-13-x.md'), hqNote({ project: 'team' }, [['t', 'S-marker outside']]));
    symlinkSync(outside, join(e.inDir, 'team'));
    mkdirSync(join(e.inDir, 'hq'));
    symlinkSync(join(outside, '2026-11-13-x.md'), join(e.inDir, 'hq/2026-11-13-x.md'));
    mkdirSync(e.outDir, { recursive: true });
    symlinkSync(e.outDir, join(e.inDir, 'zeusi')); // a link from --in into --out
    const before = treeHash(e.inDir);
    const r = e.run();
    assert.equal(r.status, 'ok');
    assert.deepEqual(e.outFiles(), []);
    assert.equal(r.counts.dropped_by_reason.unsafe, 3);
    assert.equal(treeHash(e.inDir), before);
  } finally {
    e.close();
  }
});

test('M1 CLI: a symlink below --out exits 4 (distinct), no path in the output, the input untouched', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K']]));
    mkdirSync(e.outDir, { recursive: true });
    symlinkSync(join(e.inDir, 'team'), join(e.outDir, 'team'));
    const before = treeHash(e.inDir);
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: e.dir };
    const r = spawnSync(process.execPath, [CLI, 'export-filter', '--in', e.inDir, '--out', e.outDir], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
    assert.equal(r.status, 4, r.stderr);
    assert.match(r.stderr, /symlink/);
    assert.ok(!`${r.stdout}${r.stderr}`.includes(e.dir) && !/\/staging|\/zeus-hq|team/.test(`${r.stdout}${r.stderr}`));
    assert.equal(treeHash(e.inDir), before);
  } finally {
    e.close();
  }
});

// Fix round 1, m1/m2: verification-code shapes (fake digits) and harmless numbers near the keywords.
test('m1: login / plain "code:" / spaced and dashed codes and otp / one-time / verification variants are withheld', () => {
  const d6 = ['48', '29', '13'].join('');
  const yes = [
    `login code ${d6}`,
    `code: ${d6}`,
    `code ${d6}`,
    `the code is ${d6}`,
    `2FA code: 482 913`,
    `verification code 482-913`,
    `one-time code ${d6}`,
    `one-time passcode: 4829 1377`,
    `OTP ${d6}`,
    `your verify code: ${d6}.`,
    `sign-in code (expires in 10 min): ${d6}`,
    `log in with ${d6}`,
    `passcode ${d6}`,
    `MFA: ${d6}`,
    `TOTP 48291377`,
    `recovery code ${d6}`,
    `otp 2026111`, // 7 digits after a code keyword: fail closed, not a compact date
  ];
  for (const s of yes) assert.ok(credentialSignal(s), `withheld: ${s.replace(/\d/g, '#')}`);
});

test('m2: compact dates, durations, sizes and longer numbers near "security"/"auth"/"code" are not withheld; real tokens still are', () => {
  const no = [
    'security update 20261114 shipped',
    'auth flow took 1500000 ms',
    'auth p95 is 1250000 µs',
    'security scan: 2500000 bytes scanned',
    'login page served 1200000 requests',  // a count, followed by more words: still withheld? see below
    'auth migration 20261114-02 applied',
    'security release 2026-11-14',
    'the code freeze starts 20261120',
    'auth service handled 12.500000 rps',
    'code review on PR #1188 at 10:42',
    'security ticket SEC-123456789 closed',
    'otp lib v1234567890',
    'auth took 600000s',
    'login code length is 6 digits',
  ];
  const fp = no.filter((s) => credentialSignal(s));
  // One known, documented over-withhold: a bare 7-digit count right after "login ... served". Fail closed.
  assert.deepEqual(fp.map((s) => s.replace(/\d/g, '#')), ['login page served ####### requests']);
  // Token shapes are unaffected (fail closed).
  for (const s of [FAKE_GH, FAKE_AWS, FAKE_PW, FAKE_2FA, FAKE_KEY, FAKE_URL]) assert.ok(credentialSignal(s));
});

// Fix round 1, m4: distinct exit codes; never a path in error output.
test('m4: a filesystem error is ExportFilterIoError (code only, no path); CLI exit 3; usage 2; unreadable --config 2 without its path', () => {
  const e = fresh();
  try {
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K']]));
    mkdirSync(join(e.outDir, 'team'), { recursive: true });
    chmodSync(join(e.outDir, 'team'), 0o500); // read-only project folder: the write fails EACCES
    try {
      assert.throws(() => e.run(), (err: Error) => err instanceof ExportFilterIoError && /EACCES/.test(err.message) && !err.message.includes(e.dir) && !err.message.includes('/'));
      const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: e.dir };
      const r = spawnSync(process.execPath, [CLI, 'export-filter', '--in', e.inDir, '--out', e.outDir], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
      assert.equal(r.status, 3, r.stderr);
      assert.match(r.stderr, /filesystem error \(EACCES\)/);
      assert.ok(!`${r.stdout}${r.stderr}`.includes(e.dir));
      const cfg = spawnSync(process.execPath, [CLI, 'export-filter', '--in', e.inDir, '--out', e.outDir, '--config', join(e.dir, 'missing.toml')], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
      assert.equal(cfg.status, 2, cfg.stderr);
      assert.ok(!`${cfg.stdout}${cfg.stderr}`.includes(e.dir), 'no path of --config');
      const usage = spawnSync(process.execPath, [CLI, 'export-filter', '--out', e.outDir], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
      assert.equal(usage.status, 2);
    } finally {
      chmodSync(join(e.outDir, 'team'), 0o700);
    }
  } finally {
    e.close();
  }
});

// Fix round 1, m3: a configured-but-disabled ("held") project is counted and kept in staging, never dropped silently.
// Generic since ClientCo was enabled (the owner): any slug can be held, e.g. a not-yet-enabled "labs" folder.
test('m3: held projects (e.g. a not-yet-enabled "labs" folder) are counted (files, entries), never written to --out, never deleted from --in', () => {
  const e = fresh();
  try {
    e.write('labs/2026-11-12-chat-desk.md', hqNote({ project: 'labs', date: '2026-11-12' }, [['t1', 'synthetic labs note'], ['t2', 'second']]));
    e.write('labs/2026-11-13-decisions.md', hqNote({ project: 'labs', kind: 'decision' }, [['t1', 'synthetic labs decision']]));
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K']]));
    e.write('other/2026-11-13-a.md', hqNote({ project: 'other' }, [['t1', 'K']]));
    const before = treeHash(e.inDir);
    const r = e.run({ projects: ['team', 'hq'], held: ['labs'] });
    assert.equal(r.status, 'ok');
    assert.deepEqual(e.outFiles(), ['team/2026-11-13-a.md']);
    assert.deepEqual(r.counts.held, { folders: 1, files: 2, entries: 3 });
    assert.equal(r.counts.folders_dropped, 1, 'the unconfigured folder is still refused');
    assert.equal(r.counts.files_seen, 1, 'held files are not "seen" / kept / dropped');
    assert.equal(treeHash(e.inDir), before, 'held notes stay in staging for the backfill');
    const text = formatExportResult(r, false);
    assert.match(text, /held \(project disabled\): folders 1, files 2, entries 3/);
    assert.doesNotMatch(text, /labs|synthetic|2026-11-1[23]-/i);
  } finally {
    e.close();
  }
});

test('m3 config: [hq_export] held must be slugs, not also an enabled project; the example config enables clientco and holds nothing', () => {
  const root = safeMkdtemp(join(tmpdir(), 'zeusi-xf-cfg-'));
  try {
    const src = `[[source]]\nname = "hq-team"\nkind = "zeus_memory"\nscope = "work"\nroot = "${root}"\ninclude = ["team/*.md"]\nproject = "team"\n`;
    const ok = validateSources(parseToml(`${src}\n[hq_export]\nheld = ["labs"]\n`), seedWall(), { home: root });
    assert.deepEqual(ok.hqExport?.held, ['labs']);
    const empty = validateSources(parseToml(`${src}\n[hq_export]\nheld = []\n`), seedWall(), { home: root });
    assert.deepEqual(empty.hqExport?.held, []);
    assert.throws(() => validateSources(parseToml(`${src}\n[hq_export]\nheld = ["Bad Name"]\n`), seedWall(), { home: root }), /held.*slug/);
    assert.throws(() => validateSources(parseToml(`${src}\n[hq_export]\nheld = ["team"]\n`), seedWall(), { home: root }), /held.*enabled/);
    assert.throws(() => validateSources(parseToml(`${src}\n[hq_export]\nheld = ["%70lankiva-probe"]\n`), seedWall(), { home: root }), /plankiva/i);
    // The example config: clientco is an enabled source (scope clientco), so it can no longer be held.
    const exText = readFileSync(fileURLToPath(new URL('../config/sources.example.toml', import.meta.url)), 'utf8');
    const ex = validateSources(parseToml(exText), seedWall(), { home: root });
    assert.deepEqual(ex.hqExport?.held, []);
    assert.ok(ex.sources.some((x) => x.kind === 'zeus_memory' && x.project === 'clientco' && x.scope === 'client'));
    assert.throws(() => validateSources(parseToml(exText.replace(/^held = \[\]$/m, 'held = ["clientco"]')), seedWall(), { home: root }), /held project "clientco" is also an enabled/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('m3 CLI: --config passes the held list; the report counts held notes and leaves them in staging', () => {
  const e = fresh();
  try {
    e.write('labs/2026-11-13-chat-desk.md', hqNote({ project: 'labs' }, [['t1', 'synthetic labs note']]));
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K']]));
    const cfg = join(e.dir, 'sources.toml');
    writeFileSync(cfg, `[[source]]\nname = "hq-team"\nkind = "zeus_memory"\nscope = "work"\nroot = "${e.outDir}"\ninclude = ["team/*.md"]\nproject = "team"\n\n[hq_export]\nheld = ["labs"]\n`);
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: e.dir };
    const r = spawnSync(process.execPath, [CLI, 'export-filter', '--in', e.inDir, '--out', e.outDir, '--config', cfg], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /held \(project disabled\): folders 1, files 1, entries 1/);
    assert.deepEqual(e.outFiles(), ['team/2026-11-13-a.md']);
    assert.ok(statSync(join(e.inDir, 'labs/2026-11-13-chat-desk.md')).isFile());
  } finally {
    e.close();
  }
});

// ClientCo enabled (the owner): a clientco source with scope clientco; clientco notes are written to --out, not held.
test('ClientCo CLI: with the hq-clientco source configured, clientco notes are written to --out (held 0); an Plankiva-signal clientco entry is still withheld', () => {
  const e = fresh();
  try {
    e.write('clientco/2026-11-13-chat-desk.md', hqNote({ project: 'clientco' }, [
      ['t1', 'synthetic ClientCo desk note: client alpha, CHF 120'],
      ['t2', 'synthetic exclusion probe plankiva'],
      ['t3', 'synthetic ClientCo follow-up'],
    ]));
    e.write('clientco/2026-11-12-decisions.md', hqNote({ project: 'clientco', kind: 'decision', date: '2026-11-12' }, [['t1', 'synthetic ClientCo decision']]));
    e.write('team/2026-11-13-a.md', hqNote({ project: 'team' }, [['t1', 'K']]));
    const cfg = join(e.dir, 'sources.toml');
    const src = (name: string, scope: string, project: string) =>
      `[[source]]\nname = "${name}"\nkind = "zeus_memory"\nscope = "${scope}"\nroot = "${e.outDir}"\ninclude = ["${project}/*.md"]\nproject = "${project}"\n\n`;
    writeFileSync(cfg, `${src('hq-team', 'work', 'team')}${src('hq-clientco', 'client', 'clientco')}[hq_export]\nheld = []\n`);
    const before = treeHash(e.inDir);
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: e.dir };
    const r = spawnSync(process.execPath, [CLI, 'export-filter', '--in', e.inDir, '--out', e.outDir, '--config', cfg, '--report'], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /held \(project disabled\): folders 0, files 0, entries 0/);
    assert.deepEqual(e.outFiles(), ['clientco/2026-11-12-decisions.md', 'clientco/2026-11-13-chat-desk.md', 'team/2026-11-13-a.md']);
    const desk = e.out('clientco/2026-11-13-chat-desk.md');
    assert.match(desk, /client alpha, CHF 120/, 'ClientCo content and currency are not filtered at the source');
    assert.match(desk, /synthetic ClientCo follow-up/);
    assert.doesNotMatch(desk, /plankiva/i);
    assert.ok(desk.includes(WITHHELD_MARKER));
    assert.match(r.stdout, /entries: kept \d+, withheld 1/);
    assert.match(r.stdout, /project clientco: files 2, entries kept \d+, withheld 1/);
    // With 0010 + 0011 the seed wall admits the ClientCo and currency text: nothing would quarantine.
    assert.match(r.stdout, /ingest preview \(seed wall, no allows\): would pass 3, would quarantine 0/);
    assert.doesNotMatch(r.stdout, /clientco\/|synthetic|2026-11-1[23]-/i);
    assert.equal(treeHash(e.inDir), before, '--in is never written');
  } finally {
    e.close();
  }
});

// Merge of main (#3): the Plankiva-class wall inherits the 0010 spelling regex and the 0011 "Plankiva" variants regex.
test('plankivaWall inherits the hard Plankiva regex rules of 0010 and 0011; spelled / one-n tags and titles are caught by the wall itself', () => {
  const aw = plankivaWall();
  for (const p of [PROTECTED_SPELLING_REGEX, PROTECTED_VARIANTS_REGEX]) {
    const r = aw.rules.find((x) => x.pattern === p);
    assert.ok(r && r.hard && r.kind === 'regex');
  }
  for (const probe of ['P.l.a.n.k.i.v.a', 'pl4nk1va', 'Plankiva', 'P-lankiva']) {
    const row = { vault_path: 'hq:team/2026-11-13-x.md', title: `synthetic ${probe}`, body: 'synthetic', frontmatter: { tags: [probe] }, scope: 'work', source_kind: 'zeus_memory', source_uri: 'hq:team/2026-11-13-x.md' };
    assert.ok(aw.check('notes', row).blocked, `blocked: ${probe.length} chars`);
  }
});
