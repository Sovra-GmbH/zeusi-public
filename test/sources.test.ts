// U1: importer source config (config/sources.example.toml) and hard-denied path validation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseToml, validateSources, loadSources, sourcePathGate, SOURCES_EXAMPLE } from '../src/sources.ts';
import { ConfigError } from '../src/config.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const EXAMPLE = fileURLToPath(new URL('../config/sources.example.toml', import.meta.url));

const src = (include: string[], root = '~/KnowledgeVault', extra = '') => `
[[source]]
name = "probe"
kind = "vault_note"
scope = "work"
root = "${root}"
include = [${include.map((i) => JSON.stringify(i)).join(', ')}]
${extra}
`;

function problems(text: string): string[] {
  try {
    validateSources(parseToml(text));
    return [];
  } catch (e) {
    assert.ok(e instanceof ConfigError, String(e));
    return (e as ConfigError).message.split('\n');
  }
}

test('the example config loads and validates', () => {
  const s = loadSources(EXAMPLE);
  assert.equal(SOURCES_EXAMPLE, 'config/sources.example.toml');
  assert.ok(s.sources.length >= 9);
  assert.deepEqual(s.github.repos.length, 4);
  for (const k of ['vault_note', 'lane_md', 'review_ledger', 'runner_log', 'assistant_memory']) {
    assert.ok(s.sources.some((x) => x.kind === k), `has a ${k} source`);
  }
});

test('the example config never names Plankiva (no PlankivaVault path, no requests/ exception)', () => {
  const raw = readFileSync(EXAMPLE, 'utf8');
  assert.doesNotMatch(raw, /plankiva/i);
});

test('a config pointing at a hard-denied path fails validation at load time (plankiva/, pnl); ClientCo/ is allowed since 0010', () => {
  assert.deepEqual(problems(src(['ClientCo/**/*.md'])), []);
  assert.ok(problems(src(['ClientCo/plankiva/**/*.md'])).some((p) => /plankiva/i.test(p)));
  assert.ok(problems(src(['plankiva/**'])).some((p) => /plankiva/i.test(p)));
  assert.ok(problems(src(['*/LANE.md', 'desk-pnl/LANE.md'], '~/agent-runner/lanes')).some((p) => /pnl/.test(p)));
  assert.ok(problems(src(['Work/intake/*.md'])).length > 0);
  assert.ok(problems(src(['**/*.md'], '~/KnowledgeVault-staging')).length > 0);
});

test('any path containing plankiva fails, case-insensitive, including PlankivaVault/requests/', () => {
  for (const [inc, root] of [
    [['requests/**/*.md'], '~/PlankivaVault'],
    [['**/*.md'], '~/PlankivaVault/requests'],
    [['**'], '/Users/owner/plankivavault/requests/'],
    [['Work/PLANKIVA-sync.md'], '~/KnowledgeVault'],
    [['memory/plankiva.sqlite.migrated'], '~/.assistant'],
  ] as const) {
    const p = problems(src([...inc], root));
    assert.ok(p.some((x) => /plankiva/i.test(x)), `${root} ${inc.join(',')} → ${p.join(' | ')}`);
  }
  // excludes and names count too: the config may not mention plankiva at all.
  assert.ok(problems(src(['Work/**/*.md'], '~/KnowledgeVault', 'exclude = ["plankiva/**"]')).length > 0);
  assert.ok(problems(src(['Work/**/*.md']).replace('"probe"', '"plankiva-probe"')).length > 0);
});

test('denied GitHub repos fail validation', () => {
  const gh = (repos: string[]) => `[github]\norg = "example-org"\nrepos = [${repos.map((r) => JSON.stringify(r)).join(', ')}]\nnorthbank_repos = []\n`;
  assert.deepEqual(problems(gh(['clientco-hedging-engine'])), []); // 0010: ClientCo repos are admitted
  assert.ok(problems(gh(['clientco-plankiva-tools'])).length > 0);
  assert.ok(problems(gh(['agent-config-backup-clientco-walled'])).length > 0);
  assert.ok(problems(gh(['plankiva-site'])).length > 0);
  assert.deepEqual(problems(gh(['ops-console'])), []);
});

test('unknown kind or personal scope is refused', () => {
  assert.ok(problems(src(['Work/x.md']).replace('vault_note', 'bogus')).some((p) => /kind/.test(p)));
  assert.ok(problems(src(['Work/x.md']).replace('"work"', '"personal"')).some((p) => /personal/.test(p)));
});

test('the TOML subset parser handles comments, arrays over lines, booleans, and rejects unsupported syntax', () => {
  const t = parseToml(`# top\n[a]\nx = "s # not a comment" # c\ny = [\n  "p",\n  "q", # c\n]\nz = true\nn = 3\n[[b]]\nk = 'lit'\n[[b]]\nk = "two"\n`);
  assert.deepEqual(t, { a: { x: 's # not a comment', y: ['p', 'q'], z: true, n: 3 }, b: [{ k: 'lit' }, { k: 'two' }] });
  assert.throws(() => parseToml('a = { inline = 1 }'), /unsupported/);
  assert.throws(() => parseToml('[a]\nx = 1\nx = 2'), /duplicate/);
});

// ---------------------------------------------------------------------------
// r1 MINOR-2: symlinks and percent-encoding. Fake dirs in a temp dir only.

function fakeTree() {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-src-'));
  const req = join(home, 'PlankivaVault', 'requests');
  mkdirSync(req, { recursive: true });
  writeFileSync(join(req, 'form-1.md'), 'synthetic\n');
  const team = join(home, 'KnowledgeVault', 'Work');
  mkdirSync(team, { recursive: true });
  writeFileSync(join(team, 'clean.md'), 'synthetic\n');
  symlinkSync(join(req, 'form-1.md'), join(team, 'innocent.md'));        // file symlink into the fake vault
  symlinkSync(join(home, 'PlankivaVault'), join(home, 'KnowledgeVault', 'linked'));  // dir symlink
  symlinkSync(req, join(home, 'Knowledge-shared'));                            // root symlink
  return { home, team };
}

test('importer path gate checks the logical AND the real path (symlink into a fake PlankivaVault/requests)', () => {
  const { home, team } = fakeTree();
  assert.deepEqual(sourcePathGate(join(team, 'clean.md'), { home }), { ok: true });
  const f = sourcePathGate(join(team, 'innocent.md'), { home });
  assert.equal(f.ok, false);
  assert.match(f.ok ? '' : f.reason, /real path/);
  const d = sourcePathGate(join(home, 'KnowledgeVault', 'linked', 'requests', 'form-1.md'), { home });
  assert.equal(d.ok, false);
  // ~ is expanded against home before resolving.
  assert.equal(sourcePathGate('~/KnowledgeVault/Work/innocent.md', { home }).ok, false);
  assert.equal(sourcePathGate('~/KnowledgeVault/Work/clean.md', { home }).ok, true);
  // A path that does not exist is judged on its logical path only (and still refused if it names Plankiva).
  assert.equal(sourcePathGate('~/KnowledgeVault/Work/not-there.md', { home }).ok, true);
  assert.equal(sourcePathGate('~/PlankivaVault/requests/not-there.md', { home }).ok, false);
});

test('sources validation resolves existing roots and literal include paths (symlinked root / file into PlankivaVault)', () => {
  const { home } = fakeTree();
  const probs = (text: string) => {
    try {
      validateSources(parseToml(text), undefined, { home });
      return [];
    } catch (e) {
      return (e as ConfigError).message.split('\n');
    }
  };
  assert.deepEqual(probs(src(['Work/clean.md'], '~/KnowledgeVault')), []);
  assert.ok(probs(src(['**/*.md'], '~/Knowledge-shared')).some((p) => /real path/.test(p)), 'symlinked root');
  assert.ok(probs(src(['Work/innocent.md'], '~/KnowledgeVault')).some((p) => /real path/.test(p)), 'symlinked literal include');
  assert.ok(probs(src(['linked/**/*.md'], '~/KnowledgeVault')).some((p) => /real path/.test(p)), 'glob under a symlinked dir: its literal prefix is resolved');
});

test('percent-encoded Plankiva paths fail validation and the gate (%50lankivaVault, double-encoded)', () => {
  for (const [inc, root] of [
    [['requests/**/*.md'], '~/%50lankivaVault'],
    [['Work/%70lankiva.md'], '~/KnowledgeVault'],
    [['**'], '~/%2550lankivaVault/requests'],
    [['%43lientCo/%50lankiva/**'], '~/KnowledgeVault'], // 0010: plankiva under an encoded ClientCo folder
  ] as const) {
    assert.ok(problems(src([...inc], root)).length > 0, `${root} ${inc.join(',')}`);
  }
  assert.deepEqual(problems(src(['%43lientCo/**'], '~/KnowledgeVault')), [], '0010: an encoded ClientCo folder is allowed');
  assert.equal(sourcePathGate('/tmp/x/%50lankivaVault/requests/a.md').ok, false);
  assert.equal(sourcePathGate('/tmp/x/PlАnkivaVault/a.md').ok, false, 'Cyrillic look-alike in a path');
});
