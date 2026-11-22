// U6e: offline cost estimate (no DB, no network) over the synthetic fixture vault.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall, SEED_RULES } from '../src/wall.ts';
import { importVault } from '../src/importers/vault.ts';
import { chunkMarkdown, embedText, estimateTokens } from '../src/chunking.ts';
import { estimateReport, formatEstimate, clientcoAdmittedWall, clientcoRuleIds, withClientcoSource, DEFAULT_NOTES_PER_DAY } from '../src/estimate.ts';
import { HARD_MONTHLY_CAP_USD } from '../src/embed.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const FIXTURE = fileURLToPath(new URL('./fixtures/vault/', import.meta.url));

function env() {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-est-'));
  const vault = join(home, 'vault');
  cpSync(FIXTURE, vault, { recursive: true });
  const config = validateSources(parseToml(`
[[source]]
name = "vault-work"
kind = "vault_note"
scope = "work"
root = "${vault}"
include = ["Work/**/*.md", "Home.md", "wiki/*.md"]
`), seedWall(), { home });
  return { home, vault, config };
}

test('ClientCo-named hard rules: none left in the seed wall since 0010 (#3), so nothing is lifted; Plankiva stays', () => {
  assert.deepEqual(clientcoRuleIds(), [], '0010 already lifted the six ClientCo-named hard rules');
  const w = clientcoAdmittedWall();
  assert.equal(w.rules.length, SEED_RULES.length);
  assert.ok(w.rules.some((r) => r.pattern === 'plankiva/**'), 'Plankiva rules stay');
  assert.ok(w.rules.some((r) => r.kind === 'term' && r.pattern === 'plankiva'));
  assert.ok(w.rules.some((r) => r.pattern === 'example-org/agent-config-backup*'), 'agent-config-backup stays');
});

test('observer and dry-run wall are refused in real mode', async () => {
  const { config, home } = env();
  await assert.rejects(importVault({ config, mode: 'full', home, dryRunObserver: () => {} }), /dry run only|db is required/);
});

test('the observer sees numbers only, and the token estimate matches the chunker on the embedded string', async () => {
  const { config, home } = env();
  const seen: unknown[] = [];
  const r = await importVault({ config, mode: 'full', home, dryRun: true, dryRunObserver: (o) => seen.push(o) });
  assert.equal(r.status, 'ok');
  assert.equal(seen.length, r.counts.inserted);
  for (const o of seen) {
    const json = JSON.stringify(o);
    assert.ok(/^[\d{}[\]":,a-zA-Z_]*$/.test(json), 'numbers and key names only');
    assert.ok(!/the team|\.md|synthetic/.test(json));
  }
  const total = (seen as Array<{ chunks: Array<{ estTokens: number }> }>).reduce((s, o) => s + o.chunks.length, 0);
  assert.equal(total, r.counts.chunks_written);
  // plain.md: one chunk per section; compare with a direct computation
  const body = 'A note with no frontmatter.';
  assert.equal(estimateTokens(embedText('plain', null, body)), Math.ceil([...embedText('plain', null, body)].length / 4));
  assert.ok(chunkMarkdown('# H\n\nx').length === 1);
});

test('estimate: (a) current wall, (b) ClientCo-admitted upper bound, total with safety factor 2, vs the $5 cap; counts only', async () => {
  const { config, home } = env();
  const rep = await estimateReport({ config, home });
  assert.ok(rep.base.notes > 0 && rep.base.chunks > 0 && rep.base.estTokens > 0);
  assert.ok(rep.clientcoExtra.notes >= 1, 'fixture ClientCo/client-alpha.md is admitted by the clientco-admitted profile');
  assert.ok(rep.clientcoExtra.chunks >= 1);
  assert.equal(rep.total.estTokens, rep.base.estTokens + rep.clientcoExtra.estTokens);
  assert.ok(Math.abs(rep.totalWithSafety.usd - 2 * rep.total.usd) < 1e-12);
  assert.equal(rep.capUsd, HARD_MONTHLY_CAP_USD);
  assert.equal(rep.steady.notesPerDay, DEFAULT_NOTES_PER_DAY);
  assert.ok(rep.steady.monthlyUsd > 0);
  const out = formatEstimate(rep);
  assert.match(out, /upper bound/);
  assert.match(out, /safety factor 2/);
  assert.match(out, /\$5\.00/);
  assert.ok(!/client-alpha|the team\/|\.md|synthetic/.test(out), 'no paths or text in the output');
});

test('withClientcoSource adds ClientCo/**/*.md on the same root', () => {
  const { config } = env();
  const c2 = withClientcoSource(config);
  assert.equal(c2.sources.length, config.sources.length + 1);
  assert.deepEqual(c2.sources.at(-1)!.include, ['ClientCo/**/*.md']);
  assert.equal(c2.sources.at(-1)!.root, config.sources[0]!.root);
});
