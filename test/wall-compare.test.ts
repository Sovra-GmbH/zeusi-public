// scripts/wall-compare.ts (wall-dryrun --compare-old): the importer's own pipeline, offline,
// 0009 (run 10) / 0010 (head) / 0011 walls, on the synthetic fixture vault. Counts only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { plankivaFalsePositives, compareCounts, formatCompare, formatFalsePositives, independentPlankivaSignal } from '../scripts/wall-compare.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const FIXTURE = fileURLToPath(new URL('./fixtures/vault/', import.meta.url));
const CONFIG = fileURLToPath(new URL('../config/sources.example.toml', import.meta.url));
const sum = (m: Record<string, number>) => Object.values(m).reduce((a, b) => a + b, 0);
const byLabel = (m: Record<string, number>, re: RegExp) => sum(Object.fromEntries(Object.entries(m).filter(([k]) => re.test(k))));

test('compare-old: 0010 -> 0011 admits the ClientCo currency note, blocks the Plankiva note, keeps the account rule; proof is 0; output is counts only', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cmp-'));
  try {
    const vault = join(dir, 'vault');
    cpSync(FIXTURE, vault, { recursive: true });
    mkdirSync(join(vault, 'ClientCo/clientco-erp'), { recursive: true });
    writeFileSync(join(vault, 'ClientCo/clientco-erp/budget.md'), '# Budget\n\nsynthetic ClientCo line USD 1200 noted; P&L 2025: +3.\n');
    writeFileSync(join(vault, 'ClientCo/clientco-erp/probe.md'), '# Sync\n\nsynthetic exclusion probe: P.l.a.n.k.i.v.a.\n');
    writeFileSync(join(vault, 'ClientCo/clientco-erp/acct.md'), '# Acct\n\nsynthetic acct 1234567 line.\n');
    writeFileSync(join(vault, 'Work/research/probe-1n.md'), '# Sync\n\nsynthetic exclusion probe: Plaankiva joined.\n');
    const r = await compareCounts({ vault, configPath: CONFIG, home: dir });
    assert.equal(r.runs.cfgHead.byScope['client'], 1, 'head: only the clean ClientCo note');
    assert.equal(r.runs.cfgNew.byScope['client'], 2, '0011: the currency / P&L ClientCo note joins it');
    assert.equal(byLabel(r.newlyAdmittedByHeadRule.cfg, /USD\|EUR/), 1, 'newly admitted, blocked before by the currency rule');
    assert.equal(sum(r.newlyBlockedByNewRule.cfg), 1);
    assert.equal(byLabel(r.newlyBlockedByNewRule.cfg, /Plankiva variants regex \(0011\)/), 1, 'the Plankiva note is newly blocked');
    assert.equal(byLabel(r.run10To0011.admittedNowBlocked, /Plankiva variants regex/), 1, 'run 10 admitted it; 0011 blocks it');
    assert.equal(byLabel(r.runs.cfgNew.quarantinedByRule, /login\|account/), 3, 'budget, pricing, acct: account / login number stays soft');
    const acct = r.keptRules.find((k) => /login\|account/.test(k.rule))!;
    assert.equal(acct.clientcoBlocks, 1);
    assert.equal(acct.clientcoOnlyBlocker, 1);
    assert.ok(r.keptRules.some((k) => /\*\*pnl\*\*/.test(k.rule)));
    assert.equal(r.plankivaProof.admittedNotesWithSignal, 0);
    assert.equal(r.plankivaProof.admittedChunksWithSignal, 0);
    assert.equal(r.plankivaProof.admittedNotesWithGateSignal, 0);
    assert.equal(r.plankivaProof.admittedChunksWithGateSignal, 0);
    assert.equal(r.plankivaProof.rawFilesWithSignalAdmitted, 0);
    assert.ok(r.plankivaProof.rawFilesWithSignal >= 5);
    const out = formatCompare(r);
    assert.match(out, /RESULT: PASS/);
    // Rule labels print wall patterns (config, e.g. "Work/intake/**"); note paths, names and text never appear.
    assert.doesNotMatch(out, /clientco-erp|client-alpha|plankiva-probe|budget|probe|20-notes|glossary|Home\.md|synthetic|USD 1200|plankiva joined|\/tmp|\/var\/|zeusi-cmp/i, 'no paths or text');

    // False-positive scan: rule-only files and the matched word only.
    const fp = plankivaFalsePositives(vault);
    assert.equal(fp.ruleOnly, 1);
    assert.deepEqual(fp.tokens, { plaankiva: 1 });
    assert.doesNotMatch(formatFalsePositives('<vault>', fp), /joined|probe|synthetic/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('independent proof scanner: flags every Plankiva form (also ones the wall rule does not cover), passes clean text', () => {
  for (const s of ['Plankiva', 'plankiva', 'P.l.a.n.k.i.v.a', 'P l a n k i v a', 'pl4nk1v@', 'PlАnkiva', 'Plan​kiva', '%50lankiva', '%2550lankiva', 'P--------lankiva', 'xPLANKKIVAx', 'P. L. A. N. K. I. V. A.']) {
    assert.ok(independentPlankivaSignal(s), s);
  }
  for (const s of ['plan', 'kiva', 'plankton', 'planking', 'ankiva', 'plan kiva boat', 'clean synthetic text']) {
    assert.ok(!independentPlankivaSignal(s), s);
  }
});
