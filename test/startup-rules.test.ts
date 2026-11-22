// Session-start gaps U2 / U3 (docs/plans/2026-11-18-session-start-gaps-plan.md): every current
// standing rule is either served in compact form or listed in the remainder, never neither.
// Pure tests over src/startup-rules.ts. Synthetic fixtures only (invent=NO). No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  COMPACT_TEXT_MAX_CHARS, compactRule, compareRules, estimateTokens, factRuleId, lockRuleId, oneLine, planStartupRules, REMAINDER_MAX, rulesNote,
  SCOPE_ORDER, STARTUP_RULES_BUDGET_TOKENS, type StartupRule,
} from '../src/startup-rules.ts';
import { READ_ROLES } from '../src/mcp-server.ts';

/** Deterministic PRNG (mulberry32) so the property test is reproducible. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SCOPES = ['work', 'product', 'client', 'zz_other', 'aa_other'];

function lock(i: number, o: Partial<StartupRule> = {}): StartupRule {
  const uri = o.source_uri ?? `vault:Work/ops/synthetic-${Math.floor(i / 3)}.md`;
  return {
    origin: 'note_lock', id: lockRuleId(uri, (i % 3) + 1), subject: `Synthetic note ${Math.floor(i / 3)}`, text: `SYNTHETIC standing rule ${i}: never deploy the wombat on Fridays`,
    scope: 'work', source_uri: uri, source_ts: `2026-11-${String(1 + (i % 28)).padStart(2, '0')}T00:00:00.000Z`, ...o,
  };
}

function randomRules(r: () => number, n: number): StartupRule[] {
  return Array.from({ length: n }, (_, i) => {
    const longText = r() < 0.05;
    const fact = r() < 0.1;
    const uri = `vault:Work/x/n${i}.md`;
    return lock(i, {
      origin: fact ? 'fact' : 'note_lock', id: fact ? factRuleId(uri, i) : lockRuleId(uri, 1), source_uri: uri,
      scope: SCOPES[Math.floor(r() * SCOPES.length)]!, source_ts: new Date(Date.UTC(2026, 8, 1) + Math.floor(r() * 80) * 86_400_000).toISOString(),
      text: longText ? `SYNTHETIC long ${i} ${'x'.repeat(COMPACT_TEXT_MAX_CHARS)}` : `SYNTHETIC rule ${i}\n  continued  on a second   line`,
    });
  });
}

test('startup rules invariant: every current standing rule is served or in the remainder, exactly once (seeded property test, 400 cases)', () => {
  const r = rng(20261118);
  for (let c = 0; c < 400; c++) {
    const n = Math.floor(r() * 220);
    const rules = randomRules(r, n);
    const budget = Math.floor(r() * 20_000);
    const p = planStartupRules(rules, budget);
    const served = p.served.map((x) => x.id);
    const listed = p.remainder.map((x) => x.id);
    assert.equal(p.unlisted, 0);
    assert.equal(new Set([...served, ...listed]).size, served.length + listed.length, 'no id in both lists');
    assert.deepEqual([...served, ...listed].sort(), rules.map((x) => x.id).sort(), `case ${c}: a rule is missing from both lists`);
    assert.ok(p.budget_used <= budget, 'served within the budget');
    assert.equal(p.budget_used, p.served.reduce((a, x) => a + estimateTokens(x), 0));
    // served = the top of the ranking (too_long items skipped over), every remainder 'budget' item ranks after every served one
    const ranked = [...rules].sort(compareRules).filter((x) => oneLine(x.text).length <= COMPACT_TEXT_MAX_CHARS).map((x) => x.id);
    assert.deepEqual(served, ranked.slice(0, served.length));
    for (const x of p.remainder) assert.ok(x.reason === 'budget' || x.reason === 'too_long');
  }
});

test('startup rules: a rule absent from both lists is detected (mutant: dropping the remainder fails the invariant)', () => {
  const rules = Array.from({ length: 93 }, (_, i) => lock(i));
  const p = planStartupRules(rules, 4_000);
  assert.ok(p.remainder.length > 0);
  const mutant = { ...p, remainder: p.remainder.slice(1) };
  const have = new Set([...mutant.served.map((x) => x.id), ...mutant.remainder.map((x) => x.id)]);
  assert.ok(rules.some((x) => !have.has(x.id)), 'the mutant loses a rule, and the invariant check sees it');
});

test('startup rules AE1: 93 rules over a small budget -> a ranked prefix served, the rest listed with id, subject, scope, cite and reason "budget"', () => {
  const rules = Array.from({ length: 93 }, (_, i) => lock(i));
  const one = estimateTokens(compactRule(rules[0]!));
  const p = planStartupRules(rules, one * 70 + 5);
  assert.ok(p.served.length >= 60 && p.served.length < 93, `served ${p.served.length}`);
  assert.equal(p.served.length + p.remainder.length, 93);
  const e = p.remainder[0]!;
  assert.deepEqual(Object.keys(e).sort(), ['cite', 'id', 'origin', 'reason', 'scope', 'source_ts', 'source_uri', 'subject']);
  assert.equal(e.reason, 'budget');
  assert.match(e.cite, /^vault:Work\/ops\/synthetic-\d+\.md @ 2026-11-\d\dT00:00:00\.000Z$/);
  assert.match(e.id, /#lock-[123]$/);
  assert.match(String(e.subject), /^Synthetic note \d+$/);
  const note = rulesNote(p, 93, false, one * 70 + 5);
  assert.match(note, new RegExp(`^Served ${p.served.length} of 93 current standing rules`));
  assert.match(note, new RegExp(`${p.remainder.length} are listed in rules_remainder with id, subject and cite`));
  assert.match(note, /NOT dropped/);
  assert.match(note, /zeusi_context_for_task/);
});

test('startup rules: the default budget serves 93 typical rules in full (today\'s live count), with nothing in the remainder', () => {
  const rules = Array.from({ length: 93 }, (_, i) => lock(i, { source_uri: `vault:Work/ops/2026-10-${String(1 + (i % 28)).padStart(2, '0')}-synthetic-ops-rule-note-${i}.md`, text: `SYNTHETIC ${i}: ${'a typical lock is about ninety characters of owner text, give or take '.slice(0, 85)}` }));
  const p = planStartupRules(rules);
  assert.equal(p.served.length, 93);
  assert.equal(p.remainder.length, 0);
  assert.ok(p.budget_used <= STARTUP_RULES_BUDGET_TOKENS);
  assert.match(rulesNote(p, 93, false), /^All 93 current standing rules are served in compact form/);
});

test('startup rules: compact form = one line, never cut; a too-long text is listed (too_long) and later rules are still served', () => {
  const long = lock(0, { text: `SYNTHETIC long ${'y'.repeat(COMPACT_TEXT_MAX_CHARS + 50)}`, source_ts: '2026-11-30T00:00:00.000Z' });
  const multi = lock(1, { text: 'SYNTHETIC first line\n    continued line\tand a tab' });
  const p = planStartupRules([long, multi]);
  assert.deepEqual(p.remainder.map((x) => [x.id, x.reason]), [[long.id, 'too_long']]);
  assert.equal(p.served.length, 1);
  assert.equal(p.served[0]!.text, 'SYNTHETIC first line continued line and a tab', 'whitespace collapsed, every word kept');
  assert.deepEqual(Object.keys(p.served[0]!).sort(), ['cite', 'id', 'origin', 'scope', 'source_ts', 'source_uri', 'text']);
  for (const s of p.served) assert.ok(!s.text.includes('\n'));
  // expires_at / supersedes only when set
  const x = compactRule(lock(2, { expires_at: '2026-12-01T00:00:00.000Z', supersedes: ['vault:a.md#lock-1'] }));
  assert.equal(x.expires_at, '2026-12-01T00:00:00.000Z');
  assert.deepEqual(x.supersedes, ['vault:a.md#lock-1']);
});

test('startup rules ranking: fact rules first, then scope (team, product, clientco, others A-Z), then newest first; ties keep input order', () => {
  assert.deepEqual([...SCOPE_ORDER], ['work', 'product', 'client']);
  const mk = (id: string, scope: string, ts: string, origin: 'fact' | 'note_lock' = 'note_lock') => lock(0, { id, scope, source_ts: ts, origin });
  const input = [
    mk('clientco-new', 'client', '2026-11-17T00:00:00Z'),
    mk('other-z', 'zz_other', '2026-11-17T00:00:00Z'),
    mk('other-a', 'aa_other', '2026-11-01T00:00:00Z'),
    mk('tape-old', 'product', '2026-10-01T00:00:00Z'),
    mk('team-old', 'work', '2026-09-01T00:00:00Z'),
    mk('tape-new', 'product', '2026-11-10T00:00:00Z'),
    mk('team-new-1', 'work', '2026-11-10T00:00:00Z'),
    mk('team-new-2', 'work', '2026-11-10T00:00:00Z'),
    mk('fact-clientco', 'client', '2026-01-01T00:00:00Z', 'fact'),
  ];
  assert.deepEqual(planStartupRules(input).served.map((x) => x.id),
    ['fact-clientco', 'team-new-1', 'team-new-2', 'team-old', 'tape-new', 'tape-old', 'clientco-new', 'other-a', 'other-z']);
});

test('startup rules: more than REMAINDER_MAX left over -> the extra are counted in unlisted and said in the note (never silent)', () => {
  const rules = Array.from({ length: 30 }, (_, i) => lock(i));
  const p = planStartupRules(rules, 0, 10);
  assert.equal(p.served.length, 0);
  assert.equal(p.remainder.length, 10);
  assert.equal(p.unlisted, 20);
  assert.equal(p.served.length + p.remainder.length + p.unlisted, 30);
  assert.match(rulesNote(p, 30, false, 0), /20 more are counted but not listed/);
  assert.equal(REMAINDER_MAX, 2000);
});

test('read-only role unchanged (reviewer check c): READ_ROLES is exactly the two read-only logins', () => {
  assert.deepEqual([...READ_ROLES], ['zeusi_box_ro', 'zeusi_cloud_ro']);
});
