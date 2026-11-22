// Live finding 2026-11-18 (Fly v20, test workspace, synthetic notes): after zeusi_import_preview ->
// zeusi_import_commit stored 3 notes, zeusi_onboarding_status said empty=false but zeusi_startup still
// said `empty: true` with the welcome (src/mcp-server.ts ignored notes / chunks). And a decision-log
// entry without the headed form became a note with no word on why. Hosted end to end (PGlite, real
// provisioning, the writer login, the real /mcp handler).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { Db } from '../src/db.ts';
import {
  aboutMarkdown, DECISION_EXAMPLE_JSONL, DECISION_EXAMPLE_MARKDOWN, DECISION_FORMAT, personalAboutSections, RULE_EXAMPLE_NOTE, RULE_EXAMPLE_PATH, WELCOME_MARKDOWN,
} from '../src/about.ts';
import { parseEntry, parseStructuredBody } from '../src/importers/structured.ts';
import { withheld } from '../src/mcp-wall.ts';
import { callTool, mcpPost, mintStatic, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';
import { hasNonRoleOperatorAddress } from './helpers/owner-terms.ts';

let db: Db;
let h: TenantHarness;
let teamRead: string;

before(async () => {
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  const read = await mintStatic('read');
  teamRead = read.token;
  h = await startTenantHosted({
    db, home: serviceHome(), limits: { signupPerIp: 50, signupGlobal: 50 }, writer: 'on', tokensRows: [read.row],
    wsLimits: { preview: 50, commit: 50, sync: 50 }, hostedLimits: { perToken: 100_000, global: 100_000 },
  });
});
after(async () => {
  await h.close();
  await db.close();
});

const call = async (token: string, name: string, args: Record<string, unknown> = {}) => {
  const r = toolJson(await mcpPost(h.port, token, callTool(name, args)));
  assert.equal(r.isError, false, `${name}: ${r.text}`);
  return r.json!;
};
const md = (text: string, title?: string) => ({ kind: 'markdown', text, ...(title ? { title } : {}) });
const decisionLog = (text: string, format: 'markdown' | 'jsonl' = 'markdown') => ({ kind: 'decision-log', text, format });
async function importDocs(token: string, documents: unknown[]): Promise<{ preview: Record<string, unknown>; commit: Record<string, unknown> }> {
  const preview = await call(token, 'zeusi_import_preview', { documents });
  assert.equal(preview['status'], 'preview', JSON.stringify(preview));
  const commit = await call(token, 'zeusi_import_commit', { preview_id: preview['preview_id'], confirm: true });
  return { preview, commit };
}

/** The live decision-log entry, verbatim. */
const LIVE_ENTRY = '## 2026-11-18 Readback synthetic decision\n\nDecision: use preview first, then one explicit yes, for every import.\nWhy: SYNTHETIC TEST ENTRY\n';

test('personal, 0 items: empty + welcome, unchanged; startup and onboarding_status agree', async () => {
  const u = await signIn(h, 'gh-n20');
  const st = await call(u.access, 'zeusi_startup');
  assert.equal(st['empty'], true);
  assert.equal(st['workspace'], 'personal');
  assert.match(String(st['message']), /^Your workspace is empty/);
  assert.ok(String(st['welcome']).startsWith("# Hello, I'm Zeusi."));
  assert.equal(st['notes'], undefined);
  assert.equal((await call(u.access, 'zeusi_onboarding_status'))['empty'], true);
});

test('personal, notes only (the live case): empty false, N notes, the no-rules message, no welcome; onboarding agrees', async () => {
  const u = await signIn(h, 'gh-n21');
  await importDocs(u.access, [
    md('SYNTHETIC note one about the release train.\n', 'One'), md('SYNTHETIC note two about reviews.\n', 'Two'), md('SYNTHETIC note three about hiring.\n', 'Three'),
  ]);
  const st = await call(u.access, 'zeusi_startup');
  assert.equal(st['empty'], false);
  assert.equal(st['workspace'], 'personal');
  assert.equal(st['notes'], 3);
  assert.equal(st['notes_capped'], undefined);
  assert.equal(st['welcome'], undefined, 'no empty welcome');
  const msg = String(st['message']);
  assert.match(msg, /^I have 3 notes from your imports; no rules or decisions yet/);
  assert.doesNotMatch(msg, /empty/i);
  for (const must of ['locks:', 'standing_locks:', 'zeusi://about#decision-format', 'zeusi_search']) assert.ok(msg.includes(must), must);
  assert.match(String(st['next']), /^Adding more is optional\./, 'a write grant is offered "add more", never "empty"');
  assert.deepEqual((st['rules_total'] as { total: number }).total, 0);
  const ob = await call(u.access, 'zeusi_onboarding_status');
  assert.equal(ob['empty'], false, 'startup and onboarding_status agree');
  assert.equal((ob['counts'] as { notes: number }).notes, st['notes']);
});

test('personal, rules present (the documented rule example, nightly sync): normal output, no empty, no notes-only message', async () => {
  const u = await signIn(h, 'gh-n22');
  const sync = await call(u.access, 'zeusi_sync_batch', { items: [{ path: RULE_EXAMPLE_PATH, text: RULE_EXAMPLE_NOTE }] });
  assert.equal((sync['counts'] as { inserted: number }).inserted, 1, JSON.stringify(sync));
  const st = await call(u.access, 'zeusi_startup');
  assert.equal((st['rules_total'] as { total: number }).total, 1, 'the documented example is a standing rule');
  assert.equal((st['rules'] as Array<{ text: string }>)[0]!.text, 'Never deploy on a Friday.');
  for (const k of ['empty', 'workspace', 'notes', 'message', 'welcome', 'next']) assert.equal(st[k], undefined, k);
  assert.equal((await call(u.access, 'zeusi_onboarding_status'))['empty'], false);
});

test('personal, the same note through the import: its lock AND its standing marker arrive (standing rule served); not "empty"', async () => {
  const u = await signIn(h, 'gh-n25');
  const { preview } = await importDocs(u.access, [md(RULE_EXAMPLE_NOTE, 'Release rules')]);
  assert.equal((preview['counts'] as { note_lock_rules: number }).note_lock_rules, 1, 'the lock item is carried');
  const st = await call(u.access, 'zeusi_startup');
  assert.equal((st['rules_total'] as { total: number }).total, 1, 'standing_locks is carried by the workspace import (carriedStandingLocks)');
  assert.equal((st['rules'] as Array<{ text: string }>)[0]!.text, 'Never deploy on a Friday.');
  for (const k of ['empty', 'workspace', 'notes', 'message', 'welcome']) assert.equal(st[k], undefined, k);
  assert.equal((await call(u.access, 'zeusi_onboarding_status'))['empty'], false);
});

test('the team path: zeusi_startup output keys are exactly the pre-fix set (no personal fields, no extra state)', async () => {
  const st = await call(teamRead, 'zeusi_startup');
  assert.deepEqual(Object.keys(st).sort(), [
    'days', 'decisions', 'focus', 'generated_at', 'reminder', 'rules', 'rules_budget', 'rules_note', 'rules_remainder', 'rules_remainder_count',
    'rules_served', 'rules_total', 'sources', 'withheld', ...(st['focus_message'] !== undefined ? ['focus_message'] : []),
    ...(st['focus_older_same_subject'] !== undefined ? ['focus_older_same_subject'] : []), ...(st['rules_unlisted'] !== undefined ? ['rules_unlisted'] : []),
  ].sort());
});

test('preview says WHY a decision-log entry stays a note (the live entry: no timestamped heading); commit keeps it a note', async () => {
  const u = await signIn(h, 'gh-n23');
  const { preview, commit } = await importDocs(u.access, [decisionLog(LIVE_ENTRY)]);
  assert.equal((preview['counts'] as { decisions: number }).decisions, 0);
  const kept = preview['kept_as_notes'] as { entries: number; reasons: Array<{ reason: string; count: number; why: string }>; format: string };
  assert.equal(kept.entries, 1);
  assert.deepEqual(kept.reasons.map((r) => [r.reason, r.count]), [['heading', 1]]);
  assert.match(kept.reasons[0]!.why, /no timestamped heading/);
  assert.ok(kept.format.includes('zeusi://about#decision-format'));
  assert.equal(commit['decisions'], 0);
});

test('the documented decision examples (markdown, JSONL) become decisions in the preview AND are stored as decisions (handle `me`, the workspace person)', async () => {
  const u = await signIn(h, 'gh-n24');
  for (const doc of [decisionLog(DECISION_EXAMPLE_MARKDOWN), decisionLog(`${DECISION_EXAMPLE_JSONL}\n`, 'jsonl')]) {
    const p = await call(u.access, 'zeusi_import_preview', { documents: [doc] });
    assert.equal((p['counts'] as { decisions: number }).decisions, 1, `${doc.format}: the example is a decision`);
    assert.equal(p['kept_as_notes'], undefined);
    assert.equal(p['decisions_note'], undefined, 'the workspace knows `me`: nothing to warn about');
    assert.equal(p['decisions_kept_as_notes'], undefined);
  }
  const { commit } = await importDocs(u.access, [decisionLog(DECISION_EXAMPLE_MARKDOWN)]);
  assert.equal(commit['status'], 'ok');
  assert.equal(commit['decisions'], 1);
  assert.equal(commit['decisions_kept_as_notes'], 0, 'said, and 0: every entry was stored');
  assert.equal(commit['decisions_note'], undefined);
  const found = await call(u.access, 'zeusi_search', { query: 'preview first, then one explicit yes' });
  assert.deepEqual((found['decisions'] as Array<{ who: string; kind: string }>).map((d) => [d.who, d.kind]), [['me', 'go']], 'stored as a decision of `me`');
});

test('parser reasons: the first rule an entry breaks, from the real parser', () => {
  const why = (s: string) => {
    const r = parseEntry(s.split('\n'));
    return 'why' in r ? r.why : 'record';
  };
  assert.equal(why(DECISION_EXAMPLE_MARKDOWN.trimEnd()), 'record');
  assert.equal(why(LIVE_ENTRY.trimEnd()), 'heading');
  assert.equal(why('## 2026-11-18T10:00:00+01:00 me\n\nDecision: go'), 'no_header');
  assert.equal(why('## 2026-11-18T10:00:00+01:00 me\nDecision: maybe\nSaid-at-precision: minute\n\nx'), 'decision_kind');
  assert.equal(why('## 2026-11-18T10:00:00+01:00 me\nDecision: go\n\nx'), 'said_at_precision');
  assert.equal(why('## 2026-11-18T10:00:00+01:00 me\nDecision: go\nSaid-at-precision: minute\nColour: red\n\nx'), 'other');
  assert.deepEqual(parseStructuredBody(`${LIVE_ENTRY}\n${DECISION_EXAMPLE_MARKDOWN}`).keptAsNote, { heading: 1 });
});

test('docs: the format is in zeusi://about (form B) and the site guide; no owner name; it passes the wall', () => {
  const about = aboutMarkdown(false, 'personal', true);
  for (const must of [DECISION_EXAMPLE_MARKDOWN.trimEnd(), DECISION_EXAMPLE_JSONL, 'standing_locks: [1]']) assert.ok(about.includes(must), must.slice(0, 40));
  assert.ok(personalAboutSections(true).some((s) => s.slug === 'decision-format' && s.body === DECISION_FORMAT));
  assert.ok(!personalAboutSections(false).some((s) => s.slug === 'decision-format'), 'form A unchanged');
  assert.equal(withheld([about]), false);
  const site = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
  const step = site.slice(site.indexOf('<strong>Fill your memory.</strong>'), site.indexOf('</li>', site.indexOf('<strong>Fill your memory.</strong>')));
  for (const must of ['preview first', 'nothing is saved until you say yes', 'reconnect the Zeusi connector once', '## 2026-11-18T10:00:00+01:00 me',
    'Decision: go', 'Said-at-precision: minute', '"said_at_precision":"minute"', 'standing_locks: [1]']) assert.ok(step.includes(must), must);
  for (const t of [site, about, WELCOME_MARKDOWN]) assert.equal(hasNonRoleOperatorAddress(t), false, 'no non-role operator address');
});
