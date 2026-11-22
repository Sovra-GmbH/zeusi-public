// Gap 2 (follow-up 2 of #33): the workspace import carries a strictly valid `standing_locks:`
// (src/importers/onboard.ts carriedStandingLocks), through the same filters, so an imported note can
// become a standing rule served by zeusi_startup; the team CLI import never carries it. PGlite, real
// migrations, real logins, the real hosted /mcp handler. No network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { RULES_HOWTO } from '../src/about.ts';
import { prepareImport } from '../src/import-run.ts';
import { carriedStandingLocks } from '../src/importers/onboard.ts';
import { splitNote } from '../src/importers/vault.ts';
import { callTool, mcpPost, mintStatic, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';
import { fakeGoogleKey } from './secret-fixtures.ts';

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
    wsLimits: { preview: 100, commit: 100, sync: 50 }, hostedLimits: { perToken: 100_000, global: 100_000 },
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
const preview = async (token: string, documents: unknown[]) => call(token, 'zeusi_import_preview', { documents });
async function importDocs(token: string, documents: unknown[]): Promise<{ preview: Record<string, unknown>; commit: Record<string, unknown> }> {
  const p = await preview(token, documents);
  assert.equal(p['status'], 'preview', JSON.stringify(p));
  const commit = await call(token, 'zeusi_import_commit', { preview_id: p['preview_id'], confirm: true });
  return { preview: p, commit };
}
const ruleNote = (locks: string[], marker: string | null, title = 'Release rules') =>
  `---\ntitle: ${title}\ndate: 2026-11-18\nlocks:\n${locks.map((l) => `  - ${JSON.stringify(l)}`).join('\n')}\n${marker === null ? '' : `standing_locks: ${marker}\n`}---\nWhy: SYNTHETIC.\n`;
const rulesTotal = (st: Record<string, unknown>) => (st['rules_total'] as { total: number }).total;

// ---------------------------------------------------------------------------
// Gap 2: standing_locks through the import

test('carriedStandingLocks: strict, renumbered to the staged locks, never a guess', () => {
  const c = (locks: unknown, marker: unknown) => carriedStandingLocks({ locks, standing_locks: marker } as never);
  assert.deepEqual(c(['a'], ['1']), ['1']);
  assert.deepEqual(c(['a', 'b', 'c'], '3, 1, 1'), ['1', '3']);
  assert.deepEqual(c('a', 1), ['1'], 'one string lock, one number');
  assert.deepEqual(c(['', 'a', 'b'], ['3']), ['2'], 'a blank lock is not staged: the ordinal follows its lock');
  for (const [locks, marker] of [
    [['', 'a'], ['1']], // points at a blank item
    [['a'], ['2']], // no such lock
    [['a'], ['0']], [['a'], ['x']], [['a'], ['1', 'x']], [['a'], { a: 1 }], [['a'], ''], [['a'], []],
    [undefined, ['1']], ['', ['1']], // no locks at all
  ] as Array<[unknown, unknown]>) assert.equal(c(locks, marker), null, JSON.stringify([locks, marker]));
});

test('the marker is carried ONLY by the workspace import option; the team CLI import stages no standing_locks', async () => {
  const dirIn = safeMkdtemp(join(tmpdir(), 'zeusi-standing-'));
  const notes = join(dirIn, 'notes');
  mkdirSync(notes);
  writeFileSync(join(notes, 'rules.md'), ruleNote(['', 'SYNTHETIC lock one', 'SYNTHETIC lock two'], '[3]'));
  const run = async (standingLocks: boolean | undefined) => {
    const p = await prepareImport({ inputs: [{ kind: 'markdown', path: notes }], scope: 'work', workRoot: join(dirIn, `w-${String(standingLocks)}`), home: dirIn, ...(standingLocks === undefined ? {} : { standingLocks }) });
    try {
      const [rel] = p.admitted;
      return splitNote(readFileSync(join(p.filteredDir, rel!), 'utf8')).fm!;
    } finally {
      p.cleanup();
    }
  };
  const teamFm = await run(undefined);
  assert.equal(teamFm['standing_locks'], undefined, 'CLI default (the team): not carried');
  assert.deepEqual(teamFm['locks'], ['SYNTHETIC lock one', 'SYNTHETIC lock two']);
  assert.equal((await run(false))['standing_locks'], undefined);
  const ws = await run(true);
  assert.deepEqual(ws['locks'], ['SYNTHETIC lock one', 'SYNTHETIC lock two']);
  assert.deepEqual(ws['standing_locks'], ['2'], 'renumbered: still names "SYNTHETIC lock two"');
});

test('import -> preview note_lock_rules 1 -> commit -> startup rules 1 (the exact marked lock); the team startup unchanged', async () => {
  const teamBefore = await call(teamRead, 'zeusi_startup');
  const u = await signIn(h, 'gh-n35');
  const { preview: p, commit } = await importDocs(u.access, [md(ruleNote(['', 'SYNTHETIC lock A', 'SYNTHETIC lock B'], '[3]'), 'Rules')]);
  assert.equal((p['counts'] as { note_lock_rules: number }).note_lock_rules, 2);
  assert.equal(commit['note_locks'], 2);
  const st = await call(u.access, 'zeusi_startup');
  assert.equal(rulesTotal(st), 1);
  assert.deepEqual((st['rules'] as Array<{ text: string }>).map((r) => r.text), ['SYNTHETIC lock B']);
  const teamAfter = await call(teamRead, 'zeusi_startup');
  assert.deepEqual({ ...teamAfter, generated_at: null }, { ...teamBefore, generated_at: null }, 'the team: same output');
});

test('a standing lock carrying a secret is withheld: the note is refused by the frontmatter check, no rule, nothing stored', async () => {
  const u = await signIn(h, 'gh-n36');
  const p = await preview(u.access, [md(ruleNote([`SYNTHETIC use key ${fakeGoogleKey()} for deploys`], '[1]'), 'Secret rules')]);
  assert.equal(p['status'], 'nothing_to_import', JSON.stringify(p));
  assert.ok(!JSON.stringify(p).includes(fakeGoogleKey()), 'never echoed');
  const st = await call(u.access, 'zeusi_startup');
  assert.equal(rulesTotal(st), 0);
  assert.equal(st['empty'], true);
});

test('a malformed marker is ignored (the lock stays an ordinary lock), and a marker never promotes a lock of another note', async () => {
  const u = await signIn(h, 'gh-n37');
  const { preview: p } = await importDocs(u.access, [
    md(ruleNote(['SYNTHETIC bad marker lock'], '[1, x]', 'Bad marker'), 'Bad marker'),
    md(ruleNote(['SYNTHETIC only lock'], '[2]', 'Out of range'), 'Out of range'),
    md(ruleNote(['SYNTHETIC other one', 'SYNTHETIC other two'], null, 'Other note'), 'Other note'),
  ]);
  assert.equal((p['counts'] as { note_lock_rules: number }).note_lock_rules, 4);
  const st = await call(u.access, 'zeusi_startup');
  assert.equal(rulesTotal(st), 0, 'no marker survived; "[2]" of a one-lock note never reaches the other note\'s lock 2');
  const ctx = await call(u.access, 'zeusi_context_for_task', { task: 'SYNTHETIC bad marker lock' });
  assert.ok(JSON.stringify(ctx['items']).includes('SYNTHETIC bad marker lock'), 'still an ordinary lock');
});

test('docs: RULES_HOWTO says the import keeps the marker and when it drops it', () => {
  assert.doesNotMatch(RULES_HOWTO, /not yet `standing_locks:`/);
  for (const must of ['both keep `locks:` and `standing_locks:`', 'drops a `standing_locks:`', 'not imported at all']) assert.ok(RULES_HOWTO.includes(must), must);
});
