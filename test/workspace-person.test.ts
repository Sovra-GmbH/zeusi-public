// Gap 1 (follow-up 1 of #33): a personal workspace stores real decisions and Type: rule / focus facts
// from an import. Every NEW workspace gets its own person `me` at provision (src/tenants.ts personIn),
// as the provisioning login; existing ones only through the explicit operator backfill
// (backfillPeople / `zeusi workspaces backfill-people`), never at sign-in. The writer role stays
// SELECT-only on people. PGlite, real migrations, real logins (test/helpers/tenant-fixture.ts), the
// real hosted /mcp handler. No network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { PERSONAL_DECISIONS_HANDLE, PERSONAL_DECISIONS_PENDING } from '../src/about.ts';
import { TENANT_ACL_AUDIT_SQL, tenantRole } from '../src/tenant-ddl.ts';
import {
  TenantDirectory, TenantRouter, TenantWriter, TENANT_WR_ROLE, WORKSPACE_PERSON_HANDLE, WORKSPACE_PERSON_IMPORTER, WORKSPACE_PERSON_SOURCE_URI,
} from '../src/tenants.ts';
import { callTool, IDENTITIES, mcpPost, mintStatic, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { asLogin, asOwner, plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let h: TenantHarness;
let dir: TenantDirectory;
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
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
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
const decisionLog = (text: string) => ({ kind: 'decision-log', text, format: 'markdown' });
const preview = async (token: string, documents: unknown[]) => call(token, 'zeusi_import_preview', { documents });
async function importDocs(token: string, documents: unknown[]): Promise<{ preview: Record<string, unknown>; commit: Record<string, unknown> }> {
  const p = await preview(token, documents);
  assert.equal(p['status'], 'preview', JSON.stringify(p));
  const commit = await call(token, 'zeusi_import_commit', { preview_id: p['preview_id'], confirm: true });
  return { preview: p, commit };
}
/** The workspace of a hosted sign-in (catalog read as the owner; test only). */
const tenantOf = (code: string) => asOwner(db, async () =>
  (await db.query<{ t: string }>('SELECT tenant_id AS t FROM zeusi_tenants.members WHERE subject = $1', [`github:${IDENTITIES[code]!.id}`])).rows[0]!.t);
const peopleIn = (tenant: string) => asOwner(db, async () => (await db.query<Record<string, unknown>>(
  `SELECT p.handle, p.display_name, p.kind, p.org, p.github_login, p.scope::text AS scope, p.source_kind::text AS source_kind, p.source_uri,
          p.ingested_by, r.importer, r.host, r.mode, r.status, r.started_by
     FROM "${tenant}".people p JOIN "${tenant}".ingest_runs r ON r.id = p.ingest_run_id ORDER BY p.id`)).rows);
/** A workspace made before this change: no person (as the owner; test only). */
const dropPerson = (tenant: string) => asOwner(db, () => db.query(`DELETE FROM "${tenant}".people WHERE handle = $1`, [WORKSPACE_PERSON_HANDLE]));
const teamPeople = () => asOwner(db, async () => (await db.query<{ n: number }>('SELECT count(*)::int AS n FROM zeusi.people')).rows[0]!.n);

const decisionEntry = (who: string, words: string, at = '2026-11-18T10:00:00+01:00') => `## ${at} ${who}\nDecision: go\nSaid-at-precision: minute\n\n${words}\n`;
const factEntry = (who: string, type: 'rule' | 'focus', subject: string, text: string, at: string) => `## ${at} ${who}\nType: ${type}\nSubject: ${subject}\n\n${text}\n`;
const rulesTotal = (st: Record<string, unknown>) => (st['rules_total'] as { total: number }).total;

// ---------------------------------------------------------------------------
// Gap 1: the workspace person

test('provision: a new workspace holds exactly one person `me`, made by the provisioning login with constant provenance; no GitHub login or name', async () => {
  const before = await teamPeople();
  await signIn(h, 'gh-n30');
  const t = await tenantOf('gh-n30');
  assert.deepEqual(await peopleIn(t), [{
    handle: 'me', display_name: 'me', kind: 'human', org: 'work', github_login: null, scope: 'work', source_kind: 'manual',
    source_uri: WORKSPACE_PERSON_SOURCE_URI, ingested_by: 'zeusi_tenant_admin',
    importer: WORKSPACE_PERSON_IMPORTER, host: 'provisioner', mode: 'manual', status: 'ok', started_by: 'zeusi_tenant_admin',
  }]);
  assert.equal(await teamPeople(), before, 'nothing written to the team');
  await asOwner(db, async () => assert.deepEqual((await db.query(TENANT_ACL_AUDIT_SQL, [t, tenantRole(t)])).rows, [], 'ACL audit clean'));
  // The writer role is unchanged: SELECT on people, never INSERT / UPDATE / DELETE.
  const router = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt'), cacheMs: 0 });
  const s = await new TenantWriter({ connectWriter: asLogin(db, TENANT_WR_ROLE), check: (x) => router.check(x) }).open(t);
  try {
    assert.equal((await s.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.people WHERE handle = 'me'`)).rows[0]!.n, 1);
    for (const sql of [
      `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       SELECT 'x', 'x', 'human', 'work', 'work', 'manual', 'm:x', now(), source_sha256, ingest_run_id FROM zeusi.people LIMIT 1`,
      `UPDATE zeusi.people SET display_name = 'y'`, 'DELETE FROM zeusi.people',
    ]) await assert.rejects(s.query(sql), /permission denied/);
  } finally {
    await s.close();
  }
});

test('the documented decision (`me`) and Type: rule / focus entries are STORED in a new workspace; another handle stays a note, said', async () => {
  const u = await signIn(h, 'gh-n31');
  const log = decisionEntry('me', 'SYNTHETIC ship the import preview.')
    + '\n' + factEntry('me', 'rule', 'deploys', 'SYNTHETIC never deploy on a Friday.', '2026-11-18T09:00:00+01:00')
    + '\n' + factEntry('me', 'focus', 'quarter', 'SYNTHETIC focus on onboarding.', '2026-11-18T08:00:00+01:00');
  const { preview: p, commit } = await importDocs(u.access, [decisionLog(log)]);
  assert.deepEqual([(p['counts'] as Record<string, number>)['decisions'], (p['counts'] as Record<string, number>)['rules'], (p['counts'] as Record<string, number>)['focus']], [1, 1, 1]);
  assert.equal(p['decisions_note'], undefined);
  assert.equal(p['decisions_kept_as_notes'], undefined);
  assert.equal(commit['status'], 'ok');
  assert.deepEqual([commit['decisions'], commit['rules'], commit['focus'], commit['decisions_kept_as_notes'], commit['decisions_note']], [1, 1, 1, 0, undefined]);
  const st = await call(u.access, 'zeusi_startup');
  assert.equal(rulesTotal(st), 1);
  assert.equal((st['rules'] as Array<{ text: string }>)[0]!.text, 'SYNTHETIC never deploy on a Friday.');
  assert.deepEqual((st['focus'] as Array<{ text: string }>).map((f) => f.text), ['SYNTHETIC focus on onboarding.']);

  // A handle the workspace does not know: preview and commit say so, with the handle rule.
  const other = await importDocs(u.access, [decisionLog(decisionEntry('alice', 'SYNTHETIC another person decided.', '2026-11-18T11:00:00+01:00'))]);
  assert.equal(other.preview['decisions_kept_as_notes'], 1);
  assert.equal(other.preview['decisions_note'], PERSONAL_DECISIONS_HANDLE);
  assert.deepEqual([other.commit['status'], other.commit['decisions'], other.commit['decisions_kept_as_notes'], other.commit['decisions_note']],
    ['ok_partial', 0, 1, PERSONAL_DECISIONS_HANDLE]);
});

test('an EXISTING workspace without its person: honest "not available yet"; sign-in never creates it; only the explicit backfill does, then decisions are stored', async () => {
  const u = await signIn(h, 'gh-n32');
  const t = await tenantOf('gh-n32');
  await dropPerson(t);
  const entry = decisionLog(decisionEntry('me', 'SYNTHETIC decided before the backfill.'));
  const p = await preview(u.access, [entry]);
  assert.equal(p['decisions_kept_as_notes'], 1);
  assert.equal(p['decisions_note'], PERSONAL_DECISIONS_PENDING);
  const c = await call(u.access, 'zeusi_import_commit', { preview_id: p['preview_id'], confirm: true });
  assert.deepEqual([c['status'], c['decisions'], c['decisions_kept_as_notes'], c['decisions_note']], ['ok_partial', 0, 1, PERSONAL_DECISIONS_PENDING]);
  const st = await call(u.access, 'zeusi_startup');
  assert.ok(String(st['message']).endsWith(PERSONAL_DECISIONS_PENDING), 'startup says what this workspace can do');

  // A returning sign-in (re-consent) does NOT create the person (no implicit backfill on deploy / sign-in).
  const again = await signIn(h, 'gh-n32');
  assert.deepEqual(await peopleIn(t), []);

  // Operator backfill: the dry run changes nothing; --real creates exactly the missing row; idempotent.
  const team = await teamPeople();
  const others = await asOwner(db, async () => (await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM zeusi_tenants.tenants WHERE status = 'active'`)).rows[0]!.n);
  const dry = await dir.backfillPeople({ dryRun: true });
  assert.deepEqual(dry, { active: others, missing_person: 1, ready: 0, failed: 0 });
  assert.deepEqual(await peopleIn(t), [], 'dry run: nothing changed');
  assert.deepEqual(await dir.backfillPeople({ dryRun: false }), { active: others, missing_person: 1, ready: 1, failed: 0 });
  assert.equal((await peopleIn(t)).length, 1);
  assert.deepEqual(await dir.backfillPeople({ dryRun: false }), { active: others, missing_person: 0, ready: 0, failed: 0 }, 'idempotent');
  assert.equal(await dir.ensurePerson(t), 'exists');
  assert.equal(await dir.ensurePerson('zt_' + 'a'.repeat(26)), 'unknown');
  assert.equal(await teamPeople(), team, 'nothing written to the team');
  // Now the same kind of entry is a decision.
  const after = await importDocs(again.access, [decisionLog(decisionEntry('me', 'SYNTHETIC decided after the backfill.', '2026-11-18T12:00:00+01:00'))]);
  assert.deepEqual([after.commit['decisions'], after.commit['decisions_kept_as_notes']], [1, 0]);
});

test('backfill touches only the workspaces missing their person; every other workspace keeps its row untouched', async () => {
  await signIn(h, 'gh-n33');
  await signIn(h, 'gh-n34');
  const [a, b] = [await tenantOf('gh-n33'), await tenantOf('gh-n34')];
  const rowB = await asOwner(db, async () => (await db.query(`SELECT id, ingested_at, ingest_run_id FROM "${b}".people`)).rows);
  await dropPerson(a);
  const teamBefore = await call(teamRead, 'zeusi_startup');
  const r = await dir.backfillPeople({ dryRun: false });
  assert.equal(r.missing_person, 1);
  assert.equal(r.ready, 1);
  assert.deepEqual(await asOwner(db, async () => (await db.query(`SELECT id, ingested_at, ingest_run_id FROM "${b}".people`)).rows), rowB);
  const teamAfter = await call(teamRead, 'zeusi_startup');
  assert.deepEqual({ ...teamAfter, generated_at: null }, { ...teamBefore, generated_at: null }, 'the team startup: same output');
});

test('backfill accounting: a workspace whose person setup reports unknown or throws is counted failed, never ready (review #34 P2-2, mutants m6 / m6b)', async () => {
  await signIn(h, 'gh-n35');
  await signIn(h, 'gh-n36');
  const [gone, broken] = [await tenantOf('gh-n35'), await tenantOf('gh-n36')];
  await dropPerson(gone);
  await dropPerson(broken);
  // Between the listing and the per-workspace setup, one workspace disappears ('unknown') and one fails.
  const real = dir.ensurePerson.bind(dir);
  dir.ensurePerson = async (id: string) => {
    if (id === gone) return 'unknown';
    if (id === broken) throw new Error('synthetic setup failure');
    return real(id);
  };
  try {
    const r = await dir.backfillPeople({ dryRun: false });
    assert.equal(r.failed, 2, 'unknown and thrown are both failures (the operator read-back and the CLI exit code depend on it)');
    assert.equal(r.ready, r.missing_person - 2, 'neither failure is counted ready');
  } finally {
    dir.ensurePerson = real;
  }
  assert.deepEqual(await peopleIn(gone), [], 'nothing was created for the failed workspaces');
  const again = await dir.backfillPeople({ dryRun: false });
  assert.equal(again.failed, 0);
  assert.equal((await peopleIn(gone)).length, 1);
  assert.equal((await peopleIn(broken)).length, 1);
});

test('docs: the handle rule names `me`, the workspace person', () => {
  assert.ok(PERSONAL_DECISIONS_HANDLE.includes(`\`${WORKSPACE_PERSON_HANDLE}\``));
});
