// Security bootstrap §7 item 11 (docs/plans/2026-11-18-zeusi-workspace-encryption.md; C2 plan
// docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD7): no embedding egress for personal workspaces.
//   1. Through the real hosted handler, a personal principal's deps have `embeddings: () => null`: its
//      search runs with no embeddings client even when the server's own (the team) deps carry one.
//   2. runEmbed refuses a personal-workspace target (a workspace session: router, writer, or any Db
//      that reads a zt_* schema; or a zt_* role) before it reads anything and before any API call.
//   3. The embed CLI refuses a zt_* or workspace-login --service before it connects.
// PGlite with the real roles and real provisioning; FAKE GitHub; nothing leaves loopback.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import type { Db } from '../src/db.ts';
import { assertTeamEmbedTarget, EMBED_WORKSPACE_REFUSED, EmbedRefused, runEmbed } from '../src/embed.ts';
import { OPENAI_KEY_ENV, type EmbeddingsClient } from '../src/embeddings.ts';
import { search as realSearch, type SearchOptions } from '../src/search.ts';
import { tenantRole } from '../src/tenant-ddl.ts';
import { schemaTranslatingDb, TENANT_WR_ROLE, TenantWriter } from '../src/tenants.ts';
import { callTool, mcpPost, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { asLogin, asOwner, plantInWorkspace, plantTeam, TEAM_MARKER, tenantTestDb } from './helpers/tenant-fixture.ts';

const MARKER = 'pelicanembedmarker';
let db: Db;
let h: TenantHarness;
let A: string;
let tokA: string;
const seenClients: Array<EmbeddingsClient | null | undefined> = [];
let teamFactoryCalls = 0;
let apiCalls = 0;

const spyClient = (): EmbeddingsClient => ({
  model: 'text-embedding-3-small', dims: 1536, kind: 'fake',
  embed: async () => { apiCalls++; throw new Error('must never be called'); },
});

before(async () => {
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  const home = serviceHome();
  h = await startTenantHosted({
    db, home, limits: { signupPerIp: 50, signupGlobal: 50 }, writer: 'on',
    over: {
      // The server env carries an OpenAI key, as production may for the team's hybrid search. Without the
      // personal `embeddings: () => null`, src/mcp-server.ts would fall back to a real OpenAI client built
      // from this env, and the pin below would see it (review C2R1-1). The value is a fake: the searchFn
      // seam forces `client: null` before the real search, so nothing ever leaves the process.
      env: { HOME: home, [OPENAI_KEY_ENV]: 'fake-c2-item11-not-a-key' },
      // The server's own deps carry an embeddings client: a personal principal must never get it.
      embeddings: () => { teamFactoryCalls++; return spyClient(); },
      searchFn: (s: SearchOptions) => { seenClients.push(s.client); return realSearch({ ...s, client: null }); },
    },
  });
  tokA = (await signIn(h, 'gh-stranger')).access;
  A = (await h.dir!.lookup('github:105'))!.tenantId;
  await plantInWorkspace(db, A, MARKER);
});
after(async () => {
  await h.close();
  await db.close();
});

test('item 11: a personal principal\'s search runs with no embeddings client (deps embeddings: () => null); the team client factory is never asked', async () => {
  seenClients.length = 0;
  teamFactoryCalls = 0;
  const r = toolJson(await mcpPost(h.port, tokA, callTool('zeusi_search', { query: MARKER, hybrid: true })));
  assert.equal(r.isError, false, r.text);
  assert.ok(r.text.includes(MARKER), 'its own workspace was searched');
  assert.deepEqual(seenClients, [null], 'no client, not even one built from the server env key');
  assert.equal(teamFactoryCalls, 0);
  // context_for_task matches lexically (src/context-for-task.ts) and never builds a client: still none.
  toolJson(await mcpPost(h.port, tokA, callTool('zeusi_context_for_task', { task: `work on ${MARKER}` })));
  assert.ok(seenClients.every((c) => c === null), 'every personal search ran lexical only');
  assert.equal(teamFactoryCalls, 0);
  assert.equal(apiCalls, 0);
});

test('item 11 control: a team principal on the same server does get the server\'s client (the pin above discriminates)', async () => {
  seenClients.length = 0;
  const team = (await signIn(h, 'gh-operator')).access;
  const r = toolJson(await mcpPost(h.port, team, callTool('zeusi_search', { query: TEAM_MARKER })));
  assert.equal(r.isError, false, r.text);
  assert.equal(seenClients.length, 1);
  assert.ok(seenClients[0] && seenClients[0].kind === 'fake');
  assert.ok(teamFactoryCalls > 0);
});

/** A Db that counts statements. */
function counting(inner: Db): { db: Db; sql: string[] } {
  const sql: string[] = [];
  return {
    sql,
    db: { label: inner.label, query: (q, p) => { sql.push(q); return inner.query(q, p); }, exec: (q) => { sql.push(q); return inner.exec(q); }, close: () => inner.close() },
  };
}

test('item 11: runEmbed refuses a schema-translating workspace Db before any other statement (even as the owner) and never calls the API', async () => {
  await asOwner(db, async () => {
    // Counted below the translation: what the database actually received.
    const c = counting(db);
    await assert.rejects(runEmbed({ db: schemaTranslatingDb(c.db, A), client: spyClient(), host: 'testhost' }), (e: unknown) => e instanceof EmbedRefused && e.message === EMBED_WORKSPACE_REFUSED);
    assert.equal(c.sql.length, 1, 'only the target probe ran');
    assert.match(c.sql[0]!, new RegExp(`'${A}\\.chunks'::regclass`), 'the probe was rewritten to the workspace schema, and refused');
  });
  assert.equal(apiCalls, 0);
});

test('item 11: runEmbed refuses a real workspace writer session (zeusi_tenant_wr -> <id>_w) and a real router read session', async () => {
  const writer = new TenantWriter({ connectWriter: asLogin(db, TENANT_WR_ROLE), check: (x) => h.router!.check(x) });
  const w = await writer.open(A);
  try {
    await assert.rejects(runEmbed({ db: w, client: spyClient(), host: 'testhost' }), EmbedRefused);
  } finally {
    await w.close();
  }
  const r = await h.router!.open(A);
  try {
    await assert.rejects(runEmbed({ db: r, client: spyClient(), host: 'testhost' }), EmbedRefused);
  } finally {
    await r.close();
  }
  assert.equal(apiCalls, 0);
});

test('item 11: a session whose role is a zt_* role is refused even when zeusi.chunks resolves to the team\'s schema', async () => {
  await asOwner(db, async () => {
    await db.exec(`SET ROLE ${tenantRole(A)}`);
    try {
      await assert.rejects(assertTeamEmbedTarget(db), EmbedRefused);
    } finally {
      await db.exec('RESET ROLE');
    }
  });
  // the team's own session passes the step (the rest of runEmbed is covered by test/embed.test.ts).
  await asOwner(db, () => assertTeamEmbedTarget(db));
});

test('item 11: the embed CLI refuses a zt_* or workspace-login --service before it connects (exit 2, the static refusal)', () => {
  for (const svc of [A, 'zt_whatever', 'zeusi_tenant_wr', 'zeusi_tenant_rt', 'zeusi_tenant_admin']) {
    const r = spawnSync(process.execPath, ['src/cli.ts', 'embed', '--dry-run', '--service', svc], { encoding: 'utf8', timeout: 20_000, env: { PATH: process.env['PATH'] ?? '', HOME: serviceHome(), ZEUSI_TEST_NO_REAL_CREDS: '1' } });
    assert.equal(r.status, 2, `${svc}: ${r.stderr}`);
    assert.equal(r.stderr, `error: ${EMBED_WORKSPACE_REFUSED}\n`, svc);
  }
});
