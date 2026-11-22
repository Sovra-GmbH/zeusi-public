// C7 KTD1, KTD2, KTD13 (docs/plans/2026-11-19-c7-read-path.md "Routing", §7 item 11): read routing through the REAL
// hosted handler (127.0.0.1, fake GitHub, PGlite, the real roles, writer login, B1 cache and index hook;
// test/helpers/hosted-tenants.ts) with a grant whose C4 session wraps hold a FIXED test DEK. No network, no Neon.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import type { EmbeddingsClient } from '../src/embeddings.ts';
import { readRouteFor, ReadRouteRefused, WORKSPACE_READ_CHANGING, WORKSPACE_READ_LOCKED } from '../src/read-route.ts';
import { WORKSPACE_UNAVAILABLE } from '../src/about.ts';
import { ENC_STATES } from '../src/tenants.ts';
import { sealSessionWraps } from '../src/workspace-keys.ts';
import type { TenantRoutes } from '../src/mcp-hosted.ts';
import { callTool, dcrClient, mcpPost, mintStatic, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { decisionEntry, setState, TEST_DEK } from './helpers/c6-fixture.ts';
import { asOwner, tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let h: TenantHarness;
let teamRead: string;
const spy = { encState: 0, open: 0, check: 0, embed: 0 };
let override: { tenant: string; value: string | 'throw' } | null = null;

before(async () => {
  db = await tenantTestDb({ writer: true });
  const read = await mintStatic('read');
  teamRead = read.token;
  // The request-side routes, spied: every workspace session (open) and every state read (encState) is counted.
  let inner: TenantRoutes | null = null;
  const routes: TenantRoutes = {
    check: (t) => { spy.check++; return inner!.check(t); },
    open: (t) => { spy.open++; return inner!.open(t); },
    encState: async (t) => {
      spy.encState++;
      if (override && override.tenant === t) {
        if (override.value === 'throw') throw new Error('ECONNREFUSED secret-host');
        return { status: 'active', encState: override.value };
      }
      return inner!.encState(t);
    },
  };
  const spyClient = { embed: async () => { spy.embed++; throw new Error('never'); }, model: 'x', dims: 1536 } as unknown as EmbeddingsClient;
  // keysMode 'enroll' (docs/plans/2026-11-19-c4-webauthn-verify.md KTD7): these tests mint a passkey-less grant of a
  // born-on workspace through the real consent page (the LOCKED defence under test); flag `on` refuses that at consent.
  h = await startTenantHosted({
    db, home: serviceHome(), tokensRows: [read.row], writer: 'on', routes, flagOn: { newDek: () => Buffer.from(TEST_DEK), keysMode: 'enroll' },
    limits: { signupPerIp: 50, signupGlobal: 50 }, hostedLimits: { perToken: 100_000, global: 100_000 }, wsLimits: { preview: 50, commit: 50, sync: 50 },
    over: { embeddings: () => spyClient },
  });
  inner = h.router!;
});
after(async () => {
  await h.close();
  await db.close();
});

const call = async (tok: string, name: string, args: Record<string, unknown> = {}) => toolJson(await mcpPost(h.port, tok, callTool(name, args)));
const tenantOf = (login: string) => h.store.list().grants.filter((g) => g.login === login).at(-1)!.tenant;

/** A grant of `t` with C4 session wraps of the test DEK (what /token issues after an enroll). */
async function sealedGrant(t: string, login: string, subject: string): Promise<string> {
  const clientId = await dcrClient(h);
  return h.store.createGrant({
    clientId, subject, login, tenant: t, workspaceWrite: true, seal: (g, a, r) => sealSessionWraps(t, g, a, r, TEST_DEK, 1),
  }).accessToken;
}

test('readRouteFor: off / enrolled plain; encrypting / verified / on / decrypting / decrypted sealed; anything else refused (changing)', () => {
  assert.deepEqual(ENC_STATES.map((s) => [s, readRouteFor(s)]), [
    ['off', 'plain'], ['enrolled', 'plain'], ['encrypting', 'sealed'], ['verified', 'sealed'], ['on', 'sealed'], ['decrypting', 'sealed'], ['decrypted', 'sealed'],
  ]);
  for (const bad of ['unknown', 'ON', '', null, undefined, 1, {}]) {
    assert.throws(() => readRouteFor(bad), (e: Error) => e instanceof ReadRouteRefused && e.reason === 'changing', String(bad));
  }
});

test('a born-on workspace: a grant without a session wrap gets WORKSPACE_READ_LOCKED on every read tool and NO workspace session is opened; mutant: open the session before the proof -> red', async () => {
  const plain = await signIn(h, 'gh-n1');
  const t = tenantOf('newbie-1');
  assert.equal((await h.router!.encState(t)).encState, 'on', 'born on (flag on)');
  for (const [tool, args] of [['zeusi_startup', {}], ['zeusi_search', { query: 'x' }], ['zeusi_context_for_task', { task: 'deploy x' }], ['zeusi_onboarding_status', {}]] as const) {
    const opens = spy.open;
    const r = await call(plain.access, tool, args);
    assert.equal(r.isError, true, tool);
    assert.equal(r.text, WORKSPACE_READ_LOCKED, tool);
    assert.equal(spy.open, opens, `${tool}: no workspace session before the proof`);
  }
});

test('the same workspace with a sealed grant: writes seal, every read tool answers; search is lexical and never calls the embeddings client (§7.11)', async () => {
  await signIn(h, 'gh-n2');
  const t = tenantOf('newbie-2');
  const tok = await sealedGrant(t, 'newbie-2', 'github:5002');
  const p = await call(tok, 'zeusi_import_preview', { documents: [
    { kind: 'markdown', title: 'Route note', text: '# Route\n\nharbor router notes for the route test.\n' },
    { kind: 'decision-log', format: 'markdown', text: decisionEntry('Route the harbor router reads.', { applies: ['harbor router'] }) },
  ] });
  assert.equal(p.isError, false, p.text);
  const c = await call(tok, 'zeusi_import_commit', { preview_id: (p.json as { preview_id: string }).preview_id, confirm: true });
  assert.equal(c.isError, false, c.text);
  assert.ok(h.hookStats.segments + h.hookStats.rebuilds >= 2, 'the real hook persisted the index');
  const s = await call(tok, 'zeusi_search', { query: 'harbor router' });
  assert.equal(s.isError, false, s.text);
  assert.equal(s.json!['mode'], 'lexical');
  assert.ok((s.json!['hits'] as unknown[]).length >= 1 && (s.json!['decisions'] as unknown[]).length === 1);
  assert.equal(spy.embed, 0, 'no embeddings client call on the sealed route');
  for (const tool of ['zeusi_startup', 'zeusi_onboarding_status'] as const) assert.equal((await call(tok, tool)).isError, false, tool);
  assert.equal((await call(tok, 'zeusi_context_for_task', { task: 'harbor router reads' })).isError, false);
});

test('an unknown enc_state is refused with WORKSPACE_READ_CHANGING and a state read error with WORKSPACE_UNAVAILABLE, both before any workspace SQL', async () => {
  await signIn(h, 'gh-n3');
  const t = tenantOf('newbie-3');
  const tok = await sealedGrant(t, 'newbie-3', 'github:5003');
  for (const [value, want] of [['weird', WORKSPACE_READ_CHANGING], ['throw', WORKSPACE_UNAVAILABLE]] as const) {
    override = { tenant: t, value };
    try {
      const opens = spy.open;
      const r = await call(tok, 'zeusi_startup');
      assert.equal(r.isError, true);
      assert.equal(r.text, want, value);
      assert.equal(spy.open, opens, `${value}: no workspace session`);
    } finally {
      override = null;
    }
  }
});

test('encrypting is read on the sealed route (mixed shapes): a sealed row is found and opened; mutant: encrypting -> plain -> the flipped schema has no tsv, search fails, red', async () => {
  await signIn(h, 'gh-n4');
  const t = tenantOf('newbie-4');
  const tok = await sealedGrant(t, 'newbie-4', 'github:5004');
  const p = await call(tok, 'zeusi_import_preview', { documents: [{ kind: 'markdown', title: 'Mixed', text: '# Mixed\n\nlantern meadow copper.\n' }] });
  await call(tok, 'zeusi_import_commit', { preview_id: (p.json as { preview_id: string }).preview_id, confirm: true });
  await setState(db, t, 'encrypting');
  const s = await call(tok, 'zeusi_search', { query: 'lantern meadow' });
  assert.equal(s.isError, false, s.text);
  assert.equal((s.json!['hits'] as Array<{ text: string }>)[0]!.text, '# Mixed\n\nlantern meadow copper.'.replace('# Mixed\n\n', ''), 'the sealed chunk, opened (never "null")');
  await setState(db, t, 'on');
});

test('the team never routes: a team read token never triggers a state read; a personal plain workspace reads enc_state once per request', async () => {
  const before = spy.encState;
  for (const tool of ['zeusi_startup', 'zeusi_onboarding_status'] as const) assert.equal((await call(teamRead, tool)).isError, false);
  assert.equal((await call(teamRead, 'zeusi_search', { query: 'pricing' })).isError, false);
  assert.equal(spy.encState, before, 'no the team path calls encState / readRouteFor; mutant: route the team through it -> red');
  // A personal workspace in `off` (flag off workspaces exist beside born-on ones): plain route, one state read per request.
  await signIn(h, 'gh-n5');
  const t = tenantOf('newbie-5');
  await asOwner(db, async () => { await db.query(`UPDATE zeusi_tenants.tenants SET enc_state = 'off' WHERE tenant_id = $1`, [t]); });
  const tok = await sealedGrant(t, 'newbie-5', 'github:5005');
  const b = spy.encState;
  const r = await mcpPost(h.port, tok, [callTool('zeusi_startup', {}, 1), callTool('zeusi_onboarding_status', {}, 2)]);
  assert.equal(r.status, 200);
  assert.equal(spy.encState, b + 1, 'one state read for a batch of two read tools');
});
