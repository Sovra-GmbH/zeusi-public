// C7 KTD2-KTD4 (docs/plans/2026-11-19-c7-read-path.md; D13; parent plan §7 item 9): the B1 cache. Unit level (the
// proof gate, check mismatch, rotation, LRU and idle TTL with a fake clock) and through the REAL hosted handler
// (two grants share one copy; every session-end path evicts at once; an offline revoke from a second OAuthStore
// on the same file evicts before the next lookup; a grant without a wrap is LOCKED while another grant's copy is
// hot). FIXED test DEKs only. No network, no Neon.
// Mutants: the hook not wired (test/helpers/hosted-tenants.ts mirrors src/mcp.ts) -> the copy stays after a
// revoke, red; use() skips the proof check -> the forged-proof case is red; no load(false) diff in the store ->
// the offline case is red; no rotation rule -> the version cases are red.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { B1Cache, CacheRefused, CacheVersionChanged, proveSessionWrap, WrapProof } from '../src/b1-cache.ts';
import { Merged, pack, type LoadOutcome } from '../src/b1-index.ts';
import { OAuthStore } from '../src/mcp-oauth-store.ts';
import { WORKSPACE_READ_LOCKED } from '../src/read-route.ts';
import { sealSessionWraps } from '../src/workspace-keys.ts';
import { callTool, dcrClient, mcpPost, refresh, send, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { OTHER_DEK, TEST_DEK } from './helpers/c6-fixture.ts';
import { tenantTestDb } from './helpers/tenant-fixture.ts';

const T = 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa';
const U = 'zt_bbbbbbbbbbbbbbbbbbbbbbbbbb';
const proof = (t: string, o: { dek?: Buffer; kv?: number; grant?: string } = {}) =>
  proveSessionWrap(() => ({ tenant: t, grantId: o.grant ?? 'g1', dek: Buffer.from(o.dek ?? TEST_DEK), keyVersion: o.kv ?? 1 }), { tenant: t, grantId: o.grant ?? 'g1' })!;
function merged(notes: number): Merged {
  const m = new Merged();
  for (let i = 1; i <= notes; i++) m.notes.set(i, { id: i, title: `t${i}`.padEnd(200, 'x'), vaultPath: `p${i}`, sourceUri: `u${i}`, fm: null });
  return m;
}
const loader = (calls: { n: number }, notes = 1, generation = 1) => async (): Promise<LoadOutcome> => {
  calls.n++;
  return { packed: pack(merged(notes), generation), rebuilt: false };
};
const fresh = (notes = 1, generation = 1) => ({ generation, coverage: merged(notes).coverage() });

test('unit: a cache call with a forged object, a disposed proof or a self-made proof throws; a proof for another workspace or grant is never minted', async () => {
  const c = new B1Cache();
  const calls = { n: 0 };
  await assert.rejects(c.use({ tenant: T, keyVersion: 1 } as unknown as WrapProof, fresh(), loader(calls)), CacheRefused);
  await assert.rejects(c.use(Object.create(WrapProof.prototype) as WrapProof, fresh(), loader(calls)), CacheRefused);
  assert.throws(() => new WrapProof(Symbol('x') as never, T, 'g1', undefined as never), CacheRefused);
  const p = proof(T);
  p.dispose();
  await assert.rejects(c.use(p, fresh(), loader(calls)), CacheRefused);
  assert.equal(calls.n, 0, 'nothing loaded for a refused call');
  assert.equal(proveSessionWrap(() => ({ tenant: U, grantId: 'g1', dek: Buffer.from(TEST_DEK), keyVersion: 1 }), { tenant: T, grantId: 'g1' }), null, 'another workspace');
  assert.equal(proveSessionWrap(() => ({ tenant: T, grantId: 'g2', dek: Buffer.from(TEST_DEK), keyVersion: 1 }), { tenant: T, grantId: 'g1' }), null, 'another grant');
  assert.equal(proveSessionWrap(() => null, { tenant: T, grantId: 'g1' }), null, 'no wrap');
  // The unwrapped DEK is zeroed whatever happens.
  const dek = Buffer.from(TEST_DEK);
  proveSessionWrap(() => ({ tenant: U, grantId: 'g1', dek, keyVersion: 1 }), { tenant: T, grantId: 'g1' });
  assert.ok(dek.every((b) => b === 0));
});

test('unit: one entry per (workspace, key_version) shared by two grants; a different check (another DEK, same version) evicts and reloads; stale generation or coverage reloads', async () => {
  const c = new B1Cache();
  const calls = { n: 0 };
  await c.use(proof(T, { grant: 'g1' }), fresh(), loader(calls));
  await c.use(proof(T, { grant: 'g2' }), fresh(), loader(calls));
  assert.equal(calls.n, 1, 'two grants, one load');
  assert.equal(c.list().length, 1);
  await c.use(proof(T, { dek: OTHER_DEK }), fresh(), loader(calls));
  assert.equal(calls.n, 2, 'check mismatch -> reload with the new proof');
  await c.use(proof(T), fresh(1, 2), loader(calls, 1, 2));
  assert.equal(calls.n, 3, 'a newer manifest generation reloads');
  await c.use(proof(T), fresh(2, 2), loader(calls, 2, 2));
  assert.equal(calls.n, 4, 'other coverage reloads');
  await c.use(proof(U), fresh(), loader(calls));
  assert.deepEqual(c.list().map((e) => e.tenant).sort(), [T, U], 'workspace A and B never share an entry (§7.10)');
});

test('unit: rotation: a key_version 2 proof evicts the version 1 copy; a version 1 proof is then refused (CacheVersionChanged -> WORKSPACE_READ_CHANGING)', async () => {
  const c = new B1Cache();
  const calls = { n: 0 };
  await c.use(proof(T, { kv: 1 }), fresh(), loader(calls));
  await c.use(proof(T, { kv: 2, dek: OTHER_DEK }), fresh(), loader(calls));
  assert.deepEqual(c.list().map((e) => e.keyVersion), [2]);
  await assert.rejects(c.use(proof(T, { kv: 1 }), fresh(), loader(calls)), CacheVersionChanged);
  assert.equal(c.evictTenant(T), 1);
  assert.equal(c.list().length, 0);
});

test('unit: LRU by accounted bytes (x1.25) and idle TTL with a fake clock; an entry above the cap serves its request and is not kept; eviction zero-fills (deferred while leased)', async () => {
  let now = 1_000;
  const one = pack(merged(50), 1).bytes;
  const c = new B1Cache({ capBytes: Math.ceil(one * 1.25 * 2.5), idleMs: 10_000, now: () => now });
  const calls = { n: 0 };
  const tenants = ['zt_cccccccccccccccccccccccccc', 'zt_dddddddddddddddddddddddddd', 'zt_eeeeeeeeeeeeeeeeeeeeeeeeee'];
  for (const t of tenants) {
    const p = proof(t);
    await c.use(p, fresh(50), loader(calls, 50));
    p.dispose();
    now += 10;
  }
  assert.deepEqual(c.list().map((e) => e.tenant), tenants.slice(1), 'the least recently used went first');
  assert.ok(c.accountedBytes <= Math.ceil(one * 1.25 * 2.5));
  now += 20_000;
  assert.equal(c.sweep(), 2, 'idle TTL');
  // Above the cap: served, not kept; wiped when the request's proof is disposed.
  const small = new B1Cache({ capBytes: 10 });
  const p = proof(T);
  const packed = await small.use(p, fresh(50), loader(calls, 50));
  assert.equal(small.list().length, 0);
  assert.ok(packed.records.some((b) => b !== 0), 'usable during the request');
  p.dispose();
  assert.ok(packed.records.every((b) => b === 0), 'zero-filled after the request');
});

// ---------------------------------------------------------------------------- hosted

let db: Db;
let h: TenantHarness;
before(async () => {
  db = await tenantTestDb({ writer: true });
  // keysMode 'enroll' (docs/plans/2026-11-19-c4-webauthn-verify.md KTD7): these tests mint a passkey-less grant of a
  // born-on workspace through the real consent page (the LOCKED defence under test); flag `on` refuses that at consent.
  h = await startTenantHosted({
    db, home: serviceHome(), writer: 'on', flagOn: { newDek: () => Buffer.from(TEST_DEK), keysMode: 'enroll' }, routerCacheMs: 0,
    limits: { authorize: 1000, callback: 1000, consent: 1000, token: 1000, register: 1000, registerGlobal: 1000, revoke: 1000, signupPerIp: 1000, signupGlobal: 1000 }, hostedLimits: { perToken: 100_000, global: 100_000 }, wsLimits: { preview: 50, commit: 50, sync: 50 },
  });
});
after(async () => {
  await h.close();
  await db.close();
});

const call = async (tok: string, name: string, args: Record<string, unknown> = {}) => toolJson(await mcpPost(h.port, tok, callTool(name, args)));
const tenantOf = (login: string) => h.store.list().grants.filter((g) => g.login === login).at(-1)!.tenant;
async function grant(t: string, n: number): Promise<{ access: string; refresh: string; grantId: string; clientId: string }> {
  const clientId = await dcrClient(h);
  const g = h.store.createGrant({ clientId, subject: `github:${5000 + n}`, login: `newbie-${n}`, tenant: t, workspaceWrite: true, seal: (id, a, r) => sealSessionWraps(t, id, a, r, TEST_DEK, 1) });
  return { access: g.accessToken, refresh: g.refreshToken, grantId: g.grant.grant_id, clientId };
}
async function filled(n: number): Promise<string> {
  await signIn(h, `gh-n${n}`);
  const t = tenantOf(`newbie-${n}`);
  const g = await grant(t, n);
  const p = await call(g.access, 'zeusi_import_preview', { documents: [{ kind: 'markdown', title: 'Cache note', text: '# Cache\n\nlantern harbor cache note.\n' }] });
  assert.equal((await call(g.access, 'zeusi_import_commit', { preview_id: (p.json as { preview_id: string }).preview_id, confirm: true })).isError, false);
  return t;
}
const hot = (t: string) => h.cache.list().some((e) => e.tenant === t);
const search = async (tok: string) => {
  const r = await call(tok, 'zeusi_search', { query: 'lantern harbor' });
  assert.equal(r.isError, false, r.text);
  assert.equal((r.json!['hits'] as unknown[]).length, 1);
};

test('hosted: two grants of one workspace share ONE copy (loads 1); a grant without a wrap is LOCKED while that copy is hot', async () => {
  const t = await filled(11);
  const a = await grant(t, 11);
  const b = await grant(t, 11);
  const loads = h.cache.stats.loads;
  await search(a.access);
  await search(b.access);
  assert.equal(h.cache.stats.loads, loads + 1);
  assert.ok(hot(t));
  const plain = await signIn(h, 'gh-n11');
  const r = await call(plain.access, 'zeusi_search', { query: 'lantern harbor' });
  assert.equal(r.text, WORKSPACE_READ_LOCKED, 'no wrap: refused even with a hot copy');
});

test('hosted: revokeGrant, /revoke, revokeClient, revokeTenant, revokeAll and a reused refresh each evict that workspace at once', async () => {
  const cases: Array<[string, (t: string, g: Awaited<ReturnType<typeof grant>>) => Promise<void>]> = [
    ['revokeGrant', async (_t, g) => { h.store.revokeGrant(g.grantId); }],
    ['/revoke', async (_t, g) => {
      const r = await send(h.port, { method: 'POST', path: '/revoke', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: g.refresh, client_id: g.clientId }).toString() });
      assert.equal(r.status, 200);
    }],
    ['revokeClient', async (_t, g) => { assert.ok(h.store.revokeClient(g.clientId)); }],
    ['revokeTenant', async (t) => { assert.ok(h.store.revokeTenant(t) >= 1); }],
    ['revokeAll', async () => { assert.ok(h.store.revokeAll() >= 1); }],
    ['reused refresh', async (_t, g) => {
      await refresh(h, g.clientId, g.refresh);
      const again = await send(h.port, { method: 'POST', path: '/token', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: g.refresh, client_id: g.clientId }).toString() });
      assert.equal(again.status, 400, 'reuse refused');
    }],
  ];
  let n = 20;
  for (const [what, end] of cases) {
    const t = await filled(n);
    const g = await grant(t, n);
    await search(g.access);
    assert.ok(hot(t), `${what}: hot`);
    await end(t, g);
    assert.equal(hot(t), false, `${what}: evicted at once`);
    n++;
  }
});

test('hosted: an offline revoke (a second OAuthStore on the same file, as `zeusi mcp-oauth revoke`) evicts at the next request, before the lookup; the other live grant reloads (loads + 1)', async () => {
  const t = await filled(40);
  const a = await grant(t, 40);
  const b = await grant(t, 40);
  await search(a.access);
  assert.ok(hot(t));
  const path = (h.store as unknown as { o: { path: string } }).o.path;
  const offline = new OAuthStore({ path: join(path) });
  assert.ok(offline.revokeGrant(a.grantId));
  assert.ok(hot(t), 'another process: nothing evicted yet');
  const loads = h.cache.stats.loads;
  await search(b.access);
  assert.ok(h.ended.some((e) => e.grantId === a.grantId && e.reason === 'revoked'), 'the store fired the hook for the offline revoke');
  assert.equal(h.cache.stats.loads, loads + 1, 'the copy was evicted before the lookup and rebuilt with the live grant\'s proof');
  assert.equal((await mcpPost(h.port, a.access, callTool('zeusi_search', { query: 'x' }))).status, 401, 'the revoked bearer is refused');
});
