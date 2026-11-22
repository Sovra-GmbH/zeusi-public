// C4 KTD3 (docs/plans/2026-11-18-c4-enroll.md): session wraps beside the grant in the OAuth store.
// §7 item 4 (wraps useless alone; a wrap moved to another tenant / grant / kind fails) and §7 item 9
// (refresh rewraps and replaces, reused refresh revokes grant and wraps, an expired grant cannot unlock,
// every revoke path deletes the wraps and fires the C7 hook). Hermetic: temp dirs only. Every DEK, PRF
// output and token below is a TEST value.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ACCESS_TTL_MS, OAuthStore, OAuthStoreError, REFRESH_TTL_MS, type SessionEndReason } from '../src/mcp-oauth-store.ts';
import {
  openSessionDek, openSessionWrap, rewrapSession, sealSessionWraps, sessionWrapId, type SessionWraps,
} from '../src/workspace-keys.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const KEY = 'k'.repeat(48);
const T1 = 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa';
const T2 = 'zt_bbbbbbbbbbbbbbbbbbbbbbbbbb';
const DEK = Buffer.alloc(32, 0x4d);

function storeDir(): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-c4-store-'));
  chmodSync(d, 0o700);
  return d;
}

function setup(now = { t: Date.parse('2026-11-19T10:00:00Z') }) {
  const path = join(storeDir(), 'mcp-oauth.json');
  const ended: Array<{ grantId: string; tenant: string; reason: SessionEndReason }> = [];
  const store = new OAuthStore({ hashKey: KEY, path, now: () => now.t, onSessionEnded: (e) => ended.push(e) });
  const seal = (tenant: string) => (gid: string, at: string, rt: string) => sealSessionWraps(tenant, gid, at, rt, Buffer.from(DEK), 1);
  const reseal = (g: { tenant?: string | undefined; grant_id: string; session_wraps?: SessionWraps | undefined }, old: string, at: string, rt: string) =>
    (g.session_wraps && g.tenant ? rewrapSession(g.tenant, g.grant_id, old, at, rt, g.session_wraps) : null);
  const grant = (tenant = T1, client = 'zc_client') => store.createGrant({ clientId: client, subject: 'github:7', login: 'u', tenant, workspaceWrite: true, seal: seal(tenant) });
  const file = () => readFileSync(path, 'utf8');
  return { store, path, ended, grant, reseal, file, now };
}

test('C4 session wraps: sealed in the grant commit; open only with the right token; DEK equal; file holds no token or DEK', () => {
  const { store, grant, file } = setup();
  const g = grant();
  const w = g.grant.session_wraps!;
  assert.equal(w.key_version, 1);
  assert.equal(Buffer.from(w.access, 'base64url').length, 61);
  assert.deepEqual(openSessionWrap(T1, g.grant.grant_id, 'access', g.accessToken, w)!.dek, DEK);
  assert.deepEqual(openSessionWrap(T1, g.grant.grant_id, 'refresh', g.refreshToken, w)!.dek, DEK);
  const s = openSessionDek(store, g.accessToken)!;
  assert.deepEqual([s.tenant, s.grantId, s.keyVersion], [T1, g.grant.grant_id, 1]);
  assert.deepEqual(s.dek, DEK);
  const text = file();
  assert.ok(text.includes(w.access) && text.includes(w.refresh), 'wraps are persisted beside the grant');
  for (const secret of [g.accessToken, g.refreshToken, DEK.toString('hex'), DEK.toString('base64'), DEK.toString('base64url')]) assert.ok(!text.includes(secret));
  assert.equal(sessionWrapId('access', 'abc'), 'sess:access:abc');
});

test('C4 §7 item 4: with the store file but no token, unwrap fails; a wrong token fails the tag; a wrap moved to another grant, kind or tenant fails', () => {
  const { grant } = setup();
  const a = grant();
  const b = grant(T1, 'zc_other');
  const wa = a.grant.session_wraps!;
  // Without the token: every other value that is at hand (hashes, ids, the other grant's tokens) fails.
  for (const tok of [a.grant.access_hash, b.accessToken, b.refreshToken, `zeusi_at_${'A'.repeat(43)}`, a.refreshToken]) {
    assert.equal(openSessionWrap(T1, a.grant.grant_id, 'access', tok, wa), null);
  }
  // Moved to another grant: B's slot with A's wrap, opened with A's token, fails (grant id is in KEK and AAD).
  assert.equal(openSessionWrap(T1, b.grant.grant_id, 'access', a.accessToken, wa), null);
  // Moved to another kind: the access wrap in the refresh slot.
  assert.equal(openSessionWrap(T1, a.grant.grant_id, 'refresh', a.accessToken, { ...wa, refresh: wa.access }), null);
  assert.equal(openSessionWrap(T1, a.grant.grant_id, 'refresh', a.refreshToken, { ...wa, refresh: wa.access }), null);
  // Moved to another tenant, or the key_version changed.
  assert.equal(openSessionWrap(T2, a.grant.grant_id, 'access', a.accessToken, wa), null);
  assert.equal(openSessionWrap(T1, a.grant.grant_id, 'access', a.accessToken, { ...wa, key_version: 2 }), null);
  // One flipped bit anywhere fails the tag.
  const raw = Buffer.from(wa.access, 'base64url');
  raw[30] = raw[30]! ^ 1;
  assert.equal(openSessionWrap(T1, a.grant.grant_id, 'access', a.accessToken, { ...wa, access: raw.toString('base64url') }), null);
  assert.deepEqual(openSessionWrap(T1, a.grant.grant_id, 'access', a.accessToken, wa)!.dek, DEK, 'the right token still works');
});

test('C4 §7 item 9: refresh rewraps under the new pair and replaces the old wraps in the same write; old tokens no longer open anything', () => {
  const { store, grant, reseal, file } = setup();
  const g = grant();
  const old = g.grant.session_wraps!;
  const r = store.rotate(g.refreshToken, 'zc_client', reseal);
  assert.ok(r !== 'invalid');
  const w = r.grant.session_wraps!;
  assert.notEqual(w.access, old.access);
  assert.notEqual(w.refresh, old.refresh);
  assert.deepEqual(openSessionWrap(T1, g.grant.grant_id, 'access', r.accessToken, w)!.dek, DEK);
  assert.deepEqual(openSessionWrap(T1, g.grant.grant_id, 'refresh', r.refreshToken, w)!.dek, DEK);
  assert.equal(openSessionWrap(T1, g.grant.grant_id, 'refresh', g.refreshToken, w), null, 'old refresh opens nothing new');
  const text = file();
  assert.ok(!text.includes(old.access) && !text.includes(old.refresh), 'old wraps are gone from the file');
  assert.equal(openSessionDek(store, g.accessToken), null, 'the old access token is no longer live');
  assert.deepEqual(openSessionDek(store, r.accessToken)!.dek, DEK);
  // Without a reseal (or when it fails) the wraps are dropped, never kept under retired tokens.
  const r2 = store.rotate(r.refreshToken, 'zc_client');
  assert.ok(r2 !== 'invalid');
  assert.equal(r2.grant.session_wraps, undefined);
  assert.ok(!file().includes(w.access));
  const g3 = grant();
  const r3 = store.rotate(g3.refreshToken, 'zc_client', () => { throw new Error('boom'); });
  assert.ok(r3 !== 'invalid');
  assert.equal(r3.grant.session_wraps, undefined);
});

test('C4 §7 item 9: a reused refresh token revokes the grant AND its wraps, and fires the C7 hook once', () => {
  const { store, grant, reseal, file, ended } = setup();
  const g = grant();
  const r = store.rotate(g.refreshToken, 'zc_client', reseal);
  assert.ok(r !== 'invalid');
  const w = r.grant.session_wraps!;
  assert.equal(store.rotate(g.refreshToken, 'zc_client', reseal), 'invalid');
  assert.equal(openSessionDek(store, r.accessToken), null);
  assert.equal(store.sessionWrapsFor(r.accessToken), null);
  const text = file();
  assert.ok(!text.includes(w.access) && !text.includes(w.refresh), 'wraps deleted with the grant');
  assert.ok(!text.includes(g.grant.grant_id), 'the revoked grant is pruned from the file');
  assert.deepEqual(ended, [{ grantId: g.grant.grant_id, tenant: T1, reason: 'reused_refresh' }]);
});

test('C4 §7 item 9: an expired grant cannot unlock (access expiry, refresh expiry)', () => {
  const clock = { t: Date.parse('2026-11-19T10:00:00Z') };
  const { store, grant, reseal } = setup(clock);
  const g = grant();
  assert.ok(openSessionDek(store, g.accessToken));
  clock.t += ACCESS_TTL_MS + 1;
  assert.equal(openSessionDek(store, g.accessToken), null, 'expired access token: no wraps handed out');
  clock.t += REFRESH_TTL_MS;
  assert.equal(store.rotate(g.refreshToken, 'zc_client', reseal), 'invalid', 'expired refresh cannot rotate (or rewrap)');
});

test('C4: revoke, client revoke, revokeAll and revokeTenant ("log out everywhere") delete the wraps and fire the hook', () => {
  const { store, grant, file, ended } = setup();
  const a = grant(T1, 'zc_a');
  const b = grant(T1, 'zc_b');
  const c = grant(T2, 'zc_c');
  const d = grant(T2, 'zc_d');
  const e = grant(T2, 'zc_e');
  store.revokeToken(a.accessToken, null);
  assert.equal(store.revokeTenant(T1), 1);
  assert.equal(store.revokeClient('zc_c'), true, 'a client revoke takes its grants');
  assert.equal(store.revokeAll(), 2);
  const text = file();
  for (const g of [a, b, c, d, e]) {
    assert.equal(openSessionDek(store, g.accessToken), null);
    assert.ok(!text.includes(g.grant.session_wraps!.access));
  }
  assert.deepEqual(ended.map((x) => [x.grantId, x.tenant, x.reason]), [
    [a.grant.grant_id, T1, 'revoked'], [b.grant.grant_id, T1, 'tenant_revoked'], [c.grant.grant_id, T2, 'client_revoked'],
    [d.grant.grant_id, T2, 'revoked_all'], [e.grant.grant_id, T2, 'revoked_all'],
  ]);
  // A registered client revoke takes its grants' wraps too.
  const reg = store.registerClient({ clientName: 'x', redirectUris: ['http://localhost/callback'] });
  const f = grant(T1, reg.client_id);
  assert.equal(store.revokeClient(reg.client_id), true);
  assert.equal(openSessionDek(store, f.accessToken), null);
  assert.deepEqual(ended.at(-1), { grantId: f.grant.grant_id, tenant: T1, reason: 'client_revoked' });
});

test('C4: team is refused (no session wrap for a team or legacy grant; the envelope refuses the tenant)', () => {
  const { store } = setup();
  assert.throws(() => store.createGrant({
    clientId: 'zc_x', subject: 'github:1', login: 'u', tenant: 'work', seal: (gid, at, rt) => sealSessionWraps(T1, gid, at, rt, DEK, 1),
  }), OAuthStoreError);
  assert.throws(() => sealSessionWraps('work', 'abcdefghijkl', `zeusi_at_${'A'.repeat(43)}`, `zeusi_rt_${'A'.repeat(43)}`, DEK, 1));
  const plain = store.createGrant({ clientId: 'zc_x', subject: 'github:1', login: 'u', tenant: 'work' });
  assert.equal(plain.grant.session_wraps, undefined);
  assert.equal(store.sessionWrapsFor(plain.accessToken), null);
});
