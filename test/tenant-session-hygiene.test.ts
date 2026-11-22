// U1 (docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md): session hygiene for the
// workspace logins, on PGlite with the real migrations and roles (test/helpers/tenant-fixture.ts:
// logins emulated with SET SESSION AUTHORIZATION, so SET ROLE checks real membership).
//
// The live failure: behind a transaction pooler, the session-level SET ROLE / search_path of one
// tool call stayed on the server connection, so the next client (the catalog check, or another
// workspace) ran as that workspace role. pooledLogin() reproduces it: it hands back the shared
// session exactly as the previous user left it and its close() does nothing.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { tenantRole } from '../src/tenant-ddl.ts';
import { closeClean, SESSION_RESET_SQL, TenantDirectory, TenantError, TenantRouter } from '../src/tenants.ts';
import { asLogin, asOwner, plantInWorkspace, pooledLogin, sessionState, tenantTestDb } from './helpers/tenant-fixture.ts';

const A_MARKER = 'numbatworkspacea';
let db: Db;
let A: string;
let B: string;
let defaultPath: string;

before(async () => {
  db = await tenantTestDb();
  const dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  A = ((await dir.provision('github:301')) as { tenantId: string }).tenantId;
  B = ((await dir.provision('github:302')) as { tenantId: string }).tenantId;
  await plantInWorkspace(db, A, A_MARKER);
  defaultPath = await asOwner(db, async () => (await sessionState(db)).path);
});
after(async () => db.close());

/** What tenant A's tool call left on the server connection before this fix. */
const dirtyFromA = () => `SET ROLE "${tenantRole(A)}"; SET search_path = "${A}", public; SET default_transaction_read_only = on`;

test('hygiene: a catalog check on a connection left as workspace A (pooled leak) still reads the catalog: active, not 42501 / 503', async () => {
  const router = new TenantRouter({ connectRuntime: pooledLogin(db, 'zeusi_tenant_rt', { dirty: dirtyFromA }), cacheMs: 0 });
  try {
    assert.equal(await router.check(B), 'active');
    assert.equal(await router.check(A), 'active');
    assert.equal(await router.check(`zt_${'q'.repeat(26)}`), 'unknown');
    // And check() itself leaves nothing behind for the next client of that server connection.
    const s = await sessionState(db);
    assert.deepEqual(s, { cu: 'zeusi_tenant_rt', su: 'zeusi_tenant_rt', path: defaultPath, ro: 'off' });
  } finally {
    await asOwner(db, async () => {});
  }
});

test('hygiene: open(B) on a connection left dirty by A is bound to B only (never A), and close() leaves current_user = session_user, default search_path', async () => {
  const router = new TenantRouter({ connectRuntime: pooledLogin(db, 'zeusi_tenant_rt', { dirty: dirtyFromA }), cacheMs: 0 });
  try {
    const s = await router.open(B);
    const who = (await s.query<{ cu: string; su: string; path: string }>(`SELECT current_user::text AS cu, session_user::text AS su, current_setting('search_path') AS path`)).rows[0]!;
    assert.equal(who.cu, tenantRole(B));
    assert.equal(who.su, 'zeusi_tenant_rt');
    assert.ok(who.path.includes(B) && !who.path.includes(A), 'search_path names B, never A');
    // The translating Db reads B's (empty) schema; A's row is not reachable through it.
    assert.equal((await s.query<{ n: number }>('SELECT count(*)::int AS n FROM zeusi.chunks')).rows[0]!.n, 0);
    await assert.rejects(db.query(`SELECT text FROM "${A}".chunks`), /permission denied/);
    await s.close();
    assert.deepEqual(await sessionState(db), { cu: 'zeusi_tenant_rt', su: 'zeusi_tenant_rt', path: defaultPath, ro: 'off' });
  } finally {
    await asOwner(db, async () => {});
  }
});

test('hygiene: open(A) then open(B) on ONE pooled server connection: the second never sees the first workspace', async () => {
  const router = new TenantRouter({ connectRuntime: pooledLogin(db, 'zeusi_tenant_rt'), cacheMs: 0 });
  try {
    const a = await router.open(A);
    assert.equal((await a.query<{ n: number }>('SELECT count(*)::int AS n FROM zeusi.chunks')).rows[0]!.n, 1);
    await a.close();
    assert.deepEqual(await sessionState(db), { cu: 'zeusi_tenant_rt', su: 'zeusi_tenant_rt', path: defaultPath, ro: 'off' });
    const b = await router.open(B);
    const rows = (await b.query<{ text: string }>('SELECT text FROM zeusi.chunks')).rows;
    assert.deepEqual(rows, []);
    await b.close();
    // A tool call that failed mid-transaction: close() still rolls back and resets.
    const c = await router.open(B);
    await c.exec('BEGIN READ ONLY');
    await assert.rejects(c.query('SELECT 1/0'));
    await c.close();
    assert.deepEqual(await sessionState(db), { cu: 'zeusi_tenant_rt', su: 'zeusi_tenant_rt', path: defaultPath, ro: 'off' });
  } finally {
    await asOwner(db, async () => {});
  }
});

test('hygiene: the provisioner session is reset on acquire too (a dirty admin connection still looks up and provisions)', async () => {
  // The provisioner holds ADMIN (not SET) on workspace roles (PostgreSQL 16+), so its own leak is
  // search_path and the read-only default: the latter would make provisioning fail without a reset.
  const dirtyAdmin = () => `SET search_path = "${A}", public; SET default_transaction_read_only = on`;
  const dir = new TenantDirectory({ connectAdmin: pooledLogin(db, 'zeusi_tenant_admin', { dirty: dirtyAdmin }) });
  try {
    assert.equal((await dir.lookup('github:302'))?.tenantId, B);
    const c = await dir.provision('github:303');
    assert.equal(c.kind, 'created');
    assert.deepEqual(await sessionState(db), { cu: 'zeusi_tenant_admin', su: 'zeusi_tenant_admin', path: defaultPath, ro: 'off' });
  } finally {
    await asOwner(db, async () => {});
  }
});

/** A fake session: records every statement; `failOn` makes matching exec / query throw. */
function fakeSession(o: { failOn?: RegExp; who?: { cu: string; su: string } } = {}) {
  const log: string[] = [];
  let closed = 0;
  const db: Db = {
    label: 'fake',
    async query<T>(sql: string) {
      log.push(sql);
      if (o.failOn?.test(sql)) throw Object.assign(new Error('boom secret-host:5432'), { code: '42501' });
      if (/current_user::text AS cu, session_user::text AS su$/.test(sql.trim())) return { rows: [(o.who ?? { cu: 'zeusi_tenant_rt', su: 'zeusi_tenant_rt' }) as T] };
      return { rows: [{ status: 'active', tenant_id: 'x' } as T] };
    },
    async exec(sql: string) {
      log.push(sql);
      if (o.failOn?.test(sql)) throw Object.assign(new Error('boom secret-host:5432'), { code: '25P02' });
    },
    async close() {
      closed++;
    },
  };
  return { db, log, closed: () => closed };
}

test('hygiene: a reset that fails on acquire -> TenantError (no data, nothing queried after), and the session is closed', async () => {
  for (const op of ['check', 'open'] as const) {
    const f = fakeSession({ failOn: /^RESET ROLE/ });
    const router = new TenantRouter({ connectRuntime: async () => f.db, cacheMs: 0 });
    const err = await (op === 'check' ? router.check(B) : router.open(B)).then(() => null, (e: unknown) => e);
    assert.ok(err instanceof TenantError, `${op}: ${String(err)}`);
    assert.ok(!String((err as Error).message).includes('secret-host'), 'no internals in the message');
    assert.equal(f.closed(), 1, `${op}: closed once`);
    assert.ok(!f.log.some((s) => /zeusi_tenants\.tenants|SET ROLE "/.test(s)), `${op}: nothing read or set after a failed reset`);
  }
});

test('hygiene: a session that is still another role after reset is refused (fail closed), never used', async () => {
  const f = fakeSession({ who: { cu: tenantRole(A), su: 'zeusi_tenant_rt' } });
  const router = new TenantRouter({ connectRuntime: async () => f.db, cacheMs: 0 });
  await assert.rejects(router.check(B), TenantError);
  await assert.rejects(router.open(B), TenantError);
  const g = fakeSession({ who: { cu: 'zeusi_tenant_admin', su: 'zeusi_tenant_admin' } });
  await assert.rejects(new TenantRouter({ connectRuntime: async () => g.db }).check(B), TenantError, 'the wrong login is refused too');
  assert.ok(!f.log.some((s) => /zeusi_tenants\.tenants/.test(s)) && !g.log.some((s) => /zeusi_tenants\.tenants/.test(s)));
});

test('hygiene: close never throws and a failing reset on close never masks the original error', async () => {
  const f = fakeSession({ failOn: /^(ROLLBACK|RESET ROLE)/ });
  await closeClean(f.db, true); // resolves
  assert.equal(f.closed(), 1);
  // check(): the catalog read fails; the reset on close fails too; the caller still gets the check failure.
  let n = 0;
  const g = fakeSession();
  const flaky: Db = {
    ...g.db,
    query: (sql, p) => (/zeusi_tenants\.tenants/.test(sql) ? Promise.reject(new Error('catalog down')) : g.db.query(sql, p)),
    exec: async (sql) => {
      if (sql === SESSION_RESET_SQL && n++ > 0) throw new Error('reset on close failed');
      return g.db.exec(sql);
    },
    close: () => g.db.close(),
  };
  const router = new TenantRouter({ connectRuntime: async () => flaky, cacheMs: 0 });
  await assert.rejects(router.check(B), (e: Error) => e instanceof TenantError && e.message === 'workspace check failed');
  assert.equal(g.closed(), 1);
  // open(): the status read fails; reset-on-close failure does not replace the TenantError.
  n = 0;
  await assert.rejects(router.open(B), (e: Error) => e instanceof TenantError && e.message === 'workspace session failed');
  assert.equal(g.closed(), 2);
});

test('hygiene: every close path of a real session resets (check, open + close, open refused) and the order is ROLLBACK, RESET, close', async () => {
  const f = fakeSession();
  const router = new TenantRouter({ connectRuntime: async () => f.db, cacheMs: 0 });
  await router.check(B);
  assert.equal(f.log[0], SESSION_RESET_SQL, 'reset first on acquire');
  assert.equal(f.log.at(-1), SESSION_RESET_SQL, 'reset last before close');
  f.log.length = 0;
  // open(): the fake has no verification row shape, so the session is refused; it is still reset + closed.
  await assert.rejects(router.open(B));
  assert.deepEqual(f.log.slice(-2), ['ROLLBACK', SESSION_RESET_SQL]);
  assert.equal(f.closed(), 2);
});
