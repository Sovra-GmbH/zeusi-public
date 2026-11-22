// P2-4 (review of #31): a server with NO workspace writer issues READ-ONLY personal grants. The
// consent page offers reading only (no "Write:" line), the stored grant scope and the token response
// scope are zeusi.read, and a refresh never upgrades it. (The 'grant-only' harness in
// test/workspace-write-hosted.test.ts deliberately issues write grants; this is the plain writes-off server.)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { GRANT_SCOPE_READ } from '../src/mcp-oauth-store.ts';
import { WORKSPACE_WRITE_TOOL_NAMES } from '../src/mcp-server.ts';
import { TENANT_ID_RE } from '../src/tenant-ddl.ts';
import { LIST, mcpPost, refresh, serviceHome, signIn, startTenantHosted, type TenantHarness } from './helpers/hosted-tenants.ts';
import { tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let h: TenantHarness;

before(async () => {
  db = await tenantTestDb();
  h = await startTenantHosted({ db, home: serviceHome(), limits: { signupPerIp: 50, signupGlobal: 50 } }); // no `writer`: writes off
});
after(async () => {
  await h.close();
  await db.close();
});

test('writes off (no writer): a personal sign-in gets a read-only consent page, a zeusi.read grant and a zeusi.read token response', async () => {
  const a = await signIn(h, 'gh-stranger');
  assert.match(a.consent.body, /Allow read-only access to Zeusi\?/);
  assert.match(a.consent.body, /Your personal workspace/, 'still the personal workspace block');
  assert.doesNotMatch(a.consent.body, /Write:/, 'no Write: line');
  assert.doesNotMatch(a.consent.body, /preview and you say yes/);
  assert.equal(a.scope, GRANT_SCOPE_READ, 'token response scope');
  const raw = (h.store as unknown as { doc: { grants: Array<{ tenant?: string; scope: string; login: string }> } }).doc.grants;
  const g = raw.filter((x) => x.login === 'stranger');
  assert.equal(g.length, 1);
  assert.ok(TENANT_ID_RE.test(String(g[0]!.tenant)), 'a personal workspace grant');
  assert.equal(g[0]!.scope, GRANT_SCOPE_READ, 'stored grant scope');
  const r = await refresh(h, a.clientId, a.refresh);
  const names = ((JSON.parse((await mcpPost(h.port, r.access, LIST)).body) as { result: { tools: Array<{ name: string }> } }).result.tools).map((t) => t.name);
  for (const n of WORKSPACE_WRITE_TOOL_NAMES) assert.ok(!names.includes(n), n);
  assert.equal((h.store as unknown as { doc: { grants: Array<{ login: string; scope: string }> } }).doc.grants.find((x) => x.login === 'stranger')!.scope, GRANT_SCOPE_READ, 'refresh never upgrades');
});
