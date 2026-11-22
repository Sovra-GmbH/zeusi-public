// Drift guard for the site's startup terminal (site/index.html #first-run-demo, docs/plans/site-wow.md U3):
// boot the real hosted handler (PGlite, real provisioning, workspace writes on), sign in a brand-new GitHub
// identity, call zeusi_startup on its empty personal workspace, and require the site to show exactly that
// reply (rendered by test/helpers/site-terminal.ts). Any wording change on the server fails here until the
// site is updated with it.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { callTool, mcpPost, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { overclaims } from './helpers/overclaim.ts';
import { siteTerminalLines, terminalLines, type StartupReply } from './helpers/site-terminal.ts';
import { tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let h: TenantHarness;

before(async () => {
  db = await tenantTestDb({ writer: true });
  h = await startTenantHosted({ db, home: serviceHome(), limits: { signupPerIp: 50, signupGlobal: 50 }, writer: 'on' });
});
after(async () => {
  await h.close();
  await db.close();
});

test('site terminal: shows exactly the live zeusi_startup reply of a brand-new, empty personal workspace', async () => {
  const c = await signIn(h, 'gh-n9');
  const r = toolJson(await mcpPost(h.port, c.access, callTool('zeusi_startup', {})));
  assert.equal(r.isError, false, r.text);
  const j = r.json as unknown as StartupReply;
  assert.equal(j.workspace, 'personal');
  assert.equal(j.empty, true);
  assert.deepEqual(siteTerminalLines(), terminalLines(j));
  // Review r1 F2: the whole live reply (every field, not only the two the site shows) makes no over-claim.
  assert.deepEqual(overclaims(JSON.stringify(r.json)), [], 'live zeusi_startup reply');
});
