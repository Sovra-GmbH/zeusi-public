// U4 + U6 (docs/plans/2026-11-18-workspace-write-import-plan.md KTD1, KTD2, KTD7, R7): own-workspace
// writes end to end on the hosted handler (127.0.0.1, FAKE GitHub, PGlite with the real roles and the
// writer login). Every attack in the brief is tried through the real /mcp endpoint: a forged tenant
// (argument, header), another workspace's preview id, a read-only grant, the team bearer tokens and a
// the team grant, SQL / search_path text and schema-qualified names in the imported text. Nothing may
// reach another workspace or the zeusi schema.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { GRANT_SCOPE_READ, GRANT_SCOPE_WORKSPACE_WRITE } from '../src/mcp-oauth-store.ts';
import { WORKSPACE_WRITE_TOOL_NAMES } from '../src/mcp-server.ts';
import { TENANT_ID_RE } from '../src/tenant-ddl.ts';
import { WS_AUDIT_FIELDS } from '../src/workspace-audit.ts';
import { PREVIEW_UNKNOWN, WRITES_OFF } from '../src/workspace-write.ts';
import { FILL_MEMORY_COMING, FILL_MEMORY_OFFER, RECONNECT_TO_FILL } from '../src/about.ts';
import {
  callTool, LIST, mcpPost, mintStatic, refresh, serviceHome, signIn, startTenantHosted, toolJson, type Resp, type TenantHarness,
} from './helpers/hosted-tenants.ts';
import { asOwner, plantTeam, TEAM_MARKER, tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let h: TenantHarness;
let staticRead: { token: string };
let staticWrite: { token: string };

before(async () => {
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  staticRead = await mintStatic('read');
  staticWrite = await mintStatic('write');
  const s1 = staticRead as Awaited<ReturnType<typeof mintStatic>>;
  const s2 = staticWrite as Awaited<ReturnType<typeof mintStatic>>;
  h = await startTenantHosted({
    db, home: serviceHome(), limits: { signupPerIp: 50, signupGlobal: 50 }, writer: 'on', tokensRows: [s1.row, s2.row], writeService: 'zeusi_decision',
    wsLimits: { preview: 6, commit: 6, sync: 6 },
  });
});
after(async () => {
  await h.close();
  await db.close();
});

const tenantOf = (login: string) => h.store.list().grants.filter((g) => g.login === login).at(-1)!.tenant;
const notesIn = (schema: string, like: string) => asOwner(db, async () =>
  (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${schema}".notes WHERE body LIKE $1`, [`%${like}%`])).rows[0]!.n);
const teamLike = (like: string) => asOwner(db, async () =>
  (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes WHERE body LIKE $1`, [`%${like}%`])).rows[0]!.n);
const tools = async (token: string) => ((JSON.parse((await mcpPost(h.port, token, LIST)).body) as { result: { tools: Array<{ name: string }> } }).result.tools).map((t) => t.name);
const call = (token: string, name: string, args: Record<string, unknown>, extra: Record<string, string> = {}) => mcpPost(h.port, token, callTool(name, args), extra);
const doc = (text: string, title?: string) => ({ kind: 'markdown', text, ...(title ? { title } : {}) });

let A: { access: string; refresh: string; clientId: string; tenant: string };
let B: { access: string; refresh: string; clientId: string; tenant: string };

test('single consent: a personal sign-in offers read + write-own-workspace once; the grant carries zeusi.workspace_write; the team consent unchanged and read-only', async () => {
  const a = await signIn(h, 'gh-stranger');
  assert.match(a.consent.body, /Allow access to your Zeusi workspace\?/);
  assert.match(a.consent.body, /only into your own workspace, and only after it shows you a preview and you say yes/);
  assert.match(a.consent.body, /never change anyone else's workspace/);
  A = { ...a, tenant: tenantOf('stranger') };
  const b = await signIn(h, 'gh-b');
  B = { ...b, tenant: tenantOf('user-b') };
  assert.ok(TENANT_ID_RE.test(A.tenant) && TENANT_ID_RE.test(B.tenant) && A.tenant !== B.tenant);
  const grants = h.store.list().grants;
  assert.equal(grants.length, 2);
  const s = await signIn(h, 'gh-operator');
  assert.match(s.consent.body, /Allow read-only access to Zeusi\?/);
  assert.ok(!/workspace/i.test(s.consent.body.replace(/Zeusi workspace/g, '')), 'no personal block for the team');
  // Scope in the store: write only on the two personal grants.
  const raw = (h.store as unknown as { doc: { grants: Array<{ tenant?: string; scope: string }> } }).doc.grants;
  assert.deepEqual(raw.map((g) => g.scope), [GRANT_SCOPE_WORKSPACE_WRITE, GRANT_SCOPE_WORKSPACE_WRITE, GRANT_SCOPE_READ]);
  // GitHub scopes and allow_signup are untouched by this PR (src/mcp-oauth-github.ts is not in the diff).
});

test('tools/list: the write tools only on a personal write grant; never for a team grant, a static read or write bearer', async () => {
  for (const n of WORKSPACE_WRITE_TOOL_NAMES) assert.ok((await tools(A.access)).includes(n), n);
  const team = await signIn(h, 'gh-login');
  for (const tok of [team.access, staticRead.token, staticWrite.token]) {
    const names = await tools(tok);
    for (const n of WORKSPACE_WRITE_TOOL_NAMES) assert.ok(!names.includes(n), n);
  }
});

test('preview -> commit round trip through /mcp lands in A only; a second commit is a no-op; B and the team untouched; SQL / schema names stored as text', async () => {
  const marker = 'platypusimportmarker';
  const tricky = `${marker} zeusi.notes "${B.tenant}".notes '; SET search_path = zeusi, "${B.tenant}"; INSERT INTO zeusi.notes VALUES (1); --`;
  const p = toolJson(await call(A.access, 'zeusi_import_preview', { documents: [doc(`# Plan\n\n${tricky}\n`, 'Plan'), doc('We review on Thursdays.\n')] }));
  assert.equal(p.isError, false, p.text);
  const id = String(p.json!['preview_id']);
  assert.equal(p.json!['saved'], false);
  assert.equal(await notesIn(A.tenant, marker), 0, 'preview wrote nothing');
  const c1 = toolJson(await call(A.access, 'zeusi_import_commit', { preview_id: id, confirm: true }));
  assert.equal(c1.isError, false, c1.text);
  assert.equal(c1.json!['already_committed'], false);
  assert.equal(await notesIn(A.tenant, marker), 1);
  const c2 = toolJson(await call(A.access, 'zeusi_import_commit', { preview_id: id, confirm: true }));
  assert.equal(c2.json!['already_committed'], true);
  assert.equal(await notesIn(A.tenant, marker), 1);
  assert.equal(await notesIn(B.tenant, marker), 0);
  assert.equal(await teamLike(marker), 0);
  assert.ok(await teamLike(TEAM_MARKER) > 0, 'the shared-schema rows intact');
  // A can read its own import back (lexical search in its own workspace).
  const s = toolJson(await call(A.access, 'zeusi_search', { query: marker }));
  assert.ok(s.text.includes(marker));
  // B cannot.
  assert.ok(!toolJson(await call(B.access, 'zeusi_search', { query: marker })).text.includes(marker));
});

test('a preview id from another workspace (B commits A\'s) is refused with the static text; nothing written', async () => {
  const marker = 'echidnaimportmarker';
  const p = toolJson(await call(A.access, 'zeusi_import_preview', { documents: [doc(`${marker} notes\n`)] }));
  const id = String(p.json!['preview_id']);
  const r = toolJson(await call(B.access, 'zeusi_import_commit', { preview_id: id, confirm: true }));
  assert.equal(r.isError, true);
  assert.equal(r.text, PREVIEW_UNKNOWN);
  assert.equal(await notesIn(A.tenant, marker), 0);
  assert.equal(await notesIn(B.tenant, marker), 0);
  // No commit without a preview, and no commit without confirm: true.
  assert.equal(toolJson(await call(A.access, 'zeusi_import_commit', { preview_id: 'Z'.repeat(43), confirm: true })).text, PREVIEW_UNKNOWN);
  for (const bad of [{ preview_id: id }, { preview_id: id, confirm: false }, { preview_id: id, confirm: 'yes' }]) {
    assert.equal(toolJson(await call(A.access, 'zeusi_import_commit', bad)).isError, true);
  }
  assert.equal(await notesIn(A.tenant, marker), 0);
});

test('forged tenant: a tenant argument is refused by the schema; a tenant header is ignored; writes land in the caller\'s own workspace only', async () => {
  const marker = 'quollforgedmarker';
  for (const extraArg of [{ tenant: B.tenant }, { tenant_id: B.tenant }, { workspace: 'team' }, { schema: 'zeusi' }]) {
    const r = toolJson(await call(A.access, 'zeusi_import_preview', { documents: [doc(`${marker}\n`)], ...extraArg }));
    assert.equal(r.isError, true, JSON.stringify(extraArg));
    assert.ok(!r.text.includes(B.tenant), 'never echoed');
    const s = toolJson(await call(A.access, 'zeusi_sync_batch', { items: [], deleted: ['j/2026-11-17-x.md'], ...extraArg }));
    assert.equal(s.isError, true);
  }
  const hdrs = { 'x-zeusi-tenant': B.tenant, 'x-tenant-id': B.tenant, 'fly-client-ip': '198.51.100.99' };
  const item = { path: 'journal/2026-11-17-forged.md', text: `---\nproject: journal\nkind: memory\ndate: 2026-11-17\ntitle: Forged\nsource: test\n---\n${marker}\n` };
  const r = toolJson(await call(A.access, 'zeusi_sync_batch', { items: [item] }, hdrs));
  assert.equal(r.isError, false, r.text);
  assert.equal(await notesIn(A.tenant, marker), 1);
  assert.equal(await notesIn(B.tenant, marker), 0);
  assert.equal(await teamLike(marker), 0);
});

test('read-only personal grant (pre-PR-2 / legacy): write tools 403, not listed; refresh never upgrades; a new sign-in does', async () => {
  const legacy = h.store.createGrant({ clientId: A.clientId, subject: 'github:105', login: 'stranger', tenant: A.tenant });
  assert.equal(legacy.grant.scope, GRANT_SCOPE_READ);
  for (const n of WORKSPACE_WRITE_TOOL_NAMES) assert.ok(!(await tools(legacy.accessToken)).includes(n));
  const r = await call(legacy.accessToken, 'zeusi_import_preview', { documents: [doc('x\n')] });
  assert.equal(r.status, 403);
  assert.deepEqual(JSON.parse(r.body), { error: 'forbidden' });
  const rotated = await refresh(h, A.clientId, legacy.refreshToken);
  assert.equal((await call(rotated.access, 'zeusi_import_preview', { documents: [doc('x\n')] })).status, 403, 'rotation keeps read-only');
  // Reads still work on the legacy grant.
  assert.equal(toolJson(await call(rotated.access, 'zeusi_startup', {})).isError, false);
  const again = await signIn(h, 'gh-stranger');
  assert.ok((await tools(again.access)).includes('zeusi_import_preview'), 're-consent upgrades');
});

test('the team credentials can never use the write tools: static read / write bearer and a team grant get 403; log_decision gate unchanged', async () => {
  const team = await signIn(h, 'gh-gmail');
  for (const tok of [staticRead.token, staticWrite.token, team.access]) {
    for (const n of WORKSPACE_WRITE_TOOL_NAMES) {
      const r = await call(tok, n, n === 'zeusi_import_commit' ? { preview_id: 'Z'.repeat(43), confirm: true } : { documents: [doc('x\n')], items: [] });
      assert.equal(r.status, 403, `${n}`);
    }
  }
  // In a batch, one write-tool call refuses the whole request (nothing runs).
  const batch = await mcpPost(h.port, team.access, [callTool('zeusi_search', { query: 'x' }, 1), callTool('zeusi_sync_batch', { deleted: ['a/2026-11-17-a.md'] }, 2)]);
  assert.equal(batch.status, 403);
  // A personal write grant still cannot call the team decision writer (unchanged 401).
  assert.equal((await call(A.access, 'zeusi_log_decision', {})).status, 401);
});

test('rate limits per grant and per tenant: static 429 + Retry-After, audited; the other workspace is unaffected', async () => {
  const before0 = h.wsAudits.length;
  let last: Resp | null = null;
  for (let i = 0; i < 8; i++) {
    last = await call(B.access, 'zeusi_sync_batch', { deleted: ['journal/2026-01-01-gone.md'] });
    if (last.status === 429) break;
  }
  assert.equal(last!.status, 429);
  assert.deepEqual(JSON.parse(last!.body), { error: 'rate_limited' });
  assert.match(String(last!.headers['retry-after']), /^[1-9][0-9]*$/);
  assert.ok(h.wsAudits.slice(before0).some((l) => (JSON.parse(l) as { outcome: string }).outcome === 'rate_limited'));
  // A different grant of the SAME workspace is limited too (per tenant).
  const b2 = await signIn(h, 'gh-b');
  assert.equal((await call(b2.access, 'zeusi_sync_batch', { deleted: ['journal/2026-01-01-gone.md'] })).status, 429);
  // A is not.
  assert.equal((await call(A.access, 'zeusi_sync_batch', { deleted: ['journal/2026-01-01-gone.md'] })).status, 200);
});

test('audit lines: allowlisted fields only, subject is github:<id>, no token, no text, no preview id', () => {
  assert.ok(h.wsAudits.length > 5);
  for (const l of h.wsAudits) {
    assert.deepEqual(Object.keys(JSON.parse(l) as object), [...WS_AUDIT_FIELDS]);
    for (const leak of [A.access, B.access, A.refresh, 'platypus', 'quoll', 'stranger', 'zeusi_at_', 'journal/']) assert.ok(!l.includes(leak), leak);
    const o = JSON.parse(l) as { github_subject: string | null; tenant_id: string | null };
    assert.ok(o.github_subject === null || /^github:\d+$/.test(o.github_subject));
    assert.ok(o.tenant_id === A.tenant || o.tenant_id === B.tenant);
  }
  // Request log lines name the new tools by name (allowlisted), never their arguments.
  assert.ok(h.logs.some((l) => l.includes('"tool":"zeusi_import_preview"')));
  assert.ok(!h.logs.some((l) => l.includes('platypus') || l.includes(A.access)));
});

test('welcome form B only when filling works: a new write-grant workspace gets form B (startup welcome, onboarding next, about); a read-only grant on this server gets form A + how to reconnect', async () => {
  const c = await signIn(h, 'gh-n1'); // a brand-new, empty workspace with a write grant
  const st = toolJson(await call(c.access, 'zeusi_startup', {}));
  assert.ok(String(st.json!['welcome']).includes(FILL_MEMORY_OFFER), 'startup welcome is form B');
  assert.ok(String(st.json!['message']).includes(FILL_MEMORY_OFFER));
  const ob = toolJson(await call(c.access, 'zeusi_onboarding_status', {}));
  assert.ok(String(ob.json!['next']).includes(FILL_MEMORY_OFFER) && String(ob.json!['next']).includes('zeusi_import_preview'));
  const about = JSON.parse((await mcpPost(h.port, c.access, { jsonrpc: '2.0', id: 9, method: 'resources/read', params: { uri: 'zeusi://about' } })).body) as { result: { contents: Array<{ text: string }> } };
  assert.ok(about.result.contents[0]!.text.includes(FILL_MEMORY_OFFER));
  const init = JSON.parse((await mcpPost(h.port, c.access, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } })).body) as { result: { instructions: string } };
  assert.match(init.result.instructions, /zeusi_import_preview/);
  // The same workspace through a read-only grant: form A, plus the upgrade path.
  const ro = h.store.createGrant({ clientId: c.clientId, subject: 'github:5001', login: 'newbie-1', tenant: h.store.list().grants.filter((g) => g.login === 'newbie-1').at(-1)!.tenant });
  const ob2 = toolJson(await call(ro.accessToken, 'zeusi_onboarding_status', {}));
  assert.ok(String(ob2.json!['next']).includes(FILL_MEMORY_COMING));
  assert.ok(String(ob2.json!['next']).includes(RECONNECT_TO_FILL));
  assert.ok(!JSON.stringify(ob2.json).includes(FILL_MEMORY_OFFER));
  assert.ok(String(toolJson(await call(ro.accessToken, 'zeusi_startup', {})).json!['welcome']).includes(FILL_MEMORY_COMING));
});

test('writes off on the server (grant has write, no writer): tools answer the friendly WRITES_OFF; reads unaffected; nothing saved', async () => {
  const db2 = await tenantTestDb();
  const h2 = await startTenantHosted({ db: db2, home: serviceHome(), limits: { signupPerIp: 50, signupGlobal: 50 }, writer: 'grant-only' });
  try {
    const s = await signIn(h2, 'gh-stranger');
    const r = toolJson(await call2(h2, s.access, 'zeusi_import_preview', { documents: [doc('x\n')] }));
    assert.equal(r.isError, true);
    assert.equal(r.text, WRITES_OFF);
    assert.ok(h2.wsAudits.some((l) => (JSON.parse(l) as { outcome: string; action: string }).outcome === 'writes_off'), 'audited');
    const st = toolJson(await call2(h2, s.access, 'zeusi_startup', {}));
    assert.equal(st.isError, false);
    assert.ok(String(st.json!['welcome']).includes(FILL_MEMORY_COMING), 'form A while writes are off');
    assert.ok(!st.text.includes(FILL_MEMORY_OFFER));
  } finally {
    await h2.close();
    await db2.close();
  }
});

const call2 = (hh: TenantHarness, token: string, name: string, args: Record<string, unknown>) => mcpPost(hh.port, token, callTool(name, args));
