// U4 (docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md): the first run of a brand-new,
// EMPTY personal workspace, end to end over the hosted handler (PGlite, real provisioning, real
// workspace sessions; test/helpers/hosted-tenants.ts). Every tool the connection lists (enumerated
// from tools/list, so a new tool without a case here fails), every resource and prompt: a friendly
// empty state that says what is empty and what to do next, never an error, a SQLSTATE or a stack.
// An unknown id / address: an actionable "not found in your workspace". An infra failure (router
// throws): an actionable message naming the one URL, retry / reconnect, no internals.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import {
  aboutMarkdown, FILL_MEMORY_LINE, MCP_URL, WELCOME_MARKDOWN, WELCOME_OWN, WORKSPACE_UNAVAILABLE,
} from '../src/about.ts';
import { RESOURCE_NOT_FOUND } from '../src/mcp-prompts.ts';
import { CONTEXT_EMPTY_PERSONAL, SEARCH_EMPTY_PERSONAL, STARTUP_EMPTY_PERSONAL } from '../src/mcp-server.ts';
import { SEARCH_SCOPES } from '../src/search.ts';
import { TenantError } from '../src/tenants.ts';
import { callTool, INIT, LIST, mcpPost, mintStatic, serviceHome, signIn, startTenantHosted, toolJson, type Resp, type TenantHarness } from './helpers/hosted-tenants.ts';
import { tenantTestDb } from './helpers/tenant-fixture.ts';
import { hasNonRoleOperatorAddress } from './helpers/owner-terms.ts';

let db: Db;
let home: string;
let h: TenantHarness;
let tok: string;
let teamRead: string;

before(async () => {
  db = await tenantTestDb();
  home = serviceHome();
  const read = await mintStatic('read');
  teamRead = read.token;
  h = await startTenantHosted({
    db, home, tokensRows: [read.row], routerCacheMs: 0, limits: { signupPerIp: 50, signupGlobal: 50 }, hostedLimits: { perToken: 100_000, global: 100_000 },
  });
  tok = (await signIn(h, 'gh-stranger')).access;
});
after(async () => {
  await h.close();
  await db.close();
});

/** Nothing internal ever reaches the user: no SQLSTATE, pg error text, class names, stacks or workspace ids. */
function assertNoInternals(text: string, what: string): void {
  for (const re of [/SQLSTATE/i, /error \[[0-9A-Z]{5}\]/, /\b(TenantError|TenantRefused|SearchRefused|ToolRefused)\b/, /\bat \S+\.(ts|js):\d+/,
    /permission denied/i, /zt_[a-z2-7]{26}/, /\bECONN|secret-host|-pooler/, /workspace (session|check) failed/]) {
    assert.doesNotMatch(text, re, `${what}: ${re}`);
  }
}

const rpc = (method: string, params: Record<string, unknown> = {}, id = 7) => ({ jsonrpc: '2.0', id, method, params });
const result = (r: Resp) => (JSON.parse(r.body) as { result?: Record<string, unknown>; error?: { message?: string } });

async function listedTools(port: number, token: string): Promise<string[]> {
  const r = await mcpPost(port, token, LIST);
  assert.equal(r.status, 200, r.body);
  return ((result(r).result?.['tools'] ?? []) as Array<{ name: string }>).map((t) => t.name);
}

/** One or more argument sets per tool the personal connection lists. A listed tool without a case fails the test. */
const READ_CASES: Record<string, Array<Record<string, unknown>>> = {
  zeusi_startup: [{}, { days: 90 }],
  startup: [{}],
  zeusi_search: [
    { query: 'what can zeusi do' }, { query: 'project launch plan' }, { query: 'anything at all', hybrid: false },
    ...SEARCH_SCOPES.map((scope) => ({ query: 'decisions about pricing', scope })),
  ],
  search: [{ query: 'what is zeusi' }],
  zeusi_context_for_task: [{ task: 'plan the launch for next week' }, ...SEARCH_SCOPES.map((scope) => ({ task: 'ship the release', scope }))],
  context_for_task: [{ task: 'write the weekly report' }],
  prime: [{ task: 'refactor the billing module' }],
  zeusi_onboarding_status: [{}, ...SEARCH_SCOPES.map((scope) => ({ scope }))],
  onboarding_status: [{}],
};

test('first run: every read tool and alias on an empty workspace returns a friendly empty state (enumerated from tools/list)', async () => {
  assert.equal((await mcpPost(h.port, tok, INIT)).status, 200);
  const names = await listedTools(h.port, tok);
  assert.ok(names.length >= 10, names.join(','));
  assert.ok(!names.some((n) => /log_decision/.test(n)), 'no write tool in a personal workspace');
  const uncovered = names.filter((n) => !(n in READ_CASES) && n !== 'zeusi_search_feedback');
  assert.deepEqual(uncovered, [], 'every listed tool has a first-run case here');
  for (const name of names) {
    if (name === 'zeusi_search_feedback') continue;
    for (const args of READ_CASES[name]!) {
      const r = await mcpPost(h.port, tok, callTool(name, args));
      assert.equal(r.status, 200, `${name}: ${r.body}`);
      const t = toolJson(r);
      const what = `${name} ${JSON.stringify(args)}`;
      assert.equal(t.isError, false, `${what}: ${t.text}`);
      assert.ok(t.json, `${what}: JSON body`);
      assertNoInternals(t.text, what);
      const j = t.json!;
      if (/startup/.test(name)) {
        assert.equal(j['empty'], true, what);
        assert.equal(j['message'], STARTUP_EMPTY_PERSONAL, what);
        assert.equal(j['welcome'], WELCOME_MARKDOWN, what);
        assert.match(String(j['welcome']), /^# Hello, I'm Zeusi\./);
        assert.deepEqual([j['rules'], j['decisions'], j['focus']], [[], [], []], what);
      } else if (/search/.test(name)) {
        assert.equal(j['message'], SEARCH_EMPTY_PERSONAL, what);
        assert.deepEqual([j['hits'], j['decisions']], [[], []], what);
        assert.ok(Array.isArray(j['about']), `${what}: about list present`);
      } else if (/context_for_task|prime/.test(name)) {
        assert.equal(j['message'], CONTEXT_EMPTY_PERSONAL, what);
        assert.deepEqual(j['items'], [], what);
      } else {
        assert.equal(j['empty'], true, what);
        assert.match(String(j['message']), /empty: no rules, locks, focus, decisions or notes yet/, what);
        assert.ok(String(j['next']).includes(FILL_MEMORY_LINE), `${what}: says what to do next`);
      }
      for (const m of ['message']) if (j[m] !== undefined) assert.match(String(j[m]), /empty|nothing/i, `${what}: says what is empty`);
    }
  }
});

test('first run: zeusi_search kind "about" returns the personal welcome sections (never the team\'s description), cited as zeusi://about#<slug>', async () => {
  for (const q of ['what can zeusi do', 'What can Zeusi do?', 'what is zeusi', 'own workspace', 'never store', 'filling your memory']) {
    const t = toolJson(await mcpPost(h.port, tok, callTool('zeusi_search', { query: q })));
    const about = t.json!['about'] as Array<{ source_uri: string; text: string }>;
    assert.ok(about.length > 0, q);
    for (const a of about) {
      assert.match(a.source_uri, /^zeusi:\/\/about#/);
      assert.doesNotMatch(a.text, /Work/, `${q}: no team-workspace description in a personal workspace`);
    }
  }
});

test('first run: an unknown id is an actionable "not found in your workspace" (feedback query_id, source_uri, zeusi:// address)', async () => {
  const unknown = toolJson(await mcpPost(h.port, tok, callTool('zeusi_search_feedback', { query_id: '00000000-0000-4000-8000-000000000000', source_uri: 'zeusi://about#hello', useful: true })));
  assert.equal(unknown.isError, true);
  assert.match(unknown.text, /unknown query_id: not found in your workspace/);
  assert.match(unknown.text, /Run the search again/);
  assertNoInternals(unknown.text, 'feedback unknown id');
  const s = toolJson(await mcpPost(h.port, tok, callTool('zeusi_search', { query: 'what can zeusi do' })));
  const qid = String(s.json!['query_id']);
  const wrong = toolJson(await mcpPost(h.port, tok, callTool('zeusi_search_feedback', { query_id: qid, source_uri: 'test:nope', useful: false })));
  assert.match(wrong.text, /not found in your workspace/);
  const hit = (s.json!['about'] as Array<{ source_uri: string }>)[0]!.source_uri;
  const okFb = toolJson(await mcpPost(h.port, tok, callTool('zeusi_search_feedback', { query_id: qid, source_uri: hit, useful: true })));
  assert.equal(okFb.isError, false, okFb.text);

  for (const uri of ['zeusi://notes/12345', 'zeusi://decision/999', 'zeusi://about#no-such-section']) {
    const r = result(await mcpPost(h.port, tok, rpc('resources/read', { uri })));
    assert.equal(r.error, undefined, uri);
    const text = String((r.result!['contents'] as Array<{ text: string }>)[0]!.text);
    assert.equal(text, RESOURCE_NOT_FOUND, uri);
    assert.ok(!text.includes('12345') && !text.includes('no-such-section'), 'the address is never echoed');
  }
  const part = result(await mcpPost(h.port, tok, rpc('resources/read', { uri: 'zeusi://about#your-workspace' })));
  assert.ok(String((part.result!['contents'] as Array<{ text: string }>)[0]!.text).includes(WELCOME_OWN));
});

test('first run: every listed resource and prompt answers; zeusi://about opens with the welcome (form A) and names the one URL', async () => {
  const res = result(await mcpPost(h.port, tok, rpc('resources/list')));
  const uris = ((res.result!['resources'] ?? []) as Array<{ uri: string }>).map((r) => r.uri);
  assert.deepEqual(uris, ['zeusi://about']);
  for (const uri of uris) {
    const r = result(await mcpPost(h.port, tok, rpc('resources/read', { uri })));
    assert.equal(r.error, undefined, uri);
    const text = String((r.result!['contents'] as Array<{ text: string }>)[0]!.text);
    assertNoInternals(text, uri);
    assert.ok(text.startsWith(WELCOME_MARKDOWN), 'the welcome comes first');
    for (const must of ["Hello, I'm Zeusi.", 'named after a cat', 'I never invent', 'zeusi_startup', 'zeusi_context_for_task', 'Locks are binding',
      'Every answer cites its source', 'A decision on record is not an approval', 'This workspace is your own', 'no invite is needed', 'another user\'s Zeusi sign-in cannot read it',
      'Secrets (passwords, API keys, tokens) or private client details', 'Filling your memory is coming', 'preview before anything is saved', `Server: ${MCP_URL}`]) {
      assert.ok(text.includes(must), `about: ${must}`);
    }
    assert.equal(hasNonRoleOperatorAddress(text), false, 'no non-role operator address');
    assert.doesNotMatch(text, /\bSovra\b/i, 'no company name');
    assert.doesNotMatch(text, /zeusi_log_decision/, 'read-only: the write tool is never named');
  }
  const tpl = result(await mcpPost(h.port, tok, rpc('resources/templates/list')));
  assert.deepEqual(((tpl.result!['resourceTemplates'] ?? []) as Array<{ uriTemplate: string }>).map((t) => t.uriTemplate), ['zeusi://{+path}']);
  const prompts = ((result(await mcpPost(h.port, tok, rpc('prompts/list'))).result!['prompts'] ?? []) as Array<{ name: string }>).map((p) => p.name);
  assert.deepEqual(prompts.sort(), ['onboarding', 'start-task']);
  for (const name of prompts) {
    const r = result(await mcpPost(h.port, tok, rpc('prompts/get', { name, arguments: name === 'start-task' ? { task: 'plan the week' } : {} })));
    assert.equal(r.error, undefined, name);
    assertNoInternals(JSON.stringify(r.result), name);
  }
});

test('first run: the team connections keep their about text and resources (no welcome, no lookup template)', async () => {
  const r = result(await mcpPost(h.port, teamRead, rpc('resources/read', { uri: 'zeusi://about' })));
  const text = String((r.result!['contents'] as Array<{ text: string }>)[0]!.text);
  assert.equal(text, aboutMarkdown(false));
  assert.ok(!text.includes("Hello, I'm Zeusi"));
  const tpl = result(await mcpPost(h.port, teamRead, rpc('resources/templates/list')));
  assert.deepEqual(tpl.result!['resourceTemplates'], []);
});

test('first run: an infra failure (router throws, or a query fails) is an actionable message naming the one URL, retry / reconnect, no internals', async () => {
  const pgFail = Object.assign(new Error('permission denied for schema zt_aaaaaaaaaaaaaaaaaaaaaaaaaa at secret-host'), { code: '42501' });
  const broken: Db = {
    label: 'broken', query: async () => { throw pgFail; }, exec: async () => { throw pgFail; }, close: async () => {},
  };
  for (const open of [
    async () => { throw new TenantError('workspace session failed'); },
    async () => broken,
  ]) {
    const out = await startTenantHosted({
      db, home, limits: { signupPerIp: 50, signupGlobal: 50 }, hostedLimits: { perToken: 100_000, global: 100_000 },
      routes: { check: async () => 'active', open, encState: async () => ({ status: 'active', encState: 'off' }) },
    });
    try {
      const t = (await signIn(out, 'gh-b')).access;
      const names = await listedTools(out.port, t);
      for (const name of names) {
        if (name === 'zeusi_search_feedback') continue;
        const r = toolJson(await mcpPost(out.port, t, callTool(name, READ_CASES[name]![0]!)));
        assert.equal(r.isError, true, name);
        assert.equal(r.text, WORKSPACE_UNAVAILABLE, name);
        assert.ok(r.text.includes(MCP_URL) && /Retry/.test(r.text) && /reconnect/.test(r.text), name);
        assertNoInternals(r.text, name);
      }
    } finally {
      await out.close();
    }
  }
  // The catalog check itself fails: HTTP 503 with the same actionable message, never the cause.
  const down = await startTenantHosted({
    db, home, limits: { signupPerIp: 50, signupGlobal: 50 },
    routes: { check: async () => { throw new Error('ECONNREFUSED secret-host:5432 SQLSTATE 42501'); }, open: async () => { throw new Error('x'); }, encState: async () => { throw new Error('x'); } },
  });
  try {
    const t = (await signIn(down, 'gh-b')).access;
    const r = await mcpPost(down.port, t, LIST);
    assert.equal(r.status, 503);
    assert.deepEqual(JSON.parse(r.body), { error: 'not_configured', message: WORKSPACE_UNAVAILABLE });
    assertNoInternals(r.body, '503');
  } finally {
    await down.close();
  }
});
