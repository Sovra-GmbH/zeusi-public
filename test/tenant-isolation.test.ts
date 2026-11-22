// U5 cross-tenant isolation (docs/plans/2026-11-18-open-signup-workspaces-plan.md R7-R10, AE3, AE4),
// end to end over the hosted handler: the shared-schema rows carrying a unique marker (including a walled
// one) in schema zeusi, workspace A with rows of its own, workspace B empty. A token bound to B
// calls every read tool, alias, prompt and resource with queries that match the team marker and
// A's marker: no response holds either, every withheld count is 0 (no side channel), and nothing in
// the request (headers, query string) can move it to another workspace. the team's static bearer
// tokens and legacy grants keep reading the team exactly as before.
// The database-level denials (search_path tricks, RPC, guessable ids by direct SQL) are in
// test/tenants.test.ts; the DDL ACL proof in test/tenant-ddl.test.ts.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import type { Authenticator } from '../src/mcp-auth.ts';
import { workspaceFeedbackPath } from '../src/mcp-hosted.ts';
import { LOG_FIELDS } from '../src/mcp-log.ts';
import { CLAUDE_CALLBACK } from '../src/mcp-oauth.ts';
import { OAuthStore } from '../src/mcp-oauth-store.ts';
import {
  callTool, INIT, LIST, mcpPost, mintStatic, refresh, send, serviceHome, signIn, startTenantHosted, toolJson, type Resp, type TenantHarness,
} from './helpers/hosted-tenants.ts';
import { asOwner, plantInWorkspace, plantTeam, TEAM_DECISION_URI, TEAM_LOCK_URI, TEAM_MARKER, TEAM_NOTE_URI, tenantTestDb, WALLED } from './helpers/tenant-fixture.ts';

const A_MARKER = 'wombatworkspacea';
let db: Db;
let home: string;
let h: TenantHarness;
let staticRead: string;
let tokA: string;
let tokB: string;
let bRefresh: { clientId: string; refresh: string };
let A: string;
let B: string;

/** Everything the team-only that must never reach a personal workspace. */
const TEAM_LEAKS = [TEAM_MARKER, TEAM_NOTE_URI, TEAM_LOCK_URI, TEAM_DECISION_URI, 'the team secret plan', 'team-owner', 'launch pricing stays', WALLED];

before(async () => {
  db = await tenantTestDb();
  await plantTeam(db);
  home = serviceHome();
  const read = await mintStatic('read');
  staticRead = read.token;
  // Message limits raised: these tests send hundreds of requests per token on purpose.
  h = await startTenantHosted({
    db, home, tokensRows: [read.row], routerCacheMs: 0, limits: { signupPerIp: 50, signupGlobal: 50 }, hostedLimits: { perToken: 100_000, global: 100_000 },
  });
  tokA = (await signIn(h, 'gh-stranger')).access;
  const b = await signIn(h, 'gh-b');
  tokB = b.access;
  bRefresh = { clientId: b.clientId, refresh: b.refresh };
  A = (await h.dir!.lookup('github:105'))!.tenantId;
  B = (await h.dir!.lookup('github:107'))!.tenantId;
  await plantInWorkspace(db, A, A_MARKER);
});
after(async () => {
  await h.close();
  await db.close();
});

/** Every read surface of one connection, with queries that match the team marker and A's marker. */
async function everyRead(token: string, extra: Record<string, string> = {}): Promise<Resp[]> {
  const post = (body: unknown) => mcpPost(h.port, token, body, extra);
  const out: Resp[] = [];
  out.push(await post(INIT), await post(LIST));
  for (const q of [TEAM_MARKER, A_MARKER, 'launch pricing', 'work', 'the team secret plan', `${TEAM_MARKER} ${A_MARKER}`]) {
    out.push(await post(callTool('zeusi_search', { query: q })));
    out.push(await post(callTool('search', { query: q, hybrid: false })));
    out.push(await post(callTool('zeusi_context_for_task', { task: `work on ${q} launch pricing friday` })));
    out.push(await post(callTool('prime', { task: q })));
  }
  for (const scope of [undefined, 'work', 'client']) {
    out.push(await post(callTool('zeusi_startup', {})));
    out.push(await post(callTool('zeusi_onboarding_status', scope ? { scope } : {})));
    out.push(await post(callTool('zeusi_search', scope ? { query: TEAM_MARKER, scope } : { query: TEAM_MARKER })));
  }
  out.push(await post({ jsonrpc: '2.0', id: 9, method: 'resources/read', params: { uri: 'zeusi://about' } }));
  out.push(await post({ jsonrpc: '2.0', id: 10, method: 'prompts/get', params: { name: 'onboarding' } }));
  // (start-task echoes the caller's own task argument back: give it neutral text, not the marker.)
  out.push(await post({ jsonrpc: '2.0', id: 11, method: 'prompts/get', params: { name: 'start-task', arguments: { task: 'plan the launch' } } }));
  return out;
}

function withheldCounts(rs: Resp[]): number[] {
  return rs.map((r) => toolJson(r).json?.['withheld']).filter((w): w is number => typeof w === 'number');
}

test('isolation (AE3): a token for workspace B never sees a team row or workspace A, through any tool, alias, prompt or resource; withheld is always 0', async () => {
  const rs = await everyRead(tokB);
  for (const r of rs) {
    assert.equal(r.status, 200, r.body.slice(0, 200));
    for (const leak of [...TEAM_LEAKS, A_MARKER]) assert.ok(!r.body.includes(leak), `B got ${leak}: ${r.body.slice(0, 300)}`);
  }
  const w = withheldCounts(rs);
  assert.equal(w.length, 30, 'every search, context and startup call answered (no tool error)');
  assert.ok(w.every((x) => x === 0), `withheld side channel: ${JSON.stringify(w)}`);
  const init = JSON.parse(rs[0]!.body) as { result: { instructions: string } };
  assert.ok(!init.result.instructions.includes('the team\'s sourced memory'), 'personal instructions do not describe the team\'s memory');
  assert.match(init.result.instructions, /personal workspace/);
  const tools = (JSON.parse(rs[1]!.body) as { result: { tools: Array<{ name: string }> } }).result.tools.map((t) => t.name);
  assert.ok(!tools.includes('zeusi_log_decision') && !tools.includes('log_decision'));
  const onboarding = rs.map(toolJson).find((t) => t.json?.['workspace'] === 'personal')!;
  assert.equal(onboarding.json!['empty'], true);
  assert.ok(!JSON.stringify(onboarding.json).includes('--scope team'), 'does not advertise a legacy team scope flag');
  const startup = rs.map(toolJson).find((t) => Array.isArray(t.json?.['rules']))!;
  assert.deepEqual([startup.json!['rules'], startup.json!['focus'], startup.json!['decisions']], [[], [], []]);
  assert.equal((startup.json!['rules_total'] as { total: number }).total, 0, 'no the team rule is counted for B');
});

test('isolation: a token for workspace A sees its own rows only; never the team, never B', async () => {
  const r = toolJson(await mcpPost(h.port, tokA, callTool('zeusi_search', { query: A_MARKER })));
  assert.equal(r.isError, false, r.text);
  const hits = r.json!['hits'] as Array<{ text: string; source_uri: string }>;
  assert.deepEqual(hits.map((x) => x.source_uri).sort(), [`test:${A_MARKER}#c0`]);
  for (const resp of await everyRead(tokA)) for (const leak of TEAM_LEAKS) assert.ok(!resp.body.includes(leak), `A got ${leak}`);
  const b = toolJson(await mcpPost(h.port, tokB, callTool('zeusi_search', { query: A_MARKER })));
  assert.deepEqual(b.json!['hits'], []);
});

test('isolation: request headers, query strings and tool arguments cannot choose another workspace', async () => {
  for (const extra of [{ 'x-zeusi-tenant': 'zeusi' }, { 'x-zeusi-tenant': 'work' }, { 'x-tenant': A }, { 'x-zeusi-workspace': A }, { 'fly-client-ip': '127.0.0.1' }]) {
    for (const r of await everyRead(tokB, extra)) {
      assert.equal(r.status, 200, JSON.stringify(extra));
      for (const leak of [...TEAM_LEAKS, A_MARKER]) assert.ok(!r.body.includes(leak), `${JSON.stringify(extra)}: ${leak}`);
    }
  }
  for (const qs of ['?tenant=team', `?tenant=${A}`, '?workspace=zeusi']) {
    const rq = await send(h.port, {
      method: 'POST', path: `/mcp${qs}`, body: JSON.stringify(callTool('zeusi_search', { query: TEAM_MARKER })),
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${tokB}` },
    });
    assert.equal(rq.status, 200, qs);
    assert.ok(!rq.body.includes(TEAM_MARKER), qs);
    assert.deepEqual(toolJson(rq).json!['hits'], [], qs);
  }
  // An unknown argument (e.g. a tenant or schema) is refused by the strict input schema, never echoed.
  const bad = toolJson(await mcpPost(h.port, tokB, callTool('zeusi_search', { query: TEAM_MARKER, tenant: 'work', schema: 'zeusi' })));
  assert.equal(bad.isError, true);
  assert.ok(!bad.text.includes(TEAM_MARKER));
});

test('isolation: zeusi_search_feedback cannot reach another workspace\'s query or a team uri; personal feedback goes to that workspace\'s own ledger', async () => {
  const a = toolJson(await mcpPost(h.port, tokA, callTool('zeusi_search', { query: A_MARKER })));
  const qa = a.json!['query_id'] as string;
  const cross = toolJson(await mcpPost(h.port, tokB, callTool('zeusi_search_feedback', { query_id: qa, source_uri: `test:${A_MARKER}#c0`, useful: true })));
  assert.equal(cross.isError, true);
  assert.match(cross.text, /unknown query_id/);
  const b = toolJson(await mcpPost(h.port, tokB, callTool('zeusi_search', { query: TEAM_MARKER })));
  const sov = toolJson(await mcpPost(h.port, tokB, callTool('zeusi_search_feedback', { query_id: b.json!['query_id'] as string, source_uri: `${TEAM_NOTE_URI}#c0`, useful: true })));
  assert.equal(sov.isError, true);
  assert.match(sov.text, /not a hit of that query/);
  const ok = toolJson(await mcpPost(h.port, tokA, callTool('zeusi_search_feedback', { query_id: qa, source_uri: `test:${A_MARKER}#c0`, useful: true })));
  assert.equal(ok.isError, false, ok.text);
  const teamLedger = join(home, '.zeusi', 'search-feedback.jsonl');
  const mine = workspaceFeedbackPath(teamLedger, A);
  assert.match(readFileSync(mine, 'utf8'), new RegExp(qa));
  let teamText = '';
  try { teamText = readFileSync(teamLedger, 'utf8'); } catch { /* never written */ }
  assert.ok(!teamText.includes(qa), 'not in the team ledger');
  assert.throws(() => workspaceFeedbackPath(teamLedger, '../../etc'), /not a workspace id/);
});

test('isolation: a refreshed token keeps its workspace (a token cannot switch workspace by refreshing)', async () => {
  const r = await refresh(h, bRefresh.clientId, bRefresh.refresh);
  bRefresh = { clientId: bRefresh.clientId, refresh: r.refresh };
  tokB = r.access; // the old access token is rotated away
  for (const q of [TEAM_MARKER, A_MARKER]) {
    const t = toolJson(await mcpPost(h.port, r.access, callTool('zeusi_search', { query: q })));
    assert.equal(t.isError, false, t.text);
    assert.deepEqual(t.json!['hits'], []);
    assert.equal(t.json!['withheld'], 0);
  }
  assert.equal(h.store.list().grants.find((g) => g.login === 'user-b')!.tenant, B);
});

test('isolation: a personal grant never writes, even when the server has a write service', async () => {
  const hw = await startTenantHosted({ db, home, writeService: 'zeusi_decision', limits: { signupPerIp: 50, signupGlobal: 50 } });
  try {
    const t = (await signIn(hw, 'gh-stranger')).access;
    const tools = (JSON.parse((await mcpPost(hw.port, t, LIST)).body) as { result: { tools: Array<{ name: string }> } }).result.tools.map((x) => x.name);
    assert.ok(!tools.some((n) => /log_decision/.test(n)));
    const w = await mcpPost(hw.port, t, callTool('zeusi_log_decision', { kind: 'go' }));
    assert.equal(w.status, 401);
  } finally {
    await hw.close();
  }
});

test('isolation (R10): a grant bound to an unknown or disabled workspace gets 403 {"error":"forbidden"} with nothing echoed; a catalog outage is 503', async () => {
  // Forge a grant for a workspace that does not exist, straight into the store (as an attacker who
  // could write the file could; the server must still refuse to serve it).
  const ghost = `zt_${'q'.repeat(26)}`;
  const c = h.store.registerClient({ clientName: null, redirectUris: [CLAUDE_CALLBACK] });
  const forged = h.store.createGrant({ clientId: c.client_id, subject: 'github:999', login: 'ghost', tenant: ghost });
  for (const tok of [forged.accessToken]) {
    const r = await mcpPost(h.port, tok, LIST);
    assert.equal(r.status, 403);
    assert.equal(r.body, '{"error":"forbidden"}');
  }
  await asOwner(db, () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'disabled' WHERE tenant_id = $1`, [B]));
  try {
    const r = await mcpPost(h.port, tokB, callTool('zeusi_search', { query: TEAM_MARKER }));
    assert.equal(r.status, 403);
    assert.equal(r.body, '{"error":"forbidden"}');
  } finally {
    await asOwner(db, () => db.query(`UPDATE zeusi_tenants.tenants SET status = 'active' WHERE tenant_id = $1`, [B]));
  }
  const out = await startTenantHosted({
    db, home, limits: { signupPerIp: 50, signupGlobal: 50 },
    routes: { check: async () => { throw new Error('ECONNREFUSED secret-host'); }, open: async () => { throw new Error('x'); }, encState: async () => { throw new Error('x'); } },
  });
  try {
    const t = (await signIn(out, 'gh-stranger')).access;
    const r = await mcpPost(out.port, t, LIST);
    assert.equal(r.status, 503);
    assert.ok(!r.body.includes('secret-host'));
  } finally {
    await out.close();
  }
  // No router at all: a personal grant is refused (fail closed); a team token still works.
  const read = await mintStatic('read');
  const none = await startTenantHosted({ db, home, tenants: 'off', tokensRows: [read.row] });
  try {
    const cl = none.store.registerClient({ clientName: null, redirectUris: [CLAUDE_CALLBACK] });
    const g = none.store.createGrant({ clientId: cl.client_id, subject: 'github:105', login: 'stranger', tenant: A });
    const r = await mcpPost(none.port, g.accessToken, LIST);
    assert.equal(r.status, 403);
    assert.equal(r.body, '{"error":"forbidden"}');
    assert.equal((await mcpPost(none.port, read.token, LIST)).status, 200);
  } finally {
    await none.close();
  }
});

test('isolation: a personal principal that is not class read is refused (403), whatever the authenticator says', async () => {
  const fake = { authenticate: async () => ({ ok: true, principal: { tokenId: 'abcdefghijkl', assistant: 'x', cls: 'write', tenant: A } }) } as unknown as Authenticator;
  const hx = await startTenantHosted({ db, home, authenticator: fake });
  try {
    const r = await mcpPost(hx.port, 'anything', LIST);
    assert.equal(r.status, 403);
    assert.equal(r.body, '{"error":"forbidden"}');
  } finally {
    await hx.close();
  }
});

test('isolation (AE4, R9): a static bearer token and a legacy grant (no tenant field) still read the team exactly as before', async () => {
  const s = toolJson(await mcpPost(h.port, staticRead, callTool('zeusi_search', { query: TEAM_MARKER })));
  assert.equal(s.isError, false, s.text);
  assert.ok((s.json!['hits'] as Array<{ source_uri: string }>).some((x) => x.source_uri === `${TEAM_NOTE_URI}#c0`));
  assert.equal(s.json!['withheld'], 1, 'the walled the team chunk is withheld for a team reader, as before');
  const init = JSON.parse((await mcpPost(h.port, staticRead, INIT)).body) as { result: { instructions: string } };
  assert.match(init.result.instructions, /Zeusi is the team's sourced memory/);
  // A grant written before open sign-up: drop the field from the file, reload the store.
  const legacy = await signIn(h, 'gh-login');
  const path = (h.store as unknown as { o: { path: string } }).o.path;
  const doc = JSON.parse(readFileSync(path, 'utf8')) as { grants: Array<Record<string, unknown>> };
  for (const g of doc.grants) if (g['login'] === 'OperatorOwner') delete g['tenant'];
  writeFileSync(path, JSON.stringify(doc));
  chmodSync(path, 0o600);
  assert.equal(new OAuthStore({ hashKey: 's'.repeat(48), path }).list().grants.find((g) => g.login === 'OperatorOwner')!.tenant, 'work');
  const l = toolJson(await mcpPost(h.port, legacy.access, callTool('zeusi_search', { query: TEAM_MARKER })));
  assert.equal(l.isError, false, l.text);
  assert.ok((l.json!['hits'] as Array<{ source_uri: string }>).some((x) => x.source_uri === `${TEAM_NOTE_URI}#c0`));
});

test('isolation: request log lines for personal requests carry only the existing fields; no workspace id, marker or token', async () => {
  const n0 = h.logs.length;
  await mcpPost(h.port, tokB, callTool('zeusi_search', { query: TEAM_MARKER }));
  await mcpPost(h.port, tokA, callTool('zeusi_search', { query: A_MARKER }));
  const lines = h.logs.slice(n0);
  assert.equal(lines.length, 2);
  for (const line of lines) {
    assert.deepEqual(Object.keys(JSON.parse(line) as object), [...LOG_FIELDS]);
    for (const bad of [A, B, TEAM_MARKER, A_MARKER, tokA, tokB]) assert.ok(!line.includes(bad), 'log leaks');
  }
});
