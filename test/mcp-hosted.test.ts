// Hosted MCP transport (src/mcp-hosted.ts, docs/hosting.md): the authenticated Streamable
// HTTP handler, mounted on an ephemeral 127.0.0.1 port for the test (the real bin binds the
// Fly-internal address). PGlite behind the unchanged MCP server; tokens minted into temp
// dirs only; no network beyond loopback, no Neon, no OpenAI.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync } from 'node:fs';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import { RO_PASSWORD_ENV, type Db } from '../src/db.ts';
import { search as realSearch, type SearchOptions } from '../src/search.ts';
import { TRANSPORT_ENV, type ServerlessClientLike } from '../src/transport.ts';
import { createMcpState, type McpDeps } from '../src/mcp-server.ts';
import { Authenticator } from '../src/mcp-auth.ts';
import { createHostedHandler, HSTS_VALUE, type HostedOptions } from '../src/mcp-hosted.ts';
import { ICON_PNG_BYTES, ICON_SVG_BYTES } from '../src/brand-icons.ts';
import { ICON_PNG_URL, ICON_SVG_URL, SERVER_DESCRIPTION, SERVER_TITLE, SITE_URL } from '../src/about.ts';
import { LOG_FIELDS } from '../src/mcp-log.ts';
import { generateToken, hashSecret, parseToken, verifySecret, withTokenFile, type TokenRow } from '../src/mcp-tokens.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { assertToolsAgree, CONTEXT_NOT_PERMISSION_RE, NOT_A_GO_RE, toolNamesIn } from './helpers/tool-agreement.ts';
import { fakeMaskedGoogle, P } from './secret-fixtures.ts';
import { assertGuardedChannels, assertGuardLog, plantGuardFixtures } from './helpers/fixa-guard.ts';

const WALLED = ['Plan', 'kiva synthetic wall probe'].join('');
const FAKE_HOST = ['ep-fake-444', '-pooler.eu-central-1.aws.neon.tech'].join('');
const SHA = 'ab'.repeat(32);
const FAST = { alg: 'argon2id' as const, params: { m: 64, t: 1, p: 1, dkLen: 32 } };
const EXACT_WORDS = 'Hosted decision synthetic words';

let db: Db;
let home: string;

function asRole(role: string, log?: string[]): (service: string) => Promise<Db> {
  return async (service: string) => {
    log?.push(`${service}:${role}`);
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-hosted-'));
  const svc = (name: string, user: string) => `[${name}]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;
  writeFileSync(join(home, '.pg_service.conf'), [svc('zeusi_ro', 'zeusi_box_ro'), svc('zeusi_decision', 'zeusi_box_decision')].join('\n'));
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'manual:people/owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  const nid = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/research/hosted.md', 'hosted', 'b', now(), 'work', 'vault_note', 'vault:Work/research/hosted.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  await db.exec('ALTER TABLE zeusi.chunks DISABLE TRIGGER zeusi_90_wall');
  const chunk = (i: number, text: string) => db.query(
    `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
     VALUES ($1, $2, 'Hosted', $3, sha256(convert_to($3, 'UTF8')), 5, $4)`, [nid, i, text, `vault:Work/research/hosted.md#c${i}`]);
  await chunk(0, 'quokka hosted connector chunk body');
  await chunk(1, `quokka ${WALLED}`);
  await db.exec('ALTER TABLE zeusi.chunks ENABLE TRIGGER zeusi_90_wall');
});
after(async () => db.close());

// ---------------------------------------------------------------------------
// Harness

interface Minted { token: string; row: TokenRow }

async function mint(cls: 'read' | 'write', over: Partial<TokenRow> = {}): Promise<Minted> {
  const g = generateToken();
  const now = Date.now();
  return {
    token: g.token,
    row: {
      token_id: g.tokenId, assistant: cls === 'write' ? 'zeus' : 'atlas', class: cls, hash: await hashSecret(g.tokenId, g.secret, FAST),
      issued_at: new Date(now - 1000).toISOString(), expires_at: new Date(now + 86_400_000).toISOString(), revoked_at: null, ...over,
    },
  };
}

function tokensDir(): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-hosted-tok-'));
  chmodSync(d, 0o700);
  return d;
}

async function tokensFile(rows: TokenRow[]): Promise<string> {
  const p = join(tokensDir(), 'mcp-tokens.json');
  await withTokenFile(p, () => ({ version: 1 as const, tokens: rows }));
  return p;
}

interface Hosted {
  port: number;
  logs: string[];
  hashes: { n: number };
  searches: { n: number };
  reads: string[];
  writes: string[];
  close: () => Promise<void>;
}

async function hosted(tokensPath: string, over: Partial<McpDeps> = {}, extra: Partial<HostedOptions> = {}): Promise<Hosted> {
  const logs: string[] = [];
  const hashes = { n: 0 };
  const searches = { n: 0 };
  const reads: string[] = [];
  const writes: string[] = [];
  const srv: Server = createServer();
  await new Promise<void>((res) => srv.listen(0, '127.0.0.1', res));
  const port = (srv.address() as AddressInfo).port;
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro',
    connectRead: asRole('zeusi_box_ro', reads), connectWrite: asRole('zeusi_box_decision', writes),
    embeddings: () => null,
    searchFn: (o: SearchOptions) => { searches.n++; return realSearch(o); },
    feedbackPath: join(home, '.zeusi', 'search-feedback.jsonl'), queryLedgerPath: join(home, '.zeusi', 'query-embed-ledger.json'),
    ...over,
  };
  const authenticator = new Authenticator({ tokensPath, verify: async (r, s) => { hashes.n++; return verifySecret(r, s); } });
  srv.on('request', createHostedHandler({
    deps, state: createMcpState(), authenticator, allowedHosts: [`127.0.0.1:${port}`], log: (l) => logs.push(l), ...extra,
  }));
  return { port, logs, hashes, searches, reads, writes, close: () => new Promise((res) => srv.close(() => res())) };
}

interface Resp { status: number; headers: Record<string, string | string[] | undefined>; body: string }

function send(port: number, o: { method?: string; path?: string; headers?: Record<string, string | string[]>; body?: string }): Promise<Resp> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: '127.0.0.1', port, method: o.method ?? 'POST', path: o.path ?? '/mcp',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(o.headers ?? {}) },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (o.body !== undefined) req.write(o.body);
    req.end();
  });
}

let rpcId = 1;
function rpc(port: number, token: string | null, method: string, params: Record<string, unknown> = {}, headers: Record<string, string | string[]> = {}): Promise<Resp> {
  return send(port, {
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: JSON.stringify({ jsonrpc: '2.0', id: rpcId++, method, params }),
  });
}

const INIT = { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } };
const callTool = (port: number, token: string | null, name: string, args: Record<string, unknown>, headers: Record<string, string | string[]> = {}) =>
  rpc(port, token, 'tools/call', { name, arguments: args }, headers);
const result = (r: Resp) => (JSON.parse(r.body) as { result?: { isError?: boolean; content: Array<{ text: string }>; tools?: Array<{ name: string }> } }).result!;
const toolJson = (r: Resp) => JSON.parse(result(r).content[0]!.text) as Record<string, unknown>;

const decisionArgs = (over: Record<string, unknown> = {}) => ({
  kind: 'go', who: 'owner', said_at: '2020-02-02T10:00:00Z', exact_words: EXACT_WORDS, exact_words_verbatim: true, scope: 'work',
  source_uri: 'hq:hosted-test', source_ts: '2020-02-02T10:00:00Z', ...over,
});

const hsts = (r: Resp) => r.headers['strict-transport-security'];

// ---------------------------------------------------------------------------
// R2: fail closed

test('hosted R2: with no tokens file, initialize, tools/list and tools/call each return 503 with HSTS, no tool output, nothing connects', async () => {
  const h = await hosted(join(tokensDir(), 'mcp-tokens.json'));
  try {
    const tok = generateToken().token;
    for (const r of [await rpc(h.port, tok, 'initialize', INIT), await rpc(h.port, tok, 'tools/list'), await callTool(h.port, tok, 'zeusi_search', { query: 'quokka' }), await rpc(h.port, null, 'tools/list')]) {
      assert.equal(r.status, 503);
      assert.equal(r.body, '{"error":"not_configured"}');
      assert.equal(hsts(r), HSTS_VALUE);
    }
    assert.deepEqual(h.reads, []);
    assert.equal(h.searches.n, 0);
    assert.equal(h.hashes.n, 0);
  } finally {
    await h.close();
  }
});

test('hosted: a tokens file holding only a revoked token answers 401 with HSTS', async () => {
  const revoked = await mint('read', { revoked_at: new Date().toISOString() });
  const h = await hosted(await tokensFile([revoked.row]));
  try {
    const r = await rpc(h.port, revoked.token, 'tools/list');
    assert.equal(r.status, 401);
    assert.equal(r.body, '{"error":"unauthorized"}');
    assert.equal(hsts(r), HSTS_VALUE);
    assert.equal(r.headers['www-authenticate'], 'Bearer realm="zeusi"');
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// R3: identical 401s

test('hosted R3: no header, malformed header, expired token, wrong secret: identical 401 bodies, no tool runs', async () => {
  const live = await mint('read');
  const expired = await mint('read', { expires_at: new Date(Date.now() - 1).toISOString() });
  const h = await hosted(await tokensFile([live.row, expired.row]));
  try {
    const wrong = `zeusi_${live.row.token_id}_${generateToken().secret}`;
    const rs = [
      await callTool(h.port, null, 'zeusi_search', { query: 'quokka' }),
      await callTool(h.port, null, 'zeusi_search', { query: 'quokka' }, { authorization: 'Bearer not-a-token' }),
      await callTool(h.port, null, 'zeusi_search', { query: 'quokka' }, { authorization: `Basic ${live.token}` }),
      await callTool(h.port, null, 'zeusi_search', { query: 'quokka' }, { authorization: [`Bearer ${live.token}`, `Bearer ${live.token}`] }),
      await callTool(h.port, expired.token, 'zeusi_search', { query: 'quokka' }),
      await callTool(h.port, wrong, 'zeusi_search', { query: 'quokka' }),
    ];
    for (const r of rs) {
      assert.equal(r.status, 401);
      assert.equal(r.body, '{"error":"unauthorized"}');
      assert.equal(hsts(r), HSTS_VALUE);
    }
    assert.equal(h.searches.n, 0);
    assert.deepEqual(h.reads, []);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// R10: scopes

test('hosted R10: a read token lists no write tool, runs zeusi_search and search, gets 401 for log_decision; nothing connects for writing', async () => {
  const read = await mint('read');
  const h = await hosted(await tokensFile([read.row]), { writeService: 'zeusi_decision' });
  try {
    const init = await rpc(h.port, read.token, 'initialize', INIT);
    assert.equal(init.status, 200, init.body);
    const names = result(await rpc(h.port, read.token, 'tools/list')).tools!.map((t) => t.name).sort();
    assert.deepEqual(names, ['context_for_task', 'onboarding_status', 'prime', 'search', 'startup', 'zeusi_context_for_task', 'zeusi_onboarding_status', 'zeusi_search', 'zeusi_search_feedback', 'zeusi_startup']);
    for (const name of ['zeusi_search', 'search']) {
      const r = await callTool(h.port, read.token, name, { query: 'quokka' });
      assert.equal(r.status, 200);
      const j = toolJson(r);
      assert.ok((j['hits'] as unknown[]).length >= 1);
      assert.ok((j['withheld'] as number) >= 1);
      assert.ok(!r.body.includes(WALLED));
    }
    for (const name of ['zeusi_log_decision', 'log_decision']) {
      const r = await callTool(h.port, read.token, name, decisionArgs({ source_uri: 'hq:hosted-read' }));
      assert.equal(r.status, 401);
      assert.equal(r.body, '{"error":"unauthorized"}');
    }
    // a batch that smuggles log_decision next to a search is refused whole
    const batch = await send(h.port, {
      headers: { authorization: `Bearer ${read.token}` },
      body: JSON.stringify([
        { jsonrpc: '2.0', id: 900, method: 'tools/call', params: { name: 'search', arguments: { query: 'quokka' } } },
        { jsonrpc: '2.0', id: 901, method: 'tools/call', params: { name: 'log_decision', arguments: decisionArgs({ source_uri: 'hq:hosted-read' }) } },
      ]),
    });
    assert.equal(batch.status, 401);
    assert.deepEqual(h.writes, []);
  } finally {
    await h.close();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:hosted-read'`)).rows[0]!.n, 0);
});

test('hosted: the SDK client works end to end with a read token (initialize, list, search)', async () => {
  const read = await mint('read');
  const h = await hosted(await tokensFile([read.row]));
  const client = new Client({ name: 'sdk-test', version: '0' });
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${h.port}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${read.token}` } },
    }));
    const tools = (await client.listTools()).tools.map((t) => t.name);
    assert.ok(tools.includes('zeusi_search') && !tools.includes('zeusi_log_decision'));
    const r = (await client.callTool({ name: 'zeusi_search', arguments: { query: 'quokka' } })) as { content: Array<{ text: string }> };
    assert.ok(JSON.parse(r.content[0]!.text).hits.length >= 1);
  } finally {
    await client.close();
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// R11 / R13: the existing write gate stays the last word

test('hosted R11: a write token without --write-service has no write tool (F4: refused, nothing written); with zeusi_box_decision it inserts one decision', async () => {
  const write = await mint('write');
  const path = await tokensFile([write.row]);
  const noSvc = await hosted(path);
  try {
    const r = await callTool(noSvc.port, write.token, 'log_decision', decisionArgs({ source_uri: 'hq:hosted-nosvc' }));
    assert.equal(r.status, 200);
    const j = JSON.parse(r.body) as { error?: unknown; result?: { isError?: boolean } };
    assert.ok(j.error !== undefined || j.result?.isError === true, 'unknown tool refused');
    assert.deepEqual(noSvc.writes, []);
  } finally {
    await noSvc.close();
  }
  const svc = await hosted(path, { writeService: 'zeusi_decision' });
  try {
    const r = await callTool(svc.port, write.token, 'zeusi_log_decision', decisionArgs({ source_uri: 'hq:hosted-write' }));
    assert.equal(r.status, 200, r.body);
    assert.equal(toolJson(r)['status'], 'inserted');
    assert.deepEqual(svc.writes, ['zeusi_decision:zeusi_box_decision']);
  } finally {
    await svc.close();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:hosted-write'`)).rows[0]!.n, 1);
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:hosted-nosvc'`)).rows[0]!.n, 0);
});

test('hosted write service: on one server with the write service ON, the read token gets the generic 401 for both write names and the write token inserts', async () => {
  const read = await mint('read');
  const write = await mint('write');
  const h = await hosted(await tokensFile([read.row, write.row]), { writeService: 'zeusi_decision' });
  try {
    for (const name of ['zeusi_log_decision', 'log_decision']) {
      const r = await callTool(h.port, read.token, name, decisionArgs({ source_uri: 'hq:hosted-mixed-read' }));
      assert.equal(r.status, 401);
      assert.equal(r.body, '{"error":"unauthorized"}');
      assert.equal(r.headers['www-authenticate'], 'Bearer realm="zeusi"');
    }
    assert.deepEqual(h.writes, [], 'the read token never reached a write connection');
    const w = await callTool(h.port, write.token, 'log_decision', decisionArgs({ source_uri: 'hq:hosted-mixed-write' }));
    assert.equal(w.status, 200, w.body);
    assert.equal(toolJson(w)['status'], 'inserted');
    assert.deepEqual(h.writes, ['zeusi_decision:zeusi_box_decision']);
  } finally {
    await h.close();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:hosted-mixed-read'`)).rows[0]!.n, 0);
});

test('hosted write service: a write token passes the HTTP scope check and is stopped by the write gate when the service is not the decision login', async () => {
  const write = await mint('write');
  const h = await hosted(await tokensFile([write.row]), { writeService: 'zeusi_ro' });
  try {
    const r = await callTool(h.port, write.token, 'zeusi_log_decision', decisionArgs({ source_uri: 'hq:hosted-gate' }));
    assert.equal(r.status, 200, 'not a 401: the HTTP layer let the write token through');
    assert.equal(result(r).isError, true);
    assert.match(result(r).content[0]!.text, /runs only zeusi_box_decision/);
    assert.deepEqual(h.writes, [], 'refused before any write connection');
  } finally {
    await h.close();
  }
});

test('hosted R13: under ZEUSI_TRANSPORT=serverless a write token is refused before any credential read; reads use the fake serverless client', async () => {
  const write = await mint('write');
  const securityCalls: string[][] = [];
  const sl: string[] = [];
  const fakeServerless = () => {
    sl.push('client');
    const c: ServerlessClientLike = {
      neonConfig: {}, async connect() {}, async end() {},
      async query(sql: string, params?: unknown[]) { return db.query(sql, params) as Promise<{ rows: unknown[] }>; },
    };
    return c;
  };
  const h = await hosted(await tokensFile([write.row]), {
    env: { HOME: home, [TRANSPORT_ENV]: 'serverless', [RO_PASSWORD_ENV]: 'fake-ro-pw-x' }, writeService: 'zeusi_decision',
    connectRead: undefined, connectWrite: undefined, readOnlyOptions: { serverlessClient: fakeServerless },
    runSecurity: async (a) => { securityCalls.push(a); return { code: 0, stdout: 'x\n' }; },
  });
  await db.exec('SET ROLE zeusi_box_ro');
  try {
    const w = await callTool(h.port, write.token, 'zeusi_log_decision', decisionArgs({ source_uri: 'hq:hosted-sl' }));
    assert.equal(result(w).isError, true);
    assert.match(result(w).content[0]!.text, /serverless/);
    assert.deepEqual(securityCalls, []);
    const s = await callTool(h.port, write.token, 'zeusi_search', { query: 'quokka' });
    assert.equal(result(s).isError, undefined, s.body);
    assert.equal(sl.length, 1);
  } finally {
    await db.exec('RESET ROLE');
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// R15 / R5: limits

test('hosted R15: the 61st tools/call in a minute from one token is 429 (no tool run, exact body); a second token is unaffected', async () => {
  const a = await mint('read');
  const b = await mint('read');
  const h = await hosted(await tokensFile([a.row, b.row]));
  try {
    for (let i = 0; i < 60; i++) assert.equal((await callTool(h.port, a.token, 'zeusi_search', { query: 'quokka' })).status, 200, `call ${i + 1}`);
    assert.equal(h.searches.n, 60);
    const r = await callTool(h.port, a.token, 'zeusi_search', { query: 'quokka' });
    assert.equal(r.status, 429);
    assert.equal(r.body, '{"error":"rate_limited"}');
    assert.ok(Number(r.headers['retry-after']) >= 1);
    assert.equal(hsts(r), HSTS_VALUE);
    assert.equal(h.searches.n, 60, 'no tool ran');
    // non-tool methods are counted too: this token is over its budget for them as well
    assert.equal((await rpc(h.port, a.token, 'tools/list')).status, 429);
    assert.equal((await rpc(h.port, a.token, 'initialize', INIT)).status, 429);
    assert.equal((await callTool(h.port, b.token, 'zeusi_search', { query: 'quokka' })).status, 200, 'second token unaffected');
  } finally {
    await h.close();
  }
});

test('hosted R15: the 11th log_decision in a minute is 429; the global limit stops every token', async () => {
  const w = await mint('write');
  const other = await mint('read');
  const h = await hosted(await tokensFile([w.row, other.row]), {}, { limits: { global: 15 } });
  try {
    for (let i = 0; i < 10; i++) assert.equal((await callTool(h.port, w.token, 'log_decision', decisionArgs())).status, 200);
    const r = await callTool(h.port, w.token, 'log_decision', decisionArgs());
    assert.equal(r.status, 429);
    assert.equal(r.body, '{"error":"rate_limited"}');
    // reads still fit for this token (per-token 60) until the global 15
    for (let i = 0; i < 5; i++) assert.equal((await callTool(h.port, other.token, 'zeusi_search', { query: 'quokka' })).status, 200);
    assert.equal((await callTool(h.port, other.token, 'zeusi_search', { query: 'quokka' })).status, 429, 'global limit');
  } finally {
    await h.close();
  }
});

test('hosted P2-5c: initialize, tools/list and notifications count toward the per-token and global limits, not only tools/call', async () => {
  const a = await mint('read');
  const b = await mint('read');
  const h = await hosted(await tokensFile([a.row, b.row]), {}, { limits: { perToken: 3, global: 5 } });
  try {
    assert.equal((await rpc(h.port, a.token, 'initialize', INIT)).status, 200);
    assert.equal((await rpc(h.port, a.token, 'tools/list')).status, 200);
    const note = await send(h.port, { headers: { authorization: `Bearer ${a.token}` }, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) });
    assert.ok(note.status < 300, `notification accepted: ${note.status}`);
    for (const m of ['tools/list', 'initialize'] as const) {
      const r = await rpc(h.port, a.token, m, m === 'initialize' ? INIT : {});
      assert.equal(r.status, 429, `${m} over the per-token limit`);
      assert.equal(r.body, '{"error":"rate_limited"}');
    }
    assert.equal((await callTool(h.port, a.token, 'zeusi_search', { query: 'quokka' })).status, 429);
    assert.equal(h.searches.n, 0);
    // global 5: a batch of two list calls from b fits (3 + 2), then b's next list is refused
    const batch = await send(h.port, {
      headers: { authorization: `Bearer ${b.token}` },
      body: JSON.stringify([{ jsonrpc: '2.0', id: 1, method: 'tools/list' }, { jsonrpc: '2.0', id: 2, method: 'tools/list' }]),
    });
    assert.equal(batch.status, 200);
    assert.equal((await rpc(h.port, b.token, 'tools/list')).status, 429, 'global limit covers tools/list');
  } finally {
    await h.close();
  }
});

test('hosted P2-5d: a body that does not arrive within the body timeout gets 408 and the connection is closed; nothing runs', async () => {
  const live = await mint('read');
  const h = await hosted(await tokensFile([live.row]), {}, { bodyTimeoutMs: 150 });
  try {
    const r = await new Promise<Resp>((resolve, reject) => {
      const req = request({
        host: '127.0.0.1', port: h.port, method: 'POST', path: '/mcp',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${live.token}`, 'content-length': '500' },
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => { req.destroy(); resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }); });
      });
      req.on('error', reject);
      req.write('{"jsonrpc":"2.0","id":1,'); // and then stall
    });
    assert.equal(r.status, 408);
    assert.equal(r.body, '{"error":"request_timeout"}');
    assert.equal(hsts(r), HSTS_VALUE);
    assert.equal(h.searches.n, 0);
    // a normal request on a fresh connection still works
    assert.equal((await rpc(h.port, live.token, 'tools/list')).status, 200);
  } finally {
    await h.close();
  }
});

test('hosted R5: 11 bad tokens from one Fly-Client-IP in a minute make the 11th a 429, without hashing', async () => {
  const live = await mint('read');
  const h = await hosted(await tokensFile([live.row]));
  try {
    const wrong = () => `zeusi_${live.row.token_id}_${generateToken().secret}`;
    for (let i = 0; i < 10; i++) assert.equal((await rpc(h.port, wrong(), 'tools/list', {}, { 'fly-client-ip': '203.0.113.77' })).status, 401);
    assert.equal(h.hashes.n, 10);
    const r = await rpc(h.port, wrong(), 'tools/list', {}, { 'fly-client-ip': '203.0.113.77' });
    assert.equal(r.status, 429);
    assert.equal(r.body, '{"error":"rate_limited"}');
    assert.equal(h.hashes.n, 10, 'no hash on the 11th');
    assert.equal((await rpc(h.port, wrong(), 'tools/list', {}, { 'fly-client-ip': '203.0.113.78' })).status, 401, 'another client IP');
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// R18: HSTS on every response

test('hosted R18: HSTS max-age=31536000 (no preload) on 200, 401, 404, 413, 429 and 503', async () => {
  const live = await mint('read');
  const h = await hosted(await tokensFile([live.row]), {}, { limits: { perToken: 1 } });
  const none = await hosted(join(tokensDir(), 'mcp-tokens.json'));
  try {
    const seen = new Map<number, Resp>();
    seen.set(200, await callTool(h.port, live.token, 'zeusi_search', { query: 'quokka' }));
    seen.set(429, await callTool(h.port, live.token, 'zeusi_search', { query: 'quokka' }));
    seen.set(401, await rpc(h.port, null, 'tools/list'));
    seen.set(404, await send(h.port, { path: '/other', headers: { authorization: `Bearer ${live.token}` }, body: '{}' }));
    seen.set(413, await send(h.port, { headers: { authorization: `Bearer ${live.token}` }, body: JSON.stringify({ x: 'a'.repeat(1024 * 1024 + 10) }) }));
    seen.set(503, await rpc(none.port, live.token, 'tools/list'));
    for (const [status, r] of seen) {
      assert.equal(r.status, status, r.body);
      assert.equal(hsts(r), 'max-age=31536000', String(status));
      assert.doesNotMatch(String(hsts(r)), /preload/);
    }
    assert.equal(seen.get(413)!.body, '{"error":"payload_too_large"}');
    const bad = await send(h.port, { headers: { authorization: `Bearer ${live.token}` }, body: '{not json' });
    assert.equal(bad.status, 400);
    assert.equal(hsts(bad), HSTS_VALUE);
  } finally {
    await h.close();
    await none.close();
  }
});

test('hosted listing: unauthenticated GET/HEAD /favicon.png and /favicon.svg serve the site mark; POST is 405; initialize advertises them', async () => {
  const live = await mint('read');
  const h = await hosted(await tokensFile([live.row]));
  const base = `http://127.0.0.1:${h.port}`;
  try {
    for (const [path, typ, bytes] of [
      ['/favicon.png', 'image/png', ICON_PNG_BYTES],
      ['/favicon.svg', 'image/svg+xml', ICON_SVG_BYTES],
    ] as const) {
      const get = await fetch(`${base}${path}`);
      assert.equal(get.status, 200, path);
      assert.equal(get.headers.get('content-type'), typ);
      assert.equal(get.headers.get('cache-control'), 'public, max-age=86400');
      assert.equal(get.headers.get('access-control-allow-origin'), '*');
      assert.equal(get.headers.get('strict-transport-security'), HSTS_VALUE);
      const body = Buffer.from(await get.arrayBuffer());
      assert.equal(Buffer.compare(body, bytes), 0, path);
      assert.equal(Number(get.headers.get('content-length')), bytes.length);

      const head = await fetch(`${base}${path}`, { method: 'HEAD' });
      assert.equal(head.status, 200, `HEAD ${path}`);
      assert.equal(head.headers.get('content-type'), typ);
      assert.equal(head.headers.get('strict-transport-security'), HSTS_VALUE);
      assert.equal((await head.arrayBuffer()).byteLength, 0);

      const post = await fetch(`${base}${path}`, { method: 'POST', body: 'x' });
      assert.equal(post.status, 405, `POST ${path}`);
      assert.equal(post.headers.get('allow'), 'GET, HEAD');
      assert.equal(post.headers.get('strict-transport-security'), HSTS_VALUE);
    }
    assert.equal((await fetch(`${base}/favicon.ico`)).status, 404);
    assert.equal((await fetch(`${base}/brand/logo-512.png`)).status, 404);

    const init = await rpc(h.port, live.token, 'initialize', INIT);
    assert.equal(init.status, 200, init.body);
    const info = (JSON.parse(init.body) as { result: { serverInfo: Record<string, unknown> } }).result.serverInfo;
    assert.equal(info['name'], 'zeusi');
    assert.equal(info['version'], '0.1.0');
    assert.equal(info['title'], SERVER_TITLE);
    assert.equal(info['description'], SERVER_DESCRIPTION);
    assert.equal(info['websiteUrl'], SITE_URL);
    assert.deepEqual(info['icons'], [
      { src: ICON_PNG_URL, mimeType: 'image/png', sizes: ['512x512'] },
      { src: ICON_SVG_URL, mimeType: 'image/svg+xml', sizes: ['any'] },
    ]);
  } finally {
    await h.close();
  }
});


test('hosted serve guard (security P0): a hit with a partial key (or a stored [REDACTED: marker) is withheld; the log line counts it (redacted_count = secret-withheld items), never the text', async () => {
  const r = await mint('read');
  const injected = async () => ({
    mode: 'lexical' as const,
    hits: [
      { chunkId: 5, sourceUri: 'vault:Work/products/avatar.md#c5', sourceTs: new Date().toISOString(), scope: 'work', headingPath: null, text: `key \`${fakeMaskedGoogle()}\``, score: 1, ranks: {} },
      { chunkId: 6, sourceUri: 'vault:Work/products/avatar.md#c6', sourceTs: new Date().toISOString(), scope: 'work', headingPath: null, text: 'key `[REDACTED:masked_google_api_key]` rest', score: 1, ranks: {} },
      { chunkId: 7, sourceUri: 'vault:Work/products/avatar.md#c7', sourceTs: new Date().toISOString(), scope: 'work', headingPath: null, text: 'avatar plan, clean', score: 1, ranks: {} },
    ],
  });
  const h = await hosted(await tokensFile([r.row]), { searchFn: injected });
  try {
    const s = await callTool(h.port, r.token, 'zeusi_search', { query: 'avatar key' });
    assert.equal(s.status, 200, s.body);
    assert.ok(!s.body.includes(P.google), 'no key prefix in the HTTP response');
    const j = toolJson(s) as { hits: Array<{ text: string }>; withheld: number };
    assert.deepEqual(j.hits.map((x) => x.text), ['avatar plan, clean']);
    assert.equal(j.withheld, 2);
    assert.ok(!s.body.includes('REDACTED'), 'no marker served');
    await new Promise((res) => setImmediate(res));
    const line = JSON.parse(h.logs[0]!) as Record<string, unknown>;
    assert.deepEqual(Object.keys(line), [...LOG_FIELDS]);
    assert.equal(line['redacted_count'], 2);
    assert.equal(line['withheld_count'], 2);
    assert.ok(!h.logs.join('\n').includes(P.google) && !h.logs.join('\n').includes('REDACTED'));
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// R20 / R21: logs

test('hosted R20/R21: log lines carry only the allowlisted keys and the token_id; never query, chunk text, exact_words, token, secret, host or walled text', async () => {
  const w = await mint('write');
  const h = await hosted(await tokensFile([w.row]), { writeService: 'zeusi_decision' });
  try {
    const s = await callTool(h.port, w.token, 'zeusi_search', { query: 'quokka hosted' });
    assert.equal(s.status, 200);
    const d = await callTool(h.port, w.token, 'log_decision', decisionArgs({ source_uri: 'hq:hosted-log' }));
    assert.equal(d.status, 200, d.body);
    await rpc(h.port, null, 'tools/list');
    await new Promise((res) => setImmediate(res));
    assert.equal(h.logs.length, 3);
    const lines = h.logs.map((l) => JSON.parse(l) as Record<string, unknown>);
    for (const l of lines) assert.deepEqual(Object.keys(l), [...LOG_FIELDS]);
    assert.equal(lines[0]!['token_id'], w.row.token_id);
    assert.equal(lines[0]!['assistant'], 'zeus');
    assert.equal(lines[0]!['class'], 'write');
    assert.equal(lines[0]!['tool'], 'zeusi_search');
    assert.ok((lines[0]!['hit_count'] as number) >= 1);
    assert.ok((lines[0]!['withheld_count'] as number) >= 1);
    assert.equal(lines[0]!['status'], 200);
    assert.equal(lines[1]!['tool'], 'log_decision');
    assert.deepEqual([lines[2]!['status'], lines[2]!['error_class'], lines[2]!['token_id']], [401, 'unauthorized', null]);
    const all = h.logs.join('\n');
    const { secret } = parseToken(w.token)!;
    for (const bad of ['quokka', 'chunk body', EXACT_WORDS, w.token, secret, FAKE_HOST, WALLED, 'neon.tech']) {
      assert.ok(!all.includes(bad), `log contains ${bad.slice(0, 12)}`);
    }
  } finally {
    await h.close();
  }
});

test('hosted: a Host outside the allowed list is rejected by DNS-rebinding protection, after auth', async () => {
  const live = await mint('read');
  const h = await hosted(await tokensFile([live.row]));
  try {
    const r = await rpc(h.port, live.token, 'tools/list', {}, { host: 'evil.example' });
    assert.equal(r.status, 403);
    assert.equal(hsts(r), HSTS_VALUE);
    const u = await rpc(h.port, null, 'tools/list', {}, { host: 'evil.example' });
    assert.equal(u.status, 401, 'auth runs first');
    assert.equal(h.searches.n, 0);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Speaks up first (plan U4): zeusi_context_for_task, the start-task prompt and zeusi://about on
// the real hosted handler. Read class, same auth, same limits, log allowlist, scope isolation.
// Synthetic fixtures only (invent=NO).

const PRIME_TASK = 'promote Northbank to prod hosted-distinctive-task-77';
const PRIME_WORDS = 'SYNTHETIC FIXTURE: no Northbank prod promotion during London/NY market hours';
const PRIME_ROLE = 'zeusi_test_hosted_work_only';

/** Fixtures for the prime tests, created once on first use (after the file's main before hook). */
let primeReady: Promise<void> | undefined;
const primeFixtures = () => (primeReady ??= (async () => {
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  const dec = (kind: string, words: string, uri: string, applies: string[], scope: string) => db.query(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind,
                                  source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1::zeusi.decision_kind, (SELECT id FROM zeusi.people WHERE handle = 'owner'), now() - interval '3 days', 'minute', $2, false,
             $3::text[], $4::zeusi.scope, 'manual', $5, now() - interval '3 days', sha256(convert_to($5 || $2, 'UTF8')), $6)`,
    [kind, words, applies, scope, uri, run]);
  await dec('lock', PRIME_WORDS, 'test:hosted-lock', ['northbank', 'prod'], 'product');
  await dec('park', 'SYNTHETIC FIXTURE: park the Northbank newsletter idea', 'test:hosted-park', ['newsletter'], 'work');
  await db.exec('ALTER TABLE zeusi.decisions DISABLE TRIGGER zeusi_90_wall');
  await dec('lock', `SYNTHETIC FIXTURE: Northbank prod ${WALLED}`, 'test:hosted-walled', ['northbank', 'prod'], 'product');
  await db.exec('ALTER TABLE zeusi.decisions ENABLE TRIGGER zeusi_90_wall');
  await db.exec(`CREATE ROLE ${PRIME_ROLE} NOLOGIN;
    GRANT USAGE ON SCHEMA zeusi TO ${PRIME_ROLE};
    GRANT SELECT ON zeusi.decisions, zeusi.decisions_current, zeusi.people, zeusi.notes TO ${PRIME_ROLE};
    CREATE POLICY test_hosted_work_only ON zeusi.decisions FOR SELECT TO ${PRIME_ROLE} USING (scope = 'work');
    CREATE POLICY test_hosted_work_only ON zeusi.people FOR SELECT TO ${PRIME_ROLE} USING (scope = 'work');
    CREATE POLICY test_hosted_work_only ON zeusi.notes FOR SELECT TO ${PRIME_ROLE} USING (scope = 'work');
    -- PR2 U6: zeusi_onboarding_status also counts facts and chunks (real zeusi_read roles have these grants).
    GRANT SELECT ON zeusi.facts, zeusi.facts_current, zeusi.chunks TO ${PRIME_ROLE};
    CREATE POLICY test_hosted_work_only ON zeusi.facts FOR SELECT TO ${PRIME_ROLE} USING (scope = 'work');
    CREATE POLICY test_hosted_work_only ON zeusi.chunks FOR SELECT TO ${PRIME_ROLE} USING (scope = 'work');`);
})());

type RpcResult = { isError?: boolean; content?: Array<{ text: string }>; contents?: Array<{ uri: string; text: string; mimeType?: string }>; messages?: Array<{ content: { text: string } }>; tools?: Array<{ name: string }>; capabilities?: Record<string, unknown>; instructions?: string };
const rpcResult = (r: Resp) => (JSON.parse(r.body) as { result?: RpcResult }).result!;

test('hosted prime: a read token lists the new read tools, calls zeusi_context_for_task / prime, reads zeusi://about and gets start-task; nothing is write-class', async () => {
  await primeFixtures();
  const read = await mint('read');
  const write = await mint('write');
  const h = await hosted(await tokensFile([read.row, write.row]), { writeService: 'zeusi_decision' });
  try {
    const init = rpcResult(await rpc(h.port, read.token, 'initialize', INIT));
    assert.ok(init.capabilities?.['prompts'] && init.capabilities?.['resources']);
    assert.match(init.instructions ?? '', /start of every task, call zeusi_context_for_task/);
    const names = rpcResult(await rpc(h.port, read.token, 'tools/list')).tools!.map((t) => t.name);
    for (const n of ['zeusi_context_for_task', 'context_for_task', 'prime']) assert.ok(names.includes(n), n);
    for (const name of ['zeusi_context_for_task', 'prime', 'context_for_task']) {
      const r = await callTool(h.port, read.token, name, { task: PRIME_TASK });
      assert.equal(r.status, 200, name);
      const j = toolJson(r);
      assert.equal((j['items'] as Array<{ source_uri: string }>)[0]!.source_uri, 'test:hosted-lock');
      assert.equal(j['withheld'], 1);
      assert.ok(!r.body.includes(WALLED) && !r.body.includes('hosted-distinctive-task-77'));
    }
    const res = rpcResult(await rpc(h.port, read.token, 'resources/read', { uri: 'zeusi://about' }));
    assert.equal(res.contents![0]!.uri, 'zeusi://about');
    assert.match(res.contents![0]!.text, /named after a cat/);
    const p = rpcResult(await rpc(h.port, read.token, 'prompts/get', { name: 'start-task', arguments: { task: 'promote Northbank to prod' } }));
    assert.match(p.messages![0]!.content.text, /zeusi_context_for_task/);
    // the write token sees the same read tools; none of the new names is write-class
    const wnames = rpcResult(await rpc(h.port, write.token, 'tools/list')).tools!.map((t) => t.name);
    for (const n of ['zeusi_context_for_task', 'context_for_task', 'prime', 'zeusi_log_decision']) assert.ok(wnames.includes(n), n);
    assert.deepEqual(h.writes, [], 'nothing connected for writing');
  } finally {
    await h.close();
  }
});

test('hosted F4/F5: instructions, zeusi://about and tools/list agree per token class (read bearer, write bearer without and with a write service); context, not permission', async () => {
  const read = await mint('read');
  const write = await mint('write');
  const path = await tokensFile([read.row, write.row]);
  const check = async (port: number, token: string, label: string, canWrite: boolean) => {
    const ins = rpcResult(await rpc(port, token, 'initialize', INIT)).instructions ?? '';
    const names = rpcResult(await rpc(port, token, 'tools/list')).tools!.map((t) => t.name);
    assertToolsAgree(ins, names, label);
    const about = rpcResult(await rpc(port, token, 'resources/read', { uri: 'zeusi://about' })).contents![0]!.text;
    for (const t of [ins, about]) {
      assert.match(t, CONTEXT_NOT_PERMISSION_RE, label);
      assert.match(t, NOT_A_GO_RE, label);
    }
    for (const n of ['zeusi_log_decision', 'log_decision']) {
      assert.equal(names.includes(n), canWrite, `${label} lists ${n}`);
      assert.equal(toolNamesIn(about).includes(n), canWrite, `${label} about names ${n}`);
    }
    if (!canWrite) for (const t of [ins, about]) {
      assert.doesNotMatch(t, /log_decision/, label);
      assert.match(t, /Writing decisions is not available on this connection/, label);
    }
    const p = rpcResult(await rpc(port, token, 'prompts/get', { name: 'start-task', arguments: { task: 'promote Northbank to prod' } })).messages![0]!.content.text;
    assert.match(p, CONTEXT_NOT_PERMISSION_RE, label);
    for (const n of toolNamesIn(p)) assert.ok(names.includes(n), `${label}: start-task names ${n}, which is listed`);
  };
  const noSvc = await hosted(path);
  try {
    await check(noSvc.port, read.token, 'read bearer, no write service', false);
    await check(noSvc.port, write.token, 'write bearer, no write service', false);
  } finally {
    await noSvc.close();
  }
  const svc = await hosted(path, { writeService: 'zeusi_decision' });
  try {
    await check(svc.port, read.token, 'read bearer, write service on', false);
    await check(svc.port, write.token, 'write bearer + write service', true);
    assert.deepEqual(svc.writes, [], 'nothing connected for writing');
  } finally {
    await svc.close();
  }
});

test('hosted prime: context_for_task, prompts/get and resources/read count toward the per-token limit; the 61st is 429 and runs nothing; global stops every token', async () => {
  await primeFixtures();
  const a = await mint('read');
  const b = await mint('read');
  const h = await hosted(await tokensFile([a.row, b.row]));
  try {
    for (let i = 0; i < 60; i++) {
      const r = i % 3 === 0 ? await callTool(h.port, a.token, 'zeusi_context_for_task', { task: 'Northbank prod' })
        : i % 3 === 1 ? await rpc(h.port, a.token, 'prompts/get', { name: 'start-task', arguments: { task: 'x' } })
          : await rpc(h.port, a.token, 'resources/read', { uri: 'zeusi://about' });
      assert.equal(r.status, 200, `message ${i + 1}`);
    }
    const reads = h.reads.length;
    for (const r of [
      await callTool(h.port, a.token, 'prime', { task: 'Northbank prod' }),
      await rpc(h.port, a.token, 'prompts/get', { name: 'start-task', arguments: { task: 'x' } }),
      await rpc(h.port, a.token, 'resources/read', { uri: 'zeusi://about' }),
    ]) {
      assert.equal(r.status, 429);
      assert.equal(r.body, '{"error":"rate_limited"}');
    }
    assert.equal(h.reads.length, reads, 'no tool ran over the limit');
    assert.equal((await callTool(h.port, b.token, 'zeusi_context_for_task', { task: 'Northbank prod' })).status, 200, 'second token unaffected');
  } finally {
    await h.close();
  }
  const g = await hosted(await tokensFile([a.row, b.row]), {}, { limits: { global: 4 } });
  try {
    assert.equal((await callTool(g.port, a.token, 'zeusi_context_for_task', { task: 'Northbank' })).status, 200);
    assert.equal((await rpc(g.port, a.token, 'resources/read', { uri: 'zeusi://about' })).status, 200);
    assert.equal((await rpc(g.port, b.token, 'prompts/get', { name: 'start-task', arguments: { task: 'x' } })).status, 200);
    assert.equal((await callTool(g.port, b.token, 'prime', { task: 'Northbank' })).status, 200);
    assert.equal((await callTool(g.port, a.token, 'prime', { task: 'Northbank' })).status, 429, 'global limit');
  } finally {
    await g.close();
  }
});

test('hosted prime: the log line for zeusi_context_for_task holds the tool name and counts only; never the task, exact_words, walled text, token or host; prompts/resources log tool null', async () => {
  await primeFixtures();
  const read = await mint('read');
  const h = await hosted(await tokensFile([read.row]));
  try {
    assert.equal((await callTool(h.port, read.token, 'zeusi_context_for_task', { task: PRIME_TASK })).status, 200);
    assert.equal((await rpc(h.port, read.token, 'prompts/get', { name: 'start-task', arguments: { task: PRIME_TASK } })).status, 200);
    assert.equal((await rpc(h.port, read.token, 'resources/read', { uri: 'zeusi://about' })).status, 200);
    await new Promise((res) => setImmediate(res));
    assert.equal(h.logs.length, 3);
    const lines = h.logs.map((l) => JSON.parse(l) as Record<string, unknown>);
    for (const l of lines) assert.deepEqual(Object.keys(l), [...LOG_FIELDS]);
    assert.equal(lines[0]!['tool'], 'zeusi_context_for_task');
    assert.ok((lines[0]!['hit_count'] as number) >= 1);
    assert.equal(lines[0]!['withheld_count'], 1);
    assert.equal(lines[1]!['tool'], null);
    assert.equal(lines[2]!['tool'], null);
    const all = h.logs.join('\n');
    const { secret } = parseToken(read.token)!;
    for (const bad of ['hosted-distinctive-task-77', 'Northbank', PRIME_WORDS, 'London', read.token, secret, FAKE_HOST, WALLED, 'neon.tech', 'about']) {
      assert.ok(!all.includes(bad), `log contains ${bad.slice(0, 12)}`);
    }
  } finally {
    await h.close();
  }
});

test('hosted prime scope isolation: a reader limited to scope team never sees or counts the product lock', async () => {
  await primeFixtures();
  const read = await mint('read');
  const h = await hosted(await tokensFile([read.row]), { connectRead: asRole(PRIME_ROLE) });
  try {
    const r = await callTool(h.port, read.token, 'zeusi_context_for_task', { task: 'Northbank prod newsletter' });
    assert.equal(r.status, 200);
    const j = toolJson(r);
    assert.deepEqual((j['items'] as Array<{ source_uri: string }>).map((i) => i.source_uri), ['test:hosted-park']);
    assert.equal(j['withheld'], 0);
    assert.ok(!r.body.includes('London'));
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Fix PR A on the real hosted handler: standing note-lock rules in zeusi_startup and note locks in
// zeusi_context_for_task for a READ bearer; counts-only log (never lock text or task text).

const LOCK_TEXT = 'SYNTHETIC HOSTED LOCK: no platypusrelease without two reviews';
let lockReady: Promise<void> | undefined;
const lockFixtures = () => (lockReady ??= (async () => {
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(
    `INSERT INTO zeusi.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/handbook/hosted-locks.md', 'Hosted locks (synthetic)', jsonb_build_object('locks', jsonb_build_array($1::text)), 'synthetic body', now(),
             'work', 'vault_note', 'vault:Work/handbook/hosted-locks.md', now(), decode($2, 'hex'), $3)`, [LOCK_TEXT, SHA, run]);
})());

test('hosted Fix PR A: a read bearer gets standing lock rules (origin note_lock, who null) and note locks in context_for_task; no write tool; the log holds counts only', async () => {
  await lockFixtures();
  const read = await mint('read');
  const h = await hosted(await tokensFile([read.row]), { writeService: 'zeusi_decision' });
  try {
    const names = rpcResult(await rpc(h.port, read.token, 'tools/list')).tools!.map((t) => t.name);
    assert.ok(!names.includes('zeusi_log_decision') && !names.includes('log_decision'));
    const s = await callTool(h.port, read.token, 'zeusi_startup', {});
    assert.equal(s.status, 200);
    const rules = toolJson(s)['rules'] as Array<{ origin: string; text: string; who?: unknown; source_uri: string; cite: string }>;
    const lock = rules.find((r) => r.origin === 'note_lock')!;
    assert.equal(lock.text, LOCK_TEXT);
    assert.ok(!('who' in lock), 'compact startup form: no speaker field for a note lock (never an invented who)');
    assert.equal(lock.source_uri, 'vault:Work/handbook/hosted-locks.md');
    assert.match(lock.cite, /^vault:Work\/handbook\/hosted-locks\.md @ \d{4}-/);
    const c = await callTool(h.port, read.token, 'zeusi_context_for_task', { task: 'ship the platypusrelease (marker-5151)' });
    assert.equal(c.status, 200);
    const items = toolJson(c)['items'] as Array<{ origin: string; kind: string; exact_words: string; who: unknown }>;
    assert.deepEqual(items.map((i) => [i.origin, i.kind, i.exact_words, i.who]), [['note_lock', 'lock', LOCK_TEXT, null]]);
    await new Promise((res) => setImmediate(res));
    const all = h.logs.join('\n');
    for (const bad of ['platypusrelease', 'marker-5151', 'SYNTHETIC HOSTED LOCK', 'Hosted locks', read.token]) assert.ok(!all.includes(bad), `log contains ${bad.slice(0, 12)}`);
    assert.deepEqual(h.writes, []);
  } finally {
    await h.close();
  }
});

test('hosted onboarding (PR2 U6): a read bearer lists and calls zeusi_onboarding_status / onboarding_status and gets the onboarding prompt; counts only; per-token limit applies; log holds the tool name and counts only', async () => {
  await primeFixtures();
  const read = await mint('read');
  const h = await hosted(await tokensFile([read.row]), { writeService: 'zeusi_decision' });
  try {
    const names = rpcResult(await rpc(h.port, read.token, 'tools/list')).tools!.map((t) => t.name);
    for (const n of ['zeusi_onboarding_status', 'onboarding_status']) assert.ok(names.includes(n), n);
    for (const n of ['zeusi_onboarding_status', 'onboarding_status']) {
      const r = await callTool(h.port, read.token, n, {});
      assert.equal(r.status, 200, n);
      const j = toolJson(r);
      assert.equal(j['empty'], false);
      assert.ok(((j['counts'] as Record<string, number>)['decisions'] ?? 0) >= 1);
      for (const bad of [PRIME_WORDS, 'London', WALLED, 'test:hosted-lock']) assert.ok(!r.body.includes(bad), bad);
    }
    const p = rpcResult(await rpc(h.port, read.token, 'prompts/get', { name: 'onboarding', arguments: {} }));
    assert.match(p.messages![0]!.content.text, /zeusi_onboarding_status/);
    assert.match(p.messages![0]!.content.text, /cannot run the import for you/);
    await new Promise((res) => setImmediate(res));
    const lines = h.logs.map((l) => JSON.parse(l) as Record<string, unknown>);
    const tl = lines.filter((l) => l['tool'] === 'zeusi_onboarding_status' || l['tool'] === 'onboarding_status');
    assert.equal(tl.length, 2);
    for (const l of lines) assert.deepEqual(Object.keys(l), [...LOG_FIELDS]);
    assert.ok(!h.logs.join('\n').includes(PRIME_WORDS));
    assert.deepEqual(h.writes, [], 'nothing connected for writing');
  } finally {
    await h.close();
  }
  const g = await hosted(await tokensFile([read.row]));
  try {
    for (let i = 0; i < 60; i++) assert.equal((await callTool(g.port, read.token, 'onboarding_status', {})).status, 200, `message ${i + 1}`);
    const reads = g.reads.length;
    const r = await callTool(g.port, read.token, 'zeusi_onboarding_status', {});
    assert.equal(r.status, 429);
    assert.equal(g.reads.length, reads, 'nothing ran over the limit');
  } finally {
    await g.close();
  }
});

test('hosted onboarding scope isolation: a reader limited to scope team does not count the product rows', async () => {
  await primeFixtures();
  const read = await mint('read');
  const h = await hosted(await tokensFile([read.row]), { connectRead: asRole(PRIME_ROLE) });
  try {
    const all = toolJson(await callTool(h.port, read.token, 'zeusi_onboarding_status', {}));
    const tape = toolJson(await callTool(h.port, read.token, 'zeusi_onboarding_status', { scope: 'product' }));
    assert.equal((tape['counts'] as Record<string, number>)['decisions'], 0);
    assert.equal(tape['empty'], true);
    assert.ok(((all['counts'] as Record<string, number>)['decisions'] ?? 0) >= 1, 'the shared park is visible');
  } finally {
    await h.close();
  }
});

test('hosted Fix PR A x #23 serve guard: a read bearer never gets a planted partial key from a lock item, a note title, a linked field or a hybrid hit (startup, context_for_task, search); withheld and counted, log counts only', async () => {
  const cleanup = await plantGuardFixtures(db);
  const read = await mint('read');
  const h = await hosted(await tokensFile([read.row]));
  try {
    await assertGuardedChannels(async (name, args) => {
      const r = await callTool(h.port, read.token, name, args);
      return { status: r.status, body: r.body, json: r.status === 200 ? toolJson(r) : {} };
    });
    await new Promise((res) => setImmediate(res));
    assertGuardLog(h.logs);
  } finally {
    await h.close();
    await cleanup();
  }
});
