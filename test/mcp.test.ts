// Zeusi MCP connector (docs/mcp.md): tools zeusi_startup, zeusi_search, zeusi_log_decision,
// zeusi_search_feedback over the official SDK. Tests drive the real server through the SDK
// Client + InMemoryTransport against PGlite (SET ROLE per connection). No network, no Neon,
// no OpenAI: embeddings are null (lexical) or the fake client.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import { RO_PASSWORD_ENV, type Db } from '../src/db.ts';
import { search as realSearch, type SearchOptions } from '../src/search.ts';
import { TRANSPORT_ENV, type ServerlessClientLike } from '../src/transport.ts';
import {
  createZeusiMcpServer, createMcpState, MCP_INSTRUCTIONS, TOOL_NAMES, TOOL_ALIASES, ALL_TOOL_NAMES, WRITE_ROLE, WRITE_ROLES,
  TRANSITIONAL_WRITE_ROLE, DEFAULT_DECISION_DAYS, WORKSPACE_WRITE_TOOL_NAMES,
  type McpDeps,
} from '../src/mcp-server.ts';
import { parseMcpArgs, McpArgsError } from '../src/mcp.ts';
import { insertDecision } from '../src/decisions.ts';
import { withheld } from '../src/mcp-wall.ts';
import { recordFeedback } from '../src/feedback.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

// Synthetic strings assembled at runtime (never real content or secrets).
const WALLED = ['Plan', 'kiva synthetic wall probe'].join('');
const SECRETISH = ['pass', 'word=', 'hunter2hunter2xyz'].join('');
const FAKE_HOST = ['ep-fake-333', '-pooler.eu-central-1.aws.neon.tech'].join('');
const SHA = 'ab'.repeat(32);

let db: Db;
let home: string;
let roHome: string;

function serviceFile(dir: string, sections: Record<string, string>): void {
  const body = Object.entries(sections).map(([name, user]) =>
    `[${name}]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`).join('\n');
  writeFileSync(join(dir, '.pg_service.conf'), body);
}

/** A Db over the shared PGlite that runs as `role` (SET ROLE on open, RESET on close). */
function asRole(role: string, log?: string[]): (service: string) => Promise<Db> {
  return async (service: string) => {
    log?.push(`${service}:${role}`);
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

interface Harness {
  client: Client;
  close: () => Promise<void>;
}

async function connect(over: Partial<McpDeps> = {}): Promise<Harness> {
  const deps: McpDeps = {
    env: { HOME: home },
    home,
    readService: 'zeusi_ro',
    connectRead: asRole('zeusi_box_ro'),
    connectWrite: asRole('zeusi_box_rw'),
    embeddings: () => null,
    feedbackPath: join(home, '.zeusi', 'search-feedback.jsonl'),
    queryLedgerPath: join(home, '.zeusi', 'query-embed-ledger.json'),
    ...over,
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

type CallResult = { isError?: boolean; content: Array<{ type: string; text?: string }>; structuredContent?: Record<string, unknown> };

async function call(h: Harness, name: string, args: Record<string, unknown>): Promise<CallResult> {
  return (await h.client.callTool({ name, arguments: args })) as CallResult;
}

const textOf = (r: CallResult) => r.content.map((c) => c.text ?? '').join('\n');
const jsonOf = (r: CallResult) => JSON.parse(textOf(r)) as Record<string, unknown>;

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-mcp-'));
  roHome = safeMkdtemp(join(tmpdir(), 'zeusi-mcp-ro-'));
  serviceFile(home, {
    zeusi_ro: 'zeusi_box_ro', zeusi_rw: 'zeusi_box_rw', zeusi_cloud: 'zeusi_cloud_ro', zeusi_ingest: 'zeusi_mini_ingest',
    zeusi_decision: 'zeusi_box_decision', zeusi_backup: 'zeusi_mini_backup', zeusi_owner: 'neondb_owner',
  });
  serviceFile(roHome, { zeusi_ro: 'zeusi_box_ro', zeusi_rw: 'zeusi_box_ro' }); // a "write" service misconfigured to an ro login
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'manual:people/owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  const fact = (kind: string, subject: string, text: string, uri: string) => db.query(
    `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, $2, $3, 'work', 'manual', $4, now(), sha256(convert_to($4, 'UTF8')), $5)`, [kind, subject, text, uri, run]);
  await fact('rule', 'merge-gate', 'Never merge without an independent review on the exact head.', 'vault:Work/handbook/rules.md#merge');
  await fact('state', 'focus', 'Current focus: Zeusi MCP connector.', 'vault:Work/handbook/focus.md');
  const dec = (words: string, ago: string, uri: string) => db.query(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner'), now() - $2::interval, 'minute', $1, true, 'work', 'manual', $3, now() - $2::interval, sha256(convert_to($3, 'UTF8')), $4)`,
    [words, ago, uri, run]);
  await dec('Yes pls do that', '1 day', 'hq:example-thread');
  await dec('Old go from long ago', '60 days', 'hq:old-go');
  // Rows that predate a wall rule (stale) or carry a credential: the trigger is disabled so they exist; the MCP output wall must omit them.
  await db.exec('ALTER TABLE zeusi.facts DISABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.decisions DISABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.chunks DISABLE TRIGGER zeusi_90_wall');
  await fact('rule', 'walled', `stale row ${WALLED}`, 'vault:Work/handbook/stale.md');
  await fact('state', 'creds', `focus ${SECRETISH}`, 'vault:Work/handbook/creds.md');
  await dec(`walled decision ${WALLED}`, '2 days', 'hq:walled');
  const nid = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/research/mcp.md', 'mcp', 'b', now(), 'work', 'vault_note', 'vault:Work/research/mcp.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  const chunk = (i: number, text: string) => db.query(
    `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
     VALUES ($1, $2, 'Connector > Tools', $3, sha256(convert_to($3, 'UTF8')), 5, $4)`, [nid, i, text, `vault:Work/research/mcp.md#c${i}`]);
  await chunk(0, 'zebrafinch connector startup tools are read only');
  await chunk(1, `zebrafinch ${WALLED}`);
  await chunk(2, `zebrafinch ${SECRETISH}`);
  await db.exec('ALTER TABLE zeusi.facts ENABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.decisions ENABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.chunks ENABLE TRIGGER zeusi_90_wall');
});
after(async () => db.close());

const decisionArgs = (over: Record<string, unknown> = {}) => ({
  kind: 'go', who: 'owner', said_at: '2026-11-16T10:00:00Z', exact_words: 'Ship the MCP connector as a draft PR',
  exact_words_verbatim: true, scope: 'work', source_uri: 'hq:example-thread', source_ts: '2026-11-16T10:00:00Z', ...over,
});

// ---------------------------------------------------------------------------
// Server surface

test('mcp: server instructions tell every client to call zeusi_startup, then zeusi_search before answering or asking, and cite', async () => {
  const h = await connect({ writeService: 'zeusi_decision' });
  try {
    const ins = h.client.getInstructions() ?? '';
    assert.equal(ins, MCP_INSTRUCTIONS);
    assert.match(ins, /session start.*zeusi_startup/is);
    assert.match(ins, /before answering.*asking.*zeusi_search/is);
    assert.match(ins, /source_uri/);
    assert.match(ins, /source_ts/);
  } finally {
    await h.close();
  }
});

test('mcp: lists the zeusi_* tools plus the aliases startup/search/log_decision/context_for_task/prime; read tools are annotated read-only, the write tool is not', async () => {
  const h = await connect({ writeService: 'zeusi_decision' });
  try {
    const { tools } = await h.client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), [...TOOL_NAMES, 'startup', 'search', 'log_decision', 'context_for_task', 'prime', 'onboarding_status'].sort());
    assert.deepEqual([...ALL_TOOL_NAMES].sort(), tools.map((t) => t.name).sort());
    const by = new Map(tools.map((t) => [t.name, t]));
    assert.equal(by.get('zeusi_startup')!.annotations?.readOnlyHint, true);
    assert.equal(by.get('zeusi_search')!.annotations?.readOnlyHint, true);
    assert.equal(by.get('zeusi_log_decision')!.annotations?.readOnlyHint, false);
    // Each alias has exactly its target's input schema and annotations, and says what it aliases.
    for (const [alias, target] of Object.entries(TOOL_ALIASES)) {
      assert.deepEqual(by.get(alias)!.inputSchema, by.get(target)!.inputSchema, alias);
      assert.deepEqual(by.get(alias)!.annotations, by.get(target)!.annotations, alias);
      assert.match(by.get(alias)!.description ?? '', new RegExp(`^Alias of ${target}\\.`));
    }
    assert.equal(by.has('search_feedback'), false, 'feedback has no alias');
  } finally {
    await h.close();
  }
});

// The four MCP tool annotations, pinned for every tool the server can list. A directory (OpenAI's) refuses a tool
// that omits one, and MCP reads an omitted destructiveHint or openWorldHint as true. The values follow the handlers:
// zeusi_search may send the query to the OpenAI embeddings API, and each such call is billed and counted in the
// local spend ledger (open world, not idempotent); zeusi_search_feedback appends a ledger line per call;
// zeusi_import_preview keeps a new preview per call; zeusi_sync_batch marks the listed notes deleted.
const HINTS = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'] as const;
const TOOL_HINTS: Record<string, Record<(typeof HINTS)[number], boolean>> = {
  zeusi_startup: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  zeusi_search: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  zeusi_log_decision: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  zeusi_context_for_task: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  zeusi_onboarding_status: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  zeusi_search_feedback: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  zeusi_import_preview: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  zeusi_import_commit: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  zeusi_sync_batch: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
};

test('mcp annotations: in every registration mode each listed tool (all 9 zeusi_* tools and every alias) declares all four hints as booleans, with the pinned values; an alias has its target\'s', async () => {
  const tenantRead = async (): Promise<Db> => { throw new Error('tools/list opens no workspace'); };
  const modes: Array<[string, Partial<McpDeps>]> = [
    ['read-only connector (no write service)', {}],
    ['read class with a write service', { toolClass: 'read', writeService: 'zeusi_decision' }],
    ['write service (zeusi_log_decision)', { writeService: 'zeusi_decision' }],
    ['personal workspace, read grant', { workspace: 'personal', tenantRead }],
    ['personal workspace, write grant (import / sync)', {
      workspace: 'personal', tenantRead,
      workspaceWrite: { caller: { tenantId: 'tannotations', grantId: 'gannotations', subject: null, requestId: null }, writes: null },
    }],
  ];
  const listed = new Set<string>();
  for (const [mode, over] of modes) {
    const h = await connect(over);
    try {
      const { tools } = await h.client.listTools();
      const by = new Map(tools.map((t) => [t.name, t]));
      for (const t of tools) {
        const a = (t.annotations ?? {}) as Record<string, unknown>;
        for (const k of HINTS) assert.equal(typeof a[k], 'boolean', `${mode}: ${t.name} ${k}`);
        const target: string = (TOOL_ALIASES as Record<string, string>)[t.name] ?? t.name;
        assert.deepEqual(t.annotations, TOOL_HINTS[target], `${mode}: ${t.name}`);
        if (target !== t.name) assert.deepEqual(t.annotations, by.get(target)!.annotations, `${mode}: alias ${t.name} of ${target}`);
        listed.add(t.name);
      }
    } finally {
      await h.close();
    }
  }
  // Every zeusi_* tool and every alias was listed, and so checked, in at least one mode.
  assert.deepEqual([...listed].sort(), [...ALL_TOOL_NAMES, ...WORKSPACE_WRITE_TOOL_NAMES].sort());
  assert.deepEqual(Object.keys(TOOL_HINTS).sort(), [...TOOL_NAMES, ...WORKSPACE_WRITE_TOOL_NAMES].sort());
});

test('mcp aliases: startup / search / log_decision run the same handlers, gates and walls as the zeusi_* tools', async () => {
  // startup + search as zeusi_box_ro: same output shape as the canonical tool.
  // (Decisions written here are dated 2020, outside every startup window, so later tests see the same startup.)
  const log: string[] = [];
  const h = await connect({ connectRead: asRole('zeusi_box_ro', log), writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', log) });
  try {
    const a = jsonOf(await call(h, 'startup', {}));
    const b = jsonOf(await call(h, 'zeusi_startup', {}));
    delete a['generated_at'];
    delete b['generated_at'];
    assert.deepEqual(a, b);
    const s1 = jsonOf(await call(h, 'search', { query: 'zebrafinch' }));
    const s2 = jsonOf(await call(h, 'zeusi_search', { query: 'zebrafinch' }));
    assert.deepEqual(s1['hits'], s2['hits']);
    assert.equal(s1['withheld'], s2['withheld']);
    assert.ok((s1['withheld'] as number) >= 1, 'the alias also walls');
    assert.ok(!/plankiva/i.test(JSON.stringify(s1)));
    // feedback accepts the query_id from the alias search (shared state)
    const hit = (s1['hits'] as Array<{ source_uri: string }>)[0]!;
    assert.ok(!(await call(h, 'zeusi_search_feedback', { query_id: s1['query_id'], source_uri: hit.source_uri, useful: true })).isError);
    // strict schema on the alias too
    assert.equal((await call(h, 'search', { query: 'x', nope: 1 })).isError, true);
    // log_decision alias writes through the same gate as zeusi_log_decision
    const w = jsonOf(await call(h, 'log_decision', decisionArgs({ source_uri: 'hq:alias-log', said_at: '2020-01-01T00:00:00Z', source_ts: '2020-01-01T00:00:00Z', exact_words: 'Alias decision synthetic' })));
    assert.equal(w['status'], 'inserted');
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:alias-log'`)).rows[0]!.n, 1);
  } finally {
    await h.close();
  }
  // `search` is refused for a write-role read misconfig exactly like zeusi_search (no connection).
  const calls: string[] = [];
  const bad = await connect({ readService: 'zeusi_rw', connectRead: asRole('zeusi_box_rw', calls) });
  try {
    for (const name of ['search', 'zeusi_search', 'startup', 'zeusi_startup']) {
      const r = await call(bad, name, name.endsWith('search') ? { query: 'zebrafinch' } : {});
      assert.equal(r.isError, true, name);
      assert.match(textOf(r), /read-only login/, name);
    }
    assert.deepEqual(calls, []);
  } finally {
    await bad.close();
  }
  // `log_decision` shares the write gate: read-only connector (not listed) and *_ro write user refused, no connection.
  const wcalls: string[] = [];
  const ro = await connect({ connectWrite: asRole('zeusi_box_decision', wcalls) });
  const rw = await connect({ writeService: 'zeusi_ro', connectWrite: asRole('zeusi_box_decision', wcalls) });
  try {
    for (const name of ['log_decision', 'zeusi_log_decision']) {
      // F4: without a write service the tool is not registered at all; calling it still fails.
      const r1 = await call(ro, name, decisionArgs()).catch((e: unknown) => ({ isError: true, content: [{ type: 'text', text: String(e) }] }));
      assert.equal(r1.isError, true);
      const r2 = await call(rw, name, decisionArgs());
      assert.equal(r2.isError, true);
      assert.match(textOf(r2), new RegExp(`only ${WRITE_ROLE}`));
    }
    assert.deepEqual(wcalls, []);
  } finally {
    await ro.close();
    await rw.close();
  }
});

// ---------------------------------------------------------------------------
// zeusi_startup

test('mcp startup: rules, focus and decisions in the last N days as zeusi_box_ro; old decisions excluded', async () => {
  const log: string[] = [];
  const h = await connect({ connectRead: asRole('zeusi_box_ro', log) });
  try {
    const r = await call(h, 'zeusi_startup', {});
    assert.ok(!r.isError, textOf(r));
    const j = jsonOf(r) as { days: number; rules: Array<Record<string, string>>; focus: Array<Record<string, string>>; decisions: Array<Record<string, string>>; withheld: number };
    assert.equal(j.days, DEFAULT_DECISION_DAYS);
    assert.deepEqual(j.rules.map((x) => x['source_uri']), ['vault:Work/handbook/rules.md#merge']);
    // Security P0 (final design): the credential focus row is WITHHELD at serve, as on main.
    assert.deepEqual(j.focus.map((x) => x['source_uri']), ['vault:Work/handbook/focus.md']);
    assert.ok(!JSON.stringify(j).includes(SECRETISH) && !JSON.stringify(j).includes('[REDACTED:'));
    assert.deepEqual(j.decisions.map((x) => x['source_uri']), ['hq:example-thread']);
    assert.equal(j.decisions[0]!['who'], 'owner');
    assert.ok(j.decisions[0]!['source_ts']);
    assert.equal(j.withheld, 3, 'walled rule, credential focus and walled decision are counted, not shown');
    assert.deepEqual(log, ['zeusi_ro:zeusi_box_ro']);
    const wide = jsonOf(await call(h, 'zeusi_startup', { days: 90 })) as { decisions: unknown[] };
    assert.equal(wide.decisions.length, 2);
  } finally {
    await h.close();
  }
});

test('mcp startup: refused on a session that can write (mutant: skipping the read-only session check)', async () => {
  const h = await connect({ connectRead: asRole('zeusi_box_rw') });
  try {
    const r = await call(h, 'zeusi_startup', {});
    assert.equal(r.isError, true);
    assert.match(textOf(r), /read-only/);
  } finally {
    await h.close();
  }
});

test('mcp startup/search: refused BEFORE connecting when the read service user is not a read-only login (mutant: write role for reads)', async () => {
  for (const svc of ['zeusi_rw', 'zeusi_ingest']) {
    const log: string[] = [];
    const h = await connect({ readService: svc, connectRead: asRole('zeusi_box_ro', log) });
    try {
      for (const [tool, args] of [['zeusi_startup', {}], ['zeusi_search', { query: 'zebrafinch' }]] as const) {
        const r = await call(h, tool, args);
        assert.equal(r.isError, true, `${tool} via ${svc}`);
        assert.match(textOf(r), /read-only/);
      }
      assert.deepEqual(log, [], 'no connection attempted');
    } finally {
      await h.close();
    }
  }
  const ok = await connect({ readService: 'zeusi_cloud' }); // zeusi_cloud_ro is a read-only login
  try {
    assert.ok(!(await call(ok, 'zeusi_startup', {})).isError);
  } finally {
    await ok.close();
  }
});

// ---------------------------------------------------------------------------
// zeusi_search

test('mcp search: reuses search() (same function, same options) and returns cite-ready hits + query_id', async () => {
  const seen: SearchOptions[] = [];
  const spy = async (o: SearchOptions) => {
    seen.push(o);
    return realSearch(o);
  };
  const h = await connect({ searchFn: spy });
  try {
    const r = await call(h, 'zeusi_search', { query: 'zebrafinch', limit: 5, scope: 'work' });
    assert.ok(!r.isError, textOf(r));
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.query, 'zebrafinch');
    assert.equal(seen[0]!.limit, 5);
    assert.equal(seen[0]!.scope, 'work');
    const j = jsonOf(r) as { query_id: string; mode: string; hits: Array<Record<string, unknown>>; withheld: number };
    assert.match(j.query_id, /^[0-9a-f-]{36}$/);
    assert.equal(j.mode, 'lexical');
    assert.equal(j.hits.length, 1, 'the credential hit is withheld (never served redacted)');
    assert.deepEqual(Object.keys(j.hits[0]!).sort(), ['heading_path', 'scope', 'score', 'source_ts', 'source_uri', 'text']);
    assert.equal(j.hits[0]!['source_uri'], 'vault:Work/research/mcp.md#c0');
    assert.equal(j.hits[0]!['heading_path'], 'Connector > Tools');
    assert.equal(j.hits[0]!['text'], 'zebrafinch connector startup tools are read only');
    assert.equal(j.withheld, 2);
  } finally {
    await h.close();
  }
  // the default searchFn IS the existing search export
  const { DEFAULT_SEARCH_FN } = await import('../src/mcp-server.ts');
  assert.equal(DEFAULT_SEARCH_FN, realSearch);
});

test('mcp search: refused on a write session through the existing search() check', async () => {
  const h = await connect({ connectRead: asRole('zeusi_box_rw') });
  try {
    const r = await call(h, 'zeusi_search', { query: 'zebrafinch' });
    assert.equal(r.isError, true);
    assert.match(textOf(r), /read-only role/);
  } finally {
    await h.close();
  }
});

test('mcp search: limit and scope caps refused cleanly (no connection)', async () => {
  const log: string[] = [];
  const h = await connect({ connectRead: asRole('zeusi_box_ro', log) });
  try {
    for (const args of [{ query: 'x', limit: 51 }, { query: 'x', limit: 0 }, { query: 'x', scope: 'personal' }, { query: '' }, { query: 'x', limit: 1.5 }]) {
      const r = await call(h, 'zeusi_search', args);
      assert.equal(r.isError, true, JSON.stringify(args));
    }
    assert.deepEqual(log, []);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// zeusi_log_decision role gates

test('mcp log_decision: no write service configured (read-only connector): not listed (F4), calling it fails, nothing connected', async () => {
  const log: string[] = [];
  const h = await connect({ connectWrite: asRole('zeusi_box_rw', log) });
  try {
    assert.deepEqual((await h.client.listTools()).tools.map((t) => t.name).sort(), ['zeusi_startup', 'zeusi_search', 'zeusi_search_feedback', 'startup', 'search', 'zeusi_context_for_task', 'context_for_task', 'prime', 'zeusi_onboarding_status', 'onboarding_status'].sort());
    for (const name of ['zeusi_log_decision', 'log_decision']) {
      const r = await call(h, name, decisionArgs()).catch((e: unknown) => ({ isError: true, content: [{ type: 'text', text: String(e) }] }));
      assert.equal(r.isError, true, name);
    }
    assert.deepEqual(log, []);
  } finally {
    await h.close();
  }
});

test('mcp log_decision: a *_ro write-service user is refused BEFORE any credential is read (mutants: allowed under *_ro; credential read first)', async () => {
  const securityCalls: string[][] = [];
  const log: string[] = [];
  // connectWrite: undefined -> the real connectService (the harness default is a PGlite stub,
  // which never reads a credential), with a Keychain spy: it must never run.
  // No ro env password on purpose: with one set, connectService would take it and skip the
  // Keychain, hiding an early credential read. roHome has no ~/.pgpass, so the credential
  // lookup can only go through the spy. The spy answers "not found" (44), so even a mutant
  // that reads the credential first fails before any connection attempt.
  const env: NodeJS.ProcessEnv = { HOME: roHome };
  assert.equal(env[RO_PASSWORD_ENV], undefined);
  const h = await connect({
    home: roHome, env, writeService: 'zeusi_rw', connectWrite: undefined,
    runSecurity: async (args) => { securityCalls.push(args); return { code: 44, stdout: '' }; },
    connectRead: asRole('zeusi_box_ro', log),
  });
  try {
    const r = await call(h, 'zeusi_log_decision', decisionArgs());
    assert.equal(r.isError, true);
    assert.match(textOf(r), new RegExp(`only ${WRITE_ROLE}`));
    assert.deepEqual(securityCalls, [], 'no Keychain read');
    assert.deepEqual(log, [], 'no connection of any kind');
    assert.ok(!textOf(r).includes(FAKE_HOST));
  } finally {
    await h.close();
  }
  for (const user of ['zeusi_cloud', 'zeusi_ro', 'zeusi_ingest']) {
    const calls: string[] = [];
    const g = await connect({ writeService: user, connectWrite: asRole('zeusi_box_rw', calls) });
    try {
      assert.equal((await call(g, 'zeusi_log_decision', decisionArgs())).isError, true, user);
      assert.deepEqual(calls, []);
    } finally {
      await g.close();
    }
  }
});

test('mcp log_decision: a live session that is not zeusi_box_rw is refused before any INSERT (config says rw, session is ro)', async () => {
  const before = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions`)).rows[0]!.n;
  const h = await connect({ writeService: 'zeusi_rw', connectWrite: asRole('zeusi_box_ro') });
  try {
    const r = await call(h, 'zeusi_log_decision', decisionArgs());
    assert.equal(r.isError, true);
    assert.match(textOf(r), /refused/);
  } finally {
    await h.close();
  }
  const afterN = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions`)).rows[0]!.n;
  assert.equal(afterN, before);
});

test('mcp log_decision: inserts one sourced decision as zeusi_box_rw (agent_write, own ingest run) and returns ids only', async () => {
  const h = await connect({ writeService: 'zeusi_rw' });
  try {
    const r = await call(h, 'zeusi_log_decision', decisionArgs({ applies_to: ['zeusi'] }));
    assert.ok(!r.isError, textOf(r));
    const j = jsonOf(r) as { status: string; id: number; ingest_run_id: number };
    assert.equal(j.status, 'inserted');
    assert.ok(!textOf(r).includes('Ship the MCP connector'), 'exact words are not echoed');
    const row = (await db.query<Record<string, unknown>>(
      `SELECT d.kind::text AS kind, d.source_kind::text AS sk, d.source_uri, d.applies_to, p.handle, r.importer, r.mode, r.status
       FROM zeusi.decisions d JOIN zeusi.people p ON p.id = d.who_id JOIN zeusi.ingest_runs r ON r.id = d.ingest_run_id WHERE d.id = $1`, [j.id])).rows[0]!;
    assert.deepEqual(row, { kind: 'go', sk: 'agent_write', source_uri: 'hq:example-thread', applies_to: ['zeusi'], handle: 'owner', importer: 'mcp', mode: 'agent', status: 'ok' });
    const dup = await call(h, 'zeusi_log_decision', decisionArgs({ applies_to: ['zeusi'] }));
    assert.equal(dup.isError, true, 'same source + same content is refused (unique)');
    const unknown = await call(h, 'zeusi_log_decision', decisionArgs({ who: 'nobody', source_uri: 'hq:x1' }));
    assert.equal(unknown.isError, true);
    assert.match(textOf(unknown), /unknown person/);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Decision-write role (migrations/0012, applied here on PGlite; NOT applied on Neon)

test('mcp log_decision: zeusi_box_decision (0012) is the preferred write login; zeusi_box_rw stays as the transitional fallback', async () => {
  assert.equal(WRITE_ROLE, 'zeusi_box_decision');
  assert.equal(TRANSITIONAL_WRITE_ROLE, 'zeusi_box_rw');
  assert.deepEqual([...WRITE_ROLES], ['zeusi_box_decision', 'zeusi_box_rw']);
  const log: string[] = [];
  const h = await connect({ writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', log) });
  try {
    const r = await call(h, 'zeusi_log_decision', decisionArgs({ source_uri: 'hq:decision-role', said_at: '2020-01-01T00:00:00Z', source_ts: '2020-01-01T00:00:00Z', exact_words: 'Decision role synthetic' }));
    assert.ok(!r.isError, textOf(r));
    const j = jsonOf(r) as { status: string; id: number; ingest_run_id: number };
    assert.equal(j.status, 'inserted');
    assert.deepEqual(log, ['zeusi_decision:zeusi_box_decision']);
    const run = (await db.query<{ status: string; finished: boolean }>(
      `SELECT status, finished_at IS NOT NULL AS finished FROM zeusi.ingest_runs WHERE id = $1`, [j.ingest_run_id])).rows[0]!;
    assert.deepEqual(run, { status: 'ok', finished: true }, 'the narrow role opens and closes its own ingest run');
  } finally {
    await h.close();
  }
  // transitional: a zeusi_box_rw service is still accepted (covered in depth by the zeusi_box_rw test above)
  const t = await connect({ writeService: 'zeusi_rw', connectWrite: asRole('zeusi_box_rw') });
  try {
    const r = await call(t, 'log_decision', decisionArgs({ source_uri: 'hq:transitional-rw', said_at: '2020-01-01T00:00:00Z', source_ts: '2020-01-01T00:00:00Z', exact_words: 'Transitional synthetic' }));
    assert.ok(!r.isError, textOf(r));
  } finally {
    await t.close();
  }
});

test('mcp log_decision: the live session must be the SAME write login the service names (mutant: any write role accepted live)', async () => {
  for (const [service, liveRole] of [['zeusi_decision', 'zeusi_box_rw'], ['zeusi_rw', 'zeusi_box_decision'], ['zeusi_decision', 'zeusi_mini_ingest']] as const) {
    const before = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions`)).rows[0]!.n;
    const h = await connect({ writeService: service, connectWrite: asRole(liveRole) });
    try {
      const r = await call(h, 'zeusi_log_decision', decisionArgs({ source_uri: `hq:mismatch-${liveRole}` }));
      assert.equal(r.isError, true, `${service} as ${liveRole}`);
      assert.match(textOf(r), /refused/);
    } finally {
      await h.close();
    }
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions`)).rows[0]!.n, before);
  }
});

test('mcp log_decision: *_ro, ingest, backup and owner write services are refused before any credential read or connection (both names)', async () => {
  for (const service of ['zeusi_ro', 'zeusi_cloud', 'zeusi_ingest', 'zeusi_backup', 'zeusi_owner']) {
    const securityCalls: string[][] = [];
    const calls: string[] = [];
    const h = await connect({
      writeService: service, connectWrite: undefined, connectRead: asRole('zeusi_box_ro', calls),
      runSecurity: async (a) => { securityCalls.push(a); return { code: 44, stdout: '' }; },
    });
    try {
      for (const name of ['zeusi_log_decision', 'log_decision']) {
        const r = await call(h, name, decisionArgs());
        assert.equal(r.isError, true, `${service} ${name}`);
        assert.match(textOf(r), /No credential read, nothing written/);
        assert.ok(!textOf(r).includes(FAKE_HOST));
      }
      assert.deepEqual(securityCalls, [], `${service}: no Keychain read`);
      assert.deepEqual(calls, [], `${service}: no connection`);
    } finally {
      await h.close();
    }
  }
});

test('mcp log_decision: zeusi_box_decision is refused under ZEUSI_TRANSPORT=serverless before any credential read (no serverless write exception)', async () => {
  const securityCalls: string[][] = [];
  const h = await connect({
    env: { HOME: home, [TRANSPORT_ENV]: 'serverless' }, writeService: 'zeusi_decision', connectWrite: undefined,
    runSecurity: async (a) => { securityCalls.push(a); return { code: 0, stdout: 'x\n' }; },
  });
  try {
    for (const name of ['zeusi_log_decision', 'log_decision']) {
      const r = await call(h, name, decisionArgs({ source_uri: 'hq:sl-decision' }));
      assert.equal(r.isError, true);
      assert.match(textOf(r), /serverless/);
    }
    assert.deepEqual(securityCalls, []);
  } finally {
    await h.close();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:sl-decision'`)).rows[0]!.n, 0);
});

test('mcp log_decision: walled or credential-like input is refused before connecting and never echoed', async () => {
  const log: string[] = [];
  const h = await connect({ writeService: 'zeusi_rw', connectWrite: asRole('zeusi_box_rw', log) });
  try {
    for (const over of [{ exact_words: `go ${WALLED}` }, { source_uri: `vault:Work/${WALLED}.md` }, { applies_to: [WALLED] }, { exact_words: SECRETISH }]) {
      const r = await call(h, 'zeusi_log_decision', decisionArgs(over));
      assert.equal(r.isError, true);
      assert.match(textOf(r), /withheld/);
      assert.ok(!textOf(r).includes(WALLED) && !textOf(r).includes(SECRETISH));
    }
    assert.deepEqual(log, []);
  } finally {
    await h.close();
  }
});

test('decisions: a wall trigger rejection (backstop) is quarantined by uri + hash, not stored', async () => {
  await db.exec('SET ROLE zeusi_box_rw');
  try {
    const r = await insertDecision(db, {
      kind: 'go', who: 'owner', saidAt: '2026-11-16T10:00:00Z', saidAtPrecision: 'minute', exactWords: `backstop ${WALLED}`,
      exactWordsVerbatim: true, appliesTo: [], scope: 'work', sourceUri: 'hq:backstop', sourceTs: '2026-11-16T10:00:00Z',
    });
    assert.equal(r.status, 'quarantined');
  } finally {
    await db.exec('RESET ROLE');
  }
  const n = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:backstop'`)).rows[0]!.n;
  assert.equal(n, 0);
  const q = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.quarantine WHERE source_uri = 'hq:backstop'`)).rows[0]!.n;
  assert.equal(q, 1);
});

// ---------------------------------------------------------------------------
// Transport gate

test('mcp transport: ZEUSI_TRANSPORT=serverless sends startup/search through the existing serverless transport; unset -> TCP; write still refused', async () => {
  const tcp: string[] = [];
  const sl: string[] = [];
  const fakeServerless = () => {
    sl.push('client');
    const c: ServerlessClientLike = {
      neonConfig: {},
      async connect() {},
      async query(sql: string, params?: unknown[]) { return db.query(sql, params) as Promise<{ rows: unknown[] }>; },
      async end() {},
    };
    return c;
  };
  const pwEnv = { ZEUSI_NEON_BOX_RO_PASSWORD: 'fake-ro-pw-x' };
  // No connectRead override: the default (connectReadOnly) is used with injected TCP / serverless seams.
  const mk = (env: NodeJS.ProcessEnv) => connect({
    env: { HOME: home, ...pwEnv, ...env }, writeService: 'zeusi_rw', connectRead: undefined,
    readOnlyOptions: { tcp: async (n: string) => { tcp.push(n); return asRole('zeusi_box_ro')(n); }, serverlessClient: fakeServerless },
  });
  await db.exec('SET ROLE zeusi_box_ro');
  try {
    const s = await mk({ [TRANSPORT_ENV]: 'serverless' });
    try {
      assert.ok(!(await call(s, 'zeusi_startup', {})).isError);
      assert.ok(!(await call(s, 'zeusi_search', { query: 'zebrafinch' })).isError);
      assert.equal(sl.length, 2);
      assert.deepEqual(tcp, []);
      const w = await call(s, 'zeusi_log_decision', decisionArgs({ source_uri: 'hq:sl' }));
      assert.equal(w.isError, true);
      assert.match(textOf(w), /serverless/);
    } finally {
      await s.close();
    }
    const t = await mk({});
    try {
      assert.ok(!(await call(t, 'zeusi_search', { query: 'zebrafinch' })).isError);
      assert.deepEqual(tcp, ['zeusi_ro']);
      assert.equal(sl.length, 2);
    } finally {
      await t.close();
    }
    const bad = await mk({ [TRANSPORT_ENV]: 'tcpp' });
    try {
      assert.equal((await call(bad, 'zeusi_search', { query: 'zebrafinch' })).isError, true);
    } finally {
      await bad.close();
    }
  } finally {
    await db.exec('RESET ROLE');
  }
  // ro write service under serverless: still the role refusal, no credential read
  const securityCalls: string[][] = [];
  const g = await connect({
    home: roHome, env: { HOME: roHome, [TRANSPORT_ENV]: 'serverless' }, writeService: 'zeusi_rw',
    runSecurity: async (a) => { securityCalls.push(a); return { code: 0, stdout: 'x\n' }; },
  });
  try {
    assert.equal((await call(g, 'zeusi_log_decision', decisionArgs())).isError, true);
    assert.deepEqual(securityCalls, []);
  } finally {
    await g.close();
  }
});

// ---------------------------------------------------------------------------
// Walls across every tool

test('mcp wall: the synthetic walled string and secrets never appear in any tool output', async () => {
  const injected = async () => ({
    mode: 'lexical' as const,
    notice: `notice: ${SECRETISH}`,
    hits: [
      { chunkId: 1, sourceUri: `vault:Work/${WALLED}.md#c0`, sourceTs: new Date().toISOString(), scope: 'work', headingPath: null, text: 'ok text', score: 1, ranks: {} },
      { chunkId: 2, sourceUri: 'vault:Work/x.md#c0', sourceTs: new Date().toISOString(), scope: 'work', headingPath: WALLED, text: 'ok', score: 1, ranks: {} },
      { chunkId: 3, sourceUri: 'vault:Work/y.md#c0', sourceTs: new Date().toISOString(), scope: 'work', headingPath: null, text: `see ${FAKE_HOST}`, score: 1, ranks: {} },
      { chunkId: 4, sourceUri: 'vault:Work/z.md#c0', sourceTs: new Date().toISOString(), scope: 'work', headingPath: null, text: 'clean', score: 1, ranks: {} },
    ],
  });
  const outputs: string[] = [];
  const h = await connect({ writeService: 'zeusi_rw' });
  const hi = await connect({ searchFn: injected });
  try {
    outputs.push(textOf(await call(h, 'zeusi_startup', { days: 90 })));
    const s = await call(h, 'zeusi_search', { query: 'zebrafinch', limit: 10 });
    outputs.push(textOf(s));
    const qid = (jsonOf(s) as { query_id: string }).query_id;
    const inj = await call(hi, 'zeusi_search', { query: 'anything' });
    outputs.push(textOf(inj));
    assert.deepEqual((jsonOf(inj) as { hits: Array<{ source_uri: string }> }).hits.map((x) => x.source_uri), ['vault:Work/z.md#c0']);
    assert.equal((jsonOf(inj) as { notice?: string }).notice, undefined, 'a notice carrying a credential is dropped');
    outputs.push(textOf(await call(h, 'zeusi_log_decision', decisionArgs({ exact_words: `x ${WALLED}` }))));
    outputs.push(textOf(await call(h, 'zeusi_search_feedback', { query_id: qid, source_uri: 'vault:Work/research/mcp.md#c0', useful: false, reason: WALLED })));
    outputs.push(textOf(await call(h, 'zeusi_search_feedback', { query_id: qid, source_uri: `vault:Work/${WALLED}`, useful: true })));
    outputs.push(textOf(await call(h, 'zeusi_search', { query: 'x', [WALLED]: 1 })));
  } finally {
    await h.close();
    await hi.close();
  }
  const all = outputs.join('\n');
  assert.ok(!/plankiva/i.test(all), 'no walled string in any output');
  assert.ok(!all.includes(SECRETISH));
  assert.ok(!all.includes(FAKE_HOST) && !/neon\.tech/.test(all));
  assert.equal(withheld([`a ${WALLED}`]), true);
  assert.equal(withheld(['clean text']), false);
});

test('mcp wall: tool errors go through safeMessage (redacted, replaced when walled); a raw error is never echoed (mutant: safeMessage returns the message)', async () => {
  const thrower = (msg: string) => async () => { throw new Error(msg); };
  const FAKE_URL = ['postgres', '://', 'u', ':', 'p', '@', FAKE_HOST, '/zeusi'].join(''); // synthetic, built at runtime
  const cases: Array<[string, (t: string) => void]> = [
    [`connect failed: ${FAKE_HOST} timed out`, (t) => {
      assert.ok(!t.includes(FAKE_HOST) && !/neon\.tech/.test(t), 'hostname redacted');
      assert.match(t, /connect failed: <host> timed out/, 'the rest of a clean message survives');
    }],
    [`dial ${FAKE_URL} refused`, (t) => {
      assert.ok(!t.includes('postgres://') && !t.includes(FAKE_HOST), 'connection string redacted');
    }],
    [`row mentions ${WALLED} here`, (t) => {
      assert.ok(!/plankiva/i.test(t), 'walled string not echoed');
      assert.match(t, /withheld by the wall/);
    }],
    [`auth said ${SECRETISH}`, (t) => {
      assert.ok(!t.includes(SECRETISH), 'credential-like text not echoed');
      assert.match(t, /withheld by the wall/);
    }],
  ];
  for (const [msg, check] of cases) {
    const h = await connect({ searchFn: thrower(msg) });
    try {
      const r = await call(h, 'zeusi_search', { query: 'zebrafinch' });
      assert.equal(r.isError, true);
      assert.notEqual(textOf(r), msg, 'not the raw error');
      check(textOf(r));
    } finally {
      await h.close();
    }
  }
});

// ---------------------------------------------------------------------------
// Feedback ledger

test('mcp feedback: local ledger 0600 records query id / uri / useful / short reason only; refuses unknown query ids, foreign uris and copied chunk text', async () => {
  const fb = join(safeMkdtemp(join(tmpdir(), 'zeusi-fb-')), '.zeusi', 'search-feedback.jsonl');
  const h = await connect({ feedbackPath: fb });
  try {
    const s = jsonOf(await call(h, 'zeusi_search', { query: 'zebrafinch' })) as { query_id: string; hits: Array<{ source_uri: string; text: string }> };
    const uri = s.hits[0]!.source_uri;
    const ok = await call(h, 'zeusi_search_feedback', { query_id: s.query_id, source_uri: uri, useful: true, reason: 'answered the merge-gate question' });
    assert.ok(!ok.isError, textOf(ok));
    assert.equal(statSync(fb).mode & 0o777, 0o600);
    const lines = readFileSync(fb, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(lines.length, 1);
    assert.deepEqual(Object.keys(lines[0]!).sort(), ['query_id', 'reason', 'source_uri', 'ts', 'useful']);
    assert.equal(lines[0]!['useful'], true);
    for (const [args, why] of [
      [{ query_id: '00000000-0000-4000-8000-000000000000', source_uri: uri, useful: true }, /unknown query_id/],
      [{ query_id: s.query_id, source_uri: 'vault:Work/other.md', useful: true }, /not a hit/],
      [{ query_id: s.query_id, source_uri: uri, useful: false, reason: s.hits[0]!.text }, /chunk text/],
      [{ query_id: s.query_id, source_uri: uri, useful: false, reason: SECRETISH }, /withheld/],
      [{ query_id: s.query_id, source_uri: uri, useful: 'yes' }, /./],
      [{ query_id: s.query_id, source_uri: uri, useful: true, reason: 'x'.repeat(201) }, /./],
    ] as const) {
      const r = await call(h, 'zeusi_search_feedback', args as Record<string, unknown>);
      assert.equal(r.isError, true, JSON.stringify(args).slice(0, 80));
      assert.match(textOf(r), why);
    }
    const raw = readFileSync(fb, 'utf8');
    assert.equal(raw.trim().split('\n').length, 1, 'refusals write nothing');
    assert.ok(!raw.includes('zebrafinch'), 'no chunk text or query text in the ledger');
    assert.ok(!raw.includes(SECRETISH) && !/plankiva/i.test(raw));
  } finally {
    await h.close();
  }
});

test('mcp feedback: an existing ~/.zeusi with looser permissions is tightened to 0700; the ledger stays 0600', async () => {
  const dir = join(safeMkdtemp(join(tmpdir(), 'zeusi-fb-loose-')), '.zeusi');
  mkdirSync(dir, { mode: 0o755 });
  chmodSync(dir, 0o755);
  assert.equal(statSync(dir).mode & 0o777, 0o755, 'precondition: loose dir');
  const fb = join(dir, 'search-feedback.jsonl');
  const h = await connect({ feedbackPath: fb });
  try {
    const s = jsonOf(await call(h, 'zeusi_search', { query: 'zebrafinch' })) as { query_id: string; hits: Array<{ source_uri: string }> };
    const r = await call(h, 'zeusi_search_feedback', { query_id: s.query_id, source_uri: s.hits[0]!.source_uri, useful: true });
    assert.ok(!r.isError, textOf(r));
  } finally {
    await h.close();
  }
  assert.equal(statSync(dir).mode & 0o777, 0o700, 'dir tightened to 0700');
  assert.equal(statSync(fb).mode & 0o777, 0o600, 'ledger 0600');
  // direct call too: a dir loosened again after the first write is tightened on the next write
  chmodSync(dir, 0o777);
  recordFeedback(fb, { queryId: '00000000-0000-4000-8000-000000000001', sourceUri: 'vault:x', useful: false });
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(fb).mode & 0o777, 0o600);
});

// ---------------------------------------------------------------------------
// Args

test('mcp args: unknown or invalid tool args are refused cleanly (isError), no connection, no echo of unknown keys', async () => {
  const log: string[] = [];
  const h = await connect({ writeService: 'zeusi_rw', connectRead: asRole('zeusi_box_ro', log), connectWrite: asRole('zeusi_box_rw', log) });
  try {
    const cases: Array<[string, Record<string, unknown>]> = [
      ['zeusi_startup', { days: 0 }], ['zeusi_startup', { days: 91 }], ['zeusi_startup', { evil: 1 }],
      ['zeusi_search', {}], ['zeusi_search', { query: 5 }], ['zeusi_search', { query: 'x', service: 'zeusi_rw' }],
      ['zeusi_log_decision', decisionArgs({ kind: 'merge' })], ['zeusi_log_decision', decisionArgs({ scope: 'personal' })],
      ['zeusi_log_decision', decisionArgs({ said_at: 'yesterday' })], ['zeusi_log_decision', decisionArgs({ who: 'Robert; DROP' })],
      ['zeusi_log_decision', decisionArgs({ role: 'owner' })], ['zeusi_log_decision', { kind: 'go' }],
      ['zeusi_search_feedback', { query_id: 'x', source_uri: 'u', useful: true }],
    ];
    for (const [tool, args] of cases) {
      const r = await call(h, tool, args);
      assert.equal(r.isError, true, `${tool} ${JSON.stringify(args).slice(0, 60)}`);
      assert.ok(!textOf(r).includes('evil') && !textOf(r).includes('owner'), 'unknown keys are not echoed');
    }
    assert.deepEqual(log, []);
    const unknownTool = await call(h, 'zeusi_migrate', {});
    assert.equal(unknownTool.isError, true);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Bin args

test('mcp bin args: stdio default; --http binds loopback only; unknown flags refused', () => {
  assert.deepEqual(parseMcpArgs([]), { transport: 'stdio', readService: 'zeusi_ro', days: DEFAULT_DECISION_DAYS });
  assert.deepEqual(parseMcpArgs(['--write-service', 'zeusi_rw']), { transport: 'stdio', readService: 'zeusi_ro', writeService: 'zeusi_rw', days: DEFAULT_DECISION_DAYS });
  assert.deepEqual(parseMcpArgs(['--http', '--port', '8787']), { transport: 'http', host: '127.0.0.1', port: 8787, readService: 'zeusi_ro', days: DEFAULT_DECISION_DAYS });
  assert.equal(parseMcpArgs(['--http', '--host', '::1', '--port', '9000']).host, '::1');
  for (const bad of [['--http', '--host', '0.0.0.0'], ['--http', '--host', '192.168.1.5'], ['--http', '--port', '70000'], ['--bogus'], ['--port', '8787']]) {
    assert.throws(() => parseMcpArgs(bad), McpArgsError, bad.join(' '));
  }
  assert.deepEqual(parseMcpArgs([], { ZEUSI_MCP_WRITE_SERVICE: 'zeusi_rw' }).writeService, 'zeusi_rw');
  assert.ok(!existsSync(join(home, 'nothing')));
});

// ---------------------------------------------------------------------------
// Hosted principal (docs/hosting.md): toolClass, observe hook, feedback memo binding.
// Undefined toolClass (stdio, --http) must behave exactly as above.

async function connectShared(over: Partial<McpDeps>, state: ReturnType<typeof createMcpState>): Promise<Harness> {
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro', connectRead: asRole('zeusi_box_ro'), embeddings: () => null,
    feedbackPath: join(safeMkdtemp(join(tmpdir(), 'zeusi-fb-')), 'search-feedback.jsonl'),
    queryLedgerPath: join(home, '.zeusi', 'query-embed-ledger.json'), ...over,
  };
  const server = createZeusiMcpServer(deps, state);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

test('mcp toolClass read: tools/list has no zeusi_log_decision / log_decision; calling either fails and nothing connects for writing', async () => {
  const writes: string[] = [];
  const h = await connect({ toolClass: 'read', writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', writes) });
  try {
    const names = (await h.client.listTools()).tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['zeusi_startup', 'zeusi_search', 'zeusi_search_feedback', 'startup', 'search', 'zeusi_context_for_task', 'context_for_task', 'prime', 'zeusi_onboarding_status', 'onboarding_status'].sort());
    for (const name of ['zeusi_log_decision', 'log_decision']) {
      const r = await call(h, name, decisionArgs({ source_uri: 'hq:read-class' })).catch((e: unknown) => ({ isError: true, content: [{ type: 'text', text: String(e) }] }));
      assert.equal(r.isError, true, name);
    }
    assert.deepEqual(writes, []);
    assert.ok(!(await call(h, 'search', { query: 'zebrafinch' })).isError, 'read tools still work');
  } finally {
    await h.close();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:read-class'`)).rows[0]!.n, 0);
});

test('mcp toolClass write without a write service: the write tool is not listed (F4), calling it fails, nothing connects', async () => {
  const writes: string[] = [];
  const h = await connect({ toolClass: 'write', connectWrite: asRole('zeusi_box_decision', writes) });
  try {
    assert.deepEqual((await h.client.listTools()).tools.map((t) => t.name).sort(), ['zeusi_startup', 'zeusi_search', 'zeusi_search_feedback', 'startup', 'search', 'zeusi_context_for_task', 'context_for_task', 'prime', 'zeusi_onboarding_status', 'onboarding_status'].sort());
    const r = await call(h, 'log_decision', decisionArgs({ source_uri: 'hq:write-no-svc' })).catch((e: unknown) => ({ isError: true, content: [{ type: 'text', text: String(e) }] }));
    assert.equal(r.isError, true);
    assert.deepEqual(writes, []);
  } finally {
    await h.close();
  }
});

test('mcp toolClass write + zeusi_box_decision under ZEUSI_TRANSPORT=serverless: refused before any credential read', async () => {
  const securityCalls: string[][] = [];
  const h = await connect({
    toolClass: 'write', tokenId: 'abcdefghijkl', env: { HOME: home, [TRANSPORT_ENV]: 'serverless' }, writeService: 'zeusi_decision', connectWrite: undefined,
    runSecurity: async (a) => { securityCalls.push(a); return { code: 0, stdout: 'x\n' }; },
  });
  try {
    const r = await call(h, 'zeusi_log_decision', decisionArgs({ source_uri: 'hq:sl-hosted' }));
    assert.equal(r.isError, true);
    assert.match(textOf(r), /serverless/);
    assert.deepEqual(securityCalls, []);
  } finally {
    await h.close();
  }
});

test('mcp toolClass undefined: tools/list equals ALL_TOOL_NAMES exactly with a write service (stdio / --http regression pin)', async () => {
  const h = await connect({ writeService: 'zeusi_decision' });
  try {
    assert.deepEqual((await h.client.listTools()).tools.map((t) => t.name).sort(), [...ALL_TOOL_NAMES].sort());
  } finally {
    await h.close();
  }
});

test('mcp observe: counts only (tool, hitCount, withheld) for search and startup; never text or query', async () => {
  const seen: Array<Record<string, unknown>> = [];
  const h = await connect({ observe: (o) => { seen.push({ ...o }); } });
  try {
    const s = jsonOf(await call(h, 'zeusi_search', { query: 'zebrafinch' }));
    const st = jsonOf(await call(h, 'startup', {}));
    const bad = await call(h, 'zeusi_search_feedback', { query_id: '00000000-0000-4000-8000-000000000000', source_uri: 'x', useful: true });
    assert.equal(bad.isError, true);
    assert.deepEqual(seen[0], { tool: 'zeusi_search', hitCount: (s['hits'] as unknown[]).length, withheld: s['withheld'], secretWithheld: 1 });
    assert.ok((seen[0]!['withheld'] as number) >= 1, 'the walled chunk is counted');
    const kept = (st['rules'] as unknown[]).length + (st['focus'] as unknown[]).length + (st['decisions'] as unknown[]).length;
    assert.deepEqual(seen[1], { tool: 'zeusi_startup', hitCount: kept, withheld: st['withheld'], secretWithheld: 1 });
    assert.deepEqual(seen[2], { tool: 'zeusi_search_feedback', hitCount: 0, withheld: 0, secretWithheld: 0, error: 'tool_refused' });
    for (const o of seen) {
      assert.ok(!('text' in o) && !('query' in o));
      assert.ok(!JSON.stringify(o).includes('zebrafinch'));
    }
  } finally {
    await h.close();
  }
});

test('mcp feedback memo binding: a query_id from token aaa is refused for token bbb and accepted for aaa', async () => {
  const state = createMcpState();
  const a = await connectShared({ tokenId: 'aaaaaaaaaaaa' }, state);
  const b = await connectShared({ tokenId: 'bbbbbbbbbbbb' }, state);
  const none = await connectShared({}, state);
  try {
    const s = jsonOf(await call(a, 'zeusi_search', { query: 'zebrafinch' })) as { query_id: string; hits: Array<{ source_uri: string }> };
    const args = { query_id: s.query_id, source_uri: s.hits[0]!.source_uri, useful: true };
    const rb = await call(b, 'zeusi_search_feedback', args);
    assert.equal(rb.isError, true);
    assert.match(textOf(rb), /unknown query_id/);
    const rn = await call(none, 'zeusi_search_feedback', args);
    assert.equal(rn.isError, true, 'a principal-less server cannot use a hosted memo');
    assert.ok(!(await call(a, 'zeusi_search_feedback', args)).isError);
  } finally {
    await a.close();
    await b.close();
    await none.close();
  }
});

test('mcp bin args: --hosted defaults (0.0.0.0, 8080, /data), --bind ::, and every forbidden combination; --http stays loopback-only', () => {
  const h = parseMcpArgs(['--hosted']);
  assert.deepEqual(h, {
    transport: 'hosted', bind: '0.0.0.0', port: 8080, publicHosts: ['mcp.zeusi.dev'], dataDir: '/data',
    tokensPath: '/data/mcp-tokens.json', workspaceImportDir: '/var/tmp/zeusi-mcp/workspace-import', readService: 'zeusi_ro', days: DEFAULT_DECISION_DAYS,
  });
  assert.equal(parseMcpArgs(['--hosted', '--bind', '::']).bind, '::');
  assert.equal(parseMcpArgs(['--hosted', '--data-dir', '/srv/z']).tokensPath, '/srv/z/mcp-tokens.json');
  assert.equal(parseMcpArgs(['--hosted'], { ZEUSI_MCP_TOKENS_PATH: '/x/t.json' }).tokensPath, '/x/t.json');
  assert.equal(parseMcpArgs(['--hosted', '--tokens-file', '/y/t.json'], { ZEUSI_MCP_TOKENS_PATH: '/x/t.json' }).tokensPath, '/y/t.json');
  assert.deepEqual(parseMcpArgs(['--hosted', '--public-host', 'a.example', '--public-host', 'b.example:8443']).publicHosts, ['a.example', 'b.example:8443']);
  for (const bad of [
    ['--hosted', '--http'], ['--hosted', '--bind', '10.0.0.5'], ['--hosted', '--bind', '127.0.0.1'], ['--http', '--bind', '0.0.0.0'],
    ['--public-host', 'mcp.zeusi.dev'], ['--http', '--public-host', 'x.example'], ['--data-dir', '/data'], ['--tokens-file', '/t.json'],
    ['--hosted', '--host', '127.0.0.1'], ['--hosted', '--port', '0'], ['--hosted', '--public-host', 'Bad Host'], ['--hosted', '--data-dir', 'rel'],
  ]) {
    assert.throws(() => parseMcpArgs(bad), McpArgsError, bad.join(' '));
  }
  // R16: --http is unchanged
  assert.throws(() => parseMcpArgs(['--http', '--host', '0.0.0.0']), McpArgsError);
  assert.deepEqual(parseMcpArgs(['--http']), { transport: 'http', host: '127.0.0.1', port: 8787, readService: 'zeusi_ro', days: DEFAULT_DECISION_DAYS });
});
