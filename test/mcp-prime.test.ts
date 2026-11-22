// "Zeusi speaks up first" over MCP (plan U3): zeusi_context_for_task + aliases context_for_task
// and prime, the zeusi://about resource, the start-task prompt, the rebuilt instructions, and the
// built-in about entries in zeusi_search. Real server through the SDK Client + InMemoryTransport
// against PGlite (SET ROLE per connection). Synthetic fixtures only (invent=NO). No network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import {
  ALL_TOOL_NAMES, createMcpState, createZeusiMcpServer, MCP_INSTRUCTIONS, mcpInstructions, TOOL_ALIASES, type McpDeps, type ToolObservation,
} from '../src/mcp-server.ts';
import { ABOUT_MARKDOWN, ABOUT_SECTIONS, ABOUT_SOURCE_TS, ABOUT_SUMMARY, aboutMarkdown } from '../src/about.ts';
import { onboardingText } from '../src/mcp-prompts.ts';
import { CANNOT_RUN_IT, ONBOARDING_COMMANDS } from '../src/onboarding.ts';
import { assertToolsAgree, CONTEXT_NOT_PERMISSION_RE, NOT_A_GO_RE } from './helpers/tool-agreement.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { hasNonRoleOperatorAddress } from './helpers/owner-terms.ts';

const WALLED = ['Plan', 'kiva synthetic wall probe'].join('');
const FAKE_HOST = ['ep-fake-555', '-pooler.eu-central-1.aws.neon.tech'].join('');
const SHA = 'ab'.repeat(32);
const TASK = 'promote Northbank to prod (distinctive-task-marker-91)';
const TEST_ROLE = 'zeusi_test_work_only';

let db: Db;
let home: string;
const ids: Record<string, number> = {};

function asRole(role: string, log?: string[]): (service: string) => Promise<Db> {
  return async (service: string) => {
    log?.push(`${service}:${role}`);
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

interface Harness { client: Client; close: () => Promise<void> }

async function connect(over: Partial<McpDeps> = {}): Promise<Harness> {
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro', connectRead: asRole('zeusi_box_ro'), connectWrite: asRole('zeusi_box_rw'),
    embeddings: () => null, feedbackPath: join(home, '.zeusi', 'search-feedback.jsonl'), queryLedgerPath: join(home, '.zeusi', 'query-embed-ledger.json'),
    ...over,
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

type CallResult = { isError?: boolean; content: Array<{ type: string; text?: string }> };
const call = async (h: Harness, name: string, args: Record<string, unknown>) => (await h.client.callTool({ name, arguments: args })) as CallResult;
const textOf = (r: CallResult) => r.content.map((c) => c.text ?? '').join('\n');
const jsonOf = (r: CallResult) => JSON.parse(textOf(r)) as Record<string, unknown>;
type Item = { id: number; kind: string; who: string | null; date: { said_at: string; source_ts: string }; source_uri: string; source_ts: string; cite: string; exact_words: string; applies_to: string[] };

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-mcp-prime-'));
  const svc = (name: string, user: string) => `[${name}]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;
  writeFileSync(join(home, '.pg_service.conf'), [svc('zeusi_ro', 'zeusi_box_ro'), svc('zeusi_rw', 'zeusi_box_rw')].join('\n'));
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('synthetic-owner', 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/synthetic-owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  const dec = async (key: string, o: { kind: string; words: string; uri: string; applies: string[]; scope?: string; ago?: string }) => {
    ids[key] = (await db.query<{ id: number }>(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to,
                                    scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1::zeusi.decision_kind, (SELECT id FROM zeusi.people WHERE handle = 'synthetic-owner'), now() - $2::interval, 'minute', $3, false,
               $4::text[], $5::zeusi.scope, 'manual', $6, now() - $2::interval, sha256(convert_to($6 || $3, 'UTF8')), $7)
       RETURNING id::int AS id`,
      [o.kind, o.ago ?? '3 days', o.words, o.applies, o.scope ?? 'work', o.uri, run])).rows[0]!.id;
  };
  await dec('lock', { kind: 'lock', words: 'SYNTHETIC FIXTURE: no Northbank prod promotion during London/NY market hours', uri: 'test:lock-ldn-ny', applies: ['northbank', 'prod'], scope: 'product', ago: '20 days' });
  await dec('go', { kind: 'go', words: 'SYNTHETIC FIXTURE: go ahead and promote the Northbank dashboard', uri: 'test:go-northbank', applies: ['northbank'], scope: 'product' });
  await dec('work', { kind: 'park', words: 'SYNTHETIC FIXTURE: park the Northbank newsletter idea for the team', uri: 'test:park-team', applies: ['newsletter'] });
  await db.exec('ALTER TABLE zeusi.decisions DISABLE TRIGGER zeusi_90_wall');
  await dec('walled', { kind: 'lock', words: `SYNTHETIC FIXTURE: Northbank prod lock ${WALLED}`, uri: 'test:walled', applies: ['northbank', 'prod'], scope: 'product', ago: '1 day' });
  await db.exec('ALTER TABLE zeusi.decisions ENABLE TRIGGER zeusi_90_wall');
  // A TEST-ONLY reader whose RLS reads scope team only (production readers are not narrowed: plan Risks).
  await db.exec(`CREATE ROLE ${TEST_ROLE} NOLOGIN;
    GRANT USAGE ON SCHEMA zeusi TO ${TEST_ROLE};
    GRANT SELECT ON zeusi.decisions, zeusi.decisions_current, zeusi.people, zeusi.notes TO ${TEST_ROLE};
    CREATE POLICY test_work_only ON zeusi.decisions FOR SELECT TO ${TEST_ROLE} USING (scope = 'work');
    CREATE POLICY test_work_only ON zeusi.people FOR SELECT TO ${TEST_ROLE} USING (scope = 'work');
    CREATE POLICY test_work_only ON zeusi.notes FOR SELECT TO ${TEST_ROLE} USING (scope = 'work');`);
});
after(async () => db.close());

// ---------------------------------------------------------------------------
// Surface

test('prime: instructions prepend the compact about and say "at the start of every task, call zeusi_context_for_task", plus the honesty line; old pins kept', async () => {
  const h = await connect({ writeService: 'zeusi_rw' });
  try {
    const ins = h.client.getInstructions() ?? '';
    assert.equal(ins, MCP_INSTRUCTIONS);
    assert.equal(ins, mcpInstructions(true));
    assert.ok(ins.startsWith(ABOUT_SUMMARY));
    assert.match(ins, /start of every task, call zeusi_context_for_task/);
    assert.match(ins, /cannot force/);
    assert.match(ins, /session start.*zeusi_startup/is);
    assert.match(ins, /before answering.*asking.*zeusi_search/is);
    assert.match(ins, /zeusi_search_feedback/);
    assert.match(ins, /invent=NO/);
    assert.match(ins, /withheld/);
    assert.match(ins, /context_for_task = prime = zeusi_context_for_task/);
    const caps = h.client.getServerCapabilities() ?? {};
    assert.ok(caps.prompts, 'prompts capability');
    assert.ok(caps.resources, 'resources capability');
  } finally {
    await h.close();
  }
});

test('prime F4/F5 (in-memory): instructions, zeusi://about and tools/list agree for every class; the write tool is named only where it is listed', async () => {
  const cases: Array<[string, Partial<McpDeps>, boolean]> = [
    ['stdio, no write service', {}, false],
    ['stdio + write service', { writeService: 'zeusi_rw' }, true],
    ['hosted read class + write service', { toolClass: 'read', writeService: 'zeusi_rw' }, false],
    ['hosted write class, no write service', { toolClass: 'write' }, false],
    ['hosted write class + write service', { toolClass: 'write', writeService: 'zeusi_rw' }, true],
  ];
  for (const [label, over, canWrite] of cases) {
    const h = await connect(over);
    try {
      const ins = h.client.getInstructions() ?? '';
      assert.equal(ins, mcpInstructions(canWrite), label);
      const names = (await h.client.listTools()).tools.map((t) => t.name);
      assertToolsAgree(ins, names, label);
      const about = (await h.client.readResource({ uri: 'zeusi://about' })).contents[0] as { text: string };
      assert.equal(about.text, aboutMarkdown(canWrite), label);
      assert.equal(/log_decision/.test(ins) || /log_decision/.test(about.text), canWrite, label);
      if (!canWrite) assert.match(ins, /Writing decisions is not available on this connection/, label);
      for (const t of [ins, about.text]) {
        assert.match(t, CONTEXT_NOT_PERMISSION_RE, label);
        assert.match(t, NOT_A_GO_RE, label);
      }
      // the built-in about entries in zeusi_search follow the same rule
      const s = JSON.parse(((await h.client.callTool({ name: 'zeusi_search', arguments: { query: 'tools' } })) as CallResult).content[0]!.text!) as { about: Array<{ text: string }> };
      assert.ok(s.about.length >= 1, label);
      assert.equal(s.about.some((a) => /zeusi_log_decision/.test(a.text)), canWrite, label);
      if (!canWrite) for (const a of s.about) assert.doesNotMatch(a.text, /log_decision/, label);
    } finally {
      await h.close();
    }
  }
});

test('prime: tools/list has the canonical tool and both aliases, read-only, same schema; ALL_TOOL_NAMES matches', async () => {
  const h = await connect({ writeService: 'zeusi_rw' });
  try {
    const { tools } = await h.client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), [...ALL_TOOL_NAMES].sort());
    const by = new Map(tools.map((t) => [t.name, t]));
    for (const n of ['zeusi_context_for_task', 'context_for_task', 'prime']) {
      assert.ok(by.has(n), n);
      assert.equal(by.get(n)!.annotations?.readOnlyHint, true, n);
    }
    assert.equal(TOOL_ALIASES.prime, 'zeusi_context_for_task');
    assert.deepEqual(by.get('prime')!.inputSchema, by.get('zeusi_context_for_task')!.inputSchema);
    assert.deepEqual(by.get('context_for_task')!.inputSchema, by.get('zeusi_context_for_task')!.inputSchema);
    assert.match(by.get('zeusi_context_for_task')!.description ?? '', /start of every task/);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// The tool

test('prime AE1: "promote Northbank to prod" returns the synthetic lock first, cited (id, who, date, source_uri, source_ts); conflict flagged; walled lock withheld; task not echoed', async () => {
  const obs: ToolObservation[] = [];
  const h = await connect({ observe: (o) => obs.push(o) });
  try {
    const r = await call(h, 'zeusi_context_for_task', { task: TASK });
    assert.ok(!r.isError, textOf(r));
    const j = jsonOf(r);
    const items = j['items'] as Item[];
    assert.equal(items[0]!.id, ids['lock']);
    assert.equal(items[0]!.kind, 'lock');
    assert.equal(items[0]!.who, 'synthetic-owner');
    assert.match(items[0]!.date.said_at, /^\d{4}-/);
    assert.equal(items[0]!.date.source_ts, items[0]!.source_ts);
    assert.equal(items[0]!.source_uri, 'test:lock-ldn-ny');
    assert.match(items[0]!.cite, new RegExp(`^test:lock-ldn-ny @ .+ \\(decision ${ids['lock']}, synthetic-owner, said `));
    assert.ok(items.some((i) => i.id === ids['go']));
    assert.equal(j['withheld'], 1, 'the walled lock is counted');
    const conflicts = j['conflicts'] as Array<{ ids: number[]; applies_to: string[] }>;
    assert.equal(conflicts.length, 1);
    assert.deepEqual([...conflicts[0]!.ids].sort(), [ids['go'], ids['lock']].sort());
    assert.deepEqual(conflicts[0]!.applies_to, ['northbank']);
    assert.ok(!conflicts[0]!.ids.includes(ids['walled']!), 'never references the withheld id');
    assert.ok(typeof j['conflict_hint'] === 'string');
    assert.match(String(j['query_id']), /^[0-9a-f-]{36}$/);
    const body = textOf(r);
    assert.ok(!body.includes(WALLED) && !/plankiva/i.test(body), 'walled text never returned or paraphrased');
    assert.ok(!body.includes('distinctive-task-marker-91'), 'the task is not echoed');
    assert.ok(!items.some((i) => i.id === ids['walled'] || i.source_uri === 'test:walled'), 'walled item omitted');
    assert.deepEqual(obs, [{ tool: 'zeusi_context_for_task', hitCount: items.length, withheld: 1, secretWithheld: 0 }], 'observe: counts only');
  } finally {
    await h.close();
  }
});

test('prime AE2: nothing matches -> empty items and conflicts, a plain message, no invented field', async () => {
  const h = await connect();
  try {
    const j = jsonOf(await call(h, 'zeusi_context_for_task', { task: 'quarterly penguin census' }));
    assert.deepEqual(j['items'], []);
    assert.deepEqual(j['conflicts'], []);
    assert.equal(j['withheld'], 0);
    assert.match(String(j['message']), /No current decision, lock or parked item/);
    assert.match(String(j['message']), /Nothing was invented/);
    assert.equal(j['conflict_hint'], undefined);
  } finally {
    await h.close();
  }
});

test('prime aliases: context_for_task and prime return the same body, refuse the same bad input, and withhold the same item', async () => {
  const h = await connect();
  try {
    const strip = (j: Record<string, unknown>) => { delete j['query_id']; return j; };
    const a = strip(jsonOf(await call(h, 'zeusi_context_for_task', { task: TASK })));
    for (const alias of ['context_for_task', 'prime']) {
      assert.deepEqual(strip(jsonOf(await call(h, alias, { task: TASK }))), a, alias);
      assert.equal((await call(h, alias, { task: '' })).isError, true, alias);
      assert.equal((await call(h, alias, { task: 'x', nope: 1 })).isError, true, alias);
    }
  } finally {
    await h.close();
  }
});

test('prime validation: empty, 4001-char task, unknown key, limit 0/51, unknown scope are refused before any connection; unknown keys not echoed', async () => {
  const log: string[] = [];
  const h = await connect({ connectRead: asRole('zeusi_box_ro', log) });
  try {
    for (const args of [
      { task: '' }, { task: '   ' }, { task: 'x'.repeat(4001) }, { task: 'x', secret_extra_key_zz: 1 }, { task: 'x', limit: 0 },
      { task: 'x', limit: 51 }, { task: 'x', limit: 1.5 }, { task: 'x', scope: 'personal' }, { task: 42 }, {},
    ]) {
      const r = await call(h, 'zeusi_context_for_task', args as Record<string, unknown>);
      assert.equal(r.isError, true, JSON.stringify(args).slice(0, 60));
      assert.ok(!textOf(r).includes('secret_extra_key_zz'));
    }
    assert.deepEqual(log, [], 'no connection');
    assert.ok(!(await call(h, 'zeusi_context_for_task', { task: 'x'.repeat(4000) })).isError, '4000 is allowed');
  } finally {
    await h.close();
  }
});

test('prime limit: limit 1 returns one item; the walled item never takes a slot', async () => {
  const h = await connect();
  try {
    const j = jsonOf(await call(h, 'zeusi_context_for_task', { task: TASK, limit: 1 }));
    assert.equal((j['items'] as Item[]).length, 1);
    assert.equal((j['items'] as Item[])[0]!.id, ids['lock']);
  } finally {
    await h.close();
  }
});

test('prime read gate: a read service that is a write login is refused before connecting; a write session is refused by the read-only check', async () => {
  const log: string[] = [];
  const h1 = await connect({ readService: 'zeusi_rw', connectRead: asRole('zeusi_box_ro', log) });
  try {
    const r = await call(h1, 'zeusi_context_for_task', { task: TASK });
    assert.equal(r.isError, true);
    assert.match(textOf(r), /read-only login/);
    assert.deepEqual(log, []);
  } finally {
    await h1.close();
  }
  const h2 = await connect({ connectRead: asRole('zeusi_box_rw') });
  try {
    const r = await call(h2, 'zeusi_context_for_task', { task: TASK });
    assert.equal(r.isError, true);
    assert.match(textOf(r), /read-only role/);
  } finally {
    await h2.close();
  }
});

test('prime scope isolation: a reader limited to scope team never sees (or counts) product items; scope arg narrows too', async () => {
  const h = await connect({ connectRead: asRole(TEST_ROLE) });
  try {
    const j = jsonOf(await call(h, 'zeusi_context_for_task', { task: 'Northbank prod newsletter' }));
    const items = j['items'] as Item[];
    assert.deepEqual(items.map((i) => i.id), [ids['work']]);
    assert.equal(j['withheld'], 0, 'the walled product row is invisible, not counted');
  } finally {
    await h.close();
  }
  const h2 = await connect();
  try {
    const j = jsonOf(await call(h2, 'zeusi_context_for_task', { task: 'Northbank prod newsletter', scope: 'work' }));
    assert.deepEqual((j['items'] as Item[]).map((i) => i.id), [ids['work']]);
  } finally {
    await h2.close();
  }
});

test('prime feedback: zeusi_search_feedback accepts the context query_id for a returned source_uri and refuses a foreign uri', async () => {
  const h = await connect();
  try {
    const j = jsonOf(await call(h, 'prime', { task: TASK }));
    const ok = await call(h, 'zeusi_search_feedback', { query_id: j['query_id'], source_uri: 'test:lock-ldn-ny', useful: true });
    assert.ok(!ok.isError, textOf(ok));
    const bad = await call(h, 'zeusi_search_feedback', { query_id: j['query_id'], source_uri: 'test:walled', useful: true });
    assert.equal(bad.isError, true);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Resource and prompt

/** Owner terms (hashed denylist): never in served, public-facing copy (owner request 17 Nov 2026; "named after a cat"). */

test('prime: served copy (instructions, tool/prompt/resource descriptions, about text, about search entries) names no person from the denylist', async () => {
  const pure = [ABOUT_SUMMARY, ABOUT_MARKDOWN, aboutMarkdown(false), MCP_INSTRUCTIONS, mcpInstructions(false), ...ABOUT_SECTIONS.map((s) => `${s.heading}\n${s.body}`),
    onboardingText(), CANNOT_RUN_IT, ...ONBOARDING_COMMANDS];
  for (const t of pure) assert.equal(hasNonRoleOperatorAddress(t), false);
  assert.match(ABOUT_MARKDOWN, /named after a cat/);
  assert.match(ABOUT_SUMMARY, /named after a cat/);
  for (const over of [{}, { toolClass: 'write' as const, writeService: 'zeusi_rw' }]) {
    const h = await connect(over);
    try {
      const served: string[] = [h.client.getInstructions() ?? ''];
      const { tools } = await h.client.listTools();
      assert.ok(tools.length >= 4);
      for (const t of tools) served.push(t.name, t.title ?? '', t.description ?? '', JSON.stringify(t.inputSchema), JSON.stringify(t.annotations ?? {}));
      const { prompts } = await h.client.listPrompts();
      for (const p of prompts) {
        served.push(p.name, p.description ?? '', JSON.stringify(p.arguments ?? []));
        const g = await h.client.getPrompt({ name: p.name, arguments: { task: 'ship the release' } });
        served.push(g.description ?? '', JSON.stringify(g.messages));
      }
      const { resources } = await h.client.listResources();
      for (const r of resources) {
        served.push(r.name, r.description ?? '');
        served.push(JSON.stringify((await h.client.readResource({ uri: r.uri })).contents));
      }
      for (const q of ['what is zeusi', 'cat', 'named after']) {
        const s = JSON.parse(textOf(await call(h, 'zeusi_search', { query: q }))) as { about: Array<{ heading: string; text: string }> };
        assert.ok(s.about.length >= 1, q);
        for (const a of s.about) served.push(a.heading, a.text);
      }
      // PR2: the onboarding status result (counts + the CLI commands + the honest line) is served copy too.
      served.push(textOf(await call(h, 'zeusi_onboarding_status', {})), textOf(await call(h, 'onboarding_status', {})));
      for (const t of served) assert.equal(hasNonRoleOperatorAddress(t), false, t.slice(0, 80));
    } finally {
      await h.close();
    }
  }
});

test('prime resource: zeusi://about is listed and reads the full about text as text/markdown, without a database connection', async () => {
  const log: string[] = [];
  const h = await connect({ connectRead: asRole('zeusi_box_ro', log) });
  try {
    const { resources } = await h.client.listResources();
    assert.deepEqual(resources.map((r) => r.uri), ['zeusi://about']);
    const r = await h.client.readResource({ uri: 'zeusi://about' });
    const c = r.contents[0] as { uri: string; mimeType?: string; text?: string };
    assert.equal(c.uri, 'zeusi://about');
    assert.equal(c.mimeType, 'text/markdown');
    assert.equal(c.text, aboutMarkdown(false), 'no write service: the read-connection text (F4)');
    assert.doesNotMatch(c.text ?? '', /log_decision/);
    assert.deepEqual(log, []);
    await assert.rejects(h.client.readResource({ uri: 'zeusi://other' }));
  } finally {
    await h.close();
  }
});

test('prime prompt: start-task names zeusi_context_for_task and includes the task; a walled task is not echoed; over-long or empty task refused', async () => {
  const h = await connect();
  try {
    const { prompts } = await h.client.listPrompts();
    assert.deepEqual(prompts.map((p) => p.name).sort(), ['onboarding', 'start-task']);
    assert.deepEqual(prompts.find((p) => p.name === 'start-task')!.arguments?.map((a) => [a.name, a.required]), [['task', true]]);
    const p = await h.client.getPrompt({ name: 'start-task', arguments: { task: 'promote Northbank to prod' } });
    const t = (p.messages[0]!.content as { text: string }).text;
    assert.match(t, /zeusi_context_for_task/);
    assert.match(t, /binding/);
    assert.match(t, /conflicts/);
    assert.match(t, /invent=NO/);
    assert.ok(t.endsWith('Task: promote Northbank to prod'));
    const w = await h.client.getPrompt({ name: 'start-task', arguments: { task: `fix ${WALLED}` } });
    const wt = (w.messages[0]!.content as { text: string }).text;
    assert.ok(!wt.includes(WALLED) && !/plankiva/i.test(wt));
    assert.match(wt, /zeusi_context_for_task/);
    await assert.rejects(h.client.getPrompt({ name: 'start-task', arguments: { task: 'x'.repeat(4001) } }));
    await assert.rejects(h.client.getPrompt({ name: 'start-task', arguments: { task: '' } }));
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// About in zeusi_search

test('prime AE5: zeusi_search "what is zeusi" returns the built-in overview in `about` (builtin, any scope); hits and decisions unchanged; feedback accepts it', async () => {
  const h = await connect();
  try {
    const before = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions`)).rows[0]!.n;
    const j = jsonOf(await call(h, 'zeusi_search', { query: 'what is zeusi' }));
    const about = j['about'] as Array<{ source_uri: string; builtin: boolean; scope: string; source_ts: string }>;
    assert.equal(about[0]!.source_uri, 'zeusi://about#what-zeusi-is');
    assert.equal(about[0]!.builtin, true);
    assert.equal(about[0]!.scope, 'builtin');
    assert.equal(about[0]!.source_ts, ABOUT_SOURCE_TS);
    assert.deepEqual(j['hits'], []);
    assert.deepEqual(j['decisions'], []);
    const v = jsonOf(await call(h, 'zeusi_search', { query: 'what is zeusi', scope: 'client' }));
    assert.equal((v['about'] as Array<{ source_uri: string }>)[0]!.source_uri, 'zeusi://about#what-zeusi-is');
    const f = await call(h, 'zeusi_search_feedback', { query_id: j['query_id'], source_uri: 'zeusi://about#what-zeusi-is', useful: true });
    assert.ok(!f.isError, textOf(f));
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions`)).rows[0]!.n, before, 'no row written');
    // an existing search keeps its keys and values (about is additive)
    const s = jsonOf(await call(h, 'zeusi_search', { query: 'Northbank prod promotion' }));
    assert.deepEqual(Object.keys(s).sort(), ['about', 'cite', 'decisions', 'hits', 'mode', 'notice', 'query_id', 'withheld']);
    assert.ok((s['decisions'] as unknown[]).length >= 1);
    assert.deepEqual(s['about'], []);
  } finally {
    await h.close();
  }
});
