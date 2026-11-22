// zeusi_search covers decisions (src/search.ts searchDecisions, src/mcp-server.ts): PGlite, as
// zeusi_box_ro (SET ROLE), lexical and with the fake embeddings client. No network, no Neon, no OpenAI.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { FakeEmbeddingsClient } from '../src/embeddings.ts';
import {
  search, searchDecisions, phrasePattern, formatSearch, QueryLedger, PHRASE_MIN_CHARS, type SearchResult,
} from '../src/search.ts';
import { createZeusiMcpServer, createMcpState, type McpDeps } from '../src/mcp-server.ts';

// Synthetic strings assembled at runtime (never real content).
const WALLED = ['Plan', 'kiva synthetic wall probe'].join('');
const LAUNCH = 'Go for it. Launch it boy \u{1F466}';
const SHA = 'ef'.repeat(32);
let db: Db;
let home: string;
let ids: Record<string, number> = {};

const ledger = () => new QueryLedger(join(home, '.zeusi', 'query-embed-ledger.json'));
const fake = () => new FakeEmbeddingsClient(1536);

async function as<T>(role: string, fn: () => Promise<T>): Promise<T> {
  await db.exec(`SET ROLE ${role}`);
  try {
    return await fn();
  } finally {
    await db.exec('RESET ROLE');
  }
}

const ro = (q: string, over: Partial<Parameters<typeof search>[0]> = {}) =>
  as('zeusi_box_ro', () => search({ db, query: q, limit: 10, client: null, ledger: ledger(), ...over }));

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-search-dec-'));
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  const person = (handle: string, scope: string) => db.query(
    `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, $1, 'human', 'work', $2::zeusi.scope, 'manual', 'manual:people/' || $1, now(), decode($3, 'hex'), $4)`, [handle, scope, SHA, run]);
  await person('owner', 'work');
  await person('hidden-person', 'personal');
  const dec = async (key: string, o: { words: string; uri: string; scope?: string; who?: string; applies?: string[]; ago?: string; expires?: string | null; kind?: string }) => {
    ids[key] = (await db.query<{ id: number }>(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, expires_at,
                                    scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1::zeusi.decision_kind, (SELECT id FROM zeusi.people WHERE handle = $2), now() - $3::interval, 'minute', $4, true, $5::text[],
               $6::timestamptz, $7::zeusi.scope, 'manual', $8, now() - $3::interval, sha256(convert_to($8 || $4, 'UTF8')), $9)
       RETURNING id::int AS id`,
      [o.kind ?? 'go', o.who ?? 'owner', o.ago ?? '1 day', o.words, o.applies ?? [], o.expires ?? null, o.scope ?? 'work', o.uri, run])).rows[0]!.id;
  };
  await dec('launch', { words: LAUNCH, uri: 'chat:example-thread', applies: ['zeusi', 'zeusi.ai launch'] });
  await dec('personal', { words: 'Go for it personal launch quokkabird', uri: 'hq:personal-1', scope: 'personal' });
  await dec('hiddenWho', { words: 'quokkabird ruling by a person the reader cannot see', uri: 'hq:hidden-who', who: 'hidden-person', kind: 'ruling' });
  await dec('northbank', { words: 'Park the export lane for now', uri: 'hq:t-park', scope: 'product', applies: ['northbank-export'], kind: 'park' });
  await dec('old', { words: 'Old pelicanword plan A', uri: 'hq:old', applies: ['pelican'], ago: '10 days' });
  await dec('new', { words: 'New pelicanword plan B', uri: 'hq:new', applies: ['pelican'], ago: '2 days' });
  await db.query(`SELECT zeusi.supersede_decision($1, $2)`, [ids['old'], ids['new']]);
  await dec('expired', { words: 'Expired pelicanword plan C', uri: 'hq:expired', ago: '5 days', expires: new Date(Date.now() - 3_600_000).toISOString() });
  await dec('percent', { words: 'Ship 100% of the backlog', uri: 'hq:percent' });
  // A decision that predates a wall rule: the trigger is disabled so it exists; the MCP output wall must omit it.
  await db.exec('ALTER TABLE zeusi.decisions DISABLE TRIGGER zeusi_90_wall');
  await dec('walled', { words: `quokkabird walled ${WALLED}`, uri: 'hq:walled' });
  await db.exec('ALTER TABLE zeusi.decisions ENABLE TRIGGER zeusi_90_wall');
  // A note chunk that shares words with the launch decision, embedded with the query vector of "launch".
  const nid = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/research/launch.md', 'launch', 'b', now(), 'work', 'vault_note', 'vault:Work/research/launch.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  await db.query(
    `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri, embed_model, embedding, embedded_at)
     VALUES ($1, 0, 'Launch', 'launch checklist for the site', sha256(convert_to('launch checklist', 'UTF8')), 5, 'vault:Work/research/launch.md#c0',
             'openai/text-embedding-3-small@1536', $2::halfvec(1536), now())`,
    [nid, `[${fake().vector('launch').join(',')}]`]);
});
after(async () => db.close());

test('lexical: the exact phrase "Go for it. Launch it boy" hits the decision (phrase match, ranked first)', async () => {
  const r = await ro('Go for it. Launch it boy');
  assert.equal(r.mode, 'lexical');
  const d = r.decisions![0]!;
  assert.equal(d.decisionId, ids['launch']);
  assert.equal(d.match, 'phrase');
  assert.equal(d.exactWords, LAUNCH);
  assert.equal(d.who, 'owner');
  assert.equal(d.kind, 'go');
  assert.deepEqual(d.appliesTo, ['zeusi', 'zeusi.ai launch']);
  assert.equal(d.sourceUri, 'chat:example-thread');
  // case and whitespace do not matter for the phrase fallback
  assert.equal((await ro('  go FOR it.   launch IT boy ')).decisions![0]!.decisionId, ids['launch']);
});

test('lexical: full text matches words in any order, and applies_to is searched too', async () => {
  const words = await ro('boy launch');
  assert.equal(words.decisions![0]!.decisionId, ids['launch']);
  assert.equal(words.decisions![0]!.match, 'fulltext');
  const applies = await ro('zeusi.ai launch');
  assert.ok(applies.decisions!.some((d) => d.decisionId === ids['launch'] && d.match === 'phrase'), 'applies_to element matched as a phrase');
  const tag = await ro('northbank-export');
  assert.deepEqual(tag.decisions!.map((d) => d.decisionId), [ids['northbank']]);
});

test('RLS: a personal-scope decision is never returned to a reader (the owner sees it)', async () => {
  for (const q of ['Go for it personal launch quokkabird', 'personal launch', 'quokkabird']) {
    const p = await ro(q, { limit: 50 });
    assert.ok(p.decisions!.every((d) => d.scope !== 'personal' && d.decisionId !== ids['personal']), q);
  }
  const r = await ro('quokkabird', { limit: 50 });
  const owner = await searchDecisions(db, 'quokkabird', null, 50); // owner bypasses RLS (sanity: the row exists)
  assert.ok(owner.some((d) => d.decisionId === ids['personal']));
  // a person row the reader cannot see: the decision is visible, `who` is null (never leaked)
  const hidden = r.decisions!.find((d) => d.decisionId === ids['hiddenWho']);
  assert.ok(hidden);
  assert.equal(hidden.who, null);
});

test('only current decisions: superseded and expired ones are not returned', async () => {
  const r = await ro('pelicanword', { limit: 50 });
  assert.deepEqual(r.decisions!.map((d) => d.decisionId), [ids['new']]);
});

test('--scope narrows decisions like chunks', async () => {
  assert.deepEqual((await ro('northbank-export', { scope: 'work' })).decisions, []);
  const r = await ro('Go for it. Launch it boy', { scope: 'product' });
  assert.ok(r.decisions!.every((d) => d.scope === 'product'));
});

test('LIKE wildcards in the query are literal; short queries skip the phrase fallback', async () => {
  assert.equal(phrasePattern('100% a_b\\c'), '%100\\% a\\_b\\\\c%');
  assert.deepEqual((await ro('%%%')).decisions, [], 'a bare wildcard query matches nothing');
  assert.deepEqual((await ro('100%')).decisions!.map((d) => d.decisionId), [ids['percent']]);
  // whitespace normalisation keeps every other character (an "s" is not whitespace)
  const ship = await ro('ship  100%   OF the backlog');
  assert.deepEqual(ship.decisions!.map((d) => [d.decisionId, d.match]), [[ids['percent'], 'phrase']]);
  assert.equal(PHRASE_MIN_CHARS, 3);
  assert.deepEqual((await ro('oy')).decisions, [], 'no substring match for a 2-character query');
});

test('limit caps the decisions list too', async () => {
  const all = await ro('quokkabird OR pelicanword OR launch', { limit: 50 });
  assert.ok(all.decisions!.length >= 2);
  assert.equal((await ro('quokkabird OR pelicanword OR launch', { limit: 1 })).decisions!.length, 1);
});

test('semantic mode on (fake embeddings): chunks are vector / hybrid, decisions stay lexical and still hit', async () => {
  for (const hybrid of [false, true]) {
    const r = await ro('Go for it. Launch it boy', { client: fake(), hybrid });
    assert.equal(r.mode, hybrid ? 'hybrid' : 'vector');
    assert.equal(r.notice, undefined);
    assert.equal(r.decisions![0]!.decisionId, ids['launch']);
    assert.equal(r.decisions![0]!.match, 'phrase');
    assert.ok(r.hits.every((h) => typeof h.chunkId === 'number' && h.sourceUri.startsWith('vault:')), 'decisions never enter the chunk hits');
  }
  const v = await ro('launch', { client: fake() });
  assert.equal(v.hits[0]!.sourceUri, 'vault:Work/research/launch.md#c0');
});

test('no regression on chunk search: hits are identical to a chunk-only full-text query', async () => {
  const r = await ro('launch');
  assert.deepEqual(r.hits.map((h) => h.sourceUri), ['vault:Work/research/launch.md#c0']);
  assert.deepEqual(Object.keys(r.hits[0]!).sort(), ['chunkId', 'headingPath', 'ranks', 'scope', 'score', 'sourceTs', 'sourceUri', 'text']);
  assert.deepEqual(r.hits[0]!.ranks, { lexical: 1 });
  assert.ok(r.decisions!.some((d) => d.decisionId === ids['launch']));
});

test('CLI formatSearch: a decisions section in text mode, a `decisions` array in --json', async () => {
  const r = await ro('Go for it. Launch it boy');
  const text = formatSearch(r);
  assert.match(text, /decisions \(lexical, current only\): 1 hit\(s\)/);
  assert.ok(text.includes('chat:example-thread @ '));
  const j = JSON.parse(formatSearch(r, { json: true })) as { decisions: Array<Record<string, unknown>> };
  assert.equal(j.decisions[0]!['type'], 'decision');
  // A result without decisions (an injected search) still formats.
  const bare: SearchResult = { mode: 'lexical', hits: [] };
  assert.doesNotMatch(formatSearch(bare), /decisions/);
  assert.deepEqual((JSON.parse(formatSearch(bare, { json: true })) as { decisions: unknown[] }).decisions, []);
});

// ---------------------------------------------------------------------------
// MCP (the real server over the SDK in-memory transport; read session = zeusi_box_ro)

async function mcp(over: Partial<McpDeps> = {}) {
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro',
    connectRead: async () => {
      await db.exec('SET ROLE zeusi_box_ro');
      return { label: 'pglite as zeusi_box_ro', query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
    },
    embeddings: () => null,
    feedbackPath: join(home, '.zeusi', 'search-feedback.jsonl'),
    queryLedgerPath: join(home, '.zeusi', 'query-embed-ledger.json'),
    ...over,
  };
  const { writeFileSync } = await import('node:fs');
  writeFileSync(join(home, '.pg_service.conf'), `[zeusi_ro]\nhost=${['ep-fake-444', '-pooler.eu-central-1.aws.neon.tech'].join('')}\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
    const text = r.content.map((c) => c.text ?? '').join('\n');
    assert.ok(!r.isError, text);
    return { text, json: JSON.parse(text) as Record<string, unknown> };
  };
  return { call, close: async () => { await client.close(); await server.close(); } };
}

test('mcp zeusi_search: decision hits carry type, kind, who, said_at, exact_words, applies_to, scope, source_uri, source_ts and cite', async () => {
  const h = await mcp();
  try {
    const { json } = await h.call('zeusi_search', { query: 'Go for it. Launch it boy' });
    assert.equal(json['mode'], 'lexical');
    const ds = json['decisions'] as Array<Record<string, unknown>>;
    assert.equal(ds.length, 1);
    const d = ds[0]!;
    assert.deepEqual(Object.keys(d).sort(), [
      'applies_to', 'cite', 'exact_words', 'exact_words_verbatim', 'kind', 'linked_pr', 'linked_pr_uri', 'linked_repo', 'links', 'match', 'said_at', 'scope', 'score',
      'source_note', 'source_ts', 'source_uri', 'type', 'who',
    ]);
    // Fix PR A: the link fields are additive and null when the decision has none
    for (const k of ['linked_repo', 'linked_pr', 'linked_pr_uri', 'source_note']) assert.equal(d[k], null, k);
    assert.deepEqual(d['links'], [], '0013: no decision_links rows -> []');
    assert.equal(d['type'], 'decision');
    assert.equal(d['exact_words'], LAUNCH);
    assert.equal(d['who'], 'owner');
    assert.equal(d['source_uri'], 'chat:example-thread');
    assert.equal(d['cite'], `chat:example-thread @ ${d['source_ts'] as string}`);
    assert.ok(!Number.isNaN(Date.parse(d['said_at'] as string)) && !Number.isNaN(Date.parse(d['source_ts'] as string)));
    // chunk hits keep their exact shape
    const chunk = await h.call('zeusi_search', { query: 'launch checklist' });
    assert.deepEqual(Object.keys((chunk.json['hits'] as Array<Record<string, unknown>>)[0]!).sort(), ['heading_path', 'scope', 'score', 'source_ts', 'source_uri', 'text']);
    // feedback accepts a decision hit of that query
    const fb = await h.call('zeusi_search_feedback', { query_id: json['query_id'], source_uri: 'chat:example-thread', useful: true });
    assert.equal(fb.json['status'], 'recorded');
  } finally {
    await h.close();
  }
});

test('mcp zeusi_search: a wall-withheld decision is omitted and counted; personal never appears', async () => {
  const h = await mcp();
  try {
    const { text, json } = await h.call('zeusi_search', { query: 'quokkabird', limit: 50 });
    const ds = json['decisions'] as Array<Record<string, unknown>>;
    assert.ok(ds.some((d) => d['source_uri'] === 'hq:hidden-who'), 'the clean decision is returned');
    assert.ok(!ds.some((d) => d['source_uri'] === 'hq:walled'));
    assert.ok(!ds.some((d) => d['source_uri'] === 'hq:personal-1' || d['scope'] === 'personal'));
    assert.equal(json['withheld'], 1, 'the walled decision is counted, never paraphrased');
    assert.doesNotMatch(text, /plankiva|wall probe|personal launch/i);
    // the walled row really is matched before the wall (so the omission is the wall's doing)
    const raw = await ro('quokkabird', { limit: 50 });
    assert.ok(raw.decisions!.some((d) => d.sourceUri === 'hq:walled'));
  } finally {
    await h.close();
  }
});

test('mcp zeusi_search in semantic mode (fake embeddings): decisions still returned beside the vector / hybrid hits', async () => {
  const h = await mcp({ embeddings: () => fake() });
  try {
    for (const hybrid of [false, true]) {
      const { json } = await h.call('zeusi_search', { query: 'Go for it. Launch it boy', hybrid });
      assert.equal(json['mode'], hybrid ? 'hybrid' : 'vector');
      assert.equal((json['decisions'] as Array<Record<string, unknown>>)[0]!['source_uri'], 'chat:example-thread');
    }
  } finally {
    await h.close();
  }
});

test('mcp zeusi_search default is hybrid (Fix PR A): with a key set, an UNEMBEDDED chunk is still found lexically; explicit hybrid:false stays vector-only', async () => {
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  const nid = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/research/unembedded.md', 'unembedded', 'b', now(), 'work', 'vault_note', 'vault:Work/research/unembedded.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  await db.query(
    `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
     VALUES ($1, 0, 'Prep', 'wallabyprep checklist, never embedded', sha256(convert_to('wallabyprep', 'UTF8')), 5, 'vault:Work/research/unembedded.md#c0')`, [nid]);
  const h = await mcp({ embeddings: () => fake() });
  try {
    const def = (await h.call('zeusi_search', { query: 'wallabyprep' })).json;
    assert.equal(def['mode'], 'hybrid');
    assert.ok((def['hits'] as Array<{ source_uri: string }>).some((x) => x.source_uri === 'vault:Work/research/unembedded.md#c0'), 'the lexical branch ran');
    const vec = (await h.call('zeusi_search', { query: 'wallabyprep', hybrid: false })).json;
    assert.equal(vec['mode'], 'vector');
    assert.ok(!(vec['hits'] as Array<{ source_uri: string }>).some((x) => x.source_uri === 'vault:Work/research/unembedded.md#c0'), 'explicit vector-only still skips unembedded chunks');
    const hyb = (await h.call('zeusi_search', { query: 'wallabyprep', hybrid: true })).json;
    assert.equal(hyb['mode'], 'hybrid');
  } finally {
    await h.close();
  }
  // without a key: lexical with the notice, as before
  const lex = await mcp();
  try {
    const j = (await lex.call('zeusi_search', { query: 'wallabyprep' })).json;
    assert.equal(j['mode'], 'lexical');
    assert.ok(typeof j['notice'] === 'string');
    assert.ok((j['hits'] as Array<{ source_uri: string }>).some((x) => x.source_uri === 'vault:Work/research/unembedded.md#c0'));
  } finally {
    await lex.close();
  }
});
