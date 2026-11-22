// Review r1 (PR #23) P1-1: the serve-time output wall runs on the ORIGINAL item, and an item it
// withholds stays withheld. Redaction runs only on the items the wall keeps. Before the fix
// the guard redacted first, so an item whose ONLY wall signal (an Plankiva name, a
// database host) sat inside a span the detector rewrites (a `token=` value, a URL password)
// was served redacted instead of withheld.
//
// Every path is covered: zeusi_search hits, decisions and notice; zeusi_startup rules, focus
// and decisions; zeusi_context_for_task items; the start-task prompt echo; tool error
// messages; fact add (the wall pre-check before the INSERT). PGlite only, no network. Every
// name, key and host is SYNTHETIC and built at runtime.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { insertFact } from '../src/facts.ts';
import type { SearchResult } from '../src/search.ts';
import { createMcpState, createZeusiMcpServer, type McpDeps, type ToolObservation } from '../src/mcp-server.ts';
import { guardString, safeMessage, stringsOf, wallFilter, wallSignal, withheld } from '../src/mcp-wall.ts';
import { redactDeep, redactSecrets, STORAGE_SKIP } from '../src/secrets.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { fakeMaskedGoogle, j, P } from './secret-fixtures.ts';

const SHA = 'cd'.repeat(32);
const ANN = j('Plan', 'kiva');
const ANI = j('Plaan', 'kiva');
const HOST = j('ep-fake-1', '.neon', '.tech');

/** Walled items whose ONLY wall signal sits inside a span the detector redacts. */
const W = {
  keyword: `Never share token=${ANN}Desk2024x with anyone`,
  urlPassword: `Focus: db at https://u:${ANI}pw99@example.invalid/x`,
  decision: `heron go: password=${ANN}Pw2024z for the demo`,
  hostValue: `heron api_key=${HOST}`,
  chunk: `heron secret=${ANN}Zz99 rotates`,
};
/** No walled name, no host may appear in any output. */
const walledOut = (s: string) => s.includes(ANN) || s.includes(ANI) || /plankiva|plankiva/i.test(s) || s.includes(HOST) || /neon\.tech/.test(s);

test('precondition: each walled text trips the wall raw, and redaction alone would remove the signal', () => {
  for (const [name, s] of Object.entries(W)) {
    assert.equal(withheld([s]), true, `${name}: walled raw`);
    const r = redactDeep(s);
    assert.ok(r.count >= 1, `${name}: the detector rewrites the span`);
    assert.equal(wallSignal([r.value]), false, `${name}: the signal is gone after redaction (so only wall-first ordering withholds it)`);
  }
});

test('P1-1 unit: wallFilter / guardString / safeMessage withhold walled items on the wall (not as secrets); nothing is ever redacted at serve time', () => {
  const items = [{ text: W.keyword }, { text: W.urlPassword }, { text: W.hostValue }, { text: `clean ${fakeMaskedGoogle()}` }, { text: 'clean prose' }];
  const f = wallFilter(items);
  assert.equal(f.withheld, 4);
  assert.equal(f.secretWithheld, 1, 'the three walled items count as wall hits, the key as a secret');
  assert.deepEqual(f.kept, [{ text: 'clean prose' }], 'a kept item is returned unchanged');
  // The secret check is never called on a walled item (the wall runs first).
  let calls = 0;
  wallFilter([{ text: W.keyword }], () => { calls++; return false; });
  assert.equal(calls, 0, 'the wall decides first');
  for (const s of Object.values(W)) assert.deepEqual(guardString(s), { text: null, secretWithheld: 0 });
  for (const s of Object.values(W)) assert.equal(safeMessage(`upstream said ${s}`), 'refused (details withheld by the wall)');
});

// ---------------------------------------------------------------------------
// Every MCP output path, through the real server.

let db: Db;
let home: string;

function asRole(role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-sec-order-'));
  writeFileSync(join(home, '.pg_service.conf'), '[zeusi_ro]\nhost=ep-fake-2.example.invalid\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n');
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'manual:people/owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  // Rows that predate a wall rule: the trigger is disabled so they exist; the MCP output wall must omit them.
  await db.exec('ALTER TABLE zeusi.facts DISABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.decisions DISABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.chunks DISABLE TRIGGER zeusi_90_wall');
  const fact = (kind: string, subject: string, text: string, uri: string) => db.query(
    `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, $2, $3, 'work', 'manual', $4, now(), sha256(convert_to($4, 'UTF8')), $5)`, [kind, subject, text, uri, run]);
  await fact('rule', 'keys', W.keyword, 'vault:Work/handbook/rules.md#keys');
  await fact('state', 'db', W.urlPassword, 'vault:Work/handbook/focus.md');
  await db.query(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner'), now() - interval '1 day', 'minute', $1, true, ARRAY['heron'], 'work', 'manual', 'hq:t-heron', now(), decode($2, 'hex'), $3)`,
    [W.decision, SHA, run]);
  const nid = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/products/heron.md', 'Heron', 'heron plan', now(), 'work', 'vault_note', 'vault:Work/products/heron.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  const chunk = (i: number, text: string) => db.query(
    `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
     VALUES ($1, $2, 'Heron', $3, sha256(convert_to($3, 'UTF8')), 5, $4)`, [nid, i, text, `vault:Work/products/heron.md#c${i}`]);
  await chunk(0, 'heron clean hit, nothing secret in it');
  await chunk(3, `heron key hit with ${fakeMaskedGoogle()} in it`);
  await chunk(1, W.chunk);
  await chunk(2, W.hostValue);
  await db.exec('ALTER TABLE zeusi.facts ENABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.decisions ENABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.chunks ENABLE TRIGGER zeusi_90_wall');
});
after(async () => {
  await db.close();
  rmSync(home, { recursive: true, force: true });
});

async function mcp(over: Partial<McpDeps> = {}) {
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro', connectRead: asRole('zeusi_box_ro'), embeddings: () => null,
    feedbackPath: join(home, '.zeusi', 'fb.jsonl'), queryLedgerPath: join(home, '.zeusi', 'ledger.json'), ...over,
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'sec-order-test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
    return { isError: r.isError === true, text: r.content.map((c) => c.text ?? '').join('\n') };
  };
  return { call, client, close: async () => { await client.close(); await server.close(); } };
}

test('P1-1 zeusi_search: walled hits and the walled decision are withheld (not redacted and served); the key-bearing hit is withheld too', async () => {
  const seen: ToolObservation[] = [];
  const h = await mcp({ observe: (o) => seen.push({ ...o }) });
  try {
    const r = await h.call('zeusi_search', { query: 'heron', limit: 10 });
    assert.ok(!r.isError, r.text);
    assert.ok(!walledOut(r.text), 'no walled name or host in the response');
    assert.doesNotMatch(r.text, /REDACTED:keyword_value|REDACTED:url_password/, 'no walled item was served in redacted form');
    const out = JSON.parse(r.text) as { hits: Array<{ source_uri: string; text: string }>; decisions: unknown[]; withheld: number };
    assert.deepEqual(out.hits.map((x) => x.source_uri), ['vault:Work/products/heron.md#c0']);
    assert.equal(out.hits[0]!.text, 'heron clean hit, nothing secret in it', 'served unchanged');
    assert.deepEqual(out.decisions, []);
    assert.equal(out.withheld, 4, 'two walled chunks + the key chunk + one decision withheld and counted');
    assert.equal(seen[0]!.withheld, 4);
    assert.equal(seen[0]!.secretWithheld, 1, 'only the key chunk counts as a secret withhold (the wall ran first on the rest)');
  } finally {
    await h.close();
  }
});

test('P1-1 zeusi_search notice and tool errors: walled text inside a redacted span is withheld', async () => {
  const injected = async (): Promise<SearchResult> => ({ mode: 'lexical', notice: `notice ${W.keyword}`, hits: [] });
  const h = await mcp({ searchFn: injected });
  try {
    const r = await h.call('zeusi_search', { query: 'x' });
    assert.ok(!r.isError, r.text);
    assert.ok(!walledOut(r.text));
    assert.equal((JSON.parse(r.text) as { notice?: string }).notice, undefined, 'the notice is withheld, not redacted');
  } finally {
    await h.close();
  }
  for (const s of [W.keyword, W.urlPassword, W.hostValue]) {
    const t = await mcp({ searchFn: async () => { throw new Error(`upstream said ${s}`); } });
    try {
      const r = await t.call('zeusi_search', { query: 'x' });
      assert.ok(r.isError);
      assert.equal(r.text, 'refused (details withheld by the wall)');
    } finally {
      await t.close();
    }
  }
});

test('P1-1 zeusi_startup: the walled rule, focus fact and decision are withheld, not redacted and served', async () => {
  const seen: ToolObservation[] = [];
  const h = await mcp({ observe: (o) => seen.push({ ...o }) });
  try {
    const r = await h.call('zeusi_startup', {});
    assert.ok(!r.isError, r.text);
    assert.ok(!walledOut(r.text));
    assert.doesNotMatch(r.text, /REDACTED:keyword_value|REDACTED:url_password/);
    const out = JSON.parse(r.text) as { rules: unknown[]; focus: unknown[]; decisions: unknown[]; withheld: number };
    assert.deepEqual([out.rules.length, out.focus.length, out.decisions.length], [0, 0, 0]);
    assert.equal(out.withheld, 3);
    assert.equal(seen[0]!.withheld, 3);
  } finally {
    await h.close();
  }
});

test('P1-1 zeusi_context_for_task: the walled decision is withheld, not redacted and served', async () => {
  const h = await mcp();
  try {
    const r = await h.call('zeusi_context_for_task', { task: 'heron demo' });
    assert.ok(!r.isError, r.text);
    assert.ok(!walledOut(r.text));
    const out = JSON.parse(r.text) as { items: unknown[]; withheld: number };
    assert.deepEqual(out.items, []);
    assert.ok(out.withheld >= 1);
  } finally {
    await h.close();
  }
});

test('P1-1 start-task prompt: a task whose walled name sits in a token value is not echoed', async () => {
  const h = await mcp();
  try {
    const p = await h.client.getPrompt({ name: 'start-task', arguments: { task: `fix ${W.keyword}` } });
    const t = p.messages.map((m) => (m.content as { text?: string }).text ?? '').join('\n');
    assert.ok(!walledOut(t));
    assert.doesNotMatch(t, /Task: /, 'not echoed (withheld), not echoed redacted');
  } finally {
    await h.close();
  }
});

test('P1-1 fact add: the wall pre-check sees the ORIGINAL text, so a walled name inside a token value is quarantined, not stored redacted', async () => {
  const d = await pgliteDb();
  try {
    await migrate(d);
    await d.exec('SET ROLE zeusi_mini_ingest');
    const r = await insertFact(d, {
      kind: 'other', text: `demo ${W.keyword}`, scope: 'work', sourceKind: 'manual',
      sourceUri: 'manual:sec-order', sourceTs: '2026-11-17T09:00:00Z', sourceSha256: SHA,
    });
    await d.exec('RESET ROLE');
    assert.equal(r.status, 'quarantined');
    assert.equal((await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.facts`)).rows[0]!.n, 0);
    const q = (await d.query<{ t: string }>(`SELECT row_to_json(q)::text AS t FROM zeusi.quarantine q`)).rows.map((x) => x.t).join('\n');
    assert.ok(!walledOut(q), 'quarantine holds uri + hashes only');
  } finally {
    await d.close();
  }
});

test('P1-1 the whole item is walled on its original strings (every field, keys included)', () => {
  const item = { source_uri: 'vault:x.md#c0', heading_path: 'H', text: 'clean', extra: { note: W.keyword } };
  assert.equal(wallSignal(stringsOf(item)), true);
  assert.equal(wallFilter([item]).withheld, 1);
});

test('security review r2 / fix round 2: a multi-word secret after a keyword is STORED redacted whole and never SERVED (no word of it survives)', () => {
  const words = j('correct', ' horse', ' battery', ' staple');
  for (const [s, want] of [
    [j('pass', 'phrase: ', words), 'passphrase: [REDACTED:keyword_value]'],
    [j('pass', 'word = ', words, ' # rotate'), 'password = [REDACTED:keyword_value]'],
    [j('DB_PASS', 'WORD: ', words), 'DB_PASSWORD: [REDACTED:keyword_value]'],
    [j('refresh', '_token="', words, '"'), 'refresh_token=[REDACTED:keyword_value]'],
  ] as const) {
    assert.equal(redactSecrets(s, { skip: STORAGE_SKIP }).text, want, `stored whole-redacted (length ${s.length})`);
    assert.deepEqual(guardString(s), { text: null, secretWithheld: 1 }, `withheld at serve (length ${s.length})`);
    assert.deepEqual(guardString(want), { text: null, secretWithheld: 1 }, 'the stored form is withheld at serve too');
    const w = wallFilter([{ text: s }]);
    assert.deepEqual([w.kept, w.withheld], [[], 1]);
  }
  assert.deepEqual(guardString(j('pass', 'word: Fake9', 'X0X0X0')), { text: null, secretWithheld: 1 });
});

test('security review r2: fact add as a box role (no wall tables) still walls the ORIGINAL text', async () => {
  const d = await pgliteDb();
  try {
    await migrate(d);
    await d.exec('SET ROLE zeusi_box_rw');
    const r = await insertFact(d, {
      kind: 'other', text: `demo ${W.keyword}`, scope: 'work', sourceKind: 'manual',
      sourceUri: 'manual:sec-order-box', sourceTs: '2026-11-17T09:00:00Z', sourceSha256: SHA,
    });
    await d.exec('RESET ROLE');
    assert.equal(r.status, 'quarantined');
    assert.equal((await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.facts`)).rows[0]!.n, 0);
    const q = (await d.query<{ t: string }>(`SELECT row_to_json(q)::text AS t FROM zeusi.quarantine q`)).rows.map((x) => x.t).join('\n');
    assert.ok(!walledOut(q), 'quarantine holds uri + hashes only');
    // A clean fact with only a secret is stored redacted by the same role.
    await d.exec('SET ROLE zeusi_box_rw');
    const ok = await insertFact(d, {
      kind: 'other', text: `demo key ${fakeMaskedGoogle()}`, scope: 'work', sourceKind: 'manual',
      sourceUri: 'manual:sec-order-box-2', sourceTs: '2026-11-17T09:00:00Z', sourceSha256: SHA,
    });
    await d.exec('RESET ROLE');
    assert.equal(ok.status, 'inserted');
  } finally {
    await d.close();
  }
});
