// U6c: `zeusi search` against PGlite: the fixture vault is ingested (as zeusi_mini_ingest),
// embedded with the fake client, then searched as zeusi_box_ro (SET ROLE). No network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, readFileSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { importVault } from '../src/importers/vault.ts';
import { FakeEmbeddingsClient, EmbedError } from '../src/embeddings.ts';
import { runEmbed } from '../src/embed.ts';
import {
  search, rrfFuse, SearchRefused, SEARCH_SCOPES, QueryLedger, QUERY_CAPS, formatSearch, LEXICAL_ONLY_NOTICE, type SearchHit,
} from '../src/search.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const FIXTURE = fileURLToPath(new URL('./fixtures/vault/', import.meta.url));
const SHA = 'cd'.repeat(32);
let db: Db;
let home: string;
const synonyms = { automobile: 'car', vehicle: 'car', motorcar: 'car' };
const client = () => new FakeEmbeddingsClient(1536, { synonyms });

async function as<T>(role: string, fn: () => Promise<T>): Promise<T> {
  await db.exec(`SET ROLE ${role}`);
  try {
    return await fn();
  } finally {
    await db.exec('RESET ROLE');
  }
}

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? (e as Error).name;
  }
}

const ledger = () => new QueryLedger(join(home, '.zeusi', 'query-embed-ledger.json'));

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-search-'));
  const vault = join(home, 'vault');
  cpSync(FIXTURE, vault, { recursive: true });
  // a note whose words share nothing with the query "automobile" but mean the same in the fake's synonym map
  writeFileSync(join(vault, 'Work/research/garage.md'), '---\ntitle: Garage\n---\n# Fleet\n\nThe vehicle needs new tyres before winter.\n');
  writeFileSync(join(vault, 'Work/research/lexical.md'), '---\ntitle: Lexical\n---\n# Words\n\nautomobile insurance renewal paperwork\n');
  const config = validateSources(parseToml(`
[[source]]
name = "vault-all"
kind = "vault_note"
scope = "work"
root = "${vault}"
include = ["**/*.md"]

[[source]]
name = "vault-northbank-product"
kind = "vault_note"
scope = "product"
root = "${vault}"
include = ["Work/product/**/*.md", "Work/products/product/**/*.md"]
content_scan = true
`), seedWall(), { home });
  db = await pgliteDb();
  await migrate(db);
  const r = await as('zeusi_mini_ingest', () => importVault({ db, config, mode: 'full', home, logPaths: false }));
  assert.equal(r.status, 'ok');
  assert.ok(r.counts.quarantined > 0, 'fixture has walled items');
  const e = await as('zeusi_mini_ingest', () => runEmbed({ db, client: client(), host: 'testhost' }));
  assert.equal(e.status, 'ok', e.error ?? '');
  // a personal note + chunk (owner): embedded with exactly the vector of the query "vehicle", to prove RLS hides it
  const run = (await db.query<{ id: number }>(`SELECT max(id)::int AS id FROM zeusi.ingest_runs`)).rows[0]!.id;
  const nid = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/p.md', 'p', 'vehicle private synthetic', now(), 'personal', 'vault_note', 'vault:Work/p.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
  await db.query(
    `INSERT INTO zeusi.chunks (note_id, chunk_index, text, text_sha256, token_count, source_uri, embed_model, embedding, embedded_at)
     VALUES ($1, 0, 'vehicle private synthetic', sha256(convert_to('x', 'UTF8')), 3, 'vault:Work/p.md#c0',
             'openai/text-embedding-3-small@1536', $2::halfvec(1536), now())`,
    [nid, `[${client().vector('vehicle').join(',')}]`]);
});
after(async () => db.close());

test('semantic search as zeusi_box_ro finds a chunk that shares no keyword with the query; cites uri, ts, scope, heading', async () => {
  const r = await as('zeusi_box_ro', () => search({ db, query: 'automobile', limit: 3, client: client(), ledger: ledger() }));
  assert.equal(r.mode, 'vector');
  const top = r.hits.find((h) => h.sourceUri === 'vault:Work/research/garage.md#c0')!;
  assert.ok(top, 'the synonym-only chunk is in the top 3');
  assert.ok(!/automobile/i.test(top.text));
  assert.equal(top.scope, 'work');
  assert.equal(top.headingPath, 'Fleet');
  assert.ok(!Number.isNaN(Date.parse(top.sourceTs)));
});

test('results never carry more text than the chunk (no note body, no title prefix)', async () => {
  const r = await as('zeusi_box_ro', () => search({ db, query: 'tyres winter', limit: 5, client: client(), ledger: ledger() }));
  const stored = (await db.query<{ source_uri: string; text: string }>(`SELECT source_uri, text FROM zeusi.chunks`)).rows;
  const byUri = new Map(stored.map((x) => [x.source_uri, x.text]));
  for (const h of r.hits) assert.equal(h.text, byUri.get(h.sourceUri));
  const out = formatSearch(r);
  for (const h of r.hits) assert.ok(out.includes(h.sourceUri));
  assert.ok(out.split('\n').every((l) => l.length <= 400), 'text mode prints a bounded snippet');
});

test('RLS hides personal: a personal chunk with the exact query vector never appears', async () => {
  const r = await as('zeusi_box_ro', () => search({ db, query: 'vehicle', limit: 50, client: client(), ledger: ledger(), hybrid: true }));
  assert.ok(r.hits.length > 0);
  assert.ok(r.hits.every((h) => h.scope !== 'personal' && !h.sourceUri.startsWith('vault:Work/p.md')));
});

test('wall-quarantined items never appear (vector, lexical, hybrid)', async () => {
  const q = (await db.query<{ source_uri: string }>(`SELECT source_uri FROM zeusi.quarantine`)).rows.map((x) => x.source_uri);
  assert.ok(q.length > 0);
  const walledNote = (u: string) => q.some((x) => u === x || u.startsWith(`${x}#`) || x.startsWith(u.replace(/#c\d+$/, '')));
  for (const query of ['synthetic', 'plankiva', 'estimate USD', 'client', 'runbook', 'request form', 'pnl weekly']) {
    for (const opts of [{}, { hybrid: true }, { lexicalOnly: true }]) {
      const r = await as('zeusi_box_ro', () => search({ db, query, limit: 50, client: 'lexicalOnly' in opts ? null : client(), ledger: ledger(), ...opts }));
      for (const h of r.hits) {
        assert.ok(!walledNote(h.sourceUri), `quarantined ${h.sourceUri} must not appear`);
        // ClientCo/ is admitted (scope clientco) since 0010 (#3); Plankiva stays walled.
        assert.ok(!/plankiva|USD 1200/i.test(`${h.sourceUri} ${h.text}`));
      }
    }
  }
});

test('the search connection cannot write: grants, read-only transaction, and a refusal for writer roles', async () => {
  // grants: zeusi_box_ro has no write privilege anywhere
  assert.equal(await as('zeusi_box_ro', () => code(db.query(`INSERT INTO zeusi.embed_usage (month, embed_model, host) VALUES ('2026-11-01', 'x', 'y')`))), '42501');
  assert.equal(await as('zeusi_box_ro', () => code(db.query(`UPDATE zeusi.chunks SET embedding = NULL`))), '42501');
  assert.equal(await as('zeusi_box_ro', () => code(db.query(`DELETE FROM zeusi.chunks`))), '42501');
  // the role default (applies at login; asserted from the catalog)
  const cfg = (await db.query<{ c: string[] }>(`SELECT rolconfig AS c FROM pg_roles WHERE rolname = 'zeusi_box_ro'`)).rows[0]!.c;
  assert.ok(cfg.includes('default_transaction_read_only=on'));
  // search's own transaction is READ ONLY: even the owner could not write inside it
  const seen: string[] = [];
  const spy: Db = { ...db, label: db.label, query: (s, p) => { seen.push(s); return db.query(s, p); }, exec: (s) => { seen.push(s); return db.exec(s); }, close: () => db.close() };
  await as('zeusi_box_ro', () => search({ db: spy, query: 'tyres', client: client(), ledger: ledger() }));
  assert.ok(seen.includes('BEGIN READ ONLY'));
  assert.ok(seen.some((s) => /SET LOCAL hnsw\.ef_search = 100/.test(s)));
  assert.ok(seen.some((s) => /SET LOCAL hnsw\.iterative_scan = relaxed_order/.test(s)));
  await db.exec('BEGIN READ ONLY');
  assert.equal(await code(db.query(`INSERT INTO zeusi.embed_usage (month, embed_model, host) VALUES ('2026-11-01', 'x', 'y')`)), '25006');
  await db.exec('ROLLBACK');
  // writer and owner sessions are refused before any query text is used
  for (const role of ['zeusi_box_rw', 'zeusi_mini_ingest']) {
    await assert.rejects(as(role, () => search({ db, query: 'tyres', client: client(), ledger: ledger() })), SearchRefused);
  }
  await assert.rejects(search({ db, query: 'tyres', client: client(), ledger: ledger() }), SearchRefused);
  // zeusi_cloud_ro may search too (lexical)
  const c = await as('zeusi_cloud_ro', () => search({ db, query: 'tyres', client: null, ledger: ledger() }));
  assert.equal(c.mode, 'lexical');
});

test('no key: lexical-only fallback with a clear notice', async () => {
  const r = await as('zeusi_box_ro', () => search({ db, query: 'tyres winter', client: null, ledger: ledger() }));
  assert.equal(r.mode, 'lexical');
  assert.equal(r.notice, LEXICAL_ONLY_NOTICE);
  assert.match(LEXICAL_ONLY_NOTICE, /lexical/);
  assert.equal(r.hits[0]!.sourceUri, 'vault:Work/research/garage.md#c0');
  assert.ok(formatSearch(r).includes(LEXICAL_ONLY_NOTICE));
});

test('hybrid: RRF fuses vector and full-text ranks; both the synonym hit and the keyword hit are found', async () => {
  const r = await as('zeusi_box_ro', () => search({ db, query: 'automobile', limit: 5, client: client(), ledger: ledger(), hybrid: true }));
  assert.equal(r.mode, 'hybrid');
  const uris = r.hits.map((h) => h.sourceUri);
  assert.ok(uris.includes('vault:Work/research/garage.md#c0'), 'vector-only hit');
  assert.ok(uris.includes('vault:Work/research/lexical.md#c0'), 'full-text hit');
  // the chunk that is first in BOTH lists ranks first
  const lex = r.hits.find((h) => h.sourceUri === 'vault:Work/research/lexical.md#c0')!;
  assert.ok(lex.ranks.lexical === 1);
});

test('rrfFuse: k = 60, 1-based ranks, ties broken by chunk id', () => {
  const h = (id: number): SearchHit => ({ chunkId: id, sourceUri: `u${id}`, sourceTs: '2026-01-01T00:00:00.000Z', scope: 'work', headingPath: null, text: 't', score: 0, ranks: {} });
  const fused = rrfFuse([h(1), h(2), h(3)], [h(3), h(4)], 60);
  assert.deepEqual(fused.map((x) => x.chunkId), [3, 1, 2, 4]);
  assert.ok(Math.abs(fused[0]!.score - (1 / 63 + 1 / 61)) < 1e-12);
  assert.equal(fused[0]!.ranks.vector, 3);
  assert.equal(fused[0]!.ranks.lexical, 1);
  const tie = rrfFuse([h(9)], [h(5)], 60);
  assert.deepEqual(tie.map((x) => x.chunkId), [5, 9]);
});

test('--scope filters; personal or unknown scope is refused', async () => {
  const r = await as('zeusi_box_ro', () => search({ db, query: 'synthetic', limit: 50, client: null, ledger: ledger(), scope: 'product' }));
  assert.ok(r.hits.length > 0 && r.hits.every((h) => h.scope === 'product'));
  await assert.rejects(as('zeusi_box_ro', () => search({ db, query: 'x', client: null, ledger: ledger(), scope: 'personal' })), SearchRefused);
  await assert.rejects(as('zeusi_box_ro', () => search({ db, query: 'x', client: null, ledger: ledger(), scope: 'nope' })), SearchRefused);
});

test('--scope clientco returns only clientco-scope rows through zeusi_box_ro; no scope filter widens what RLS allows', async () => {
  assert.ok((SEARCH_SCOPES as readonly string[]).includes('client'));
  const v = await as('zeusi_box_ro', () => search({ db, query: 'synthetic', limit: 50, client: null, ledger: ledger(), scope: 'client' }));
  assert.ok(v.hits.length > 0, 'the fixture has admitted ClientCo notes');
  assert.ok(v.hits.every((h) => h.scope === 'client' && h.sourceUri.startsWith('vault:ClientCo/')));
  const visible = new Set((await as('zeusi_box_ro', () => db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.chunks`))).rows.map((r) => r.id));
  const ownerOnly = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.chunks WHERE scope = 'personal'`)).rows.map((r) => r.id);
  assert.ok(ownerOnly.length > 0 && ownerOnly.every((id) => !visible.has(id)), 'RLS hides personal from the reader');
  for (const scope of SEARCH_SCOPES) {
    for (const hybrid of [false, true]) {
      const r = await as('zeusi_box_ro', () => search({ db, query: 'vehicle synthetic', limit: 50, client: hybrid ? client() : null, ledger: ledger(), scope, hybrid }));
      assert.ok(r.hits.every((h) => h.scope === scope && visible.has(h.chunkId)), `scope ${scope} stays inside the RLS-visible set`);
    }
  }
});

test('query-embed spend: local ledger (0600, counts only, no query text) + per-process cap; over cap falls back to lexical', async () => {
  const path = join(safeMkdtemp(join(tmpdir(), 'zeusi-ledger-')), '.zeusi', 'query-embed-ledger.json');
  const l = new QueryLedger(path);
  const c = client();
  await as('zeusi_box_ro', () => search({ db, query: 'secret-looking query words', client: c, ledger: l }));
  const raw = readFileSync(path, 'utf8');
  assert.ok(!raw.includes('secret-looking'), 'no query text in the ledger');
  const j = JSON.parse(raw) as Record<string, { requests: number; tokens: number }>;
  const m = Object.values(j)[0]!;
  assert.equal(m.requests, 1);
  assert.ok(m.tokens > 0);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  // per-process cap
  for (let i = 1; i < QUERY_CAPS.maxRequestsPerProcess; i++) await as('zeusi_box_ro', () => search({ db, query: 'tyres', client: c, ledger: l }));
  const over = await as('zeusi_box_ro', () => search({ db, query: 'tyres', client: c, ledger: l }));
  assert.equal(over.mode, 'lexical');
  assert.match(over.notice ?? '', /per-process/);
  // monthly local cap
  const l2 = new QueryLedger(join(safeMkdtemp(join(tmpdir(), 'zeusi-ledger-')), 'l.json'));
  mkdirSync(join(l2.path, '..'), { recursive: true });
  writeFileSync(l2.path, JSON.stringify({ [new Date().toISOString().slice(0, 7)]: { requests: 1, tokens: 1e12, usd: 1e9 } }), { mode: 0o600 });
  const capped = await as('zeusi_box_ro', () => search({ db, query: 'tyres', client: client(), ledger: l2 }));
  assert.equal(capped.mode, 'lexical');
  assert.match(capped.notice ?? '', /monthly/);
});

test('a failing query embed falls back to lexical with a notice (never a write, never the key)', async () => {
  const c = client();
  c.failOnCall = 1;
  const r = await as('zeusi_box_ro', () => search({ db, query: 'tyres', client: c, ledger: ledger() }));
  assert.equal(r.mode, 'lexical');
  assert.match(r.notice ?? '', /query embedding failed/);
  assert.ok(EmbedError);
});

test('--json output: one object per hit with the citation fields', async () => {
  const r = await as('zeusi_box_ro', () => search({ db, query: 'tyres', client: null, ledger: ledger() }));
  const j = JSON.parse(formatSearch(r, { json: true })) as { mode: string; hits: Array<Record<string, unknown>> };
  assert.equal(j.mode, 'lexical');
  assert.deepEqual(Object.keys(j.hits[0]!).sort(), ['chunk_id', 'heading_path', 'ranks', 'scope', 'score', 'source_ts', 'source_uri', 'text']);
});
