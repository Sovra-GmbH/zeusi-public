// Security P0 (17 Nov 2026): a partial secret was served by zeusi_search. One detector
// (src/secrets.ts) is used at ingest (vault + hq-sync + fact add), in the nightly export
// filter, at serve time (every MCP tool output + CLI search) and by `zeusi rescrub`.
// PGlite only; no network, no Neon, no OpenAI. Every key is SYNTHETIC, built at runtime.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { HQ_PROFILE, importVault } from '../src/importers/vault.ts';
import { runExportFilter } from '../src/hq-export.ts';
import { dummyVector, insertFact } from '../src/facts.ts';
import { formatSearch, search as realSearch, type SearchResult } from '../src/search.ts';
import { createMcpState, createZeusiMcpServer, type McpDeps, type ToolObservation } from '../src/mcp-server.ts';
import { wallFilter, safeMessage } from '../src/mcp-wall.ts';
import { formatRescrub, runRescrub } from '../src/rescrub.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { hqNote } from './hq-fixtures.ts';
import { fakeGoogleKey, fakeMaskedGoogle, P } from './secret-fixtures.ts';

const MODEL = 'openai/text-embedding-3-small@1536';
const OLD = new Date('2026-01-05T10:00:00Z');
const SHA = 'cd'.repeat(32);
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const ANTHROPIC = () => [P.anthropic, 'X0'.repeat(10)].join('');

/** The prefix of every synthetic key: none may appear in any stored row or output. */
const leaks = (s: string) => s.includes(P.google) || s.includes(P.anthropic);

// ---------------------------------------------------------------------------
// Ingest: vault + hq-sync (one importer, one place)

async function ingestEnv(profile: 'vault' | 'hq') {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-sec-ingest-'));
  const root = join(dir, 'src');
  const db = await pgliteDb();
  await migrate(db);
  const toml = profile === 'vault'
    ? `[[source]]\nname = "v"\nkind = "vault_note"\nscope = "work"\nroot = "${root}"\ninclude = ["**/*.md"]\n`
    : `[[source]]\nname = "hq-general"\nkind = "zeus_memory"\nscope = "work"\nroot = "${root}"\ninclude = ["hq/*.md"]\nproject = "hq"\n`;
  mkdirSync(join(root, profile === 'vault' ? 'Work/products' : 'hq'), { recursive: true });
  return {
    db, dir, root,
    write(rel: string, text: string) {
      writeFileSync(join(root, rel), text);
      utimesSync(join(root, rel), OLD, OLD);
    },
    async run() {
      const config = validateSources(parseToml(toml), seedWall(), { home: dir });
      await db.exec('SET ROLE zeusi_mini_ingest');
      try {
        return await importVault({ db, config, mode: 'full', home: dir, log: () => {}, ...(profile === 'hq' ? { profile: HQ_PROFILE } : {}) });
      } finally {
        await db.exec('RESET ROLE');
      }
    },
    async stored() {
      const n = (await db.query<{ t: string }>(`SELECT title || ' ' || body || ' ' || frontmatter::text AS t FROM zeusi.notes`)).rows.map((r) => r.t);
      const c = (await db.query<{ t: string }>(`SELECT coalesce(heading_path, '') || ' ' || text AS t FROM zeusi.chunks`)).rows.map((r) => r.t);
      return { notes: n, chunks: c, all: [...n, ...c].join('\n') };
    },
    async close() {
      await db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

test('vault ingest: a note with the leaked shape (and a full key in the frontmatter) is stored redacted, the rest kept; counts only', async () => {
  const e = await ingestEnv('vault');
  try {
    e.write('Work/products/avatar.md', [
      '---', `title: Avatar phases`, `gemini_key: ${fakeGoogleKey()}`, 'date: 2026-05-03', '---', '',
      '# Avatar', '', '## Phase 0b', '', `- Gemini key in use: \`${fakeMaskedGoogle()}\` (AI Studio)`, '- Next: rig the avatar.', '',
    ].join('\n'));
    e.write('Work/products/clean.md', '# Clean\n\nNothing secret here, only the avatar plan.\n');
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.inserted, 2);
    assert.equal(r.counts.notes_redacted, 1);
    assert.equal(r.counts.secrets_redacted, 2);
    const s = await e.stored();
    assert.ok(!leaks(s.all), 'no stored row carries the prefix');
    assert.match(s.all, /\[REDACTED:masked_google_api_key\]/);
    assert.match(s.all, /\[REDACTED:google_api_key\]/);
    assert.match(s.all, /Next: rig the avatar\./, 'the rest of the note is kept');
    // A second run: unchanged file (same sha) is skipped and stays redacted.
    const r2 = await e.run();
    assert.equal(r2.counts.skipped, 2);
    assert.ok(!leaks((await e.stored()).all));
  } finally {
    await e.close();
  }
});

test('hq-sync ingest: the same importer redacts a planted partial key in an HQ entry', async () => {
  const e = await ingestEnv('hq');
  try {
    e.write('hq/2026-11-13-avatar.md', hqNote({ project: 'hq' }, [['t1', `key for the demo: ${[P.google, 'SyX0X0X0'].join('')}`], ['t2', 'clean entry']]));
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.inserted, 1);
    assert.equal(r.counts.notes_redacted, 1);
    const s = await e.stored();
    assert.ok(!leaks(s.all));
    assert.match(s.all, /\[REDACTED:google_api_key\]/);
    assert.match(s.all, /clean entry/);
  } finally {
    await e.close();
  }
});

test('nightly export filter: an HQ entry with a partial / masked key is withheld (shared detector); the output gate passes', () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-sec-export-'));
  try {
    const inDir = join(dir, 'staging');
    const outDir = join(dir, 'out');
    mkdirSync(join(inDir, 'hq'), { recursive: true });
    writeFileSync(join(inDir, 'hq', '2026-11-13-keys.md'), hqNote({ project: 'hq' }, [
      ['t1', `C1 the key is \`${fakeMaskedGoogle()}\``],
      ['t2', `C2 truncated ${[P.google, 'SyX0X0'].join('')}`],
      ['t3', 'K3 clean entry'],
    ]));
    const r = runExportFilter({ inDir, outDir, projects: ['hq'] });
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.withheld_by_signal.credential, 2);
    const out = readFileSync(join(outDir, 'hq', '2026-11-13-keys.md'), 'utf8');
    assert.ok(!leaks(out));
    assert.doesNotMatch(out, /C[12] /);
    assert.match(out, /K3 clean entry/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('fact add (insertFact): the fact text is redacted before the wall pre-check and the INSERT', async () => {
  const db = await pgliteDb();
  try {
    await migrate(db);
    await db.exec('SET ROLE zeusi_mini_ingest');
    const r = await insertFact(db, {
      kind: 'other', text: `demo key ${fakeMaskedGoogle()} for the avatar`, scope: 'work', sourceKind: 'manual',
      sourceUri: 'manual:sec-test', sourceTs: '2026-11-17T09:00:00Z', sourceSha256: SHA,
    });
    await db.exec('RESET ROLE');
    assert.equal(r.status, 'inserted');
    const t = (await db.query<{ text: string }>(`SELECT text FROM zeusi.facts`)).rows[0]!.text;
    assert.equal(t, 'demo key [REDACTED:masked_google_api_key] for the avatar');
  } finally {
    await db.close();
  }
});

// ---------------------------------------------------------------------------
// Serve time: every MCP output path, through the real server (stdio-equivalent in-memory transport)

let db: Db;
let home: string;

function asRole(role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-sec-mcp-'));
  writeFileSync(join(home, '.pg_service.conf'), '[zeusi_ro]\nhost=ep-fake-1.example.invalid\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n');
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'manual:people/owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  // Rows that predate the detector (as the live DB has): written directly, unredacted.
  const fact = (kind: string, subject: string, text: string, uri: string) => db.query(
    `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, $2, $3, 'work', 'manual', $4, now(), sha256(convert_to($4, 'UTF8')), $5)`, [kind, subject, text, uri, run]);
  await fact('rule', 'keys', `Never paste keys like ${fakeMaskedGoogle()} into chat`, 'vault:Work/handbook/rules.md#keys');
  await fact('state', 'avatar', `Avatar demo uses ${fakeGoogleKey()}`, 'vault:Work/handbook/focus.md');
  await db.query(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner'), now() - interval '1 day', 'minute', $1, true, ARRAY['ocelot'], 'work', 'manual', 'hq:t-ocelot', now(), decode($2, 'hex'), $3)`,
    [`ocelot go: use ${ANTHROPIC()} for the demo`, SHA, run]);
  const nid = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/products/avatar.md', 'Avatar phases', $1, now(), 'work', 'vault_note', 'vault:Work/products/avatar.md', now(), decode($2, 'hex'), $3)
     RETURNING id::int AS id`, [`ocelot avatar key \`${fakeMaskedGoogle()}\``, SHA, run])).rows[0]!.id;
  const chunk = (i: number, text: string, embedded: boolean) => db.query(
    `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri, embed_model, embedding, embedded_at)
     VALUES ($1, $2, 'Avatar > Phase 0b', $3, sha256(convert_to($3, 'UTF8')), 5, $4, $5, $6::halfvec, CASE WHEN $5::text IS NULL THEN NULL ELSE now() END)`,
    [nid, i, text, `vault:Work/products/avatar.md#c${i}`, embedded ? MODEL : null, embedded ? dummyVector(i) : null]);
  await chunk(0, 'ocelot avatar plan, phase 0a done', true);
  await chunk(5, `ocelot Gemini key in use: \`${fakeMaskedGoogle()}\` (AI Studio)`, true);
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
  const client = new Client({ name: 'sec-test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
    return { isError: r.isError === true, text: r.content.map((c) => c.text ?? '').join('\n') };
  };
  return { call, client, close: async () => { await client.close(); await server.close(); } };
}

test('serve guard: zeusi_search WITHHOLDS the leaked-shape chunk and the decision (never redacted-and-served); counted, never the text', async () => {
  const seen: ToolObservation[] = [];
  const h = await mcp({ observe: (o) => seen.push({ ...o }) });
  try {
    const r = await h.call('zeusi_search', { query: 'ocelot', limit: 10 });
    assert.ok(!r.isError, r.text);
    assert.ok(!leaks(r.text), 'no key prefix in the response');
    assert.ok(!r.text.includes('[REDACTED:'), 'nothing is redacted at serve time');
    const j = JSON.parse(r.text) as { hits: Array<{ source_uri: string; text: string }>; decisions: Array<{ exact_words: string }>; withheld: number };
    assert.ok(!j.hits.some((x) => x.source_uri.endsWith('#c5')), 'the hit is withheld');
    assert.ok(j.hits.some((x) => x.source_uri.endsWith('#c0')), 'the clean chunk of the same note is served');
    assert.equal(j.decisions.length, 0);
    assert.equal(j.withheld, 2);
    assert.deepEqual(seen, [{ tool: 'zeusi_search', hitCount: j.hits.length, withheld: 2, secretWithheld: 2 }]);
    assert.ok(!JSON.stringify(seen).includes('ocelot'), 'the observation carries counts only');
  } finally {
    await h.close();
  }
});

test('serve guard: zeusi_startup rules, focus and decisions carrying a credential are withheld', async () => {
  const seen: ToolObservation[] = [];
  const h = await mcp({ observe: (o) => seen.push({ ...o }) });
  try {
    const r = await h.call('startup', {});
    assert.ok(!r.isError, r.text);
    assert.ok(!leaks(r.text) && !r.text.includes('[REDACTED:'));
    const j = JSON.parse(r.text) as { rules: unknown[]; focus: unknown[]; decisions: unknown[]; withheld: number };
    assert.deepEqual([j.rules, j.focus, j.decisions], [[], [], []]);
    assert.equal(j.withheld, 3);
    assert.equal(seen[0]!.secretWithheld, 3);
  } finally {
    await h.close();
  }
});

test('serve guard: injected hits, notices and error messages carrying a credential are withheld; fail closed when the check throws', async () => {
  const injected = async (): Promise<SearchResult> => ({
    mode: 'lexical', notice: `notice ${fakeMaskedGoogle()}`,
    hits: [
      { chunkId: 1, sourceUri: 'vault:a.md#c0', sourceTs: new Date().toISOString(), scope: 'work', headingPath: `H ${fakeGoogleKey()}`, text: 'clean', score: 1, ranks: {} },
      { chunkId: 2, sourceUri: 'vault:b.md#c0', sourceTs: new Date().toISOString(), scope: 'work', headingPath: null, text: 'also clean', score: 1, ranks: {} },
    ],
  });
  const h = await mcp({ searchFn: injected });
  try {
    const r = await h.call('zeusi_search', { query: 'x' });
    assert.ok(!leaks(r.text) && !r.text.includes('[REDACTED:'));
    const j = JSON.parse(r.text) as { hits: Array<{ text: string }>; notice?: string; withheld: number };
    assert.deepEqual(j.hits.map((x) => x.text), ['also clean'], 'the hit with a key in its heading is withheld whole');
    assert.equal(j.notice, undefined, 'a notice carrying a credential is not served');
    assert.equal(j.withheld, 1);
  } finally {
    await h.close();
  }
  // Fail closed: a check that throws withholds every item (and the notice), never serves it raw.
  const seen: ToolObservation[] = [];
  const broken = await mcp({ searchFn: injected, serveCheck: () => { throw new Error('guard down'); }, observe: (o) => seen.push({ ...o }) });
  try {
    const r = await broken.call('zeusi_search', { query: 'x' });
    assert.ok(!r.isError, r.text);
    const j = JSON.parse(r.text) as { hits: unknown[]; withheld: number; notice?: string };
    assert.deepEqual(j.hits, []);
    assert.equal(j.withheld, 2);
    assert.equal(j.notice, undefined);
    assert.ok(!leaks(r.text));
    assert.equal(seen[0]!.withheld, 2);
  } finally {
    await broken.close();
  }
  // Error messages: a message carrying a credential is replaced whole.
  const thrower = await mcp({ searchFn: async () => { throw new Error(`upstream said ${fakeMaskedGoogle()} is invalid`); } });
  try {
    const r = await thrower.call('zeusi_search', { query: 'x' });
    assert.ok(r.isError);
    assert.equal(r.text, 'refused (details withheld by the wall)');
  } finally {
    await thrower.close();
  }
  assert.equal(safeMessage(`a ${ANTHROPIC()} b`), 'refused (details withheld by the wall)');
  assert.equal(safeMessage('upstream said [REDACTED:keyword_value] x'), 'refused (details withheld by the wall)', 'a marker is never served');
  assert.equal(safeMessage('connection reset by peer'), 'connection reset by peer', 'a clean message is served unchanged');
});

test('serve guard: zeusi_context_for_task items carrying a credential are withheld, counted; fail closed when the check throws', async () => {
  const seen: ToolObservation[] = [];
  const h = await mcp({ observe: (o) => seen.push({ ...o }) });
  try {
    const r = await h.call('zeusi_context_for_task', { task: 'ocelot demo' });
    assert.ok(!r.isError, r.text);
    assert.ok(!leaks(r.text) && !r.text.includes('[REDACTED:'), 'no key prefix, no marker in the response');
    const j = JSON.parse(r.text) as { items: unknown[]; withheld: number };
    assert.deepEqual(j.items, [], 'the decision is withheld');
    assert.equal(j.withheld, 1);
    assert.deepEqual(seen, [{ tool: 'zeusi_context_for_task', hitCount: 0, withheld: 1, secretWithheld: 1 }]);
  } finally {
    await h.close();
  }
  const seen2: ToolObservation[] = [];
  const broken = await mcp({ serveCheck: () => { throw new Error('guard down'); }, observe: (o) => seen2.push({ ...o }) });
  try {
    const r = await broken.call('zeusi_context_for_task', { task: 'ocelot demo' });
    assert.ok(!r.isError, r.text);
    assert.ok(!leaks(r.text));
    const j = JSON.parse(r.text) as { items: unknown[]; withheld: number };
    assert.deepEqual(j.items, []);
    assert.equal(j.withheld, 1);
    assert.equal(seen2[0]!.withheld, 1);
  } finally {
    await broken.close();
  }
});

test('serve guard: about hits in zeusi_search pass the guard (fail closed: withheld when it throws)', async () => {
  const h = await mcp();
  try {
    const j = JSON.parse((await h.call('zeusi_search', { query: 'cite', limit: 10 })).text) as { about: unknown[] };
    assert.ok(j.about.length >= 1, 'about entries match "cite" with the guard on');
  } finally {
    await h.close();
  }
  const seen: ToolObservation[] = [];
  const broken = await mcp({ serveCheck: () => { throw new Error('guard down'); }, observe: (o) => seen.push({ ...o }) });
  try {
    const r = await broken.call('zeusi_search', { query: 'cite', limit: 10 });
    assert.ok(!r.isError, r.text);
    const j = JSON.parse(r.text) as { about: unknown[]; withheld: number };
    assert.deepEqual(j.about, []);
    assert.ok(j.withheld >= 1);
    assert.equal(seen[0]!.withheld, j.withheld, 'the log count matches the response count');
  } finally {
    await broken.close();
  }
});

test('serve guard: the start-task prompt does not echo a task carrying a credential; zeusi://about passes the guard; fail closed', async () => {
  const promptText = async (h: Awaited<ReturnType<typeof mcp>>, task: string) => {
    const p = await h.client.getPrompt({ name: 'start-task', arguments: { task } });
    return p.messages.map((m) => (m.content as { text?: string }).text ?? '').join('\n');
  };
  const h = await mcp();
  try {
    const t = await promptText(h, `wire the avatar with ${fakeMaskedGoogle()} today`);
    assert.ok(!leaks(t) && !t.includes('[REDACTED:'));
    assert.doesNotMatch(t, /Task: /);
    assert.match(t, /not repeated here/);
    assert.match(await promptText(h, 'wire the avatar today'), /Task: wire the avatar today/, 'a clean task is echoed unchanged');
    const res = await h.client.readResource({ uri: 'zeusi://about' });
    assert.match(String((res.contents[0] as { text?: string }).text), /Zeusi/);
  } finally {
    await h.close();
  }
  const broken = await mcp({ serveCheck: () => { throw new Error('guard down'); } });
  try {
    const t = await promptText(broken, 'wire the avatar today');
    assert.doesNotMatch(t, /Task: /, 'not echoed when the check throws');
    assert.match(t, /not repeated here/);
    const res = await broken.client.readResource({ uri: 'zeusi://about' });
    assert.equal((res.contents[0] as { text?: string }).text, 'About Zeusi: details withheld by the wall.');
  } finally {
    await broken.close();
  }
});

test('serve guard mutant: without the guard (a check that never fires) the hit is served', () => {
  const hit = { source_uri: 'vault:x.md#c5', text: `key \`${fakeMaskedGoogle()}\`` };
  const good = wallFilter([hit]);
  assert.deepEqual(good.kept, []);
  assert.deepEqual([good.withheld, good.secretWithheld], [1, 1]);
  const noGuard = wallFilter([hit], () => false);
  assert.equal(noGuard.kept.length, 1, 'mutant: the guard dropped serves the key');
});

test('CLI search output (formatSearch) is redacted too, text and --json', () => {
  const r: SearchResult = {
    mode: 'lexical',
    hits: [{ chunkId: 5, sourceUri: 'vault:a.md#c5', sourceTs: '2026-05-03T00:00:00.000Z', scope: 'work', headingPath: null, text: `k ${fakeMaskedGoogle()}`, score: 1, ranks: {} }],
  };
  for (const json of [false, true]) {
    const out = formatSearch(r, { json });
    assert.ok(!leaks(out), `json=${json}`);
    assert.match(out, /\[REDACTED:masked_google_api_key\]/);
  }
});

// ---------------------------------------------------------------------------
// zeusi rescrub (PGlite, as zeusi_mini_ingest)

async function snapshot(): Promise<string> {
  const parts: string[] = [];
  for (const t of ['notes', 'chunks', 'facts', 'decisions', 'ingest_runs', 'quarantine']) {
    parts.push((await db.query<{ h: string | null; n: number }>(`SELECT md5(coalesce(string_agg(x::text, '|' ORDER BY x.id), '')) AS h, count(*)::int AS n FROM zeusi.${t} x`)).rows.map((r) => `${t}:${r.n}:${r.h}`).join());
  }
  return parts.join('\n');
}

async function asIngest<T>(fn: () => Promise<T>): Promise<T> {
  await db.exec('SET ROLE zeusi_mini_ingest');
  try {
    return await fn();
  } finally {
    await db.exec('RESET ROLE');
  }
}

test('rescrub: dry run reports counts by kind and writes zero rows; real run redacts, clears embeddings for re-embed, is idempotent', async () => {
  // A second matched note (review r1 P2-5): with 2+ matched notes a dry run that tried to write
  // would show up as write_errors (the READ ONLY transaction refuses the UPDATE) and, after
  // writeRow's ROLLBACK ended that transaction, as rows written in autocommit.
  const run = (await db.query<{ id: number }>(`SELECT min(id)::int AS id FROM zeusi.ingest_runs`)).rows[0]!.id;
  await db.query(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/products/avatar-2.md', 'Avatar 2', $1, now(), 'work', 'vault_note', 'vault:Work/products/avatar-2.md', now(), decode($2, 'hex'), $3)`,
    [`second key ${fakeGoogleKey()}`, SHA, run]);
  const before0 = await snapshot();
  const dry = await asIngest(() => runRescrub({ db, real: false }));
  assert.equal(dry.status, 'ok', dry.error ?? '');
  assert.equal(dry.counts.write_errors, 0, 'dry run: no write was even attempted');
  assert.equal(dry.counts.notes_rewritten + dry.counts.chunks_rewritten + dry.counts.chunks_flagged_reembed, 0);
  assert.equal(await snapshot(), before0, 'dry run: zero rows written (no ingest_runs row either)');
  assert.deepEqual(dry.counts.matched, { notes: 2, chunks: 1, facts: 2, decisions: 1 });
  assert.deepEqual(dry.counts.by_kind, { masked_google_api_key: 3, google_api_key: 2, anthropic_key: 1 });
  const dryOut = formatRescrub(dry);
  assert.ok(!leaks(dryOut) && !dryOut.includes('ocelot') && !dryOut.includes('Avatar'), 'counts, kinds and ids only');
  assert.match(dryOut, /dry run: read-only, zero rows written/);

  const real = await asIngest(() => runRescrub({ db, real: true, host: 'test' }));
  assert.equal(real.status, 'ok', real.error ?? '');
  assert.equal(real.counts.notes_rewritten, 2);
  assert.equal(real.counts.chunks_rewritten, 1);
  assert.equal(real.counts.chunks_flagged_reembed, 1);
  assert.equal(real.counts.write_errors, 0);
  assert.equal(real.counts.owner_followup.facts.length, 2, 'facts are insert-only for the ingest role: listed for the owner');
  assert.equal(real.counts.owner_followup.decisions.length, 1);
  const notes = (await db.query<{ body: string }>(`SELECT body FROM zeusi.notes ORDER BY id`)).rows;
  assert.deepEqual(notes.map((n) => n.body), ['ocelot avatar key `[REDACTED:masked_google_api_key]`', 'second key [REDACTED:google_api_key]']);
  const chunks = (await db.query<{ i: number; text: string; e: boolean; m: string | null; sha_ok: boolean }>(
    `SELECT chunk_index AS i, text, embedding IS NOT NULL AS e, embed_model AS m, text_sha256 = sha256(convert_to(text, 'UTF8')) AS sha_ok
     FROM zeusi.chunks ORDER BY chunk_index`)).rows;
  assert.deepEqual(chunks.map((c) => [c.i, c.e, c.sha_ok]), [[0, true, true], [5, false, true]], 'only the changed chunk lost its vector');
  assert.equal(chunks[1]!.text, 'ocelot Gemini key in use: `[REDACTED:masked_google_api_key]` (AI Studio)');
  assert.equal(chunks[1]!.m, null);
  const runs = (await db.query<{ importer: string; status: string; counts: Record<string, unknown> }>(`SELECT importer, status, counts FROM zeusi.ingest_runs WHERE importer = 'rescrub'`)).rows;
  assert.equal(runs.length, 1);
  assert.equal(runs[0]!.status, 'ok');
  assert.ok(!leaks(JSON.stringify(runs[0]!.counts)));
  // The pending chunk is what `embed` picks up (embedding IS NULL).
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.chunks WHERE embedding IS NULL`)).rows[0]!.n, 1);

  // Idempotent: a second real run finds no notes / chunks and changes nothing in them.
  const s1 = await snapshot();
  const again = await asIngest(() => runRescrub({ db, real: true, host: 'test' }));
  assert.equal(again.status, 'ok');
  assert.deepEqual({ n: again.counts.matched.notes, c: again.counts.matched.chunks }, { n: 0, c: 0 });
  assert.equal(again.counts.notes_rewritten + again.counts.chunks_rewritten + again.counts.chunks_flagged_reembed, 0);
  const strip = (s: string) => s.split('\n').filter((l) => !l.startsWith('ingest_runs')).join('\n');
  assert.equal(strip(await snapshot()), strip(s1), 'second run: notes, chunks, facts, decisions unchanged');
});

test('rescrub real refuses to interleave with a running ingest (an importer lock is held): nothing changed', async () => {
  const before0 = await snapshot();
  const locked: Db = {
    label: 'pglite, vault lock held elsewhere', exec: db.exec.bind(db), close: async () => {},
    query: (async (sql: string, params?: unknown[]) => (/pg_try_advisory_lock/.test(sql) ? { rows: [{ ok: false }] } : db.query(sql, params))) as Db['query'],
  };
  const r = await asIngest(() => runRescrub({ db: locked, real: true }));
  assert.equal(r.status, 'locked');
  assert.match(formatRescrub(r), /holds its lock; nothing was changed/);
  assert.equal(await snapshot(), before0);
});

test('CLI rescrub: flags for --real only; --real refuses Neon main offline (no connection, no host printed)', () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-sec-cli-'));
  try {
    const host = ['ep-fake-777', '.eu-central-1.aws.neon.tech'].join('');
    writeFileSync(join(dir, '.pg_service.conf'), `[zeusi_ingest]\nhost=${host}\nport=5432\ndbname=zeusi\nuser=zeusi_mini_ingest\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
    const run = (args: string[], extra: Record<string, string> = {}) => {
      const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: dir, PGSERVICEFILE: join(dir, '.pg_service.conf'), ...extra };
      const r = spawnSync(process.execPath, [CLI, 'rescrub', ...args], { cwd: dir, encoding: 'utf8', env, timeout: 20_000 });
      return { code: r.status, out: `${r.stdout}${r.stderr}` };
    };
    let r = run(['--skip-embed']);
    assert.equal(r.code, 2, r.out);
    assert.match(r.out, /apply to --real only/);
    r = run(['--real']);
    assert.equal(r.code, 2, r.out);
    assert.match(r.out, /ZEUSI_MAIN_ENDPOINT_ID/);
    assert.match(r.out, /No connection made/);
    r = run(['--real'], { ZEUSI_MAIN_ENDPOINT_ID: 'ep-fake-777' });
    assert.equal(r.code, 2, r.out);
    assert.match(r.out, /targets the default branch \(main\)/);
    for (const x of [run(['--real']), run(['--real'], { ZEUSI_MAIN_ENDPOINT_ID: 'ep-fake-777' })]) assert.ok(!x.out.includes(host) && !x.out.includes('neon.tech'));
    r = run(['--real', '--bogus']);
    assert.notEqual(r.code, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
