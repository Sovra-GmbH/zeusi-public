// U6b: embedding pipeline + $5 cap against PGlite with the real migrations and grants.
// Runs as zeusi_mini_ingest (SET ROLE). Fake client only: no network, no key.
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { embedText } from '../src/chunking.ts';
import { FakeEmbeddingsClient } from '../src/embeddings.ts';
import {
  EMBED_MODEL_LABEL, HARD_MONTHLY_CAP_USD, PRICE_USD_PER_1M_TOKENS, effectiveCapUsd, monthOf, monthToDate, reserveTokens,
  runEmbed, usdForTokens, worstCaseTokens, EmbedRefused, embedKey,
} from '../src/embed.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const SHA = 'ab'.repeat(32);
let db: Db;
let run: number;
const NOW = new Date('2026-11-14T18:00:00Z');
const MONTH = '2026-11-01';

async function note(path: string, title: string, scope: string, chunks: Array<[string | null, string]>): Promise<number> {
  const id = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, $2, 'synthetic body', now(), $3::zeusi.scope, 'vault_note', $4, now(), decode($5, 'hex'), $6) RETURNING id::int AS id`,
    [path, title, scope, `vault:${path}`, SHA, run])).rows[0]!.id;
  let i = 0;
  for (const [h, t] of chunks) {
    await db.query(
      `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
       VALUES ($1, $2, $3, $4::text, sha256(convert_to($4::text, 'UTF8')), 5, $5)`,
      [id, i, h, t, `vault:${path}#c${i}`]);
    i++;
  }
  return id;
}

async function asIngest<T>(fn: () => Promise<T>): Promise<T> {
  await db.exec('SET ROLE zeusi_mini_ingest');
  try {
    return await fn();
  } finally {
    await db.exec('RESET ROLE');
  }
}

async function pending(): Promise<number> {
  return (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.chunks WHERE embedding IS NULL AND scope <> 'personal'`)).rows[0]!.n;
}

async function usageRows() {
  return (await db.query<{ month: string; embed_model: string; host: string; tokens: number; est_usd: string }>(
    `SELECT to_char(month, 'YYYY-MM-DD') AS month, embed_model, host, tokens::int AS tokens, est_usd::text AS est_usd FROM zeusi.embed_usage ORDER BY host`)).rows;
}

beforeEach(async () => {
  db = await pgliteDb();
  await migrate(db);
  run = Number((await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('vault', 'mini', 'full') RETURNING id::int AS id`)).rows[0]!.id);
  await note('Work/a.md', 'Alpha', 'work', [['Intro', 'deploy the connector on friday'], ['Intro > Steps', 'run the migration then the proof'], [null, 'plain closing words']]);
  await note('Work/b.md', 'Beta', 'work', [['Intro', 'deploy the connector on friday']]); // same text + heading, other title: NOT a duplicate
  await note('Work/c.md', 'Alpha', 'product', [['Intro', 'deploy the connector on friday']]); // identical embedded text to a.md#c0
  await note('Work/p.md', 'Private', 'personal', [[null, 'private synthetic words']]);
});
afterEach(async () => db.close());

test('pricing and cap constants: $0.02 / 1M tokens, hard cap $5.00; override can only lower', () => {
  assert.equal(PRICE_USD_PER_1M_TOKENS[EMBED_MODEL_LABEL], 0.02);
  assert.equal(EMBED_MODEL_LABEL, 'openai/text-embedding-3-small@1536');
  assert.equal(HARD_MONTHLY_CAP_USD, 5);
  assert.equal(effectiveCapUsd(), 5);
  assert.equal(effectiveCapUsd(1.25), 1.25);
  assert.throws(() => effectiveCapUsd(5.01), /only lower/);
  assert.throws(() => effectiveCapUsd(-1), /positive/);
  assert.throws(() => effectiveCapUsd(Number.NaN), /positive/);
  assert.equal(usdForTokens(1_000_000), 0.02);
  assert.equal(usdForTokens(250_000_000), 5);
  assert.equal(monthOf(NOW), MONTH);
});

test('worst-case token bound is UTF-8 bytes (>= any byte-level BPE count, >= the chunker estimate)', () => {
  for (const s of ['hello world', 'Grüße aus Zürich', '日本語のテキスト', '🙂🙂', 'x'.repeat(1000)]) {
    assert.equal(worstCaseTokens(s), Buffer.byteLength(s, 'utf8'));
    assert.ok(worstCaseTokens(s) >= Math.ceil([...s].length / 4));
  }
});

test('embeds pending chunks with title > heading path + chunk; stored text stays the chunk; personal never sent', async () => {
  const client = new FakeEmbeddingsClient();
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(r.status, 'ok', r.error ?? '');
  assert.equal(await pending(), 0);
  const sent = client.calls.flat();
  assert.ok(sent.includes(embedText('Alpha', 'Intro', 'deploy the connector on friday')));
  assert.ok(sent.includes(embedText('Beta', 'Intro', 'deploy the connector on friday')));
  assert.ok(sent.includes(embedText('Alpha', null, 'plain closing words')));
  assert.ok(!sent.some((s) => s.includes('private synthetic')), 'personal rows are invisible to ingest (RLS) and never sent');
  // same-run duplicate (a.md#c0 and c.md#c0 share the embedded string): one input
  assert.equal(sent.filter((s) => s === embedText('Alpha', 'Intro', 'deploy the connector on friday')).length, 1);
  assert.equal(r.counts.apiInputs, 4);
  assert.equal(r.counts.sameRunDuplicates, 1);
  assert.equal(r.counts.embedded, 5);
  const rows = (await db.query<{ text: string; embed_model: string; ok: boolean }>(
    `SELECT text, embed_model, embedded_at IS NOT NULL AS ok FROM zeusi.chunks WHERE scope <> 'personal'`)).rows;
  assert.ok(rows.every((x) => x.embed_model === EMBED_MODEL_LABEL && x.ok));
  assert.ok(rows.every((x) => !x.text.includes(' > ')), 'stored text is the chunk only');
  // the stored vector is the vector of the embedded string
  const v = (await db.query<{ d: number }>(
    `SELECT (embedding <=> $1::halfvec(1536))::float8 AS d FROM zeusi.chunks WHERE source_uri = 'vault:Work/b.md#c0'`,
    [`[${client.vector(embedText('Beta', 'Intro', 'deploy the connector on friday')).join(',')}]`])).rows[0]!.d;
  assert.ok(v < 1e-3);
});

test('usage is recorded from the API-reported tokens (UPSERT add), reservation settled', async () => {
  const client = new FakeEmbeddingsClient();
  client.reportTokens = (inputs) => inputs.length * 7;
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(r.status, 'ok');
  let u = await usageRows();
  assert.equal(u.length, 1);
  assert.deepEqual([u[0]!.month, u[0]!.embed_model, u[0]!.host, u[0]!.tokens], [MONTH, EMBED_MODEL_LABEL, 'testhost', 28]);
  assert.equal(Number(u[0]!.est_usd), 0.0001, 'est_usd rounds UP to 4 decimals (display); tokens are the truth');
  // second run, new chunk: adds
  await note('Work/d.md', 'Delta', 'work', [[null, 'one more chunk']]);
  await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  u = await usageRows();
  assert.equal(u[0]!.tokens, 35);
});

test('missing API usage keeps the worst-case reservation (never under-counts)', async () => {
  const client = new FakeEmbeddingsClient();
  client.reportTokens = () => null;
  await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  const worst = client.calls.flat().reduce((s, x) => s + worstCaseTokens(x), 0);
  assert.equal((await usageRows())[0]!.tokens, worst);
});

test('reuse: an existing vector for the same embedded text is copied, not re-embedded; unchanged chunks are not re-embedded', async () => {
  const client = new FakeEmbeddingsClient();
  await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  const callsAfterFirst = client.calls.flat().length;
  // nothing pending: a second run sends nothing and spends nothing
  const again = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(again.status, 'ok');
  assert.equal(again.counts.pending, 0);
  assert.equal(client.calls.flat().length, callsAfterFirst);
  const tokensBefore = (await usageRows())[0]!.tokens;
  // a re-ingest writes a new chunk row with the same text + title + heading (embedding NULL): reused, no API call
  await note('Work/e.md', 'Alpha', 'work', [['Intro > Steps', 'run the migration then the proof'], [null, 'brand new words']]);
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(r.counts.reused, 1);
  assert.equal(r.counts.apiInputs, 1);
  assert.deepEqual(client.calls.at(-1), [embedText('Alpha', null, 'brand new words')]);
  assert.ok((await usageRows())[0]!.tokens > tokensBefore);
  // a same text_sha256 but different title is NOT reused (vector would be for another embedded string)
  await note('Work/f.md', 'Gamma', 'work', [['Intro > Steps', 'run the migration then the proof']]);
  const r2 = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(r2.counts.reused, 0);
  assert.equal(r2.counts.apiInputs, 1);
});

test('embedKey is sha256 of the exact embedded string', () => {
  assert.equal(embedKey('T', 'H', 'x'), embedKey('T', 'H', 'x'));
  assert.notEqual(embedKey('T', 'H', 'x'), embedKey('U', 'H', 'x'));
  assert.equal(embedKey('T', 'H', 'x').length, 64);
});

test('cap: a batch that would cross the cap is refused before the API call; nothing written', async () => {
  // month-to-date already at the cap minus 10 tokens' worth (other host): any real batch crosses it
  await db.query(`INSERT INTO zeusi.embed_usage (month, embed_model, host, tokens, est_usd) VALUES ($1, $2, 'box', $3, 5)`,
    [MONTH, EMBED_MODEL_LABEL, 250_000_000 - 10]);
  const client = new FakeEmbeddingsClient();
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(r.status, 'capped');
  assert.match(r.error ?? '', /cap/);
  assert.equal(client.calls.length, 0, 'no API call');
  assert.equal(await pending(), 5);
  assert.equal((await usageRows()).length, 1, 'no reservation row added');
});

test('cap: a lowered config cap is honoured; at 99% the next batch is not sent', async () => {
  const client = new FakeEmbeddingsClient();
  const capUsd = 0.000001; // 50 tokens
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW, capUsd, batch: { maxInputs: 1 } }));
  assert.equal(r.status, 'capped');
  const mtd = await asIngest(() => monthToDate(db, MONTH));
  assert.ok(mtd.usd <= capUsd, 'month-to-date never exceeds the cap');
  assert.ok(client.calls.length >= 1 && client.calls.length < 4, 'stopped part-way');
});

test('cap holds across a crash: the reservation is committed before the call and survives', async () => {
  const client = new FakeEmbeddingsClient();
  client.failOnCall = 1; // "crash" between reservation and settlement
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(r.status, 'failed');
  const u = await usageRows();
  assert.equal(u.length, 1);
  assert.ok(u[0]!.tokens > 0, 'worst-case reservation kept (over-counts, never under-counts)');
  assert.equal(await pending(), 5, 'nothing written for the failed batch');
});

test('cap holds across concurrent runs: reservations serialise on one advisory xact lock and see each other', async () => {
  // Run B reserves while run A is inside its API call (A already reserved). Combined > cap: B is refused.
  const statements: string[] = [];
  const spy: Db = { ...db, label: db.label, query: (sql, p) => { statements.push(sql); return db.query(sql, p); }, exec: (s) => db.exec(s), close: () => db.close() };
  const capUsd = usdForTokens(400); // 400 tokens
  let bResult: Awaited<ReturnType<typeof reserveTokens>> | undefined;
  const client = new FakeEmbeddingsClient();
  const orig = client.embed.bind(client);
  client.embed = async (inputs) => {
    if (!bResult) bResult = await reserveTokens(spy, { month: MONTH, model: EMBED_MODEL_LABEL, host: 'box', tokens: 300, capUsd });
    return orig(inputs);
  };
  const r = await asIngest(() => runEmbed({ db: spy, client, host: 'testhost', now: () => NOW, capUsd, batch: { maxInputs: 10 } }));
  assert.equal(r.status, 'ok', 'A fits on its own');
  assert.equal(bResult!.ok, false, 'B sees A\'s committed reservation and is refused');
  assert.ok(statements.some((s) => /pg_advisory_xact_lock/.test(s)), 'reservation takes the cap lock');
  const mtd = await asIngest(() => monthToDate(db, MONTH));
  assert.ok(mtd.usd <= capUsd);
});

test('an unknown model in this month\'s usage fails closed', async () => {
  await db.query(`INSERT INTO zeusi.embed_usage (month, embed_model, host, tokens) VALUES ($1, 'other/model@9', 'mini', 1)`, [MONTH]);
  const client = new FakeEmbeddingsClient();
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(r.status, 'capped');
  assert.match(r.error ?? '', /unknown embed_model/);
  assert.equal(client.calls.length, 0);
});

test('fail closed: wall_audit rows block the whole run before any text leaves', async () => {
  // owner inserts a chunk that breaks a hard rule by bypassing the trigger (simulates a rule added after ingest)
  await db.exec(`ALTER TABLE zeusi.chunks DISABLE TRIGGER zeusi_90_wall`);
  const nid = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.notes WHERE vault_path = 'Work/a.md'`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.chunks (note_id, chunk_index, text, text_sha256, token_count, source_uri)
                  VALUES ($1, 9, 'mentions plankiva synthetic', sha256(convert_to('x', 'UTF8')), 3, 'vault:Work/a.md#c9')`, [nid]);
  await db.exec(`ALTER TABLE zeusi.chunks ENABLE TRIGGER zeusi_90_wall`);
  const client = new FakeEmbeddingsClient();
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW }));
  assert.equal(r.status, 'wall');
  assert.equal(client.calls.length, 0);
});

/** Fresh PGlite with only the migrations whose file name sorts before `below` (e.g. '0010'). */
async function partialDb(below: string): Promise<Db> {
  const p = await pgliteDb();
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-mig-'));
  const src = fileURLToPath(new URL('../migrations/', import.meta.url));
  for (const f of readdirSync(src).filter((x) => x < below)) cpSync(join(src, f), join(dir, f));
  await migrate(p, { dir });
  return p;
}

async function insertSyntheticPlankivaAsIngest(d: Db): Promise<void> {
  // Through the trigger, as the ingest role: the pre-0011 wall does not catch the one-n spelling.
  await d.exec('SET ROLE zeusi_mini_ingest');
  try {
    const r = Number((await d.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('vault', 'mini', 'full') RETURNING id::int AS id`)).rows[0]!.id);
    const nid = (await d.query<{ id: number }>(
      `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('Work/m.md', 'Meeting', 'synthetic body', now(), 'work', 'vault_note', 'vault:Work/m.md', now(), decode($1, 'hex'), $2) RETURNING id::int AS id`,
      [SHA, r])).rows[0]!.id;
    await d.query(
      `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
       VALUES ($1, 0, NULL, $2::text, sha256(convert_to($2::text, 'UTF8')), 5, 'vault:Work/m.md#c0')`,
      [nid, 'SYNTHETIC: met Plaankiva about the plan']);
  } finally {
    await d.exec('RESET ROLE');
  }
}

test('MAJOR-1 repro: on 0001-0009 (no 0010/0011) embed refuses before anything is read or sent (dry run and real)', async () => {
  const p9 = await partialDb('0010');
  try {
    await insertSyntheticPlankivaAsIngest(p9);
    assert.equal((await p9.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.wall_audit()`)).rows[0]!.n, 0, 'the 0009 wall audit is blind to it');
    for (const dryRun of [true, false]) {
      const client = new FakeEmbeddingsClient();
      const statements: string[] = [];
      const spy: Db = { ...p9, query: (sql, params) => { statements.push(sql); return p9.query(sql, params); } };
      await p9.exec('SET ROLE zeusi_mini_ingest');
      try {
        await assert.rejects(runEmbed({ db: spy, client, host: 'testhost', now: () => NOW, dryRun }), (err: Error) =>
          err instanceof EmbedRefused && /embed refused/.test(err.message) && /migration 0010/.test(err.message) && /migration 0011/.test(err.message));
      } finally {
        await p9.exec('RESET ROLE');
      }
      assert.equal(client.calls.length, 0, 'nothing sent');
      assert.ok(!statements.some((s) => /FROM zeusi\.chunks/.test(s)), 'no chunk text read');
    }
    assert.equal((await p9.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.chunks WHERE embedding IS NOT NULL`)).rows[0]!.n, 0, 'embedded 0');
    assert.equal((await p9.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.embed_usage`)).rows[0]!.n, 0);
    // Control: the same DB after 0010 + 0011. The readiness gate passes; wall_audit now catches the row.
    await migrate(p9, { tookSnapshot: true });
    const client = new FakeEmbeddingsClient();
    await p9.exec('SET ROLE zeusi_mini_ingest');
    try {
      const r = await runEmbed({ db: p9, client, host: 'testhost', now: () => NOW });
      assert.equal(r.status, 'wall');
      assert.equal(r.counts.embedded, 0);
    } finally {
      await p9.exec('RESET ROLE');
    }
    assert.equal(client.calls.length, 0);
  } finally {
    await p9.close();
  }
});

test('embed refuses on 0001-0010 (no 0011), naming 0011 only', async () => {
  const p10 = await partialDb('0011');
  try {
    const client = new FakeEmbeddingsClient();
    await p10.exec('SET ROLE zeusi_mini_ingest');
    try {
      await assert.rejects(runEmbed({ db: p10, client, host: 'testhost', now: () => NOW, dryRun: true }), (err: Error) =>
        err instanceof EmbedRefused && /migration 0011/.test(err.message) && !/migration 0010 /.test(err.message));
    } finally {
      await p10.exec('RESET ROLE');
    }
    assert.equal(client.calls.length, 0);
  } finally {
    await p10.close();
  }
});

test('refused for an owner-privileged session', async () => {
  const client = new FakeEmbeddingsClient();
  await assert.rejects(runEmbed({ db, client, host: 'testhost', now: () => NOW }), EmbedRefused);
  assert.equal(client.calls.length, 0);
});

test('dry run: counts and cost only; no API call, no write', async () => {
  const client = new FakeEmbeddingsClient();
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW, dryRun: true }));
  assert.equal(r.status, 'ok');
  assert.equal(r.counts.pending, 5);
  assert.equal(r.counts.apiInputs, 4, 'unique embedded strings that would be sent');
  assert.ok(r.counts.estTokens > 0 && r.counts.worstTokens >= r.counts.estTokens);
  assert.equal(client.calls.length, 0);
  assert.equal(await pending(), 5);
  assert.equal((await usageRows()).length, 0);
});

test('--limit caps the chunks considered', async () => {
  const client = new FakeEmbeddingsClient();
  const r = await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW, limit: 2 }));
  assert.equal(r.counts.pending, 2);
  assert.equal(await pending(), 3);
});

test('batching: many inputs are split by maxInputs', async () => {
  const client = new FakeEmbeddingsClient();
  await asIngest(() => runEmbed({ db, client, host: 'testhost', now: () => NOW, batch: { maxInputs: 2 } }));
  assert.deepEqual(client.calls.map((c) => c.length), [2, 2]);
});
