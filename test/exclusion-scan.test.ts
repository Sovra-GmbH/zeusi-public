// scripts/exclusion-scan.ts (0011 follow-up, read-only): per-table counts of rows with any Plankiva signal,
// as the connected role, plain SELECT only, counts only. Synthetic exclusion probes, PGlite only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { exclusionScan, formatExclusionScan, SCAN_EXCLUDED } from '../src/exclusion-scan.ts';

const SHA = 'cd'.repeat(32);
let db: Db & { raw: unknown };
const statements: string[] = [];
/** The same Db, recording every statement the scan sends. */
const recording: Db = {
  label: 'recording',
  query: (sql, params) => {
    statements.push(sql);
    return db.query(sql, params);
  },
  exec: (sql) => {
    statements.push(sql);
    return db.exec(sql);
  },
  close: async () => {},
};

before(async () => {
  db = await pgliteDb();
  await migrate(db);
  const run = Number((await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
  // Clean rows.
  await db.query(`INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('other', 'clean synthetic', 'work', 'manual', 'zeusi:test/clean', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  // Rows ingested before 0011 (the wall did not know the one-n spelling): simulated with the wall trigger off.
  for (const t of ['notes', 'chunks', 'facts']) await db.exec(`ALTER TABLE zeusi.${t} DISABLE TRIGGER zeusi_90_wall`);
  const nid = Number((await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('Work/research/probe.md', 'Probe', 'synthetic exclusion probe: Plankiva', now(), 'work', 'vault_note', 'vault:Work/research/probe.md', now(), decode($1, 'hex'), $2)
     RETURNING id::int AS id`, [SHA, run])).rows[0]!.id);
  await db.query(`INSERT INTO zeusi.chunks (note_id, chunk_index, text, text_sha256, token_count, source_uri)
                  VALUES ($1, 0, 'synthetic P-l-a-n-k-k-i-v-a probe', decode($2, 'hex'), 3, 'vault:Work/research/probe.md#c0')`, [nid, SHA]);
  await db.query(`INSERT INTO zeusi.chunks (note_id, chunk_index, text, text_sha256, token_count, source_uri)
                  VALUES ($1, 1, 'clean synthetic', decode($2, 'hex'), 2, 'vault:Work/research/probe.md#c1')`, [nid, SHA]);
  await db.query(`INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('other', 'synthetic', 'client', 'manual', 'vault:ClientCo/PlАnkiva.md', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  for (const t of ['notes', 'chunks', 'facts']) await db.exec(`ALTER TABLE zeusi.${t} ENABLE TRIGGER zeusi_90_wall`);
  await db.query(`SELECT zeusi.quarantine_record('vault_note', 'vault:Work/research/Plankiva-sync.md', decode($1, 'hex'), NULL, $2, 'notes', NULL)`, ['ab'.repeat(32), run]);
});
after(async () => db.close());

async function as<T>(role: string, fn: () => Promise<T>): Promise<T> {
  await db.exec(`SET ROLE ${role}`);
  try {
    return await fn();
  } finally {
    await db.exec('RESET ROLE');
  }
}

test('exclusion-scan as the backup role: per-table counts of rows with an Plankiva signal; plain SELECT only; output is counts only', async () => {
  statements.length = 0;
  const r = await as('zeusi_mini_backup', () => exclusionScan(recording));
  const by = Object.fromEntries(r.tables.map((t) => [t.table, t]));
  assert.equal(by['notes']!.matching, 1);
  assert.equal(by['chunks']!.matching, 1, 'the chunk with the separated spelling; the clean chunk does not count');
  assert.equal(by['chunks']!.rows, 2);
  assert.equal(by['facts']!.matching, 1, 'the Cyrillic look-alike in source_uri');
  assert.equal(by['facts']!.rows, 2);
  assert.equal(by['quarantine']!.matching, 1, 'a quarantine uri carrying the name');
  for (const t of ['people', 'decisions', 'episodes', 'prs', 'pr_reviews', 'routine_runs', 'wall_allow', 'ingest_runs', 'backup_runs', 'embed_usage']) {
    assert.equal(by[t]!.matching, 0, t);
    assert.ok(by[t]!.readable, t);
  }
  for (const t of Object.keys(SCAN_EXCLUDED)) assert.equal(by[t], undefined, `${t} is not scanned (it holds the rule patterns / file names)`);
  assert.equal(r.total, 4);
  assert.equal(r.unreadable, 0);
  for (const s of statements) assert.match(s.trimStart(), /^(SELECT|WITH)\b/i, 'plain SELECT only');
  assert.ok(!statements.some((s) => /row_security|SET\s|INSERT|UPDATE|DELETE|TRUNCATE|ALTER|CREATE|DROP/i.test(s)));
  const out = formatExclusionScan(r);
  assert.match(out, /notes\s+rows 1\s+matching 1/);
  assert.match(out, /RESULT: 4 matching row\(s\)/);
  assert.doesNotMatch(out, /plankiva|probe|Work\/|ClientCo\/|synthetic|vault:/i, 'counts and table names only');
});

test('exclusion-scan after retraction: zero everywhere; a role without SELECT on a table reports it unreadable (never throws, never prints the error text)', async () => {
  await db.exec('BEGIN');
  try {
    // The documented retraction (docs/wall.md), run here on the synthetic rows only.
    await db.exec(`DELETE FROM zeusi.chunks c USING zeusi.notes n WHERE n.id = c.note_id AND n.source_uri = 'vault:Work/research/probe.md'`);
    await db.exec(`DELETE FROM zeusi.notes WHERE source_uri = 'vault:Work/research/probe.md'`);
    await db.exec(`DELETE FROM zeusi.facts WHERE source_uri = 'vault:ClientCo/PlАnkiva.md'`);
    await db.exec(`DELETE FROM zeusi.quarantine WHERE source_uri = 'vault:Work/research/Plankiva-sync.md'`);
    const r = await as('zeusi_mini_backup', () => exclusionScan(db));
    assert.equal(r.total, 0);
    assert.match(formatExclusionScan(r), /RESULT: 0 matching rows/);
    const ro = await as('zeusi_box_ro', () => exclusionScan(db));
    const q = ro.tables.find((t) => t.table === 'quarantine')!;
    assert.equal(q.readable, false);
    assert.ok(ro.unreadable > 0);
    assert.match(formatExclusionScan(ro), /quarantine\s+not readable by this role/);
  } finally {
    await db.exec('ROLLBACK');
  }
});

test('the retraction SQL documented in docs/wall.md removes every stored Plankiva row (notes, chunks, rows pointing into them, uri-only tables) and nothing else', async () => {
  const doc = readFileSync(fileURLToPath(new URL('../docs/wall.md', import.meta.url)), 'utf8');
  const m = /```sql\n(-- zeusi:retraction-0011[\s\S]*?)```/.exec(doc);
  assert.ok(m, 'retraction block present in docs/wall.md');
  const iso = await pgliteDb();
  try {
    await migrate(iso);
    const run = Number((await iso.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
    const note = async (path: string, body: string) => Number((await iso.query<{ id: number }>(
      `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1, 'T', $2, now(), 'work', 'vault_note', 'vault:' || $1, now(), decode($3, 'hex'), $4) RETURNING id::int AS id`, [path, body, SHA, run])).rows[0]!.id);
    const chunk = (nid: number, i: number, text: string, path: string) => iso.query(
      `INSERT INTO zeusi.chunks (note_id, chunk_index, text, text_sha256, token_count, source_uri) VALUES ($1, $2, $3, decode($4, 'hex'), 1, $5)`,
      [nid, i, text, SHA, `vault:${path}#c${i}`]);
    // Clean rows that must survive.
    const clean = await note('Work/clean.md', 'clean synthetic');
    await chunk(clean, 0, 'clean synthetic', 'Work/clean.md');
    await iso.query(`INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                     VALUES ('other', 'clean synthetic', 'work', 'manual', 'vault:Work/clean.md#x', now(), decode($1, 'hex'), $2)`, [SHA, run]);
    await iso.query(`SELECT zeusi.quarantine_record('vault_note', 'vault:Work/other.md', decode($1, 'hex'), NULL, $2, 'notes', NULL)`, ['ef'.repeat(32), run]);
    // Rows stored before 0011 knew the one-n spelling (simulated with the wall trigger off).
    for (const t of ['notes', 'chunks', 'facts']) await iso.exec(`ALTER TABLE zeusi.${t} DISABLE TRIGGER zeusi_90_wall`);
    const bad = await note('Work/research/sync.md', 'synthetic exclusion probe: Plankiva joined');
    await chunk(bad, 0, 'synthetic Plankiva probe', 'Work/research/sync.md');
    await chunk(bad, 1, 'clean part of the same note', 'Work/research/sync.md');
    await iso.query(`INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                     VALUES ('other', 'clean text, derived from the probe note', 'work', 'manual', 'vault:Work/research/sync.md#Notes', now(), decode($1, 'hex'), $2)`, [SHA, run]);
    await iso.query(`INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                     VALUES ('other', 'synthetic pl4nk1v@ probe', 'client', 'manual', 'zeusi:test/fact-probe', now(), decode($1, 'hex'), $2)`, [SHA, run]);
    for (const t of ['notes', 'chunks', 'facts']) await iso.exec(`ALTER TABLE zeusi.${t} ENABLE TRIGGER zeusi_90_wall`);
    await iso.query(`SELECT zeusi.quarantine_record('vault_note', 'vault:Work/research/PlАnkiva-weekly.md', decode($1, 'hex'), NULL, $2, 'notes', NULL)`, ['ab'.repeat(32), run]);
    await iso.query(`SELECT zeusi.quarantine_record('vault_note', 'vault:Work/research/%50lankiva-2.md', decode($1, 'hex'), NULL, $2, 'notes', NULL)`, ['ac'.repeat(32), run]);

    const before = await iso.query(`SELECT count(*)::int AS n FROM zeusi.wall_audit()`);
    assert.ok((before.rows[0] as { n: number }).n >= 3, 'the audit sees the stored rows');
    await iso.exec(m![1]!);

    const n = async (sql: string) => (await iso.query<{ n: number }>(sql)).rows[0]!.n;
    assert.equal(await n(`SELECT count(*)::int AS n FROM zeusi.notes`), 1, 'only the clean note is left');
    assert.equal(await n(`SELECT count(*)::int AS n FROM zeusi.chunks`), 1, 'the probe note chunks (also the clean one) are gone by cascade');
    assert.equal(await n(`SELECT count(*)::int AS n FROM zeusi.facts`), 1, 'the derived fact and the probe fact are gone; the clean fact stays');
    assert.equal(await n(`SELECT count(*)::int AS n FROM zeusi.quarantine`), 1, 'uri-only rows carrying the name are gone; the other stays');
    assert.equal(await n(`SELECT count(*)::int AS n FROM zeusi.wall_audit()`), 0);
    await iso.exec('SET ROLE zeusi_mini_backup');
    try {
      assert.equal((await exclusionScan(iso)).total, 0);
    } finally {
      await iso.exec('RESET ROLE');
    }
  } finally {
    await iso.close();
  }
});
