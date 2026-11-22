// Session-start gaps U6 (docs/plans/2026-11-18-session-start-gaps-plan.md; docs/hq-sync.md
// "Typed Focus block"): the Focus block the HQ floor sync must emit (the step 8b memory header,
// Type: focus + Subject) runs the whole nightly path (staging -> export-filter -> importVault
// (HQ_PROFILE) -> extractHqStructured) into facts kind state and shows in zeusi_startup focus,
// newest per (scope, subject). Fixture files only (test/fixtures/hq-focus-block/); no live HQ
// data, no network, PGlite as zeusi_mini_ingest / zeusi_box_ro.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
import { runExportFilter } from '../src/hq-export.ts';
import { HQ_PROFILE, importVault, splitNote } from '../src/importers/vault.ts';
import { extractHqStructured } from '../src/importers/hq-structured.ts';
import { parseEntry } from '../src/importers/structured.ts';
import { createMcpState, createZeusiMcpServer, FOCUS_READ_FACTOR, STARTUP_CAPS, type McpDeps } from '../src/mcp-server.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const FIX = fileURLToPath(new URL('./fixtures/hq-focus-block/team/', import.meta.url));
const DAY1 = '2026-11-16-memory.md';
const DAY2 = '2026-11-17-memory.md';
const SHA = 'ef'.repeat(32);
const FAKE_HOST = ['ep-fake-999', '-pooler.eu-central-1.aws.neon.tech'].join('');

function asRole(db: Db, role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

test('Focus block fixture: the step 8b grammar (Type: focus + Subject) parses into focus records; the unheaded delta does not', () => {
  const lines = (s: string) => s.split('\n');
  const body = splitNote(readFileSync(join(FIX, DAY2), 'utf8')).body;
  const entries = body.split(/\n(?=## )/).map((e) => e.trim()).filter((e) => e.startsWith('## '));
  assert.equal(entries.length, 3);
  const parsed = entries.map((e) => parseEntry(lines(e), new Date('2026-11-18T00:00:00Z')));
  assert.equal(parsed.filter((p) => 'record' in p).length, 2, 'two headed focus entries');
  assert.match(JSON.stringify(parsed), /synthetic-q4-numbat/);
  assert.match(JSON.stringify(parsed), /synthetic-wombat-launch/);
  assert.equal(parsed.filter((p) => !('record' in p)).length, 1, 'the unheaded delta is not a record');
});

test('Focus block end to end: export-filter -> ingest hq-sync -> facts state -> zeusi_startup focus, newest per subject, older same-subject counted', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-focus-block-'));
  const staging = join(dir, 'staging');
  const source = join(dir, 'zeus-hq');
  mkdirSync(join(staging, 'team'), { recursive: true });
  mkdirSync(join(source, 'team'), { recursive: true });
  const db = await pgliteDb();
  try {
    await migrate(db);
    const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                    VALUES ('synthetic-owner', 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/synthetic-owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
    const cfg = validateSources(parseToml(`[[source]]\nname = "hq-team"\nkind = "zeus_memory"\nscope = "work"\nroot = "${source}"\ninclude = ["team/*.md"]\nproject = "team"\n`), seedWall(), { home: dir });
    for (const f of [DAY1, DAY2]) copyFileSync(join(FIX, f), join(staging, 'team', f));
    const filtered = runExportFilter({ inDir: staging, outDir: source, projects: ['team'] });
    assert.equal(filtered.status, 'ok', filtered.error ?? '');
    await db.exec('SET ROLE zeusi_mini_ingest');
    let s;
    try {
      const notes = await importVault({ db, config: cfg, mode: 'full', home: dir, profile: HQ_PROFILE, logPaths: false });
      assert.equal(notes.status, 'ok', notes.error ?? '');
      s = await extractHqStructured(db, { mode: notes.mode, host: 'testhost' });
    } finally {
      await db.exec('RESET ROLE');
    }
    assert.equal(s.write.focus_inserted, 3, 'day 1 + two day-2 focus entries become facts kind state');
    assert.equal(s.write.rules_inserted, 0);
    const rows = (await db.query<{ subject: string; text: string; scope: string; source_kind: string }>(
      `SELECT subject, text, scope::text AS scope, source_kind::text AS source_kind FROM zeusi.facts WHERE kind = 'state' ORDER BY source_ts`)).rows;
    assert.deepEqual(rows.map((r) => [r.subject, r.scope, r.source_kind]), [
      ['synthetic-q4-numbat', 'work', 'zeus_memory'], ['synthetic-q4-numbat', 'work', 'zeus_memory'], ['synthetic-wombat-launch', 'work', 'zeus_memory'],
    ]);

    writeFileSync(join(dir, '.pg_service.conf'), `[zeusi_ro]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
    const deps: McpDeps = {
      env: { HOME: dir }, home: dir, readService: 'zeusi_ro', connectRead: asRole(db, 'zeusi_box_ro'), embeddings: () => null,
      feedbackPath: join(dir, '.zeusi', 'f.jsonl'), queryLedgerPath: join(dir, '.zeusi', 'q.json'),
    };
    const server = createZeusiMcpServer(deps, createMcpState());
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test', version: '0' });
    await Promise.all([server.connect(a), client.connect(b)]);
    try {
      const r = (await client.callTool({ name: 'zeusi_startup', arguments: {} })) as { isError?: boolean; content: Array<{ text?: string }> };
      assert.ok(!r.isError);
      const j = JSON.parse(r.content.map((c) => c.text ?? '').join('')) as { focus: Array<{ subject: string; text: string; source_uri: string }>; focus_older_same_subject?: number; focus_message?: string };
      assert.deepEqual(j.focus.map((f) => [f.subject, f.text]), [
        ['synthetic-wombat-launch', 'SYNTHETIC focus: prepare the wombat launch checklist'],
        ['synthetic-q4-numbat', 'SYNTHETIC focus (updated): ship the numbat importer, then the quokka review'],
      ], 'newest first, one per subject');
      assert.equal(j.focus_older_same_subject, 1, 'the day-1 numbat focus is counted, not served as current');
      assert.ok(!('focus_message' in j));
      for (const f of j.focus) assert.match(f.source_uri, /^hq:team\/entry\/[0-9a-f]{16}$/);
      assert.ok(!JSON.stringify(j).includes('without a header block'), 'free text never becomes focus');
    } finally {
      await client.close();
      await server.close();
    }
  } finally {
    await db.close();
    rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(FOCUS_READ_FACTOR * STARTUP_CAPS.focus, 200);
});
