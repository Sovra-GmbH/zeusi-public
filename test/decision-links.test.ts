// Migration 0013 decision_links (DESIGN, NOT applied on Neon) and its writers / readers, on PGlite
// only. No network, no Neon, no OpenAI, no live MCP (SDK Client over InMemoryTransport).
// lanes DIG-startup-links.md D2 tests 15-17; plan addendum "0013 decision links" (L1-L4).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { listMigrations, migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { createZeusiMcpServer, createMcpState, type McpDeps } from '../src/mcp-server.ts';
import { wallAudit } from '../src/wall-admin.ts';
import {
  fetchDecisionLinks, insertDecisionLinks, LINK_TARGET_KINDS, linkTargetKind, linkWallVerdict, MAX_LINKS, serveWithLinks, type LinkTargetKind,
} from '../src/decision-links.ts';
import { searchDecisions } from '../src/search.ts';
import { parseStructuredBody, recordSha256, writeStructured, type DecisionRecord } from '../src/importers/structured.ts';
import { loadWall, seedWall } from '../src/wall.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

// Synthetic strings assembled at runtime (never real content or secrets).
const WALLED = ['Plan', 'kiva synthetic wall probe'].join('');
const SECRETISH = ['pass', 'word=', 'hunter2hunter2xyz'].join('');
const FAKE_HOST = ['ep-fake-333', '-pooler.eu-central-1.aws.neon.tech'].join('');
const SHA = 'cd'.repeat(32);
const MIG = '0013_decision_links.sql';
const WORK_SCOPE_ONLY = 'zeusi_test_links_work_only';

let db: Db;
let home: string;
let run: number;
const ids: Record<string, number> = {};

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? 'unknown';
  }
}

async function as<T>(d: Db, role: string, fn: () => Promise<T>): Promise<T> {
  await d.exec(`SET ROLE ${role}`);
  try {
    return await fn();
  } finally {
    await d.exec('RESET ROLE');
  }
}

/** A Db over the shared PGlite that runs as `role` (MCP seams). */
function asRole(role: string, log?: string[]): (service: string) => Promise<Db> {
  return async (service: string) => {
    log?.push(`${service}:${role}`);
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

function subsetDir(keep: (name: string) => boolean): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-mig13-'));
  for (const f of listMigrations()) if (keep(f.name)) copyFileSync(join(MIGRATIONS_DIR, f.name), join(dir, f.name));
  return dir;
}

const insLink = (d: Db, decisionId: number, kind: string, uri: string, over: { scope?: string; source?: string } = {}) => d.query(
  `INSERT INTO zeusi.decision_links (decision_id, target_kind, target_uri, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
   VALUES ($1, $2::zeusi.link_target_kind, $3, $4::zeusi.scope, 'agent_write', $5, now(), decode($6, 'hex'), $7)`,
  [decisionId, kind, uri, over.scope ?? 'work', over.source ?? 'hq:links-src', SHA, run]);

async function decision(key: string, words: string, scope = 'work', uri = `hq:links-${key}`): Promise<number> {
  const id = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner-13'), now() - interval '1 day', 'minute', $1, true, '{zeusi}', $2::zeusi.scope, 'manual', $3, now() - interval '1 day', sha256(convert_to($3, 'UTF8')), $4)
     RETURNING id::int AS id`, [words, scope, uri, run])).rows[0]!.id;
  ids[key] = id;
  return id;
}

const note = (path: string, title: string, scope: string, body: string) => db.query(
  `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
   VALUES ($1, $2, $3, now(), $4::zeusi.scope, 'vault_note', 'vault:' || $1, now(), sha256(convert_to($3, 'UTF8')), $5)`, [path, title, body, scope, run]);

function serviceFile(dir: string, sections: Record<string, string>): void {
  const body = Object.entries(sections).map(([name, user]) =>
    `[${name}]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`).join('\n');
  writeFileSync(join(dir, '.pg_service.conf'), body);
}

type CallResult = { isError?: boolean; content: Array<{ type: string; text?: string }> };
interface Harness { client: Client; close: () => Promise<void> }

async function connect(over: Partial<McpDeps> = {}): Promise<Harness> {
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro', connectRead: asRole('zeusi_box_ro'), connectWrite: asRole('zeusi_box_decision'),
    embeddings: () => null, feedbackPath: join(home, '.zeusi', 'fb.jsonl'), queryLedgerPath: join(home, '.zeusi', 'ql.json'), ...over,
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, close: async () => { await client.close(); await server.close(); } };
}
const call = async (h: Harness, name: string, args: Record<string, unknown>) => (await h.client.callTool({ name, arguments: args })) as CallResult;
const textOf = (r: CallResult) => r.content.map((c) => c.text ?? '').join('\n');
const jsonOf = (r: CallResult) => JSON.parse(textOf(r)) as Record<string, unknown>;

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-links-'));
  serviceFile(home, { zeusi_ro: 'zeusi_box_ro', zeusi_rw: 'zeusi_box_rw', zeusi_decision: 'zeusi_box_decision' });
  db = await pgliteDb();
  await migrate(db);
  run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('owner-13', 'Owner', 'human', 'work', 'work', 'manual', 'manual:people/owner-13', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  await decision('base', 'SYNTHETIC base decision for link grants');
  await decision('tape', 'SYNTHETIC northbank decision', 'product');
  await decision('personal', 'SYNTHETIC personal decision', 'personal');
  // Read fixtures: one decision with a visible note, an RLS-hidden note, a PR, a job and a walled link.
  await note('Work/products/zeusi/spec-links.md', 'Synthetic links spec', 'work', 'SYNTHETIC BODY never served');
  await note('Northbank/spec-hidden.md', 'Synthetic northbank spec', 'product', 'SYNTHETIC hidden body');
  const rd = await decision('read', 'SYNTHETIC zebra linked decision');
  await insLink(db, rd, 'note', 'vault:Work/products/zeusi/spec-links.md#Locks');
  await insLink(db, rd, 'note', 'vault:Northbank/spec-hidden.md');
  await insLink(db, rd, 'pr', 'gh:Synthetic-Org/zeusi#11');
  await insLink(db, rd, 'job', 'job:nightly-ingest');
  await db.exec('ALTER TABLE zeusi.decision_links DISABLE TRIGGER zeusi_90_wall');
  await insLink(db, rd, 'note', `vault:Work/${WALLED}.md`); // predates a rule: the serve guard must drop it
  await db.exec('ALTER TABLE zeusi.decision_links ENABLE TRIGGER zeusi_90_wall');
  // A TEST-ONLY reader limited to scope team (production readers are not narrowed).
  await db.exec(`CREATE ROLE ${WORK_SCOPE_ONLY} NOLOGIN;
    GRANT USAGE ON SCHEMA zeusi TO ${WORK_SCOPE_ONLY};
    GRANT SELECT ON zeusi.decisions, zeusi.decisions_current, zeusi.people, zeusi.notes, zeusi.chunks, zeusi.decision_links TO ${WORK_SCOPE_ONLY};
    CREATE POLICY test_work_only ON zeusi.decisions FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY test_work_only ON zeusi.people FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY test_work_only ON zeusi.notes FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY test_work_only ON zeusi.decision_links FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');`);
});
after(async () => db.close());

// ---------------------------------------------------------------------------
// Schema and grants (test 15)

test('0013: the file is additive and design-only (no password, no host, says NOT APPLIED; replaces no existing function)', () => {
  const sql = readFileSync(join(MIGRATIONS_DIR, MIG), 'utf8');
  assert.match(sql, /NOT APPLIED/);
  assert.doesNotMatch(sql, /PASSWORD|neon\.tech|postgres:\/\//i);
  assert.doesNotMatch(sql, /CREATE OR REPLACE|ALTER TABLE zeusi\.(?!decision_links)|DROP |UPDATE zeusi\.|DELETE FROM/i);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION zeusi\.supersede_fact/i, '0013-a stays out');
});

test('0013 grant matrix: readers SELECT only; zeusi_ingest and zeusi_decision_write INSERT only; nobody UPDATE / DELETE / TRUNCATE', async () => {
  const priv = (role: string, p: string) => db.query<{ x: boolean }>(`SELECT has_table_privilege($1, 'zeusi.decision_links', $2) AS x`, [role, p]).then((q) => q.rows[0]!.x);
  for (const role of ['zeusi_read', 'zeusi_box_ro', 'zeusi_cloud_ro', 'zeusi_backup', 'zeusi_mini_backup', 'zeusi_box_rw', 'zeusi_mini_ingest', 'zeusi_box_decision']) {
    assert.equal(await priv(role, 'SELECT'), true, `${role} SELECT`);
    assert.equal(await priv(role, 'UPDATE'), false, `${role} no UPDATE`);
    assert.equal(await priv(role, 'DELETE'), false, `${role} no DELETE`);
    assert.equal(await priv(role, 'TRUNCATE'), false, `${role} no TRUNCATE`);
  }
  for (const role of ['zeusi_read', 'zeusi_box_ro', 'zeusi_cloud_ro', 'zeusi_backup', 'zeusi_mini_backup', 'zeusi_agent_write', 'zeusi_box_rw']) {
    assert.equal(await priv(role, 'INSERT'), false, `${role} no INSERT`);
  }
  for (const role of ['zeusi_ingest', 'zeusi_mini_ingest', 'zeusi_decision_write', 'zeusi_box_decision']) assert.equal(await priv(role, 'INSERT'), true, `${role} INSERT`);
  assert.equal((await db.query<{ x: boolean }>(`SELECT has_table_privilege('public', 'zeusi.decision_links', 'SELECT, INSERT, UPDATE, DELETE') AS x`)).rows[0]!.x, false);
  for (const fn of ['zeusi.decision_link_wall_check()', 'zeusi.decision_links_inherit()', 'zeusi.decision_links_wall_audit()']) {
    assert.equal((await db.query<{ x: boolean }>(`SELECT has_function_privilege('public', $1, 'EXECUTE') AS x`, [fn])).rows[0]!.x, false, fn);
  }
  // live: the writers insert and cannot change or remove; readers cannot insert
  for (const role of ['zeusi_box_decision', 'zeusi_mini_ingest']) {
    await as(db, role, async () => {
      assert.equal(await code(insLink(db, ids['base']!, 'pr', `gh:Synthetic-Org/grants#${role.length}`)), 'ok', role);
      assert.equal(await code(db.query(`UPDATE zeusi.decision_links SET target_uri = 'job:changed'`)), '42501', role);
      assert.equal(await code(db.query(`DELETE FROM zeusi.decision_links`)), '42501', role);
      assert.equal(await code(db.exec(`ALTER TABLE zeusi.decision_links DISABLE TRIGGER zeusi_90_wall`)), '42501', role);
    });
  }
  for (const role of ['zeusi_box_ro', 'zeusi_cloud_ro', 'zeusi_box_rw']) {
    await as(db, role, async () => assert.equal(await code(insLink(db, ids['base']!, 'job', 'job:reader-try')), '42501', role));
  }
});

test('0013 RLS: readers never see personal links; writers cannot write a personal link; the unique key holds', async () => {
  await insLink(db, ids['personal']!, 'job', 'job:personal-probe', { scope: 'personal' }); // owner: RLS bypassed
  for (const role of ['zeusi_box_ro', 'zeusi_cloud_ro', 'zeusi_box_decision', 'zeusi_mini_ingest']) {
    await as(db, role, async () => {
      assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decision_links WHERE scope = 'personal'`)).rows[0]!.n, 0, role);
      assert.ok((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decision_links`)).rows[0]!.n > 0, role);
    });
  }
  for (const role of ['zeusi_box_decision', 'zeusi_mini_ingest']) {
    await as(db, role, async () => assert.equal(await code(insLink(db, ids['personal']!, 'job', 'job:personal-write', { scope: 'personal' })), '42501', role));
  }
  await as(db, 'zeusi_mini_backup', async () => {
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decision_links WHERE scope = 'personal'`)).rows[0]!.n, 1);
  });
  assert.equal(await code(insLink(db, ids['read']!, 'pr', 'gh:Synthetic-Org/zeusi#11')), '23505', 'UNIQUE (decision_id, target_uri)');
});

test('0013: a bad scheme or a kind / uri mismatch is refused by the CHECK; scope must equal the decision\'s', async () => {
  const bad: Array<[string, string]> = [
    ['note', 'https://example.com/x'], ['uri', 'https://example.com/x'], ['note', 'javascript:alert(1)'], ['note', 'file:///etc/hosts'],
    ['pr', 'gh:Synthetic-Org/zeusi'], ['repo', 'gh:Synthetic-Org/zeusi#3'], ['pr', 'gh:Synthetic-Org/zeusi#0'], ['note', 'gh:Synthetic-Org/zeusi#3'],
    ['job', 'job:has space'], ['note', 'vault:Work/x\n.md'], ['note', 'vault:Work/x\t.md'], ['note', 'vault:Work/../etc.md'],
    ['note', 'vault:./x.md'], ['note', 'vault:/abs.md'], ['note', 'vault: lead.md'], ['note', `vault:${'a'.repeat(500)}`], ['uri', 'lane:'],
    ['job', 'job:'], ['note', 'VAULT:Work/x.md'], ['note', 'notes:Work/x.md'],
  ];
  for (const [kind, uri] of bad) {
    assert.equal(await code(insLink(db, ids['base']!, kind, uri)), '23514', `${kind} ${JSON.stringify(uri)}`);
  }
  assert.equal(await code(insLink(db, ids['base']!, 'job', 'job:scope-mismatch', { scope: 'product' })), '23514', 'scope mismatch');
  assert.equal(await code(insLink(db, ids['tape']!, 'job', 'job:scope-mismatch', { scope: 'work' })), '23514', 'scope mismatch (other way)');
  assert.equal(await code(insLink(db, ids['tape']!, 'job', 'job:scope-match', { scope: 'product' })), 'ok');
  assert.equal(await code(insLink(db, 999_999, 'job', 'job:no-parent')), '23503', 'FK');
});

test('0013: src/decision-links.ts linkTargetKind mirrors the SQL CHECK (accepted with exactly its kind; refused by both)', async () => {
  const corpus = [
    'gh:Synthetic-Org/zeusi#11', 'gh:Synthetic-Org/zeusi', 'gh:a/b#999999999', 'vault:Work/products/x y.md', 'vault:Work/x.md#Heading two',
    'hq:zeusi/2026-11-16-decisions.md', 'import:proj/entry/abc', 'job:nightly-ingest', 'job:ccr:zeusi/hq-sync', 'lane:zeusi-v2-prime',
    'https://example.com', 'gh:a/b#0', 'gh:a/b#1234567890', 'vault:Work/../x', 'vault:x.md#', 'vault:x.md ', 'lane:a b', 'job:-x',
    'hq:a#b#c', 'vault:Work/x\u0000.md', 'gh:a b/c',
    // security review M1: astral characters count as ONE character on both sides
    'hq:\u{1F600}', 'vault:\u{1F600}', 'vault:\u{1F600}\u{1F600}', 'hq:a\u{1F600}', 'vault:Work/\u{1F600}x.md', `job:${'a'.repeat(199)}`,
    `vault:${'\u{1F600}'.repeat(494)}`, `vault:${'\u{1F600}'.repeat(495)}`,
  ];
  let n = 0;
  for (const uri of corpus) {
    const ts = linkTargetKind(uri);
    for (const kind of LINK_TARGET_KINDS) {
      const sqlOk = (await code(insLink(db, ids['base']!, kind, uri))) === 'ok';
      if (sqlOk) await db.query(`DELETE FROM zeusi.decision_links WHERE decision_id = $1 AND target_uri = $2`, [ids['base'], uri]);
      assert.equal(sqlOk, ts === kind, `${JSON.stringify(uri)} as ${kind}: sql ${sqlOk}, ts ${ts}`);
      n++;
    }
  }
  assert.equal(n, corpus.length * LINK_TARGET_KINDS.length);
  // TypeScript is stricter than SQL on Unicode whitespace / format characters (refused before any query).
  for (const u of ['vault:Work/x y.md', 'vault:Work/x​y.md', 'job:a b']) assert.equal(linkTargetKind(u), null, JSON.stringify(u));
});

// ---------------------------------------------------------------------------
// Wall (test 16)

test('0013 wall: zeusi_90_wall rejects a walled target (path rule and content rule) and a walled link source; nothing stored', async () => {
  const before = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decision_links`)).rows[0]!.n;
  for (const role of ['zeusi_box_decision', 'zeusi_mini_ingest']) {
    await as(db, role, async () => {
      assert.equal(await code(insLink(db, ids['base']!, 'note', 'vault:plankiva/notes.md')), 'ZW001', `${role}: hard path rule on the target`);
      assert.equal(await code(insLink(db, ids['base']!, 'note', `vault:Work/${WALLED}.md`)), 'ZW001', `${role}: content rule on the target`);
      assert.equal(await code(insLink(db, ids['base']!, 'job', 'job:clean-target', { source: 'vault:plankiva/src.md' })), 'ZW001', `${role}: walled source`);
    });
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decision_links`)).rows[0]!.n, before);
  // the error carries the uri and hash only, never the text
  try {
    await insLink(db, ids['base']!, 'note', `vault:Work/${WALLED}.md`);
    assert.fail('expected ZW001');
  } catch (e) {
    const err = e as { code?: string; message: string; detail?: string };
    assert.equal(err.code, 'ZW001');
    assert.ok(!`${err.message} ${err.detail ?? ''}`.includes(WALLED), 'no walled text in the error');
  }
  // the TypeScript pre-check gives the same verdicts (src/wall.ts parity)
  const wall = await loadWall(db);
  assert.equal(linkWallVerdict(wall, 'hq:links-src', 'vault:plankiva/notes.md').blocked, true);
  assert.equal(linkWallVerdict(wall, 'hq:links-src', `vault:Work/${WALLED}.md`).blocked, true);
  assert.equal(linkWallVerdict(wall, 'vault:plankiva/src.md', 'job:clean-target').blocked, true);
  assert.equal(linkWallVerdict(wall, 'hq:links-src', 'job:clean-target').blocked, false);
  assert.equal(linkWallVerdict(seedWall(), 'hq:links-src', 'gh:Synthetic-Org/zeusi#11').blocked, false);
});

test('0013 audit (security review M2): a link stored before a rule existed is reported by wallAudit (wall_audit + decision_links_wall_audit); no text', async () => {
  const before = (await wallAudit(db)).filter((r) => r.table_name === 'decision_links');
  assert.equal(before.length, 1, 'the fixture link that bypassed the trigger is already reported');
  assert.equal(before[0]!.row_ref, String((await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.decision_links WHERE target_uri LIKE 'vault:Work/Plan%'`)).rows[0]!.id));
  await insLink(db, ids['base']!, 'job', 'job:audit-probe-13');
  const rule = (await db.query<{ id: number }>(`INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason) VALUES ('term', true, 'audit-probe-13', 'test') RETURNING id`)).rows[0]!.id;
  try {
    const rows = (await wallAudit(db)).filter((r) => r.table_name === 'decision_links');
    assert.equal(rows.length, 2);
    assert.ok(rows.some((r) => r.problem === `hard rule ${rule} (term)`));
    assert.ok(rows.every((r) => !JSON.stringify(r).includes(WALLED) && !JSON.stringify(r).includes('audit-probe-13')), 'no target text');
    // the ingest and backup logins may run it; readers may not
    for (const [role, ok] of [['zeusi_mini_ingest', true], ['zeusi_mini_backup', true], ['zeusi_box_ro', false], ['zeusi_box_decision', false]] as const) {
      const x = (await db.query<{ x: boolean }>(`SELECT has_function_privilege($1, 'zeusi.decision_links_wall_audit()', 'EXECUTE') AS x`, [role])).rows[0]!.x;
      assert.equal(x, ok, role);
    }
    const asIngest = await as(db, 'zeusi_mini_ingest', () => wallAudit(db));
    assert.equal(asIngest.filter((r) => r.table_name === 'decision_links').length, 2);
  } finally {
    await db.query(`DELETE FROM zeusi.decision_links WHERE target_uri = 'job:audit-probe-13'`);
    await db.query(`DELETE FROM zeusi.wall_denylist WHERE id = $1`, [rule]);
  }
});

test('0013 writer (security review M1 / L3): a CHECK refusal (scope mismatch, shape) is counted invalid, never thrown; other links still land', async () => {
  // a team-scoped link onto the northbank decision: the inherit trigger refuses it (23514)
  const c = await as(db, 'zeusi_mini_ingest', () => insertDecisionLinks(db, {
    decisionId: ids['tape']!, scope: 'work', sourceKind: 'manual', sourceUri: 'hq:links-l3', sourceTs: '2026-11-16T10:00:00Z', runId: run,
    targets: ['job:l3-probe'],
  }));
  assert.deepEqual(c, { inserted: 0, deduped: 0, quarantined: 0, invalid: 1 });
  const ok = await as(db, 'zeusi_mini_ingest', () => insertDecisionLinks(db, {
    decisionId: ids['tape']!, scope: 'product', sourceKind: 'manual', sourceUri: 'hq:links-l3', sourceTs: '2026-11-16T10:00:00Z', runId: run,
    targets: ['job:l3-probe', 'job:l3-probe-2'],
  }));
  assert.deepEqual(ok, { inserted: 2, deduped: 0, quarantined: 0, invalid: 0 });
});

// ---------------------------------------------------------------------------
// Write path (test 17): zeusi_log_decision with links

const args = (over: Record<string, unknown> = {}) => ({
  kind: 'go', who: 'owner-13', said_at: '2026-11-16T10:00:00Z', exact_words: 'SYNTHETIC GO with links', exact_words_verbatim: true,
  scope: 'work', source_uri: 'hq:links-log-1', source_ts: '2026-11-16T10:00:00Z', ...over,
});

test('log_decision links: zeusi_box_decision inserts the decision and its typed links in one run (kinds derived, scope / source / run inherited)', async () => {
  const h = await connect({ writeService: 'zeusi_decision' });
  try {
    const links = ['gh:Synthetic-Org/zeusi#11', 'vault:Work/products/zeusi/spec-links.md', 'gh:Synthetic-Org/zeusi', 'job:nightly-ingest', 'lane:zeusi-v2-prime', 'gh:Synthetic-Org/zeusi#11'];
    const r = await call(h, 'zeusi_log_decision', args({ links }));
    assert.ok(!r.isError, textOf(r));
    const j = jsonOf(r) as { status: string; id: number; ingest_run_id: number; links: Record<string, number> };
    assert.equal(j.status, 'inserted');
    assert.deepEqual(j.links, { inserted: 5, already_linked: 0, withheld: 0, invalid: 0 }, 'a duplicate target is written once');
    assert.ok(!textOf(r).includes('SYNTHETIC GO with links'), 'never echoes the words');
    const rows = (await db.query<{ k: string; u: string; scope: string; src: string; run: number; by: string }>(
      `SELECT target_kind::text AS k, target_uri AS u, scope::text AS scope, source_uri AS src, ingest_run_id::int AS run, ingested_by AS by
       FROM zeusi.decision_links WHERE decision_id = $1 ORDER BY id`, [j.id])).rows;
    assert.deepEqual(rows.map((x) => [x.k, x.u]), [
      ['pr', 'gh:Synthetic-Org/zeusi#11'], ['note', 'vault:Work/products/zeusi/spec-links.md'], ['repo', 'gh:Synthetic-Org/zeusi'],
      ['job', 'job:nightly-ingest'], ['uri', 'lane:zeusi-v2-prime'],
    ]);
    for (const x of rows) assert.deepEqual([x.scope, x.src, x.run], ['work', 'hq:links-log-1', j.ingest_run_id]);
    const counts = (await db.query<{ c: Record<string, number> }>(`SELECT counts AS c FROM zeusi.ingest_runs WHERE id = $1`, [j.ingest_run_id])).rows[0]!.c;
    assert.deepEqual(counts, { inserted: 1, links_inserted: 5, links_deduped: 0, links_quarantined: 0, links_invalid: 0 });
  } finally {
    await h.close();
  }
});

test('log_decision links: a link the DB wall rejects is quarantined by uri + hash and counted; the decision and the clean links stay', async () => {
  // A DB-only soft rule the connector's input wall does not know: only the trigger can catch it.
  const rule = (await db.query<{ id: number }>(`INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason) VALUES ('term', false, 'zeusi-link-probe', 'test') RETURNING id`)).rows[0]!.id;
  const h = await connect({ writeService: 'zeusi_decision' });
  try {
    const r = await call(h, 'zeusi_log_decision', args({ source_uri: 'hq:links-log-wall', links: ['job:zeusi-link-probe', 'gh:Synthetic-Org/zeusi#12'] }));
    assert.ok(!r.isError, textOf(r));
    const j = jsonOf(r) as { id: number; links: Record<string, number> };
    assert.deepEqual(j.links, { inserted: 1, already_linked: 0, withheld: 1, invalid: 0 });
    assert.deepEqual((await db.query<{ u: string }>(`SELECT target_uri AS u FROM zeusi.decision_links WHERE decision_id = $1`, [j.id])).rows.map((x) => x.u), ['gh:Synthetic-Org/zeusi#12']);
    const q = (await db.query<{ t: string; r: number }>(`SELECT target_table AS t, rule_id AS r FROM zeusi.quarantine WHERE source_uri = 'hq:links-log-wall'`)).rows;
    assert.deepEqual(q, [{ t: 'decision_links', r: rule }]);
  } finally {
    await h.close();
    await db.query(`DELETE FROM zeusi.wall_denylist WHERE id = $1`, [rule]);
  }
});

test('log_decision links: bad scheme, too many, walled or credential-like links are refused BEFORE connecting and never echoed', async () => {
  const log: string[] = [];
  const h = await connect({ writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', log) });
  try {
    const cases: unknown[] = [
      ['https://example.com/x'], ['gh:Synthetic-Org/zeusi#0'], ['vault:Work/../x.md'], 'gh:Synthetic-Org/zeusi#1',
      Array.from({ length: MAX_LINKS + 1 }, (_, i) => `job:j${i}`), [`vault:Work/${WALLED}.md`], [`job:${SECRETISH.replace('=', '-')}`, `vault:Work/${SECRETISH}.md`],
      [`vault:${FAKE_HOST}/x.md`], [{ uri: 'gh:Synthetic-Org/zeusi#1' }],
    ];
    for (const links of cases) {
      const r = await call(h, 'zeusi_log_decision', args({ source_uri: 'hq:links-refused', links }));
      assert.equal(r.isError, true, JSON.stringify(links).slice(0, 80));
      for (const s of [WALLED, SECRETISH, FAKE_HOST, 'example.com']) assert.ok(!textOf(r).includes(s), `not echoed: ${s}`);
    }
    assert.deepEqual(log, [], 'nothing connected');
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:links-refused'`)).rows[0]!.n, 0);
  } finally {
    await h.close();
  }
});

test('log_decision links: the transitional zeusi_box_rw (no INSERT on decision_links) is refused before any INSERT; without links it still writes', async () => {
  const h = await connect({ writeService: 'zeusi_rw', connectWrite: asRole('zeusi_box_rw') });
  try {
    const r = await call(h, 'zeusi_log_decision', args({ source_uri: 'hq:links-rw', links: ['gh:Synthetic-Org/zeusi#11'] }));
    assert.equal(r.isError, true);
    assert.match(textOf(r), /links need migration 0013/);
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:links-rw'`)).rows[0]!.n, 0, 'nothing written');
    const ok = await call(h, 'zeusi_log_decision', args({ source_uri: 'hq:links-rw' }));
    assert.ok(!ok.isError, textOf(ok));
    assert.equal((jsonOf(ok) as { links?: unknown }).links, undefined);
  } finally {
    await h.close();
  }
});

test('log_decision links: a read class (hosted read bearer / OAuth zeusi.read) has no write path even with a write service configured', async () => {
  const log: string[] = [];
  const h = await connect({ toolClass: 'read', writeService: 'zeusi_decision', connectWrite: asRole('zeusi_box_decision', log) });
  try {
    const { tools } = await h.client.listTools();
    assert.ok(!tools.some((t) => /log_decision/.test(t.name)), 'not listed');
    for (const name of ['zeusi_log_decision', 'log_decision']) {
      const r = await call(h, name, args({ source_uri: 'hq:links-read-class', links: ['gh:Synthetic-Org/zeusi#11'] }));
      assert.equal(r.isError, true, name);
    }
    assert.deepEqual(log, []);
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE source_uri = 'hq:links-read-class'`)).rows[0]!.n, 0);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Read paths (test 17)

type Link = { target_kind: LinkTargetKind; target_uri: string; resolved: boolean; title?: string };
const EXPECTED_READ: Link[] = [
  { target_kind: 'note', target_uri: 'vault:Work/products/zeusi/spec-links.md#Locks', resolved: true, title: 'Synthetic links spec' },
  { target_kind: 'note', target_uri: 'vault:Northbank/spec-hidden.md', resolved: true, title: 'Synthetic northbank spec' },
  { target_kind: 'pr', target_uri: 'gh:Synthetic-Org/zeusi#11', resolved: false },
  { target_kind: 'job', target_uri: 'job:nightly-ingest', resolved: false },
];

test('read paths: search, startup and context_for_task return links (note titles resolved, PR unresolved, never a body); the walled link is withheld and counted', async () => {
  const h = await connect();
  try {
    const s = jsonOf(await call(h, 'zeusi_search', { query: 'zebra' }));
    const sd = (s['decisions'] as Array<{ links: Link[] }>);
    assert.equal(sd.length, 1);
    assert.deepEqual(sd[0]!.links, EXPECTED_READ);
    assert.equal(s['withheld'], 1, 'search: the walled link counted');
    const st = jsonOf(await call(h, 'zeusi_startup', {}));
    const zd = (st['decisions'] as Array<{ exact_words: string; links: Link[] }>).find((d) => d.exact_words.includes('zebra'))!;
    assert.deepEqual(zd.links, EXPECTED_READ);
    assert.ok((st['withheld'] as number) >= 1);
    const c = jsonOf(await call(h, 'zeusi_context_for_task', { task: 'zebra decision follow-up' }));
    const cd = (c['items'] as Array<{ exact_words: string; links: Link[] }>).find((d) => d.exact_words.includes('zebra'))!;
    assert.deepEqual(cd.links, EXPECTED_READ);
    assert.equal(c['withheld'], 1, 'context: the walled link counted');
    for (const body of [JSON.stringify(s), JSON.stringify(st), JSON.stringify(c)]) {
      assert.ok(!body.includes(WALLED), 'walled target never served');
      assert.ok(!body.includes('SYNTHETIC BODY') && !body.includes('SYNTHETIC hidden body'), 'never a note body');
    }
  } finally {
    await h.close();
  }
});

test('read paths: a note the caller cannot see under RLS stays unresolved (no title); the decision and its other links stay', async () => {
  const h = await connect({ connectRead: asRole(WORK_SCOPE_ONLY) });
  try {
    // the read gate checks the read session; the team-only test role has no write privilege, so it passes
    const s = jsonOf(await call(h, 'zeusi_search', { query: 'zebra' }));
    const links = (s['decisions'] as Array<{ links: Link[] }>)[0]!.links;
    assert.deepEqual(links[1], { target_kind: 'note', target_uri: 'vault:Northbank/spec-hidden.md', resolved: false });
    assert.ok(!JSON.stringify(s).includes('Synthetic northbank spec'));
    assert.equal(links[0]!.title, 'Synthetic links spec');
  } finally {
    await h.close();
  }
});

test('read paths: each link string goes through the #23 serve guard (a secret-flagged link is dropped and counted as secret; fail closed on a throw)', () => {
  const item = { type: 'decision', exact_words: 'x', links: [
    { target_kind: 'job', target_uri: 'job:clean', resolved: false },
    { target_kind: 'job', target_uri: 'job:flagged-secret', resolved: false },
  ] };
  const G = serveWithLinks([item], (s) => s === 'job:flagged-secret');
  assert.deepEqual(G.kept[0]!.links.map((l) => l.target_uri), ['job:clean']);
  assert.deepEqual([G.withheld, G.secretWithheld], [1, 1]);
  const T = serveWithLinks([item], (s) => { if (s === 'job:flagged-secret') throw new Error('boom'); return false; });
  assert.deepEqual([T.kept[0]!.links.length, T.withheld, T.secretWithheld], [1, 1, 1], 'a throwing check withholds the link');
  // an item that is withheld whole is counted once (its dropped links are not double counted)
  const W = serveWithLinks([{ ...item, exact_words: WALLED }], (s) => s === 'job:flagged-secret');
  assert.deepEqual([W.kept.length, W.withheld, W.secretWithheld], [0, 1, 0]);
  // items without links pass through wallFilter unchanged
  assert.deepEqual(serveWithLinks([{ text: 'plain' }]).kept, [{ text: 'plain' }]);
});

test('read paths: without 0013 (a DB at 0012) links are [] and nothing errors', async () => {
  const old = await pgliteDb();
  try {
    await migrate(old, { dir: subsetDir((n) => n < '0013') });
    assert.equal((await fetchDecisionLinks(old, [1, 2, 3])).size, 0);
    await old.exec('BEGIN READ ONLY');
    try {
      assert.deepEqual(await searchDecisions(old, 'anything', null, 5), []);
    } finally {
      await old.exec('ROLLBACK');
    }
  } finally {
    await old.close();
  }
});

// ---------------------------------------------------------------------------
// Structured import: Links: header -> rows

const BODY = [
  '## 2026-11-16T20:27:00+01:00 owner-13',
  'Decision: go',
  'Said-at-precision: minute',
  'Links: gh:Synthetic-Org/zeusi#11, vault:Work/products/zeusi/spec-links.md, https://example.com/x, job:nightly-ingest, gh:Synthetic-Org/zeusi#12',
  '',
  'SYNTHETIC structured GO with links',
].join('\n');

test('structured: Links: keeps every allowlisted item (first PR still fills linked_repo / linked_pr); links are not part of the record sha', () => {
  const { records } = parseStructuredBody(BODY, new Date('2026-11-17T00:00:00Z'));
  const r = records[0] as DecisionRecord;
  assert.equal(r.linkedRepo, 'Synthetic-Org/zeusi');
  assert.equal(r.linkedPr, 11);
  assert.deepEqual(r.links, ['gh:Synthetic-Org/zeusi#11', 'vault:Work/products/zeusi/spec-links.md', 'job:nightly-ingest', 'gh:Synthetic-Org/zeusi#12']);
  const { links: _l, ...without } = r;
  void _l;
  assert.equal(recordSha256(r), recordSha256(without as DecisionRecord), 'a pre-0013 record keeps its sha (no false conflict)');
  const many = BODY.replace(/^Links: .*$/m, `Links: ${Array.from({ length: 30 }, (_, i) => `job:j${i}`).join(', ')}`);
  assert.equal((parseStructuredBody(many, new Date('2026-11-17T00:00:00Z')).records[0] as DecisionRecord).links!.length, MAX_LINKS);
});

test('structured write (zeusi_mini_ingest): links land with the decision; a re-run adds none; a walled link is quarantined; at 0012 they are counted skipped', async () => {
  const { records } = parseStructuredBody(BODY, new Date('2026-11-17T00:00:00Z'));
  const wall = await loadWall(db);
  const items = records.map((record) => ({ record, project: 'links13' }));
  const opts = { scope: 'work' as const, sourceKind: 'manual' as const, uriPrefix: 'import:', runId: run, wall };
  const first = await as(db, 'zeusi_mini_ingest', () => writeStructured(db, items, opts));
  assert.deepEqual([first.decisions_inserted, first.links_inserted, first.links_quarantined, first.links_skipped], [1, 4, 0, 0]);
  const again = await as(db, 'zeusi_mini_ingest', () => writeStructured(db, items, opts));
  assert.deepEqual([again.deduped, again.links_inserted], [1, 0]);
  const stored = (await db.query<{ k: string; src: string }>(
    `SELECT l.target_kind::text AS k, l.source_uri AS src FROM zeusi.decision_links l JOIN zeusi.decisions d ON d.id = l.decision_id
     WHERE d.source_uri LIKE 'import:links13/%' ORDER BY l.id`)).rows;
  assert.deepEqual(stored.map((x) => x.k), ['pr', 'note', 'job', 'pr']);
  assert.ok(stored.every((x) => x.src.startsWith('import:links13/entry/')));
  // a link added to the header later lands on the already stored decision (deduped decision, new link)
  const plus = parseStructuredBody(BODY.replace('job:nightly-ingest', 'job:nightly-ingest, lane:zeusi-v2-prime'), new Date('2026-11-17T00:00:00Z')).records;
  const third = await as(db, 'zeusi_mini_ingest', () => writeStructured(db, plus.map((record) => ({ record, project: 'links13' })), opts));
  assert.deepEqual([third.deduped, third.links_inserted], [1, 1]);
  // a walled link (pre-check) is quarantined, never stored
  const walled = parseStructuredBody(BODY.replace('2026-11-16T20:27', '2026-11-16T21:27').replace('job:nightly-ingest', 'vault:plankiva/x.md'), new Date('2026-11-17T00:00:00Z')).records;
  const w = await as(db, 'zeusi_mini_ingest', () => writeStructured(db, walled.map((record) => ({ record, project: 'links13' })), opts));
  assert.deepEqual([w.decisions_inserted, w.links_inserted, w.links_quarantined], [1, 3, 1]);
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decision_links WHERE target_uri = 'vault:plankiva/x.md'`)).rows[0]!.n, 0);
  // at 0012 (no table): decisions still land, links are counted skipped
  const old = await pgliteDb();
  try {
    await migrate(old, { dir: subsetDir((n) => n < '0013') });
    const r0 = (await old.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    await old.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                     VALUES ('owner-13', 'Owner', 'human', 'work', 'work', 'manual', 'manual:people/owner-13', now(), decode($1, 'hex'), $2)`, [SHA, r0]);
    const s = await as(old, 'zeusi_mini_ingest', async () => writeStructured(old, items, { ...opts, runId: r0, wall: await loadWall(old) }));
    assert.deepEqual([s.decisions_inserted, s.links_inserted, s.links_skipped], [1, 0, 4]);
  } finally {
    await old.close();
  }
});

// ---------------------------------------------------------------------------
// Migration runner and rollback

test('migrate --dry-run on a DB at 0012 lists exactly 0013 and writes nothing; the apply then needs the snapshot flag', async () => {
  const d = await pgliteDb();
  try {
    await migrate(d, { dir: subsetDir((n) => n < '0013') });
    // Up to 0013 only: later migrations (0014 onward) are pinned by their own tests.
    const upTo13 = subsetDir((n) => n <= MIG);
    const lines: string[] = [];
    const r = await migrate(d, { dir: upTo13, dryRun: true, log: (l) => lines.push(l) });
    assert.deepEqual(r.pending, [MIG]);
    assert.deepEqual(lines, [`pending: ${MIG}`]);
    assert.deepEqual(r.applied, []);
    assert.equal((await d.query<{ t: string | null }>(`SELECT to_regclass('zeusi.decision_links')::text AS t`)).rows[0]!.t, null);
    await assert.rejects(migrate(d, { dir: upTo13 }), /snapshot/);
    const a = await migrate(d, { dir: upTo13, tookSnapshot: true });
    assert.deepEqual(a.applied, [MIG]);
  } finally {
    await d.close();
  }
});

test('ROLLBACK-0013.md: its SQL returns the schema to 0012 (table, functions, type gone; 0013 pending again; re-apply works)', async () => {
  const md = readFileSync(join(MIGRATIONS_DIR, 'ROLLBACK-0013.md'), 'utf8');
  const sql = /## SQL\s+```sql\n([\s\S]*?)```/.exec(md)?.[1];
  assert.ok(sql, 'the runbook has one sql block under ## SQL');
  const d = await pgliteDb();
  try {
    // Up to 0013 only: later migrations (0014 onward) are pinned by their own tests.
    const upTo13 = subsetDir((n) => n <= MIG);
    await migrate(d, { dir: upTo13 });
    await d.exec(sql);
    const q = async (s: string) => (await d.query<{ x: unknown }>(s)).rows[0]!.x;
    assert.equal(await q(`SELECT to_regclass('zeusi.decision_links')::text AS x`), null);
    assert.equal(await q(`SELECT count(*)::int AS x FROM pg_type WHERE typname = 'link_target_kind'`), 0);
    assert.equal(await q(`SELECT count(*)::int AS x FROM pg_proc WHERE proname IN ('decision_link_wall_check', 'decision_links_inherit', 'decision_links_wall_audit')`), 0);
    assert.equal(await q(`SELECT max(filename) AS x FROM zeusi.schema_migrations`), '0012_decision_write_role.sql');
    assert.deepEqual((await migrate(d, { dir: upTo13, dryRun: true })).pending, [MIG]);
    assert.deepEqual((await migrate(d, { dir: upTo13, tookSnapshot: true })).applied, [MIG]);
  } finally {
    await d.close();
  }
});
