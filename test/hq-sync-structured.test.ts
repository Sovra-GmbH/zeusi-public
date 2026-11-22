// Fix PR B (lanes DIG-startup-links.md D1-focus / D1-decisions; tests 7-12): `ingest hq-sync`
// turns explicitly headed HQ decision / memory entries into zeusi.decisions / zeusi.facts rows
// with the shared parser (src/importers/structured.ts). The whole nightly path runs here:
// staging -> runExportFilter (unchanged) -> importVault(HQ_PROFILE) -> extractHqStructured.
// PGlite only, as zeusi_mini_ingest (SET ROLE). Synthetic fixtures; planted secret and walled
// term are built at runtime. No network, no Neon, no OpenAI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources, type SourcesConfig } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { wallAudit } from '../src/wall-admin.ts';
import { runExportFilter } from '../src/hq-export.ts';
import { HQ_PROFILE, importVault, type VaultDryRunObservation } from '../src/importers/vault.ts';
import {
  collectHqRecords, extractHqStructured, formatHqStructuredPreview, formatHqStructuredResult, hqNoteFromObservation,
  HQ_STRUCTURED_IMPORTER, previewHqStructured, type HqNoteInput,
} from '../src/importers/hq-structured.ts';
import { parseEntry } from '../src/importers/structured.ts';
import { createMcpState, createZeusiMcpServer, type McpDeps } from '../src/mcp-server.ts';
import { hqNote } from './hq-fixtures.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

// Planted values, built at runtime so no secret-shaped literal sits in the repo.
const TOKEN = ['gh', 'p_', 'Q'.repeat(36)].join('');
const WALL_TERM = ['Plan', 'kiva'].join('');
const SHA = 'ab'.repeat(32);
const FAKE_HOST = ['ep-fake-888', '-pooler.eu-central-1.aws.neon.tech'].join('');
const OWNER = 'synthetic-owner';

const D_GO = `## 2026-11-16T20:27:00+01:00 ${OWNER}\nDecision: go\nSaid-at-precision: minute\nVerbatim: yes\nApplies-to: zeusi, oss\nLinks: vault:Work/x.md, gh:Synthetic-Org/zeusi#11, hq:zeusi/2026-11-16-decisions.md\n\nSYNTHETIC go for the quokka open-source prep`;
const D_LOCK = `## 2026-11-16T21:00:00+01:00 ${OWNER}\nDecision: lock\nSaid-at-precision: day\nExpires: after #13 merges\n\nSYNTHETIC lock: no wombat migration before the review`;
const D_PLAIN = `## 2026-11-16T22:00:00+01:00 ${OWNER}\n\nSYNTHETIC plain decision text without a header (stays a note)`;
const M_FOCUS = `## 2026-11-16T23:00:00+01:00 ${OWNER}\nType: focus\nSubject: synthetic-quarter\n\nSYNTHETIC focus: ship the numbat importer`;
const M_RULE = `## 2026-11-16T23:05:00+01:00 ${OWNER}\nType: rule\nSubject: synthetic-review\n\nSYNTHETIC rule: every PR gets a second login review`;

/** hqNote takes [heading, body]; the headed entries are raw H2 blocks, so build those files by hand. */
function rawNote(o: { project: string; kind: string; date?: string }, entries: string[]): string {
  const date = o.date ?? '2026-11-16';
  return ['---', `title: "${o.project} ${o.kind} ${date}"`, `date: ${date}`, 'source: zeus-hq', `project: ${o.project}`,
    `thread_id: ${o.kind}`, `kind: ${o.kind}`, 'tags: [hq-sync]', '---', '', entries.join('\n\n'), ''].join('\n');
}

function config(root: string): SourcesConfig {
  const src = (name: string, scope: string, project: string) =>
    `[[source]]\nname = "${name}"\nkind = "zeus_memory"\nscope = "${scope}"\nroot = "${root}"\ninclude = ["${project}/*.md"]\nproject = "${project}"\n`;
  return validateSources(parseToml([src('hq-team', 'work', 'team'), src('hq-northbank', 'product', 'northbank'), src('hq-clientco', 'client', 'clientco')].join('\n')), seedWall(), { home: root });
}

interface Env {
  db: Db;
  dir: string;
  staging: string;
  source: string;
  config: SourcesConfig;
  stage(rel: string, text: string): void;
  filter(): ReturnType<typeof runExportFilter>;
  run(): Promise<{ notes: Awaited<ReturnType<typeof importVault>>; s: Awaited<ReturnType<typeof extractHqStructured>> }>;
  close(): Promise<void>;
}

async function fresh(people: string[] = [OWNER]): Promise<Env> {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-hq-structured-'));
  const staging = join(dir, 'staging');
  const source = join(dir, 'zeus-hq');
  for (const p of ['work', 'team', 'northbank', 'client', 'clientco']) {
    mkdirSync(join(staging, p), { recursive: true });
    mkdirSync(join(source, p), { recursive: true });
  }
  const db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  for (const h of people) {
    await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                    VALUES ($1, 'Synthetic Owner', 'human', 'work', 'work', 'manual', $2, now(), decode($3, 'hex'), $4)`, [h, `manual:people/${h}`, SHA, run]);
  }
  const cfg = config(source);
  const env: Env = {
    db, dir, staging, source, config: cfg,
    stage(rel, text) {
      writeFileSync(join(staging, rel), text);
    },
    filter() {
      return runExportFilter({ inDir: staging, outDir: source, projects: ['team', 'northbank', 'clientco'] });
    },
    async run() {
      const f = env.filter();
      assert.equal(f.status, 'ok', f.error ?? '');
      await db.exec('SET ROLE zeusi_mini_ingest');
      try {
        const notes = await importVault({ db, config: cfg, mode: 'full', home: dir, profile: HQ_PROFILE, logPaths: false });
        assert.equal(notes.status, 'ok', notes.error ?? '');
        const s = await extractHqStructured(db, { mode: notes.mode, host: 'testhost' });
        return { notes, s };
      } finally {
        await db.exec('RESET ROLE');
      }
    },
    async close() {
      await db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return env;
}

const decisions = async (db: Db) => (await db.query<{
  kind: string; who: string; said_at: string; said_at_precision: string; exact_words: string; exact_words_verbatim: boolean; applies_to: string[];
  linked_repo: string | null; linked_pr: number | null; expires_rule: string | null; scope: string; source_kind: string; source_uri: string;
}>(`SELECT d.kind::text AS kind, p.handle AS who, d.said_at::text AS said_at, d.said_at_precision, d.exact_words, d.exact_words_verbatim, d.applies_to,
           d.linked_repo, d.linked_pr, d.expires_rule, d.scope::text AS scope, d.source_kind::text AS source_kind, d.source_uri
    FROM zeusi.decisions d JOIN zeusi.people p ON p.id = d.who_id ORDER BY d.said_at`)).rows;
const facts = async (db: Db) => (await db.query<{ kind: string; subject: string; text: string; scope: string; source_kind: string; source_uri: string }>(
  `SELECT kind::text AS kind, subject, text, scope::text AS scope, source_kind::text AS source_kind, source_uri FROM zeusi.facts ORDER BY kind, subject`)).rows;
const count = async (db: Db, table: string) => (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.${table}`)).rows[0]!.n;

function seedTeam(e: Env): void {
  e.stage('team/2026-11-16-decisions.md', rawNote({ project: 'team', kind: 'decision' }, [D_GO, D_LOCK, D_PLAIN]));
  e.stage('team/2026-11-16-memory.md', rawNote({ project: 'team', kind: 'memory' }, [M_FOCUS, M_RULE]));
  // A chat note is never parsed, even when an entry looks headed.
  e.stage('team/2026-11-16-chat-t1.md', rawNote({ project: 'team', kind: 'chat' }, [D_GO.replace('quokka', 'chatty')]));
}

test('hq-sync structured: headed decisions -> decisions rows, Type focus/rule -> facts state/rule, unheaded stays a note; startup shows the focus', async () => {
  const e = await fresh();
  try {
    seedTeam(e);
    const { notes, s } = await e.run();
    assert.equal(notes.counts.inserted, 3);
    assert.equal(s.status, 'ok', s.error ?? '');
    // 0013: the fixture's Links: headers become decision_links rows (3 allowlisted targets).
    assert.deepEqual(s.write, { decisions_inserted: 2, rules_inserted: 1, focus_inserted: 1, deduped: 0, conflict: 0, unknown_person: 0, quarantined: 0, secret_withheld: 0, links_inserted: 3, links_quarantined: 0, links_skipped: 0, links_invalid: 0 });
    assert.equal(s.parse.notes, 2, 'decision + memory notes only; chat is never parsed');
    assert.equal(s.parse.entries, 5);
    assert.equal(s.parse.unstructured, 1);
    assert.equal(s.parse.invalid, 0);

    const d = await decisions(e.db);
    assert.equal(d.length, 2);
    const go = d.find((x) => x.kind === 'go')!;
    assert.equal(go.who, OWNER);
    assert.equal(new Date(go.said_at).toISOString(), '2026-11-16T19:27:00.000Z', 'said_at = the H2 timestamp');
    assert.equal(go.said_at_precision, 'minute');
    assert.equal(go.exact_words, 'SYNTHETIC go for the quokka open-source prep', 'exact_words = the entry text, header lines excluded');
    assert.equal(go.exact_words_verbatim, true);
    assert.deepEqual(go.applies_to, ['zeusi', 'oss']);
    assert.equal(go.linked_repo, 'Synthetic-Org/zeusi');
    assert.equal(go.linked_pr, 11);
    assert.equal(go.source_kind, 'zeus_memory');
    assert.match(go.source_uri, /^hq:team\/entry\/[0-9a-f]{16}$/);
    const lock = d.find((x) => x.kind === 'lock')!;
    assert.equal(lock.exact_words_verbatim, false, 'Verbatim defaults to no');
    assert.equal(lock.expires_rule, 'after #13 merges');
    assert.equal(lock.linked_pr, null);
    assert.ok(d.every((x) => x.scope === 'work'));
    assert.doesNotMatch(JSON.stringify(d), /chatty|plain decision/, 'chat and unheaded entries are not decisions');

    const f = await facts(e.db);
    assert.deepEqual(f.map((x) => [x.kind, x.subject, x.text, x.scope, x.source_kind]), [
      ['rule', 'synthetic-review', 'SYNTHETIC rule: every PR gets a second login review', 'work', 'zeus_memory'],
      ['state', 'synthetic-quarter', 'SYNTHETIC focus: ship the numbat importer', 'work', 'zeus_memory'],
    ]);

    const run = (await e.db.query<{ importer: string; status: string; mode: string }>(`SELECT importer, status, mode FROM zeusi.ingest_runs WHERE id = $1`, [s.runId])).rows[0]!;
    assert.deepEqual(run, { importer: HQ_STRUCTURED_IMPORTER, status: 'ok', mode: 'full' });

    // zeusi_startup (read role) lists the focus and the rule.
    writeFileSync(join(e.dir, '.pg_service.conf'), `[zeusi_ro]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
    const deps: McpDeps = {
      env: { HOME: e.dir }, home: e.dir, readService: 'zeusi_ro', embeddings: () => null,
      connectRead: async () => {
        await e.db.exec('SET ROLE zeusi_box_ro');
        return { label: 'pglite as zeusi_box_ro', query: e.db.query.bind(e.db), exec: e.db.exec.bind(e.db), close: async () => { await e.db.exec('RESET ROLE'); } };
      },
      feedbackPath: join(e.dir, '.zeusi', 'search-feedback.jsonl'), queryLedgerPath: join(e.dir, '.zeusi', 'query-embed-ledger.json'),
    };
    const server = createZeusiMcpServer(deps, createMcpState());
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test', version: '0' });
    await Promise.all([server.connect(a), client.connect(b)]);
    try {
      const r = (await client.callTool({ name: 'zeusi_startup', arguments: { days: 30 } })) as { isError?: boolean; content: Array<{ text?: string }> };
      assert.notEqual(r.isError, true, r.content[0]?.text ?? '');
      const j = JSON.parse(r.content.map((c) => c.text ?? '').join('')) as { focus: unknown; rules: unknown };
      assert.match(JSON.stringify(j.focus), /SYNTHETIC focus: ship the numbat importer/);
      assert.match(JSON.stringify(j.rules), /SYNTHETIC rule: every PR gets a second login review/);
    } finally {
      await client.close();
      await server.close();
    }
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('hq-sync structured: unknown speaker -> unknown_person, no people row created; resumable once the person exists', async () => {
  const e = await fresh([]);
  try {
    seedTeam(e);
    const { s } = await e.run();
    assert.equal(s.status, 'ok_partial');
    assert.equal(s.write.unknown_person, 4);
    assert.equal(await count(e.db, 'people'), 0, 'people are never created');
    assert.equal(await count(e.db, 'decisions'), 0);
    assert.equal(await count(e.db, 'facts'), 0);
    assert.equal((await e.db.query<{ status: string }>(`SELECT status FROM zeusi.ingest_runs WHERE id = $1`, [s.runId])).rows[0]!.status, 'ok_partial');
    assert.match(formatHqStructuredResult(s), /unknown_person 4/);

    const run = (await e.db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    await e.db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                      VALUES ($1, 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/x', now(), decode($2, 'hex'), $3)`, [OWNER, SHA, run]);
    const again = await e.run();
    assert.equal(again.s.status, 'ok');
    assert.equal(again.s.write.decisions_inserted, 2);
    assert.equal(again.s.write.focus_inserted, 1);
  } finally {
    await e.close();
  }
});

test('hq-sync structured: a second run inserts nothing (deduped); an edited entry is a conflict, refused, nothing updated', async () => {
  const e = await fresh();
  try {
    seedTeam(e);
    await e.run();
    const second = await e.run();
    assert.equal(second.s.status, 'ok');
    assert.deepEqual(second.s.write, { decisions_inserted: 0, rules_inserted: 0, focus_inserted: 0, deduped: 4, conflict: 0, unknown_person: 0, quarantined: 0, secret_withheld: 0, links_inserted: 0, links_quarantined: 0, links_skipped: 0, links_invalid: 0 });
    assert.equal(await count(e.db, 'decisions'), 2);
    assert.equal(await count(e.db, 'facts'), 2);

    // The routine re-exports the same day with one decision entry edited.
    e.stage('team/2026-11-16-decisions.md', rawNote({ project: 'team', kind: 'decision' }, [D_GO.replace('quokka', 'edited-quokka'), D_LOCK, D_PLAIN]));
    const edited = await e.run();
    assert.equal(edited.notes.counts.updated, 1, 'the note itself is updated in place (notes lifecycle unchanged)');
    assert.equal(edited.s.status, 'ok_partial');
    assert.equal(edited.s.write.conflict, 1);
    assert.equal(edited.s.write.decisions_inserted, 0);
    const d = await decisions(e.db);
    assert.equal(d.length, 2);
    assert.ok(d.some((x) => x.exact_words === 'SYNTHETIC go for the quokka open-source prep'), 'the stored row is unchanged (no UPDATE)');
    assert.ok(!d.some((x) => /edited-quokka/.test(x.exact_words)));
  } finally {
    await e.close();
  }
});

test('hq-sync structured: a planted walled term or a synthetic secret in a HEADED entry is withheld by the export filter first; nothing of it lands', async () => {
  const e = await fresh();
  try {
    const walled = `## 2026-11-16T10:00:00+01:00 ${OWNER}\nDecision: stop\nSaid-at-precision: minute\nApplies-to: ${WALL_TERM.toLowerCase()}-project\n\nSYNTHETIC stop: wall probe in the header`;
    const secret = `## 2026-11-16T11:00:00+01:00 ${OWNER}\nDecision: park\nSaid-at-precision: minute\n\nSYNTHETIC park, token ${TOKEN}`;
    const clean = `## 2026-11-16T12:00:00+01:00 ${OWNER}\nDecision: ruling\nSaid-at-precision: minute\n\nSYNTHETIC ruling: clean`;
    e.stage('team/2026-11-16-decisions.md', rawNote({ project: 'team', kind: 'decision' }, [walled, secret, clean]));
    const f = e.filter();
    assert.equal(f.status, 'ok');
    assert.equal(f.counts.withheld_by_signal.plankiva, 1);
    assert.equal(f.counts.withheld_by_signal.credential, 1);
    const out = readFileSync(join(e.source, 'team/2026-11-16-decisions.md'), 'utf8');
    assert.ok(!out.includes(TOKEN) && !out.toLowerCase().includes(WALL_TERM.toLowerCase()));
    const { s } = await e.run();
    assert.equal(s.write.decisions_inserted, 1);
    const all = JSON.stringify([await decisions(e.db), await facts(e.db), (await e.db.query(`SELECT * FROM zeusi.quarantine`)).rows]);
    assert.ok(!all.includes(TOKEN));
    assert.ok(!all.toLowerCase().includes(WALL_TERM.toLowerCase()));
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('hq-sync structured: a walled header that reaches the source folder anyway (filter bypassed) is quarantined with the note; no decision row', async () => {
  const e = await fresh();
  try {
    const walled = `## 2026-11-16T10:00:00+01:00 ${OWNER}\nDecision: stop\nSaid-at-precision: minute\nApplies-to: ${WALL_TERM.toLowerCase()}\n\nSYNTHETIC stop`;
    writeFileSync(join(e.source, 'team/2026-11-16-decisions.md'), rawNote({ project: 'team', kind: 'decision' }, [walled]));
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      const r = await importVault({ db: e.db, config: e.config, mode: 'full', home: e.dir, profile: HQ_PROFILE, logPaths: false });
      assert.equal(r.counts.quarantined, 1);
      const s = await extractHqStructured(e.db, { mode: 'full', host: 'testhost' });
      assert.equal(s.status, 'ok');
      assert.equal(s.runId, null, 'nothing admitted, nothing to write');
    } finally {
      await e.db.exec('RESET ROLE');
    }
    assert.equal(await count(e.db, 'decisions'), 0);
    const q = (await e.db.query<{ source_uri: string }>(`SELECT source_uri FROM zeusi.quarantine`)).rows;
    assert.ok(q.length >= 1 && q.every((x) => /^hq:team\/2026-11-16-decisions\.md(#c\d+)?$/.test(x.source_uri)), 'uri + hash only');
  } finally {
    await e.close();
  }
});

test('hq-sync structured: scope comes from the source config only; a clientco row is invisible to a team-only reader; a Scope header is refused', async () => {
  const e = await fresh();
  try {
    seedTeam(e);
    e.stage('clientco/2026-11-16-decisions.md', rawNote({ project: 'clientco', kind: 'decision' }, [D_GO.replace('quokka', 'clientco-desk')]));
    e.stage('northbank/2026-11-16-memory.md', rawNote({ project: 'northbank', kind: 'memory' }, [M_FOCUS.replace('numbat', 'northbank-watcher')]));
    // A header cannot pick a scope: an unknown key makes the header invalid (note only).
    e.stage('northbank/2026-11-16-decisions.md', rawNote({ project: 'northbank', kind: 'decision' }, [
      `## 2026-11-16T09:00:00+01:00 ${OWNER}\nDecision: go\nSaid-at-precision: minute\nScope: personal\n\nSYNTHETIC tries to pick a scope`,
    ]));
    const { s } = await e.run();
    assert.equal(s.status, 'ok', s.error ?? '');
    assert.equal(s.parse.invalid, 1);
    const d = await decisions(e.db);
    assert.deepEqual(d.map((x) => [x.scope, x.source_uri.split('/')[0]]).sort(), [['client', 'hq:clientco'], ['work', 'hq:team'], ['work', 'hq:team']]);
    const f = await facts(e.db);
    assert.ok(f.some((x) => x.scope === 'product' && /northbank-watcher/.test(x.text)));
    assert.doesNotMatch(JSON.stringify(d), /tries to pick a scope/);

    const role = 'zeusi_test_hqs_work_only';
    await e.db.exec(`CREATE ROLE ${role} NOLOGIN; GRANT USAGE ON SCHEMA zeusi TO ${role};
      GRANT SELECT ON zeusi.decisions, zeusi.facts TO ${role};
      CREATE POLICY t_work ON zeusi.decisions FOR SELECT TO ${role} USING (scope = 'work');
      CREATE POLICY t_work ON zeusi.facts FOR SELECT TO ${role} USING (scope = 'work');`);
    await e.db.exec(`SET ROLE ${role}`);
    try {
      const seen = (await e.db.query<{ t: string }>(`SELECT coalesce(string_agg(exact_words, ' '), '') AS t FROM zeusi.decisions`)).rows[0]!.t
        + (await e.db.query<{ t: string }>(`SELECT coalesce(string_agg(text, ' '), '') AS t FROM zeusi.facts`)).rows[0]!.t;
      assert.doesNotMatch(seen, /clientco-desk|northbank-watcher/);
      assert.match(seen, /quokka/);
    } finally {
      await e.db.exec('RESET ROLE');
    }
  } finally {
    await e.close();
  }
});

test('hq-sync structured: header values are validated (enums, lengths, ISO timestamps, gh link shape); the note kind decides the record type', () => {
  const lines = (s: string) => s.split('\n');
  const h = `## 2026-11-16T20:27:00+01:00 ${OWNER}`;
  const bad = [
    `${h}\nDecision: maybe\nSaid-at-precision: minute\n\nx`, // enum
    `${h}\nDecision: go\nSaid-at-precision: hour\n\nx`, // enum
    `${h}\nDecision: go\n\nx`, // precision missing
    `${h}\nDecision: go\nSaid-at-precision: minute\nVerbatim: perhaps\n\nx`,
    `${h}\nDecision: go\nSaid-at-precision: minute\nExpires: 2026-13-45T99:00:00Z\n\nx`, // ISO-shaped but not a date
    `${h}\nDecision: go\nSaid-at-precision: minute\nApplies-to: ${'a'.repeat(201)}\n\nx`,
    `${h}\nType: focus\nSubject: ${'s'.repeat(201)}\n\nx`,
    `${h}\nType: retire\nSubject: s\n\nx`, // retirement needs migration 0013-a: not supported
    `${h}\nType: focus\n\nx`, // subject missing
    `${h}\nDecision: go\nSaid-at-precision: minute\nDecision: stop\n\nx`, // duplicate key
    `${h}\nDecision: go\nSaid-at-precision: minute\nType: rule\n\nx`, // mixed
    `${h}\nDecision: go\nSaid-at-precision: minute\n\n${'x'.repeat(4001)}`,
    `${h}\nDecision: go\nSaid-at-precision: minute\n\n`, // no text
    `## 2026-11-16T20:27:00 ${OWNER}\nDecision: go\nSaid-at-precision: minute\n\nx`, // no offset: not a structured H2
    `## 2026-02-30T20:27:00+01:00 ${OWNER}\nDecision: go\nSaid-at-precision: minute\n\nx`, // impossible date
    `## 2026-11-16T20:27:00+15:30 ${OWNER}\nDecision: go\nSaid-at-precision: minute\n\nx`, // impossible offset
    `${h}\nDecision: go\nSaid-at-precision: minute\nExpires: 2026-02-30T00:00:00Z\n\nx`, // impossible expiry day
    `## 2026-11-16T20:27:00+01:00 Not A Handle\nDecision: go\nSaid-at-precision: minute\n\nx`,
  ];
  for (const b of bad) assert.ok('skip' in parseEntry(lines(b)), b.slice(0, 120));
  for (const l of ['gh:Synthetic-Org/zeusi', 'gh:Synthetic-Org/zeusi#0', 'gh:Org/repo#12;drop', 'gh:../x#1x', 'https://github.com/o/r/pull/1', 'gh:o/r#1234567890']) {
    const r = parseEntry(lines(`${h}\nDecision: go\nSaid-at-precision: minute\nLinks: ${l}\n\nx`));
    assert.ok('record' in r && r.record.type === 'decision');
    if ('record' in r && r.record.type === 'decision') assert.deepEqual([r.record.linkedRepo, r.record.linkedPr], [null, null], l);
  }

  const n = (kind: string, body: string): HqNoteInput => ({ rel: `team/2026-11-16-${kind}.md`, scope: 'work', kind, body });
  const c = collectHqRecords([
    n('decision', M_FOCUS), // a fact in a decision note: invalid
    n('memory', D_GO), // a decision in a memory note: invalid
    n('journal', D_GO), // journal: never parsed
    { rel: 'team/2026-11-16-decision.md', scope: 'personal', kind: 'decision', body: D_GO }, // never personal
  ]);
  assert.equal(c.items.length, 0);
  assert.equal(c.counts.invalid, 2);
  assert.equal(c.counts.notes, 2);
});

test('hq-sync structured (security review M1, M2): a far-future H2 is invalid; two headed entries with the same who and time both land', async () => {
  const lines = (x: string) => x.split('\n');
  const now = new Date('2026-11-17T12:00:00Z');
  assert.ok('skip' in parseEntry(lines(`## 2099-01-01T00:00:00Z ${OWNER}\nType: focus\nSubject: pinned\n\nx`), now), 'far future refused');
  assert.ok('skip' in parseEntry(lines(`## 2026-11-19T12:00:00Z ${OWNER}\nType: focus\nSubject: pinned\n\nx`), now), '48 h ahead refused');
  assert.ok('record' in parseEntry(lines(`## 2026-11-18T12:00:00+01:00 ${OWNER}\nType: focus\nSubject: ok\n\nx`), now), 'within the 36 h skew');

  const e = await fresh();
  try {
    const day = (kind: string, text: string) => `## 2026-11-16T00:00:00+01:00 ${OWNER}\nDecision: ${kind}\nSaid-at-precision: day\n\n${text}`;
    e.stage('team/2026-11-16-decisions.md', rawNote({ project: 'team', kind: 'decision' }, [day('go', 'SYNTHETIC first same-day go'), day('stop', 'SYNTHETIC second same-day stop')]));
    const first = await e.run();
    assert.equal(first.s.write.decisions_inserted, 2);
    assert.equal(first.s.write.conflict, 0);
    const d = await decisions(e.db);
    assert.equal(new Set(d.map((x) => x.source_uri)).size, 2, 'distinct uris');
    const again = await e.run();
    assert.deepEqual([again.s.write.deduped, again.s.write.conflict], [2, 0]);
  } finally {
    await e.close();
  }
});

test('hq-sync structured dry run: preview prints the would-insert counts offline (no connection, zero writes), counts only', async () => {
  const e = await fresh();
  try {
    seedTeam(e);
    assert.equal(e.filter().status, 'ok');
    const admitted: HqNoteInput[] = [];
    const r = await importVault({
      config: e.config, mode: 'full', dryRun: true, profile: HQ_PROFILE, home: e.dir,
      dryRunObserve: (o: VaultDryRunObservation) => { const x = hqNoteFromObservation(o); if (x) admitted.push(x); },
    });
    assert.equal(r.status, 'ok');
    const p = previewHqStructured(admitted, seedWall());
    assert.equal(p.counts.decisions, 2);
    assert.deepEqual(p.counts.decisions_by_kind, { go: 1, lock: 1 });
    assert.equal(p.counts.rules, 1);
    assert.equal(p.counts.focus, 1);
    assert.equal(p.counts.unstructured, 1);
    assert.equal(p.counts.handles_named, 1);
    const text = formatHqStructuredPreview(p);
    assert.match(text, /would insert: decisions 2 \(go 1 \/ lock 1\), facts rule 1 \/ state \(focus\) 1/);
    assert.doesNotMatch(text, /SYNTHETIC|quokka|synthetic-owner|synthetic-quarter/);
    for (const t of ['decisions', 'facts', 'notes', 'quarantine', 'ingest_runs']) {
      assert.equal(await count(e.db, t), t === 'ingest_runs' ? 1 : 0, `dry run wrote nothing to ${t}`);
    }

    // The CLI: offline (an unreadable service file: any connection attempt would fail), counts only.
    const cfg = join(e.dir, 'sources.toml');
    writeFileSync(cfg, `[[source]]\nname = "hq-team"\nkind = "zeus_memory"\nscope = "work"\nroot = "${e.source}"\ninclude = ["team/*.md"]\nproject = "team"\n`);
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: e.dir, PGSERVICEFILE: join(e.dir, 'missing.conf') };
    const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
    const d = spawnSync(process.execPath, [cli, 'ingest', 'hq-sync', '--dry-run', '--config', cfg], { cwd: e.dir, encoding: 'utf8', env, timeout: 20_000 });
    assert.equal(d.status, 0, d.stderr);
    assert.match(d.stdout, /would insert: 3 note\(s\)/);
    assert.match(d.stdout, /would insert: decisions 2 \(go 1 \/ lock 1\), facts rule 1 \/ state \(focus\) 1/);
    assert.match(d.stdout, /unstructured 1/);
    assert.doesNotMatch(d.stdout, /SYNTHETIC|quokka|synthetic-owner|2026-11-16-decisions/);
    assert.ok(!existsSync(join(e.dir, '.zeusi')) || readdirSync(join(e.dir, '.zeusi')).length === 0);
  } finally {
    await e.close();
  }
});

// #23 shared detector (PR2 P3): a synthetic PARTIAL key (provider prefix + a few key characters,
// built at runtime) in a headed HQ entry is never stored raw and never becomes a record.
const PARTIAL = ['AI', 'za', 'Sy', 'X0X0', 'X0X'].join('');

test('hq-sync structured (#23 detector): a partial key in a headed HQ entry is withheld by the export filter (counted); a copy that bypasses the filter is redacted in the note and counted secret, never a decision; dry run counts it', async () => {
  const e = await fresh();
  try {
    const headed = (t: string) => `## 2026-11-16T11:00:00+01:00 ${OWNER}\nDecision: go\nSaid-at-precision: minute\nApplies-to: deploy\n\nSYNTHETIC go, key ${t}`;
    // 1. Through the nightly filter: the entry is withheld before staging reaches the source folder.
    e.stage('team/2026-11-16-decisions.md', rawNote({ project: 'team', kind: 'decision' }, [headed(PARTIAL), D_LOCK]));
    const f = e.filter();
    assert.equal(f.status, 'ok');
    assert.equal(f.counts.withheld_by_signal.credential, 1, 'the export filter counts it');
    assert.ok(!readFileSync(join(e.source, 'team/2026-11-16-decisions.md'), 'utf8').includes(PARTIAL));

    // 2. Filter bypassed (a file written straight into the source folder): the importer redacts the
    //    note with the shared detector; the structured parser sees the marker and counts it secret.
    const memo = `## 2026-11-16T23:30:00+01:00 ${OWNER}\nType: focus\nSubject: synthetic-key\n\nSYNTHETIC focus with ${PARTIAL}`;
    writeFileSync(join(e.source, 'team/2026-11-17-decisions.md'), rawNote({ project: 'team', kind: 'decision', date: '2026-11-17' }, [headed(PARTIAL)]));
    writeFileSync(join(e.source, 'team/2026-11-17-memory.md'), rawNote({ project: 'team', kind: 'memory', date: '2026-11-17' }, [memo]));

    // Dry run first: counts only, the secret entries counted, nothing written.
    const admitted: HqNoteInput[] = [];
    const dr = await importVault({
      config: e.config, mode: 'full', dryRun: true, profile: HQ_PROFILE, home: e.dir,
      dryRunObserve: (o: VaultDryRunObservation) => { const x = hqNoteFromObservation(o); if (x) admitted.push(x); },
    });
    assert.equal(dr.status, 'ok');
    const p = previewHqStructured(admitted, seedWall());
    assert.equal(p.counts.secret, 2, 'the bypassing decision and focus are counted secret');
    assert.equal(p.counts.decisions, 1, 'only the clean lock');
    assert.equal(p.counts.focus, 0);
    const text = formatHqStructuredPreview(p);
    assert.match(text, /secret 2/);
    assert.ok(!text.includes(PARTIAL));
    assert.equal(await count(e.db, 'decisions'), 0, 'dry run wrote nothing');

    await e.db.exec('SET ROLE zeusi_mini_ingest');
    let s: Awaited<ReturnType<typeof extractHqStructured>>;
    try {
      const r = await importVault({ db: e.db, config: e.config, mode: 'full', home: e.dir, profile: HQ_PROFILE, logPaths: false });
      assert.equal(r.status, 'ok');
      s = await extractHqStructured(e.db, { mode: 'full', host: 'testhost' });
    } finally {
      await e.db.exec('RESET ROLE');
    }
    assert.equal(s.parse.secret, 2);
    assert.equal(s.write.decisions_inserted, 1, 'the clean lock only');
    assert.equal(s.write.focus_inserted, 0);
    assert.match(formatHqStructuredResult(s), /secret 2/);
    const dump = JSON.stringify(await Promise.all(['notes', 'chunks', 'decisions', 'facts', 'quarantine'].map(async (t) =>
      (await e.db.query(`SELECT row_to_json(x)::text AS j FROM zeusi.${t} x`)).rows)));
    assert.ok(!dump.includes(PARTIAL), 'never stored raw');
    assert.ok(!dump.includes('SyX0X0X0X'), 'no key piece stored');
    assert.ok(dump.includes('[REDACTED:'), 'the note keeps the redaction marker (redacted before insert)');
    const recs = JSON.stringify([await decisions(e.db), await facts(e.db)]);
    assert.ok(!recs.includes('[REDACTED:'), 'no record carries a marker (the serve guard would withhold it)');
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});
