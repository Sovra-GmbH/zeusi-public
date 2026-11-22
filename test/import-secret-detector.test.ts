// PR2 P3 x #23: the import / onboard pipeline uses the ONE shared detector (src/secrets.ts) the
// same way ingest does: the unchanged export filter withholds a credential-bearing entry (counted
// in the preview), importVault redacts what is left before insert, the structured parser never
// turns a secret-bearing headed entry into a record, and every MCP output (incl.
// zeusi_onboarding_status and the onboarding prompt) passes the serve guard.
//
// A synthetic PARTIAL key (provider prefix + a few key characters, built at runtime) is planted in
// a Claude chat export, a markdown note, a git commit message and a decision-log line. It is never
// stored raw and never served. PGlite only (SET ROLE), no network, no Neon, no OpenAI.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { executeImport, formatPreview, formatRealResult, prepareImport } from '../src/import-run.ts';
import { assertIngestReady } from '../src/importers/vault.ts';
import {
  entrySecretSignal, parseStructuredBody, recordSecretSignal, writeStructured, type StructuredRecord,
} from '../src/importers/structured.ts';
import { credentialSignal, strictCredentialSignal } from '../src/secrets.ts';
import { seedWall } from '../src/wall.ts';
import { wallAudit } from '../src/wall-admin.ts';
import { createMcpState, createZeusiMcpServer, type McpDeps } from '../src/mcp-server.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const PARTIAL = ['AI', 'za', 'Sy', 'X0X0', 'X0X'].join('');
const PIECE = ['Sy', 'X0X0', 'X0X'].join('');
const OWNER = 'synthetic-owner';
const SHA = '7e'.repeat(32);
const FAKE_HOST = ['ep-fake-919', '-pooler.eu-central-1.aws.neon.tech'].join('');

let db: Db;
let dir: string;

before(async () => {
  dir = safeMkdtemp(join(tmpdir(), 'zeusi-import-secret-'));
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ($1, 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/x', now(), decode($2, 'hex'), $3)`, [OWNER, SHA, run]);
  const svc = (name: string, user: string) => `[${name}]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;
  writeFileSync(join(dir, '.pg_service.conf'), svc('zeusi_ro', 'zeusi_box_ro'));
});
after(async () => db.close());

function inputs(): Parameters<typeof prepareImport>[0]['inputs'] {
  const repo = join(dir, 'repo');
  mkdirSync(join(repo, '.git'), { recursive: true });
  // 1. Claude chat export: the key inside a message.
  const chat = join(dir, 'claude.json');
  writeFileSync(chat, JSON.stringify([{
    uuid: 'c1', name: 'Synthetic chat', created_at: '2026-11-10T09:00:00Z',
    chat_messages: [
      { sender: 'human', text: `SYNTHETIC chat: the key starts ${PARTIAL}`, created_at: '2026-11-10T09:00:01Z' },
      { sender: 'assistant', text: 'SYNTHETIC chat answer clean', created_at: '2026-11-10T09:00:02Z' },
    ],
  }]));
  // 2. Markdown note: the key in the body, next to a clean note.
  const md = join(dir, 'notes');
  mkdirSync(md, { recursive: true });
  writeFileSync(join(md, 'key.md'), `---\ntitle: Key note\ndate: 2026-11-10\n---\nSYNTHETIC note, partial key ${PARTIAL} here\n`);
  writeFileSync(join(md, 'clean.md'), '---\ntitle: Clean\ndate: 2026-11-10\n---\nSYNTHETIC clean markdown note\n');
  // 3. Decision log: a headed line carrying the key, and a clean headed decision.
  const log = join(dir, 'log.md');
  writeFileSync(log, [
    '---', 'date: 2026-11-14', '---', '',
    `## 2026-11-14T10:00:00+01:00 ${OWNER}`, 'Decision: go', 'Said-at-precision: day', '', `SYNTHETIC go with key ${PARTIAL}`, '',
    `## 2026-11-14T11:00:00+01:00 ${OWNER}`, 'Decision: lock', 'Said-at-precision: day', '', 'SYNTHETIC lock: clean decision', '',
  ].join('\n'));
  return [
    { kind: 'claude-export', path: chat },
    { kind: 'markdown', path: md },
    { kind: 'decision-log', path: log },
    { kind: 'git', path: repo },
  ];
}

// 4. Git: a decision-like commit whose message carries the key (test seam replaces `git log`).
const gitLog = async () => [
  '', ['a'.repeat(40), '2026-11-11T10:00:00Z', '', 'feat: lock the release train (decision)', `rotated key ${PARTIAL} today`].join('\x1f'),
  ['b'.repeat(40), '2026-11-11T11:00:00Z', '', 'feat: park the newsletter (decision)', 'SYNTHETIC clean commit body'].join('\x1f'),
].join('\x1e');

const dumpAll = async () => JSON.stringify(await Promise.all(['notes', 'chunks', 'decisions', 'facts', 'quarantine', 'ingest_runs'].map(async (t) =>
  (await db.query(`SELECT row_to_json(x)::text AS j FROM zeusi.${t} x`)).rows)));

test('the planted value is a partial key the shared detector catches (sanity)', () => {
  assert.equal(credentialSignal(PARTIAL), true);
  assert.equal(strictCredentialSignal(`key ${PARTIAL}`), true);
});

test('import x #23: a partial key in a chat export, a markdown note, a git commit message and a decision-log line is counted in the preview, never stored raw, never served; the clean decision lands', async () => {
  const before = await dumpAll();
  const p = await prepareImport({ inputs: inputs(), scope: 'work', workRoot: join(dir, 'work-root'), home: dir, git: gitLog, gitRemotes: async () => [] });
  try {
    const v = p.preview;
    assert.equal(v.error, undefined);
    assert.equal(v.filter.withheld_by_signal.credential, 4, 'one withheld entry per input (chat, markdown, decision log, git)');
    assert.equal(v.targets.decisions, 1, 'only the clean headed decision');
    assert.deepEqual(v.targets.decisions_by_kind, { lock: 1 });
    const text = formatPreview(v);
    assert.match(text, /credential 4/);
    assert.ok(!text.includes(PARTIAL) && !text.includes(PIECE), 'the preview prints counts only');
    assert.equal(await dumpAll(), before, 'dry run: zero writes');

    await db.exec('SET ROLE zeusi_mini_ingest');
    let r: Awaited<ReturnType<typeof executeImport>>;
    try {
      await assertIngestReady(db);
      r = await executeImport(p, db, { host: 'test', home: dir });
    } finally {
      await db.exec('RESET ROLE');
    }
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.structured.decisions_inserted, 1);
    assert.ok(!formatRealResult(r).includes(PARTIAL));
  } finally {
    p.cleanup();
  }
  const dump = await dumpAll();
  assert.ok(!dump.includes(PARTIAL), 'never stored raw');
  assert.ok(!dump.includes(PIECE), 'no key piece stored');
  assert.deepEqual(await wallAudit(db), []);

  // Served: every read tool and the onboarding status / prompt, through the serve guard.
  const deps: McpDeps = {
    env: { HOME: dir }, home: dir, readService: 'zeusi_ro', embeddings: () => null,
    connectRead: async () => {
      await db.exec('SET ROLE zeusi_box_ro');
      return { label: 'pglite as zeusi_box_ro', query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
    },
    feedbackPath: join(dir, '.zeusi', 'fb.jsonl'), queryLedgerPath: join(dir, '.zeusi', 'ledger.json'),
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    const served: string[] = [];
    const callText = async (name: string, args: Record<string, unknown>) => {
      const res = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
      const t = res.content.map((c) => c.text ?? '').join('\n');
      assert.notEqual(res.isError, true, `${name}: ${t.slice(0, 120)}`);
      served.push(t);
      return t;
    };
    await callText('zeusi_startup', { days: 90 });
    for (const q of ['SYNTHETIC', 'key', 'partial key', 'chat', 'rotated key', 'release train']) await callText('zeusi_search', { query: q });
    const ctx = await callText('zeusi_context_for_task', { task: 'SYNTHETIC go key deploy release train' });
    assert.match(ctx, /SYNTHETIC lock: clean decision/, 'the clean decision is served');
    const status = JSON.parse(await callText('zeusi_onboarding_status', {})) as { empty: boolean; counts: Record<string, number> };
    assert.equal(status.empty, false);
    assert.equal(status.counts['decisions'], 1);
    const prompt = await client.getPrompt({ name: 'onboarding', arguments: {} });
    served.push(JSON.stringify(prompt.messages));
    for (const t of served) {
      assert.ok(!t.includes(PARTIAL) && !t.includes(PIECE), 'never served');
      assert.ok(!t.includes('[REDACTED:'), 'a redacted item is withheld at serve time, not served with its marker');
    }
  } finally {
    await client.close();
    await server.close();
  }
});

test('structured (#23): a headed entry that reaches the parser with a key or a [REDACTED: marker yields no record (counted secret); the writer refuses a secret-bearing record before any query', async () => {
  const entry = (t: string) => `## 2026-11-14T10:00:00+01:00 ${OWNER}\nDecision: go\nSaid-at-precision: day\nApplies-to: deploy\n\nSYNTHETIC ${t}`;
  for (const t of [`key ${PARTIAL}`, 'key [REDACTED:google_api_key]', 'clean']) {
    const p = parseStructuredBody(entry(t));
    assert.equal(p.counts.secret, t === 'clean' ? 0 : 1, t.slice(0, 12));
    assert.equal(p.records.length, t === 'clean' ? 1 : 0);
  }
  // In a header value too (Applies-to).
  assert.equal(parseStructuredBody(entry('clean').replace('Applies-to: deploy', `Applies-to: deploy, ${PARTIAL}`)).counts.secret, 1);
  assert.equal(entrySecretSignal(['clean']), false);

  const rec: StructuredRecord = {
    type: 'decision', who: OWNER, saidAt: '2026-11-14T09:00:00.000Z', saidAtPrecision: 'day', kind: 'go', verbatim: false,
    appliesTo: [PARTIAL], linkedRepo: null, linkedPr: null, expiresAt: null, expiresRule: null, text: 'SYNTHETIC',
  };
  assert.equal(recordSecretSignal(rec), true);
  assert.equal(recordSecretSignal({ ...rec, appliesTo: ['deploy'] }), false);
  const queries: string[] = [];
  const spy: Db = { label: 'spy', query: async (sql: string) => { queries.push(sql); return { rows: [], rowCount: 0 } as never; }, exec: async () => {}, close: async () => {} } as unknown as Db;
  const w = await writeStructured(spy, [{ record: rec, project: 'team' }], { scope: 'work', sourceKind: 'manual', uriPrefix: 'import:', runId: 1, wall: seedWall() });
  assert.equal(w.secret_withheld, 1);
  assert.equal(w.decisions_inserted, 0);
  assert.deepEqual(queries, [], 'no query carried the record');
});

test('serve guard (#23): zeusi_onboarding_status and the onboarding prompt pass the serve check; a check that fires (or throws) withholds them whole', async () => {
  for (const check of [() => true, () => { throw new Error('guard down'); }]) {
    const deps: McpDeps = {
      env: { HOME: dir }, home: dir, readService: 'zeusi_ro', embeddings: () => null, serveCheck: check,
      connectRead: async () => {
        await db.exec('SET ROLE zeusi_box_ro');
        return { label: 'pglite as zeusi_box_ro', query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
      },
      feedbackPath: join(dir, '.zeusi', 'fb.jsonl'), queryLedgerPath: join(dir, '.zeusi', 'ledger.json'),
    };
    const server = createZeusiMcpServer(deps, createMcpState());
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test', version: '0' });
    await Promise.all([server.connect(a), client.connect(b)]);
    try {
      const r = (await client.callTool({ name: 'zeusi_onboarding_status', arguments: {} })) as { content: Array<{ text?: string }> };
      const j = JSON.parse(r.content.map((c) => c.text ?? '').join('')) as Record<string, unknown>;
      assert.equal(j['withheld'], 1);
      assert.equal(j['counts'], undefined, 'nothing of the body served');
      const p = await client.getPrompt({ name: 'onboarding', arguments: {} });
      const t = JSON.stringify(p.messages);
      assert.match(t, /withheld by the serve guard/);
      assert.doesNotMatch(t, /zeusi import/, 'the guidance itself is not served');
    } finally {
      await client.close();
      await server.close();
    }
  }
});

// ---------------------------------------------------------------------------
// Security review (PR2 update 3) regressions.

test('review H1: a markdown note walled only by its original frontmatter (tags / aliases / any key) is skipped (path_gated), never staged; a key in an uncarried key too', async () => {
  const walled = ['Plan', 'kiva'].join('');
  const md = join(dir, 'h1-notes');
  mkdirSync(md, { recursive: true });
  writeFileSync(join(md, 'tag.md'), `---\ntitle: Tagged\ndate: 2026-11-10\ntags: [${walled.toLowerCase()}]\n---\nSYNTHETIC body without the name\n`);
  writeFileSync(join(md, 'alias.md'), `---\ntitle: Aliased\ndate: 2026-11-10\naliases: [${walled.slice(0, 3)}a${walled.slice(3)}]\n---\nSYNTHETIC body two\n`);
  writeFileSync(join(md, 'key.md'), `---\ntitle: Keyed\ndate: 2026-11-10\nsource_key: ${PARTIAL}\n---\nSYNTHETIC body three\n`);
  writeFileSync(join(md, 'clean.md'), '---\ntitle: Clean\ndate: 2026-11-10\ntags: [ops]\n---\nSYNTHETIC clean\n');
  const p = await prepareImport({ inputs: [{ kind: 'markdown', path: md }], scope: 'work', workRoot: join(dir, 'work-h1'), home: dir });
  try {
    assert.equal(p.preview.inputs[0]!.skipped.path_gated, 3);
    assert.equal(p.preview.inputs[0]!.notes_staged, 1);
    assert.equal(p.preview.targets.notes, 1, 'only the clean note');
  } finally {
    p.cleanup();
  }
});

test('review M1 + L1: a git input whose folder name or remote matches a hard wall repo rule is refused; a folder without its own .git is refused', async () => {
  const mk = (name: string) => {
    const r = join(dir, 'm1', name);
    mkdirSync(join(r, '.git'), { recursive: true });
    return r;
  };
  const run = (path: string, remotes: string[]) => prepareImport({
    inputs: [{ kind: 'git', path }], scope: 'work', workRoot: join(dir, 'work-m1'), home: dir, git: gitLog, gitRemotes: async () => remotes,
  });
  await assert.rejects(run(mk('agent-config-backup'), []), /refused by the wall/);
  await assert.rejects(run(mk('innocent-name'), ['git@github.com:example-org/agent-config-backup-2.git']), /refused by the wall/);
  await assert.rejects(run(mk('plain'), [`https://github.com/Some-Org/${['plan', 'kiva'].join('')}-notes.git`]), /refused by the wall/);
  // ClientCo repos are admitted since wall 0010 (only the walled person and agent config backups stay out).
  (await run(mk('clientco-engine'), [])).cleanup();
  const ok = await run(mk('tooling'), ['https://github.com/Synthetic-Org/tooling.git']);
  ok.cleanup();
  const sub = join(dir, 'm1', 'tooling', 'sub');
  mkdirSync(sub, { recursive: true });
  await assert.rejects(run(sub, []), /no \.git/);
});

test('review M2: raw staging copies are gone right after the filter; a stale run dir from an interrupted run is swept at the next start', async () => {
  const { sweepStaleRuns, STALE_RUN_MS } = await import('../src/import-run.ts');
  const root = join(dir, 'work-m2');
  const p = await prepareImport({ inputs: inputs().filter((i) => i.kind === 'markdown'), scope: 'work', workRoot: root, home: dir });
  try {
    const { existsSync } = await import('node:fs');
    assert.equal(existsSync(join(p.workDir, 'staging')), false, 'no unfiltered copy left while the run continues');
    assert.equal(existsSync(p.filteredDir), true);
    // Pretend this run was interrupted long ago: the next start removes it.
    assert.equal(sweepStaleRuns(root, Date.now() + STALE_RUN_MS + 1000), 1);
    assert.equal(existsSync(p.workDir), false);
  } finally {
    p.cleanup();
  }
});

test('review r2 P1-1 of #55: a stale run dir whose name holds `-` and `_` (base64url, as randomRunName makes) is swept too; every randomRunName is isRunName (mutant: sweep regex back to [A-Za-z0-9]+ -> 0 !== 1, red)', async () => {
  const { sweepStaleRuns, STALE_RUN_MS } = await import('../src/import-run.ts');
  const { isRunName, randomRunName } = await import('../src/run-dir.ts');
  const { existsSync } = await import('node:fs');
  const root = join(dir, 'work-p1-1');
  const p = await prepareImport({ inputs: inputs().filter((i) => i.kind === 'markdown'), scope: 'work', workRoot: root, home: dir, runName: () => 'a-b_c-d_e' });
  try {
    assert.equal(p.workDir, join(root, 'run-a-b_c-d_e'));
    assert.equal(sweepStaleRuns(root, Date.now() + STALE_RUN_MS + 1000), 1);
    assert.equal(existsSync(p.workDir), false, 'the stale dir and its filtered/ copy are gone');
  } finally {
    p.cleanup();
  }
  for (let i = 0; i < 2000; i++) assert.ok(isRunName(randomRunName()));
  assert.equal(isRunName('a/b'), false);
  assert.equal(isRunName('..'), false);
});
