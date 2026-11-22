// First-run onboarding status over MCP (plan U6, R16, R17, R23-R26, AE6): zeusi_onboarding_status
// + alias onboarding_status and the onboarding prompt. Real server through the SDK Client +
// InMemoryTransport against PGlite (SET ROLE per connection). Synthetic fixtures only. No network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { createMcpState, createZeusiMcpServer, mcpInstructions, type McpDeps, type ToolObservation } from '../src/mcp-server.ts';
import { CANNOT_RUN_IT, ONBOARDING_COUNT_KEYS, onboardingCounts } from '../src/onboarding.ts';
import { ABOUT_MARKDOWN } from '../src/about.ts';
import { withheld } from '../src/mcp-wall.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const FAKE_HOST = ['ep-fake-777', '-pooler.eu-central-1.aws.neon.tech'].join('');
const SHA = 'cd'.repeat(32);
const TEST_ROLE = 'zeusi_test_onboard_work_only';
const BODY_MARKER = 'onboarding-body-marker-4411';
const LOCK_MARKER = 'onboarding-lock-marker-4412';

let db: Db;
let home: string;
let run: number;

function asRole(role: string, log?: string[]): (service: string) => Promise<Db> {
  return async (service: string) => {
    log?.push(`${service}:${role}`);
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

interface Harness { client: Client; close: () => Promise<void> }

async function connect(over: Partial<McpDeps> = {}): Promise<Harness> {
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro', connectRead: asRole('zeusi_box_ro'), connectWrite: asRole('zeusi_box_rw'),
    embeddings: () => null, feedbackPath: join(home, '.zeusi', 'fb.jsonl'), queryLedgerPath: join(home, '.zeusi', 'ledger.json'),
    ...over,
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

type CallResult = { isError?: boolean; content: Array<{ type: string; text?: string }> };
const call = async (h: Harness, name: string, args: Record<string, unknown>) => (await h.client.callTool({ name, arguments: args })) as CallResult;
const textOf = (r: CallResult) => r.content.map((c) => c.text ?? '').join('\n');
type Status = { empty: boolean; scope: string; counts: Record<string, number>; capped: Record<string, boolean>; next?: { commands: string[]; honesty: string }; message: string };
const statusOf = (r: CallResult) => JSON.parse(textOf(r)) as Status;

async function note(path: string, scope: string, fm: Record<string, unknown> = {}): Promise<number> {
  return (await db.query<{ id: number }>(
    `INSERT INTO zeusi.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, 'Synthetic onboarding note', $2::jsonb, $3, now(), $4::zeusi.scope, 'manual', $5, now(), decode($6, 'hex'), $7)
     RETURNING id::int AS id`, [path, JSON.stringify(fm), `synthetic ${BODY_MARKER}`, scope, `test:${path}`, SHA, run])).rows[0]!.id;
}

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-onboard-status-'));
  const svc = (name: string, user: string) => `[${name}]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;
  writeFileSync(join(home, '.pg_service.conf'), [svc('zeusi_ro', 'zeusi_box_ro'), svc('zeusi_ingest', 'zeusi_mini_ingest')].join('\n'));
  db = await pgliteDb();
  await migrate(db);
  run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.exec(`CREATE ROLE ${TEST_ROLE} NOLOGIN;
    GRANT USAGE ON SCHEMA zeusi TO ${TEST_ROLE};
    GRANT SELECT ON zeusi.facts, zeusi.facts_current, zeusi.decisions, zeusi.decisions_current, zeusi.people, zeusi.notes, zeusi.chunks TO ${TEST_ROLE};
    CREATE POLICY t_work ON zeusi.facts FOR SELECT TO ${TEST_ROLE} USING (scope = 'work');
    CREATE POLICY t_work ON zeusi.decisions FOR SELECT TO ${TEST_ROLE} USING (scope = 'work');
    CREATE POLICY t_work ON zeusi.people FOR SELECT TO ${TEST_ROLE} USING (scope = 'work');
    CREATE POLICY t_work ON zeusi.notes FOR SELECT TO ${TEST_ROLE} USING (scope = 'work');
    CREATE POLICY t_work ON zeusi.chunks FOR SELECT TO ${TEST_ROLE} USING (scope = 'work');`);
});
after(async () => db.close());

test('onboarding (AE6): an empty database reports empty: true, every count 0, the CLI commands (dry run first) and the honest "cannot run it" line', async () => {
  const obs: ToolObservation[] = [];
  const h = await connect({ observe: (o) => obs.push(o) });
  try {
    const r = await call(h, 'zeusi_onboarding_status', {});
    assert.ok(!r.isError, textOf(r));
    const s = statusOf(r);
    assert.equal(s.empty, true);
    assert.equal(s.scope, 'all visible');
    assert.deepEqual(Object.keys(s.counts).sort(), [...ONBOARDING_COUNT_KEYS].sort());
    for (const k of ONBOARDING_COUNT_KEYS) {
      assert.equal(s.counts[k], 0, k);
      assert.equal(s.capped[k], false, k);
    }
    assert.ok(s.next!.commands.every((c) => c.startsWith('zeusi onboard ') && !c.includes('--real')));
    assert.equal(s.next!.honesty, CANNOT_RUN_IT);
    assert.match(CANNOT_RUN_IT, /cannot force a model to run anything/);
    assert.match(CANNOT_RUN_IT, /the user runs `zeusi onboard` locally/);
    assert.equal(withheld([textOf(r)]), false, 'the fixed guidance passes the wall');
    assert.deepEqual(obs, [{ tool: 'zeusi_onboarding_status', hitCount: 0, withheld: 0, secretWithheld: 0 }]);
  } finally {
    await h.close();
  }
});

test('onboarding: a personal-scope row only is invisible to the reader (RLS): still empty', async () => {
  const id = await note('onboard/personal.md', 'personal');
  const h = await connect();
  try {
    assert.equal(statusOf(await call(h, 'zeusi_onboarding_status', {})).empty, true);
  } finally {
    await h.close();
    await db.query(`DELETE FROM zeusi.notes WHERE id = $1`, [id]);
  }
});

test('onboarding (AE6): one visible decision makes empty false with decisions 1; the alias answers the same; no row text or content uri is returned', async () => {
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('synthetic-owner', 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/synthetic-owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  await db.query(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to,
                                  scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('lock', (SELECT id FROM zeusi.people WHERE handle = 'synthetic-owner'), now(), 'minute', $1, false, '{}',
             'product', 'manual', 'test:onboard-decision', now(), decode($2, 'hex'), $3)`, [`SYNTHETIC ${BODY_MARKER}`, SHA, run]);
  const h = await connect();
  try {
    const a = await call(h, 'zeusi_onboarding_status', {});
    const b = await call(h, 'onboarding_status', {});
    const s = statusOf(a);
    assert.equal(s.empty, false);
    assert.equal(s.counts['decisions'], 1);
    assert.equal(s.next, undefined);
    assert.match(s.message, /optional/);
    assert.equal(textOf(a), textOf(b), 'alias parity');
    for (const bad of [BODY_MARKER, 'test:onboard-decision', 'synthetic-owner']) assert.ok(!textOf(a).includes(bad), bad);
  } finally {
    await h.close();
  }
});

test('onboarding: notes, note lock items, chunks and facts (rules / focus) are counted; scope narrows; a team-only reader sees none of the product rows', async () => {
  const n1 = await note('onboard/a.md', 'product', { locks: [`lock one ${LOCK_MARKER}`, 'lock two', ' '] });
  await note('onboard/b.md', 'product', { locks: 'single lock' });
  await db.query(`INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, scope, source_kind, source_uri)
                  VALUES ($1, 0, NULL, $2, sha256(convert_to($2, 'UTF8')), 3, 'product', 'manual', 'test:onboard/a.md#c0')`, [n1, `chunk ${BODY_MARKER}`]);
  for (const [kind, subject] of [['rule', 'r1'], ['state', 'f1'], ['other', 'o1']] as const) {
    await db.query(`INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                    VALUES ($1, $2, 'synthetic fact', 'product', 'manual', $3, now(), decode($4, 'hex'), $5)`, [kind, subject, `test:fact-${subject}`, SHA, run]);
  }
  const h = await connect();
  try {
    const all = statusOf(await call(h, 'zeusi_onboarding_status', {}));
    // rules = fact rules + CURRENT standing note locks (onboard/ is not a standing folder): 1 + 0.
    assert.deepEqual(all.counts, {
      facts: 3, rules: 1, focus: 1, notes: 2, note_locks: 3, note_locks_current: 3, note_locks_superseded: 0, note_locks_expired: 0, chunks: 1, decisions: 1,
    });
    const team = statusOf(await call(h, 'zeusi_onboarding_status', { scope: 'work' }));
    assert.equal(team.empty, true);
    assert.equal(team.scope, 'work');
    const tape = statusOf(await call(h, 'onboarding_status', { scope: 'product' }));
    assert.equal(tape.counts['notes'], 2);
    assert.ok(!JSON.stringify(all).includes(LOCK_MARKER) && !JSON.stringify(all).includes(BODY_MARKER));
  } finally {
    await h.close();
  }
  const narrow = await connect({ connectRead: asRole(TEST_ROLE) });
  try {
    // The test role is not a login the read gate accepts by name, so the service still says
    // zeusi_box_ro (the gate checks the configured login offline); RLS on the role decides rows.
    const s = statusOf(await call(narrow, 'zeusi_onboarding_status', {}));
    assert.equal(s.empty, true, 'scope isolation: product rows are invisible to a team-only reader');
    for (const k of ONBOARDING_COUNT_KEYS) assert.equal(s.counts[k], 0, k);
  } finally {
    await narrow.close();
  }
});

test('onboarding: each count is capped (LIMIT cap+1 subquery) and flagged', async () => {
  await db.exec('SET ROLE zeusi_box_ro');
  try {
    await db.exec('BEGIN READ ONLY');
    const s = await onboardingCounts(db, null, 2);
    await db.exec('ROLLBACK');
    assert.equal(s.counts['note_locks'], 2);
    assert.equal(s.capped['note_locks'], true);
    assert.equal(s.counts['facts'], 2);
    assert.equal(s.capped['facts'], true);
    assert.equal(s.counts['chunks'], 1);
    assert.equal(s.capped['chunks'], false);
  } finally {
    await db.exec('RESET ROLE');
  }
});

test('onboarding: the real cap is 10 000 (10 001 chunks report 10 000 with capped true)', async () => {
  const nid = await note('onboard/bulk.md', 'work');
  await db.exec('ALTER TABLE zeusi.chunks DISABLE TRIGGER zeusi_90_wall');
  try {
    await db.query(`INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, scope, source_kind, source_uri)
                    SELECT $1, g, NULL, 'bulk', sha256(convert_to('bulk', 'UTF8')), 1, 'work', 'manual', 'test:bulk#c' || g FROM generate_series(1, 10001) g`, [nid]);
  } finally {
    await db.exec('ALTER TABLE zeusi.chunks ENABLE TRIGGER zeusi_90_wall');
  }
  const h = await connect();
  try {
    const s = statusOf(await call(h, 'zeusi_onboarding_status', { scope: 'work' }));
    assert.equal(s.counts['chunks'], 10_000);
    assert.equal(s.capped['chunks'], true);
  } finally {
    await h.close();
    await db.query(`DELETE FROM zeusi.chunks WHERE note_id = $1`, [nid]);
    await db.query(`DELETE FROM zeusi.notes WHERE id = $1`, [nid]);
  }
});

test('onboarding: strict schema (unknown key, bad scope) refused without echo; the read gate refuses a non-read login before connecting', async () => {
  const h = await connect();
  try {
    const a = await call(h, 'zeusi_onboarding_status', { scope: 'personal' });
    assert.equal(a.isError, true);
    const b = await call(h, 'onboarding_status', { sneaky_key_5151: 1 });
    assert.equal(b.isError, true);
    assert.ok(!textOf(b).includes('sneaky_key_5151'));
  } finally {
    await h.close();
  }
  const connects: string[] = [];
  const g = await connect({ readService: 'zeusi_ingest', connectRead: asRole('zeusi_box_ro', connects) });
  try {
    const r = await call(g, 'zeusi_onboarding_status', {});
    assert.equal(r.isError, true);
    assert.match(textOf(r), /read-only login/);
    assert.deepEqual(connects, [], 'nothing connected');
  } finally {
    await g.close();
  }
});

test('onboarding: listed read-only for every class (read, write without service, write with service); instructions point at it with the honest line', async () => {
  for (const over of [{ toolClass: 'read' as const }, {}, { writeService: 'zeusi_rw' }]) {
    const h = await connect(over);
    try {
      const tools = (await h.client.listTools()).tools;
      for (const n of ['zeusi_onboarding_status', 'onboarding_status']) {
        const t = tools.find((x) => x.name === n);
        assert.ok(t, n);
        assert.equal(t.annotations?.readOnlyHint, true, n);
      }
      const ins = h.client.getInstructions() ?? '';
      assert.match(ins, /if zeusi_onboarding_status says empty, offer the onboarding prompt; the import is a CLI the user runs\./i);
      assert.ok(ins.includes(CANNOT_RUN_IT));
      assert.match(ins, /onboarding_status = zeusi_onboarding_status/);
    } finally {
      await h.close();
    }
  }
  for (const w of [true, false]) assert.ok(mcpInstructions(w).includes(CANNOT_RUN_IT));
  for (const n of ['zeusi_onboarding_status', 'onboarding_status', 'Prompt onboarding']) assert.ok(ABOUT_MARKDOWN.includes(n), n);
});

test('onboarding prompt: names zeusi_onboarding_status, the dry-run command and "cannot run it"; names no write tool; never claims a run', async () => {
  const h = await connect({ writeService: 'zeusi_rw' });
  try {
    const { prompts } = await h.client.listPrompts();
    const p = prompts.find((x) => x.name === 'onboarding');
    assert.ok(p);
    assert.deepEqual(p.arguments ?? [], []);
    const g = await h.client.getPrompt({ name: 'onboarding', arguments: {} });
    const t = (g.messages[0]!.content as { text: string }).text;
    assert.match(t, /zeusi_onboarding_status/);
    assert.match(t, /zeusi onboard --markdown <notes-folder> --scope work/);
    assert.match(t, /dry run/);
    assert.match(t, /cannot run the import for you/);
    assert.match(t, /Never claim that you ran an import/);
    assert.match(t, /names, emails and phone numbers are not detected/);
    assert.doesNotMatch(t, /log_decision/);
    assert.doesNotMatch(t, /--real --/);
    assert.equal(withheld([t]), false);
  } finally {
    await h.close();
  }
});
