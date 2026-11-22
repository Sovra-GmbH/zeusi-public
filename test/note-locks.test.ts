// Fix PR A (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md, "Addendum: Fix PR A"): standing
// rules from the `locks` frontmatter of active notes (src/note-locks.ts) in zeusi_startup, note
// locks in zeusi_context_for_task, decision link fields and source_note. Real server through the
// SDK Client + InMemoryTransport against PGlite (SET ROLE per connection); the lock notes are
// ingested by the real importVault as zeusi_mini_ingest. Synthetic fixtures only (invent=NO).
// No network, no Neon, no OpenAI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { importVault } from '../src/importers/vault.ts';
import { createMcpState, createZeusiMcpServer, type McpDeps, type ToolObservation } from '../src/mcp-server.ts';
import { isStandingPath, STANDING_LOCK_PREFIXES } from '../src/note-locks.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const WALLED = ['Plan', 'kiva synthetic wall probe'].join('');
const FAKE_HOST = ['ep-fake-777', '-pooler.eu-central-1.aws.neon.tech'].join('');
const SHA = 'cd'.repeat(32);
const WORK_SCOPE_ONLY = 'zeusi_test_locks_work_only';

const OPS_LOCK_1 = 'SYNTHETIC LOCK: no wombatdeploy on Fridays';
const OPS_LOCK_2 = 'SYNTHETIC LOCK: two reviewers for the quokka repo';
const META_INLINE = 'SYNTHETIC LOCK inline: numbat meta rule';
const PRODUCT_LOCK = 'SYNTHETIC LOCK: zeusi opensource prep waits for the security review';
const BLANKS_LOCK = 'SYNTHETIC LOCK: the only real item in a list with blanks';

const FILES: Record<string, string> = {
  'Work/ops/ops-rules.md': `---\ntitle: Ops rules (synthetic)\ndate: 2026-11-10\nstatus: locked\nlocks:\n  - ${OPS_LOCK_1}\n  - ${OPS_LOCK_2}\n---\n# Ops\n\nSynthetic body text that must never be returned by startup.\n`,
  'Work/handbook/meta-inline.md': `---\ntitle: Meta inline (synthetic)\ndate: 2026-11-12\nlocks: ${META_INLINE}\n---\n# Meta\n\nSynthetic.\n`,
  'Work/handbook/empty-locks.md': `---\ntitle: Empty locks (synthetic)\ndate: 2026-11-13\nlocks: []\n---\n# Empty\n\nSynthetic.\n`,
  'Work/handbook/blank-items.md': `---\ntitle: Blank items (synthetic)\ndate: 2026-11-05\nlocks:\n  - ""\n  - ${BLANKS_LOCK}\n  - "   "\n---\n# Blanks\n\nSynthetic.\n`,
  'Work/products/zeusi/product-lock.md': `---\ntitle: Zeusi opensource spec (synthetic)\ndate: 2026-11-16\nstatus: locked\nlocks:\n  - ${PRODUCT_LOCK}\n---\n# Spec\n\nSynthetic spec body, never returned.\n`,
  'Work/research/plain.md': '# Plain\n\nSynthetic note without locks.\n',
};

interface Env {
  db: Db;
  dir: string;
  vault: string;
  run: number;
  ingest(): Promise<void>;
  close(): Promise<void>;
}

async function fresh(): Promise<Env> {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-locks-'));
  const vault = join(dir, 'vault');
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(join(vault, rel)), { recursive: true });
    writeFileSync(join(vault, rel), text);
  }
  writeFileSync(join(dir, '.pg_service.conf'), `[zeusi_ro]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
  const config = validateSources(parseToml(`[[source]]\nname = "vault-all"\nkind = "vault_note"\nscope = "work"\nroot = "${vault}"\ninclude = ["**/*.md"]\n`), seedWall(), { home: dir });
  const db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('synthetic-owner', 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/synthetic-owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  const env: Env = {
    db, dir, vault, run,
    async ingest() {
      await db.exec('SET ROLE zeusi_mini_ingest');
      try {
        const r = await importVault({ db, config, mode: 'full', home: dir });
        assert.equal(r.counts.errors, 0);
      } finally {
        await db.exec('RESET ROLE');
      }
    },
    async close() {
      await db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
  await env.ingest();
  return env;
}

function asRole(db: Db, role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

interface Harness { call(name: string, args: Record<string, unknown>): Promise<{ text: string; json: Record<string, unknown>; isError: boolean }>; close(): Promise<void> }

async function mcp(e: Env, over: Partial<McpDeps> = {}): Promise<Harness> {
  const deps: McpDeps = {
    env: { HOME: e.dir }, home: e.dir, readService: 'zeusi_ro', connectRead: asRole(e.db, 'zeusi_box_ro'), embeddings: () => null,
    feedbackPath: join(e.dir, '.zeusi', 'search-feedback.jsonl'), queryLedgerPath: join(e.dir, '.zeusi', 'query-embed-ledger.json'), ...over,
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return {
    async call(name, args) {
      const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
      const text = r.content.map((c) => c.text ?? '').join('\n');
      return { text, json: r.isError ? {} : JSON.parse(text) as Record<string, unknown>, isError: r.isError === true };
    },
    close: async () => { await client.close(); await server.close(); },
  };
}

type Rule = { origin: string; subject: string | null; text: string; who?: string | null; scope: string; source_uri: string; source_ts: string; cite: string };

async function factRule(e: Env, text: string, uri: string): Promise<void> {
  await e.db.query(
    `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('rule', 'synthetic', $1, 'work', 'manual', $2, '2026-11-01T00:00:00Z', sha256(convert_to($2, 'UTF8')), $3)`, [text, uri, e.run]);
}

/** A lock note inserted directly (owner): for scope, wall and cap cases the importer would refuse or not produce. */
async function lockNote(e: Env, o: { path: string; title: string; locks: unknown; scope?: string; ts?: string; wallOff?: boolean; fm?: Record<string, unknown> }): Promise<void> {
  if (o.wallOff) await e.db.exec('ALTER TABLE zeusi.notes DISABLE TRIGGER zeusi_90_wall');
  try {
    await e.db.query(
      `INSERT INTO zeusi.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1, $2, $3::jsonb, 'synthetic body never returned', now(), $4::zeusi.scope, 'vault_note', 'vault:' || $1,
               $5::timestamptz, decode($6, 'hex'), $7)`,
      [o.path, o.title, JSON.stringify({ ...(o.fm ?? {}), locks: o.locks }), o.scope ?? 'work', o.ts ?? '2026-11-14T00:00:00Z', SHA, e.run]);
  } finally {
    if (o.wallOff) await e.db.exec('ALTER TABLE zeusi.notes ENABLE TRIGGER zeusi_90_wall');
  }
}

// ---------------------------------------------------------------------------
// The standing set

test('note locks: STANDING_LOCK_PREFIXES is exactly Work/ops/ and Work/handbook/; isStandingPath matches by prefix only', () => {
  assert.deepEqual([...STANDING_LOCK_PREFIXES], ['Work/ops/', 'Work/handbook/']);
  assert.ok(isStandingPath('Work/ops/x.md'));
  assert.ok(isStandingPath('Work/handbook/deep/y.md'));
  for (const p of ['Work/products/zeusi/x.md', 'Work/opsx/x.md', 'x/Work/ops/y.md', 'hq:team/x.md', 'team/40-ops/x.md']) assert.ok(!isStandingPath(p), p);
});

// ---------------------------------------------------------------------------
// zeusi_startup

test('startup: fact rules first, then verbatim lock items of standing notes (ingested by importVault), cited, who null; product locks and bodies absent; blanks skipped', async () => {
  const e = await fresh();
  try {
    await factRule(e, 'Synthetic fact rule: never merge without review.', 'manual:synthetic-fact-rule');
    const h = await mcp(e);
    try {
      const { text, json } = await h.call('zeusi_startup', {});
      const rules = json['rules'] as Rule[];
      assert.equal(rules[0]!.origin, 'fact');
      assert.match(rules[0]!.cite, /^manual:synthetic-fact-rule @ /);
      assert.match((rules[0] as unknown as { id: string }).id, /^manual:synthetic-fact-rule#fact-\d+$/);
      const locks = rules.filter((r) => r.origin === 'note_lock');
      // newest note first (source_ts from `date:`), in-note order kept
      assert.deepEqual(locks.map((r) => r.text), [META_INLINE, OPS_LOCK_1, OPS_LOCK_2, BLANKS_LOCK]);
      const ops = locks[1]! as unknown as Record<string, unknown>;
      // compact one-line form: id, origin, scope, text, source_uri, source_ts, cite (subject / who / ord dropped; ord is in the id)
      assert.deepEqual(ops, {
        id: 'vault:Work/ops/ops-rules.md#lock-1', origin: 'note_lock', scope: 'work', text: OPS_LOCK_1,
        source_uri: 'vault:Work/ops/ops-rules.md', source_ts: '2026-11-10T00:00:00.000Z',
        cite: 'vault:Work/ops/ops-rules.md @ 2026-11-10T00:00:00.000Z',
      });
      assert.ok(!text.includes(PRODUCT_LOCK), 'a non-standing lock is for context_for_task, not startup');
      assert.ok(!/Synthetic body text|never returned/.test(text), 'note bodies never cross');
      assert.equal(json['withheld'], 0);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('startup: a deleted lock note (file removed, re-ingested) no longer yields rules', async () => {
  const e = await fresh();
  try {
    rmSync(join(e.vault, 'Work/ops/ops-rules.md'));
    await e.ingest();
    assert.equal((await e.db.query<{ status: string }>(`SELECT status FROM zeusi.notes WHERE vault_path = 'Work/ops/ops-rules.md'`)).rows[0]!.status, 'deleted');
    const h = await mcp(e);
    try {
      const { text, json } = await h.call('zeusi_startup', {});
      assert.ok(!text.includes(OPS_LOCK_1) && !text.includes(OPS_LOCK_2));
      assert.deepEqual((json['rules'] as Rule[]).map((r) => r.text), [META_INLINE, BLANKS_LOCK]);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('startup: an empty focus is stated honestly (focus_message), and a recorded focus has none', async () => {
  const e = await fresh();
  try {
    const h = await mcp(e);
    try {
      const { json } = await h.call('zeusi_startup', {});
      assert.deepEqual(json['focus'], []);
      assert.match(String(json['focus_message']), /no current focus recorded/i);
      assert.match(String(json['focus_message']), /not .*(mean|proof)/i, 'never implies there is no focus');
      await e.db.query(
        `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ('state', 'focus', 'Synthetic focus.', 'work', 'manual', 'manual:focus', now(), sha256(convert_to('manual:focus', 'UTF8')), $1)`, [e.run]);
      const again = (await h.call('zeusi_startup', {})).json;
      assert.equal((again['focus'] as unknown[]).length, 1);
      assert.ok(!('focus_message' in again));
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('startup: facts first, then newest lock notes; 60 locks are all served (no 50 cap); a walled lock item is withheld and counted, in neither list', async () => {
  const e = await fresh();
  try {
    await factRule(e, 'Synthetic fact rule kept first.', 'manual:fact-first');
    const sixty = Array.from({ length: 60 }, (_, i) => `SYNTHETIC CAP LOCK ${i}`);
    await lockNote(e, { path: 'Work/handbook/cap.md', title: 'Cap (synthetic)', locks: sixty, ts: '2026-11-17T00:00:00Z' });
    const h = await mcp(e);
    try {
      const j = (await h.call('zeusi_startup', {})).json;
      const rules = j['rules'] as Rule[];
      assert.match(rules[0]!.cite, /^manual:fact-first @ /);
      const capLocks = rules.filter((r) => r.text.startsWith('SYNTHETIC CAP LOCK'));
      assert.deepEqual(capLocks.map((r) => r.text), sixty, 'every one of the 60, in note order');
      assert.equal(j['rules_remainder_count'], 0);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
  const w = await fresh();
  try {
    await lockNote(w, { path: 'Work/ops/walled.md', title: 'Walled (synthetic)', locks: [`lock ${WALLED}`, 'SYNTHETIC LOCK clean sibling'], ts: '2026-11-17T00:00:00Z', wallOff: true });
    const obs: ToolObservation[] = [];
    const h = await mcp(w, { observe: (o) => obs.push(o) });
    try {
      const { text, json } = await h.call('zeusi_startup', {});
      assert.equal(json['withheld'], 1);
      assert.ok((json['rules'] as Rule[]).some((r) => r.text === 'SYNTHETIC LOCK clean sibling'));
      assert.ok(!(json['rules_remainder'] as Array<{ id: string }>).some((r) => r.id.endsWith('walled.md#lock-1')), 'a walled rule is not listed in the remainder either');
      assert.doesNotMatch(text, /plankiva|wall probe/i);
      assert.deepEqual(obs.at(-1), { tool: 'zeusi_startup', hitCount: (json['rules'] as unknown[]).length + (json['decisions'] as unknown[]).length, withheld: 1, secretWithheld: 0 });
    } finally {
      await h.close();
    }
  } finally {
    await w.close();
  }
});

// ---------------------------------------------------------------------------
// Scope isolation (RLS) for startup and context_for_task

async function workScopeOnlyRole(e: Env): Promise<void> {
  await e.db.exec(`CREATE ROLE ${WORK_SCOPE_ONLY} NOLOGIN;
    GRANT USAGE ON SCHEMA zeusi TO ${WORK_SCOPE_ONLY};
    GRANT SELECT ON zeusi.notes, zeusi.facts, zeusi.facts_current, zeusi.decisions, zeusi.decisions_current, zeusi.people TO ${WORK_SCOPE_ONLY};
    CREATE POLICY test_locks_work_only ON zeusi.notes FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY test_locks_work_only ON zeusi.facts FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY test_locks_work_only ON zeusi.decisions FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY test_locks_work_only ON zeusi.people FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');`);
}

test('scope isolation: a product lock note is visible to zeusi_box_ro but never to a reader whose RLS reads team only (startup and context_for_task)', async () => {
  const e = await fresh();
  try {
    const TAPE = 'SYNTHETIC LOCK northbank: no wombatdeploy during London hours';
    await lockNote(e, { path: 'Work/ops/northbank-ops.md', title: 'Northbank ops (synthetic)', locks: [TAPE], scope: 'product', ts: '2026-11-17T00:00:00Z' });
    await workScopeOnlyRole(e);
    const all = await mcp(e);
    const narrow = await mcp(e, { connectRead: asRole(e.db, WORK_SCOPE_ONLY) });
    try {
      assert.ok((await all.call('zeusi_startup', {})).text.includes(TAPE), 'precondition: the reader with all scopes sees it');
      const s = await narrow.call('zeusi_startup', {});
      assert.ok(!s.isError, s.text);
      assert.ok(!s.text.includes(TAPE) && !s.text.includes('northbank-ops'));
      assert.ok(s.text.includes(OPS_LOCK_1), 'the shared lock is still there');
      const task = { task: 'plan the wombatdeploy' };
      assert.ok((await all.call('zeusi_context_for_task', task)).text.includes(TAPE));
      const c = await narrow.call('zeusi_context_for_task', task);
      assert.ok(!c.isError, c.text);
      assert.ok(!c.text.includes(TAPE));
      assert.ok((c.json['items'] as Array<{ exact_words: string }>).some((i) => i.exact_words === OPS_LOCK_1));
    } finally {
      await all.close();
      await narrow.close();
    }
  } finally {
    await e.close();
  }
});

// ---------------------------------------------------------------------------
// zeusi_context_for_task

type Item = {
  type: string; origin: string; id: number | null; kind: string; who: string | null; date: { said_at: string | null; source_ts: string };
  exact_words: string; exact_words_verbatim: boolean | null; applies_to: string[]; scope: string; source_uri: string; source_ts: string; cite: string;
  note_title?: string; linked_repo?: string | null; linked_pr?: number | null; linked_pr_uri?: string | null;
  source_note?: { source_uri: string; title: string; source_ts: string } | null;
};

async function decision(e: Env, o: { kind: string; words: string; uri: string; applies: string[]; repo?: string; pr?: number; ago?: string }): Promise<number> {
  return (await e.db.query<{ id: number }>(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind,
                                  source_uri, source_ts, source_sha256, ingest_run_id, linked_repo, linked_pr)
     VALUES ($1::zeusi.decision_kind, (SELECT id FROM zeusi.people WHERE handle = 'synthetic-owner'), now() - $8::interval, 'minute', $2, true,
             $3::text[], 'work', 'manual', $4, now() - $8::interval, sha256(convert_to($4 || $2, 'UTF8')), $5, $6, $7)
     RETURNING id::int AS id`,
    [o.kind, o.words, o.applies, o.uri, e.run, o.repo ?? null, o.pr ?? null, o.ago ?? '1 day'])).rows[0]!.id;
}

test('context_for_task: note locks of any folder match by task terms (lock text + note title) as kind lock, origin note_lock, id/who null; conflicts stay over decisions; task not echoed', async () => {
  const e = await fresh();
  try {
    const go = await decision(e, { kind: 'go', words: 'SYNTHETIC: go ahead with the zeusi opensource prep', uri: 'test:go-oss', applies: ['zeusi-oss'] });
    const stop = await decision(e, { kind: 'stop', words: 'SYNTHETIC: stop the zeusi opensource prep for now', uri: 'test:stop-oss', applies: ['zeusi-oss'] });
    const obs: ToolObservation[] = [];
    const h = await mcp(e, { observe: (o) => obs.push(o) });
    try {
      const { text, json } = await h.call('zeusi_context_for_task', { task: 'zeusi opensource prep (marker-task-4242)' });
      const items = json['items'] as Item[];
      const lock = items.find((i) => i.origin === 'note_lock')!;
      assert.ok(lock, text);
      assert.equal(lock.type, 'lock');
      assert.equal(lock.kind, 'lock');
      assert.equal(lock.id, null);
      assert.equal(lock.who, null);
      assert.equal(lock.exact_words, PRODUCT_LOCK);
      assert.equal(lock.exact_words_verbatim, null);
      assert.equal(lock.note_title, 'Zeusi opensource spec (synthetic)');
      assert.deepEqual(lock.applies_to, []);
      assert.equal(lock.source_uri, 'vault:Work/products/zeusi/product-lock.md');
      assert.equal(lock.date.said_at, null);
      assert.equal(lock.date.source_ts, lock.source_ts);
      assert.match(lock.cite, /^vault:Work\/products\/zeusi\/product-lock\.md @ 2026-11-16T00:00:00\.000Z \(note lock in "Zeusi opensource spec \(synthetic\)", who not recorded\)$/);
      const decs = items.filter((i) => i.origin === 'decision');
      assert.deepEqual(decs.map((d) => d.id).sort(), [go, stop].sort());
      for (const d of decs) assert.equal(d.type, 'decision');
      const conflicts = json['conflicts'] as Array<{ ids: number[] }>;
      assert.equal(conflicts.length, 1);
      assert.deepEqual([...conflicts[0]!.ids].sort(), [go, stop].sort());
      assert.ok(!text.includes('marker-task-4242'), 'the task is never echoed');
      assert.ok(!/never returned/.test(text), 'note bodies never cross');
      assert.deepEqual(obs.at(-1), { tool: 'zeusi_context_for_task', hitCount: items.length, withheld: 0, secretWithheld: 0 });
      // the title alone matches too
      // ("blank" is only in the note title "Blank items (synthetic)"; its lock text says "blanks")
      const byTitle = (await h.call('zeusi_context_for_task', { task: 'blank' })).json['items'] as Item[];
      assert.deepEqual(byTitle.map((i) => i.exact_words), [BLANKS_LOCK]);
      // nothing matches: honest empty list
      const none = (await h.call('zeusi_context_for_task', { task: 'xylophonequartz' })).json;
      assert.deepEqual(none['items'], []);
      assert.ok(typeof none['message'] === 'string');
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('context_for_task: the caller\'s scope argument narrows lock items too (review F4; RLS still decides visibility)', async () => {
  const e = await fresh();
  try {
    const TEAM_SCOPED = 'SYNTHETIC LOCK kiwiscope: team side';
    const TAPE_SCOPED = 'SYNTHETIC LOCK kiwiscope: northbank side';
    await lockNote(e, { path: 'Work/products/kiwi/team.md', title: 'Kiwi team (synthetic)', locks: [TEAM_SCOPED], scope: 'work' });
    await lockNote(e, { path: 'Work/products/kiwi/tape.md', title: 'Kiwi tape (synthetic)', locks: [TAPE_SCOPED], scope: 'product' });
    const h = await mcp(e);
    try {
      const words = async (args: Record<string, unknown>) => {
        const r = await h.call('zeusi_context_for_task', args);
        assert.ok(!r.isError, r.text);
        return (r.json['items'] as Item[]).filter((i) => i.origin === 'note_lock').map((i) => `${i.scope}|${i.exact_words}`).sort();
      };
      assert.deepEqual(await words({ task: 'kiwiscope' }), [`product|${TAPE_SCOPED}`, `work|${TEAM_SCOPED}`], 'no scope: both');
      assert.deepEqual(await words({ task: 'kiwiscope', scope: 'work' }), [`work|${TEAM_SCOPED}`]);
      assert.deepEqual(await words({ task: 'kiwiscope', scope: 'product' }), [`product|${TAPE_SCOPED}`]);
      assert.deepEqual(await words({ task: 'kiwiscope', scope: 'client' }), []);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('context_for_task: a walled lock item is withheld and counted; its clean sibling still returned', async () => {
  const e = await fresh();
  try {
    await lockNote(e, { path: 'Work/products/x/walled.md', title: 'Walled product (synthetic)', locks: [`gnuprep ${WALLED}`, 'SYNTHETIC gnuprep clean lock'], wallOff: true });
    const h = await mcp(e);
    try {
      const { text, json } = await h.call('zeusi_context_for_task', { task: 'gnuprep' });
      assert.equal(json['withheld'], 1);
      assert.deepEqual((json['items'] as Item[]).map((i) => i.exact_words), ['SYNTHETIC gnuprep clean lock']);
      assert.doesNotMatch(text, /plankiva|wall probe/i);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

// ---------------------------------------------------------------------------
// Decision links: linked_repo / linked_pr / source_note (no migration)

test('decision links: search, startup and context_for_task carry linked_repo, linked_pr, linked_pr_uri and source_note (title, never the body)', async () => {
  const e = await fresh();
  try {
    const id = await decision(e, {
      kind: 'go', words: 'SYNTHETIC: go for the kiwilink opensource prep', uri: 'vault:Work/products/zeusi/product-lock.md#decision-1',
      applies: ['zeusi'], repo: 'Synthetic-Org/zeusi', pr: 11,
    });
    await decision(e, { kind: 'go', words: 'SYNTHETIC: kiwilink without links', uri: 'hq:not-ingested', applies: [] });
    const h = await mcp(e);
    try {
      const want = (d: Item | Record<string, unknown>) => {
        assert.equal(d['linked_repo' as keyof typeof d], 'Synthetic-Org/zeusi');
        assert.equal(d['linked_pr' as keyof typeof d], 11);
        assert.equal(d['linked_pr_uri' as keyof typeof d], 'gh:Synthetic-Org/zeusi#11');
        assert.deepEqual(d['source_note' as keyof typeof d], {
          source_uri: 'vault:Work/products/zeusi/product-lock.md', title: 'Zeusi opensource spec (synthetic)', source_ts: '2026-11-16T00:00:00.000Z',
        });
      };
      const bare = (d: Record<string, unknown>) => {
        assert.equal(d['linked_repo'], null);
        assert.equal(d['linked_pr'], null);
        assert.equal(d['linked_pr_uri'], null);
        assert.equal(d['source_note'], null);
      };
      const s = await h.call('zeusi_search', { query: 'kiwilink' });
      const sd = s.json['decisions'] as Array<Record<string, unknown>>;
      want(sd.find((d) => d['source_uri'] === 'vault:Work/products/zeusi/product-lock.md#decision-1')!);
      bare(sd.find((d) => d['source_uri'] === 'hq:not-ingested')!);
      const st = await h.call('zeusi_startup', {});
      const std = st.json['decisions'] as Array<Record<string, unknown>>;
      want(std.find((d) => d['source_uri'] === 'vault:Work/products/zeusi/product-lock.md#decision-1')!);
      bare(std.find((d) => d['source_uri'] === 'hq:not-ingested')!);
      const c = await h.call('zeusi_context_for_task', { task: 'kiwilink' });
      const cd = (c.json['items'] as Item[]).find((i) => i.id === id)!;
      want(cd);
      for (const t of [s.text, st.text, c.text]) assert.ok(!/Synthetic spec body|never returned/.test(t), 'the note body never crosses');
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('decision links: source_note follows RLS (a reader that cannot see the note gets null, the decision itself stays)', async () => {
  const e = await fresh();
  try {
    await lockNote(e, { path: 'Work/products/product/spec.md', title: 'Northbank spec (synthetic)', locks: [], scope: 'product' });
    await decision(e, { kind: 'go', words: 'SYNTHETIC: go for the emuspec', uri: 'vault:Work/products/product/spec.md', applies: [] });
    await workScopeOnlyRole(e);
    const all = await mcp(e);
    const narrow = await mcp(e, { connectRead: asRole(e.db, WORK_SCOPE_ONLY) });
    try {
      const a = (await all.call('zeusi_search', { query: 'emuspec' })).json['decisions'] as Array<Record<string, unknown>>;
      assert.equal((a[0]!['source_note'] as { title: string }).title, 'Northbank spec (synthetic)');
      const n = await narrow.call('zeusi_startup', {});
      const nd = (n.json['decisions'] as Array<Record<string, unknown>>).find((d) => d['source_uri'] === 'vault:Work/products/product/spec.md')!;
      assert.equal(nd['source_note'], null);
      assert.ok(!n.text.includes('Northbank spec (synthetic)'));
    } finally {
      await all.close();
      await narrow.close();
    }
  } finally {
    await e.close();
  }
});

// ---------------------------------------------------------------------------
// Session-start gaps (docs/plans/2026-11-18-session-start-gaps-plan.md U2, U3, U5)

type Served = { id: string; text: string; scope: string; cite: string; source_uri: string; source_ts: string };
type Remainder = { id: string; subject: string; cite: string; reason: string };

test('startup U5: a Northbank lock marked standing_locks is a startup rule; its unmarked sibling is not, and context_for_task still returns it', async () => {
  const e = await fresh();
  try {
    await lockNote(e, {
      path: 'Work/products/product/synthetic-broker-rules.md', title: 'Synthetic broker onboarding rules', scope: 'product', ts: '2026-11-15T00:00:00Z',
      locks: ['SYNTHETIC PRODUCT: never ask a broker for a separate tick login', 'SYNTHETIC PRODUCT: wombat staging merge waits for the gate'],
      fm: { standing_locks: ['1'] },
    });
    await lockNote(e, {
      path: 'Work/products/product/synthetic-unmarked.md', title: 'Synthetic unmarked', scope: 'product', ts: '2026-11-15T00:00:00Z',
      locks: ['SYNTHETIC PRODUCT unmarked: numbat dashboards stay dark'],
    });
    const h = await mcp(e);
    try {
      const s = (await h.call('zeusi_startup', {})).json;
      const rules = s['rules'] as Served[];
      const t = rules.find((r) => r.text === 'SYNTHETIC PRODUCT: never ask a broker for a separate tick login');
      assert.ok(t, 'the marked lock is served');
      assert.equal(t.id, 'vault:Work/products/product/synthetic-broker-rules.md#lock-1');
      assert.equal(t.scope, 'product');
      assert.ok(!JSON.stringify(s).includes('wombat staging merge'), 'lock 2 is not marked: not a startup rule');
      assert.ok(!JSON.stringify(s).includes('numbat dashboards'), 'an unmarked Northbank note is not standing');
      assert.equal((s['rules_total'] as { note_lock: number }).note_lock, 5, '4 ops/meta locks + 1 marked Northbank lock');
      // ranking: team rules before the product one
      assert.ok(rules.findIndex((r) => r.scope === 'product') > rules.findIndex((r) => r.scope === 'work'));
      const c = await h.call('zeusi_context_for_task', { task: 'wombat staging merge gate' });
      assert.match(c.text, /wombat staging merge waits for the gate/, 'unpromoted current locks stay available to context_for_task');
      const o = (await h.call('zeusi_onboarding_status', {})).json['counts'] as Record<string, number>;
      assert.equal(o['rules'], 5, 'onboarding counts the same standing set');
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('startup U2 (reviewer check a): over the budget, every current standing rule is served or listed in rules_remainder with lookup ids; none in neither', async () => {
  const e = await fresh();
  try {
    const long = 'SYNTHETIC LONG LOCK ' + 'quokka '.repeat(120);
    const many = Array.from({ length: 220 }, (_, i) => `SYNTHETIC BUDGET LOCK ${i}: the wombat release train never leaves without two reviewers and a passing gate`);
    await lockNote(e, { path: 'Work/ops/budget.md', title: 'Budget probe (synthetic)', locks: [long, ...many], ts: '2026-11-17T00:00:00Z' });
    const h = await mcp(e);
    try {
      const s = (await h.call('zeusi_startup', {})).json;
      const served = s['rules'] as Served[];
      const rem = s['rules_remainder'] as Remainder[];
      const total = s['rules_total'] as { total: number; visible: number };
      assert.equal(total.total, 225, '4 fixture locks + 221 probe locks');
      assert.ok(rem.length > 0, 'the budget is exceeded');
      assert.equal(s['rules_served'], served.length);
      assert.equal(s['rules_remainder_count'], rem.length);
      assert.equal(served.length + rem.length, total.visible);
      const ids = new Set([...served.map((r) => r.id), ...rem.map((r) => r.id)]);
      assert.equal(ids.size, total.visible, 'no id in both lists');
      for (let ord = 1; ord <= 221; ord++) assert.ok(ids.has(`vault:Work/ops/budget.md#lock-${ord}`), `lock ${ord} is in neither list`);
      assert.ok(ids.has('vault:Work/ops/ops-rules.md#lock-1') && ids.has('vault:Work/handbook/meta-inline.md#lock-1'));
      const tooLong = rem.find((r) => r.id === 'vault:Work/ops/budget.md#lock-1')!;
      assert.equal(tooLong.reason, 'too_long');
      assert.equal(tooLong.subject, 'Budget probe (synthetic)');
      assert.equal(tooLong.cite, 'vault:Work/ops/budget.md @ 2026-11-17T00:00:00.000Z');
      assert.ok(!served.some((r) => r.text.startsWith('SYNTHETIC LONG LOCK')), 'never truncated into the served list');
      const budget = s['rules_budget'] as { tokens: number; used: number };
      assert.ok(budget.used <= budget.tokens);
      assert.match(String(s['rules_note']), /NOT dropped/);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('startup U3 (reviewer check c): a read connection lists no write tool; zeusi_startup is annotated read-only and runs as the read role', async () => {
  const e = await fresh();
  try {
    const deps: McpDeps = {
      env: { HOME: e.dir }, home: e.dir, readService: 'zeusi_ro', connectRead: asRole(e.db, 'zeusi_box_ro'), embeddings: () => null,
      feedbackPath: join(e.dir, '.zeusi', 'f.jsonl'), queryLedgerPath: join(e.dir, '.zeusi', 'q.json'),
    };
    const server = createZeusiMcpServer(deps, createMcpState());
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test', version: '0' });
    await Promise.all([server.connect(a), client.connect(b)]);
    try {
      const tools = (await client.listTools()).tools;
      assert.ok(!tools.some((t) => /log_decision/.test(t.name)), 'no write tool on a read connection');
      const st = tools.find((t) => t.name === 'zeusi_startup')!;
      assert.equal(st.annotations?.readOnlyHint, true);
      const r = (await client.callTool({ name: 'zeusi_startup', arguments: {} })) as { isError?: boolean };
      assert.ok(!r.isError);
      assert.equal((await e.db.query<{ u: string }>('SELECT current_user AS u')).rows[0]!.u, 'postgres', 'the read role was reset after the call');
    } finally {
      await client.close();
      await server.close();
    }
  } finally {
    await e.close();
  }
});

test('startup U6: focus is newest per (scope, subject); a withheld newest focus is counted and never lets an older same-subject focus pass as current', async () => {
  const e = await fresh();
  try {
    const focus = (subject: string, text: string, uri: string, ts: string) => e.db.query(
      `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('state', $1, $2, 'work', 'manual', $3, $4::timestamptz, sha256(convert_to($3, 'UTF8')), $5)`, [subject, text, uri, ts, e.run]);
    await focus('wombat', 'SYNTHETIC focus wombat v1', 'manual:f1', '2026-11-10T00:00:00Z');
    await focus('wombat', 'SYNTHETIC focus wombat v2', 'manual:f2', '2026-11-12T00:00:00Z');
    await focus('numbat', 'SYNTHETIC focus numbat', 'manual:f3', '2026-11-11T00:00:00Z');
    const h = await mcp(e);
    try {
      const s = (await h.call('zeusi_startup', {})).json;
      assert.deepEqual((s['focus'] as Array<{ text: string }>).map((f) => f.text), ['SYNTHETIC focus wombat v2', 'SYNTHETIC focus numbat']);
      assert.equal(s['focus_older_same_subject'], 1);
      // a newer wombat focus that the wall withholds: counted in withheld; v2 / v1 are NOT promoted to current
      await e.db.exec('ALTER TABLE zeusi.facts DISABLE TRIGGER zeusi_90_wall');
      try {
        await focus('wombat', `SYNTHETIC focus ${WALLED}`, 'manual:f4', '2026-11-14T00:00:00Z');
      } finally {
        await e.db.exec('ALTER TABLE zeusi.facts ENABLE TRIGGER zeusi_90_wall');
      }
      const s2 = (await h.call('zeusi_startup', {})).json;
      assert.deepEqual((s2['focus'] as Array<{ text: string }>).map((f) => f.text), ['SYNTHETIC focus numbat']);
      assert.equal(s2['withheld'], 1);
      assert.equal(s2['focus_older_same_subject'], 2);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('startup (review fix): the wall and secret check see the SERVED compact text; a code that only matches once a newline is collapsed is withheld', async () => {
  const e = await fresh();
  try {
    const code = ['48', '2913'].join(''); // built at runtime: no code-shaped literal in the repo
    const multi = `SYNTHETIC use the recovery\n${code}`;
    await lockNote(e, { path: 'Work/ops/multiline.md', title: 'Multiline (synthetic)', locks: [multi, 'SYNTHETIC LOCK clean multiline sibling'], ts: '2026-11-17T00:00:00Z', wallOff: true });
    const h = await mcp(e);
    try {
      const { text, json } = await h.call('zeusi_startup', {});
      assert.ok(!text.includes(code), 'the code never crosses');
      assert.equal(json['withheld'], 1);
      assert.ok((json['rules'] as Rule[]).some((r) => r.text === 'SYNTHETIC LOCK clean multiline sibling'));
      assert.ok(!(json['rules_remainder'] as Array<{ id: string }>).some((r) => r.id.endsWith('multiline.md#lock-1')));
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});
