// zeusi_context_for_task core (src/context-for-task.ts, plan U2): task terms, candidate SQL on
// decisions_current (PGlite as zeusi_box_ro: RLS, scope), pure ranking and conflicts. Every
// decision here is a clearly SYNTHETIC fixture (invent=NO: no real owner words). No network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import {
  findConflicts, MAX_TERMS, queryCandidates, rankForTask, taskTerms, type CandidateRow,
} from '../src/context-for-task.ts';

const SHA = 'cd'.repeat(32);
let db: Db;
const ids: Record<string, number> = {};

async function as<T>(role: string, fn: () => Promise<T>): Promise<T> {
  await db.exec(`SET ROLE ${role}`);
  try {
    await db.exec('BEGIN READ ONLY');
    try {
      return await fn();
    } finally {
      await db.exec('ROLLBACK');
    }
  } finally {
    await db.exec('RESET ROLE');
  }
}

const candidates = (task: string, scope: string | null = null, role = 'zeusi_box_ro') =>
  as(role, () => queryCandidates(db, taskTerms(task), task, scope));
const ranked = async (task: string, scope: string | null = null, role = 'zeusi_box_ro') => rankForTask(await candidates(task, scope, role), task, new Date());

before(async () => {
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('synthetic-owner', 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/synthetic-owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  const dec = async (key: string, o: { words: string; uri: string; kind?: string; scope?: string; applies?: string[]; ago?: string; expires?: string | null }) => {
    ids[key] = (await db.query<{ id: number }>(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, expires_at,
                                    scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1::zeusi.decision_kind, (SELECT id FROM zeusi.people WHERE handle = 'synthetic-owner'), now() - $2::interval, 'minute', $3, false,
               $4::text[], $5::timestamptz, $6::zeusi.scope, 'manual', $7, now() - $2::interval, sha256(convert_to($7 || $3, 'UTF8')), $8)
       RETURNING id::int AS id`,
      [o.kind ?? 'go', o.ago ?? '1 day', o.words, o.applies ?? [], o.expires ?? null, o.scope ?? 'work', o.uri, run])).rows[0]!.id;
  };
  // AE1: synthetic London/NY-hours lock (fixture wording, not the owner's).
  await dec('lock', { kind: 'lock', words: 'SYNTHETIC FIXTURE: no Northbank prod promotion during London/NY market hours', uri: 'test:lock-ldn-ny', applies: ['northbank', 'prod'], ago: '20 days', scope: 'product' });
  await dec('goTape', { kind: 'go', words: 'SYNTHETIC FIXTURE: go ahead with the Northbank dashboard', uri: 'test:go-northbank', applies: ['northbank'], ago: '2 days', scope: 'product' });
  await dec('park', { kind: 'park', words: 'SYNTHETIC FIXTURE: park the wombat billing export', uri: 'test:park-wombat', applies: ['wombat-billing'], ago: '5 days' });
  await dec('old', { kind: 'ruling', words: 'SYNTHETIC FIXTURE: pelican release uses plan A', uri: 'test:old', applies: ['pelican'], ago: '30 days' });
  await dec('new', { kind: 'ruling', words: 'SYNTHETIC FIXTURE: pelican release uses plan B', uri: 'test:new', applies: ['pelican'], ago: '3 days' });
  await db.query(`SELECT zeusi.supersede_decision($1, $2)`, [ids['old'], ids['new']]);
  await dec('expired', { kind: 'lock', words: 'SYNTHETIC FIXTURE: pelican freeze', uri: 'test:expired', applies: ['pelican'], expires: new Date(Date.now() - 3_600_000).toISOString() });
  await dec('personal', { kind: 'lock', words: 'SYNTHETIC FIXTURE: personal pelican lock', uri: 'test:personal', applies: ['pelican'], scope: 'personal' });
  await dec('disjointGo', { kind: 'go', words: 'SYNTHETIC FIXTURE: go for the otter migration', uri: 'test:otter-go', applies: ['otter'] });
  await dec('disjointLock', { kind: 'lock', words: 'SYNTHETIC FIXTURE: lock the otter docs wording', uri: 'test:otter-lock', applies: ['otter-docs'] });
});
after(async () => db.close());

// ---------------------------------------------------------------------------
// taskTerms

test('context terms: lower-case, stopwords dropped, deduped, letters and digits only; operators never survive', () => {
  assert.deepEqual(taskTerms('Promote Northbank to prod'), ['promote', 'northbank', 'prod']);
  assert.deepEqual(taskTerms('the and to of bitte und'), [], 'only stopwords: no terms, no query');
  assert.deepEqual(taskTerms('prod PROD Prod'), ['prod']);
  const t = taskTerms(`a&b | c!d :* "quoted" (paren) 'x' \\ % _ ; -- DROP`);
  for (const term of t) assert.match(term, /^[\p{L}\p{N}]+$/u, term);
  assert.ok(!t.some((x) => /[&|!:*"'()\\%_;-]/.test(x)));
  assert.ok(taskTerms('w'.repeat(65)).length === 0, 'over 64 characters dropped');
  const long = Array.from({ length: 900 }, (_, i) => `term${i}`).join(' ').slice(0, 4000);
  assert.ok(taskTerms(long).length <= MAX_TERMS);
  assert.deepEqual(taskTerms('Ｎｏｒｔｈｂａｎｋ'), ['northbank'], 'NFKC');
});

// ---------------------------------------------------------------------------
// SQL + ranking

test('context AE1: the synthetic London/NY lock ranks first for "promote Northbank to prod", with id, who, said_at, source_uri, source_ts', async () => {
  const r = await ranked('promote Northbank to prod');
  assert.ok(r.length >= 1);
  const top = r[0]!;
  assert.equal(top.id, ids['lock']);
  assert.equal(top.kind, 'lock');
  assert.equal(top.who, 'synthetic-owner');
  assert.match(top.saidAt, /^\d{4}-\d\d-\d\dT/);
  assert.equal(top.sourceUri, 'test:lock-ldn-ny');
  assert.match(top.sourceTs, /^\d{4}-\d\d-\d\dT/);
  assert.deepEqual(top.matchedAppliesTo.sort(), ['northbank', 'prod']);
});

test('context AE2: an unrelated task returns nothing (no invented item, no conflict)', async () => {
  const r = await ranked('quarterly penguin census');
  assert.deepEqual(r, []);
  assert.deepEqual(findConflicts([]), []);
  assert.deepEqual(await candidates('the to of and'), [], 'stopword-only task: no query');
});

test('context AE3: a superseded decision is absent and its replacement present; an expired one is absent; personal never reaches the reader', async () => {
  const r = await ranked('pelican release plan');
  const got = r.map((x) => x.id);
  assert.ok(got.includes(ids['new']!));
  assert.ok(!got.includes(ids['old']!), 'superseded');
  assert.ok(!got.includes(ids['expired']!), 'expired');
  assert.ok(!got.includes(ids['personal']!), 'personal hidden by RLS');
  // the owner (migration role, no RLS) does see the personal one: proves RLS did the hiding
  const owner = rankForTask(await (async () => {
    await db.exec('BEGIN READ ONLY');
    try { return await queryCandidates(db, taskTerms('pelican'), 'pelican', null); } finally { await db.exec('ROLLBACK'); }
  })(), 'pelican', new Date());
  assert.ok(owner.some((x) => x.id === ids['personal']));
});

test('context scope: scope narrows candidates (product lock absent under scope team)', async () => {
  assert.ok((await ranked('promote Northbank to prod', 'product')).some((x) => x.id === ids['lock']));
  assert.ok(!(await ranked('promote Northbank to prod', 'work')).some((x) => x.id === ids['lock']));
});

test('context: applies_to matches as a whole word or phrase of the task ("wombat-billing")', async () => {
  const r = await ranked('fix the wombat-billing job');
  assert.equal(r[0]!.id, ids['park']);
  assert.deepEqual(r[0]!.matchedAppliesTo, ['wombat-billing']);
});

// ---------------------------------------------------------------------------
// Pure ranking and conflicts

const row = (o: Partial<CandidateRow> & { id: number }): CandidateRow => ({
  kind: 'go', who: 'w', saidAt: '2026-11-01T00:00:00.000Z', exactWords: 'alpha beta', exactWordsVerbatim: false, appliesTo: [],
  expiresAt: null, scope: 'work', sourceUri: `test:${o.id}`, sourceTs: '2026-11-01T00:00:00.000Z', ...o,
});
const NOW = new Date('2026-11-17T00:00:00Z');

test('context rank: with equal text match a lock outranks a go; with equal kind the newer ranks higher; applies_to beats body-only', () => {
  assert.deepEqual(rankForTask([row({ id: 1, kind: 'go' }), row({ id: 2, kind: 'lock' })], 'alpha', NOW).map((r) => r.id), [2, 1]);
  assert.deepEqual(rankForTask([row({ id: 1, kind: 'park' }), row({ id: 2, kind: 'ruling' })], 'alpha', NOW).map((r) => r.id), [1, 2]);
  assert.deepEqual(rankForTask([
    row({ id: 1, saidAt: '2026-01-01T00:00:00.000Z' }), row({ id: 2, saidAt: '2026-11-10T00:00:00.000Z' }),
  ], 'alpha', NOW).map((r) => r.id), [2, 1]);
  assert.deepEqual(rankForTask([
    row({ id: 1, kind: 'lock', exactWords: 'alpha words' }), row({ id: 2, kind: 'go', exactWords: 'other words', appliesTo: ['alpha'] }),
  ], 'alpha', NOW).map((r) => r.id), [2, 1]);
  assert.deepEqual(rankForTask([row({ id: 1, exactWords: 'gamma' })], 'alpha', NOW), [], 'no relevance: dropped');
});

test('context AE4: a go and a lock sharing applies_to conflict (ids + shared target only); disjoint targets or same-side kinds do not', async () => {
  const items = [
    { id: 1, kind: 'go', applies_to: ['Northbank'] }, { id: 2, kind: 'lock', applies_to: ['northbank', 'prod'] },
    { id: 3, kind: 'go', applies_to: ['otter'] }, { id: 4, kind: 'lock', applies_to: ['otter-docs'] },
    { id: 5, kind: 'ruling', applies_to: ['northbank'] },
  ];
  assert.deepEqual(findConflicts(items), [{ ids: [1, 2], kinds: ['go', 'lock'], applies_to: ['northbank'] }]);
  assert.deepEqual(findConflicts([{ id: 1, kind: 'lock', applies_to: ['x'] }, { id: 2, kind: 'park', applies_to: ['x'] }]), []);
  // on the fixture: the Northbank go and the Northbank lock are both current and conflict
  const r = await ranked('Northbank');
  const shaped = r.map((x) => ({ id: x.id, kind: x.kind, applies_to: x.appliesTo }));
  assert.ok(shaped.some((x) => x.id === ids['goTape']) && shaped.some((x) => x.id === ids['lock']));
  assert.deepEqual(findConflicts(shaped).map((c) => c.applies_to), [['northbank']]);
  // otter go vs otter-docs lock: disjoint targets, no conflict
  const o = (await ranked('otter migration docs')).map((x) => ({ id: x.id, kind: x.kind, applies_to: x.appliesTo }));
  assert.deepEqual(findConflicts(o), []);
});
