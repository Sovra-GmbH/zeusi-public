// Lock-lifecycle addendum (docs/note-locks.md): explicit lock-level supersession and expiry,
// resolved at read time (src/lock-lifecycle.ts), and ONE rule definition shared by zeusi_startup
// and zeusi_onboarding_status. Pure resolver tests, then the real server (SDK Client +
// InMemoryTransport) against PGlite with SET ROLE per connection. Synthetic fixtures only
// (invent=NO). No network, no Neon, no OpenAI.
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
import {
  lockItemsOf, parseLockUntil, parseStandingMarker, parseSupersede, parseUntil, resolveLockLifecycle, zurichMidnight, type LockNoteInput,
} from '../src/lock-lifecycle.ts';
import { currentStandingLocks, isStandingLock } from '../src/note-locks.ts';
import { RULES_DEFINITION } from '../src/onboarding.ts';
import { SOURCES_OF_RULES_FACTS_FOCUS, aboutMarkdown } from '../src/about.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const NOW = new Date('2026-11-17T12:00:00Z');
const FAKE_HOST = ['ep-fake-777', '-pooler.eu-central-1.aws.neon.tech'].join('');
const SHA = 'ab'.repeat(32);
const WORK_SCOPE_ONLY = 'zeusi_test_lifecycle_work_only';

// ---------------------------------------------------------------------------
// Grammar (pure)

test('lifecycle grammar: supersedes items (lock-level, whole-note, own-ordinal prefix, alias / heading stripped); malformed is null', () => {
  assert.deepEqual(parseSupersede('[[2026-10-29-old-locks]] lock 2'), { ownOrd: null, target: '2026-10-29-old-locks', ord: 2 });
  assert.deepEqual(parseSupersede('  [[Work/ops/old.md|Old]]  '), { ownOrd: null, target: 'Work/ops/old.md', ord: null });
  assert.deepEqual(parseSupersede('1: [[old#Locks]] lock 3'), { ownOrd: 1, target: 'old', ord: 3 });
  assert.deepEqual(parseSupersede('[[old]] LOCKS 4'), { ownOrd: null, target: 'old', ord: 4 });
  for (const bad of ['old lock 2', '[[old]] lock', '[[old]] lock 0', '0: [[old]]', '[[old]] lock 2 and more', '[[ ]]', '', '[[a]] [[b]]']) {
    assert.equal(parseSupersede(bad), null, bad);
  }
});

test('lifecycle grammar: until = ISO with offset as is; a date = end of that day Europe/Zurich (incl. the 25 Oct 2026 DST day); no offset / bad date = null', () => {
  assert.equal(parseUntil('2026-10-25T00:00+02:00')!.toISOString(), '2026-10-24T22:00:00.000Z');
  assert.equal(parseUntil('2026-10-25T00:00:00Z')!.toISOString(), '2026-10-25T00:00:00.000Z');
  // CEST (+02:00) on 24 Oct: the day ends 25 Oct 00:00+02:00
  assert.equal(parseUntil('2026-10-24')!.toISOString(), '2026-10-24T22:00:00.000Z');
  // 25 Oct 2026 is the DST day (03:00 CEST -> 02:00 CET, 25 hours): it ends 26 Oct 00:00+01:00
  assert.equal(parseUntil('2026-10-25')!.toISOString(), '2026-10-25T23:00:00.000Z');
  assert.equal(parseUntil('2026-10-25')!.getTime() - parseUntil('2026-10-24')!.getTime(), 25 * 3600_000);
  // spring forward (29 Mar 2026, 23 hours) and a winter day
  assert.equal(parseUntil('2026-03-29')!.getTime() - parseUntil('2026-03-28')!.getTime(), 23 * 3600_000);
  assert.equal(parseUntil('2026-12-31')!.toISOString(), '2026-12-31T23:00:00.000Z');
  assert.equal(zurichMidnight(2026, 10, 25).toISOString(), '2026-10-24T22:00:00.000Z');
  for (const bad of ['2026-10-25T00:00', '2026-02-30', 'next week', '25.10.2026', '2026-10-25T00:00+0200x']) assert.equal(parseUntil(bad), null, bad);
  assert.deepEqual(parseLockUntil('1: 2026-10-25T00:00+02:00'), { ord: 1, until: new Date('2026-10-24T22:00:00Z') });
  for (const bad of ['2026-10-25', '0: 2026-10-25', 'x: 2026-10-25', '1: soon']) assert.equal(parseLockUntil(bad), null, bad);
});

test('lifecycle: lock items keep their 1-based list position (blanks skipped); a single string is one item', () => {
  assert.deepEqual(lockItemsOf(['', 'a', '  ', 'b']), [{ ord: 2, text: 'a' }, { ord: 4, text: 'b' }]);
  assert.deepEqual(lockItemsOf('solo'), [{ ord: 1, text: 'solo' }]);
  assert.deepEqual(lockItemsOf(null), []);
  assert.deepEqual(lockItemsOf({ x: 1 }), []);
});

// ---------------------------------------------------------------------------
// Resolver (pure)

let nid = 0;
function n(o: Partial<LockNoteInput> & { path: string; ts: string }): LockNoteInput {
  const path = o.path;
  return {
    noteId: o.noteId ?? ++nid, vaultPath: path, title: o.title ?? path.split('/').pop()!.replace(/\.md$/, ''), scope: o.scope ?? 'work',
    sourceUri: `vault:${path}`, sourceTs: new Date(o.ts).toISOString(), locks: o.locks ?? null, supersedes: o.supersedes ?? null,
    lockUntil: o.lockUntil ?? null, until: o.until ?? null,
  };
}
const status = (r: ReturnType<typeof resolveLockLifecycle>) => r.locks.map((l) => `${l.vaultPath}:${l.ord}=${l.status}`).sort();

test('resolver: lock-level supersession by a newer note; the old lock links forward (superseded_by), the new one back (supersedes)', () => {
  const old = n({ path: 'Work/ops/2026-10-29-old.md', ts: '2026-10-29', locks: ['old one', 'old two (replaced)', 'old three'] });
  const neu = n({ path: 'Work/ops/2026-11-11-new.md', ts: '2026-11-11', locks: ['new one (replaces old two)', 'new two'], supersedes: ['1: [[2026-10-29-old]] lock 2'] });
  const r = resolveLockLifecycle([old, neu], NOW);
  assert.deepEqual(status(r), [
    'Work/ops/2026-10-29-old.md:1=current', 'Work/ops/2026-10-29-old.md:2=superseded', 'Work/ops/2026-10-29-old.md:3=current',
    'Work/ops/2026-11-11-new.md:1=current', 'Work/ops/2026-11-11-new.md:2=current',
  ]);
  const victim = r.locks.find((l) => l.status === 'superseded')!;
  assert.deepEqual(victim.supersededBy, { note_title: '2026-11-11-new', ord: 1, text: 'new one (replaces old two)', source_uri: neu.sourceUri, source_ts: neu.sourceTs });
  const head = r.locks.find((l) => l.noteId === neu.noteId && l.ord === 1)!;
  assert.deepEqual(head.supersedes, [{ note_title: '2026-10-29-old', ord: 2, text: 'old two (replaced)', source_uri: old.sourceUri, source_ts: old.sourceTs }]);
  assert.deepEqual(r.locks.find((l) => l.noteId === neu.noteId && l.ord === 2)!.supersedes, [], 'own-ordinal claim: only lock 1 carries it');
  assert.equal(r.counts.supersede_applied, 1);
  assert.equal(r.counts.current + r.counts.superseded + r.counts.expired, r.counts.items);
});

test('resolver: whole-note supersession (no `lock N`) retires every lock of the target; a note-level claim is carried by every lock of the claimant', () => {
  const old = n({ path: 'Work/handbook/a.md', ts: '2026-09-01', locks: ['a1', 'a2'] });
  const neu = n({ path: 'Work/handbook/b.md', ts: '2026-09-02', locks: ['b1', 'b2'], supersedes: '[[Work/handbook/a.md]]' });
  const r = resolveLockLifecycle([neu, old], NOW);
  assert.deepEqual(status(r), ['Work/handbook/a.md:1=superseded', 'Work/handbook/a.md:2=superseded', 'Work/handbook/b.md:1=current', 'Work/handbook/b.md:2=current']);
  for (const l of r.locks.filter((x) => x.noteId === neu.noteId)) assert.deepEqual(l.supersedes.map((s) => s.ord), [1, 2]);
  // a retiring note without locks of its own is cited by title (ord / text null)
  const retire = n({ path: 'Work/handbook/retire.md', ts: '2026-09-03', supersedes: ['[[b]]'] });
  const r2 = resolveLockLifecycle([neu, old, retire], NOW);
  assert.ok(r2.locks.every((l) => l.status === 'superseded'));
  assert.deepEqual(r2.locks.find((l) => l.noteId === neu.noteId)!.supersededBy, { note_title: 'retire', ord: null, text: null, source_uri: retire.sourceUri, source_ts: retire.sourceTs });
});

test('resolver: an OLDER (or same-time) note claiming to supersede a newer one is ignored and counted supersede_invalid; so are self claims and malformed items', () => {
  const newer = n({ path: 'Work/ops/newer.md', ts: '2026-11-10', locks: ['stays current'] });
  const older = n({ path: 'Work/ops/older.md', ts: '2026-11-01', locks: ['older'], supersedes: ['[[newer]] lock 1'] });
  const same = n({ path: 'Work/ops/same.md', ts: '2026-11-10', locks: ['same ts'], supersedes: ['[[newer]]', '[[same]]', 'not a link', '3: [[older]]'] });
  const r = resolveLockLifecycle([newer, older, same], NOW);
  assert.ok(r.locks.every((l) => l.status === 'current'), JSON.stringify(status(r)));
  assert.equal(r.counts.supersede_claims, 5);
  assert.equal(r.counts.supersede_invalid, 5, 'older->newer, equal ts, self, malformed, own ordinal 3 not present');
  assert.equal(r.counts.supersede_applied, 0);
});

test('resolver: unresolved targets are counted, never guessed (missing note, ambiguous name, missing lock ordinal)', () => {
  const a1 = n({ path: 'Work/ops/dup.md', ts: '2026-01-01', locks: ['x'] });
  const a2 = n({ path: 'Work/handbook/dup.md', ts: '2026-01-02', locks: ['y'] });
  const t = n({ path: 'Work/ops/target.md', ts: '2026-01-03', locks: ['only one'] });
  const c = n({ path: 'Work/ops/claims.md', ts: '2026-02-01', locks: ['c'], supersedes: ['[[nowhere]]', '[[dup]]', '[[target]] lock 2'] });
  const r = resolveLockLifecycle([a1, a2, t, c], NOW);
  assert.ok(r.locks.every((l) => l.status === 'current'));
  assert.equal(r.counts.supersede_unresolved, 3);
  // a full path disambiguates
  const r2 = resolveLockLifecycle([a1, a2, t, n({ path: 'Work/ops/c2.md', ts: '2026-02-02', supersedes: ['[[Work/handbook/dup]]'] })], NOW);
  assert.deepEqual(r2.locks.filter((l) => l.status === 'superseded').map((l) => l.vaultPath), ['Work/handbook/dup.md']);
});

test('resolver: a chain of three — only the newest lock is current; each link points one step forward and back', () => {
  const a = n({ path: 'Work/ops/chain-a.md', ts: '2026-10-01', locks: ['A'] });
  const b = n({ path: 'Work/ops/chain-b.md', ts: '2026-10-10', locks: ['B'], supersedes: ['[[chain-a]] lock 1'] });
  const c = n({ path: 'Work/ops/chain-c.md', ts: '2026-10-20', locks: ['C'], supersedes: ['[[chain-b]] lock 1'] });
  const r = resolveLockLifecycle([c, a, b], NOW);
  const by = (t: string) => r.locks.find((l) => l.text === t)!;
  assert.deepEqual([by('A').status, by('B').status, by('C').status], ['superseded', 'superseded', 'current']);
  assert.equal(by('A').supersededBy!.text, 'B');
  assert.equal(by('B').supersededBy!.text, 'C');
  assert.deepEqual(by('C').supersedes.map((x) => x.text), ['B']);
  assert.deepEqual(by('B').supersedes.map((x) => x.text), ['A']);
});

test('resolver: expiry — past / future / end-exclusive / note-level until / lock_until wins / invalid counted; superseded wins over expired', () => {
  const x = n({
    path: 'Work/ops/2026-10-20-switch.md', ts: '2026-10-20',
    locks: ['Through Sat 24 Oct (synthetic)', 'During the switch (synthetic)', 'Standing (synthetic)', 'Future (synthetic)'],
    lockUntil: ['1: 2026-10-25T00:00+02:00', '2: 2026-10-24', '4: 2027-01-01', '9: 2026-10-24', '3: soon'],
  });
  const r = resolveLockLifecycle([x], NOW);
  assert.deepEqual(r.locks.map((l) => [l.ord, l.status, l.until]), [
    [1, 'expired', '2026-10-24T22:00:00.000Z'], [2, 'expired', '2026-10-24T22:00:00.000Z'], [3, 'current', null], [4, 'current', '2027-01-01T23:00:00.000Z'],
  ]);
  assert.equal(r.counts.until_invalid, 2, 'ordinal 9 does not exist; "soon" is not a time');
  // end-exclusive: at exactly the bound the lock has ended; one ms before it still holds
  const bound = new Date('2026-10-24T22:00:00Z');
  assert.equal(resolveLockLifecycle([x], bound).locks[0]!.status, 'expired');
  assert.equal(resolveLockLifecycle([x], new Date(bound.getTime() - 1)).locks[0]!.status, 'current');
  // note-level until applies to every lock; a per-lock lock_until wins
  const y = n({ path: 'Work/ops/y.md', ts: '2026-10-01', locks: ['y1', 'y2'], until: '2026-10-31', lockUntil: '2: 2027-06-30' });
  assert.deepEqual(resolveLockLifecycle([y], NOW).locks.map((l) => l.status), ['expired', 'current']);
  // superseded > expired
  const z = n({ path: 'Work/ops/z.md', ts: '2026-11-01', locks: ['z'], supersedes: '[[2026-10-20-switch]] lock 1' });
  const rz = resolveLockLifecycle([x, z], NOW);
  assert.equal(rz.locks.find((l) => l.noteId === x.noteId && l.ord === 1)!.status, 'superseded');
  assert.equal(rz.counts.current + rz.counts.superseded + rz.counts.expired, rz.counts.items);
});

// ---------------------------------------------------------------------------
// MCP read path (PGlite)

const OLD_PATH = 'Work/ops/2026-10-29-desk-locks.md';
const NEW_PATH = 'Work/ops/2026-11-11-desk-wipe-locks.md';
const SWITCH_PATH = 'Work/ops/2026-10-20-switch-locks.md';
const OLD_2 = 'SYNTHETIC: wipe the old desk to distro-A (superseded)';
const NEW_1 = 'SYNTHETIC: archive, then Zeus may wipe the desk and install its chosen OS';
const SWITCH_1 = 'SYNTHETIC: through Sat 24 Oct 2026 new coding goes to tool-A; tool-B resumes Sun 25 Oct';
const SWITCH_3 = 'SYNTHETIC: standing quokkacheck every 30 minutes';
const HASH_LOCK = 'Close #1157; set the quokkabot to weekly with a PR limit';

const FILES: Record<string, string> = {
  [OLD_PATH]: `---\ntitle: Desk locks (synthetic)\ndate: 2026-10-29\nlocks:\n  - SYNTHETIC: move builds to the mini first\n  - ${OLD_2}\n---\nbody\n`,
  [NEW_PATH]: `---\ntitle: Desk wipe locks (synthetic)\ndate: 2026-11-11\nlocks:\n  - ${NEW_1}\n  - SYNTHETIC: keep the phone plan\nsupersedes:\n  - "1: [[2026-10-29-desk-locks]] lock 2"\n---\nbody\n`,
  [SWITCH_PATH]: `---\ntitle: Switch locks (synthetic)\ndate: 2026-10-20\nlocks:\n  - ${SWITCH_1}\n  - SYNTHETIC: during the switch balance both accounts\n  - ${SWITCH_3}\nlock_until:\n  - "1: 2026-10-25T00:00+02:00"\n  - "2: 2026-10-24"\n---\nbody\n`,
  'Work/handbook/2026-11-02-hash-locks.md': `---\ntitle: Hash locks (synthetic)\ndate: 2026-11-02\nlocks:\n  - ${HASH_LOCK}\n  - Keep fixing #1057, #1059 and #1060 — do not park them\n---\nbody\n`,
  'Work/products/p/product.md': `---\ntitle: Product (synthetic)\ndate: 2026-11-05\nlocks:\n  - SYNTHETIC product lock, not standing\n---\nbody\n`,
};

interface Env { db: Db; dir: string; run: number; close(): Promise<void> }

async function fresh(): Promise<Env> {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-lifecycle-'));
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
  await db.exec('SET ROLE zeusi_mini_ingest');
  try {
    const r = await importVault({ db, config, mode: 'full', home: dir });
    assert.equal(r.counts.errors, 0);
  } finally {
    await db.exec('RESET ROLE');
  }
  return { db, dir, run, close: async () => { await db.close(); rmSync(dir, { recursive: true, force: true }); } };
}

function asRole(db: Db, role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

interface Harness { names: string[]; call(name: string, args: Record<string, unknown>): Promise<{ text: string; json: Record<string, unknown>; isError: boolean }>; close(): Promise<void> }

async function mcp(e: Env, over: Partial<McpDeps> = {}): Promise<Harness> {
  const deps: McpDeps = {
    env: { HOME: e.dir }, home: e.dir, readService: 'zeusi_ro', connectRead: asRole(e.db, 'zeusi_box_ro'), embeddings: () => null, now: () => NOW,
    feedbackPath: join(e.dir, '.zeusi', 'fb.jsonl'), queryLedgerPath: join(e.dir, '.zeusi', 'ledger.json'), ...over,
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  const names = (await client.listTools()).tools.map((t) => t.name);
  return {
    names,
    async call(name, args) {
      const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
      const text = r.content.map((c) => c.text ?? '').join('\n');
      return { text, json: r.isError ? {} : JSON.parse(text) as Record<string, unknown>, isError: r.isError === true };
    },
    close: async () => { await client.close(); await server.close(); },
  };
}

type Rule = { origin: string; text: string; ord?: number; expires_at?: string | null; supersedes?: Array<{ text: string; ord: number }>; source_uri: string };

test('startup + onboarding: superseded and expired locks are not served; the superseding lock carries the chain; `#1157` items arrive whole; counts agree (rules == startup total)', async () => {
  const e = await fresh();
  try {
    const obs: ToolObservation[] = [];
    const h = await mcp(e, { observe: (o) => obs.push(o) });
    try {
      const s = await h.call('zeusi_startup', {});
      assert.ok(!s.isError, s.text);
      const rules = s.json['rules'] as Rule[];
      const texts = rules.map((r) => r.text);
      assert.ok(!texts.includes(OLD_2), 'superseded lock is not a current rule');
      assert.ok(!texts.includes(SWITCH_1), 'expired lock is not a current rule');
      assert.ok(!texts.some((t) => /during the switch/.test(t)), 'expired (date-only, end of 24 Oct Zurich)');
      assert.ok(texts.includes(SWITCH_3) && texts.includes(NEW_1));
      assert.ok(texts.includes(HASH_LOCK) && texts.includes('Keep fixing #1057, #1059 and #1060 — do not park them'), 'no "Close" / "Keep fixing" fragments');
      assert.ok(!texts.includes('Close') && !texts.includes('Keep fixing'));
      assert.ok(!texts.some((t) => /product lock/.test(t)), 'non-standing locks stay out of startup');
      const head = rules.find((r) => r.text === NEW_1)! as unknown as { supersedes: string[] };
      // compact form: supersedes carries the replaced lock's id (its text is in the remainder / context_for_task history)
      assert.equal(head.supersedes.length, 1);
      assert.match(head.supersedes[0]!, /#lock-2$/);
      assert.ok(!('expires_at' in rules.find((r) => r.text === SWITCH_3)!), 'compact form: no expires_at key when none is set');
      const total = s.json['rules_total'] as { fact: number; note_lock: number; total: number; visible: number; capped: boolean };
      assert.deepEqual(total, { fact: 0, note_lock: 6, total: 6, visible: 6, capped: false });
      assert.equal(s.json['rules_served'], 6);
      assert.equal(s.json['rules_remainder_count'], 0);
      assert.deepEqual(s.json['rules_remainder'], []);
      assert.ok(!('rules_cap' in s.json), 'no item cap any more: a token budget plus an explicit remainder');
      assert.match(String(s.json['rules_note']), /^All 6 current standing rules are served/);
      assert.match(String(s.json['rules_note']), /CURRENT lock items of the standing notes/);
      assert.equal(s.json['sources'], SOURCES_OF_RULES_FACTS_FOCUS);
      assert.match(String(s.json['focus_message']), /HQ sync.*typed Focus block/);
      assert.match(String(s.json['focus_message']), /does not mean there is no focus/);

      const o = await h.call('zeusi_onboarding_status', {});
      const counts = o.json['counts'] as Record<string, number>;
      assert.equal(counts['rules'], total.total, 'onboarding rules == startup rules_total.total');
      assert.deepEqual(o.json['rules_by_origin'], { fact: 0, note_lock: total.note_lock });
      // 2 + 2 + 3 + 2 + 1 = 10 lock items; 1 superseded, 2 expired
      assert.deepEqual([counts['note_locks'], counts['note_locks_current'], counts['note_locks_superseded'], counts['note_locks_expired']], [10, 7, 1, 2]);
      assert.equal(counts['note_locks_current']! + counts['note_locks_superseded']! + counts['note_locks_expired']!, counts['note_locks']);
      assert.equal(counts['focus'], 0);
      assert.match(String(o.json['focus_message']), /HQ sync/);
      assert.equal(o.json['rules_definition'], RULES_DEFINITION);
      assert.ok(!o.text.includes('SYNTHETIC'), 'onboarding: counts only, no lock text');
      // a fact rule counts on both sides alike
      await e.db.query(`INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                        VALUES ('rule', 'r', 'Synthetic fact rule', 'work', 'manual', 'manual:r', now(), decode($1, 'hex'), $2)`, [SHA, e.run]);
      const s2 = (await h.call('zeusi_startup', {})).json;
      const o2 = (await h.call('zeusi_onboarding_status', {})).json;
      assert.deepEqual(s2['rules_total'], { fact: 1, note_lock: 6, total: 7, visible: 7, capped: false });
      assert.equal((o2['counts'] as Record<string, number>)['rules'], 7);
      assert.deepEqual(o2['rules_by_origin'], { fact: 1, note_lock: 6 });
      // the hosted log hook gets counts only
      for (const x of obs) assert.deepEqual(Object.keys(x).sort(), ['hitCount', 'secretWithheld', 'tool', 'withheld']);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('startup: more current standing rules than the old 50 cap are all served within the budget, and the true total is reported', async () => {
  const e = await fresh();
  try {
    const many = Array.from({ length: 70 }, (_, i) => `SYNTHETIC MANY ${i}`);
    await e.db.query(
      `INSERT INTO zeusi.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('Work/handbook/many.md', 'Many', jsonb_build_object('locks', $1::jsonb), 'b', now(), 'work', 'vault_note', 'vault:Work/handbook/many.md', '2026-11-16T00:00:00Z', decode($2, 'hex'), $3)`,
      [JSON.stringify(many), SHA, e.run]);
    const h = await mcp(e);
    try {
      const s = (await h.call('zeusi_startup', {})).json;
      assert.equal((s['rules'] as unknown[]).length, 76, 'all 76 fit the token budget: none is cut at 50');
      assert.equal(s['rules_served'], 76);
      assert.equal(s['rules_remainder_count'], 0);
      assert.equal((s['rules_total'] as { total: number }).total, 76);
      assert.match(String(s['rules_note']), /^All 76 current standing rules are served/);
      assert.equal(((await h.call('zeusi_onboarding_status', {})).json['counts'] as Record<string, number>)['rules'], 76);
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('context_for_task: current locks in items; superseded / expired matches only in `history`, with superseded_by (cite) or expired_at', async () => {
  const e = await fresh();
  try {
    const h = await mcp(e);
    try {
      const r = await h.call('zeusi_context_for_task', { task: 'wipe the desk' });
      assert.ok(!r.isError, r.text);
      const items = r.json['items'] as Array<{ exact_words: string; status: string; supersedes?: Array<{ text: string }> }>;
      assert.ok(items.some((i) => i.exact_words === NEW_1 && i.status === 'current'));
      assert.ok(!items.some((i) => i.exact_words === OLD_2), 'a superseded lock is never a current item');
      assert.deepEqual(items.find((i) => i.exact_words === NEW_1)!.supersedes!.map((x) => x.text), [OLD_2]);
      const hist = r.json['history'] as Array<{ exact_words: string; status: string; superseded_by?: { text: string; ord: number; source_uri: string; cite: string } }>;
      const old = hist.find((x) => x.exact_words === OLD_2)!;
      assert.equal(old.status, 'superseded');
      assert.equal(old.superseded_by!.text, NEW_1);
      assert.equal(old.superseded_by!.source_uri, `vault:${NEW_PATH}`);
      assert.match(old.superseded_by!.cite, /^vault:Work\/ops\/2026-11-11-desk-wipe-locks\.md @ 2026-11-11T00:00:00\.000Z \(lock 1 of "Desk wipe locks \(synthetic\)"\)$/);
      assert.match(String(r.json['history_note']), /not binding/);
      const sw = await h.call('zeusi_context_for_task', { task: 'tool-A coding switch' });
      const swItems = sw.json['items'] as Array<{ exact_words: string }>;
      assert.ok(!swItems.some((i) => i.exact_words === SWITCH_1));
      const swHist = sw.json['history'] as Array<{ exact_words: string; status: string; expired_at?: string }>;
      assert.deepEqual(swHist.filter((x) => x.exact_words === SWITCH_1).map((x) => [x.status, x.expired_at]), [['expired', '2026-10-24T22:00:00.000Z']]);
      // nothing historic matches: no history key at all
      const none = await h.call('zeusi_context_for_task', { task: 'quokkacheck' });
      assert.ok(!('history' in none.json));
    } finally {
      await h.close();
    }
  } finally {
    await e.close();
  }
});

test('RLS: a superseding note the reader cannot see does not exist for it — the old lock stays current (startup, onboarding, context)', async () => {
  const e = await fresh();
  try {
    // Move the superseding note to product (owner, test only); the team-only reader cannot read it.
    await e.db.query(`UPDATE zeusi.notes SET scope = 'product' WHERE vault_path = $1`, [NEW_PATH]);
    await e.db.exec(`CREATE ROLE ${WORK_SCOPE_ONLY} NOLOGIN;
      GRANT USAGE ON SCHEMA zeusi TO ${WORK_SCOPE_ONLY};
      GRANT SELECT ON zeusi.notes, zeusi.chunks, zeusi.facts, zeusi.facts_current, zeusi.decisions, zeusi.decisions_current, zeusi.people TO ${WORK_SCOPE_ONLY};
      CREATE POLICY t_lc ON zeusi.notes FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
      CREATE POLICY t_lc ON zeusi.chunks FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
      CREATE POLICY t_lc ON zeusi.facts FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
      CREATE POLICY t_lc ON zeusi.decisions FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
      CREATE POLICY t_lc ON zeusi.people FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');`);
    const all = await mcp(e);
    const narrow = await mcp(e, { connectRead: asRole(e.db, WORK_SCOPE_ONLY) });
    try {
      assert.ok(!((await all.call('zeusi_startup', {})).json['rules'] as Rule[]).some((r) => r.text === OLD_2), 'precondition: full reader sees the supersession');
      const s = await narrow.call('zeusi_startup', {});
      assert.ok(!s.isError, s.text);
      const rules = s.json['rules'] as Rule[];
      assert.ok(rules.some((r) => r.text === OLD_2), 'old lock current for the narrow reader');
      assert.ok(!s.text.includes(NEW_1) && !s.text.includes('desk-wipe'), 'nothing of the invisible note leaks (not even via supersedes)');
      const o = (await narrow.call('zeusi_onboarding_status', {})).json['counts'] as Record<string, number>;
      assert.equal(o['note_locks_superseded'], 0);
      assert.equal(o['rules'], (s.json['rules_total'] as { total: number }).total);
      const c = await narrow.call('zeusi_context_for_task', { task: 'wipe the desk' });
      assert.ok((c.json['items'] as Array<{ exact_words: string }>).some((i) => i.exact_words === OLD_2));
      assert.ok(!c.text.includes(NEW_1));
    } finally {
      await all.close();
      await narrow.close();
    }
  } finally {
    await e.close();
  }
});

test('read path: the read class registers no write tool, and startup / context / onboarding change no row (frontmatter digest unchanged)', async () => {
  const e = await fresh();
  try {
    const digest = async () => (await e.db.query<{ d: string }>(
      `SELECT md5(string_agg(id::text || frontmatter::text || status, ',' ORDER BY id)) AS d FROM zeusi.notes`)).rows[0]!.d;
    const before = await digest();
    const h = await mcp(e, { toolClass: 'read' });
    try {
      assert.ok(!h.names.includes('zeusi_log_decision') && !h.names.includes('log_decision'));
      for (const [t, a] of [['zeusi_startup', {}], ['zeusi_onboarding_status', {}], ['zeusi_context_for_task', { task: 'wipe the desk' }]] as const) {
        assert.ok(!(await h.call(t, a)).isError, t);
      }
    } finally {
      await h.close();
    }
    assert.equal(await digest(), before);
    assert.match(aboutMarkdown(false), /Rules come from locks in notes \(standing folders\)/);
  } finally {
    await e.close();
  }
});

// ---------------------------------------------------------------------------
// Standing marker (session-start gaps U1): `standing_locks:` makes a lock standing, explicitly

test('standing marker: parseStandingMarker reads lists, one string and numbers; anything else is invalid (null), never guessed', () => {
  assert.deepEqual(parseStandingMarker(['1', '3']), [1, 3]);
  assert.deepEqual(parseStandingMarker('1, 3'), [1, 3]);
  assert.deepEqual(parseStandingMarker(2), [2]);
  assert.deepEqual(parseStandingMarker(['0', 'x', '1.5', '', ' 4 ']), [null, null, null, 4]);
  assert.deepEqual(parseStandingMarker(null), []);
  assert.deepEqual(parseStandingMarker({ a: 1 }), []);
});

test('standing marker: marked ordinals are standingMarked (any folder); a missing ordinal is counted invalid; supersession still wins', () => {
  const base = { scope: 'product', supersedes: null, lockUntil: null, until: null };
  const notes = [
    { ...base, noteId: 1, vaultPath: 'Work/products/product/a.md', title: 'A', sourceUri: 'vault:Work/products/product/a.md', sourceTs: '2026-11-01T00:00:00.000Z', locks: ['one', 'two'], standingLocks: ['1', '9'] },
    { ...base, noteId: 2, vaultPath: 'Work/products/product/b.md', title: 'B', sourceUri: 'vault:Work/products/product/b.md', sourceTs: '2026-11-02T00:00:00.000Z', locks: ['three'] },
    { ...base, noteId: 3, vaultPath: 'Work/products/product/c.md', title: 'C', sourceUri: 'vault:Work/products/product/c.md', sourceTs: '2026-11-03T00:00:00.000Z', locks: ['four'], standingLocks: '1', supersedes: '[[A]] lock 1' },
  ];
  const r = resolveLockLifecycle(notes, new Date('2026-11-18T00:00:00Z'));
  const by = (id: number, ord: number) => r.locks.find((l) => l.noteId === id && l.ord === ord)!;
  assert.equal(by(1, 1).standingMarked, true);
  assert.equal(by(1, 2).standingMarked, false);
  assert.equal(by(2, 1).standingMarked, false);
  assert.equal(r.counts.standing_marked, 2);
  assert.equal(r.counts.standing_marker_invalid, 1, 'ordinal 9 does not exist');
  assert.equal(by(1, 1).status, 'superseded');
  assert.deepEqual(currentStandingLocks(r.locks).map((l) => [l.noteId, l.ord]), [[3, 1]], 'superseded marked lock is not served; unmarked never');
  assert.ok(isStandingLock({ vaultPath: 'Work/ops/x.md', standingMarked: false }));
  assert.ok(!isStandingLock({ vaultPath: 'Work/products/product/x.md', standingMarked: false }));
});
