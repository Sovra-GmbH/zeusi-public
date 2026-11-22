// The off-route golden (test/c7-off-golden.test.ts) must give the same result on every run day. It broke
// one day after capture for two reasons, and both are pinned here without a database:
//   1. stable() rewrote the fixed ABOUT_SOURCE_TS stamp into the rolling D-<k> window (the k grew by one each day);
//   2. note-lock recency was scored against a recent fixed note date, so the scores (and in time the order against
//      the decisions) moved with the calendar.
// Mutants: drop the ABOUT_SOURCE_TS tokenisation in stable() -> test 1 red; date a lock note back to 2026-10-10 ->
// test 2 red; remove the recency term from rankLocksForTask -> test 3 red.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ABOUT_SOURCE_TS } from '../src/about.ts';
import type { ResolvedLock } from '../src/lock-lifecycle.ts';
import { rankLocksForTask } from '../src/note-locks.ts';
import { C7_DAYS, C7_NOW, c7Notes, c7Sync, stable } from './helpers/c7-fixture.ts';

const DAY = 86_400_000;
const lock = (sourceTs: string, noteId = 1): ResolvedLock => ({ title: 'Rule', text: 'alpha rule', sourceTs, noteId, ord: 1 }) as unknown as ResolvedLock;
const scoreAt = (sourceTs: string, now: Date) => rankLocksForTask([lock(sourceTs)], 'alpha', now)[0]!.score;

test('c7 golden date-stable: stable() maps ABOUT_SOURCE_TS to one fixed token wherever it falls in the rolling window', () => {
  const aboutDay = ABOUT_SOURCE_TS.slice(0, 10);
  const cite = `zeusi://about#hello @ ${ABOUT_SOURCE_TS}`;
  for (let k = 0; k < 15; k++) {
    const days = Array.from({ length: 15 }, (_, i) => new Date(Date.parse(`${aboutDay}T00:00:00Z`) + (k - i) * DAY).toISOString().slice(0, 10));
    assert.equal(days[k], aboutDay);
    assert.equal(stable(cite, days), 'zeusi://about#hello @ ABOUT_TS', `about date at D-${k}`);
    assert.deepEqual(stable({ source_ts: ABOUT_SOURCE_TS, at: [ABOUT_SOURCE_TS] }, days), { source_ts: 'ABOUT_TS', at: ['ABOUT_TS'] });
    assert.equal(stable(`${aboutDay}T10:00:00.000Z`, days), `D-${k}T10:00:00.000Z`);
  }
  assert.equal(stable(cite), 'zeusi://about#hello @ ABOUT_TS');
  assert.equal(stable(`${C7_DAYS[3]!}T10:00:00+00:00`), 'D-3T10:00:00+00:00');
});

test('c7 golden date-stable: every fixture lock note is old enough that its context_for_task score does not move with the run day', () => {
  const lockDates = [...c7Notes().map((n) => (n as { text?: string }).text ?? ''), ...c7Sync().map((s) => s.text)]
    .filter((t) => /^locks:/m.test(t))
    .map((t) => /^date: (\d{4}-\d\d-\d\d)$/m.exec(t)?.[1]);
  assert.ok(lockDates.length >= 5, `the lock notes of the corpus (${lockDates.length})`);
  for (const d of lockDates) {
    assert.ok(d, 'every lock note has a fixed date');
    const ts = `${d}T00:00:00.000Z`;
    const today = scoreAt(ts, C7_NOW);
    for (const years of [1, 5, 30]) assert.equal(scoreAt(ts, new Date(C7_NOW.getTime() + years * 365 * DAY)), today, `${d}: same score ${years} year(s) later`);
    assert.equal(today, 1.6, `${d}: hits + lock weight, recency rounded to 0`);
  }
});

test('c7 golden date-stable: note-lock recency is still scored (fixed clock), newer first', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');
  assert.equal(scoreAt('2026-01-01T00:00:00.000Z', now), 1.9, 'age 0: 1 hit + 0.6 + 0.3');
  assert.equal(scoreAt('2025-10-03T00:00:00.000Z', now), Math.round((1.6 + 0.3 * Math.exp(-1)) * 1e6) / 1e6, 'age 90 days: 0.3 / e');
  const ranked = rankLocksForTask([lock('2025-10-03T00:00:00.000Z', 1), lock('2026-01-01T00:00:00.000Z', 2)], 'alpha', now);
  assert.deepEqual(ranked.map((r) => r.noteId), [2, 1]);
  assert.ok(ranked[0]!.score > ranked[1]!.score, 'recency, not only the source_ts tie-break, orders them');
});
