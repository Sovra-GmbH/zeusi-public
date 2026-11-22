// Count-only measurement: how often the SOFT wall rules of the seed wall would quarantine
// Zeus HQ chat exports at ingest (docs/hq-sync.md, "Soft rules and chat exports").
// Since 0011 these are account/login numbers and IBAN only (currency and P&L/book lines
// were lifted); the recorded measurements in the doc predate 0011.
//
//   node scripts/hq-soft-wall-sample.ts            # deterministic synthetic sample
//   node scripts/hq-soft-wall-sample.ts --dir <d>  # plus H2 sections of local *.md (read-only)
//
// The importer quarantines a WHOLE note when any of its chunks hits a rule, so the
// per-note rate is ~ 1 - (1 - p)^n for n turns per note: the file granularity matters.
// The wall is NOT changed: this only measures. No database, no network, nothing
// written. OUTPUT IS COUNTS ONLY (rule ids and numbers): never a path or any text.
// --dir skips, unlisted, every folder or file the hard wall or the Plankiva rule refuses.

import { closeSync, constants, openSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { chunkMarkdown } from '../src/chunking.ts';
import { mentionsProtectedName } from '../src/sources.ts';
import { compileWall, seedWall } from '../src/wall.ts';

const wall = compileWall(seedWall().rules, []);
const softIds = new Set(wall.rules.filter((r) => !r.hard).map((r) => r.id));
const softHit = (text: string): number | null => {
  const v = wall.check('chunks', { heading_path: null, text, source_uri: 'hq:sample/x.md#c0' });
  return v.blocked && softIds.has(v.ruleId!) ? v.ruleId : null;
};

// ---- Synthetic HQ chat turns (engineering / ops talk; fake numbers; no real data).
const TURNS = [
  'Opened the PR for the importer refactor; CI is green on the first push.',
  'Review round 2 came back SAFE, the head moved so I asked for a re-check.',
  'Can you rebase the lane on main and rerun the tests?',
  'The nightly backup ran at 03:15 and wrote the manifest.',
  'Plan: U1 schema, U2 roles, U3 wall, then the importer.',
  'I merged the docs PR, the README now lists the new command.',
  'The Mini was asleep last night, the catch-up job ran on wake.',
  'Typecheck fails on line 42 of the CLI, missing import.',
  'Use `for f in *.md; do echo $f; done` to list them.',
  'The script takes the file as $1 and the mode as $2.',
  'Neon compute is about $0.10 a day at this load.',
  'The embedding run for 2,000 chunks cost under $1.',
  'the owner approved the GO for the branch-first apply.',
  'Ticket 4411 is the one with the flaky snapshot test.',
  'The coverage watcher missed two runs on Tuesday.',
  'Northbank connector release notes are drafted.',
  'Ops dashboard: the chart now loads in under a second.',
  'Moved the meeting to 14:30 Zurich time.',
  'The demo login 51234567 sees the new symbols after the restart.',
  'Account 7741233 is the demo one for the screenshots.',
  'Invoice from the hosting provider: EUR 49 for November.',
  'The test fixture has 12 notes and 3 quarantined ones.',
  'Book 2 mirror rebuilt; the counts match.',
  'PnL lane stays parked until the owner decides.',
  'Retention: 14 daily, 8 weekly, 6 monthly dumps.',
  'The release is tagged v0.3.1.',
  'Pushed the fix, waiting for the reviewer.',
  'Zeus memory: the owner prefers short plans with numbered units.',
  'Journal: quiet day, two reviews, one merge.',
  'Decision: the HQ export folder lives on the Mini.',
];

function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function sample(days: number, threadsPerDay: number, turnsPerThread: number) {
  const rnd = mulberry32(20261114);
  const byRule: Record<string, number> = {};
  let turns = 0, turnHits = 0, threadNotes = 0, threadHits = 0, dayNotes = 0, dayHits = 0;
  for (let d = 0; d < days; d++) {
    let dayHit = false;
    for (let t = 0; t < threadsPerDay; t++) {
      let threadHit = false;
      for (let k = 0; k < turnsPerThread; k++) {
        const text = TURNS[Math.floor(rnd() * TURNS.length)]!;
        turns++;
        const r = softHit(text);
        if (r !== null) {
          turnHits++;
          byRule[String(r)] = (byRule[String(r)] ?? 0) + 1;
          threadHit = true;
        }
      }
      threadNotes++;
      if (threadHit) threadHits++;
      if (threadHit) dayHit = true;
    }
    dayNotes++;
    if (dayHit) dayHits++;
  }
  return { turns, turnHits, byRule, threadNotes, threadHits, dayNotes, dayHits };
}

const pct = (a: number, b: number) => (b === 0 ? '0.0' : ((100 * a) / b).toFixed(1));
const { values } = parseArgs({ options: { dir: { type: 'string' } } });

const s = sample(30, 5, 8);
const templateHits = TURNS.filter((t) => softHit(t) !== null).length;
console.log('synthetic HQ chat sample (seeded; 30 days x 5 threads x 8 turns):');
console.log(`  turn templates hitting a soft rule: ${templateHits} of ${TURNS.length}`);
console.log(`  turns: ${s.turns}, soft-rule hits: ${s.turnHits} (${pct(s.turnHits, s.turns)}%)`);
for (const [k, v] of Object.entries(s.byRule).sort((a, b) => Number(a[0]) - Number(b[0]))) console.log(`    rule ${k}: ${v}`);
console.log(`  one note per thread per day: ${s.threadHits} of ${s.threadNotes} notes quarantined (${pct(s.threadHits, s.threadNotes)}%)`);
console.log(`  one note per project per day: ${s.dayHits} of ${s.dayNotes} notes quarantined (${pct(s.dayHits, s.dayNotes)}%)`);

if (values.dir) {
  const hardBlocked = (p: string) => mentionsProtectedName(p) || wall.checkUri(`file:${p}`).blocked || wall.checkUri(`file:${p}/`).blocked
    || wall.check('facts', { source_uri: `file:${p}`, lane: p.split('/').pop(), kind: 'other', subject: null, text: '' }).hard;
  let files = 0, fileHits = 0, sections = 0, sectionHits = 0, skipped = 0;
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name.startsWith('.')) continue;
      const p = join(dir, e.name);
      if (hardBlocked(p)) {
        skipped++;
        continue; // never listed or opened
      }
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && e.name.endsWith('.md')) {
        const fd = openSync(p, constants.O_RDONLY | constants.O_NOFOLLOW);
        let text: string;
        try {
          text = readFileSync(fd, 'utf8');
        } finally {
          closeSync(fd);
        }
        files++;
        let hit = false;
        for (const c of chunkMarkdown(text)) {
          sections++;
          if (softHit(c.text) !== null) {
            sectionHits++;
            hit = true;
          }
        }
        if (hit) fileHits++;
      }
    }
  };
  walk(values.dir);
  console.log('local markdown (--dir, read-only):');
  console.log(`  entries skipped unread by the hard wall / Plankiva rule: ${skipped}`);
  console.log(`  files: ${files}, with a soft-rule hit: ${fileHits} (${pct(fileHits, files)}%)`);
  console.log(`  chunks: ${sections}, with a soft-rule hit: ${sectionHits} (${pct(sectionHits, sections)}%)`);
}
