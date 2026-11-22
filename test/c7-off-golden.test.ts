// C7 (docs/plans/2026-11-19-c7-read-path.md, "Off route unchanged"): every read tool on an `off` personal
// workspace issues exactly the recorded statements with exactly the recorded parameters, and returns the
// recorded JSON. The golden (test/fixtures/c7-off-golden.json) was captured from the code at the C6 merge
// (635ca8f), BEFORE the C7 read route existed, with C7_GOLDEN_WRITE=1. Run-day dependent values (the
// decision dates of the fixture and the uris that hash them) are normalised to D-<k> / HASH;
// ABOUT_SOURCE_TS is normalised to ABOUT_TS so it does not drift with the calendar.
// Mutant: change one SQL string (or one parameter) while moving it behind the read source -> red.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { c6Fixture, callerOf, newWorkspace, type C6Fixture } from './helpers/c6-fixture.ts';
import { fillC7, runCalls, type GoldenCall } from './helpers/c7-fixture.ts';

const GOLDEN = fileURLToPath(new URL('./fixtures/c7-off-golden.json', import.meta.url));

let f: C6Fixture;
let t: string;
before(async () => {
  f = await c6Fixture();
  t = await newWorkspace(f, 'off');
  await fillC7(f, callerOf(t));
});
after(async () => {
  await f.close();
});

test('off route: every read tool on a P workspace issues exactly the recorded statements and parameters, and returns the recorded JSON', async () => {
  const got = await runCalls(f, t);
  assert.ok(got.every((c) => !c.isError), 'no call errors on the off route');
  assert.ok(got.some((c) => c.tool === 'zeusi_search' && ((c.output as { hits: unknown[] }).hits.length > 0)), 'the corpus is searchable');
  if (process.env['C7_GOLDEN_WRITE'] === '1') writeFileSync(GOLDEN, `${JSON.stringify(got, null, 1)}\n`);
  const golden = JSON.parse(readFileSync(GOLDEN, 'utf8')) as GoldenCall[];
  assert.equal(got.length, golden.length);
  for (let i = 0; i < golden.length; i++) {
    const g = golden[i]!;
    const c = got[i]!;
    const what = `${g.tool} ${JSON.stringify(g.args)}`;
    assert.deepEqual(c.statements, g.statements, `${what}: statements and parameters`);
    assert.deepEqual(c.output, g.output, `${what}: output`);
  }
});
