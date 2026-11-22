// The wall-safe temp-dir helper (review delta-dccd5c9 P2-1): a random mkdtemp suffix
// that spells a walled term ("PnLTJL") must never reach a fixture.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { safeMkdtemp, safeTmpDir, tempPathWallHit } from './helpers/safe-tmp.ts';

test('tempPathWallHit flags pnl in any case, other walled terms, and passes clean paths', () => {
  for (const p of ['/tmp/zeusi-hq-PnLTJL', '/tmp/zeusi-hq-pnlabc', '/tmp/zeusi-hq-xPNLx/zeus-hq', '/tmp/zeusi-hq-p&lxyz']) {
    assert.match(tempPathWallHit(p) ?? '', /pnl|p&l/i, p);
  }
  assert.ok(tempPathWallHit('/tmp/zeusi-hq-xPlankivaq'), 'plankiva variant');
  assert.ok(tempPathWallHit('/tmp/zeusi-hq-PLANKIVA'), 'plankiva');
  assert.ok(tempPathWallHit('/tmp/zeusi-hq-aclientcozz'), 'clientco (legacy wall)');
  assert.equal(tempPathWallHit('/tmp/zeusi-hq-a1b2c3'), null);
});

test('safeMkdtemp rejects a created dir whose random suffix contains pnl, removes it and retries', () => {
  const base = safeTmpDir('zeusi-safetmp-');
  try {
    const names = ['zeusi-hq-PnLTJL', 'zeusi-hq-xxpnlx', 'zeusi-hq-ok1234'];
    const made: string[] = [];
    const fake = (prefix: string) => {
      const d = join(base, names[made.length]!);
      assert.equal(prefix, join(base, 'zeusi-hq-'));
      mkdirSync(d);
      made.push(d);
      return d;
    };
    const dir = safeMkdtemp(join(base, 'zeusi-hq-'), fake);
    assert.equal(dir, join(base, 'zeusi-hq-ok1234'));
    assert.equal(made.length, 3);
    assert.ok(!existsSync(made[0]!) && !existsSync(made[1]!), 'walled dirs are removed');
    assert.deepEqual(readdirSync(base), ['zeusi-hq-ok1234']);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('safeMkdtemp gives up loudly when every name is walled, and refuses a walled prefix outright', () => {
  const base = safeTmpDir('zeusi-safetmp-');
  try {
    let n = 0;
    const always = () => {
      const d = join(base, `zeusi-hq-pnl${n++}`);
      mkdirSync(d);
      return d;
    };
    assert.throws(() => safeMkdtemp(join(base, 'zeusi-hq-'), always), /no wall-safe name/);
    assert.deepEqual(readdirSync(base), [], 'no walled dir left behind');
    assert.throws(() => safeMkdtemp(join(base, 'zeusi-pnl-')), /prefix itself is walled/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('the wall itself is unchanged: a source root under a pnl temp name still fails closed', () => {
  assert.throws(
    () => validateSources(parseToml('[[source]]\nname = "hq-team"\nkind = "zeus_memory"\nscope = "work"\nroot = "/tmp/zeusi-hq-PnLTJL/zeus-hq"\ninclude = ["team/*.md"]\nproject = "team"\n'), seedWall()),
    /\*\*pnl\*\*/,
  );
});

// The ban on raw mkdtemp moved to the repo guard `safe-tmp` (scripts/guards/safe-tmp.ts, `npm run guards`):
// it also covers test/helpers, scripts/ and src/, and aliased imports. Proofs: test/correct-guards.test.ts.

test('safeTmpDir works under the real tmpdir', () => {
  const d = safeTmpDir('zeusi-safetmp-real-');
  try {
    assert.ok(d.startsWith(tmpdir()));
    assert.equal(tempPathWallHit(d), null);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
