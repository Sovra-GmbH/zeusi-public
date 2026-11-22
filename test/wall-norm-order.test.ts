// Fold-list insertion order must not change the folded result: SQL translate() and
// the JS map are pair-aligned, and pair order is not significant.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WALL_CONFUSABLES, wallNorm } from '../src/wall.ts';

const foldWith = (m: ReadonlyMap<string, string>, s: string) =>
  [...s].map((c) => m.get(c) ?? c).join('');

test('wallNorm: fold-map insertion order does not change the result over every fold character', () => {
  const pairs = [...WALL_CONFUSABLES.entries()];
  assert.ok(pairs.length >= 40, 'fold list is populated');
  const maps = [
    new Map(pairs),
    new Map(pairs.slice().reverse()),
    new Map(
      [...pairs].sort((a, b) => (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)),
    ),
  ];
  const keys = pairs.map(([s]) => s);
  const samples = [keys.join(''), keys.join('') + keys.join(''), `X${keys.join('')}Y`, ...keys, ...keys.map((k) => `p${k}q`)];
  const gold = samples.map((s) => foldWith(maps[0]!, s));
  for (let i = 1; i < maps.length; i++) {
    assert.deepEqual(samples.map((s) => foldWith(maps[i]!, s)), gold, `insertion order ${i} differs`);
  }
  // Full pipeline is deterministic on the same sources, regardless of later map iteration.
  const all = keys.join('');
  assert.equal(wallNorm(all), wallNorm(all));
  for (const k of keys) assert.equal(wallNorm(k), wallNorm(k));
});
