// Wall-safe temp dirs for tests (review delta-dccd5c9 P2-1).
//
// mkdtempSync appends a random 6-character suffix. That suffix can spell a walled
// term in any case ("zeusi-hq-PnLTJL" hits the hard path_glob '**pnl**'), so a
// fixture root built under it fails validateSources closed at random. The wall is
// right; the fixture must never hand it such a path. A hex-only suffix would not be
// enough either: wall rules can contain hex-looking words, and rules change.
//
// safeMkdtemp() creates the dir, then checks its logical and real path against every
// seed wall the tests use (current, 0010 and the legacy 0009 wall), hard AND soft
// rules, and against the Plankiva rule of the config validator. On any hit it removes
// the dir and tries again. It never weakens a rule; it only picks another name.

import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mentionsProtectedName } from '../../src/sources.ts';
import { legacySeedWall, seedWall, wall0010SeedWall, type Wall } from '../../src/wall.ts';

const WALLS: ReadonlyArray<readonly [string, Wall]> = [
  ['seed', seedWall()],
  ['0010', wall0010SeedWall()],
  ['legacy', legacySeedWall()],
];

const MAX_ATTEMPTS = 50;

/**
 * Why `p` is unsafe as a test temp path, or null when it clears every seed wall
 * (any rule kind, hard or soft, as a file: uri and as free text) and the Plankiva rule.
 */
export function tempPathWallHit(p: string): string | null {
  if (mentionsProtectedName(p)) return `"${p}" mentions plankiva or a variant`;
  for (const [name, wall] of WALLS) {
    for (const v of [
      wall.checkUri(`file:${p}`),
      wall.check('facts', { source_uri: `file:${p}`, kind: 'other', text: p, subject: p }),
    ]) {
      if (v.blocked) {
        const r = wall.rules.find((x) => x.id === v.ruleId);
        return `"${p}" hits ${name} wall rule ${v.ruleId} (${v.kind} ${JSON.stringify(r?.pattern ?? '')})`;
      }
    }
  }
  return null;
}

function realOr(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

/**
 * Drop-in for mkdtempSync(prefix) whose result (logical and real path) never matches
 * a wall rule. Throws when the prefix itself is walled, or after MAX_ATTEMPTS misses.
 * `mk` is injectable so a test can force a walled suffix.
 */
export function safeMkdtemp(prefix: string, mk: (prefix: string) => string = mkdtempSync): string {
  const base = tempPathWallHit(prefix) ?? tempPathWallHit(realOr(prefix.replace(/[^/]*$/, '') || '.'));
  if (base) throw new Error(`safeMkdtemp: the prefix itself is walled, retrying cannot help: ${base}`);
  const misses: string[] = [];
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    const dir = mk(prefix);
    const hit = tempPathWallHit(dir) ?? tempPathWallHit(realOr(dir));
    if (hit === null) return dir;
    misses.push(hit);
    rmSync(dir, { recursive: true, force: true });
  }
  throw new Error(`safeMkdtemp: no wall-safe name after ${MAX_ATTEMPTS} attempts; last: ${misses.at(-1)}`);
}

/** safeMkdtemp(join(tmpdir(), name)). */
export function safeTmpDir(name: string): string {
  return safeMkdtemp(join(tmpdir(), name));
}
