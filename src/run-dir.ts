// A private, randomly named work directory whose path the path gate accepts (AGENTS.md rule safe-tmp).
//
// Past mistakes: #12 (a test temp suffix "...-PnLTJL" hit the hard path_glob '**pnl**') and PR #55 CI run
// 44862668470: `mkdtempSync(join(parent, 'run-'))` in src/preview-seal.ts gave the commit's run root a random
// 6-character suffix; about 1 name in 5 000 spells a walled term in some case, and the importer then refuses
// the whole run ("root is refused by the path gate", src/importers/vault.ts), so the commit answered
// "Saving did not complete" at random. The gate is right; the server must never hand it such a name.
//
// gatedRunDir() creates `<parent>/<prefix><random>` (0700, exclusive: never an existing path, never through a
// symlink), then asks `accept` about the path that now exists. On a refusal it removes the dir and picks
// another name. It never weakens a rule; it only re-rolls the name. runDirGate() is the accept of every caller:
// the dir and each sub-path a later gate will check, through sourcePathGate (the one gate: logical and real
// path, the Plankiva rule, the wall's hard rules), for every wall that later gate uses.
import { randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { sourcePathGate } from './sources.ts';
import type { Wall } from './wall.ts';

export const RUN_DIR_ATTEMPTS = 50;

/** No wall-safe name after RUN_DIR_ATTEMPTS tries (the parent itself is walled, or the rules changed). No path in it. */
export class RunDirError extends Error {
  override name = 'RunDirError';
}

/**
 * The one run-name rule (AGENTS.md rule one-rule; review r2 P1-1 of #55): every name randomRunName() makes
 * matches it, and sweepStaleRuns (src/import-run.ts) removes exactly the `run-<name>` dirs it matches. Under
 * mkdtemp the names were alphanumeric; base64url adds `-` and `_`, which a narrower sweep regex silently skipped.
 */
export const RUN_NAME_RE = /^[A-Za-z0-9_-]+$/;
export const isRunName = (name: string): boolean => RUN_NAME_RE.test(name);

/** 12 random characters [A-Za-z0-9_-] (72 bits); always isRunName. */
export const randomRunName = (): string => randomBytes(9).toString('base64url');

/** Accept a dir when it and each of `subPaths` (relative, '/'-separated) pass sourcePathGate under every wall. */
export function runDirGate(walls: readonly Wall[], home: string, subPaths: readonly string[] = []): (dir: string) => boolean {
  return (dir) => [dir, ...subPaths.map((p) => join(dir, ...p.split('/')))].every((p) => walls.every((wall) => sourcePathGate(p, { wall, home }).ok));
}

/**
 * Create a fresh private directory `<parent>/<prefix><name()>` that `accept` approves. `name` is injectable so a
 * test can force a walled name first. Throws RunDirError after RUN_DIR_ATTEMPTS refusals.
 */
export function gatedRunDir(parent: string, prefix: string, accept: (dir: string) => boolean, name: () => string = randomRunName): string {
  for (let i = 0; i < RUN_DIR_ATTEMPTS; i++) {
    const dir = join(parent, `${prefix}${name()}`);
    try {
      mkdirSync(dir, { recursive: false, mode: 0o700 });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EEXIST') continue;
      throw e;
    }
    const st = lstatSync(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) throw new RunDirError('run dir: the new directory is not a real directory');
    if (accept(dir)) return dir;
    rmSync(dir, { recursive: true, force: true });
  }
  throw new RunDirError(`run dir: no name the path gate accepts after ${RUN_DIR_ATTEMPTS} attempts`);
}
