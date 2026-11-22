// Random runtime names that a later gate refuses (AGENTS.md rule safe-tmp; PR #55 CI run 44862668470): work
// dirs whose name a wall rule matches, and a served preview id that trips the serve guard. Root cause of that red run: `mkdtempSync(join(parent, 'run-'))` gave the commit's run root a
// random suffix; about 1 name in 5 000 spells a hard path rule of the seed wall in some case, the importer's root
// gate (src/importers/vault.ts) then refused the whole run, and the commit answered "Saving did not complete".
// src/run-dir.ts re-rolls such a name. These tests force a walled name first. The walled name is built at run
// time from the seed wall's own rule (never spelled here).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importVault } from '../src/importers/vault.ts';
import { gatedRunDir, randomRunName, RUN_DIR_ATTEMPTS, RunDirError, runDirGate } from '../src/run-dir.ts';
import { wallFilter } from '../src/mcp-wall.ts';
import { parseToml, sourcePathGate, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { PREVIEW_ID_ATTEMPTS, servablePreviewId } from '../src/workspace-write.ts';
import { c6Fixture, callerOf, commitDocs, counts, hqItem, newWorkspace, type C6Fixture } from './helpers/c6-fixture.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asOwner } from './helpers/tenant-fixture.ts';

/** A name core that a hard `**<word>**` path rule of the seed wall matches, in mixed case (as in #12). */
function walledCore(): string {
  const r = seedWall().rules.filter((x) => x.hard && x.kind === 'path_glob' && /^\*\*[a-z0-9]+\*\*$/i.test(x.pattern))
    .sort((a, b) => a.pattern.length - b.pattern.length)[0];
  assert.ok(r, 'the seed wall has a hard **word** path rule');
  const w = r.pattern.slice(2, -2);
  return [...w].map((ch, i) => (i % 2 === 0 ? ch.toUpperCase() : ch.toLowerCase())).join('');
}
const WALLED = `x${walledCore()}y`;

test('run dir: the walled name really is refused by the gate the importer applies (precondition of every test below)', () => {
  const parent = safeMkdtemp(join(tmpdir(), 'zeusi-rundir-'));
  assert.equal(sourcePathGate(join(parent, `run-${WALLED}`), { wall: seedWall(), home: parent }).ok, false);
  assert.equal(sourcePathGate(join(parent, 'run-ok1'), { wall: seedWall(), home: parent }).ok, true);
});

test('gatedRunDir: a walled name is removed and re-rolled; the dir it returns passes the gate, is 0700 and is the only one left (mutant: ignore accept -> red)', () => {
  const parent = safeMkdtemp(join(tmpdir(), 'zeusi-rundir-'));
  const names = [WALLED, WALLED, 'ok1'];
  const dir = gatedRunDir(parent, 'run-', runDirGate([seedWall()], parent, ['staging', 'filtered']), () => names.shift()!);
  assert.equal(dir, join(parent, 'run-ok1'));
  assert.deepEqual(readdirSync(parent), ['run-ok1'], 'the refused dirs are gone');
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(names.length, 0);
});

test('gatedRunDir: never reuses an existing path (exclusive create); gives up with RunDirError and leaves nothing after RUN_DIR_ATTEMPTS refusals', () => {
  const parent = safeMkdtemp(join(tmpdir(), 'zeusi-rundir-'));
  mkdirSync(join(parent, 'run-taken'));
  const names = ['taken', 'ok2'];
  assert.equal(gatedRunDir(parent, 'run-', () => true, () => names.shift()!), join(parent, 'run-ok2'));
  const empty = safeMkdtemp(join(tmpdir(), 'zeusi-rundir-'));
  let n = 0;
  assert.throws(() => gatedRunDir(empty, 'run-', runDirGate([seedWall()], empty), () => `${WALLED}${n++}`), RunDirError);
  assert.equal(n, RUN_DIR_ATTEMPTS);
  assert.deepEqual(readdirSync(empty), []);
});

test('runDirGate: refuses a walled sub-path of a clean dir too (the importer gates filtered/, not only the run dir)', () => {
  const parent = safeMkdtemp(join(tmpdir(), 'zeusi-rundir-'));
  const dir = join(parent, 'run-ok3');
  assert.equal(runDirGate([seedWall()], parent, ['filtered'])(dir), true);
  assert.equal(runDirGate([seedWall()], parent, [`a${WALLED}`])(dir), false);
});

let f: C6Fixture;
let offered = 0;
let walledOffered = 0;
before(async () => {
  // Every work dir the writer creates is offered a walled name first, then a clean one (strict alternation:
  // the clean name is always accepted, so each new dir starts with a walled offer).
  f = await c6Fixture({ runName: () => (offered++ % 2 === 0 ? (walledOffered++, WALLED) : `ok${offered}`) });
});
after(async () => {
  await f.close();
});

test('#55 CI shape: with a walled name offered first for the inbox, the preview run and the commit run, a sealed commit, a plain commit and a sealed sync all save (mutant: commit unsealRun accepts any name -> "Saving did not complete", red)', async () => {
  for (const state of ['on', 'off'] as const) {
    const t = await newWorkspace(f, state);
    const before0 = walledOffered;
    const r = await commitDocs(f, callerOf(t), [{ kind: 'markdown', title: 'Gate', text: '# Gate\n\nheron gate note.\n' }]);
    assert.equal(r.saved, true, state);
    assert.equal(r.notes.inserted, 1, state);
    assert.equal((await counts(f.db, t))['notes'], 1, state);
    assert.ok(walledOffered - before0 >= 3, `${state}: inbox, preview run and commit run were each offered the walled name first`);
  }
  const t = await newWorkspace(f, 'on');
  const before1 = walledOffered;
  const s = await f.ww.sync(callerOf(t), [hqItem('alpha', '2026-10-15-gate.md', 'Sync gate', '# Sync gate\n\nheron sync note.')], []);
  assert.equal(s.counts.inserted, 1, JSON.stringify(s));
  assert.ok(walledOffered - before1 >= 1, 'the sync work dir was offered the walled name first');
});


test('review r2 P3-5 of #55: the commit run dir is also checked against the live wall; a name only a workspace-added hard path rule refuses is re-rolled and the commit saves (mutant: commit gate without loadWall(db) -> "Saving did not complete", red)', async () => {
  // A synthetic hard rule that the seed wall does not have, added to this workspace's own wall only.
  const LIVE = 'xQzLiveOnlyY';
  const next: string[] = [];
  const g = await c6Fixture({ runName: () => next.shift() ?? randomRunName() });
  try {
    const t = await newWorkspace(g, 'on');
    await asOwner(g.db, async () => {
      await g.db.query(`INSERT INTO "${t}".wall_denylist (kind, hard, pattern, reason) VALUES ('path_glob', true, '**qzliveonly**', 'test: live-only rule')`);
    });
    assert.equal(sourcePathGate(join(tmpdir(), `run-${LIVE}`), { wall: seedWall(), home: tmpdir() }).ok, true, 'precondition: the seed wall accepts the name');
    const c = callerOf(t);
    const p = await g.ww.preview(c, [{ kind: 'markdown', title: 'Live', text: '# Live\n\nheron live wall note.\n' }]);
    assert.equal(p.status, 'preview', JSON.stringify(p));
    next.push(LIVE, 'okLive1');
    const r = await g.ww.commit(c, (p as { preview_id: string }).preview_id);
    assert.equal(next.length, 0, 'the commit was offered the live-walled name first, then the clean one');
    assert.equal(r.saved, true);
    assert.equal(r.notes.inserted, 1);
  } finally {
    await g.close();
  }
});

test('review r2 P3-6 of #55: importVault fails a run whose root the path gate refuses, before reading anything (mutant: delete the root-gate throw in src/importers/vault.ts -> status ok, red)', async () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-rundir-'));
  const clean = join(home, 'vault');
  const walled = join(home, `v${WALLED}`);
  const fixture = fileURLToPath(new URL('./fixtures/vault/', import.meta.url));
  cpSync(fixture, clean, { recursive: true });
  cpSync(fixture, walled, { recursive: true });
  const config = validateSources(parseToml(`[[source]]\nname = "vault-work"\nkind = "vault_note"\nscope = "work"\nroot = "${clean}"\ninclude = ["Work/**/*.md", "Home.md", "wiki/*.md"]\n`), seedWall(), { home });
  assert.equal((await importVault({ config, mode: 'full', home, dryRun: true })).status, 'ok', 'precondition: the clean root imports');
  const bad = { ...config, sources: config.sources.map((x) => ({ ...x, root: walled })) };
  const r = await importVault({ config: bad, mode: 'full', home, dryRun: true });
  assert.equal(r.status, 'failed');
  assert.match(r.error ?? '', /root is refused by the path gate/);
  assert.equal(r.counts.inserted, 0, 'nothing read');
});

// ---- the served preview id (fix r1 of #55: seen withheld once in a local full run) ----
// A random 43-character base64url id trips the serve guard about 1 time in 80 000 (wall term or credential shape);
// the whole preview result then comes back "withheld by the serve guard". The guard here is an injected check, so
// no walled term or credential shape is spelled in this file.
const BAD = 'A'.repeat(43);
const GOOD = 'B'.repeat(43);
const refusesBad = (s: string) => s.includes(BAD);

test('servablePreviewId: an id the serve check refuses (or a malformed one) is re-rolled; gives up after PREVIEW_ID_ATTEMPTS', () => {
  const ids = [BAD, 'short', GOOD];
  assert.equal(servablePreviewId(refusesBad, () => ids.shift()!), GOOD);
  let n = 0;
  assert.throws(() => servablePreviewId(refusesBad, () => (n++, BAD)), /no preview id/);
  assert.equal(n, PREVIEW_ID_ATTEMPTS);
});

test('preview: an id the serve guard would withhold is never handed out; the served preview result passes the guard (mutant: preview uses the first random id -> withheld, red)', async () => {
  const ids = [BAD, GOOD];
  const g = await c6Fixture({ previewIdSource: () => ids.shift() ?? GOOD, serveCheck: refusesBad });
  try {
    const t = await newWorkspace(g, 'on');
    const p = await g.ww.preview(callerOf(t), [{ kind: 'markdown', title: 'Id', text: '# Id\n\nheron id note.\n' }]);
    assert.equal((p as { preview_id: string }).preview_id, GOOD);
    assert.equal(wallFilter([p], refusesBad).kept.length, 1, 'the whole result is served');
  } finally {
    await g.close();
  }
});
