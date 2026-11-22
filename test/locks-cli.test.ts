// Lock-lifecycle addendum K5: `zeusi locks lint` (offline, read-only, old vs new parser, walled
// paths never opened) and `zeusi ingest vault --reparse-frontmatter` (dry run = zero writes; real =
// notes.frontmatter only). PGlite, synthetic vault in a temp dir. No network, no Neon, no OpenAI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources, type SourcesConfig } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { frontmatterBlock, importVault, wikilinks } from '../src/importers/vault.ts';
import { parseFrontmatterLegacy } from '../src/importers/frontmatter-legacy.ts';
import { formatLint, lintVault, WITHHELD_TEXT } from '../src/locks-lint.ts';
import { formatReparse, runReparse } from '../src/locks-reparse.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const NOW = new Date('2026-11-17T12:00:00Z');
const WALLED_DIR = ['Plan', 'kiva'].join('');
const WALLED_WORD = ['plan', 'kiva'].join('');

const HASH = '---\ntitle: Hash (synthetic)\ndate: 2026-11-02\nlocks:\n  - SYNTHETIC first\n  - Close #1157; set the quokkabot to weekly\n  - Keep fixing #1057, #1059 — do not park them\n---\nbody text\n';
const MULTI = '---\ntitle: Multi (synthetic)\ndate: 2026-11-04\nlocks:\n  - After gates wombat\n    #1188 merge, make it required\n  - SYNTHETIC second\n---\nb\n';
const SWITCH = '---\ntitle: Switch (synthetic)\ndate: 2026-10-20\nlocks:\n  - SYNTHETIC through Sat 24 Oct tool-A; tool-B resumes Sun 25 Oct\n  - SYNTHETIC during the switch balance both\n---\nb\n';
const OLD = '---\ntitle: Old desk (synthetic)\ndate: 2026-10-29\nlocks:\n  - SYNTHETIC move builds first\n  - SYNTHETIC wipe the platypus desk to distro-A\n---\nb\n';
const NEW = '---\ntitle: New desk (synthetic)\ndate: 2026-11-11\nlocks:\n  - SYNTHETIC archive, then wipe the platypus desk and install any OS\nsupersedes:\n  - "1: [[2026-10-29-old-desk]] lock 2"\n---\nb\n';

const FILES: Record<string, string> = {
  'Work/ops/2026-11-02-hash.md': HASH,
  'Work/handbook/2026-11-04-multi.md': MULTI,
  'Work/ops/2026-10-20-switch.md': SWITCH,
  'Work/ops/2026-10-29-old-desk.md': OLD,
  'Work/ops/2026-11-11-new-desk.md': NEW,
  [`Work/ops/${WALLED_DIR}/secret-locks.md`]: '---\ntitle: never read\nlocks:\n  - SYNTHETIC-NEVER-OPENED #1\n---\n',
  'Work/handbook/walled-text.md': `---\ntitle: Walled text (synthetic)\ndate: 2026-09-01\nlocks:\n  - SYNTHETIC mention of ${WALLED_WORD} here #9\n---\n`,
  'Work/products/p/product.md': '---\ntitle: Product (synthetic)\ndate: 2026-11-05\nlocks:\n  - Ship #42 first\n---\n',
};

function vault(): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-locks-cli-'));
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(join(dir, 'vault', rel)), { recursive: true });
    writeFileSync(join(dir, 'vault', rel), text);
  }
  return dir;
}

test('locks lint: old vs new counts, changed items as vault_path:ord, lifecycle resolution, candidates; walled path never listed, walled text withheld', () => {
  const dir = vault();
  try {
    const r = lintVault({ root: join(dir, 'vault'), now: NOW });
    assert.deepEqual(r.scanned_prefixes, ['Work/ops/', 'Work/handbook/']);
    assert.equal(r.files, 6, 'the walled folder is never walked; products are outside the standing set');
    // old: the multi-line block was ONE raw string; new: two items
    assert.deepEqual(r.lock_items, { old: 10, new: 11 });
    assert.deepEqual(r.changed.map((c) => c.ref).sort(), [
      'Work/handbook/2026-11-04-multi.md:1', 'Work/handbook/2026-11-04-multi.md:2', 'Work/handbook/walled-text.md:1',
      'Work/ops/2026-11-02-hash.md:2', 'Work/ops/2026-11-02-hash.md:3',
    ]);
    const by = (ref: string) => r.changed.find((c) => c.ref === ref)!;
    assert.deepEqual(by('Work/ops/2026-11-02-hash.md:2'), { ref: 'Work/ops/2026-11-02-hash.md:2', old: 'Close', new: 'Close #1157; set the quokkabot to weekly' });
    assert.deepEqual(by('Work/handbook/2026-11-04-multi.md:1'), {
      ref: 'Work/handbook/2026-11-04-multi.md:1', old: '  - After gates wombat\n    #1188 merge, make it required\n  - SYNTHETIC second', new: 'After gates wombat #1188 merge, make it required',
    });
    assert.deepEqual(by('Work/handbook/2026-11-04-multi.md:2'), { ref: 'Work/handbook/2026-11-04-multi.md:2', old: null, new: 'SYNTHETIC second' });
    assert.deepEqual([by('Work/handbook/walled-text.md:1').old, by('Work/handbook/walled-text.md:1').new], [WITHHELD_TEXT, WITHHELD_TEXT]);
    assert.deepEqual(r.superseded, [{ ref: 'Work/ops/2026-10-29-old-desk.md:2', by: 'Work/ops/2026-11-11-new-desk.md:1' }]);
    assert.equal(r.lifecycle.supersede_applied, 1);
    assert.deepEqual(r.candidates_timebox.map((t) => t.ref), ['Work/ops/2026-10-20-switch.md:1', 'Work/ops/2026-10-20-switch.md:2']);
    const out = formatLint(r);
    assert.ok(!out.includes('SYNTHETIC-NEVER-OPENED') && !out.includes(WALLED_DIR));
    assert.doesNotMatch(out, /plankiva/i);
    assert.match(out, /CANDIDATES \(not applied/);
    // --all: every Work/ folder (still never the walled one)
    const all = lintVault({ root: join(dir, 'vault'), all: true, now: NOW });
    assert.equal(all.files, 7);
    assert.ok(all.changed.some((c) => c.ref === 'Work/products/p/product.md:1' && c.old === 'Ship' && c.new === 'Ship #42 first'));
    assert.doesNotMatch(JSON.stringify(all), /plankiva|NEVER-OPENED/i);
    // nothing in the vault changed
    for (const [rel, text] of Object.entries(FILES)) assert.equal(readFileSync(join(dir, 'vault', rel), 'utf8'), text);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// reparse

interface Env { db: Db; dir: string; config: SourcesConfig; close(): Promise<void> }

async function ingested(): Promise<Env> {
  const dir = vault();
  rmSync(join(dir, 'vault', 'Work/ops', WALLED_DIR), { recursive: true, force: true });
  const config = validateSources(parseToml(`[[source]]\nname = "vault-all"\nkind = "vault_note"\nscope = "work"\nroot = "${join(dir, 'vault')}"\ninclude = ["**/*.md"]\n`), seedWall(), { home: dir });
  const db = await pgliteDb();
  await migrate(db);
  await db.exec('SET ROLE zeusi_mini_ingest');
  try {
    const r = await importVault({ db, config, mode: 'full', home: dir });
    assert.equal(r.status, 'ok');
  } finally {
    await db.exec('RESET ROLE');
  }
  // Simulate what the OLD parser stored (frontmatter only; owner, test setup).
  for (const [rel, text] of Object.entries(FILES)) {
    if (rel.includes(WALLED_DIR)) continue;
    const fm = parseFrontmatterLegacy(frontmatterBlock(text)!);
    const links = wikilinks(...Object.values(fm).flat(), text.slice(text.indexOf('\n---\n') + 5));
    await db.query(`UPDATE zeusi.notes SET frontmatter = $2::jsonb WHERE vault_path = $1`, [rel, JSON.stringify({ ...fm, links })]);
  }
  return { db, dir, config, close: async () => { await db.close(); rmSync(dir, { recursive: true, force: true }); } };
}

const snapshot = async (db: Db) => (await db.query<{ d: string }>(
  `SELECT md5(coalesce((SELECT string_agg(concat_ws('|', id, vault_path, title, body, status, scope, source_sha256, source_ts, ingest_run_id, ingested_at, ingested_by, file_mtime), ',' ORDER BY id) FROM zeusi.notes), '')
          || coalesce((SELECT string_agg(concat_ws('|', id, note_id, text, heading_path, text_sha256, embedding IS NULL), ',' ORDER BY id) FROM zeusi.chunks), '')
          || (SELECT count(*) FROM zeusi.ingest_runs)::text || (SELECT count(*) FROM zeusi.quarantine)::text) AS d`)).rows[0]!.d;
const frontmatters = async (db: Db) => (await db.query<{ d: string }>(`SELECT md5(string_agg(frontmatter::text, ',' ORDER BY id)) AS d FROM zeusi.notes`)).rows[0]!.d;

test('reparse dry run: counts only, ZERO writes (READ ONLY); real run: ONLY notes.frontmatter changes, then startup-relevant locks are whole', async () => {
  const e = await ingested();
  try {
    const before = await snapshot(e.db);
    const fmBefore = await frontmatters(e.db);
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    let dry;
    try {
      dry = await runReparse({ db: e.db, config: e.config, real: false, now: NOW, home: e.dir });
    } finally {
      await e.db.exec('RESET ROLE');
    }
    assert.equal(dry.status, 'ok');
    assert.equal(dry.notes_scanned, 6, 'the walled-text note was never stored (content wall)');
    assert.equal(dry.not_stored, 1, 'never stored: counted before the file is even opened');
    assert.equal(dry.blocked, 0);
    assert.equal(dry.frontmatter_changed, 3, 'hash, multi, product');
    assert.equal(dry.frontmatter_updated, 0);
    assert.deepEqual([dry.locks_before.items, dry.locks_after.items], [10, 11]);
    assert.deepEqual([dry.locks_after.current, dry.locks_after.superseded, dry.locks_after.expired], [10, 1, 0]);
    assert.equal(await snapshot(e.db), before);
    assert.equal(await frontmatters(e.db), fmBefore, 'dry run wrote nothing');
    const out = formatReparse(dry);
    assert.match(out, /dry run: READ ONLY, nothing written/);
    assert.ok(!/SYNTHETIC|Close|quokkabot|the team\//.test(out), 'counts only: no text, no path');

    await e.db.exec('SET ROLE zeusi_mini_ingest');
    let real;
    try {
      real = await runReparse({ db: e.db, config: e.config, real: true, now: NOW, home: e.dir });
    } finally {
      await e.db.exec('RESET ROLE');
    }
    assert.equal(real.status, 'ok');
    assert.equal(real.frontmatter_updated, 3);
    assert.equal(real.write_errors, 0);
    assert.equal(await snapshot(e.db), before, 'body, title, chunks, embeddings, provenance, runs, quarantine untouched');
    assert.notEqual(await frontmatters(e.db), fmBefore);
    const locks = (await e.db.query<{ l: string[] }>(`SELECT frontmatter->'locks' AS l FROM zeusi.notes WHERE vault_path = 'Work/ops/2026-11-02-hash.md'`)).rows[0]!.l;
    assert.deepEqual(locks, ['SYNTHETIC first', 'Close #1157; set the quokkabot to weekly', 'Keep fixing #1057, #1059 — do not park them']);
    const multi = (await e.db.query<{ l: string[] }>(`SELECT frontmatter->'locks' AS l FROM zeusi.notes WHERE vault_path = 'Work/handbook/2026-11-04-multi.md'`)).rows[0]!.l;
    assert.deepEqual(multi, ['After gates wombat #1188 merge, make it required', 'SYNTHETIC second']);
    // idempotent
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      const again = await runReparse({ db: e.db, config: e.config, real: true, now: NOW, home: e.dir });
      assert.deepEqual([again.frontmatter_changed, again.frontmatter_updated, again.frontmatter_unchanged], [0, 0, 6]);
    } finally {
      await e.db.exec('RESET ROLE');
    }
  } finally {
    await e.close();
  }
});

test('reparse: a changed file, a new file and a note the wall now blocks are left untouched (no insert, no quarantine, no retract); --scope narrows', async () => {
  const e = await ingested();
  try {
    writeFileSync(join(e.dir, 'vault', 'Work/ops/2026-10-20-switch.md'), SWITCH.replace('balance both', 'balance both (edited)'));
    writeFileSync(join(e.dir, 'vault', 'Work/ops/brand-new.md'), '---\ntitle: New (synthetic)\nlocks:\n  - Do #7\n---\n');
    const before = await snapshot(e.db);
    const notes = (await e.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes`)).rows[0]!.n;
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      const r = await runReparse({ db: e.db, config: e.config, real: true, now: NOW, home: e.dir });
      assert.equal(r.file_changed, 1);
      assert.equal(r.not_stored, 2, 'brand-new file + the never-stored walled-text note');
      const none = await runReparse({ db: e.db, config: e.config, real: true, now: NOW, home: e.dir, scope: 'client' });
      assert.deepEqual([none.notes_scanned, none.frontmatter_changed], [0, 0]);
    } finally {
      await e.db.exec('RESET ROLE');
    }
    assert.equal((await e.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes`)).rows[0]!.n, notes, 'nothing inserted');
    assert.equal(await snapshot(e.db), before);
    // a note the content wall blocks now (the file names the walled person): left exactly as stored
    writeFileSync(join(e.dir, 'vault', 'Work/ops/2026-10-29-old-desk.md'), OLD.replace('move builds first', `move builds first ${WALLED_WORD}`));
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      const r = await runReparse({ db: e.db, config: e.config, real: true, now: NOW, home: e.dir });
      assert.equal(r.status, 'ok');
      assert.equal(r.blocked, 1, 'the now-walled old desk note');
    } finally {
      await e.db.exec('RESET ROLE');
    }
    assert.equal(await snapshot(e.db), before, 'no quarantine row, no retracted chunk');
  } finally {
    await e.close();
  }
});

// ---------------------------------------------------------------------------
// CLI refusals (offline, before any connection)

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function cli(args: string[], files: Record<string, string> = {}) {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-locks-cmd-'));
  try {
    for (const [rel, text] of Object.entries(files)) writeFileSync(join(dir, rel), text.replaceAll('$DIR', dir));
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: dir, PGSERVICEFILE: join(dir, 'pg_service.conf') };
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', env, timeout: 20_000 });
    return { code: r.status, out: `${r.stdout}${r.stderr}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('cli: locks lint usage, walled --vault refused; reparse flag combinations refused and a pooled endpoint refused offline (no connection)', () => {
  assert.equal(cli(['locks']).code, 2);
  assert.match(cli(['locks', 'lint']).out, /usage: locks lint --vault <root>/);
  assert.match(cli(['locks', 'lint', '--vault', `/tmp/${WALLED_DIR}Vault`]).out, /refused \(walled path\)/);
  const cfg = { 'sources.toml': '[[source]]\nname = "v"\nkind = "vault_note"\nscope = "work"\nroot = "$DIR"\ninclude = ["**/*.md"]\n' };
  assert.match(cli(['ingest', 'hq-sync', '--reparse-frontmatter']).out, /for ingest vault only/);
  assert.match(cli(['ingest', 'vault', '--reparse-frontmatter', '--real', '--dry-run', '--config', 'sources.toml'], cfg).out, /exclude each other/);
  assert.match(cli(['ingest', 'vault', '--reparse-frontmatter', '--i-know-this-is-main', '--config', 'sources.toml'], cfg).out, /applies to --real only/);
  assert.match(cli(['ingest', 'vault', '--reparse-frontmatter', '--scope', 'personal', '--config', 'sources.toml'], cfg).out, /--scope must be one of/);
  const pooled = cli(['ingest', 'vault', '--reparse-frontmatter', '--config', 'sources.toml'], {
    ...cfg, 'pg_service.conf': `[zeusi_ingest]\nhost=${['ep-fake-9', '-pooler.eu-central-1.aws.neon.tech'].join('')}\nport=5432\ndbname=zeusi\nuser=zeusi_ingest\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`,
  });
  assert.notEqual(pooled.code, 0);
  assert.match(pooled.out, /pooled|direct/i);
  assert.doesNotMatch(pooled.out, /neon\.tech/);
});
