// Zeus HQ export ingest (docs/hq-sync.md): importVault with HQ_PROFILE.
// Synthetic notes written to a temp dir at test time. PGlite only: no network, no Neon.
// Imports run as zeusi_mini_ingest (SET ROLE) so the grants are exercised.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources, type SourcesConfig } from '../src/sources.ts';
import { seedWall, sha256Hex, wallReadiness } from '../src/wall.ts';
import { wallAudit } from '../src/wall-admin.ts';
import { ConfigError } from '../src/config.ts';
import { HQ_PROFILE, importVault, formatVaultResult, pathQuarantineUri, type VaultImportOptions } from '../src/importers/vault.ts';
import { hqFormatProblem } from '../src/importers/profile.ts';
import { hqNote } from './hq-fixtures.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const OLD = new Date('2026-01-05T10:00:00Z');

function config(root: string, extra = ''): SourcesConfig {
  return validateSources(parseToml(`
[[source]]
name = "hq-general"
kind = "zeus_memory"
scope = "work"
root = "${root}"
include = ["hq/*.md"]
project = "hq"

[[source]]
name = "hq-team"
kind = "zeus_memory"
scope = "work"
root = "${root}"
include = ["team/*.md"]
project = "team"

[[source]]
name = "hq-northbank"
kind = "zeus_memory"
scope = "product"
root = "${root}"
include = ["northbank/*.md"]
project = "northbank"
content_scan = true
${extra}`), seedWall(), { home: root });
}

interface Env {
  db: Db;
  dir: string;
  root: string;
  config: SourcesConfig;
  logs: string[];
  write(rel: string, text: string): void;
  run(o?: Partial<VaultImportOptions>): ReturnType<typeof importVault>;
  close(): Promise<void>;
}

async function fresh(): Promise<Env> {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-hq-'));
  const root = join(dir, 'zeus-hq');
  for (const p of ['hq', 'work', 'team', 'northbank', 'client', 'clientco']) mkdirSync(join(root, p), { recursive: true });
  const db = await pgliteDb();
  await migrate(db);
  const logs: string[] = [];
  const env: Env = {
    db, dir, root, config: config(root), logs,
    write(rel, text) {
      writeFileSync(join(root, rel), text);
      utimesSync(join(root, rel), OLD, OLD);
    },
    async run(o = {}) {
      await db.exec('SET ROLE zeusi_mini_ingest');
      try {
        return await importVault({ db, config: env.config, mode: 'full', home: dir, log: (l) => logs.push(l), profile: HQ_PROFILE, ...o });
      } finally {
        await db.exec('RESET ROLE');
      }
    },
    async close() {
      await db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return env;
}

async function notes(db: Db) {
  return (await db.query<{ vault_path: string; title: string; status: string; scope: string; source_kind: string; source_uri: string; note_date: string | null; frontmatter: Record<string, unknown> }>(
    `SELECT vault_path, title, status, scope::text AS scope, source_kind::text AS source_kind, source_uri, note_date::text AS note_date, frontmatter
     FROM zeusi.notes ORDER BY vault_path`,
  )).rows;
}

function seed(e: Env) {
  e.write('team/2026-11-13-hq-chat.md', hqNote({ project: 'team' }, [
    ['2026-11-13T09:00:00+01:00 owner', 'Synthetic turn one about the release checklist.'],
    ['2026-11-13T09:05:00+01:00 zeus', 'Synthetic turn two: the checklist has four steps.'],
  ]));
  e.write('northbank/2026-11-13-standup.md', hqNote({ project: 'northbank', kind: 'decision', title: 'Northbank standup' }, [
    ['2026-11-13T10:00:00+01:00 decision', 'Synthetic decision: ship the coverage watcher docs first.'],
  ]));
  e.write('hq/2026-11-13-journal.md', hqNote({ project: 'hq', kind: 'journal', title: 'Journal' }, [
    ['2026-11-13T22:00:00+01:00', 'Synthetic journal entry.'],
  ]));
  e.write('hq/2026-11-13-memory.md', hqNote({ project: 'hq', kind: 'memory', title: 'Memory delta' }, [
    ['2026-11-13T23:00:00+01:00 memory', 'Synthetic memory delta: prefers short plans.'],
  ]));
}

test('hq-sync: export notes land as zeus_memory with hq: uris, project scope, kind in frontmatter; second run skips all', async () => {
  const e = await fresh();
  try {
    seed(e);
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.inserted, 4);
    const all = await notes(e.db);
    assert.deepEqual(all.map((n) => n.vault_path), [
      'hq:hq/2026-11-13-journal.md', 'hq:hq/2026-11-13-memory.md', 'hq:northbank/2026-11-13-standup.md', 'hq:team/2026-11-13-hq-chat.md',
    ]);
    for (const n of all) {
      assert.equal(n.source_kind, 'zeus_memory');
      assert.equal(n.source_uri, n.vault_path, 'source_uri hq:<project>/<file>');
      assert.equal(n.note_date, '2026-11-13');
    }
    const chat = all.find((n) => n.vault_path.includes('hq-chat'))!;
    assert.equal(chat.frontmatter['project'], 'team');
    assert.equal(chat.frontmatter['kind'], 'chat');
    assert.equal(chat.frontmatter['thread_id'], 't-0001');
    assert.equal(chat.scope, 'work');
    assert.equal(all.find((n) => n.vault_path.includes('standup'))!.scope, 'product');

    // One chunk per H2 entry; chunk uris #c<n>, never heading text.
    const ch = (await e.db.query<{ heading_path: string; source_uri: string; source_kind: string }>(
      `SELECT c.heading_path, c.source_uri, c.source_kind::text AS source_kind FROM zeusi.chunks c JOIN zeusi.notes n ON n.id = c.note_id
       WHERE n.vault_path = 'hq:team/2026-11-13-hq-chat.md' ORDER BY c.chunk_index`)).rows;
    assert.deepEqual(ch.map((c) => c.source_uri), ['hq:team/2026-11-13-hq-chat.md#c0', 'hq:team/2026-11-13-hq-chat.md#c1']);
    assert.deepEqual(ch.map((c) => c.heading_path), ['2026-11-13T09:00:00+01:00 owner', '2026-11-13T09:05:00+01:00 zeus']);
    assert.ok(ch.every((c) => c.source_kind === 'zeus_memory'));

    // chat / journal / memory / decision are distinguishable in queries.
    const kinds = (await e.db.query<{ kind: string; n: number }>(
      `SELECT frontmatter->>'kind' AS kind, count(*)::int AS n FROM zeusi.notes WHERE source_kind = 'zeus_memory' GROUP BY 1 ORDER BY 1`)).rows;
    assert.deepEqual(kinds, [{ kind: 'chat', n: 1 }, { kind: 'decision', n: 1 }, { kind: 'journal', n: 1 }, { kind: 'memory', n: 1 }]);

    const run = (await e.db.query<{ importer: string; status: string }>(`SELECT importer, status FROM zeusi.ingest_runs WHERE id = $1`, [r.runId])).rows[0]!;
    assert.deepEqual(run, { importer: 'hq-sync', status: 'ok' }, 'own ingest_runs rows: KTD13 freshness per importer');

    const r2 = await e.run();
    assert.equal(r2.counts.inserted, 0);
    assert.equal(r2.counts.updated, 0);
    assert.equal(r2.counts.skipped, 4);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('hq-sync: same-day re-export with identical bytes is skipped, an edit updates in place, a removed file is marked deleted', async () => {
  const e = await fresh();
  try {
    seed(e);
    await e.run();
    seed(e); // the routine rewrites the same file names with the same bytes
    const same = await e.run();
    assert.equal(same.counts.skipped, 4);
    assert.equal(same.counts.updated, 0);

    e.write('team/2026-11-13-hq-chat.md', hqNote({ project: 'team' }, [
      ['2026-11-13T09:00:00+01:00 owner', 'Synthetic turn one about the release checklist.'],
      ['2026-11-13T09:05:00+01:00 zeus', 'Synthetic turn two: edited later the same day.'],
      ['2026-11-13T18:00:00+01:00 owner', 'Synthetic turn three, appended in the evening export.'],
    ]));
    const edit = await e.run();
    assert.equal(edit.counts.updated, 1);
    assert.equal(edit.counts.skipped, 3);
    const texts = (await e.db.query<{ text: string }>(
      `SELECT c.text FROM zeusi.chunks c JOIN zeusi.notes n ON n.id = c.note_id WHERE n.vault_path = 'hq:team/2026-11-13-hq-chat.md' ORDER BY c.chunk_index`)).rows;
    assert.equal(texts.length, 3);
    assert.match(texts[1]!.text, /edited later/);

    rmSync(join(e.root, 'hq/2026-11-13-memory.md'));
    const del = await e.run();
    assert.equal(del.counts.deleted, 1);
    const n = (await notes(e.db)).find((x) => x.vault_path === 'hq:hq/2026-11-13-memory.md')!;
    assert.equal(n.status, 'deleted');
  } finally {
    await e.close();
  }
});

test('hq-sync and the vault importer never delete each other\'s notes (source_kind + vault_path prefix)', async () => {
  const e = await fresh();
  try {
    seed(e);
    const vault = join(e.dir, 'vault');
    mkdirSync(join(vault, 'Work'), { recursive: true });
    writeFileSync(join(vault, 'Work/plain.md'), '# Plain\n\nSynthetic vault note.\n');
    const vcfg = validateSources(parseToml(`[[source]]\nname = "v"\nkind = "vault_note"\nscope = "work"\nroot = "${vault}"\ninclude = ["Work/*.md"]\n`), seedWall(), { home: e.dir });
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    const v1 = await importVault({ db: e.db, config: vcfg, mode: 'full', home: e.dir });
    await e.db.exec('RESET ROLE');
    assert.equal(v1.counts.inserted, 1);
    const h = await e.run();
    assert.equal(h.counts.inserted, 4);
    assert.equal(h.counts.deleted, 0);
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    const v2 = await importVault({ db: e.db, config: vcfg, mode: 'full', home: e.dir });
    await e.db.exec('RESET ROLE');
    assert.equal(v2.counts.deleted, 0);
    assert.equal(v2.counts.skipped, 1);
    assert.equal((await notes(e.db)).filter((n) => n.status === 'active').length, 5);
  } finally {
    await e.close();
  }
});

test('hq-sync: files that are not in the export format are errors (no text logged), never inserted', async () => {
  const e = await fresh();
  try {
    seed(e);
    e.write('team/notes.md', '# no date in the name\n');
    e.write('team/2026-11-13-wrong-project.md', hqNote({ project: 'northbank' }, [['t', 'synthetic body marker-wp']]));
    e.write('team/2026-11-13-bad-kind.md', hqNote({ project: 'team', kind: 'gossip' }, [['t', 'synthetic body marker-bk']]));
    e.write('team/2026-11-13-date-mismatch.md', hqNote({ project: 'team', date: '2026-11-12' }, [['t', 'synthetic body marker-dm']]));
    e.write('team/2026-11-13-no-fm.md', '## 09:00\n\nsynthetic body marker-nf\n');
    const r = await e.run();
    assert.equal(r.counts.inserted, 4);
    assert.equal(r.counts.errors, 5);
    assert.equal(r.counts.quarantined, 0);
    assert.ok(e.logs.every((l) => !/marker-/.test(l)), 'no note text in logs');
  } finally {
    await e.close();
  }
});

test('hqFormatProblem: layout and frontmatter rules', () => {
  const fm = { title: 'x', date: '2026-11-13', source: 'zeus-hq', project: 'team', kind: 'chat' };
  assert.equal(hqFormatProblem('team/2026-11-13-a.md', fm, 'team'), null);
  assert.match(hqFormatProblem('team/2026-11-13-a.md', fm, 'hq')!, /source project/);
  assert.match(hqFormatProblem('team/sub/2026-11-13-a.md', fm, null)!, /project>\/<file/);
  assert.match(hqFormatProblem('team/2026-02-30-a.md', { ...fm, date: '2026-02-30' }, null)!, /file name/);
  assert.match(hqFormatProblem('Work/2026-11-13-a.md', fm, null)!, /slug/);
  assert.match(hqFormatProblem('team/2026-11-13-a.md', { ...fm, title: '' }, null)!, /title/);
  assert.match(hqFormatProblem('team/2026-11-13-a.md', { ...fm, source: '' }, null)!, /source/);
  assert.match(hqFormatProblem('team/2026-11-13-a.md', null, null)!, /frontmatter/);
});

test('hq-sync: the wall still applies: hard Plankiva text quarantines the whole note (uri + hash only), a soft rule (account number) quarantines too; currency passes since 0011', async () => {
  const e = await fresh();
  try {
    seed(e);
    // Obviously synthetic exclusion probes (the filter would have withheld these entries).
    e.write('team/2026-11-13-probe-hard.md', hqNote({ project: 'team' }, [['t1', 'synthetic exclusion probe: plankiva']]));
    e.write('team/2026-11-13-probe-soft.md', hqNote({ project: 'team' }, [['t1', 'synthetic account 1234567']]));
    // 0011 (the owner 15 Nov 2026 01:09) lifted the soft currency and P&L rules: currency text is admitted.
    e.write('team/2026-11-13-currency.md', hqNote({ project: 'team' }, [['t1', 'synthetic invoice of CHF 120']]));
    const r = await e.run();
    assert.equal(r.counts.inserted, 5);
    assert.equal(r.counts.quarantined, 2);
    const q = (await e.db.query<{ source_uri: string; source_kind: string }>(`SELECT source_uri, source_kind::text AS source_kind FROM zeusi.quarantine ORDER BY 1`)).rows;
    assert.ok(q.every((x) => x.source_kind === 'zeus_memory' && /^hq:team\/2026-11-13-probe-(hard|soft)\.md(#c\d+)?$/.test(x.source_uri)));
    const dump = (await e.db.query<{ t: string }>(`SELECT coalesce(string_agg(body, ' '), '') AS t FROM zeusi.notes`)).rows[0]!.t;
    assert.doesNotMatch(dump, /plankiva|account 1234567/i);
    assert.match(dump, /CHF 120/);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('hq-sync: a walled file name is path-gated by hash (hq-path-sha256:), never opened', async () => {
  const e = await fresh();
  try {
    seed(e);
    const rel = 'team/2026-11-13-plankiva-probe.md';
    e.write(rel, hqNote({ project: 'team' }, [['t', 'synthetic']]));
    const r = await e.run();
    assert.equal(r.counts.path_gated, 1);
    const q = (await e.db.query<{ source_uri: string }>(`SELECT source_uri FROM zeusi.quarantine`)).rows;
    assert.deepEqual(q.map((x) => x.source_uri), [pathQuarantineUri(rel, HQ_PROFILE)]);
    assert.equal(pathQuarantineUri(rel, HQ_PROFILE), `hq-path-sha256:${sha256Hex(rel)}`);
  } finally {
    await e.close();
  }
});

test('hq-sync config: a project key must be a slug, zeus_memory only, includes under the folder; a clientco folder loads only as its own scope clientco source', () => {
  const root = safeMkdtemp(join(tmpdir(), 'zeusi-hq-cfg-'));
  try {
    const bad = (extra: string) => {
      try {
        config(root, extra);
        return '';
      } catch (err) {
        assert.ok(err instanceof ConfigError);
        return err.message;
      }
    };
    assert.match(bad('\n[[source]]\nname = "x"\nkind = "zeus_memory"\nroot = "/tmp/x"\ninclude = ["Bad/*.md"]\nproject = "Bad"\n'), /slug/);
    assert.match(bad('\n[[source]]\nname = "x"\nkind = "vault_note"\nroot = "/tmp/x"\ninclude = ["a/*.md"]\nproject = "a"\n'), /only valid for kind zeus_memory/);
    assert.match(bad('\n[[source]]\nname = "x"\nkind = "zeus_memory"\nroot = "/tmp/x"\ninclude = ["b/*.md"]\nproject = "a"\n'), /under "a\/"/);
    // the owner: ClientCo goes into Zeusi with its own scope (0010 lifted the ClientCo hard rules).
    const clientco = (scope: string, project = 'clientco', include = 'clientco/*.md') =>
      `\n[[source]]\nname = "hq-clientco"\nkind = "zeus_memory"\nscope = "${scope}"\nroot = "${root}"\ninclude = ["${include}"]\nproject = "${project}"\n`;
    assert.equal(bad(clientco('client')), '');
    const v = config(root, clientco('client')).sources.find((x) => x.name === 'hq-clientco')!;
    assert.deepEqual([v.kind, v.scope, v.project, v.include], ['zeus_memory', 'client', 'clientco', ['clientco/*.md']]);
    // The clientco folder never lands under another scope, and scope clientco is only for the clientco folder.
    assert.match(bad(clientco('work')), /project "clientco" needs scope "client"/);
    assert.match(bad(clientco('product')), /project "clientco" needs scope "client"/);
    assert.match(bad(clientco('client', 'labs', 'labs/*.md')), /scope "client" is only for project "clientco"/);
    assert.match(bad('\n[[source]]\nname = "x"\nkind = "zeus_memory"\nscope = "client"\nroot = "/tmp/x"\ninclude = ["clientco/*.md"]\n'), /scope "client" is only for project "clientco"/);
    // The Plankiva rule still applies to a clientco source (synthetic exclusion probe).
    assert.match(bad(clientco('client', 'clientco', 'clientco/%70lankiva-probe/*.md')), /plankiva/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('hq-sync dry run: no database, counts only, hq-sync label', async () => {
  const e = await fresh();
  try {
    seed(e);
    const r = await importVault({ config: e.config, mode: 'full', dryRun: true, home: e.dir, profile: HQ_PROFILE });
    assert.equal(r.counts.inserted, 4);
    const out = formatVaultResult(r, seedWall().rules, true, HQ_PROFILE);
    assert.match(out, /^hq-sync ingest \(dry run/);
    assert.doesNotMatch(out, /2026-11-13|team\//);
  } finally {
    await e.close();
  }
});

test('example config: one zeus_memory source per HQ project folder, one shared root, Northbank scoped product with content_scan', async () => {
  const { loadSources } = await import('../src/sources.ts');
  const ex = loadSources(fileURLToPath(new URL('../config/sources.example.toml', import.meta.url)));
  const hq = ex.sources.filter((s) => s.kind === 'zeus_memory');
  assert.deepEqual(hq.map((s) => s.project), ['team', 'northbank', 'clientco']);
  assert.equal(new Set(hq.map((s) => s.root)).size, 1);
  assert.ok(hq.every((s) => s.include.length === 1 && s.include[0] === `${s.project}/*.md`));
  const t = hq.find((s) => s.project === 'northbank')!;
  assert.equal(t.scope, 'product');
  assert.equal(t.contentScan, true);
  const v = hq.find((s) => s.project === 'clientco')!;
  assert.deepEqual([v.name, v.scope, v.root, v.include], ['hq-clientco', 'client', '~/zeusi-sources/hq-export', ['clientco/*.md']]);
  assert.ok(hq.filter((s) => s !== t && s !== v).every((s) => s.scope === 'work'));
  assert.ok(!(ex.hqExport?.held ?? []).includes('clientco'), 'clientco is enabled, no longer held');
});

test('hq-sync ClientCo (0010 + 0011 applied): a clientco note is imported with scope clientco; an Plankiva-signal clientco note is quarantined (hard), never stored', async () => {
  const e = await fresh();
  try {
    e.config = config(e.root, `\n[[source]]\nname = "hq-clientco"\nkind = "zeus_memory"\nscope = "client"\nroot = "${e.root}"\ninclude = ["clientco/*.md"]\nproject = "clientco"\n`);
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      assert.deepEqual((await wallReadiness(e.db)).problems, [], 'wall migrations 0006-0011 applied');
    } finally {
      await e.db.exec('RESET ROLE');
    }
    seed(e);
    e.write('clientco/2026-11-13-chat-desk.md', hqNote({ project: 'clientco' }, [['t1', 'Synthetic ClientCo desk note: client alpha review, CHF 120 fee.']]));
    // Obviously synthetic exclusion probe (export-filter would have withheld this entry).
    e.write('clientco/2026-11-13-chat-probe.md', hqNote({ project: 'clientco' }, [['t1', 'synthetic exclusion probe: plankiva']]));
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.inserted, 5);
    assert.equal(r.counts.quarantined, 1);
    assert.equal(r.counts.by_scope['client'], 1);
    const v = (await notes(e.db)).filter((n) => n.vault_path.startsWith('hq:clientco/'));
    assert.deepEqual(v.map((n) => [n.vault_path, n.scope, n.source_kind, n.source_uri]), [
      ['hq:clientco/2026-11-13-chat-desk.md', 'client', 'zeus_memory', 'hq:clientco/2026-11-13-chat-desk.md'],
    ]);
    const ch = (await e.db.query<{ scope: string }>(`SELECT scope::text AS scope FROM zeusi.chunks WHERE source_uri LIKE 'hq:clientco/%'`)).rows;
    assert.ok(ch.length > 0 && ch.every((c) => c.scope === 'client'));
    const q = (await e.db.query<{ source_uri: string; hard: boolean }>(
      `SELECT q.source_uri, d.hard FROM zeusi.quarantine q JOIN zeusi.wall_denylist d ON d.id = q.rule_id`)).rows;
    assert.ok(q.length >= 1 && q.every((x) => x.hard && /^hq:clientco\/2026-11-13-chat-probe\.md(#c\d+)?$/.test(x.source_uri)));
    const dump = (await e.db.query<{ t: string }>(`SELECT coalesce(string_agg(body, ' '), '') AS t FROM zeusi.notes`)).rows[0]!.t;
    assert.doesNotMatch(dump, /plankiva/i);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('hq-sync ClientCo: a clientco/ note reached by a non-clientco source is a file error, never stored under another scope', async () => {
  const e = await fresh();
  try {
    // No project key, so validation cannot tie the glob to a folder; the importer refuses at run time.
    e.config = config(e.root, `\n[[source]]\nname = "hq-wide"\nkind = "zeus_memory"\nscope = "work"\nroot = "${e.root}"\ninclude = ["c*/*.md"]\n`);
    seed(e);
    e.write('clientco/2026-11-13-chat-desk.md', hqNote({ project: 'clientco' }, [['t1', 'Synthetic ClientCo desk note.']]));
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.inserted, 4);
    assert.equal(r.counts.errors, 1);
    assert.equal((await notes(e.db)).filter((n) => n.vault_path.startsWith('hq:clientco/')).length, 0);
  } finally {
    await e.close();
  }
});

test('CLI: ingest hq-sync refuses write mode without --real (no connection) and dry-runs offline with counts only', () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-hq-cli-'));
  try {
    const root = join(dir, 'zeus-hq');
    mkdirSync(join(root, 'work'), { recursive: true });
    mkdirSync(join(root, 'team'), { recursive: true });
    writeFileSync(join(root, 'team/2026-11-13-hq-chat.md'), hqNote({ project: 'team' }, [['t1', 'synthetic clean turn']]));
    const cfg = join(dir, 'sources.toml');
    writeFileSync(cfg, `[[source]]\nname = "hq-team"\nkind = "zeus_memory"\nscope = "work"\nroot = "${root}"\ninclude = ["team/*.md"]\nproject = "team"\n`);
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: dir, PGSERVICEFILE: join(dir, 'missing.conf') };
    const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
    const run = (args: string[]) => spawnSync(process.execPath, [cli, ...args], { cwd: dir, encoding: 'utf8', env, timeout: 20_000 });
    const w = run(['ingest', 'hq-sync', '--config', cfg]);
    assert.equal(w.status, 2);
    assert.match(w.stderr, /needs --real/);
    const d = run(['ingest', 'hq-sync', '--dry-run', '--config', cfg]);
    assert.equal(d.status, 0, d.stderr);
    assert.match(d.stdout, /^hq-sync ingest \(dry run/);
    assert.match(d.stdout, /would insert: 1 note\(s\)/);
    assert.doesNotMatch(d.stdout, /hq-chat|synthetic/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Fix round 1, m6: the deletion guard's prefix clause (left(vault_path, len) = 'hq:') on its own.
test('m6: a zeus_memory row without the hq: prefix (another writer) is never read, marked deleted or counted by hq-sync', async () => {
  const e = await fresh();
  try {
    const run = Number((await e.db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
    await e.db.query(
      `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('zx:other-writer/n.md', 'n', 'synthetic other writer', now(), 'work', 'zeus_memory', 'zx:other-writer/n.md', now(), decode($1, 'hex'), $2)`,
      [sha256Hex('n'), run],
    );
    seed(e);
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.inserted, 4);
    assert.equal(r.counts.deleted, 0);
    const other = (await notes(e.db)).find((x) => x.vault_path === 'zx:other-writer/n.md')!;
    assert.equal(other.status, 'active', 'same source_kind, other prefix: untouched');
    // A second run with every HQ file gone trips the empty-folder guard on the 4 hq: rows only.
    for (const f of ['team/2026-11-13-hq-chat.md', 'northbank/2026-11-13-standup.md', 'hq/2026-11-13-journal.md', 'hq/2026-11-13-memory.md']) rmSync(join(e.root, f));
    const g = await e.run();
    assert.match(g.error ?? '', /4 active notes/);
  } finally {
    await e.close();
  }
});

// Fix round 1, m7: a vault file whose relative path starts with "hq:" cannot overwrite an HQ row.
test('m7: the vault importer refuses a relative path starting with "hq:" (no ON CONFLICT overwrite of an HQ row)', async () => {
  const e = await fresh();
  try {
    seed(e);
    await e.run();
    const vault = join(e.dir, 'vault');
    mkdirSync(join(vault, 'hq:team'), { recursive: true });
    writeFileSync(join(vault, 'hq:team/2026-11-13-hq-chat.md'), '# Plain\n\nSynthetic vault note marker-m7.\n');
    const vcfg = validateSources(parseToml(`[[source]]\nname = "v"\nkind = "vault_note"\nscope = "work"\nroot = "${vault}"\ninclude = ["**/*.md"]\n`), seedWall(), { home: e.dir });
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    const v = await importVault({ db: e.db, config: vcfg, mode: 'full', home: e.dir, log: (l) => e.logs.push(l) });
    await e.db.exec('RESET ROLE');
    assert.equal(v.counts.inserted + v.counts.updated, 0);
    assert.equal(v.counts.errors, 1);
    const n = (await notes(e.db)).find((x) => x.vault_path === 'hq:team/2026-11-13-hq-chat.md')!;
    assert.equal(n.source_kind, 'zeus_memory');
    assert.doesNotMatch(n.title + JSON.stringify(n.frontmatter), /marker-m7/);
    assert.ok(e.logs.every((l) => !/marker-m7/.test(l)));
  } finally {
    await e.close();
  }
});
