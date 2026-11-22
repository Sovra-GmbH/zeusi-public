// U5 vault importer (PLAN.md U5, "Idempotency and runs", KTD7, R1 R2 R7 R10 R11).
// Synthetic fixtures only (test/fixtures/vault), copied to a temp dir per test;
// symlinks and the PlankivaVault target are created there at test time. PGlite only:
// no network, no Neon. Imports run as zeusi_mini_ingest (SET ROLE) so the grants are
// exercised; the owner (test superuser) only seeds vectors and pins wall_allow.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, constants, cpSync, mkdirSync, readdirSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources, type SourcesConfig } from '../src/sources.ts';
import { PROTECTED_VARIANTS_REGEX, compileWall, legacySeedWall, seedWall } from '../src/wall.ts';
import { formatAudit, formatReport, ownerActionLine, wallAllow, wallAudit, wallReport } from '../src/wall-admin.ts';
import { dummyVector } from '../src/facts.ts';
import { CHUNK, embedText } from '../src/chunking.ts';
import {
  importVault, nodeVaultFs, pathQuarantineUri, assertIngestReady, scopeFor, IngestNotReady, formatVaultResult, type VaultFs, type VaultImportOptions,
  type VaultDryRunObservation,
} from '../src/importers/vault.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const FIXTURE = fileURLToPath(new URL('./fixtures/vault/', import.meta.url));
const MODEL = 'openai/text-embedding-3-small@1536';
const OLD = new Date('2026-01-05T10:00:00Z');

/** Notes the fixture run must insert (relative paths). */
const ALLOWED = [
  'Home.md', 'wiki/glossary.md', 'Work/handbook/2026-11-01-sample-decision.md', 'Work/research/plain.md',
  'Work/research/long-headingless.md', 'Work/research/clean-link.md', 'Work/product/overview.md',
  'ClientCo/client-alpha.md', // 0010: ClientCo is admitted, scope clientco
].sort();
/** Refused by the path gates: never listed (dirs) or never opened (files). */
const PATH_GATED = [
  'ClientCo/plankiva-probe.md', 'Work/plankiva', 'Work/intake', 'Work/ops/attic', 'Work/finance/weekly-pnl.md',
  'Work/research/av-link.md', 'Work/linked-dir',
].sort();
const WALLED = /plankiva|pnl|_archive|_inbox/i;

interface Env {
  db: Db;
  dir: string;
  vault: string;
  config: SourcesConfig;
  opened: Array<{ path: string; flags: number }>;
  listed: string[];
  logs: string[];
  fs: VaultFs;
  run(o?: Partial<VaultImportOptions>): ReturnType<typeof importVault>;
  close(): Promise<void>;
}

function setTimes(root: string, t: Date) {
  for (const e of readdirSync(root, { withFileTypes: true, recursive: true })) {
    const p = join(e.parentPath, e.name);
    if (e.isFile()) utimesSync(p, t, t);
  }
}

async function fresh(opts: { migrations?: boolean } = {}): Promise<Env> {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-u5-'));
  const vault = join(dir, 'vault');
  cpSync(FIXTURE, vault, { recursive: true });
  // Outside the vault: a walled tree a symlink points into.
  mkdirSync(join(dir, 'PlankivaVault', 'requests'), { recursive: true });
  writeFileSync(join(dir, 'PlankivaVault', 'requests', 'r1.md'), 'synthetic walled request body\n');
  symlinkSync(join(dir, 'PlankivaVault', 'requests', 'r1.md'), join(vault, 'Work/research/av-link.md'));
  symlinkSync(join(dir, 'PlankivaVault'), join(vault, 'Work/linked-dir'));
  symlinkSync(join(vault, 'Work/research/plain.md'), join(vault, 'Work/research/clean-link.md'));
  setTimes(vault, OLD);

  const config = validateSources(parseToml(`
[[source]]
name = "vault-all"
kind = "vault_note"
scope = "work"
root = "${vault}"
include = ["**/*.md"]

[[source]]
name = "vault-northbank-product"
kind = "vault_note"
scope = "product"
root = "${vault}"
include = ["Work/product/**/*.md", "Work/products/product/**/*.md"]
content_scan = true
`), seedWall(), { home: dir });

  const db = await pgliteDb();
  if (opts.migrations !== false) await migrate(db);
  const opened: Env['opened'] = [];
  const listed: string[] = [];
  const logs: string[] = [];
  const fs: VaultFs = {
    ...nodeVaultFs,
    open(p, flags) {
      opened.push({ path: relative(dir, p), flags });
      return nodeVaultFs.open(p, flags);
    },
    readdir(p) {
      listed.push(relative(dir, p));
      return nodeVaultFs.readdir(p);
    },
  };
  const env: Env = {
    db, dir, vault, config, opened, listed, logs, fs,
    async run(o = {}) {
      await db.exec('SET ROLE zeusi_mini_ingest');
      try {
        return await importVault({ db, config, mode: 'full', home: dir, fs, log: (l) => logs.push(l), ...o });
      } finally {
        await db.exec('RESET ROLE');
      }
    },
    async close() {
      await db.close();
      chmodTree(dir, true);
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return env;
}

function chmodTree(root: string, writable: boolean) {
  const walk = (p: string) => {
    const st = statSync(p, { throwIfNoEntry: false });
    if (!st) return;
    if (st.isDirectory()) {
      chmodSync(p, writable ? 0o755 : 0o555);
      for (const e of readdirSync(p, { withFileTypes: true })) if (!e.isSymbolicLink()) walk(join(p, e.name));
    } else chmodSync(p, writable ? 0o644 : 0o444);
  };
  walk(root);
}

async function notes(db: Db) {
  return (await db.query<{ id: number; vault_path: string; title: string; status: string; scope: string; source_uri: string; source_ts: Date; note_date: string | null; frontmatter: Record<string, unknown>; deleted_seen_at: Date | null; ingest_run_id: number }>(
    `SELECT id::int AS id, vault_path, title, status, scope::text AS scope, source_uri, source_ts, note_date::text AS note_date,
            frontmatter, deleted_seen_at, ingest_run_id::int AS ingest_run_id FROM zeusi.notes ORDER BY vault_path`,
  )).rows;
}

async function chunksOf(db: Db, vaultPath: string) {
  return (await db.query<{ id: number; chunk_index: number; heading_path: string | null; text: string; sha: string; token_count: number; source_uri: string; scope: string; has_vec: boolean; embed_model: string | null }>(
    `SELECT c.id::int AS id, c.chunk_index, c.heading_path, c.text, encode(c.text_sha256, 'hex') AS sha, c.token_count,
            c.source_uri, c.scope::text AS scope, c.embedding IS NOT NULL AS has_vec, c.embed_model
     FROM zeusi.chunks c JOIN zeusi.notes n ON n.id = c.note_id WHERE n.vault_path = $1 ORDER BY c.chunk_index`, [vaultPath],
  )).rows;
}

async function quarantine(db: Db) {
  return (await db.query<{ source_uri: string; target_table: string | null; rule_id: number | null; content_sha256: string | null; source_sha256: string }>(
    `SELECT source_uri, target_table, rule_id, encode(content_sha256, 'hex') AS content_sha256, encode(source_sha256, 'hex') AS source_sha256
     FROM zeusi.quarantine ORDER BY source_uri`,
  )).rows;
}

async function contentDump(db: Db): Promise<string> {
  const r = await db.query<{ t: string }>(
    `SELECT coalesce((SELECT string_agg(concat_ws(' ', vault_path, title, body, frontmatter::text, source_uri), E'\n') FROM zeusi.notes), '') || E'\n' ||
            coalesce((SELECT string_agg(concat_ws(' ', heading_path, text, source_uri), E'\n') FROM zeusi.chunks), '') AS t`,
  );
  return r.rows[0]!.t;
}

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const ruleId = (pattern: string, kind?: string) => seedWall().rules.find((r) => r.pattern === pattern && (!kind || r.kind === kind))!.id;

test('first full run inserts the allowed notes; a second run inserts 0 and skips them all', async () => {
  const e = await fresh();
  try {
    const r1 = await e.run();
    assert.equal(r1.status, 'ok', r1.error ?? '');
    assert.equal(r1.counts.inserted, ALLOWED.length);
    assert.equal(r1.counts.updated, 0);
    assert.deepEqual((await notes(e.db)).map((n) => n.vault_path), ALLOWED);
    assert.ok(r1.counts.chunks_written >= ALLOWED.length);

    const run = (await e.db.query<{ importer: string; host: string; mode: string; status: string; counts: Record<string, number>; finished_at: Date | null }>(
      `SELECT importer, host, mode, status, counts, finished_at FROM zeusi.ingest_runs WHERE id = $1`, [r1.runId])).rows[0]!;
    assert.deepEqual([run.importer, run.host, run.mode, run.status], ['vault', 'mini', 'full', 'ok']);
    assert.ok(run.finished_at);
    for (const k of ['inserted', 'updated', 'skipped', 'quarantined', 'deleted', 'errors']) assert.equal(typeof run.counts[k], 'number', k);

    const r2 = await e.run();
    assert.equal(r2.status, 'ok');
    assert.equal(r2.counts.inserted, 0);
    assert.equal(r2.counts.updated, 0);
    assert.equal(r2.counts.skipped, ALLOWED.length);
    assert.equal(r2.counts.chunks_written, 0);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('provenance: source_uri vault:<rel>, chunk uris #c<index> (never heading text), source_ts from frontmatter date, frontmatter fields and links', async () => {
  const e = await fresh();
  try {
    await e.run();
    const all = await notes(e.db);
    const dec = all.find((n) => n.vault_path === 'Work/handbook/2026-11-01-sample-decision.md')!;
    assert.equal(dec.source_uri, 'vault:Work/handbook/2026-11-01-sample-decision.md');
    assert.equal(dec.title, 'Sample decision: fixture lock');
    assert.equal(dec.note_date, '2026-11-01');
    assert.equal(new Date(dec.source_ts).toISOString(), '2026-11-01T00:00:00.000Z');
    assert.equal(dec.scope, 'work');
    assert.equal(dec.frontmatter['status'], 'locked');
    assert.deepEqual(dec.frontmatter['locks'], ['fixture-lock-one', 'fixture-lock-two']);
    assert.deepEqual(dec.frontmatter['tags'], ['ops', 'zeusi']);
    assert.equal(dec.frontmatter['source'], 'synthetic fixture');
    assert.deepEqual(dec.frontmatter['related'], ['[[Home]]', '[[wiki/glossary]]']);
    assert.deepEqual(dec.frontmatter['links'], ['Home', 'wiki/glossary']);
    const body = (await e.db.query<{ body: string }>(`SELECT body FROM zeusi.notes WHERE id = $1`, [dec.id])).rows[0]!.body;
    assert.match(body, /\[\[wiki\/glossary#Chunk\]\]/, 'wikilinks stay as text');

    const ch = await chunksOf(e.db, dec.vault_path);
    assert.deepEqual(ch.map((c) => c.heading_path), ['Sample decision', 'Sample decision > Context', 'Sample decision > Ruling', 'Sample decision > Ruling > Follow-up']);
    assert.deepEqual(ch.map((c) => c.source_uri), [
      'vault:Work/handbook/2026-11-01-sample-decision.md#c0',
      'vault:Work/handbook/2026-11-01-sample-decision.md#c1',
      'vault:Work/handbook/2026-11-01-sample-decision.md#c2',
      'vault:Work/handbook/2026-11-01-sample-decision.md#c3',
    ]);
    assert.ok(ch.every((c) => !c.has_vec && c.embed_model === null), 'U5 writes no embeddings');
    for (const c of ch) assert.equal(c.sha, sha(c.text));

    const home = all.find((n) => n.vault_path === 'Home.md')!;
    assert.deepEqual(home.frontmatter['links'], ['wiki/glossary', 'Work/handbook/2026-11-01-sample-decision']);
  } finally {
    await e.close();
  }
});

test('a note without frontmatter uses its mtime as source_ts and its filename as title', async () => {
  const e = await fresh();
  try {
    await e.run();
    const n = (await notes(e.db)).find((x) => x.vault_path === 'Work/research/plain.md')!;
    assert.equal(n.title, 'plain');
    assert.equal(new Date(n.source_ts).toISOString(), OLD.toISOString());
    assert.equal(n.note_date, null);
    assert.deepEqual(n.frontmatter, { links: ['Home', 'wiki/glossary'] });
  } finally {
    await e.close();
  }
});

test('the heading-less ~3,000-token note splits into chunks of at most 800 tokens', async () => {
  const e = await fresh();
  try {
    await e.run();
    const ch = await chunksOf(e.db, 'Work/research/long-headingless.md');
    assert.ok(ch.length >= 4, `${ch.length} chunks`);
    assert.ok(ch.every((c) => c.token_count <= CHUNK.max && c.heading_path === null));
    assert.equal(ch[0]!.source_uri, 'vault:Work/research/long-headingless.md#c0');
    assert.equal(ch[1]!.source_uri, 'vault:Work/research/long-headingless.md#c1');
  } finally {
    await e.close();
  }
});

test('editing one note re-chunks only that note and reuses vectors for unchanged chunk shas', async () => {
  const e = await fresh();
  try {
    await e.run();
    const path = 'Work/handbook/2026-11-01-sample-decision.md';
    // Owner seeds vectors on every chunk (stands in for U6).
    await e.db.query(`UPDATE zeusi.chunks SET embed_model = $1, embedding = $2::halfvec, embedded_at = now()`, [MODEL, dummyVector(3)]);
    const before = await chunksOf(e.db, path);
    const otherIds = (await e.db.query<{ id: number }>(
      `SELECT c.id::int AS id FROM zeusi.chunks c JOIN zeusi.notes n ON n.id = c.note_id WHERE n.vault_path <> $1 ORDER BY 1`, [path])).rows.map((r) => r.id);

    const file = join(e.vault, path);
    const text = (await import('node:fs')).readFileSync(file, 'utf8').replace('Original wording.', 'Edited wording.');
    writeFileSync(file, text);

    e.opened.length = 0;
    const r = await e.run({ mode: 'incremental' });
    assert.equal(r.mode, 'incremental');
    assert.equal(r.counts.updated, 1);
    assert.equal(r.counts.inserted, 0);
    assert.equal(r.counts.skipped, ALLOWED.length - 1);
    const after = await chunksOf(e.db, path);
    assert.equal(after.length, before.length);
    const ruling = after.find((c) => c.heading_path === 'Sample decision > Ruling')!;
    assert.match(ruling.text, /Edited wording/);
    assert.equal(ruling.has_vec, false, 'changed chunk loses its vector (U6 re-embeds)');
    for (const c of after.filter((x) => x !== ruling)) {
      assert.ok(before.some((b) => b.sha === c.sha), c.heading_path ?? '');
      assert.equal(c.has_vec, true, `vector reused for ${c.heading_path}`);
      assert.equal(c.embed_model, MODEL);
    }
    assert.equal(r.counts.vectors_reused, before.length - 1);
    assert.ok(after.every((c) => !before.some((b) => b.id === c.id)), 'chunks of the changed note were replaced');
    const othersAfter = (await e.db.query<{ id: number }>(
      `SELECT c.id::int AS id FROM zeusi.chunks c JOIN zeusi.notes n ON n.id = c.note_id WHERE n.vault_path <> $1 ORDER BY 1`, [path])).rows.map((x) => x.id);
    assert.deepEqual(othersAfter, otherIds, 'other notes were not touched');

    // Incremental: unchanged active notes were not even opened.
    const openedRel = e.opened.map((o) => relative('vault', o.path));
    assert.ok(openedRel.includes(path));
    for (const p of ALLOWED.filter((x) => x !== path)) assert.ok(!openedRel.includes(p), `${p} not opened`);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('a deleted file becomes status deleted, its chunks drop out; it comes back when restored', async () => {
  const e = await fresh();
  try {
    await e.run();
    const path = 'wiki/glossary.md';
    const file = join(e.vault, path);
    const saved = (await import('node:fs')).readFileSync(file);
    rmSync(file);
    const r = await e.run();
    assert.equal(r.counts.deleted, 1);
    const n = (await notes(e.db)).find((x) => x.vault_path === path)!;
    assert.equal(n.status, 'deleted');
    assert.ok(n.deleted_seen_at);
    assert.equal((await chunksOf(e.db, path)).length, 0, 'chunks of a deleted note are unavailable to search');
    assert.equal((await notes(e.db)).length, ALLOWED.length, 'no note row is deleted');

    const r2 = await e.run();
    assert.equal(r2.counts.deleted, 0, 'already-deleted notes are not re-counted');

    writeFileSync(file, saved);
    const r3 = await e.run();
    assert.equal(r3.counts.updated, 1);
    const back = (await notes(e.db)).find((x) => x.vault_path === path)!;
    assert.equal(back.status, 'active');
    assert.equal(back.deleted_seen_at, null);
    assert.ok((await chunksOf(e.db, path)).length > 0);
  } finally {
    await e.close();
  }
});

test('non-UTF-8 files are skipped, logged by path only, counted as errors, not quarantined', async () => {
  const e = await fresh();
  try {
    const r = await e.run();
    assert.equal(r.counts.errors, 1);
    assert.equal(r.status, 'ok');
    const line = e.logs.find((l) => l.includes('Work/research/latin1.md'));
    assert.ok(line, e.logs.join('\n'));
    assert.match(line!, /not UTF-8/);
    assert.doesNotMatch(e.logs.join('\n'), /Caf|synthetic bytes/);
    assert.ok(!(await quarantine(e.db)).some((q) => q.source_uri.includes('latin1')));
    assert.ok(!(await notes(e.db)).some((n) => n.vault_path.includes('latin1')));
  } finally {
    await e.close();
  }
});

test('read-only: every open uses O_RDONLY|O_NOFOLLOW, the importer works on a chmod a-w tree, and nothing changes on disk', async () => {
  const e = await fresh();
  try {
    const snap = () => readdirSync(e.vault, { recursive: true, withFileTypes: true })
      .map((d) => { const p = join(d.parentPath, d.name); const s = statSync(p, { throwIfNoEntry: false }); return `${relative(e.vault, p)} ${s?.size} ${s?.mtimeMs}`; })
      .sort().join('\n');
    const before = snap();
    chmodTree(e.vault, false);
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.inserted, ALLOWED.length);
    assert.ok(e.opened.length > 0);
    for (const o of e.opened) assert.equal(o.flags, constants.O_RDONLY | constants.O_NOFOLLOW, `${o.path} opened with flags ${o.flags}`);
    chmodTree(e.vault, true);
    assert.equal(snap(), before);
  } finally {
    await e.close();
  }
});

test('wall: Plankiva (also under ClientCo/) / P&L / requests / symlink-to-PlankivaVault are never listed or opened, never inserted, quarantined by path hash only', async () => {
  const e = await fresh();
  try {
    const r = await e.run();
    for (const o of e.opened) assert.doesNotMatch(o.path, WALLED, `opened ${o.path}`);
    for (const l of e.listed) assert.doesNotMatch(l, WALLED, `listed ${l}`);
    assert.ok(!e.opened.some((o) => o.path.includes('PlankivaVault')));
    assert.equal(r.counts.path_gated, PATH_GATED.length);

    const q = await quarantine(e.db);
    for (const rel of PATH_GATED) {
      const row = q.find((x) => x.source_uri === pathQuarantineUri(rel));
      assert.ok(row, `quarantine row for ${rel}`);
      assert.equal(row!.source_sha256, sha(rel));
      assert.equal(row!.content_sha256, null, 'never opened: no content hash');
    }
    for (const x of q) assert.doesNotMatch(x.source_uri, WALLED, 'walled names are not stored, only their hash');

    // Content-level hard hits (opened, clean path): the note uri, never text.
    const word = q.filter((x) => x.source_uri.startsWith('vault:Work/research/word-probe.md'));
    assert.deepEqual(word.map((x) => [x.source_uri, x.target_table, x.rule_id]), [['vault:Work/research/word-probe.md', 'notes', ruleId('plankiva', 'term')]]);
    const tag = q.filter((x) => x.source_uri.startsWith('vault:Work/research/tag-probe.md'));
    assert.equal(tag.length, 1);
    assert.equal(seedWall().rules.find((x) => x.id === tag[0]!.rule_id)!.kind, 'tag');

    const dump = await contentDump(e.db);
    assert.doesNotMatch(dump, /plankiva|weekly-pnl|walled|exclusion probe|1234567|4900001/i);
    assert.doesNotMatch(e.logs.join('\n'), /plankiva|pnl|_archive|_inbox|word-probe|tag-probe|budget|pricing|linked-dir|av-link/i, 'logs never name quarantined items');
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

// 0011 lifted the soft currency rule: the fixture's budget note carries a synthetic login number (soft rule kept).
test('login-number note: quarantined (note + chunk), allowed by wall_allow for the exact sha, quarantined again after an edit', async () => {
  const e = await fresh();
  try {
    const path = 'Work/research/budget.md';
    await e.run();
    let q = (await quarantine(e.db)).filter((x) => x.source_uri.startsWith(`vault:${path}`));
    assert.deepEqual(q.map((x) => [x.source_uri, x.target_table, x.rule_id]), [
      [`vault:${path}`, 'notes', ruleId('\\m(login|account|acct)\\M[^0-9\\n]{0,4}[0-9]{5,}')],
      [`vault:${path}#c1`, 'chunks', ruleId('\\m(login|account|acct)\\M[^0-9\\n]{0,4}[0-9]{5,}')],
    ]);
    assert.ok(!(await notes(e.db)).some((n) => n.vault_path === path));

    // the owner pins each quarantined (uri, content sha) — owner only.
    for (const x of q) await wallAllow(e.db, x.source_uri, x.content_sha256!);
    const r = await e.run();
    assert.equal(r.counts.inserted, 1);
    assert.ok((await notes(e.db)).some((n) => n.vault_path === path && n.status === 'active'));
    assert.equal((await chunksOf(e.db, path)).length, 2, 'the empty H1 section is dropped: Clean part + Amount');
    assert.deepEqual(await wallAudit(e.db), [], 'allowed content is not a breach');

    // Edit: a new content sha is not covered by the pin.
    const file = join(e.vault, path);
    writeFileSync(file, (await import('node:fs')).readFileSync(file, 'utf8').replace('login 1234567', 'login 1234568'));
    const r2 = await e.run();
    assert.equal(r2.counts.quarantined, r.counts.quarantined + 1, 'the edited note joins the other quarantined items');
    assert.equal(r2.counts.retracted, 1);
    q = (await quarantine(e.db)).filter((x) => x.source_uri === `vault:${path}`);
    assert.equal(q.length, 2, 'old and new source sha both recorded');
    assert.equal((await chunksOf(e.db, path)).length, 0, 'stale chunks are retracted from search');
    const dump = await contentDump(e.db);
    assert.doesNotMatch(dump, /1234568/);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('Northbank product notes: scope product when clean; quarantined otherwise, even with a wall_allow pin (OD5)', async () => {
  const e = await fresh();
  try {
    await e.run();
    const ov = (await notes(e.db)).find((n) => n.vault_path === 'Work/product/overview.md')!;
    assert.equal(ov.scope, 'product');
    assert.ok((await chunksOf(e.db, ov.vault_path)).every((c) => c.scope === 'product'));
    assert.ok((await notes(e.db)).filter((n) => !n.vault_path.includes('product') && !n.vault_path.startsWith('ClientCo/') && !n.vault_path.startsWith('Work/product')).every((n) => n.scope === 'work'));

    const path = 'Work/products/product/pricing.md';
    const q = (await quarantine(e.db)).filter((x) => x.source_uri.startsWith(`vault:${path}`));
    assert.ok(q.length >= 1);
    for (const x of q) await wallAllow(e.db, x.source_uri, x.content_sha256!);
    const r = await e.run();
    assert.ok(!(await notes(e.db)).some((n) => n.vault_path === path), 'OD5: only a clean scan admits product');
    assert.ok(r.counts.quarantined >= 1);
    assert.equal(r.counts.by_scope['product'], 1);
  } finally {
    await e.close();
  }
});

test('trigger backstop: with the importer pre-check bypassed, ZW001 is caught and quarantined, not a crash', async () => {
  const e = await fresh();
  try {
    const r = await e.run({ testOnlyContentWall: compileWall([], []) });
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.ok(r.counts.backstop >= 3, `backstop ${r.counts.backstop}`); // budget, word-probe, tag-probe, pricing
    assert.equal(r.counts.inserted, ALLOWED.length);
    const q = await quarantine(e.db);
    assert.ok(q.some((x) => x.source_uri.startsWith('vault:Work/research/budget.md') && x.content_sha256));
    assert.ok(q.some((x) => x.source_uri === 'vault:Work/research/word-probe.md' && x.rule_id === ruleId('plankiva', 'term')));
    // The path gate is never bypassed.
    for (const o of e.opened) assert.doesNotMatch(o.path, WALLED);
    assert.doesNotMatch(await contentDump(e.db), /plankiva|1234567/i);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('incremental: no ok full run in 7 days promotes to full; otherwise only changed or new files are opened', async () => {
  const e = await fresh();
  try {
    const r1 = await e.run({ mode: 'incremental' });
    assert.equal(r1.mode, 'full', 'no full run yet: weekly re-hash due');
    e.opened.length = 0;
    const r2 = await e.run({ mode: 'incremental' });
    assert.equal(r2.mode, 'incremental');
    assert.equal(r2.counts.skipped, ALLOWED.length);
    const opened = e.opened.map((o) => relative('vault', o.path));
    for (const p of ALLOWED) assert.ok(!opened.includes(p), `${p} unchanged and active: not opened`);
    await e.db.query(`UPDATE zeusi.ingest_runs SET started_at = started_at - interval '8 days', finished_at = finished_at - interval '8 days'`);
    const r3 = await e.run({ mode: 'incremental' });
    assert.equal(r3.mode, 'full');
  } finally {
    await e.close();
  }
});

test('guards: missing root or an emptied vault fails the run and deletes nothing', async () => {
  const e = await fresh();
  try {
    await e.run();
    for (const name of ['Work', 'wiki', 'Home.md', 'ClientCo']) rmSync(join(e.vault, name), { recursive: true, force: true });
    const r = await e.run();
    assert.equal(r.status, 'failed');
    assert.match(r.error ?? '', /deletion guard/);
    assert.ok((await notes(e.db)).every((n) => n.status === 'active'));
    const st = (await e.db.query<{ status: string }>(`SELECT status FROM zeusi.ingest_runs WHERE id = $1`, [r.runId])).rows[0]!;
    assert.equal(st.status, 'failed');

    rmSync(e.vault, { recursive: true, force: true });
    const r2 = await e.run();
    assert.equal(r2.status, 'failed');
    assert.match(r2.error ?? '', /root/);
  } finally {
    await e.close();
  }
});

test('0010 dry-run hooks: dryRunWall + dryRunObserve agree with the counters; the 0009 wall gates ClientCo/, the current one admits it; refused outside dry runs', async () => {
  const e = await fresh();
  try {
    const tally = async (wall: ReturnType<typeof seedWall>) => {
      const obs: VaultDryRunObservation[] = [];
      const r = await importVault({ config: e.config, mode: 'full', dryRun: true, home: e.dir, dryRunWall: wall, dryRunObserve: (o) => obs.push(o) });
      const n = (k: string) => obs.filter((o) => o.outcome === k).length;
      assert.equal(n('admitted'), r.counts.inserted);
      assert.equal(n('path_gated'), r.counts.path_gated);
      assert.equal(n('content'), r.counts.quarantined - r.counts.path_gated);
      assert.equal(n('error'), r.counts.errors);
      for (const o of obs) if (o.outcome === 'admitted') assert.equal(o.chunks.length > 0 || o.note['body'] === '', true);
      return obs;
    };
    const old = await tally(legacySeedWall());
    const now = await tally(seedWall());
    assert.ok(old.some((o) => o.outcome === 'path_gated' && o.rel === 'ClientCo'), 'the 0009 wall gates the ClientCo folder');
    assert.ok(now.some((o) => o.outcome === 'admitted' && o.rel === 'ClientCo/client-alpha.md' && o.scope === 'client'));
    assert.ok(now.some((o) => o.outcome === 'path_gated' && o.rel === 'ClientCo/plankiva-probe.md'));
    await assert.rejects(importVault({ db: e.db, config: e.config, mode: 'full', home: e.dir, dryRunObserve: () => {} }), /dry runs only/);
    await assert.rejects(importVault({ db: e.db, config: e.config, mode: 'full', home: e.dir, dryRunWall: seedWall() }), /dry runs only/);
  } finally {
    await e.close();
  }
});

test('dry run: no database, counts only (by scope, rule, quarantine)', async () => {
  const e = await fresh();
  try {
    const r = await importVault({ config: e.config, mode: 'full', dryRun: true, home: e.dir, fs: e.fs, log: (l) => e.logs.push(l) });
    assert.equal(r.runId, null);
    assert.equal(r.counts.inserted, ALLOWED.length, 'would insert');
    assert.equal(r.counts.path_gated, PATH_GATED.length);
    assert.equal(r.counts.by_scope['product'], 1);
    assert.equal(r.counts.by_scope['client'], 1);
    assert.equal(r.counts.by_scope['work'], ALLOWED.length - 2);
    assert.ok(Object.values(r.counts.by_rule).reduce((a, b) => a + b, 0) >= PATH_GATED.length + 4);
    assert.doesNotMatch(e.logs.join('\n'), /the team\/|wiki\/|Home\.md/, 'dry-run output carries no paths');
  } finally {
    await e.close();
  }
});

test('real-mode precondition: refuses owner-privileged sessions and databases without wall migrations 0006-0011', async () => {
  const e = await fresh();
  try {
    await assert.rejects(assertIngestReady(e.db), IngestNotReady, 'superuser / owner session refused');
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      await assertIngestReady(e.db);
    } finally {
      await e.db.exec('RESET ROLE');
    }
  } finally {
    await e.close();
  }
  const partial = await fresh({ migrations: false });
  try {
    const dir = safeMkdtemp(join(tmpdir(), 'zeusi-mig-'));
    const src = fileURLToPath(new URL('../migrations/', import.meta.url));
    for (const f of readdirSync(src).filter((x) => /^000[1-5]_/.test(x))) cpSync(join(src, f), join(dir, f));
    await migrate(partial.db, { dir });
    await partial.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      await assert.rejects(assertIngestReady(partial.db), (err: Error) => err instanceof IngestNotReady && /0006|0007|0008|0009/.test(err.message));
    } finally {
      await partial.db.exec('RESET ROLE');
    }
  } finally {
    await partial.close();
  }
  // Prod today (0001-0009, no 0010): refused, naming 0010 and the missing Plankiva spelling seed.
  const p9 = await fresh({ migrations: false });
  try {
    const dir = safeMkdtemp(join(tmpdir(), 'zeusi-mig-'));
    const src = fileURLToPath(new URL('../migrations/', import.meta.url));
    for (const f of readdirSync(src).filter((x) => x < '0010')) cpSync(join(src, f), join(dir, f));
    await migrate(p9.db, { dir });
    await p9.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      await assert.rejects(assertIngestReady(p9.db), (err: Error) =>
        err instanceof IngestNotReady && /migration 0010/.test(err.message) && /seeded wall rule/.test(err.message) && !/0009 \(/.test(err.message));
    } finally {
      await p9.db.exec('RESET ROLE');
    }
  } finally {
    await p9.close();
  }
  // 0001-0010 (no 0011): refused, naming 0011 (Plankiva variants rule, soft currency / P&L lift).
  const p10 = await fresh({ migrations: false });
  try {
    const dir = safeMkdtemp(join(tmpdir(), 'zeusi-mig-'));
    const src = fileURLToPath(new URL('../migrations/', import.meta.url));
    for (const f of readdirSync(src).filter((x) => x < '0011')) cpSync(join(src, f), join(dir, f));
    await migrate(p10.db, { dir });
    await p10.db.exec('SET ROLE zeusi_mini_ingest');
    try {
      await assert.rejects(assertIngestReady(p10.db), (err: Error) =>
        err instanceof IngestNotReady && /migration 0011/.test(err.message) && !/migration 0010 /.test(err.message));
    } finally {
      await p10.db.exec('RESET ROLE');
    }
  } finally {
    await p10.close();
  }
});

test('an unreadable directory is an error, not a deletion; a symlink leaving the vault is refused even when clean', async () => {
  const e = await fresh();
  try {
    await e.run();
    writeFileSync(join(e.dir, 'outside.md'), '# Outside\nclean synthetic text\n');
    symlinkSync(join(e.dir, 'outside.md'), join(e.vault, 'wiki/outside-link.md'));
    chmodSync(join(e.vault, 'Work/product'), 0o000);
    try {
      const r = await e.run();
      assert.equal(r.status, 'ok', r.error ?? '');
      assert.equal(r.counts.errors, 2, 'latin1 + the unreadable directory');
      assert.equal(r.counts.deleted, 0);
      assert.equal((await notes(e.db)).find((n) => n.vault_path === 'Work/product/overview.md')!.status, 'active');
      assert.ok(e.logs.some((l) => l === 'skipped (directory not readable): Work/product'));
      assert.equal(r.counts.by_rule['none'], 1, 'outside symlink: refused with no rule');
      assert.ok((await quarantine(e.db)).some((q) => q.source_uri === pathQuarantineUri('wiki/outside-link.md')));
      assert.ok(!e.opened.some((o) => o.path.includes('outside')));
    } finally {
      chmodSync(join(e.vault, 'Work/product'), 0o755);
    }
  } finally {
    await e.close();
  }
});

// ---------------------------------------------------------------------------
// Review r1 fixes.

/** Text that must never leave the content tables (headings and file names that hit the wall). */
/** (Not "plankiva": that word is a wall rule pattern, printed by design in the by-rule counts.) */
const LEAK = /Invoice|ClientX|5000|9000|Call notes/i;

async function outputs(e: Env, r: Awaited<ReturnType<typeof importVault>>): Promise<string> {
  const runs = (await e.db.query<{ counts: unknown }>(`SELECT counts FROM zeusi.ingest_runs ORDER BY id`)).rows.map((x) => JSON.stringify(x.counts));
  return [
    ...e.logs,
    formatVaultResult(r, seedWall().rules, false),
    formatReport(await wallReport(e.db)),
    formatAudit(await wallAudit(e.db)),
    ...runs,
    ...(await quarantine(e.db)).map((q) => q.source_uri),
    ...(await e.db.query<{ u: string }>(`SELECT source_uri AS u FROM zeusi.wall_allow`)).rows.map((x) => x.u),
  ].join('\n');
}

const HEADING_NOTE = 'Work/research/heading-leak.md';
const HARD_HEADING_NOTE = 'Work/research/hard-heading.md';
function addHeadingNotes(e: Env) {
  writeFileSync(join(e.vault, HEADING_NOTE), '# Top\n\nclean intro text.\n\n## Invoice acct 5000123 for ClientX\n\nsynthetic line without figures.\n');
  writeFileSync(join(e.vault, HARD_HEADING_NOTE), '# Top\n\nclean intro text.\n\n## Call notes Plankiva\n\nsynthetic line.\n');
  setTimes(e.vault, OLD);
}

test('r1 MAJOR-1: a soft hit inside a heading never reaches quarantine uris, wall report, run counts, logs or output; #c<n> pins admit it', async () => {
  const e = await fresh();
  try {
    addHeadingNotes(e);
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    const q = (await quarantine(e.db)).filter((x) => x.source_uri.startsWith(`vault:${HEADING_NOTE}`));
    const soft = ruleId('\\m(login|account|acct)\\M[^0-9\\n]{0,4}[0-9]{5,}');
    assert.deepEqual(q.map((x) => [x.source_uri, x.target_table, x.rule_id]), [
      [`vault:${HEADING_NOTE}`, 'notes', soft],
      [`vault:${HEADING_NOTE}#c1`, 'chunks', soft],
    ]);
    const hard = (await quarantine(e.db)).filter((x) => x.source_uri.startsWith(`vault:${HARD_HEADING_NOTE}`));
    assert.deepEqual(hard.map((x) => [x.source_uri, x.target_table, x.rule_id]), [[`vault:${HARD_HEADING_NOTE}`, 'notes', ruleId('plankiva', 'term')]]);
    assert.doesNotMatch(await outputs(e, r), LEAK);

    // the owner pins the reported (uri, content sha) rows: the pin address is the chunk uri the importer writes.
    for (const x of q) await wallAllow(e.db, x.source_uri, x.content_sha256!);
    const r2 = await e.run();
    assert.equal(r2.counts.inserted, 1);
    const ch = await chunksOf(e.db, HEADING_NOTE);
    assert.deepEqual(ch.map((c) => [c.source_uri, c.heading_path]), [
      [`vault:${HEADING_NOTE}#c0`, 'Top'],
      [`vault:${HEADING_NOTE}#c1`, 'Top > Invoice acct 5000123 for ClientX'],
    ], 'heading_path keeps the heading for admitted chunks only');
    assert.deepEqual(await wallAudit(e.db), []);
    e.logs.length = 0;
    const out = (await outputs(e, r2)).replace(/vault:Work\/20-notes\/heading-leak\.md(#c\d+)?/g, '');
    assert.doesNotMatch(out, LEAK);
  } finally {
    await e.close();
  }
});

test('r1 MAJOR-1: trigger backstop on a heading-walled chunk records #c<n>, never the heading', async () => {
  const e = await fresh();
  try {
    addHeadingNotes(e);
    await e.run();
    // Pin the note row only; with the pre-check bypassed the trigger must refuse the chunk.
    const note = (await quarantine(e.db)).find((x) => x.source_uri === `vault:${HEADING_NOTE}`)!;
    await wallAllow(e.db, note.source_uri, note.content_sha256!);
    await e.db.query(`DELETE FROM zeusi.quarantine`);
    e.logs.length = 0;
    const r = await e.run({ testOnlyContentWall: compileWall([], []) });
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.ok(r.counts.backstop >= 2, `backstop ${r.counts.backstop}`);
    const q = await quarantine(e.db);
    assert.ok(q.some((x) => x.source_uri === `vault:${HEADING_NOTE}#c1` && x.target_table === 'chunks'), q.map((x) => x.source_uri).join('\n'));
    assert.ok(q.some((x) => x.source_uri === `vault:${HARD_HEADING_NOTE}`));
    assert.ok(!(await notes(e.db)).some((n) => n.vault_path === HEADING_NOTE), 'note transaction rolled back');
    assert.doesNotMatch(await outputs(e, r), LEAK);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});

test('r1 leak class: a file or folder NAME that hits a soft rule is path-gated by hash, never opened', async () => {
  const e = await fresh();
  try {
    writeFileSync(join(e.vault, 'Work/research/Invoice acct 5000123 ClientX.md'), 'clean synthetic text.\n');
    mkdirSync(join(e.vault, 'Work/acct 9000123 deals'), { recursive: true });
    writeFileSync(join(e.vault, 'Work/acct 9000123 deals/x.md'), 'clean synthetic text.\n');
    setTimes(e.vault, OLD);
    const r = await e.run();
    assert.equal(r.counts.path_gated, PATH_GATED.length + 2);
    const q = await quarantine(e.db);
    assert.ok(q.some((x) => x.source_uri === pathQuarantineUri('Work/research/Invoice acct 5000123 ClientX.md')));
    assert.ok(q.some((x) => x.source_uri === pathQuarantineUri('Work/acct 9000123 deals')));
    for (const o of e.opened) assert.doesNotMatch(o.path, LEAK);
    for (const l of e.listed) assert.doesNotMatch(l, LEAK);
    assert.doesNotMatch(await outputs(e, r), LEAK);
    assert.doesNotMatch(await contentDump(e.db), LEAK);
  } finally {
    await e.close();
  }
});

test('r1 MINOR-4: hard-linked files (nlink > 1) are refused unopened and counted as errors', async () => {
  const e = await fresh();
  try {
    (await import('node:fs')).linkSync(join(e.vault, 'wiki/glossary.md'), join(e.vault, 'Work/research/hl.md'));
    const r = await e.run();
    assert.equal(r.counts.hardlinks, 2);
    assert.equal(r.counts.errors, 3, 'latin1 + both names of the hard link');
    assert.ok(!e.opened.some((o) => /glossary|hl\.md/.test(o.path)));
    assert.ok(!(await notes(e.db)).some((n) => /glossary|hl\.md/.test(n.vault_path)));
    assert.ok(e.logs.some((l) => l === 'skipped (hard link): Work/research/hl.md'));
  } finally {
    await e.close();
  }
});

test('r1 MINOR-3: a symlink is re-gated right before open and the real path opened with O_NOFOLLOW', async () => {
  const e = await fresh();
  try {
    const realpaths: string[] = [];
    const fs: VaultFs = { ...e.fs, realpath(p) { realpaths.push(relative(e.dir, p)); return nodeVaultFs.realpath(p); } };
    const r = await e.run({ fs });
    assert.equal(r.status, 'ok', r.error ?? '');
    const link = 'vault/Work/research/clean-link.md';
    const plainOpens = e.opened.filter((x) => x.path.endsWith('Work/research/plain.md'));
    assert.ok(realpaths.filter((p) => p === link).length >= 2, 'resolved at walk time and again before open');
    assert.equal(plainOpens.length, 2, 'plain.md itself, and the link opened through its gated real path');
    assert.ok(!e.opened.some((x) => x.path.endsWith('clean-link.md')), 'the link name itself is never opened');
    for (const x of e.opened) assert.equal(x.flags, constants.O_RDONLY | constants.O_NOFOLLOW);
  } finally {
    await e.close();
  }
});

test('r1 MINOR-5: a held advisory lock makes the run exit cleanly with no writes; the lock is released after a run', async () => {
  const e = await fresh();
  try {
    const sqls: string[] = [];
    const held: Db = {
      label: 'held', close: () => e.db.close(), exec: (s) => e.db.exec(s),
      async query<T>(sql: string, params?: unknown[]) {
        sqls.push(sql);
        if (/pg_try_advisory_lock/.test(sql)) return { rows: [{ ok: false }] as T[] };
        return e.db.query<T>(sql, params);
      },
    };
    await e.db.exec('SET ROLE zeusi_mini_ingest');
    let r;
    try {
      r = await importVault({ db: held, config: e.config, mode: 'full', home: e.dir, fs: e.fs, log: (l) => e.logs.push(l) });
    } finally {
      await e.db.exec('RESET ROLE');
    }
    assert.equal(r.status, 'locked');
    assert.equal(r.runId, null);
    assert.match(r.error ?? '', /another vault ingest run/);
    assert.equal(e.opened.length, 0, 'nothing opened');
    assert.ok(!sqls.some((s) => /INSERT|UPDATE|DELETE|quarantine_record/i.test(s)), 'no writes');
    assert.equal(Number((await e.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.ingest_runs`)).rows[0]!.n), 0);
    assert.match(formatVaultResult(r, seedWall().rules, false), /another vault ingest run/);

    const ok = await e.run();
    assert.equal(ok.status, 'ok', ok.error ?? '');
    const locks = await e.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory'`);
    assert.equal(Number(locks.rows[0]!.n), 0, 'lock released');
  } finally {
    await e.close();
  }
});

test('r1 MINOR-6: vector reuse is keyed on the embedded text, so a title rename drops the old vectors', async () => {
  const e = await fresh();
  try {
    await e.run();
    const path = 'Work/handbook/2026-11-01-sample-decision.md';
    await e.db.query(`UPDATE zeusi.chunks SET embed_model = $1, embedding = $2::halfvec, embedded_at = now()`, [MODEL, dummyVector(3)]);
    const file = join(e.vault, path);
    writeFileSync(file, (await import('node:fs')).readFileSync(file, 'utf8').replace('title: "Sample decision: fixture lock"', 'title: "Renamed decision"'));
    const r = await e.run();
    assert.equal(r.counts.updated, 1);
    assert.equal(r.counts.vectors_reused, 0);
    assert.ok((await chunksOf(e.db, path)).every((c) => !c.has_vec), 'stale vectors (old title prefix) are not reused');
    assert.notEqual(embedText('Renamed decision', 'A', 'x'), embedText('Sample decision: fixture lock', 'A', 'x'));
  } finally {
    await e.close();
  }
});

test('r1 MINOR-9 (r2 MINOR-2): scope mapping is case-insensitive (Work/products/Product/ is product)', async () => {
  const e = await fresh();
  try {
    // Case-only rename through a temp name, so no lower-case twin is left: on a
    // case-insensitive filesystem (APFS) a mkdir of Product would resolve to product.
    const lower = join(e.vault, 'Work/products/product');
    renameSync(lower, `${lower}.tmp`);
    renameSync(`${lower}.tmp`, join(e.vault, 'Work/products/Product'));
    assert.ok(readdirSync(join(e.vault, 'Work/products')).includes('Product'));
    assert.ok(!readdirSync(join(e.vault, 'Work/products')).includes('product'));
    writeFileSync(join(e.vault, 'Work/products/Product/notes.md'), '# Product notes\n\nclean synthetic product text.\n');
    setTimes(e.vault, OLD);
    await e.run();
    const n = (await notes(e.db)).find((x) => x.vault_path === 'Work/products/Product/notes.md');
    assert.ok(n, 'imported under its exact (capitalised) path');
    assert.equal(n.scope, 'product');
  } finally {
    await e.close();
  }
});

test('0010: the ClientCo folder maps to scope clientco (note and chunks); case-insensitive; Plankiva under ClientCo/ (name, text, separators) stays out', async () => {
  const e = await fresh();
  try {
    mkdirSync(join(e.vault, 'ClientCo/clientco-erp'), { recursive: true });
    writeFileSync(join(e.vault, 'ClientCo/clientco-erp/plan.md'), '# ClientCo ERP\n\n## Scope\nclean synthetic ClientCo ERP plan.\n');
    writeFileSync(join(e.vault, 'ClientCo/clientco-erp/word.md'), '# Sync\n\nsynthetic exclusion probe: Plankiva.\n');
    writeFileSync(join(e.vault, 'ClientCo/clientco-erp/spaced.md'), '# Sync\n\nsynthetic exclusion probe: P l a n k i v a.\n');
    setTimes(e.vault, OLD);
    const r = await e.run();
    assert.equal(r.status, 'ok');
    const all = await notes(e.db);
    for (const p of ['ClientCo/client-alpha.md', 'ClientCo/clientco-erp/plan.md']) {
      const n = all.find((x) => x.vault_path === p);
      assert.ok(n, p);
      assert.equal(n.scope, 'client', p);
      const cs = await chunksOf(e.db, p);
      assert.ok(cs.length > 0 && cs.every((c) => c.scope === 'client'), `${p} chunks`);
    }
    assert.ok(!all.some((n) => /plankiva|word\.md|spaced\.md/i.test(n.vault_path)));
    const q = await quarantine(e.db);
    const rid = (p: string) => q.find((x) => x.source_uri === `vault:${p}`)?.rule_id;
    assert.equal(rid('ClientCo/clientco-erp/word.md'), ruleId('plankiva', 'term'));
    assert.equal(seedWall().rules.find((x) => x.id === rid('ClientCo/clientco-erp/spaced.md'))?.kind, 'regex');
    assert.ok(q.some((x) => x.source_uri === pathQuarantineUri('ClientCo/plankiva-probe.md')));
    assert.equal(r.counts.by_scope['client'], 2);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
  // A source with scope = "client" maps its notes to clientco, and lower-case clientco/ is the same folder.
  assert.equal(scopeFor('clientco/x.md', []), 'client');
  assert.equal(scopeFor('Work/x.md', [{ spec: { scope: 'client' } }]), 'client');
  assert.equal(scopeFor('Work/x.md', [{ spec: { scope: 'work' } }]), 'work');
  assert.equal(scopeFor('Work/product/x.md', []), 'product');
});

test('r1 MINOR-1 + leak class: audit output carries no uri; a non-zero audit prints OWNER ACTION NEEDED (counts only)', () => {
  const rows = [
    { table_name: 'notes', row_ref: '7', source_uri: 'vault:Work/x ClientX.md', problem: 'content rule 9 (regex)' },
    { table_name: 'chunks', row_ref: '8', source_uri: 'vault:Work/x ClientX.md#c0', problem: 'content rule 9 (regex)' },
  ];
  assert.doesNotMatch(formatAudit(rows), /vault:|ClientX/);
  assert.match(formatAudit(rows), /notes 7: content rule 9/);
  const line = ownerActionLine(rows);
  assert.match(line ?? '', /^OWNER ACTION NEEDED: wall audit found 2 row\(s\)/);
  assert.match(line ?? '', /chunks 1, notes 1/);
  assert.doesNotMatch(line ?? '', /vault:|ClientX/);
  assert.equal(ownerActionLine([]), null);
});

// 0011 (the owner 15 Nov 2026 01:09 Zurich): "Plankiva" (one n) IS Plankiva (hard, no wall_allow); the soft currency and
// P&L rules are lifted. Synthetic exclusion probes only.
test('0011: Plankiva notes (body, name, tag, ClientCo folder) never reach notes/chunks; currency and P&L notes are admitted', async () => {
  const e = await fresh();
  try {
    mkdirSync(join(e.vault, 'ClientCo/clientco-erp'), { recursive: true });
    writeFileSync(join(e.vault, 'Work/research/probe-1n.md'), '# Sync\n\n## Notes\n\nsynthetic exclusion probe: Plaankiva joined.\n');
    writeFileSync(join(e.vault, 'Work/research/Plaankiva-sync.md'), 'clean synthetic text.\n');
    writeFileSync(join(e.vault, 'Work/research/tag-1n.md'), '---\ntags: [ops, Plaankiva]\n---\nclean synthetic text.\n');
    writeFileSync(join(e.vault, 'ClientCo/clientco-erp/probe-1n.md'), '# ClientCo\n\nsynthetic probe P-l-a-n-k-i-v-a.\n');
    writeFileSync(join(e.vault, 'ClientCo/clientco-erp/fx.md'), '# FX\n\nsynthetic CHF 1200 budget; P&L 2025: +3.2; book 7.\n');
    writeFileSync(join(e.vault, 'Work/research/price.md'), '# Price\n\nsynthetic list price $ 49 per seat; pnl 12.\n');
    setTimes(e.vault, OLD);
    const r = await e.run();
    assert.equal(r.status, 'ok', r.error ?? '');
    const paths = (await notes(e.db)).map((n) => n.vault_path);
    for (const p of ['ClientCo/clientco-erp/fx.md', 'Work/research/price.md']) assert.ok(paths.includes(p), `${p} admitted`);
    for (const p of ['Work/research/probe-1n.md', 'Work/research/Plaankiva-sync.md', 'Work/research/tag-1n.md', 'ClientCo/clientco-erp/probe-1n.md']) {
      assert.ok(!paths.includes(p), `${p} not admitted`);
    }
    const plankiva = seedWall().rules.find((x) => x.kind === 'regex' && x.pattern === PROTECTED_VARIANTS_REGEX)!.id;
    const q = await quarantine(e.db);
    assert.ok(q.some((x) => x.source_uri === 'vault:Work/research/probe-1n.md' && x.rule_id === plankiva));
    assert.ok(q.some((x) => x.source_uri === pathQuarantineUri('Work/research/Plaankiva-sync.md') && x.rule_id === plankiva), 'the name is path-gated by hash');
    assert.ok(!q.some((x) => /plankiva/i.test(x.source_uri)), 'no Plankiva name stored in quarantine');
    assert.doesNotMatch(await contentDump(e.db), /plankiva|p-l-a-n-k-i-v-a/i);
    assert.deepEqual(await wallAudit(e.db), []);
  } finally {
    await e.close();
  }
});
