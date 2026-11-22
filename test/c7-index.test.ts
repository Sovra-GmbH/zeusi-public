// C7 KTD5, KTD6, KTD8 (docs/plans/2026-11-19-c7-read-path.md; parent plan §7 items 5, 10, 19): the persisted B1 index
// under the index lock, its AAD binding, the repair paths and the table's ACL. PGlite with the real migrations,
// tenant logins and writer login; the REAL index hook; a FIXED test DEK. No network, no Neon, no real workspace.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { WORKSPACE_UNAVAILABLE } from '../src/about.ts';
import { COMPACT_SEGMENTS } from '../src/b1-index.ts';
import { TENANT_ACL_AUDIT_SQL, tenantRole } from '../src/tenant-ddl.ts';
import { TenantRefused } from '../src/tenants.ts';
import { callerOf, commitDocs, decisionEntry, decisionLog, hqItem, newWorkspace, setState } from './helpers/c6-fixture.ts';
import { mcpHarness } from './helpers/c7-fixture.ts';
import { c7World, routedDeps, type C7World } from './helpers/c7-sealed.ts';
import { asLogin, asOwner } from './helpers/tenant-fixture.ts';

let w: C7World;
before(async () => {
  w = await c7World();
});
after(async () => {
  await w.f.close();
});

interface IdxRow { kind: string; shard_no: number; generation: number; h: string }
const idx = (t: string) => asOwner(w.f.db, async () => (await w.f.db.query<{ kind: string; shard_no: number; generation: string; blob_ct: Uint8Array }>(
  `SELECT kind, shard_no, generation::text AS generation, blob_ct FROM "${t}".b1_index ORDER BY kind, shard_no`)).rows
  .map((r): IdxRow => ({ kind: r.kind, shard_no: r.shard_no, generation: Number(r.generation), h: createHash('sha256').update(r.blob_ct).digest('hex') })));
const manifestGen = async (t: string) => (await idx(t)).find((r) => r.kind === 'manifest')?.generation ?? 0;
const md = (title: string, text: string) => ({ kind: 'markdown' as const, title, text });
const search = async (t: string, query: string) => {
  const r = await (await mcpHarness(routedDeps(w, t))).call('zeusi_search', { query });
  return r;
};
const hitsOf = (r: { json: Record<string, unknown> | null }) => (r.json!['hits'] as Array<{ source_uri: string; text: string }>).map((h) => h.text);

test('§7.19: every sealed write transaction appends ONE segment and bumps the generation; it rewrites only its segment and the manifest', async () => {
  const t = await newWorkspace(w.f, 'on');
  const c = callerOf(t);
  await commitDocs(w.f, c, [md('First', '# First\n\nfalcon note one.\n')]);
  const a = await idx(t);
  assert.ok(a.some((r) => r.kind === 'manifest'));
  const g0 = await manifestGen(t);
  await commitDocs(w.f, c, [md('Second', '# Second\n\nember note two.\n'), md('Third', '# Third\n\nwillow note three.\n')]);
  const b = await idx(t);
  assert.equal(await manifestGen(t), g0 + 2, 'two notes = two sealed transactions = two generations');
  const segA = a.filter((r) => r.kind === 'segment');
  const segB = b.filter((r) => r.kind === 'segment');
  assert.equal(segB.length, segA.length + 2, 'one segment per transaction');
  for (const r of a.filter((x) => x.kind !== 'manifest')) assert.deepEqual(b.find((x) => x.kind === r.kind && x.shard_no === r.shard_no), r, `${r.kind} ${r.shard_no} untouched`);
  assert.deepEqual(new Set(segB.map((s) => s.generation)).size, segB.length, 'each segment carries its own generation');
  for (const q of ['falcon', 'ember', 'willow']) assert.equal(hitsOf(await search(t, q)).length, 1, q);
});

test('§7.19: a commit and a sync against one workspace both land in the index; a later search finds both (and a sync deletion leaves it)', async () => {
  const t = await newWorkspace(w.f, 'on');
  const c = callerOf(t);
  await commitDocs(w.f, c, [md('Commit', '# Commit\n\norbit commit note.\n')]);
  await w.f.ww.sync(c, [hqItem('alpha', '2026-10-15-ka.md', 'Sync', '# Sync\n\norbit sync note.')], []);
  assert.equal(hitsOf(await search(t, 'orbit')).length, 2);
  await w.f.ww.sync(c, [], ['alpha/2026-10-15-ka.md']);
  assert.deepEqual(hitsOf(await search(t, 'orbit')), ['orbit commit note.'], 'the deleted note left the index (hook, exact tombstones)');
});

test('§7.19: missing manifest on a sealed write: a full build from rows, then incremental again; compaction rewrites only the base shards it touches', async () => {
  const t = await newWorkspace(w.f, 'on');
  const c = callerOf(t);
  await commitDocs(w.f, c, [md('Base', '# Base\n\npebble base note.\n'), decisionLog(decisionEntry('pebble decision for the record shard.'))]);
  await asOwner(w.f.db, async () => { await w.f.db.query(`DELETE FROM "${t}".b1_index`); });
  const rebuilds = w.stats.rebuilds;
  await commitDocs(w.f, c, [md('After', '# After\n\npebble after note.\n')]);
  assert.equal(w.stats.rebuilds, rebuilds + 1, 'the write found no manifest and built the full index under the lock');
  const built = await idx(t);
  assert.deepEqual(built.filter((r) => r.kind === 'segment'), [], 'a full build writes base shards only');
  assert.ok(built.some((r) => r.kind === 'base' && r.shard_no >= 2_000_000), 'the decision lives in its record base shard');
  const segs = w.stats.segments;
  await commitDocs(w.f, c, [md('Incr', '# Incr\n\npebble incremental note.\n')]);
  assert.equal(w.stats.segments, segs + 1, 'then incremental again');
  // Compaction: more than COMPACT_SEGMENTS note transactions; only note shard 0 is touched.
  const before0 = await idx(t);
  const items = Array.from({ length: COMPACT_SEGMENTS + 2 }, (_, i) => hqItem('beta', `2026-10-01-c${i}.md`, `C${i}`, `# C${i}\n\nquartz compaction note ${i}.`));
  const compactions = w.stats.compactions;
  await w.f.ww.sync(c, items, []);
  assert.ok(w.stats.compactions > compactions, 'compacted');
  const after0 = await idx(t);
  const rec = (rows: IdxRow[]) => rows.filter((r) => r.kind === 'base' && r.shard_no >= 1_000_000);
  assert.deepEqual(rec(after0), rec(before0), 'record base shards untouched by a compaction of note segments');
  assert.ok(after0.filter((r) => r.kind === 'segment').length < COMPACT_SEGMENTS);
  assert.equal(hitsOf(await search(t, 'quartz')).length, 10, 'every compacted note is found (limit 10)');
  assert.equal(hitsOf(await search(t, 'pebble')).length, 4, 'three notes and the decision-log note');
});

test('§7.5 AAD: a base shard copied onto another shard number or into another workspace does not open; the read rebuilds from rows and serves the correct answer; mutant: AAD without the object number -> the swapped shard opens, the answer differs, red', async () => {
  const t = await newWorkspace(w.f, 'on');
  const u = await newWorkspace(w.f, 'on');
  await commitDocs(w.f, callerOf(t), [md('Mine', '# Mine\n\njade mine note.\n'), decisionLog(decisionEntry('jade decision of mine.'))]);
  await commitDocs(w.f, callerOf(u), [md('Other', '# Other\n\njade other note.\n')]);
  for (const ws of [t, u]) {
    await asOwner(w.f.db, async () => { await w.f.db.query(`DELETE FROM "${ws}".b1_index WHERE kind <> 'manifest'`); });
    // A write rebuilds the base shards (full build), so both workspaces hold base shard 0.
    await asOwner(w.f.db, async () => { await w.f.db.query(`DELETE FROM "${ws}".b1_index`); });
    await commitDocs(w.f, callerOf(ws), [md(`Fill ${ws.slice(3, 6)}`, '# Fill\n\nfiller.\n')]);
  }
  const want = hitsOf(await search(t, 'jade'));
  assert.ok(want.includes('jade mine note.') && !want.includes('jade other note.'));
  const swap = async (sql: string) => {
    w.cache.clear();
    const r0 = w.cache.stats.rebuilds;
    await asOwner(w.f.db, async () => { await w.f.db.query(sql); });
    const r = await search(t, 'jade');
    assert.equal(r.isError, false, r.text);
    assert.deepEqual(hitsOf(r), want, 'the correct answer');
    assert.equal(w.cache.stats.rebuilds, r0 + 1, 'built from rows (the swapped object did not open)');
  };
  // Another shard number: the record shard's blob moved onto note shard 0.
  await swap(`UPDATE "${t}".b1_index SET blob_ct = (SELECT blob_ct FROM "${t}".b1_index WHERE kind = 'base' AND shard_no >= 2000000 LIMIT 1) WHERE kind = 'base' AND shard_no = 0`);
  // Another workspace: u's shard 0 copied into t.
  await swap(`UPDATE "${t}".b1_index SET blob_ct = (SELECT blob_ct FROM "${u}".b1_index WHERE kind = 'base' AND shard_no = 0) WHERE kind = 'base' AND shard_no = 0`);
  // The manifest of another workspace.
  await swap(`UPDATE "${t}".b1_index SET blob_ct = (SELECT blob_ct FROM "${u}".b1_index WHERE kind = 'manifest') WHERE kind = 'manifest'`);
});

test('§7.5 AAD: a chunk text_ct moved onto another chunk, or a decision exact_words_ct onto another decision (then a rebuild): the read fails closed with WORKSPACE_UNAVAILABLE, nothing served; mutant: openedRow serves NULL on a tag failure -> red', async () => {
  const t = await newWorkspace(w.f, 'on');
  await commitDocs(w.f, callerOf(t), [md('A', '# A\n\nonyx alpha.\n'), md('B', '# B\n\nonyx beta.\n'), decisionLog(decisionEntry('onyx one.') + decisionEntry('onyx two.', { at: '2026-11-18T10:00:00+01:00' }))]);
  assert.equal(hitsOf(await search(t, 'onyx')).length, 4, 'two notes and the two decision-log chunks');
  await asOwner(w.f.db, async () => {
    await w.f.db.query(`UPDATE "${t}".chunks SET text_ct = (SELECT text_ct FROM "${t}".chunks ORDER BY id LIMIT 1) WHERE id = (SELECT max(id) FROM "${t}".chunks)`);
  });
  const r = await search(t, 'onyx');
  assert.equal(r.isError, true);
  assert.equal(r.text, WORKSPACE_UNAVAILABLE);
  const t2 = await newWorkspace(w.f, 'on');
  await commitDocs(w.f, callerOf(t2), [decisionLog(decisionEntry('onyx one.') + decisionEntry('onyx two.', { at: '2026-11-18T10:00:00+01:00' }))]);
  await asOwner(w.f.db, async () => {
    await w.f.db.query(`UPDATE "${t2}".decisions SET exact_words_ct = (SELECT exact_words_ct FROM "${t2}".decisions ORDER BY id LIMIT 1) WHERE id = (SELECT max(id) FROM "${t2}".decisions)`);
    await w.f.db.query(`DELETE FROM "${t2}".b1_index`);
  });
  w.cache.clear();
  const s = await (await mcpHarness(routedDeps(w, t2))).call('zeusi_startup', {});
  assert.equal(s.isError, true);
  assert.equal(s.text, WORKSPACE_UNAVAILABLE);
});

test('§7.10: the ACL audit passes with b1_index after prepare, flip, relax and unflip; the read role cannot write b1_index; open() still accepts the session; mutant: grant the reader INSERT -> open() refuses, red', async () => {
  const t = await newWorkspace(w.f, 'off');
  for (const [step, state] of [['prepare', null], ['flip', 'verified'], ['relax', null], ['unflip', 'decrypted']] as const) {
    if (state) await setState(w.f.db, t, state);
    const r = await w.f.dir.overlayStep(t, step, { dryRun: false });
    assert.equal(r.outcome, 'applied', `${step}: ${r.reason ?? ''}`);
    const bad = await asOwner(w.f.db, async () => (await w.f.db.query(TENANT_ACL_AUDIT_SQL, [t, tenantRole(t)])).rows);
    assert.deepEqual(bad, [], `${step}: ACL audit`);
  }
  assert.ok((await idx(t)).length === 0 && await asOwner(w.f.db, async () => (await w.f.db.query<{ ok: boolean }>(`SELECT to_regclass('"${t}".b1_index') IS NOT NULL AS ok`)).rows[0]!.ok), 'unflip keeps the table');
  const s = await w.f.router.open(t);
  try {
    await assert.rejects(s.query(`INSERT INTO zeusi.b1_index (key_version, kind, shard_no, generation, blob_ct) VALUES (1, 'base', 0, 1, $1::bytea)`, [Buffer.alloc(29, 1)]), (e: { code?: string }) => e.code === '25006' || e.code === '42501');
    await s.exec('ROLLBACK').catch(() => {});
    await s.exec('SET default_transaction_read_only = off');
    await assert.rejects(s.query(`DELETE FROM zeusi.b1_index`), (e: { code?: string }) => e.code === '42501', 'no write privilege, even outside read-only');
  } finally {
    await s.close();
  }
  await asOwner(w.f.db, async () => { await w.f.db.exec(`GRANT INSERT ON "${t}".b1_index TO "${tenantRole(t)}"`); });
  await assert.rejects(w.f.router.open(t), TenantRefused, 'a read role that can write any table is refused');
  await asOwner(w.f.db, async () => { await w.f.db.exec(`REVOKE INSERT ON "${t}".b1_index FROM "${tenantRole(t)}"`); });
  (await w.f.router.open(t)).close();
  // The writer: exactly SELECT/INSERT/UPDATE/DELETE; anything more fails the audit.
  await asOwner(w.f.db, async () => { await w.f.db.exec(`GRANT TRUNCATE ON "${t}".b1_index TO "${t}_w"`); });
  const bad = await asOwner(w.f.db, async () => (await w.f.db.query<{ kind: string; name: string }>(TENANT_ACL_AUDIT_SQL, [t, tenantRole(t)])).rows);
  assert.deepEqual(bad.map((b) => [b.kind, b.name]), [['relation', 'b1_index']]);
  await asOwner(w.f.db, async () => { await w.f.db.exec(`REVOKE TRUNCATE ON "${t}".b1_index FROM "${t}_w"`); });
  void asLogin;
});

test('a workspace prepared before C7 (no b1_index yet) converges at the next writer ensure; until then writes persist nothing and reads build from rows', async () => {
  const t = await newWorkspace(w.f, 'on');
  await asOwner(w.f.db, async () => { await w.f.db.exec(`DROP TABLE "${t}".b1_index`); });
  const skipped = w.stats.skippedNoTable;
  await commitDocs(w.f, callerOf(t), [md('Pre', '# Pre\n\ncobalt pre note.\n')]);
  assert.equal(w.stats.skippedNoTable, skipped + 1);
  w.cache.clear();
  const r0 = w.cache.stats.rebuilds;
  assert.deepEqual(hitsOf(await search(t, 'cobalt')), ['cobalt pre note.']);
  assert.equal(w.cache.stats.rebuilds, r0 + 1, 'built from rows in memory');
  assert.equal(await w.f.dir.ensureWriter(t), 'ready');
  assert.ok((await idx(t)).length === 0, 'the table exists again (empty): the next write builds it');
  await commitDocs(w.f, callerOf(t), [md('Post', '# Post\n\ncobalt post note.\n')]);
  assert.ok((await idx(t)).some((r) => r.kind === 'manifest'));
  assert.equal(hitsOf(await search(t, 'cobalt')).length, 2);
});
