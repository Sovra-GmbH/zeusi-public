// U5 (docs/plans/2026-11-18-workspace-write-import-plan.md KTD5, KTD6, KTD8): import preview ->
// commit and the nightly sync into a caller's OWN workspace, on PGlite with the real migrations, the
// tenant logins and the writer login (test/helpers/tenant-fixture.ts). The pipeline is the unchanged
// `zeusi import` / nightly one; these tests prove it runs per workspace and never reaches anything else.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { MAX_TENANTS, TenantDirectory, TenantRouter, TenantWriter, TENANT_WR_ROLE } from '../src/tenants.ts';
import { buildWsAuditLine, WS_AUDIT_FIELDS, AUDIT_COUNT_KEYS, type WsAuditEvent } from '../src/workspace-audit.ts';
import {
  diskUsage, PREVIEW_DISK_FULL, PREVIEW_TTL_MS, PREVIEW_UNKNOWN, WORKSPACE_WRITE_CAPS, WorkspaceWriteRefused, WorkspaceWrites, workspaceImportProfile,
  workspaceSyncProfile,
} from '../src/workspace-write.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { j, P, X0 } from './secret-fixtures.ts';
import { asLogin, asOwner, plantTeam, TEAM_MARKER, tenantTestDb, WALLED } from './helpers/tenant-fixture.ts';

let db: Db;
let A: string;
let B: string;
let ww: WorkspaceWrites;
let clock = Date.parse('2026-11-18T12:00:00Z');
const audits: WsAuditEvent[] = [];
const IBAN = ['CH93', '0076', '2011', '6238', '5295', '7'].join(' ');
const FAKE_KEY = j(P.akia, X0(8));
const callerA = (grantId = 'grantaaaaaaaaaaaaaaaaaaa') => ({ tenantId: A, grantId, subject: 'github:601', requestId: '00000000-0000-4000-8000-000000000001' });
const callerB = () => ({ tenantId: B, grantId: 'grantbbbbbbbbbbbbbbbbbbb', subject: 'github:602', requestId: null });

before(async () => {
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  const dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  const router = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt'), cacheMs: 0 });
  A = ((await dir.provision('github:601')) as { tenantId: string }).tenantId;
  B = ((await dir.provision('github:602')) as { tenantId: string }).tenantId;
  const writer = new TenantWriter({ connectWriter: asLogin(db, TENANT_WR_ROLE), check: (t) => router.check(t) });
  const root = join(safeMkdtemp(join(tmpdir(), 'zeusi-wsw-')), 'workspace-import');
  ww = new WorkspaceWrites({ workRoot: root, openWrite: (t) => writer.open(t), encState: (t) => router.encState(t), audit: (e) => audits.push(e), now: () => clock });
});
after(async () => {
  ww.close();
  await db.close();
});

const count = (schema: string, where = `status = 'active'`) => asOwner(db, async () =>
  (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${schema}".notes WHERE ${where}`)).rows[0]!.n);
const teamNotes = () => asOwner(db, async () => (await db.query<{ n: number }>('SELECT count(*)::int AS n FROM zeusi.notes')).rows[0]!.n);
const bodies = (schema: string) => asOwner(db, async () => (await db.query<{ body: string }>(`SELECT body FROM "${schema}".notes ORDER BY id`)).rows.map((r) => r.body).join('\n'));

const NOTES = [
  { kind: 'markdown' as const, title: 'Shipping rules', text: '---\ntitle: Shipping rules\ndate: 2026-11-10\nlocks:\n  - never ship on friday\n---\nWe ship on Mondays only.\n' },
  { kind: 'markdown' as const, title: 'Tricky text', text: `Text that names zeusi.notes, "${'zt_'}${'b'.repeat(26)}".notes and '; SET search_path = zeusi; DROP TABLE zeusi.notes; --\n` },
  { kind: 'markdown' as const, title: 'Bank', text: `pay to ${IBAN} please\n` },
  { kind: 'markdown' as const, title: 'Key', text: `## 2026-11-10\n\nkey ${FAKE_KEY}\n\n## 2026-11-11\n\nclean entry\n` },
];

test('preview: offline counts + admitted titles only; nothing written anywhere; quarantined / withheld text never shown', async () => {
  const before0 = { a: await count(A), b: await count(B), s: await teamNotes() };
  const p = await ww.preview(callerA(), NOTES);
  assert.equal(p.status, 'preview');
  if (p.status !== 'preview') return;
  assert.match(p.preview_id, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(p.saved, false);
  assert.ok(p.counts.notes >= 2, 'clean notes admitted');
  assert.ok(p.counts.quarantined >= 1, 'the IBAN note is quarantined (soft wall)');
  const shown = JSON.stringify(p.items);
  assert.ok(shown.includes('Shipping rules'));
  for (const leak of [IBAN, FAKE_KEY, 'pay to']) assert.ok(!shown.includes(leak) && !JSON.stringify(p).includes(leak), leak);
  assert.deepEqual({ a: await count(A), b: await count(B), s: await teamNotes() }, before0, 'a preview writes nothing');
  assert.equal(audits.at(-1)?.action, 'import_preview');
  assert.equal(audits.at(-1)?.outcome, 'ok');
});

test('commit: writes exactly the preview into A once; a second commit is a no-op; B and the team unchanged; text with schema names / SQL is stored as text', async () => {
  const p = await ww.preview(callerA(), NOTES);
  assert.equal(p.status, 'preview');
  if (p.status !== 'preview') return;
  const team0 = await teamNotes();
  const b0 = await count(B);
  const r1 = await ww.commit(callerA(), p.preview_id);
  assert.equal(r1.already_committed, false);
  assert.equal(r1.notes.inserted, p.counts.notes, 'exactly what the preview said');
  const a1 = await count(A);
  assert.equal(a1, p.counts.notes);
  const r2 = await ww.commit(callerA(), p.preview_id);
  assert.equal(r2.already_committed, true);
  assert.equal(await count(A), a1, 'second commit wrote nothing');
  assert.equal(await count(B), b0);
  assert.equal(await teamNotes(), team0);
  const text = await bodies(A);
  assert.ok(text.includes('SET search_path = zeusi; DROP TABLE zeusi.notes'), 'stored verbatim, never executed');
  assert.ok(!text.includes(IBAN) && !text.includes(FAKE_KEY));
  await asOwner(db, async () => {
    assert.ok((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${A}".ingest_runs WHERE importer = $1`, [workspaceImportProfile(A).importer])).rows[0]!.n >= 1);
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes WHERE body LIKE '%Mondays%'`)).rows[0]!.n, 0);
    assert.ok((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes WHERE body LIKE '%' || $1 || '%'`, [TEAM_MARKER])).rows[0]!.n > 0, 'the shared-schema rows intact');
  });
  // Committing the same preview id from the reused A one more time after expiry: still a no-op, never a re-run.
  clock += PREVIEW_TTL_MS - 1000;
  assert.equal((await ww.commit(callerA(), p.preview_id)).already_committed, true);
});

test('commit refusals: another tenant, another grant, a forged / unknown id, an expired preview: the same static text, nothing written', async () => {
  const p = await ww.preview(callerA('grant-two-aaaaaaaaaaaaaaa'), [{ kind: 'markdown', text: 'a fresh note about gardening\n' }]);
  assert.equal(p.status, 'preview');
  if (p.status !== 'preview') return;
  const a0 = await count(A);
  const b0 = await count(B);
  for (const [who, id] of [
    [callerB(), p.preview_id], // another workspace
    [callerA('grant-other-aaaaaaaaaaaaa'), p.preview_id], // same workspace, another grant
    [callerA('grant-two-aaaaaaaaaaaaaaa'), 'A'.repeat(43)], // unknown
    [callerA('grant-two-aaaaaaaaaaaaaaa'), `${p.preview_id}x`], // malformed
    [{ ...callerB(), tenantId: A }, p.preview_id], // B's grant claiming A (forged tenant): grant mismatch
  ] as const) {
    await assert.rejects(ww.commit(who, id), (e: unknown) => e instanceof WorkspaceWriteRefused && e.message === PREVIEW_UNKNOWN);
  }
  clock += PREVIEW_TTL_MS + 1;
  await assert.rejects(ww.commit(callerA('grant-two-aaaaaaaaaaaaaaa'), p.preview_id), (e: unknown) => e instanceof WorkspaceWriteRefused && e.message === PREVIEW_UNKNOWN);
  assert.equal(await count(A), a0);
  assert.equal(await count(B), b0);
});

test('preview caps: documents, bytes per document, total bytes: actionable refusals, nothing stored', async () => {
  const pending = ww.pending();
  const big = 'x'.repeat(WORKSPACE_WRITE_CAPS.documentBytes + 1);
  await assert.rejects(ww.preview(callerA(), [{ kind: 'markdown', text: big }]), /larger than 256 KiB; split it/);
  await assert.rejects(ww.preview(callerA(), Array.from({ length: WORKSPACE_WRITE_CAPS.previewDocuments + 1 }, () => ({ kind: 'markdown' as const, text: 'a' }))), /At most 50 documents/);
  await assert.rejects(ww.preview(callerA(), Array.from({ length: 4 }, () => ({ kind: 'markdown' as const, text: 'y'.repeat(250 * 1024) }))), /add up to more than 900 KB/);
  await assert.rejects(ww.preview(callerA(), []), /at least one document/);
  assert.equal(ww.pending(), pending);
  assert.ok(audits.slice(-4).every((a) => a.outcome === 'too_large' || a.outcome === 'refused'));
});

test('preview of a walled-person document: refused or withheld; the name never appears in the answer', async () => {
  const r = await ww.preview(callerA(), [{ kind: 'markdown', text: `## 2026-11-10\n\nmeeting with ${WALLED} about plans\n` }]).catch((e: Error) => e);
  assert.ok(!JSON.stringify(r instanceof Error ? r.message : r).toLowerCase().includes(WALLED.toLowerCase()));
});

const hq = (project: string, file: string, title: string, body: string) =>
  ({ path: `${project}/${file}`, text: `---\nproject: ${project}\nkind: memory\ndate: ${file.slice(0, 10)}\ntitle: ${title}\nsource: assistant\n---\n${body}\n` });

test('sync: upsert by uri + sha (same batch twice = unchanged), the export filter runs, deletes only listed paths in the own workspace', async () => {
  const b0 = await count(B);
  const s0 = await teamNotes();
  const batch = [
    hq('journal', '2026-11-17-day.md', 'Day', '## 2026-11-17\n\nwrote tests'),
    hq('journal', '2026-11-18-day.md', 'Day 2', `## 2026-11-18\n\nkey ${FAKE_KEY}\n\n## 2026-11-18b\n\nclean`),
  ];
  const r1 = await ww.sync(callerA(), batch, []);
  assert.equal(r1.counts.inserted, 2);
  const r2 = await ww.sync(callerA(), batch, []);
  assert.equal(r2.counts.inserted, 0);
  assert.equal(r2.counts.unchanged, 2, 'same uri + sha: skipped');
  const edited = [hq('journal', '2026-11-17-day.md', 'Day', '## 2026-11-17\n\nwrote more tests')];
  assert.equal((await ww.sync(callerA(), edited, [])).counts.updated, 1);
  assert.ok(!(await bodies(A)).includes(FAKE_KEY), 'the nightly filter withheld the credential entry');
  // P2-1 (review of #31): the nightly export filter ran ENTRY by entry (runExportFilter), not only the
  // importer's own secret gate (which would quarantine the whole note): one entry withheld, the clean
  // sibling entry of the same note stored.
  assert.ok(r1.counts.withheld_entries >= 1, 'the export filter withheld the credential entry');
  const day2 = await asOwner(db, async () => (await db.query<{ body: string }>(
    `SELECT body FROM "${A}".notes WHERE vault_path = 'hq:journal/2026-11-18-day.md' AND status = 'active'`)).rows.map((r) => r.body));
  assert.equal(day2.length, 1, 'the note with the withheld entry is stored, not quarantined whole');
  assert.ok(day2[0]!.includes('2026-11-18b') && /\bclean\b/.test(day2[0]!) && !day2[0]!.includes(FAKE_KEY), 'clean sibling entry stored');
  // P2-2 (review of #31): notes with the same tail path that are NOT this workspace's synced hq: notes.
  const plantNote = (path: string, kind: string, marker: string) => asOwner(db, async () => {
    const run = (await db.query<{ id: number }>(`INSERT INTO "${A}".ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    await db.query(
      `INSERT INTO "${A}".notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1, 't', $2, now(), 'work', $3::"${A}".source_kind, $4, now(), sha256(convert_to($2, 'UTF8')), $5)`,
      [path, `planted ${marker}`, kind, `test:${marker}`, run]);
  });
  await plantNote('import:journal/2026-11-18-day.md', 'manual', 'quollimported');
  await plantNote('legacy/hq:journal/2026-11-18-day.md', 'vault_note', 'quolllegacy');
  await plantNote('hq:journal/2026-11-16-manual.md', 'manual', 'quollmanual');
  // Deletion: only the listed path, only hq: notes of A; an imported (import:) note with any name is untouched.
  const imported0 = await count(A, `status = 'active' AND vault_path LIKE 'import:%'`);
  const d = await ww.sync(callerA(), [], ['journal/2026-11-18-day.md', 'journal/2026-01-01-missing.md']);
  assert.equal(d.counts.deleted, 1);
  assert.equal(d.counts.deleted_not_found, 1);
  assert.equal(await count(A, `status = 'active' AND vault_path = 'hq:journal/2026-11-18-day.md'`), 0);
  assert.equal(await count(A, `status = 'active' AND vault_path = 'hq:journal/2026-11-17-day.md'`), 1);
  assert.equal(await count(A, `status = 'active' AND vault_path LIKE 'import:%'`), imported0);
  for (const p of ['import:journal/2026-11-18-day.md', 'legacy/hq:journal/2026-11-18-day.md']) {
    assert.equal(await count(A, `status = 'active' AND vault_path = '${p}'`), 1, `${p} survives a sync delete of the same tail path`);
  }
  // An hq: path that is not a synced (zeus_memory) note is never deleted by sync.
  const dm = await ww.sync(callerA(), [], ['journal/2026-11-16-manual.md']);
  assert.deepEqual([dm.counts.deleted, dm.counts.deleted_not_found], [0, 1]);
  assert.equal(await count(A, `status = 'active' AND vault_path = 'hq:journal/2026-11-16-manual.md'`), 1, 'a manual hq: note stays active');
  assert.equal(await count(B), b0);
  assert.equal(await teamNotes(), s0);
  await asOwner(db, async () => {
    assert.ok((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${A}".ingest_runs WHERE importer = $1`, [workspaceSyncProfile(A).importer])).rows[0]!.n >= 1);
  });
  // B deleting A's path deletes nothing (B's own schema has no such note).
  const bd = await ww.sync(callerB(), [], ['journal/2026-11-17-day.md']);
  assert.equal(bd.counts.deleted, 0);
  assert.equal(await count(A, `status = 'active' AND vault_path = 'hq:journal/2026-11-17-day.md'`), 1);
});

test('sync refusals: bad paths (traversal, schema-qualified, absolute), caps, duplicates, empty batch; nothing changed', async () => {
  const a0 = await count(A);
  for (const bad of ['../x/2026-11-17-a.md', '/etc/2026-11-17-a.md', 'zeusi.notes/2026-11-17-a.md', 'journal/../../2026-11-17-a.md', 'Journal/2026-11-17-a.md', 'journal/notes.md', 'a/b/2026-11-17-a.md']) {
    await assert.rejects(ww.sync(callerA(), [{ path: bad, text: 'x' }], []), /<project>\/YYYY-MM-DD-<slug>\.md/, bad);
    await assert.rejects(ww.sync(callerA(), [], [bad]), /<project>\/YYYY-MM-DD-<slug>\.md/, bad);
  }
  await assert.rejects(ww.sync(callerA(), [], []), /empty batch/);
  await assert.rejects(ww.sync(callerA(), Array.from({ length: 101 }, (_, i) => hq('j', `2026-11-17-n${i}.md`, 't', 'b')), []), /At most 100 items/);
  await assert.rejects(ww.sync(callerA(), [hq('j', '2026-11-17-a.md', 't', 'x'.repeat(WORKSPACE_WRITE_CAPS.syncItemBytes + 1))], []), /larger than 256 KiB/);
  await assert.rejects(ww.sync(callerA(), [hq('j', '2026-11-17-a.md', 't', 'b'), hq('j', '2026-11-17-a.md', 't', 'c')], []), /appears twice/);
  await assert.rejects(ww.sync(callerA(), [hq('j', '2026-11-17-a.md', 't', 'b')], ['j/2026-11-17-a.md']), /both in items and in deleted/);
  assert.equal(await count(A), a0);
});

test('workspace size cap: a commit or sync that would exceed it is refused before anything is written', async () => {
  const c = WORKSPACE_WRITE_CAPS as { workspaceNotes: number };
  const saved = c.workspaceNotes;
  try {
    // Room for the preview when it is made (review P1-1 of #32: a preview over the room is refused at
    // preview time); the workspace is full by commit time, so the commit's own check refuses.
    c.workspaceNotes = (await count(A)) + 1;
    const p = await ww.preview(callerA(), [{ kind: 'markdown', text: 'one more note about birds\n' }]);
    assert.equal(p.status, 'preview');
    if (p.status !== 'preview') return;
    c.workspaceNotes = await count(A); // full
    const a0 = await count(A);
    await assert.rejects(ww.commit(callerA(), p.preview_id), /over its size limit/);
    await assert.rejects(ww.sync(callerA(), [hq('j', '2026-11-17-full.md', 't', 'b')], []), /over its size limit/);
    assert.equal(await count(A), a0);
  } finally {
    c.workspaceNotes = saved;
  }
});

test('review fix: a sync delete blanks the stored text (storage cannot pile up behind deletions); a later sync of the same note restores it', async () => {
  const note = hq('garden', '2026-11-17-roses.md', 'Roses', 'roses need water wombatgardenmarker');
  await ww.sync(callerA(), [note], []);
  await ww.sync(callerA(), [], [note.path]);
  const row = async () => asOwner(db, async () => (await db.query<{ status: string; body: string }>(`SELECT status, body FROM "${A}".notes WHERE vault_path = $1`, [`hq:${note.path}`])).rows[0]!);
  assert.deepEqual(await row(), { status: 'deleted', body: '' });
  const r = await ww.sync(callerA(), [note], []);
  assert.equal(r.counts.updated, 1, 'a deleted note with the same hash is rewritten, not skipped');
  const back = await row();
  assert.equal(back.status, 'active');
  assert.ok(back.body.includes('wombatgardenmarker'));
});

test('review fix: removed notes still count toward the row cap; a full preview store refuses new previews instead of evicting another workspace\'s', async () => {
  const c = WORKSPACE_WRITE_CAPS as { workspaceRows: number; previewsTotal: number };
  const savedRows = c.workspaceRows;
  try {
    c.workspaceRows = await asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${A}".notes`)).rows[0]!.n);
    await assert.rejects(ww.sync(callerA(), [hq('garden', '2026-11-18-tulips.md', 't', 'b')], []), /over its size limit/);
  } finally {
    c.workspaceRows = savedRows;
  }
  const savedTotal = c.previewsTotal;
  try {
    const pb = await ww.preview(callerB(), [{ kind: 'markdown', text: 'a note of B about kites\n' }]);
    assert.equal(pb.status, 'preview');
    if (pb.status !== 'preview') return;
    c.previewsTotal = ww.pending();
    await assert.rejects(ww.preview(callerA(), [{ kind: 'markdown', text: 'a note of A about owls\n' }]), /too many open previews/);
    const r = await ww.commit(callerB(), pb.preview_id);
    assert.equal(r.already_committed, false, "B's pending preview survived A's attempt");
  } finally {
    c.previewsTotal = savedTotal;
  }
});

// P2-7 (review of #31): the global preview store is sized for every workspace's own allowance, so
// other workspaces holding all their previews can never refuse this workspace's.
test('review P2-7: MAX_TENANTS workspaces each holding previewsPerTenant open previews: every preview is accepted (no cross-workspace refusal)', async () => {
  const caps = WORKSPACE_WRITE_CAPS;
  assert.ok(caps.previewsTotal >= MAX_TENANTS * caps.previewsPerTenant, 'global budget >= MAX_TENANTS x previewsPerTenant');
  const b32 = 'abcdefghijklmnopqrstuvwxyz234567';
  const tid = (i: number) => `zt_${Array.from({ length: 26 }, (_, k) => b32[(Math.floor(i / 32 ** Math.min(k, 3)) + k) % 32]).join('')}`;
  const ids = Array.from({ length: MAX_TENANTS }, (_, i) => tid(i));
  assert.equal(new Set(ids).size, MAX_TENANTS);
  const root = join(safeMkdtemp(join(tmpdir(), 'zeusi-wsw-budget-')), 'workspace-import');
  const store = new WorkspaceWrites({ workRoot: root, openWrite: () => Promise.reject(new Error('previews are offline')), encState: async () => ({ status: 'active', encState: 'off' }), now: () => clock });
  try {
    // Every other workspace holds its full allowance of open previews (each still holding prepared
    // text); the last one holds all but one. Seeded directly: 600 real previews would take ~20 s.
    const map = (store as unknown as { previews: Map<string, unknown> }).previews;
    const last = ids.at(-1)!;
    for (const [i, t] of ids.entries()) {
      for (let n = 0; n < caps.previewsPerTenant - (t === last ? 1 : 0); n++) {
        map.set(`seed-${i}-${n}`, {
          tenantId: t, grantId: `grant-${i}`, expires: clock + PREVIEW_TTL_MS, prepared: { cleanup: () => {} }, bytes: 1, notes: 1, result: null, running: null,
          // Each workspace also holds its full on-disk byte allowance (review P1-1 of #32): the global
          // byte budget never refuses another workspace's own allowance either.
          disk: Math.floor(caps.tenantDiskBytes / caps.previewsPerTenant),
        });
      }
    }
    assert.equal(store.pending(), MAX_TENANTS * caps.previewsPerTenant - 1);
    const p = await store.preview({ tenantId: last, grantId: 'grant-last', subject: null, requestId: null }, [{ kind: 'markdown', text: 'a note about herons\n' }]);
    assert.equal(p.status, 'preview', 'the last workspace still gets its own allowance');
    assert.equal(store.pending(), MAX_TENANTS * caps.previewsPerTenant);
    // A committed preview keeps only its small result (no text on disk): it holds no slot.
    const extra = { tenantId: `zt_${'x'.repeat(26)}`, grantId: 'grant-extra', subject: null, requestId: null };
    const doc1 = [{ kind: 'markdown' as const, text: 'a note about storks\n' }];
    if (caps.previewsTotal === MAX_TENANTS * caps.previewsPerTenant) await assert.rejects(store.preview(extra, doc1), /too many open previews/);
    Object.assign(map.get('seed-0-0') as object, { prepared: null, result: { status: 'ok' } });
    assert.equal((await store.preview(extra, doc1)).status, 'preview');
  } finally {
    store.close();
  }
});

// Review P1-1 of #32: preview text on disk is bounded by notes per preview, the workspace's remaining
// room and MEASURED on-disk bytes (per preview, per workspace, global, free-space floor); every refusal
// leaves no file behind.
const claudeExport = (n: number, from = 0) => JSON.stringify(Array.from({ length: n }, (_, i) => ({
  name: `c${from + i}`, created_at: '2026-11-10T09:00:00Z',
  chat_messages: [{ sender: 'human', created_at: '2026-11-10T09:00:01Z', text: `tiny ${from + i}` }],
})));
const offlineStore = (o: { freeBytes?: (p: string) => number | null } = {}) => {
  const root = join(safeMkdtemp(join(tmpdir(), 'zeusi-wsw-disk-')), 'workspace-import');
  const seen: WsAuditEvent[] = [];
  const store = new WorkspaceWrites({
    workRoot: root, openWrite: () => Promise.reject(new Error('offline')), encState: async () => ({ status: 'active', encState: 'off' }), now: () => clock, audit: (e) => seen.push(e), ...o,
  });
  return { root, store, seen };
};
const leftovers = (root: string) => [...readdirSync(join(root, 'runs')), ...readdirSync(join(root, 'inbox'))];
const callerX = (n = 1) => ({ tenantId: `zt_${'q'.repeat(25)}${'abcdefgh'[n]}`, grantId: `grant-x-${n}`, subject: null, requestId: null });

test('review P1-1: a many-tiny-conversations Claude export (the review probe shape) is refused at the per-preview note cap; no file is left', async () => {
  const caps = WORKSPACE_WRITE_CAPS;
  // Three exports of tiny conversations, each under documentBytes, together under previewTotalBytes
  // (the probe: 783 KB -> 6 973 notes, about 28 MB on disk).
  const docs: Array<{ kind: 'claude-export'; text: string }> = [];
  let total = 0;
  for (let d = 0; d < 3; d++) {
    let n = 2400;
    while (Buffer.byteLength(claudeExport(n, d * 10_000)) > caps.documentBytes) n -= 100;
    docs.push({ kind: 'claude-export', text: claudeExport(n, d * 10_000) });
    total += n;
  }
  assert.ok(total > caps.previewNotes * 5, `the probe shape stages ${total} notes`);
  assert.ok(docs.reduce((a, d) => a + Buffer.byteLength(d.text), 0) <= caps.previewTotalBytes);
  const { root, store, seen } = offlineStore();
  try {
    await assert.rejects(store.preview(callerX(), docs), (e: unknown) => e instanceof WorkspaceWriteRefused
      && new RegExp(`One preview holds at most ${caps.previewNotes} notes`).test(e.message) && /Nothing was saved/.test(e.message));
    // Staging stopped at the cap (ImportNotesCapError inside prepareImport): no dry pass ran, so the
    // refusal carries no note counts; the 6 973-file run of the probe was never written.
    assert.deepEqual({ outcome: seen.at(-1)?.outcome, counts: seen.at(-1)?.counts }, { outcome: 'too_large', counts: { documents: 3, bytes: docs.reduce((a, d) => a + Buffer.byteLength(d.text), 0) } });
    assert.deepEqual(leftovers(root), [], 'no inbox, staging or run dir is left');
    assert.equal(store.pending(), 0);
    // Exactly at the cap is bounded and accepted; its on-disk size is measured and within the budget.
    const ok = await store.preview(callerX(), [{ kind: 'claude-export', text: claudeExport(caps.previewNotes) }]);
    assert.equal(ok.status, 'preview');
    assert.equal(ok.counts.notes, caps.previewNotes);
    const e = [...(store as unknown as { previews: Map<string, { disk: number; prepared: { sealed: { dir: string } } }> }).previews.values()][0]!;
    assert.equal(e.disk, diskUsage(e.prepared.sealed.dir).bytes);
    assert.ok(e.disk <= caps.previewDiskBytes, `${e.disk} bytes on disk for ${caps.previewNotes} notes`);
  } finally {
    store.close();
  }
  assert.deepEqual(leftovers(root), []);
});

test('review P1-1: budgets count MEASURED on-disk bytes, not request bytes: per preview, per workspace (own oldest go first), global, free-space floor', async () => {
  const caps = WORKSPACE_WRITE_CAPS as unknown as Record<'previewDiskBytes' | 'tenantDiskBytes' | 'diskBytesTotal' | 'workDiskFloorBytes', number>;
  const saved = { ...caps };
  const doc = (from: number) => [{ kind: 'claude-export' as const, text: claudeExport(40, from) }];
  const requestBytes = Buffer.byteLength(doc(0)[0]!.text);
  let free: number | null = Number.MAX_SAFE_INTEGER;
  const { root, store } = offlineStore({ freeBytes: () => free });
  type Entry = { tenantId: string; disk: number; prepared: { sealed: { dir: string } } | null };
  const entries = () => [...(store as unknown as { previews: Map<string, Entry> }).previews.values()];
  try {
    const p1 = await store.preview(callerX(1), doc(0));
    assert.equal(p1.status, 'preview');
    const one = entries()[0]!;
    const measured = diskUsage(one.prepared!.sealed.dir);
    assert.equal(one.disk, measured.bytes, 'charged exactly the allocated bytes of the prepared run');
    assert.ok(measured.files >= 40, 'one sealed file per note');
    assert.ok(one.disk > requestBytes, `on disk ${one.disk} > request ${requestBytes}: the request size is not the budget`);

    // Per preview: a cap above the request bytes but below the measured bytes refuses; nothing kept.
    caps.previewDiskBytes = one.disk - 1;
    await assert.rejects(store.preview(callerX(2), doc(100)), /take too much space as a preview/);
    assert.equal(entries().length, 1);
    assert.equal(readdirSync(join(root, 'runs')).length, 1, 'only the first preview holds files');
    caps.previewDiskBytes = saved.previewDiskBytes;

    // Per workspace: room for one preview only -> the workspace's own oldest goes, the new one stays.
    caps.tenantDiskBytes = one.disk + Math.floor(one.disk / 2);
    const p2 = await store.preview(callerX(1), doc(200));
    assert.equal(p2.status, 'preview');
    assert.equal(entries().length, 1, 'own oldest dropped to fit');
    assert.equal(readdirSync(join(root, 'runs')).length, 1);
    caps.tenantDiskBytes = saved.tenantDiskBytes;

    // Global: all open previews' measured bytes; another workspace is refused, nothing evicted or kept.
    caps.diskBytesTotal = entries()[0]!.disk + Math.floor(one.disk / 2);
    await assert.rejects(store.preview(callerX(3), doc(300)), (e: unknown) => e instanceof Error && e.message === PREVIEW_DISK_FULL);
    assert.equal(entries().length, 1, "the other workspace's preview survives");
    assert.equal(readdirSync(join(root, 'runs')).length, 1);
    caps.diskBytesTotal = saved.diskBytesTotal;

    // Free-space floor on the work filesystem: refused before anything is written.
    free = caps.workDiskFloorBytes - 1;
    await assert.rejects(store.preview(callerX(3), doc(400)), (e: unknown) => e instanceof Error && e.message === PREVIEW_DISK_FULL);
    free = caps.workDiskFloorBytes + one.disk - 1;
    await assert.rejects(store.preview(callerX(3), doc(400)), (e: unknown) => e instanceof Error && e.message === PREVIEW_DISK_FULL, 'checked again with the measured size');
    assert.equal(readdirSync(join(root, 'runs')).length, 1);
    assert.deepEqual(readdirSync(join(root, 'inbox')), []);
    free = null;
    assert.equal((await store.preview(callerX(3), doc(500))).status, 'preview', 'statfs not reported: the byte budgets still apply');
  } finally {
    Object.assign(caps, saved);
    store.close();
  }
  assert.deepEqual(leftovers(root), []);
});

test('review P1-1: a preview whose admitted notes exceed the workspace\'s remaining room is refused and keeps no file', async () => {
  const c = WORKSPACE_WRITE_CAPS as { workspaceNotes: number };
  const saved = c.workspaceNotes;
  const root = (ww as unknown as { root: string }).root;
  const runsBefore = readdirSync(join(root, 'runs')).sort();
  const pendingBefore = ww.pending();
  try {
    const have = await count(A);
    c.workspaceNotes = have + 2;
    const three = ['wren', 'robin', 'finch'].map((b) => ({ kind: 'markdown' as const, text: `a note of A about a ${b}\n` }));
    await assert.rejects(ww.preview(callerA(), three), /no room for this many notes \(it holds at most/);
    assert.deepEqual(readdirSync(join(root, 'runs')).sort(), runsBefore, 'no run dir kept');
    assert.deepEqual(readdirSync(join(root, 'inbox')), []);
    assert.equal(ww.pending(), pendingBefore);
    // Full: refused before anything is written.
    c.workspaceNotes = have;
    await assert.rejects(ww.preview(callerA(), three.slice(0, 1)), /no room for this many notes/);
    assert.deepEqual(readdirSync(join(root, 'runs')).sort(), runsBefore);
    // Within the room: accepted.
    c.workspaceNotes = have + 3;
    assert.equal((await ww.preview(callerA(), three)).status, 'preview');
  } finally {
    c.workspaceNotes = saved;
  }
});

test('nothing left on disk: the inbox is removed after every preview, sync work dirs after every batch', () => {
  const root = (ww as unknown as { root: string }).root;
  assert.deepEqual(readdirSync(join(root, 'inbox')), []);
  assert.ok(readdirSync(join(root, 'runs')).every((n) => !n.startsWith('sync-')));
  ww.close();
  assert.equal(ww.pending(), 0);
  assert.ok(existsSync(root));
});

test('audit: allowlisted fields only; no content, title, path, preview id or token; counts numeric only', () => {
  assert.ok(audits.length >= 10);
  for (const e of audits) {
    const line = buildWsAuditLine(e);
    const o = JSON.parse(line) as Record<string, unknown>;
    assert.deepEqual(Object.keys(o), [...WS_AUDIT_FIELDS]);
    for (const k of Object.keys(o['counts'] as object)) assert.ok((AUDIT_COUNT_KEYS as readonly string[]).includes(k), k);
    for (const leak of ['Shipping', 'Mondays', 'journal/', IBAN, FAKE_KEY, 'grantaaaa', 'zeusi.notes']) assert.ok(!line.includes(leak), `${leak} in ${line}`);
    assert.match(String(o['grant_hash']), /^[0-9a-f]{16}$/);
  }
  const forged = buildWsAuditLine({
    requestId: 'not a uuid; DROP', subject: 'OperatorOwner', tenantId: 'work', grantId: 'x y', action: 'import_commit', outcome: 'ok',
    counts: { notes: 3, evil: 5, text: 'secret' } as never,
  });
  assert.deepEqual(JSON.parse(forged), {
    ts: (JSON.parse(forged) as { ts: string }).ts, request_id: null, github_subject: null, tenant_id: null, grant_hash: null,
    action: 'import_commit', outcome: 'ok', counts: { notes: 3 },
  });
});
