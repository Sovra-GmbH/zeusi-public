// Security bootstrap §7 item 7 (docs/plans/2026-11-18-zeusi-workspace-encryption.md; C2 plan
// docs/plans/2026-11-18-c2-log-disk-hygiene.md R5): no plain text in logs and disks. A canary string is
// sent through preview, commit, sync, search, search feedback, startup and context_for_task of a
// personal workspace on the real hosted handler (PGlite, real roles, FAKE GitHub, loopback only). Then
// it must not appear in:
//   * stderr (everything the process wrote to it during the run),
//   * the MCP request log (and every line keeps exactly the allowlisted fields, src/mcp-log.ts),
//   * the sign-in audit and the workspace-write audit,
//   * the feedback ledgers (the team's and the workspace's),
//   * the preview work root, while the preview is pending and after commit / sync.
// Controls make sure the canary really travelled: it is stored in the workspace, it is in the hit's
// source_uri (so a plain-uri ledger would fail), and the work root really holds the pending preview.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, lstatSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { WORKSPACE_URI_KEY_ID } from '../src/feedback.ts';
import { workspaceFeedbackPath } from '../src/mcp-hosted.ts';
import { LOG_FIELDS } from '../src/mcp-log.ts';
import { WorkspaceWrites } from '../src/workspace-write.ts';
import { callTool, mcpPost, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asOwner, plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';

const CANARY = 'wombatcanary7c2x9q';
const CANARY_B = Buffer.from(CANARY, 'utf8');

/** Every path below `root` (names) and every regular file's bytes, never through a symlink. */
function scanTree(root: string): { names: string[]; files: number; hit: string[] } {
  const names: string[] = [];
  const hit: string[] = [];
  let files = 0;
  const walk = (p: string) => {
    for (const n of readdirSync(p)) {
      const q = join(p, n);
      names.push(q);
      if (q.toLowerCase().includes(CANARY)) hit.push(`name ${q}`);
      const st = lstatSync(q);
      if (st.isDirectory()) walk(q);
      else if (st.isFile()) {
        files++;
        if (readFileSync(q).includes(CANARY_B)) hit.push(`content ${q}`);
      }
    }
  };
  if (existsSync(root)) walk(root);
  return { names, files, hit };
}

let db: Db;
let h: TenantHarness;
let home: string;
let workRoot: string;
let tok: string;
let tenant: string;
const stderr: string[] = [];
let restoreStderr: () => void;

before(async () => {
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
    stderr.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return (orig as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;
  restoreStderr = () => { process.stderr.write = orig; };
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  home = serviceHome();
  workRoot = join(safeMkdtemp(join(tmpdir(), 'zeusi-c2-work-')), 'workspace-import');
  h = await startTenantHosted({
    db, home, workRoot, writer: 'on', limits: { signupPerIp: 50, signupGlobal: 50 }, wsLimits: { preview: 20, commit: 20, sync: 20 },
  });
  tok = (await signIn(h, 'gh-stranger')).access;
  tenant = (await h.dir!.lookup('github:105'))!.tenantId;
});
after(async () => {
  restoreStderr();
  await h.close();
  await db.close();
});

const call = async (name: string, args: Record<string, unknown>) => {
  const r = toolJson(await mcpPost(h.port, tok, callTool(name, args)));
  assert.equal(r.isError, false, `${name}: ${r.text}`);
  return r;
};
/** True when the request log has a line for `tool` that was served (HTTP 200, no error class). */
const served = (tool: string) => h.logs.some((l) => {
  const j = JSON.parse(l) as Record<string, unknown>;
  return j['tool'] === tool && j['status'] === 200 && j['error_class'] === null;
});
const storedIn = (like: string) => asOwner(db, async () =>
  (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${tenant}".notes WHERE body LIKE $1 OR title LIKE $1`, [`%${like}%`])).rows[0]!.n);

test('item 7: the canary goes through preview, commit, sync, search, feedback, startup and context_for_task; it is nowhere in logs, audits, ledgers or the work root', async () => {
  // Preview: a title (it named the inbox file before C2) and a body carrying the canary.
  const p = await call('zeusi_import_preview', {
    documents: [
      { kind: 'markdown', title: `${CANARY} plan`, text: `# Plan\n\nThe ${CANARY} project ships on Monday.\n` },
      { kind: 'markdown', text: `---\ntitle: ${CANARY} notes\ndate: 2026-11-17\n---\nWe met about ${CANARY}.\n` },
      // A note lock: context_for_task returns it as an item, so the second feedback call below has a target.
      // It is marked standing, so startup serves it too (review C2R2-1: a control that startup really ran).
      { kind: 'markdown', title: `${CANARY} rules`, text: `---\ntitle: ${CANARY} rules\ndate: 2026-11-18\nlocks:\n  - "The ${CANARY} release waits for a review"\nstanding_locks:\n  - 1\n---\nWhy: ${CANARY}.\n` },
    ],
  });
  assert.ok(p.text.includes(CANARY), 'control: the preview items show the canary to the caller (the response, not a log)');
  const previewId = String(p.json!['preview_id']);

  // While the preview is pending (up to 30 minutes in production): the work root holds the sealed run only.
  const pending = scanTree(workRoot);
  assert.ok(pending.files >= 2, `control: the pending preview is on disk (${pending.files} files)`);
  assert.deepEqual(pending.hit, [], 'no canary in a name or a byte of the pending preview');
  assert.ok(pending.names.every((n) => !/inbox\/.+/.test(n.slice(workRoot.length))), 'no inbox left after the call');

  await call('zeusi_import_commit', { preview_id: previewId, confirm: true });
  assert.ok(await storedIn(CANARY) >= 2, 'control: the canary is stored in the workspace');
  assert.deepEqual(scanTree(workRoot).hit, [], 'after commit');

  // Sync: the canary in the HQ file name (it becomes the source_uri) and in the text.
  const path = `notes/2026-11-18-${CANARY}.md`;
  await call('zeusi_sync_batch', {
    items: [{ path, text: `---\nproject: notes\nkind: memory\ndate: 2026-11-18\ntitle: ${CANARY} sync\nsource: assistant\n---\nSynced ${CANARY} text.\n` }],
  });
  assert.deepEqual(scanTree(workRoot).hit, [], 'after sync');

  // Search, then feedback on a hit whose source_uri carries the canary, with a reason that names it.
  const s = await call('zeusi_search', { query: CANARY });
  const hits = s.json!['hits'] as Array<{ source_uri: string }>;
  const hit = hits.find((x) => x.source_uri.includes(CANARY));
  assert.ok(hit, `control: a hit's source_uri carries the canary (${hits.map((x) => x.source_uri).join(', ')})`);
  await call('zeusi_search_feedback', { query_id: s.json!['query_id'], source_uri: hit.source_uri, useful: true, reason: `${CANARY} helped me` });

  // Startup (review C2R2-1): its result is used. It is this workspace's startup, and it serves the
  // canary standing lock, so dropping the call (or serving another workspace) fails here.
  const st = await call('zeusi_startup', {});
  const rules = (st.json!['rules'] ?? []) as Array<{ origin?: string; text?: string }>;
  assert.ok(rules.some((r) => r.origin === 'note_lock' && r.text?.includes(CANARY)), `control: startup served this workspace's canary standing lock (${rules.length} rules)`);
  assert.ok(served('zeusi_startup'), 'control: the request log has a served zeusi_startup line');
  const ctx = await call('zeusi_context_for_task', { task: `prepare the ${CANARY} release` });
  assert.ok(ctx.text.includes(CANARY), 'control: context_for_task served the canary lock (the response, not a log)');
  assert.ok(served('zeusi_context_for_task'), 'control: the request log has a served zeusi_context_for_task line');
  // context_for_task: feedback on its query_id as well (it returns `items`; review C2R1-4).
  const cq = ctx.json!['query_id'];
  assert.equal(typeof cq, 'string', 'control: context_for_task returned a query_id');
  const items = (ctx.json!['items'] ?? []) as Array<{ source_uri?: string; exact_words?: string }>;
  const cu = items.find((x) => x.exact_words?.includes(CANARY))?.source_uri;
  assert.ok(cu, `control: context_for_task returned the canary lock as an item (${items.length} items)`);
  const fb = await call('zeusi_search_feedback', { query_id: cq, source_uri: cu, useful: false, reason: `${CANARY} was not it` });
  assert.equal(fb.isError, false, 'control: the second feedback call ran and was accepted');

  // --- the scans ---
  assert.ok(h.logs.length >= 8, 'control: requests were logged');
  for (const line of h.logs) {
    assert.ok(!line.includes(CANARY), `request log: ${line}`);
    assert.deepEqual(Object.keys(JSON.parse(line) as object), [...LOG_FIELDS], 'request-log allowlist (src/mcp-log.ts) holds');
  }
  assert.ok(h.audits.length >= 1, 'control: the sign-in was audited');
  for (const line of h.audits) assert.ok(!line.includes(CANARY), `sign-in audit: ${line}`);
  assert.ok(h.wsAudits.length >= 3, 'control: preview, commit and sync were audited');
  for (const line of h.wsAudits) assert.ok(!line.includes(CANARY), `workspace audit: ${line}`);

  const ledgers = scanTree(join(home, '.zeusi'));
  assert.deepEqual(ledgers.hit, [], 'feedback ledgers (the team and workspace) and every other file under the data dir');
  const mine = readFileSync(workspaceFeedbackPath(join(home, '.zeusi', 'search-feedback.jsonl'), tenant), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
  assert.equal(mine.length, 2, 'control: both feedback calls (search and context_for_task) were recorded in the workspace ledger');
  for (const l of mine) {
    assert.deepEqual(Object.keys(l), ['ts', 'query_id', 'uri_hmac', 'uri_key', 'useful']);
    assert.equal(l['uri_key'], WORKSPACE_URI_KEY_ID);
  }

  const err = stderr.join('');
  assert.ok(!err.includes(CANARY), 'stderr');
  assert.deepEqual(scanTree(workRoot).hit, [], 'work root at the end');
});

test('item 7: a commit that fails after unsealing leaves no plain text in the work root; a retry unseals the same preview again', async () => {
  const root = join(safeMkdtemp(join(tmpdir(), 'zeusi-c2-fail-')), 'workspace-import');
  // A write session whose room check works and whose every later statement fails (a lost connection).
  // `importerCalls` counts statements after the room check: the importer only gets there once the
  // run was unsealed and read.
  let importerCalls = 0;
  const failing: Db = {
    label: 'failing',
    query: async (sql: string) => {
      if (/count\(\*\) FILTER/.test(sql)) return { rows: [{ n: 0, all: 0, b: 0 }] } as never;
      // C6 KTD3: the commit takes the importer lock before the room check (and releases it in finally).
      if (/pg_try_advisory_lock|pg_advisory_unlock/.test(sql)) return { rows: [{ ok: true }] } as never;
      importerCalls++;
      throw new Error(`connection lost while holding ${CANARY}`);
    },
    exec: async () => { throw new Error('connection lost'); },
    close: async () => {},
  };
  const store = new WorkspaceWrites({ workRoot: root, openWrite: () => Promise.resolve(failing), encState: async () => ({ status: 'active', encState: 'off' }) });
  try {
    const caller = { tenantId: `zt_${'c'.repeat(26)}`, grantId: 'grant-c', subject: null, requestId: null };
    const p = await store.preview(caller, [{ kind: 'markdown', title: `${CANARY} doc`, text: `Body ${CANARY}\n` }]);
    assert.equal(p.status, 'preview');
    assert.deepEqual(scanTree(root).hit, []);
    const id = (p as { preview_id: string }).preview_id;
    await assert.rejects(store.commit(caller, id));
    const first = importerCalls;
    assert.ok(first > 0, 'control: the importer ran on the unsealed run');
    const after = scanTree(root);
    assert.deepEqual(after.hit, [], 'the unsealed run was removed in finally');
    assert.equal(readdirSync(join(root, 'runs')).length, 1, 'only the sealed run is left');
    // Retry: the same preview id unseals again (key and sealed files kept after a failed commit).
    await assert.rejects(store.commit(caller, id));
    assert.ok(importerCalls > first, 'the retry reached the importer again');
    assert.deepEqual(scanTree(root).hit, []);
    assert.equal(readdirSync(join(root, 'runs')).length, 1);
  } finally {
    store.close();
  }
  assert.deepEqual(readdirSync(join(root, 'runs')), [], 'close() removes the sealed run');
});

test('C2 KTD5: neutral inbox names keep today\'s titles and path gates (the former name is the adapter\'s logical name, in memory)', async () => {
  const root = join(safeMkdtemp(join(tmpdir(), 'zeusi-c2-names-')), 'workspace-import');
  const store = new WorkspaceWrites({ workRoot: root, openWrite: () => Promise.reject(new Error('offline')), encState: async () => ({ status: 'active', encState: 'off' }) });
  const caller = { tenantId: `zt_${'d'.repeat(26)}`, grantId: 'grant-d', subject: null, requestId: null };
  try {
    // No frontmatter title: the title comes from the logical name, exactly as before (`001-<slug>`).
    const p = await store.preview(caller, [{ kind: 'markdown', title: 'Kestrel Plan', text: 'Plain body.\n' }, { kind: 'markdown', text: 'Second body.\n' }]);
    assert.equal(p.status, 'preview');
    assert.deepEqual((p as { items: Array<{ title: string }> }).items.map((x) => x.title).sort(), ['001-kestrel-plan', '002-note']);
    // A title the path wall refuses still gates the note (it is checked on the logical name).
    const walled = ['Plan', 'kiva'].join('');
    const g = await store.preview(caller, [{ kind: 'markdown', title: `${walled} notes`, text: 'An innocent body.\n' }]);
    assert.equal(g.status, 'nothing_to_import');
  } finally {
    store.close();
  }
});
