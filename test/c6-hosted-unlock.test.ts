// C6 KTD4 / U5 (docs/plans/2026-11-19-c6-write-path.md; parent plan §7 item 1, hosted): the session key of a
// workspace write comes ONLY from the request's own OAuth bearer opening its grant's C4 session wrap. The hosted
// handler on 127.0.0.1 (FAKE GitHub, PGlite, the real roles and writer login, test/helpers/hosted-tenants.ts).
// The grant is created by OAuthStore.createGrant with a `seal` (exactly what /token does after a C4 enroll),
// under a FIXED test DEK. No network, no Neon, no real workspace or key.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Db } from '../src/db.ts';
import { sealSessionWraps } from '../src/workspace-keys.ts';
import { WORKSPACE_LOCKED } from '../src/workspace-write.ts';
import { WorkspaceKey } from '../src/workspace-seal.ts';
import { callTool, dcrClient, mcpPost, serviceHome, signIn, startTenantHosted, toolJson, type TenantHarness } from './helpers/hosted-tenants.ts';
import { decisionEntry, setState, TEST_DEK } from './helpers/c6-fixture.ts';
import { asOwner, tenantTestDb } from './helpers/tenant-fixture.ts';

const CANARY = 'c6hostedcanarywallaby';

let db: Db;
let h: TenantHarness;
before(async () => {
  db = await tenantTestDb({ writer: true });
  h = await startTenantHosted({ db, home: serviceHome(), limits: { signupPerIp: 50, signupGlobal: 50 }, writer: 'on', wsLimits: { preview: 20, commit: 20, sync: 20 } });
});
after(async () => {
  await h.close();
  await db.close();
});

const call = (token: string, name: string, args: Record<string, unknown>) => mcpPost(h.port, token, callTool(name, args));
const tenantOfLogin = (login: string) => h.store.list().grants.filter((g) => g.login === login).at(-1)!.tenant;
const canaryRows = (t: string) => asOwner(db, async () => {
  let n = 0;
  for (const r of ['notes', 'chunks', 'facts', 'decisions', 'decision_links', 'quarantine', 'ingest_runs']) {
    n += (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}".${r} x WHERE strpos(lower(to_jsonb(x)::text), $1) > 0 OR strpos(to_jsonb(x)::text, $2) > 0`,
      [CANARY, Buffer.from(CANARY).toString('hex')])).rows[0]!.n;
  }
  return n;
});

test('item 1 (hosted): a grant with session wraps commits and syncs through /mcp; the owner scan finds no canary; a grant without wraps is refused (WORKSPACE_LOCKED)', async () => {
  // A personal sign-in (no wraps: the server's flag is off) gives the workspace and a grant without wraps.
  const plain = await signIn(h, 'gh-n41');
  const t = tenantOfLogin('newbie-41');
  assert.equal((await h.dir!.overlayStep(t, 'prepare', { dryRun: false })).outcome, 'applied');
  await setState(db, t, 'verified');
  // The same user's grant WITH session wraps of the workspace DEK (as /token makes them after enroll).
  const clientId = await dcrClient(h);
  const sealed = h.store.createGrant({
    clientId, subject: 'github:5041', login: 'newbie-41', tenant: t, workspaceWrite: true,
    seal: (grantId, access, refresh) => sealSessionWraps(t, grantId, access, refresh, TEST_DEK, 1),
  });
  const tok = sealed.accessToken;

  const p = toolJson(await call(tok, 'zeusi_import_preview', {
    documents: [
      { kind: 'markdown', title: `Plan ${CANARY}`, text: `# ${CANARY}\n\nbody ${CANARY}\n` },
      { kind: 'decision-log', format: 'markdown', text: decisionEntry(`decide ${CANARY}`, { links: [`vault:notes/${CANARY}.md`] }) },
    ],
  }));
  assert.equal(p.isError, false, p.text);
  const c = toolJson(await call(tok, 'zeusi_import_commit', { preview_id: String(p.json!['preview_id']), confirm: true }));
  assert.equal(c.isError, false, c.text);
  assert.equal((c.json!['notes'] as { inserted: number }).inserted, 2);
  assert.equal(c.json!['decisions'], 1);
  const s = toolJson(await call(tok, 'zeusi_sync_batch', {
    items: [{ path: `journal/2026-11-19-${CANARY}.md`, text: `---\nproject: journal\nkind: memory\ndate: 2026-11-19\ntitle: ${CANARY}\nsource: assistant\n---\n## day\n\nsync ${CANARY}\n` }], deleted: [],
  }));
  assert.equal(s.isError, false, s.text);
  assert.equal((s.json!['counts'] as { inserted: number }).inserted, 1);

  // As the owner: every row is sealed and the canary is nowhere (text or hex).
  assert.equal(await canaryRows(t), 0);
  const kv = await asOwner(db, async () => (await db.query<{ kv: number | null; n: number }>(`SELECT key_version AS kv, count(*)::int AS n FROM "${t}".notes GROUP BY 1`)).rows);
  assert.deepEqual(kv, [{ kv: 1, n: 3 }]);
  // And the rows open with the workspace DEK (the one inside the session wrap).
  const k = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  try {
    const titles = await asOwner(db, async () => (await db.query<{ id: number; ct: Uint8Array }>(`SELECT id::int AS id, title_ct AS ct FROM "${t}".notes ORDER BY id`)).rows);
    assert.ok(titles.map((x) => k.open('notes', 'title', x.id, x.ct)).some((x) => x.includes(CANARY)));
  } finally {
    k.dispose();
  }

  // The same workspace through the grant WITHOUT wraps: refused, nothing written.
  const n0 = await asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}".notes`)).rows[0]!.n);
  const r = toolJson(await call(plain.access, 'zeusi_sync_batch', { items: [{ path: 'journal/2026-11-19-locked.md', text: '---\nproject: journal\nkind: memory\ndate: 2026-11-19\ntitle: L\nsource: assistant\n---\nlocked\n' }], deleted: [] }));
  assert.equal(r.isError, true);
  assert.equal(r.text, WORKSPACE_LOCKED);
  assert.equal(await asOwner(db, async () => (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}".notes`)).rows[0]!.n), n0);
});
