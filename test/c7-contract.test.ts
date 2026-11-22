// C7 Preconditions 2 (docs/plans/2026-11-19-c7-read-path.md, "Contract check against merged C6"): every fact of the
// merged C5 + C6 code (635ca8f) that the C7 read path relies on, asserted here and kept. If one goes red, C6 changed
// shape: amend the C7 plan (and its "Deltas vs merged C6" section) before touching the read path.
// PGlite with the real migrations, tenant logins and writer login; a FIXED test DEK. No network, no real key.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { b1IndexHook } from '../src/b1-index.ts';
import { deltaShardAad, INDEX_HMAC_PURPOSES, mainShardAad, manifestAad } from '../src/crypto-envelope.ts';
import { importerLockKey } from '../src/ingest-run.ts';
import { listMigrations } from '../src/migrate.ts';
import { OAuthServer } from '../src/mcp-oauth.ts';
import { ENC_PROGRESS_TABLE } from '../src/tenant-ddl.ts';
import { offPathAllowed, OVERLAY_SPEC } from '../src/tenant-overlay.ts';
import { ENC_STATES, TenantError } from '../src/tenants.ts';
import { openSessionDek } from '../src/workspace-keys.ts';
import { openedRow, sealRow, WorkspaceKey } from '../src/workspace-seal.ts';
import { workspaceIndexLockKey, type IndexHook } from '../src/write-route.ts';
import { c6Fixture, callerOf, commitDocs, decisionEntry, decisionLog, holdsAdvisory, newWorkspace, rowsOf, TEST_DEK, type C6Fixture } from './helpers/c6-fixture.ts';
import { asOwner } from './helpers/tenant-fixture.ts';
import { assertSecretEqual } from './redact.ts';

let f: C6Fixture;
const lockSeen: boolean[] = [];
before(async () => {
  // The REAL hook (src/b1-index.ts), wrapped to observe the index lock from inside beforeCommit.
  f = await c6Fixture({
    indexHook: (key) => {
      const h: IndexHook = b1IndexHook(key);
      return {
        ...h,
        beforeCommit: async (tx) => {
          const schema = (await tx.query<{ s: string }>(`SELECT 'zeusi'::text AS s`)).rows[0]!.s;
          lockSeen.push(await holdsAdvisory(tx, workspaceIndexLockKey(schema)));
          await h.beforeCommit!(tx);
        },
      };
    },
  });
});
after(async () => {
  await f.close();
});

const hex = (v: unknown) => Buffer.from(v as Uint8Array).toString('hex');
const keyFor = (t: string) => {
  const k = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  k.startCounter(0);
  return k;
};

test('C7 contract (a): offPathAllowed is true for exactly off and enrolled (C5 KTD12)', () => {
  assert.deepEqual(ENC_STATES.filter((s) => offPathAllowed(s)), ['off', 'enrolled']);
});

test('C7 contract (b): TenantRouter.encState returns { status, encState } as the runtime login and fails closed (C6 KTD2)', async () => {
  const t = await newWorkspace(f, 'on');
  assert.deepEqual(await f.router.encState(t), { status: 'active', encState: 'on' });
  for (const bad of ['zt_aaaaaaaaaaaaaaaaaaaaaaaaaa', 'work', 'not-an-id']) {
    await assert.rejects(f.router.encState(bad), (e: Error) => e instanceof TenantError, bad);
  }
});

test('C7 contract (c): openedRow opens every column sealRow writes, under (table, plain column, row id as decimal, key_version); frontmatter JSON text, applies_to JSON array', () => {
  const t = 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa';
  const key = keyFor(t);
  const values: Record<string, Record<string, string | null>> = {
    notes: { title: 'T', body: 'B', frontmatter: JSON.stringify({ locks: ['x'] }), vault_path: 'hq:p/a.md', source_uri: 'hq:p/a.md' },
    chunks: { heading_path: null, text: 'chunk', source_uri: 'hq:p/a.md#c0' },
    facts: { subject: 's', text: 'fact', source_uri: 'u' },
    decisions: { exact_words: 'w', applies_to: JSON.stringify(['a', 'b']), expires_rule: null, linked_repo: 'org/repo', linked_job: null, source_uri: 'u' },
    decision_links: { target_uri: 'gh:o/r#1', source_uri: 'u' },
  };
  for (const spec of OVERLAY_SPEC) {
    const row: Record<string, unknown> = { id: 42 };
    for (const [c, v] of sealRow(key, spec.table, 42, values[spec.table]!)) row[c] = v;
    const cols = spec.columns.map((c) => c.plain);
    const o = openedRow(key, spec.table, row, cols);
    for (const c of cols) {
      const v = values[spec.table]![c];
      const want = c === 'frontmatter' || c === 'applies_to' ? (v === null ? null : JSON.parse(v!)) : v;
      assert.deepEqual(o[c], want, `${spec.table}.${c}`);
    }
    // The AAD binds the row id: the same ciphertexts under another id do not open.
    assert.throws(() => openedRow(key, spec.table, { ...row, id: 43 }, cols));
  }
  key.dispose();
});

test('C7 contract (d): C6 stores indexHmac(uri) of the fragment-free note uri, of each chunk\'s own uri and of each link target; (e) the real hook runs inside the sealed transaction with the index lock held', async () => {
  const t = await newWorkspace(f, 'on');
  const c = callerOf(t);
  await commitDocs(f, c, [{ kind: 'markdown', title: 'Contract note', text: '# Contract\n\nbody text.\n' }]);
  await commitDocs(f, c, [decisionLog(decisionEntry('contract decision words', { links: ['gh:Synthetic-Org/zz#3', 'hq:alpha/2026-10-15-kx.md'] }))]);
  const key = keyFor(t);
  const notes = await rowsOf<Record<string, unknown>>(f.db, t, 'notes', 'id, key_version, title_ct, source_uri_ct, source_uri_hmac, vault_path_ct, vault_path_hmac, frontmatter_ct, title, source_uri, vault_path, frontmatter');
  assert.ok(notes.length >= 2);
  for (const n of notes) {
    const o = openedRow(key, 'notes', n, ['source_uri', 'vault_path']);
    assertSecretEqual(hex(n['source_uri_hmac']), key.indexHmac('uri', String(o['source_uri'])).toString('hex'));
    assertSecretEqual(hex(n['vault_path_hmac']), key.indexHmac('vault_path', String(o['vault_path'])).toString('hex'));
  }
  for (const ch of await rowsOf<Record<string, unknown>>(f.db, t, 'chunks', 'id, key_version, source_uri_ct, source_uri_hmac, source_uri')) {
    const u = String(openedRow(key, 'chunks', ch, ['source_uri'])['source_uri']);
    assert.match(u, /#c\d+$/, 'a chunk stores its own uri (<note uri>#c<n>)');
    assertSecretEqual(hex(ch['source_uri_hmac']), key.indexHmac('uri', u).toString('hex'));
  }
  const links = await rowsOf<Record<string, unknown>>(f.db, t, 'decision_links', 'id, key_version, target_uri_ct, target_uri_hmac, target_uri');
  assert.equal(links.length, 2);
  for (const l of links) assertSecretEqual(hex(l['target_uri_hmac']), key.indexHmac('uri', String(openedRow(key, 'decision_links', l, ['target_uri'])['target_uri'])).toString('hex'));
  key.dispose();
  assert.ok(lockSeen.length >= 3 && lockSeen.every(Boolean), 'every sealed write transaction ran beforeCommit with workspace-index:<id> held');
  assert.equal(workspaceIndexLockKey(t), importerLockKey(`workspace-index:${t}`), 'the lock key C6 takes (C6 KTD10)');
});

test('C7 contract (f): facts_current / decisions_current keep their 0001 definitions: no key_version, _ct or _hmac column in the views of a born-on workspace', async () => {
  const t = await newWorkspace(f, 'on');
  const cols = await asOwner(f.db, async () => (await f.db.query<{ table_name: string; column_name: string }>(
    `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name IN ('facts_current', 'decisions_current')`, [t])).rows);
  assert.ok(cols.length > 10);
  assert.deepEqual(cols.filter((c) => /^key_version$|_ct$|_hmac$/.test(c.column_name)), [], 'the views do not carry the sealed columns: C7 reads _ct from the base tables');
  assert.ok(cols.some((c) => c.table_name === 'decisions_current' && c.column_name === 'exact_words'));
});

test('C7 contract (g): the session unlock names, C1 index AADs, the b1-cache-check purpose and the enc_progress shape C7 builds on', async () => {
  assert.equal(typeof OAuthServer.prototype.sessionKeyFor, 'function', 'C6 U5: OAuthServer.sessionKeyFor(accessToken)');
  assert.equal(typeof openSessionDek, 'function', 'C4: openSessionDek(store, accessToken)');
  assert.ok((INDEX_HMAC_PURPOSES as readonly string[]).includes('uri') && (INDEX_HMAC_PURPOSES as readonly string[]).includes('b1-cache-check'));
  const t = 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa';
  // C1's index AAD binds (tenant, kind tag, object number, key_version): three distinct labels.
  const a = [mainShardAad(t, 3, 1), deltaShardAad(t, 3, 1), manifestAad(t, 1), mainShardAad(t, 4, 1), mainShardAad(t, 3, 2)].map((b) => b.toString('hex'));
  assert.equal(new Set(a).size, a.length);
  const w = await newWorkspace(f, 'on');
  const chk = await asOwner(f.db, async () => (await f.db.query<{ def: string }>(
    `SELECT pg_get_constraintdef(k.oid) AS def FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND c.relname = $2 AND k.contype = 'c' AND pg_get_constraintdef(k.oid) LIKE '%table_name%'`, [w, ENC_PROGRESS_TABLE])).rows);
  assert.equal(chk.length, 1);
  for (const tb of ['all', 'notes', 'chunks', 'facts', 'decisions', 'decision_links']) assert.ok(chk[0]!.def.includes(`'${tb}'`), tb);
  assert.ok(!chk[0]!.def.includes('b1_index'), 'C5 accepts only the five tables: index seals are counted under notes (open decision 3)');
});

test('C7 KTD6: an index object opens only under its own (workspace, kind, object number, key_version); mutant: AAD without the object number -> red', () => {
  const k = keyFor('zt_aaaaaaaaaaaaaaaaaaaaaaaaaa');
  const blob = k.sealIndex({ kind: 'base', no: 3 }, Buffer.from('plain index bytes'));
  assert.equal(k.openIndex({ kind: 'base', no: 3 }, blob).toString(), 'plain index bytes');
  for (const other of [{ kind: 'base' as const, no: 4 }, { kind: 'segment' as const, no: 3 }, { kind: 'manifest' as const }]) assert.throws(() => k.openIndex(other, blob), JSON.stringify(other));
  const k2 = keyFor('zt_bbbbbbbbbbbbbbbbbbbbbbbbbb');
  assert.throws(() => k2.openIndex({ kind: 'base', no: 3 }, blob), 'another workspace');
  const kv2 = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 2 }, 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.throws(() => kv2.openIndex({ kind: 'base', no: 3 }, blob), 'another key_version');
  assert.deepEqual(k.takePending(), [['notes', 1]], 'an index seal counts under notes (open decision 3)');
  for (const x of [k, k2, kv2]) x.dispose();
});

test('C7 contract (h): migrate checksums the WHOLE file (src/migrate.ts:37-38, :84-85), so the applied 0016 is byte-pinned (its header is NOT edited)', () => {
  const f16 = listMigrations().find((m) => m.name === '0016_catalog_rt_enc_state.sql')!;
  assert.equal(f16.sha256, createHash('sha256').update(readFileSync('migrations/0016_catalog_rt_enc_state.sql', 'utf8')).digest('hex'));
  // Public-tree pin of this file (fresh history; not a production checksum). Any later edit must update this pin.
  assert.equal(f16.sha256, '4cec7369e0391695b66a31da25f030b154cbb0e90b4d301f80ca6c043595d11d');
});
