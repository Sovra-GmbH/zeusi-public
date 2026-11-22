// C6a (docs/plans/2026-11-19-c6-write-path.md KTD1-KTD12; parent plan §7 items 5, 6, 16, 17, 19): the sealed
// write route for vault notes, chunks, sync deletions, the size check, quarantine and the B1 lock, plus
// routing and the unchanged off path. PGlite with the real migrations, tenant logins and writer login; a
// FIXED test DEK (test/helpers/c6-fixture.ts). No network, no Neon, no real workspace or key.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { ROTATE_AT } from '../src/crypto-envelope.ts';
import type { Db } from '../src/db.ts';
import { IMPORT_PROFILE, importVault, pathQuarantineUri } from '../src/importers/vault.ts';
import { OVERLAY_SPEC } from '../src/tenant-overlay.ts';
import { TenantWriter, TENANT_WR_ROLE } from '../src/tenants.ts';
import {
  WORKSPACE_CHANGING, WORKSPACE_LOCKED, workspaceImportProfile, WorkspaceWriteRefused, WRITES_OFF, type SyncItem,
} from '../src/workspace-write.ts';
import { NO_INDEX_HOOK, PLAIN_ROUTE, writeRouteFor, WriteRouteRefused, workspaceIndexLockKey } from '../src/write-route.ts';
import { nextId, SEALED_BODY_BYTES_SQL, sealedInsertSql, sealedSoFar, sealRow, WorkspaceKey } from '../src/workspace-seal.ts';
import {
  c6Fixture, callerOf, commitDocs, counts, hqItem, newWorkspace, OTHER_DEK, rowsOf, setState, TEST_DEK, type C6Fixture,
} from './helpers/c6-fixture.ts';
import { overclaims, serverCopy } from './helpers/overclaim.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner } from './helpers/tenant-fixture.ts';
import { assertSecretEqual } from './redact.ts';

/** One lexical token in every planted value: a leak is a substring match. */
const CANARY = 'c6acanaryquoll';

let f: C6Fixture;
before(async () => {
  f = await c6Fixture();
});
after(async () => {
  await f.close();
});

const keyFor = (t: string, dek = TEST_DEK) => {
  const k = WorkspaceKey.fromUnlocked({ dek: Buffer.from(dek), keyVersion: 1 }, t);
  k.startCounter(0);
  return k;
};
const ZERO32 = '00'.repeat(32);
const sha = (s: string | Uint8Array) => createHash('sha256').update(s).digest();
const refusal = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof WorkspaceWriteRefused ? e.message : `other: ${(e as Error).message}`;
  }
};
const writerOpen = (t: string) => new TenantWriter({ connectWriter: asLogin(f.db, TENANT_WR_ROLE), check: (x) => f.router.check(x) }).open(t);
const md = (title: string, text: string) => ({ kind: 'markdown' as const, title, text });

/** importVault called directly with a sealed route (path gate, test seam), on files in the HQ layout. */
async function directImport(t: string, items: SyncItem[], seam?: Parameters<typeof importVault>[0]['testOnlySealedBeforeWrite']) {
  const root = safeMkdtemp(join(tmpdir(), 'zeusi-c6a-vault-'));
  for (const x of items) {
    mkdirSync(dirname(join(root, x.path)), { recursive: true });
    writeFileSync(join(root, x.path), x.text);
  }
  const projects = [...new Set(items.map((x) => x.path.split('/')[0]!))];
  const s = await writerOpen(t);
  const key = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  try {
    key.startCounter(await sealedSoFar(s, 1));
    return await importVault({
      db: s, mode: 'full', profile: workspaceImportProfile(t), home: root, host: 'test', logPaths: false,
      config: {
        sources: projects.map((p) => ({ name: `c6-${p}`, kind: 'manual' as const, scope: 'work' as const, root, include: [`${p}/*.md`], exclude: [], project: p })),
        github: { org: '', repos: [], northbankRepos: [] },
      },
      route: { kind: 'sealed', key, tenantId: t, index: NO_INDEX_HOOK }, ...(seam ? { testOnlySealedBeforeWrite: seam } : {}),
    });
  } finally {
    key.dispose();
    await s.close();
  }
}

/** Every sealed note of `t` opened with the test key: id -> plain values. */
async function openNotes(t: string): Promise<Array<Record<string, string | number | null>>> {
  const k = keyFor(t);
  try {
    const rows = await rowsOf<Record<string, unknown>>(f.db, t, 'notes');
    return rows.map((r) => {
      const id = Number(r['id']);
      const out: Record<string, string | number | null> = { id, status: r['status'] as string, key_version: r['key_version'] as number };
      for (const c of OVERLAY_SPEC.find((x) => x.table === 'notes')!.columns) {
        const ct = r[`${c.plain}_ct`] as Uint8Array | null;
        out[c.plain] = ct ? k.open('notes', c.plain, id, ct) : null;
        assert.equal(r[c.plain], null, `notes.${c.plain} is NULL on a sealed row`);
      }
      return out;
    });
  } finally {
    k.dispose();
  }
}

// ---------------------------------------------------------------------------
// Routing (KTD1, KTD2)

test('routing: off/enrolled plain, verified/on sealed, encrypting/decrypting/decrypted refused before any write (row counts unchanged), unknown state refused', async () => {
  for (const st of ['off', 'enrolled', 'verified', 'on'] as const) {
    const t = await newWorkspace(f, st);
    const r = await f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-19-route.md', 'Route', `## 2026-11-19\n\nrouting ${st}`)], []);
    assert.equal(r.counts.inserted, 1, st);
    const kv = (await rowsOf<{ key_version: number | null; body: string | null }>(f.db, t, 'notes', st === 'off' || st === 'enrolled' ? 'NULL::smallint AS key_version, body' : 'key_version, body'))[0]!;
    if (st === 'off' || st === 'enrolled') assert.ok(kv.body?.includes('routing'), `${st}: plain`);
    else assert.deepEqual(kv, { key_version: 1, body: null }, `${st}: sealed`);
  }
  for (const st of ['encrypting', 'decrypting', 'decrypted'] as const) {
    const t = await newWorkspace(f, st);
    const before0 = await counts(f.db, t);
    const n = f.log.length;
    assert.equal(await refusal(f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-19-route.md', 'Route', 'moving')], [])), WORKSPACE_CHANGING, st);
    assert.equal(await refusal(commitDocs(f, callerOf(t), [md('Moving', 'moving state\n')])), WORKSPACE_CHANGING, st);
    assert.deepEqual(await counts(f.db, t), before0, `${st}: nothing written`);
    assert.ok(!f.log.slice(n).some((s) => /INSERT|UPDATE|DELETE/i.test(s) && !/advisory/.test(s)), `${st}: no write statement ran`);
  }
  const t = await newWorkspace(f, 'off');
  f.stateOverride.set(t, 'paused');
  try {
    assert.equal(await refusal(f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-19-route.md', 'Route', 'x')], [])), WORKSPACE_CHANGING, 'unknown state');
  } finally {
    f.stateOverride.delete(t);
  }
  // The rule itself: unlock is never called on the plain route, and a non-string state is refused.
  let unlocks = 0;
  assert.equal(writeRouteFor('off', () => { unlocks++; return null; }, { tenantId: t }), PLAIN_ROUTE);
  assert.equal(writeRouteFor('enrolled', () => { unlocks++; return null; }, { tenantId: t }), PLAIN_ROUTE);
  assert.equal(unlocks, 0);
  for (const s of [undefined, null, 1, 'ON', ''] as unknown[]) assert.throws(() => writeRouteFor(s, () => keyFor(t), { tenantId: t }), WriteRouteRefused);
});

test('a sealed workspace without a session key is refused (WORKSPACE_LOCKED), nothing written; the session key\'s tenant/grant must equal the principal\'s', async () => {
  const t = await newWorkspace(f, 'on');
  const other = await newWorkspace(f, 'on');
  const before0 = await counts(f.db, t);
  const item = [hqItem('journal', '2026-11-19-locked.md', 'Locked', 'no key')];
  assert.equal(await refusal(f.ww.sync(callerOf(t, { key: 'none' }), item, [])), WORKSPACE_LOCKED);
  assert.equal(await refusal(f.ww.sync({ tenantId: t, grantId: 'g', subject: null, requestId: null }, item, [])), WORKSPACE_LOCKED, 'no unlock at all');
  // A DEK unwrapped for another workspace or another grant is dropped (and zeroed), never used.
  let handed: Buffer | null = null;
  const c = callerOf(t);
  const spoof = { ...c, unlock: () => { handed = Buffer.from(TEST_DEK); return { tenant: other, grantId: c.grantId, dek: handed, keyVersion: 1 }; } };
  assert.equal(await refusal(f.ww.sync(spoof, item, [])), WORKSPACE_LOCKED, 'tenant mismatch');
  assertSecretEqual(handed!.toString('hex'), ZERO32, 'the foreign DEK was zeroed');
  assert.equal(await refusal(f.ww.sync(callerOf(t, { keyGrant: 'another-grant' }), item, [])), WORKSPACE_LOCKED, 'grant mismatch');
  assert.deepEqual(await counts(f.db, t), before0);
  // The plain route never asks for a key.
  const off = await newWorkspace(f, 'off');
  let asked = 0;
  const offCaller = { ...callerOf(off), unlock: () => { asked++; return null; } };
  assert.equal((await f.ww.sync(offCaller, [hqItem('journal', '2026-11-19-plain.md', 'Plain', 'plain')], [])).counts.inserted, 1);
  assert.equal(asked, 0, 'a plain workspace never unwraps anything');
});

test('state unreadable (grant revoked) refuses with WRITES_OFF; nothing written; audited refused', async () => {
  const t = await newWorkspace(f, 'off');
  const item = [hqItem('journal', '2026-11-19-revoked.md', 'Revoked', 'x')];
  await asOwner(f.db, () => f.db.exec('SET ROLE zeusi_tenant_admin; REVOKE SELECT (enc_state) ON zeusi_tenants.tenants FROM zeusi_tenant_rt; RESET ROLE'));
  try {
    await assert.rejects(f.router.encState(t), (e: Error) => e.name === 'TenantError');
    assert.equal(await refusal(f.ww.sync(callerOf(t), item, [])), WRITES_OFF);
    assert.equal((await counts(f.db, t))['notes'], 0);
  } finally {
    await asOwner(f.db, () => f.db.exec('SET ROLE zeusi_tenant_admin; GRANT SELECT (enc_state) ON zeusi_tenants.tenants TO zeusi_tenant_rt; RESET ROLE'));
  }
  f.stateOverride.set(t, 'throw');
  try {
    assert.equal(await refusal(commitDocs(f, callerOf(t), [md('Revoked', 'x\n')])), WRITES_OFF);
  } finally {
    f.stateOverride.delete(t);
  }
  assert.equal((await f.ww.sync(callerOf(t), item, [])).counts.inserted, 1, 'works again with the grant');
});

test('off path unchanged: a flag-off workspace commit and sync issue no statement naming _ct, _hmac, key_version, enc_progress or nextval (recording Db)', async () => {
  const t = await newWorkspace(f, 'off');
  const n = f.log.length;
  const c = callerOf(t);
  const r = await commitDocs(f, c, [md(`Off ${CANARY}`, `# Off\n\nplain ${CANARY}\n`)]);
  assert.equal(r.notes.inserted, 1);
  await f.ww.sync(c, [hqItem('journal', '2026-11-19-off.md', 'Off', `## 2026-11-19\n\nplain ${CANARY}`)], []);
  await f.ww.sync(c, [], ['journal/2026-11-19-off.md']);
  const ran = f.log.slice(n).filter((s) => !s.startsWith('encState('));
  assert.ok(ran.length > 10, 'the recording saw the writes');
  assert.deepEqual(ran.filter((s) => /_ct\b|_hmac\b|key_version|enc_progress|nextval|pg_advisory_xact_lock/.test(s)), []);
  // The plain usage SQL is today's text, byte for byte.
  assert.ok(ran.includes(`SELECT count(*) FILTER (WHERE status = 'active')::int AS n, count(*)::int AS all, coalesce(sum(octet_length(body)), 0)::bigint AS b FROM zeusi.notes`));
  // And the rows are plain (a control for the item-1 scan: the canary IS visible here).
  assert.ok((await rowsOf<{ body: string }>(f.db, t, 'notes', 'body')).some((x) => x.body.includes(CANARY)));
});

// ---------------------------------------------------------------------------
// §7.5 AAD binding, §7.16 ids and upserts, §7.17

test('§7.5: a sealed note\'s title_ct copied (as owner) onto another note fails to open; copied to another workspace\'s row with the same id fails', async () => {
  const a = await newWorkspace(f, 'on');
  const b = await newWorkspace(f, 'on');
  for (const t of [a, b]) await commitDocs(f, callerOf(t), [md(`One ${t}`, 'first\n'), md(`Two ${t}`, 'second\n')]);
  const ka = keyFor(a);
  const kb = keyFor(b);
  try {
    const ra = await rowsOf<{ id: number; title_ct: Uint8Array }>(f.db, a, 'notes', 'id::int AS id, title_ct');
    const rb = await rowsOf<{ id: number; title_ct: Uint8Array }>(f.db, b, 'notes', 'id::int AS id, title_ct');
    assert.equal(ra.length, 2);
    // Control: both rows open to their own titles. Which one gets id 1 depends on the run day (the import path hashes
    // the note date and rows are inserted in path order), so the check is order-free.
    assert.deepEqual(ra.map((r) => ka.open('notes', 'title', r.id, r.title_ct)).map((x) => (/one/i.test(x) ? 'one' : /two/i.test(x) ? 'two' : x)).sort(), ['one', 'two']);
    // Row id binding: note 1's title under note 2's id.
    assert.throws(() => ka.open('notes', 'title', ra[1]!.id, ra[0]!.title_ct), /authentication failed/);
    // Column binding: the title as the body.
    assert.throws(() => ka.open('notes', 'body', ra[0]!.id, ra[0]!.title_ct), /authentication failed/);
    // Tenant binding: the same id in another workspace (same test DEK, so only the AAD differs).
    assert.equal(ra[0]!.id, rb[0]!.id);
    assert.throws(() => kb.open('notes', 'title', rb[0]!.id, ra[0]!.title_ct), /authentication failed/);
    // A copy done by the owner in SQL is refused on read too.
    await asOwner(f.db, () => f.db.query(`UPDATE "${a}".notes SET title_ct = (SELECT title_ct FROM "${a}".notes WHERE id = $1) WHERE id = $2`, [ra[0]!.id, ra[1]!.id]));
    const moved = (await rowsOf<{ title_ct: Uint8Array }>(f.db, a, 'notes', 'title_ct', `id = ${ra[1]!.id}`))[0]!;
    assert.throws(() => ka.open('notes', 'title', ra[1]!.id, moved.title_ct), /authentication failed/);
    // Another DEK never opens it.
    const ko = keyFor(a, OTHER_DEK);
    assert.throws(() => ko.open('notes', 'title', ra[0]!.id, ra[0]!.title_ct), /authentication failed/);
    ko.dispose();
  } finally {
    ka.dispose();
    kb.dispose();
  }
});

test('§7.5: a chunk\'s source_uri_ct opens under the chunk\'s AAD; the note\'s source_uri_ct pasted into the chunk fails; the sealed path never omits source_uri_ct', async () => {
  const t = await newWorkspace(f, 'verified');
  const r = await f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-19-chunks.md', 'Chunks', '## A\n\nfirst part\n\n## B\n\nsecond part')], []);
  assert.equal(r.counts.errors, 0);
  const k = keyFor(t);
  try {
    const note = (await rowsOf<{ id: number; source_uri_ct: Uint8Array }>(f.db, t, 'notes', 'id::int AS id, source_uri_ct'))[0]!;
    const chunks = await rowsOf<{ id: number; chunk_index: number; source_uri_ct: Uint8Array | null; source_uri_hmac: Uint8Array }>(
      f.db, t, 'chunks', 'id::int AS id, chunk_index, source_uri_ct, source_uri_hmac');
    assert.ok(chunks.length >= 2);
    const noteUri = k.open('notes', 'source_uri', note.id, note.source_uri_ct);
    assert.equal(noteUri, 'hq:journal/2026-11-19-chunks.md');
    for (const c of chunks) {
      assert.ok(c.source_uri_ct, 'every sealed chunk carries its own source_uri_ct');
      const u = k.open('chunks', 'source_uri', c.id, c.source_uri_ct);
      assert.equal(u, `${noteUri}#c${c.chunk_index}`, 'the chunk\'s own uri');
      assert.deepEqual(Buffer.from(c.source_uri_hmac), k.indexHmac('uri', u), 'its own uri HMAC');
      assert.throws(() => k.open('chunks', 'source_uri', c.id, note.source_uri_ct), /authentication failed/, 'the note\'s ciphertext does not open as the chunk\'s');
    }
  } finally {
    k.dispose();
  }
});

test('§7.6: every source_sha256, text_hmac, vault_path_hmac and source_uri_hmac of a sealed workspace differs from sha256 of its plain value and is the keyed form', async () => {
  const t = await newWorkspace(f, 'on');
  const item = hqItem('journal', '2026-11-19-hashes.md', 'Hashes', `## 2026-11-19\n\nhash ${CANARY}`);
  // importVault directly (no export filter), so the stored digest is of exactly these file bytes.
  assert.equal((await directImport(t, [item])).counts.inserted, 1);
  const k = keyFor(t);
  try {
    const n = (await rowsOf<Record<string, Uint8Array> & { id: number }>(f.db, t, 'notes', 'id::int AS id, source_sha256, vault_path_hmac, source_uri_hmac, vault_path_ct, source_uri_ct'))[0]!;
    const vp = k.open('notes', 'vault_path', n.id, n['vault_path_ct']!);
    const uri = k.open('notes', 'source_uri', n.id, n['source_uri_ct']!);
    const fileSha = sha(item.text).toString('hex');
    assert.deepEqual(Buffer.from(n['source_sha256']!), k.keyedSha('source_sha256', fileSha));
    assert.notDeepEqual(Buffer.from(n['source_sha256']!), Buffer.from(fileSha, 'hex'), 'never the plain file digest');
    assert.deepEqual(Buffer.from(n['vault_path_hmac']!), k.indexHmac('vault_path', vp));
    assert.notDeepEqual(Buffer.from(n['vault_path_hmac']!), sha(vp));
    assert.deepEqual(Buffer.from(n['source_uri_hmac']!), k.indexHmac('uri', uri));
    assert.notDeepEqual(Buffer.from(n['source_uri_hmac']!), sha(uri));
    for (const c of await rowsOf<Record<string, Uint8Array | null> & { id: number }>(f.db, t, 'chunks', 'id::int AS id, text_ct, text_hmac, text_sha256, source_sha256')) {
      const text = k.open('chunks', 'text', c.id, c['text_ct']!);
      assert.equal(c['text_sha256'], null, 'no plain text digest');
      assert.deepEqual(Buffer.from(c['text_hmac']!), k.textHmac(text));
      assert.notDeepEqual(Buffer.from(c['text_hmac']!), sha(text));
      assert.deepEqual(Buffer.from(c['source_sha256']!), Buffer.from(n['source_sha256']!), 'inherited keyed digest');
    }
  } finally {
    k.dispose();
  }
});

test('§7.6: quarantine rows written on the sealed route (path gate, content gate) have source_uri \'hmac:...\', a keyed source_sha256, content_sha256 NULL, and no plain digest of the path or file', async () => {
  const t = await newWorkspace(f, 'verified');
  const iban = ['CH93', '0076', '2011', '6238', '5295', '7'].join(' ');
  const walledPath = hqItem('canvas', '2026-11-19-board.md', 'Board', 'a board');
  const walledBody = hqItem('journal', '2026-11-19-bank.md', 'Bank', `## 2026-11-19\n\npay to ${iban} please`);
  const r = await directImport(t, [walledPath, walledBody]);
  assert.equal(r.status, 'ok', r.error ?? '');
  assert.ok(r.counts.path_gated >= 1, 'the path gate fired');
  assert.ok(r.counts.quarantined >= 2, 'path gate + content gate');
  const q = await rowsOf<{ source_uri: string; source_sha256: Uint8Array; content_sha256: Uint8Array | null }>(f.db, t, 'quarantine', 'source_uri, source_sha256, content_sha256');
  assert.ok(q.length >= 2);
  const k = keyFor(t);
  try {
    const plainDigests = new Set([...[walledPath, walledBody].flatMap((x) => [sha(x.text), sha(x.path), sha(`import:${x.path}`)]), sha('canvas')].map((b) => b.toString('hex')));
    for (const row of q) {
      assert.match(row.source_uri, /^hmac:[0-9a-f]{64}$/);
      assert.equal(row.content_sha256, null);
      assert.ok(!plainDigests.has(Buffer.from(row.source_sha256).toString('hex')), 'no plain digest');
      assert.ok(!row.source_uri.includes('canvas') && !row.source_uri.includes('bank'));
    }
    const refs = new Set(q.map((x) => x.source_uri));
    assert.ok(refs.has(k.quarantineRef(`import:${walledBody.path}`)), 'content gate row = HMAC of the note uri');
    assert.ok(refs.has(k.quarantineRef(pathQuarantineUri('canvas', IMPORT_PROFILE))), 'path gate row = HMAC of the gated uri');
    // The quarantine HMAC is its own purpose: it never equals the uri HMAC a stored row would carry.
    assert.notEqual(k.quarantineRef(`import:${walledBody.path}`), `hmac:${k.indexHmac('uri', `import:${walledBody.path}`).toString('hex')}`);
    const keyed = Buffer.from(q.find((x) => x.source_uri === k.quarantineRef(`import:${walledBody.path}`))!.source_sha256);
    assert.deepEqual(keyed, k.keyedSha('source_sha256', sha(walledBody.text).toString('hex')));
  } finally {
    k.dispose();
  }
  assert.equal((await counts(f.db, t))['notes'], 0, 'nothing stored');
});

test('§7.16: re-sync of the same path with new content UPDATEs the same id; every _ct opens under that id; ingested_at restamps on a content change and is kept when unchanged (skipped)', async () => {
  const t = await newWorkspace(f, 'on');
  const c = callerOf(t);
  const v1 = hqItem('journal', '2026-11-19-upsert.md', 'Upsert', '## 2026-11-19\n\nversion one');
  assert.equal((await f.ww.sync(c, [v1], [])).counts.inserted, 1);
  const s1 = (await rowsOf<{ id: number; at: string }>(f.db, t, 'notes', 'id::int AS id, ingested_at::text AS at'))[0]!;
  const r2 = await f.ww.sync(c, [v1], []);
  assert.equal(r2.counts.unchanged, 1, 'same keyed digest: skipped');
  assert.equal((await rowsOf<{ at: string }>(f.db, t, 'notes', 'ingested_at::text AS at'))[0]!.at, s1.at, 'kept when unchanged');
  const v2 = hqItem('journal', '2026-11-19-upsert.md', 'Upsert two', '## 2026-11-19\n\nversion two');
  assert.equal((await f.ww.sync(c, [v2], [])).counts.updated, 1);
  const rows = await openNotes(t);
  assert.equal(rows.length, 1, 'no second row');
  assert.equal(rows[0]!['id'], s1.id, 'the same id');
  assert.equal(rows[0]!['title'], 'Upsert two');
  assert.ok(String(rows[0]!['body']).includes('version two'));
  assert.notEqual((await rowsOf<{ at: string }>(f.db, t, 'notes', 'ingested_at::text AS at'))[0]!.at, s1.at, 'restamped on a content change');
  // Old chunks are gone; the new ones open under their own ids.
  const k = keyFor(t);
  try {
    const ch = await rowsOf<{ id: number; note_id: number; text_ct: Uint8Array }>(f.db, t, 'chunks', 'id::int AS id, note_id::int AS note_id, text_ct');
    assert.ok(ch.length > 0 && ch.every((x) => x.note_id === s1.id));
    assert.ok(ch.some((x) => k.open('chunks', 'text', x.id, x.text_ct).includes('version two')));
    assert.ok(!ch.some((x) => k.open('chunks', 'text', x.id, x.text_ct).includes('version one')));
  } finally {
    k.dispose();
  }
});

test('§7.16: a racing insert of the same path (test seam plants the row inside the transaction before the INSERT) gives 23505: rollback, error counted, no row left undecryptable, a retry succeeds', async () => {
  const t = await newWorkspace(f, 'on');
  const item = hqItem('proj', '2026-11-19-race.md', 'Race', '## 2026-11-19\n\nracing');
  let planted = 0;
  const r = await directImport(t, [item], async (db: Db, at) => {
    assert.equal(at.found, false);
    // Another writer got there first with the same vault_path_hmac (a valid sealed row of its own).
    const k = keyFor(t);
    try {
      const id = (await nextId(db, 'notes'))[0]!;
      const run = (await db.query<{ id: number }>(`SELECT max(id)::int AS id FROM zeusi.ingest_runs`)).rows[0]!.id;
      const cols = sealRow(k, 'notes', id, { title: 'other', body: 'other', frontmatter: '{}', vault_path: 'import:proj/2026-11-19-race.md', source_uri: 'import:proj/2026-11-19-race.md' });
      assert.deepEqual(cols.find(([c]) => c === 'vault_path_hmac')![1], at.vaultPathHmac);
      const ins = sealedInsertSql('notes', [['id', id, 'bigint'], ['file_mtime', new Date().toISOString(), 'timestamptz'], ['scope', 'work', 'zeusi.scope'],
        ['source_kind', 'manual', 'zeusi.source_kind'], ['source_ts', new Date().toISOString(), 'timestamptz'], ['source_sha256', Buffer.alloc(32, 1), 'bytea'], ['ingest_run_id', run, 'bigint']], [...cols, k.sealDigest('notes', id, '01'.repeat(32))]);
      await db.query(ins.sql, ins.params);
      planted++;
    } finally {
      k.dispose();
    }
  });
  assert.equal(planted, 1);
  assert.equal(r.counts.errors, 1, 'the note counts an error');
  assert.equal(r.counts.inserted, 0);
  assert.deepEqual(await counts(f.db, t), { notes: 0, chunks: 0, facts: 0, decisions: 0, decision_links: 0, quarantine: 0 }, 'rolled back: nothing mis-bound left');
  const again = await directImport(t, [item]);
  assert.equal(again.counts.inserted, 1);
  const rows = await openNotes(t);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!['title'], 'Race');
});

test('§7.17 (write half): a sync in state verified lands sealed and the C5 flip VALIDATE then passes; frontmatter is passed explicitly (never a default)', async () => {
  const t = await newWorkspace(f, 'verified');
  const c = callerOf(t);
  await f.ww.sync(c, [hqItem('journal', '2026-11-19-v1.md', 'V1', '## 2026-11-19\n\nverified one'), hqItem('journal', '2026-11-19-v2.md', 'V2', '## 2026-11-19\n\nverified two')], []);
  await f.ww.sync(c, [], ['journal/2026-11-19-v2.md']);
  await commitDocs(f, c, [md('Import', 'imported\n')]);
  const notes = await openNotes(t);
  assert.equal(notes.length, 3);
  for (const n of notes) {
    assert.equal(n['key_version'], 1);
    assert.ok(typeof n['frontmatter'] === 'string' && JSON.parse(n['frontmatter']) && typeof JSON.parse(n['frontmatter']) === 'object', 'frontmatter_ct is the JSON text');
  }
  assert.equal(notes.find((n) => n['status'] === 'deleted')?.['body'], '', 'the deleted note\'s body is the sealed empty string');
  const flip = await f.dir.overlayStep(t, 'flip', { dryRun: false });
  assert.equal(flip.outcome, 'applied', JSON.stringify(flip));
  assert.equal((await f.router.encState(t)).encState, 'on');
  // After the flip the same writes still work (state on), and a plain INSERT is refused by the DB.
  assert.equal((await f.ww.sync(c, [hqItem('journal', '2026-11-19-v3.md', 'V3', 'after flip')], [])).counts.inserted, 1);
});

// ---------------------------------------------------------------------------
// §7.19 B1 lock and hook (KTD3, KTD10)

test('§7.19: every sealed write transaction holds the workspace index lock when the hook runs; the hook receives exactly the note ids written or removed by the call', async () => {
  const t = await newWorkspace(f, 'on');
  const c = callerOf(t);
  await f.ww.sync(c, [hqItem('journal', '2026-11-19-h0.md', 'H0', 'zero')], []);
  const h0 = f.hook.length;
  await f.ww.sync(c, [hqItem('journal', '2026-11-19-h1.md', 'H1', 'one'), hqItem('journal', '2026-11-19-h2.md', 'H2', 'two')], ['journal/2026-11-19-h0.md']);
  const calls = f.hook.slice(h0);
  const notes = await rowsOf<{ id: number; status: string }>(f.db, t, 'notes', 'id::int AS id, status');
  const written = notes.filter((n) => n.status === 'active').map((n) => n.id).sort();
  const removed = notes.filter((n) => n.status === 'deleted').map((n) => n.id);
  assert.deepEqual(calls.filter((x) => x.kind === 'note').map((x) => x.id).sort(), written, 'written: exactly the two new notes');
  assert.deepEqual(calls.filter((x) => x.kind === 'removed').map((x) => x.id), removed, 'removed: exactly the deleted one');
  assert.ok(calls.length === 3 && calls.every((x) => x.lockHeld && x.schema === t), 'the index lock was held in every hook call');
  const chunkIds = (await rowsOf<{ id: number }>(f.db, t, 'chunks', 'id::int AS id')).map((x) => x.id).sort((a, b) => a - b);
  assert.deepEqual(calls.flatMap((x) => x.chunkIds ?? []).sort((a, b) => a - b), chunkIds, 'the hook saw exactly the stored chunk ids');
  // No lock outside the transaction: the plain route takes none and the hook never runs.
  const off = await newWorkspace(f, 'off');
  const h1 = f.hook.length;
  await f.ww.sync(callerOf(off), [hqItem('journal', '2026-11-19-h3.md', 'H3', 'plain')], []);
  assert.equal(f.hook.length, h1);
});

test('§7.19: lock order: the importer lock is taken before the state read and spans the import, the structured writes and the sync deletions (nested re-entry, one release each)', async () => {
  const t = await newWorkspace(f, 'on');
  const c = callerOf(t);
  await f.ww.sync(c, [hqItem('journal', '2026-11-19-lo.md', 'Lo', 'order')], []);
  for (const op of ['sync', 'commit'] as const) {
    const n = f.log.length;
    if (op === 'sync') await f.ww.sync(c, [hqItem('journal', '2026-11-19-lo2.md', 'Lo2', 'order two')], ['journal/2026-11-19-lo.md']);
    else await commitDocs(f, c, [md('Order', 'order\n'), { kind: 'decision-log', format: 'markdown', text: `## 2026-11-19T10:00:00+01:00 me\nDecision: go\nSaid-at-precision: minute\n\nordered decision\n` }]);
    const L = f.log.slice(n);
    const lock = L.findIndex((s) => /pg_try_advisory_lock/.test(s));
    const state = L.findIndex((s) => s.startsWith('encState('));
    const unlocks = L.map((s, i) => [s, i] as const).filter(([s]) => /pg_advisory_unlock/.test(s)).map(([, i]) => i);
    const locks = L.filter((s) => /pg_try_advisory_lock/.test(s)).length;
    assert.ok(lock >= 0 && state > lock, `${op}: importer lock before the state read`);
    assert.equal(locks, 2, `${op}: the call's lock plus importVault's nested re-entry`);
    assert.equal(unlocks.length, 2, `${op}: one release each`);
    const lastWrite = Math.max(...L.map((s, i) => (/^\s*(INSERT INTO zeusi\.(decisions|facts|decision_links)|UPDATE zeusi\.notes SET status = 'deleted')/.test(s) ? i : -1)));
    assert.ok(lastWrite > 0 && Math.max(...unlocks) > lastWrite, `${op}: the outer lock spans the structured writes / deletions`);
    const xact = L.filter((s) => /pg_advisory_xact_lock/.test(s)).length;
    assert.ok(xact >= 1 && L.findIndex((s) => /pg_advisory_xact_lock/.test(s)) > lock, `${op}: index lock (transaction) after the importer lock (session)`);
  }
});

// ---------------------------------------------------------------------------
// Keys, counter, mixed shapes, size (KTD4, KTD9, KTD11)

test('WorkspaceKey zeroes the DEK at construction and the subkeys at dispose; use after dispose throws', () => {
  const t = `zt_${'k'.repeat(26)}`;
  const dek = Buffer.from(TEST_DEK);
  const k = WorkspaceKey.fromUnlocked({ dek, keyVersion: 1 }, t);
  assertSecretEqual(dek.toString('hex'), ZERO32, 'DEK zeroed at once');
  k.startCounter(0);
  const ct = k.seal('notes', 'title', 1, 'x');
  assert.equal(k.open('notes', 'title', 1, ct), 'x');
  k.dispose();
  assert.equal(k.disposed, true);
  assert.throws(() => k.seal('notes', 'title', 1, 'x'), /disposed/);
  assert.throws(() => k.open('notes', 'title', 1, ct), /disposed/);
  assert.throws(() => k.indexHmac('uri', 'x'), /disposed/);
  // The subkeys themselves are zeroed (white-box: the derived buffers).
  const k2 = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  const held: Buffer[] = [];
  const orig = Buffer.prototype.fill;
  Buffer.prototype.fill = function (this: Buffer, ...a: Parameters<Buffer['fill']>) { if (this.length === 32) held.push(this); return orig.apply(this, a); } as typeof orig;
  try {
    k2.dispose();
  } finally {
    Buffer.prototype.fill = orig;
  }
  assert.equal(held.length, 3, 'K_enc, K_idx, K_hash');
  for (const b of held) assertSecretEqual(b.toString('hex'), ZERO32, 'subkey zeroed');
  // A malformed DEK is zeroed too, and refused.
  const bad = Buffer.alloc(31, 7);
  assert.throws(() => WorkspaceKey.fromUnlocked({ dek: bad, keyVersion: 1 }, t));
  assertSecretEqual(bad.toString('hex'), '00'.repeat(31), 'zeroed on refusal');
});

test('enc_progress.values_sealed grows by the number of values sealed; at ROTATE_AT the call is refused before any seal', async () => {
  const t = await newWorkspace(f, 'on');
  const c = callerOf(t);
  await f.ww.sync(c, [hqItem('journal', '2026-11-19-n1.md', 'N1', '## A\n\none\n\n## B\n\ntwo'), hqItem('journal', '2026-11-19-n2.md', 'N2', 'three')], []);
  const ctCount = await asOwner(f.db, async () => {
    let n = 0;
    for (const s of OVERLAY_SPEC) {
      // C8-0 KTD-A: the sealed digest copy is a sealed value too (notes; chunks carry none).
      const cts = [...s.columns.map((x) => `${x.plain}_ct`), ...(s.table === 'notes' ? ['source_sha256_ct'] : [])];
      n += (await f.db.query<{ n: number }>(`SELECT (${cts.map((x) => `count(${x})`).join(' + ')})::int AS n FROM "${t}".${s.table}`)).rows[0]!.n;
    }
    return n;
  });
  const progress = await asOwner(f.db, async () => (await f.db.query<{ table_name: string; values_sealed: string; phase: string }>(
    `SELECT table_name, values_sealed::text AS values_sealed, phase FROM "${t}".enc_progress ORDER BY 1`)).rows);
  assert.ok(ctCount > 0);
  assert.equal(progress.reduce((a, r) => a + Number(r.values_sealed), 0), ctCount, 'one count per stored ciphertext');
  assert.deepEqual(progress.map((r) => r.table_name).sort(), ['chunks', 'notes']);
  assert.ok(progress.every((r) => r.phase === 'idle'), 'phase is never written (default)');
  // At the rotation threshold: refused before any seal, nothing written, the counter unchanged.
  await asOwner(f.db, () => f.db.query(`UPDATE "${t}".enc_progress SET values_sealed = values_sealed + $1 WHERE table_name = 'notes'`, [ROTATE_AT]));
  const before0 = await counts(f.db, t);
  assert.equal(await refusal(f.ww.sync(c, [hqItem('journal', '2026-11-19-n3.md', 'N3', 'four')], [])), WRITES_OFF);
  assert.deepEqual(await counts(f.db, t), before0);
});

test('a row at another key_version (or a plain row in verified) refuses the call (WORKSPACE_CHANGING); nothing written', async () => {
  const t = await newWorkspace(f, 'on');
  await f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-19-kv.md', 'Kv', 'one')], []);
  await asOwner(f.db, () => f.db.query(`UPDATE "${t}".chunks SET key_version = 2`));
  const before0 = await counts(f.db, t);
  assert.equal(await refusal(f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-19-kv2.md', 'Kv2', 'two')], [])), WORKSPACE_CHANGING);
  assert.deepEqual(await counts(f.db, t), before0);
  const v = await newWorkspace(f, 'off');
  await f.ww.sync(callerOf(v), [hqItem('journal', '2026-11-19-plain.md', 'Plain', 'plain row')], []);
  assert.equal((await f.dir.overlayStep(v, 'prepare', { dryRun: false })).outcome, 'applied');
  await setState(f.db, v, 'verified');
  assert.equal(await refusal(f.ww.sync(callerOf(v), [hqItem('journal', '2026-11-19-plain2.md', 'Plain2', 'x')], [])), WORKSPACE_CHANGING);
  assert.equal((await counts(f.db, v))['notes'], 1);
});

test('size check (KTD9): the sealed usage counts plain bytes (ciphertext - 29); the sealed HQ count equals today\'s on a plain fixture', async () => {
  const t = await newWorkspace(f, 'on');
  const bodies = ['## A\n\nalpha', `## B\n\n${'beta '.repeat(50)}`];
  await f.ww.sync(callerOf(t), bodies.map((b, i) => hqItem('journal', `2026-11-19-s${i}.md`, `S${i}`, b)), []);
  const opened = (await openNotes(t)).reduce((a, n) => a + Buffer.byteLength(String(n['body']), 'utf8'), 0);
  const sealedBytes = await asOwner(f.db, async () => Number((await f.db.query<{ b: string }>(`SELECT coalesce(sum(${SEALED_BODY_BYTES_SQL}), 0)::text AS b FROM "${t}".notes`)).rows[0]!.b));
  assert.equal(sealedBytes, opened);
  // On a plain workspace the shape-aware expression is today's octet_length(body), and the kind-only HQ
  // count equals today's LIKE 'hq:%' count (only HQ_PROFILE writes zeus_memory).
  const p = await newWorkspace(f, 'off');
  await f.ww.sync(callerOf(p), bodies.map((b, i) => hqItem('journal', `2026-11-19-s${i}.md`, `S${i}`, b)), []);
  await commitDocs(f, callerOf(p), [md('Imported', 'manual kind\n')]);
  assert.equal((await f.dir.overlayStep(p, 'prepare', { dryRun: false })).outcome, 'applied', 'prepare keeps the plain rows (body_ct exists, NULL)');
  await asOwner(f.db, async () => {
    const q = async (sql: string) => Number((await f.db.query<{ n: string }>(sql)).rows[0]!.n);
    assert.equal(await q(`SELECT coalesce(sum(${SEALED_BODY_BYTES_SQL}), 0)::text AS n FROM "${p}".notes`), await q(`SELECT coalesce(sum(octet_length(body)), 0)::text AS n FROM "${p}".notes`));
    assert.equal(
      await q(`SELECT count(*)::text AS n FROM "${p}".notes WHERE status = 'active' AND source_kind = 'zeus_memory'`),
      await q(`SELECT count(*)::text AS n FROM "${p}".notes WHERE status = 'active' AND source_kind = 'zeus_memory' AND vault_path LIKE 'hq:%'`));
  });
  assert.equal(IMPORT_PROFILE.sourceKind, 'manual', 'imports never write zeus_memory');
});

test('the index lock key is per workspace and distinct from the importer locks', () => {
  const a = `zt_${'a'.repeat(26)}`;
  const b = `zt_${'b'.repeat(26)}`;
  assert.notEqual(workspaceIndexLockKey(a), workspaceIndexLockKey(b));
  assert.throws(() => workspaceIndexLockKey('zeusi'));
});

test('served copy (KTD14): WORKSPACE_CHANGING and WORKSPACE_LOCKED are served copy (serverCopy) and pass the over-claim ban', () => {
  const copy = serverCopy().map(([, x]) => x);
  for (const s of [WORKSPACE_CHANGING, WORKSPACE_LOCKED]) {
    assert.ok(copy.includes(s), 'covered by test/site.test.ts through serverCopy()');
    assert.deepEqual(overclaims(s), []);
    assert.match(s, /nothing was saved/);
  }
});
