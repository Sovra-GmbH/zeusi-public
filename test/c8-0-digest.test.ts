// C8-0 U1 (docs/plans/2026-11-21-c8-refresh.md KTD-A, §5): the sealed copy of the plain source digest
// (source_sha256_ct) on every sealed row of notes, facts, decisions and decision_links. PGlite with the real
// migrations, tenant logins and writer login (test/helpers/c6-fixture.ts); a FIXED test DEK, never a real key. No
// network, no Neon, no real workspace. Each test names the mutant that turns it red.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync } from 'node:fs';
import type { Db } from '../src/db.ts';
import { EnvelopeError } from '../src/crypto-envelope.ts';
import { linkSha256 } from '../src/decision-links.ts';
import { encryptStatusAll, readWorkspaceDigest } from '../src/encrypt-status.ts';
import { closeRun, openRun } from '../src/facts.ts';
import { recordSha256, writeStructured, type DecisionRecord, type FactRecord } from '../src/importers/structured.ts';
import { TENANT_ACL_AUDIT_SQL, tenantRole } from '../src/tenant-ddl.ts';
import {
  ensureSealedDigest, OVERLAY_SPEC, PREPARE_SHA256, readOverlayState, SEALED_DIGEST_COLUMN, SEALED_DIGEST_TABLES, sealedDigestDropSql,
  sealedDigestFormatConstraint, sealedDigestPlainConstraint, sealedDigestPresence, sealedDigestReady,
} from '../src/tenant-overlay.ts';
import { ENC_STATE_LOCK_TIMEOUT, TenantDirectory, TenantWriter, TENANT_WR_ROLE } from '../src/tenants.ts';
import { loadWall } from '../src/wall.ts';
import { enrollmentWraps } from '../src/workspace-keys.ts';
import {
  digestCopyMatches, sealedInsertSql, sealedSoFar, sealedUpdateSql, sealRow, WorkspaceKey, type SqlCol,
} from '../src/workspace-seal.ts';
import { WORKSPACE_CHANGING, WorkspaceWriteRefused } from '../src/workspace-write.ts';
import { NO_INDEX_HOOK, type SealedRoute } from '../src/write-route.ts';
import {
  c6Fixture, callerOf, commitDocs, decisionEntry, decisionLog, factEntry, hqItem, newWorkspace, rowsOf, setState, TEST_DEK, type C6Fixture,
} from './helpers/c6-fixture.ts';
import { asLogin, asOwner } from './helpers/tenant-fixture.ts';

/** One lexical token in planted content: a leak is a substring match (plain or UTF-8 hex inside a bytea). */
const CANARY = 'c80digestcanarykoala';

let f: C6Fixture;
before(async () => {
  f = await c6Fixture();
});
after(async () => {
  await f.close();
});

const keyFor = (t: string) => {
  const k = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  k.startCounter(0);
  return k;
};
const withKey = <T>(t: string, fn: (k: WorkspaceKey) => T): T => {
  const k = keyFor(t);
  try {
    return fn(k);
  } finally {
    k.dispose();
  }
};
const refusal = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof WorkspaceWriteRefused ? e.message : `other: ${(e as Error).message}`;
  }
};
const hex = (s: string) => Buffer.from(s, 'utf8').toString('hex');
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
/** A sealed-shaped dummy value (format byte 0x01 + 28 random bytes) and a 32-byte dummy HMAC. */
const sealedDummy = (len = 29) => Buffer.concat([Buffer.from([0x01]), randomBytes(len - 1)]);
const mac = () => randomBytes(32);
const owner = <T>(fn: () => Promise<T>) => asOwner(f.db, fn);
const q1 = async <T>(sql: string, params: unknown[] = []) => owner(async () => (await f.db.query<T>(sql, params)).rows);

/** Every sealed row (key_version set) of the four digest tables of `t`, as the owner. */
async function sealedRows(t: string): Promise<Array<{ table: string; row: Record<string, unknown> }>> {
  const out: Array<{ table: string; row: Record<string, unknown> }> = [];
  for (const table of SEALED_DIGEST_TABLES) {
    for (const row of await rowsOf<Record<string, unknown>>(f.db, t, table, '*', 'key_version IS NOT NULL')) out.push({ table, row });
  }
  return out;
}

/** The born-on corpus: a commit (note, decision with Links, fact), a sync with a new note, then an edit of it. */
async function fillCorpus(t: string): Promise<{ syncedText: string }> {
  const c = callerOf(t);
  const r = await commitDocs(f, c, [
    { kind: 'markdown', title: `Plan ${CANARY}`, text: `# ${CANARY}\n\n${CANARY} words in the body.\n` },
    decisionLog(decisionEntry(`decide ${CANARY} now`, { links: ['vault:notes/plan.md', 'gh:Org/repo#3'] }) + '\n' + factEntry('rule', 'subj', `a rule about ${CANARY}`)),
  ]);
  assert.equal(r.decisions, 1, JSON.stringify(r));
  const first = hqItem('journal', '2026-11-21-digest.md', 'Digest', `first ${CANARY} body`);
  assert.equal((await f.ww.sync(c, [first], [])).counts.inserted, 1);
  const edited = hqItem('journal', '2026-11-21-digest.md', 'Digest', `edited ${CANARY} body`);
  assert.equal((await f.ww.sync(c, [edited], [])).counts.updated, 1);
  return { syncedText: edited.text };
}

async function scan(t: string, words: string[]): Promise<string[]> {
  return owner(async () => {
    await f.db.exec('ANALYZE');
    const hits: string[] = [];
    const rels = (await f.db.query<{ r: string }>(`SELECT c.relname::text AS r FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind = 'r'`, [t])).rows.map((x) => x.r);
    for (const w of words) {
      for (const r of rels) {
        const n = (await f.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}"."${r}" x WHERE strpos(lower(to_jsonb(x)::text), $1) > 0 OR strpos(to_jsonb(x)::text, $2) > 0`, [w, hex(w)])).rows[0]!.n;
        if (n > 0) hits.push(`${r}:${w.slice(0, 12)}`);
      }
      const st = (await f.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_stats s WHERE s.schemaname = $1 AND (strpos(lower(to_jsonb(s)::text), $2) > 0 OR strpos(to_jsonb(s)::text, $3) > 0)`, [t, w, hex(w)])).rows[0]!.n;
      if (st > 0) hits.push(`pg_stats:${w.slice(0, 12)}`);
      const ix = (await f.db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_indexes WHERE schemaname = $1 AND strpos(lower(indexdef), $2) > 0`, [t, w])).rows[0]!.n;
      if (ix > 0) hits.push(`pg_indexes:${w.slice(0, 12)}`);
    }
    return hits;
  });
}

// ---------------------------------------------------------------------------
// §7 item 1, the digest-copy rule end to end, §7 item 15 enabler

test('§7 item 1: born-on workspace: after commit, sync and a decision with Links carrying a canary, the owner scan finds neither the canary nor its plain digest hex in any column (source_sha256_ct included), pg_stats or index definition', async () => {
  // Mutant: sealDigest stores the plain digest unsealed behind the format byte (passes the CHECK) -> the hex of the
  // digest text is found in source_sha256_ct, red. Stored raw without the format byte -> the format CHECK refuses the
  // commit, red (the CHECK is the first line of defence; review r2 P3-4).
  const t = await newWorkspace(f, 'on');
  await fillCorpus(t);
  const rows = await sealedRows(t);
  const digests = withKey(t, (k) => rows.map(({ table, row }) => k.open(table, 'source_sha256', Number(row['id']), row[SEALED_DIGEST_COLUMN] as Uint8Array)));
  assert.ok(digests.length >= 6, `sealed rows of every kind (${digests.length})`);
  assert.deepEqual(await scan(t, [CANARY, ...digests]), [], 'no canary and no plain digest at rest');
});

test('the digest copy is never skipped (r1 P1-2): every sealed writer that sets source_sha256 also sets source_sha256_ct; the builders refuse otherwise; end to end digest_missing = 0', async () => {
  // Mutants: delete the throw in sealedInsertSql / sealedUpdateSql -> the builder assertions turn red; remove one call
  // site's sealDigest (e.g. the decision-link INSERT) -> its write fails, the per-table counts below turn red.
  const T = `zt_${'d'.repeat(26)}`;
  const k = keyFor(T);
  try {
    for (const table of SEALED_DIGEST_TABLES) {
      const spec = OVERLAY_SPEC.find((s) => s.table === table)!;
      const values = Object.fromEntries(spec.columns.map((c) => [c.plain, c.required ? `v-${c.plain}` : null]));
      const cols = sealRow(k, table, 7, values);
      const meta: SqlCol[] = [['source_sha256', Buffer.alloc(32, 1), 'bytea'], ['ingest_run_id', 1, 'bigint']];
      assert.throws(() => sealedInsertSql(table, meta, cols), (e: unknown) => e instanceof EnvelopeError && /without its sealed copy/.test(e.message), `${table} insert`);
      assert.throws(() => sealedUpdateSql(table, 7, meta, cols), (e: unknown) => e instanceof EnvelopeError && /without its sealed copy/.test(e.message), `${table} update`);
      assert.throws(() => sealedInsertSql(table, meta, [...cols, [SEALED_DIGEST_COLUMN, null]]), EnvelopeError, `${table}: a NULL copy is not a copy`);
      const ok = sealedInsertSql(table, meta, [...cols, k.sealDigest(table, 7, 'ab'.repeat(32))]);
      assert.match(ok.sql, /source_sha256_ct/);
      // Without source_sha256 in meta (a metadata-only statement) the builders are unaffected.
      assert.match(sealedUpdateSql(table, 7, [['status', 'active']], cols).sql, /^UPDATE zeusi\./);
    }
    // Chunks inherit the parent's digest: no copy is asked for.
    const cc = sealRow(k, 'chunks', 8, { heading_path: null, text: 'x', source_uri: 'u#c0' });
    assert.match(sealedInsertSql('chunks', [['note_id', 1, 'bigint']], cc).sql, /^INSERT INTO zeusi\.chunks/);
  } finally {
    k.dispose();
  }
  const t = await newWorkspace(f, 'on');
  await fillCorpus(t);
  const per: Record<string, number> = {};
  for (const { table, row } of await sealedRows(t)) {
    per[table] = (per[table] ?? 0) + 1;
    assert.ok(row[SEALED_DIGEST_COLUMN] instanceof Uint8Array, `${table} ${String(row['id'])}: has its copy`);
  }
  // notes: the two notes the commit stores (the markdown note and one from the decision log document) and the synced (then edited) HQ note.
  assert.deepEqual(per, { notes: 3, facts: 1, decisions: 1, decision_links: 2 }, 'every kind of sealed writer ran');
  assert.deepEqual(await owner(() => readWorkspaceDigest(f.db, t)), { gone: false, prepared: true, columnMissing: false, missing: 0 });
});

test('§7 item 15 enabler: opening source_sha256_ct gives exactly the plain digest the importer computed (vault sha, recordSha256, linkSha256) as 64 lowercase hex characters, and keyedSha of it equals the stored source_sha256; sealDigest refuses any other shape', async () => {
  // Mutants: write keyedDigest into source_sha256_ct -> the opened value is not the plain digest, red; seal the 32
  // raw bytes -> open fails (fatal UTF-8) or the hex check fails, red; drop the lowercase check -> the refusal
  // assertions turn red.
  const t = await newWorkspace(f, 'on');
  const { syncedText } = await fillCorpus(t);
  // Structured records written directly, so recordSha256 is computable here.
  const dec: DecisionRecord = {
    type: 'decision', who: 'me', saidAt: '2026-11-21T09:00:00.000Z', saidAtPrecision: 'minute', kind: 'go', verbatim: false, appliesTo: ['zeusi'],
    linkedRepo: null, linkedPr: null, expiresAt: null, expiresRule: null, text: 'a direct decision', links: ['vault:notes/direct.md'],
  };
  const fact: FactRecord = { type: 'fact', who: 'me', saidAt: '2026-11-21T08:00:00.000Z', factKind: 'rule', subject: 'direct', text: 'a direct rule' };
  const db = await new TenantWriter({ connectWriter: asLogin(f.db, TENANT_WR_ROLE), check: (x) => f.router.check(x) }).open(t);
  const key = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  try {
    key.startCounter(await sealedSoFar(db, 1));
    const route: SealedRoute = { kind: 'sealed', key, tenantId: t, index: NO_INDEX_HOOK };
    const run = await openRun(db, { importer: 'c80-test', host: 'test', mode: 'manual' });
    const w = await writeStructured(db, [{ record: dec, project: 'proj' }, { record: fact, project: 'proj' }],
      { scope: 'work', sourceKind: 'manual', uriPrefix: 'import:', runId: run, wall: await loadWall(db), route });
    await closeRun(db, run, 'ok', {});
    assert.equal(w.decisions_inserted + w.rules_inserted, 2, JSON.stringify(w));
  } finally {
    key.dispose();
    await db.close();
  }
  const want = new Set([recordSha256(dec), recordSha256(fact)]);
  let notesSeen = 0;
  let structuredSeen = 0;
  let linksSeen = 0;
  const rows = await sealedRows(t);
  withKey(t, (k) => {
    for (const { table, row } of rows) {
      const id = Number(row['id']);
      const h = k.open(table, 'source_sha256', id, row[SEALED_DIGEST_COLUMN] as Uint8Array);
      assert.match(h, /^[0-9a-f]{64}$/, `${table} ${id}: 64 lowercase hex`);
      assert.ok(Buffer.from(row['source_sha256'] as Uint8Array).equals(k.keyedSha('source_sha256', h)), `${table} ${id}: keyedSha(open(copy)) = source_sha256`);
      assert.equal(digestCopyMatches(k, table, row), true);
      if (table === 'decision_links') {
        const o = (c: string) => k.open(table, c, id, row[`${c}_ct`] as Uint8Array);
        assert.equal(h, linkSha256(o('source_uri'), o('target_uri')), 'linkSha256');
        linksSeen++;
      }
      if (table === 'notes' && k.open('notes', 'vault_path', id, row['vault_path_ct'] as Uint8Array).includes('2026-11-21-digest.md')) {
        assert.equal(h, sha(syncedText), 'the vault sha of the edited file (the copy follows the UPDATE)');
        notesSeen++;
      }
      if ((table === 'decisions' || table === 'facts') && want.has(h)) structuredSeen++;
    }
  });
  assert.equal(notesSeen, 1);
  assert.equal(structuredSeen, 2, 'recordSha256 of both direct records');
  assert.equal(linksSeen, 3);
  withKey(t, (k) => {
    for (const bad of ['AB'.repeat(32), 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64), '', ' '.repeat(64), `${'a'.repeat(63)}\n`]) {
      assert.throws(() => k.sealDigest('notes', 1, bad), (e: unknown) => e instanceof EnvelopeError && /64 lowercase hex/.test(e.message), JSON.stringify(bad.slice(0, 4)));
    }
    assert.throws(() => k.sealDigest('chunks', 1, 'a'.repeat(64)), EnvelopeError, 'chunks carry no copy');
  });
});

// ---------------------------------------------------------------------------
// §7 item 5 (AAD), tenant isolation, stale copy, nonce counter

test('§7 item 5: a source_sha256_ct copied to another row, table or workspace fails to open; it opens only under AAD column source_sha256 of its own row; workspace A\'s key cannot open B\'s copy with the same row id', async () => {
  // Mutants: seal under the parent note's id or under column `title` -> the own-row open fails or another open
  // succeeds, red; AAD without the tenant -> A's key opens B's copy, red.
  const A = await newWorkspace(f, 'on');
  const B = await newWorkspace(f, 'on');
  for (const t of [A, B]) await f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-21-a.md', 'A', 'one'), hqItem('journal', '2026-11-21-b.md', 'B', 'two')], []);
  const notesA = await rowsOf<Record<string, unknown>>(f.db, A, 'notes');
  const notesB = await rowsOf<Record<string, unknown>>(f.db, B, 'notes');
  const [a1, a2] = [notesA[0]!, notesA[1]!];
  const ct = a1[SEALED_DIGEST_COLUMN] as Uint8Array;
  withKey(A, (k) => {
    // Every row's copy opens under its own id (two rows, so an AAD pinned to one id cannot pass).
    for (const r of notesA) assert.match(k.open('notes', 'source_sha256', Number(r['id']), r[SEALED_DIGEST_COLUMN] as Uint8Array), /^[0-9a-f]{64}$/, 'own row, own column');
    assert.throws(() => k.open('notes', 'source_sha256', Number(a2['id']), ct), 'another row');
    assert.throws(() => k.open('facts', 'source_sha256', Number(a1['id']), ct), 'another table');
    for (const col of ['title', 'body', 'source_uri', 'vault_path']) assert.throws(() => k.open('notes', col, Number(a1['id']), ct), `column ${col}`);
    assert.equal(digestCopyMatches(k, 'notes', { ...a2, [SEALED_DIGEST_COLUMN]: ct }), false, 'moved to another row');
  });
  const b1 = notesB.find((r) => Number(r['id']) === Number(a1['id']))!;
  assert.ok(b1, 'B has a row with the same id');
  withKey(A, (k) => {
    assert.throws(() => k.open('notes', 'source_sha256', Number(b1['id']), b1[SEALED_DIGEST_COLUMN] as Uint8Array), 'A cannot open B');
    assert.equal(digestCopyMatches(k, 'notes', b1), false);
  });
  withKey(B, (k) => assert.equal(digestCopyMatches(k, 'notes', b1), true, 'B opens its own'));
});

test('stale copy (r1 P2-2): source_sha256 rewritten to keyed(other digest) by raw SQL, as a reverted image\'s UPDATE does, leaving the copy: digestCopyMatches is false; fresh row true; NULL, moved or broken copy false; it never throws', async () => {
  // Mutant: digestCopyMatches returns true whenever the copy is non-NULL and opens (no keyed comparison) -> the stale
  // case turns red.
  const t = await newWorkspace(f, 'on');
  await f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-21-s1.md', 'S1', 'one'), hqItem('journal', '2026-11-21-s2.md', 'S2', 'two')], []);
  const [r1, r2] = await rowsOf<Record<string, unknown>>(f.db, t, 'notes');
  withKey(t, (k) => {
    assert.equal(digestCopyMatches(k, 'notes', r1!), true, 'fresh row');
  });
  const staleSha = withKey(t, (k) => k.keyedSha('source_sha256', sha('the reverted image wrote other content')));
  await owner(() => f.db.query(`UPDATE "${t}".notes SET source_sha256 = $2 WHERE id = $1`, [Number(r1!['id']), staleSha]));
  const [s1] = await rowsOf<Record<string, unknown>>(f.db, t, 'notes', '*', `id = ${Number(r1!['id'])}`);
  withKey(t, (k) => {
    const broken = Buffer.from(r2![SEALED_DIGEST_COLUMN] as Uint8Array);
    broken[broken.length - 1]! ^= 0x01;
    const cases: Array<[string, Record<string, unknown>, boolean]> = [
      ['stale', s1!, false],
      ['fresh', r2!, true],
      ['NULL copy', { ...r2!, [SEALED_DIGEST_COLUMN]: null }, false],
      ['moved copy', { ...r2!, [SEALED_DIGEST_COLUMN]: r1![SEALED_DIGEST_COLUMN] }, false],
      ['broken ciphertext', { ...r2!, [SEALED_DIGEST_COLUMN]: broken }, false],
      ['not bytes', { ...r2!, [SEALED_DIGEST_COLUMN]: 'x' }, false],
      ['no id', { ...r2!, id: null }, false],
    ];
    for (const [what, row, want] of cases) {
      let got: boolean | 'threw' = 'threw';
      assert.doesNotThrow(() => { got = digestCopyMatches(k, 'notes', row); }, what);
      assert.equal(got, want, what);
    }
    assert.equal(digestCopyMatches(k, 'chunks', r2!), false, 'not a digest table');
  });
});

test('nonce counter (r1 P2-3): a sealed commit grows enc_progress.values_sealed per table by exactly one more per row than the non-NULL spec values sealRow sealed for that row (notes, facts, decisions, decision_links)', async () => {
  // Mutant: sealDigest seals through sealValue directly, skipping seal's counter and #pending -> the +1 is missing, red.
  const t = await newWorkspace(f, 'on');
  await fillCorpus(t);
  const progress = Object.fromEntries((await q1<{ t: string; n: string }>(`SELECT table_name AS t, values_sealed::text AS n FROM "${t}".enc_progress WHERE key_version = 1`)).map((r) => [r.t, Number(r.n)]));
  for (const table of SEALED_DIGEST_TABLES) {
    const spec = OVERLAY_SPEC.find((s) => s.table === table)!;
    const rows = await rowsOf<Record<string, unknown>>(f.db, t, table);
    assert.ok(rows.length > 0, table);
    // Every value sealed for a row that is still stored: its non-NULL spec _ct values, plus 1 for the copy. Notes were
    // also sealed once more by the edit (an UPDATE of the same row): count the first write of that row too.
    let expect = rows.reduce((a, r) => a + spec.columns.filter((c) => r[`${c.plain}_ct`] !== null).length + 1, 0);
    if (table === 'notes') expect += spec.columns.length + 1; // the first version of the edited note (5 required values + copy)
    assert.equal(progress[table], expect, `${table}: values_sealed`);
  }
});

// ---------------------------------------------------------------------------
// Pre-C8-0 workspaces (deploy window), §7 item 17 DDL, R3-2 counts, migration reversibility

/** The documented rollback (KTD-A) on all four tables: the pre-U1 shape. */
const dropDigest = (t: string) => owner(async () => {
  for (const table of SEALED_DIGEST_TABLES) await f.db.exec(sealedDigestDropSql(t, table));
});

/** A TenantDirectory whose admin sessions record every statement (the provisioner connection). */
function recordingDir(log: string[]): TenantDirectory {
  const base = asLogin(f.db, 'zeusi_tenant_admin');
  return new TenantDirectory({
    connectAdmin: async () => {
      const db = await base();
      return {
        label: db.label,
        query: (sql, params) => { log.push(sql); return db.query(sql, params); },
        exec: (sql) => { log.push(sql); return db.exec(sql); },
        close: () => db.close(),
      } satisfies Db;
    },
  });
}

test('pre-C8-0 workspace (r1 P1-1): born on with the pre-U1 DDL, then the U1 code: enroll works and readOverlayState names no missing column; a sealed commit or sync is refused with exactly WORKSPACE_CHANGING and writes nothing; after ensureWriter / backfill-writers --real both succeed with a copy; --all shows digest_column_missing, then not', async () => {
  // Mutants: drop the presence check in readOverlayState -> enroll throws 42703, red; drop the sealedDigestReady
  // refusal in routeFor -> the write fails with another error, not WORKSPACE_CHANGING, red.
  const t = await newWorkspace(f, 'on');
  const u = await newWorkspace(f, 'on');
  await dropDigest(t);
  await dropDigest(u);
  assert.equal(await owner(() => sealedDigestReady(f.db, t)), false);
  const all0 = await encryptStatusAll(f.dir);
  assert.ok(all0.digestColumnMissing >= 2);
  assert.equal((await owner(() => readWorkspaceDigest(f.db, t))).columnMissing, true);
  const st = await owner(() => readOverlayState(f.db, t));
  assert.equal(st.prepared, true);
  const e = enrollmentWraps({ tenant: t, prfOutput: randomBytes(32), credentialId: randomBytes(16), prfSalt: randomBytes(32) });
  assert.equal(await f.dir.enroll(t, { passkey: e.passkey, recovery: e.recovery }), 'enrolled', 'enroll on a not-converged schema');
  e.dek.fill(0);
  const c = callerOf(t);
  const p = await f.ww.preview(c, [{ kind: 'markdown', title: 'Pre', text: '# Pre\n\nbefore convergence\n' }]);
  assert.equal(p.status, 'preview');
  const before0 = await q1<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}".notes`);
  assert.equal(await refusal(f.ww.commit(c, (p as { preview_id: string }).preview_id)), WORKSPACE_CHANGING);
  assert.equal(await refusal(f.ww.sync(c, [hqItem('journal', '2026-11-21-pre.md', 'Pre', 'x')], [])), WORKSPACE_CHANGING);
  assert.deepEqual(await q1<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}".notes`), before0, 'nothing written');
  // Convergence: a sign-in (ensureWriter) for t, the post-deploy backfill for u.
  assert.equal(await f.dir.ensureWriter(t), 'ready');
  const bf = await f.dir.backfillWriters({ dryRun: false });
  assert.equal(bf.failed, 0);
  for (const x of [t, u]) assert.equal(await owner(() => sealedDigestReady(f.db, x)), true, 'converged');
  assert.equal((await f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-21-pre.md', 'Pre', 'x')], [])).counts.inserted, 1);
  assert.equal((await f.ww.sync(callerOf(u), [hqItem('journal', '2026-11-21-pre.md', 'Pre', 'x')], [])).counts.inserted, 1);
  for (const x of [t, u]) assert.equal((await owner(() => readWorkspaceDigest(f.db, x))).missing, 0);
  const all1 = await encryptStatusAll(f.dir);
  assert.equal(all1.digestColumnMissing, all0.digestColumnMissing - 2);
});

test('§7 item 17: ensureSealedDigest is idempotent (twice = once: same columns and the two named constraints); PREPARE_SHA256 unchanged; the plain-side and format CHECKs refuse; ACL audit clean; the team zeusi has no copy column', async () => {
  // Mutants: put the column into the prepare template -> the PREPARE_SHA256 pin fails; drop the plain-side CHECK ->
  // the plain-row INSERT passes; always ALTER -> the second run issues an ALTER (and a duplicate constraint), red.
  assert.equal(PREPARE_SHA256, '5e926e99775841f6e9520f3382a31f20796653eadc45ae691420e4a877d953fa', 'the prepare template is unchanged (value at f057be8)');
  const t = await newWorkspace(f, 'on');
  const shapeOf = async () => q1<{ x: string }>(
    `SELECT c.relname || '.' || k.conname || ':' || pg_get_constraintdef(k.oid) AS x FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND k.conname LIKE '%source_sha256_ct%'
     UNION ALL SELECT a.attrelid::regclass::text || '.' || a.attname || ':' || format_type(a.atttypid, a.atttypmod) || ':' || (NOT a.attnotnull)::text
       FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND a.attname = $2 AND NOT a.attisdropped ORDER BY 1`, [t, SEALED_DIGEST_COLUMN]);
  const s0 = await shapeOf();
  assert.equal(s0.length, 12, 'four columns and eight named constraints');
  for (const table of SEALED_DIGEST_TABLES) {
    assert.ok(s0.some((r) => r.x.startsWith(`${table}.${sealedDigestFormatConstraint(table)}:`)));
    assert.ok(s0.some((r) => r.x.startsWith(`${table}.${sealedDigestPlainConstraint(table)}:`)));
  }
  assert.equal(await owner(() => ensureSealedDigest(f.db, t, ENC_STATE_LOCK_TIMEOUT)), 0, 'converged: no ALTER');
  assert.deepEqual(await shapeOf(), s0);
  await dropDigest(t);
  assert.equal(await owner(() => ensureSealedDigest(f.db, t, ENC_STATE_LOCK_TIMEOUT)), 4, 'one ALTER per table');
  assert.equal(await owner(() => ensureSealedDigest(f.db, t, ENC_STATE_LOCK_TIMEOUT)), 0, 'twice = once');
  assert.deepEqual(await shapeOf(), s0);
  // Only the missing part is added (one constraint dropped by hand).
  await owner(() => f.db.exec(`ALTER TABLE "${t}".facts DROP CONSTRAINT ${sealedDigestPlainConstraint('facts')}`));
  assert.deepEqual((await owner(() => sealedDigestPresence(f.db, t))).find((p) => p.table === 'facts'), { table: 'facts', column: true, format: true, plain: false });
  assert.equal(await owner(() => sealedDigestReady(f.db, t)), false, 'ready needs both CHECKs too (r2 P3-1)');
  assert.equal(await owner(() => ensureSealedDigest(f.db, t, ENC_STATE_LOCK_TIMEOUT)), 1);
  assert.deepEqual(await shapeOf(), s0);
  // The CHECKs bite. A sealed fact with a too-short copy (format), then a plain fact with a copy (plain side).
  const run = (await q1<{ id: number }>(`SELECT max(id)::int AS id FROM "${t}".ingest_runs`))[0]!.id;
  const sealedFact = (copy: Buffer) => owner(() => f.db.query(
    `INSERT INTO "${t}".facts (kind, text_ct, scope, source_kind, source_uri_ct, source_uri_hmac, source_ts, source_sha256, ingest_run_id, key_version, source_sha256_ct)
     VALUES ('rule', $1, 'personal', 'manual', $2, $3, now(), $4, $5, 1, $6)`, [sealedDummy(), sealedDummy(), mac(), mac(), run, copy]));
  await assert.rejects(sealedFact(Buffer.from([0x01, 2, 3, 4, 5])), new RegExp(sealedDigestFormatConstraint('facts')));
  await assert.rejects(sealedFact(Buffer.concat([Buffer.from([0x02]), randomBytes(60)])), new RegExp(sealedDigestFormatConstraint('facts')), 'wrong format byte');
  const off = await newWorkspace(f, 'off');
  assert.equal((await f.dir.overlayStep(off, 'prepare', { dryRun: false })).outcome, 'applied');
  assert.equal(await owner(() => sealedDigestReady(f.db, off)), true, 'prepare converges too');
  const run2 = (await q1<{ id: number }>(`SELECT max(id)::int AS id FROM "${off}".ingest_runs`))[0]!.id;
  await assert.rejects(owner(() => f.db.query(
    `INSERT INTO "${off}".facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id, source_sha256_ct)
     VALUES ('rule', 'plain', 'personal', 'manual', 'import:x', now(), $1, $2, $3)`, [mac(), run2, sealedDummy(93)])), new RegExp(sealedDigestPlainConstraint('facts')));
  for (const x of [t, off]) assert.deepEqual(await q1(TENANT_ACL_AUDIT_SQL, [x, tenantRole(x)]), [], 'ACL audit clean');
  assert.deepEqual(await q1(`SELECT table_name FROM information_schema.columns WHERE table_schema = 'zeusi' AND column_name = $1`, [SEALED_DIGEST_COLUMN]), [], 'the team unchanged');
});

test('§7 item 17 (r1 P2-1): on a converged workspace a second ensureWriter issues no ALTER TABLE on the provisioner connection; on a not-converged one the ALTERs are preceded by set_config(\'lock_timeout\', \'5s\', true) and followed by the restore', async () => {
  // Mutants: drop the presence guard (always ALTER) -> the converged run logs an ALTER (and fails on the duplicate
  // constraint), red; drop the lock_timeout line -> the order assertion turns red.
  assert.equal(ENC_STATE_LOCK_TIMEOUT, '5s');
  const t = await newWorkspace(f, 'on');
  const log: string[] = [];
  const dir = recordingDir(log);
  assert.equal(await dir.ensureWriter(t), 'ready');
  log.length = 0;
  assert.equal(await dir.ensureWriter(t), 'ready');
  assert.ok(log.length > 5);
  assert.deepEqual(log.filter((s) => /^\s*ALTER TABLE/i.test(s)), [], 'converged: no ALTER TABLE');
  assert.ok(!log.some((s) => s.startsWith(`SELECT set_config('lock_timeout'`)), 'nor a lock_timeout change of ensureSealedDigest');
  await dropDigest(t);
  log.length = 0;
  assert.equal(await dir.ensureWriter(t), 'ready');
  const alters = log.map((s, i) => [s, i] as const).filter(([s]) => /^\s*ALTER TABLE/i.test(s) && s.includes(SEALED_DIGEST_COLUMN));
  assert.equal(alters.length, 4);
  const lt = log.findIndex((s) => s === `SELECT set_config('lock_timeout', '5s', true)`);
  assert.ok(lt >= 0 && lt < alters[0]![1], 'lock_timeout first');
  assert.ok(log.findIndex((s, i) => i > alters[3]![1] && /set_config\('lock_timeout', \$1, true\)/.test(s)) > 0, 'then restored');
});

test('§7 item 17 (R3-2 counts): readOverlayState counts source_sha256_ct as a ciphertext value; unflip\'s guard refuses a decrypted-shape table with one digest copy left', async () => {
  // Mutant: leave source_sha256_ct out of ctValues -> the count is one short and unflip would apply, red.
  const t = await newWorkspace(f, 'on');
  await f.ww.sync(callerOf(t), [hqItem('journal', '2026-11-21-r.md', 'R', 'one')], []);
  const notes = (await owner(() => readOverlayState(f.db, t))).tables.find((x) => x.table === 'notes')!;
  assert.equal(notes.ctValues, OVERLAY_SPEC.find((s) => s.table === 'notes')!.columns.length + 1, 'five spec values + the copy');
  // A plain workspace, prepared, with one plain note whose copy was left behind (the plain CHECK dropped by hand to
  // build the shape), in `decrypted`: the only ciphertext left is the copy.
  const v = await newWorkspace(f, 'off');
  await f.ww.sync(callerOf(v), [hqItem('journal', '2026-11-21-v.md', 'V', 'plain')], []);
  assert.equal((await f.dir.overlayStep(v, 'prepare', { dryRun: false })).outcome, 'applied');
  await owner(async () => {
    await f.db.exec(`ALTER TABLE "${v}".notes DROP CONSTRAINT ${sealedDigestPlainConstraint('notes')}`);
    await f.db.query(`UPDATE "${v}".notes SET source_sha256_ct = $1`, [sealedDummy(93)]);
  });
  await setState(f.db, v, 'decrypted');
  const r = await f.dir.overlayStep(v, 'unflip', { dryRun: true });
  assert.equal(r.outcome, 'refused');
  assert.match(r.reason!, /ciphertext left \(notes 1\)/);
});

test('migration reversibility: a reverted-image write (a sealed row without source_sha256_ct, by raw SQL) is accepted and counted digest_missing by --all; the documented DROP returns the tables to their pre-U1 columns and constraints; every migration from 0013 has its ROLLBACK file and none is above 0017', async () => {
  // Mutants: add NOT NULL on the sealed side -> the reverted write fails, red; add a 0018 without a rollback file -> red.
  const t = await newWorkspace(f, 'on');
  const all0 = await encryptStatusAll(f.dir);
  const run = (await q1<{ id: number }>(`SELECT max(id)::int AS id FROM "${t}".ingest_runs`))[0]!.id;
  await owner(() => f.db.query(
    `INSERT INTO "${t}".facts (kind, text_ct, scope, source_kind, source_uri_ct, source_uri_hmac, source_ts, source_sha256, ingest_run_id, key_version)
     VALUES ('rule', $1, 'personal', 'manual', $2, $3, now(), $4, $5, 1)`, [sealedDummy(), sealedDummy(), mac(), mac(), run]));
  assert.equal((await owner(() => readWorkspaceDigest(f.db, t))).missing, 1);
  assert.equal((await encryptStatusAll(f.dir)).digestMissing, all0.digestMissing + 1, '--all counts it');
  // The documented DROP: everything else of the four tables stays exactly as it was.
  const shape = async () => q1<{ x: string }>(
    `SELECT c.relname || '.' || k.conname AS x FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND c.relname = ANY ($2::text[])
     UNION ALL SELECT c.relname || '.' || a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND c.relname = ANY ($2::text[]) AND a.attnum > 0 AND NOT a.attisdropped ORDER BY 1`, [t, [...SEALED_DIGEST_TABLES]]);
  const s0 = (await shape()).map((r) => r.x);
  await dropDigest(t);
  const s1 = (await shape()).map((r) => r.x);
  assert.deepEqual(s1, s0.filter((x) => !x.includes('source_sha256_ct')));
  assert.equal(s0.length - s1.length, 12);
  assert.equal((await owner(() => readWorkspaceDigest(f.db, t))).missing, 1, 'a sealed row in a table without the column still counts as missing');
  const files = readdirSync('migrations');
  const nums = files.map((x) => /^(\d{4})_.*\.sql$/.exec(x)?.[1]).filter((x): x is string => x !== undefined).map(Number);
  assert.equal(Math.max(...nums), 17, 'C8-0 adds no migration file');
  for (const n of nums.filter((x) => x >= 13)) assert.ok(files.includes(`ROLLBACK-${String(n).padStart(4, '0')}.md`), `ROLLBACK-${n}`);
});
