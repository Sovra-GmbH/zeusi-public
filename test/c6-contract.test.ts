// C6 Preconditions 2 (docs/plans/2026-11-19-c6-write-path.md): the merged C5 code matches the contract
// the C6 write path is built on (docs/plans/2026-11-19-c5-tenant-ddl.md KTD2, KTD3, KTD5, KTD7). If one
// of these goes red, C5 changed shape: amend the C6 plan before touching the write path. Dummy bytes of
// the right shape only (no key); PGlite with the real migrations and tenant logins. No network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type { Db } from '../src/db.ts';
import { ENC_PROGRESS_TABLE } from '../src/tenant-ddl.ts';
import { OVERLAY_SPEC, OVERLAY_TABLES } from '../src/tenant-overlay.ts';
import { TenantDirectory } from '../src/tenants.ts';
import { asLogin, asOwner, tenantTestDb } from './helpers/tenant-fixture.ts';

let db: Db;
let P: string;

before(async () => {
  db = await tenantTestDb({ writer: true });
  const dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  P = ((await dir.provision('github:6601')) as { tenantId: string }).tenantId;
  const r = await dir.overlayStep(P, 'prepare', { dryRun: false });
  assert.equal(r.outcome, 'applied');
});
after(async () => {
  await db.close();
});

const sealed = () => Buffer.concat([Buffer.from([1]), randomBytes(12 + 9 + 16)]);
const mac = () => randomBytes(32);
const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? (e as Error).name;
  }
};

test('C6 contract (a): OVERLAY_SPEC lists exactly the columns of C5 KTD2 (plain, required/optional, hmac)', () => {
  // C5 KTD2 table, copied by hand: [plain, required, hmac].
  const KTD2: Record<string, Array<[string, boolean, boolean]>> = {
    notes: [['title', true, false], ['body', true, false], ['frontmatter', true, false], ['vault_path', true, true], ['source_uri', true, true]],
    chunks: [['heading_path', false, false], ['text', true, true], ['source_uri', true, true]],
    facts: [['subject', false, false], ['text', true, false], ['source_uri', true, true]],
    decisions: [
      ['exact_words', true, false], ['applies_to', true, false], ['expires_rule', false, false], ['linked_repo', false, false], ['linked_job', false, false],
      ['source_uri', true, true],
    ],
    decision_links: [['target_uri', true, true], ['source_uri', true, true]],
  };
  assert.deepEqual([...OVERLAY_TABLES], Object.keys(KTD2));
  for (const t of OVERLAY_SPEC) {
    assert.deepEqual(t.columns.map((c) => [c.plain, c.required, c.hmac === true]), KTD2[t.table], t.table);
  }
  assert.deepEqual(OVERLAY_SPEC.find((t) => t.table === 'chunks')!.derived, ['text_sha256', 'embedding']);
  // Defaults dropped at prepare (an encrypted INSERT must pass them explicitly): frontmatter and applies_to.
  assert.deepEqual(OVERLAY_SPEC.flatMap((t) => t.columns.filter((c) => c.dropDefault).map((c) => `${t.table}.${c.plain}`)), ['notes.frontmatter', 'decisions.applies_to']);
});

test('C6 contract (b): enc_progress has PK (key_version, table_name), accepts the five table names, and phase has a default', async () => {
  await asOwner(db, async () => {
    const pk = (await db.query<{ cols: string[] }>(
      `SELECT ARRAY(SELECT a.attname::text FROM unnest(k.conkey) WITH ORDINALITY u(n, o) JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.n ORDER BY u.o) AS cols
         FROM pg_constraint k WHERE k.conrelid = format('%I.%I', $1::text, $2::text)::regclass AND k.contype = 'p'`, [P, ENC_PROGRESS_TABLE])).rows;
    assert.deepEqual(pk.map((r) => r.cols), [['key_version', 'table_name']]);
    await db.exec('BEGIN');
    try {
      for (const t of OVERLAY_TABLES) {
        await db.query(`INSERT INTO "${P}".${ENC_PROGRESS_TABLE} (key_version, table_name, values_sealed) VALUES (1, $1, 3)`, [t]);
      }
      const rows = (await db.query<{ t: string; phase: string }>(`SELECT table_name AS t, phase FROM "${P}".${ENC_PROGRESS_TABLE} ORDER BY 1`)).rows;
      assert.deepEqual(rows.map((r) => r.t), [...OVERLAY_TABLES].sort());
      assert.ok(rows.every((r) => r.phase === 'idle'), 'phase defaults');
      assert.equal(await code(db.query(`INSERT INTO "${P}".${ENC_PROGRESS_TABLE} (key_version, table_name) VALUES (1, 'notes')`)), '23505');
    } finally {
      await db.exec('ROLLBACK');
    }
  });
});

test('C6 contract (c) + (d): a sealed chunk without source_uri_ct is refused (KTD5); a half-sealed row is refused (KTD3)', async () => {
  await asOwner(db, async () => {
    const s = `"${P}"`;
    const run = (await db.query<{ id: number }>(`INSERT INTO ${s}.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    const note = async (half: boolean) => db.query<{ id: number }>(
      `INSERT INTO ${s}.notes (file_mtime, scope, source_kind, source_ts, source_sha256, ingest_run_id, key_version,
                               title, title_ct, body_ct, frontmatter_ct, vault_path_ct, source_uri_ct, vault_path_hmac, source_uri_hmac)
       VALUES (now(), 'personal', 'manual', now(), $1, $2, 1, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id::int AS id`,
      [mac(), run, half ? 'plain title' : null, sealed(), sealed(), sealed(), sealed(), sealed(), mac(), mac()]);
    // (d) key_version set while a plain content column is also set.
    assert.equal(await code(note(true)), '23514');
    const nid = (await note(false)).rows[0]!.id;
    const chunk = (withUri: boolean) => db.query(
      `INSERT INTO ${s}.chunks (note_id, chunk_index, token_count, key_version, text_ct, source_uri_ct, text_hmac, source_uri_hmac)
       VALUES ($1, 0, 1, 1, $2, $3, $4, $5)`, [nid, sealed(), withUri ? sealed() : null, mac(), mac()]);
    // (c) no source_uri_ct on an encrypted chunk.
    assert.equal(await code(chunk(false)), '23514');
    assert.equal(await code(chunk(true)), 'ok');
    // (d) also: a plain row carrying an HMAC.
    assert.equal(await code(db.query(
      `INSERT INTO ${s}.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id, source_uri_hmac)
       VALUES ('rule', 'x', 'personal', 'manual', 'test:f', now(), $1, $2, $3)`, [mac(), run, mac()])), '23514');
  });
});
