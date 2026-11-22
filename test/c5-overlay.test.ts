// C5 (docs/plans/2026-11-19-c5-tenant-ddl.md; parent plan §4.6, §5.2a, §7 items 2, 10, 17, §8.1): the
// tenant schema overlay (prepare, flip, relax, rollback-start, unflip) and flag-`on` provisioning, on
// PGlite with the real migrations, the real tenant logins and the writer login
// (test/helpers/tenant-fixture.ts). Ciphertext and HMACs here are dummy bytes of the right shape: no
// key, no C6/C8 code. No network, no Neon, no real workspace.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Db } from '../src/db.ts';
import { FORMAT_V1, MAX_KEY_VERSION, NONCE_BYTES, TAG_BYTES } from '../src/crypto-envelope.ts';
import { QueryLedger, search } from '../src/search.ts';
import { ENC_PROGRESS_TABLE, TENANT_ACL_AUDIT_SQL, tenantRole, tenantWriterRole } from '../src/tenant-ddl.ts';
import {
  flipStatements, formatOverlayStep, HMAC_BYTES, OVERLAY_MAX_KEY_VERSION, OVERLAY_SPEC, offPathAllowed, prepareStatements, readOverlayState,
  relaxStatements, SEALED_FORMAT_BYTE, SEALED_MIN_BYTES, unflipStatements,
} from '../src/tenant-overlay.ts';
import {
  ENC_STATES, overlayGuard, OVERLAY_STEP_FROM, OVERLAY_STEPS, TenantDirectory, TenantError, TenantRouter, TenantWriter, TENANT_WR_ROLE,
  type EncState,
} from '../src/tenants.ts';
import { enrollmentWraps } from '../src/workspace-keys.ts';
import { WorkspaceWrites } from '../src/workspace-write.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, plantTeam, tenantTestDb } from './helpers/tenant-fixture.ts';

/** One lexical token in every planted content value: a leak is a substring match. */
const CANARY = 'c5canarywombat';
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

let db: Db;
let dir: TenantDirectory;
let dirOn: TenantDirectory;
let router: TenantRouter;
let writer: TenantWriter;
let ww: WorkspaceWrites;
let OFF: string; // flag off, never overlaid
let P: string; // the prepare -> flip -> relax -> unflip cycle
let R: string; // the R3-2 pre-flip rollback
let BORN: string; // flag on
let team0: string;
type Shape = Record<'columns' | 'relations' | 'constraints' | 'functions' | 'triggers' | 'defaults', string[]>;
let zeusiShape0: Shape;

const caller = (tenantId: string, n: number) => ({
  tenantId, grantId: `grant${String(n).padStart(19, '0')}`, subject: `github:${n}`, requestId: null,
});

before(async () => {
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  dirOn = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin'), bornEncrypted: true });
  router = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt'), cacheMs: 0 });
  writer = new TenantWriter({ connectWriter: asLogin(db, TENANT_WR_ROLE), check: (t) => router.check(t) });
  ww = new WorkspaceWrites({ workRoot: join(safeMkdtemp(join(tmpdir(), 'zeusi-c5-')), 'workspace-import'), openWrite: (t) => writer.open(t), encState: (t) => router.encState(t) });
  team0 = await teamSnapshot();
  zeusiShape0 = await shape('zeusi');
  OFF = ((await dir.provision('github:5101')) as { tenantId: string }).tenantId;
  P = ((await dir.provision('github:5102')) as { tenantId: string }).tenantId;
  R = ((await dir.provision('github:5104')) as { tenantId: string }).tenantId;
  await plantContent(P);
  await plantContent(R);
});
after(async () => {
  ww.close();
  await db.close();
});

// ---------------------------------------------------------------------------
// Helpers (as the PGlite superuser = the schema owner's view)

const one = async <T>(sql: string, params: unknown[] = []) => asOwner(db, async () => (await db.query<T>(sql, params)).rows[0]!);
const all = async <T>(sql: string, params: unknown[] = []) => asOwner(db, async () => (await db.query<T>(sql, params)).rows);
const state = async (t: string) => (await one<{ s: EncState }>(`SELECT enc_state AS s FROM zeusi_tenants.tenants WHERE tenant_id = $1`, [t])).s;
const setState = (t: string, s: EncState) => asOwner(db, async () => {
  await db.query(`UPDATE zeusi_tenants.tenants SET enc_state = $2 WHERE tenant_id = $1`, [t, s]);
});
const audit = (t: string) => all(TENANT_ACL_AUDIT_SQL, [t, tenantRole(t)]);
const sealed = () => Buffer.concat([Buffer.from([1]), randomBytes(12 + 9 + 16)]);
const mac = () => randomBytes(32);
const sqlState = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? (e as Error).name;
  }
};
const apply = (t: string, step: (typeof OVERLAY_STEPS)[number]) => dir.overlayStep(t, step, { dryRun: false });

async function shape(schema: string): Promise<Shape> {
  return asOwner(db, async () => {
    const rows = async (sql: string) => (await db.query<{ x: string }>(sql, [schema])).rows.map((r) => r.x.split(`${schema}.`).join('zeusi.')).sort();
    return {
      columns: await rows(`SELECT table_name || '.' || column_name || ':' || data_type || ':' || is_nullable AS x FROM information_schema.columns WHERE table_schema = $1 AND table_name <> 'schema_migrations'`),
      relations: await rows(`SELECT c.relname || ':' || c.relkind::text AS x FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname NOT LIKE 'schema_migrations%'`),
      constraints: await rows(`SELECT c.relname || '.' || k.conname || ':' || k.contype::text AS x FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname <> 'schema_migrations'`),
      functions: await rows(`SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' || p.prosecdef::text AS x FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1`),
      triggers: await rows(`SELECT c.relname || '.' || t.tgname AS x FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND NOT t.tgisinternal`),
      defaults: await rows(`SELECT table_name || '.' || column_name || '=' || coalesce(column_default, '-') AS x FROM information_schema.columns WHERE table_schema = $1 AND table_name <> 'schema_migrations'`),
    };
  });
}

async function teamSnapshot(): Promise<string> {
  return asOwner(db, async () => JSON.stringify({
    acl: (await db.query(`SELECT c.relname, c.relacl::text AS acl, c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'zeusi' ORDER BY 1`)).rows,
    fns: (await db.query(`SELECT p.proname, p.proacl::text AS acl, md5(p.prosrc) AS src FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'zeusi' ORDER BY 1, 2, 3`)).rows,
    cons: (await db.query(`SELECT k.conname, pg_get_constraintdef(k.oid) AS d FROM pg_constraint k JOIN pg_namespace n ON n.oid = k.connamespace WHERE n.nspname = 'zeusi' ORDER BY 1, 2`)).rows,
    policies: (await db.query(`SELECT tablename, policyname, roles::text, qual FROM pg_policies WHERE schemaname = 'zeusi' ORDER BY 1, 2`)).rows,
    rows: (await db.query(`SELECT (SELECT md5(string_agg(to_jsonb(x)::text, '' ORDER BY id)) FROM zeusi.notes x) n, (SELECT md5(string_agg(to_jsonb(x)::text, '' ORDER BY id)) FROM zeusi.chunks x) c,
                                  (SELECT count(*) FROM zeusi.schema_migrations)::int m`)).rows,
  }));
}

/** Plain rows in every overlay table plus a quarantine row and a wall_allow row (as the owner). */
async function plantContent(t: string): Promise<void> {
  await asOwner(db, async () => {
    const s = `"${t}"`;
    const run = (await db.query<{ id: number }>(`INSERT INTO ${s}.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    const me = (await db.query<{ id: number }>(`SELECT id::int AS id FROM ${s}.people WHERE handle = 'me'`)).rows[0]!.id;
    for (const [i, path] of ['mine/a.md', 'mine/b.md'].entries()) {
      const nid = (await db.query<{ id: number }>(
        `INSERT INTO ${s}.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ($1, $2, $3::jsonb, $4, now(), 'personal', 'manual', $5, now(), sha256(convert_to($4, 'UTF8')), $6) RETURNING id::int AS id`,
        [path, `title ${i} ${CANARY}`, JSON.stringify({ locks: [`lock ${CANARY}`] }), `body ${i} ${CANARY}`, `vault:${path}`, run])).rows[0]!.id;
      await db.query(`INSERT INTO ${s}.chunks (note_id, chunk_index, heading_path, text, token_count) VALUES ($1, 0, 'Head', $2, 3)`, [nid, `chunk ${i} ${CANARY}`]);
    }
    await db.query(`INSERT INTO ${s}.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                    VALUES ('rule', 'subj', $1, 'personal', 'manual', 'test:fact', now(), sha256(convert_to($1, 'UTF8')), $2)`, [`fact ${CANARY}`, run]);
    const did = (await db.query<{ id: number }>(
      `INSERT INTO ${s}.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('lock', $1, now(), 'minute', $2, true, '{alpha}', 'personal', 'manual', 'test:decision', now(), sha256(convert_to($2, 'UTF8')), $3) RETURNING id::int AS id`,
      [me, `decision ${CANARY}`, run])).rows[0]!.id;
    await db.query(`INSERT INTO ${s}.decision_links (decision_id, target_kind, target_uri, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                    VALUES ($1, 'note', 'vault:mine/a.md', 'personal', 'manual', 'test:decision', now(), sha256(convert_to('l', 'UTF8')), $2)`, [did, run]);
    await db.query(`INSERT INTO ${s}.quarantine (source_kind, source_uri, source_sha256) VALUES ('manual', 'test:q', sha256(convert_to('q', 'UTF8')))`);
    await db.query(`INSERT INTO ${s}.wall_allow (source_uri, content_sha256, rule_id)
                    SELECT 'test:allow', sha256(convert_to('a', 'UTF8')), id FROM ${s}.wall_denylist WHERE NOT hard ORDER BY id LIMIT 1`);
  });
}

const originals = new Map<string, Record<string, unknown>>();

/** Encrypt-shaped UPDATE (plan §5.2 step 4.2): one statement sets every _ct / _hmac / key_version and NULLs the plain text. */
async function encryptRows(t: string, keyVersion = 1, only?: string): Promise<void> {
  await asOwner(db, async () => {
    for (const spec of ['notes', 'facts', 'decisions', 'chunks', 'decision_links'].map((n) => OVERLAY_SPEC.find((x) => x.table === n)!)) {
      if (only && spec.table !== only) continue;
      const ids = (await db.query<{ id: number; j: Record<string, unknown> }>(`SELECT id::int AS id, to_jsonb(x) AS j FROM "${t}".${spec.table} x WHERE key_version IS NULL ORDER BY id`)).rows;
      for (const r of ids) {
        originals.set(`${t}.${spec.table}.${r.id}`, r.j);
        const sets: string[] = [`key_version = ${keyVersion}`, 'source_sha256 = $1'];
        const params: unknown[] = [mac()];
        for (const c of spec.columns) {
          params.push(sealed());
          sets.push(`${c.plain}_ct = $${params.length}`, `${c.plain} = NULL`);
          if (c.hmac) {
            params.push(mac());
            sets.push(`${c.plain}_hmac = $${params.length}`);
          }
        }
        params.push(r.id);
        await db.query(`UPDATE "${t}".${spec.table} SET ${sets.join(', ')} WHERE id = $${params.length}`, params);
      }
    }
  });
}

/** Decrypt-shaped UPDATE (C8b contract R3-3): plain values and plain source_sha256 back, every _ct / _hmac / key_version NULL. */
async function decryptRows(t: string, only?: string): Promise<void> {
  await asOwner(db, async () => {
    for (const spec of ['notes', 'facts', 'decisions', 'chunks', 'decision_links'].map((n) => OVERLAY_SPEC.find((x) => x.table === n)!)) {
      if (only && spec.table !== only) continue;
      const ids = (await db.query<{ id: number }>(`SELECT id::int AS id FROM "${t}".${spec.table} WHERE key_version IS NOT NULL ORDER BY id`)).rows;
      for (const { id } of ids) {
        const j = originals.get(`${t}.${spec.table}.${id}`)!;
        const cols = [...spec.columns.map((c) => c.plain), 'source_sha256'];
        const nulls = ['key_version', ...spec.columns.map((c) => `${c.plain}_ct`), ...spec.columns.filter((c) => c.hmac).map((c) => `${c.plain}_hmac`)];
        await db.query(
          `UPDATE "${t}".${spec.table} AS x SET ${cols.map((c) => `${c} = r.${c}`).join(', ')}, ${nulls.map((c) => `${c} = NULL`).join(', ')}
             FROM jsonb_populate_record(NULL::"${t}".${spec.table}, $1::jsonb) AS r WHERE x.id = $2`, [JSON.stringify(j), id]);
      }
    }
  });
}

const insertPlainNote = (t: string, path: string) => asOwner(db, async () => {
  const run = (await db.query<{ id: number }>(`SELECT max(id)::int AS id FROM "${t}".ingest_runs`)).rows[0]!.id;
  await db.query(`INSERT INTO "${t}".notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ($1, 'late', '{}', 'late body', now(), 'personal', 'manual', 'test:late', now(), sha256(convert_to('late', 'UTF8')), $2)`, [path, run]);
});

// ---------------------------------------------------------------------------

test('C5 constants: the overlay literals equal the C1 envelope; every builder refuses a non-workspace schema', () => {
  assert.equal(SEALED_FORMAT_BYTE, FORMAT_V1);
  assert.equal(SEALED_MIN_BYTES, 1 + NONCE_BYTES + TAG_BYTES);
  assert.equal(OVERLAY_MAX_KEY_VERSION, MAX_KEY_VERSION);
  assert.equal(HMAC_BYTES, 32);
  for (const f of [prepareStatements, flipStatements, relaxStatements, (s: string) => unflipStatements(s, { tsv: true, tsvIndex: true, hnsw: true, uniques: [], targetUriIndex: true })]) {
    for (const bad of ['zeusi', 'zeusi_tenants', 'public', `zt_${'a'.repeat(25)}`]) assert.throws(() => f(bad), /not a workspace id/);
  }
  // No overlay statement names the zeusi schema (the overlay is tenant-only, plan §5.2a).
  const S = `zt_${'b'.repeat(26)}`;
  const text = [...prepareStatements(S), ...flipStatements(S), ...relaxStatements(S), ...unflipStatements(S, { tsv: false, tsvIndex: false, hnsw: false, uniques: [], targetUriIndex: false })].join('\n');
  assert.doesNotMatch(text, /\bzeusi\./);
  assert.ok(readdirSync('migrations').every((f) => !/overlay|c5/i.test(f)), 'no migration file: the team keeps the migrations unchanged');
});

test('C5 flag off (§7.17 N2-5): provisioning has no overlay and no enc_progress, enc_state off; ensureWriter ready; ACL audit clean', async () => {
  const st = await asOwner(db, async () => readOverlayState(db, OFF));
  assert.equal(st.prepared, false);
  assert.equal(st.encProgress, false);
  assert.equal(st.flipChecks, 0);
  assert.equal(await state(OFF), 'off');
  assert.deepEqual(await shape(OFF), zeusiShape0, 'flag-off workspace = the team migrations, no overlay');
  assert.deepEqual(await audit(OFF), []);
  assert.equal(await dir.ensureWriter(OFF), 'ready');
  assert.deepEqual(await audit(OFF), []);
});

test('C5a prepare (§7.17): every existing plain row stays valid and reads the same; shape = the team migrations + the exact overlay delta', async () => {
  const before0 = await shape(P);
  assert.deepEqual(before0, zeusiShape0);
  const cols = (await all<{ table_name: string; column_name: string }>(`SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name IN ('notes', 'chunks', 'facts', 'decisions', 'decision_links')`, [P]))
    .reduce<Record<string, string[]>>((m, r) => ({ ...m, [r.table_name]: [...(m[r.table_name] ?? []), r.column_name] }), {});
  const rowsOf = async () => {
    const out: Record<string, string> = {};
    for (const [tb, cs] of Object.entries(cols)) {
      out[tb] = JSON.stringify(await all(`SELECT ${cs.filter((c) => c !== 'tsv' && c !== 'embedding').map((c) => `"${c}"`).join(', ')} FROM "${P}".${tb} ORDER BY id`));
    }
    return out;
  };
  const rows0 = await rowsOf();
  const dry = await dir.overlayStep(P, 'prepare', { dryRun: true });
  assert.equal(dry.outcome, 'would_apply');
  assert.equal((await asOwner(db, async () => readOverlayState(db, P))).prepared, false, 'a dry run changes nothing');
  const r = await apply(P, 'prepare');
  assert.equal(r.outcome, 'applied');
  assert.equal(r.from, 'off');
  assert.equal(r.to, 'off', 'prepare does not move the state');
  assert.equal(await state(P), 'off');
  assert.deepEqual(await rowsOf(), rows0, 'every plain row reads exactly the same');
  // Shape: the team migrations + overlay, spelled out here (not derived from OVERLAY_SPEC).
  const added: Record<string, string[]> = {
    notes: ['title_ct', 'body_ct', 'frontmatter_ct', 'vault_path_ct', 'source_uri_ct', 'vault_path_hmac', 'source_uri_hmac'],
    chunks: ['heading_path_ct', 'text_ct', 'source_uri_ct', 'text_hmac', 'source_uri_hmac'],
    facts: ['subject_ct', 'text_ct', 'source_uri_ct', 'source_uri_hmac'],
    decisions: ['exact_words_ct', 'applies_to_ct', 'expires_rule_ct', 'linked_repo_ct', 'linked_job_ct', 'source_uri_ct', 'source_uri_hmac'],
    decision_links: ['target_uri_ct', 'source_uri_ct', 'target_uri_hmac', 'source_uri_hmac'],
  };
  const nowNullable: Record<string, string[]> = {
    notes: ['title', 'body', 'frontmatter', 'vault_path', 'source_uri'], chunks: ['text', 'text_sha256', 'source_uri'], facts: ['text', 'source_uri'],
    decisions: ['exact_words', 'applies_to', 'source_uri'], decision_links: ['target_uri', 'source_uri'],
  };
  const expectCols = zeusiShape0.columns.map((c) => {
    const [tc, type] = c.split(':');
    const [tb, col] = tc!.split('.');
    return nowNullable[tb!]?.includes(col!) ? `${tc}:${type}:YES` : c;
  });
  for (const [tb, cs] of Object.entries(added)) {
    expectCols.push(`${tb}.key_version:smallint:YES`, ...cs.map((c) => `${tb}.${c}:bytea:YES`));
  }
  // C8-0 KTD-A (docs/plans/2026-11-21-c8-refresh.md), changed on purpose: prepare also adds the sealed digest copy
  // (an idempotent add-on, not part of the prepare template) to the four tables that carry source_sha256.
  for (const tb of ['notes', 'facts', 'decisions', 'decision_links']) expectCols.push(`${tb}.source_sha256_ct:bytea:YES`);
  for (const c of ['key_version:smallint', 'table_name:text', 'phase:text', 'cursor_id:bigint', 'rows_done:bigint', 'rows_skipped:bigint', 'rows_mismatched:bigint', 'values_sealed:bigint', 'updated_at:timestamp with time zone']) {
    expectCols.push(`enc_progress.${c.split(':')[0]}:${c.split(':')[1]}:NO`);
  }
  // C7 KTD5 (docs/plans/2026-11-19-c7-read-path.md), changed on purpose: prepare also creates the B1 index table.
  for (const c of ['key_version:smallint', 'kind:text', 'shard_no:integer', 'generation:bigint', 'blob_ct:bytea', 'updated_at:timestamp with time zone']) {
    expectCols.push(`b1_index.${c.split(':')[0]}:${c.split(':')[1]}:NO`);
  }
  const after0 = await shape(P);
  assert.deepEqual(after0.columns, expectCols.sort());
  assert.deepEqual(after0.relations, [...zeusiShape0.relations, 'enc_progress:r', 'enc_progress_pkey:i', 'notes_vault_path_hmac_key:i', 'facts_source_uri_hmac_source_sha256_key:i',
    'decisions_source_uri_hmac_source_sha256_key:i', 'decision_links_decision_id_target_uri_hmac_key:i', 'b1_index:r', 'b1_index_pkey:i'].sort());
  assert.deepEqual(after0.functions, zeusiShape0.functions, 'functions replaced in place (same signatures), none added');
  assert.deepEqual(after0.triggers, zeusiShape0.triggers);
  assert.deepEqual(after0.defaults.filter((d) => !zeusiShape0.defaults.includes(d)).filter((d) => !d.startsWith('enc_progress.') && !d.startsWith('b1_index.') && !/_ct=-|_hmac=-|key_version=-/.test(d)),
    ['decisions.applies_to=-', 'notes.frontmatter=-'], 'only the two plan defaults are dropped');
  assert.equal(after0.constraints.filter((c) => !zeusiShape0.constraints.includes(c)).filter((c) => /_enc_shape:c$/.test(c)).length, 5);
  // Prepare twice: refused, nothing changes.
  const again = await apply(P, 'prepare');
  assert.equal(again.outcome, 'refused');
  assert.match(again.reason!, /already prepared/);
  assert.equal(await teamSnapshot(), team0, 'the zeusi schema byte-identical');
  assert.deepEqual(await shape('zeusi'), zeusiShape0);
});

test('C5a prepare: the off importer and the off search still run on a prepared workspace (commit + sync through the real pipeline)', async () => {
  const p = await ww.preview(caller(P, 5102), [{ kind: 'markdown', title: 'Prepared', text: `prepared note ${CANARY}\n` }]);
  assert.equal(p.status, 'preview');
  if (p.status !== 'preview') return;
  const c = await ww.commit(caller(P, 5102), p.preview_id);
  assert.equal(c.notes.inserted, 1);
  const hq = { path: 'journal/2026-11-19-day.md', text: `---\nproject: journal\nkind: memory\ndate: 2026-11-19\ntitle: Day\nsource: assistant\n---\nsynced ${CANARY}\n` };
  assert.equal((await ww.sync(caller(P, 5102), [hq], [])).counts.inserted, 1);
  assert.equal((await ww.sync(caller(P, 5102), [{ ...hq, text: `${hq.text}more\n` }], [])).counts.updated, 1, 'ON CONFLICT (vault_path) upsert');
  const rdb = await router.open(P);
  try {
    const s = await search({ db: rdb, query: CANARY, client: null, ledger: new QueryLedger(join(safeMkdtemp(join(tmpdir(), 'zeusi-c5-l-')), 'l.json')) });
    assert.ok(s.hits.length >= 1, 'c.tsv search works');
  } finally {
    await rdb.close();
  }
});

test('C5a prepare (§7.17, §7.10): ACL audit clean with enc_progress; ensureWriter re-run ready; RLS off and no read-role grant on enc_progress; writer has no DDL', async () => {
  assert.deepEqual(await audit(P), []);
  assert.equal(await dir.ensureWriter(P), 'ready');
  assert.deepEqual(await audit(P), []);
  const w = tenantWriterRole(P);
  const r = await one<{ rls: boolean; rsel: boolean; wsel: boolean; wins: boolean; wupd: boolean; wdel: boolean; wcreate: boolean }>(
    `SELECT c.relrowsecurity AS rls, has_table_privilege($2::text, c.oid, 'SELECT') AS rsel, has_table_privilege($3::text, c.oid, 'SELECT') AS wsel,
            has_table_privilege($3::text, c.oid, 'INSERT') AS wins, has_table_privilege($3::text, c.oid, 'UPDATE') AS wupd,
            has_table_privilege($3::text, c.oid, 'DELETE') AS wdel, has_schema_privilege($3::text, $1::text, 'CREATE') AS wcreate
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $4`, [P, tenantRole(P), w, ENC_PROGRESS_TABLE]);
  assert.deepEqual(r, { rls: false, rsel: false, wsel: true, wins: true, wupd: true, wdel: false, wcreate: false });
  // The writer cannot change the schema (owner-only DDL).
  const wdb = await writer.open(P);
  try {
    assert.equal(await sqlState(wdb.exec('ALTER TABLE zeusi.notes DROP CONSTRAINT notes_enc_shape')), '42501');
  } finally {
    await wdb.close();
  }
  // The read session check is unchanged and still passes (no write privilege for the read role).
  const rdb = await router.open(P);
  await rdb.close();
  // A grant beyond the allowed writer set on enc_progress is caught by the audit.
  await asOwner(db, async () => db.exec(`GRANT DELETE ON "${P}".enc_progress TO "${w}"`));
  assert.deepEqual((await audit(P)).map((x) => (x as { name: string }).name), ['enc_progress']);
  await asOwner(db, async () => db.exec(`REVOKE DELETE ON "${P}".enc_progress FROM "${w}"`));
  assert.deepEqual(await audit(P), []);
});

test('C5a R3-5: drop and re-create the writer of a prepared workspace; ensureWriter restores the enc_progress grant; a real writer session writes a counter row', async () => {
  const w = tenantWriterRole(P);
  await asOwner(db, async () => db.exec(`DROP OWNED BY "${w}"; DROP ROLE "${w}"`));
  assert.equal((await one<{ n: number }>(`SELECT count(*)::int AS n FROM pg_roles WHERE rolname = $1`, [w])).n, 0);
  assert.equal(await dir.ensureWriter(P), 'ready');
  const g = await one<{ s: boolean; i: boolean; u: boolean }>(
    `SELECT has_table_privilege($1::text, $2::text, 'SELECT') AS s, has_table_privilege($1::text, $2::text, 'INSERT') AS i, has_table_privilege($1::text, $2::text, 'UPDATE') AS u`,
    [w, `"${P}".enc_progress`]);
  assert.deepEqual(g, { s: true, i: true, u: true }, 'the grant is back (mutant: remove the writerIn hook)');
  assert.deepEqual(await audit(P), []);
  const wdb = await writer.open(P);
  try {
    await wdb.exec('BEGIN');
    await wdb.query(`INSERT INTO zeusi.enc_progress (key_version, table_name, phase) VALUES (1, 'all', 'idle')`);
    await wdb.query(`UPDATE zeusi.enc_progress SET values_sealed = values_sealed + 7, updated_at = now() WHERE key_version = 1 AND table_name = 'all'`);
    assert.equal(Number((await wdb.query<{ v: string }>(`SELECT values_sealed AS v FROM zeusi.enc_progress`)).rows[0]!.v), 7);
    assert.equal(await sqlState(wdb.query(`DELETE FROM zeusi.enc_progress`)), '42501', 'no DELETE for the writer');
  } finally {
    await wdb.close();
  }
  // backfill-writers also takes the hook (same writerIn).
  assert.equal((await dir.backfillWriters({ dryRun: false })).failed, 0);
});

test('C5a (§7.17 N2-3, R3-3): NULL plain with its _ct is accepted for decision_links and notes.frontmatter; mixed rows and plain rows with HMACs are refused', async () => {
  const s = `"${P}"`;
  const run = (await one<{ id: number }>(`SELECT max(id)::int AS id FROM ${s}.ingest_runs`)).id;
  const did = (await one<{ id: number }>(`SELECT id::int AS id FROM ${s}.decisions ORDER BY id LIMIT 1`)).id;
  const link = (p: { targetUri: string | null; targetCt: Buffer | null; targetMac: Buffer | null; srcUri: string | null; srcCt: Buffer | null; srcMac: Buffer | null; kv: number | null }) =>
    sqlState(asOwner(db, async () => db.query(
      `INSERT INTO ${s}.decision_links (decision_id, target_kind, target_uri, target_uri_ct, target_uri_hmac, source_uri, source_uri_ct, source_uri_hmac, key_version,
                                       scope, source_kind, source_ts, source_sha256, ingest_run_id)
       VALUES ($1, 'note', $2, $3, $4, $5, $6, $7, $8, 'personal', 'manual', now(), $9, $10)`,
      [did, p.targetUri, p.targetCt, p.targetMac, p.srcUri, p.srcCt, p.srcMac, p.kv, mac(), run])));
  assert.equal(await link({ targetUri: null, targetCt: sealed(), targetMac: mac(), srcUri: null, srcCt: sealed(), srcMac: mac(), kv: 1 }), 'ok', 'encrypted link accepted');
  assert.equal(await link({ targetUri: 'vault:mine/b.md', targetCt: sealed(), targetMac: mac(), srcUri: null, srcCt: sealed(), srcMac: mac(), kv: 1 }), '23514', 'plain + ct refused');
  assert.equal(await link({ targetUri: null, targetCt: null, targetMac: null, srcUri: null, srcCt: sealed(), srcMac: mac(), kv: 1 }), '23514', 'neither plain nor ct refused');
  assert.equal(await link({ targetUri: null, targetCt: sealed(), targetMac: mac(), srcUri: null, srcCt: sealed(), srcMac: mac(), kv: null }), '23514', 'ciphertext without key_version refused');
  assert.equal(await link({ targetUri: null, targetCt: sealed(), targetMac: null, srcUri: null, srcCt: sealed(), srcMac: mac(), kv: 1 }), '23514', 'encrypted link without its HMAC refused');
  assert.equal(await link({ targetUri: 'vault:mine/b.md', targetCt: null, targetMac: mac(), srcUri: 'test:x', srcCt: null, srcMac: null, kv: null }), '23514', 'plain row with an HMAC refused (R3-3)');
  assert.equal(await link({ targetUri: null, targetCt: Buffer.from([2, ...randomBytes(40)]), targetMac: mac(), srcUri: null, srcCt: sealed(), srcMac: mac(), kv: 1 }), '23514', 'wrong format byte refused');
  assert.equal(await link({ targetUri: null, targetCt: sealed(), targetMac: mac(), srcUri: null, srcCt: sealed(), srcMac: mac(), kv: 0 }), '23514', 'key_version 0 refused');
  // notes.frontmatter NULL with frontmatter_ct (and every other note column encrypted).
  const note = (fm: string | null, fmCt: Buffer | null) => sqlState(asOwner(db, async () => db.query(
    `INSERT INTO ${s}.notes (vault_path_ct, vault_path_hmac, title_ct, frontmatter, frontmatter_ct, body_ct, source_uri_ct, source_uri_hmac, key_version,
                             file_mtime, scope, source_kind, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, 1, now(), 'personal', 'manual', now(), $9, $10)`,
    [sealed(), mac(), sealed(), fm, fmCt, sealed(), sealed(), mac(), mac(), run])));
  assert.equal(await note(null, sealed()), 'ok');
  assert.equal(await note('{}', sealed()), '23514', 'a plain frontmatter on an encrypted note is refused');
  assert.equal(await note(null, null), '23514', 'frontmatter must be present in one form');
  // Clean up the encrypted rows (the cycle below expects only the planted plain rows).
  await asOwner(db, async () => {
    await db.exec(`DELETE FROM ${s}.decision_links WHERE key_version IS NOT NULL; DELETE FROM ${s}.notes WHERE key_version IS NOT NULL`);
  });
});

test('C5a chunks_inherit (§4.1a, §7.5): an encrypted chunk needs its own source_uri_ct; it inherits the parent HMACs, never a plain hash; a plain chunk is as before', async () => {
  const s = `"${P}"`;
  await encryptRows(P, 1, 'notes');
  const n = await one<{ id: number; h: Buffer; sha: Buffer }>(`SELECT id::int AS id, source_uri_hmac AS h, source_sha256 AS sha FROM ${s}.notes WHERE key_version IS NOT NULL ORDER BY id LIMIT 1`);
  // Refused by the trigger itself (its own message), even with the parent's plain-shape columns supplied.
  await assert.rejects(asOwner(db, async () => db.query(
    `INSERT INTO ${s}.chunks (note_id, chunk_index, text_ct, text_hmac, source_uri_hmac, token_count, key_version) VALUES ($1, 9, $2, $3, $4, 1, 1)`, [n.id, sealed(), mac(), mac()])),
  (e: unknown) => (e as { code?: string }).code === '23514' && /needs its own source_uri_ct/.test((e as Error).message), 'mutant: drop the trigger refusal');
  const c = await asOwner(db, async () => (await db.query<{ h: Buffer; sha: Buffer; tsha: Buffer | null; uri: string | null }>(
    `INSERT INTO ${s}.chunks (note_id, chunk_index, text_ct, text_hmac, text_sha256, source_uri_ct, token_count, key_version)
     VALUES ($1, 9, $2, $3, sha256(convert_to('guess', 'UTF8')), $4, 1, 1) RETURNING source_uri_hmac AS h, source_sha256 AS sha, text_sha256 AS tsha, source_uri AS uri`,
    [n.id, sealed(), mac(), sealed()])).rows[0]!);
  assert.ok(Buffer.from(c.h).equals(Buffer.from(n.h)), 'inherits the parent source_uri_hmac');
  assert.ok(Buffer.from(c.sha).equals(Buffer.from(n.sha)), 'inherits the parent source_sha256 (an HMAC on an encrypted parent)');
  assert.equal(c.tsha, null, 'no plain-text hash on an encrypted chunk, even when one is passed');
  assert.equal(c.uri, null);
  // A plain chunk under an encrypted parent inherits no plain uri: refused.
  assert.equal(await sqlState(asOwner(db, async () => db.query(`INSERT INTO ${s}.chunks (note_id, chunk_index, text, token_count) VALUES ($1, 8, 'plain', 1)`, [n.id]))), '23514');
  // Plain chunk under a plain parent: unchanged behaviour (uri copied, sha256(text) computed).
  await asOwner(db, async () => db.exec(`DELETE FROM ${s}.chunks WHERE chunk_index = 9`));
  await decryptRows(P, 'notes');
  const pn = await one<{ id: number; uri: string }>(`SELECT id::int AS id, source_uri AS uri FROM ${s}.notes ORDER BY id LIMIT 1`);
  const pc = await asOwner(db, async () => (await db.query<{ uri: string; ok: boolean }>(
    `INSERT INTO ${s}.chunks (note_id, chunk_index, text, token_count) VALUES ($1, 7, 'plain chunk', 1)
     RETURNING source_uri AS uri, text_sha256 = sha256(convert_to('plain chunk', 'UTF8')) AS ok`, [pn.id])).rows[0]!);
  assert.equal(pc.uri, pn.uri);
  assert.equal(pc.ok, true);
  await asOwner(db, async () => db.exec(`DELETE FROM ${s}.chunks WHERE chunk_index = 7`));
});

test('C5a stamp_provenance (§7.17 N2-11): encrypt, rotate and decrypt keep ingested_at/by; a real content change restamps; people keep the old rule', async () => {
  const s = `"${P}"`;
  const stamp = async () => all<{ id: number; at: string; by: string }>(`SELECT id::int AS id, ingested_at::text AS at, ingested_by AS by FROM ${s}.facts ORDER BY id`);
  // Set an old stamp with the trigger off (the trigger would keep OLD on an unchanged source_sha256).
  await asOwner(db, async () => db.exec(`ALTER TABLE ${s}.facts DISABLE TRIGGER zeusi_10_provenance; UPDATE ${s}.facts SET ingested_at = '2026-01-01T00:00:00Z', ingested_by = 'someone-earlier'; ALTER TABLE ${s}.facts ENABLE TRIGGER zeusi_10_provenance`));
  const s0 = await stamp();
  await encryptRows(P, 1, 'facts');
  assert.deepEqual(await stamp(), s0, 'encrypt keeps the stamp');
  // Rotate: new key_version, new ciphertext, new HMAC.
  await asOwner(db, async () => db.query(`UPDATE ${s}.facts SET key_version = 2, text_ct = $1, subject_ct = $2, source_uri_ct = $3, source_uri_hmac = $4, source_sha256 = $5`, [sealed(), sealed(), sealed(), mac(), mac()]));
  assert.deepEqual(await stamp(), s0, 'rotate keeps the stamp');
  // Content change under the same key_version: the HMAC-valued source_sha256 changes -> restamp.
  await asOwner(db, async () => db.query(`UPDATE ${s}.facts SET text_ct = $1, source_sha256 = $2`, [sealed(), mac()]));
  const s1 = await stamp();
  assert.ok(s1.every((r, i) => r.at !== s0[i]!.at), 'a content change restamps');
  await asOwner(db, async () => db.exec(`ALTER TABLE ${s}.facts DISABLE TRIGGER zeusi_10_provenance; UPDATE ${s}.facts SET ingested_at = '2026-01-01T00:00:00Z', ingested_by = 'someone-earlier'; ALTER TABLE ${s}.facts ENABLE TRIGGER zeusi_10_provenance`));
  await decryptRows(P, 'facts');
  assert.deepEqual(await stamp(), s0, 'decrypt keeps the stamp');
  // A plain content change still restamps.
  await asOwner(db, async () => db.exec(`UPDATE ${s}.facts SET text = text || ' x', source_sha256 = sha256(convert_to(text || ' x', 'UTF8'))`));
  assert.ok((await stamp()).every((r, i) => r.at !== s0[i]!.at));
  // people (no key_version column): unchanged rule, no error.
  const p0 = await one<{ at: string }>(`SELECT ingested_at::text AS at FROM ${s}.people WHERE handle = 'me'`);
  await asOwner(db, async () => db.exec(`UPDATE ${s}.people SET kind = 'human' WHERE handle = 'me'`));
  assert.equal((await one<{ at: string }>(`SELECT ingested_at::text AS at FROM ${s}.people WHERE handle = 'me'`)).at, p0.at);
});

test('C5b guards: every step refuses from a wrong state; flip refuses while plain rows are left (counts only); nothing moves', () => {
  const base = {
    schemaExists: true, prepared: true, encProgress: true, flipChecks: 0, otherRows: 0, quarantineRows: 0, wallAllowRows: 0,
    shape: { tsv: true, tsvIndex: true, hnsw: true, uniques: [], targetUriIndex: true },
    tables: OVERLAY_SPEC.map((t) => ({ table: t.table, rows: 1, plainRows: 0, encryptedRows: 1, ctValues: 3 })),
  };
  for (const step of OVERLAY_STEPS) {
    for (const st of ENC_STATES) {
      const r = overlayGuard(step, st, base);
      if (!OVERLAY_STEP_FROM[step].includes(st)) assert.match(r ?? '', /enc_state is/, `${step} from ${st}`);
    }
  }
  assert.deepEqual(OVERLAY_STEP_FROM, { prepare: ['off', 'enrolled'], flip: ['verified'], relax: ['on'], 'rollback-start': ['encrypting', 'verified'], unflip: ['decrypted'] });
  assert.equal(overlayGuard('flip', 'verified', base), null);
  assert.match(overlayGuard('flip', 'verified', { ...base, tables: base.tables.map((t, i) => (i === 0 ? { ...t, plainRows: 2 } : t)) })!, /plain-text rows left \(notes 2\)/);
  assert.match(overlayGuard('flip', 'verified', { ...base, otherRows: 1 })!, /does not cover/);
  assert.match(overlayGuard('flip', 'verified', { ...base, prepared: false })!, /not prepared/);
  assert.match(overlayGuard('relax', 'on', base)!, /not flipped/);
  assert.equal(overlayGuard('relax', 'on', { ...base, flipChecks: 5 }), null);
  assert.match(overlayGuard('rollback-start', 'verified', { ...base, flipChecks: 5 })!, /relax/);
  assert.match(overlayGuard('unflip', 'decrypted', base)!, /ciphertext left/);
  assert.match(overlayGuard('unflip', 'decrypted', { ...base, flipChecks: 5 })!, /relax first/);
  const clean = { ...base, tables: base.tables.map((t) => ({ ...t, plainRows: 1, encryptedRows: 0, ctValues: 0 })) };
  assert.equal(overlayGuard('unflip', 'decrypted', clean), null);
  for (const s of ENC_STATES) assert.equal(offPathAllowed(s), s === 'off' || s === 'enrolled', s);
});

test('C5b flip (§7.17): refused from the wrong state and while plain rows are left; VALIDATE itself fails on plain text; state and schema unchanged', async () => {
  assert.equal((await apply(P, 'flip')).outcome, 'refused', 'state off');
  await setState(P, 'verified');
  const r = await apply(P, 'flip');
  assert.equal(r.outcome, 'refused');
  assert.match(r.reason!, /^plain-text rows left \(notes \d+, chunks \d+, facts 1, decisions 1, decision_links 1\)/);
  assert.equal(await state(P), 'verified');
  // The backstop: run flip's SQL directly (no guard) on a workspace with plain text. VALIDATE refuses.
  const shape0 = await shape(P);
  const code = await asOwner(db, async () => {
    await db.exec('BEGIN');
    try {
      for (const stmt of flipStatements(P)) await db.exec(stmt);
      return 'ok';
    } catch (e) {
      return (e as { code?: string }).code ?? 'error';
    } finally {
      await db.exec('ROLLBACK');
    }
  });
  assert.equal(code, '23514', 'check_violation from VALIDATE (mutant: drop the VALIDATE statements -> ok)');
  assert.deepEqual(await shape(P), shape0);
});

test('C5b flip (§7.2, §7.10): verified -> on; plain INSERT refused; tsv / GIN / HNSW / plain UNIQUEs / target index gone; quarantine and wall_allow emptied; ACL clean; sessions unchanged', async () => {
  await encryptRows(P);
  const r = await apply(P, 'flip');
  assert.equal(r.outcome, 'applied', r.reason ?? '');
  assert.equal(await state(P), 'on');
  const st = r.state;
  assert.equal(st.flipChecks, 5);
  assert.deepEqual(st.shape, { tsv: false, tsvIndex: false, hnsw: false, uniques: [], targetUriIndex: false });
  assert.equal(st.quarantineRows, 0);
  assert.equal(st.wallAllowRows, 0);
  assert.deepEqual(await audit(P), []);
  // §7.2: the DB itself refuses plain text in an `on` workspace, for the owner too.
  assert.equal(await sqlState(insertPlainNote(P, 'mine/late.md')), '23514');
  const run = (await one<{ id: number }>(`SELECT max(id)::int AS id FROM "${P}".ingest_runs`)).id;
  assert.equal(await sqlState(asOwner(db, async () => db.query(`INSERT INTO "${P}".facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
    VALUES ('rule', 'plain fact', 'personal', 'manual', 'test:p', now(), sha256(convert_to('p', 'UTF8')), $1)`, [run]))), '23514');
  // ANALYZE ran: statistics exist for the flipped tables and hold no plain text.
  const stats = await all<{ t: string }>(`SELECT DISTINCT tablename::text AS t FROM pg_stats WHERE schemaname = $1`, [P]);
  assert.ok(stats.some((x) => x.t === 'notes'), 'analyzed');
  assert.ok(!JSON.stringify(await all(`SELECT most_common_vals::text AS v, histogram_bounds::text AS h FROM pg_stats WHERE schemaname = $1`, [P])).includes(CANARY));
  // §7.10: the read and write session checks still pass on a flipped workspace.
  await (await router.open(P)).close();
  await (await writer.open(P)).close();
  // Flip again: refused.
  assert.equal((await apply(P, 'flip')).outcome, 'refused');
});

test('C5b relax (§7.17 N1-1): on -> decrypting; a decrypt-shaped UPDATE writes plain text; the off search and the off importer still cannot run', async () => {
  const r = await apply(P, 'relax');
  assert.equal(r.outcome, 'applied', r.reason ?? '');
  assert.equal(await state(P), 'decrypting');
  assert.equal(r.state.flipChecks, 0);
  assert.equal(r.state.shape.tsv, false, 'relax does not bring tsv back');
  assert.equal(offPathAllowed('decrypting'), false);
  await decryptRows(P, 'notes');
  assert.equal((await one<{ n: number }>(`SELECT count(*)::int AS n FROM "${P}".notes WHERE key_version IS NULL AND body IS NOT NULL`)).n >= 2, true, 'plain text written back');
  // The off search (c.tsv) and the off importer (ON CONFLICT (vault_path)) fail loudly while decrypting.
  const rdb = await router.open(P);
  try {
    await assert.rejects(search({ db: rdb, query: CANARY, client: null, ledger: new QueryLedger(join(safeMkdtemp(join(tmpdir(), 'zeusi-c5-l-')), 'l.json')) }));
  } finally {
    await rdb.close();
  }
  assert.equal(await sqlState(asOwner(db, async () => db.query(`INSERT INTO "${P}".notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
    SELECT vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id FROM "${P}".notes WHERE key_version IS NULL LIMIT 1
    ON CONFLICT (vault_path) DO NOTHING`))), '42P10', 'no plain UNIQUE for ON CONFLICT (vault_path)');
  assert.equal((await apply(P, 'relax')).outcome, 'refused', 'relax twice');
});

test('C5b unflip (§7.17, R3-2): refused while ciphertext is left; a duplicate vault_path fails loudly and rolls back; then decrypted -> off and the off search and importer work', async () => {
  await setState(P, 'decrypted');
  const refused = await apply(P, 'unflip');
  assert.equal(refused.outcome, 'refused');
  assert.match(refused.reason!, /^ciphertext left \(/);
  assert.doesNotMatch(refused.reason!, new RegExp(CANARY));
  await decryptRows(P);
  // A duplicate vault_path (possible while the plain UNIQUE is gone): unflip fails loudly, nothing changes.
  const paths = await all<{ id: number; p: string }>(`SELECT id::int AS id, vault_path AS p FROM "${P}".notes ORDER BY id`);
  await asOwner(db, async () => db.query(`UPDATE "${P}".notes SET vault_path = $1 WHERE id = $2`, [paths[0]!.p, paths[1]!.id]));
  const shape0 = await shape(P);
  await assert.rejects(apply(P, 'unflip'), (e: unknown) => e instanceof TenantError && /unflip failed \(SQLSTATE 23505\); rolled back/.test((e as Error).message) && !(e as Error).message.includes('mine/'));
  assert.equal(await state(P), 'decrypted', 'the state did not move');
  assert.deepEqual(await shape(P), shape0, 'nothing re-added');
  await asOwner(db, async () => db.query(`UPDATE "${P}".notes SET vault_path = $1 WHERE id = $2`, [paths[1]!.p, paths[1]!.id]));
  await asOwner(db, async () => db.exec(`INSERT INTO "${P}".quarantine (source_kind, source_uri, source_sha256) VALUES ('manual', 'test:post-flip', sha256(convert_to('hmac-keyed', 'UTF8')))`));
  const r = await apply(P, 'unflip');
  assert.equal(r.outcome, 'applied', r.reason ?? '');
  assert.equal(await state(P), 'off');
  assert.deepEqual(r.state.shape, { tsv: true, tsvIndex: true, hnsw: true, uniques: ['decision_links_decision_id_target_uri_key', 'decisions_source_uri_source_sha256_key', 'facts_source_uri_source_sha256_key', 'notes_vault_path_key'], targetUriIndex: true });
  assert.equal(r.state.quarantineRows, 0, 'post-flip (HMAC-keyed) quarantine rows deleted');
  assert.equal(r.state.prepared, true, 'the prepare overlay stays');
  assert.deepEqual(await audit(P), []);
  // The off path is back: search through c.tsv, and the importer's ON CONFLICT (vault_path) upsert.
  const rdb = await router.open(P);
  try {
    const s = await search({ db: rdb, query: CANARY, client: null, ledger: new QueryLedger(join(safeMkdtemp(join(tmpdir(), 'zeusi-c5-l-')), 'l.json')) });
    assert.ok(s.hits.length >= 1, 'c.tsv search finds the decrypted chunks');
  } finally {
    await rdb.close();
  }
  const hq = { path: 'journal/2026-11-19-day.md', text: `---\nproject: journal\nkind: memory\ndate: 2026-11-19\ntitle: Day\nsource: assistant\n---\nsynced again ${CANARY}\n` };
  assert.equal((await ww.sync(caller(P, 5102), [hq], [])).counts.updated, 1, 'ON CONFLICT (vault_path) works after unflip');
  // Shape after the round trip = prepared shape (columns order aside): tsv and the plain UNIQUEs are back.
  const sh = await shape(P);
  assert.ok(sh.columns.includes('chunks.tsv:tsvector:YES'));
  assert.equal(await teamSnapshot(), team0, 'the zeusi schema byte-identical after the whole cycle');
  assert.deepEqual(await shape('zeusi'), zeusiShape0);
});

test('C5 R3-2 pre-flip rollback: verified -> rollback-start -> decrypting (no relax); refused once flipped; unflip only deletes quarantine rows and ends off', async () => {
  assert.equal((await apply(R, 'prepare')).outcome, 'applied');
  await setState(R, 'encrypting');
  await encryptRows(R, 1, 'notes');
  await setState(R, 'verified');
  const r = await apply(R, 'rollback-start');
  assert.equal(r.outcome, 'applied', r.reason ?? '');
  assert.equal(await state(R), 'decrypting');
  assert.equal(offPathAllowed(await state(R)), false);
  assert.equal((await apply(R, 'rollback-start')).outcome, 'refused');
  await decryptRows(R);
  await setState(R, 'decrypted');
  const shapeBefore = await shape(R);
  const u = await apply(R, 'unflip');
  assert.equal(u.outcome, 'applied', u.reason ?? '');
  assert.equal(await state(R), 'off');
  assert.equal(u.state.quarantineRows, 0);
  assert.deepEqual(await shape(R), shapeBefore, 'nothing re-added: tsv and the plain UNIQUEs never left');
  // rollback-start after a flip is refused (use relax).
  await encryptRows(R);
  await setState(R, 'verified');
  assert.equal((await apply(R, 'flip')).outcome, 'applied');
  await setState(R, 'verified');
  const x = await apply(R, 'rollback-start');
  assert.equal(x.outcome, 'refused');
  assert.match(x.reason!, /run relax instead/);
});

test('C5 flag on (§5.1, KTD11): a new workspace is born flipped at enc_state on with no wrap; plain text refused; ACL clean; enroll keeps on and is refused once ciphertext exists', async () => {
  BORN = ((await dirOn.provision('github:5103')) as { tenantId: string }).tenantId;
  assert.equal(await state(BORN), 'on');
  const st = await asOwner(db, async () => readOverlayState(db, BORN));
  assert.equal(st.prepared, true);
  assert.equal(st.flipChecks, 5);
  assert.equal(st.shape.tsv, false);
  assert.deepEqual(await audit(BORN), []);
  assert.equal((await one<{ i: boolean }>(`SELECT has_table_privilege($1::text, $2::text, 'INSERT') AS i`, [tenantWriterRole(BORN), `"${BORN}".enc_progress`])).i, true);
  assert.equal((await one<{ n: number }>(`SELECT count(*)::int AS n FROM "${BORN}".people WHERE handle = 'me'`)).n, 1, 'the workspace person is still created');
  assert.equal(await sqlState(insertPlainNote(BORN, 'x/y.md')), '23514', 'never holds plain text');
  await (await router.open(BORN)).close();
  await (await writer.open(BORN)).close();
  assert.equal(await dir.ensureWriter(BORN), 'ready');
  // C4 hooks: no passkey wrap before enrollment; enroll inserts both wraps and leaves `on`.
  const e = enrollmentWraps({ tenant: BORN, prfOutput: randomBytes(32), credentialId: randomBytes(16), prfSalt: randomBytes(32) });
  const extra = enrollmentWraps({ tenant: BORN, prfOutput: randomBytes(32), credentialId: randomBytes(16), prfSalt: randomBytes(32) });
  assert.equal(await dir.putPasskeyWrap(BORN, extra.passkey), 'not_enrolled');
  assert.equal(await dir.enroll(BORN, { passkey: e.passkey, recovery: e.recovery }), 'enrolled');
  assert.equal(await state(BORN), 'on', 'born encrypted: the state stays on');
  assert.equal((await dir.encryptionView(BORN))!.recovery, 1);
  assert.equal(await dir.enroll(BORN, { passkey: extra.passkey, recovery: extra.recovery }), 'already');
  assert.equal(await dir.putPasskeyWrap(BORN, extra.passkey), 'inserted', 'after enrollment, more passkeys');
  e.dek.fill(0);
  extra.dek.fill(0);
  // A second born workspace whose schema holds a ciphertext row but no wrap: enroll refuses (no fresh DEK over old ciphertext).
  const B2 = ((await dirOn.provision('github:5105')) as { tenantId: string }).tenantId;
  const run = (await one<{ id: number }>(`SELECT max(id)::int AS id FROM "${B2}".ingest_runs`)).id;
  await asOwner(db, async () => db.query(`INSERT INTO "${B2}".facts (kind, text_ct, scope, source_kind, source_uri_ct, source_uri_hmac, source_ts, source_sha256, ingest_run_id, key_version)
    VALUES ('rule', $1, 'personal', 'manual', $2, $3, now(), $4, $5, 1)`, [sealed(), sealed(), mac(), mac(), run]));
  const e2 = enrollmentWraps({ tenant: B2, prfOutput: randomBytes(32), credentialId: randomBytes(16), prfSalt: randomBytes(32) });
  assert.equal(await dir.enroll(B2, { passkey: e2.passkey, recovery: e2.recovery }), 'already');
  e2.dek.fill(0);
  assert.equal((await dir.encryptionView(B2))!.recovery, 0, 'no wrap written');
  // Flag off / enroll provisioning stays plain (the flag-off test pins the shape); the flag-on one does not apply to a returning subject.
  assert.deepEqual(await dirOn.provision('github:5101'), { kind: 'existing', tenantId: OFF, status: 'active' });
  assert.equal(await state(OFF), 'off');
});

test('C5 CLI (KTD14): usage and snapshot refusals are offline; the dry-run output carries counts and reasons only', async () => {
  const run = (args: string[]) => {
    const home = safeMkdtemp(join(tmpdir(), 'zeusi-c5-cli-'));
    const r = spawnSync(process.execPath, [CLI, ...args], {
      cwd: home, encoding: 'utf8', timeout: 20_000,
      env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: home, PGSERVICEFILE: join(home, 'missing.conf') },
    });
    return { code: r.status, out: `${r.stdout}${r.stderr}` };
  };
  const T = `zt_${'c'.repeat(26)}`;
  const snap = run(['workspaces', 'overlay', 'flip', '--tenant', T, '--real']);
  assert.equal(snap.code, 2);
  assert.match(snap.out, /--real needs --i-took-a-snapshot/);
  assert.equal(run(['workspaces', 'overlay', 'encrypt', '--tenant', T]).code, 2, 'unknown step');
  assert.match(run(['workspaces', 'overlay', 'prepare', '--tenant', 'zeusi']).out, /not a workspace id/);
  assert.equal(run(['workspaces', 'overlay', 'prepare', '--tenant', T, '--i-took-a-snapshot']).code, 2);
  const noService = run(['workspaces', 'overlay', 'prepare', '--tenant', T]);
  assert.notEqual(noService.code, 0, 'needs the admin service; never connects elsewhere');
  // Output of a dry run on a workspace full of canary text: counts and constant reasons only.
  const OFF2 = ((await dir.provision('github:5106')) as { tenantId: string }).tenantId;
  await plantContent(OFF2);
  for (const step of OVERLAY_STEPS) {
    const r = await dir.overlayStep(OFF2, step, { dryRun: true });
    const lines = formatOverlayStep(OFF2, r).join('\n');
    assert.ok(!lines.includes(CANARY) && !lines.includes('mine/') && !lines.includes('vault:'), `${step}: no value in the output`);
    assert.match(lines, new RegExp(`workspace ${OFF2}: overlay ${step}: `));
  }
  assert.equal((await asOwner(db, async () => readOverlayState(db, OFF2))).prepared, false, 'dry runs wrote nothing');
});
