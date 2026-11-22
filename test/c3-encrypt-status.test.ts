// C3 (docs/plans/2026-11-18-c3-catalog-enc-state.md KTD8, KTD9): `zeusi workspaces encrypt-status`.
// Counts only, read-only, no key. Hermetic: PGlite (real migrations, real owner SQL, logins emulated
// with SET SESSION AUTHORIZATION) and the CLI spawned offline. No network, no Neon.
// Every wrap blob, credential id and salt below is a TEST byte pattern, never a production secret.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Db } from '../src/db.ts';
import {
  encryptStatus, EncryptStatusRefused, formatEncryptStatus, PLAIN_COLUMNS, readEncryptStatus, readWorkspaceCounts, ROW_ONLY_TABLES, type EncryptStatus,
} from '../src/encrypt-status.ts';
import { listMigrations, migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { TenantDirectory } from '../src/tenants.ts';
import { pgliteDb } from './pglite-db.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, OWNER_SQL, plantInWorkspace, plantTeam, SHA, TEAM_MARKER, tenantTestDb } from './helpers/tenant-fixture.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const MARK = 'platypuscanarybody';
const URI = `vault:Private/${MARK}-secret-plan.md`;
const VAULT_PATH = `Private/${MARK}-folder/plan.md`;
const QUAR_URI = 'vault:Private/quarantined-wombatcanary.md';
const ALLOW_URI = 'vault:Private/allowed-echidnacanary.md';
const WRAP_ID = 'wrapid-numbatcanary';
const CRED = Buffer.from('credential-id-quollcanary', 'utf8');
const SALT = Buffer.alloc(32, 0x7e);
const SEALED = Buffer.concat([Buffer.of(0x01), Buffer.from('sealed-dek-bilbycanary'.padEnd(60, 'z'), 'utf8')]);
const CANARIES = [
  MARK, URI, VAULT_PATH, QUAR_URI, ALLOW_URI, 'wombatcanary', 'echidnacanary', WRAP_ID, 'numbatcanary', TEAM_MARKER, 'wombatworkspaceb',
  'quollcanary', 'bilbycanary', SHA,
  ...[CRED, SALT, SEALED].flatMap((b) => [b.toString('hex'), b.toString('base64'), b.toString('base64url'), b.toString('hex').slice(0, 16)]),
];

let db: Db;
let dir: TenantDirectory;
let A: string;
let B: string;
let C: string;
let connects = 0;

async function rowCounts(d: Db, schema: string): Promise<Record<string, number>> {
  return asOwner(d, async () => {
    const out: Record<string, number> = {};
    for (const t of [...PLAIN_COLUMNS.map((p) => p.table), ...ROW_ONLY_TABLES, 'people', 'ingest_runs']) {
      out[t] = (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${schema}"."${t}"`)).rows[0]!.n;
    }
    return out;
  });
}

async function catalogState(d: Db): Promise<unknown> {
  return asOwner(d, async () => ({
    tenants: (await d.query(`SELECT * FROM zeusi_tenants.tenants ORDER BY tenant_id`)).rows,
    members: (await d.query(`SELECT * FROM zeusi_tenants.members ORDER BY subject`)).rows,
    wraps: (await d.query(`SELECT tenant_id, wrap_id, kind, key_version FROM zeusi_tenants.key_wraps ORDER BY 1, 2`)).rows,
    cols: (await d.query(`SELECT attrelid::regclass::text AS rel, attname::text AS col FROM pg_attribute
                           WHERE attrelid IN ('zeusi_tenants.tenants'::regclass, 'zeusi_tenants.key_wraps'::regclass) AND attnum > 0 AND NOT attisdropped ORDER BY 1, 2`)).rows,
  }));
}

before(async () => {
  db = await tenantTestDb({ writer: true });
  await plantTeam(db);
  const login = asLogin(db, 'zeusi_tenant_admin');
  dir = new TenantDirectory({ connectAdmin: async () => { connects++; return login(); } });
  A = ((await dir.provision('github:501')) as { tenantId: string }).tenantId;
  B = ((await dir.provision('github:502')) as { tenantId: string }).tenantId;
  C = ((await dir.provision('github:503')) as { tenantId: string }).tenantId;
  await plantInWorkspace(db, B, 'wombatworkspaceb');
  // Workspace A: a note and two chunks, a fact, a quarantine row and a wall_allow row (all canaries), two wraps.
  await asOwner(db, async () => {
    const s = `"${A}"`;
    const run = (await db.query<{ id: number }>(`INSERT INTO ${s}.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    const nid = (await db.query<{ id: number }>(
      `INSERT INTO ${s}.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1, $2, $3, now(), 'personal', 'manual', $4, now(), decode($5, 'hex'), $6) RETURNING id::int AS id`,
      [VAULT_PATH, `title ${MARK}`, `body ${MARK}`, URI, SHA, run])).rows[0]!.id;
    for (const i of [0, 1]) {
      await db.query(
        `INSERT INTO ${s}.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
         VALUES ($1, $2, $3, $4, sha256(convert_to($4, 'UTF8')), 3, $5)`, [nid, i, `Heading ${MARK}`, `chunk ${i} ${MARK}`, `${URI}#c${i}`]);
    }
    await db.query(
      `INSERT INTO ${s}.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('rule', $1, $2, 'personal', 'manual', $3, now(), decode($4, 'hex'), $5)`, [`subject.${MARK}`, `fact ${MARK}`, `${URI}#fact`, SHA, run]);
    await db.query(`INSERT INTO ${s}.quarantine (source_kind, source_uri, source_sha256) VALUES ('manual', $1, decode($2, 'hex'))`, [QUAR_URI, SHA]);
    await db.query(`INSERT INTO ${s}.wall_allow (source_uri, content_sha256, rule_id) VALUES ($1, decode($2, 'hex'), (SELECT min(id) FROM ${s}.wall_denylist WHERE NOT hard))`, [ALLOW_URI, SHA]);
    await db.query(`INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek, credential_id, prf_salt) VALUES ($1, $2, 'passkey', 1, $3, $4, $5)`,
      [A, WRAP_ID, SEALED, CRED, SALT]);
    await db.query(`INSERT INTO zeusi_tenants.key_wraps (tenant_id, wrap_id, kind, key_version, sealed_dek) VALUES ($1, $2, 'recovery', 1, $3)`, [A, `${WRAP_ID}-r`, SEALED]);
    await db.query(`UPDATE zeusi_tenants.tenants SET status = 'disabled' WHERE tenant_id = $1`, [C]);
  });
});
after(async () => db.close());

const col = (s: EncryptStatus, table: string, column: string) => s.tables.find((t) => t.table === table)!.plain.find((p) => p.column === column)!.count;
const rows = (s: EncryptStatus, table: string) => s.tables.find((t) => t.table === table)?.rows ?? s.rowOnly.find((t) => t.table === table)!.rows;

test('encrypt-status: counts per table and column still in plain text, wraps per kind, enc_state, quarantine and wall_allow rows', async () => {
  const s = await encryptStatus(dir, A);
  assert.equal(s.encState, 'off');
  assert.deepEqual(s.wraps, { passkey: 1, recovery: 1, total: 2 });
  assert.equal(rows(s, 'notes'), 1);
  for (const c of ['title', 'body', 'frontmatter', 'vault_path', 'source_uri', 'source_sha256']) assert.equal(col(s, 'notes', c), 1, c);
  assert.equal(rows(s, 'chunks'), 2);
  for (const c of ['heading_path', 'text', 'text_sha256', 'tsv', 'source_uri']) assert.equal(col(s, 'chunks', c), 2, c);
  assert.equal(col(s, 'chunks', 'embedding'), 0, 'no embeddings in a workspace');
  assert.equal(rows(s, 'facts'), 1);
  assert.equal(col(s, 'facts', 'text'), 1);
  assert.equal(rows(s, 'decisions'), 0);
  assert.equal(rows(s, 'quarantine'), 1);
  assert.equal(col(s, 'quarantine', 'source_uri'), 1);
  assert.equal(col(s, 'quarantine', 'content_sha256'), 0);
  assert.equal(rows(s, 'wall_allow'), 1);
  assert.equal(s.plainTotal, 6 + 5 * 2 + 4 + 2);

  const empty = await encryptStatus(dir, B);
  assert.deepEqual(empty.wraps, { passkey: 0, recovery: 0, total: 0 });
  assert.equal(rows(empty, 'notes'), 1, 'B has its own note, not A\'s');
  assert.equal(rows(empty, 'wall_allow'), 0);
  // A disabled workspace is still reported (status is not encryption state).
  assert.equal((await encryptStatus(dir, C)).plainTotal, 0);
});

test('encrypt-status canary: no body, title, path, URI, hash, wrap id, wrap blob, credential id or salt in the output; only constant words, numbers and the id', async () => {
  const out = formatEncryptStatus(await encryptStatus(dir, A)).join('\n');
  for (const c of CANARIES) assert.ok(!out.includes(c), `canary leaked: ${c.slice(0, 12)}...`);
  assert.ok(!out.includes(B) && !out.includes(C), 'no other workspace id');
  // Vocabulary: the tokens of an all-zero report for the same id. Anything else (other than digits) is data.
  const zero: EncryptStatus = {
    tenantId: A, encState: 'off', wraps: { passkey: 0, recovery: 0, total: 0 }, plainTotal: 0,
    tables: PLAIN_COLUMNS.map((p) => ({ table: p.table, rows: 0, plain: p.columns.map((column) => ({ column, count: 0 })) })),
    rowOnly: ROW_ONLY_TABLES.map((table) => ({ table, rows: 0 })),
  };
  const vocab = new Set(formatEncryptStatus(zero).join('\n').split(/[^A-Za-z0-9_]+/).filter(Boolean));
  const extra = out.split(/[^A-Za-z0-9_]+/).filter((t) => t && !/^\d+$/.test(t) && !vocab.has(t));
  assert.deepEqual(extra, []);
  assert.match(out, /^workspaces encrypt-status \(dry run, counts only, nothing changed\)$/m);
  assert.match(out, new RegExp(`^workspace ${A}: enc_state off; key wraps 2 \\(passkey 1, recovery 1\\)$`, 'm'));
  assert.match(out, /no ciphertext columns exist before the C5 overlay/);
  assert.match(out, /^ {2}wall_allow: rows 1$/m);
  assert.doesNotMatch(out, /absent/, 'every counted column exists in a provisioned workspace');
});

test('encrypt-status writes nothing: catalog and workspace unchanged; it runs in a READ ONLY transaction; the ensure path is not run', async () => {
  const cat0 = await catalogState(db);
  const a0 = await rowCounts(db, A);
  await encryptStatus(dir, A);
  await encryptStatus(dir, B);
  assert.deepEqual(await catalogState(db), cat0);
  assert.deepEqual(await rowCounts(db, A), a0);
  // The transaction the directory hands out refuses any write.
  const err = await dir.readOnly((d) => d.exec(`UPDATE zeusi_tenants.tenants SET enc_state = 'enrolled'`)).then(() => 'ok', (e: { code?: string }) => e.code);
  assert.equal(err, '25006');
  assert.equal(await dir.readOnly(async (d) => (await d.query<{ ro: string }>(`SELECT current_setting('transaction_read_only') AS ro`)).rows[0]!.ro), 'on');
  // And the session is left clean for the next user.
  assert.equal(await asOwner(db, async () => (await db.query<{ u: string }>('SELECT current_user::text AS u')).rows[0]!.u), 'postgres');
});

test('encrypt-status refuses a malformed or team id before connecting, an unknown workspace, and a missing schema', async () => {
  const before0 = connects;
  for (const bad of ['work', 'zt_x', `${A}; DROP SCHEMA zeusi`, `${A.toUpperCase()}`, '', 'zeusi', `"${A}"`]) {
    await assert.rejects(encryptStatus(dir, bad), /not a workspace id/, bad);
  }
  assert.equal(connects, before0, 'no connection for a malformed id');
  await assert.rejects(encryptStatus(dir, 'zt_cccccccccccccccccccccccccc'), (e: unknown) => e instanceof EncryptStatusRefused && /no such workspace/.test((e as Error).message));
  // A catalog row whose schema is gone (never happens through provisioning): reported, not guessed.
  const ghost = 'zt_gggggggggggggggggggggggggg';
  await asOwner(db, () => db.query(`INSERT INTO zeusi_tenants.tenants (tenant_id) VALUES ($1)`, [ghost]));
  try {
    await assert.rejects(encryptStatus(dir, ghost), /workspace schema does not exist/);
  } finally {
    await asOwner(db, () => db.query(`DELETE FROM zeusi_tenants.tenants WHERE tenant_id = $1`, [ghost]));
  }
});

test('encrypt-status on a catalog without 0014 reports "not migrated" and does not fix it (no DDL)', async () => {
  const d = await pgliteDb();
  try {
    const sub = safeMkdtemp(join(tmpdir(), 'zeusi-mig14s-'));
    for (const f of listMigrations()) if (f.name < '0014') copyFileSync(join(MIGRATIONS_DIR, f.name), join(sub, f.name));
    await migrate(d, { dir: sub });
    await d.exec(readFileSync(OWNER_SQL, 'utf8'));
    await d.exec(`SET SESSION AUTHORIZATION zeusi_tenant_admin;
      CREATE SCHEMA zeusi_tenants;
      CREATE TABLE zeusi_tenants.tenants (tenant_id text PRIMARY KEY, status text NOT NULL DEFAULT 'active', created_at timestamptz NOT NULL DEFAULT now());
      INSERT INTO zeusi_tenants.tenants (tenant_id) VALUES ('zt_aaaaaaaaaaaaaaaaaaaaaaaaaa');
      RESET ROLE; SET SESSION AUTHORIZATION postgres;`);
    const ldir = new TenantDirectory({ connectAdmin: asLogin(d, 'zeusi_tenant_admin') });
    await assert.rejects(encryptStatus(ldir, 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa'), /catalog not migrated/);
    const n = (await d.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_attribute WHERE attrelid = 'zeusi_tenants.tenants'::regclass AND attname = 'enc_state'`)).rows[0]!.n;
    assert.equal(n, 0, 'still no enc_state');
    assert.equal((await d.query<{ t: string | null }>(`SELECT to_regclass('zeusi_tenants.key_wraps')::text AS t`)).rows[0]!.t, null);
  } finally {
    await d.close();
  }
});

test('encrypt-status: every counted table and column exists in a freshly provisioned workspace', async () => {
  const s = await readEncryptStatusAsOwner(C);
  for (const t of [...s.tables, ...s.rowOnly]) assert.notEqual(t.rows, null, t.table);
  for (const t of s.tables) for (const p of t.plain) assert.notEqual(p.count, null, `${t.table}.${p.column}`);
});

async function readEncryptStatusAsOwner(id: string): Promise<EncryptStatus> {
  return asOwner(db, async () => {
    await db.exec('BEGIN TRANSACTION READ ONLY');
    try {
      return await readEncryptStatus(db, id);
    } finally {
      await db.exec('ROLLBACK');
    }
  });
}

test('encrypt-status: the workspace counts run in their own transaction and hold no lock on the catalog', async () => {
  const held = await dir.readOnly(async (d) => {
    await readWorkspaceCounts(d, A);
    return (await d.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_locks l JOIN pg_class c ON c.oid = l.relation JOIN pg_namespace s ON s.oid = c.relnamespace
        WHERE s.nspname = 'zeusi_tenants' AND l.pid = pg_backend_pid()`)).rows[0]!.n;
  });
  assert.equal(held, 0);
  const n0 = connects;
  await encryptStatus(dir, A);
  assert.equal(connects - n0, 2, 'catalog, then workspace: two short sessions');
});

// The C1 test "not wired" (test/crypto-envelope.test.ts) scans every file under src/, scripts/ and site/;
// this one names the C3 files explicitly so a C3 regression points here.
test('encrypt-status is not wired to the envelope module: no import of it from the CLI, the catalog or this command', () => {
  for (const f of ['../src/encrypt-status.ts', '../src/cli.ts', '../src/tenants.ts', '../src/tenant-ddl.ts']) {
    assert.doesNotMatch(readFileSync(fileURLToPath(new URL(f, import.meta.url)), 'utf8'), /crypto-envelope/, f);
  }
});

// --------------------------------------------------------------------------- CLI, offline

const FAKE_OWNER = ['postgresql://', 'owner', ':', 'fakeOwnerPw', '@', 'ep-fake-1', '.eu-central-1.aws.neon.tech/zeusi'].join('');
function run(args: string[], serviceFile?: string) {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-c3-cli-'));
  writeFileSync(join(d, '.env.local'), `DATABASE_URL=${FAKE_OWNER}\nDATABASE_URL_UNPOOLED=${FAKE_OWNER}\n`);
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: d, PGSERVICEFILE: serviceFile ?? join(d, 'missing.conf') };
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: d, encoding: 'utf8', env, timeout: 20_000 });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

test('CLI workspaces encrypt-status: offline refusals before any connection (no id, malformed id, --real, --tenant on a backfill); never the owner URL', () => {
  const id = 'zt_aaaaaaaaaaaaaaaaaaaaaaaaaa';
  for (const [args, re] of [
    [['workspaces', 'encrypt-status'], /usage: .*workspaces encrypt-status --tenant <id>/],
    [['workspaces', 'encrypt-status', '--tenant', 'work'], /--tenant: not a workspace id/],
    [['workspaces', 'encrypt-status', '--tenant', `${id}; DROP SCHEMA zeusi`], /--tenant: not a workspace id/],
    [['workspaces', 'encrypt-status', '--tenant', 'zt_short'], /--tenant: not a workspace id/],
    [['workspaces', 'encrypt-status', '--tenant', id, '--real'], /dry run only/],
    [['workspaces', 'encrypt-status', id], /usage: /],
    [['workspaces', 'backfill-people', '--tenant', id], /usage: /],
    [['workspaces', 'encrypt-status', '--tenant', id, '--admin-service', 'x;y'], /--admin-service: letters, digits/],
    [['workspaces', 'encrypt-status', '--tenant', id], /Service "zeusi_tenant_admin" not found/],
  ] as Array<[string[], RegExp]>) {
    const r = run(args);
    assert.notEqual(r.code, 0, `${args.join(' ')}: ${r.out}`);
    assert.match(r.out, re, args.join(' '));
    assert.doesNotMatch(r.out, /fakeOwnerPw|postgres(ql)?:\/\//);
  }
  assert.match(run(['help']).out, /workspaces encrypt-status --tenant <zt_id>/);
});
