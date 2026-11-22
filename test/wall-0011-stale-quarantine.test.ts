// A2 fix 0: 0011 no longer deletes quarantine rows. Measures, on PGlite, what happens to the
// quarantine rows of the two lifted soft rules (currency, P&L / book): they stay with rule_id NULL
// (ON DELETE SET NULL), a re-ingest admits their content, and then wall_audit flags them and the
// real-ingest exit code is 1. Then tests the separate owner SQL
// (scripts/owner-sql/quarantine-lifted-rules.sql) that clears exactly those rows after the owner's yes.
// Synthetic notes only. PGlite only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { realIngestExitCode, wallAudit } from '../src/wall-admin.ts';
import { importVault } from '../src/importers/vault.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const M0011 = '0011_wall_name_variants_soft_lift.sql';
const OWNER_SQL = fileURLToPath(new URL('../scripts/owner-sql/quarantine-lifted-rules.sql', import.meta.url));
const CURRENCY = '(USD|EUR|CHF|GBP|JPY)[ ]?[0-9]|\\$[ ]?[0-9]';
const PNL = '(p&l|\\mpnl\\M|\\mbook\\M)[^\\n]*[0-9]';
const ACCT = '\\m(login|account|acct)\\M[^0-9\\n]{0,4}[0-9]{5,}';

/** Statements of one marked step of the owner SQL file (comments stripped). */
function ownerStep(name: string): string[] {
  const src = readFileSync(OWNER_SQL, 'utf8');
  const m = new RegExp(`-- @${name}[^\\n]*\\n([\\s\\S]*?)-- @end`).exec(src);
  assert.ok(m, `step ${name} present`);
  return m![1]!.replace(/--[^\n]*/g, '').split(';').map((s) => s.trim()).filter(Boolean);
}

interface Q { uri: string; rule_id: number | null; target_table: string | null }
const quarantine = async (db: Db) => (await db.query<Q>(
  `SELECT source_uri AS uri, rule_id, target_table FROM zeusi.quarantine ORDER BY source_uri, target_table`)).rows;

test('owner SQL file is outside migrations/ and carries the yes-needed header', () => {
  assert.ok(!readdirSync(MIGRATIONS_DIR).some((f) => f.includes('quarantine-lifted')), 'migrate never applies it');
  const src = readFileSync(OWNER_SQL, 'utf8');
  assert.match(src, /NEEDS THE OPERATOR'S EXPLICIT YES/);
  assert.match(src, /NO content/);
  const m11 = readFileSync(join(MIGRATIONS_DIR, M0011), 'utf8').replace(/--.*$/gm, '');
  assert.doesNotMatch(m11, /DELETE\s+FROM\s+zeusi\.quarantine/i, '0011 deletes no quarantine row');
  assert.doesNotMatch(m11, /zeusi\.quarantine/i);
});

test('0011 keeps the lifted rules\' quarantine rows (rule_id NULL); after a re-ingest wall_audit flags them and the real ingest exits 1; the owner SQL clears exactly them', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-0011-stale-'));
  const mig = join(dir, 'migrations');
  const vault = join(dir, 'vault');
  mkdirSync(mig);
  mkdirSync(join(vault, 'Work', 'research'), { recursive: true });
  mkdirSync(join(vault, 'Work', 'intake'), { recursive: true });
  const note = (rel: string, body: string) => writeFileSync(join(vault, rel), body);
  note('Work/research/fx.md', '# FX\n\nsynthetic amount USD 12,345 noted\n');
  note('Work/research/desk.md', '# Desk\n\nsynthetic p&l line 42\n');
  note('Work/research/mixed.md', '# Mixed\n\nsynthetic amount USD 99 and account 1234567\n'); // currency first, account kept
  note('Work/research/acct.md', '# Acct\n\nsynthetic account 7654321\n');
  note('Work/research/plain.md', '# Plain\n\nnothing walled here\n');
  note('Work/intake/x.md', '# Inbox\n\nsynthetic\n'); // path-gated, keeps its rule
  const config = validateSources(parseToml(`
[[source]]
name = "vault-all"
kind = "vault_note"
scope = "work"
root = "${vault}"
include = ["**/*.md"]
`), seedWall(), { home: dir });

  const db = await pgliteDb();
  const ingest = async () => {
    await db.exec('SET ROLE zeusi_mini_ingest');
    try {
      return await importVault({ db, config, mode: 'full', home: dir, log: () => {} });
    } finally {
      await db.exec('RESET ROLE');
    }
  };
  const runOwner = async (name: string) => {
    const out: Array<Record<string, unknown>[]> = [];
    for (const s of ownerStep(name)) {
      if (/^(BEGIN|COMMIT|ROLLBACK)$/i.test(s)) await db.exec(s);
      else out.push((await db.query<Record<string, unknown>>(s)).rows);
    }
    return out;
  };
  try {
    for (const f of readdirSync(MIGRATIONS_DIR).filter((x) => x < '0011')) cpSync(join(MIGRATIONS_DIR, f), join(mig, f));
    await migrate(db, { dir: mig });
    const ids = (await db.query<{ id: number; pattern: string }>(`SELECT id::int AS id, pattern FROM zeusi.wall_denylist`)).rows;
    const idOf = (p: string) => ids.find((r) => r.pattern === p)!.id;
    const inboxRule = idOf('Work/intake/**');

    // Run A (0010 wall): fx, pnl, mixed, acct quarantined by content; _inbox path-gated.
    const a = await ingest();
    assert.equal(a.status, 'ok');
    assert.equal(a.counts.inserted, 1, 'only plain.md admitted');
    const qa = await quarantine(db);
    const uriRules = (rows: Q[]) => [...new Set(rows.map((r) => r.rule_id))].sort();
    const lifted = qa.filter((r) => r.rule_id === idOf(CURRENCY) || r.rule_id === idOf(PNL));
    assert.ok(lifted.length >= 3, `lifted-rule rows before 0011: ${lifted.length}`);
    assert.deepEqual(uriRules(qa), [idOf(CURRENCY), idOf(PNL), idOf(ACCT), inboxRule].sort());
    assert.deepEqual(await wallAudit(db), []);

    // Apply 0011: no quarantine row deleted; the lifted rules' rows now have rule_id NULL.
    cpSync(join(MIGRATIONS_DIR, M0011), join(mig, M0011));
    assert.deepEqual((await migrate(db, { dir: mig, tookSnapshot: true })).applied, [M0011]);
    const qb = await quarantine(db);
    assert.equal(qb.length, qa.length, '0011 deletes no quarantine row');
    assert.equal(qb.filter((r) => r.rule_id === null).length, lifted.length, 'exactly the lifted-rule rows have rule_id NULL (FK ON DELETE SET NULL, no FK error)');
    assert.deepEqual(await wallAudit(db), [], 'before a re-ingest the stale rows collide with nothing');
    // Owner SQL dry run before the re-ingest: nothing to delete.
    assert.deepEqual((await runOwner('step1-dry-run'))[0], []);

    // Run B (0011 wall): fx and pnl admitted; mixed re-quarantined by the account rule.
    const b = await ingest();
    assert.equal(b.status, 'ok');
    assert.equal(b.counts.inserted, 2, 'fx.md and desk.md admitted');
    const qc = await quarantine(db);
    const nullRows = qc.filter((r) => r.rule_id === null);
    const audit = await wallAudit(db);
    // MEASURED: wall_audit flags every stale row whose (uri, sha) is now stored content (note row and chunk rows).
    assert.ok(audit.length > 0, 'wall_audit flags the stale rows');
    assert.ok(audit.every((r) => r.problem === 'quarantined (uri, sha) present in content'), JSON.stringify(audit.map((r) => r.problem)));
    assert.deepEqual([...new Set(audit.map((r) => r.table_name))].sort(), ['chunks', 'notes']);
    const notesUris = (await db.query<{ u: string }>(`SELECT source_uri AS u FROM zeusi.notes WHERE vault_path IN ('Work/research/fx.md', 'Work/research/desk.md')`)).rows.map((r) => r.u);
    assert.ok(audit.every((r) => notesUris.some((u) => r.source_uri.startsWith(u))), 'only fx / desk uris are flagged');
    assert.equal(realIngestExitCode(b.status, audit), 1, 'ingest vault --real exits 1');
    // No clearing path: the importer only upserts quarantine rows; a further run changes nothing.
    const c = await ingest();
    assert.equal(c.status, 'ok');
    assert.equal((await wallAudit(db)).length, audit.length, 'a second re-ingest does not clear them');
    assert.equal(realIngestExitCode(c.status, await wallAudit(db)), 1);
    // A rule_id NULL row whose content is NOT stored must survive the owner SQL.
    const run = Number((await db.query<{ id: number }>(`SELECT max(id)::int AS id FROM zeusi.ingest_runs`)).rows[0]!.id);
    await db.query(`SELECT zeusi.quarantine_record('vault_note', 'zeusi:test/orphan', decode($1, 'hex'), NULL, $2, 'notes', NULL)`, ['ee'.repeat(32), run]);

    // Owner SQL step 1 (count-only) then step 2 (delete) and COMMIT.
    const dry = (await runOwner('step1-dry-run'))[0] as Array<{ target_table: string; rows_to_delete: number }>;
    const total = dry.reduce((n, r) => n + r.rows_to_delete, 0);
    assert.equal(total, audit.length, 'step 1 counts exactly the audit-flagged rows');
    assert.equal(total, nullRows.length, 'every rule_id NULL row left after run B (fx / desk; mixed was re-pinned to the account rule)');
    const [del, aud] = await runOwner('step2-delete');
    assert.deepEqual(del, [{ deleted: total }]);
    assert.deepEqual(aud, [{ audit_rows: 0 }]);
    await db.exec('COMMIT');

    assert.deepEqual(await wallAudit(db), []);
    assert.equal(realIngestExitCode('ok', await wallAudit(db)), 0);
    const qd = await quarantine(db);
    assert.deepEqual(qd.filter((r) => r.rule_id === null).map((r) => r.uri), ['zeusi:test/orphan'], 'rows whose content is not stored stay');
    assert.deepEqual(uriRules(qd.filter((r) => r.rule_id !== null)), [idOf(ACCT), inboxRule].sort(), 'kept rules\' rows stay (mixed re-pinned to the account rule)');
  } finally {
    await db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
