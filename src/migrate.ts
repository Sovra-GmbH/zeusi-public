// Plain-SQL migration runner (PLAN.md KTD14). Files in migrations/NNNN_name.sql are
// applied in order, each in its own transaction, and recorded with their sha256
// in zeusi.schema_migrations. Run over the DIRECT (unpooled) URL as the schema owner.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Db } from './db.ts';

export const MIGRATIONS_DIR = fileURLToPath(new URL('../migrations/', import.meta.url));

export interface MigrationFile {
  name: string;
  sql: string;
  sha256: string;
}

export interface MigrateOptions {
  dryRun?: boolean;
  /** Required when the DB already has applied migrations (take a Neon snapshot first). */
  tookSnapshot?: boolean;
  dir?: string;
  log?: (line: string) => void;
}

export interface MigrateResult {
  applied: string[];
  pending: string[];
  alreadyApplied: string[];
}

export function listMigrations(dir: string = MIGRATIONS_DIR): MigrationFile[] {
  return readdirSync(dir)
    .filter((f) => /^\d{4}_[a-z0-9_]+\.sql$/.test(f))
    .sort()
    .map((name) => {
      const sql = readFileSync(`${dir}/${name}`, 'utf8');
      return { name, sql, sha256: createHash('sha256').update(sql).digest('hex') };
    });
}

const BOOKKEEPING = `
CREATE SCHEMA IF NOT EXISTS zeusi;
CREATE TABLE IF NOT EXISTS zeusi.schema_migrations (
  filename   text PRIMARY KEY,
  sha256     text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now(),
  applied_by text NOT NULL DEFAULT session_user
);`;

const LOCK_KEY = `hashtext('zeusi.migrate')`;

/**
 * Apply pending migrations. A session advisory lock is taken BEFORE the applied
 * list is read (review r1 MINOR-7), so two concurrent runs serialise instead of the
 * second one failing on the schema_migrations primary key. Each file still runs in
 * its own transaction. Over the DIRECT URL only (session locks need a real session).
 */
export async function migrate(db: Db, opts: MigrateOptions = {}): Promise<MigrateResult> {
  await db.query(`SELECT pg_advisory_lock(${LOCK_KEY})`);
  try {
    return await migrateLocked(db, opts);
  } finally {
    await db.query(`SELECT pg_advisory_unlock(${LOCK_KEY})`).catch(() => {});
  }
}

async function migrateLocked(db: Db, opts: MigrateOptions): Promise<MigrateResult> {
  const log = opts.log ?? (() => {});
  const files = listMigrations(opts.dir);

  const hasTable = await db.query<{ t: string | null }>(`SELECT to_regclass('zeusi.schema_migrations')::text AS t`);
  const applied = new Map<string, string>();
  if (hasTable.rows[0]?.t) {
    const r = await db.query<{ filename: string; sha256: string }>(
      'SELECT filename, sha256 FROM zeusi.schema_migrations ORDER BY filename',
    );
    for (const row of r.rows) applied.set(row.filename, row.sha256);
  }

  for (const [name, sha] of applied) {
    const f = files.find((x) => x.name === name);
    if (!f) throw new Error(`Applied migration ${name} is missing from ${opts.dir ?? 'migrations/'}.`);
    if (f.sha256 !== sha) {
      throw new Error(`Applied migration ${name} was edited after it ran (sha256 mismatch). Add a new migration instead.`);
    }
  }

  const pending = files.filter((f) => !applied.has(f.name));
  const result: MigrateResult = { applied: [], pending: pending.map((p) => p.name), alreadyApplied: [...applied.keys()] };

  if (pending.length === 0) {
    log('No pending migrations.');
    return result;
  }
  if (opts.dryRun) {
    for (const p of pending) log(`pending: ${p.name}`);
    return result;
  }
  if (applied.size > 0 && !opts.tookSnapshot) {
    throw new Error(
      'This database already has applied migrations. Take a Neon snapshot (or migrate a branch first), ' +
        'then re-run with --i-took-a-snapshot.',
    );
  }

  if (!hasTable.rows[0]?.t) await db.exec(BOOKKEEPING);

  for (const f of pending) {
    log(`applying ${f.name} ...`);
    await db.exec('BEGIN');
    try {
      await db.exec(f.sql);
      await db.query('INSERT INTO zeusi.schema_migrations (filename, sha256) VALUES ($1, $2)', [f.name, f.sha256]);
      await db.exec('COMMIT');
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw e;
    }
    result.applied.push(f.name);
    log(`applied ${f.name}`);
  }
  return result;
}
