// Read-only, count-only scan for Plankiva signals left in the database
// (0011 follow-up; HQ runs it as zeusi_backup after retracting rows ingested before 0011).
//
// * Plain SELECT only, as the connected role, with row security as configured (never
//   SET row_security, never SET ROLE): what the role may read is what is counted.
//   zeusi_backup reads every row (RLS policy backup_read_all, USING (true)).
// * Every base table in schema zeusi is scanned, except the two that hold the exclusion
//   rules themselves (SCAN_EXCLUDED). A table the role cannot SELECT is reported as not
//   readable (checked with has_table_privilege first, so nothing is attempted or thrown).
// * A row matches when any string in to_jsonb(row) (keys and values; embedding and tsv
//   dropped), or all of them joined, carries a signal by mentionsProtectedName(): "plankiva",
//   the 0010 spelling regex, the 0011 variants regex, raw, percent-decoded or normalised.
// * Output: table names and counts only. Never text, uris, paths or ids.

import type { Db } from './db.ts';
import { mentionsProtectedName } from './sources.ts';

/** Tables not scanned, and why (their rows name the word by design). */
export const SCAN_EXCLUDED: Readonly<Record<string, string>> = {
  wall_denylist: 'holds the exclusion rule patterns themselves',
  schema_migrations: 'holds migration file names',
};

export interface ExclusionScanTable {
  table: string;
  readable: boolean;
  rows: number;
  matching: number;
}

export interface ExclusionScanResult {
  tables: ExclusionScanTable[];
  total: number;
  unreadable: number;
}

const IDENT = /^[a-z_][a-z0-9_]*$/;

function strings(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.flatMap(strings);
  if (v && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => [k, ...strings(x)]);
  return [];
}

/** True when a row (as to_jsonb) carries any Plankiva signal. */
export function rowHasSignal(row: unknown): boolean {
  const xs = strings(row);
  return xs.some(mentionsProtectedName) || mentionsProtectedName(xs.join('\n'));
}

export async function exclusionScan(db: Db): Promise<ExclusionScanResult> {
  const list = await db.query<{ t: string; ok: boolean }>(
    `SELECT c.relname::text AS t, has_table_privilege(c.oid, 'SELECT') AS ok
       FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'zeusi' AND c.relkind IN ('r', 'p')
      ORDER BY 1`,
  );
  const tables: ExclusionScanTable[] = [];
  for (const { t, ok } of list.rows) {
    if (Object.hasOwn(SCAN_EXCLUDED, t)) continue;
    if (!IDENT.test(t) || !ok) {
      tables.push({ table: t, readable: false, rows: 0, matching: 0 });
      continue;
    }
    try {
      const r = await db.query<{ r: unknown }>(`SELECT to_jsonb(x) - 'embedding' - 'tsv' AS r FROM zeusi."${t}" x`);
      tables.push({ table: t, readable: true, rows: r.rows.length, matching: r.rows.filter((x) => rowHasSignal(x.r)).length });
    } catch {
      tables.push({ table: t, readable: false, rows: 0, matching: 0 }); // error text is never printed
    }
  }
  return {
    tables,
    total: tables.reduce((a, x) => a + x.matching, 0),
    unreadable: tables.filter((x) => !x.readable).length,
  };
}

export function formatExclusionScan(r: ExclusionScanResult): string {
  const w = Math.max(...r.tables.map((x) => x.table.length), 5);
  const lines = ['exclusion scan (read-only, plain SELECT as the connected role, counts only)'];
  for (const x of r.tables) {
    lines.push(x.readable
      ? `  ${x.table.padEnd(w)}  rows ${x.rows}  matching ${x.matching}`
      : `  ${x.table.padEnd(w)}  not readable by this role`);
  }
  for (const [t, why] of Object.entries(SCAN_EXCLUDED)) lines.push(`  ${t.padEnd(w)}  not scanned (${why})`);
  lines.push(`RESULT: ${r.total === 0 ? '0 matching rows' : `${r.total} matching row(s)`}${r.unreadable ? `; ${r.unreadable} table(s) not readable` : ''}`);
  return lines.join('\n');
}
