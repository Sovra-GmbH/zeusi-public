// Test-only Db adapter over PGlite (in-process Postgres + pgvector). No network, no Neon.
import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite-pgvector';
import type { Db } from '../src/db.ts';

export async function pgliteDb(): Promise<Db & { raw: PGlite }> {
  const raw = await PGlite.create({ extensions: { vector } });
  return {
    raw,
    label: 'pglite (in-memory test DB)',
    async query<T>(sql: string, params?: unknown[]) {
      const r = await raw.query<T>(sql, params as unknown[] | undefined);
      return { rows: r.rows };
    },
    async exec(sql: string) {
      await raw.exec(sql);
    },
    async close() {
      await raw.close();
    },
  };
}
