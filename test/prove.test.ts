// Local proof: migrations + `prove` against an in-process Postgres with pgvector
// (PGlite). Exercises the same code path `npm start -- prove` runs against Neon.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrate, MIGRATIONS_DIR } from '../src/migrate.ts';
import { prove, formatReport } from '../src/prove.ts';
import { pgliteDb } from './pglite-db.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

test('migrations apply, re-run is a no-op, and prove passes with cleanup', async () => {
  const db = await pgliteDb();
  try {
    const first = await migrate(db);
    assert.deepEqual(first.applied, ['0001_core.sql', '0002_search.sql', '0003_wall.sql', '0004_roles.sql', '0005_rls.sql', '0006_wall_tag_kind.sql', '0007_wall_protected_name.sql', '0008_wall_normalise.sql', '0009_wall_r2.sql', '0010_wall_client_admit.sql', '0011_wall_name_variants_soft_lift.sql', '0012_decision_write_role.sql', '0013_decision_links.sql', '0014_catalog_key_wraps.sql', '0015_key_wraps_credential_unique.sql', '0016_catalog_rt_enc_state.sql', '0017_key_wraps_webauthn.sql']);

    const again = await migrate(db);
    assert.equal(again.applied.length, 0, 're-run applies nothing');

    const report = await prove(db);
    const text = formatReport(report, db.label);
    const failed = report.checks.filter((c) => c.status === 'FAIL');
    assert.equal(failed.length, 0, text);
    assert.ok(report.ok, text);
    assert.ok(text.includes('PROVE PASS'));
    // Every planned check ran (none skipped in a superuser test DB).
    assert.equal(report.checks.filter((c) => c.status === 'SKIP').length, 0, text);

    // Cleanup left nothing behind.
    const left = await db.query<{ n: number }>(
      `SELECT (SELECT count(*) FROM zeusi.facts) + (SELECT count(*) FROM zeusi.chunks)
            + (SELECT count(*) FROM zeusi.quarantine) + (SELECT count(*) FROM zeusi.ingest_runs)
            + (SELECT count(*) FROM zeusi.wall_allow) AS n`,
    );
    assert.equal(Number(left.rows[0]!.n), 0);

    // Report carries no connection details.
    assert.doesNotMatch(text, /postgres(ql)?:\/\/|password|neon\.tech/i);
  } finally {
    await db.close();
  }
});

test('prove fails closed on an unmigrated database', async () => {
  const db = await pgliteDb();
  try {
    const r = await prove(db);
    assert.equal(r.ok, false);
    assert.match(r.checks[0]!.detail, /run `npm start -- migrate`/);
  } finally {
    await db.close();
  }
});

test('migrate refuses an edited applied migration and needs a snapshot flag on a non-empty DB', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-mig-'));
  for (const f of readdirSync(MIGRATIONS_DIR)) writeFileSync(join(dir, f), readFileSync(join(MIGRATIONS_DIR, f)));
  const db = await pgliteDb();
  try {
    // Apply only 0001-0002 first.
    const dir2 = safeMkdtemp(join(tmpdir(), 'zeusi-mig-'));
    for (const f of ['0001_core.sql', '0002_search.sql']) writeFileSync(join(dir2, f), readFileSync(join(MIGRATIONS_DIR, f)));
    await migrate(db, { dir: dir2 });

    await assert.rejects(migrate(db, { dir }), /--i-took-a-snapshot/);
    const r = await migrate(db, { dir, tookSnapshot: true });
    assert.deepEqual(r.applied, ['0003_wall.sql', '0004_roles.sql', '0005_rls.sql', '0006_wall_tag_kind.sql', '0007_wall_protected_name.sql', '0008_wall_normalise.sql', '0009_wall_r2.sql', '0010_wall_client_admit.sql', '0011_wall_name_variants_soft_lift.sql', '0012_decision_write_role.sql', '0013_decision_links.sql', '0014_catalog_key_wraps.sql', '0015_key_wraps_credential_unique.sql', '0016_catalog_rt_enc_state.sql', '0017_key_wraps_webauthn.sql']);

    writeFileSync(join(dir, '0001_core.sql'), readFileSync(join(dir, '0001_core.sql'), 'utf8') + '\n-- edited\n');
    await assert.rejects(migrate(db, { dir }), /sha256 mismatch/);
  } finally {
    await db.close();
  }
});
