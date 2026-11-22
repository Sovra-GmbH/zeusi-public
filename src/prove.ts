// End-to-end proof against a migrated database (Neon or a local test DB).
// Inserts and reads back a sourced fact, proves the wall and invent=NO, checks the
// HNSW index with a dummy vector (no embedding provider), then removes every test
// row it created. The report holds no secrets: no URLs, hosts, or credentials.

import { randomBytes, createHash } from 'node:crypto';
import { asPgError, type Db } from './db.ts';
import {
  dummyVector, getFact, hnswIndexInfo, INDEXED_EMBED_MODEL, insertFact, openRun,
  vectorQuery, vectorQueryUsesHnsw, WALL_GUARD, WALL_REJECTED,
} from './facts.ts';

export type CheckStatus = 'PASS' | 'FAIL' | 'SKIP';

export interface Check {
  name: string;
  status: CheckStatus;
  detail: string;
}

export interface ProveReport {
  ok: boolean;
  token: string;
  checks: Check[];
}

const LOGIN_ROLES = ['zeusi_mini_ingest', 'zeusi_mini_backup', 'zeusi_box_rw', 'zeusi_box_ro', 'zeusi_cloud_ro'];

function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

/** Run `fn` expecting it to fail with one of `codes`. */
async function expectError(fn: () => Promise<unknown>, codes: string[]): Promise<{ ok: boolean; code: string }> {
  try {
    await fn();
    return { ok: false, code: 'no error (row was accepted)' };
  } catch (e) {
    const code = asPgError(e).code ?? 'unknown';
    return { ok: codes.includes(code), code };
  }
}

export async function prove(db: Db): Promise<ProveReport> {
  const token = `zeusi-prove-${randomBytes(6).toString('hex')}`;
  const checks: Check[] = [];
  const add = (name: string, pass: boolean | 'skip', detail: string) =>
    checks.push({ name, status: pass === 'skip' ? 'SKIP' : pass ? 'PASS' : 'FAIL', detail });
  const runIds: number[] = [];
  const now = new Date().toISOString();

  try {
    // 0. Preflight: migrations and pgvector.
    const mig = await db.query<{ t: string | null }>(`SELECT to_regclass('zeusi.schema_migrations')::text AS t`);
    if (!mig.rows[0]?.t) {
      add('preflight: migrations applied', false, 'zeusi.schema_migrations missing; run `npm start -- migrate` first');
      return { ok: false, token, checks };
    }
    const applied = (await db.query<{ filename: string }>('SELECT filename FROM zeusi.schema_migrations ORDER BY 1')).rows.map(
      (r) => r.filename,
    );
    add('preflight: migrations applied', applied.length >= 3, applied.join(', '));
    const ext = await db.query<{ extversion: string }>(`SELECT extversion FROM pg_extension WHERE extname = 'vector'`);
    add('preflight: pgvector installed', ext.rows.length === 1, ext.rows[0] ? `vector ${ext.rows[0].extversion}` : 'missing');

    // 1. Scope type has no Plankiva value and only the known scopes (0010 adds clientco, owner rule).
    const scopes = (
      await db.query<{ v: string }>(
        `SELECT enumlabel AS v FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
         JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'zeusi' AND t.typname = 'scope' ORDER BY e.enumsortorder`,
      )
    ).rows.map((r) => r.v);
    const known = ['work', 'product', 'client', 'personal'];
    add('wall: scope enum has no plankiva value and only known scopes',
      scopes.length > 0 && !scopes.some((s) => /plankiva/i.test(s)) && scopes.every((s) => known.includes(s)), scopes.join(', '));

    // 2. Insert a sourced test fact.
    const factText = `Zeusi prove test fact ${token}`;
    const factUri = `zeusi:prove/${token}`;
    const factSha = sha256Hex(factText);
    const ins = await insertFact(
      db,
      { kind: 'other', subject: `prove.${token}`, text: factText, scope: 'work', sourceKind: 'manual', sourceUri: factUri, sourceTs: now, sourceSha256: factSha },
      { importer: 'prove', mode: 'manual' },
    );
    runIds.push(ins.runId);
    add('insert sourced fact', ins.status === 'inserted', ins.status === 'inserted' ? `fact id ${ins.id}, run ${ins.runId}` : `unexpected ${ins.status}`);
    const factId = ins.status === 'inserted' ? ins.id : undefined;

    // 3. Read it back.
    if (factId !== undefined) {
      const row = await getFact(db, factId);
      const good =
        !!row && row.text === factText && row.source_uri === factUri && row.source_sha256_hex === factSha &&
        row.scope === 'work' && row.ingest_run_id === ins.runId && !!row.ingested_by &&
        new Date(row.source_ts).toISOString() === now;
      add('read fact back with provenance', good, row ? `source_uri=${row.source_uri} source_ts=${new Date(row.source_ts).toISOString()} ingested_by set=${!!row.ingested_by}` : 'not found');
    } else {
      add('read fact back with provenance', false, 'no fact id');
    }

    // 4. invent=NO: rows missing provenance are rejected by the database.
    const runId = await openRun(db, { importer: 'prove', host: 'prove', mode: 'manual' });
    runIds.push(runId);
    const rawInsert = (uri: string | null, ts: string | null, sha: string | null, run: number | null) => () =>
      db.query(
        `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ('other', $1, 'work', 'manual', $2, $3::timestamptz, CASE WHEN $4::text IS NULL THEN NULL ELSE decode($4, 'hex') END, $5)`,
        [`invent=NO probe ${token}`, uri, ts, sha, run],
      );
    const sha = sha256Hex(token);
    const cases: Array<[string, () => Promise<unknown>, string[]]> = [
      ['missing source_uri', rawInsert(null, now, sha, runId), ['23502']],
      ['blank source_uri', rawInsert('   ', now, sha, runId), ['23514']],
      ['missing source_ts', rawInsert(`zeusi:prove/${token}/no-ts`, null, sha, runId), ['23502']],
      ['missing source hash', rawInsert(`zeusi:prove/${token}/no-sha`, now, null, runId), ['23502']],
      ['missing ingest run', rawInsert(`zeusi:prove/${token}/no-run`, now, sha, null), ['23502']],
    ];
    for (const [label, fn, codes] of cases) {
      const r = await expectError(fn, codes);
      add(`invent=NO: reject ${label}`, r.ok, `SQLSTATE ${r.code}`);
    }

    // 5. Wall: hard rules reject Plankiva rows (also inside the ClientCo folder, 0010); quarantine keeps uri + hash only.
    for (const [label, uri] of [
      ['plankiva file under the ClientCo folder', `vault:ClientCo/plankiva-${token}.md`],
      ['PlankivaVault path', `file:~/PlankivaVault/${token}.md`],
      ['plankiva in name', `vault:Work/notes/plankiva-${token}.md`],
    ] as const) {
      const text = `wall probe ${token}`;
      const r = await insertFact(
        db,
        { kind: 'other', text, scope: 'work', sourceKind: 'manual', sourceUri: uri, sourceTs: now, sourceSha256: sha256Hex(uri) },
        { importer: 'prove', mode: 'manual' },
      );
      runIds.push(r.runId);
      const inFacts = await db.query('SELECT 1 FROM zeusi.facts WHERE source_uri = $1', [uri]);
      add(
        `wall: reject ${label}`,
        r.status === 'quarantined' && r.ruleId !== null && inFacts.rows.length === 0,
        r.status === 'quarantined' ? `rule ${r.ruleId}, quarantine id ${r.quarantineId}` : 'ROW WAS ACCEPTED',
      );
    }

    // Lane rule (desk P&L lane) on an episode.
    const lane = await expectError(
      () =>
        db.query(
          `INSERT INTO zeusi.episodes (occurred_at, day, actor, lane, kind, summary, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
           VALUES (now(), current_date, 'prove', 'session-pnl', 'note', $1, 'work', 'manual', $2, now(), decode($3, 'hex'), $4)`,
          [`lane probe ${token}`, `zeusi:prove/${token}/lane`, sha, runId],
        ),
      [WALL_REJECTED],
    );
    add('wall: reject hard-denied lane session-pnl', lane.ok, `SQLSTATE ${lane.code}`);

    const qcols = (
      await db.query<{ column_name: string }>(
        `SELECT column_name FROM information_schema.columns WHERE table_schema = 'zeusi' AND table_name = 'quarantine'`,
      )
    ).rows.map((r) => r.column_name);
    const contentCols = qcols.filter((c) => /text|body|summary|exact_words|title|content$/.test(c));
    add('wall: quarantine table has no content columns', qcols.length > 0 && contentCols.length === 0, `columns: ${qcols.join(', ')}`);

    const qrows = await db.query<{ n: string }>(`SELECT count(*) AS n FROM zeusi.quarantine WHERE source_uri LIKE '%' || $1 || '%'`, [token]);
    add('wall: blocked items recorded in quarantine', Number(qrows.rows[0]!.n) === 3, `${qrows.rows[0]!.n} quarantine rows for this run`);

    // 6. Content rule: quarantined, then allowed only by a wall_allow pinned to the exact hash.
    const cUri = `zeusi:prove/${token}/content`;
    // 0011 lifted the soft currency rule; the soft account / login-number rule stays.
    const cText = `synthetic acct 1234567 ${token}`;
    const c1 = await insertFact(
      db,
      { kind: 'other', text: cText, scope: 'work', sourceKind: 'manual', sourceUri: cUri, sourceTs: now, sourceSha256: sha256Hex(cText) },
      { importer: 'prove', mode: 'manual' },
    );
    runIds.push(c1.runId);
    add('wall: content rule quarantines synthetic account number', c1.status === 'quarantined', c1.status === 'quarantined' ? `rule ${c1.ruleId}` : 'ROW WAS ACCEPTED');
    if (c1.status === 'quarantined' && c1.ruleId !== null && c1.contentSha256) {
      const allow = await expectError(
        () => db.query(`INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ($1, decode($2, 'hex'), $3)`, [cUri, c1.contentSha256, c1.ruleId]),
        [],
      );
      if (allow.code === '42501') {
        add('wall: wall_allow pinned to exact hash admits the row', 'skip', 'connected role cannot write wall_allow (owner only)');
      } else {
        const c2 = await insertFact(
          db,
          { kind: 'other', text: cText, scope: 'work', sourceKind: 'manual', sourceUri: cUri, sourceTs: now, sourceSha256: sha256Hex(cText) },
          { importer: 'prove', mode: 'manual' },
        );
        runIds.push(c2.runId);
        add('wall: wall_allow pinned to exact hash admits the row', c2.status === 'inserted', c2.status);
        const c3 = await insertFact(
          db,
          { kind: 'other', text: `${cText} edited`, scope: 'work', sourceKind: 'manual', sourceUri: cUri, sourceTs: now, sourceSha256: sha256Hex(`${cText} edited`) },
          { importer: 'prove', mode: 'manual' },
        );
        runIds.push(c3.runId);
        add('wall: edited content is quarantined again', c3.status === 'quarantined', c3.status);
      }
      // Hard rules cannot be allowed.
      const hardRule = await db.query<{ id: number }>(`SELECT id FROM zeusi.wall_denylist WHERE kind = 'path_glob' AND pattern = '**plankiva**'`);
      if (hardRule.rows[0]) {
        const h = await expectError(
          () => db.query(`INSERT INTO zeusi.wall_allow (source_uri, content_sha256, rule_id) VALUES ($1, decode($2, 'hex'), $3)`, [`vault:Work/plankiva-${token}.md`, sha, hardRule.rows[0]!.id]),
          [WALL_GUARD],
        );
        add('wall: hard rule cannot be overridden by wall_allow', h.ok || h.code === '42501', `SQLSTATE ${h.code}`);
      }
    }

    // 7. HNSW index + dummy vector query (no embedding provider).
    const idx = await hnswIndexInfo(db);
    const idxOk =
      idx.exists && idx.method === 'hnsw' && idx.opclass === 'halfvec_cosine_ops' &&
      idx.options.includes('m=16') && idx.options.includes('ef_construction=64');
    add('hnsw: chunks_hnsw_te3s exists (halfvec_cosine_ops, m=16, ef_construction=64)', idxOk,
      idx.exists ? `${idx.method} ${idx.opclass} [${idx.options.join(', ')}] where ${idx.predicate}` : 'missing');
    if (factId !== undefined) {
      const vec = dummyVector(7);
      const ch = await db.query<{ id: string }>(
        `INSERT INTO zeusi.chunks (fact_id, chunk_index, text, text_sha256, token_count, embed_model, embedding, embedded_at, source_uri)
         VALUES ($1, 0, $2, decode($3, 'hex'), 8, $4, $5::halfvec(1536), now(), $6) RETURNING id`,
        [factId, factText, factSha, INDEXED_EMBED_MODEL, vec, factUri],
      );
      const chunkId = Number(ch.rows[0]!.id);
      const hits = await vectorQuery(db, vec, 5);
      const top = hits[0];
      add('hnsw: dummy vector query returns the test chunk with citation',
        !!top && top.id === chunkId && top.distance < 1e-3 && !!top.source_uri && !!top.source_ts,
        top ? `top chunk ${top.id} distance ${top.distance.toFixed(6)} source_uri=${top.source_uri}` : 'no rows');
      const plan = await vectorQueryUsesHnsw(db, vec);
      add('hnsw: planner uses chunks_hnsw_te3s for ORDER BY embedding <=> $1', plan.used,
        plan.used ? 'Index Scan using chunks_hnsw_te3s' : plan.plan.split('\n')[0] ?? '');
    }

    // 8. Roles (only when 0004 is applied). Checked via catalog, no SET ROLE needed.
    const roles = await db.query<{ rolname: string; rolsuper: boolean; rolbypassrls: boolean }>(
      `SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = ANY($1)`, [LOGIN_ROLES],
    );
    if (roles.rows.length === 0) {
      add('roles: login roles present', 'skip', '0004_roles.sql not applied');
    } else {
      add('roles: login roles present', roles.rows.length === LOGIN_ROLES.length, roles.rows.map((r) => r.rolname).sort().join(', '));
      add('roles: no login role is superuser or bypasses RLS', roles.rows.every((r) => !r.rolsuper && !r.rolbypassrls), 'rolsuper/rolbypassrls false');
      const ns = await db.query<{ n: string }>(
        `SELECT count(*) AS n FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member JOIN pg_roles g ON g.oid = m.roleid
         WHERE g.rolname = 'neon_superuser' AND r.rolname LIKE 'zeusi\\_%'`,
      );
      add('roles: no zeusi role is a member of neon_superuser', Number(ns.rows[0]!.n) === 0, `${ns.rows[0]!.n} memberships`);
      const priv = await db.query<Record<string, boolean>>(
        `SELECT has_table_privilege('zeusi_box_rw', 'zeusi.facts', 'INSERT') AS rw_insert,
                has_table_privilege('zeusi_box_rw', 'zeusi.facts', 'UPDATE') AS rw_update,
                has_table_privilege('zeusi_box_rw', 'zeusi.facts', 'DELETE') AS rw_delete,
                has_table_privilege('zeusi_box_rw', 'zeusi.wall_denylist', 'INSERT') AS rw_wall,
                has_table_privilege('zeusi_cloud_ro', 'zeusi.facts', 'INSERT') AS ro_insert,
                has_table_privilege('zeusi_cloud_ro', 'zeusi.wall_denylist', 'SELECT') AS ro_wall_read,
                has_table_privilege('zeusi_mini_ingest', 'zeusi.facts', 'UPDATE') AS ingest_fact_update,
                has_table_privilege('zeusi_mini_ingest', 'zeusi.wall_denylist', 'INSERT') AS ingest_wall_write`,
      );
      const p = priv.rows[0]!;
      const privOk = p['rw_insert'] === true && !p['rw_update'] && !p['rw_delete'] && !p['rw_wall'] && !p['ro_insert'] &&
        !p['ro_wall_read'] && !p['ingest_fact_update'] && !p['ingest_wall_write'];
      add('roles: grant matrix (agents insert-only, readers read-only, wall owner-only)', privOk,
        Object.entries(p).map(([k, v]) => `${k}=${v}`).join(' '));
      // 0013 decision_links (design, not applied on Neon): readers SELECT only, ingest / decision-write INSERT only, nobody UPDATE / DELETE.
      const dl = await db.query<Record<string, boolean | null>>(
        `SELECT to_regclass('zeusi.decision_links') IS NOT NULL AS present`);
      if (!dl.rows[0]!['present']) {
        add('roles: decision_links grant matrix (0013)', 'skip', '0013_decision_links.sql not applied');
      } else {
        const lp = (await db.query<Record<string, boolean>>(
          `SELECT has_table_privilege('zeusi_cloud_ro', 'zeusi.decision_links', 'SELECT') AS ro_select,
                  has_table_privilege('zeusi_cloud_ro', 'zeusi.decision_links', 'INSERT, UPDATE, DELETE, TRUNCATE') AS ro_write,
                  has_table_privilege('zeusi_box_rw', 'zeusi.decision_links', 'INSERT') AS rw_insert,
                  has_table_privilege('zeusi_mini_ingest', 'zeusi.decision_links', 'INSERT') AS ingest_insert,
                  has_table_privilege('zeusi_mini_ingest', 'zeusi.decision_links', 'UPDATE, DELETE, TRUNCATE') AS ingest_change,
                  has_table_privilege('zeusi_decision_write', 'zeusi.decision_links', 'INSERT') AS dw_insert,
                  has_table_privilege('zeusi_decision_write', 'zeusi.decision_links', 'UPDATE, DELETE, TRUNCATE') AS dw_change`)).rows[0]!;
        const linksOk = lp['ro_select'] === true && !lp['ro_write'] && !lp['rw_insert'] && lp['ingest_insert'] === true && !lp['ingest_change'] &&
          lp['dw_insert'] === true && !lp['dw_change'];
        add('roles: decision_links grant matrix (0013: readers SELECT, ingest / decision-write INSERT only)', linksOk,
          Object.entries(lp).map(([k, v]) => `${k}=${v}`).join(' '));
      }
    }
  } catch (e) {
    const pe = asPgError(e);
    add('unexpected error', false, `SQLSTATE ${pe.code ?? 'unknown'}: ${pe.message.slice(0, 200)}`);
  } finally {
    // 9. Cleanup: every row created by this run.
    try {
      const like = `%${token}%`;
      await db.query('DELETE FROM zeusi.chunks WHERE source_uri LIKE $1', [like]);
      await db.query('DELETE FROM zeusi.facts WHERE source_uri LIKE $1', [like]);
      await db.query('DELETE FROM zeusi.episodes WHERE source_uri LIKE $1', [like]);
      await db.query('DELETE FROM zeusi.wall_allow WHERE source_uri LIKE $1', [like]);
      await db.query('DELETE FROM zeusi.quarantine WHERE source_uri LIKE $1', [like]);
      if (runIds.length) await db.query('DELETE FROM zeusi.ingest_runs WHERE id = ANY($1::bigint[])', [runIds]);
      const left = await db.query<{ n: string }>(
        `SELECT (SELECT count(*) FROM zeusi.facts WHERE source_uri LIKE $1)
              + (SELECT count(*) FROM zeusi.chunks WHERE source_uri LIKE $1)
              + (SELECT count(*) FROM zeusi.episodes WHERE source_uri LIKE $1)
              + (SELECT count(*) FROM zeusi.quarantine WHERE source_uri LIKE $1)
              + (SELECT count(*) FROM zeusi.wall_allow WHERE source_uri LIKE $1)
              + (SELECT count(*) FROM zeusi.ingest_runs WHERE id = ANY($2::bigint[])) AS n`,
        [like, runIds],
      );
      add('cleanup: test rows removed', Number(left.rows[0]!.n) === 0, `${left.rows[0]!.n} rows left`);
    } catch (e) {
      const pe = asPgError(e);
      add('cleanup: test rows removed', false, `SQLSTATE ${pe.code ?? 'unknown'} (rows tagged ${token} may remain)`);
    }
  }
  return { ok: checks.every((c) => c.status !== 'FAIL'), token, checks };
}

export function formatReport(r: ProveReport, label: string): string {
  const lines = [`zeusi prove — ${label} — run tag ${r.token}`];
  for (const c of r.checks) lines.push(`  ${c.status.padEnd(4)}  ${c.name}${c.detail ? ` — ${c.detail}` : ''}`);
  const pass = r.checks.filter((c) => c.status === 'PASS').length;
  const fail = r.checks.filter((c) => c.status === 'FAIL').length;
  const skip = r.checks.filter((c) => c.status === 'SKIP').length;
  lines.push(`PROVE ${r.ok ? 'PASS' : 'FAIL'} (${pass} pass, ${fail} fail, ${skip} skip)`);
  return lines.join('\n');
}
