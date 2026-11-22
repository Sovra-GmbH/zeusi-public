// Schema, wall, role and RLS behaviour against PGlite (Postgres + pgvector, in process).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';

const SHA = 'ab'.repeat(32);
const HEAD1 = '1'.repeat(40);
const HEAD2 = '2'.repeat(40);
let db: Db;
let run: number;

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return (e as { code?: string }).code ?? 'unknown';
  }
}

const fact = (uri: string, text: string, opts: { subject?: string; ts?: string; scope?: string } = {}) =>
  db.query<{ id: number }>(
    `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('rule', $1, $2, $3::zeusi.scope, 'manual', $4, $5::timestamptz, decode($6, 'hex'), $7) RETURNING id::int AS id`,
    [opts.subject ?? null, text, opts.scope ?? 'work', uri, opts.ts ?? '2026-11-01T10:00:00Z', SHA, run],
  );

before(async () => {
  db = await pgliteDb();
  await migrate(db);
  run = Number((await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
});
after(async () => db.close());

test('wall: hard repo rule rejects an plankiva / agent-config-backup PR; a ClientCo PR passes since 0010', async () => {
  const pr = (repo: string, n: number) =>
    db.query(
      `INSERT INTO zeusi.prs (repo, number, title, head_sha, state, gh_updated_at, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1::text, $2::int, 'test', $3, 'open', now(), 'work', 'github_api', 'gh:' || $1::text || '#' || $2::int, now(), decode($4, 'hex'), $5)`,
      [repo, n, HEAD1, SHA, run],
    );
  assert.equal(await code(pr('example-org/clientco-hedging-engine', 1)), 'ok'); // 0010: ClientCo is admitted
  assert.equal(await code(pr('clientco-plankiva-tools', 4)), 'ZW001');
  assert.equal(await code(pr('agent-config-backup-clientco-walled', 2)), 'ZW001'); // bare name normalised to example-org/
  assert.equal(await code(pr('ops-console', 3)), 'ok');
});

test('wall: hard path rules are case-insensitive and cover pnl names', async () => {
  assert.equal(await code(fact('vault:Work/ops/Desk-PnL-notes.md', 'x')), 'ZW001');
  assert.equal(await code(fact('vault:clientco/Plankiva/clients.md', 'x')), 'ZW001');
  assert.equal(await code(fact('vault:clientco/clients.md', 'x')), 'ok'); // 0010: ClientCo is admitted
  assert.equal(await code(fact('vault:Work/intake/new.md', 'x')), 'ZW001');
  assert.equal(await code(fact('vault:Work/ops/merge-gate-lock.md#Lock', 'merge gate is opus SAFE')), 'ok');
});

test('wall: UPDATE that introduces denied content is rejected', async () => {
  const id = (await fact('vault:Work/ops/update-probe.md', 'clean text')).rows[0]!.id;
  assert.equal(await code(db.query(`UPDATE zeusi.facts SET text = 'acct 1234567 balance' WHERE id = $1`, [id])), 'ZW001');
});

test('wall: decisions applies_to with a denied lane is rejected', async () => {
  const who = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'zeusi:test/people', now(), decode($1, 'hex'), $2) RETURNING id::int AS id`,
    [SHA, run],
  )).rows[0]!.id;
  const dec = (appliesTo: string[], uri: string) =>
    db.query(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to,
                                    scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('go', $1, now(), 'minute', 'GO', true, $2, 'work', 'lane_md', $3, now(), decode($4, 'hex'), $5)`,
      [who, appliesTo, uri, SHA, run],
    );
  assert.equal(await code(dec(['desk-pnl'], 'zeusi:test/dec1')), 'ZW001');
  assert.equal(await code(dec(['ops-console'], 'zeusi:test/dec2')), 'ok');
});

test('supersession: only via function, later source_ts, once', async () => {
  const a = (await fact('zeusi:test/sup-a', 'old rule', { subject: 'merge-gate.test', ts: '2026-11-01T10:00:00Z' })).rows[0]!.id;
  const b = (await fact('zeusi:test/sup-b', 'new rule', { subject: 'merge-gate.test', ts: '2026-11-02T10:00:00Z' })).rows[0]!.id;
  const c = (await fact('zeusi:test/sup-c', 'older rule', { subject: 'merge-gate.test', ts: '2026-10-01T10:00:00Z' })).rows[0]!.id;
  assert.equal(await code(db.query('SELECT zeusi.supersede_fact($1, $2)', [b, c])), '23514'); // older replacement
  assert.equal(await code(db.query('SELECT zeusi.supersede_fact($1, $2)', [a, b])), 'ok');
  assert.equal(await code(db.query('SELECT zeusi.supersede_fact($1, $2)', [a, b])), '23514'); // already superseded
  const cur = await db.query(`SELECT id FROM zeusi.facts_current WHERE subject = 'merge-gate.test' ORDER BY id`);
  assert.deepEqual(cur.rows.map((r) => Number((r as { id: number }).id)), [b, c]);
});

test('pr_status flags a verdict on a stale head', async () => {
  await db.query(
    `INSERT INTO zeusi.prs (repo, number, title, head_sha, state, gh_updated_at, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('example-org/northbank-connector', 7, 't', $1, 'open', now(), 'product', 'github_api', 'gh:example-org/northbank-connector#7', now(), decode($2, 'hex'), $3)`,
    [HEAD1, SHA, run],
  );
  await db.query(
    `INSERT INTO zeusi.pr_reviews (repo, number, review_round, verdict, verdict_head, reviewer, reviewed_at, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('example-org/northbank-connector', 7, 1, 'SAFE', $1, 'opus', now(), 'product', 'review_ledger', 'ledger:rounds-ledger.tsv:L2', now(), decode($2, 'hex'), $3)`,
    [HEAD1, SHA, run],
  );
  const s1 = (await db.query<{ verdict_is_current: boolean; verdict_is_stale: boolean }>(`SELECT * FROM zeusi.pr_status WHERE number = 7`)).rows[0]!;
  assert.equal(s1.verdict_is_current, true);
  assert.equal(s1.verdict_is_stale, false);
  await db.query(`UPDATE zeusi.prs SET head_sha = $1 WHERE number = 7`, [HEAD2]); // force-push
  const s2 = (await db.query<{ verdict_is_current: boolean; verdict_is_stale: boolean; safe_on_stale_head: boolean }>(`SELECT * FROM zeusi.pr_status WHERE number = 7`)).rows[0]!;
  assert.equal(s2.verdict_is_current, false);
  assert.equal(s2.verdict_is_stale, true);
  assert.equal(s2.safe_on_stale_head, true);
});

test('chunks: two parents rejected; scope inherited from parent', async () => {
  const f = (await fact('zeusi:test/chunk-parent', 'parent')).rows[0]!.id;
  assert.equal(await code(db.query(
    `INSERT INTO zeusi.chunks (fact_id, episode_id, text, text_sha256, token_count) VALUES ($1, $1, 'x', decode($2, 'hex'), 1)`, [f, SHA])), '23514');
  const r = await db.query<{ scope: string; source_uri: string }>(
    `INSERT INTO zeusi.chunks (fact_id, text, text_sha256, token_count) VALUES ($1, 'x', decode($2, 'hex'), 1) RETURNING scope::text, source_uri`, [f, SHA]);
  assert.equal(r.rows[0]!.scope, 'work');
  assert.equal(r.rows[0]!.source_uri, 'zeusi:test/chunk-parent');
  assert.equal(await code(db.query(
    `INSERT INTO zeusi.chunks (fact_id, text, text_sha256, token_count, scope) VALUES ($1, 'x', decode($2, 'hex'), 1, 'product')`, [f, SHA])), '23514');
});

test('roles: box_rw inserts but cannot update/delete text or touch the wall; cloud_ro is read-only and blind to personal', async () => {
  await fact('zeusi:test/personal', 'private', { scope: 'personal' });  // as owner
  try {
    await db.exec('SET ROLE zeusi_box_rw');
    const r = await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('agent:zeus', 'box', 'agent') RETURNING id::int AS id`);
    const rid = r.rows[0]!.id;
    const ins = await code(db.query(
      `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('state', 'agent fact', 'work', 'agent_write', 'agent:zeus/test-1', now(), decode($1, 'hex'), $2)`, [SHA, rid]));
    assert.equal(ins, 'ok');
    assert.equal(await code(db.query(`UPDATE zeusi.facts SET text = 'changed' WHERE source_uri = 'agent:zeus/test-1'`)), '42501');
    assert.equal(await code(db.query(`DELETE FROM zeusi.facts WHERE source_uri = 'agent:zeus/test-1'`)), '42501');
    assert.equal(await code(db.query(`INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason) VALUES ('term', false, 'x', 'y')`)), '42501');
    assert.equal(await code(db.query(`DELETE FROM zeusi.wall_denylist`)), '42501');
    assert.equal(await code(db.query(
      `INSERT INTO zeusi.facts (kind, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('state', 'p', 'personal', 'agent_write', 'agent:zeus/test-2', now(), decode($1, 'hex'), $2)`, [SHA, rid])), '42501');
    const by = await db.query<{ ingested_by: string }>(`SELECT ingested_by FROM zeusi.facts WHERE source_uri = 'agent:zeus/test-1'`);
    assert.ok(by.rows[0]!.ingested_by.length > 0);
    await db.exec('RESET ROLE');

    await db.exec('SET ROLE zeusi_mini_ingest');
    assert.equal(await code(db.exec('ALTER TABLE zeusi.facts DISABLE TRIGGER zeusi_90_wall')), '42501');
    await db.exec('RESET ROLE');

    await db.exec('SET ROLE zeusi_cloud_ro');
    assert.equal(await code(db.query(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('x', 'cloud', 'manual')`)), '42501');
    const seen = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.facts WHERE scope = 'personal'`);
    assert.equal(Number(seen.rows[0]!.n), 0);
    const visible = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.facts`);
    assert.ok(Number(visible.rows[0]!.n) > 0);
    assert.equal(await code(db.query(`SELECT * FROM zeusi.wall_denylist`)), '42501');
    assert.equal(await code(db.query(`SELECT * FROM zeusi.quarantine`)), '42501');
  } finally {
    await db.exec('RESET ROLE');
  }
});

test('wall_audit is clean, and flags a hard-matching row forced in as owner', async () => {
  const clean = await db.query(`SELECT * FROM zeusi.wall_audit()`);
  assert.equal(clean.rows.length, 0);
  await db.exec('ALTER TABLE zeusi.facts DISABLE TRIGGER zeusi_90_wall');
  await fact('vault:ClientCo/plankiva-forced.md', 'forced');
  await db.exec('ALTER TABLE zeusi.facts ENABLE TRIGGER zeusi_90_wall');
  const dirty = await db.query<{ source_uri: string }>(`SELECT * FROM zeusi.wall_audit()`);
  assert.ok(dirty.rows.some((r) => r.source_uri === 'vault:ClientCo/plankiva-forced.md'));
  await db.query(`DELETE FROM zeusi.facts WHERE source_uri = 'vault:ClientCo/plankiva-forced.md'`);
});
