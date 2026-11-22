// C6b (docs/plans/2026-11-19-c6-write-path.md KTD7, KTD12, KTD13, U7; parent plan §7 items 6, 16, 17, R3-4): the
// sealed route for structured records (facts, decisions), decision_links and every quarantine_record caller.
// PGlite with the real migrations, tenant logins and writer login; a FIXED test DEK. No network, no Neon.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { insertDecisionLinks, linkShape, linkTargetKind } from '../src/decision-links.ts';
import { closeRun, openRun } from '../src/facts.ts';
import { recordUri, writeStructured, type DecisionRecord, type FactRecord } from '../src/importers/structured.ts';
import { TenantWriter, TENANT_WR_ROLE } from '../src/tenants.ts';
import { compileWall, loadWall } from '../src/wall.ts';
import { nextId, sealedInsertSql, sealedSoFar, sealRow, WorkspaceKey } from '../src/workspace-seal.ts';
import { NO_INDEX_HOOK, PLAIN_ROUTE, sealedTx, type SealedRoute } from '../src/write-route.ts';
import {
  c6Fixture, callerOf, commitDocs, counts, decisionEntry, decisionLog, factEntry, newWorkspace, rowsOf, TEST_DEK, type C6Fixture,
} from './helpers/c6-fixture.ts';
import { asLogin, asOwner } from './helpers/tenant-fixture.ts';

let f: C6Fixture;
before(async () => {
  f = await c6Fixture();
});
after(async () => {
  await f.close();
});

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest();
const writerOpen = (t: string) => new TenantWriter({ connectWriter: asLogin(f.db, TENANT_WR_ROLE), check: (x) => f.router.check(x) }).open(t);
const keyFor = (t: string) => {
  const k = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  k.startCounter(0);
  return k;
};

/** A writer session and a sealed route on `t` (the same pieces WorkspaceWrites builds). */
async function sealedSession<T>(t: string, fn: (db: Db, route: SealedRoute) => Promise<T>): Promise<T> {
  const db = await writerOpen(t);
  const key = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  try {
    key.startCounter(await sealedSoFar(db, 1));
    return await fn(db, { kind: 'sealed', key, tenantId: t, index: NO_INDEX_HOOK });
  } finally {
    key.dispose();
    await db.close();
  }
}

const decision = (text: string, o: Partial<DecisionRecord> = {}): DecisionRecord => ({
  type: 'decision', who: 'me', saidAt: '2026-11-19T09:00:00.000Z', saidAtPrecision: 'minute', kind: 'go', verbatim: false, appliesTo: ['zeusi'],
  linkedRepo: null, linkedPr: null, expiresAt: null, expiresRule: null, text, ...o,
});
const fact = (text: string, o: Partial<FactRecord> = {}): FactRecord => ({ type: 'fact', who: 'me', saidAt: '2026-11-19T08:00:00.000Z', factKind: 'rule', subject: 'subj', text, ...o });

/** Every sealed decision of `t`, opened. */
async function openDecisions(t: string) {
  const k = keyFor(t);
  try {
    return (await rowsOf<Record<string, unknown>>(f.db, t, 'decisions')).map((r) => {
      const id = Number(r['id']);
      const o = (c: string) => (r[`${c}_ct`] ? k.open('decisions', c, id, r[`${c}_ct`] as Uint8Array) : null);
      for (const c of ['exact_words', 'applies_to', 'expires_rule', 'linked_repo', 'linked_job', 'source_uri']) assert.equal(r[c], null, `decisions.${c} NULL`);
      return { id, exact_words: o('exact_words'), applies_to: o('applies_to'), linked_repo: o('linked_repo'), source_uri: o('source_uri'), key_version: r['key_version'] };
    });
  } finally {
    k.dispose();
  }
}

// ---------------------------------------------------------------------------
// R3-4 (KTD13)

test('R3-4: on an `on` workspace a `..` note target is refused (invalid +1, no decision_links row, no quarantine row); the same headed entry through commit drops the link at parse', async () => {
  const t = await newWorkspace(f, 'on');
  const c = callerOf(t);
  const r1 = await commitDocs(f, c, [decisionLog(decisionEntry('a decision with no links yet'))]);
  assert.equal(r1.decisions, 1);
  const did = (await rowsOf<{ id: number }>(f.db, t, 'decisions', 'id::int AS id'))[0]!.id;
  const before0 = await counts(f.db, t);
  const res = await sealedSession(t, async (db, route) => {
    const run = await openRun(db, { importer: 'c6b-test', host: 'test', mode: 'manual' });
    const l = await sealedTx(db, route, () => insertDecisionLinks(db, {
      decisionId: did, scope: 'work', sourceKind: 'manual', sourceUri: 'import:proj/x.md', sourceTs: '2026-11-19T09:00:00Z', runId: run,
      targets: ['vault:../secret.md', 'hq:a/./b.md', 'vault:notes/fine.md'], inTransaction: true, route,
    }));
    await closeRun(db, run, 'ok', {});
    return l;
  });
  assert.deepEqual(res, { inserted: 1, deduped: 0, quarantined: 0, invalid: 2 });
  const after0 = await counts(f.db, t);
  assert.equal(after0['decision_links'], before0['decision_links']! + 1, 'only the valid link');
  assert.equal(after0['quarantine'], before0['quarantine'], 'no quarantine row for a refused shape');
  // Why the app gate is needed: on a sealed row target_uri is NULL, so the DB CHECK is blind to the shape.
  await sealedSession(t, async (db, route) => {
    const run = await openRun(db, { importer: 'c6b-test', host: 'test', mode: 'manual' });
    await sealedTx(db, route, async () => {
      const id = (await nextId(db, 'decision_links'))[0]!;
      const ins = sealedInsertSql('decision_links', [
        ['id', id, 'bigint'], ['decision_id', did, 'bigint'], ['target_kind', 'note', 'zeusi.link_target_kind'], ['scope', 'work', 'zeusi.scope'],
        ['source_kind', 'manual', 'zeusi.source_kind'], ['source_ts', '2026-11-19T09:00:00Z', 'timestamptz'], ['source_sha256', Buffer.alloc(32, 9), 'bytea'], ['ingest_run_id', run, 'bigint'],
      ], [...sealRow(route.key, 'decision_links', id, { target_uri: 'vault:../blind.md', source_uri: 'import:proj/x.md' }), route.key.sealDigest('decision_links', id, '09'.repeat(32))]);
      await db.query(ins.sql, ins.params);
      throw new Error('rollback on purpose');
    }).catch((e: Error) => assert.equal(e.message, 'rollback on purpose', 'the DB accepted a `..` target on a sealed row'));
    await closeRun(db, run, 'ok', {});
  });
  // Through commit: the parser keeps only allowlisted links, so the `..` target never reaches the writer.
  const r2 = await commitDocs(f, c, [decisionLog(decisionEntry('dot dot link', { at: '2026-11-19T11:00:00+01:00', links: ['vault:../up.md', 'gh:Org/repo#3'] }))]);
  assert.equal(r2.decisions, 1);
  const k = keyFor(t);
  try {
    const targets = (await rowsOf<{ id: number; target_uri_ct: Uint8Array }>(f.db, t, 'decision_links', 'id::int AS id, target_uri_ct'))
      .map((x) => k.open('decision_links', 'target_uri', x.id, x.target_uri_ct));
    assert.ok(!targets.some((x) => x.includes('..')), 'no dot segment stored');
    assert.ok(targets.includes('gh:Org/repo#3'));
  } finally {
    k.dispose();
  }
});

test('linkShape equals the SQL CHECK decision_links_target_uri_shape on a table of shapes (both run on a plain workspace); linkTargetKind is linkShape(..)?.kind', async () => {
  const t = await newWorkspace(f, 'off');
  await commitDocs(f, callerOf(t), [decisionLog(decisionEntry('plain decision for links'))]);
  const did = (await rowsOf<{ id: number }>(f.db, t, 'decisions', 'id::int AS id'))[0]!.id;
  const shapes = [
    'gh:Org/repo#7', 'gh:Org/repo', 'gh:Org/repo#0', 'gh:Org/re po', 'vault:notes/a.md', 'vault:notes/a.md#h', 'hq:p/2026-11-19-a.md', 'import:x/y.md',
    'vault:../a.md', 'vault:a/../b.md', 'vault:a/./b.md', 'vault:a/..#x', 'vault:./a.md', 'vault:/abs.md', 'vault:a#b#c', 'job:nightly-sync', 'job:-bad',
    'lane:zeusi-encryption', 'lane:a/b', 'http://x.y/z', 'vault', 'vault:x', `vault:${'a'.repeat(495)}`, `vault:${'a'.repeat(496)}`, 'vault:a\tb.md',
    'vault:a b.md', 'vault: a.md', 'vault:a.md ', 'gh:Org/repo#12345678901',
  ];
  const db = f.db;
  const run = await asOwner(db, async () => (await db.query<{ id: number }>(`INSERT INTO "${t}".ingest_runs (importer, host, mode) VALUES ('t', 'm', 'manual') RETURNING id::int AS id`)).rows[0]!.id);
  for (const s of shapes) {
    const app = linkShape(s);
    assert.equal(linkTargetKind(s), app?.kind ?? null);
    // The SQL CHECK, with the kind the app derived (or every kind, when the app refused: none may pass).
    const kinds = app ? [app.kind] : ['pr', 'repo', 'note', 'job', 'uri'];
    let sqlOk = false;
    for (const kind of kinds) {
      const ok = await asOwner(db, async () => {
        await db.exec('BEGIN');
        try {
          await db.query(
            `INSERT INTO "${t}".decision_links (decision_id, target_kind, target_uri, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
             VALUES ($1, $2::"${t}".link_target_kind, $3, 'work', 'manual', 'import:x', now(), $4, $5)`, [did, kind, s, Buffer.alloc(32, 1), run]);
          return true;
        } catch (e) {
          assert.equal((e as { code?: string }).code, '23514', s);
          return false;
        } finally {
          await db.exec('ROLLBACK');
        }
      });
      sqlOk ||= ok;
    }
    assert.equal(app !== null, sqlOk, `same verdict for ${JSON.stringify(s.slice(0, 40))}`);
  }
});

// ---------------------------------------------------------------------------
// §7.16 / §7.17: dedupe, conflict, explicit applies_to; §7.6 quarantine

test('§7.16 C6b: facts and decisions dedupe on (source_uri_hmac, keyed sha); an edited record is a conflict; links dedupe on (decision_id, target_uri_hmac); applies_to is passed explicitly', async () => {
  const t = await newWorkspace(f, 'verified');
  const c = callerOf(t);
  const log = decisionEntry('ship the sealed path', { links: ['gh:Org/repo#7'], applies: ['zeusi', 'oss'] }) + '\n' + factEntry('rule', 'deploys', 'never deploy on a friday');
  const r1 = await commitDocs(f, c, [decisionLog(log)]);
  assert.deepEqual([r1.decisions, r1.rules], [1, 1]);
  const r2 = await commitDocs(f, c, [decisionLog(log)]);
  assert.deepEqual([r2.decisions, r2.rules], [0, 0], 'deduped');
  assert.deepEqual([(await counts(f.db, t))['decisions'], (await counts(f.db, t))['facts'], (await counts(f.db, t))['decision_links']], [1, 1, 1]);
  // Links stated after the first import are added to the stored decision; a repeated link is not.
  const r3 = await commitDocs(f, c, [decisionLog(decisionEntry('ship the sealed path', { links: ['gh:Org/repo#7', 'vault:notes/plan.md'], applies: ['zeusi', 'oss'] }))]);
  assert.equal(r3.decisions, 0);
  assert.equal((await counts(f.db, t))['decision_links'], 2, 'one new link, the repeated one deduped');
  // An edited record (same header, other words) is a conflict: nothing updated.
  const r4 = await commitDocs(f, c, [decisionLog(decisionEntry('ship something else', { applies: ['zeusi', 'oss'] }))]);
  assert.equal(r4.status, 'ok_partial');
  assert.equal((await counts(f.db, t))['decisions'], 1);
  const d = await openDecisions(t);
  assert.equal(d[0]!.exact_words, 'ship the sealed path');
  assert.deepEqual(JSON.parse(d[0]!.applies_to!), ['zeusi', 'oss'], 'applies_to sealed as a JSON array');
  assert.equal(d[0]!.linked_repo, 'Org/repo');
  assert.equal(d[0]!.key_version, 1);
  // Stored hashes are keyed, never the record's plain digest.
  const rows = await rowsOf<{ source_sha256: Uint8Array; source_uri_hmac: Uint8Array }>(f.db, t, 'decisions', 'source_sha256, source_uri_hmac');
  const k = keyFor(t);
  try {
    assert.deepEqual(Buffer.from(rows[0]!.source_uri_hmac), k.indexHmac('uri', d[0]!.source_uri!));
    assert.notDeepEqual(Buffer.from(rows[0]!.source_uri_hmac), sha(d[0]!.source_uri!));
    for (const l of await rowsOf<{ id: number; target_uri_ct: Uint8Array; target_uri_hmac: Uint8Array; target_uri: string | null }>(f.db, t, 'decision_links', 'id::int AS id, target_uri_ct, target_uri_hmac, target_uri')) {
      assert.equal(l.target_uri, null);
      const target = k.open('decision_links', 'target_uri', l.id, l.target_uri_ct);
      assert.deepEqual(Buffer.from(l.target_uri_hmac), k.indexHmac('uri', target), 'the same uri purpose as notes (C7 joins on it)');
    }
  } finally {
    k.dispose();
  }
  // Every sealed write ran under the index lock and reached the hook.
  const recs = f.hook.filter((h) => h.schema === t && h.kind === 'record');
  assert.ok(recs.length >= 4 && recs.every((h) => h.lockHeld));
  assert.deepEqual([...new Set(recs.map((h) => h.table))].sort(), ['decision_links', 'decisions', 'facts']);
  // And the C5 flip passes on what C6b wrote.
  assert.equal((await f.dir.overlayStep(t, 'flip', { dryRun: false })).outcome, 'applied');
});

test('§7.6 C6b: a structured record and a link quarantined on the sealed route have source_uri \'hmac:...\', a keyed source_sha256 and content_sha256 NULL; a racing 23505 counts deduped', async () => {
  const t = await newWorkspace(f, 'on');
  const term = ['c6b', 'walled', 'word'].join('');
  const out = await sealedSession(t, async (db, route) => {
    const run = await openRun(db, { importer: 'c6b-test', host: 'test', mode: 'manual' });
    const base = await loadWall(db);
    // A test term under an existing rule's id (quarantine.rule_id references wall_denylist).
    const wall = compileWall([...base.rules, { id: Math.max(...base.rules.map((r) => r.id)), kind: 'term', hard: true, pattern: term }], []);
    const w = await writeStructured(db, [
      { record: fact(`a rule with ${term} inside`), project: 'proj' },
      { record: decision('a clean decision with a walled link', { links: ['vault:canvas/board.md', 'vault:notes/ok.md'] }), project: 'proj' },
    ], { scope: 'work', sourceKind: 'manual', uriPrefix: 'import:', runId: run, wall, route });
    await closeRun(db, run, 'ok', {});
    return w;
  });
  assert.equal(out.quarantined, 1, 'the fact');
  assert.equal(out.links_quarantined, 1, 'the canvas link');
  assert.equal(out.links_inserted, 1);
  assert.equal(out.decisions_inserted, 1);
  const q = await rowsOf<{ source_uri: string; source_sha256: Uint8Array; content_sha256: Uint8Array | null; target_table: string }>(f.db, t, 'quarantine', 'source_uri, source_sha256, content_sha256, target_table');
  assert.equal(q.length, 2);
  const k = keyFor(t);
  try {
    const factUri = recordUri('import:', 'proj', fact(`a rule with ${term} inside`));
    for (const row of q) {
      assert.match(row.source_uri, /^hmac:[0-9a-f]{64}$/);
      assert.equal(row.content_sha256, null);
    }
    const fq = q.find((x) => x.target_table === 'facts')!;
    assert.equal(fq.source_uri, k.quarantineRef(factUri));
    assert.ok(!JSON.stringify(q).includes(term) && !q.some((x) => x.source_uri.includes('import:')));
  } finally {
    k.dispose();
  }
  // A concurrent run that already stored the same (source_uri_hmac, keyed sha): 23505 -> deduped, nothing thrown.
  const again = await sealedSession(t, async (db, route) => {
    const run = await openRun(db, { importer: 'c6b-test', host: 'test', mode: 'manual' });
    // The dedupe SELECT is skipped by asking for the record under a racing seam: plant the row first, then
    // write the same record through a wrapper whose dedupe lookup sees nothing.
    const blind: Db = { ...db, query: (sql, p) => (/WHERE source_uri_hmac = \$1::bytea/.test(sql) ? Promise.resolve({ rows: [] } as never) : db.query(sql, p)) };
    const w = await writeStructured(blind, [{ record: decision('a clean decision with a walled link', { links: ['vault:notes/ok.md'] }), project: 'proj' }],
      { scope: 'work', sourceKind: 'manual', uriPrefix: 'import:', runId: run, wall: await loadWall(db), route });
    await closeRun(db, run, 'ok', {});
    return w;
  });
  assert.equal(again.deduped, 1);
  assert.equal(again.decisions_inserted, 0);
  assert.equal((await counts(f.db, t))['decisions'], 1);
});

test('the plain route of writeStructured / insertDecisionLinks is unchanged (the team-style plain rows; an off-list target still throws)', async () => {
  const t = await newWorkspace(f, 'off');
  const r = await commitDocs(f, callerOf(t), [decisionLog(decisionEntry('plain words', { links: ['gh:Org/repo#9'] }))]);
  assert.equal(r.decisions, 1);
  const d = await rowsOf<{ exact_words: string; key_version?: unknown }>(f.db, t, 'decisions', 'exact_words');
  assert.equal(d[0]!.exact_words, 'plain words');
  const db = await writerOpen(t);
  try {
    await assert.rejects(insertDecisionLinks(db, {
      decisionId: 1, scope: 'work', sourceKind: 'manual', sourceUri: 'import:x', sourceTs: '2026-11-19T09:00:00Z', runId: 1, targets: ['vault:../x.md'],
    }), /not on the allowlist/);
    await assert.rejects(insertDecisionLinks(db, {
      decisionId: 1, scope: 'work', sourceKind: 'manual', sourceUri: 'import:x', sourceTs: '2026-11-19T09:00:00Z', runId: 1, targets: ['gh:Org/repo#9'],
      route: { kind: 'sealed', key: keyFor(t), tenantId: t, index: NO_INDEX_HOOK },
    }), /inside the record's sealed transaction/, 'a sealed link outside a sealed transaction is refused');
  } finally {
    await db.close();
  }
  assert.equal(PLAIN_ROUTE.kind, 'plain');
});

// ---------------------------------------------------------------------------
// One caller of quarantine_record (KTD12)

test('quarantine_record is called only from src/wall.ts (and granted in src/tenant-ddl.ts): every other caller goes through recordQuarantine', () => {
  const hits: string[] = [];
  const walk = (dir: string) => {
    for (const n of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, n.name);
      if (n.isDirectory()) walk(p);
      else if (/\.ts$/.test(n.name) && /quarantine_record\(/.test(readFileSync(p, 'utf8'))) hits.push(p);
    }
  };
  walk('src');
  assert.deepEqual(hits.sort(), ['src/tenant-ddl.ts', 'src/wall.ts']);
  const wall = readFileSync('src/wall.ts', 'utf8');
  assert.equal((wall.match(/quarantine_record\(/g) ?? []).length, 1, 'one call site in wall.ts');
  for (const p of ['src/facts.ts', 'src/decisions.ts', 'src/importers/vault.ts', 'src/importers/structured.ts', 'src/decision-links.ts']) {
    assert.match(readFileSync(p, 'utf8'), /recordQuarantine\(/, p);
  }
});
