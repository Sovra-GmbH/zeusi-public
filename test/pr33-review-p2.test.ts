// #33 review r1 P2s, pinned: P2-1 the team zeusi_startup path runs no emptiness (or person) query;
// P2-2 the `secret` kept-as-note reason; P2-3 the warning names decision, rule or focus entries.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { Db } from '../src/db.ts';
import { PERSONAL_DECISIONS_HANDLE, PERSONAL_DECISIONS_PENDING } from '../src/about.ts';
import { parseStructuredBody } from '../src/importers/structured.ts';
import { createMcpState, createZeusiMcpServer } from '../src/mcp-server.ts';
import { migrate } from '../src/migrate.ts';
import { keptAsNotes } from '../src/workspace-write.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { pgliteDb } from './pglite-db.ts';
import { fakeGoogleKey } from './secret-fixtures.ts';

test('P2-1: the team zeusi_startup runs no emptiness query and no person lookup (counting db)', async () => {
  const sdb = await pgliteDb();
  await migrate(sdb);
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-p21-'));
  writeFileSync(join(home, '.pg_service.conf'),
    '[zeusi_ro]\nhost=ep-fake-1.eu-central-1.aws.neon.tech\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n');
  const seen: string[] = [];
  const server = createZeusiMcpServer({
    env: { HOME: home }, home, readService: 'zeusi_ro', embeddings: () => null,
    connectRead: async () => {
      await sdb.exec('SET ROLE zeusi_box_ro');
      return {
        label: 'counting', exec: (sql) => { seen.push(sql); return sdb.exec(sql); }, query: (sql, params) => { seen.push(sql); return sdb.query(sql, params); },
        close: async () => { await sdb.exec('RESET ROLE'); },
      } as Db;
    },
    feedbackPath: join(home, 'fb.jsonl'), queryLedgerPath: join(home, 'ledger.json'),
  }, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  try {
    const r = (await client.callTool({ name: 'zeusi_startup', arguments: {} })) as { isError?: boolean };
    assert.notEqual(r.isError, true);
    assert.ok(seen.some((s) => s.includes('zeusi.facts_current')), 'the counter sees the startup queries');
    const extra = seen.filter((s) => /zeusi\.chunks|zeusi\.people WHERE handle|AS n FROM \(SELECT 1 FROM/.test(s));
    assert.deepEqual(extra, [], 'no emptiness count and no person lookup on the team path');
  } finally {
    await client.close();
    await server.close();
    await sdb.close();
  }
});

test('P2-2: a headed entry withheld by the secret detector is counted with reason `secret` and explained', () => {
  const body = `## 2026-11-18T10:00:00+01:00 me\nDecision: go\nSaid-at-precision: minute\n\nSYNTHETIC use ${fakeGoogleKey()} in prod.\n`;
  const r = parseStructuredBody(body);
  assert.equal(r.records.length, 0);
  assert.equal(r.counts.secret, 1);
  assert.deepEqual(r.keptAsNote, { secret: 1 });
  const k = keptAsNotes(r.keptAsNote)!;
  assert.deepEqual(k.reasons.map((x) => [x.reason, x.count]), [['secret', 1]]);
  assert.match(k.reasons[0]!.why, /withheld by the secret detector/);
});

test('P2-3: the warning names decision, rule or focus entries', () => {
  for (const t of [PERSONAL_DECISIONS_PENDING, PERSONAL_DECISIONS_HANDLE]) assert.match(t, /decision, rule or focus entry/);
});
