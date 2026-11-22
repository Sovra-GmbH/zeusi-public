// r2 MINOR-1: the vault importer holds a SESSION advisory lock, which does not hold over
// Neon's pooled (PgBouncer transaction mode) endpoint. The importer's service must be the
// direct endpoint; a pooled host is refused offline, before any password read or connect.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connectDirectService, isPooledHost, PooledEndpointRefused, requireDirectEndpoint } from '../src/endpoint-guard.ts';
import { resolveService } from '../src/service.ts';
import { ConfigError } from '../src/config.ts';
import type { Db } from '../src/db.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

// Fake hosts assembled at runtime; never real.
const POOLED = ['ep-x', '-pooler.example.invalid'].join('');
const DIRECT = ['ep-x', '.example.invalid'].join('');

function svcFile(host: string): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-eg-'));
  const p = join(dir, 'pg_service.conf');
  writeFileSync(p, `[zeusi_ingest]\nhost=${host}\nport=5432\ndbname=zeusi\nuser=zeusi_mini_ingest\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
  return p;
}
const env = (file: string) => ({ env: { PGSERVICEFILE: file } });

test('isPooledHost: "-pooler" in any letter case is pooled; the direct host is not', () => {
  for (const h of [POOLED, POOLED.toUpperCase(), POOLED.replace('-pooler', '-Pooler'), 'EP-X-POOLER.c-2.eu-central-1.aws.example.invalid']) {
    assert.equal(isPooledHost(h), true, 'pooled variant');
  }
  for (const h of [DIRECT, DIRECT.toUpperCase(), 'ep-pool-1.example.invalid', 'localhost']) assert.equal(isPooledHost(h), false, 'direct variant');
});

test('requireDirectEndpoint: a pooled host is refused naming service and file, never the host', () => {
  for (const host of [POOLED, POOLED.toUpperCase(), POOLED.replace('-pooler', '-PoOlEr')]) {
    const file = svcFile(host);
    assert.throws(() => requireDirectEndpoint('zeusi_ingest', env(file)), (e: Error) => {
      assert.ok(e instanceof PooledEndpointRefused && e instanceof ConfigError, 'ConfigError subclass (CLI exit 2)');
      assert.match(e.message, /zeusi_ingest/);
      assert.ok(e.message.includes(file), 'names the file');
      assert.match(e.message, /pooled/i);
      assert.match(e.message, /direct/i);
      assert.match(e.message, /no connection made/i);
      assert.ok(!e.message.toLowerCase().includes('ep-x') && !e.message.toLowerCase().includes('example.invalid'), 'no host text');
      return true;
    });
  }
});

test('requireDirectEndpoint: a direct host is accepted; the TLS checks still apply', () => {
  const svc = requireDirectEndpoint('zeusi_ingest', env(svcFile(DIRECT)));
  assert.equal(svc.host, DIRECT);
  assert.equal(svc.sslmode, 'verify-full');
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-eg-'));
  const weak = join(dir, 'pg_service.conf');
  writeFileSync(weak, `[zeusi_ingest]\nhost=${DIRECT}\ndbname=zeusi\nuser=zeusi_mini_ingest\nsslmode=require\nsslrootcert=system\nchannel_binding=require\n`);
  assert.throws(() => requireDirectEndpoint('zeusi_ingest', env(weak)), (e: Error) => e instanceof ConfigError && /verify-full/.test(e.message));
});

test('connectDirectService: pooled ⇒ refused before connect (so no password is read); direct ⇒ connects', async () => {
  const calls: string[] = [];
  const fakeDb = { label: 'fake', close: async () => {} } as unknown as Db;
  const deps = (file: string) => ({
    resolve: (name: string) => { calls.push(`resolve ${name}`); return resolveService(name, env(file)); },
    connect: async (name: string) => { calls.push(`connect ${name}`); return fakeDb; },
  });
  await assert.rejects(connectDirectService('zeusi_ingest', deps(svcFile(POOLED))), PooledEndpointRefused);
  assert.deepEqual(calls, ['resolve zeusi_ingest'], 'connect (which reads the password) never called');
  calls.length = 0;
  assert.equal(await connectDirectService('zeusi_ingest', deps(svcFile(DIRECT))), fakeDb);
  assert.deepEqual(calls, ['resolve zeusi_ingest', 'connect zeusi_ingest']);
});
