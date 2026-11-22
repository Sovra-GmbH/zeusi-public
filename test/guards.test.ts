// r1 MINOR-5 / MINOR-7: owner-path guards, all offline (no network, no .env.local).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ConfigError } from '../src/config.ts';
import { connectOwner, type Db } from '../src/db.ts';
import { endpointIdOf, mainBranchGuard } from '../src/owner-guard.ts';
import { migrate } from '../src/migrate.ts';

const url = (host: string) => ['postgresql://', 'u', ':', 'fakePw', '@', host, '/zeusi'].join('');

test('endpointIdOf: first host label, -pooler removed', () => {
  assert.equal(endpointIdOf(url('ep-a-1-pooler.eu-central-1.aws.neon.tech')), 'ep-a-1');
  assert.equal(endpointIdOf(url('ep-a-1.eu-central-1.aws.neon.tech')), 'ep-a-1');
  assert.equal(endpointIdOf('not a url'), undefined);
});

test('mainBranchGuard: refuses unless the target is provably not main, or --i-know-this-is-main', () => {
  const branch = url('ep-branch-2-pooler.eu-central-1.aws.neon.tech');
  const main = url('ep-main-1-pooler.eu-central-1.aws.neon.tech');
  assert.throws(() => mainBranchGuard(branch, {}, false), /ZEUSI_MAIN_ENDPOINT_ID/);
  assert.throws(() => mainBranchGuard(main, { ZEUSI_MAIN_ENDPOINT_ID: 'ep-main-1' }, false), /default branch/);
  assert.throws(() => mainBranchGuard(main, { ZEUSI_MAIN_ENDPOINT_ID: 'EP-MAIN-1 ' }, false), /default branch/);
  assert.throws(() => mainBranchGuard('garbage', { ZEUSI_MAIN_ENDPOINT_ID: 'ep-main-1' }, false), /cannot read the endpoint/);
  assert.deepEqual(mainBranchGuard(branch, { ZEUSI_MAIN_ENDPOINT_ID: 'ep-main-1' }, false), { onMain: false });
  assert.deepEqual(mainBranchGuard(main, { ZEUSI_MAIN_ENDPOINT_ID: 'ep-main-1' }, true), { onMain: true });
  assert.deepEqual(mainBranchGuard(branch, {}, true), { onMain: true });
  // r2 MINOR-A: the configured id is normalised like the target (first host label,
  // -pooler stripped, lower-case); anything that is not ^ep-[a-z0-9-]+$ is refused.
  for (const cfg of ['ep-main-1-pooler', 'ep-main-1.eu-central-1.aws.neon.tech', 'EP-MAIN-1-POOLER.eu-central-1.aws.neon.tech', ' ep-main-1-pooler.eu-central-1.aws.neon.tech ']) {
    assert.throws(() => mainBranchGuard(main, { ZEUSI_MAIN_ENDPOINT_ID: cfg }, false), /default branch/, cfg);
    assert.deepEqual(mainBranchGuard(branch, { ZEUSI_MAIN_ENDPOINT_ID: cfg }, false), { onMain: false }, cfg);
  }
  for (const cfg of ['main', 'ep_main_1', 'ep-', 'postgresql://u@ep-main-1.neon.tech/db', 'ep-main-1/x', 'xep-main-1', 'ep-mäin-1', '-pooler']) {
    assert.throws(() => mainBranchGuard(branch, { ZEUSI_MAIN_ENDPOINT_ID: cfg }, false), /not a Neon endpoint id/, cfg);
  }
  // Messages never carry the host, endpoint id or URL.
  for (const [u, env] of [[main, { ZEUSI_MAIN_ENDPOINT_ID: 'ep-main-1' }], [branch, {}]] as const) {
    try {
      mainBranchGuard(u, env, false);
    } catch (e) {
      assert.doesNotMatch((e as Error).message, /fakePw|ep-main-1|ep-branch-2|neon\.tech|postgres/);
    }
  }
});

test('connectOwner: ZEUSI_CHANNEL_BINDING=off without the explicit flag is refused before connecting', async () => {
  const env = { DATABASE_URL: url('ep-x-1-pooler.invalid'), ZEUSI_CHANNEL_BINDING: 'off' };
  await assert.rejects(connectOwner('pooled', env), (e: unknown) => e instanceof ConfigError && /--insecure-no-channel-binding/.test((e as Error).message));
  await assert.rejects(connectOwner('pooled', { ...env, ZEUSI_CHANNEL_BINDING: 'weird' }), ConfigError);
});

test('migrate takes the session advisory lock before it reads the applied list, and releases it', async () => {
  const seen: string[] = [];
  const fake: Db = {
    label: 'fake',
    async query<T>(sql: string) {
      seen.push(sql.replace(/\s+/g, ' ').trim());
      if (/to_regclass/.test(sql)) return { rows: [{ t: 'zeusi.schema_migrations' }] as T[] };
      if (/FROM zeusi.schema_migrations/.test(sql)) throw new Error('stop after the read');
      return { rows: [] as T[] };
    },
    async exec(sql: string) {
      seen.push(sql.trim());
    },
    async close() {},
  };
  await assert.rejects(migrate(fake), /stop after the read/);
  const lock = seen.findIndex((s) => /pg_advisory_lock\(/.test(s));
  const read = seen.findIndex((s) => /to_regclass/.test(s));
  assert.ok(lock >= 0 && lock < read, seen.join(' | '));
  assert.ok(seen.findIndex((s) => /pg_advisory_unlock\(/.test(s)) > read, 'unlocked in finally');
});
