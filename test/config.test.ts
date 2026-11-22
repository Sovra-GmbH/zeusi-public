import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deriveDirectFromPooled, describeUrl, prepareUrl, resolveUrl, ConfigError } from '../src/config.ts';
import { validateFact, ValidationError, dummyVector } from '../src/facts.ts';

// Fake credentials only; never real values.
// Assembled at runtime so no credential-shaped URL literal sits in the repo.
const POOLED = ['postgresql', '://u:', 'fakepw', '@ep-test-123-pooler.eu-central-1.aws.neon.tech/zeusi?sslmode=require&channel_binding=require'].join('');

test('direct URL prefers explicit names, else derives from the Neon pooler host', () => {
  assert.equal(resolveUrl('direct', { DATABASE_URL_UNPOOLED: 'postgresql://a@direct/x', DATABASE_URL: POOLED }).sourceName, 'DATABASE_URL_UNPOOLED');
  const d = resolveUrl('direct', { DATABASE_URL: POOLED });
  assert.match(d.sourceName, /derived/);
  assert.match(d.url, /ep-test-123\.eu-central-1/);
  assert.equal(deriveDirectFromPooled('postgresql://u@localhost/x'), undefined);
  assert.throws(() => resolveUrl('direct', {}), ConfigError);
  assert.throws(() => resolveUrl('pooled', {}), ConfigError);
});

test('TLS cannot be disabled; tls params are stripped for explicit driver config', () => {
  assert.throws(() => prepareUrl(['postgresql://', 'h/db?sslmode=disable'].join('')), /TLS is required/);
  assert.throws(() => prepareUrl(['postgresql://', 'h/db?sslmode=prefer'].join('')), /TLS is required/);
  assert.doesNotMatch(prepareUrl(POOLED), /sslmode|channel_binding/);
});

test('errors and labels never include credentials', () => {
  assert.equal(describeUrl(POOLED), 'ep-test-123-pooler.eu-central-1.aws.neon.tech/zeusi');
  try {
    prepareUrl('not a url with secret fakepw');
  } catch (e) {
    assert.doesNotMatch((e as Error).message, /fakepw/);
  }
});

test('invent=NO client-side validation', () => {
  assert.throws(() => validateFact({ kind: 'other', text: 'x', scope: 'work', sourceKind: 'manual' }), /sourceUri, sourceTs, sourceSha256/);
  assert.throws(() => validateFact({ kind: 'other', text: 'x', scope: 'plankiva' as never, sourceKind: 'manual', sourceUri: 'u', sourceTs: '2026-01-01', sourceSha256: 'ab'.repeat(32) }), ValidationError);
  assert.ok(validateFact({ kind: 'other', text: 'x', scope: 'client', sourceKind: 'manual', sourceUri: 'u', sourceTs: '2026-01-01', sourceSha256: 'ab'.repeat(32) })); // 0010
  assert.throws(() => validateFact({ kind: 'other', text: 'x', scope: 'personal', sourceKind: 'manual', sourceUri: 'u', sourceTs: '2026-01-01', sourceSha256: 'ab'.repeat(32) }), /personal/);
  assert.throws(() => validateFact({ kind: 'other', text: 'x', scope: 'work', sourceKind: 'manual', sourceUri: 'u', sourceTs: '2026-01-01', sourceSha256: 'zz' }), /64 hex/);
  assert.ok(validateFact({ kind: 'other', text: 'x', scope: 'work', sourceKind: 'manual', sourceUri: 'u', sourceTs: '2026-01-01', sourceSha256: 'ab'.repeat(32) }));
});

test('dummy vector has 1536 dims and is non-zero', () => {
  const v = JSON.parse(dummyVector(3)) as number[];
  assert.equal(v.length, 1536);
  assert.ok(v.some((x) => x !== 0));
});
