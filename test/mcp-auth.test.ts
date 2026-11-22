// Hosted MCP auth gate (src/mcp-auth.ts), sliding-window limiter (src/rate-limit.ts) and the
// allowlisted request log builder (src/mcp-log.ts). Pure request-level logic: no HTTP server.
// Every failed-auth test counts slow-hash calls through the injected verify seam.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Authenticator, type AuthResult } from '../src/mcp-auth.ts';
import { SlidingWindowLimiter } from '../src/rate-limit.ts';
import { buildLogLine, LOG_FIELDS, type RequestLogRecord } from '../src/mcp-log.ts';
import { generateToken, hashSecret, verifySecret, withTokenFile, type TokenRow } from '../src/mcp-tokens.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const FAST = { alg: 'argon2id' as const, params: { m: 64, t: 1, p: 1, dkLen: 32 } };

interface Minted { token: string; row: TokenRow }

async function mint(over: Partial<TokenRow> = {}, now = Date.now()): Promise<Minted> {
  const g = generateToken();
  return {
    token: g.token,
    row: {
      token_id: g.tokenId, assistant: 'atlas', class: 'read', hash: await hashSecret(g.tokenId, g.secret, FAST),
      issued_at: new Date(now - 1000).toISOString(), expires_at: new Date(now + 86_400_000).toISOString(), revoked_at: null, ...over,
    },
  };
}

function storeDir(): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-auth-'));
  chmodSync(d, 0o700);
  return d;
}

async function store(rows: TokenRow[]): Promise<string> {
  const p = join(storeDir(), 'mcp-tokens.json');
  await withTokenFile(p, () => ({ version: 1 as const, tokens: rows }));
  return p;
}

/** Authenticator with a fake clock and a counting hash. */
function auth(tokensPath: string) {
  let t = Date.now();
  const calls = { n: 0 };
  const a = new Authenticator({
    tokensPath, now: () => t,
    verify: async (row, secret) => { calls.n++; return verifySecret(row, secret); },
  });
  return { a, calls, advance: (ms: number) => { t += ms; }, now: () => t };
}

const bearer = (tok: string) => [`Bearer ${tok}`];
const strip = (r: AuthResult) => (r.ok ? r : { ok: r.ok, status: r.status, errorClass: r.errorClass });

// ---------------------------------------------------------------------------
// Fail closed

test('auth: an unconfigured store answers 503 not_configured for any header, with zero hash calls', async () => {
  const missing = join(storeDir(), 'mcp-tokens.json');
  const loose = join(storeDir(), 'mcp-tokens.json');
  writeFileSync(loose, JSON.stringify({ version: 1, tokens: [] }), { mode: 0o644 });
  chmodSync(loose, 0o644);
  for (const p of [missing, loose]) {
    const { a, calls } = auth(p);
    for (const h of [[], ['Basic x'], bearer(generateToken().token), bearer('nope')]) {
      const r = await a.authenticate(h, '198.51.100.7');
      assert.deepEqual(strip(r), { ok: false, status: 503, errorClass: 'not_configured' });
    }
    assert.equal(calls.n, 0);
  }
});

test('auth: a configured store with zero usable rows answers the same 401 as an unknown id, revealing no count', async () => {
  const revoked = await mint({ revoked_at: new Date().toISOString() });
  const empty = auth(await store([]));
  const onlyRevoked = auth(await store([revoked.row]));
  const unknown = generateToken().token;
  const r1 = await empty.a.authenticate(bearer(unknown), '198.51.100.7');
  const r2 = await onlyRevoked.a.authenticate(bearer(unknown), '198.51.100.7');
  assert.deepEqual(strip(r1), strip(r2));
  assert.deepEqual(strip(r1), { ok: false, status: 401, errorClass: 'unauthorized' });
  assert.ok(!/count|tokens?\b|\d+ /i.test(JSON.stringify(strip(r1)).replace(/"errorClass":"unauthorized"/, '')));
});

test('auth: every failure mode returns an identical generic 401; unknown/revoked/expired do not hash, a wrong secret hashes once', async () => {
  const now = Date.now();
  const live = await mint();
  const revoked = await mint({ revoked_at: new Date(now - 1).toISOString() });
  const expired = await mint({ expires_at: new Date(now - 1).toISOString() });
  const { a, calls } = auth(await store([live.row, revoked.row, expired.row]));
  const wrong = `zeusi_${live.row.token_id}_${generateToken().secret}`;
  const cases: Array<[string, string[], number]> = [
    ['no header', [], 0],
    ['Basic scheme', ['Basic dXNlcjpwYXNz'], 0],
    ['two Authorization values', [`Bearer ${live.token}`, `Bearer ${live.token}`], 0],
    ['two spaces', [`Bearer  ${live.token}`], 0],
    ['malformed token', bearer('zeusi_short_x'), 0],
    ['unknown id', bearer(generateToken().token), 0],
    ['revoked row', bearer(revoked.token), 0],
    ['expired row', bearer(expired.token), 0],
    ['wrong secret', bearer(wrong), 1],
  ];
  const results = [];
  for (const [name, h, hashes] of cases) {
    const before = calls.n;
    // distinct IPs so the failed-auth limit does not interfere
    const r = await a.authenticate(h, `198.51.100.${results.length + 1}`);
    assert.equal(calls.n - before, hashes, `${name}: hash calls`);
    results.push(strip(r));
  }
  for (const r of results) assert.deepEqual(r, { ok: false, status: 401, errorClass: 'unauthorized' });
  // the scheme is case-insensitive; the live token passes
  const ok = await a.authenticate([`bEaReR ${live.token}`], '198.51.100.99');
  assert.ok(ok.ok);
  if (ok.ok) assert.deepEqual(ok.principal, { tokenId: live.row.token_id, assistant: 'atlas', cls: 'read', tenant: 'work' });
});

// ---------------------------------------------------------------------------
// R5: failed-auth limit before hashing

test('auth R5: 10 failures/min per IP then 429 without hashing; other IPs until 60 global; reset after 60 s', async () => {
  const live = await mint();
  const { a, calls, advance } = auth(await store([live.row]));
  const wrong = () => `zeusi_${live.row.token_id}_${generateToken().secret}`;
  for (let i = 0; i < 10; i++) assert.equal((await a.authenticate(bearer(wrong()), '203.0.113.1') as { status: number }).status, 401);
  assert.equal(calls.n, 10);
  const r11 = await a.authenticate(bearer(wrong()), '203.0.113.1');
  assert.deepEqual(strip(r11), { ok: false, status: 429, errorClass: 'auth_rate_limited' });
  assert.ok(!r11.ok && (r11.retryAfterSec ?? 0) >= 1);
  assert.equal(calls.n, 10, 'the 11th did not hash');
  // a fresh IP still gets 401 until the global 60 is reached
  let ip = 0;
  for (let i = 10; i < 60; i++) {
    const r = await a.authenticate(bearer(wrong()), `203.0.113.${100 + (ip++ % 50)}`);
    assert.equal((r as { status: number }).status, 401, `failure ${i + 1}`);
  }
  const before = calls.n;
  const g = await a.authenticate(bearer(wrong()), '192.0.2.200');
  assert.deepEqual(strip(g), { ok: false, status: 429, errorClass: 'auth_rate_limited' });
  assert.equal(calls.n, before, 'global limit: no hash');
  // even a VALID token that is not cached is refused while the gate is closed (no hash budget left)
  assert.equal((await a.authenticate(bearer(live.token), '192.0.2.201') as { status: number }).status, 429);
  advance(60_001);
  assert.equal((await a.authenticate(bearer(wrong()), '203.0.113.1') as { status: number }).status, 401, 'window passed');
  assert.ok((await a.authenticate(bearer(live.token), '203.0.113.1')).ok);
});

test('auth: malformed headers count per IP without hashing', async () => {
  const { a, calls } = auth(await store([(await mint()).row]));
  for (let i = 0; i < 10; i++) await a.authenticate(['Bearer nope'], '203.0.113.9');
  const r = await a.authenticate(bearer(generateToken().token), '203.0.113.9');
  assert.equal((r as { status: number }).status, 429);
  assert.equal(calls.n, 0);
});

test('auth P2-1: malformed, unknown-id, revoked and expired failures (no hash) from many IPs never close the global gate', async () => {
  const now = Date.now();
  const live = await mint();
  const revoked = await mint({ revoked_at: new Date(now - 1).toISOString() });
  const expired = await mint({ expires_at: new Date(now - 1).toISOString() });
  const { a, calls } = auth(await store([live.row, revoked.row, expired.row]));
  const junk = [['Bearer nope'], [], bearer(generateToken().token), bearer(revoked.token), bearer(expired.token)];
  // 200 no-hash failures spread over 40 IPs (5 each, under the per-IP 10): far past the global 60
  for (let i = 0; i < 200; i++) {
    const r = await a.authenticate(junk[i % junk.length]!, `198.18.0.${i % 40}`);
    assert.equal((r as { status: number }).status, 401, `junk ${i}`);
  }
  assert.equal(calls.n, 0);
  const ok = await a.authenticate(bearer(live.token), '192.0.2.77');
  assert.ok(ok.ok, 'an uncached real token still authenticates (global bucket untouched)');
  // ... while the per-IP bucket still counts them: 10 junk from one IP close that IP
  for (let i = 0; i < 10; i++) await a.authenticate(['Bearer nope'], '198.18.1.1');
  assert.equal((await a.authenticate(bearer(generateToken().token), '198.18.1.1') as { status: number }).status, 429);
});

test('auth P2-3: concurrent wrong secrets for a known id cannot all pass the gate; in-flight hashes count against per IP, global and the queue cap', async () => {
  const live = await mint();
  const p = await store([live.row]);
  const wrong = () => bearer(`zeusi_${live.row.token_id}_${generateToken().secret}`);
  function gated(o: { failedPerIp?: number; failedGlobal?: number; maxInflightHashes?: number }) {
    const started: Array<() => void> = [];
    const a = new Authenticator({
      tokensPath: p, ...o,
      // a slow verifier the test releases by hand: nothing finishes until release()
      verify: (row, secret) => new Promise<boolean>((res) => { started.push(() => { void verifySecret(row, secret).then(res); }); }),
    });
    return { a, started, release: () => { for (const f of started.splice(0)) f(); } };
  }
  const statuses = (rs: AuthResult[]) => rs.map((r) => (r.ok ? 200 : r.status)).sort().join(',');

  // one IP: 15 concurrent -> exactly 10 hashes start, 5 are 429 before hashing
  {
    const g = gated({ maxInflightHashes: 100 });
    const pending = Array.from({ length: 15 }, () => g.a.authenticate(wrong(), '203.0.113.30'));
    await new Promise((r) => setImmediate(r));
    assert.equal(g.started.length, 10, 'per-IP: in-flight hashes reserve failure slots');
    g.release();
    assert.equal(statuses(await Promise.all(pending)), [...Array(10).fill(401), ...Array(5).fill(429)].sort().join(','));
    assert.equal(g.a.inflightHashes(), 0);
  }
  // many IPs, global 5: exactly 5 hashes start
  {
    const g = gated({ failedGlobal: 5, maxInflightHashes: 100 });
    const pending = Array.from({ length: 12 }, (_, i) => g.a.authenticate(wrong(), `203.0.113.${40 + i}`));
    await new Promise((r) => setImmediate(r));
    assert.equal(g.started.length, 5, 'global: in-flight hashes reserve failure slots');
    g.release();
    await Promise.all(pending);
  }
  // many IPs, defaults: the queue cap (8) bounds hashes in flight even under the global 60
  {
    const g = gated({});
    const pending = Array.from({ length: 30 }, (_, i) => g.a.authenticate(wrong(), `203.0.113.${100 + i}`));
    await new Promise((r) => setImmediate(r));
    assert.equal(g.started.length, 8, 'at most MAX_INFLIGHT_HASHES queued');
    assert.equal(g.a.inflightHashes(), 8);
    g.release();
    const rs = await Promise.all(pending);
    assert.equal(rs.filter((r) => !r.ok && r.status === 429).length, 22);
    assert.equal(g.a.inflightHashes(), 0);
    // a success releases its slot too
    const okP = g.a.authenticate(bearer(live.token), '203.0.113.200');
    await new Promise((r) => setImmediate(r));
    assert.equal(g.a.inflightHashes(), 1);
    g.release();
    assert.ok((await okP).ok);
    assert.equal(g.a.inflightHashes(), 0);
  }
});

// ---------------------------------------------------------------------------
// R6: success cache, revocation on file change

test('auth R6: a second request with a valid token within 5 minutes does not hash; a revoke written to the file applies on the next request', async () => {
  const live = await mint();
  const other = await mint({ assistant: 'lyra' });
  const p = await store([live.row, other.row]);
  const { a, calls, advance } = auth(p);
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.1')).ok);
  assert.equal(calls.n, 1);
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.1')).ok);
  advance(4 * 60_000);
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.1')).ok);
  assert.equal(calls.n, 1, 'cached');
  advance(60_001 + 1); // past the 5-minute TTL from the first fill
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.1')).ok);
  assert.equal(calls.n, 2, 'TTL expired: one more hash');
  // revoke through the writer (as the CLI does)
  await withTokenFile(p, (doc) => ({ ...doc, tokens: doc.tokens.map((t) => (t.token_id === live.row.token_id ? { ...t, revoked_at: new Date().toISOString() } : t)) }));
  const r = await a.authenticate(bearer(live.token), '198.51.100.1');
  assert.deepEqual(strip(r), { ok: false, status: 401, errorClass: 'unauthorized' });
  // the other token still works
  assert.ok((await a.authenticate(bearer(other.token), '198.51.100.1')).ok);
});

test('auth R6: any tokens-file change drops the success cache (a row whose hash was replaced in place no longer accepts the old token)', async () => {
  const live = await mint();
  const p = await store([live.row]);
  const { a, calls } = auth(p);
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.2')).ok);
  // same token_id, new secret: an operator re-keyed the row by hand
  const g = generateToken();
  const rehash = await hashSecret(live.row.token_id, g.secret, FAST);
  await withTokenFile(p, (doc) => ({ ...doc, tokens: doc.tokens.map((t) => ({ ...t, hash: rehash })) }));
  const before = calls.n;
  assert.deepEqual(strip(await a.authenticate(bearer(live.token), '198.51.100.2')), { ok: false, status: 401, errorClass: 'unauthorized' });
  assert.equal(calls.n - before, 1, 'the old token was re-verified, not served from the cache');
  assert.ok((await a.authenticate(bearer(`zeusi_${live.row.token_id}_${g.secret}`), '198.51.100.2')).ok);
});

test('auth P2-2: a cache hit still re-checks expiry: past expires_at but inside the 5-minute TTL is a 401, without hashing', async () => {
  const t0 = Date.now();
  const live = await mint({ expires_at: new Date(t0 + 60_000).toISOString() }, t0);
  const { a, calls, advance } = auth(await store([live.row]));
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.60')).ok);
  assert.equal(calls.n, 1);
  advance(30_000);
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.60')).ok, 'cache hit before expiry');
  assert.equal(calls.n, 1);
  advance(60_000); // 90 s after the fill: expired, cache entry still inside its 5-minute TTL
  const r = await a.authenticate(bearer(live.token), '198.51.100.60');
  assert.deepEqual(strip(r), { ok: false, status: 401, errorClass: 'unauthorized' });
  assert.equal(calls.n, 1, 'no hash');
});

test('auth: a cached valid token still passes while its IP is over the failed-auth limit; a wrong secret for a cached id does not ride the cache', async () => {
  const live = await mint();
  const { a, calls } = auth(await store([live.row]));
  assert.ok((await a.authenticate(bearer(live.token), '203.0.113.50')).ok);
  const wrong = `zeusi_${live.row.token_id}_${generateToken().secret}`;
  for (let i = 0; i < 10; i++) assert.equal((await a.authenticate(bearer(wrong), '203.0.113.50') as { status: number }).status, 401);
  assert.equal((await a.authenticate(bearer(wrong), '203.0.113.50') as { status: number }).status, 429);
  const n = calls.n;
  assert.ok((await a.authenticate(bearer(live.token), '203.0.113.50')).ok, 'cache hit bypasses the gate');
  assert.equal(calls.n, n);
});

test('auth: the file going missing after a good load turns the server to 503 (fail closed), and back when restored', async () => {
  const live = await mint();
  const p = await store([live.row]);
  const { a } = auth(p);
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.1')).ok);
  chmodSync(p, 0o644);
  assert.equal((await a.authenticate(bearer(live.token), '198.51.100.1') as { status: number }).status, 503, 'cache does not outlive a broken file');
  chmodSync(p, 0o600);
  assert.ok((await a.authenticate(bearer(live.token), '198.51.100.1')).ok);
});

// ---------------------------------------------------------------------------
// Limiter

test('limiter: 60 per minute per key, the 61st refused with a retry-after; a cost-3 batch at 59 used is refused whole', () => {
  const l = new SlidingWindowLimiter();
  const t0 = 1_000_000;
  for (let i = 0; i < 60; i++) {
    assert.equal(l.retryAfter('k', 60, 1, t0 + i), 0);
    l.add('k', 1, t0 + i);
  }
  const ra = l.retryAfter('k', 60, 1, t0 + 100);
  assert.ok(ra >= 1 && ra <= 60, String(ra));
  assert.equal(l.retryAfter('other', 60, 1, t0 + 100), 0, 'keys are independent');
  const m = new SlidingWindowLimiter();
  for (let i = 0; i < 59; i++) m.add('b', 1, t0);
  assert.ok(m.retryAfter('b', 60, 3, t0) > 0, 'batch of 3 at 59 refused');
  assert.equal(m.retryAfter('b', 60, 1, t0), 0, 'a single call still fits');
  assert.equal(m.retryAfter('b', 60, 3, t0 + 60_001), 0, 'window passed');
});

test('limiter: the key map stays under its cap with 10,000 distinct keys, and the most recent key survives', () => {
  const l = new SlidingWindowLimiter({ maxKeys: 1000 });
  for (let i = 0; i < 10_000; i++) {
    l.add(`ip:${i}`, 1, 1_000 + i);
    if (i % 7 === 0) l.add('global', 1, 1_000 + i);
  }
  assert.ok(l.size() <= 1000, String(l.size()));
  assert.ok(l.retryAfter('global', 1, 1, 11_000) > 0, 'recently used global key kept');
});

// ---------------------------------------------------------------------------
// Log builder

const R20 = ['ts', 'request_id', 'token_id', 'assistant', 'class', 'tool', 'duration_ms', 'hit_count', 'withheld_count', 'redacted_count', 'status', 'error_class'];

test('log: output keys are exactly the R20 allowlist, in a fixed order; extra properties are dropped; unknown tool names become "unknown"', () => {
  assert.deepEqual([...LOG_FIELDS], R20);
  const rec: RequestLogRecord = {
    ts: '2026-11-16T18:00:00.000Z', request_id: 'r1', token_id: generateToken().tokenId, assistant: 'zeus', class: 'write',
    tool: 'zeusi_search', duration_ms: 12.4, hit_count: 3, withheld_count: 1, status: 200, error_class: null,
  };
  const smuggled = { ...rec, query: 'secret query text', token: 'zeusi_x', text: 'chunk', tool: 'zeusi_search' } as unknown as RequestLogRecord;
  const line = buildLogLine(smuggled);
  const j = JSON.parse(line) as Record<string, unknown>;
  assert.deepEqual(Object.keys(j), R20);
  assert.ok(!line.includes('secret query text') && !line.includes('zeusi_x') && !line.includes('chunk'));
  assert.equal(j['duration_ms'], 12);
  assert.equal(JSON.parse(buildLogLine({ ...rec, tool: 'drop table; please log me' }))['tool'], 'unknown');
  assert.equal(JSON.parse(buildLogLine({ ...rec, token_id: 'not a real id!' }))['token_id'], 'unknown');
  assert.equal(JSON.parse(buildLogLine({ ...rec, assistant: 'Has Spaces' }))['assistant'], 'unknown');
  assert.equal(JSON.parse(buildLogLine({ ...rec, error_class: 'whatever' as never }))['error_class'], 'internal');
  assert.equal(JSON.parse(buildLogLine({ ...rec, tool: 'log_decision' }))['tool'], 'log_decision');
  assert.equal(JSON.parse(buildLogLine({ ...rec, tool: null, token_id: null }))['tool'], null);
});
