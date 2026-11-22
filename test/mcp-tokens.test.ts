// Hosted MCP token store (src/mcp-tokens.ts, docs/hosting.md): token format, slow hashes
// (argon2id, scrypt fallback), the fail-closed tokens-file loader and the atomic writer.
// Every token here is generated at runtime into a temp dir; nothing is real.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  emptyTokenFile, generateToken, hashSecret, loadTokenStore, parseToken, TOKEN_RE, TokenFileError, usableRows, verifySecret,
  withTokenFile, type TokenRow,
} from '../src/mcp-tokens.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { assertSecretEqual, fingerprint } from './redact.ts';

const FAST_ARGON = { m: 64, t: 1, p: 1, dkLen: 32 };
const FAST_SCRYPT = { N: 1024, r: 8, p: 1, dkLen: 32 };

function tmpStoreDir(): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-tokens-'));
  chmodSync(dir, 0o700);
  return dir;
}

async function row(over: Partial<TokenRow> = {}, alg: 'argon2id' | 'scrypt' = 'argon2id'): Promise<{ row: TokenRow; token: string; secret: string }> {
  const { tokenId, secret, token } = generateToken();
  const hash = await hashSecret(tokenId, secret, alg === 'argon2id' ? { alg, params: FAST_ARGON } : { alg, params: FAST_SCRYPT });
  const now = Date.now();
  return {
    token, secret,
    row: {
      token_id: tokenId, assistant: 'test-bot', class: 'read', hash,
      issued_at: new Date(now).toISOString(), expires_at: new Date(now + 86_400_000).toISOString(), revoked_at: null, ...over,
    },
  };
}

function writeStore(dir: string, rows: TokenRow[], mode = 0o600): string {
  const p = join(dir, 'mcp-tokens.json');
  writeFileSync(p, JSON.stringify({ version: 1, tokens: rows }), { mode });
  chmodSync(p, mode);
  return p;
}

// ---------------------------------------------------------------------------
// Format

test('tokens: a generated token matches the format; token_id has no "_"; a secret with "_" still parses', () => {
  for (let i = 0; i < 200; i++) {
    const g = generateToken();
    assert.ok(TOKEN_RE.test(g.token), `token ${fingerprint(g.token)} matches TOKEN_RE`);
    assert.match(g.tokenId, /^[a-z2-7]{12}$/);
    assert.equal(g.secret.length, 43);
    const parsed = parseToken(g.token);
    assert.equal(parsed?.tokenId, g.tokenId);
    assertSecretEqual(parsed?.secret, g.secret, 'parsed secret');
  }
  const id = 'abcdefghij23';
  const secret = `${'A'.repeat(20)}_${'b'.repeat(10)}_-${'c'.repeat(10)}`;
  assert.equal(secret.length, 43);
  const p = parseToken(`zeusi_${id}_${secret}`);
  assert.equal(p?.tokenId, id);
  assertSecretEqual(p?.secret, secret, 'secret with "_"');
});

test('tokens: malformed tokens are rejected by parseToken', () => {
  const g = generateToken();
  const bad = [
    `zeusl_${g.tokenId}_${g.secret}`, `Zeusi_${g.tokenId}_${g.secret}`, `zeusi_${g.tokenId.slice(1)}_${g.secret}`,
    `zeusi_${g.tokenId}_${g.secret.slice(1)}`, `zeusi_${g.tokenId}_${g.secret}x`, `zeusi_${g.tokenId}_${g.secret}_x`,
    `zeusi_${g.tokenId.toUpperCase()}_${g.secret}`, ` ${g.token}`, `${g.token} `, `${g.token}\n`, '', 'zeusi__',
    `zeusi_${g.tokenId}_${g.secret.slice(0, 42)}é`, `zeusi_${g.tokenId.slice(0, 11)}1_${g.secret}`,
  ];
  bad.forEach((b, i) => assert.ok(parseToken(b) === null, `malformed token #${i} (${fingerprint(b)}) must not parse`));
});

// ---------------------------------------------------------------------------
// Hashing

test('tokens: argon2id hash then verify succeeds; wrong secret fails; same secret under another token_id fails (binding)', async () => {
  const { row: r, secret } = await row();
  assert.equal(r.hash.alg, 'argon2id');
  assert.equal(await verifySecret(r, secret), true);
  assert.equal(await verifySecret(r, generateToken().secret), false);
  const other = generateToken().tokenId;
  assert.equal(await verifySecret({ ...r, token_id: other }, secret), false);
});

test('tokens: default argon2id parameters are m=19456 KiB, t=2, p=1, dkLen 32, 16-byte salt', async () => {
  const { tokenId, secret } = generateToken();
  const h = await hashSecret(tokenId, secret);
  assert.equal(h.alg, 'argon2id');
  assert.deepEqual({ m: (h as { m: number }).m, t: (h as { t: number }).t, p: h.p, dkLen: h.dkLen }, { m: 19456, t: 2, p: 1, dkLen: 32 });
  assert.equal(Buffer.from(h.salt, 'base64').length, 16);
  assert.equal(Buffer.from(h.digest, 'base64').length, 32);
});

test('tokens: a scrypt row verifies with the right secret and fails with a wrong one', async () => {
  const { row: r, secret } = await row({}, 'scrypt');
  assert.equal(r.hash.alg, 'scrypt');
  assert.equal(await verifySecret(r, secret), true);
  assert.equal(await verifySecret(r, generateToken().secret), false);
});

test('tokens: a stored hash of a different length fails cleanly (timingSafeEqual never throws to the caller)', async () => {
  const { row: r, secret } = await row();
  const short = { ...r, hash: { ...r.hash, digest: Buffer.alloc(16).toString('base64') } };
  assert.equal(await verifySecret(short, secret), false);
  const garbage = { ...r, hash: { ...r.hash, salt: '' } };
  assert.equal(await verifySecret(garbage, secret), false);
});

test('tokens: concurrent verifies all resolve correctly through the single hash slot', async () => {
  let active = 0;
  let peak = 0;
  const { row: r, secret } = await row();
  const probe = async () => {
    active++;
    peak = Math.max(peak, active);
    try {
      return await verifySecret(r, secret);
    } finally {
      active--;
    }
  };
  // verifySecret itself queues; the probe only proves the callers overlap, the queue serialises.
  const results = await Promise.all([probe(), probe(), probe()]);
  assert.deepEqual(results, [true, true, true]);
  assert.ok(peak >= 2, 'callers overlapped');
});

// ---------------------------------------------------------------------------
// Loader (fail closed)

test('tokens: the store is unconfigured when the file is missing, invalid JSON, has an unknown key or bad class, mode 0644, or a 0755 dir', async () => {
  const { row: r } = await row();
  const cases: Array<[string, (dir: string) => string]> = [
    ['missing', (d) => join(d, 'mcp-tokens.json')],
    ['invalid json', (d) => { const p = join(d, 'mcp-tokens.json'); writeFileSync(p, '{nope', { mode: 0o600 }); return p; }],
    ['unknown top key', (d) => { const p = join(d, 'mcp-tokens.json'); writeFileSync(p, JSON.stringify({ version: 1, tokens: [], extra: 1 }), { mode: 0o600 }); return p; }],
    ['unknown row key', (d) => writeStore(d, [{ ...r, plaintext: 'x' } as unknown as TokenRow])],
    ['bad class', (d) => writeStore(d, [{ ...r, class: 'admin' } as unknown as TokenRow])],
    ['bad version', (d) => { const p = join(d, 'mcp-tokens.json'); writeFileSync(p, JSON.stringify({ version: 2, tokens: [] }), { mode: 0o600 }); return p; }],
    ['bad timestamp', (d) => writeStore(d, [{ ...r, expires_at: 'tomorrow' }])],
    ['file 0644', (d) => writeStore(d, [r], 0o644)],
    ['file 0640', (d) => writeStore(d, [r], 0o640)],
    ['dir 0755', (d) => { const p = writeStore(d, [r]); chmodSync(d, 0o755); return p; }],
    ['not a file', (d) => { const p = join(d, 'mcp-tokens.json'); mkdirSync(p, { mode: 0o700 }); return p; }],
  ];
  for (const [name, make] of cases) {
    const s = loadTokenStore(make(tmpStoreDir()));
    assert.equal(s.state, 'unconfigured', name);
  }
  // owner check: a uid that is not the process uid
  const dir = tmpStoreDir();
  const p = writeStore(dir, [r]);
  assert.equal(loadTokenStore(p, { uid: (process.getuid?.() ?? 0) + 1 }).state, 'unconfigured', 'other owner');
  assert.equal(loadTokenStore(p).state, 'loaded');
});

test('tokens: zero rows, or only revoked / expired rows, load as configured with zero usable tokens', async () => {
  const now = Date.now();
  const revoked = (await row({ revoked_at: new Date(now - 1000).toISOString() })).row;
  const expired = (await row({ expires_at: new Date(now - 1000).toISOString() })).row;
  for (const rows of [[], [revoked], [expired], [revoked, expired]]) {
    const s = loadTokenStore(writeStore(tmpStoreDir(), rows));
    assert.equal(s.state, 'loaded');
    if (s.state === 'loaded') assert.equal(usableRows(s.rows, now).length, 0);
  }
  const live = (await row()).row;
  const s = loadTokenStore(writeStore(tmpStoreDir(), [revoked, live]));
  assert.ok(s.state === 'loaded' && usableRows(s.rows, now).length === 1);
});

// ---------------------------------------------------------------------------
// Writer

test('tokens: an atomic append leaves file 0600 and dir 0700; a concurrent writer is refused by the lock file', async () => {
  const dir = join(safeMkdtemp(join(tmpdir(), 'zeusi-tokens-')), 'fresh', 'store'); // created by the writer
  const p = join(dir, 'mcp-tokens.json');
  const { row: r, secret, token } = await row();
  await withTokenFile(p, (doc) => ({ ...doc, tokens: [...doc.tokens, r] }));
  assert.equal(statSync(p).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(loadTokenStore(p).state, 'loaded');
  // The serialized file never contains the plaintext token or secret.
  const bytes = readFileSync(p, 'utf8');
  assert.ok(!bytes.includes(secret));
  assert.ok(!bytes.includes(token));
  // A concurrent writer: the first holds the lock while the second tries.
  let release!: () => void;
  const held = new Promise<void>((res) => { release = res; });
  const first = withTokenFile(p, async (doc) => { await held; return doc; });
  await assert.rejects(withTokenFile(p, (doc) => doc), (e: unknown) => e instanceof TokenFileError && e.code === 'locked');
  release();
  await first;
  assert.equal(existsSync(`${p}.lock`), false, 'lock released');
  // A file that exists but is invalid is never overwritten.
  writeFileSync(p, '{broken', { mode: 0o600 });
  await assert.rejects(withTokenFile(p, (doc) => doc), (e: unknown) => e instanceof TokenFileError && e.code === 'invalid');
  assert.equal(readFileSync(p, 'utf8'), '{broken');
});

test('tokens: emptyTokenFile is version 1 with no rows', () => {
  assert.deepEqual(emptyTokenFile(), { version: 1, tokens: [] });
});

test('tokens: an existing 0755 directory holding another file is refused ("dir must be 0700") and never tightened; an existing 0700 one is used as is', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-tokens-loose-'));
  chmodSync(dir, 0o755);
  writeFileSync(join(dir, 'other.txt'), 'someone else\'s file');
  const p = join(dir, 'mcp-tokens.json');
  await assert.rejects(withTokenFile(p, (doc) => doc), (e: unknown) => e instanceof TokenFileError && e.code === 'io' && /dir must be 0700/.test(e.message));
  assert.equal(statSync(dir).mode & 0o7777, 0o755, 'existing directory never silently tightened');
  assert.equal(existsSync(p), false);
  assert.equal(existsSync(`${p}.lock`), false);
  assert.equal(readFileSync(join(dir, 'other.txt'), 'utf8'), 'someone else\'s file');
  chmodSync(dir, 0o700);
  const { row: r } = await row();
  await withTokenFile(p, (doc) => ({ ...doc, tokens: [...doc.tokens, r] }));
  assert.equal(statSync(dir).mode & 0o7777, 0o700);
  assert.equal(loadTokenStore(p).state, 'loaded');
});

test('tokens: the writer refuses a shared (sticky or world-writable) directory and never chmods it', async () => {
  for (const mode of [0o1777, 0o777]) {
    const dir = safeMkdtemp(join(tmpdir(), 'zeusi-tokens-shared-'));
    chmodSync(dir, mode);
    const p = join(dir, 'mcp-tokens.json');
    await assert.rejects(withTokenFile(p, (doc) => doc), (e: unknown) => e instanceof TokenFileError && e.code === 'io');
    assert.equal(statSync(dir).mode & 0o7777, mode, 'directory mode untouched');
    assert.equal(existsSync(p), false);
    chmodSync(dir, 0o700);
  }
});
