// `zeusi mcp-token mint|list|revoke` (src/mcp-token-admin.ts, docs/hosting.md): offline
// token admin. Spawns the CLI against temp dirs only; no database, no network, no live volume.
// The plaintext token must reach only the --out file, never stdout or stderr.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadTokenStore, parseToken, TOKEN_RE, verifySecret } from '../src/mcp-tokens.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function tmp(): string {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-mint-'));
  chmodSync(d, 0o700);
  return d;
}

function run(args: string[], env: Record<string, string> = {}) {
  const cwd = tmp();
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd, encoding: 'utf8', timeout: 60_000,
    env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: cwd, PGSERVICEFILE: join(cwd, 'missing.conf'), ...env },
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function rows(file: string) {
  return (JSON.parse(readFileSync(file, 'utf8')) as { tokens: Array<Record<string, unknown>> }).tokens;
}

test('mcp-token mint: writes the token only to --out (0600), appends one hash row (0600), prints the token_id but never the token', async () => {
  const d = tmp();
  const file = join(d, 'mcp-tokens.json');
  const out = join(d, 'zeus.token');
  const r = run(['mcp-token', 'mint', '--label', 'zeus', '--class', 'write', '--out', out, '--file', file]);
  assert.equal(r.code, 0, r.stderr);
  const content = readFileSync(out, 'utf8');
  assert.ok(/^zeusi_[a-z2-7]{12}_[A-Za-z0-9_-]{43}\n$/.test(content), 'the out file holds one well-formed token (value not shown)');
  const token = content.trimEnd();
  assert.ok(TOKEN_RE.test(token), 'token matches TOKEN_RE (value not shown)');
  const { tokenId, secret } = parseToken(token)!;
  assert.equal(statSync(out).mode & 0o777, 0o600);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  // never on a terminal stream: check both streams separately, for the token and for the secret
  for (const [name, s] of [['stdout', r.stdout], ['stderr', r.stderr]] as const) {
    assert.ok(!s.includes(token), `${name} has the token`);
    assert.ok(!s.includes(secret), `${name} has the secret`);
  }
  assert.ok(r.stdout.includes(tokenId), 'stdout names the token_id');
  // the tokens file: one row with the label, class, a 90-day expiry; no secret in its bytes
  const t = rows(file);
  assert.equal(t.length, 1);
  assert.equal(t[0]!['token_id'], tokenId);
  assert.equal(t[0]!['assistant'], 'zeus');
  assert.equal(t[0]!['class'], 'write');
  assert.equal(t[0]!['revoked_at'], null);
  const days = (Date.parse(t[0]!['expires_at'] as string) - Date.parse(t[0]!['issued_at'] as string)) / 86_400_000;
  assert.equal(days, 90);
  const bytes = readFileSync(file, 'utf8');
  assert.ok(!bytes.includes(secret) && !bytes.includes(token));
  // the row verifies the minted secret (and the store loads)
  const store = loadTokenStore(file);
  assert.equal(store.state, 'loaded');
  if (store.state === 'loaded') assert.equal(await verifySecret(store.byId.get(tokenId)!, secret), true);
});

test('mcp-token mint over an existing 0644 --out file replaces it and leaves 0600', () => {
  const d = tmp();
  const out = join(d, 'reed.token');
  writeFileSync(out, 'old contents\n', { mode: 0o644 });
  chmodSync(out, 0o644);
  const r = run(['mcp-token', 'mint', '--label', 'reed', '--class', 'read', '--out', out, '--file', join(d, 'mcp-tokens.json')]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(statSync(out).mode & 0o777, 0o600);
  assert.match(readFileSync(out, 'utf8'), /^zeusi_[a-z2-7]{12}_[A-Za-z0-9_-]{43}\n$/);
});

test('mcp-token mint refusals exit 2 with nothing written', () => {
  const d = tmp();
  const file = join(d, 'mcp-tokens.json');
  const target = join(d, 'target');
  writeFileSync(target, 'x');
  const link = join(d, 'link.token');
  symlinkSync(target, link);
  const cases: Array<[string, string[]]> = [
    ['--out is a symlink', ['--label', 'a', '--class', 'read', '--out', link]],
    ['--out equals --file', ['--label', 'a', '--class', 'read', '--out', file]],
    ['--out parent missing', ['--label', 'a', '--class', 'read', '--out', join(d, 'nope', 'a.token')]],
    ['--class admin', ['--label', 'a', '--class', 'admin', '--out', join(d, 'a.token')]],
    ['--label missing', ['--class', 'read', '--out', join(d, 'a.token')]],
    ['--label bad', ['--label', 'Bad Label', '--class', 'read', '--out', join(d, 'a.token')]],
    ['--out missing', ['--label', 'a', '--class', 'read']],
    ['--expires-days 0', ['--label', 'a', '--class', 'read', '--out', join(d, 'a.token'), '--expires-days', '0']],
    ['--expires-days 91', ['--label', 'a', '--class', 'read', '--out', join(d, 'a.token'), '--expires-days', '91']],
  ];
  for (const [name, args] of cases) {
    const r = run(['mcp-token', 'mint', ...args, '--file', file]);
    assert.equal(r.code, 2, `${name}: ${r.stdout}${r.stderr}`);
    assert.equal(existsSync(file), false, `${name}: no tokens file written`);
    assert.equal(existsSync(join(d, 'a.token')), false, `${name}: no out file`);
  }
  assert.equal(readFileSync(target, 'utf8'), 'x', 'symlink target untouched');
});

test('mcp-token mint --file in an existing 0755 directory holding another file: refused, dir stays 0755, no token anywhere', () => {
  const d = safeMkdtemp(join(tmpdir(), 'zeusi-mint-loose-'));
  chmodSync(d, 0o755);
  writeFileSync(join(d, 'notes.txt'), 'unrelated');
  const outDir = tmp();
  const out = join(outDir, 'a.token');
  const r = run(['mcp-token', 'mint', '--label', 'atlas', '--class', 'read', '--out', out, '--file', join(d, 'mcp-tokens.json')]);
  assert.equal(r.code, 2, `${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /dir must be 0700/);
  assert.equal(statSync(d).mode & 0o7777, 0o755, 'existing directory not tightened');
  assert.equal(existsSync(join(d, 'mcp-tokens.json')), false);
  assert.equal(existsSync(out), false, 'no token written');
});

test('mcp-token list shows ids, labels, classes and the three timestamps; never hash, salt or secret', () => {
  const d = tmp();
  const file = join(d, 'mcp-tokens.json');
  const outs = ['atlas', 'lyra'].map((l) => {
    const out = join(d, `${l}.token`);
    assert.equal(run(['mcp-token', 'mint', '--label', l, '--class', 'read', '--out', out, '--file', file, '--expires-days', '30']).code, 0);
    return readFileSync(out, 'utf8').trimEnd();
  });
  const r = run(['mcp-token', 'list', '--file', file]);
  assert.equal(r.code, 0, r.stderr);
  for (const t of rows(file)) {
    for (const k of ['token_id', 'assistant', 'class', 'issued_at', 'expires_at']) assert.ok(r.stdout.includes(String(t[k])), k);
    const h = t['hash'] as { salt: string; digest: string };
    assert.ok(!r.stdout.includes(h.salt) && !r.stdout.includes(h.digest));
  }
  assert.match(r.stdout, /revoked_at/);
  assert.doesNotMatch(r.stdout, /hash|salt|digest/i);
  for (const tok of outs) {
    const { secret } = parseToken(tok)!;
    assert.ok(!r.stdout.includes(secret) && !r.stderr.includes(secret));
  }
});

test('mcp-token revoke sets revoked_at, list shows it, unknown id exits 2, other rows untouched, a second revoke keeps the first time', async () => {
  const d = tmp();
  const file = join(d, 'mcp-tokens.json');
  for (const l of ['nova', 'quiet-ops']) {
    assert.equal(run(['mcp-token', 'mint', '--label', l, '--class', 'read', '--out', join(d, `${l}.token`), '--file', file]).code, 0);
  }
  const [a, b] = rows(file);
  const r = run(['mcp-token', 'revoke', a!['token_id'] as string, '--file', file]);
  assert.equal(r.code, 0, r.stderr);
  const after = rows(file);
  const ra = after.find((t) => t['token_id'] === a!['token_id'])!;
  assert.match(String(ra['revoked_at']), /^\d{4}-\d\d-\d\dT/);
  assert.deepEqual(after.find((t) => t['token_id'] === b!['token_id']), b, 'other row unchanged');
  assert.match(run(['mcp-token', 'list', '--file', file]).stdout, new RegExp(`${a!['token_id']}.*${String(ra['revoked_at']).replace(/[.]/g, '\\.')}`));
  await new Promise((res) => setTimeout(res, 20));
  assert.equal(run(['mcp-token', 'revoke', a!['token_id'] as string, '--file', file]).code, 0);
  assert.equal(rows(file).find((t) => t['token_id'] === a!['token_id'])!['revoked_at'], ra['revoked_at'], 'first revoke time kept');
  assert.equal(run(['mcp-token', 'revoke', 'aaaaaaaaaaaa', '--file', file]).code, 2);
  assert.equal(run(['mcp-token', 'revoke', 'not-an-id', '--file', file]).code, 2);
});

test('mcp-token honours ZEUSI_MCP_TOKENS_PATH when --file is absent; --file wins when both are set', () => {
  const d = tmp();
  const envFile = join(d, 'env-tokens.json');
  const flagFile = join(d, 'flag-tokens.json');
  assert.equal(run(['mcp-token', 'mint', '--label', 'a', '--class', 'read', '--out', join(d, 'a.token')], { ZEUSI_MCP_TOKENS_PATH: envFile }).code, 0);
  assert.equal(rows(envFile).length, 1);
  assert.equal(run(['mcp-token', 'mint', '--label', 'b', '--class', 'read', '--out', join(d, 'b.token'), '--file', flagFile], { ZEUSI_MCP_TOKENS_PATH: envFile }).code, 0);
  assert.equal(rows(envFile).length, 1);
  assert.equal(rows(flagFile).length, 1);
});

test('mcp-token is refused under ZEUSI_TRANSPORT=serverless (not a serverless command) and needs no database', () => {
  const d = tmp();
  const r = run(['mcp-token', 'list', '--file', join(d, 'x.json')], { ZEUSI_TRANSPORT: 'serverless' });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /mcp-token/);
  const u = run(['mcp-token', 'bogus']);
  assert.equal(u.code, 2);
  assert.match(u.stderr, /usage: mcp-token/);
});
