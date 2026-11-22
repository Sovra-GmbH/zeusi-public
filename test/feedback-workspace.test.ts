// C2 (docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD1, KTD2): a personal workspace's feedback ledger
// holds HMAC(K_hash, uri) and a key id, never the uri and never a reason. the team's ledger is unchanged (D4).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, fsyncSync, readdirSync, readFileSync, statSync, symlinkSync, truncateSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  FeedbackKeyError, recordFeedback, recordWorkspaceFeedback, uriHmac, WORKSPACE_URI_KEY_FILE, WORKSPACE_URI_KEY_ID, workspaceUriKey,
} from '../src/feedback.ts';
import { workspaceFeedbackPath } from '../src/mcp-hosted.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const URI = 'hq:notes/2026-11-18-ospreyledgercanary.md#c0';
const QID = '00000000-0000-4000-8000-000000000001';
const T1 = `zt_${'a'.repeat(26)}`;
const T2 = `zt_${'b'.repeat(26)}`;
const lines = (p: string) => readFileSync(p, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);

test('workspace ledger line: ts, query_id, uri_hmac, uri_key, useful; no uri, no reason; key file 0600 beside it, dir 0700', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const path = workspaceFeedbackPath(join(home, '.zeusi', 'search-feedback.jsonl'), T1);
  recordWorkspaceFeedback(path, { queryId: QID, sourceUri: URI, useful: true }, new Date('2026-11-18T10:00:00Z'));
  const text = readFileSync(path, 'utf8');
  assert.ok(!text.includes('ospreyledgercanary') && !text.includes('hq:'), 'no uri in the ledger');
  const [l] = lines(path);
  assert.deepEqual(Object.keys(l!), ['ts', 'query_id', 'uri_hmac', 'uri_key', 'useful']);
  assert.equal(l!['uri_key'], WORKSPACE_URI_KEY_ID);
  assert.match(String(l!['uri_hmac']), /^[0-9a-f]{64}$/);
  assert.notEqual(l!['uri_hmac'], createHash('sha256').update(URI).digest('hex'), 'keyed, not a plain sha256');
  const keyPath = join(dirname(path), WORKSPACE_URI_KEY_FILE);
  assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  assert.equal(statSync(keyPath).size, 32);
  assert.equal(statSync(dirname(path)).mode & 0o777, 0o700);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test('the hash is stable within a workspace (same key file) and differs across workspaces (own key)', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const team = join(home, '.zeusi', 'search-feedback.jsonl');
  const p1 = workspaceFeedbackPath(team, T1);
  const p2 = workspaceFeedbackPath(team, T2);
  recordWorkspaceFeedback(p1, { queryId: QID, sourceUri: URI, useful: true });
  recordWorkspaceFeedback(p1, { queryId: QID, sourceUri: URI, useful: false });
  recordWorkspaceFeedback(p2, { queryId: QID, sourceUri: URI, useful: true });
  const [a, b] = lines(p1);
  const [c] = lines(p2);
  assert.equal(a!['uri_hmac'], b!['uri_hmac']);
  assert.notEqual(a!['uri_hmac'], c!['uri_hmac']);
  assert.equal(a!['uri_hmac'], uriHmac(workspaceUriKey(dirname(p1)), URI), 'recomputable by whoever holds the key file (documented limit)');
  assert.ok(!existsSync(team), 'nothing in the team ledger');
});

test('a key entry that is not a 32-byte regular file (symlink, wrong size) refuses: nothing recorded', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const path = workspaceFeedbackPath(join(home, '.zeusi', 'search-feedback.jsonl'), T1);
  const dir = dirname(path);
  workspaceUriKey(dir); // creates dir + key
  const keyPath = join(dir, WORKSPACE_URI_KEY_FILE);
  writeFileSync(keyPath, 'short');
  assert.throws(() => recordWorkspaceFeedback(path, { queryId: QID, sourceUri: URI, useful: true }), FeedbackKeyError);
  assert.ok(!existsSync(path));
  const home2 = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const path2 = workspaceFeedbackPath(join(home2, '.zeusi', 'search-feedback.jsonl'), T2);
  workspaceUriKey(dirname(path2));
  const k2 = join(dirname(path2), WORKSPACE_URI_KEY_FILE);
  const target = join(home2, 'elsewhere.key');
  writeFileSync(target, Buffer.alloc(32, 1));
  // Replace the key with a symlink to a 32-byte file.
  unlinkSync(k2);
  symlinkSync(target, k2);
  assert.throws(() => recordWorkspaceFeedback(path2, { queryId: QID, sourceUri: URI, useful: true }), FeedbackKeyError);
  assert.ok(!existsSync(path2));
});

test('the team ledger unchanged (D4): source_uri and the optional reason are still written', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const team = join(home, '.zeusi', 'search-feedback.jsonl');
  recordFeedback(team, { queryId: QID, sourceUri: 'vault:x.md#c0', useful: true, reason: 'answered it' }, new Date('2026-11-18T10:00:00Z'));
  assert.deepEqual(lines(team), [{ ts: '2026-11-18T10:00:00.000Z', query_id: QID, source_uri: 'vault:x.md#c0', useful: true, reason: 'answered it' }]);
});

test('the key file is created whole (temp file + link): no temp file is left, and a second creator reuses the first key', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const dir = dirname(workspaceFeedbackPath(join(home, '.zeusi', 'search-feedback.jsonl'), T1));
  const a = workspaceUriKey(dir);
  const b = workspaceUriKey(dir);
  assert.ok(a.equals(b));
  assert.deepEqual(readdirSync(dir), [WORKSPACE_URI_KEY_FILE]);
});

test('the key file is created durably (review C2R1-3): the temp file is fsynced before the link, the dir after it; a present key is not rewritten', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const dir = dirname(workspaceFeedbackPath(join(home, '.zeusi', 'search-feedback.jsonl'), T1));
  const keyPath = join(dir, WORKSPACE_URI_KEY_FILE);
  const seen: Array<{ what: string; keyLinked: boolean; tmpFiles: number }> = [];
  const fsync = (fd: number, what: 'file' | 'dir') => {
    fsyncSync(fd); // still the real fsync: the seam only observes
    seen.push({ what, keyLinked: existsSync(keyPath), tmpFiles: readdirSync(dir).filter((n) => n.endsWith('.tmp')).length });
  };
  const k = workspaceUriKey(dir, { fsync });
  assert.equal(k.length, 32);
  assert.deepEqual(seen, [{ what: 'file', keyLinked: false, tmpFiles: 1 }, { what: 'dir', keyLinked: true, tmpFiles: 1 }]);
  assert.deepEqual(readdirSync(dir), [WORKSPACE_URI_KEY_FILE]);
  seen.length = 0;
  assert.ok(workspaceUriKey(dir, { fsync }).equals(k));
  assert.deepEqual(seen, [], 'an existing key is read, not written');
});

test('a failed fsync fails closed: FeedbackKeyError, no key file and no temp file left, nothing recorded; the next call creates the key', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const dir = dirname(workspaceFeedbackPath(join(home, '.zeusi', 'search-feedback.jsonl'), T1));
  assert.throws(() => workspaceUriKey(dir, { fsync: () => { throw Object.assign(new Error('EIO'), { code: 'EIO' }); } }),
    (e: unknown) => e instanceof FeedbackKeyError && e.message === 'feedback key could not be created; nothing recorded');
  assert.deepEqual(readdirSync(dir), []);
  assert.equal(workspaceUriKey(dir).length, 32);
});

test('a 0-byte key file owned by this user (an unsynced create cut by a host crash) is replaced, not a permanent refusal', () => {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-fb-'));
  const path = workspaceFeedbackPath(join(home, '.zeusi', 'search-feedback.jsonl'), T1);
  const dir = dirname(path);
  workspaceUriKey(dir);
  const keyPath = join(dir, WORKSPACE_URI_KEY_FILE);
  truncateSync(keyPath, 0);
  recordWorkspaceFeedback(path, { queryId: QID, sourceUri: URI, useful: true });
  assert.equal(statSync(keyPath).size, 32);
  assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  const [l] = lines(path);
  assert.equal(l!['uri_hmac'], uriHmac(workspaceUriKey(dir), URI));
  assert.deepEqual(readdirSync(dir).sort(), [WORKSPACE_URI_KEY_FILE, 'search-feedback.jsonl'].sort());
});
