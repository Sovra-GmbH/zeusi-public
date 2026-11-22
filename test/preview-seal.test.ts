// C2 (docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD3): sealed preview staging. Every file of a kept
// run is AES-256-GCM sealed under a per-preview key held in memory, under a neutral name; the relative
// paths stay in memory. Ephemeral staging hygiene, not workspace encryption.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { destroySealed, readSealed, SEALED_DIR, SealError, sealRun, unsealRun } from '../src/preview-seal.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const CANARY = 'kestrelpreviewcanary7731';

function allFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, n.name);
      if (n.isDirectory()) walk(p);
      else out.push(p);
    }
  };
  walk(dir);
  return out;
}

function makeRun(): { root: string; run: string } {
  const root = safeMkdtemp(join(tmpdir(), 'zeusi-seal-'));
  const run = join(root, 'run-abc');
  mkdirSync(join(run, 'filtered', 'team'), { recursive: true, mode: 0o700 });
  writeFileSync(join(run, 'filtered', 'team', `2026-11-18-memory-${CANARY}.md`), `---\ntitle: "${CANARY} title"\n---\n${CANARY} body\n`, { mode: 0o600 });
  writeFileSync(join(run, 'filtered', 'team', '2026-11-18-memory-two.md'), 'second note\n', { mode: 0o600 });
  return { root, run };
}

test('sealRun: afterwards the run holds only neutral sealed files: no canary in names or bytes; files 0600, dir 0700', () => {
  const { root, run } = makeRun();
  const s = sealRun(run);
  try {
    assert.deepEqual(readdirSync(run), [SEALED_DIR]);
    const files = allFiles(run);
    assert.equal(files.length, 2);
    for (const f of files) {
      assert.match(relative(run, f), /^sealed\/\d{6}$/);
      assert.ok(!readFileSync(f).includes(Buffer.from(CANARY)), 'no plain text on disk');
      assert.ok(!readFileSync(f).includes(Buffer.from('second note')));
      assert.equal(statSync(f).mode & 0o777, 0o600);
    }
    assert.equal(statSync(join(run, SEALED_DIR)).mode & 0o777, 0o700);
    assert.ok(!allFiles(root).some((f) => f.includes(CANARY)));
    assert.equal(s.key?.length, 32);
  } finally {
    destroySealed(s);
  }
});

test('readSealed opens a file in memory; unsealRun restores the exact layout in a fresh private dir that cleanup removes', () => {
  const { root, run } = makeRun();
  const s = sealRun(run);
  try {
    const rel = `filtered/team/2026-11-18-memory-${CANARY}.md`;
    assert.equal(readSealed(s, rel)!.toString('utf8'), `---\ntitle: "${CANARY} title"\n---\n${CANARY} body\n`);
    assert.equal(readSealed(s, 'filtered/team/missing.md'), null);
    const parent = join(root, 'runs');
    mkdirSync(parent, { mode: 0o700 });
    const o = unsealRun(s, parent, () => true);
    assert.match(relative(parent, o.workDir), /^run-/);
    assert.equal(statSync(o.workDir).mode & 0o777, 0o700);
    assert.equal(readFileSync(join(o.workDir, rel), 'utf8'), `---\ntitle: "${CANARY} title"\n---\n${CANARY} body\n`);
    assert.equal(readFileSync(join(o.workDir, 'filtered/team/2026-11-18-memory-two.md'), 'utf8'), 'second note\n');
    assert.equal(statSync(join(o.workDir, rel)).mode & 0o777, 0o600);
    o.cleanup();
    assert.ok(!existsSync(o.workDir));
    // The sealed run is untouched by an unseal (a failed commit can be retried).
    assert.equal(readdirSync(join(run, SEALED_DIR)).length, 2);
  } finally {
    destroySealed(s);
  }
});

test('tamper, swap and a wrong key fail closed (AES-GCM tag over the bytes, AAD binds the relative path)', () => {
  const { root, run } = makeRun();
  const s = sealRun(run);
  try {
    const rels = [...s.entries.keys()];
    const [a, b] = rels.map((r) => join(run, SEALED_DIR, s.entries.get(r)!));
    // Swap the two sealed files: each now fails under the other's path.
    const tmp = join(run, SEALED_DIR, 'tmp');
    renameSync(a!, tmp);
    renameSync(b!, a!);
    renameSync(tmp, b!);
    assert.throws(() => readSealed(s, rels[0]!), SealError);
    renameSync(a!, tmp);
    renameSync(b!, a!);
    renameSync(tmp, b!);
    assert.ok(readSealed(s, rels[0]!));
    // Flip one ciphertext byte.
    const bytes = readFileSync(a!);
    bytes[bytes.length - 1]! ^= 1;
    writeFileSync(a!, bytes);
    assert.throws(() => readSealed(s, rels[0]!), SealError);
    const parent = join(root, 'runs');
    mkdirSync(parent, { mode: 0o700 });
    assert.throws(() => unsealRun(s, parent, () => true), SealError);
    assert.deepEqual(readdirSync(parent), [], 'a failed unseal leaves no dir');
    // Wrong key.
    const good = s.key!;
    s.key = Buffer.alloc(32, 7);
    assert.throws(() => readSealed(s, rels[1]!), SealError);
    s.key = good;
    assert.ok(readSealed(s, rels[1]!));
  } finally {
    destroySealed(s);
  }
});

test('destroySealed zero-fills the key, forgets it and removes the files; nothing opens afterwards', () => {
  const { run } = makeRun();
  const s = sealRun(run);
  const key = s.key!;
  destroySealed(s);
  assert.equal(s.key, null);
  assert.ok(key.every((x) => x === 0), 'key bytes zeroed');
  assert.ok(!existsSync(run));
  assert.throws(() => readSealed(s, [...s.entries.keys()][0]!), /key is gone/);
  destroySealed(s); // idempotent
});

test('two previews never share a key (a fresh random key per sealRun)', () => {
  const a = sealRun(makeRun().run);
  const b = sealRun(makeRun().run);
  try {
    assert.ok(!a.key!.equals(b.key!));
  } finally {
    destroySealed(a);
    destroySealed(b);
  }
});
