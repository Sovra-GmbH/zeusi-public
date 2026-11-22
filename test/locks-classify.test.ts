// Session-start gaps U4 / U5 (docs/plans/2026-11-18-session-start-gaps-plan.md;
// docs/locks-classifier.md): the Northbank standing-rule classifier, its dry-run preview, and the
// --real write that marks EXACTLY the previewed set. Synthetic fixture vault in a temp dir only
// (invent=NO: the wording mirrors the classes seen in the real notes, never their text). No
// network, no database except the PGlite end-to-end case.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  applyStandingMarkers, CLASSIFY_PREFIXES, classifyLock, classifyVault, DURABLE_PATTERNS, formatClassify, ONE_OFF_PATTERNS, PROMOTABLE_NOTE_STATUSES, withStandingMarker,
} from '../src/locks-classify.ts';
import { frontmatterBlock, parseFrontmatter } from '../src/importers/vault.ts';
import { parseStandingMarker } from '../src/lock-lifecycle.ts';
import { STANDING_LOCK_PREFIXES } from '../src/note-locks.ts';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { importVault } from '../src/importers/vault.ts';
import { createMcpState, createZeusiMcpServer, type McpDeps } from '../src/mcp-server.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

const T = 'Work/products/product';
const WALLED_DIR = ['plan', 'kiva'].join('');

const note = (o: { title: string; status?: string; date?: string; locks: string[]; extra?: string }) =>
  `---\ntitle: ${o.title}\ndate: ${o.date ?? '2026-11-10'}\n${o.status === undefined ? 'status: locked' : o.status === '' ? '' : `status: ${o.status}`}\n${o.extra ?? ''}locks:\n${o.locks.map((l) => `  - ${JSON.stringify(l)}`).join('\n')}\ntags: [northbank, lock]\n---\n# ${o.title}\n\nSynthetic body.\n`.replace(/\n\n(?=locks:)/, '\n');

const FILES: Record<string, string> = {
  [`${T}/2026-11-01-broker-onboarding-lock.md`]: note({ title: 'Synthetic broker onboarding', locks: [
    'Brokers onboard with one admin login for the whole wombat package; never ask for a separate tick login',
    'Staging only; merge via gate only if SAFE; no prod without a separate GO',
    'The numbat dashboard shows a short note for every missing component',
  ] }),
  [`${T}/2026-11-02-dated-lock.md`]: note({ title: 'Synthetic dated', locks: [
    'Validate the quokka report day by day against the source (2026-11-02 04:41 Zurich)',
    'Only the quokka team edits this until Friday',
    'Never invent a missing quokka value; show a blank with a reason',
  ] }),
  [`${T}/2026-11-03-parked.md`]: note({ title: 'Synthetic parked', status: 'parked', locks: ['Never ship the platypus without review'] }),
  [`${T}/2026-11-04-approved.md`]: note({ title: 'Synthetic approved', locks: [
    'Opus platypus design approved (13 screens)',
    'Kept the branch; do not delete it',
    'Is the platypus API as open as the wombat API?',
    'Then the sidecar chip lands',
    'Keep login 1068 as-is',
    'Every wombat call to the clientco test server is read-only',
    'The platypus card has a soft shadow',
  ] }),
  [`${T}/engineering/2026-11-05-each.md`]: note({ title: 'Synthetic engineering', status: 'Lock', locks: ['Each book transfer is recorded before the wombat call', 'The venue feed is the source of truth for wombat data'] }),
  ['Work/product/2026-11-06-root-northbank.md']: note({ title: 'Synthetic root northbank', locks: ['Every wombat alert must also fire the app push'] }),
  [`${T}/2026-11-07-marked.md`]: note({ title: 'Synthetic already marked', locks: ['Always label the wombat markup', 'Never mix the numbat markup'], extra: 'standing_locks: [1]\n' }),
  [`${T}/2026-11-08-superseded.md`]: note({ title: 'Synthetic superseded', locks: ['Never use the old wombat path'] }),
  [`${T}/2026-11-09-superseder.md`]: note({ title: 'Synthetic superseder', date: '2026-11-12', locks: ['Never use the old wombat path, use the new one'], extra: 'supersedes: "[[2026-11-08-superseded]]"\n' }),
  ['Work/ops/ops-rule.md']: note({ title: 'Synthetic ops', locks: ['Never deploy the wombat on Fridays'] }),
  [`${T}/${WALLED_DIR}-notes/walled.md`]: note({ title: 'Walled', locks: ['Never open this walled note'] }),
  [`${T}/broker-pnl-lock.md`]: note({ title: 'Walled by name', locks: ['Never open this pnl-named note'] }),
};

function fixtureVault(): string {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-classify-'));
  const root = join(dir, 'vault');
  for (const [rel, text] of Object.entries(FILES)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

function hashTree(root: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else out.set(p.slice(root.length + 1), createHash('sha256').update(readFileSync(p)).digest('hex'));
    }
  };
  walk(root);
  return out;
}

const decide = (text: string, noteStatus: string | null = 'locked') => classifyLock({ text, noteStatus, lockStatus: 'current', standing: false });

test('classifier rules: documented constants (Northbank prefixes only; standing prefixes NOT broadened)', () => {
  assert.deepEqual([...CLASSIFY_PREFIXES], ['Work/product/', 'Work/products/product/']);
  assert.deepEqual([...STANDING_LOCK_PREFIXES], ['Work/ops/', 'Work/handbook/'], 'the shortcut of broadening the standing folders is not taken');
  assert.deepEqual([...PROMOTABLE_NOTE_STATUSES], ['locked', 'lock']);
  assert.deepEqual(ONE_OFF_PATTERNS.map(([c]) => c), ['dated', 'timebox', 'timebox', 'pr_or_merge', 'event', 'go', 'open', 'staging', 'scoped_to_now', 'sequence', 'specific', 'cross_scope']);
  assert.deepEqual(DURABLE_PATTERNS.map(([c]) => c), ['never_always', 'every_each', 'must_only', 'prohibition', 'source_of_truth']);
});

test('classifier AE3: each rule class, first match wins; ambiguous locks are skipped with their reason', () => {
  const cases: Array<[string, string | null, string]> = [
    ['Never ask a broker for a separate tick login', 'locked', 'durable:never_always'],
    ['Every surface gives the data vendor visible credit', 'locked', 'durable:every_each'],
    ['Volume counts only trade deals', 'LOCK', 'durable:must_only'],
    ['No client-level data is quoted', 'locked', 'durable:prohibition'],
    ['Do not blank a zero value', 'locked', 'durable:prohibition'],
    ['The wombat feed is the source of truth', 'locked', 'durable:source_of_truth'],
    ['Never ship it', 'parked', 'note_status:parked'],
    ['Never ship it', null, 'note_status:(none)'],
    ['Never ship it', 'locked (staging only; nothing to prod)', 'note_status:locked (staging only; nothing to prod)'],
    ['Never ship it before 2026-11-02', 'locked', 'one_off:dated'],
    ['Never ship it on 5 Nov', 'locked', 'one_off:dated'],
    ['Never ship it until the review', 'locked', 'one_off:timebox'],
    ['Never ship it this week', 'locked', 'one_off:timebox'],
    ['Never merge #1157 without review', 'locked', 'one_off:pr_or_merge+specific'],
    ['Only the v2 contract', 'locked', 'one_off:pr_or_merge'],
    ['Design approved, never change it', 'locked', 'one_off:event'],
    ['No prod without a separate GO', 'locked', 'one_off:go'],
    ['Should we always do this?', 'locked', 'one_off:open'],
    ['Staging only; never prod', 'locked', 'one_off:staging'],
    ['No residual mills for this climb', 'locked', 'one_off:scoped_to_now'],
    ['Then the sidecar chip only', 'locked', 'one_off:sequence'],
    ['Never touch login 1068', 'locked', 'one_off:specific'],
    ['Only 0.26 on the ask side', 'locked', 'one_off:specific'],
    ['Never point at 10.0.0.1', 'locked', 'one_off:specific'],
    ['Every clientco server is test only', 'locked', 'one_off:cross_scope'],
    ['The card has a soft shadow', 'locked', 'no_standing_signal'],
  ];
  for (const [text, st, reason] of cases) assert.equal(decide(text, st).reason, reason, text);
  assert.equal(decide('Never ship it').decision, 'promote');
  assert.deepEqual(classifyLock({ text: 'Never ship it', noteStatus: 'locked', lockStatus: 'superseded', standing: false }), { decision: 'skip', reason: 'not_current:superseded' });
  assert.deepEqual(classifyLock({ text: 'Never ship it', noteStatus: 'locked', lockStatus: 'expired', standing: false }), { decision: 'skip', reason: 'not_current:expired' });
  assert.deepEqual(classifyLock({ text: 'whatever', noteStatus: 'parked', lockStatus: 'current', standing: true }), { decision: 'already_standing', reason: 'already_standing' });
});

test('classifier preview on a fixture vault: Northbank only, walled paths never read, exact promote set and counts; nothing written', () => {
  const root = fixtureVault();
  try {
    const before = hashTree(root);
    const r = classifyVault({ root, now: new Date('2026-11-18T00:00:00Z') });
    assert.deepEqual(r.promote, [
      'Work/product/2026-11-06-root-northbank.md:1',
      `${T}/2026-11-01-broker-onboarding-lock.md:1`,
      `${T}/2026-11-01-broker-onboarding-lock.md:3`,
      `${T}/2026-11-02-dated-lock.md:3`,
      `${T}/2026-11-07-marked.md:2`,
      `${T}/2026-11-09-superseder.md:1`,
      `${T}/engineering/2026-11-05-each.md:1`,
      `${T}/engineering/2026-11-05-each.md:2`,
    ]);
    const reason = (ref: string) => r.items.find((i) => i.ref === ref)!.reason;
    assert.equal(reason(`${T}/2026-11-01-broker-onboarding-lock.md:2`), 'one_off:pr_or_merge+go+staging');
    assert.equal(reason(`${T}/2026-11-03-parked.md:1`), 'note_status:parked');
    assert.equal(reason(`${T}/2026-11-07-marked.md:1`), 'already_standing');
    assert.equal(reason(`${T}/2026-11-08-superseded.md:1`), 'not_current:superseded');
    assert.equal(reason(`${T}/2026-11-04-approved.md:7`), 'no_standing_signal');
    assert.deepEqual(r.counts, { promote: 8, skip: 12, already_standing: 1 });
    assert.equal(r.lock_items, 21);
    assert.equal(r.counts.promote + r.counts.skip + r.counts.already_standing, r.lock_items);
    assert.ok(!r.items.some((i) => i.vaultPath.startsWith('Work/ops/')), 'standing folders are not classified');
    assert.ok(!r.items.some((i) => /walled|pnl/i.test(i.ref)), 'walled names / seed-wall paths are never read');
    const text = formatClassify(r);
    assert.match(text, /DRY RUN: nothing written/);
    assert.match(text, /promote 8 \/ skip 12 \/ already standing 1/);
    assert.deepEqual(hashTree(root), before, 'the preview writes nothing');
  } finally {
    rmSync(dirname(root), { recursive: true, force: true });
  }
});

test('classifier (reviewer check b): --real marks EXACTLY the previewed set (same ids); re-classify shows them already standing; a second write changes nothing', () => {
  const root = fixtureVault();
  try {
    const now = new Date('2026-11-18T00:00:00Z');
    const preview = classifyVault({ root, now });
    const before = hashTree(root);
    const w = applyStandingMarkers(root, preview);
    assert.deepEqual(w.refused, []);
    assert.deepEqual(w.written, preview.promote, 'write set == preview set, same ids, same order');
    assert.equal(w.files_changed, new Set(preview.promote.map((x) => x.slice(0, x.lastIndexOf(':')))).size);
    // what is now on disk = the preview set (re-parsed from the files themselves)
    const onDisk: string[] = [];
    for (const rel of before.keys()) {
      const block = frontmatterBlock(readFileSync(join(root, rel), 'utf8'));
      if (!block || !CLASSIFY_PREFIXES.some((p) => rel.startsWith(p))) continue;
      for (const o of parseStandingMarker(parseFrontmatter(block)['standing_locks'])) if (o !== null) onDisk.push(`${rel}:${o}`);
    }
    assert.deepEqual(onDisk.filter((x) => !x.endsWith('2026-11-07-marked.md:1')).sort(), [...preview.promote].sort());
    // only the promoted notes changed
    const after = hashTree(root);
    for (const [rel, h] of before) {
      const touched = preview.promote.some((x) => x.startsWith(`${rel}:`));
      assert.equal(after.get(rel) !== h, touched, rel);
    }
    const again = classifyVault({ root, now });
    assert.deepEqual(again.promote, []);
    assert.equal(again.counts.already_standing, preview.counts.already_standing + preview.counts.promote);
    const w2 = applyStandingMarkers(root, again);
    assert.deepEqual([w2.written, w2.files_changed], [[], 0]);
    assert.deepEqual(hashTree(root), after);
  } finally {
    rmSync(dirname(root), { recursive: true, force: true });
  }
});

test('classifier write: frontmatter edit keeps every other byte; an existing marker is merged in place; CRLF kept', () => {
  const a = '---\ntitle: X\nstatus: locked\nlocks:\n  - "Never a"\n  - "Never b"\n---\nbody\n';
  assert.equal(withStandingMarker(a, [2]), '---\ntitle: X\nstatus: locked\nlocks:\n  - "Never a"\n  - "Never b"\nstanding_locks: [2]\n---\nbody\n');
  const b = '---\ntitle: X\nstanding_locks:\n  - 3\nlocks: ["a", "b", "c"]\n---\nbody';
  assert.equal(withStandingMarker(b, [1]), '---\ntitle: X\nstanding_locks: [1, 3]\nlocks: ["a", "b", "c"]\n---\nbody');
  const c = '---\r\ntitle: X\r\nlocks: ["a"]\r\n---\r\nbody\r\n';
  assert.equal(withStandingMarker(c, [1]), '---\r\ntitle: X\r\nlocks: ["a"]\r\nstanding_locks: [1]\r\n---\r\nbody\r\n');
  assert.equal(withStandingMarker('no frontmatter', [1]), null);
});

test('classifier write: a file changed after the preview is refused and left as it is; a symlinked note is refused', () => {
  const root = fixtureVault();
  try {
    const preview = classifyVault({ root });
    const victim = join(root, `${T}/2026-11-02-dated-lock.md`);
    writeFileSync(victim, `${readFileSync(victim, 'utf8')}\nedited after the preview\n`);
    const edited = readFileSync(victim, 'utf8');
    const linkTarget = join(root, `${T}/engineering/2026-11-05-each.md`);
    const real = readFileSync(linkTarget);
    rmSync(linkTarget);
    writeFileSync(join(dirname(root), 'outside.md'), real);
    symlinkSync(join(dirname(root), 'outside.md'), linkTarget);
    const w = applyStandingMarkers(root, preview);
    assert.deepEqual(w.refused.map((x) => x.vault_path).sort(), [`${T}/2026-11-02-dated-lock.md`, `${T}/engineering/2026-11-05-each.md`]);
    assert.equal(readFileSync(victim, 'utf8'), edited);
    assert.ok(!readFileSync(join(dirname(root), 'outside.md'), 'utf8').includes('standing_locks'), 'never writes through a symlink');
    assert.ok(!w.written.some((x) => x.includes('dated-lock') || x.includes('each.md')));
  } finally {
    rmSync(dirname(root), { recursive: true, force: true });
  }
});

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

test('locks classify CLI: dry run by default (prints counts, writes nothing); --real --from <saved preview> writes exactly that set; walled --vault refused', () => {
  const root = fixtureVault();
  const home = dirname(root);
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: home, PGSERVICEFILE: join(home, 'pg_service.conf') };
  const run = (args: string[]) => spawnSync(process.execPath, [CLI, 'locks', 'classify', ...args], { cwd: home, encoding: 'utf8', env, timeout: 20_000 });
  try {
    const before = hashTree(root);
    const d = run(['--vault', root]);
    assert.equal(d.status, 0, d.stderr);
    assert.match(d.stdout, /DRY RUN: nothing written/);
    assert.match(d.stdout, /promote 8 \/ skip 12 \/ already standing 1/);
    assert.doesNotMatch(d.stdout, /Never ask for a separate/, 'lock text only with --show-text');
    assert.deepEqual(hashTree(root), before);
    const j = run(['--vault', root, '--json']);
    const pj = JSON.parse(j.stdout) as { promote: string[]; dry_run: boolean; items: Array<Record<string, unknown>> };
    assert.equal(pj.dry_run, true);
    assert.ok(pj.items.every((i) => !('text' in i)));
    assert.equal(run(['--vault', root, '--real']).status, 2, '--real needs --from <saved preview>');
    const saved = join(home, 'preview.json');
    const sp = run(['--vault', root, '--save-preview', saved]);
    assert.equal(sp.status, 0, sp.stderr);
    assert.deepEqual(hashTree(root), before, 'saving the preview writes nothing in the vault');
    const savedJson = JSON.parse(readFileSync(saved, 'utf8')) as { promote: string[] };
    assert.deepEqual(savedJson.promote, pj.promote);
    const real = run(['--vault', root, '--real', '--from', saved, '--json']);
    assert.equal(real.status, 0, real.stderr);
    const rj = JSON.parse(real.stdout) as { promote: string[]; applied: { written: string[] } };
    assert.deepEqual(rj.applied.written, savedJson.promote, 'written == the saved dry-run preview');
    assert.equal(run(['--vault', join(home, 'Plan' + 'kiva')]).status, 2);
    assert.equal(run([]).status, 2);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// End to end: preview -> write -> the real vault importer -> zeusi_startup (U5).
function asRole(db: Db, role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

test('classifier U5 end to end: after the write and a normal vault ingest, the promoted Northbank rules are in zeusi_startup; skipped ones stay out', async () => {
  const root = fixtureVault();
  const dir = dirname(root);
  const fakeHost = ['ep-fake-777', '-pooler.eu-central-1.aws.neon.tech'].join('');
  writeFileSync(join(dir, '.pg_service.conf'), `[zeusi_ro]\nhost=${fakeHost}\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
  const config = validateSources(parseToml(`[[source]]\nname = "vault-northbank-product"\nkind = "vault_note"\nscope = "product"\nroot = "${root}"\ninclude = ["Work/product/**/*.md", "Work/products/product/**/*.md"]\n`), seedWall(), { home: dir });
  const db = await pgliteDb();
  try {
    await migrate(db);
    applyStandingMarkers(root, classifyVault({ root }));
    await db.exec('SET ROLE zeusi_mini_ingest');
    try {
      const r = await importVault({ db, config, mode: 'full', home: dir });
      assert.equal(r.counts.errors, 0);
    } finally {
      await db.exec('RESET ROLE');
    }
    const deps: McpDeps = {
      env: { HOME: dir }, home: dir, readService: 'zeusi_ro', connectRead: asRole(db, 'zeusi_box_ro'), embeddings: () => null,
      feedbackPath: join(dir, '.zeusi', 'f.jsonl'), queryLedgerPath: join(dir, '.zeusi', 'q.json'),
    };
    const server = createZeusiMcpServer(deps, createMcpState());
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test', version: '0' });
    await Promise.all([server.connect(a), client.connect(b)]);
    try {
      const res = (await client.callTool({ name: 'zeusi_startup', arguments: {} })) as { content: Array<{ text?: string }> };
      const j = JSON.parse(res.content.map((c) => c.text ?? '').join('')) as { rules: Array<{ id: string; scope: string }>; rules_remainder: Array<{ id: string }> };
      const ids = [...j.rules.map((r) => r.id), ...j.rules_remainder.map((r) => r.id)].sort();
      const expected = [
        `vault:${T}/2026-11-01-broker-onboarding-lock.md#lock-1`, `vault:${T}/2026-11-01-broker-onboarding-lock.md#lock-3`, `vault:${T}/2026-11-02-dated-lock.md#lock-3`,
        `vault:${T}/2026-11-07-marked.md#lock-1`, `vault:${T}/2026-11-07-marked.md#lock-2`, `vault:${T}/2026-11-09-superseder.md#lock-1`,
        `vault:${T}/engineering/2026-11-05-each.md#lock-1`, `vault:${T}/engineering/2026-11-05-each.md#lock-2`, 'vault:Work/product/2026-11-06-root-northbank.md#lock-1',
      ].sort();
      assert.deepEqual(ids, expected, 'promoted (+ the one already marked) and nothing else');
      assert.ok(j.rules.every((r) => r.scope === 'product'));
    } finally {
      await client.close();
      await server.close();
    }
  } finally {
    await db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('locks classify CLI (review fix): a note edited or added after the saved dry run refuses the whole --real run; nothing is written', () => {
  for (const change of ['edit', 'add'] as const) {
    const root = fixtureVault();
    const home = dirname(root);
    const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: home, PGSERVICEFILE: join(home, 'pg_service.conf') };
    const run = (args: string[]) => spawnSync(process.execPath, [CLI, 'locks', 'classify', ...args], { cwd: home, encoding: 'utf8', env, timeout: 20_000 });
    try {
      const saved = join(home, 'preview.json');
      assert.equal(run(['--vault', root, '--save-preview', saved]).status, 0);
      if (change === 'edit') {
        const f = join(root, `${T}/2026-11-04-approved.md`);
        writeFileSync(f, readFileSync(f, 'utf8').replace('The platypus card has a soft shadow', 'Never round the platypus card'));
      } else {
        writeFileSync(join(root, `${T}/2026-11-10-new.md`), note({ title: 'Synthetic new', locks: ['Every numbat export carries its source'] }));
      }
      const before = hashTree(root);
      const r = run(['--vault', root, '--real', '--from', saved]);
      assert.equal(r.status, 1, change);
      assert.match(r.stderr, /REFUSED, nothing written/);
      assert.deepEqual(hashTree(root), before, `${change}: nothing written`);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
});

test('classifier write (review fix): an existing marker with a non-ordinal entry is refused, never silently rewritten', () => {
  assert.equal(withStandingMarker('---\ntitle: X\nstanding_locks: [1, x]\nlocks: ["a", "b"]\n---\nbody\n', [2]), null);
  const root = fixtureVault();
  try {
    const f = join(root, `${T}/2026-11-01-broker-onboarding-lock.md`);
    writeFileSync(f, readFileSync(f, 'utf8').replace('tags: [northbank, lock]', 'standing_locks: [2, x]\ntags: [northbank, lock]'));
    const body = readFileSync(f, 'utf8');
    const w = applyStandingMarkers(root, classifyVault({ root }));
    assert.ok(w.refused.some((x) => x.vault_path.endsWith('broker-onboarding-lock.md') && /did not verify/.test(x.why)));
    assert.equal(readFileSync(f, 'utf8'), body);
    assert.ok(!readdirSync(dirname(f)).some((n) => n.includes('zeusi-classify')), 'no temp file left behind');
  } finally {
    rmSync(dirname(root), { recursive: true, force: true });
  }
});
