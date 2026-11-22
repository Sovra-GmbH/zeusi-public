// First-run import pipeline (plan U8, AE7, AE8; PR2 P1-P5): adapters -> runExportFilter (unchanged)
// -> importVault(IMPORT_PROFILE) -> structured decisions / facts. Dry run offline; real runs on
// PGlite as zeusi_mini_ingest only (SET ROLE). Planted secret / Plankiva / IBAN values are built at
// runtime. No network, no Neon.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import {
  executeImport, formatPreview, formatRealResult, prepareImport, SCOPE_PROJECT, STRUCTURED_IMPORTER, type PreparedImport,
} from '../src/import-run.ts';
import { ImportInputError, type ImportInput } from '../src/importers/onboard.ts';
import { HQ_PROFILE, IMPORT_PROFILE, VAULT_PROFILE, assertIngestReady } from '../src/importers/vault.ts';
import { RESERVED_VAULT_PREFIXES, vaultFormatProblem } from '../src/importers/profile.ts';
import { MainBranchRefused, mainBranchGuardForHost, MAIN_ENDPOINT_ENV } from '../src/owner-guard.ts';
import { wallAudit } from '../src/wall-admin.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';

// Planted values, built at runtime so no secret-shaped literal sits in the repo.
const TOKEN = ['gh', 'p_', 'Z'.repeat(36)].join('');
const WALL_TERM = ['Plan', 'kiva'].join('');
const IBAN = ['CH93', '0076', '2011', '6238', '5295', '7'].join(' ');
const SHA = 'ef'.repeat(32);
const WORK_SCOPE_ONLY = 'zeusi_test_import_work_only';

let db: Db;
let dir: string;

before(async () => {
  dir = safeMkdtemp(join(tmpdir(), 'zeusi-import-run-'));
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  for (const h of ['synthetic-owner']) {
    await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                    VALUES ($1, 'Synthetic Owner', 'human', 'work', 'work', 'manual', 'manual:people/x', now(), decode($2, 'hex'), $3)`, [h, SHA, run]);
  }
  await db.exec(`CREATE ROLE ${WORK_SCOPE_ONLY} NOLOGIN;
    GRANT USAGE ON SCHEMA zeusi TO ${WORK_SCOPE_ONLY};
    GRANT SELECT ON zeusi.notes, zeusi.chunks, zeusi.decisions, zeusi.decisions_current, zeusi.facts, zeusi.facts_current TO ${WORK_SCOPE_ONLY};
    CREATE POLICY t_work ON zeusi.notes FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY t_work ON zeusi.chunks FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY t_work ON zeusi.decisions FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');
    CREATE POLICY t_work ON zeusi.facts FOR SELECT TO ${WORK_SCOPE_ONLY} USING (scope = 'work');`);
});
after(async () => db.close());

/** The AE7 sample folder: clean, planted token, planted wall term, IBAN, plus a lock note. */
function sampleFolder(name: string): string {
  const f = join(dir, name);
  mkdirSync(f, { recursive: true });
  writeFileSync(join(f, 'clean.md'), '---\ntitle: Clean synthetic note\ndate: 2026-11-10\n---\nA clean synthetic note about deploy windows.\n');
  writeFileSync(join(f, 'token.md'), `---\ntitle: Token note\ndate: 2026-11-10\n---\nthe key is ${TOKEN}\n`);
  writeFileSync(join(f, 'wall.md'), `---\ntitle: Wall note\ndate: 2026-11-10\n---\nsomething about ${WALL_TERM} here\n`);
  writeFileSync(join(f, 'iban.md'), `---\ntitle: Bank note\ndate: 2026-11-10\n---\npay to ${IBAN} please\n`);
  writeFileSync(join(f, 'locks.md'), '---\ntitle: Ops locks (synthetic)\ndate: 2026-11-11\nlocks:\n  - SYNTHETIC no prod deploys on Fridays\n  - SYNTHETIC keep the release train locked\n---\n## Why\nsynthetic reasons\n');
  return f;
}

function decisionLog(name: string, lines: object[]): string {
  const p = join(dir, `${name}.jsonl`);
  writeFileSync(p, lines.map((x) => JSON.stringify(x)).join('\n') + '\n');
  return p;
}

const LOCK_LINE = { kind: 'lock', who: 'synthetic-owner', said_at: '2026-11-12T08:00:00+01:00', said_at_precision: 'minute', exact_words: 'SYNTHETIC no Northbank prod promotion during market hours', exact_words_verbatim: false, applies_to: ['northbank', 'prod'], linked_repo: 'Synthetic-Org/northbank', linked_pr: 42 };
const UNKNOWN_LINE = { kind: 'go', who: 'nobody-known', said_at: '2026-11-12T09:00:00Z', said_at_precision: 'day', exact_words: 'SYNTHETIC go from an unknown person' };
const FOCUS_MD = '## 2026-11-13T10:00:00Z synthetic-owner\nType: focus\nSubject: synthetic-quarter\n\nSYNTHETIC focus: ship the importer\n\n## 2026-11-13T11:00:00Z synthetic-owner\nType: rule\nSubject: synthetic-review\n\nSYNTHETIC rule: every PR gets a second login review\n';

async function counts(): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const t of ['notes', 'chunks', 'quarantine', 'ingest_runs', 'decisions', 'facts', 'people']) {
    out[t] = Number((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.${t}`)).rows[0]!.n);
  }
  return out;
}

/** As zeusi_mini_ingest (grants exercised), like `import --real` after the guards. */
async function real(p: PreparedImport, wrap?: (d: Db) => Db) {
  await db.exec('SET ROLE zeusi_mini_ingest');
  try {
    await assertIngestReady(db);
    return await executeImport(p, wrap ? wrap(db) : db, { host: 'test', home: dir });
  } finally {
    await db.exec('RESET ROLE');
  }
}

const prep = (inputs: ImportInput[], scope: string, workRoot = join(dir, 'work')) => prepareImport({ inputs, scope, workRoot, home: dir });

test('import (AE7): dry run on the planted folder: token and wall-term entries withheld, IBAN note would-quarantine, clean note admitted; zero database writes; work dir removed', async () => {
  const before = await counts();
  const p = await prep([{ kind: 'markdown', path: sampleFolder('ae7') }], 'work');
  try {
    const v = p.preview;
    assert.equal(v.error, undefined);
    assert.equal(v.inputs[0]!.notes_staged, 5);
    assert.equal(v.filter.entries_withheld, 2);
    assert.equal(v.filter.withheld_by_signal.plankiva, 1);
    assert.equal(v.filter.withheld_by_signal.credential, 1);
    assert.equal(v.importer.quarantined, 1, 'the IBAN note (soft rule)');
    assert.equal(v.targets.notes, 4, 'clean + lock note + two marker-only notes, as the nightly path admits them');
    assert.equal(v.targets.note_locks, 2);
    const text = formatPreview(v);
    for (const bad of [TOKEN, WALL_TERM, IBAN, 'Clean synthetic note', 'deploy windows', dir]) assert.ok(!text.includes(bad), `preview has ${bad.slice(0, 8)}`);
    assert.match(text, /nothing written/);
    assert.match(text, /withheld \(export filter, same as nightly\): entries 2/);
  } finally {
    p.cleanup();
  }
  assert.equal(existsSync(p.workDir), false, 'work dir removed');
  assert.deepEqual(await counts(), before, 'zero rows written by a dry run');
});

test('import (AE8): real run as zeusi_mini_ingest into product: notes manual with import: uris; planted values absent everywhere; IBAN in quarantine by uri + hash; one ingest_runs row; second run inserts 0', async () => {
  const folder = sampleFolder('ae8');
  const p1 = await prep([{ kind: 'markdown', path: folder }], 'product');
  let r1;
  try {
    r1 = await real(p1);
  } finally {
    p1.cleanup();
  }
  assert.equal(r1.status, 'ok', r1.error ?? '');
  assert.equal(r1.notes.inserted, 4);
  assert.equal(r1.notes.quarantined, 1);
  assert.equal(r1.targets.note_locks, 2);
  const rows = (await db.query<{ source_kind: string; source_uri: string; scope: string; vault_path: string }>(
    `SELECT source_kind::text, source_uri, scope::text, vault_path FROM zeusi.notes WHERE vault_path LIKE 'import:%' ORDER BY id`)).rows;
  assert.equal(rows.length, 4);
  for (const r of rows) {
    assert.equal(r.source_kind, 'manual');
    assert.equal(r.scope, 'product');
    assert.match(r.source_uri, /^import:northbank\/2026-11-1[01]-memory-[0-9a-f]{8}\.md$/);
  }
  for (const [t, cols] of [['notes', 'title || body || frontmatter::text'], ['chunks', 'text'], ['quarantine', 'source_uri'], ['ingest_runs', 'counts::text']] as const) {
    for (const bad of [TOKEN, WALL_TERM.toLowerCase(), IBAN]) {
      const n = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.${t} WHERE lower(${cols}) LIKE '%' || lower($1) || '%'`, [bad])).rows[0]!.n;
      assert.equal(n, 0, `${t} holds a planted value`);
    }
  }
  const q = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.quarantine WHERE source_uri LIKE 'import:northbank/%' AND source_kind = 'manual'`)).rows[0]!.n;
  assert.ok(q >= 1, 'the IBAN note is quarantined by uri + hash');
  const runs = (await db.query<{ importer: string; status: string }>(`SELECT importer, status FROM zeusi.ingest_runs WHERE importer = $1`, [IMPORT_PROFILE.importer])).rows;
  assert.deepEqual(runs, [{ importer: 'onboard-import', status: 'ok' }]);
  await db.exec('SET ROLE zeusi_mini_ingest');
  try {
    assert.deepEqual(await wallAudit(db), [], 'wall audit clean after the import');
  } finally {
    await db.exec('RESET ROLE');
  }

  // Idempotent: the same input again writes nothing new, resumes as unchanged, records a new run.
  const p2 = await prep([{ kind: 'markdown', path: folder }], 'product');
  try {
    const r2 = await real(p2);
    assert.equal(r2.status, 'ok');
    assert.equal(r2.notes.inserted, 0);
    assert.equal(r2.notes.skipped, 4);
    assert.match(formatRealResult(r2), /resumed \/ unchanged 4/);
  } finally {
    p2.cleanup();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.ingest_runs WHERE importer = 'onboard-import'`)).rows[0]!.n, 2);

  // Scope isolation: a reader limited to scope team sees none of the product import.
  await db.exec(`SET ROLE ${WORK_SCOPE_ONLY}`);
  try {
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes WHERE vault_path LIKE 'import:%'`)).rows[0]!.n, 0);
    assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.chunks WHERE source_uri LIKE 'import:%'`)).rows[0]!.n, 0);
  } finally {
    await db.exec('RESET ROLE');
  }
});

test('import (P1): structured decisions, rules and focus land only with an existing who; unknown_person skipped (no person created); re-run dedupes; an edited entry is a conflict (no UPDATE)', async () => {
  const peopleBefore = (await counts())['people'];
  const log = decisionLog('decisions', [LOCK_LINE, UNKNOWN_LINE]);
  const mdLog = join(dir, 'focus-log.md');
  writeFileSync(mdLog, FOCUS_MD);
  const inputs: ImportInput[] = [{ kind: 'decision-log', path: log }, { kind: 'decision-log', path: mdLog }];
  const p = await prep(inputs, 'work');
  try {
    assert.equal(p.preview.targets.decisions, 2, 'dry run: both headed decisions would insert (people are checked on the real run)');
    assert.deepEqual(p.preview.targets.decisions_by_kind, { go: 1, lock: 1 });
    assert.equal(p.preview.targets.rules, 1);
    assert.equal(p.preview.targets.focus, 1);
    assert.equal(p.preview.structured.handles_named, 2);
    assert.equal(p.preview.structured.duplicate_in_run, 0);
    const r = await real(p);
    assert.equal(r.status, 'ok_partial');
    assert.deepEqual(
      [r.structured.decisions_inserted, r.structured.rules_inserted, r.structured.focus_inserted, r.structured.unknown_person, r.structured.conflict],
      [1, 1, 1, 1, 0],
    );
  } finally {
    p.cleanup();
  }
  assert.equal((await counts())['people'], peopleBefore, 'no person created');
  const d = (await db.query<Record<string, unknown>>(
    `SELECT kind::text, said_at_precision, exact_words, exact_words_verbatim, applies_to, linked_repo, linked_pr, scope::text, source_kind::text, source_uri,
            (SELECT handle FROM zeusi.people p WHERE p.id = d.who_id) AS who
     FROM zeusi.decisions d WHERE source_uri LIKE 'import:%'`)).rows;
  assert.equal(d.length, 1);
  assert.deepEqual({ ...d[0], source_uri: undefined }, {
    kind: 'lock', said_at_precision: 'minute', exact_words: LOCK_LINE.exact_words, exact_words_verbatim: false, applies_to: ['northbank', 'prod'],
    linked_repo: 'Synthetic-Org/northbank', linked_pr: 42, scope: 'work', source_kind: 'manual', who: 'synthetic-owner', source_uri: undefined,
  });
  assert.match(String(d[0]!['source_uri']), /^import:team\/entry\/[0-9a-f]{16}$/);
  const f = (await db.query<{ kind: string; subject: string; text: string }>(`SELECT kind, subject, text FROM zeusi.facts_current WHERE source_uri LIKE 'import:%' ORDER BY kind`)).rows;
  assert.deepEqual(f.map((x) => [x.kind, x.subject]), [['rule', 'synthetic-review'], ['state', 'synthetic-quarter']]);
  const sruns = (await db.query<{ status: string }>(`SELECT status FROM zeusi.ingest_runs WHERE importer = $1`, [STRUCTURED_IMPORTER])).rows;
  assert.deepEqual(sruns.map((x) => x.status), ['ok_partial']);

  // Re-run: everything deduped, nothing inserted.
  const p2 = await prep(inputs, 'work');
  try {
    const r2 = await real(p2);
    assert.deepEqual([r2.structured.decisions_inserted, r2.structured.rules_inserted, r2.structured.focus_inserted, r2.structured.deduped], [0, 0, 0, 3]);
  } finally {
    p2.cleanup();
  }
  // Edited entry (same who + said_at, new words): conflict, refused, the old row unchanged.
  const edited = decisionLog('decisions-edited', [{ ...LOCK_LINE, exact_words: 'SYNTHETIC edited words' }]);
  const p3 = await prep([{ kind: 'decision-log', path: edited }], 'work');
  try {
    const r3 = await real(p3);
    assert.equal(r3.structured.conflict, 1);
    assert.equal(r3.structured.decisions_inserted, 0);
    assert.equal(r3.status, 'ok_partial');
  } finally {
    p3.cleanup();
  }
  const words = (await db.query<{ exact_words: string }>(`SELECT exact_words FROM zeusi.decisions WHERE source_uri LIKE 'import:%'`)).rows.map((x) => x.exact_words);
  assert.deepEqual(words, [LOCK_LINE.exact_words]);
});

test('import (P1, P3): a structured entry with an IBAN is quarantined (uri + hash only); one with a planted token or wall term never reaches the decision table', async () => {
  const log = decisionLog('walled', [
    { ...LOCK_LINE, said_at: '2026-11-15T08:00:00Z', exact_words: `SYNTHETIC pay ${IBAN}` },
    { ...LOCK_LINE, said_at: '2026-11-15T09:00:00Z', exact_words: `SYNTHETIC token ${TOKEN}` },
    { ...LOCK_LINE, said_at: '2026-11-15T10:00:00Z', exact_words: `SYNTHETIC about ${WALL_TERM}` },
  ]);
  const before = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions`)).rows[0]!.n;
  const p = await prep([{ kind: 'decision-log', path: log }], 'work');
  try {
    assert.equal(p.preview.filter.entries_withheld, 2, 'token and wall-term entries withheld by the nightly filter');
    const r = await real(p);
    assert.equal(r.structured.decisions_inserted, 0);
    assert.ok(r.structured.quarantined + r.notes.quarantined >= 1, 'the IBAN entry is quarantined');
  } finally {
    p.cleanup();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions`)).rows[0]!.n, before);
  for (const bad of [TOKEN, IBAN, WALL_TERM]) {
    const n = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE exact_words LIKE '%' || $1 || '%'`, [bad])).rows[0]!.n;
    assert.equal(n, 0);
  }
});

test('import: input A then input B keeps A active (no deletion pass); clientco lands in folder clientco with scope clientco; a team import never produces clientco rows', async () => {
  const a = join(dir, 'in-a');
  const b = join(dir, 'in-b');
  mkdirSync(a);
  mkdirSync(b);
  writeFileSync(join(a, 'a.md'), '---\ndate: 2026-11-01\n---\nSYNTHETIC note A unique-a-771\n');
  writeFileSync(join(b, 'b.md'), '---\ndate: 2026-11-02\n---\nSYNTHETIC note B unique-b-772\n');
  for (const [inp, scope] of [[a, 'work'], [b, 'work'], [a, 'client']] as const) {
    const p = await prep([{ kind: 'markdown', path: inp }], scope);
    try {
      assert.equal((await real(p)).status, 'ok');
    } finally {
      p.cleanup();
    }
  }
  const rows = (await db.query<{ status: string; scope: string; vault_path: string }>(
    `SELECT status, scope::text, vault_path FROM zeusi.notes WHERE body LIKE '%unique-a-771%' OR body LIKE '%unique-b-772%' ORDER BY vault_path`)).rows;
  assert.deepEqual(rows.map((r) => [r.status, r.scope, r.vault_path.split('/')[0]]), [['active', 'client', 'import:clientco'], ['active', 'work', 'import:team'], ['active', 'work', 'import:team']]);
  assert.equal(SCOPE_PROJECT.client, 'clientco');
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes WHERE vault_path LIKE 'import:team/%' AND scope = 'client'`)).rows[0]!.n, 0);
});

test('import: resumable: a database error on one note leaves the others in; the re-run inserts the rest and skips the completed one', async () => {
  const f = join(dir, 'resume');
  mkdirSync(f);
  for (const n of [1, 2, 3]) writeFileSync(join(f, `n${n}.md`), `---\ndate: 2026-10-0${n}\n---\nSYNTHETIC resume note ${n} resume-marker-88\n`);
  let noteInserts = 0;
  const failSecond = (d: Db): Db => ({
    ...d,
    query: async (sql: string, params?: unknown[]) => {
      if (/INSERT INTO zeusi\.notes/.test(sql) && ++noteInserts === 2) throw Object.assign(new Error('synthetic connection drop'), { code: '08006' });
      return d.query(sql, params);
    },
  } as Db);
  const p1 = await prep([{ kind: 'markdown', path: f }], 'work');
  try {
    const r = await real(p1, failSecond);
    assert.equal(r.notes.inserted, 2);
    assert.equal(r.notes.errors, 1);
  } finally {
    p1.cleanup();
  }
  const p2 = await prep([{ kind: 'markdown', path: f }], 'work');
  try {
    const r = await real(p2);
    assert.deepEqual([r.notes.inserted, r.notes.skipped], [1, 2]);
  } finally {
    p2.cleanup();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.notes WHERE body LIKE '%resume-marker-88%' AND status = 'active'`)).rows[0]!.n, 3);
});

test('import: an owner-privileged session is refused by assertIngestReady before any write', async () => {
  await assert.rejects(assertIngestReady(db), /owner-privileged/);
});

test('import: bad inputs are refused with a safe message and the work dir is removed; scope is required and fixed', async () => {
  const workRoot = join(dir, 'work-bad');
  await assert.rejects(prep([], 'work', workRoot), /at least one input/);
  await assert.rejects(prep([{ kind: 'markdown', path: join(dir, 'missing') }], 'work', workRoot), (e: Error) => {
    assert.ok(e instanceof ImportInputError);
    assert.ok(!e.message.includes(dir));
    return true;
  });
  await assert.rejects(prep([{ kind: 'markdown', path: dir }], 'personal', workRoot), /--scope must be one of/);
  assert.deepEqual(existsSync(workRoot) ? readdirSync(workRoot) : [], [], 'no work dir left behind');
});

test('profiles: vault and hq-sync still delete by default; imports never delete; import: is a reserved vault prefix', () => {
  assert.equal(VAULT_PROFILE.deletes, undefined);
  assert.equal(HQ_PROFILE.deletes, undefined);
  assert.equal(IMPORT_PROFILE.deletes, false);
  assert.deepEqual([IMPORT_PROFILE.sourceKind, IMPORT_PROFILE.scheme, IMPORT_PROFILE.storedPrefix, IMPORT_PROFILE.importer], ['manual', 'import', 'import:', 'onboard-import']);
  assert.ok((RESERVED_VAULT_PREFIXES as readonly string[]).includes('import:'));
  assert.match(vaultFormatProblem('import:x/y.md') ?? '', /reserved prefix/);
  assert.equal(vaultFormatProblem('Work/x.md'), null);
});

test('main-branch guard (host): refused when the env id is unset, not an id, or equal to the service host; passes for a branch; --i-know-this-is-main overrides; no host in messages', () => {
  const host = ['ep-synthetic-main-123', '.eu-central-1.aws.neon.tech'].join('');
  const branch = ['ep-synthetic-branch-456', '.eu-central-1.aws.neon.tech'].join('');
  const cases: Array<[NodeJS.ProcessEnv, string]> = [[{}, host], [{ [MAIN_ENDPOINT_ENV]: 'not-an-id' }, host], [{ [MAIN_ENDPOINT_ENV]: 'ep-synthetic-main-123' }, host], [{ [MAIN_ENDPOINT_ENV]: 'ep-synthetic-main-123' }, 'localhost']];
  for (const [env, h] of cases) {
    assert.throws(() => mainBranchGuardForHost(h, env, false), (e: Error) => {
      assert.ok(e instanceof MainBranchRefused);
      assert.ok(!e.message.includes('ep-synthetic') && !e.message.includes('neon.tech'));
      return true;
    });
  }
  assert.deepEqual(mainBranchGuardForHost(branch, { [MAIN_ENDPOINT_ENV]: 'ep-synthetic-main-123' }, false), { onMain: false });
  assert.deepEqual(mainBranchGuardForHost(host, {}, true), { onMain: true });
});

test('import: the same headed entry reached through two inputs is counted and written once', async () => {
  const f = join(dir, 'dup-in-run');
  mkdirSync(f);
  const entry = '## 2026-11-16T10:00:00Z synthetic-owner\nDecision: stop\nSaid-at-precision: day\n\nSYNTHETIC stop the dup-marker-55 migration\n';
  writeFileSync(join(f, 'log.md'), entry);
  const p = await prep([{ kind: 'markdown', path: f }, { kind: 'decision-log', path: join(f, 'log.md') }], 'work');
  try {
    assert.equal(p.preview.targets.decisions, 1);
    assert.equal(p.preview.structured.duplicate_in_run, 1);
    const r = await real(p);
    assert.deepEqual([r.structured.decisions_inserted, r.structured.deduped], [1, 0]);
  } finally {
    p.cleanup();
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.decisions WHERE exact_words LIKE '%dup-marker-55%'`)).rows[0]!.n, 1);
});
