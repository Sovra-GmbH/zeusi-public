// `zeusi people add|list` (src/people.ts, src/cli.ts): seed zeusi.people with a recorded source.
// PGlite for the database paths; the CLI is spawned only for offline refusals (main guard,
// validation, --dry-run), which happen before .env.local's URL is used. No network, no Neon.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { migrate } from '../src/migrate.ts';
import { ValidationError } from '../src/facts.ts';
import { insertDecision } from '../src/decisions.ts';
import { addPerson, displayUri, formatPeopleList, formatPlan, listPeople, PEOPLE_IMPORTER, PeopleRefused, validatePerson, type RawPersonFlags } from '../src/people.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const FAKE_OWNER = ['postgresql://', 'owner', ':', 'fakeOwnerPw', '@', 'ep-fake-1', '.eu-central-1.aws.neon.tech/zeusi'].join('');
// Synthetic walled value assembled at runtime (hard Plankiva rule, migrations 0011).
const WALLED = ['Plan', 'kiva P'].join('');
const SOURCE_TEXT = 'synthetic: the owner asked to seed the people table with owner';

let db: Db;

const flags = (over: RawPersonFlags = {}): RawPersonFlags => ({
  handle: 'owner', displayName: 'the owner', kind: 'human', org: 'work', scope: 'work',
  sourceUri: 'zeusi:test/people-add/owner', sourceTs: '2026-11-17T03:13:00+01:00', sourceText: SOURCE_TEXT, host: 'testhost',
  ...over,
});

const count = async (table: string, where = 'true', params: unknown[] = []) =>
  Number((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.${table} WHERE ${where}`, params)).rows[0]!.n);

function cli(args: string[], extraEnvFile = '') {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-people-cli-'));
  writeFileSync(join(dir, '.env.local'), `DATABASE_URL=${FAKE_OWNER}\nDATABASE_URL_UNPOOLED=${FAKE_OWNER}\n${extraEnvFile}`);
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: dir, PGSERVICEFILE: join(dir, 'missing.conf') };
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', env, timeout: 20_000 });
  const out = `${r.stdout}${r.stderr}`;
  assert.doesNotMatch(out, /fakeOwnerPw|neon\.tech|postgres(ql)?:\/\//, 'never prints the owner URL or host');
  return { code: r.status, out };
}

const ADD = ['people', 'add', '--handle', 'owner', '--display-name', 'the owner', '--kind', 'human', '--org', 'work', '--scope', 'work',
  '--source-uri', 'zeusi:test/people-add/owner', '--source-ts', '2026-11-17T03:13:00+01:00', '--source-text', SOURCE_TEXT, '--host', 'testhost'];

before(async () => {
  db = await pgliteDb();
  await migrate(db);
});
after(async () => { await db.close(); });

test('people add: inserts the person and one ingest_runs row (cli:people-add, manual, ok, finished, {inserted:1}) with sha256(source text)', async () => {
  const r = await addPerson(db, validatePerson(flags()));
  assert.equal(r.status, 'inserted');
  if (r.status !== 'inserted') return;
  const sha = createHash('sha256').update(SOURCE_TEXT, 'utf8').digest('hex');
  assert.equal(r.sha256, sha);
  const p = (await db.query<Record<string, unknown>>(
    `SELECT handle, display_name, kind, org, github_login, scope::text AS scope, source_kind::text AS source_kind, source_uri,
            source_ts, encode(source_sha256, 'hex') AS sha, ingest_run_id::int AS run FROM zeusi.people WHERE id = $1`, [r.id])).rows[0]!;
  assert.deepEqual({ ...p, source_ts: new Date(p['source_ts'] as string).toISOString() }, {
    handle: 'owner', display_name: 'the owner', kind: 'human', org: 'work', github_login: null, scope: 'work', source_kind: 'manual',
    source_uri: 'zeusi:test/people-add/owner', source_ts: '2026-11-17T02:13:00.000Z', sha, run: r.runId,
  });
  const run = (await db.query<{ importer: string; host: string; mode: string; status: string; finished: boolean; counts: unknown }>(
    `SELECT importer, host, mode, status, finished_at IS NOT NULL AS finished, counts FROM zeusi.ingest_runs WHERE id = $1`, [r.runId])).rows[0]!;
  assert.deepEqual(run, { importer: PEOPLE_IMPORTER, host: 'testhost', mode: 'manual', status: 'ok', finished: true, counts: { inserted: 1 } });
});

test('people add: an existing handle is reported and nothing changes (no update, no new run)', async () => {
  const people = await count('people');
  const runs = await count('ingest_runs');
  const r = await addPerson(db, validatePerson(flags({ displayName: 'Someone Else', sourceText: 'different text' })));
  assert.equal(r.status, 'exists');
  assert.equal(await count('people'), people);
  assert.equal(await count('ingest_runs'), runs);
  assert.equal((await db.query<{ d: string }>(`SELECT display_name AS d FROM zeusi.people WHERE handle = 'owner'`)).rows[0]!.d, 'the owner');
});

test('people add: after it, insertDecision with that who succeeds', async () => {
  await addPerson(db, validatePerson(flags({ handle: 'zeus-seed', displayName: 'Zeus', kind: 'agent', sourceUri: 'zeusi:test/people-add/zeus' })));
  const r = await insertDecision(db, {
    kind: 'go', who: 'zeus-seed', saidAt: '2026-11-17T03:13:00+01:00', saidAtPrecision: 'minute', exactWords: 'synthetic smoke-test go',
    exactWordsVerbatim: true, appliesTo: ['zeusi'], scope: 'work', sourceUri: 'zeusi:test/decision-after-seed', sourceTs: '2026-11-17T03:13:00+01:00',
  });
  assert.equal(r.status, 'inserted');
  await assert.rejects(insertDecision(db, {
    kind: 'go', who: 'not-seeded', saidAt: '2026-11-17T03:13:00+01:00', saidAtPrecision: 'minute', exactWords: 'x',
    exactWordsVerbatim: true, appliesTo: [], scope: 'work', sourceUri: 'zeusi:test/decision-unknown', sourceTs: '2026-11-17T03:13:00+01:00',
  }), /unknown person handle/);
});

test('people add: a walled value is refused by the trigger; the whole transaction rolls back (no person, no run)', async () => {
  const people = await count('people');
  const runs = await count('ingest_runs');
  await assert.rejects(addPerson(db, validatePerson(flags({ handle: 'walled-probe', displayName: WALLED }))), (e: unknown) => {
    assert.ok(e instanceof PeopleRefused);
    assert.match(e.message, /refused by the wall \(rule \d+/);
    assert.doesNotMatch(e.message, new RegExp(WALLED, 'i'), 'the refused value is never echoed');
    return true;
  });
  assert.equal(await count('people'), people);
  assert.equal(await count('ingest_runs'), runs);
  assert.equal(await count('people', 'handle = $1', ['walled-probe']), 0);
  // The connection is usable afterwards (not left in an aborted transaction).
  assert.equal((await addPerson(db, validatePerson(flags({ handle: 'after-wall', sourceUri: 'zeusi:test/people-add/after' })))).status, 'inserted');
});

test('people add: invalid handles and missing / bad flags are refused offline', () => {
  for (const handle of ['the owner', '-owner', 'ow ner', 'owner!', '', 'a'.repeat(65), 'zeus/x']) {
    assert.throws(() => validatePerson(flags({ handle })), ValidationError, handle);
  }
  assert.throws(() => validatePerson(flags({ sourceUri: ' ' })), /--source-uri/);
  assert.throws(() => validatePerson(flags({ sourceText: '' })), /--source-text/);
  assert.throws(() => validatePerson(flags({ displayName: undefined })), /--display-name/);
  assert.throws(() => validatePerson(flags({ scope: undefined })), /--scope/, 'no default scope');
  assert.throws(() => validatePerson(flags({ scope: 'public' })), /--scope must be/);
  assert.throws(() => validatePerson(flags({ kind: 'robot' })), /--kind/);
  assert.throws(() => validatePerson(flags({ org: 'client' })), /--org/);
  assert.throws(() => validatePerson(flags({ sourceTs: '2026-11-17' })), /--source-ts/);
  assert.throws(() => validatePerson(flags({ sourceTs: '2026-11-17T03:13:00' })), /--source-ts/, 'zone required');
  assert.throws(() => validatePerson(flags({ host: 'box.example.com' })), /--host/);
  assert.throws(() => validatePerson(flags({ githubLogin: 'bad login' })), /--github-login/);
  // personal only when typed explicitly AND acknowledged with --allow-personal (P2-4).
  assert.throws(() => validatePerson(flags({ scope: 'personal' })), /--allow-personal.*invisible to the decision writer/);
  assert.equal(validatePerson(flags({ scope: 'personal', allowPersonal: true })).scope, 'personal');
  // --host is required: no machine-name default (P2-3).
  assert.throws(() => validatePerson(flags({ host: undefined })), /missing or empty: --host/);
  assert.throws(() => validatePerson(flags({ host: ' ' })), /--host/);
  assert.throws(() => validatePerson(flags({ host: 'workstation.local' })), /--host must be a short label/);
});

test('people add: the exists path leaves no transaction open (P2-1)', async () => {
  // If ROLLBACK were missing on the exists path, the next statement would run inside that open
  // transaction, and a later ROLLBACK would undo it. Here the probe row must survive.
  assert.equal((await addPerson(db, validatePerson(flags()))).status, 'exists');
  const probe = (await db.query<{ id: number }>(
    `INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test:exists-probe', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.exec('ROLLBACK'); // a no-op (warning only) outside a transaction
  assert.equal(await count('ingest_runs', 'id = $1', [probe]), 1, 'the exists path left a transaction open');
  // and the statements it sent were BEGIN ... ROLLBACK, balanced
  const seen: string[] = [];
  const spy: Db = { ...db, label: db.label, query: (q, p) => { seen.push(q.trim().split(/\s+/)[0]!); return db.query(q, p); }, exec: (q) => { seen.push(q); return db.exec(q); }, close: () => db.close() };
  assert.equal((await addPerson(spy, validatePerson(flags()))).status, 'exists');
  assert.deepEqual(seen, ['BEGIN', 'SELECT', 'ROLLBACK']);
});

test('people: an http(s) source_uri is never echoed by --dry-run or list (P2-2)', async () => {
  const url = ['https://', 'chat.example', '.com/c/abc123?msg=42'].join('');
  assert.equal(displayUri(url), 'https://…');
  assert.equal(displayUri(['HTTP://', 'x.example/y'].join('')), 'http://…');
  for (const keep of ['manual:people/owner', 'zeusi:test/x', 'chat:example-thread', 'hq:example-thread']) assert.equal(displayUri(keep), keep);
  const plan = formatPlan(validatePerson(flags({ handle: 'url-person', sourceUri: url })));
  assert.match(plan, /source_uri=https:\/\/… source_sha256=/);
  assert.ok(!plan.includes('example'), 'no part of the URL is printed');
  const list = formatPeopleList([{ handle: 'url-person', kind: 'human', source_uri: url }, { handle: 'owner', kind: 'human', source_uri: 'manual:people/owner' }]);
  assert.ok(!list.includes('example'));
  assert.match(list, /url-person {2}human {2}https:\/\/…/);
  assert.match(list, /owner {2}human {2}manual:people\/owner/);
  const args = [...ADD];
  args[args.indexOf('--source-uri') + 1] = url;
  const r = cli([...args, '--dry-run']);
  assert.equal(r.code, 0, r.out);
  assert.ok(!r.out.includes('example'), r.out);
  assert.match(r.out, /source_uri=https:\/\/…/);
});

test('people list: handle, kind and source_uri only', async () => {
  const rows = await listPeople(db);
  assert.ok(rows.some((r) => r.handle === 'owner'));
  for (const r of rows) assert.deepEqual(Object.keys(r).sort(), ['handle', 'kind', 'source_uri']);
});

test('people add --dry-run: prints the row (sha prefix, no display name or text) and writes nothing, with no connection', async () => {
  const before = { people: await count('people'), runs: await count('ingest_runs') };
  const plan = formatPlan(validatePerson(flags({ handle: 'dry-only' })));
  assert.match(plan, /handle=dry-only kind=human org=work scope=work/);
  assert.match(plan, /source_uri=zeusi:test\/people-add\/owner source_sha256=[0-9a-f]{12}\.\.\./);
  assert.doesNotMatch(plan, /the owner|synthetic: /);
  assert.deepEqual({ people: await count('people'), runs: await count('ingest_runs') }, before);
  // CLI: no main-endpoint id set, so a real write would be refused; the dry run never gets that far.
  const r = cli([...ADD, '--dry-run']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /dry run: would insert .*no connection made/);
  assert.match(r.out, /handle=owner kind=human org=work scope=work/);
});

test('people add: the main-branch guard refuses before connecting (unknown main id, or the owner URL is main)', () => {
  let r = cli(ADD);
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /ZEUSI_MAIN_ENDPOINT_ID/);
  assert.match(r.out, /No connection made/);
  r = cli(ADD, 'ZEUSI_MAIN_ENDPOINT_ID=ep-fake-1\n');
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /targets the default branch \(main\)/);
});

test('people add (CLI): an invalid handle or a missing flag is refused offline with exit 2', () => {
  const bad = [...ADD];
  bad[bad.indexOf('--handle') + 1] = 'Not Valid';
  let r = cli(bad);
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /--handle must match/);
  r = cli(['people', 'add', '--handle', 'owner']);
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /missing or empty: --display-name/);
  // --host is required; --scope personal needs --allow-personal
  r = cli(ADD.filter((_, i) => i < ADD.indexOf('--host')));
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /missing or empty: --host/);
  const personal = [...ADD];
  personal[personal.indexOf('--scope') + 1] = 'personal';
  r = cli([...personal, '--dry-run']);
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /--allow-personal/);
  r = cli([...personal, '--allow-personal', '--dry-run']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /scope=personal/);
  r = cli(['people', 'add', '--nope']);
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /usage: people add/);
});
