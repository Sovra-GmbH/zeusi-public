// CLI wiring: role commands never read the owner URL (.env.local); wall allow refuses
// hard uris offline, before any connection. Spawns the CLI in a temp dir; no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { redact } from './redact.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const FAKE_OWNER = ['postgresql://', 'owner', ':', 'fakeOwnerPw', '@', 'ep-fake-1', '.eu-central-1.aws.neon.tech/zeusi'].join('');

function run(args: string[], extraEnvFile = '', serviceFile?: string) {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cli-'));
  writeFileSync(join(dir, '.env.local'), `DATABASE_URL=${FAKE_OWNER}\nDATABASE_URL_UNPOOLED=${FAKE_OWNER}\n${extraEnvFile}`);
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: dir, PGSERVICEFILE: serviceFile ?? join(dir, 'missing.conf') };
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', env, timeout: 20_000 });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

test('role commands use the service file and ignore .env.local (owner URL)', () => {
  for (const args of [['doctor'], ['doctor', '--roles'], ['wall', 'audit'], ['wall', 'report'], ['fact', 'get', '1'], ['vector-probe']]) {
    const r = run(args);
    assert.equal(r.code, 2, `${args.join(' ')}: ${r.out}`);
    assert.match(r.out, /Service "zeusi_(ingest|backup)" not found/, args.join(' '));
    assert.doesNotMatch(r.out, /fakeOwnerPw|neon\.tech|postgres(ql)?:\/\//, 'nothing from the owner URL is printed');
  }
});

test('wall allow refuses a hard (Plankiva, also under ClientCo/) uri offline, before any owner connection', () => {
  const sha = 'ab'.repeat(32);
  for (const uri of ['file:~/PlankivaVault/requests/form-1.md', 'vault:ClientCo/plankiva-x.md', 'vault:ClientCo/P-l-a-n-k-i-v-a.md', 'vault:Work/notes/plankiva.md']) {
    const r = run(['wall', 'allow', uri, sha]);
    assert.equal(r.code, 2, r.out);
    assert.match(r.out, /no connection made/);
  }
  assert.match(run(['wall', 'allow', 'vault:Work/x.md', 'zz']).out, /64 hex/);
});

test('doctor --offline makes no connection and prints no secrets', () => {
  const r = run(['doctor', '--offline']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /service file: MISSING/);
  assert.match(r.out, /0008_wall_normalise\.sql/);
  assert.match(r.out, /0009_wall_r2\.sql/);
  assert.doesNotMatch(r.out, /fakeOwnerPw|neon\.tech/);
});

// r1 MINOR-5: prove / embed-smoke write probe rows; they refuse Neon main offline.
test('prove and embed-smoke refuse before connecting when the target may be Neon main', () => {
  for (const cmd of ['prove', 'embed-smoke']) {
    // Main endpoint unknown → cannot prove the target is a branch → refuse.
    let r = run([cmd]);
    assert.equal(r.code, 2, `${cmd}: ${r.out}`);
    assert.match(r.out, /ZEUSI_MAIN_ENDPOINT_ID/);
    assert.match(r.out, /no connection made/i);
    // The owner URL points at the main endpoint → refuse.
    r = run([cmd], 'ZEUSI_MAIN_ENDPOINT_ID=ep-fake-1\n');
    assert.equal(r.code, 2, `${cmd}: ${r.out}`);
    assert.match(r.out, /default branch/);
    assert.match(r.out, /--i-know-this-is-main/);
    assert.doesNotMatch(r.out, /fakeOwnerPw|ep-fake-1|neon\.tech|postgres(ql)?:\/\//, 'no host or URL printed');
  }
});

// r1 MINOR-7: the channel-binding downgrade needs an explicit flag.
test('ZEUSI_CHANNEL_BINDING=off alone is refused before any owner connection', () => {
  const r = run(['migrate', '--dry-run'], 'ZEUSI_CHANNEL_BINDING=off\n');
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /--insecure-no-channel-binding/);
  assert.doesNotMatch(r.out, /fakeOwnerPw|ep-fake-1|neon\.tech/);
});

// U5: `ingest vault`. Write mode needs --real (refused before any connection);
// --dry-run reads a FIXTURE vault in a temp dir, needs no database, prints counts only.
function vaultFixtureConfig(dir: string): string {
  const vault = join(dir, 'vault');
  cpSync(fileURLToPath(new URL('./fixtures/vault/', import.meta.url)), vault, { recursive: true });
  const cfg = join(dir, 'sources.toml');
  writeFileSync(cfg, `[[source]]\nname = "v"\nkind = "vault_note"\nscope = "work"\nroot = "${vault}"\ninclude = ["**/*.md"]\n`);
  return cfg;
}

test('ingest vault: write mode without --real is refused before any connection', () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cli-v-'));
  const cfg = vaultFixtureConfig(dir);
  for (const args of [['ingest', 'vault', '--config', cfg], ['ingest', 'vault', '--full', '--config', cfg], ['ingest', 'vault', '--incremental', '--config', cfg]]) {
    const r = run(args);
    assert.equal(r.code, 2, r.out);
    assert.match(r.out, /--real/);
    assert.match(r.out, /no connection made/);
    assert.doesNotMatch(r.out, /Service "/, 'never reached the service lookup');
  }
  const both = run(['ingest', 'vault', '--full', '--incremental', '--dry-run', '--config', cfg]);
  assert.equal(both.code, 2, both.out);
  assert.match(both.out, /either --full or --incremental/);
  const missing = run(['ingest', 'vault', '--dry-run']);
  assert.equal(missing.code, 2, missing.out);
  assert.match(missing.out, /config\/sources\.toml/);
});

test('ingest vault --real goes through the zeusi_ingest service (never .env.local)', () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cli-v-'));
  const r = run(['ingest', 'vault', '--real', '--config', vaultFixtureConfig(dir)]);
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /Service "zeusi_ingest" not found/);
  assert.doesNotMatch(r.out, /fakeOwnerPw|neon\.tech|postgres(ql)?:\/\//);
});

test('ingest vault --dry-run on a fixture vault: no database, counts only, no paths or text', () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cli-v-'));
  const r = run(['ingest', 'vault', '--dry-run', '--config', vaultFixtureConfig(dir)]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /dry run, no database/);
  assert.match(r.out, /would insert: 7/); // 0010: the ClientCo note is admitted (scope clientco)
  assert.match(r.out, /client 1/);
  assert.match(r.out, /path-gated: 5/);
  assert.match(r.out, /errors: 1/);
  assert.doesNotMatch(r.out, /20-notes|00-meta|wiki\/glossary|Home\.md|budget|pricing|Synthetic|USD 1200|fakeOwnerPw/, "no note paths or text (rule patterns are wall config)");
});

// r2 MINOR-1: the importer's session advisory lock does not hold over the pooled endpoint.
test('ingest vault --real refuses a pooled zeusi_ingest host offline: no password read, no connect, no host printed', () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cli-v-'));
  const svc = join(dir, 'pg_service.conf');
  const host = ['ep-x', '-pooler.example.invalid'].join('');
  writeFileSync(svc, `[zeusi_ingest]\nhost=${host}\nport=5432\ndbname=zeusi\nuser=zeusi_mini_ingest\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
  const r = run(['ingest', 'vault', '--real', '--config', vaultFixtureConfig(dir)], '', svc);
  assert.equal(r.code, 2, r.out);
  assert.match(r.out, /service "zeusi_ingest"/i);
  assert.match(r.out, /pooled/i);
  assert.match(r.out, /no connection made/i);
  assert.ok(r.out.includes(svc), 'names the service file');
  assert.doesNotMatch(r.out, /ep-x|example\.invalid|pooler\./i, 'no host text');
  assert.doesNotMatch(r.out, /Keychain|pgpass|connection failed|ENOTFOUND/i, 'refused before the password read / connect');
  // The dry run never looks at the service file: unaffected.
  const d = run(['ingest', 'vault', '--dry-run', '--config', vaultFixtureConfig(safeMkdtemp(join(tmpdir(), 'zeusi-cli-v-')))], '', svc);
  assert.equal(d.code, 0, d.out);
  assert.match(d.out, /would insert: 7/);
});

// ---------------------------------------------------------------------------
// U6: embed / search wiring (offline refusals; no network, no DB)

const FAKE_KEY = ['sk-', 'proj-', 'FAKEcli', 'never-print'].join('');
const FIXTURE_VAULT = fileURLToPath(new URL('./fixtures/vault/', import.meta.url));

/** Credential-looking values a test hands the CLI: redacted from `out`; `leaked` says if the raw output had one. */
function credentialOut(raw: string, extra: Record<string, string>): { out: string; leaked: boolean } {
  const secrets = Object.entries(extra).filter(([k]) => /PASSWORD|KEY|SECRET|TOKEN|PGPASS/i.test(k)).map(([, v]) => v).filter((v) => v !== '');
  return { out: redact(raw, secrets), leaked: secrets.some((s) => raw.includes(s)) };
}

function runEnv(args: string[], extra: Record<string, string> = {}) {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cli6-'));
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: dir, PGSERVICEFILE: join(dir, 'missing.conf'), ...extra };
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', env, timeout: 30_000 });
  return { code: r.status, ...credentialOut(`${r.stdout}${r.stderr}`, extra), dir };
}

test('embed: write mode needs --real; --real needs ZEUSI_OPENAI_API_KEY; both refused before any connection', () => {
  const a = runEnv(['embed']);
  assert.equal(a.code, 2, a.out);
  assert.match(a.out, /--real/);
  assert.doesNotMatch(a.out, /Service "/, 'no connection attempted');
  const b = runEnv(['embed', '--real']);
  assert.equal(b.code, 2, b.out);
  assert.match(b.out, /ZEUSI_OPENAI_API_KEY is not set/);
  assert.doesNotMatch(b.out, /Service "/);
  const c = runEnv(['embed', '--real', '--dry-run']);
  assert.equal(c.code, 2);
  // with a key, --real goes on to the (missing) ingest service: the key is never printed
  const d = runEnv(['embed', '--real'], { ZEUSI_OPENAI_API_KEY: FAKE_KEY });
  assert.equal(d.code, 2, d.out);
  assert.match(d.out, /Service "zeusi_ingest" not found/);
  assert.ok(!d.out.includes(FAKE_KEY));
  // the cap can only be lowered, offline
  const e = runEnv(['embed', '--dry-run', '--cap-usd', '6']);
  assert.equal(e.code, 2);
  assert.match(e.out, /only lower/);
});

test('embed --estimate runs offline over a vault (counts only, no paths)', () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cli6e-'));
  const vault = join(dir, 'vault');
  cpSync(FIXTURE_VAULT, vault, { recursive: true });
  const cfg = join(dir, 'sources.toml');
  writeFileSync(cfg, `[[source]]\nname = "vault-work"\nkind = "vault_note"\nscope = "work"\nroot = "${vault}"\ninclude = ["Work/**/*.md", "Home.md", "wiki/*.md"]\n`);
  const r = runEnv(['embed', '--estimate', '--config', cfg, '--notes-per-day', '12']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /\(a\) current wall: \d+ notes, \d+ chunks/);
  assert.match(r.out, /upper bound/);
  assert.match(r.out, /\+12 new\/changed notes per day/);
  assert.doesNotMatch(r.out, /client-alpha|the team\/|\.md\b|synthetic/);
});

test('search: uses service zeusi_ro; without a key it says lexical-only; never prints the ro password', () => {
  const pw = ['ro-', 'cli-', 'pw-x'].join('');
  const a = runEnv(['search', 'hello'], { ZEUSI_NEON_BOX_RO_PASSWORD: pw });
  assert.equal(a.code, 2, a.out);
  assert.match(a.out, /Service "zeusi_ro" not found/);
  assert.match(a.out, /lexical-only/);
  assert.ok(!a.leaked, 'the ro password never reaches stdout/stderr');
  const b = runEnv(['search', 'hello', '--scope', 'personal']);
  assert.equal(b.code, 2);
  assert.match(b.out, /--scope must be one of/);
  const c = runEnv(['search']);
  assert.equal(c.code, 2);
  assert.match(c.out, /usage: search/);
});

test('ingest never embeds: the importer does not import the embed pipeline or a client', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(fileURLToPath(new URL('../src/importers/vault.ts', import.meta.url)), 'utf8');
  assert.doesNotMatch(src, /from '\.\.\/embed\.ts'|from '\.\.\/embeddings\.ts'|runEmbed|createOpenAIClient/);
});

// ---------------------------------------------------------------------------
// Serverless (wss/443) transport gate: offline refusals only (no network, no DB)

function runSl(args: string[], extra: Record<string, string>, serviceText?: string) {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-cli-sl-'));
  writeFileSync(join(dir, '.env.local'), `DATABASE_URL=${FAKE_OWNER}\nDATABASE_URL_UNPOOLED=${FAKE_OWNER}\n`);
  const svc = join(dir, 'pg_service.conf');
  if (serviceText !== undefined) writeFileSync(svc, serviceText);
  const env = { PATH: process.env['PATH'] ?? '/usr/bin:/bin', ZEUSI_TEST_NO_REAL_CREDS: '1', HOME: dir, PGSERVICEFILE: svc, ...extra };
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', env, timeout: 30_000 });
  return { code: r.status, ...credentialOut(`${r.stdout}${r.stderr}`, extra) };
}

const SL_HOST = ['ep-sl', '-pooler.example.invalid'].join('');
const slSection = (service: string, user: string) =>
  `[${service}]\nhost=${SL_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;

test('ZEUSI_TRANSPORT=serverless refuses every command but search and doctor, before any connection or .env.local read', () => {
  const all = ['zeusi_ingest', 'zeusi_backup', 'zeusi_rw', 'zeusi_ro'].map((s) => slSection(s, 'zeusi_box_ro')).join('\n');
  for (const args of [
    ['ingest', 'vault', '--dry-run'], ['ingest', 'hq-sync', '--real'], ['embed', '--dry-run'], ['embed', '--estimate'], ['embed', '--real'],
    ['migrate'], ['migrate', '--dry-run'], ['prove'], ['embed-smoke'], ['wall', 'allow', 'vault:x.md', 'ab'.repeat(32)], ['wall', 'audit'],
    ['wall', 'report'], ['fact', 'get', '1'], ['fact', 'add'], ['vector-probe'], ['export-filter', '--in', 'a', '--out', 'b'],
  ]) {
    const r = runSl(args, { ZEUSI_TRANSPORT: 'serverless', ZEUSI_OPENAI_API_KEY: FAKE_KEY }, all);
    assert.equal(r.code, 2, `${args.join(' ')}: ${r.out}`);
    assert.match(r.out, /ZEUSI_TRANSPORT=serverless is only for search and doctor/, args.join(' '));
    assert.match(r.out, new RegExp(`"${args[0]}" keeps the TCP path`));
    assert.doesNotMatch(r.out, /Service "|fakeOwnerPw|neon\.tech|example\.invalid|Keychain|pgpass|connection failed|sk-proj/, args.join(' '));
  }
});

test('an invalid ZEUSI_TRANSPORT value is refused for every command (never ignored); help still prints', () => {
  for (const bad of ['serverles', 'tcp', 'SERVERLESS', 'https']) {
    for (const args of [['search', 'hello'], ['doctor'], ['ingest', 'vault', '--dry-run'], ['migrate']]) {
      const r = runSl(args, { ZEUSI_TRANSPORT: bad });
      assert.equal(r.code, 2, `${bad} ${args.join(' ')}: ${r.out}`);
      assert.match(r.out, /ZEUSI_TRANSPORT may only be "serverless"/);
      assert.ok(!r.out.includes(`"${bad}"`), 'value not echoed');
      assert.doesNotMatch(r.out, /Service "|lexical-only/);
    }
  }
  const h = runSl(['help'], { ZEUSI_TRANSPORT: 'typo' });
  assert.equal(h.code, 0);
  assert.match(h.out, /ZEUSI_TRANSPORT=serverless/);
});

test('gate on: search / doctor as a write-capable role are refused offline (no password read, no host printed)', () => {
  const pw = ['sl-', 'cli-', 'pw-y'].join('');
  for (const [args, service, user] of [
    [['search', 'hello', '--limit', '3'], 'zeusi_ro', 'zeusi_box_rw'],
    [['search', 'hello', '--service', 'zeusi_rw'], 'zeusi_rw', 'zeusi_box_rw'],
    [['doctor'], 'zeusi_ingest', 'zeusi_mini_ingest'],
    [['doctor', '--roles'], 'zeusi_backup', 'zeusi_mini_backup'],
    [['doctor', '--service', 'zeusi_ro'], 'zeusi_ro', 'neondb_owner'],
  ] as const) {
    const r = runSl([...args], { ZEUSI_TRANSPORT: 'serverless', ZEUSI_NEON_BOX_RO_PASSWORD: pw }, slSection(service, user));
    assert.equal(r.code, 2, `${args.join(' ')}: ${r.out}`);
    assert.match(r.out, new RegExp(`user ${user} refused on the serverless transport`), args.join(' '));
    assert.match(r.out, /No password read, no connection made/);
    assert.ok(!r.leaked, 'the ro password never reaches stdout/stderr');
    assert.doesNotMatch(r.out, /example\.invalid|ep-sl|Keychain|pgpass|connection failed|ENOTFOUND/i);
  }
});

test('gate on: doctor --offline still works (no connection)', () => {
  const r = runSl(['doctor', '--offline'], { ZEUSI_TRANSPORT: 'serverless' });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /migrations: 0001/);
});

test('workspaces backfill-people: offline refusals before any connection (bad flag, bad service name, a service that is not the provisioner); never the owner URL', () => {
  const svc = join(safeMkdtemp(join(tmpdir(), 'zeusi-cli-svc-')), 'pg_service.conf');
  writeFileSync(svc, '[other]\nhost=ep-fake-1.eu-central-1.aws.neon.tech\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n');
  for (const [args, re] of [
    [['workspaces', 'backfill-people', '--nope'], /usage: workspaces backfill-writers\|backfill-people/],
    [['workspaces', 'backfill-nobody'], /usage: workspaces backfill-writers\|backfill-people/],
    [['workspaces', 'backfill-people', '--admin-service', 'x;y'], /--admin-service: letters, digits/],
    [['workspaces', 'backfill-people', '--admin-service', 'other'], /--admin-service must log in as zeusi_tenant_admin/],
  ] as Array<[string[], RegExp]>) {
    const r = run(args, '', svc);
    assert.notEqual(r.code, 0, `${args.join(' ')}: ${r.out}`);
    assert.match(r.out, re, args.join(' '));
    assert.doesNotMatch(r.out, /fakeOwnerPw|postgres(ql)?:\/\//);
  }
});
