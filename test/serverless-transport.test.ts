// HTTPS (WebSocket over 443) serverless transport for `zeusi search` + read-only `doctor`.
// No network: the @neondatabase/serverless Client is replaced by an injected factory. The
// one-transaction tests run search through the serverless Db against PGlite (fake Client
// that forwards to PGlite), so SET LOCAL semantics are real Postgres semantics.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConfigError } from '../src/config.ts';
import { ConnectError, RO_PASSWORD_ENV, type Db } from '../src/db.ts';
import {
  assertTransportAllowed, connectReadOnly, connectServerless, resolveTransport, serverlessDb, SERVERLESS_COMMANDS,
  SERVERLESS_ROLES, TRANSPORT_ENV, TransportRefused, WssOnlyWebSocket,
  type ServerlessClientConfig, type ServerlessClientFactory, type ServerlessClientLike,
} from '../src/transport.ts';
import type { SecurityRunner } from '../src/keychain.ts';
import { collectDoctor, doctorExitOk, formatDoctor, runDoctor } from '../src/doctor.ts';
import { pgliteDb } from './pglite-db.ts';
import { migrate } from '../src/migrate.ts';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { importVault } from '../src/importers/vault.ts';
import { FakeEmbeddingsClient } from '../src/embeddings.ts';
import { runEmbed } from '../src/embed.ts';
import { QueryLedger, search, SearchRefused } from '../src/search.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { assertRejectsRedacted, assertSecretEqual } from './redact.ts';
import { withPlatform } from './helpers/platform.ts';

// Fake values assembled at runtime; never real.
const FAKE_HOST = ['ep-fake-222', '-pooler.eu-central-1.aws.neon.tech'].join('');
const ENV_PW = ['sl-env-', 'pw-never-', 'print-7'].join('');
const KC_PW = ['sl-keychain-', 'pw-', 'q'].join('');
const GATE = { [TRANSPORT_ENV]: 'serverless' };

function svc(user: string, service = 'zeusi_ro') {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-sl-'));
  const file = join(home, 'pg_service.conf');
  writeFileSync(file, `[${service}]\nhost=${FAKE_HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`);
  return { home, file };
}

interface FakeLog {
  configs: ServerlessClientConfig[];
  clients: FakeClient[];
}

class FakeClient implements ServerlessClientLike {
  neonConfig: Record<string, unknown> = {};
  statements: string[] = [];
  connected = false;
  ended = false;
  private readonly onConnect: () => Promise<void>;
  private readonly forward: ((sql: string, params?: unknown[]) => Promise<{ rows: unknown[] }>) | undefined;
  constructor(onConnect: () => Promise<void> = async () => {}, forward?: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[] }>) {
    this.onConnect = onConnect;
    this.forward = forward;
  }
  async connect() {
    await this.onConnect();
    this.connected = true;
  }
  async query(sql: string, params?: unknown[]) {
    if (!this.connected) throw new Error('not connected');
    this.statements.push(sql);
    return this.forward ? this.forward(sql, params) : { rows: [] };
  }
  async end() {
    this.ended = true;
  }
}

function factory(log: FakeLog, make: () => FakeClient = () => new FakeClient()): ServerlessClientFactory {
  return (cfg) => {
    log.configs.push(cfg);
    const c = make();
    log.clients.push(c);
    return c;
  };
}

const keychain = (calls: string[][] = []): SecurityRunner => async (args) => {
  calls.push(args);
  return { code: 0, stdout: `${KC_PW}\n` };
};
const noKeychain: SecurityRunner = async () => ({ code: 44, stdout: '' });

// ---------------------------------------------------------------------------
// Gate

test('gate value: unset / empty -> tcp; exactly "serverless" -> serverless; anything else refused', () => {
  assert.equal(TRANSPORT_ENV, 'ZEUSI_TRANSPORT');
  assert.equal(resolveTransport({}), 'tcp');
  assert.equal(resolveTransport({ ZEUSI_TRANSPORT: '' }), 'tcp');
  assert.equal(resolveTransport({ ZEUSI_TRANSPORT: 'serverless' }), 'serverless');
  for (const bad of ['tcp', 'serverles', 'SERVERLESS', ' serverless', 'serverless ', 'https', 'http', 'ws', '1', 'true', 'on']) {
    assert.throws(() => resolveTransport({ ZEUSI_TRANSPORT: bad }), (e: Error) => e instanceof TransportRefused && e instanceof ConfigError && /ZEUSI_TRANSPORT/.test(e.message), bad);
  }
});

test('gate on: only search and doctor may run; every other command is refused; help always runs', () => {
  assert.deepEqual([...SERVERLESS_COMMANDS].sort(), ['doctor', 'search']);
  for (const cmd of ['search', 'doctor']) assert.equal(assertTransportAllowed(cmd, GATE), 'serverless');
  for (const cmd of ['ingest', 'embed', 'migrate', 'prove', 'embed-smoke', 'wall', 'fact', 'vector-probe', 'export-filter', 'nope']) {
    assert.throws(() => assertTransportAllowed(cmd, GATE), (e: Error) => e instanceof TransportRefused && e.message.includes(cmd), cmd);
  }
  for (const cmd of [undefined, 'help', '--help', '-h']) assert.equal(assertTransportAllowed(cmd, { ZEUSI_TRANSPORT: 'typo' }), 'tcp');
  // gate off: every command keeps the TCP path; an invalid value is refused for every command
  for (const cmd of ['ingest', 'migrate', 'search']) {
    assert.equal(assertTransportAllowed(cmd, {}), 'tcp');
    assert.throws(() => assertTransportAllowed(cmd, { ZEUSI_TRANSPORT: 'severless' }), TransportRefused);
  }
});

test('gate off: connectReadOnly takes the existing TCP connectService path; the serverless client is never constructed', async () => {
  const { home, file } = svc('zeusi_box_ro');
  const log: FakeLog = { configs: [], clients: [] };
  const tcpCalls: string[] = [];
  const tcpDb = { label: 'tcp' } as Db;
  const db = await connectReadOnly('zeusi_ro', {
    env: { PGSERVICEFILE: file }, home, serverlessClient: factory(log),
    tcp: async (name) => { tcpCalls.push(name); return tcpDb; },
  });
  assert.equal(db, tcpDb);
  assert.deepEqual(tcpCalls, ['zeusi_ro']);
  assert.equal(log.configs.length, 0);
});

test('connectServerless refuses without the gate (no client constructed)', async () => {
  const { home, file } = svc('zeusi_box_ro');
  const log: FakeLog = { configs: [], clients: [] };
  await assert.rejects(connectServerless('zeusi_ro', { env: { PGSERVICEFILE: file }, home, runSecurity: keychain(), serverlessClient: factory(log) }), TransportRefused);
  assert.equal(log.configs.length, 0);
});

// ---------------------------------------------------------------------------
// Roles

test('SERVERLESS_ROLES is exactly zeusi_box_ro + zeusi_cloud_ro (a widened allow-list goes red here)', () => {
  assert.deepEqual([...SERVERLESS_ROLES].sort(), ['zeusi_box_ro', 'zeusi_cloud_ro']);
});

test('gate on + write-capable or unknown role: refused before any password read, client or connect', async () => {
  for (const user of ['zeusi_box_rw', 'zeusi_mini_ingest', 'zeusi_mini_backup', 'neondb_owner', 'zeusi_owner', 'postgres', 'zeusi_box_ro2', 'ZEUSI_BOX_RO', 'zeusi_read']) {
    const { home, file } = svc(user);
    const log: FakeLog = { configs: [], clients: [] };
    const sec: string[][] = [];
    const tcp: string[] = [];
    await assertRejectsRedacted(
      connectReadOnly('zeusi_ro', {
        env: { PGSERVICEFILE: file, ...GATE, [RO_PASSWORD_ENV]: ENV_PW }, home, runSecurity: keychain(sec), serverlessClient: factory(log),
        tcp: async (n) => { tcp.push(n); throw new Error('tcp must not be used'); },
      }),
      (e) => e instanceof TransportRefused && e.message.includes(user) && /read-only/.test(e.message) && !e.message.includes(FAKE_HOST), [ENV_PW],
      user,
    );
    assert.equal(log.configs.length, 0, `${user}: no client constructed`);
    assert.equal(sec.length, 0, `${user}: no Keychain read`);
    assert.equal(tcp.length, 0, `${user}: no TCP fallback`);
  }
});

test('gate on + zeusi_box_ro / zeusi_cloud_ro: serverless client over wss, default proxy, password as a config field, never a URL', () => withPlatform('darwin', async () => {
  for (const [user, service, pw, env] of [
    ['zeusi_box_ro', 'zeusi_ro', ENV_PW, { [RO_PASSWORD_ENV]: ENV_PW }],
    ['zeusi_cloud_ro', 'zeusi_cloud', KC_PW, { [RO_PASSWORD_ENV]: ENV_PW }], // cloud_ro never takes the box_ro env var
  ] as const) {
    const { home, file } = svc(user, service);
    const log: FakeLog = { configs: [], clients: [] };
    const tcp: string[] = [];
    const db = await connectReadOnly(service, {
      env: { PGSERVICEFILE: file, ...GATE, ...env }, home, runSecurity: keychain(), serverlessClient: factory(log),
      tcp: async (n) => { tcp.push(n); throw new Error('tcp must not be used'); },
    });
    assert.equal(tcp.length, 0);
    assert.equal(log.configs.length, 1);
    const cfg = log.configs[0]!;
    assert.equal(cfg.user, user);
    assertSecretEqual(cfg.password, pw, `${user} password source`);
    assert.equal(cfg.host, FAKE_HOST);
    assert.equal(cfg.database, 'zeusi');
    assert.equal(cfg.port, 443);
    assert.ok(!('connectionString' in cfg), 'no URL string');
    const nc = log.clients[0]!.neonConfig;
    assert.equal(nc['useSecureWebSocket'], true, 'wss only');
    assert.equal(nc['forceDisablePgSSL'], true, 'TLS is the verified wss layer');
    assert.equal(nc['webSocketConstructor'], WssOnlyWebSocket);
    assert.equal(nc['pipelineConnect'], false);
    assert.ok(!('wsProxy' in nc), 'default Neon proxy (no override)');
    assert.ok(!('subtls' in nc) && !('rootCerts' in nc), 'no experimental pure-JS TLS');
    assert.ok(log.clients[0]!.connected);
    assert.deepEqual(db.transport, { tls: true, channelBinding: false, kind: 'serverless' });
    assert.ok(!db.label.includes(FAKE_HOST));
    await db.close();
    assert.ok(log.clients[0]!.ended);
  }
}));

test('only the WebSocket Client is used: no HTTP one-shot neon() / Pool / fetch in the transport', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(fileURLToPath(new URL('../src/transport.ts', import.meta.url)), 'utf8');
  const imports = src.split('\n').filter((l) => l.includes("from '@neondatabase/serverless'"));
  assert.deepEqual(imports, ["import { Client } from '@neondatabase/serverless';"]);
  const code = src.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  assert.doesNotMatch(code, /\bneon\(|\bPool\b|fetchEndpoint|poolQueryViaFetch|fetch\(|wsProxy\s*[:=]|subtls|rootCerts|useSecureWebSocket:\s*false/);
});

// ---------------------------------------------------------------------------
// TLS

test('TLS: the socket constructor refuses a non-wss URL; NODE_TLS_REJECT_UNAUTHORIZED=0 is refused before connecting', async () => {
  assert.throws(() => new WssOnlyWebSocket('ws://example.invalid/v2'), /wss/);
  assert.throws(() => new WssOnlyWebSocket('http://example.invalid/v2'), /wss/);
  const { home, file } = svc('zeusi_box_ro');
  const log: FakeLog = { configs: [], clients: [] };
  await assert.rejects(
    connectServerless('zeusi_ro', { env: { PGSERVICEFILE: file, ...GATE, NODE_TLS_REJECT_UNAUTHORIZED: '0', [RO_PASSWORD_ENV]: ENV_PW }, home, serverlessClient: factory(log) }),
    (e: Error) => e instanceof TransportRefused && /NODE_TLS_REJECT_UNAUTHORIZED/.test(e.message),
  );
  assert.equal(log.configs.length, 0);
});

test('service file TLS lines are still required on the serverless path (no relaxed section)', async () => {
  const { home, file } = svc('zeusi_box_ro');
  writeFileSync(file, `[zeusi_ro]\nhost=${FAKE_HOST}\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=require\nsslrootcert=system\nchannel_binding=disable\n`);
  const log: FakeLog = { configs: [], clients: [] };
  await assert.rejects(connectServerless('zeusi_ro', { env: { PGSERVICEFILE: file, ...GATE }, home, serverlessClient: factory(log) }), ConfigError);
  assert.equal(log.configs.length, 0);
});

test('a serverless connect error is redacted of host and password', async () => {
  const { home, file } = svc('zeusi_box_ro');
  const log: FakeLog = { configs: [], clients: [] };
  const err = factory(log, () => new FakeClient(async () => { throw new Error(`password authentication failed "${ENV_PW}" for wss://${FAKE_HOST}/v2`); }));
  let caught: unknown;
  try {
    await connectServerless('zeusi_ro', { env: { PGSERVICEFILE: file, ...GATE, [RO_PASSWORD_ENV]: ENV_PW }, home, serverlessClient: err });
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof ConnectError);
  const all = [String(caught), (caught as Error).stack ?? '', JSON.stringify(caught)].join('\n');
  assert.ok(!all.includes(ENV_PW) && !all.includes(FAKE_HOST));
  assert.ok(log.clients[0]!.ended, 'client closed after a failed connect');
});

test('the box_ro env password is honoured only for zeusi_box_ro on serverless too; without it, Keychain / ~/.pgpass', () => withPlatform('darwin', async () => {
  const { home, file } = svc('zeusi_box_ro');
  const log: FakeLog = { configs: [], clients: [] };
  await connectServerless('zeusi_ro', { env: { PGSERVICEFILE: file, ...GATE }, home, runSecurity: keychain(), serverlessClient: factory(log) });
  assertSecretEqual(log.configs[0]!.password, KC_PW, 'Keychain password');
  const c = svc('zeusi_cloud_ro', 'zeusi_cloud');
  await assertRejectsRedacted(
    connectServerless('zeusi_cloud', { env: { PGSERVICEFILE: c.file, ...GATE, [RO_PASSWORD_ENV]: ENV_PW, PGPASSWORD: ENV_PW }, home: c.home, runSecurity: noKeychain, serverlessClient: factory(log) }),
    (e) => /No password for role zeusi_cloud_ro/.test(e.message), [ENV_PW],
  );
}));

// ---------------------------------------------------------------------------
// Search over the serverless Db: SET LOCAL stays in the same transaction (PGlite)

const FIXTURE = fileURLToPath(new URL('./fixtures/vault/', import.meta.url));
let pg: Awaited<ReturnType<typeof pgliteDb>>;
let home: string;
const client = () => new FakeEmbeddingsClient(1536, { synonyms: { automobile: 'car', vehicle: 'car' } });

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-sl-search-'));
  const vault = join(home, 'vault');
  cpSync(FIXTURE, vault, { recursive: true });
  writeFileSync(join(vault, 'Work/research/garage.md'), '---\ntitle: Garage\n---\n# Fleet\n\nThe vehicle needs new tyres before winter.\n');
  const config = validateSources(parseToml(`
[[source]]
name = "vault-all"
kind = "vault_note"
scope = "work"
root = "${vault}"
include = ["**/*.md"]
`), seedWall(), { home });
  pg = await pgliteDb();
  await migrate(pg);
  await pg.exec('SET ROLE zeusi_mini_ingest');
  assert.equal((await importVault({ db: pg, config, mode: 'full', home, logPaths: false })).status, 'ok');
  assert.equal((await runEmbed({ db: pg, client: client(), host: 'testhost' })).status, 'ok');
  await pg.exec('RESET ROLE');
});
after(async () => pg.close());

interface Probe {
  ef: string;
  iterative: string;
}

/** Fake serverless Client on PGlite. Before each chunks query it records the settings in effect on the same session. */
function pgliteClient(probes: Probe[]): FakeClient {
  return new FakeClient(async () => {}, async (sql, params) => {
    if (/FROM zeusi\.chunks/.test(sql)) {
      const r = (await pg.raw.query<{ ef: string; it: string }>(
        `SELECT current_setting('hnsw.ef_search') AS ef, current_setting('hnsw.iterative_scan') AS it`,
      )).rows[0]!;
      probes.push({ ef: r.ef, iterative: r.it });
    }
    const r = await pg.raw.query(sql, params ?? []);
    return { rows: r.rows };
  });
}

/** Problems with the probes: empty means every chunks query saw both SET LOCALs. */
function setLocalProblems(probes: Probe[]): string[] {
  if (probes.length === 0) return ['no chunks query ran'];
  return probes.flatMap((p, i) => [
    ...(p.ef === '100' ? [] : [`query ${i}: hnsw.ef_search=${p.ef}, expected 100 (SET LOCAL not in this transaction)`]),
    ...(p.iterative === 'relaxed_order' ? [] : [`query ${i}: hnsw.iterative_scan=${p.iterative}, expected relaxed_order`]),
  ]);
}

async function asRole<T>(role: string, fn: () => Promise<T>): Promise<T> {
  await pg.exec(`SET ROLE ${role}`);
  try {
    return await fn();
  } finally {
    await pg.exec('RESET ROLE');
  }
}

test('search over the serverless Db: one client, BEGIN READ ONLY .. SET LOCAL x2 .. query .. ROLLBACK, settings in effect at query time', async () => {
  for (const hybrid of [false, true]) {
    const probes: Probe[] = [];
    const fc = pgliteClient(probes);
    await fc.connect();
    const db = serverlessDb(fc, 'zeusi_ro');
    const r = await asRole('zeusi_box_ro', () => search({ db, query: 'automobile', hybrid, client: client(), ledger: new QueryLedger(join(home, `l-${hybrid}.json`)) }));
    assert.ok(r.hits.length > 0);
    assert.deepEqual(setLocalProblems(probes), []);
    const s = fc.statements;
    const begin = s.indexOf('BEGIN READ ONLY');
    const ef = s.findIndex((x) => /^SET LOCAL hnsw\.ef_search = 100$/.test(x));
    const it = s.findIndex((x) => /^SET LOCAL hnsw\.iterative_scan = relaxed_order$/.test(x));
    const q = s.findIndex((x) => /FROM zeusi\.chunks/.test(x));
    const rb = s.lastIndexOf('ROLLBACK');
    assert.ok(begin >= 0 && begin < ef && ef < it && it < q && q < rb, s.join(' | '));
    assert.ok(!s.slice(begin + 1, rb).some((x) => /^(COMMIT|ROLLBACK|BEGIN|END)\b/i.test(x)), 'no transaction boundary in between');
    assert.equal(s.at(-1), 'ROLLBACK');
  }
});

test('MUTANT: a one-shot transport (each statement auto-commits, as the HTTP API would) is caught: SET LOCAL not in effect', async () => {
  const probes: Probe[] = [];
  const fc = pgliteClient(probes);
  await fc.connect();
  // Mutant Db: drops the transaction boundaries, so each statement is its own implicit transaction.
  const oneShot: Db = {
    label: 'mutant one-shot',
    query: (sql, params) => fc.query(sql, params) as never,
    exec: async (sql) => { if (!/^(BEGIN|ROLLBACK)/.test(sql)) await fc.query(sql); },
    close: async () => {},
  };
  await asRole('zeusi_box_ro', () => search({ db: oneShot, query: 'automobile', client: client(), ledger: new QueryLedger(join(home, 'l-m.json')) }));
  const problems = setLocalProblems(probes);
  assert.ok(problems.length > 0, 'the probe must flag SET LOCAL outside the query transaction');
  assert.match(problems.join('\n'), /hnsw\.ef_search=(?!100)/);
});

test('writer and owner sessions are still refused by search over the serverless Db', async () => {
  const fc = pgliteClient([]);
  await fc.connect();
  const db = serverlessDb(fc, 'zeusi_ro');
  for (const role of ['zeusi_box_rw', 'zeusi_mini_ingest', 'zeusi_mini_backup']) {
    await assert.rejects(asRole(role, () => search({ db, query: 'tyres', client: null, ledger: new QueryLedger(join(home, 'l-w.json')) })), SearchRefused, role);
  }
  await assert.rejects(search({ db, query: 'tyres', client: null, ledger: new QueryLedger(join(home, 'l-o.json')) }), SearchRefused, 'owner');
});

// ---------------------------------------------------------------------------
// Doctor honesty

test('doctor over serverless: TLS yes, channel binding no (named exception), never claims SCRAM-SHA-256-PLUS; runs READ ONLY', async () => {
  const fc = pgliteClient([]);
  await fc.connect();
  const base = serverlessDb(fc, 'zeusi_ro');
  const db: Db = { ...base, label: base.label, transport: { tls: true, channelBinding: false, kind: 'serverless' } };
  const info = await asRole('zeusi_box_ro', () => runDoctor(db, 'zeusi_ro'));
  assert.equal(info.transport, 'serverless');
  assert.equal(info.tls, true);
  assert.equal(info.channelBinding, false);
  const out = formatDoctor(info);
  assert.match(out, /^transport: serverless/m);
  assert.match(out, /^channel binding: no \(serverless transport: password over verified TLS/m);
  assert.doesNotMatch(out, /SCRAM-SHA-256-PLUS\)/);
  assert.doesNotMatch(out, /channel binding: yes/);
  assert.ok(!out.includes(FAKE_HOST));
  assert.equal(fc.statements[0], 'BEGIN READ ONLY');
  assert.equal(fc.statements.at(-1), 'ROLLBACK');
  assert.equal(doctorExitOk(info), info.pgvector !== null);
  // a TCP session without channel binding still fails doctor; serverless without TLS fails too
  assert.equal(doctorExitOk({ ...info, transport: 'tcp' }), false);
  assert.equal(doctorExitOk({ ...info, tls: false }), false);
});

test('doctor over TCP is unchanged: SCRAM-SHA-256-PLUS shown only when channel binding was used; no READ ONLY wrapper added', async () => {
  const seen: string[] = [];
  const db: Db = { ...pg, label: pg.label, transport: { tls: true, channelBinding: true }, query: (s, p) => { seen.push(s); return pg.query(s, p); }, exec: (s) => { seen.push(s); return pg.exec(s); } };
  const info = await runDoctor(db, 'zeusi_ingest');
  assert.equal(info.transport, 'tcp');
  assert.match(formatDoctor(info), /^channel binding: yes \(SCRAM-SHA-256-PLUS\)$/m);
  assert.ok(!seen.includes('BEGIN READ ONLY'));
  assert.equal(doctorExitOk(info), info.pgvector !== null);
  assert.equal(doctorExitOk({ ...info, channelBinding: false }), false);
  const direct = await collectDoctor(db, 'zeusi_ingest');
  assert.equal(direct.transport, 'tcp');
});
