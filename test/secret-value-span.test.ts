// Fix round 2 finish (self-review fix2d): every detector rule whose value is bounded by a
// delimiter redacts the WHOLE credential span, never a residue:
//   * url_password: to the LAST `@` of the authority (`scheme://user:<p1>@<p2>@host`), user may be empty;
//   * private_key: BEGIN to the END line, or to the end of the text (never to a blank line:
//     PGP armor and encrypted PEM have one between the headers and the key body);
//   * bearer: a token68 start, then on to the next whitespace or quote;
//   * masked provider fragments: the tail runs on across further strong masks;
//   * keyword = value as a YAML block scalar (`password: |` + indented lines).
// The withhold floor (defence in depth) withholds the residue shapes the old spans left.
// Table-driven through every serve path and every storage path, like secret-keyword-span.
//
// All values are synthetic, assembled at runtime; every value piece carries the marker VW, so
// "no value piece survives" is one substring check. Nothing here is or resembles a real key.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import { parseToml, validateSources } from '../src/sources.ts';
import { seedWall } from '../src/wall.ts';
import { importVault } from '../src/importers/vault.ts';
import { insertFact } from '../src/facts.ts';
import type { SearchResult } from '../src/search.ts';
import { createMcpState, createZeusiMcpServer, type McpDeps } from '../src/mcp-server.ts';
import { guardString, safeMessage, wallFilter } from '../src/mcp-wall.ts';
import { runRescrub } from '../src/rescrub.ts';
import { redactDeep, redactSecrets, STORAGE_SKIP, strictCredentialSignal, withholdFloor } from '../src/secrets.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { j, P } from './secret-fixtures.ts';
import { b64, BEGIN, END, pw, survives, VALUE_CASES as CASES, VW } from './secret-shapes.ts';

const SHA = 'ab'.repeat(32);
const OLD = new Date('2026-01-05T10:00:00Z');
const MARKS = /\[REDACTED:[a-z_]+\]/g;
const markers = (s: string) => (s.match(MARKS) ?? []).length;

/** Cases joined into texts of at most `max` characters (facts.text is capped at 4000). */
function batches(max: number): string[] {
  const out: string[] = [];
  let cur = '';
  for (const c of CASES) {
    const add = `${c.text}\nnext line kept\n`;
    if (cur.length + add.length > max) { out.push(cur); cur = ''; }
    cur += add;
  }
  if (cur) out.push(cur);
  return out;
}

// ---------------------------------------------------------------------------
// Detector + floor, unit level

test('fix2d: every delimiter-bounded rule redacts the whole credential span, keeps the rest, idempotent', () => {
  for (const c of CASES) {
    const r = redactSecrets(`before\n${c.text}\nafter kept`);
    assert.ok(!survives(r.text), `no value piece: ${c.name}`);
    assert.ok(r.text.includes(`[REDACTED:${c.kind}]`), `kind ${c.kind}: ${c.name}`);
    assert.ok(r.text.includes(c.keep) && r.text.startsWith('before\n') && r.text.endsWith('\nafter kept'), `rest kept: ${c.name}`);
    assert.equal(redactSecrets(r.text).count, 0, `idempotent: ${c.name}`);
    assert.equal(strictCredentialSignal(r.text), false, `served, not withheld: ${c.name}`);
    const s = redactSecrets(c.text, { skip: STORAGE_SKIP });
    assert.ok(!survives(s.text), `storage view: ${c.name}`);
  }
});

test('fix2d: exact outputs of the new spans', () => {
  const r = (s: string) => redactSecrets(s).text;
  assert.equal(r(`redis://admin:${pw('a')}@${pw('b')}@cache.example.com/0`), 'redis://admin:[REDACTED:url_password]@cache.example.com/0');
  assert.equal(r(`redis://:${pw('a')}@h.example.com`), 'redis://:[REDACTED:url_password]@h.example.com');
  assert.equal(r(`x ${BEGIN('PGP')}\nVersion: 1\n\n${b64('a')}\n${END('PGP')} y`), 'x [REDACTED:private_key] y');
  assert.equal(r(`${BEGIN('EC')}\n\n${b64('a')}\n\n${b64('b')}`), '[REDACTED:private_key]', 'no END line: to the end of the text');
  assert.equal(r(`Bearer ${j('abcdefghij', 'klmnopqrst')}%${VW}x" kept`), 'Bearer [REDACTED:bearer]" kept');
  assert.equal(r(`k: |\n  ${pw('a')}\n\n  ${pw('b')}\n\nnext`), 'k: |\n  ' + pw('a') + '\n\n  ' + pw('b') + '\n\nnext', 'not a keyword: untouched');
  assert.equal(r(`token: |\n  ${pw('a')}\n\n  ${pw('b')}\n\nnext`), 'token: [REDACTED:keyword_value]\n\nnext');
  // A block header with no indented line below (a flattened heading): the line-end rule applies.
  assert.equal(r(`- client_secret: |+ # rotate ${pw('a')} ${pw('b')}`), '- client_secret: [REDACTED:keyword_value]');
});

test('fix2d: benign look-alikes stay unchanged', () => {
  const same = [
    'see https://host.example.com:8080/path and mail a@b.example.com',
    'https://user@host.example.com/x (no password)',
    'git@github.com:org/repo.git',
    'password: |', // an empty block: nothing to redact
    'password: |\nnext: line', // a block with no indented line
    'notes: |\n  plain text that is no secret',
    '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----',
    'the bearer of the news said hello',
    `${P.google}\u2026 is the prefix shape`,
  ];
  for (const s of same) assert.equal(redactSecrets(s).text, s, s.slice(0, 30));
  // A short password-less URL and a plain address are not withheld either.
  assert.equal(strictCredentialSignal('https://user@host.example.com/x and a@b.example.com'), false);
});

test('fix2d floor: the residue shapes the old spans left are withheld (defence in depth)', () => {
  const residue = [
    `redis://admin:[REDACTED:url_password]@${pw('b')}@cache.example.com`, // first-@ split (old url rule)
    `https://:[REDACTED:url_password]@${pw('b')}@h.example.com/x`,
    `[REDACTED:private_key]\n${b64('l1')}\n${END('PGP')}`, // stopped at the blank line (old PEM rule)
    `${b64('l1')}\n${END('RSA')}`, // an END line alone
    `Bearer [REDACTED:bearer]${VW}tail`, // a marker with a key character right after it
    `key [REDACTED:masked_google_api_key]${VW}9`,
  ];
  for (const s of residue) assert.equal(withholdFloor(s), true, s.slice(0, 40).replace(VW, '<W>'));
  const clean = [
    'redis://admin:[REDACTED:url_password]@cache.example.com/0',
    'redis://admin:[REDACTED:url_password]@cache.example.com:6379 next',
    '"amqp://u:[REDACTED:url_password]@mq.example.com"',
    '[REDACTED:private_key]\nkept',
    'Bearer [REDACTED:bearer] kept',
    'a [REDACTED:keyword_value] | b [REDACTED:jwt].',
  ];
  for (const s of clean) assert.equal(withholdFloor(s), false, s);
  // The legacy first-@ split is redacted whole on the next pass (rescrub), then clean.
  const fixed = redactSecrets(residue[0]!).text;
  assert.equal(fixed, 'redis://admin:[REDACTED:url_password]@cache.example.com');
  assert.equal(strictCredentialSignal(fixed), false);
});

test('fix2d: a list of values under a keyword-named field is redacted entry by entry', () => {
  const d = redactDeep({ api_key: [pw('a'), j(VW, ' two words'), 'short'], name: 'kept' });
  assert.ok(!survives(JSON.stringify(d.value)));
  assert.deepEqual(d.value, { api_key: ['[REDACTED:keyword_value]', '[REDACTED:keyword_value]', 'short'], name: 'kept' });
});

test('fix2d: linear time on adversarial runs for the new spans', () => {
  const n = 40_000;
  const inputs = [
    'a://u:' + '@'.repeat(n), // url: many @, no delimiter
    'a://u:x'.repeat(n / 7), // many schemes in one run
    j(P.google, '*').repeat(n / 5), // weak masks: every start rejected
    j(P.google, 'x\u2026').repeat(n / 6), // strong masks: one chain
    'Bearer ' + 'a'.repeat(n) + '%'.repeat(n),
    'password: |\n' + '  x\n'.repeat(n / 4),
    BEGIN('RSA').repeat(n / 30),
  ];
  for (const s of inputs) {
    const t0 = performance.now();
    redactSecrets(s);
    withholdFloor(s);
    assert.ok(performance.now() - t0 < 1500, `slow on ${s.slice(0, 12)}`);
  }
});

// ---------------------------------------------------------------------------
// Serve paths, through the real MCP server

let db: Db;
let home: string;
const RULES = batches(3500);

function asRole(role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-vspan-mcp-'));
  writeFileSync(join(home, '.pg_service.conf'), '[zeusi_ro]\nhost=ep-fake-1.example.invalid\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n');
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'manual:people/owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  // Legacy rows (stored before the detector): every case, raw.
  for (const [i, text] of RULES.entries()) {
    for (const kind of ['rule', 'state']) {
      const uri = `vault:Work/handbook/v${kind}-${i}.md`;
      await db.query(
        `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ($1, $2, $3, 'work', 'manual', $4, now(), sha256(convert_to($4, 'UTF8')), $5)`, [kind, `s${i}`, text, uri, run]);
    }
    await db.query(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner'), now() - interval '1 day', 'minute', $1, true, ARRAY['ocelot'], 'work', 'manual', $2, now(), decode($3, 'hex'), $4)`,
      [`ocelot go:\n${text}`, `hq:t-vocelot-${i}`, SHA, run]);
  }
});
after(async () => {
  await db.close();
  rmSync(home, { recursive: true, force: true });
});

async function mcp(over: Partial<McpDeps> = {}) {
  const deps: McpDeps = {
    env: { HOME: home }, home, readService: 'zeusi_ro', connectRead: asRole('zeusi_box_ro'), embeddings: () => null,
    feedbackPath: join(home, '.zeusi', 'fb.jsonl'), queryLedgerPath: join(home, '.zeusi', 'ledger.json'), ...over,
  };
  const server = createZeusiMcpServer(deps, createMcpState());
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'vspan-test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
    return { isError: r.isError === true, text: r.content.map((c) => c.text ?? '').join('\n') };
  };
  return { call, client, close: async () => { await client.close(); await server.close(); } };
}

/** Nothing served may carry a marker: the serve guard never redacts, and never serves stored redactions. */
const marked = (s: string) => s.includes('[REDACTED:');

test('serve (zeusi_search): every case in a hit (text or heading) or the notice WITHHOLDS the item; only the clean hit is served', async () => {
  const now = new Date().toISOString();
  const hits = CASES.flatMap((c, i) => [
    { chunkId: 3 * i + 1, sourceUri: `vault:v${i}.md#c0`, sourceTs: now, scope: 'work', headingPath: null, text: `${c.text}\nkept`, score: 1, ranks: {} },
    { chunkId: 3 * i + 2, sourceUri: `vault:v${i}.md#c1`, sourceTs: now, scope: 'work', headingPath: c.text.replace(/\n/g, ' '), text: 'kept', score: 1, ranks: {} },
  ]);
  hits.push({ chunkId: 0, sourceUri: 'vault:clean.md#c0', sourceTs: now, scope: 'work', headingPath: null, text: 'clean prose', score: 1, ranks: {} });
  const searchFn = async (): Promise<SearchResult> => ({ mode: 'lexical', notice: CASES[CASES.length - 1]!.text, hits });
  const h = await mcp({ searchFn });
  try {
    const r = await h.call('zeusi_search', { query: 'x', limit: 50 });
    assert.ok(!r.isError);
    assert.ok(!survives(r.text) && !marked(r.text), 'no value piece and no marker in the response');
    const out = JSON.parse(r.text) as { hits: Array<{ text: string }>; withheld: number; notice?: string };
    assert.deepEqual(out.hits.map((x) => x.text), ['clean prose']);
    assert.equal(out.withheld, 2 * CASES.length);
    assert.equal(out.notice, undefined);
  } finally {
    await h.close();
  }
});

test('serve (zeusi_startup, zeusi_context_for_task): rules, focus and decisions holding any case are withheld whole', async () => {
  const h = await mcp();
  try {
    const r = await h.call('startup', {});
    assert.ok(!r.isError, r.text);
    assert.ok(!survives(r.text) && !marked(r.text));
    const out = JSON.parse(r.text) as { rules: unknown[]; focus: unknown[]; decisions: unknown[]; withheld: number };
    assert.deepEqual([out.rules, out.focus, out.decisions], [[], [], []]);
    assert.ok(out.withheld >= RULES.length * 2);
    const c = await h.call('zeusi_context_for_task', { task: 'ocelot demo', limit: 50 });
    assert.ok(!c.isError, c.text);
    assert.ok(!survives(c.text) && !marked(c.text));
    const co = JSON.parse(c.text) as { items: unknown[]; withheld: number };
    assert.deepEqual(co.items, []);
    assert.equal(co.withheld, RULES.length);
  } finally {
    await h.close();
  }
});

test('serve (start-task prompt echo, error messages, guard units): every case is withheld, never echoed', async () => {
  const h = await mcp({ searchFn: async (o) => { throw new Error(`upstream rejected: ${o.query}`); } });
  try {
    for (const c of CASES) {
      const p = await h.client.getPrompt({ name: 'start-task', arguments: { task: `deploy with ${c.text}` } });
      const t = p.messages.map((m) => (m.content as { text?: string }).text ?? '').join('\n');
      assert.ok(!survives(t) && !marked(t) && !t.includes('Task: '), `start-task: ${c.name}`);
      const e = await h.call('zeusi_search', { query: c.text });
      assert.ok(e.isError);
      assert.equal(e.text, 'refused (details withheld by the wall)', `error message: ${c.name}`);
    }
  } finally {
    await h.close();
  }
  for (const c of CASES) {
    assert.deepEqual(guardString(c.text), { text: null, secretWithheld: 1 }, `guardString: ${c.name}`);
    assert.deepEqual(wallFilter([{ text: c.text, heading: 'about' }]).kept, [], `wallFilter: ${c.name}`);
    // What storage wrote for the case is not served either (the marker check).
    assert.deepEqual(guardString(redactSecrets(c.text, { skip: STORAGE_SKIP }).text).text, null, `stored form: ${c.name}`);
    assert.equal(safeMessage(c.text), 'refused (details withheld by the wall)', `safeMessage: ${c.name}`);
  }
});

// ---------------------------------------------------------------------------
// Storage paths: vault ingest, fact add, rescrub --real

test('storage (vault ingest): every case is stored with the whole span redacted', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-vspan-ingest-'));
  const root = join(dir, 'src');
  const d = await pgliteDb();
  try {
    await migrate(d);
    mkdirSync(join(root, 'Work/products'), { recursive: true });
    const write = (rel: string, text: string) => { writeFileSync(join(root, rel), text); utimesSync(join(root, rel), OLD, OLD); };
    for (const [i, text] of batches(20_000).entries()) write(`Work/products/v${i}.md`, `# Note ${i}\n\n${text}\nbody kept\n`);
    write('Work/products/fm.md', ['---', 'title: FM', `api_key: [${pw('a')}, ${pw('b')}]`, '---', '', '# FM', '', 'body kept'].join('\n'));
    const toml = `[[source]]\nname = "v"\nkind = "vault_note"\nscope = "work"\nroot = "${root}"\ninclude = ["Work/**/*.md"]\n`;
    const config = validateSources(parseToml(toml), seedWall(), { home: dir });
    await d.exec('SET ROLE zeusi_mini_ingest');
    const r = await importVault({ db: d, config, mode: 'full', home: dir, log: () => {} });
    await d.exec('RESET ROLE');
    assert.equal(r.status, 'ok', r.error ?? '');
    const rows = (await d.query<{ t: string }>(`SELECT title || ' ' || body || ' ' || frontmatter::text AS t FROM zeusi.notes
                                                 UNION ALL SELECT coalesce(heading_path, '') || ' ' || text FROM zeusi.chunks`)).rows.map((x) => x.t);
    const leaks = CASES.filter((c) => rows.some((t) => t.includes(c.text.slice(0, 20)) && survives(t))).map((c) => c.name);
    assert.deepEqual(leaks, []);
    const all = rows.join('\n');
    assert.ok(!survives(all), 'no stored note, frontmatter or chunk holds a value piece');
    assert.match(all, /body kept/);
    for (const c of CASES) assert.ok(all.includes(c.keep), `kept: ${c.name}`);
    assert.ok(markers(all) >= CASES.length);
  } finally {
    await d.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('storage (fact add, ingest role): every case is stored with the whole span redacted', async () => {
  const d = await pgliteDb();
  try {
    await migrate(d);
    for (const [i, text] of RULES.entries()) {
      await d.exec('SET ROLE zeusi_mini_ingest');
      const r = await insertFact(d, {
        kind: 'other', subject: `s${i}`, text, scope: 'work', sourceKind: 'manual',
        sourceUri: `manual:vspan-${i}`, sourceTs: '2026-11-17T09:00:00Z', sourceSha256: SHA,
      });
      await d.exec('RESET ROLE');
      assert.equal(r.status, 'inserted');
    }
    const all = (await d.query<{ t: string }>(`SELECT text AS t FROM zeusi.facts`)).rows.map((x) => x.t).join('\n');
    assert.ok(!survives(all));
    assert.ok(markers(all) >= CASES.length);
  } finally {
    await d.close();
  }
});

test('storage (rescrub --real on PGlite): raw rows AND the legacy first-@ url split are rewritten whole; idempotent', async () => {
  const d = await pgliteDb();
  try {
    await migrate(d);
    const run = (await d.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    // What the previous head stored for a p1@p2@host URL: only p1 redacted.
    const legacyUrl = CASES.filter((c) => c.kind === 'url_password').map((c) => c.text.replace(new RegExp(`${VW}a9k`), '[REDACTED:url_password]')).join('\n');
    assert.ok(survives(legacyUrl) && legacyUrl.includes('[REDACTED:url_password]@'));
    const bodies = [...batches(20_000), legacyUrl];
    for (const [i, body] of bodies.entries()) {
      const nid = (await d.query<{ id: number }>(
        `INSERT INTO zeusi.notes (vault_path, title, body, frontmatter, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ($1, 'N', $2, $3::jsonb, now(), 'work', 'vault_note', $4, now(), decode($5, 'hex'), $6) RETURNING id::int AS id`,
        [`Work/v${i}.md`, body, JSON.stringify({ api_key: [pw('a'), pw('b')] }), `vault:Work/v${i}.md`, SHA, run])).rows[0]!.id;
      await d.query(
        `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
         VALUES ($1, 0, 'H', $2, sha256(convert_to($2, 'UTF8')), 5, $3)`, [nid, body, `vault:Work/v${i}.md#c0`]);
    }
    await d.exec('SET ROLE zeusi_mini_ingest');
    const r = await runRescrub({ db: d, real: true, host: 'test' });
    await d.exec('RESET ROLE');
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.notes_rewritten, bodies.length);
    assert.equal(r.counts.chunks_rewritten, bodies.length);
    const all = (await d.query<{ t: string }>(`SELECT body || ' ' || frontmatter::text AS t FROM zeusi.notes UNION ALL SELECT text FROM zeusi.chunks`)).rows.map((x) => x.t).join('\n');
    assert.ok(!survives(all), 'no value piece left in notes, frontmatter or chunks');
    const texts = (await d.query<{ t: string }>(`SELECT body AS t FROM zeusi.notes UNION ALL SELECT text FROM zeusi.chunks`)).rows.map((x) => x.t);
    for (const t of texts) assert.equal(strictCredentialSignal(t), false, 'served as is, not withheld');
    await d.exec('SET ROLE zeusi_mini_ingest');
    const again = await runRescrub({ db: d, real: true, host: 'test' });
    await d.exec('RESET ROLE');
    assert.deepEqual({ n: again.counts.matched.notes, c: again.counts.matched.chunks }, { n: 0, c: 0 }, 'idempotent');
  } finally {
    await d.close();
  }
});
