// Review r2 P1-1 / P2-1 (fix round 2): ONE keyword definition (src/secrets.ts KEYWORD_HEAD) and
// the WHOLE value span of a keyword = value / keyword: value is redacted, so no word of a
// multi-word value is served or stored. Table-driven: every keyword form x quoting style x
// single / multi-word value, through every serve path (search hits + notice, startup rules /
// focus / decisions, context_for_task, start-task echo, the about guard, error messages) and
// every storage path (vault ingest, fact add, rescrub --real on PGlite).
//
// All values are synthetic, assembled at runtime; every value word carries the marker VW, so
// "no value word survives" is one substring check. Nothing here is or resembles a real key.
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
import { HQ_PROFILE, importVault } from '../src/importers/vault.ts';
import { insertFact } from '../src/facts.ts';
import { runExportFilter } from '../src/hq-export.ts';
import type { SearchResult } from '../src/search.ts';
import { createMcpState, createZeusiMcpServer, STARTUP_CAPS, type McpDeps } from '../src/mcp-server.ts';
import { guardString, safeMessage, wallFilter } from '../src/mcp-wall.ts';
import { runRescrub } from '../src/rescrub.ts';
import { credentialSignal, redactDeep, redactSecrets, STORAGE_SKIP, strictCredentialSignal, withholdFloor } from '../src/secrets.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { hqNote } from './hq-fixtures.ts';
import { j } from './secret-fixtures.ts';
import { KEYWORDS, KEYWORD_CASES as CASES, MARK, MULTI, SINGLE, STYLES, survives, VALUES, VW } from './secret-shapes.ts';

const SHA = 'ef'.repeat(32);
const OLD = new Date('2026-01-05T10:00:00Z');

/** Lines grouped into texts of at most `max` characters (facts.text is capped at 4000). */
function batches(max: number): string[] {
  const out: string[] = [];
  let cur = '';
  for (const c of CASES) {
    const add = `L ${c.line}\nnext line kept\n`;
    if (cur.length + add.length > max) { out.push(cur); cur = ''; }
    cur += add;
  }
  if (cur) out.push(cur);
  return out;
}

// ---------------------------------------------------------------------------
// Detector: every case, unit level

test('r2 P1-1: every keyword form x style x single/multi-word value: the whole value is redacted, nothing else, idempotent', () => {
  assert.ok(CASES.length >= KEYWORDS.length * VALUES.length * STYLES.length);
  for (const c of CASES) {
    const text = `before\n${c.line}\nafter kept`;
    const r = redactSecrets(text);
    assert.ok(!survives(r.text), `${c.name}: no value word survives`);
    assert.equal(r.byKind.keyword_value, 1, `${c.name}: one keyword_value`);
    assert.ok(r.text.includes(MARK), c.name);
    assert.ok(r.text.startsWith('before\n') && r.text.endsWith('\nafter kept'), `${c.name}: other lines kept`);
    if (c.keep) assert.ok(r.text.includes(c.keep), `${c.name}: text after the value span kept`);
    assert.equal(credentialSignal(r.text), false, c.name);
    assert.equal(strictCredentialSignal(r.text), false, `${c.name}: the served copy is not withheld`);
    assert.equal(redactSecrets(r.text).count, 0, `${c.name}: idempotent`);
    // Storage options (STORAGE_SKIP) redact the same span.
    assert.equal(redactSecrets(text, { skip: STORAGE_SKIP }).text, r.text, c.name);
  }
});

test('fix round 2: value span rule, exact outputs (value start to the line end, quoted or not; a table row: to the cell bar)', () => {
  const k = j('DB_PASS', 'WORD');
  const m = MULTI;
  const cases: Array<[string, string]> = [
    [`${k}: ${m}`, `${k}: ${MARK}`],
    [`${k}: ${m}  `, `${k}: ${MARK}  `],
    [`${k}="${m}" then prose`, `${k}=${MARK}`],
    [`${k}='${m}'; next=1`, `${k}=${MARK}`],
    [`${k}: "${m}`, `${k}: ${MARK}`],
    [`${k} := ${m}`, `${k} := ${MARK}`],
    [`'${k}' => '${m}',`, `'${k}' => ${MARK}`],
    [`${k}: "[REDACTED:keyword_value]"`, `${k}: ${MARK}`], // a quoted marker (older heads) is normalised
    [`${k}=${m}; next=1`, `${k}=${MARK}`], // unquoted: to the line end, a following setting included
    [`${k}=${m}, next=1`, `${k}=${MARK}`],
    [`${k}=a,b;c${m}`, `${k}=${MARK}`], // , / ; without a space after them are inside the value
    [`| ${k}: ${m} | x |`, `| ${k}: ${MARK} | x |`],
    [`${k}: ${m}\nnext: line`, `${k}: ${MARK}\nnext: line`],
    [`${k}:\n  ${m}\nnext`, `${k}:\n  ${MARK}\nnext`],
  ];
  for (const [i, [input, want]] of cases.entries()) assert.equal(redactSecrets(input).text, want, `case ${i}`);
});

test('r2 P2-1: a legacy first-word-only row (`kw: [REDACTED:keyword_value] w2 w3`) is redacted whole on the next pass; the floor withholds it meanwhile', () => {
  for (const k of KEYWORDS) {
    const legacy = `${k}: ${MARK} ${j(VW, 'b')} ${j(VW, 'charlie')}`;
    // Defence in depth: the ONE keyword definition in the withhold floor too (review r2: the
    // old floor had its own keyword list and missed compound forms and `token`).
    assert.equal(withholdFloor(legacy), true, `the floor on its own withholds legacy residue (keyword #${KEYWORDS.indexOf(k)})`);
    assert.equal(strictCredentialSignal(legacy), true);
    // The floor's keyword rule (whole-value placeholders, which redaction keeps) uses the same definition.
    assert.equal(withholdFloor(`${k}: ${j('$', '{SOME_VAR}')}`), true, `floor keyword rule (keyword #${KEYWORDS.indexOf(k)})`);
    assert.equal(withholdFloor(`${k}: ${MARK}`), false, 'a fully redacted value is not withheld');
    const r = redactSecrets(legacy);
    assert.equal(r.text, `${k}: ${MARK}`, `rescrub cleans it (keyword #${KEYWORDS.indexOf(k)})`);
    assert.equal(strictCredentialSignal(r.text), false);
    // At the serve layer, a guard that left residue (e.g. redaction truncated to the first word) is caught by the floor.
    assert.equal(wallFilter([{ text: legacy }]).withheld, 1, `withheld, not served half-redacted (keyword #${KEYWORDS.indexOf(k)})`); // stored residue is never served
  }
});

test('self-review r2: `|` / escaped quote / `, ` / `; ` inside a value: exact outputs, and the floor withholds the legacy split shapes', () => {
  const a = j(VW, 'Aa9', 'bb');
  const b = j(VW, 'Cc8', 'dd');
  for (const k of KEYWORDS) {
    const id = `keyword #${KEYWORDS.indexOf(k)}`;
    const cases: Array<[string, string]> = [
      [`${k}: ${a}|${b}`, `${k}: ${MARK}`],
      [`| svc | ${k}: ${a}|${b} | x |`, `| svc | ${k}: ${MARK} | x |`],
      [`{"${k}": "${a}\\"${b}"}`, `{"${k}": ${MARK}`],
      [`${k}='${a}\\'${b}' z`, `${k}=${MARK}`],
      // Self-review fix2c: quoting that continues after a closing quote.
      [`${k}: '${a}''${b}'`, `${k}: ${MARK}`],
      [`${k}: "${a}""${b}"`, `${k}: ${MARK}`],
      [`${k}=\`${a}\`\`${b}\``, `${k}=${MARK}`],
      [`export ${k}='${a}'"'"'${b}'`, `export ${k}=${MARK}`],
      [`${k} = "${a}" + "${b}"`, `${k} = ${MARK}`],
      [`${k}: "${a}" # ${b}`, `${k}: ${MARK}`],
      [`${k}=${a}, ${b}`, `${k}=${MARK}`],
      [`${k}: ${a}; ${b}`, `${k}: ${MARK}`],
      [`${k}=${a}, user=bob`, `${k}=${MARK}`], // review r2b: never end the value at a following setting
      [`${k}: ${a};Name=Root;Key=${b}`, `${k}: ${MARK}`],
      [`${k}: ${a}; "next": 1`, `${k}: ${MARK}`],
    ];
    for (const [i, [input, want]] of cases.entries()) {
      const r = redactSecrets(input);
      assert.equal(r.text, want, `${id} case ${i}`);
      assert.equal(strictCredentialSignal(r.text), false, `${id} case ${i}: served, not withheld`);
      assert.equal(redactSecrets(input, { skip: STORAGE_SKIP }).text, want, `${id} case ${i}: stored the same`);
    }
    // What the previous head stored / served for those shapes (the span ended inside the value):
    // the floor ON ITS OWN withholds each, and the detector re-redacts it whole (rescrub).
    const legacy: Array<[string, string]> = [
      [`${k}: ${MARK}|${b}`, `${k}: ${MARK}`],
      [`| svc | ${k}: ${MARK}|${b} | x |`, `| svc | ${k}: ${MARK} | x |`],
      [`{"${k}": "${MARK}"${b}"}`, `{"${k}": ${MARK}`],
      // What head 049b0af served for the fix2c shapes (the span ended at the first closing quote).
      [`${k}: '${MARK}''${b}'`, `${k}: ${MARK}`],
      [`${k}: "${MARK}""${b}"`, `${k}: ${MARK}`],
      [`export ${k}='${MARK}'"'"'${b}'`, `export ${k}=${MARK}`],
      [`${k} = "${MARK}" + "${b}"`, `${k} = ${MARK}`],
      [`{"${k}": "${MARK}", "user": "${b}"}`, `{"${k}": ${MARK}`],
      [`${k}=${MARK}, ${b}`, `${k}=${MARK}`],
      [`${k}: ${MARK}; ${b}`, `${k}: ${MARK}`],
      [`${k}: ${MARK};Name=Root;Key=${b}`, `${k}: ${MARK}`],
      [`${k}=${MARK}, user=${b}`, `${k}=${MARK}`],
    ];
    for (const [i, [row, cleaned]] of legacy.entries()) {
      assert.equal(withholdFloor(row), true, `${id} legacy ${i}: the floor withholds it`);
      assert.equal(wallFilter([{ text: row }]).withheld, 1, `${id} legacy ${i}: a span that ends early is withheld at serve`); // stored residue is never served
      if (cleaned) assert.equal(redactSecrets(row).text, cleaned, `${id} legacy ${i}: rescrub cleans it`);
      assert.ok(!survives(redactSecrets(row).text) || withholdFloor(redactSecrets(row).text), `${id} legacy ${i}: never served`);
    }
    // Not withheld: a marker with only whitespace after it (non-table line), or before the cell bar (table row).
    for (const ok of [`{"${k}": ${MARK}`, `${k}=${MARK}  `, `| ${k}: ${MARK} | x |`, `| ${k}: ${MARK}\t| x, "y" |`, `${k}: ${MARK}\r\nnext "line"`]) {
      assert.equal(withholdFloor(ok), false, `${id}: clean shape not withheld`);
    }
  }
});

test('fix round 2 finish: ` |` ends an unquoted value only on a table row; elsewhere the value runs to the line end (every keyword form)', () => {
  const a = j(VW, 'Aa9', 'bb');
  const b = j(VW, 'Cc8', 'dd');
  for (const k of KEYWORDS) {
    const id = `keyword #${KEYWORDS.indexOf(k)}`;
    // Table rows: the secret cell is redacted whole, every other cell stays readable.
    const table: Array<[string, string]> = [
      [`| ${k}: ${a} | keep |`, `| ${k}: ${MARK} | keep |`],
      [`| ${k}: ${a} ${b} | keep | more |`, `| ${k}: ${MARK} | keep | more |`],
      [`  | svc | ${k}=${a}|${b} | keep |`, `  | svc | ${k}=${MARK} | keep |`],
      [`\t| ${k}: ${a} |`, `\t| ${k}: ${MARK} |`],
      [`| ${k}: ${a} | keep | ${k}: ${b} | tail |`, `| ${k}: ${MARK} | keep | ${k}: ${MARK} | tail |`],
      [`| ${k}: | keep this cell |`, `| ${k}: | keep this cell |`], // an empty secret cell: the next cell is not its value
      [`x\n| ${k}: ${a} | keep |\ny`, `x\n| ${k}: ${MARK} | keep |\ny`],
    ];
    // Not a table row (no leading `|`): nothing after the keyword on that line is served or stored.
    const plain: Array<[string, string]> = [
      [`${k}: ${a} |${b}`, `${k}: ${MARK}`],
      [`${k}: ${a} | ${b}`, `${k}: ${MARK}`],
      [`${k}=${a} | ${b} | ${b} |`, `${k}=${MARK}`],
      [`${k} = ${a}\t|${b}  `, `${k} = ${MARK}  `],
      [`${k}: | ${b} ${b}`, `${k}: ${MARK}`],
      [`L | ${k}: ${a} | ${b} |`, `L | ${k}: ${MARK}`],
      [`> | ${k}: ${a} | ${b} |`, `> | ${k}: ${MARK}`],
      [`| x |\n${k}: ${a} |${b}\n| y |`, `| x |\n${k}: ${MARK}\n| y |`],
      [`${k}: ${a} |${b}\r\nnext`, `${k}: ${MARK}\r\nnext`],
    ];
    for (const [i, [input, want]] of [...table, ...plain].entries()) {
      for (const [path, out] of [['serve', redactSecrets(input).text], ['storage', redactSecrets(input, { skip: STORAGE_SKIP }).text]] as const) {
        assert.equal(out, want, `${id} case ${i} (${path})`);
        assert.ok(!survives(out), `${id} case ${i} (${path}): no value fragment`);
        assert.equal(strictCredentialSignal(out), false, `${id} case ${i} (${path}): served, not withheld`);
        assert.equal(redactSecrets(out).count, 0, `${id} case ${i}: idempotent`);
      }
    }
    // What the previous head served / stored for a non-table line (the span ended at ` |`):
    // the floor ON ITS OWN withholds it, at serve too, and the detector re-redacts it whole.
    const residue = [
      `${k}: ${MARK} |${b}`, `${k}: ${MARK} | ${b}`, `${k}=${MARK} , ${b}`, `${k}: ${MARK} ;${b}`, `${k}: ${MARK}\t| ${b}`,
      `L | ${k}: ${MARK} | ${b} |`, `"${k}": ${MARK} | ${b}`, `ok\n${k}: ${MARK} |${b}\nok`,
    ];
    for (const [i, row] of residue.entries()) {
      assert.equal(withholdFloor(row), true, `${id} residue ${i}: the floor withholds it`);
      assert.equal(wallFilter([{ text: row }]).withheld, 1, `${id} residue ${i}: withheld at serve`); // stored residue is never served
      assert.ok(!survives(redactSecrets(row).text), `${id} residue ${i}: rescrub cleans it`);
    }
    // Not withheld: table rows with a redacted secret cell, quoted values, a value alone.
    for (const ok of [`| ${k}: ${MARK} | keep |`, `  | svc | ${k}=${MARK} | keep, more; x |`, `{"${k}": ${MARK}`, `${k}: ${MARK}`, `${k}: ${MARK} `]) {
      assert.equal(withholdFloor(ok), false, `${id}: clean shape not withheld`);
    }
  }
});

test('r2 P1-1: keyword-named object fields (parsed frontmatter / JSON): the whole value is redacted', () => {
  const fm = { title: 'T', [j('db_pass', 'word')]: MULTI, nested: { [j('GEMINI_API', '_KEY')]: SINGLE, token_count: 512 }, list: [{ [j('tok', 'en')]: MULTI }], note: 'clean' };
  const r = redactDeep(fm);
  assert.ok(!survives(JSON.stringify(r.value)));
  assert.equal(r.byKind.keyword_value, 3);
  assert.equal((r.value as { title: string }).title, 'T');
  assert.equal((r.value as { nested: { token_count: number } }).nested.token_count, 512, 'not a keyword field');
  // Placeholders in a keyword field are kept (not a value).
  assert.deepEqual(redactDeep({ password: '${DB_PW}', token: '<your-token>', api_key: 'abc' }).count, 0);
});

test('r2 P1-1: benign look-alikes stay unchanged (prose without an assignment, longer words, placeholders)', () => {
  const benign = [
    'the token was revoked yesterday and rotated',
    'rotate the password every quarter, then tell the team',
    'tokenizer: whitespace splitter for the chunker',
    'passwords: see the team vault entry',
    'token count: 512 per chunk',
    'password reset flow: done and shipped',
    'the secret sauce is the citation format',
    'secretary: Anna will book the room',
    'Token: 3 left',
    'api_key: <your-key-here>',
    'password: ${DB_PW}',
    'token = process.env.ZEUSI_TOKEN',
    'secret: ********',
    'DB_PASSWORD: xxxxxxxx',
    'password: [REDACTED:keyword_value]',
  ];
  for (const s of benign) {
    assert.equal(redactSecrets(s).text, s, `unchanged (length ${s.length})`);
    assert.equal(credentialSignal(s), false, `no signal (length ${s.length})`);
  }
});

test('r2 P1-1: linear time on long keyword-heavy lines (whole-span rule)', () => {
  const units = ['token: a ', 'password=a, ', 'token="', 'token: $A, ', 'TOKEN=', 'token:\n', "token: 'a", 'a_token= x|', `${MARK} `, 'token: a|', 'token: a, ', 'token="a\\"', 'token: x, y=', 'token: a;B=c', `token: ${MARK};B=c `, `token: ${MARK}|a `, `token: ${MARK}, a `, 'token: a ' + ' '.repeat(64), j('kw: ', MARK, ' a '), '| token: a ', 'token: a |b ', `token: ${MARK} |a `, `| token: ${MARK} | a `, 'token: |\n|', `token: ${MARK} |\n`];
  const time = (n: number) => {
    let worst = 0;
    for (const u of units) {
      const s = u.repeat(Math.ceil(n / u.length));
      const t = performance.now();
      redactSecrets(s);
      strictCredentialSignal(s);
      worst = Math.max(worst, performance.now() - t);
    }
    return worst;
  };
  time(20_000);
  const small = time(50_000);
  const big = time(400_000);
  assert.ok(big < 3000, `400 KB worst ${Math.round(big)} ms`);
  assert.ok(big < Math.max(50, small) * 40, `linear (50 KB ${Math.round(small)} ms, 400 KB ${Math.round(big)} ms)`);
});

// ---------------------------------------------------------------------------
// Serve paths, through the real MCP server

let db: Db;
let home: string;

function asRole(role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

const RULES = batches(3500);

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-kwspan-mcp-'));
  writeFileSync(join(home, '.pg_service.conf'), '[zeusi_ro]\nhost=ep-fake-1.example.invalid\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n');
  db = await pgliteDb();
  await migrate(db);
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'manual:people/owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  // Legacy rows (stored before the detector): every case, raw.
  for (const [i, text] of RULES.entries()) {
    for (const kind of ['rule', 'state']) {
      const uri = `vault:Work/handbook/${kind}-${i}.md`;
      await db.query(
        `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ($1, $2, $3, 'work', 'manual', $4, now(), sha256(convert_to($4, 'UTF8')), $5)`, [kind, `s${i}`, text, uri, run]);
    }
    await db.query(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner'), now() - interval '1 day', 'minute', $1, true, ARRAY['ocelot'], 'work', 'manual', $2, now(), decode($3, 'hex'), $4)`,
      [`ocelot go:\n${text}`, `hq:t-ocelot-${i}`, SHA, run]);
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
  const client = new Client({ name: 'kwspan-test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
    return { isError: r.isError === true, text: r.content.map((c) => c.text ?? '').join('\n') };
  };
  return { call, client, close: async () => { await client.close(); await server.close(); } };
}

const markers = (s: string) => s.split(MARK).length - 1;

/** Nothing served may carry a marker: the serve guard never redacts, and never serves stored redactions. */
const marked = (s: string) => s.includes('[REDACTED:');

test('serve (zeusi_search): every case in a hit (text or heading) or the notice WITHHOLDS the item; only the clean hit is served', async () => {
  const now = new Date().toISOString();
  const hits = CASES.flatMap((c, i) => [
    { chunkId: 3 * i + 1, sourceUri: `vault:k${i}.md#c0`, sourceTs: now, scope: 'work', headingPath: null, text: `${c.line}\nkept`, score: 1, ranks: {} },
    { chunkId: 3 * i + 2, sourceUri: `vault:k${i}.md#c1`, sourceTs: now, scope: 'work', headingPath: c.line.replace(/\n/g, ' '), text: 'kept', score: 1, ranks: {} },
  ]);
  hits.push({ chunkId: 0, sourceUri: 'vault:clean.md#c0', sourceTs: now, scope: 'work', headingPath: null, text: 'clean prose', score: 1, ranks: {} });
  const searchFn = async (): Promise<SearchResult> => ({ mode: 'lexical', notice: CASES[CASES.length - 1]!.line, hits });
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
      const p = await h.client.getPrompt({ name: 'start-task', arguments: { task: `deploy with ${c.line}` } });
      const t = p.messages.map((m) => (m.content as { text?: string }).text ?? '').join('\n');
      assert.ok(!survives(t) && !marked(t) && !t.includes('Task: '), `start-task: ${c.name}`);
      const e = await h.call('zeusi_search', { query: c.line });
      assert.ok(e.isError);
      assert.equal(e.text, 'refused (details withheld by the wall)', `error message: ${c.name}`);
    }
  } finally {
    await h.close();
  }
  for (const c of CASES) {
    assert.deepEqual(guardString(c.line), { text: null, secretWithheld: 1 }, `guardString: ${c.name}`);
    assert.deepEqual(wallFilter([{ text: c.line, heading: 'about' }]).kept, [], `wallFilter: ${c.name}`);
    // What storage wrote for the case is not served either (the marker check).
    assert.deepEqual(guardString(redactSecrets(c.line, { skip: STORAGE_SKIP }).text).text, null, `stored form: ${c.name}`);
    assert.equal(safeMessage(c.line), 'refused (details withheld by the wall)', `safeMessage: ${c.name}`);
  }
});

// ---------------------------------------------------------------------------
// Storage paths: ingest (vault + hq), fact add, rescrub --real, and the export filter

test('storage (vault + hq ingest): every case in body and frontmatter is stored with the whole value redacted', async () => {
  const dir = safeMkdtemp(join(tmpdir(), 'zeusi-kwspan-ingest-'));
  const root = join(dir, 'src');
  const d = await pgliteDb();
  try {
    await migrate(d);
    mkdirSync(join(root, 'Work/products'), { recursive: true });
    mkdirSync(join(root, 'hq'), { recursive: true });
    const write = (rel: string, text: string) => { writeFileSync(join(root, rel), text); utimesSync(join(root, rel), OLD, OLD); };
    for (const [i, text] of batches(20_000).entries()) write(`Work/products/n${i}.md`, `# Note ${i}\n\n${text}`);
    // Frontmatter fields named like a credential (one per keyword, multi-word value; one as a YAML block scalar).
    write('Work/products/fm.md', ['---', 'title: FM', ...KEYWORDS.map((k) => `${k}: ${MULTI}`), `bot_token: |`, `  ${MULTI}`, '---', '', '# FM', '', 'body kept'].join('\n'));
    write('hq/2026-11-13-keys.md', hqNote({ project: 'hq' }, CASES.slice(0, 60).map((c, i) => [`t${i}`, c.line.replace(/\n/g, ' ')])));
    const toml = `[[source]]\nname = "v"\nkind = "vault_note"\nscope = "work"\nroot = "${root}"\ninclude = ["Work/**/*.md"]\n`;
    const config = validateSources(parseToml(toml), seedWall(), { home: dir });
    const hqToml = `[[source]]\nname = "hq-general"\nkind = "zeus_memory"\nscope = "work"\nroot = "${root}"\ninclude = ["hq/*.md"]\nproject = "hq"\n`;
    const hqConfig = validateSources(parseToml(hqToml), seedWall(), { home: dir });
    await d.exec('SET ROLE zeusi_mini_ingest');
    const r = await importVault({ db: d, config, mode: 'full', home: dir, log: () => {} });
    const rh = await importVault({ db: d, config: hqConfig, mode: 'full', home: dir, log: () => {}, profile: HQ_PROFILE });
    await d.exec('RESET ROLE');
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(rh.status, 'ok', rh.error ?? '');
    assert.equal(rh.counts.inserted, 1, 'the HQ entry file is ingested (redacted)');
    const all = (await d.query<{ t: string }>(`SELECT title || ' ' || body || ' ' || frontmatter::text AS t FROM zeusi.notes
                                                UNION ALL SELECT coalesce(heading_path, '') || ' ' || text FROM zeusi.chunks`)).rows.map((x) => x.t).join('\n');
    const leakRows = (await d.query<{ src: string; t: string }>(`SELECT 'title' AS src, title AS t FROM zeusi.notes UNION ALL SELECT 'body', body FROM zeusi.notes
      UNION ALL SELECT 'fm', frontmatter::text FROM zeusi.notes UNION ALL SELECT 'chunk', text FROM zeusi.chunks UNION ALL SELECT 'heading', coalesce(heading_path, '') FROM zeusi.chunks`)).rows
      .filter((x) => survives(x.t)).map((x) => `${x.src}:${x.t.split('\n').filter(survives).map((l) => CASES.findIndex((c) => c.line.split('\n').some((cl) => l.includes(cl.slice(0, 12))))).join(',')}`);
    assert.deepEqual(leakRows, [], 'no stored note, frontmatter or chunk holds a value word');
    assert.match(all, /body kept/);
    assert.ok(markers(all) >= CASES.length);
    // The nightly export filter withholds every such HQ entry (raw text, the same signal).
    const out = join(dir, 'out');
    const e = runExportFilter({ inDir: root, outDir: out, projects: ['hq'] });
    assert.equal(e.status, 'ok', e.error ?? '');
    assert.equal(e.counts.withheld_by_signal.credential, 60);
  } finally {
    await d.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('storage (fact add, ingest role): every case is stored with the whole value redacted', async () => {
  const d = await pgliteDb();
  try {
    await migrate(d);
    for (const [i, text] of RULES.entries()) {
      await d.exec('SET ROLE zeusi_mini_ingest');
      const r = await insertFact(d, {
        kind: 'other', subject: `s${i}`, text, scope: 'work', sourceKind: 'manual',
        sourceUri: `manual:kwspan-${i}`, sourceTs: '2026-11-17T09:00:00Z', sourceSha256: SHA,
      });
      await d.exec('RESET ROLE');
      assert.equal(r.status, 'inserted');
    }
    const all = (await d.query<{ t: string }>(`SELECT text AS t FROM zeusi.facts`)).rows.map((x) => x.t).join('\n');
    assert.ok(!survives(all));
    assert.equal(markers(all), CASES.length);
  } finally {
    await d.close();
  }
});

test('storage (rescrub --real on PGlite): raw AND legacy first-word-only rows are rewritten whole; idempotent', async () => {
  const d = await pgliteDb();
  try {
    await migrate(d);
    const run = (await d.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    const legacy = (s: string) => s.replace(new RegExp(`${VW}alpha7`, 'g'), MARK); // what the r2 head stored: first word only
    const bodies = [...batches(20_000), ...batches(20_000).map(legacy)];
    for (const [i, body] of bodies.entries()) {
      const nid = (await d.query<{ id: number }>(
        `INSERT INTO zeusi.notes (vault_path, title, body, frontmatter, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ($1, 'N', $2, $3::jsonb, now(), 'work', 'vault_note', $4, now(), decode($5, 'hex'), $6) RETURNING id::int AS id`,
        [`Work/n${i}.md`, body, JSON.stringify({ [j('db_pass', 'word')]: MULTI }), `vault:Work/n${i}.md`, SHA, run])).rows[0]!.id;
      await d.query(
        `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
         VALUES ($1, 0, 'H', $2, sha256(convert_to($2, 'UTF8')), 5, $3)`, [nid, body, `vault:Work/n${i}.md#c0`]);
    }
    await d.exec('SET ROLE zeusi_mini_ingest');
    const r = await runRescrub({ db: d, real: true, host: 'test' });
    await d.exec('RESET ROLE');
    assert.equal(r.status, 'ok', r.error ?? '');
    assert.equal(r.counts.notes_rewritten, bodies.length);
    assert.equal(r.counts.chunks_rewritten, bodies.length);
    const all = (await d.query<{ t: string }>(`SELECT body || ' ' || frontmatter::text AS t FROM zeusi.notes UNION ALL SELECT text FROM zeusi.chunks`)).rows.map((x) => x.t).join('\n');
    assert.ok(!survives(all), 'no value word left in notes, frontmatter or chunks');
    // Served text (bodies, chunks) is clean for the withhold check too. (frontmatter is jsonb and
    // never served as text; its redacted field values are bare markers, checked per value.)
    const texts = (await d.query<{ t: string }>(`SELECT body AS t FROM zeusi.notes UNION ALL SELECT text FROM zeusi.chunks`)).rows.map((x) => x.t);
    for (const t of texts) assert.equal(strictCredentialSignal(t), false);
    const fms = (await d.query<{ f: Record<string, string> }>(`SELECT frontmatter AS f FROM zeusi.notes`)).rows;
    for (const f of fms) for (const v of Object.values(f.f)) assert.equal(strictCredentialSignal(v), false);
    await d.exec('SET ROLE zeusi_mini_ingest');
    const again = await runRescrub({ db: d, real: true, host: 'test' });
    await d.exec('RESET ROLE');
    assert.deepEqual({ n: again.counts.matched.notes, c: again.counts.matched.chunks }, { n: 0, c: 0 }, 'idempotent');
  } finally {
    await d.close();
  }
});
