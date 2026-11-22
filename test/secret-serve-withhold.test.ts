// PR #23 final design: serve time WITHHOLDS, it never redacts. Property-style over every shape
// table (keyword forms x styles, delimiter-bounded values, keys and bearer tokens wrapped over
// several lines, stored residue, one sample per origin/main credential pattern), in raw form,
// in stored (ingest / rescrub) form, and inside generated contexts:
//
//   P1  every serve path returns an item with NO detector hit, NO main-pattern hit, NO
//       `[REDACTED:` marker and no value piece, or withholds it (and counts it);
//   P2  serve strictness >= origin/main: anything main's credentialSignal flags is withheld;
//   P3  code-constant text (zeusi://about, server instructions, the start-task prompt) passes
//       the detector and the main patterns;
//   mutants: drop the marker check, drop the main floor (with the detector disabled, so the
//   floor is what carries P2), drop the guard: each breaks P1 or P2.
//
// All values are synthetic, assembled at runtime. Nothing here is or resembles a real key.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import type { DecisionHit, SearchResult } from '../src/search.ts';
import { aboutMarkdown, aboutSections } from '../src/about.ts';
import { createMcpState, createZeusiMcpServer, mcpInstructions, type McpDeps, type ToolObservation } from '../src/mcp-server.ts';
import { onboardingText, startTaskText } from '../src/mcp-prompts.ts';
import { CANNOT_RUN_IT, ONBOARDING_COMMANDS } from '../src/onboarding.ts';
import { guardString, safeMessage, serveSecretSignal, wallFilter, type ServeCheck } from '../src/mcp-wall.ts';
import { MAIN_CREDENTIAL_PATTERNS, mainCredentialSignal } from '../src/secrets-main-floor.ts';
import { redactSecrets, STORAGE_SKIP, strictCredentialSignal } from '../src/secrets.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { j, P } from './secret-fixtures.ts';
import { KEYWORD_CASES, RESIDUE_CASES, survives, VALUE_CASES, VW, WRAPPED_CASES } from './secret-shapes.ts';

const SHA = '9a'.repeat(32);
const MARKER = '[REDACTED:';

/** One synthetic sample per origin/main credential pattern (in pattern order), each with VW in its value. */
const MAIN_SAMPLES: string[] = [
  j('-----BEGIN ', 'RSA PRIVATE KEY', '-----\n', VW, 'AbCd0123'),
  j('id ', P.akia, 'Q7', VW.toUpperCase(), 'ABCDEFGHIJ'),
  j(P.ghp, VW, 'a1'.repeat(14)),
  j(P.ghPat, VW, 'B2'.repeat(10)),
  j(P.openai, VW, 'c3'.repeat(10)),
  j(P.slack, VW, '4d4d4d'),
  j(P.neon, VW, 'e5'.repeat(6)),
  j('ey', 'J', VW, 'f6f6f6', '.ey', 'J', VW, 'g7g7g7', '.', VW, 'h8h8h8'),
  j('amqp://svc:', VW, 'i9i9@mq.example.com'),
  j('client-', 'secret=', VW, 'j0j0'),
  j('Authorization: ', 'Bearer ', VW, 'k1'.repeat(10)),
  j('your 2fa code ', '481', '516', ' (', VW, ')'),
  j('the code is ', '730', '194', ' ', VW),
];

/** Every shape, raw. */
const RAW: string[] = [
  ...KEYWORD_CASES.map((c) => c.line),
  ...VALUE_CASES.map((c) => c.text),
  ...WRAPPED_CASES.map((c) => c.text),
  ...RESIDUE_CASES,
  ...MAIN_SAMPLES,
];
/** Raw and stored (what ingest / fact add / rescrub --real writes) forms; the stored form of a raw shape is served under the same rules. */
const FORMS: string[] = [...new Set(RAW.flatMap((s) => [s, redactSecrets(s, { skip: STORAGE_SKIP }).text]))];

/**
 * Deterministic contexts around a shape. `same`: the context keeps the shape's meaning, so no
 * value piece may be served either. The `>` quote and the table flattening RESHAPE some cases
 * (a YAML block scalar is no longer one; `password: | x` becomes an empty table cell before a
 * cell `x`), so there P1 is the spec's: no detector hit, no main hit, no marker (origin/main
 * served those reshaped strings too; recorded as a residual in RESULT-SEC).
 */
const CONTEXTS: Array<{ f: (s: string) => string; same: boolean }> = [
  { f: (s) => s, same: true },
  { f: (s) => `Note from the call.\n${s}\nThat was all.`, same: true },
  { f: (s) => `- item: ${s}`, same: true },
  { f: (s) => `> ${s.replace(/\n/g, '\n> ')}`, same: false },
  { f: (s) => `\`\`\`\n${s}\n\`\`\``, same: true },
  { f: (s) => `| a | ${s.replace(/\n/g, ' ')} | b |`, same: false },
  { f: (s) => `"${s}"`, same: true },
  { f: (s) => `(${s})`, same: true },
];

/** P1 for one served string: no detector hit, no main hit, no marker; and (strict) no value piece. */
function servable(s: string, strict = true): boolean {
  return !(strict && survives(s)) && !s.includes(MARKER) && !strictCredentialSignal(s) && !mainCredentialSignal(s);
}
/** Every string in a JSON value. */
function allStrings(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.flatMap(allStrings);
  if (v && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => [k, ...allStrings(x)]);
  return [];
}

/** P1 + P2 violations of a serve check over every form in every context (unit level: wallFilter + guardString + safeMessage). */
function violations(check: ServeCheck): { p1: number; p2: number } {
  let p1 = 0;
  let p2 = 0;
  for (const f of FORMS) {
    for (const ctx of CONTEXTS) {
      const s = ctx.f(f);
      const kept = wallFilter([{ text: s }], check).kept;
      const g = guardString(s, check).text;
      const m = safeMessage(s, [], check);
      const served = [...kept.map((x) => x.text), ...(g === null ? [] : [g]), ...(m.startsWith('refused') ? [] : [m])];
      p1 += served.filter((x) => !servable(x, ctx.same)).length;
      if (mainCredentialSignal(s)) p2 += served.length;
    }
  }
  return { p1, p2 };
}

test('the shape tables are what they claim (each raw shape carries a value piece; each main sample trips its own main pattern)', () => {
  for (const s of RAW) assert.ok(survives(s.toLowerCase()), `value piece present (length ${s.length})`);
  assert.equal(MAIN_SAMPLES.length, MAIN_CREDENTIAL_PATTERNS.length);
  for (const [i, s] of MAIN_SAMPLES.entries()) assert.ok(MAIN_CREDENTIAL_PATTERNS[i]!.test(s), `main pattern #${i}`);
  assert.ok(FORMS.some((f) => f.includes(MARKER)), 'stored forms carry markers');
  assert.ok(WRAPPED_CASES.some((c) => c.text.split('\n').length >= 4), 'keys wrapped over 3+ lines are covered');
});

test('the main floor is origin/main credentialSignal VERBATIM (pinned: change it only together with this hash)', () => {
  const h = createHash('sha256').update(MAIN_CREDENTIAL_PATTERNS.map((r) => `${r.source}/${r.flags}`).join('\n')).digest('hex');
  assert.equal(h, MAIN_FLOOR_SHA256);
});

test('P1 + P2 (unit): over every form in every context, a served string trips nothing; anything main flags is withheld', () => {
  assert.deepEqual(violations((s) => serveSecretSignal(s)), { p1: 0, p2: 0 });
  // A clean string is served byte-for-byte (the guard never rewrites).
  for (const s of ['clean prose, nothing secret', 'the token was revoked yesterday', 'password reset flow: done']) {
    assert.deepEqual(guardString(s), { text: s, secretWithheld: 0 });
    assert.equal(safeMessage(s), s);
  }
});

test('P2 (generated): serve strictness >= origin/main on generated near-miss strings around every main pattern', () => {
  let seed = 7;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const pick = <T,>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)]!;
  const heads = [P.openai, P.openaiProj, P.anthropic, P.ghp, P.ghs, P.ghPat, P.slack, P.neon, P.akia, j('ey', 'J'), 'Bearer ', 'bearer ',
    'password: ', 'pwd=', 'secret: ', 'api_key=', 'access-token=', 'client_secret: ', 'https://u:', 'x+y://:', 'code: ', 'otp ', '2fa code ', 'login: ', 'recovery '];
  const alpha = ['a', 'B', '7', 'x', 'Q', '3', '_', '-', '.', '~', '+', '/', '=', '"', "'", '`', '$', '{', '}', '<', '>', '*', '\u2026', ' ', '\n', ':', '@', '%', '#'];
  let flagged = 0;
  for (let i = 0; i < 30000; i++) {
    let t = '';
    const n = 4 + Math.floor(rnd() * 40);
    for (let k = 0; k < n; k++) t += rnd() < 0.6 ? pick(['a', 'B', '7', 'x', 'Q', '3']) : pick(alpha);
    const s = pick(['', 'x ', '(', '"', '`', '-', '[', 'key ']) + pick(heads) + t;
    if (!mainCredentialSignal(s)) continue;
    flagged++;
    assert.equal(guardString(s).text, null, `main flags generated string #${i}: withheld`);
  }
  assert.ok(flagged > 1000, `enough generated strings trip main (${flagged})`);
});

test('P3: code-constant text (zeusi://about, every about section, server instructions, the start-task and onboarding prompts, the onboarding CLI commands) trips no detector rule and no main pattern', () => {
  const texts = [true, false].flatMap((w) => [aboutMarkdown(w), mcpInstructions(w), ...aboutSections(w).flatMap((s) => allStrings(s))]);
  texts.push(startTaskText(null), startTaskText('ship the release notes'), onboardingText(), CANNOT_RUN_IT, ...ONBOARDING_COMMANDS);
  for (const [i, t] of texts.entries()) {
    assert.equal(strictCredentialSignal(t), false, `constant #${i}: detector`);
    assert.equal(mainCredentialSignal(t), false, `constant #${i}: main patterns`);
    assert.equal(guardString(t).text, t, `constant #${i}: served unchanged by the full guard`);
  }
});

test('mutants: drop the marker check -> stored residue is served (P1 red); drop the guard -> everything is served (P1 + P2 red)', () => {
  const noMarker = violations((s) => serveSecretSignal(s, { marker: false }));
  assert.ok(noMarker.p1 > 0, `marker check dropped: P1 violations ${noMarker.p1}`);
  for (const r of RESIDUE_CASES) assert.equal(guardString(r).text, null, 'every residue shape withheld by the full guard');
  const none = violations(() => false);
  assert.ok(none.p1 > 0 && none.p2 > 0, 'guard dropped');
});

test('mutants: the main floor alone carries P2 (detector disabled: P2 holds with the floor, red without it)', () => {
  const floorOnly = violations((s) => serveSecretSignal(s, { detector: false, marker: false }));
  assert.equal(floorOnly.p2, 0, 'the main floor on its own withholds everything main flags');
  const neither = violations((s) => serveSecretSignal(s, { detector: false, marker: false, mainFloor: false }));
  assert.ok(neither.p2 > 0, `main floor dropped: P2 violations ${neither.p2}`);
  const withMarker = violations((s) => serveSecretSignal(s, { detector: false, mainFloor: false }));
  assert.ok(withMarker.p2 > 0, 'the marker check does not stand in for the main floor');
});

// ---------------------------------------------------------------------------
// Every MCP serve path, through the real server (in-memory transport, PGlite rows).

let db: Db;
let home: string;

function asRole(role: string): (service: string) => Promise<Db> {
  return async () => {
    await db.exec(`SET ROLE ${role}`);
    return { label: `pglite as ${role}`, query: db.query.bind(db), exec: db.exec.bind(db), close: async () => { await db.exec('RESET ROLE'); } };
  };
}

before(async () => {
  home = safeMkdtemp(join(tmpdir(), 'zeusi-serve-withhold-'));
  writeFileSync(join(home, '.pg_service.conf'), '[zeusi_ro]\nhost=ep-fake-9.example.invalid\nport=5432\ndbname=zeusi\nuser=zeusi_box_ro\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n');
  db = await pgliteDb();
  await migrate(db);
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
  const client = new Client({ name: 'serve-withhold-test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text?: string }> };
    return { isError: r.isError === true, text: r.content.map((c) => c.text ?? '').join('\n') };
  };
  return { call, client, close: async () => { await client.close(); await server.close(); } };
}

/** P1 over a whole tool response: every string in it is servable. */
function assertServable(text: string, what: string): void {
  const strings = allStrings(JSON.parse(text));
  const bad = strings.filter((s) => !servable(s)).length;
  assert.equal(bad, 0, `${what}: ${bad} served string(s) trip the guard`);
}

const decisionHit = (i: number, words: string): DecisionHit => ({
  type: 'decision', decisionId: i, kind: 'go', who: 'owner', saidAt: new Date().toISOString(), exactWords: words, exactWordsVerbatim: true,
  appliesTo: ['ocelot'], scope: 'work', sourceUri: `hq:t-${i}`, sourceTs: new Date().toISOString(), score: 1, match: 'phrase',
});

test('P1 zeusi_search: every form as hit text, as heading, as a decision and as the notice is withheld; the clean items are served; counts add up', async () => {
  const now = new Date().toISOString();
  const hits = FORMS.flatMap((f, i) => [
    { chunkId: 2 * i + 1, sourceUri: `vault:w${i}.md#c0`, sourceTs: now, scope: 'work', headingPath: null, text: f, score: 1, ranks: {} },
    { chunkId: 2 * i + 2, sourceUri: `vault:w${i}.md#c1`, sourceTs: now, scope: 'work', headingPath: f.replace(/\n/g, ' '), text: 'kept', score: 1, ranks: {} },
  ]);
  hits.push({ chunkId: 0, sourceUri: 'vault:clean.md#c0', sourceTs: now, scope: 'work', headingPath: 'Clean', text: 'clean prose', score: 1, ranks: {} });
  const decisions = [...FORMS.map((f, i) => decisionHit(i + 1, f)), decisionHit(0, 'ocelot go: ship it')];
  for (const notice of [FORMS[0]!, RESIDUE_CASES[0]!, MAIN_SAMPLES[11]!]) {
    const seen: ToolObservation[] = [];
    const h = await mcp({ searchFn: async (): Promise<SearchResult> => ({ mode: 'lexical', notice, hits, decisions }), observe: (o) => seen.push({ ...o }) });
    try {
      const r = await h.call('zeusi_search', { query: 'x', limit: 50 });
      assert.ok(!r.isError);
      assertServable(r.text, 'zeusi_search');
      const out = JSON.parse(r.text) as { hits: Array<{ text: string }>; decisions: Array<{ exact_words: string }>; withheld: number; notice?: string };
      assert.deepEqual(out.hits.map((x) => x.text), ['clean prose']);
      assert.deepEqual(out.decisions.map((x) => x.exact_words), ['ocelot go: ship it']);
      assert.equal(out.notice, undefined);
      assert.equal(out.withheld, 3 * FORMS.length);
      assert.equal(seen[0]!.secretWithheld, 3 * FORMS.length + 1, 'hits + headings + decisions + the notice, counted');
    } finally {
      await h.close();
    }
  }
});

test('P1 zeusi_startup + zeusi_context_for_task: rules, focus and decisions holding any form (in rounds of 20 rows) are withheld; clean rows served', async () => {
  await db.exec('ALTER TABLE zeusi.facts DISABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.decisions DISABLE TRIGGER zeusi_90_wall');
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  await db.query(`INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
                  VALUES ('owner', 'the owner', 'human', 'work', 'work', 'manual', 'manual:people/owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
  const fact = (kind: string, text: string, uri: string) => db.query(
    `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ($1, 's', $2, 'work', 'manual', $3, now(), sha256(convert_to($3, 'UTF8')), $4)`, [kind, text, uri, run]);
  const decision = (words: string, uri: string) => db.query(
    `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
     VALUES ('go', (SELECT id FROM zeusi.people WHERE handle = 'owner'), now() - interval '1 day', 'minute', $1, true, ARRAY['ocelot'], 'work', 'manual', $2, now(), decode($3, 'hex'), $4)`,
    [words, uri, SHA, run]);
  // Only the DB-sized forms (facts.text <= 4000); the keyword table is covered row by row in batches by secret-keyword-span.
  const forms = FORMS.filter((f) => !KEYWORD_CASES.some((c) => c.line === f) && f.length <= 3900);
  const h = await mcp();
  try {
    for (let i = 0; i < forms.length; i += 19) {
      const round = forms.slice(i, i + 19);
      await db.exec('DELETE FROM zeusi.facts; DELETE FROM zeusi.decisions');
      for (const [k, f] of round.entries()) {
        await fact('rule', f, `vault:r/${i + k}.md`);
        await fact('state', f, `vault:s/${i + k}.md`);
        await decision(`ocelot go:\n${f}`, `hq:t-ocelot-${i + k}`);
      }
      await fact('rule', 'clean rule', 'vault:r/clean.md');
      await fact('state', 'clean focus', 'vault:s/clean.md');
      await decision('ocelot go: clean', 'hq:t-ocelot-clean');
      const s = await h.call('zeusi_startup', {});
      assert.ok(!s.isError, s.text);
      assertServable(s.text, `zeusi_startup round ${i}`);
      const so = JSON.parse(s.text) as { rules: Array<{ text: string }>; focus: Array<{ text: string }>; decisions: Array<{ exact_words: string }>; withheld: number };
      assert.deepEqual([so.rules.map((x) => x.text), so.focus.map((x) => x.text), so.decisions.map((x) => x.exact_words)], [['clean rule'], ['clean focus'], ['ocelot go: clean']]);
      assert.equal(so.withheld, 3 * round.length);
      const c = await h.call('zeusi_context_for_task', { task: 'ocelot demo', limit: 50 });
      assert.ok(!c.isError, c.text);
      assertServable(c.text, `zeusi_context_for_task round ${i}`);
      const co = JSON.parse(c.text) as { items: Array<{ exact_words: string }>; withheld: number };
      assert.deepEqual(co.items.map((x) => x.exact_words), ['ocelot go: clean']);
      assert.equal(co.withheld, round.length);
    }
  } finally {
    await h.close();
    await db.exec('ALTER TABLE zeusi.facts ENABLE TRIGGER zeusi_90_wall; ALTER TABLE zeusi.decisions ENABLE TRIGGER zeusi_90_wall');
  }
});

test('P1 start-task echo, error messages, the about resource: every form is withheld; constants served', async () => {
  const h = await mcp({ searchFn: async (o) => { throw new Error(`upstream rejected: ${o.query}`); } });
  try {
    for (const f of FORMS.filter((x) => x.length <= 3900)) {
      const p = await h.client.getPrompt({ name: 'start-task', arguments: { task: `deploy: ${f}` } });
      const t = p.messages.map((m) => (m.content as { text?: string }).text ?? '').join('\n');
      assert.ok(servable(t) && !t.includes('Task: '), 'start-task: not echoed');
      const e = await h.call('zeusi_search', { query: f });
      assert.ok(e.isError);
      assert.equal(e.text, 'refused (details withheld by the wall)');
    }
    const res = await h.client.readResource({ uri: 'zeusi://about' });
    const about = String((res.contents[0] as { text?: string }).text);
    assert.equal(about, aboutMarkdown(false));
    assert.ok(servable(about));
  } finally {
    await h.close();
  }
});

/** sha256 over the main floor's pattern sources + flags (origin/main src/hq-export.ts CREDENTIAL_PATTERNS). */
const MAIN_FLOOR_SHA256 = '59b923b4e13e6eab79a1f83f97e18ae48f3425287f8982d2f61cdd031a8fdd45';

test('storage (fix2e): keys and bearer tokens wrapped over 2..6 lines are stored with no key line left; the prose after them is kept; idempotent', () => {
  for (const c of WRAPPED_CASES) {
    const r = redactSecrets(c.text, { skip: STORAGE_SKIP });
    assert.ok(!survives(r.text), `no key line survives: ${c.name}`);
    assert.ok(r.text.includes(c.keep), `prose after the key kept: ${c.name}`);
    assert.equal(redactSecrets(r.text).count, 0, `idempotent: ${c.name}`);
  }
  // A line with anything besides key characters ends the chain (prose is never swallowed).
  const t = j(P.openaiProj, 'Ab3'.repeat(10), '9\n', 'Cd4'.repeat(4), '\nthe next line is prose');
  assert.equal(redactSecrets(t).text, '[REDACTED:openai_key]\nthe next line is prose');
});
