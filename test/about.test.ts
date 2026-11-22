// The canonical about text (src/about.ts, plan U1): one source, every tool named, wall-safe,
// secret-free, honest about forcing; the built-in search entry matches lexically in Postgres
// (PGlite, as zeusi_box_ro) without any table or row. No network, no Neon.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { migrate } from '../src/migrate.ts';
import { pgliteDb } from './pglite-db.ts';
import type { Db } from '../src/db.ts';
import {
  ABOUT_MARKDOWN, ABOUT_SECTIONS, ABOUT_SOURCE_TS, ABOUT_SUMMARY, ABOUT_TOOLS, ABOUT_URI, aboutHit, aboutMarkdown, aboutSections,
  CONTEXT_NOT_PERMISSION, FILL_MEMORY_COMING, FILL_MEMORY_LINE, MCP_URL, NO_WRITE_LINE, personalAboutSections, searchAbout, toolNamesFor,
  WELCOME_MARKDOWN, welcomeMarkdown, WORKSPACE_UNAVAILABLE,
} from '../src/about.ts';
import { defaultServeCheck, guardString } from '../src/mcp-wall.ts';
import { ALL_TOOL_NAMES, MCP_INSTRUCTIONS, mcpInstructions, TOOL_ALIASES, TOOL_NAMES } from '../src/mcp-server.ts';
import { withheld } from '../src/mcp-wall.ts';
import { hasNonRoleOperatorAddress } from './helpers/owner-terms.ts';

/** Same shapes as test/skill-startup.test.ts secretProblems (kept in sync by hand). */
function secretProblems(text: string): string[] {
  const checks: Array<[string, RegExp]> = [
    ['ZEUSI_NEON_ env name', /ZEUSI_NEON_/],
    ['ZEUSI_OPENAI_ env name', /ZEUSI_OPENAI_/],
    ['password assignment', /pass(word)?\s*[=:]\s*\S/i],
    ['connection string', /postgres(ql)?:\/\//i],
    ['Neon host', /neon\.tech|\bep-[a-z0-9]+-[a-z0-9-]+/i],
    ['pooler host', /-pooler\./i],
    ['OpenAI key shape', /\bsk-[A-Za-z0-9_-]{16,}/],
    ['bearer token value', /Bearer\s+(?!<)[A-Za-z0-9._~+/-]{12,}/],
    ['IPv4 address', /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/],
    ['PGPASSWORD', /PGPASSWORD/],
    ['fly / infra ids', /fly\.dev|\bvol_|\bprj_|\bteam_/i],
  ];
  return checks.filter(([, re]) => re.test(text)).map(([w]) => w);
}

let db: Db;
before(async () => {
  db = await pgliteDb();
  await migrate(db);
});
after(async () => db.close());

test('about: every tool name and alias the server lists appears in the full text; the tool record matches TOOL_NAMES / TOOL_ALIASES', () => {
  for (const n of ALL_TOOL_NAMES) assert.ok(ABOUT_MARKDOWN.includes(n), n);
  assert.deepEqual(Object.keys(ABOUT_TOOLS).sort(), [...TOOL_NAMES].sort());
  for (const [alias, target] of Object.entries(TOOL_ALIASES)) assert.ok(ABOUT_TOOLS[target]!.aliases.includes(alias), alias);
  const listed = Object.values(ABOUT_TOOLS).flatMap((t) => t.aliases).sort();
  assert.deepEqual(listed, Object.keys(TOOL_ALIASES).sort(), 'no alias the server does not register');
  assert.equal(ABOUT_TOOLS['zeusi_log_decision']!.cls, 'write');
  for (const n of ['zeusi_startup', 'zeusi_search', 'zeusi_context_for_task']) assert.equal(ABOUT_TOOLS[n]!.cls, 'read', n);
  assert.match(ABOUT_MARKDOWN, /start-task/);
  assert.ok(ABOUT_MARKDOWN.includes(ABOUT_URI));
});

test('about: required substance (cat, model-agnostic, read-only default, invent=NO, cite format, never-store list, cannot force)', () => {
  for (const p of [
    'shared, model-agnostic memory for decisions, digs, parked items and locks', 'named after a cat', 'read-only by default',
    'invent=NO', '<source_uri> @ <source_ts>', 'decision id', 'secrets', 'credentials', 'tokens', '2FA codes', 'client personal data',
    'hard wall', 'cannot force a model to call a tool or run a script', 'only instruct and offer prompts', 'command-line tool',
    'always read-only',
  ]) assert.ok(ABOUT_MARKDOWN.includes(p), p);
});

test('about: every served copy passes the MCP wall (KTD2: the wall is named generically) and holds no secret shape', () => {
  for (const w of [true, false]) {
    assert.equal(withheld([aboutMarkdown(w)]), false, `full text ${w}`);
    assert.equal(withheld([mcpInstructions(w)]), false, `instructions ${w}`);
    for (const s of aboutSections(w)) {
      const h = aboutHit(s);
      assert.equal(withheld([h.text, h.heading, h.source_uri, h.cite]), false, s.slug);
    }
    for (const t of [aboutMarkdown(w), mcpInstructions(w)]) assert.deepEqual(secretProblems(t), []);
    assert.doesNotMatch(aboutMarkdown(w), /plankiva|plankiva/i);
  }
  assert.equal(withheld([ABOUT_SUMMARY]), false, 'summary');
  assert.deepEqual(secretProblems(ABOUT_SUMMARY), []);
});

test('about F4: the read-connection copies never name the write tool; the write-connection copies name every tool; same slugs either way', () => {
  assert.deepEqual(toolNamesFor(true), [...TOOL_NAMES].sort((a, b) => Object.keys(ABOUT_TOOLS).indexOf(a) - Object.keys(ABOUT_TOOLS).indexOf(b)));
  assert.deepEqual(toolNamesFor(false), toolNamesFor(true).filter((n) => n !== 'zeusi_log_decision'));
  for (const t of [aboutMarkdown(false), mcpInstructions(false), ...aboutSections(false).map((s) => s.body)]) assert.doesNotMatch(t, /log_decision/);
  assert.ok(aboutMarkdown(false).includes(NO_WRITE_LINE));
  assert.ok(mcpInstructions(false).includes(NO_WRITE_LINE));
  assert.equal(mcpInstructions(false).split(NO_WRITE_LINE).length, 2, 'one honest line in the instructions');
  assert.ok(!mcpInstructions(true).includes(NO_WRITE_LINE) && !aboutMarkdown(true).includes(NO_WRITE_LINE));
  for (const n of ALL_TOOL_NAMES) assert.ok(mcpInstructions(true).includes(n), n);
  assert.deepEqual(aboutSections(false).map((s) => s.slug), aboutSections(true).map((s) => s.slug));
  assert.ok(aboutMarkdown(false).includes('always read-only'));
});

test('about F5: a Zeusi decision is context, not permission, in every served copy (about text, its search entry, summary, instructions, both classes)', () => {
  assert.match(CONTEXT_NOT_PERMISSION, /context, not permission/);
  assert.match(CONTEXT_NOT_PERMISSION, /not an approval or a GO to act now/);
  assert.match(CONTEXT_NOT_PERMISSION, /current, explicit approval/);
  for (const w of [true, false]) {
    for (const t of [aboutMarkdown(w), mcpInstructions(w)]) {
      assert.ok(t.includes(CONTEXT_NOT_PERMISSION), `full wording, canWrite=${w}`);
    }
    const sec = aboutSections(w).find((s) => s.slug === 'decisions-are-context');
    assert.ok(sec && sec.body.includes(CONTEXT_NOT_PERMISSION));
  }
  assert.match(ABOUT_SUMMARY, /context, not permission/);
});

test('about: source_ts is ISO 8601 with offset and not in the future; slugs are unique and URL-safe; summary is compact', () => {
  assert.match(ABOUT_SOURCE_TS, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/);
  assert.ok(Date.parse(ABOUT_SOURCE_TS) <= Date.now());
  const slugs = ABOUT_SECTIONS.map((s) => s.slug);
  assert.equal(new Set(slugs).size, slugs.length);
  for (const s of slugs) assert.match(s, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.equal(slugs[0], 'what-zeusi-is');
  assert.ok(ABOUT_SUMMARY.length < 1200, `summary length ${ABOUT_SUMMARY.length}`);
  assert.ok(MCP_INSTRUCTIONS.startsWith(ABOUT_SUMMARY), 'instructions prepend the compact about');
});

test('about search: "what is zeusi" finds the overview first, as the read-only role, with no table and no row written', async () => {
  const before = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_stat_user_tables`)).rows[0]!.n;
  await db.exec('SET ROLE zeusi_box_ro');
  try {
    const hits = await searchAbout(db, 'what is zeusi', 10);
    assert.ok(hits.length >= 1);
    assert.equal(hits[0]!.source_uri, 'zeusi://about#what-zeusi-is');
    assert.equal(hits[0]!.builtin, true);
    assert.equal(hits[0]!.scope, 'builtin');
    assert.equal(hits[0]!.source_ts, ABOUT_SOURCE_TS);
    assert.equal(hits[0]!.cite, `zeusi://about#what-zeusi-is @ ${ABOUT_SOURCE_TS}`);
    // phrase fallback and other sections
    assert.equal((await searchAbout(db, 'cannot force', 10))[0]!.source_uri, 'zeusi://about#what-a-connector-can-do');
    assert.ok((await searchAbout(db, 'zeusi_context_for_task', 10)).some((h) => h.source_uri === 'zeusi://about#tools'));
    // unrelated, empty, and tsquery/LIKE syntax are harmless
    assert.deepEqual(await searchAbout(db, 'quarterly penguin census', 10), []);
    assert.deepEqual(await searchAbout(db, '   ', 10), []);
    for (const q of ['%', '_', "'); DROP TABLE x; --", '!&|:*()', '\\']) await searchAbout(db, q, 10);
    assert.equal((await searchAbout(db, 'zeusi', 2)).length, 2, 'limit applies');
  } finally {
    await db.exec('RESET ROLE');
  }
  assert.equal((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_stat_user_tables`)).rows[0]!.n, before);
});

test('about (welcome, U3): the welcome is ONE constant with the brief\'s substance, form A, the one URL, and no owner name', () => {
  const expected = [
    "# Hello, I'm Zeusi.", '',
    "I'm a shared memory for you and your AI assistant, named after a cat. I keep your rules, locks, focus, decisions and notes, each with its source. I never invent: if I don't have something, I say so.", '',
    '## What I do for your assistant', '',
    '- At the start of a session, zeusi_startup hands it your standing rules, locks and current focus.',
    '- Before a task, zeusi_context_for_task pulls the notes, locks and decisions that apply.',
    '- Locks are binding: the assistant follows them instead of guessing.',
    '- Every answer cites its source.',
    '- A decision on record is not an approval.', '',
    '## Your own workspace', '',
    'This workspace is your own. It starts empty. You signed in with GitHub; no invite is needed, and another user\'s Zeusi sign-in cannot read it.', '',
    '## What I never store', '',
    'Secrets (passwords, API keys, tokens) or private client details.', '',
    "Filling your memory is coming. Soon I'll offer to fill it from your notes, and I'll show you a preview before anything is saved. For now your workspace is empty and read-only.", '',
    'Server: https://mcp.zeusi.dev/mcp',
  ].join('\n');
  assert.equal(WELCOME_MARKDOWN, expected);
  assert.equal(FILL_MEMORY_LINE, FILL_MEMORY_COMING, 'form A in PR 1');
  // Form B later is one binding: the rest of the welcome does not change.
  const formB = "Want me to fill your memory now? I'll show a preview first.";
  assert.equal(welcomeMarkdown(formB), expected.replace(FILL_MEMORY_COMING, formB));
  assert.equal(hasNonRoleOperatorAddress(WELCOME_MARKDOWN), false, 'no non-role operator address');
  assert.doesNotMatch(WELCOME_MARKDOWN, /\bTeam\b/i);
  assert.ok(aboutMarkdown(false, 'personal').startsWith(WELCOME_MARKDOWN), 'personal about opens with the welcome');
  assert.ok(personalAboutSections().some((s) => s.body === FILL_MEMORY_LINE));
});

test('about (welcome, U3): every personal copy passes the wall and the serve guard and holds no secret shape; the team copies unchanged', () => {
  const personal = [aboutMarkdown(false, 'personal'), WELCOME_MARKDOWN, WORKSPACE_UNAVAILABLE, ...personalAboutSections().flatMap((s) => [s.heading, s.body])];
  for (const t of personal) {
    assert.equal(withheld([t]), false, t.slice(0, 40));
    assert.equal(guardString(t, defaultServeCheck).text, t, `serve guard keeps: ${t.slice(0, 40)}`);
    assert.deepEqual(secretProblems(t), [], t.slice(0, 40));
    assert.doesNotMatch(t, /log_decision|plankiva|plankiva/i);
  }
  assert.ok(WORKSPACE_UNAVAILABLE.includes(MCP_URL));
  assert.equal(aboutMarkdown(false), aboutMarkdown(false, 'team'));
  assert.ok(!aboutMarkdown(true).includes("Hello, I'm Zeusi") && !aboutMarkdown(false).includes("Hello, I'm Zeusi"));
  const slugs = personalAboutSections().map((s) => s.slug);
  assert.equal(new Set(slugs).size, slugs.length);
  for (const sl of slugs) assert.match(sl, /^[a-z0-9-]+$/);
});
