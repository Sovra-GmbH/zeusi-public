// Contract test for the canonical startup skill (skills/zeusi-startup/SKILL.md) and the hosting
// proposal (docs/hosting.md). Not a wording eval: it checks the frontmatter, that the required
// tools / rules are named, and that no credential, env secret name, host or token is in the text.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TOOL_ALIASES, TOOL_NAMES } from '../src/mcp-server.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const SKILL = `${ROOT}skills/zeusi-startup/SKILL.md`;
const README = `${ROOT}skills/README.md`;
const HOSTING = `${ROOT}docs/hosting.md`;
const MCP_DOC = `${ROOT}docs/mcp.md`;

/** Minimal agentskills.io frontmatter parse: `---` block of `key: value` lines at the very top. */
export function parseSkill(text: string): { meta: Record<string, string>; body: string } {
  const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  if (!m) throw new Error('no frontmatter');
  const meta: Record<string, string> = {};
  for (const line of m[1]!.split('\n')) {
    if (!line.trim()) continue;
    const kv = /^([a-z][a-z0-9_-]*):\s*(.*)$/.exec(line);
    if (!kv) throw new Error('bad frontmatter line');
    meta[kv[1]!] = kv[2]!.trim();
  }
  return { meta, body: m[2]! };
}

/** Things that must never be in the skill or the hosting doc. */
function secretProblems(text: string): string[] {
  const out: string[] = [];
  const checks: Array<[string, RegExp]> = [
    ['ZEUSI_NEON_ env name', /ZEUSI_NEON_/],
    ['ZEUSI_OPENAI_ env name', /ZEUSI_OPENAI_/],
    ['password assignment', /pass(word)?\s*[=:]\s*\S/i],
    ['connection string', /postgres(ql)?:\/\//i],
    ['Neon host', /neon\.tech|\bep-[a-z0-9]+-[a-z0-9-]+/i],
    ['pooler host', /-pooler\./i],
    ['OpenAI key shape', /\bsk-[A-Za-z0-9_-]{16,}/],
    ['bearer token value', /Bearer\s+(?!<)[A-Za-z0-9._~+/-]{12,}/],
    ['IPv4 address', /\b(?!127\.0\.0\.1\b)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/],
    ['PGPASSWORD', /PGPASSWORD/],
  ];
  for (const [what, re] of checks) if (re.test(text)) out.push(what);
  return out;
}

test('skill: skills/zeusi-startup/SKILL.md exists with agentskills.io frontmatter (name zeusi-startup, description "Use when...")', () => {
  assert.ok(existsSync(SKILL), 'skill file exists');
  const { meta, body } = parseSkill(readFileSync(SKILL, 'utf8'));
  assert.equal(meta['name'], 'zeusi-startup');
  assert.match(meta['description'] ?? '', /^Use when /);
  assert.ok((meta['description'] ?? '').length <= 1024, 'description fits the agentskills.io limit');
  assert.match(meta['name']!, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.ok(body.trim().length > 0);
});

test('skill: frontmatter parser rejects a missing or malformed block (the contract test can fail)', () => {
  assert.throws(() => parseSkill('# no frontmatter\n'));
  assert.throws(() => parseSkill('---\nname zeusi\n---\nbody\n'));
});

test('skill: names every tool (canonical and alias), the cite format, feedback and session start', () => {
  const { body } = parseSkill(readFileSync(SKILL, 'utf8'));
  for (const t of TOOL_NAMES) assert.ok(body.includes(`\`${t}\``), t);
  for (const [alias, target] of Object.entries(TOOL_ALIASES)) {
    assert.ok(body.includes(`\`${alias}\``), alias);
    assert.ok(body.includes(`\`${target}\``), target);
  }
  assert.match(body, /source_uri @ source_ts/, 'cite format');
  assert.match(body, /session start/i);
  assert.match(body, /before asking the owner/i);
  assert.match(body, /say so/i, 'say so when nothing answers it');
});

test('skill: states invent=NO, the Plankiva exclusion (no paraphrase around the wall) and the read-only default', () => {
  const { body } = parseSkill(readFileSync(SKILL, 'utf8'));
  assert.match(body, /invent=NO/);
  assert.match(body, /only\*\* for a decision the owner actually made|only for a decision the owner actually made/);
  assert.match(body, /Plankiva[^\n]*\bexcluded\b/, 'the exclusion is stated');
  assert.match(body, /^## The Plankiva exclusion$/m);
  assert.match(body, /Do not search for it, do not log it/);
  for (const [alias, target] of Object.entries(TOOL_ALIASES)) {
    assert.match(body, new RegExp(`\\| \`${target}\` \\| \`${alias}\` \\|`), `alias table row ${alias}`);
  }
  assert.match(body, /never paraphrase/i);
  assert.match(body, /withheld/);
  assert.match(body, /read-only/i);
  assert.match(body, /--write-service/);
  assert.match(body, /unless the owner said so/);
  assert.match(body, /dist\/mcp\.js/, 'how to connect (stdio)');
  // connect story: the hosted URL + bearer placeholder is the default, local stdio is secondary with a real path
  const connect = section(body, /^## How to connect$/);
  assert.match(connect, /\*\*Default: the hosted server\.\*\* URL `https:\/\/mcp\.zeusi\.dev\/mcp`/);
  assert.match(connect, /claude mcp add --transport http zeusi https:\/\/mcp\.zeusi\.dev\/mcp --header "Authorization: Bearer \$ZEUSI_READ_TOKEN"/);
  assert.match(connect, /\*\*Secondary: local stdio\*\*/);
  assert.ok(connect.indexOf('Default: the hosted server') < connect.indexOf('Secondary: local stdio'), 'hosted before stdio');
  assert.match(connect, /real absolute path/);
  assert.doesNotMatch(connect, /\/path\/to\/zeusi\//, 'no bare /path/to/zeusi placeholder');
  assert.match(connect, /docs\/mcp\.md/);
  assert.match(connect, /Customize > Connectors, \+ Add, Add custom connector, URL `https:\/\/mcp\.zeusi\.dev\/mcp`/);
  assert.match(connect, /always read-only/);
  assert.doesNotMatch(connect, /there is no OAuth sign-in/);
});

test('F5: the skill, the README "What Zeusi is" and docs/mcp.md say a Zeusi decision is context, not permission (no GO to act now; current, explicit approval)', () => {
  const readme = readFileSync(`${ROOT}README.md`, 'utf8');
  const what = readme.slice(readme.indexOf('## What Zeusi is'), readme.indexOf('\n## ', readme.indexOf('## What Zeusi is') + 3));
  for (const [label, t] of [['skill', parseSkill(readFileSync(SKILL, 'utf8')).body], ['README', what], ['docs/mcp.md', readFileSync(MCP_DOC, 'utf8')]] as const) {
    assert.match(t, /context, not permission/, label);
    assert.match(t, /not an approval or a GO to act now/, label);
    assert.match(t, /current, explicit approval/, label);
  }
});

test('skill: no credential, env secret name, hostname or token in the skill or the skills README', () => {
  for (const f of [SKILL, README]) assert.deepEqual(secretProblems(readFileSync(f, 'utf8')), [], f);
  // the checker itself flags each shape (assembled at runtime, never stored)
  for (const bad of [['ZEUSI_', 'NEON_X'], ['ZEUSI_', 'OPENAI_API_KEY'], ['pass', 'word=abc'], ['postgres', 'ql://u@h/d'], ['ep-cool', '-name-123.eu.aws.neon', '.tech'], ['Bearer ', 'abcdefghijklmnop1234']]) {
    assert.notDeepEqual(secretProblems(bad.join('')), [], bad.join(''));
  }
});

test('docs: docs/mcp.md points at the skill as canonical; skills/README.md exists', () => {
  const doc = readFileSync(MCP_DOC, 'utf8');
  assert.match(doc, /skills\/zeusi-startup\/SKILL\.md/);
  assert.match(doc, /canonical/i);
  assert.match(doc, /docs\/hosting\.md/);
  assert.ok(existsSync(README));
  assert.match(readFileSync(README, 'utf8'), /zeusi-startup/);
});

function section(t: string, heading: RegExp): string {
  const lines = t.split('\n');
  const i = lines.findIndex((l) => heading.test(l));
  assert.ok(i >= 0, `section ${heading}`);
  const level = /^#+/.exec(lines[i]!)![0].length;
  const end = lines.findIndex((l, j) => j > i && /^#+ /.test(l) && /^#+/.exec(l)![0].length <= level);
  return lines.slice(i, end < 0 ? undefined : end).join('\n');
}

const ROOT_README = `${ROOT}README.md`;

function forbiddenInDocs(text: string): string[] {
  const bad = [['ZEUSI_', 'NEON_'], ['ZEUSI_', 'OPENAI_'], ['postgres', '://']].map((p) => p.join(''));
  const out = bad.filter((b) => text.includes(b));
  if (/[a-z0-9.-]+\.neon\.tech/i.test(text)) out.push('*.neon.tech host');
  return out;
}

function leakProblems(text: string): string[] {
  const out: string[] = [];
  const checks: Array<[string, RegExp]> = [
    ['hosted token', /zeusi_[a-z2-7]{12}_[A-Za-z0-9_-]{43}/],
    ['bearer token value', /Bearer\s+(?!<)[A-Za-z0-9._~+/-]{12,}/],
    ['connection string', /postgres(ql)?:\/\//i],
    ['Neon host', /[a-z0-9.-]+\.neon\.tech/i],
    ['IPv4 address', /\b(?!127\.0\.0\.1\b)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/],
    ['password assignment', /pass(word)?\s*[=:]\s*\S/i],
  ];
  for (const [what, re] of checks) if (re.test(text)) out.push(what);
  return out;
}

function generateTokenLike(): string {
  return ['zeusi_', 'abcdefghijkl', '_', 'Q'.repeat(43)].join('');
}

function infraIdProblems(text: string): string[] {
  const checks: Array<[string, RegExp]> = [
    ['Fly volume id', new RegExp(['vol', '_[a-z0-9]{8,}'].join(''))],
    ['Fly ownership value', new RegExp(['\\bapp', '-[a-z0-9]{5,}\\b'].join(''))],
    ['Fly ACME target', new RegExp(['fly', 'dns\\.net'].join(''))],
    ['Vercel team slug', new RegExp(['-projects', '\\b'].join(''))],
    ['Vercel id', new RegExp(['\\b(prj|team)', '_[A-Za-z0-9]{8,}'].join(''))],
    ['Fly org slug', new RegExp(['zeus', '-team'].join(''))],
    ['IPv4 address', /\b(?!127\.0\.0\.1\b)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/],
  ];
  return checks.filter(([, re]) => re.test(text)).map(([what]) => what);
}


test('docs: the hosting doc exists, names the official endpoint, and holds no secret', () => {
  assert.ok(existsSync(HOSTING));
  const t = readFileSync(HOSTING, 'utf8');
  assert.match(t, /mcp\.zeusi\.dev\/mcp/);
  assert.doesNotMatch(t, /plan only|not deployed/i);
  assert.match(t, /not attached/i);
  assert.match(t, /read-only/i);
  assert.match(t, /zeusi_box_decision/);
  assert.match(t, /TCP/);
  assert.deepEqual(secretProblems(t), []);
  assert.deepEqual(forbiddenInDocs(t), []);
  assert.deepEqual(leakProblems(t), []);
  assert.deepEqual(infraIdProblems(t), []);
});

test('docs: hosting doc describes hosted mode, the token CLI, fail-closed 503, HSTS and no plain HTTP', () => {
  const t = readFileSync(HOSTING, 'utf8');
  assert.match(t, /--hosted/);
  assert.match(t, /mcp-token mint/);
  assert.match(t, /mcp-token revoke/);
  assert.match(t, /HTTP 503/);
  assert.match(t, /HTTP 401/);
  assert.match(t, /HTTP 429/);
  assert.match(t, /Strict-Transport-Security: max-age=31536000/);
  assert.match(t, /\*\*Refuse plain HTTP, do not redirect\.\*\*/);
  assert.match(t, /argon2id/);
  assert.match(t, /zeusi_<token_id>_<secret>/);
  assert.ok(!t.includes(['hotmail', '.com'].join('')), 'never the hotmail address');
  const never = t;
  for (const w of ['query text', 'chunk text', 'exact_words', 'passwords', 'connection strings']) {
    assert.ok(never.includes(w), `mentions ${w}`);
  }
});

test('docs: README and docs/mcp.md point at the official hosted URL and docs/hosting.md', () => {
  const readme = readFileSync(ROOT_README, 'utf8');
  assert.match(readme, /https:\/\/mcp\.zeusi\.dev\/mcp/);
  assert.match(readme, /docs\/hosting\.md/);
  const mc = readFileSync(MCP_DOC, 'utf8');
  assert.match(mc, /https:\/\/mcp\.zeusi\.dev\/mcp/);
  assert.match(mc, /docs\/hosting\.md/);
  assert.doesNotMatch(mc, /mcp-hosting\.md|runbook-0010-0012-dry-run\.md/);
  for (const f of [ROOT_README, MCP_DOC, HOSTING]) {
    assert.deepEqual(forbiddenInDocs(readFileSync(f, 'utf8')), [], f);
    assert.deepEqual(leakProblems(readFileSync(f, 'utf8')), [], f);
  }
  for (const bad of [generateTokenLike(), ['Bearer ', 'abcdefghijklmnop1234'].join(''), ['10.1', '.2.3'].join('')]) {
    assert.notDeepEqual(leakProblems(bad), [], bad.slice(0, 8));
  }
});

test('docs: mcp.md lists --hosted next to the loopback-only --http; hosted snippets come first', () => {
  const m = readFileSync(MCP_DOC, 'utf8');
  assert.match(m, /node dist\/mcp\.js --hosted/);
  assert.match(m, /`--hosted` and `--http` exclude each other/);
  const snip = m.slice(m.indexOf('\n## Startup snippets\n'), m.indexOf('\n## Seed people\n'));
  assert.ok(snip.length > 0, 'Startup snippets section');
  assert.ok(snip.indexOf('### Connect: the hosted server (default)') >= 0, 'hosted section');
  assert.ok(snip.indexOf('### Connect: the hosted server (default)') < snip.indexOf('### Connect: local stdio (secondary)'), 'hosted before stdio');
  assert.match(snip, /claude mcp add --transport http zeusi https:\/\/mcp\.zeusi\.dev\/mcp \\\n {2}--header "Authorization: Bearer \$ZEUSI_READ_TOKEN"/);
  assert.match(snip, /claude mcp add --transport http zeusi https:\/\/mcp\.zeusi\.dev\/mcp\n```/, 'Claude Code OAuth: URL only, no token');
  assert.match(snip, /Do not put a token in the URL/);
  assert.deepEqual(secretProblems(readFileSync(SKILL, 'utf8')), []);
});

test('docs: hosting, README, site README and mcp.md name no Fly / Vercel ids; the checker can fail', () => {
  const t = readFileSync(HOSTING, 'utf8');
  assert.match(t, /mcp\.zeusi\.dev/);
  for (const f of [HOSTING, ROOT_README, `${ROOT}site/README.md`, MCP_DOC]) {
    assert.deepEqual(infraIdProblems(readFileSync(f, 'utf8')), [], f);
  }
  for (const bad of [['vol', '_abcdefgh1234'], ['app', '-12ab34c'], ['x.', 'flydns.net'], ['someone-1234s', '-projects'], ['prj', '_AbCdEfGh12'], ['10.1', '.2.3']]) {
    assert.notDeepEqual(infraIdProblems(bad.join('')), [], bad.join(''));
  }
});

test('site: README says live at zeusi.ai, static files from site/; root README points there; no draft wording', () => {
  const s = readFileSync(`${ROOT}site/README.md`, 'utf8');
  assert.match(s, /Live at <https:\/\/zeusi\.ai>/);
  assert.match(s, /deployed to Vercel as static files/);
  assert.match(s, /`README\.md` is not uploaded/);
  assert.doesNotMatch(s, /Draft only|Not deployed/i);
  const r = section(readFileSync(ROOT_README, 'utf8'), /^## Site$/);
  assert.match(r, /https:\/\/zeusi\.ai/);
  assert.match(r, /site\/README\.md/);
  assert.doesNotMatch(r, /draft|not deployed/i);
});

test('license: MIT, Sovra GmbH 2026, and package.json says MIT', () => {
  const l = readFileSync(`${ROOT}LICENSE`, 'utf8');
  assert.match(l.split('\n')[0]!, /^MIT License$/);
  assert.match(l, /^Copyright \(c\) 2026 Sovra GmbH$/m);
  assert.match(l, /Permission is hereby granted, free of charge/);
  assert.match(l, /THE SOFTWARE IS PROVIDED "AS IS"/);
  const pkg = JSON.parse(readFileSync(`${ROOT}package.json`, 'utf8')) as { license?: string };
  assert.equal(pkg.license, 'MIT');
});

test('skill (PR2 U10): a "First run" step names zeusi_onboarding_status / onboarding_status, the dry-run onboard command and the honest limits', () => {
  const { body } = parseSkill(readFileSync(SKILL, 'utf8'));
  assert.match(body, /\*\*First run\.\*\*/);
  assert.match(body, /`zeusi_onboarding_status` \(alias `onboarding_status`\)/);
  assert.match(body, /`zeusi onboard --markdown <notes-folder> --scope work`/);
  assert.match(body, /dry run \(counts only, nothing written\)/);
  assert.match(body, /cannot force a model to run anything/);
  assert.match(body, /never claim you ran it/);
  assert.match(body, /names, emails and phone numbers are not filtered/);
  const mcp = readFileSync(new URL('../docs/mcp.md', import.meta.url), 'utf8');
  for (const n of ['zeusi_onboarding_status', 'onboarding_status', '### First-run onboarding']) assert.ok(mcp.includes(n), `docs/mcp.md: ${n}`);
});
