// U7 (docs/plans/2026-11-18-workspace-write-import-plan.md KTD9, R8): welcome form B is one switch in
// src/about.ts, shown only when filling really works on the connection. Pure copy checks here; the
// hosted gating is in test/workspace-write-hosted.test.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  aboutMarkdown, FILL_MEMORY_COMING, FILL_MEMORY_LINE, FILL_MEMORY_OFFER, fillMemoryLine, MCP_URL, NO_WRITE_LINE, PERSONAL_WRITE_LINE,
  personalAboutSections, RECONNECT_TO_FILL, WELCOME_MARKDOWN, welcomeMarkdown,
} from '../src/about.ts';
import { withheld } from '../src/mcp-wall.ts';
import { mcpInstructions, personalEmptyStates } from '../src/mcp-server.ts';
import { onboardingText } from '../src/mcp-prompts.ts';
import { hasNonRoleOperatorAddress } from './helpers/owner-terms.ts';

/** A subset of test/about.test.ts secretProblems (that helper is file-local). */
const secretProblems = (t: string) => [/postgres(ql)?:\/\//i, /neon\.tech|\bep-[a-z0-9]+-[a-z0-9-]+/i, /-pooler\./i, /Bearer\s+(?!<)[A-Za-z0-9._~+/-]{12,}/,
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, /PGPASSWORD/, /fly\.dev/i, /ZEUSI_TENANT_WR_PGPASS/].filter((re) => re.test(t)).map((re) => re.source);

test('form B: the exact owner-asked wording, one switch; form A stays the fallback', () => {
  assert.equal(FILL_MEMORY_OFFER, 'Want me to fill your memory now? I\'ll show a preview first.\nSay "fill my memory" and paste your notes, or point me at an export; nothing is saved until you say yes.');
  assert.equal(fillMemoryLine(true), FILL_MEMORY_OFFER);
  assert.equal(fillMemoryLine(false), FILL_MEMORY_COMING);
  assert.equal(FILL_MEMORY_LINE, FILL_MEMORY_COMING);
  const b = welcomeMarkdown(fillMemoryLine(true));
  assert.equal(b, WELCOME_MARKDOWN.replace(FILL_MEMORY_COMING, FILL_MEMORY_OFFER), 'only the last paragraph changes');
  assert.ok(b.endsWith(`${FILL_MEMORY_OFFER}\n\nServer: ${MCP_URL}`));
  assert.ok(aboutMarkdown(false, 'personal', true).startsWith(b));
  assert.ok(aboutMarkdown(false, 'personal', false).startsWith(WELCOME_MARKDOWN));
});

test('form B surfaces name the write tools and the preview-first rule; form A surfaces never do', () => {
  const on = [aboutMarkdown(false, 'personal', true), mcpInstructions(false, 'personal', true), onboardingText('personal', true),
    ...personalAboutSections(true).map((s) => s.body), ...Object.values(personalEmptyStates(true))];
  const off = [aboutMarkdown(false, 'personal', false), mcpInstructions(false, 'personal', false), onboardingText('personal', false),
    ...personalAboutSections(false).map((s) => s.body), ...Object.values(personalEmptyStates(false)), aboutMarkdown(false), mcpInstructions(false), mcpInstructions(true)];
  assert.ok(on.join('\n').includes('zeusi_import_preview') && on.join('\n').includes('zeusi_import_commit'));
  assert.ok(personalAboutSections(true).some((s) => s.body.includes(PERSONAL_WRITE_LINE)));
  assert.ok(personalAboutSections(false).some((s) => s.body.includes(NO_WRITE_LINE)));
  for (const t of off) assert.doesNotMatch(t, /zeusi_import_|zeusi_sync_batch|Want me to fill/, t.slice(0, 60));
  for (const t of Object.values(personalEmptyStates(true))) assert.ok(t.includes(FILL_MEMORY_OFFER));
  for (const t of [...on, RECONNECT_TO_FILL]) {
    assert.equal(withheld([t]), false, t.slice(0, 60));
    assert.deepEqual(secretProblems(t), []);
    assert.equal(hasNonRoleOperatorAddress(t), false, 'no non-role operator address');
    for (const u of t.match(/https?:\/\/\S+/g) ?? []) assert.ok(u.startsWith(MCP_URL), u);
  }
});
