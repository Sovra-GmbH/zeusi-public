// One URL everywhere (docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md R9): every
// user-facing surface in src/, site/ and skills/ names the MCP server only as
// https://mcp.zeusi.dev/mcp (src/about.ts MCP_URL). Any other MCP endpoint URL, a zeusi.ai/mcp
// address or a Fly app hostname fails. No fly.dev app hostname is shown to a user or used as a default Host allowlist entry.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MCP_URL, WELCOME_MARKDOWN, WORKSPACE_UNAVAILABLE } from '../src/about.ts';
import { DEFAULT_PUBLIC_HOSTS } from '../src/mcp.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const TEXT = /\.(ts|js|html|css|md|svg|json|txt)$/;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : TEXT.test(p) ? [p] : [];
  });
}

const SCANNED = ['src', 'site', 'skills'].flatMap((d) => files(join(ROOT, d)));
/** A literal MCP endpoint URL: scheme, a literal host, optional port, path /mcp at its end. */
const MCP_ENDPOINT = /https?:\/\/[A-Za-z0-9.-]+(?::\d+)?\/mcp(?![\w/-])/g;
test('one URL: the canonical MCP URL is https://mcp.zeusi.dev/mcp and the hosted Host allowlist still serves it', () => {
  assert.equal(MCP_URL, 'https://mcp.zeusi.dev/mcp');
  assert.equal(new URL(MCP_URL).host, DEFAULT_PUBLIC_HOSTS[0]);
  assert.ok(WELCOME_MARKDOWN.includes(`Server: ${MCP_URL}`));
  assert.ok(WORKSPACE_UNAVAILABLE.includes(MCP_URL));
});

test('one URL: no other MCP endpoint URL, no zeusi.ai/mcp and no fly.dev address anywhere in src/, site/ or skills/', () => {
  assert.ok(SCANNED.length > 50, `scanned ${SCANNED.length} files`);
  const problems: string[] = [];
  for (const f of SCANNED) {
    const rel = relative(ROOT, f);
    readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
      const at = `${rel}:${i + 1}`;
      for (const m of line.match(MCP_ENDPOINT) ?? []) if (m !== MCP_URL) problems.push(`${at}: other MCP URL ${m}`);
      if (/zeusi\.ai\/mcp/i.test(line)) problems.push(`${at}: zeusi.ai/mcp`);
      if (/fly\.dev/i.test(line)) problems.push(`${at}: fly.dev`);
    });
  }
  assert.deepEqual(problems, []);
});

test('one URL: the guard itself catches the shapes it is for', () => {
  const hits = (s: string) => (s.match(MCP_ENDPOINT) ?? []).filter((m) => m !== MCP_URL);
  assert.deepEqual(hits(`see ${MCP_URL} now`), []);
  assert.deepEqual(hits('connect to https://example.fly.dev/mcp'), ['https://example.fly.dev/mcp']);
  assert.deepEqual(hits('or https://zeusi.ai/mcp.'), ['https://zeusi.ai/mcp']);
  assert.deepEqual(hits('callback https://claude.ai/api/mcp/auth_callback'), [], 'a client callback path is not an MCP endpoint');
});
