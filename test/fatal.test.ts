// C2 (docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD6; security bootstrap §7 item 7, stderr): the MCP
// server process prints the error CLASS only for an uncaught exception, an unhandled rejection and a
// failed start; never the message, never a stack. Real child processes, real handlers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { DatabaseError } from 'pg';
import { ConfigError } from '../src/config.ts';
import { PooledEndpointRefused } from '../src/endpoint-guard.ts';
import { errorClass } from '../src/fatal.ts';
import { McpArgsError, startErrorKeepsMessage } from '../src/mcp.ts';
import { MainBranchRefused } from '../src/owner-guard.ts';
import { TransportRefused } from '../src/transport.ts';

const CANARY = 'heronfatalcanary4410';
const child = (mode: string) => spawnSync(process.execPath, ['test/fixtures/fatal-child.ts', mode, CANARY], { encoding: 'utf8', timeout: 20_000 });

for (const [mode, line, code] of [
  ['throw', 'zeusi-mcp: fatal: RowValueError', 1],
  ['reject', 'zeusi-mcp: fatal: TypeError', 1],
  ['reject-string', 'zeusi-mcp: fatal: non-error', 1],
  ['main', 'zeusi-mcp: error: RowValueError', 2],
] as const) {
  test(`${mode}: stderr is exactly "${line}"; no canary, no stack; exit ${code}`, () => {
    const r = child(mode);
    assert.equal(r.status, code, r.stderr);
    assert.equal(r.stderr, `${line}\n`);
    assert.ok(!r.stderr.includes(CANARY) && !r.stdout.includes(CANARY));
    assert.ok(!/\bat\s/.test(r.stderr), 'no stack frame');
  });
}

test('a value-free start error keeps its message (operators still learn what to fix)', () => {
  const r = child('main-safe');
  assert.equal(r.status, 2);
  assert.equal(r.stderr, 'zeusi-mcp: error: --port must be a number\n');
});

test('the real server entry runs under these handlers: a bad flag prints its McpArgsError text, exit 2', () => {
  const r = spawnSync(process.execPath, ['src/mcp.ts', '--port', 'nope'], { encoding: 'utf8', timeout: 20_000, env: { PATH: process.env['PATH'] ?? '' } });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /^zeusi-mcp: error: /);
  assert.ok(!/\bat\s/.test(r.stderr));
  assert.match(readFileSync('src/mcp.ts', 'utf8'), /runMain\('zeusi-mcp', \(\) => main\(process\.argv\.slice\(2\)\), \{ safeMessage: startErrorKeepsMessage \}\);/);
});

test('the real start-error boundary (review C2R1-5): only McpArgsError and the ConfigError family keep their message', () => {
  const ok = [
    new McpArgsError('--port must be a number'), new ConfigError('x'), new TransportRefused('x'),
    new PooledEndpointRefused('ZEUSI_DB_URL', 'service.toml'), new MainBranchRefused('x'),
  ];
  for (const e of ok) assert.equal(startErrorKeepsMessage(e), true, e.constructor.name);
  const no: unknown[] = [
    new Error(CANARY), new TypeError(CANARY), new RangeError(CANARY), new DatabaseError(CANARY, 0, 'error'),
    Object.assign(new Error(CANARY), { name: 'ConfigError' }), // a look-alike name is not the class
    { message: CANARY }, CANARY, null, undefined,
  ];
  for (const e of no) assert.equal(startErrorKeepsMessage(e), false, String((e as Error | undefined)?.constructor?.name ?? e));
});

test('errorClass: constructor name only; odd values fall back', () => {
  class X extends Error {}
  assert.equal(errorClass(new X(CANARY)), 'X');
  assert.equal(errorClass(new RangeError(CANARY)), 'RangeError');
  assert.equal(errorClass(CANARY), 'non-error');
  assert.equal(errorClass(null), 'non-error');
  const weird = new Error(CANARY);
  Object.defineProperty(weird, 'constructor', { value: { name: `${CANARY} with spaces` } });
  assert.equal(errorClass(weird), 'Error');
});
