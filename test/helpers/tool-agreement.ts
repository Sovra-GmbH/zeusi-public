// F4 (live finding 17 Nov 2026): what a connection is TOLD it can call must equal what it LISTS.
// Shared by the in-memory, hosted bearer and OAuth tests. No network, no credential.
import assert from 'node:assert/strict';
import { ALL_TOOL_NAMES } from '../../src/mcp-server.ts';

/** Tool names (canonical and aliases) a text names, matched as whole identifiers. */
export function toolNamesIn(text: string): string[] {
  return ALL_TOOL_NAMES.filter((n) => new RegExp(`(?<![A-Za-z0-9_])${n}(?![A-Za-z0-9_])`).test(text)).sort();
}

/** Every tool the instructions name is listed, and every listed tool is named (both directions). */
export function assertToolsAgree(instructions: string, listed: readonly string[], label: string): void {
  const core = [...listed].filter((n) => ALL_TOOL_NAMES.includes(n)).sort();
  assert.deepEqual(core, [...listed].sort(), `${label}: only known tools are listed`);
  assert.deepEqual(toolNamesIn(instructions), core, `${label}: instructions name exactly the listed tools`);
}

/** F5 wording every served copy carries. */
export const CONTEXT_NOT_PERMISSION_RE = /context, not permission/;
export const NOT_A_GO_RE = /not an approval or a GO to act now/;
