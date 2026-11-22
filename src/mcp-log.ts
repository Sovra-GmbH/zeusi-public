// Allowlisted request log for the hosted MCP server (docs/hosting.md "Logging"). One JSON
// line per request, built only from these fields, in this order:
//   ts, request_id, token_id, assistant, class, tool, duration_ms, hit_count, withheld_count,
//   redacted_count, status, error_class
// redacted_count: items the serve-time secret guard WITHHELD from the response (a secret
// shape, origin/main's credential patterns or a [REDACTED: marker; a subset of withheld_count).
// The name is kept for log-schema stability; nothing is redacted at serve time. Count only.
// Never query text, chunk text, exact_words, a token or secret, a password, a connection
// string, a database host or walled content: no field can carry free text. Values that do not
// match their field's shape are replaced (tool -> "unknown", error_class -> "internal").

import { ALL_TOOL_NAMES, WORKSPACE_WRITE_TOOL_NAMES } from './mcp-server.ts';
import { LABEL_RE, TOKEN_ID_RE } from './mcp-tokens.ts';

export const ERROR_CLASSES = [
  'unauthorized', 'forbidden', 'rate_limited', 'auth_rate_limited', 'not_configured', 'bad_request', 'payload_too_large', 'tool_refused',
  'tool_error', 'internal',
] as const;
export type ErrorClass = (typeof ERROR_CLASSES)[number];

export const LOG_FIELDS = [
  'ts', 'request_id', 'token_id', 'assistant', 'class', 'tool', 'duration_ms', 'hit_count', 'withheld_count', 'redacted_count', 'status', 'error_class',
] as const;

/** A request with more than one tools/call logs its tool as "batch". */
export const BATCH_TOOL = 'batch';

export interface RequestLogRecord {
  ts: string;
  request_id: string;
  token_id: string | null;
  assistant: string | null;
  class: 'read' | 'write' | null;
  tool: string | null;
  duration_ms: number;
  hit_count: number | null;
  withheld_count: number | null;
  /** Items withheld by the serve-time secret guard (src/mcp-wall.ts; subset of withheld_count). Optional: absent = null. */
  redacted_count?: number | null;
  status: number;
  error_class: ErrorClass | null;
}

const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const UUIDISH = /^[0-9a-f-]{1,64}$/i;
const count = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.round(v) : null);
const shaped = (v: unknown, re: RegExp): string | null => (v === null || v === undefined ? null : typeof v === 'string' && re.test(v) ? v : 'unknown');

export function buildLogLine(r: RequestLogRecord): string {
  const out: Record<(typeof LOG_FIELDS)[number], unknown> = {
    ts: typeof r.ts === 'string' && ISO.test(r.ts) ? r.ts : new Date().toISOString(),
    request_id: shaped(r.request_id, UUIDISH),
    token_id: shaped(r.token_id, TOKEN_ID_RE),
    assistant: shaped(r.assistant, LABEL_RE),
    class: r.class === 'read' || r.class === 'write' ? r.class : null,
    tool: r.tool === null || r.tool === undefined ? null : r.tool === BATCH_TOOL || ALL_TOOL_NAMES.includes(r.tool) || (WORKSPACE_WRITE_TOOL_NAMES as readonly string[]).includes(r.tool) ? r.tool : 'unknown',
    duration_ms: count(r.duration_ms) ?? 0,
    hit_count: count(r.hit_count),
    withheld_count: count(r.withheld_count),
    redacted_count: count(r.redacted_count),
    status: Number.isInteger(r.status) && r.status >= 100 && r.status <= 599 ? r.status : 0,
    error_class: r.error_class === null || r.error_class === undefined ? null
      : (ERROR_CLASSES as readonly string[]).includes(r.error_class) ? r.error_class : 'internal',
  };
  return JSON.stringify(out, [...LOG_FIELDS]);
}
