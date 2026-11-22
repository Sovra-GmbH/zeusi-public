// Workspace-write audit (docs/plans/2026-11-18-workspace-write-import-plan.md KTD8, R6). One JSON
// line per import preview, import commit and sync batch (and per refusal of one), and per operator
// `zeusi workspaces delete` run (action workspace_delete: its dry run, refusal or delete;
// docs/plans/2026-11-20-workspaces-delete.md KTD12), built ONLY from these fields, in this order:
//
//   ts, request_id, github_subject, tenant_id, grant_hash, action, outcome, counts
//
//   github_subject  `github:<numeric id>` (never a login, an email or a name)
//   grant_hash      the first 16 hex characters of sha256(grant id): links the lines of one grant
//                   without naming it (a grant id is not a secret, but it is an operator handle)
//   counts          numbers only, under AUDIT_COUNT_KEYS (anything else is dropped)
//   workspace_delete  an operator action: github_subject, grant_hash and request_id are null; outcome
//                   dry_run (nothing changed), ok, empty (nothing was left), refused, busy, failed or
//                   partial; counts grants, members, key_wraps, tenants, schemas, roles, rows
//
// Never content, a title, a path, a preview id, a token or an IP address. Every field is
// shape-checked; anything off-shape becomes null / "failed". Writing the audit never changes a result.

import { createHash } from 'node:crypto';
import { appendFileSync, chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { TENANT_ID_RE } from './tenant-ddl.ts';

export const WS_AUDIT_FIELDS = ['ts', 'request_id', 'github_subject', 'tenant_id', 'grant_hash', 'action', 'outcome', 'counts'] as const;
export const WS_AUDIT_ACTIONS = ['import_preview', 'import_commit', 'sync', 'workspace_delete'] as const;
export const WS_AUDIT_OUTCOMES = ['ok', 'partial', 'empty', 'duplicate', 'refused', 'too_large', 'rate_limited', 'busy', 'writes_off', 'failed', 'dry_run'] as const;
export const AUDIT_COUNT_KEYS = [
  'documents', 'items', 'admitted', 'notes', 'chunks', 'rules', 'focus', 'decisions', 'quarantined', 'withheld', 'dropped', 'deleted', 'unchanged', 'errors', 'bytes',
  'grants', 'members', 'key_wraps', 'tenants', 'schemas', 'roles', 'rows',
] as const;
export type WsAuditAction = (typeof WS_AUDIT_ACTIONS)[number];
export type WsAuditOutcome = (typeof WS_AUDIT_OUTCOMES)[number];
export type WsAuditCounts = Partial<Record<(typeof AUDIT_COUNT_KEYS)[number], number>>;

export interface WsAuditEvent {
  ts?: string | undefined;
  requestId: string | null;
  subject: string | null;
  tenantId: string | null;
  grantId: string | null;
  action: WsAuditAction;
  outcome: WsAuditOutcome;
  counts?: WsAuditCounts | undefined;
}

export type WsAuditSink = (e: WsAuditEvent) => void;

const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const UUIDISH = /^[0-9a-f-]{1,64}$/i;
const SUBJECT_RE = /^github:[0-9]{1,20}$/;

/** sha256(grant id), 16 hex characters; null for a missing or off-shape id. */
export function grantHash(grantId: string | null | undefined): string | null {
  if (typeof grantId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(grantId)) return null;
  return createHash('sha256').update(`zeusi-grant:${grantId}`, 'utf8').digest('hex').slice(0, 16);
}

export function buildWsAuditLine(e: WsAuditEvent): string {
  const counts: Record<string, number> = {};
  for (const k of AUDIT_COUNT_KEYS) {
    const v = e.counts?.[k];
    if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) counts[k] = v;
  }
  const out: Record<(typeof WS_AUDIT_FIELDS)[number], unknown> = {
    ts: typeof e.ts === 'string' && ISO.test(e.ts) ? e.ts : new Date().toISOString(),
    request_id: typeof e.requestId === 'string' && UUIDISH.test(e.requestId) ? e.requestId : null,
    github_subject: typeof e.subject === 'string' && SUBJECT_RE.test(e.subject) ? e.subject : null,
    tenant_id: typeof e.tenantId === 'string' && TENANT_ID_RE.test(e.tenantId) ? e.tenantId : null,
    grant_hash: grantHash(e.grantId),
    action: (WS_AUDIT_ACTIONS as readonly string[]).includes(e.action) ? e.action : null,
    outcome: (WS_AUDIT_OUTCOMES as readonly string[]).includes(e.outcome) ? e.outcome : 'failed',
    counts,
  };
  // The replacer lists the top-level fields and the count keys only: nothing else can be serialised.
  return JSON.stringify(out, [...WS_AUDIT_FIELDS, ...AUDIT_COUNT_KEYS]);
}

/** stderr (default) plus, when `file` is set, a 0600 file in a 0700 directory. Never throws. */
export function wsAuditSink(o: { log?: ((line: string) => void) | undefined; file?: string | undefined } = {}): WsAuditSink {
  const log = o.log ?? ((line: string) => { process.stderr.write(`${line}\n`); });
  return (e) => {
    let line: string;
    try {
      line = buildWsAuditLine(e);
    } catch {
      return;
    }
    try { log(line); } catch { /* never changes a result */ }
    if (!o.file) return;
    try {
      const dir = dirname(o.file);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      chmodSync(dir, 0o700);
      appendFileSync(o.file, `${line}\n`, { mode: 0o600 });
    } catch { /* the stderr line stands */ }
  };
}
