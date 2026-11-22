// Workspace-key audit (C4, docs/plans/2026-11-18-c4-enroll.md KTD4; parent plan §4.4 "audited by count
// only", §7 item 8). One JSON line per enroll / unlock outcome on the consent page, built ONLY from these
// fields, in this order:
//
//   ts, request_id, tenant_id, action, outcome, count
//
//   action    enroll, unlock_passkey, unlock_recovery
//   outcome   ok, failed, already, rate_limited, unavailable
//   count     recovery attempts of this workspace in the current hour (unlock_recovery only), else null
//
// Never a DEK, PRF output, credential id, recovery code (or any part or hash of it), token, IP or free
// text: every field is shape-checked. Lines go to stderr and, on the hosted server, are appended to a
// 0600 file on the volume. Writing the audit never changes a sign-in.

import { appendFileSync, chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { TENANT_ID_RE } from './tenant-ddl.ts';

export const ENROLL_AUDIT_FIELDS = ['ts', 'request_id', 'tenant_id', 'action', 'outcome', 'count'] as const;
export const ENROLL_AUDIT_ACTIONS = ['enroll', 'unlock_passkey', 'unlock_recovery'] as const;
export const ENROLL_AUDIT_OUTCOMES = ['ok', 'failed', 'already', 'rate_limited', 'unavailable'] as const;
export type EnrollAuditAction = (typeof ENROLL_AUDIT_ACTIONS)[number];
export type EnrollAuditOutcome = (typeof ENROLL_AUDIT_OUTCOMES)[number];

export interface EnrollAuditEvent {
  ts?: string | undefined;
  requestId: string | null;
  tenantId: string;
  action: EnrollAuditAction;
  outcome: EnrollAuditOutcome;
  count?: number | null | undefined;
}

export type EnrollAuditSink = (e: EnrollAuditEvent) => void;

const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const UUIDISH = /^[0-9a-f-]{1,64}$/i;

export function buildEnrollAuditLine(e: EnrollAuditEvent): string {
  const out: Record<(typeof ENROLL_AUDIT_FIELDS)[number], unknown> = {
    ts: typeof e.ts === 'string' && ISO.test(e.ts) ? e.ts : new Date().toISOString(),
    request_id: typeof e.requestId === 'string' && UUIDISH.test(e.requestId) ? e.requestId : null,
    tenant_id: typeof e.tenantId === 'string' && TENANT_ID_RE.test(e.tenantId) ? e.tenantId : 'unknown',
    action: (ENROLL_AUDIT_ACTIONS as readonly string[]).includes(e.action) ? e.action : 'enroll',
    outcome: (ENROLL_AUDIT_OUTCOMES as readonly string[]).includes(e.outcome) ? e.outcome : 'failed',
    count: typeof e.count === 'number' && Number.isSafeInteger(e.count) && e.count >= 0 && e.count <= 1000 ? e.count : null,
  };
  return JSON.stringify(out, [...ENROLL_AUDIT_FIELDS]);
}

export function enrollAuditSink(o: { log?: ((line: string) => void) | undefined; file?: string | undefined } = {}): EnrollAuditSink {
  const log = o.log ?? ((line: string) => { process.stderr.write(`${line}\n`); });
  return (e) => {
    let line: string;
    try {
      line = buildEnrollAuditLine(e);
    } catch {
      return;
    }
    try { log(line); } catch { /* never changes a sign-in */ }
    if (!o.file) return;
    try {
      const dir = dirname(o.file);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      chmodSync(dir, 0o700);
      appendFileSync(o.file, `${line}\n`, { mode: 0o600 });
    } catch { /* the stderr line stands */ }
  };
}
