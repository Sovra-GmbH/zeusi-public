// Sign-in audit for the hosted OAuth flow (docs/plans/2026-11-18-open-signup-workspaces-plan.md
// KTD11, R15). One JSON line per sign-in outcome at the GitHub callback, built ONLY from these
// fields, in this order:
//
//   ts, request_id, github_id, login, tenant_id, action, outcome
//
//   action    signin (a operator member), signup (a new personal workspace was asked for), reuse (a
//             returning personal workspace), denied, error
//   outcome   ok, created, rate_limited, cap_reached, disabled, unavailable, failed, cancelled
//
// Never an email, a GitHub token, an OAuth code / token / state / verifier, a client secret, an IP
// address or free text: every field is shape-checked and anything off-shape becomes "unknown" (or
// null). Lines go to stderr (Fly logs) and, on the hosted server, are appended to a 0600 file on the
// volume so they outlive log retention. Writing the audit never changes a sign-in result.

import { appendFileSync, chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { TENANT_REF_RE } from './tenant-ddl.ts';

export const AUDIT_FIELDS = ['ts', 'request_id', 'github_id', 'login', 'tenant_id', 'action', 'outcome'] as const;
export const AUDIT_ACTIONS = ['signin', 'signup', 'reuse', 'denied', 'error'] as const;
export const AUDIT_OUTCOMES = ['ok', 'created', 'rate_limited', 'cap_reached', 'disabled', 'unavailable', 'failed', 'cancelled'] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];

export interface SigninAuditEvent {
  ts?: string | undefined;
  requestId: string | null;
  githubId: number | null;
  login: string | null;
  tenantId: string | null;
  action: AuditAction;
  outcome: AuditOutcome;
}

export type AuditSink = (e: SigninAuditEvent) => void;

const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const UUIDISH = /^[0-9a-f-]{1,64}$/i;
const LOGIN_RE = /^[A-Za-z0-9-]{1,39}$/;

export function buildAuditLine(e: SigninAuditEvent): string {
  const shaped = (v: unknown, re: RegExp): string | null => (v === null || v === undefined ? null : typeof v === 'string' && re.test(v) ? v : 'unknown');
  const out: Record<(typeof AUDIT_FIELDS)[number], unknown> = {
    ts: typeof e.ts === 'string' && ISO.test(e.ts) ? e.ts : new Date().toISOString(),
    request_id: shaped(e.requestId, UUIDISH),
    github_id: typeof e.githubId === 'number' && Number.isSafeInteger(e.githubId) && e.githubId >= 0 ? e.githubId : null,
    login: shaped(e.login, LOGIN_RE),
    tenant_id: shaped(e.tenantId, TENANT_REF_RE),
    action: (AUDIT_ACTIONS as readonly string[]).includes(e.action) ? e.action : 'error',
    outcome: (AUDIT_OUTCOMES as readonly string[]).includes(e.outcome) ? e.outcome : 'failed',
  };
  return JSON.stringify(out, [...AUDIT_FIELDS]);
}

/**
 * A sink writing each line to `log` (default stderr) and, when `file` is set, appending it to that
 * file (mode 0600, directory 0700). Never throws.
 */
export function auditSink(o: { log?: ((line: string) => void) | undefined; file?: string | undefined } = {}): AuditSink {
  const log = o.log ?? ((line: string) => { process.stderr.write(`${line}\n`); });
  return (e) => {
    let line: string;
    try {
      line = buildAuditLine(e);
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
