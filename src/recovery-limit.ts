// Recovery-code attempt limit (C4 KTD4, docs/plans/2026-11-18-c4-enroll.md; parent plan §4.4, §4.5,
// §7 item 8). 5 attempts per hour per workspace (the main limit: rotating IPs does not help) and 5 per
// hour per client IP, counted BEFORE the code is decoded, derived or unwrapped.
//
// Persisted, counts only: a 0600 JSON file in a 0700 directory on the volume holds, per workspace id
// and per HMAC(signing key, "ip:" + ip), the timestamps of attempts inside the window. Never the code,
// its bytes, a hash of them, or a raw IP. It is read on every attempt and written atomically (temp +
// rename), so a restart (or a second instance on the same file) keeps the counts. A file that does not
// validate refuses every recovery attempt (fail closed) and is never overwritten.

import { chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { createHmac, randomBytes } from 'node:crypto';
import { dirname } from 'node:path';
import { z } from 'zod';
import { TENANT_ID_RE } from './tenant-ddl.ts';

export const RECOVERY_LIMIT = 5;
export const RECOVERY_WINDOW_MS = 60 * 60_000;
/** Distinct IP keys kept (oldest dropped first); workspace keys are bounded by the catalog cap. */
export const MAX_IP_KEYS = 4096;

const Stamps = z.array(z.number().int().nonnegative()).max(64);
const LimitFile = z.strictObject({
  version: z.literal(1),
  tenants: z.record(z.string().regex(TENANT_ID_RE), Stamps),
  ips: z.record(z.string().regex(/^[0-9a-f]{64}$/), Stamps),
});
type LimitDoc = z.infer<typeof LimitFile>;

export type RecoveryAttempt =
  | { ok: true; count: number }
  | { ok: false; reason: 'limited'; count: number; retryAfter: number }
  | { ok: false; reason: 'unavailable'; count: null; retryAfter: number };

export interface RecoveryLimiterOptions {
  /** HMAC key for the IP keys (the OAuth signing key). */
  hashKey: string;
  /** The counts file; omitted = memory only (tests). */
  file?: string | undefined;
  now?: (() => number) | undefined;
  limit?: number | undefined;
  windowMs?: number | undefined;
}

export class RecoveryAttemptLimiter {
  private readonly o: RecoveryLimiterOptions;
  private readonly now: () => number;
  readonly limit: number;
  readonly windowMs: number;
  private mem: LimitDoc = { version: 1, tenants: {}, ips: {} };

  constructor(o: RecoveryLimiterOptions) {
    if (o.hashKey.length < 32) throw new Error('recovery limiter key too short');
    this.o = o;
    this.now = o.now ?? Date.now;
    this.limit = o.limit ?? RECOVERY_LIMIT;
    this.windowMs = o.windowMs ?? RECOVERY_WINDOW_MS;
  }

  private ipKey(ip: string): string {
    return createHmac('sha256', this.o.hashKey).update(`ip:${ip}`, 'utf8').digest('hex');
  }

  private read(): LimitDoc | null {
    const f = this.o.file;
    if (!f) return this.mem;
    let st;
    try {
      st = lstatSync(f);
    } catch (e) {
      return (e as { code?: string }).code === 'ENOENT' ? { version: 1, tenants: {}, ips: {} } : null;
    }
    if (!st.isFile() || (st.mode & 0o077) !== 0) return null;
    try {
      const r = LimitFile.safeParse(JSON.parse(readFileSync(f, 'utf8')));
      return r.success ? r.data : null;
    } catch {
      return null;
    }
  }

  private write(doc: LimitDoc): boolean {
    const f = this.o.file;
    if (!f) {
      this.mem = doc;
      return true;
    }
    const tmp = `${f}.tmp-${randomBytes(6).toString('hex')}`;
    try {
      mkdirSync(dirname(f), { recursive: true, mode: 0o700 });
      chmodSync(dirname(f), 0o700);
      const fd = openSync(tmp, 'wx', 0o600);
      try {
        writeSync(fd, `${JSON.stringify(doc)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, f);
      return true;
    } catch {
      try { unlinkSync(tmp); } catch { /* gone */ }
      return false;
    }
  }

  private live(arr: readonly number[] | undefined, now: number): number[] {
    const cut = now - this.windowMs;
    return (arr ?? []).filter((t) => t > cut && t <= now + this.windowMs);
  }

  /**
   * One recovery attempt for `tenant` from `ip`. Allowed attempts are recorded (and persisted) before
   * this returns; a refused one changes nothing. `count`: attempts for this workspace in the window,
   * this one included when allowed.
   */
  attempt(tenant: string, ip: string): RecoveryAttempt {
    const now = this.now();
    const doc = this.read();
    if (!doc || !TENANT_ID_RE.test(tenant)) return { ok: false, reason: 'unavailable', count: null, retryAfter: Math.ceil(this.windowMs / 1000) };
    const ipk = this.ipKey(ip);
    const t = this.live(doc.tenants[tenant], now);
    const i = this.live(doc.ips[ipk], now);
    if (t.length >= this.limit || i.length >= this.limit) {
      const oldest = Math.min(...(t.length >= this.limit ? [t[t.length - this.limit]!] : []), ...(i.length >= this.limit ? [i[i.length - this.limit]!] : []));
      return { ok: false, reason: 'limited', count: t.length + 1, retryAfter: Math.max(1, Math.ceil((oldest + this.windowMs - now) / 1000)) };
    }
    const tenants: Record<string, number[]> = {};
    for (const [k, v] of Object.entries(doc.tenants)) {
      const l = this.live(v, now);
      if (l.length > 0) tenants[k] = l;
    }
    tenants[tenant] = [...t, now];
    const ipEntries = Object.entries(doc.ips).map(([k, v]) => [k, this.live(v, now)] as const).filter(([k, v]) => v.length > 0 && k !== ipk);
    ipEntries.push([ipk, [...i, now]]);
    while (ipEntries.length > MAX_IP_KEYS) ipEntries.shift();
    if (!this.write({ version: 1, tenants, ips: Object.fromEntries(ipEntries) })) {
      return { ok: false, reason: 'unavailable', count: null, retryAfter: Math.ceil(this.windowMs / 1000) };
    }
    return { ok: true, count: t.length + 1 };
  }
}
