// In-memory sliding-window limiter for the hosted MCP server (docs/hosting.md "Rate
// limits"). One instance counts events per key over the last window (default 60 s); the hosted
// layer uses it for failed auth (per IP, global) and tool calls (per token, per token for
// log_decision, global). Check first with retryAfter(), then add() only when the whole request
// is allowed, so nothing is partially counted. Keys are pruned on access and the map is
// capped (least recently used first), so a flood of distinct keys cannot grow memory.

export interface LimiterOptions {
  windowMs?: number;
  maxKeys?: number;
}

export class SlidingWindowLimiter {
  readonly windowMs: number;
  readonly maxKeys: number;
  private readonly events = new Map<string, number[]>();

  constructor(o: LimiterOptions = {}) {
    this.windowMs = o.windowMs ?? 60_000;
    this.maxKeys = o.maxKeys ?? 4096;
  }

  private live(key: string, now: number): number[] {
    const arr = this.events.get(key);
    if (!arr) return [];
    const cut = now - this.windowMs;
    let i = 0;
    while (i < arr.length && arr[i]! <= cut) i++;
    if (i > 0) arr.splice(0, i);
    if (arr.length === 0) this.events.delete(key);
    return arr;
  }

  /** 0 when `cost` more events fit under `limit`; otherwise the seconds until they would. */
  retryAfter(key: string, limit: number, cost: number, now: number): number {
    const arr = this.live(key, now);
    if (arr.length + cost <= limit) return 0;
    if (cost > limit) return Math.ceil(this.windowMs / 1000);
    // The oldest (arr.length + cost - limit) events must expire first.
    const mustExpire = arr[arr.length + cost - limit - 1]!;
    return Math.max(1, Math.ceil((mustExpire + this.windowMs - now) / 1000));
  }

  add(key: string, cost: number, now: number): void {
    const arr = this.live(key, now);
    for (let i = 0; i < cost; i++) arr.push(now);
    this.events.delete(key); // re-insert: Map order is the LRU order
    this.events.set(key, arr);
    if (this.events.size > this.maxKeys) this.evict(now, key);
  }

  private evict(now: number, keep: string): void {
    for (const k of [...this.events.keys()]) this.live(k, now);
    for (const k of this.events.keys()) {
      if (this.events.size <= this.maxKeys) break;
      if (k !== keep) this.events.delete(k);
    }
  }

  size(): number {
    return this.events.size;
  }
}
