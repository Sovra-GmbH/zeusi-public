// The B1 cache and the per-request wrap proof (C7a, docs/plans/2026-11-19-c7-read-path.md KTD2-KTD4; D13, decided
// by the owner 2026-11-18 20:36 Zurich: ONE unlocked copy per (workspace, key_version), not per grant; every
// request proves it holds its grant's session wrap before it may use or rebuild that copy; revoke, "log out
// everywhere" and DEK rotation evict at once).
//
//   WrapProof   made ONLY by proveSessionWrap from the request's own bearer: the hosted handler passes
//               OAuthServer.sessionKeyFor(bearer) (C6's one unlock path, src/workspace-keys.ts openSessionDek),
//               and the unwrapped key must be for exactly the principal's workspace and grant. It carries the
//               session WorkspaceKey and check = indexHmac('b1-cache-check', tenant). Issued proofs sit in a
//               module WeakSet; dispose() (request end) zeroes the key and releases the request's leases.
//               Any cache call with an object that is not a live issued proof throws.
//   B1Cache     one per process, keyed (tenant, key_version). A hit is used only when the entry's check equals
//               the proof's (timing-safe) AND its manifest generation and coverage equal the values read from
//               the database in this request; anything else evicts and reloads with the proof's key. LRU by
//               accounted bytes (decrypted bytes x 1.25, cap 96 MiB, C0 §2) and an idle TTL (1 h). An entry
//               larger than the cap serves its request and is not kept. Eviction zero-fills the packed buffers
//               (best effort), deferred while a request still holds a lease on them. Memory only, never disk.
//
// Never logs or returns a key, a check value, a term or a value.

import { timingSafeEqual } from 'node:crypto';
import { sameCoverage, wipePacked, type Coverage, type LoadOutcome, type Packed } from './b1-index.ts';
import { assertTenantId } from './tenant-ddl.ts';
import { WorkspaceKey, type UnlockedKey } from './workspace-seal.ts';

export const B1_CACHE_CAP_BYTES = 96 * 1024 * 1024;
/** Accounted bytes per decrypted byte (C0 §2). */
export const B1_CACHE_OVERHEAD = 1.25;
/** Idle TTL = the access-token lifetime (src/mcp-oauth-store.ts ACCESS_TTL_MS). */
export const B1_CACHE_IDLE_MS = 60 * 60 * 1000;

/** A cache call without a live proof (forged, disposed, another module's object): a bug or an attack. */
export class CacheRefused extends Error {
  override name = 'CacheRefused';
}
/** The proof's key_version is older than a cached copy of the same workspace (a rotation): refused. */
export class CacheVersionChanged extends Error {
  override name = 'CacheVersionChanged';
}

interface Entry {
  tenant: string;
  keyVersion: number;
  check: Buffer;
  packed: Packed;
  accounted: number;
  lastUse: number;
  leases: number;
  doomed: boolean;
}

const MINT: unique symbol = Symbol('b1-wrap-proof');
const issued = new WeakSet<object>();

export class WrapProof {
  readonly tenant: string;
  readonly grantId: string;
  readonly keyVersion: number;
  #key: WorkspaceKey | null;
  #check: Buffer | null;
  readonly #leases: Array<() => void> = [];

  /** Module-private: only proveSessionWrap mints a proof (the token is not exported). */
  constructor(token: typeof MINT, tenant: string, grantId: string, key: WorkspaceKey) {
    if (token !== MINT) throw new CacheRefused('a wrap proof is minted only by proveSessionWrap');
    this.tenant = tenant;
    this.grantId = grantId;
    this.keyVersion = key.keyVersion;
    this.#key = key;
    this.#check = key.cacheCheck();
    issued.add(this);
  }

  get disposed(): boolean {
    return this.#key === null;
  }

  /** The session key of this request (throws once disposed). */
  get key(): WorkspaceKey {
    if (!this.#key || this.#key.disposed) throw new CacheRefused('wrap proof disposed');
    return this.#key;
  }

  /** @internal the check value (B1Cache only). */
  checkValue(): Buffer {
    if (!this.#check) throw new CacheRefused('wrap proof disposed');
    return this.#check;
  }

  /** @internal a lease to release at dispose (B1Cache only). */
  hold(release: () => void): void {
    this.#leases.push(release);
  }

  /** Zero the key and the check, release every lease. Idempotent. */
  dispose(): void {
    const k = this.#key;
    this.#key = null;
    k?.dispose();
    this.#check?.fill(0);
    this.#check = null;
    issued.delete(this);
    for (const r of this.#leases.splice(0)) {
      try { r(); } catch { /* best effort */ }
    }
  }
}

/** What the request's own bearer unlocks (src/mcp-oauth.ts sessionKeyFor), or null. */
export interface SessionUnlock extends UnlockedKey {
  tenant: string;
  grantId: string;
}

/**
 * KTD2: a proof for exactly `principal` from the request's bearer, or null (no wraps, wrong token, another
 * workspace or grant, a malformed key). The unwrapped DEK is zeroed here whatever happens.
 */
export function proveSessionWrap(unlock: () => SessionUnlock | null, principal: { tenant: string; grantId: string }): WrapProof | null {
  let u: SessionUnlock | null = null;
  try {
    u = unlock();
  } catch {
    u = null;
  }
  if (!u) return null;
  try {
    assertTenantId(principal.tenant);
    if (u.tenant !== principal.tenant || u.grantId !== principal.grantId) return null;
    return new WrapProof(MINT, principal.tenant, principal.grantId, WorkspaceKey.fromUnlocked(u, principal.tenant));
  } catch {
    return null;
  } finally {
    if (u.dek instanceof Uint8Array) u.dek.fill(0);
  }
}

function assertLive(p: unknown): asserts p is WrapProof {
  if (!(p instanceof WrapProof) || !issued.has(p) || p.disposed) throw new CacheRefused('not a live wrap proof');
}

export interface CacheStats { hits: number; loads: number; rebuilds: number; evictions: number }

export interface B1CacheOptions {
  capBytes?: number | undefined;
  idleMs?: number | undefined;
  now?: (() => number) | undefined;
}

export class B1Cache {
  readonly #entries = new Map<string, Entry>();
  readonly #cap: number;
  readonly #idle: number;
  readonly #now: () => number;
  readonly stats: CacheStats = { hits: 0, loads: 0, rebuilds: 0, evictions: 0 };

  constructor(o: B1CacheOptions = {}) {
    this.#cap = o.capBytes ?? B1_CACHE_CAP_BYTES;
    this.#idle = o.idleMs ?? B1_CACHE_IDLE_MS;
    this.#now = o.now ?? Date.now;
  }

  /** Entries held (tests, the RSS watch): workspace, key_version, accounted bytes. Never content. */
  list(): Array<{ tenant: string; keyVersion: number; accounted: number }> {
    return [...this.#entries.values()].map((e) => ({ tenant: e.tenant, keyVersion: e.keyVersion, accounted: e.accounted }));
  }

  get accountedBytes(): number {
    let n = 0;
    for (const e of this.#entries.values()) n += e.accounted;
    return n;
  }

  /**
   * The packed copy for this request. `fresh` = the manifest generation and the coverage read from the
   * database in this request; `load` builds or opens the copy with the proof's key (only called on a miss).
   */
  async use(proof: WrapProof, fresh: { generation: number; coverage: Coverage }, load: (key: WorkspaceKey) => Promise<LoadOutcome>): Promise<Packed> {
    assertLive(proof);
    const id = `${proof.tenant}:${proof.keyVersion}`;
    // Rotation (KTD4): a newer key_version evicts the older copies; an older proof is refused.
    for (const e of [...this.#entries.values()]) {
      if (e.tenant !== proof.tenant) continue;
      if (e.keyVersion < proof.keyVersion) this.#drop(e);
      else if (e.keyVersion > proof.keyVersion) throw new CacheVersionChanged('a newer key_version of this workspace is cached');
    }
    const hit = this.#entries.get(id);
    if (hit) {
      const c = proof.checkValue();
      const same = hit.check.length === c.length && timingSafeEqual(hit.check, c);
      if (same && hit.packed.generation === fresh.generation && sameCoverage(hit.packed.coverage, fresh.coverage)) {
        this.stats.hits++;
        hit.lastUse = this.#now();
        this.#entries.delete(id);
        this.#entries.set(id, hit); // most recently used last
        this.#lease(proof, hit);
        return hit.packed;
      }
      this.#drop(hit);
    }
    const out = await load(proof.key);
    assertLive(proof);
    this.stats.loads++;
    if (out.rebuilt) this.stats.rebuilds++;
    const e: Entry = {
      tenant: proof.tenant, keyVersion: proof.keyVersion, check: Buffer.from(proof.checkValue()), packed: out.packed,
      accounted: Math.ceil(out.packed.bytes * B1_CACHE_OVERHEAD), lastUse: this.#now(), leases: 0, doomed: false,
    };
    this.#lease(proof, e);
    if (e.accounted > this.#cap) {
      e.doomed = true; // serves this request only
      return e.packed;
    }
    const prev = this.#entries.get(id);
    if (prev) this.#drop(prev);
    this.#entries.set(id, e);
    this.#fit();
    return e.packed;
  }

  /** Every copy of one workspace (session end, offline revoke, rotation commit). */
  evictTenant(tenant: string): number {
    let n = 0;
    for (const e of [...this.#entries.values()]) if (e.tenant === tenant) {
      this.#drop(e);
      n++;
    }
    return n;
  }

  evict(tenant: string, keyVersion: number): boolean {
    const e = this.#entries.get(`${tenant}:${keyVersion}`);
    if (!e) return false;
    this.#drop(e);
    return true;
  }

  /** Idle TTL: drop entries unused for longer than the idle time. */
  sweep(now: number = this.#now()): number {
    let n = 0;
    for (const e of [...this.#entries.values()]) if (now - e.lastUse > this.#idle) {
      this.#drop(e);
      n++;
    }
    return n;
  }

  /** Drop everything (shutdown, tests). */
  clear(): void {
    for (const e of [...this.#entries.values()]) this.#drop(e);
  }

  #lease(proof: WrapProof, e: Entry): void {
    e.leases++;
    proof.hold(() => {
      e.leases--;
      if (e.doomed && e.leases === 0) wipePacked(e.packed);
    });
  }

  #drop(e: Entry): void {
    const id = `${e.tenant}:${e.keyVersion}`;
    if (this.#entries.get(id) === e) this.#entries.delete(id);
    this.stats.evictions++;
    e.doomed = true;
    e.check.fill(0);
    if (e.leases === 0) wipePacked(e.packed);
  }

  #fit(): void {
    let total = this.accountedBytes;
    for (const e of [...this.#entries.values()]) {
      if (total <= this.#cap) return;
      total -= e.accounted;
      this.#drop(e);
    }
  }
}
