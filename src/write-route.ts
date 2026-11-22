// Workspace write routing (C6, docs/plans/2026-11-19-c6-write-path.md KTD1, KTD10, KTD11).
//
// ONE rule decides how a personal workspace is written, from its catalog enc_state (read by
// TenantRouter.encState, src/tenants.ts):
//
//   off, enrolled                          plain   (offPathAllowed, C5 KTD12): today's SQL, unchanged
//   verified, on                           sealed  (the session key is unwrapped only here, lazily)
//   encrypting, decrypting, decrypted, *   refused (WORKSPACE_CHANGING): nothing is written
//
// Every write function takes the route as a parameter and defaults to PLAIN_ROUTE, so the team CLI and
// every existing caller are unchanged. No write function reads the state itself (AGENTS.md one-rule).
//
// B1 (KTD10): every sealed write transaction takes the workspace index lock
// pg_advisory_xact_lock(workspaceIndexLockKey(tenant)) and calls the IndexHook inside the transaction,
// with in-memory plain values only. Lock order: importer lock (session), then index lock
// (transaction); C8 must take its locks in the same order. C6 ships NO_INDEX_HOOK; C7 supplies the
// real hook and its shard table. The plain route takes no index lock.
//
// C7 (docs/plans/2026-11-19-c7-read-path.md KTD8): an IndexHook may also implement beforeCommit (called by
// sealedTx after `fn`, before the enc_progress flush, lock still held: the hook persists ONE segment per
// transaction there) and afterRollback (the transaction failed: drop what was staged). A hook that needs the
// session key is given as an IndexHookFactory (called once per sealed route with that route's key).
// onNoteRemoved receives the ids of the chunks it removed.

import type { Db } from './db.ts';
import { importerLockKey } from './ingest-run.ts';
import { assertTenantId } from './tenant-ddl.ts';
import { offPathAllowed } from './tenant-overlay.ts';
import type { EncState } from './tenants.ts';
import { flushProgress, type WorkspaceKey } from './workspace-seal.ts';

export interface IndexedChunk {
  id: number;
  headingPath: string | null;
  text: string;
}

/** B1 index maintenance, called inside the sealed write transaction under the index lock (C7 implements it). */
export interface IndexHook {
  onNoteWritten(tx: Db, n: { noteId: number; title: string; chunks: readonly IndexedChunk[]; removedChunkIds: readonly number[] }): Promise<void>;
  /** C7: `removedChunkIds` = the chunks this transaction deleted for the note (undefined: unknown, the hook rebuilds). */
  onNoteRemoved(tx: Db, noteId: number, removedChunkIds?: readonly number[]): Promise<void>;
  onRecordWritten(tx: Db, r: { table: 'facts' | 'decisions' | 'decision_links'; id: number }): Promise<void>;
  /** C7: once per sealed transaction, after `fn`, before the enc_progress flush and COMMIT (index lock held). */
  beforeCommit?(tx: Db): Promise<void>;
  /** C7: the sealed transaction rolled back; forget what was staged. Never throws. */
  afterRollback?(): void;
}

/** C7: a hook bound to one sealed route's session key (src/b1-index.ts b1IndexHook). */
export type IndexHookFactory = (key: WorkspaceKey) => IndexHook;

/** C6: no index yet. Safe: no workspace is verified before C8 or on before the flag (C5 KTD13). */
export const NO_INDEX_HOOK: IndexHook = Object.freeze({
  onNoteWritten: async () => {},
  onNoteRemoved: async () => {},
  onRecordWritten: async () => {},
});

export type WriteRoute =
  | { readonly kind: 'plain' }
  | { readonly kind: 'sealed'; readonly key: WorkspaceKey; readonly tenantId: string; readonly index: IndexHook };

export const PLAIN_ROUTE: WriteRoute = Object.freeze({ kind: 'plain' as const });

export type SealedRoute = Extract<WriteRoute, { kind: 'sealed' }>;

/** Why a route was refused: `locked` (no session key), `changing` (a state move in progress or unknown state). */
export class WriteRouteRefused extends Error {
  override name = 'WriteRouteRefused';
  readonly reason: 'locked' | 'changing';
  constructor(reason: 'locked' | 'changing') {
    super(reason === 'locked' ? 'workspace key not available' : 'workspace state does not allow writes');
    this.reason = reason;
  }
}

/**
 * KTD1. `unlock` is called only for verified / on, at most once; null -> refused (locked). Any state
 * other than the five handled ones (including a value outside ENC_STATES) -> refused (changing).
 */
export function writeRouteFor(state: unknown, unlock: () => WorkspaceKey | null, o: { tenantId: string; index?: IndexHook | IndexHookFactory | undefined }): WriteRoute {
  assertTenantId(o.tenantId);
  // One rule (C5 KTD12): plain exactly when offPathAllowed says so; anything not a string is refused below.
  if (typeof state === 'string' && offPathAllowed(state as EncState)) return PLAIN_ROUTE;
  if (state === 'verified' || state === 'on') {
    let key: WorkspaceKey | null = null;
    try {
      key = unlock();
    } catch {
      key = null;
    }
    if (!key || key.disposed || key.tenantId !== o.tenantId) {
      key?.dispose();
      throw new WriteRouteRefused('locked');
    }
    const index = typeof o.index === 'function' ? o.index(key) : (o.index ?? NO_INDEX_HOOK);
    return { kind: 'sealed', key, tenantId: o.tenantId, index };
  }
  throw new WriteRouteRefused('changing');
}

/** The B1 index lock key of one workspace (reuses the importer key derivation, src/ingest-run.ts). */
export function workspaceIndexLockKey(tenantId: string): string {
  assertTenantId(tenantId);
  return importerLockKey(`workspace-index:${tenantId}`);
}

/**
 * One sealed write transaction (KTD8, KTD10, KTD11): BEGIN, the index lock, `fn`, the index hook's
 * beforeCommit (C7: the B1 segment), the enc_progress flush, COMMIT; ROLLBACK, the hook's afterRollback
 * and rethrow on any error. `fn` and beforeCommit run with the lock held.
 */
export async function sealedTx<T>(db: Db, route: SealedRoute, fn: () => Promise<T>): Promise<T> {
  await db.exec('BEGIN');
  try {
    await db.query('SELECT pg_advisory_xact_lock($1::bigint)', [workspaceIndexLockKey(route.tenantId)]);
    const out = await fn();
    if (route.index.beforeCommit) await route.index.beforeCommit(db);
    await flushProgress(db, route.key);
    await db.exec('COMMIT');
    return out;
  } catch (e) {
    await db.exec('ROLLBACK').catch(() => {});
    try { route.index.afterRollback?.(); } catch { /* never masks the error */ }
    throw e;
  }
}
