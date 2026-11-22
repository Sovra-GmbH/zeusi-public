// Test-only fixture for the C6 write path (docs/plans/2026-11-19-c6-write-path.md): PGlite with the real
// migrations, tenant logins and writer login (test/helpers/tenant-fixture.ts), a WorkspaceWrites wired like
// src/mcp.ts (writer sessions + TenantRouter.encState), a FIXED test DEK, a spy index hook that checks the
// B1 lock from inside the transaction, and a statement log. No network, no Neon, no real workspace, no
// real key. Workspaces are moved between enc_states by owner SQL (the C8 tool does not exist yet).
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../../src/db.ts';
import { OVERLAY_TABLES } from '../../src/tenant-overlay.ts';
import { TenantDirectory, TenantRouter, TenantWriter, TENANT_WR_ROLE, type EncState } from '../../src/tenants.ts';
import { WorkspaceWrites, type PreviewDocument, type SyncItem, type UnlockedSessionKey, type WorkspaceCaller } from '../../src/workspace-write.ts';
import { workspaceIndexLockKey, type IndexHook, type IndexHookFactory } from '../../src/write-route.ts';
import { safeMkdtemp } from './safe-tmp.ts';
import { asLogin, asOwner, tenantTestDb } from './tenant-fixture.ts';

/** A fixed test DEK (a byte pattern, as test/crypto-envelope.test.ts). Never a real key. */
export const TEST_DEK = Buffer.alloc(32, 0x6c);
export const OTHER_DEK = Buffer.alloc(32, 0x6d);

export interface HookCall {
  kind: 'note' | 'removed' | 'record';
  id: number;
  table?: string;
  chunkIds?: number[];
  removedChunkIds?: number[];
  /** The workspace index lock was granted to this backend when the hook ran. */
  lockHeld: boolean;
  schema: string;
}

export interface C6Fixture {
  db: Db;
  dir: TenantDirectory;
  dirOn: TenantDirectory;
  router: TenantRouter;
  ww: WorkspaceWrites;
  /** Every statement the writer sessions ran, plus 'encState(<tenant>)' when the state was read. */
  log: string[];
  hook: HookCall[];
  /** Per-tenant state override for the encState reader ('throw' = unreadable). */
  stateOverride: Map<string, string>;
  close: () => Promise<void>;
}

function recording(db: Db, log: string[]): Db {
  return {
    label: db.label, ...(db.transport ? { transport: db.transport } : {}),
    query: (sql, params) => {
      log.push(sql);
      return db.query(sql, params);
    },
    exec: (sql) => {
      log.push(sql);
      return db.exec(sql);
    },
    close: () => db.close(),
  };
}

/** True when this backend holds the bigint advisory lock `key` (pg_locks splits it into classid / objid). */
export async function holdsAdvisory(tx: Db, key: string): Promise<boolean> {
  const k = BigInt(key);
  const r = await tx.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND granted AND pid = pg_backend_pid()
       AND classid = $1::bigint::oid AND objid = $2::bigint::oid AND objsubid = 1`, [(k >> 32n).toString(), (k & 0xffffffffn).toString()]);
  return (r.rows[0]?.n ?? 0) > 0;
}

/** `o.indexHook` (C7): the hook the WorkspaceWrites gets instead of the spy (e.g. the real B1 hook factory). */
export async function c6Fixture(o: { indexHook?: IndexHook | IndexHookFactory; runName?: () => string; previewIdSource?: () => string; serveCheck?: (s: string) => boolean } = {}): Promise<C6Fixture> {
  const db = await tenantTestDb({ writer: true });
  const dir = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin') });
  const dirOn = new TenantDirectory({ connectAdmin: asLogin(db, 'zeusi_tenant_admin'), bornEncrypted: true });
  const router = new TenantRouter({ connectRuntime: asLogin(db, 'zeusi_tenant_rt'), cacheMs: 0 });
  const writer = new TenantWriter({ connectWriter: asLogin(db, TENANT_WR_ROLE), check: (t) => router.check(t) });
  const log: string[] = [];
  const hook: HookCall[] = [];
  const stateOverride = new Map<string, string>();
  const lockOf = async (tx: Db) => {
    // The writer session's translating Db rewrites the literal 'zeusi' to this workspace's schema (src/tenants.ts translateSql).
    const schema = (await tx.query<{ s: string }>(`SELECT 'zeusi'::text AS s`)).rows[0]!.s;
    return { schema, lockHeld: await holdsAdvisory(tx, workspaceIndexLockKey(schema)) };
  };
  const indexHook: IndexHook = {
    onNoteWritten: async (tx, n) => {
      hook.push({ kind: 'note', id: n.noteId, chunkIds: n.chunks.map((c) => c.id), removedChunkIds: [...n.removedChunkIds], ...(await lockOf(tx)) });
    },
    onNoteRemoved: async (tx, id) => {
      hook.push({ kind: 'removed', id, ...(await lockOf(tx)) });
    },
    onRecordWritten: async (tx, r) => {
      hook.push({ kind: 'record', id: r.id, table: r.table, ...(await lockOf(tx)) });
    },
  };
  const ww = new WorkspaceWrites({
    workRoot: join(safeMkdtemp(join(tmpdir(), 'zeusi-c6-')), 'workspace-import'),
    openWrite: async (t) => recording(await writer.open(t), log),
    encState: async (t) => {
      log.push(`encState(${t})`);
      const o = stateOverride.get(t);
      if (o === 'throw') throw new Error('state not readable');
      if (o !== undefined) return { status: 'active', encState: o };
      return router.encState(t);
    },
    indexHook: o.indexHook ?? indexHook,
    ...(o.runName ? { runName: o.runName } : {}),
    ...(o.previewIdSource ? { previewIdSource: o.previewIdSource } : {}),
    ...(o.serveCheck ? { serveCheck: o.serveCheck } : {}),
  });
  return {
    db, dir, dirOn, router, ww, log, hook, stateOverride,
    close: async () => {
      ww.close();
      await db.close();
    },
  };
}

let seq = 9000;
/** A new workspace in `state`: `on` is born flipped (C5 flag on); verified and the moving states are prepared first. */
export async function newWorkspace(f: C6Fixture, state: EncState): Promise<string> {
  const subject = `github:${seq++}`;
  if (state === 'on') return ((await f.dirOn.provision(subject)) as { tenantId: string }).tenantId;
  const t = ((await f.dir.provision(subject)) as { tenantId: string }).tenantId;
  if (state !== 'off' && state !== 'enrolled') assert.equal((await f.dir.overlayStep(t, 'prepare', { dryRun: false })).outcome, 'applied');
  if (state !== 'off') await setState(f.db, t, state);
  return t;
}

export const setState = (db: Db, t: string, s: EncState) => asOwner(db, async () => {
  await db.query(`UPDATE zeusi_tenants.tenants SET enc_state = $2 WHERE tenant_id = $1`, [t, s]);
});

/** The caller of a workspace; `key`: the session key `unlock` returns (a COPY of the test DEK; it is zeroed after use). */
export function callerOf(t: string, o: { grant?: string; key?: 'test' | 'other' | 'none'; keyTenant?: string; keyGrant?: string } = {}): WorkspaceCaller {
  const grantId = o.grant ?? `grant-${t.slice(3, 12)}`;
  const k = o.key ?? 'test';
  return {
    tenantId: t, grantId, subject: null, requestId: null,
    unlock: (): UnlockedSessionKey | null => (k === 'none' ? null : {
      tenant: o.keyTenant ?? t, grantId: o.keyGrant ?? grantId, dek: Buffer.from(k === 'test' ? TEST_DEK : OTHER_DEK), keyVersion: 1,
    }),
  };
}

export async function commitDocs(f: C6Fixture, c: WorkspaceCaller, docs: PreviewDocument[]) {
  const p = await f.ww.preview(c, docs);
  assert.equal(p.status, 'preview', JSON.stringify(p));
  return f.ww.commit(c, (p as { preview_id: string }).preview_id);
}

/** An HQ export item (`<project>/YYYY-MM-DD-<slug>.md` with HQ frontmatter). */
export const hqItem = (project: string, file: string, title: string, body: string): SyncItem =>
  ({ path: `${project}/${file}`, text: `---\nproject: ${project}\nkind: memory\ndate: ${file.slice(0, 10)}\ntitle: ${title}\nsource: assistant\n---\n${body}\n` });

/** A headed decision entry of a decision log (src/importers/structured.ts grammar). */
export const decisionEntry = (words: string, o: { at?: string; links?: string[]; applies?: string[] } = {}) =>
  `## ${o.at ?? '2026-11-19T10:00:00+01:00'} me\nDecision: go\nSaid-at-precision: minute\n${o.applies ? `Applies-to: ${o.applies.join(', ')}\n` : ''}`
  + `${o.links ? `Links: ${o.links.join(', ')}\n` : ''}\n${words}\n`;
export const factEntry = (type: 'rule' | 'focus', subject: string, text: string, at = '2026-11-19T09:00:00+01:00') =>
  `## ${at} me\nType: ${type}\nSubject: ${subject}\n\n${text}\n`;
export const decisionLog = (text: string): PreviewDocument => ({ kind: 'decision-log', text, format: 'markdown' });

/** Rows of one workspace table as the owner. */
export const rowsOf = <T = Record<string, unknown>>(db: Db, t: string, table: string, cols = '*', where = 'true') =>
  asOwner(db, async () => (await db.query<T>(`SELECT ${cols} FROM "${t}".${table} WHERE ${where} ORDER BY id`)).rows);

/** Row counts of the five overlay tables plus quarantine. */
export async function counts(db: Db, t: string): Promise<Record<string, number>> {
  return asOwner(db, async () => {
    const out: Record<string, number> = {};
    for (const x of [...OVERLAY_TABLES, 'quarantine']) out[x] = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${t}".${x}`)).rows[0]!.n;
    return out;
  });
}
