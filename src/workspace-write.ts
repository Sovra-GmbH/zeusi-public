// Writes into a caller's OWN personal workspace (docs/plans/2026-11-18-workspace-write-import-plan.md
// KTD5, KTD6; R4, R5, R6). Three actions, each for one (tenant, grant) taken from the authenticated
// principal by the hosted handler (src/mcp-hosted.ts), never from the request:
//
//   preview   the request's documents -> a private inbox (0700 dir, 0600 files) -> prepareImport
//             (src/import-run.ts, UNCHANGED pipeline: adapters -> runExportFilter -> importer dry pass
//             with the seed wall: soft wall + quarantine counted). The pipeline is offline; the workspace's
//             own write session is read only for its room and for which record handles are its people
//             (structuredFate: which decision / rule / focus entries would stay notes). The prepared
//             run (filtered text only; the inbox is removed at once; sealed, see Disk) is kept under an opaque 256-bit
//             preview id bound to (tenant, grant), TTL 30 min. Returns counts and, for ADMITTED notes
//             only, a title and first line (each through the serve wall); never quarantined text.
//   commit    exactly that prepared run, once, into the caller's schema through a TenantWriter
//             session (src/tenants.ts): executeImport with IMPORT_PROFILE renamed per workspace (own
//             advisory lock, own ingest_runs rows). A second commit is a no-op that returns the first
//             result. Unknown, expired, another tenant's or another grant's preview: one static refusal.
//   sync      an incremental batch in the HQ export layout (`<project>/YYYY-MM-DD-<slug>.md`, HQ
//             frontmatter) -> private staging -> runExportFilter (UNCHANGED) -> importVault with
//             HQ_PROFILE renamed per workspace and `deletes: false` (upsert by source uri + sha256);
//             then ONLY the paths the batch lists as gone are marked deleted (the importer's own
//             statements, under its DELETE_GUARD), in the caller's schema only.
//
// Caps (WORKSPACE_WRITE_CAPS) are checked before anything is written; refusals are actionable and
// never echo content. Counts only leave this module (and go to the audit, src/workspace-audit.ts).
//
// Routing (C6, docs/plans/2026-11-19-c6-write-path.md KTD1-KTD4, KTD9): commit and sync take the
// profile's importer lock on the writer session FIRST, then read the workspace's enc_state
// (TenantRouter.encState through `encState`; any failure refuses with WRITES_OFF), then pick the route
// with writeRouteFor (src/write-route.ts) and do ALL the work under that lock (importVault re-enters it,
// the active check, the structured writes, the sync deletions). Plain route (off / enrolled): today's
// SQL, unchanged. Sealed route (verified / on): the session key comes from the caller's `unlock` (the
// request's C4 session wrap, src/mcp-hosted.ts), only then, and is disposed in `finally`; a call with
// any row of another shape or key_version is refused (WORKSPACE_CHANGING). Other states are refused
// before anything is read or written.
//
// Disk (review P1-1 of #32): a preview keeps its prepared run on disk for up to 30 minutes, one
// file per note (a tiny-conversation chat export of 783 KB became 6 973 files, about 28 MB
// allocated). C2 (docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD3-KTD5): the kept run is SEALED
// (src/preview-seal.ts): every file AES-256-GCM under a per-preview key held in memory only, under a
// neutral name; the relative paths stay in memory too. The inbox uses neutral names (`001.md`; the
// former name is the markdown adapter's logical name, in memory). Plain text exists on the work disk
// only inside the preview call (inbox, staging, filtered: removed before it returns) and inside the
// commit call (the run unsealed into a fresh private dir, removed in `finally`); removal does not
// overwrite, so freed disk blocks can keep those bytes until reused. This is staging hygiene, not
// workspace encryption. The work root therefore lives OFF the data volume that holds mcp-oauth.json and the
// ledgers (src/mcp.ts workspaceWriteSetup refuses a work root on the same filesystem), a preview is
// capped at previewNotes notes (staging stops at the cap) and at the workspace's remaining room, and
// every kept preview is charged its MEASURED allocated bytes against a per-preview, a per-workspace
// and a global budget, plus a free-space floor on the work filesystem.

import { randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, statfsSync, writeFileSync } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';
import type { Db } from './db.ts';
import { runExportFilter, WITHHELD_MARKER } from './hq-export.ts';
import { executeImport, FILTERED_DIR, prepareImport, STAGING_DIR, type ImportRealResult, type PreparedImport } from './import-run.ts';
import { ABOUT_URI, PERSONAL_DECISIONS_HANDLE, PERSONAL_DECISIONS_PENDING } from './about.ts';
import { ImportInputError, ImportNotesCapError, type ImportInput } from './importers/onboard.ts';
import { KEPT_AS_NOTE_REASONS, type KeptAsNoteReason } from './importers/structured.ts';
import { HQ_FILE_RE, HQ_PROFILE, HQ_PROJECT_RE, IMPORT_PROFILE, type ImportProfile } from './importers/profile.ts';
import { DELETE_GUARD, importVault, splitNote } from './importers/vault.ts';
import { tryLockImporter, unlockImporter } from './ingest-run.ts';
import { defaultServeCheck, withheld, type ServeCheck } from './mcp-wall.ts';
import { loadWall, seedWall } from './wall.ts';
import { destroySealed, readSealed, sealRun, unsealRun, type SealedRun } from './preview-seal.ts';
import { gatedRunDir, runDirGate } from './run-dir.ts';
import type { SourcesConfig } from './sources.ts';
import { assertTenantId, TENANT_ID_RE } from './tenant-ddl.ts';
import { sealedDigestReady } from './tenant-overlay.ts';
import { MAX_TENANTS, WORKSPACE_PERSON_HANDLE } from './tenants.ts';
import type { WsAuditAction, WsAuditCounts, WsAuditOutcome, WsAuditSink } from './workspace-audit.ts';
import { mixedShape, SEALED_BODY_BYTES_SQL, SealRefused, sealedSoFar, WorkspaceKey, type UnlockedKey } from './workspace-seal.ts';
import { PLAIN_ROUTE, sealedTx, writeRouteFor, WriteRouteRefused, type IndexHook, type IndexHookFactory, type WriteRoute } from './write-route.ts';

/** Size caps [estimate] (OD7). The hosted body cap (src/mcp-hosted.ts MAX_BODY_BYTES, 1 MiB) comes first. */
export const WORKSPACE_WRITE_CAPS = {
  previewDocuments: 50,
  /** Non-markdown documents (decision logs, chat exports): one importer input each. */
  previewFileDocuments: 10,
  documentBytes: 256 * 1024,
  previewTotalBytes: 900 * 1000,
  syncItems: 100,
  syncItemBytes: 256 * 1024,
  syncDeleted: 200,
  workspaceNotes: 5000,
  /** Note rows of any status (removed notes keep a row, with their text blanked). */
  workspaceRows: 20_000,
  workspaceBytes: 50 * 1024 * 1024,
  /** Pending previews kept per workspace (the oldest is dropped) and in total. */
  previewsPerTenant: 3,
  /**
   * Open previews (those still holding prepared text on disk) in total. At least MAX_TENANTS x
   * previewsPerTenant (review P2-7 of #31): other workspaces filling their own allowance can never
   * refuse this workspace's previews by COUNT. The disk is bounded by the byte budgets below, not by
   * this count: request bytes say little about disk use (review P1-1 of #32: one 783 KB export of
   * tiny conversations staged 6 973 notes, one file each, about 28 MB allocated at 4 KiB per file).
   */
  previewsTotal: MAX_TENANTS * 3,
  /**
   * Notes one preview may stage (staging stops at the cap; nothing is kept). Also never more than the
   * workspace's remaining room (workspaceNotes / workspaceRows minus what it holds): a preview that
   * could never be committed keeps no files.
   */
  previewNotes: 1000,
  /**
   * MEASURED allocated bytes (st_blocks x 512, every file and directory of the prepared run) one kept
   * preview may hold. 1000 notes at the 4 KiB minimum allocation are about 4 MiB, plus the filtered
   * text (at most about 1 MB from 900 KB of documents) and directories.
   */
  previewDiskBytes: 8 * 1024 * 1024,
  /** Measured bytes of one workspace's open previews together (its own oldest go first to fit). */
  tenantDiskBytes: 16 * 1024 * 1024,
  /**
   * Measured bytes of all open previews together: MAX_TENANTS x tenantDiskBytes (3.2 GiB), so no
   * workspace's own allowance is refused by others (P2-7). The free-space floor below protects the
   * work filesystem when it is smaller than that.
   */
  diskBytesTotal: MAX_TENANTS * 16 * 1024 * 1024,
  /** A preview is refused when the work filesystem would have less than this free afterwards. */
  workDiskFloorBytes: 512 * 1024 * 1024,
  /** Items shown in a preview (titles / first lines of admitted notes). */
  previewItemsShown: 20,
} as const;
export const PREVIEW_TTL_MS = 30 * 60_000;
export const PREVIEW_ID_RE = /^[A-Za-z0-9_-]{43}$/;
export const WS_HOST = 'zeusi-mcp';
/** Scope of imported items inside a workspace (OD2: the pipeline's default import scope; it means "this workspace"). */
export const WS_SCOPE = 'work';

/** A deliberate refusal: safe, actionable text (no content, no path, no id of anyone else's). */
export class WorkspaceWriteRefused extends Error {
  override name = 'WorkspaceWriteRefused';
}

export const PREVIEW_UNKNOWN =
  'Unknown or expired preview_id: nothing was saved. Previews last 30 minutes and belong to the connection that made them. '
  + 'Run zeusi_import_preview again, show the user the new preview, and commit only after they say yes.';
export const WRITES_OFF =
  'Filling your memory is not available on this server right now: nothing was read or saved. Your workspace and everything in it are unchanged. Try again later.';
export const WRITE_BUSY =
  'Another write into your workspace is running right now: nothing was saved by this call. Retry in a minute.';
/** C6 KTD14: the workspace is moving between states (encrypting, decrypting, ...), or holds rows of another shape. */
export const WORKSPACE_CHANGING =
  'Your workspace is in the middle of a change you started; nothing was saved. Try again in a few minutes.';
/** C6 KTD14: the workspace needs this connection's key and it is not available (no or another session wrap). */
export const WORKSPACE_LOCKED =
  'This connection cannot write to your workspace right now; nothing was saved. Sign in to Zeusi again from your assistant, then retry.';
export const PREVIEW_DISK_FULL =
  'Zeusi has no room for more open previews right now; nothing was saved. Retry in a few minutes (open previews expire after 30 minutes).';

/** Who is writing: from the authenticated principal only (src/mcp-hosted.ts). */
export interface WorkspaceCaller {
  tenantId: string;
  grantId: string;
  subject: string | null;
  requestId: string | null;
  /**
   * C6 KTD4: the session DEK of THIS request (src/mcp-hosted.ts: the request's bearer and its C4 session
   * wrap, src/workspace-keys.ts openSessionDek). Called only when the workspace is verified or on, at
   * most once per call; its tenant and grant must equal the caller's or it is dropped (zeroed). No
   * other unlock path.
   */
  unlock?: (() => UnlockedSessionKey | null) | undefined;
}

/** What `unlock` returns: the unwrapped DEK and the grant it was wrapped for. */
export interface UnlockedSessionKey extends UnlockedKey {
  tenant: string;
  grantId: string;
}

/** A refusal that is already audited (the caller's catch must not audit it again). */
class AuditedRefusal extends WorkspaceWriteRefused {}

export type PreviewDocument =
  | { kind: 'markdown'; text: string; title?: string | undefined }
  | { kind: 'decision-log'; text: string; format?: 'markdown' | 'jsonl' | undefined }
  | { kind: 'claude-export' | 'chatgpt-export'; text: string };

export interface SyncItem { path: string; text: string }

export interface WorkspaceWritesOptions {
  /** Private parent of every inbox / run dir (created 0700; emptied at start: previews are memory-only). */
  workRoot: string;
  /** A TenantWriter session for exactly this workspace (src/tenants.ts). */
  openWrite: (tenantId: string) => Promise<Db>;
  /**
   * C6 KTD2: the workspace's catalog status and enc_state, uncached (TenantRouter.encState). Any throw
   * refuses the write (WRITES_OFF, audit `refused`). Required: there is no default route.
   */
  encState: (tenantId: string) => Promise<{ status: string; encState: string }>;
  /** C6 KTD10: the B1 index hook of sealed writes (default NO_INDEX_HOOK); C7: src/b1-index.ts b1IndexHook (a factory). */
  indexHook?: IndexHook | IndexHookFactory | undefined;
  audit?: WsAuditSink | undefined;
  now?: (() => number) | undefined;
  serveCheck?: ServeCheck | undefined;
  /** TEST seam: free bytes on the work filesystem (default statfs). */
  freeBytes?: ((path: string) => number | null) | undefined;
  /** TEST seam: the random name of each run / sync work dir (src/run-dir.ts), so a test can force a walled name first. */
  runName?: (() => string) | undefined;
  /** TEST seam: the random preview id candidates (servablePreviewId), so a test can force a withheld one first. */
  previewIdSource?: (() => string) | undefined;
}

export const PREVIEW_ID_ATTEMPTS = 50;

/**
 * A random preview id that the serve guard passes. The whole preview result is served through the guard
 * (src/mcp-server.ts writeResult: wallFilter over every string), so an id that trips it (about 1 random
 * 43-character id in 80 000 spells a walled term or a credential shape) withholds the whole preview at
 * random. Re-roll such an id; never weaken the guard. Throws after PREVIEW_ID_ATTEMPTS refusals.
 */
export function servablePreviewId(check: ServeCheck, source: () => string = () => randomBytes(32).toString('base64url')): string {
  for (let i = 0; i < PREVIEW_ID_ATTEMPTS; i++) {
    const id = source();
    if (PREVIEW_ID_RE.test(id) && !withheld([id], check)) return id;
  }
  throw new Error('preview: no preview id the serve guard passes');
}

/** A kept preview's run: the pipeline's metadata (its paths are dead) and the sealed files with their key. */
interface KeptRun {
  meta: PreparedImport;
  /** The filtered folder's path relative to the run (where the importer reads). */
  filteredRel: string;
  sealed: SealedRun;
}

interface PreviewEntry {
  tenantId: string;
  grantId: string;
  expires: number;
  prepared: KeptRun | null;
  bytes: number;
  /** Measured allocated bytes of the prepared run on disk (0 once its files are gone). */
  disk: number;
  notes: number;
  result: CommitResult | null;
  running: Promise<CommitResult> | null;
}

export interface CommitResult {
  status: 'ok' | 'ok_partial';
  notes: { inserted: number; updated: number; unchanged: number; quarantined: number; errors: number; chunks: number };
  rules: number;
  focus: number;
  decisions: number;
  note_locks: number;
  /**
   * Headed decision / rule / focus entries saved only as notes (their handle is not a person of the
   * workspace). Present whenever the preview had such entries; 0 when all were stored.
   */
  decisions_kept_as_notes?: number;
  decisions_note?: string;
}

/**
 * The preview's "why did this stay a note" block (live finding 2026-11-18): per reason a count and a
 * short static text from the parser's rules; null when every headed entry parsed (or there was none).
 */
export function keptAsNotes(by: Partial<Record<KeptAsNoteReason, number>>): {
  entries: number; reasons: Array<{ reason: KeptAsNoteReason; count: number; why: string }>; format: string;
} | null {
  const reasons = (Object.keys(KEPT_AS_NOTE_REASONS) as KeptAsNoteReason[])
    .filter((k) => (by[k] ?? 0) > 0).map((k) => ({ reason: k, count: by[k]!, why: KEPT_AS_NOTE_REASONS[k] }));
  if (reasons.length === 0) return null;
  return {
    entries: reasons.reduce((a, r) => a + r.count, 0), reasons,
    format: `These headed entries are saved as notes, not as decisions. The accepted decision format, with examples: ${ABOUT_URI}#decision-format.`,
  };
}

/** Per-workspace importer names: own advisory lock key and own ingest_runs rows (KTD6). */
export function workspaceImportProfile(tenantId: string): ImportProfile {
  assertTenantId(tenantId);
  return { ...IMPORT_PROFILE, importer: `workspace-import:${tenantId}` };
}
export function workspaceSyncProfile(tenantId: string): ImportProfile {
  assertTenantId(tenantId);
  return { ...HQ_PROFILE, importer: `workspace-sync:${tenantId}`, deletes: false };
}

const utf8Bytes = (s: string) => Buffer.byteLength(s, 'utf8');
const oneLine = (s: string, max: number) => {
  const t = s.replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1).trimEnd()}…` : t;
};
const slug = (s: string) => s.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);

/**
 * Allocated bytes of a directory tree as stored (st_blocks x 512 for every entry, the directory itself
 * included; never through a symlink). Falls back to st_size where st_blocks is not reported.
 */
export function diskUsage(path: string): { bytes: number; files: number } {
  let bytes = 0;
  let files = 0;
  const walk = (p: string) => {
    const st = lstatSync(p);
    bytes += typeof st.blocks === 'number' && st.blocks > 0 ? st.blocks * 512 : st.size;
    if (st.isDirectory()) for (const n of readdirSync(p)) walk(join(p, n));
    else files++;
  };
  walk(path);
  return { bytes, files };
}

/** Free bytes for this process on the filesystem holding `path` (null if not reported). */
function freeBytes(path: string): number | null {
  try {
    const f = statfsSync(path);
    return Number(f.bavail) * Number(f.bsize);
  } catch {
    return null;
  }
}

/**
 * Writes a preview's raw documents into `inbox` (a fresh 0700 dir) and returns the importer inputs.
 * Neutral names on disk (C2 KTD5): notes are `notes/NNN.md`, other documents `<kind>-<i>.<ext>`. A
 * note's former name (it carried the title) stays in memory only, as the file's logical name, so
 * titles, path gates and the imported notes are unchanged. Exported so the on-disk names are pinned
 * (test/c2-inbox-names.test.ts): the inbox lives only inside the preview call.
 */
export function writeInbox(inbox: string, docs: readonly PreviewDocument[]): ImportInput[] {
  const inputs: ImportInput[] = [];
  const notes = docs.filter((d) => d.kind === 'markdown');
  if (notes.length > 0) {
    const dir = freshDir(join(inbox, 'notes'));
    const names = new Map<string, string>();
    notes.forEach((d, i) => {
      const n = String(i + 1).padStart(3, '0');
      names.set(`${n}.md`, `${n}${d.title && slug(d.title) ? `-${slug(d.title)}` : '-note'}.md`);
      writeFileSync(join(dir, `${n}.md`), d.text, { mode: 0o600, flag: 'wx' });
    });
    inputs.push({ kind: 'markdown', path: dir, names });
  }
  docs.forEach((d, i) => {
    if (d.kind === 'markdown') return;
    const ext = d.kind === 'decision-log' ? (d.format === 'jsonl' ? 'jsonl' : 'md') : 'json';
    const file = join(inbox, `${d.kind}-${i + 1}.${ext}`);
    writeFileSync(file, d.text, { mode: 0o600, flag: 'wx' });
    inputs.push({ kind: d.kind, path: file });
  });
  return inputs;
}

/** A 0700 directory created fresh (never through an existing entry). */
function freshDir(path: string): string {
  mkdirSync(path, { recursive: false, mode: 0o700 });
  const st = lstatSync(path);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new WorkspaceWriteRefused('internal work directory problem; nothing was saved');
  return path;
}

export class WorkspaceWrites {
  private readonly o: WorkspaceWritesOptions;
  private readonly now: () => number;
  private readonly previews = new Map<string, PreviewEntry>();
  private readonly root: string;
  private readonly freeBytes: (path: string) => number | null;
  /** One write (commit or sync) per workspace at a time in this process: the size check and the write never interleave. */
  private readonly lanes = new Map<string, Promise<unknown>>();

  constructor(o: WorkspaceWritesOptions) {
    this.o = o;
    this.now = o.now ?? Date.now;
    this.freeBytes = o.freeBytes ?? freeBytes;
    this.root = o.workRoot;
    if (basename(this.root) !== 'workspace-import') throw new Error('workspace writes: the work root must be a dedicated workspace-import directory');
    // Previews live in memory: whatever an earlier process left on disk is unreachable; remove it.
    rmSync(this.root, { recursive: true, force: true });
    mkdirSync(join(this.root, 'runs'), { recursive: true, mode: 0o700 });
    mkdirSync(join(this.root, 'inbox'), { recursive: true, mode: 0o700 });
  }

  private audit(c: WorkspaceCaller, action: WsAuditAction, outcome: WsAuditOutcome, counts?: WsAuditCounts): void {
    try {
      this.o.audit?.({ requestId: c.requestId, subject: c.subject, tenantId: c.tenantId, grantId: c.grantId, action, outcome, counts });
    } catch { /* the audit never changes a result */ }
  }

  private drop(id: string): void {
    const e = this.previews.get(id);
    this.previews.delete(id);
    try { if (e?.prepared) destroySealed(e.prepared.sealed); } catch { /* best effort */ }
  }

  /** Measured bytes held by open previews: all of them, or one workspace's. */
  private diskHeld(tenantId?: string): number {
    let n = 0;
    for (const e of this.previews.values()) if (e.prepared && (!tenantId || e.tenantId === tenantId)) n += e.disk;
    return n;
  }

  /** Global byte budget and the free-space floor (`add`: the bytes about to be kept). */
  private assertDiskRoom(c: WorkspaceCaller, add: number): void {
    const caps = WORKSPACE_WRITE_CAPS;
    const free = this.freeBytes(this.root);
    if (this.diskHeld() + add > caps.diskBytesTotal || (free !== null && free - add < caps.workDiskFloorBytes)) {
      this.audit(c, 'import_preview', 'busy');
      throw new WorkspaceWriteRefused(PREVIEW_DISK_FULL);
    }
  }

  /** The workspace's own oldest open previews go first so the new one fits its byte budget. */
  private fitTenantDisk(c: WorkspaceCaller, add: number): void {
    const mine = [...this.previews].filter(([, e]) => e.tenantId === c.tenantId && e.prepared && !e.running && !e.result);
    while (mine.length > 0 && this.diskHeld(c.tenantId) + add > WORKSPACE_WRITE_CAPS.tenantDiskBytes) this.drop(mine.shift()![0]);
    if (this.diskHeld(c.tenantId) + add > WORKSPACE_WRITE_CAPS.tenantDiskBytes) {
      // Only previews being committed right now are left: they free their files when done.
      this.audit(c, 'import_preview', 'busy');
      throw new WorkspaceWriteRefused(WRITE_BUSY);
    }
  }

  /**
   * Expired previews go (their filtered text with them); a workspace keeps at most previewsPerTenant
   * (its own oldest go first). Another workspace's preview is never evicted: when the store is full,
   * a new preview is refused instead (busy, retry later).
   */
  private sweep(tenantId?: string): void {
    const t = this.now();
    for (const [id, e] of [...this.previews]) if (e.expires <= t && !e.running) this.drop(id);
    if (tenantId) {
      const mine = [...this.previews].filter(([, e]) => e.tenantId === tenantId && !e.running && !e.result);
      while (mine.length >= WORKSPACE_WRITE_CAPS.previewsPerTenant) this.drop(mine.shift()![0]);
    }
  }

  private assertStoreRoom(c: WorkspaceCaller): void {
    // Committed previews keep only their small result (for the no-op repeat), no text: they hold no slot.
    let open = 0;
    for (const e of this.previews.values()) if (e.prepared) open++;
    if (open >= WORKSPACE_WRITE_CAPS.previewsTotal) {
      this.audit(c, 'import_preview', 'busy');
      throw new WorkspaceWriteRefused('Zeusi is holding too many open previews right now; nothing was saved. Retry in a few minutes.');
    }
  }

  private serial<T>(tenantId: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.lanes.get(tenantId) ?? Promise.resolve();
    const run = prev.catch(() => {}).then(fn);
    const tail = run.catch(() => {});
    this.lanes.set(tenantId, tail);
    void tail.then(() => { if (this.lanes.get(tenantId) === tail) this.lanes.delete(tenantId); });
    return run;
  }

  /** Pending previews (tests / ops). */
  pending(): number {
    this.sweep();
    return this.previews.size;
  }

  /** The workspace's active notes and their body bytes, read in the caller's own write session. */
  /**
   * Active notes, note rows of any status, and the bytes of every stored note body (active or not:
   * a removed note's text is blanked by sync, so bytes cannot pile up behind deletions).
   */
  private static async usage(db: Db, route: WriteRoute = PLAIN_ROUTE): Promise<{ notes: number; rows: number; bytes: number }> {
    // C6 KTD9: on the sealed route a body is ciphertext; its plain length is the ciphertext length minus 29.
    const bytes = route.kind === 'sealed' ? SEALED_BODY_BYTES_SQL : 'octet_length(body)';
    const r = (await db.query<{ n: number; all: number; b: string | number }>(
      `SELECT count(*) FILTER (WHERE status = 'active')::int AS n, count(*)::int AS all, coalesce(sum(${bytes}), 0)::bigint AS b FROM zeusi.notes`)).rows[0];
    return { notes: Number(r?.n ?? 0), rows: Number(r?.all ?? 0), bytes: Number(r?.b ?? 0) };
  }

  /**
   * C6 KTD1-KTD4, KTD9, KTD11 (call this with the importer lock held): the state, then the route. Sealed:
   * the session key (only now), the mixed-shape guard and the seal counter. Every refusal is audited
   * here as `refused` and nothing has been written. The caller disposes route.key in `finally`.
   */
  private async routeFor(c: WorkspaceCaller, db: Db, action: WsAuditAction, counts?: WsAuditCounts): Promise<WriteRoute> {
    const refuse = (msg: string): never => {
      this.audit(c, action, 'refused', counts);
      throw new AuditedRefusal(msg);
    };
    let st: { status: string; encState: string };
    try {
      st = await this.o.encState(c.tenantId);
    } catch {
      return refuse(WRITES_OFF);
    }
    if (st.status !== 'active') return refuse(WRITES_OFF);
    let route: WriteRoute;
    try {
      route = writeRouteFor(st.encState, () => {
        const u = c.unlock?.() ?? null;
        if (!u) return null;
        if (u.tenant !== c.tenantId || u.grantId !== c.grantId) {
          u.dek.fill(0);
          return null;
        }
        return WorkspaceKey.fromUnlocked(u, c.tenantId);
      }, { tenantId: c.tenantId, index: this.o.indexHook });
    } catch (e) {
      if (e instanceof WriteRouteRefused) return refuse(e.reason === 'locked' ? WORKSPACE_LOCKED : WORKSPACE_CHANGING);
      return refuse(WRITES_OFF);
    }
    if (route.kind === 'sealed') {
      let problem: string | null = null;
      try {
        // C8-0 KTD-A "Presence": a workspace prepared before C8-0 has no sealed digest column until it converges
        // (its next sign-in, or backfill-writers --real); refuse before any statement names it (never a 42703).
        if (!(await sealedDigestReady(db, c.tenantId))) problem = WORKSPACE_CHANGING;
        else if (await mixedShape(db, route.key.keyVersion)) problem = WORKSPACE_CHANGING;
        else {
          route.key.startCounter(await sealedSoFar(db, route.key.keyVersion));
          if (route.key.mustRotate) problem = WRITES_OFF;
        }
      } catch {
        problem = WRITES_OFF;
      }
      if (problem) {
        route.key.dispose();
        return refuse(problem);
      }
    }
    return route;
  }

  private static assertRoom(u: { notes: number; rows: number; bytes: number }, add: { notes: number; bytes: number }): void {
    const c = WORKSPACE_WRITE_CAPS;
    if (u.notes + add.notes > c.workspaceNotes || u.rows + add.notes > c.workspaceRows || u.bytes + add.bytes > c.workspaceBytes) {
      throw new WorkspaceWriteRefused(
        `Your workspace would go over its size limit (${c.workspaceNotes} notes or ${Math.round(c.workspaceBytes / 1024 / 1024)} MiB of text; `
        + `it holds ${u.notes} notes now). Nothing was saved. Import fewer or shorter notes.`);
    }
  }

  // -------------------------------------------------------------------------
  // Preview

  async preview(c: WorkspaceCaller, docs: readonly PreviewDocument[]) {
    assertTenantId(c.tenantId);
    const caps = WORKSPACE_WRITE_CAPS;
    const total = docs.reduce((a, d) => a + utf8Bytes(d.text), 0);
    const refuse = (msg: string, outcome: WsAuditOutcome = 'too_large'): never => {
      this.audit(c, 'import_preview', outcome, { documents: docs.length, bytes: total });
      throw new WorkspaceWriteRefused(msg);
    };
    if (docs.length === 0) refuse('Give at least one document (pasted notes, a decision log, or a chat export). Nothing was saved.', 'refused');
    if (docs.length > caps.previewDocuments) refuse(`At most ${caps.previewDocuments} documents per preview; split them into several previews. Nothing was saved.`);
    if (docs.filter((d) => d.kind !== 'markdown').length > caps.previewFileDocuments) {
      refuse(`At most ${caps.previewFileDocuments} decision logs or chat exports per preview; split them. Nothing was saved.`);
    }
    if (docs.some((d) => utf8Bytes(d.text) > caps.documentBytes)) {
      refuse(`A document is larger than ${caps.documentBytes / 1024} KiB; split it into smaller documents. Nothing was saved.`);
    }
    if (total > caps.previewTotalBytes) refuse(`The documents add up to more than ${Math.round(caps.previewTotalBytes / 1000)} KB; split them into several previews. Nothing was saved.`);

    this.sweep(c.tenantId);
    this.assertStoreRoom(c);
    this.assertDiskRoom(c, 0);
    // Notes this preview may hold: the per-preview cap and the workspace's remaining room. A preview
    // that could never be committed is refused here or below, and keeps no files.
    const room = await this.noteRoom(c.tenantId);
    const maxNotes = Math.min(caps.previewNotes, room ?? caps.workspaceNotes);
    if (maxNotes <= 0) refuse(this.fullMessage(), 'too_large');
    // Every input path under it is gated (src/importers/onboard.ts, seed wall): a random name that passes (src/run-dir.ts).
    const inbox = gatedRunDir(join(this.root, 'inbox'), '', runDirGate([seedWall()], this.root, ['notes']), this.o.runName);
    let prepared: PreparedImport;
    try {
      const inputs = writeInbox(inbox, docs);
      prepared = await prepareImport({
        inputs, scope: WS_SCOPE, workRoot: join(this.root, 'runs'), home: this.root, stagedNotes: caps.previewNotes, ...(this.o.runName ? { runName: this.o.runName } : {}),
        // A strictly valid standing_locks marker of a note is carried into the caller's own workspace only.
        standingLocks: true,
      });
    } catch (e) {
      if (e instanceof ImportNotesCapError) {
        // prepareImport removed its work dir; the inbox goes in finally.
        this.audit(c, 'import_preview', 'too_large', { documents: docs.length, bytes: total });
        throw new WorkspaceWriteRefused(this.notesCapMessage());
      }
      const msg = e instanceof ImportInputError
        ? `${e.message.replace(/^import:\s*/, '')}. Nothing was saved.`
        : 'The documents could not be prepared (an internal problem); nothing was saved. Retry, or send fewer documents.';
      this.audit(c, 'import_preview', 'refused', { documents: docs.length, bytes: total });
      throw new WorkspaceWriteRefused(msg);
    } finally {
      // The raw (unfiltered) text is not needed any more; the filtered run is sealed below before the call returns.
      rmSync(inbox, { recursive: true, force: true });
    }

    const p = prepared.preview;
    const counts = {
      notes: p.targets.notes, chunks: p.targets.chunks, rules: p.targets.rules, note_lock_rules: p.targets.note_locks, focus: p.targets.focus,
      decisions: p.targets.decisions, quarantined: p.importer.quarantined + p.structured.would_quarantine,
      withheld_entries: p.filter.entries_withheld, dropped_files: p.filter.files_dropped, errors: p.importer.errors,
    };
    const auditCounts = {
      documents: docs.length, bytes: total, admitted: prepared.admitted.length, notes: counts.notes, chunks: counts.chunks,
      quarantined: counts.quarantined, withheld: counts.withheld_entries, dropped: counts.dropped_files, errors: counts.errors,
    };
    if (p.error || p.filter.status !== 'ok') {
      prepared.cleanup();
      this.audit(c, 'import_preview', 'refused', auditCounts);
      throw new WorkspaceWriteRefused('The safety filter refused these documents as a whole (they look like they contain content Zeusi never stores). Nothing was saved. Remove that content and try again.');
    }
    if (prepared.admitted.length === 0) {
      prepared.cleanup();
      this.audit(c, 'import_preview', 'empty', auditCounts);
      return {
        status: 'nothing_to_import' as const, counts,
        message: 'Nothing in these documents can be imported (empty, filtered out, or quarantined). Nothing was saved and there is nothing to commit.',
      };
    }

    let items: ReturnType<WorkspaceWrites['previewItems']>;
    let structured: Awaited<ReturnType<WorkspaceWrites['structuredFate']>>;
    let disk: number;
    let kept: KeptRun | null = null;
    try {
      // Admitted notes over the room: this preview could never be committed, so it keeps nothing.
      if (Math.max(prepared.admitted.length, counts.notes) > maxNotes) {
        this.audit(c, 'import_preview', 'too_large', auditCounts);
        throw new WorkspaceWriteRefused(maxNotes < caps.previewNotes ? this.fullMessage() : this.notesCapMessage());
      }
      // Sealed before anything else (and before any await): from here on the kept run holds no plain
      // text and no note name on disk (C2 KTD3).
      kept = { meta: prepared, filteredRel: relative(prepared.workDir, prepared.filteredDir).split(sep).join('/'), sealed: sealRun(prepared.workDir) };
      // The run's real size on disk (allocated blocks), not the request size.
      disk = diskUsage(kept.sealed.dir).bytes;
      if (disk > caps.previewDiskBytes) {
        this.audit(c, 'import_preview', 'too_large', auditCounts);
        throw new WorkspaceWriteRefused(
          `These documents take too much space as a preview (more than ${Math.round(caps.previewDiskBytes / 1024 / 1024)} MiB once split into notes). `
          + 'Nothing was saved. Split them into several smaller previews.');
      }
      items = this.previewItems(kept);
      structured = await this.structuredFate(c.tenantId, prepared.handles);
      // Re-check after the await: concurrent previews of one workspace (a JSON-RPC batch) stay within its caps.
      this.sweep(c.tenantId);
      this.assertStoreRoom(c);
      this.fitTenantDisk(c, disk);
      this.assertDiskRoom(c, disk);
    } catch (err) {
      if (kept) destroySealed(kept.sealed);
      prepared.cleanup();
      throw err;
    }
    const id = servablePreviewId(this.o.serveCheck ?? defaultServeCheck, this.o.previewIdSource);
    const expires = this.now() + PREVIEW_TTL_MS;
    this.previews.set(id, {
      tenantId: c.tenantId, grantId: c.grantId, expires, prepared: kept, bytes: total, disk, notes: counts.notes, result: null, running: null,
    });
    this.audit(c, 'import_preview', 'ok', auditCounts);
    const asNotes = keptAsNotes(p.structured.kept_as_note);
    return {
      status: 'preview' as const,
      preview_id: id,
      expires_at: new Date(expires).toISOString(),
      saved: false,
      counts,
      ...(asNotes ? { kept_as_notes: asNotes } : {}),
      // A headed decision / rule / focus entry is written only for a handle the workspace knows
      // (structured.ts writeStructured, unknown_person): checked against the workspace's people now.
      ...structured,
      items: items.shown,
      more_items: items.more,
      next: 'Nothing is saved yet. Show the user these counts and items. Only if they clearly say yes, call zeusi_import_commit with this preview_id and confirm: true. '
        + 'If they say no, do nothing: the preview expires by itself in 30 minutes.',
    };
  }

  /**
   * Which of the preview's structured records (decision / rule / focus entries, per handle) the commit
   * would keep as notes: those whose handle is not a person of this workspace (writeStructured
   * unknown_person). Read in the workspace's own write session (SELECT on people only). {} when there
   * is no record or every handle is known; the honest note when not (PERSONAL_DECISIONS_PENDING when
   * the workspace does not know its own person `me` yet); the static rule alone when it cannot be read.
   */
  private async structuredFate(tenantId: string, handles: ReadonlyMap<string, number>): Promise<{ decisions_kept_as_notes?: number; decisions_note?: string }> {
    if (handles.size === 0) return {};
    let db: Db;
    try {
      db = await this.o.openWrite(tenantId);
    } catch {
      return { decisions_note: PERSONAL_DECISIONS_HANDLE };
    }
    try {
      const known = new Set((await db.query<{ handle: string }>(
        'SELECT handle FROM zeusi.people WHERE handle = ANY($1::text[])', [[...new Set([...handles.keys(), WORKSPACE_PERSON_HANDLE])]])).rows.map((r) => r.handle));
      const kept = [...handles].reduce((a, [h, n]) => a + (known.has(h) ? 0 : n), 0);
      if (kept === 0) return {};
      return { decisions_kept_as_notes: kept, decisions_note: known.has(WORKSPACE_PERSON_HANDLE) ? PERSONAL_DECISIONS_HANDLE : PERSONAL_DECISIONS_PENDING };
    } catch {
      return { decisions_note: PERSONAL_DECISIONS_HANDLE };
    } finally {
      await db.close().catch(() => {});
    }
  }

  /** Does this workspace know its own person (`me`)? null when it cannot be read. */
  private static async knowsPerson(db: Db): Promise<boolean | null> {
    try {
      return (await db.query<{ n: number }>('SELECT count(*)::int AS n FROM zeusi.people WHERE handle = $1', [WORKSPACE_PERSON_HANDLE])).rows[0]?.n === 1;
    } catch {
      return null;
    }
  }

  /**
   * Notes the workspace can still take (active-note and row caps minus what it holds), read in the
   * workspace's own write session; null when it cannot be read now (the per-preview cap still bounds
   * the files, and commit checks the room again before writing).
   */
  private async noteRoom(tenantId: string): Promise<number | null> {
    let db: Db;
    try {
      db = await this.o.openWrite(tenantId);
    } catch {
      return null;
    }
    try {
      const u = await WorkspaceWrites.usage(db);
      const c = WORKSPACE_WRITE_CAPS;
      return Math.max(0, Math.min(c.workspaceNotes - u.notes, c.workspaceRows - u.rows));
    } catch {
      return null;
    } finally {
      await db.close().catch(() => {});
    }
  }

  private fullMessage(): string {
    return `Your workspace has no room for this many notes (it holds at most ${WORKSPACE_WRITE_CAPS.workspaceNotes} notes). `
      + 'Nothing was saved. Import fewer notes.';
  }

  private notesCapMessage(): string {
    return `One preview holds at most ${WORKSPACE_WRITE_CAPS.previewNotes} notes (a chat export becomes one note per conversation). `
      + 'Nothing was saved. Split the documents into several previews, or send fewer conversations at a time.';
  }

  /** Title and first line of each ADMITTED note, from the filtered text (opened in memory), each through the serve wall. */
  private previewItems(k: KeptRun): { shown: Array<{ title: string; first_line: string }>; more: number } {
    const check = this.o.serveCheck ?? defaultServeCheck;
    const shown: Array<{ title: string; first_line: string }> = [];
    const p = k.meta;
    for (const rel of p.admitted.slice(0, WORKSPACE_WRITE_CAPS.previewItemsShown)) {
      let title = '(untitled)';
      let first = '';
      try {
        const text = readSealed(k.sealed, `${k.filteredRel}/${rel}`);
        if (text === null) throw new Error('missing');
        const { fm, body } = splitNote(text.toString('utf8'));
        const t = fm?.['title'];
        if (typeof t === 'string' && t.trim() !== '') title = oneLine(t, 80);
        const line = body.split('\n').map((l) => l.trim()).find((l) => l !== '' && l !== WITHHELD_MARKER && !/^-{3,}$/.test(l));
        first = line ? oneLine(line.replace(/^#+\s*/, ''), 120) : '';
      } catch { /* shown as untitled */ }
      if (withheld([title], check)) title = '(title withheld)';
      if (withheld([first], check)) first = '(withheld)';
      shown.push({ title, first_line: first });
    }
    return { shown, more: Math.max(0, p.admitted.length - shown.length) };
  }

  // -------------------------------------------------------------------------
  // Commit

  async commit(c: WorkspaceCaller, previewId: string): Promise<CommitResult & { already_committed: boolean; saved: true }> {
    assertTenantId(c.tenantId);
    this.sweep();
    const e = typeof previewId === 'string' && PREVIEW_ID_RE.test(previewId) ? this.previews.get(previewId) : undefined;
    // Unknown, expired, another workspace's or another grant's: the same static refusal (nothing confirms it exists).
    if (!e || e.tenantId !== c.tenantId || e.grantId !== c.grantId || (e.expires <= this.now() && !e.result && !e.running)) {
      this.audit(c, 'import_commit', 'refused');
      throw new WorkspaceWriteRefused(PREVIEW_UNKNOWN);
    }
    if (e.result) {
      this.audit(c, 'import_commit', 'duplicate', { notes: 0 });
      return { ...e.result, already_committed: true, saved: true };
    }
    if (e.running) {
      const r = await e.running.catch(() => null);
      if (!r) throw new WorkspaceWriteRefused(WRITE_BUSY);
      this.audit(c, 'import_commit', 'duplicate', { notes: 0 });
      return { ...r, already_committed: true, saved: true };
    }
    const run = this.serial(c.tenantId, () => this.runCommit(c, e));
    e.running = run;
    try {
      const r = await run;
      e.result = r;
      return { ...r, already_committed: false, saved: true };
    } finally {
      e.running = null;
    }
  }

  private async runCommit(c: WorkspaceCaller, e: PreviewEntry): Promise<CommitResult> {
    const kept = e.prepared!;
    const prepared = kept.meta;
    let db: Db;
    try {
      db = await this.o.openWrite(c.tenantId);
    } catch (err) {
      this.audit(c, 'import_commit', 'failed');
      throw err;
    }
    let r: ImportRealResult;
    let knowsPerson: boolean | null = null;
    let open: { workDir: string; cleanup: () => void } | null = null;
    const profile = workspaceImportProfile(c.tenantId);
    let locked = false;
    let route: WriteRoute = PLAIN_ROUTE;
    try {
      // C6 KTD3: the importer lock first, then the state, then all the work under it.
      if (!(await tryLockImporter(db, profile.importer))) {
        this.audit(c, 'import_commit', 'busy');
        throw new AuditedRefusal(WRITE_BUSY);
      }
      locked = true;
      route = await this.routeFor(c, db, 'import_commit');
      WorkspaceWrites.assertRoom(await WorkspaceWrites.usage(db, route), { notes: e.notes, bytes: e.bytes });
      // The importer reads a real folder: the run is unsealed into a fresh private dir for this call only. Its
      // random name must pass the importer's root gate (the live wall, plus the seed wall), or the whole run fails.
      const gate = runDirGate([seedWall(), await loadWall(db)], this.root, [kept.filteredRel]);
      open = unsealRun(kept.sealed, join(this.root, 'runs'), gate, this.o.runName);
      r = await executeImport({ ...prepared, workDir: open.workDir, filteredDir: join(open.workDir, ...kept.filteredRel.split('/')), cleanup: open.cleanup }, db, {
        host: WS_HOST, home: this.root, profile, ...(route.kind === 'sealed' ? { route } : {}),
      });
      if (r.structured.unknown_person > 0) knowsPerson = await WorkspaceWrites.knowsPerson(db);
    } catch (err) {
      if (!(err instanceof AuditedRefusal)) this.audit(c, 'import_commit', err instanceof WorkspaceWriteRefused ? 'too_large' : 'failed');
      throw err;
    } finally {
      try { open?.cleanup(); } catch { /* best effort */ }
      if (locked) await unlockImporter(db, profile.importer).catch(() => {});
      if (route.kind === 'sealed') route.key.dispose();
      await db.close().catch(() => {});
    }
    if (r.status === 'locked') {
      this.audit(c, 'import_commit', 'busy');
      throw new WorkspaceWriteRefused(WRITE_BUSY);
    }
    const counts = {
      notes: r.notes.inserted + r.notes.updated, unchanged: r.notes.skipped, chunks: r.notes.chunks_written, quarantined: r.notes.quarantined + r.structured.quarantined,
      errors: r.notes.errors, decisions: r.structured.decisions_inserted, rules: r.structured.rules_inserted, focus: r.structured.focus_inserted,
    };
    if (r.status === 'failed') {
      // Nothing is marked committed: notes are written one transaction each and a retry skips what is
      // already there (same uri + sha), so the user can simply commit the same preview again.
      this.audit(c, 'import_commit', 'failed', counts);
      throw new WorkspaceWriteRefused('Saving did not complete (a temporary problem). Anything already saved stays; commit the same preview_id again to finish.');
    }
    const result: CommitResult = {
      status: r.status,
      notes: {
        inserted: r.notes.inserted, updated: r.notes.updated, unchanged: r.notes.skipped, quarantined: r.notes.quarantined, errors: r.notes.errors, chunks: r.notes.chunks_written,
      },
      rules: r.structured.rules_inserted, focus: r.structured.focus_inserted, decisions: r.structured.decisions_inserted, note_locks: r.targets.note_locks,
      // Headed entries whose handle the workspace does not know stay notes (structured.ts unknown_person): said, never
      // silent. Present whenever the preview had such entries: 0 when every one was stored as a decision / rule / focus.
      ...(r.structured.unknown_person > 0 || prepared.handles.size > 0 ? { decisions_kept_as_notes: r.structured.unknown_person } : {}),
      ...(r.structured.unknown_person > 0 ? { decisions_note: knowsPerson === false ? PERSONAL_DECISIONS_PENDING : PERSONAL_DECISIONS_HANDLE } : {}),
    };
    // The sealed run and its key are not needed after a successful commit; the id stays (TTL) so a repeat is a no-op.
    try { destroySealed(kept.sealed); } catch { /* best effort */ }
    e.prepared = null;
    e.disk = 0;
    this.audit(c, 'import_commit', r.status === 'ok' ? 'ok' : 'partial', counts);
    return result;
  }

  // -------------------------------------------------------------------------
  // Nightly sync

  sync(c: WorkspaceCaller, items: readonly SyncItem[], deleted: readonly string[]) {
    assertTenantId(c.tenantId);
    return this.serial(c.tenantId, () => this.runSync(c, items, deleted));
  }

  private async runSync(c: WorkspaceCaller, items: readonly SyncItem[], deleted: readonly string[]) {
    const caps = WORKSPACE_WRITE_CAPS;
    const bytes = items.reduce((a, x) => a + utf8Bytes(x.text), 0);
    const base = { items: items.length, bytes };
    const refuse = (msg: string, outcome: WsAuditOutcome = 'refused'): never => {
      this.audit(c, 'sync', outcome, base);
      throw new WorkspaceWriteRefused(msg);
    };
    if (items.length === 0 && deleted.length === 0) refuse('An empty batch: give items to add or update, or paths that are gone. Nothing was changed.');
    if (items.length > caps.syncItems) refuse(`At most ${caps.syncItems} items per batch; send several batches. Nothing was changed.`, 'too_large');
    if (deleted.length > caps.syncDeleted) refuse(`At most ${caps.syncDeleted} deleted paths per batch; send several batches. Nothing was changed.`, 'too_large');
    if (items.some((x) => utf8Bytes(x.text) > caps.syncItemBytes)) refuse(`An item is larger than ${caps.syncItemBytes / 1024} KiB; split that note. Nothing was changed.`, 'too_large');
    const paths = [...items.map((x) => x.path), ...deleted];
    for (const p of paths) {
      const [project, file, ...rest] = typeof p === 'string' ? p.split('/') : [];
      if (rest.length > 0 || !project || !file || !HQ_PROJECT_RE.test(project) || !HQ_FILE_RE.test(file)) {
        refuse('Every path must be <project>/YYYY-MM-DD-<slug>.md (the HQ export layout: lower-case project folder, dated file name). Nothing was changed.');
      }
    }
    if (new Set(items.map((x) => x.path)).size !== items.length) refuse('A path appears twice in items; send each note once. Nothing was changed.');
    const itemSet = new Set(items.map((x) => x.path));
    if (deleted.some((p) => itemSet.has(p))) refuse('A path is both in items and in deleted; send it in one of them. Nothing was changed.');

    // The random name must pass the gates applied under it (export filter on staging/ and filtered/, the importer
    // on filtered/; seed wall): src/run-dir.ts.
    const work = gatedRunDir(join(this.root, 'runs'), 'sync-', runDirGate([seedWall()], this.root, [STAGING_DIR, FILTERED_DIR]), this.o.runName);
    try {
      const staging = freshDir(join(work, STAGING_DIR));
      const filtered = join(work, FILTERED_DIR);
      const projects = [...new Set(items.map((x) => x.path.split('/')[0]!))].sort();
      for (const p of projects) freshDir(join(staging, p));
      for (const x of items) writeFileSync(join(staging, x.path), x.text, { mode: 0o600, flag: 'wx' });
      let filterKept = 0;
      let withheldEntries = 0;
      if (items.length > 0) {
        const f = runExportFilter({ inDir: staging, outDir: filtered, projects });
        rmSync(staging, { recursive: true, force: true });
        withheldEntries = f.counts.entries_withheld;
        filterKept = f.counts.files_kept;
        if (f.status !== 'ok') refuse('The safety filter refused this batch as a whole. Nothing was changed. Remove the content Zeusi never stores and send it again.');
      }

      const db = await this.o.openWrite(c.tenantId);
      const profile = workspaceSyncProfile(c.tenantId);
      let locked = false;
      let route: WriteRoute = PLAIN_ROUTE;
      try {
        // C6 KTD3: the importer lock first, then the state, then all the work (import AND deletions) under it.
        if (!(await tryLockImporter(db, profile.importer))) refuse(WRITE_BUSY, 'busy');
        locked = true;
        route = await this.routeFor(c, db, 'sync', base);
        const u = await WorkspaceWrites.usage(db, route);
        try {
          WorkspaceWrites.assertRoom(u, { notes: items.length, bytes });
        } catch (e) {
          refuse((e as Error).message, 'too_large');
        }
        // The importer's deletion guard, on this workspace's own active HQ notes. Sealed (C6 KTD9): the path
        // is not readable in SQL; only HQ_PROFILE writes source_kind zeus_memory, so the kind alone counts them.
        const activeHq = Number((await db.query<{ n: number }>(route.kind === 'sealed'
          ? `SELECT count(*)::int AS n FROM zeusi.notes WHERE status = 'active' AND source_kind = 'zeus_memory'::zeusi.source_kind`
          : `SELECT count(*)::int AS n FROM zeusi.notes WHERE status = 'active' AND source_kind = 'zeus_memory'::zeusi.source_kind AND vault_path LIKE 'hq:%'`)).rows[0]?.n ?? 0);
        const limit = Math.max(DELETE_GUARD.min, Math.floor(DELETE_GUARD.fraction * activeHq));
        if (deleted.length > limit) {
          refuse(`Deletion guard: this batch would delete ${deleted.length} of ${activeHq} synced notes (limit ${limit}). Nothing was changed. Send fewer deletions per batch.`);
        }

        let imported = { inserted: 0, updated: 0, skipped: 0, quarantined: 0, errors: 0, chunks: 0 };
        if (items.length > 0 && filterKept > 0) {
          const config: SourcesConfig = {
            sources: projects.map((p) => ({ name: `workspace-sync-${p}`, kind: 'zeus_memory' as const, scope: WS_SCOPE, root: filtered, include: [`${p}/*.md`], exclude: [], project: p })),
            github: { org: '', repos: [], northbankRepos: [] },
          };
          const r = await importVault({
            db, config, mode: 'full', profile, home: this.root, host: WS_HOST, logPaths: false, ...(route.kind === 'sealed' ? { route } : {}),
          });
          if (r.status === 'locked') refuse(WRITE_BUSY, 'busy');
          if (r.status === 'failed') {
            this.audit(c, 'sync', 'failed', { ...base, errors: r.counts.errors });
            throw new WorkspaceWriteRefused('The sync did not complete (a temporary problem). Notes already saved stay; send the same batch again.');
          }
          imported = {
            inserted: r.counts.inserted, updated: r.counts.updated, skipped: r.counts.skipped, quarantined: r.counts.quarantined,
            errors: r.counts.errors, chunks: r.counts.chunks_written,
          };
        }

        // Deletions: ONLY the listed paths, ONLY synced (hq:) notes of this workspace's own schema.
        let removed = 0;
        let notFound = 0;
        for (const p of deleted) {
          if (route.kind === 'sealed') {
            // C6 KTD9: by vault_path_hmac; the blanked body is sealed ('' under the note's own AAD); index lock + hook.
            const sr = route;
            try {
              const hit = await sealedTx(db, sr, async () => {
                const ids = (await db.query<{ id: number }>(
                  `SELECT id::int AS id FROM zeusi.notes WHERE vault_path_hmac = $1::bytea AND status = 'active'
                     AND source_kind = 'zeus_memory'::zeusi.source_kind FOR UPDATE`, [sr.key.indexHmac('vault_path', `${HQ_PROFILE.storedPrefix}${p}`)])).rows;
                for (const h of ids) {
                  const id = Number(h.id);
                  await db.query(`UPDATE zeusi.notes SET status = 'deleted', deleted_seen_at = now(), body_ct = $2::bytea WHERE id = $1`, [id, sr.key.seal('notes', 'body', id, '')]);
                  // C7 KTD8: the hook gets the ids it removed (exact index tombstones).
                  const gone = (await db.query<{ id: number }>(`DELETE FROM zeusi.chunks WHERE note_id = $1 RETURNING id::int AS id`, [id])).rows.map((r) => Number(r.id));
                  await sr.index.onNoteRemoved(db, id, gone);
                }
                return ids.length;
              });
              if (hit > 0) removed++;
              else notFound++;
            } catch (e) {
              if (e instanceof SealRefused) throw e;
              imported.errors++;
            }
            continue;
          }
          try {
            await db.exec('BEGIN');
            const hit = (await db.query<{ id: string }>(
              // The importer's deletion (status + chunks), and the stored text blanked so removed notes
              // never hold storage (a later sync of the same path rewrites it in full).
              `UPDATE zeusi.notes SET status = 'deleted', deleted_seen_at = now(), body = ''
                WHERE vault_path = $1 AND status = 'active' AND source_kind = 'zeus_memory'::zeusi.source_kind RETURNING id`, [`${HQ_PROFILE.storedPrefix}${p}`])).rows;
            for (const h of hit) await db.query(`DELETE FROM zeusi.chunks WHERE note_id = $1`, [h.id]);
            await db.exec('COMMIT');
            if (hit.length > 0) removed++;
            else notFound++;
          } catch {
            await db.exec('ROLLBACK').catch(() => {});
            imported.errors++;
          }
        }
        const counts = {
          inserted: imported.inserted, updated: imported.updated, unchanged: imported.skipped, quarantined: imported.quarantined,
          withheld_entries: withheldEntries, dropped_by_filter: items.length - filterKept, deleted: removed, deleted_not_found: notFound,
          chunks: imported.chunks, errors: imported.errors,
        };
        this.audit(c, 'sync', imported.errors > 0 ? 'partial' : 'ok', {
          ...base, notes: imported.inserted + imported.updated, unchanged: imported.skipped, quarantined: imported.quarantined,
          withheld: withheldEntries, dropped: counts.dropped_by_filter, deleted: removed, chunks: imported.chunks, errors: imported.errors,
        });
        return { status: imported.errors > 0 ? 'ok_partial' as const : 'ok' as const, saved: true as const, counts };
      } finally {
        if (locked) await unlockImporter(db, profile.importer).catch(() => {});
        if (route.kind === 'sealed') route.key.dispose();
        await db.close().catch(() => {});
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }

  /** Remove every pending preview and its files (shutdown, tests). */
  close(): void {
    for (const id of [...this.previews.keys()]) this.drop(id);
  }
}

/** Tenant id shape check for callers outside this module (re-export, one place). */
export const isWorkspaceId = (t: unknown): t is string => typeof t === 'string' && TENANT_ID_RE.test(t);
