// `zeusi workspaces delete <zt_id>` (docs/plans/2026-11-20-workspaces-delete.md U4; KTD2, KTD4, KTD7, KTD10, KTD12,
// KTD13): the refusal rules, the typed confirmation, the order of the OAuth file around the database transaction, the
// audit line and the output. Process concerns (argument parsing, .env.local, the admin service and its guards, stdin)
// stay in src/cli.ts and arrive as dependencies, so every rule here is tested without a process.
//
// Gates, in order. Every refusal: exit 2, one `refused` audit line; nothing is read before gate 1 passes.
//   1. the id      `work` (the reserved workspace), `zeusi` (its schema) and every non-workspace id: constant text.
//   2. the flags   --confirm, --i-took-a-snapshot and --i-know-this-is-main go with --apply only; --apply needs
//                  --i-took-a-snapshot (the drop cannot be undone: a snapshot or point-in-time restore is the way back).
//   3. confirm     with --apply: a --confirm that is not exactly the id, or no --confirm and no terminal.
//   4. preflight   (the CLI) .env.local, the admin service (user zeusi_tenant_admin, direct host), the main-branch guard.
//   5. typed       --apply without --confirm: the id typed once at the terminal, exactly.
//   6. the store   --apply needs the OAuth store file (KTD10: a missing file reads as an empty store, so on the wrong
//                  machine nothing would be revoked while the drop went ahead); a dry run reports it missing.
// Then the dry run (counts and names, exit 0) or the delete, in this order (KTD4; the file cannot join the transaction):
//   a. revokeTenant(id)   a crash after it leaves an intact workspace with no live grant
//   b. the transaction    TenantDirectory.deleteWorkspace; a failure rolls back, the grants stay revoked: exit 1, re-run.
//                         A COMMIT that did not complete (outcome unknown): the sweep of c still runs, exit 1, re-run.
//   c. revokeTenant(id)   again, for a grant minted between a and b; a failure here: exit 1 `partial`, re-run
// revokeTenant is called with the validated id only (never `team`), and the assistant tokens file is never opened.
// Output and audit: the validated id, names derived from it, constant catalog and login names, sanitised table names
// and numbers. Never a value, a token, a grant id, a subject, a host or a server error text. (A config refusal of the
// CLI preflight names the service and its file, as for every other command; never a host or a password.)

import { OAuthStoreError } from './mcp-oauth-store.ts';
import { assertTenantId, WORK_TENANT, TENANT_ID_RE, tenantRole } from './tenant-ddl.ts';
import {
  CONTROL_SCHEMA, deleteCountsOf, TENANT_RT_ROLE, TENANT_WR_ROLE, TenantBusy, TenantCommitUnknown, TenantError,
  type WorkspaceDbState, type WorkspaceDeleteCounts, type WorkspaceDeleteResult, type WorkspaceRoleState,
} from './tenants.ts';
import type { WsAuditCounts, WsAuditOutcome, WsAuditSink } from './workspace-audit.ts';

/** A refusal from a dependency (the CLI preflight): a constant text, printed as is. */
export class WorkspaceDeleteRefused extends Error {
  override name = 'WorkspaceDeleteRefused';
}

export interface WorkspaceDeleteArgs {
  /** The one positional argument, unvalidated (gate 1 validates it). */
  tenantId: string;
  apply: boolean;
  confirm: string | undefined;
  iTookASnapshot: boolean;
  iKnowThisIsMain: boolean;
  /** The OAuth store file (CLI --file, default /data/mcp-oauth.json, as `zeusi mcp-oauth`). */
  storePath: string;
}

export interface WorkspaceDeleteDirectory {
  deleteWorkspace(tenantId: string, o: { dryRun: boolean }): Promise<WorkspaceDeleteResult>;
}

/** The two OAuthStore methods this command uses (KTD11: one predicate behind both). */
export interface WorkspaceDeleteStore {
  countTenantGrants(tenant: string): number;
  revokeTenant(tenant: string): number;
}

export interface WorkspaceDeleteDeps {
  /** Gate 4 (CLI): offline checks; throws WorkspaceDeleteRefused to refuse. Returns the directory and warning lines. */
  preflight: (o: { apply: boolean; iKnowThisIsMain: boolean }) => { directory: WorkspaceDeleteDirectory; warnings: string[] };
  /** stdin is a terminal (the typed confirmation is possible). */
  interactive: boolean;
  /** Ask once at the terminal: the answer line without its terminator, or null (no answer). */
  ask: (question: string) => Promise<string | null>;
  /** Whether the store file exists (no read). */
  storeExists: (path: string) => boolean;
  /** Open (read and validate) the store; throws OAuthStoreError when it is not a valid store. */
  openStore: (path: string) => WorkspaceDeleteStore;
  audit: WsAuditSink;
  out: (line: string) => void;
  err: (line: string) => void;
}

const TEAM_SCHEMA = 'zeusi';
/** src/mcp-oauth-store.ts commit(): the store was held or changed by another writer; a retry is the answer. */
const STORE_BUSY_RE = /locked by another writer|changed on disk/;

/**
 * Gates 1-3 (KTD2, KTD7, KTD8): a constant refusal, or null. Pure, no I/O. The input is never echoed: only `team` and
 * `zeusi` are named (constants), and a valid id may be.
 */
export function deleteRefusal(a: Omit<WorkspaceDeleteArgs, 'storePath'>, interactive: boolean): string | null {
  if (a.tenantId === WORK_TENANT) return 'refused: work is the team workspace; it is never deleted';
  if (a.tenantId === TEAM_SCHEMA) return 'refused: zeusi is the zeusi schema; it is never deleted';
  if (typeof a.tenantId !== 'string' || !TENANT_ID_RE.test(a.tenantId)) return 'refused: not a workspace id (zt_ + 26 base32)';
  if (!a.apply) {
    if (a.confirm !== undefined) return 'refused: --confirm goes with --apply';
    if (a.iTookASnapshot) return 'refused: --i-took-a-snapshot goes with --apply';
    if (a.iKnowThisIsMain) return 'refused: --i-know-this-is-main goes with --apply';
    return null;
  }
  if (!a.iTookASnapshot) return 'refused: --apply needs --i-took-a-snapshot: take a Neon snapshot or branch of this database first';
  if (a.confirm !== undefined && a.confirm !== a.tenantId) return 'refused: --confirm does not match the workspace id; nothing changed';
  if (a.confirm === undefined && !interactive) return 'refused: --apply needs --confirm <zt_id> (or a terminal to type the id); nothing changed';
  return null;
}

function auditCounts(grants: number | null, c: WorkspaceDeleteCounts): WsAuditCounts {
  return { ...(grants === null ? {} : { grants }), tenants: c.tenants, members: c.members, key_wraps: c.keyWraps, schemas: c.schemas, roles: c.roles, rows: c.rows };
}

const nothingIn = (grants: number, c: WorkspaceDeleteCounts) => grants + c.tenants + c.members + c.keyWraps + c.schemas + c.roles === 0;

/** The text of a database failure: TenantError texts are constants with a SQLSTATE at most (src/tenants.ts deleteError). */
const failureText = (e: unknown, what: string) => (e instanceof TenantError ? e.message : `${what} failed`);

/** Run the command: the exit code (0 done / nothing to do, 1 runtime failure, 2 refused). Exactly one audit line. */
export async function runWorkspaceDelete(a: WorkspaceDeleteArgs, d: WorkspaceDeleteDeps): Promise<number> {
  const audit = (outcome: WsAuditOutcome, counts?: WsAuditCounts) => d.audit({
    requestId: null, subject: null, tenantId: a.tenantId, grantId: null, action: 'workspace_delete', outcome, counts,
  });
  const say = (line: string) => d.err(`workspaces delete: ${line}`);
  const refuse = (why: string) => {
    say(why);
    audit('refused');
    return 2;
  };
  const why = deleteRefusal(a, d.interactive);
  if (why !== null) return refuse(why);
  const id = a.tenantId;

  let directory: WorkspaceDeleteDirectory;
  try {
    const p = d.preflight({ apply: a.apply, iKnowThisIsMain: a.iKnowThisIsMain });
    directory = p.directory;
    for (const w of p.warnings) d.err(w);
  } catch (e) {
    if (e instanceof WorkspaceDeleteRefused) return refuse(e.message);
    say('the preflight failed; nothing changed');
    audit('failed');
    return 1;
  }

  if (a.apply && a.confirm === undefined) {
    let typed: string | null;
    try {
      typed = await d.ask(`Type the workspace id to delete ${id} and everything in it: `);
    } catch {
      typed = null;
    }
    if (typed !== id) return refuse('refused: the typed id does not match; nothing changed');
  }

  const exists = d.storeExists(a.storePath);
  if (a.apply && !exists) {
    return refuse('refused: --apply needs the OAuth store file (--file): without it no grant would be revoked; '
      + 'run it on the hosted machine as the user that owns the store');
  }
  let store: WorkspaceDeleteStore | null = null;
  if (exists) {
    try {
      store = d.openStore(a.storePath);
    } catch (e) {
      return refuse(e instanceof OAuthStoreError ? `refused: ${e.message}` : 'refused: the OAuth store could not be opened');
    }
  }

  if (!a.apply) {
    let grants: number | null = null;
    if (store) {
      try {
        grants = store.countTenantGrants(id);
      } catch (e) {
        return refuse(e instanceof OAuthStoreError ? `refused: ${e.message}` : 'refused: the OAuth store could not be read');
      }
    }
    let r: WorkspaceDeleteResult;
    try {
      r = await directory.deleteWorkspace(id, { dryRun: true });
    } catch (e) {
      say(failureText(e, 'workspace delete dry run'));
      audit(e instanceof TenantBusy ? 'busy' : 'failed');
      return 1;
    }
    for (const line of formatDeleteDryRun(r, grants)) d.out(line);
    audit('dry_run', auditCounts(grants, deleteCountsOf(r.before)));
    return 0;
  }

  // a. Revoke first: from here on no grant of this workspace authenticates, whatever happens next.
  let first: number;
  try {
    first = store!.revokeTenant(id);
  } catch (e) {
    const busy = e instanceof OAuthStoreError && STORE_BUSY_RE.test(e.message);
    say(busy ? 'the OAuth store is busy (another writer); nothing changed, retry' : 'the OAuth store could not be written; nothing changed');
    audit(busy ? 'busy' : 'failed');
    return 1;
  }
  // b. The one database transaction (KTD3).
  let r: WorkspaceDeleteResult;
  try {
    r = await directory.deleteWorkspace(id, { dryRun: false });
  } catch (e) {
    say(failureText(e, 'workspace delete'));
    if (e instanceof TenantCommitUnknown) {
      // The workspace may be gone already: sweep a grant minted meanwhile (revoking again is always safe here).
      let late = 0;
      try {
        late = store!.revokeTenant(id);
      } catch { /* the next --apply sweeps */ }
      say(`${first + late} OAuth grant(s) of ${id} were revoked; whether the database part committed is unknown. Run the dry run to see what is left, then re-run --apply.`);
      audit('failed', { grants: first + late });
      return 1;
    }
    say(`${first} OAuth grant(s) of ${id} were revoked before the database step; the database is unchanged. Fix the cause, then re-run --apply.`);
    audit(e instanceof TenantBusy ? 'busy' : 'failed', { grants: first });
    return 1;
  }
  // c. Revoke again: a sign-in that minted a grant between a and b.
  let second: number;
  try {
    second = store!.revokeTenant(id);
  } catch {
    say(`${id} was removed from the database, but the final OAuth grant sweep failed (the store was busy or not writable); re-run --apply to sweep it.`);
    audit('partial', auditCounts(first, r.removed));
    return 1;
  }
  const grants = first + second;
  for (const line of formatDeleteApplied(r, grants)) d.out(line);
  audit(nothingIn(grants, r.removed) ? 'empty' : 'ok', auditCounts(grants, r.removed));
  return 0;
}

function schemaLine(id: string, st: WorkspaceDbState): string {
  if (!st.schema) return `  schema ${id}: absent`;
  const listed = st.tables.filter((t) => t.rows === null || t.rows > 0).map((t) => `${t.table} ${t.rows ?? 'unreadable'}`);
  return `  schema ${id}: present, ${st.tables.length} tables, ${st.rows} rows${listed.length > 0 ? ` (${listed.join(', ')})` : ''}`;
}

function roleLine(id: string, r: WorkspaceRoleState): string {
  if (!r.exists) return `  role ${r.role}: absent`;
  const login = r.role === tenantRole(id) ? TENANT_RT_ROLE : TENANT_WR_ROLE;
  return `  role ${r.role}: present; held by ${login} ${r.held ? 'yes' : 'no'}; other memberships ${r.otherMemberships}; provisioner ADMIN option `
    + (r.admin ? 'yes' : 'no (--apply fails with SQLSTATE 42501 until the owner grants it back)');
}

/** `; N table(s) not counted (unreadable)` when the provisioner could not count every table, else nothing. */
function unreadable(st: WorkspaceDbState): string {
  const n = st.tables.filter((t) => t.rows === null).length;
  return n > 0 ? `; ${n} table(s) not counted (unreadable)` : '';
}

/** The dry-run report (R10): what a delete would remove. Names derived from the id, constant names and numbers only. */
export function formatDeleteDryRun(r: WorkspaceDeleteResult, grants: number | null): string[] {
  const id = r.tenantId;
  assertTenantId(id);
  const st = r.before;
  const w = deleteCountsOf(st);
  // Without the store the grant count is unknown: never "nothing (already gone)" then.
  const nothing = grants !== null && nothingIn(grants, w);
  const noDb = nothingIn(0, w);
  return [
    `workspace ${id}: dry run, nothing changed`,
    grants === null
      ? '  OAuth store file missing: --apply refuses without it (run it on the hosted machine as the user that owns the store)'
      : `  OAuth grants to revoke: ${grants}`,
    `  catalog ${CONTROL_SCHEMA}: tenants ${st.tenants}, members ${st.members}, key_wraps ${st.keyWraps}`,
    schemaLine(id, st),
    ...st.roles.map((x) => roleLine(id, x)),
    nothing ? '  would remove: nothing (already gone)'
      : grants === null && noDb ? '  would remove: no database objects; OAuth grants unknown (the store file is missing)'
        : `  would remove: OAuth grants ${grants ?? 'unknown'}, catalog rows ${w.tenants + w.members + w.keyWraps}, schemas ${w.schemas}, roles ${w.roles}, rows ${w.rows}`,
    ...(nothing ? [] : [`  to delete it: take a Neon snapshot or branch first, then run: zeusi workspaces delete ${id} --apply --confirm ${id} --i-took-a-snapshot`]),
  ];
}

/** The report of a committed delete: what the transaction removed and how many grants were revoked. */
export function formatDeleteApplied(r: WorkspaceDeleteResult, grants: number): string[] {
  const id = r.tenantId;
  assertTenantId(id);
  const x = r.removed;
  if (nothingIn(grants, x)) return [`workspace ${id}: nothing left to delete (already gone); OAuth grants revoked 0`];
  const roles = r.before.roles.filter((q) => q.exists).map((q) => q.role);
  return [
    `workspace ${id}: deleted`,
    `  OAuth grants revoked: ${grants}`,
    `  catalog ${CONTROL_SCHEMA} rows removed: tenants ${x.tenants}, members ${x.members}, key_wraps ${x.keyWraps}`,
    x.schemas > 0 ? `  schema ${id} dropped (${r.before.tables.length} tables, ${x.rows} rows${unreadable(r.before)})` : `  schema ${id}: already absent`,
    roles.length > 0 ? `  roles dropped: ${roles.join(', ')}` : '  roles: already absent',
  ];
}
