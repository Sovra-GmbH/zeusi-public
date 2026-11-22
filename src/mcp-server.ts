// Zeusi MCP connector (docs/mcp.md): a model-agnostic MCP server built on the official SDK.
// Six tools, plus short aliases (startup, search, log_decision, context_for_task, prime, onboarding_status)
// registered with the SAME config and handler as their zeusi_* tool (TOOL_ALIASES). Every one of
// them goes through the gates below and the output wall (src/mcp-wall.ts). Canonical skill text:
// skills/zeusi-startup. What Zeusi is: src/about.ts (instructions, zeusi://about, search `about`).
//
//   zeusi_startup          READ-ONLY. Every current standing rule (facts_current kind rule + the
//                          CURRENT lock items of the standing notes: src/note-locks.ts,
//                          src/lock-lifecycle.ts), served compact within a token budget or listed
//                          in rules_remainder (src/startup-rules.ts), current focus (facts_current
//                          kind state; an empty focus is said out loud) and decisions_current from
//                          the last N days (with their links: src/decision-links.ts).
//   zeusi_context_for_task READ-ONLY. "Speaks up first": the current decisions, locks and parked
//                          items that apply to a task (src/context-for-task.ts), plus matching note
//                          locks (src/note-locks.ts), ranked, cited, conflicts (decisions only)
//                          flagged, walled items counted; never echoes the task text.
//   zeusi_search           READ-ONLY. The existing search() (src/search.ts): RLS, the read-only
//                          session check, BEGIN READ ONLY, the scope and limit caps. Chunk hits in
//                          `hits`; current decisions (always lexical) in `decisions`, each with
//                          type "decision" and cite; both lists pass the same output wall. Plus
//                          the code-shipped about entries in `about` (builtin, no database row).
//                          `hybrid` defaults to true (Fix PR A): the full-text branch always runs,
//                          so chunks without an embedding stay findable when a key is set.
//   zeusi_log_decision     WRITE. Into the existing zeusi.decisions table (src/decisions.ts), as
//                          zeusi_box_decision (preferred, migrations/0012, NOT applied yet) or the
//                          transitional zeusi_box_rw, through its own service (default none: the
//                          connector is read-only unless --write-service / ZEUSI_MCP_WRITE_SERVICE is set;
//                          without one, or for a read token class, the tool is not registered at all).
//   zeusi_search_feedback  LOCAL ledger only (src/feedback.ts): "did this hit answer it?".
//   zeusi_onboarding_status READ-ONLY. First run (src/onboarding.ts): capped counts of what this
//                          connection can see (facts, notes, note locks, chunks, decisions), no
//                          row text; when empty, the CLI commands the user runs (dry run first).
//
// Read gate (startup, context_for_task, search, onboarding_status), before anything connects: ZEUSI_TRANSPORT is valid, and the
// read service's user= (offline parse of the service file) is a read-only login
// (zeusi_box_ro / zeusi_cloud_ro). Then the existing connectReadOnly (TCP by default,
// ZEUSI_TRANSPORT=serverless -> the existing wss transport, which itself allows only those
// two logins). Then the session is checked live (assertReadOnlySession: no superuser, no
// write privilege on any zeusi table).
//
// Write gate (log_decision), in this order, and nothing before step 5 reads a secret:
//   1. a write service is configured, else refused (read-only connector; defence in depth: the
//      tool is not registered without one);
//   2. that service's user= is one of WRITE_ROLES (offline parse): zeusi_box_decision, or the
//      transitional zeusi_box_rw. Any *_ro login, the ingest / backup logins and the owner are
//      refused;
//   3. ZEUSI_TRANSPORT is unset (the serverless auth exception is for read-only roles only);
//   4. the arguments are valid and pass the wall (refused, never echoed, if not);
//   5. only now connectService (the password is read here, TCP, channel binding required);
//   6. the live session must be current_user = that same configured user (one of WRITE_ROLES),
//      not superuser, with INSERT on zeusi.decisions; else refused before any INSERT.

import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { asPgError, connectService, type Db } from './db.ts';
import { DECISION_KINDS, DECISION_SCOPES, insertDecision, WHO_HANDLE_RE } from './decisions.ts';
import { createOpenAIClient, OPENAI_KEY_ENV, type EmbeddingsClient } from './embeddings.ts';
import { copiesText, defaultFeedbackPath, FEEDBACK_REASON_MAX, recordFeedback, recordWorkspaceFeedback } from './feedback.ts';
import type { SecurityRunner } from './keychain.ts';
import { defaultServeCheck, guardString, safeMessage, wallFilter, withheld, stringsOf, type ServeCheck } from './mcp-wall.ts';
import {
  ABOUT_SUMMARY, ABOUT_URI, aboutSections, CONTEXT_NOT_PERMISSION, FILL_MEMORY_LINE, fillMemoryLine, ICON_PNG_URL, ICON_SVG_URL,
  NO_WRITE_LINE, PERSONAL_DECISIONS_HANDLE, PERSONAL_DECISIONS_PENDING, PERSONAL_WRITE_LINE,
  RECONNECT_TO_FILL, RULES_HOWTO, SERVER_DESCRIPTION, SERVER_TITLE, SITE_URL,
  personalAboutSections, SOURCES_OF_RULES_FACTS_FOCUS, WELCOME_MARKDOWN, welcomeMarkdown, WORKSPACE_UNAVAILABLE,
} from './about.ts';
import {
  CONFLICT_HINT, contextItemJson, DEFAULT_CONTEXT_LIMIT, findConflicts, MAX_CONTEXT_LIMIT, MAX_TASK_CHARS, NOTHING_FOUND,
  rankForTask, taskTerms, type ContextItem,
} from './context-for-task.ts';
import { registerPromptsAndResources } from './mcp-prompts.ts';
import {
  CANNOT_RUN_IT, FILL_STEPS, FOCUS_EMPTY_WHY, onboardingJson, PERSONAL_WORKSPACE_NOTE, PERSONAL_WORKSPACE_NOTE_FILL, RULES_DEFINITION,
} from './onboarding.ts';
import { canInsertLinks, LINK_TARGET_SHAPES, linkTargetKind, linksOf, MAX_LINK_URI, MAX_LINKS, serveWithLinks } from './decision-links.ts';
import { BUDGET_ESTIMATE, COMPACT_TEXT_MAX_CHARS, factRuleId, oneLine, planStartupRules, rulesNote, STARTUP_RULES_BUDGET_TOKENS, type StartupRule } from './startup-rules.ts';
import { currentStandingLocks, lockHistoryJson, lockItemJson, lockRuleJson, lockStartupRule, rankLocksForTask, type LockHistoryItem, type LockItem } from './note-locks.ts';
import { PLAIN_READ, ReadRouteRefused, sqlReadSource, type ReadRoute, type ReadSource } from './read-route.ts';
import { sealedReadSource } from './sealed-read.ts';
import {
  assertReadOnlySession, decisionJson, defaultLedgerPath, MAX_LIMIT, QueryLedger, search, SEARCH_SCOPES,
  type SearchOptions, type SearchResult,
} from './search.ts';
import { resolveService } from './service.ts';
import { TenantError, TenantRefused } from './tenants.ts';
import {
  PREVIEW_ID_RE, WORKSPACE_WRITE_CAPS, WorkspaceWriteRefused, WRITES_OFF, type PreviewDocument, type WorkspaceCaller, type WorkspaceWrites,
} from './workspace-write.ts';
import {
  connectReadOnly, resolveTransport, SERVERLESS_ROLES, SERVERLESS_VALUE, TRANSPORT_ENV, type ReadOnlyConnectOptions,
} from './transport.ts';

export const TOOL_NAMES = [
  'zeusi_startup', 'zeusi_search', 'zeusi_log_decision', 'zeusi_search_feedback', 'zeusi_context_for_task', 'zeusi_onboarding_status',
] as const;
/** Short names some clients / prompts use. Same input schema, same handler, same gates and walls. */
export const TOOL_ALIASES = {
  startup: 'zeusi_startup', search: 'zeusi_search', log_decision: 'zeusi_log_decision',
  context_for_task: 'zeusi_context_for_task', prime: 'zeusi_context_for_task', onboarding_status: 'zeusi_onboarding_status',
} as const;
/** Every name the server lists: the zeusi_* tools first, then the aliases. */
export const ALL_TOOL_NAMES: readonly string[] = [...TOOL_NAMES, ...Object.keys(TOOL_ALIASES)];
/**
 * Own-workspace write tools (docs/plans/2026-11-18-workspace-write-import-plan.md KTD7). Registered
 * ONLY on a personal connection whose grant has zeusi.workspace_write; never on a team connection,
 * a static bearer token or a read-only personal grant (the hosted handler refuses them first, 403).
 * No aliases.
 */
export const WORKSPACE_WRITE_TOOL_NAMES = ['zeusi_import_preview', 'zeusi_import_commit', 'zeusi_sync_batch'] as const;
/** The preferred login zeusi_log_decision writes as (migrations/0012, group zeusi_decision_write). */
export const WRITE_ROLE = 'zeusi_box_decision';
/** Transitional fallback until the owner applies 0012 and sets its password (docs/roles.md). */
export const TRANSITIONAL_WRITE_ROLE = 'zeusi_box_rw';
/** The only logins zeusi_log_decision writes as. Nothing else (no *_ro, ingest, backup, owner). */
export const WRITE_ROLES: readonly string[] = [WRITE_ROLE, TRANSITIONAL_WRITE_ROLE];
/** The only logins the read tools run as (same list as the serverless transport). */
export const READ_ROLES: readonly string[] = SERVERLESS_ROLES;
export const WRITE_SERVICE_ENV = 'ZEUSI_MCP_WRITE_SERVICE';
export const DEFAULT_DECISION_DAYS = 14;
export const MAX_DECISION_DAYS = 90;
/**
 * focus / decisions: at most this many served. Rules have NO item cap: every current standing rule
 * is served within STARTUP_RULES_BUDGET_TOKENS or listed in rules_remainder (src/startup-rules.ts).
 */
export const STARTUP_CAPS = { focus: 20, decisions: 50 } as const;
/** Focus rows read per call (newest first) before keeping the newest per (scope, subject). */
export const FOCUS_READ_FACTOR = 10;
/** The fact-rule total startup reports is counted over at most this many rows (LIMIT cap+1). */
export const STARTUP_TOTAL_CAP = 10_000;
/** Said when no focus is visible: honest about the gap and where focus would come from, never "there is no focus". */
export const NO_FOCUS_MESSAGE = FOCUS_EMPTY_WHY;
/** zeusi_search runs hybrid unless the caller passes hybrid: false (Fix PR A). */
export const DEFAULT_SEARCH_HYBRID = true;
/** query ids kept in memory for feedback (hit uris + texts, never written anywhere). */
export const QUERY_MEMORY = 256;
/** The search the connector uses: the existing export, not a reimplementation. */
export const DEFAULT_SEARCH_FN = search;

/**
 * The MCP `instructions` for a connection (F4): they name only tools this connection lists.
 * canWrite = zeusi_log_decision is registered (non-read token class AND a write service). A read
 * connection gets one honest line instead and never sees the write tool's name. F5: a returned
 * decision is context, not permission.
 */
export function mcpInstructions(canWrite: boolean, workspace: 'team' | 'personal' = 'team', canFill = false): string {
  const fill = workspace === 'personal' && canFill;
  return [
    ...(workspace === 'personal'
      ? [fill ? PERSONAL_INSTRUCTIONS_LEAD_FILL : PERSONAL_INSTRUCTIONS_LEAD, fill ? PERSONAL_WORKSPACE_NOTE_FILL : PERSONAL_WORKSPACE_NOTE, 'Use it like this, every session:']
      : [ABOUT_SUMMARY, 'Zeusi is the team\'s sourced memory (rules, focus, decisions, notes). Use it like this, every session:']),
    '1. At session start, call zeusi_startup once and follow the standing rules, current focus and recent decisions it returns.',
    '2. At the start of every task, call zeusi_context_for_task with a short description of the work. Treat returned locks and stops as binding unless the owner overrides them, respect parked items, cite each item you use, and ask the owner about any listed conflict. An empty list means Zeusi has nothing that applies: say so, never invent one.',
    '3. Before answering the user, and before asking the owner anything, call zeusi_search first. Cite every hit you rely on by its source_uri and source_ts (add scope and heading_path when useful). If no hit answers the question, say so, then ask.',
    '4. After using a hit, call zeusi_search_feedback with the query_id, the hit source_uri and whether it answered the question.',
    canWrite
      ? '5. Call zeusi_log_decision only for a decision the owner actually made, with its real source (invent=NO).'
      : fill
        ? `5. Write only into this workspace and only with the user's yes: zeusi_import_preview first (nothing is saved), then zeusi_import_commit with confirm: true. ${PERSONAL_WRITE_LINE}`
        : NO_WRITE_LINE,
    `${CONTEXT_NOT_PERMISSION} Locks and stops still limit what you do; no decision widens it.`,
    'Zeusi cannot force you to call a tool; it can only ask. Following these steps is how you avoid breaking a lock or redoing parked work.',
    'Walled content is never returned; an omitted item is counted in "withheld", never paraphrased.',
    workspace === 'personal'
      ? fill
        ? `First run: if zeusi_onboarding_status says empty, tell the user this personal workspace is empty and offer to fill it. ${FILL_STEPS}`
        : 'First run: if zeusi_onboarding_status says empty, tell the user this personal workspace is empty; importing into it is not available yet.'
      : `First run: if zeusi_onboarding_status says empty, offer the onboarding prompt; the import is a CLI the user runs. ${CANNOT_RUN_IT}`,
    `Aliases: startup = zeusi_startup, search = zeusi_search, ${canWrite ? 'log_decision = zeusi_log_decision, ' : ''}context_for_task = prime = zeusi_context_for_task, onboarding_status = zeusi_onboarding_status (same tools). Prompts: start-task, onboarding.`,
  ].join('\n');
}

/** The first line for a personal-workspace connection that can fill its workspace (KTD9). */
export const PERSONAL_INSTRUCTIONS_LEAD_FILL =
  'Zeusi is a model-agnostic, sourced memory (rules, focus, decisions, notes), each item with its source. A decision is context, not permission. '
  + `Reads this workspace; writes only into it, only after a preview the user approves; invent=NO. Full description: resource ${ABOUT_URI}.`;
/** The first line for a personal-workspace connection (open sign-up): no team-workspace description. */
export const PERSONAL_INSTRUCTIONS_LEAD =
  'Zeusi is a model-agnostic, sourced memory (rules, focus, decisions, notes), each item with its source. A decision is context, not permission. '
  + `Read-only on this connection; invent=NO. Full description: resource ${ABOUT_URI}.`;

// First-run empty states of a PERSONAL workspace (docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md
// U4): say what is empty and what to do next; never an error, never invented content.
const ASK_ABOUT = `Ask "What can Zeusi do?" (resource ${ABOUT_URI}) for what Zeusi is and does.`;
/** zeusi_startup on an empty personal workspace (with `welcome`). */
export const STARTUP_EMPTY_PERSONAL =
  'Your workspace is empty: no rules, locks, focus or decisions yet. That is normal for a new workspace. '
  + `Show the user the welcome below, say plainly that there is nothing to follow yet, and never invent rules. ${ASK_ABOUT} ${FILL_MEMORY_LINE}`;
/**
 * zeusi_startup on a personal workspace that holds notes (or other items) but no rule yet (live finding
 * 2026-11-18: imported notes were reported as "empty"). Says what is there, that nothing binds yet, and
 * how a rule and a decision come about (src/about.ts RULES_HOWTO, decision-format section).
 */
export function startupNoRulesMessage(notes: number, notesCapped: boolean, decisions: number, knowsPerson = false): string {
  const n = `${notes}${notesCapped ? '+' : ''} note${notes === 1 && !notesCapped ? '' : 's'}`;
  return `I have ${n} from your imports; no rules${decisions === 0 ? ' or decisions' : ''} yet, so there is nothing standing to follow. `
    + 'Search the notes with zeusi_search and cite them; never invent rules or decisions. '
    + `${RULES_HOWTO} A decision comes from a decision-log entry in the exact format in ${ABOUT_URI}#decision-format; the import preview says why an entry stays a note. `
    // Only what this workspace can do: its own person `me` is checked (src/tenants.ts WORKSPACE_PERSON_HANDLE).
    + (knowsPerson ? PERSONAL_DECISIONS_HANDLE : PERSONAL_DECISIONS_PENDING);
}
/** zeusi_search in a personal workspace with no note or decision hit. */
export const SEARCH_EMPTY_PERSONAL =
  'Nothing in your workspace matches this search (no notes or decisions found). If your workspace is new, it is still empty. '
  + `Say so plainly and never invent an answer. ${ASK_ABOUT} ${FILL_MEMORY_LINE}`;
/** zeusi_context_for_task in a personal workspace with nothing that applies. */
export const CONTEXT_EMPTY_PERSONAL =
  'Nothing in your workspace applies to this task (no decisions or locks found). If your workspace is new, it is still empty. '
  + `Nothing was invented: proceed, and ask the user if a decision is needed. ${FILL_MEMORY_LINE}`;
/** The three empty-state messages for a connection (form B only when it can fill, KTD9). */
export function personalEmptyStates(canFill: boolean): { startup: string; search: string; context: string } {
  if (!canFill) return { startup: STARTUP_EMPTY_PERSONAL, search: SEARCH_EMPTY_PERSONAL, context: CONTEXT_EMPTY_PERSONAL };
  const b = fillMemoryLine(true);
  return {
    startup: STARTUP_EMPTY_PERSONAL.replace(FILL_MEMORY_LINE, b),
    search: SEARCH_EMPTY_PERSONAL.replace(FILL_MEMORY_LINE, b),
    context: CONTEXT_EMPTY_PERSONAL.replace(FILL_MEMORY_LINE, b),
  };
}
/** zeusi_search_feedback with a query_id or source_uri this connection does not know. */
export const FEEDBACK_NOT_FOUND_PERSONAL =
  'not found in your workspace (feedback is accepted only for a zeusi_search or zeusi_context_for_task result of this connection, using its query_id and one of its source_uri values). '
  + 'Run the search again and use the query_id it returns. Nothing recorded.';

/** The write-capable instructions (docs, tests). Each connection is served mcpInstructions(canWrite). */
export const MCP_INSTRUCTIONS = mcpInstructions(true);

export class ToolRefused extends Error {
  override name = 'ToolRefused';
}

export interface McpDeps {
  env: NodeJS.ProcessEnv;
  home?: string | undefined;
  /** Service for startup/search (default zeusi_ro). */
  readService: string;
  /** Service for zeusi_log_decision. Unset: the connector is read-only. */
  writeService?: string | undefined;
  defaultDays?: number | undefined;
  /** TEST seam: replaces connectReadOnly (the read gate still runs first). */
  connectRead?: ((service: string) => Promise<Db>) | undefined;
  /** TEST seam: replaces connectService for the write role (the write gate still runs first). */
  connectWrite?: ((service: string) => Promise<Db>) | undefined;
  /** TEST seams handed to connectReadOnly (TCP / serverless client factories). */
  readOnlyOptions?: Pick<ReadOnlyConnectOptions, 'tcp' | 'serverlessClient'> | undefined;
  runSecurity?: SecurityRunner | undefined;
  /** Query embedding client; default: OpenAI when ZEUSI_OPENAI_API_KEY is set, else null (lexical). */
  embeddings?: (() => EmbeddingsClient | null) | undefined;
  searchFn?: ((o: SearchOptions) => Promise<SearchResult>) | undefined;
  feedbackPath?: string | undefined;
  queryLedgerPath?: string | undefined;
  now?: (() => Date) | undefined;
  /**
   * Hosted mode only (src/mcp-hosted.ts): the caller's token class. 'read' does not register
   * zeusi_log_decision / log_decision at all. Undefined (stdio, --http): as 'write'. In every
   * class the write tool is registered only when writeService is set as well (F4), and the
   * write gate below still decides whether a write can happen.
   */
  toolClass?: 'read' | 'write' | undefined;
  /** Hosted mode only: the caller's token_id. Binds feedback query_ids to the token that searched. */
  tokenId?: string | undefined;
  /** Hosted mode only: per-call counts for the allowlisted request log. Never text. */
  observe?: ((o: ToolObservation) => void) | undefined;
  /** TEST seam: the serve-time secret check (default: src/mcp-wall.ts serveSecretSignal). */
  serveCheck?: ServeCheck | undefined;
  /**
   * Hosted personal workspace only (open sign-up, src/mcp-hosted.ts): a fail-closed session bound to
   * exactly that workspace (src/tenants.ts TenantRouter.open). When set, EVERY read tool uses it
   * instead of the team read service, and the write tool is never registered.
   */
  tenantRead?: (() => Promise<Db>) | undefined;
  /** Which workspace this connection reads: 'personal' only together with tenantRead. Default 'team'. */
  workspace?: 'team' | 'personal' | undefined;
  /**
   * Hosted personal workspace with a zeusi.workspace_write grant only (src/mcp-hosted.ts): the caller
   * (tenant + grant from the principal, never the request) and the write service, or null when this
   * server has workspace writes off (the tools then answer WRITES_OFF; nothing is read or saved).
   */
  workspaceWrite?: { caller: WorkspaceCaller; writes: WorkspaceWrites | null } | undefined;
  /**
   * Hosted personal workspace with a READ-ONLY grant while this server can fill workspaces: the
   * onboarding status says how to upgrade (sign in again). Never enables a write.
   */
  workspaceWritesOn?: boolean | undefined;
  /**
   * C7 (docs/plans/2026-11-19-c7-read-path.md KTD1): hosted personal workspace only: this request's read route
   * (src/read-route.ts), computed once per request BEFORE the workspace session opens (the enc_state, and on the
   * sealed route this request's wrap proof). Throws ReadRouteRefused (served) or a TenantError (unavailable).
   * Unset (the team, stdio, --http): today's plain path.
   */
  readRoute?: (() => Promise<ReadRoute>) | undefined;
}

/** What a tool reports to the hosted request log: counts and an error class only. */
export interface ToolObservation {
  tool: (typeof TOOL_NAMES)[number] | (typeof WORKSPACE_WRITE_TOOL_NAMES)[number];
  hitCount: number;
  withheld: number;
  /** Items the serve-time secret guard withheld (detector, main floor, marker, guard error); a subset of withheld. Count only. */
  secretWithheld: number;
  error?: 'tool_refused' | 'tool_error';
}

interface QueryMemo {
  uris: Set<string>;
  texts: string[];
  /** Hosted mode: the token_id that ran the search (undefined for stdio / --http). */
  tokenId?: string | undefined;
  /** C7 KTD12: a sealed-route result: `uris` are memoUri() keyed hashes and `texts` is empty. */
  hashed?: boolean | undefined;
}

/** C7 KTD12: a random per-process key; the feedback memo of a sealed-route result keeps only HMACs of its uris. */
const MEMO_KEY = randomBytes(32);
export function memoUri(uri: string): string {
  return createHmac('sha256', MEMO_KEY).update(uri, 'utf8').digest('base64url');
}

/** C7 KTD12: drop the feedback memo entries of one grant (the OAuth store's session-end hook, src/mcp.ts). */
export function purgeQueries(state: McpState, tokenId: string): number {
  let n = 0;
  for (const [id, m] of [...state.queries.entries()]) if (m.tokenId === tokenId) {
    state.queries.delete(id);
    n++;
  }
  return n;
}

/** Shared across server instances of one process (stateless HTTP makes one server per request). */
export interface McpState {
  queries: Map<string, QueryMemo>;
  ledger: QueryLedger | undefined;
}

export function createMcpState(): McpState {
  return { queries: new Map(), ledger: undefined };
}

type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };

const ok = (v: unknown): ToolResult => ({ content: [{ type: 'text', text: JSON.stringify(v, null, 2) }] });
const fail = (e: unknown): ToolResult => {
  const pe = asPgError(e);
  const msg = pe.code ? `error [${pe.code}]: ${pe.message}` : pe.message;
  return { content: [{ type: 'text', text: safeMessage(msg) }], isError: true };
};

const iso = (v: unknown): string | null => (v === null || v === undefined ? null : new Date(v as string).toISOString());

/** zod objects that refuse unknown keys without echoing them. */
function strict<T extends z.ZodRawShape>(shape: T) {
  return z.strictObject(shape, { error: (iss) => (iss.code === 'unrecognized_keys' ? 'unexpected argument(s) refused' : undefined) });
}
const isoTs = () => z.iso.datetime({ offset: true });

export function createZeusiMcpServer(deps: McpDeps, state: McpState = createMcpState()): McpServer {
  const env = deps.env;
  const home = deps.home ?? homedir();
  const svcOpts = { env, home };
  const defaultDays = deps.defaultDays ?? DEFAULT_DECISION_DAYS;
  const searchFn = deps.searchFn ?? DEFAULT_SEARCH_FN;
  const serveCheck = deps.serveCheck ?? defaultServeCheck;
  const observe = (o: ToolObservation) => {
    try { deps.observe?.(o); } catch { /* the log hook never changes a tool result */ }
  };
  /**
   * fail() plus a count-only observation (hosted log). A personal workspace never sees an internal:
   * any failure that is not a deliberate refusal (router TenantError / TenantRefused, a session
   * check, a query error) becomes WORKSPACE_UNAVAILABLE (retry / reconnect, the one URL).
   */
  const failed = (tool: ToolObservation['tool'], e0: unknown): ToolResult => {
    // C7 KTD13: a read-route refusal (locked / changing) is a deliberate, served refusal.
    const e = e0 instanceof ReadRouteRefused ? new ToolRefused(e0.message) : e0;
    observe({ tool, hitCount: 0, withheld: 0, secretWithheld: 0, error: e instanceof ToolRefused ? 'tool_refused' : 'tool_error' });
    if (personal && !(e instanceof ToolRefused)) return { content: [{ type: 'text', text: WORKSPACE_UNAVAILABLE }], isError: true };
    return fail(e);
  };

  async function openRead(): Promise<Db> {
    // A personal workspace never falls back to the team read service: its own session or nothing.
    if (personal) return deps.tenantRead!();
    resolveTransport(env); // an invalid ZEUSI_TRANSPORT is refused here (no connection)
    const user = resolveService(deps.readService, svcOpts).user;
    if (!READ_ROLES.includes(user)) {
      throw new ToolRefused(`read tools run only as a read-only login (${READ_ROLES.join(', ')}); service ${deps.readService} is not one. No connection made.`);
    }
    if (deps.connectRead) return deps.connectRead(deps.readService);
    return connectReadOnly(deps.readService, { ...svcOpts, ...(deps.runSecurity ? { runSecurity: deps.runSecurity } : {}), ...(deps.readOnlyOptions ?? {}) });
  }

  /** Write gate steps 1-3 (offline, no secret read). Returns the service and its (allowed) user. */
  function writeGate(): { service: string; user: string } {
    if (!deps.writeService) {
      throw new ToolRefused(`this connector is read-only: no write service configured (--write-service / ${WRITE_SERVICE_ENV}). Nothing written.`);
    }
    const user = resolveService(deps.writeService, svcOpts).user;
    if (!WRITE_ROLES.includes(user)) {
      throw new ToolRefused(`zeusi_log_decision runs only ${WRITE_ROLE} (or, transitional, ${TRANSITIONAL_WRITE_ROLE}); service ${deps.writeService} is a different login (read-only or other). No credential read, nothing written.`);
    }
    if (resolveTransport(env) === 'serverless') {
      throw new ToolRefused(`zeusi_log_decision is refused with ${TRANSPORT_ENV}=${SERVERLESS_VALUE} (that transport is for read-only roles only); writes keep the TCP path. Nothing written.`);
    }
    return { service: deps.writeService, user };
  }

  // F4: the write tool is registered (and described) only when this connection can use it: not
  // a read token class (hosted read bearer, OAuth zeusi.read) and a write service is configured.
  // The write gate below still decides whether a write can actually happen.
  const personal = deps.workspace === 'personal' || deps.tenantRead !== undefined;
  if (personal && (deps.workspace !== 'personal' || deps.tenantRead === undefined)) {
    throw new ToolRefused('a personal workspace connection needs both its workspace session and workspace: personal');
  }
  if (deps.workspaceWrite && !personal) throw new ToolRefused('own-workspace writes exist only on a personal workspace connection');
  const workspace = personal ? 'personal' as const : 'team' as const;
  const canWrite = !personal && deps.toolClass !== 'read' && !!deps.writeService;
  // Form B (KTD9): only when filling really works on this connection (write grant AND writer on).
  const canFill = personal && !!deps.workspaceWrite?.writes;
  const fillState: 'on' | 'reconnect' | 'off' = canFill ? 'on' : personal && !deps.workspaceWrite && deps.workspaceWritesOn === true ? 'reconnect' : 'off';
  const empties = personalEmptyStates(canFill);
  const sections = personal ? personalAboutSections(canFill) : aboutSections(canWrite);
  const server = new McpServer({
    name: 'zeusi',
    version: '0.1.0',
    title: SERVER_TITLE,
    description: SERVER_DESCRIPTION,
    websiteUrl: SITE_URL,
    icons: [
      { src: ICON_PNG_URL, mimeType: 'image/png', sizes: ['512x512'] },
      { src: ICON_SVG_URL, mimeType: 'image/svg+xml', sizes: ['any'] },
    ],
  }, { instructions: mcpInstructions(canWrite, workspace, canFill) });
  registerPromptsAndResources(server, canWrite, serveCheck, workspace, canFill);

  /** C7 KTD1: this request's read route (personal hosted only; computed before the workspace session opens). */
  const readRoute = async (): Promise<ReadRoute> => (deps.readRoute ? deps.readRoute() : PLAIN_READ);
  /** C7 KTD10: the row source of one tool call on `db` for its route. */
  const sourceOf = (db: Db, route: ReadRoute): ReadSource => (route.kind === 'sealed' ? sealedReadSource(db, route) : sqlReadSource(db, searchFn));

  /**
   * Remember a result's uris + texts for zeusi_search_feedback (in memory only, bounded). C7 KTD12: on the
   * sealed route only keyed hashes of the uris and no text (copiesText cannot fire there).
   */
  const remember = (uris: string[], texts: string[], route: ReadRoute = PLAIN_READ): string => {
    const queryId = randomUUID();
    const sealed = route.kind === 'sealed';
    state.queries.set(queryId, sealed
      ? { uris: new Set(uris.map(memoUri)), texts: [], tokenId: deps.tokenId, hashed: true }
      : { uris: new Set(uris), texts, tokenId: deps.tokenId });
    while (state.queries.size > QUERY_MEMORY) state.queries.delete(state.queries.keys().next().value!);
    return queryId;
  };

  /** Register a zeusi_* tool and, if it has any, its aliases with the same config and handler. */
  const register: typeof server.registerTool = ((name: string, config: never, cb: never) => {
    const tool = server.registerTool(name, config, cb);
    for (const [alias, target] of Object.entries(TOOL_ALIASES)) {
      if (target !== name) continue;
      const c = config as { title?: string; description?: string };
      server.registerTool(alias, { ...(config as object), title: `${c.title ?? name} (alias of ${name})`, description: `Alias of ${name}. ${c.description ?? ''}` } as never, cb);
    }
    return tool;
  }) as never;

  register('zeusi_startup', {
    title: 'Zeusi startup',
    description: `Call once at session start. Returns EVERY current standing rule (recorded rules, and the CURRENT locks of the standing ops/meta notes or of notes that mark them standing_locks; superseded / expired locks are not rules): the top-ranked in compact one-line form in rules (within a token budget), every other one listed in rules_remainder with id, subject and cite (look it up with zeusi_context_for_task; it binds like a served rule), rules_total the full count; current focus, newest per subject (or a plain message saying why none is recorded) and the owner's decisions from the last N days (default ${defaultDays}, max ${MAX_DECISION_DAYS}), each with source_uri and source_ts. Read-only.`,
    inputSchema: strict({ days: z.number().int().min(1).max(MAX_DECISION_DAYS).optional() }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (args) => {
    try {
      const days = args.days ?? defaultDays;
      const route = await readRoute();
      const db = await openRead();
      try {
        const src = sourceOf(db, route);
        await assertReadOnlySession(db);
        await src.begin();
        try {
          const asFact = (r: Record<string, unknown>) => ({
            subject: r['subject'] ?? null, text: r['text'], scope: r['scope'], source_uri: r['source_uri'], source_ts: iso(r['source_ts']),
          });
          // Every current standing rule (plan 2026-11-18, U2): all fact rules (up to STARTUP_TOTAL_CAP)
          // and every CURRENT standing lock item (read-time supersession / expiry / standing marker:
          // src/lock-lifecycle.ts; who never invented). The output wall runs on the FULL items first,
          // then src/startup-rules.ts ranks them and splits served (compact, token budget) from
          // rules_remainder (listed with ids): none is dropped without being named.
          const factRows = await src.factRules(STARTUP_TOTAL_CAP + 1);
          const factCapped = factRows.length > STARTUP_TOTAL_CAP;
          const factRules = factRows.slice(0, STARTUP_TOTAL_CAP).map((r): StartupRule => ({
            origin: 'fact', id: factRuleId(String(r['source_uri']), String(r['id'])), subject: (r['subject'] as string | null) ?? null, text: String(r['text']),
            scope: String(r['scope']), source_uri: String(r['source_uri']), source_ts: iso(r['source_ts']) ?? '',
          }));
          const lc = await src.lockLifecycle(deps.now?.() ?? new Date());
          const standing = currentStandingLocks(lc.locks);
          // `served` = the exact text the compact form serves (whitespace collapsed): the wall and the secret
          // check see it too, so a pattern that only matches once a newline becomes a space is still withheld.
          const candidates = [
            ...factRules.map((rule) => ({ rule, view: rule, served: oneLine(rule.text) })),
            ...standing.map((l) => { const rule = lockStartupRule(l); return { rule, view: lockRuleJson(l), served: oneLine(rule.text) }; }),
          ];
          const R = wallFilter(candidates, serveCheck);
          const rulesPlan = planStartupRules(R.kept.map((c) => c.rule));
          const rulesTotal = {
            fact: factRules.length, note_lock: standing.length, total: factRules.length + standing.length,
            visible: R.kept.length, capped: factCapped || lc.capped,
          };
          // Focus: newest per (scope, subject) (plan U6, KTD10). ingest cannot supersede a fact yet, so an
          // older focus row with the same subject is counted, not served as current; a null subject stands alone.
          // The output wall runs on EVERY row read first (withheld counts stay exact); a withheld newest row
          // still hides its older same-subject rows (an older focus is never promoted to current).
          const focusRows = (await src.facts('state', STARTUP_CAPS.focus * FOCUS_READ_FACTOR)).map(asFact);
          const F = wallFilter(focusRows, serveCheck);
          const keptFocus = new Set(F.kept);
          const seenFocus = new Set<string>();
          const focus: typeof focusRows = [];
          let focusOlder = 0;
          for (const f of focusRows) {
            const k = f.subject === null ? null : JSON.stringify([f.scope, f.subject]);
            if (k !== null && seenFocus.has(k)) {
              if (keptFocus.has(f)) focusOlder++;
              continue;
            }
            if (k !== null) seenFocus.add(k);
            if (keptFocus.has(f) && focus.length < STARTUP_CAPS.focus) focus.push(f);
          }
          const decisionRows = await src.recentDecisions(days, STARTUP_CAPS.decisions);
          // 0013 links (RLS as the caller; [] when the table does not exist yet).
          const linkMap = await src.decisionLinks(decisionRows.map((r) => Number(r['id'])));
          const decisions = decisionRows.map((r) => ({
            kind: r['kind'], who: r['who'] ?? null, said_at: iso(r['said_at']), exact_words: r['exact_words'],
            exact_words_verbatim: r['exact_words_verbatim'], applies_to: r['applies_to'] ?? [], expires_at: iso(r['expires_at']),
            scope: r['scope'], source_uri: r['source_uri'], source_ts: iso(r['source_ts']), ...linksOf(r, linkMap.get(Number(r['id']))),
          }));
          // Each link is guarded on its own (a walled link is dropped and counted), then the decision whole.
          const D = serveWithLinks(decisions, serveCheck);
          // Personal workspaces only (the team path runs no extra query and its output is unchanged).
          // Empty = the ONE rule shared with zeusi_onboarding_status (src/onboarding.ts emptinessCounts):
          // no fact, note, chunk or decision. Imported notes without a rule are NOT empty (live finding 2026-11-18).
          const ws = personal ? await src.emptiness(null) : null;
          const emptyPersonal = ws !== null && ws.empty;
          const noRulesPersonal = ws !== null && !ws.empty && ws.counts.notes > 0 && rulesTotal.total === 0;
          // Personal path only, and only for that message: does the workspace know its own person (`me`)?
          const knowsPerson = noRulesPersonal ? await src.knowsPerson() : false;
          observe({
            tool: 'zeusi_startup', hitCount: rulesPlan.served.length + focus.length + D.kept.length, withheld: R.withheld + F.withheld + D.withheld,
            secretWithheld: R.secretWithheld + F.secretWithheld + D.secretWithheld,
          });
          return ok({
            ...(emptyPersonal ? { workspace: 'personal', empty: true, message: empties.startup, welcome: canFill ? welcomeMarkdown(fillMemoryLine(true)) : WELCOME_MARKDOWN } : {}),
            ...(noRulesPersonal ? {
              workspace: 'personal', empty: false, notes: ws.counts.notes, ...(ws.capped.notes ? { notes_capped: true } : {}),
              message: startupNoRulesMessage(ws.counts.notes, ws.capped.notes, ws.counts.decisions, knowsPerson),
              ...(canFill ? { next: `Adding more is optional. ${FILL_STEPS}` } : fillState === 'reconnect' ? { next: RECONNECT_TO_FILL } : {}),
            } : {}),
            generated_at: (deps.now?.() ?? new Date()).toISOString(), days,
            rules: rulesPlan.served, rules_served: rulesPlan.served.length, rules_total: rulesTotal,
            rules_remainder: rulesPlan.remainder, rules_remainder_count: rulesPlan.remainder.length,
            ...(rulesPlan.unlisted > 0 ? { rules_unlisted: rulesPlan.unlisted } : {}),
            rules_budget: { tokens: STARTUP_RULES_BUDGET_TOKENS, used: rulesPlan.budget_used, estimate: BUDGET_ESTIMATE, text_max_chars: COMPACT_TEXT_MAX_CHARS },
            rules_note: `${rulesNote(rulesPlan, R.kept.length, rulesTotal.capped)} ${RULES_DEFINITION}`,
            sources: SOURCES_OF_RULES_FACTS_FOCUS,
            focus, ...(focus.length === 0 ? { focus_message: NO_FOCUS_MESSAGE } : {}),
            ...(focusOlder > 0 ? { focus_older_same_subject: focusOlder } : {}),
            decisions: D.kept, withheld: R.withheld + F.withheld + D.withheld,
            reminder: 'Before answering or asking the owner, call zeusi_search and cite source_uri + source_ts.',
          });
        } finally {
          await src.end();
        }
      } finally {
        await db.close().catch(() => {});
      }
    } catch (e) {
      return failed('zeusi_startup', e);
    }
  });

  register('zeusi_search', {
    title: 'Zeusi search',
    description: `Search Zeusi before answering or asking the owner. Returns note/chunk hits in \`hits\` and the owner's current decisions (matched on their exact words and applies_to) in \`decisions\`. Cite hits by source_uri + source_ts. limit 1..${MAX_LIMIT} (default 10, per list), scope ${SEARCH_SCOPES.join('|')}, hybrid (default true: full text always runs; false = semantic only when a key is set). Read-only. Returns a query_id for zeusi_search_feedback.`,
    inputSchema: strict({
      query: z.string().trim().min(1).max(4000),
      limit: z.number().int().min(1).max(MAX_LIMIT).optional(),
      scope: z.enum(SEARCH_SCOPES).optional(),
      hybrid: z.boolean().optional(),
    }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (args) => {
    try {
      const route = await readRoute();
      const db = await openRead();
      try {
        const src = sourceOf(db, route);
        state.ledger ??= new QueryLedger(deps.queryLedgerPath ?? defaultLedgerPath(home));
        // C7 KTD7 / §7.11: the sealed route never builds or calls an embeddings client.
        const client = route.kind === 'sealed' ? null : deps.embeddings ? deps.embeddings() : (env[OPENAI_KEY_ENV]?.trim() ? createOpenAIClient({ env }) : null);
        const r = await src.search({
          db, query: args.query, limit: args.limit ?? 10, hybrid: args.hybrid ?? DEFAULT_SEARCH_HYBRID, client, ledger: state.ledger,
          ...(args.scope !== undefined ? { scope: args.scope } : {}), ...(deps.now ? { now: deps.now } : {}),
        });
        const hits = r.hits.map((h) => ({
          source_uri: h.sourceUri, source_ts: h.sourceTs, scope: h.scope, heading_path: h.headingPath, text: h.text, score: h.score,
        }));
        // Output wall + serve-time secret guard (src/mcp-wall.ts): an item is served unchanged or withheld, never redacted.
        const W = wallFilter(hits, serveCheck);
        // Decisions pass the same output wall (every string of the item: words, applies_to, who, uri).
        // 0013 links: each link guarded on its own (dropped + counted), then the decision whole.
        const D = serveWithLinks((r.decisions ?? []).map(decisionJson), serveCheck);
        // Built-in about entries (src/about.ts): code-shipped, scope "builtin", no row; the same
        // read-only session, its own READ ONLY transaction. They pass the guard and the wall like everything else.
        const A = wallFilter(await src.about(args.query, args.limit ?? 10, sections), serveCheck);
        const queryId = remember(
          [...W.kept.map((h) => h.source_uri), ...D.kept.map((d) => d.source_uri), ...A.kept.map((a) => a.source_uri)],
          [...W.kept.map((h) => h.text), ...D.kept.map((d) => d.exact_words), ...A.kept.map((a) => a.text)],
          route,
        );
        const N = r.notice !== undefined ? guardString(r.notice, serveCheck) : { text: null, secretWithheld: 0 };
        const notice = N.text ?? undefined;
        observe({
          tool: 'zeusi_search', hitCount: W.kept.length + D.kept.length, withheld: W.withheld + D.withheld + A.withheld,
          secretWithheld: W.secretWithheld + D.secretWithheld + A.secretWithheld + N.secretWithheld,
        });
        return ok({
          query_id: queryId, mode: r.mode, ...(notice !== undefined ? { notice } : {}), hits: W.kept, decisions: D.kept,
          about: A.kept, withheld: W.withheld + D.withheld + A.withheld,
          ...(personal && W.kept.length === 0 && D.kept.length === 0 ? { message: empties.search } : {}),
          cite: 'cite each hit or decision you use as <source_uri> @ <source_ts>',
        });
      } finally {
        await db.close().catch(() => {});
      }
    } catch (e) {
      return failed('zeusi_search', e);
    }
  });

  if (canWrite) register('zeusi_log_decision', {
    title: 'Zeusi log decision',
    description: `Record a decision the owner actually made, with its source (invent=NO). Optional links (<= ${MAX_LINKS}): the PRs, notes, repos, jobs or lanes the decision covers, as stated by the source (${LINK_TARGET_SHAPES}); links need ${WRITE_ROLE} and migration 0013. Writes as ${WRITE_ROLE} (or, transitional, ${TRANSITIONAL_WRITE_ROLE}, without links) only; refused on read-only connectors. Returns ids and counts, never the words.`,
    inputSchema: strict({
      kind: z.enum(DECISION_KINDS),
      who: z.string().regex(WHO_HANDLE_RE),
      said_at: isoTs(),
      said_at_precision: z.enum(['minute', 'day']).optional(),
      exact_words: z.string().trim().min(1).max(4000),
      exact_words_verbatim: z.boolean(),
      applies_to: z.array(z.string().trim().min(1).max(200)).max(20).optional(),
      scope: z.enum(DECISION_SCOPES),
      source_uri: z.string().trim().min(1).max(2000),
      source_ts: isoTs(),
      expires_at: isoTs().optional(),
      linked_repo: z.string().trim().min(1).max(200).optional(),
      linked_pr: z.number().int().positive().optional(),
      links: z.array(z.string().trim().min(1).max(MAX_LINK_URI).refine((u) => linkTargetKind(u) !== null, {
        error: `link target refused: allowed are ${LINK_TARGET_SHAPES}`,
      })).max(MAX_LINKS).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async (args) => {
    try {
      const { service, user } = writeGate();
      if (withheld(stringsOf(args))) throw new ToolRefused('withheld: the input trips the wall (or looks like a credential / host); nothing written, nothing connected.');
      const db = deps.connectWrite
        ? await deps.connectWrite(service)
        : await connectService(service, { ...svcOpts, ...(deps.runSecurity ? { runSecurity: deps.runSecurity } : {}) });
      try {
        const s = (await db.query<{ u: string; su: boolean; ins: boolean }>(
          `SELECT current_user::text AS u, coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false) AS su,
                  has_table_privilege('zeusi.decisions', 'INSERT') AS ins`)).rows[0];
        if (!s || s.u !== user || !WRITE_ROLES.includes(s.u) || s.su || !s.ins) {
          throw new ToolRefused(`refused: the write session is not ${user} (one of ${WRITE_ROLES.join(', ')}) with INSERT on zeusi.decisions. Nothing written.`);
        }
        const links = args.links ?? [];
        if (links.length > 0 && !(await canInsertLinks(db))) {
          throw new ToolRefused(`refused: links need migration 0013 and INSERT on zeusi.decision_links (${WRITE_ROLE}); this session has neither. Nothing written; retry without links or after 0013.`);
        }
        const r = await insertDecision(db, {
          kind: args.kind, who: args.who, saidAt: args.said_at, saidAtPrecision: args.said_at_precision ?? 'minute',
          exactWords: args.exact_words, exactWordsVerbatim: args.exact_words_verbatim, appliesTo: args.applies_to ?? [],
          scope: args.scope, sourceUri: args.source_uri, sourceTs: args.source_ts, expiresAt: args.expires_at,
          linkedRepo: args.linked_repo, linkedPr: args.linked_pr, links,
        });
        observe({ tool: 'zeusi_log_decision', hitCount: 0, withheld: 0, secretWithheld: 0 });
        return r.status === 'inserted'
          ? ok({
            status: 'inserted', id: r.id, ingest_run_id: r.runId,
            ...(r.links ? { links: { inserted: r.links.inserted, already_linked: r.links.deduped, withheld: r.links.quarantined, invalid: r.links.invalid } } : {}),
          })
          : ok({ status: 'withheld', ingest_run_id: r.runId, note: 'the database wall rejected it; recorded in quarantine by uri and hash only' });
      } finally {
        await db.close().catch(() => {});
      }
    } catch (e) {
      return failed('zeusi_log_decision', e);
    }
  });

  register('zeusi_context_for_task', {
    title: 'Zeusi context for a task',
    description: `Call at the start of every task with a short description of the work (1..${MAX_TASK_CHARS} characters). Returns the owner's CURRENT decisions, locks and parked items that apply (not superseded, not expired), plus matching CURRENT note locks (type lock, origin note_lock, id and who null; superseded or expired lock matches only in history, with superseded_by / expired_at), ranked by relevance, kind and recency, each with id, kind, who, date, exact_words, applies_to, source_uri, source_ts and a ready cite; conflicts between current items are flagged. An empty list means nothing applies: say so, never invent one. limit 1..${MAX_CONTEXT_LIMIT} (default ${DEFAULT_CONTEXT_LIMIT}), scope ${SEARCH_SCOPES.join('|')}. Read-only. Returns a query_id for zeusi_search_feedback.`,
    inputSchema: strict({
      task: z.string().trim().min(1).max(MAX_TASK_CHARS),
      scope: z.enum(SEARCH_SCOPES).optional(),
      limit: z.number().int().min(1).max(MAX_CONTEXT_LIMIT).optional(),
    }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (args) => {
    try {
      const limit = args.limit ?? DEFAULT_CONTEXT_LIMIT;
      const terms = taskTerms(args.task);
      const route = await readRoute();
      const db = await openRead();
      // One list, ranked by score: decisions (src/context-for-task.ts) and note locks (src/note-locks.ts).
      let ranked: Array<{ score: number; at: string; item: ContextItem | LockItem }>;
      let historyRanked: LockHistoryItem[];
      try {
        const src = sourceOf(db, route);
        await assertReadOnlySession(db);
        await src.begin();
        try {
          const now = deps.now?.() ?? new Date();
          const scope = args.scope ?? null;
          const decisionRows = rankForTask(await src.taskCandidates(terms, args.task, scope), args.task, now);
          // Note locks through the one resolver (RLS-visible notes, explicit supersession / expiry):
          // current ones rank with the decisions; superseded / expired matches go to `history`.
          const lc = terms.length === 0 ? { locks: [] } : await src.lockLifecycle(now);
          const visible = lc.locks.filter((l) => scope === null || l.scope === scope);
          const lockRows = rankLocksForTask(visible.filter((l) => l.status === 'current'), args.task, now);
          historyRanked = rankLocksForTask(visible.filter((l) => l.status !== 'current'), args.task, now).map(lockHistoryJson);
          ranked = [
            ...decisionRows.map((r) => ({ score: r.score, at: r.saidAt, item: contextItemJson(r) as ContextItem | LockItem })),
            ...lockRows.map((r) => ({ score: r.score, at: r.sourceTs, item: lockItemJson(r) as ContextItem | LockItem })),
          ].sort((a, b) => b.score - a.score || b.at.localeCompare(a.at));
        } finally {
          await src.end();
        }
      } finally {
        await db.close().catch(() => {});
      }
      // Wall in rank order: walled items are skipped and counted, never paraphrased; the next
      // clean item takes their place up to the limit. Conflicts only over what is returned.
      // The wall + serve-time secret guard (src/mcp-wall.ts wallFilter: every string incl.
      // exact_words, cite, source_note and link fields; decisions AND note-lock items alike;
      // an item is served unchanged or withheld; fail closed).
      const items: Array<ContextItem | LockItem> = [];
      let walled = 0;
      let secretWithheld = 0;
      for (const { item } of ranked) {
        if (items.length >= limit) break;
        const G = serveWithLinks([item], serveCheck); // decision links guarded one by one first (0013)
        walled += G.withheld;
        secretWithheld += G.secretWithheld;
        items.push(...G.kept);
      }
      // History (superseded / expired lock matches): the same wall, its own limit; never binding.
      const history: LockHistoryItem[] = [];
      for (const h of historyRanked) {
        if (history.length >= limit) break;
        const G = wallFilter([h], serveCheck);
        walled += G.withheld;
        secretWithheld += G.secretWithheld;
        history.push(...G.kept);
      }
      // Conflicts over decisions only: note locks have no applies_to (KTD5).
      const conflicts = findConflicts(items.filter((i): i is ContextItem => i.type === 'decision'));
      const queryId = remember(items.map((i) => i.source_uri), items.map((i) => i.exact_words), route);
      observe({ tool: 'zeusi_context_for_task', hitCount: items.length, withheld: walled, secretWithheld });
      return ok({
        query_id: queryId, items, conflicts, withheld: walled,
        ...(history.length > 0 ? { history, history_note: 'history lists superseded or expired locks that match the task: not binding; follow superseded_by to the current lock.' } : {}),
        ...(conflicts.length > 0 ? { conflict_hint: CONFLICT_HINT } : {}),
        ...(items.length === 0 ? { message: personal ? empties.context : NOTHING_FOUND } : {}),
        rule: 'Locks and stops are binding unless the owner overrides them; respect parked items; ask the owner about conflicts. invent=NO.',
        cite: 'cite each item you use with its cite field (<source_uri> @ <source_ts>, decision id, who, said_at)',
      });
    } catch (e) {
      return failed('zeusi_context_for_task', e);
    }
  });

  register('zeusi_onboarding_status', {
    title: 'Zeusi onboarding status',
    description: 'First run: is Zeusi empty for this connection? Returns counts only (current facts, rules, focus, active notes, note lock items, chunks, current decisions; each capped), never row text, optionally for one scope. When empty, it lists the zeusi CLI commands the user runs locally (dry run first); the connector cannot run the import. Read-only.',
    inputSchema: strict({ scope: z.enum(SEARCH_SCOPES).optional() }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (args) => {
    try {
      const route = await readRoute();
      const db = await openRead();
      try {
        const src = sourceOf(db, route);
        await assertReadOnlySession(db);
        await src.begin();
        try {
          const s = await src.onboarding(args.scope ?? null, deps.now?.() ?? new Date());
          const total = Object.values(s.counts).reduce((a, b) => a + b, 0);
          // The serve guard like every other MCP output (#23): counts and code constants only,
          // so it trips nothing; if it ever does (or the guard throws) the body is withheld whole.
          const G = wallFilter([onboardingJson(s, workspace, fillState)], serveCheck);
          observe({ tool: 'zeusi_onboarding_status', hitCount: G.kept.length > 0 ? total : 0, withheld: G.withheld, secretWithheld: G.secretWithheld });
          return G.kept.length > 0
            ? ok(G.kept[0])
            : ok({ withheld: G.withheld, message: 'The onboarding status was withheld by the serve guard. Run `zeusi onboard` locally.' });
        } finally {
          await src.end();
        }
      } finally {
        await db.close().catch(() => {});
      }
    } catch (e) {
      return failed('zeusi_onboarding_status', e);
    }
  });

  register('zeusi_search_feedback', {
    title: 'Zeusi search feedback',
    description: personal
      ? `Say whether a zeusi_search or zeusi_context_for_task result answered the question (query_id from that call, the hit source_uri, useful true/false; an optional reason up to ${FEEDBACK_REASON_MAX} characters is accepted but not stored for this workspace). Stored in a local ledger only, with the source_uri as a keyed hash.`
      : `Say whether a zeusi_search or zeusi_context_for_task result answered the question (query_id from that call, the hit source_uri, useful true/false, optional reason up to ${FEEDBACK_REASON_MAX} characters: never paste chunk text or secrets). Stored in a local ledger only.`,
    inputSchema: strict({
      query_id: z.uuid(),
      source_uri: z.string().trim().min(1).max(2000),
      useful: z.boolean(),
      reason: z.string().trim().max(FEEDBACK_REASON_MAX).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
  }, async (args) => {
    try {
      const memo = state.queries.get(args.query_id);
      // Hosted: a query_id is only valid for the token that ran the search (same refusal as unknown).
      if (!memo || memo.tokenId !== deps.tokenId) {
        throw new ToolRefused(personal
          ? `unknown query_id: ${FEEDBACK_NOT_FOUND_PERSONAL}`
          : 'unknown query_id (feedback is accepted only for a zeusi_search or zeusi_context_for_task of this connector session); nothing recorded.');
      }
      if (!memo.uris.has(memo.hashed ? memoUri(args.source_uri) : args.source_uri)) {
        throw new ToolRefused(personal ? `source_uri is not a hit of that query: ${FEEDBACK_NOT_FOUND_PERSONAL}` : 'source_uri is not a hit of that query; nothing recorded.');
      }
      if (args.reason && withheld([args.reason])) throw new ToolRefused('withheld: the reason trips the wall (or looks like a credential / host); nothing recorded.');
      if (args.reason && copiesText(args.reason, memo.texts)) throw new ToolRefused('the reason copies chunk text; give a short reason in your own words. Nothing recorded.');
      const at = deps.now?.() ?? new Date();
      // A personal workspace's ledger holds a keyed hash of the uri and no reason (C2 KTD1, KTD2); the team's is unchanged (D4).
      if (personal) recordWorkspaceFeedback(deps.feedbackPath ?? defaultFeedbackPath(home), { queryId: args.query_id, sourceUri: args.source_uri, useful: args.useful }, at);
      else recordFeedback(deps.feedbackPath ?? defaultFeedbackPath(home), { queryId: args.query_id, sourceUri: args.source_uri, useful: args.useful, reason: args.reason }, at);
      observe({ tool: 'zeusi_search_feedback', hitCount: 0, withheld: 0, secretWithheld: 0 });
      return ok({ status: 'recorded' });
    } catch (e) {
      return failed('zeusi_search_feedback', e);
    }
  });

  if (personal && deps.workspaceWrite) registerWorkspaceWriteTools(deps.workspaceWrite);

  return server;

  /**
   * Own-workspace write tools (KTD5, KTD7): the caller is the principal's tenant + grant, fixed when
   * this per-request server was built; no argument names a workspace. Outputs are counts and the
   * preview items (already serve-checked) and pass the output wall again as a whole.
   */
  function registerWorkspaceWriteTools(ww: { caller: WorkspaceCaller; writes: WorkspaceWrites | null }): void {
    const writeResult = (tool: (typeof WORKSPACE_WRITE_TOOL_NAMES)[number], v: Record<string, unknown>, hits: number): ToolResult => {
      const G = wallFilter([v], serveCheck);
      observe({ tool, hitCount: G.kept.length > 0 ? hits : 0, withheld: G.withheld, secretWithheld: G.secretWithheld });
      return G.kept.length > 0 ? ok(G.kept[0]) : ok({ withheld: G.withheld, message: 'The result was withheld by the serve guard; nothing more can be shown.' });
    };
    const writeFailed = (tool: (typeof WORKSPACE_WRITE_TOOL_NAMES)[number], e: unknown): ToolResult => {
      if (e instanceof WorkspaceWriteRefused) {
        observe({ tool, hitCount: 0, withheld: 0, secretWithheld: 0, error: 'tool_refused' });
        return { content: [{ type: 'text', text: e.message }], isError: true };
      }
      // TenantRefused / TenantError / anything else: the workspace could not be opened (never an internal).
      return failed(tool, e instanceof TenantRefused || e instanceof TenantError ? e : new Error('workspace write failed'));
    };
    const off = (tool: (typeof WORKSPACE_WRITE_TOOL_NAMES)[number]): ToolResult => {
      observe({ tool, hitCount: 0, withheld: 0, secretWithheld: 0, error: 'tool_refused' });
      return { content: [{ type: 'text', text: WRITES_OFF }], isError: true };
    };
    const caps = WORKSPACE_WRITE_CAPS;
    const textField = (max: number) => z.string().min(1).max(max);

    server.registerTool('zeusi_import_preview', {
      title: 'Zeusi import preview (your workspace)',
      description: 'Step 1 of filling the user\'s OWN workspace: a dry run, NOTHING is saved. Pass the user\'s pasted notes (markdown), a decision log, or a Claude / ChatGPT conversations.json export as documents. '
        + 'Zeusi runs its safety filters (secrets, credentials, walled content are withheld or quarantined) and returns counts, a short list of what would be saved (titles and first lines), and a preview_id. '
        + 'Show that preview to the user; call zeusi_import_commit only after they clearly say yes. '
        + `A decision-log entry becomes a decision only in the format in ${ABOUT_URI}#decision-format; kept_as_notes says why an entry stays a note. `
        + `Limits: ${caps.previewDocuments} documents, ${caps.documentBytes / 1024} KiB each, ${Math.round(caps.previewTotalBytes / 1000)} KB in total.`,
      inputSchema: strict({
        documents: z.array(strict({
          kind: z.enum(['markdown', 'decision-log', 'claude-export', 'chatgpt-export']),
          text: textField(caps.documentBytes),
          title: z.string().trim().max(120).optional(),
          format: z.enum(['markdown', 'jsonl']).optional(),
        })).min(1).max(caps.previewDocuments),
      }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    }, async (args) => {
      if (!ww.writes) return off('zeusi_import_preview');
      try {
        const docs: PreviewDocument[] = args.documents.map((d) => (d.kind === 'markdown'
          ? { kind: 'markdown' as const, text: d.text, title: d.title }
          : d.kind === 'decision-log' ? { kind: 'decision-log' as const, text: d.text, format: d.format } : { kind: d.kind, text: d.text }));
        const r = await ww.writes.preview(ww.caller, docs);
        return writeResult('zeusi_import_preview', r as unknown as Record<string, unknown>, r.status === 'preview' ? r.counts.notes : 0);
      } catch (e) {
        return writeFailed('zeusi_import_preview', e);
      }
    });

    server.registerTool('zeusi_import_commit', {
      title: 'Zeusi import commit (your workspace)',
      description: 'Step 2: save exactly the preview the user approved into their OWN workspace. Needs the preview_id from zeusi_import_preview (valid 30 minutes, this connection only) and confirm: true. '
        + 'Never call it without the user\'s explicit yes to that preview. Saving the same preview twice saves nothing the second time.',
      inputSchema: strict({ preview_id: z.string().regex(PREVIEW_ID_RE), confirm: z.literal(true) }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    }, async (args) => {
      if (!ww.writes) return off('zeusi_import_commit');
      try {
        const r = await ww.writes.commit(ww.caller, args.preview_id);
        return writeResult('zeusi_import_commit', { ...r, workspace: 'personal' }, r.notes.inserted + r.notes.updated);
      } catch (e) {
        return writeFailed('zeusi_import_commit', e);
      }
    });

    server.registerTool('zeusi_sync_batch', {
      title: 'Zeusi nightly sync (your workspace)',
      description: 'For a nightly routine the user set up: add or update notes in the user\'s OWN workspace and remove the ones that are gone. '
        + 'items: notes in the HQ export layout (path <project>/YYYY-MM-DD-<slug>.md, text with frontmatter project, kind, date, title, source). '
        + 'deleted: paths of notes that no longer exist. The same safety filters as the nightly export run first; unchanged notes are skipped. '
        + `Limits: ${caps.syncItems} items, ${caps.syncItemBytes / 1024} KiB each, ${caps.syncDeleted} deleted paths per batch.`,
      inputSchema: strict({
        items: z.array(strict({ path: z.string().min(1).max(200), text: textField(caps.syncItemBytes) })).max(caps.syncItems).optional(),
        deleted: z.array(z.string().min(1).max(200)).max(caps.syncDeleted).optional(),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    }, async (args) => {
      if (!ww.writes) return off('zeusi_sync_batch');
      try {
        const r = await ww.writes.sync(ww.caller, args.items ?? [], args.deleted ?? []);
        return writeResult('zeusi_sync_batch', { ...r, workspace: 'personal' }, r.counts.inserted + r.counts.updated);
      } catch (e) {
        return writeFailed('zeusi_sync_batch', e);
      }
    });
  }
}
