// Hosted MCP transport (`zeusi-mcp --hosted`, docs/hosting.md): authenticated Streamable
// HTTP for the Fly machine behind Fly TLS. Separate from the loopback `--http` server, which
// stays unauthenticated and loopback-only (src/mcp.ts).
//
// Per request, in this order (every exit carries HSTS and produces one allowlisted log line):
//   1. HSTS header.                         5. body: 1 MiB cap (413), 10 s read timeout (408),
//                                              JSON (400).
//   2. path: OAuth routes (src/mcp-oauth.ts; 503 when
//      OAuth is not configured, 404 when the
//      handler has no OAuth at all), GET/HEAD /favicon.png and
//      /favicon.svg (listing icons, unauthenticated), /mcp, else 404. 6. scope: a read token calling zeusi_log_decision /
//   3. auth (src/mcp-auth.ts): 503 when        log_decision (also inside a batch) -> generic 401.
//      the tokens file is not configured,   7. limits: 60/min per token and 300/min global over
//      401 for every auth failure, 429         every MCP message (initialize, tools/list,
//      for the failed-auth limit.              tools/call, notifications; a request without a
//                                              method costs 1), 10/min log_decision per token
//                                              -> 429, nothing runs (a batch is all or nothing).
//   4. client IP: Fly-Client-IP, else the   8. one stateless MCP server per request, scoped to the
//      socket address.                         token (toolClass, tokenId, observe), behind the
//                                              unchanged read gate, write gate and output wall.
//
// Workspaces (open sign-up, docs/plans/2026-11-18-open-signup-workspaces-plan.md KTD8): the
// principal's tenant comes only from the server's own records (static tokens and legacy grants:
// team). A personal tenant must be class read, the router must be configured and the workspace
// active (else 403 {"error":"forbidden"}, nothing echoed; a catalog failure is 503). Its requests
// read ONLY that workspace (src/tenants.ts TenantRouter.open per tool call), never the team read
// service: no write service, no query embeddings (lexical only), a per-workspace feedback ledger.
// No header or parameter of the request can choose or change the workspace.
//
// Own-workspace writes (docs/plans/2026-11-18-workspace-write-import-plan.md KTD7): the tools in
// WORKSPACE_WRITE_TOOL_NAMES (also inside a batch) from any principal that is not a personal grant with
// ownWrite -> 403 {"error":"forbidden"}, nothing runs. Per action, per tenant AND per grant, hourly
// limits (WORKSPACE_WRITE_LIMITS) -> static 429 + Retry-After (fail closed: a limiter error is a 429
// too), audited. The write service gets the caller (tenant, grant, GitHub subject, request id) from
// the principal only.

import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { isIP } from 'node:net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { readBody } from './http-body.ts';
import type { Authenticator, AuthPrincipal } from './mcp-auth.ts';
import { BATCH_TOOL, buildLogLine, type ErrorClass } from './mcp-log.ts';
import { OAUTH_PATHS, type OAuthSetup } from './mcp-oauth.ts';
import { OAUTH_ACCESS_RE } from './mcp-oauth-store.ts';
import { createMcpState, createZeusiMcpServer, WORKSPACE_WRITE_TOOL_NAMES, type McpDeps, type McpState } from './mcp-server.ts';
import type { WsAuditAction, WsAuditSink } from './workspace-audit.ts';
import type { WorkspaceWrites } from './workspace-write.ts';
import type { Db } from './db.ts';
import { defaultFeedbackPath } from './feedback.ts';
import { SlidingWindowLimiter } from './rate-limit.ts';
import { ICON_PNG_PATH, ICON_SVG_PATH, WORKSPACE_UNAVAILABLE } from './about.ts';
import { ICON_PNG_BYTES, ICON_SVG_BYTES } from './brand-icons.ts';
import { WORK_TENANT, TENANT_ID_RE } from './tenant-ddl.ts';
import { proveSessionWrap, type B1Cache, type WrapProof } from './b1-cache.ts';
import { PLAIN_READ, readRouteFor, ReadRouteRefused, type ReadRoute } from './read-route.ts';

export const HSTS_VALUE = 'max-age=31536000';
/** Unauthenticated listing icons (MCP initialize / OAuth logo_uri). Exact paths only; no directory listing. */
const BRAND_ICONS: Readonly<Record<string, { body: Buffer; type: string }>> = {
  [ICON_PNG_PATH]: { body: ICON_PNG_BYTES, type: 'image/png' },
  [ICON_SVG_PATH]: { body: ICON_SVG_BYTES, type: 'image/svg+xml' },
};
const ICON_HEADERS = {
  'cache-control': 'public, max-age=86400',
  'access-control-allow-origin': '*',
} as const;
export const MAX_BODY_BYTES = 1024 * 1024;
export const BODY_TIMEOUT_MS = 10_000;
export const WRITE_TOOL_NAMES: readonly string[] = ['zeusi_log_decision', 'log_decision'];

export interface HostedLimits {
  perToken: number;
  writePerToken: number;
  global: number;
}
export const HOSTED_LIMITS: HostedLimits = { perToken: 60, writePerToken: 10, global: 300 };

/** Own-workspace write calls per HOUR, each per tenant and per grant [estimate] (OD7). */
export interface WorkspaceWriteLimits {
  preview: number;
  commit: number;
  sync: number;
}
export const WORKSPACE_WRITE_LIMITS: WorkspaceWriteLimits = { preview: 20, commit: 10, sync: 30 };
export const WORKSPACE_WRITE_WINDOW_MS = 60 * 60_000;
const WS_ACTION: Readonly<Record<string, { key: keyof WorkspaceWriteLimits; audit: WsAuditAction }>> = {
  zeusi_import_preview: { key: 'preview', audit: 'import_preview' },
  zeusi_import_commit: { key: 'commit', audit: 'import_commit' },
  zeusi_sync_batch: { key: 'sync', audit: 'sync' },
};

export interface HostedOptions {
  /** Base deps; toolClass, tokenId and observe are set per request from the token. */
  deps: McpDeps;
  state?: McpState | undefined;
  authenticator: Authenticator;
  /** Host header values accepted by the SDK's DNS-rebinding protection. */
  allowedHosts: string[];
  limits?: Partial<HostedLimits> | undefined;
  now?: (() => number) | undefined;
  /** One JSON line per request (default: stderr). */
  log?: ((line: string) => void) | undefined;
  maxBodyBytes?: number | undefined;
  /** The whole body must arrive within this many ms (default BODY_TIMEOUT_MS), else 408. */
  bodyTimeoutMs?: number | undefined;
  /**
   * OAuth for MCP clients (src/mcp-oauth.ts). Unset: no OAuth routes (404) and the old 401
   * challenge. Disabled: OAuth routes answer 503 and /mcp keeps the old challenge. Enabled: the
   * routes are served and a 401 points at the protected-resource metadata. The authenticator
   * must be given the same server (AuthenticatorOptions.oauth) for its tokens to work on /mcp.
   */
  oauth?: OAuthSetup | undefined;
  /**
   * Personal workspaces (src/tenants.ts TenantRouter). Unset: every personal principal gets 403
   * (fail closed); the team principals are unaffected.
   */
  tenants?: TenantRoutes | undefined;
  /**
   * Own-workspace writes (src/workspace-write.ts), set only when the writer login passed its startup
   * check. Unset: write-grant connections still list the write tools, which answer "not available".
   */
  writes?: WorkspaceWrites | undefined;
  wsAudit?: WsAuditSink | undefined;
  wsLimits?: Partial<WorkspaceWriteLimits> | undefined;
  /**
   * C7 (docs/plans/2026-11-19-c7-read-path.md KTD3): the process's one B1 cache (src/mcp.ts). Unset: a workspace on
   * the sealed read route is answered WORKSPACE_UNAVAILABLE (nothing is read).
   */
  cache?: B1Cache | undefined;
}

/** The request side of src/tenants.ts TenantRouter (injected; tests may wrap it). */
export interface TenantRoutes {
  check(tenantId: string): Promise<'active' | 'unknown'>;
  open(tenantId: string): Promise<Db>;
  /** C7 KTD1: the workspace's status and enc_state, uncached, as the runtime login (C6 KTD2's one reader). */
  encState(tenantId: string): Promise<{ status: string; encState: string }>;
}

/** The feedback ledger of one personal workspace: beside the team ledger, never in it. */
export function workspaceFeedbackPath(teamFeedbackPath: string, tenantId: string): string {
  if (!TENANT_ID_RE.test(tenantId)) throw new Error('not a workspace id');
  return join(dirname(teamFeedbackPath), 'workspaces', tenantId, 'search-feedback.jsonl');
}

interface Ctx {
  requestId: string;
  started: number;
  principal: AuthPrincipal | null;
  tokenId: string | null;
  tool: string | null;
  hits: number | null;
  withheld: number | null;
  redacted: number | null;
  errorClass: ErrorClass | null;
}

function respond(res: ServerResponse, status: number, body?: Record<string, string>, headers: Record<string, string> = {}): void {
  if (res.headersSent) return;
  const text = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, { ...headers, ...(body === undefined ? {} : { 'content-type': 'application/json' }) });
  res.end(text);
}

/** Every raw Authorization value (Node keeps only one in req.headers). */
function authorizationValues(req: IncomingMessage): string[] {
  const out: string[] = [];
  for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i]!.toLowerCase() === 'authorization') out.push(req.rawHeaders[i + 1]!);
  }
  return out;
}

/** Fly's proxy sets Fly-Client-IP (and overwrites a client-sent one); else the socket peer. */
function clientIp(req: IncomingMessage): string {
  const h = req.headers['fly-client-ip'];
  if (typeof h === 'string' && isIP(h.trim())) return h.trim();
  return req.socket.remoteAddress ?? 'unknown';
}

/** MCP messages carrying a method (requests and notifications) in a message or batch. */
function methodCount(body: unknown): number {
  const msgs = Array.isArray(body) ? body : [body];
  return msgs.filter((m) => m && typeof m === 'object' && typeof (m as { method?: unknown }).method === 'string').length;
}

/** Names of every tools/call in a single JSON-RPC message or a batch ('' when not a string). */
function toolCalls(body: unknown): string[] {
  const msgs = Array.isArray(body) ? body : [body];
  const names: string[] = [];
  for (const m of msgs) {
    if (!m || typeof m !== 'object' || (m as { method?: unknown }).method !== 'tools/call') continue;
    const name = (m as { params?: { name?: unknown } }).params?.name;
    names.push(typeof name === 'string' ? name : '');
  }
  return names;
}

export function createHostedHandler(o: HostedOptions): (req: IncomingMessage, res: ServerResponse) => void {
  const state = o.state ?? createMcpState();
  const limits: HostedLimits = { ...HOSTED_LIMITS, ...(o.limits ?? {}) };
  const toolLimiter = new SlidingWindowLimiter({ maxKeys: 4096 });
  // Keys: 3 actions x (tenants + grants); sized well above MAX_TENANTS (200) and MAX_GRANTS (1000) so
  // LRU eviction (which would reset a count) never happens at today's caps.
  const wsLimiter = new SlidingWindowLimiter({ windowMs: WORKSPACE_WRITE_WINDOW_MS, maxKeys: 16_384 });
  const wsLimits: WorkspaceWriteLimits = { ...WORKSPACE_WRITE_LIMITS, ...(o.wsLimits ?? {}) };
  const now = o.now ?? Date.now;
  const log = o.log ?? ((line: string) => { process.stderr.write(`${line}\n`); });
  const maxBody = o.maxBodyBytes ?? MAX_BODY_BYTES;
  const bodyTimeout = o.bodyTimeoutMs ?? BODY_TIMEOUT_MS;
  const challenge = o.oauth?.state === 'enabled' ? o.oauth.server.challenge() : 'Bearer realm="zeusi"';

  async function handle(req: IncomingMessage, res: ServerResponse, ctx: Ctx): Promise<void> {
    const path = (req.url ?? '').split('?')[0]!;
    if (o.oauth && OAUTH_PATHS.includes(path)) {
      if (o.oauth.state !== 'enabled') {
        ctx.errorClass = 'not_configured';
        respond(res, 503, { error: 'not_configured' });
        return;
      }
      ctx.errorClass = await o.oauth.server.handle(path, req, res, clientIp(req), ctx.requestId);
      return;
    }
    const icon = BRAND_ICONS[path];
    if (icon) {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        ctx.errorClass = 'bad_request';
        respond(res, 405, undefined, { allow: 'GET, HEAD' });
        return;
      }
      if (res.headersSent) return;
      res.writeHead(200, {
        ...ICON_HEADERS,
        'content-type': icon.type,
        'content-length': icon.body.length,
      });
      res.end(req.method === 'HEAD' ? undefined : icon.body);
      return;
    }
    if (path !== '/mcp') {
      ctx.errorClass = 'bad_request';
      respond(res, 404);
      return;
    }

    const auth = await o.authenticator.authenticate(authorizationValues(req), clientIp(req));
    if (!auth.ok) {
      ctx.tokenId = auth.tokenId ?? null;
      ctx.errorClass = auth.errorClass;
      if (auth.status === 503) respond(res, 503, { error: 'not_configured' });
      else if (auth.status === 429) respond(res, 429, { error: 'rate_limited' }, { 'retry-after': String(auth.retryAfterSec ?? 60) });
      else respond(res, 401, { error: 'unauthorized' }, { 'www-authenticate': challenge });
      return;
    }
    const p = auth.principal;
    ctx.principal = p;
    ctx.tokenId = p.tokenId;
    const personal = p.tenant !== WORK_TENANT;
    if (personal) {
      // Fail closed: a personal workspace is served only read-only, only through the router, and
      // only while the catalog says it is active. Static body; nothing about the workspace echoed.
      if (!o.tenants || p.cls !== 'read' || !TENANT_ID_RE.test(p.tenant)) {
        ctx.errorClass = 'forbidden';
        respond(res, 403, { error: 'forbidden' });
        return;
      }
      let st: 'active' | 'unknown';
      try {
        st = await o.tenants.check(p.tenant);
      } catch {
        // Static, actionable text (retry / reconnect, the one URL); never the cause.
        ctx.errorClass = 'not_configured';
        respond(res, 503, { error: 'not_configured', message: WORKSPACE_UNAVAILABLE });
        return;
      }
      if (st !== 'active') {
        ctx.errorClass = 'forbidden';
        respond(res, 403, { error: 'forbidden' });
        return;
      }
    }

    let parsed: unknown;
    if (req.method === 'POST') {
      const declared = Number(req.headers['content-length']);
      const raw = Number.isFinite(declared) && declared > maxBody ? null : await readBody(req, maxBody, bodyTimeout);
      if (raw === 'timeout') {
        ctx.errorClass = 'bad_request';
        respond(res, 408, { error: 'request_timeout' }, { connection: 'close' });
        req.destroy();
        return;
      }
      if (raw === null) {
        ctx.errorClass = 'payload_too_large';
        respond(res, 413, { error: 'payload_too_large' }, { connection: 'close' });
        return;
      }
      try {
        parsed = JSON.parse(raw.toString('utf8'));
      } catch {
        ctx.errorClass = 'bad_request';
        respond(res, 400, { error: 'bad_request' });
        return;
      }
    }

    const calls = toolCalls(parsed);
    ctx.tool = calls.length === 1 ? calls[0]! : calls.length > 1 ? BATCH_TOOL : null;
    const writes = calls.filter((n) => WRITE_TOOL_NAMES.includes(n)).length;
    if (p.cls !== 'write' && writes > 0) {
      ctx.errorClass = 'unauthorized';
      respond(res, 401, { error: 'unauthorized' }, { 'www-authenticate': challenge });
      return;
    }
    // Own-workspace writes: only a personal grant with ownWrite, only into its own tenant (KTD7).
    const wsCalls = calls.filter((n) => (WORKSPACE_WRITE_TOOL_NAMES as readonly string[]).includes(n));
    const ownWrite = personal && p.ownWrite === true && TENANT_ID_RE.test(p.tenant);
    if (wsCalls.length > 0 && !ownWrite) {
      ctx.errorClass = 'forbidden';
      respond(res, 403, { error: 'forbidden' });
      return;
    }
    const wsAdds: Array<[string, number]> = [];
    if (wsCalls.length > 0) {
      const t = now();
      let retry = 0;
      const adds = wsAdds;
      try {
        for (const [name, a] of Object.entries(WS_ACTION)) {
          const cost = wsCalls.filter((n) => n === name).length;
          if (cost === 0) continue;
          for (const k of [`ws:${a.key}:tenant:${p.tenant}`, `ws:${a.key}:grant:${p.tokenId}`]) {
            retry = Math.max(retry, wsLimiter.retryAfter(k, wsLimits[a.key], cost, t));
            adds.push([k, cost]);
          }
        }
      } catch {
        retry = 60; // fail closed
      }
      if (retry > 0) {
        for (const n of new Set(wsCalls)) {
          try {
            o.wsAudit?.({ requestId: ctx.requestId, subject: p.subject ?? null, tenantId: p.tenant, grantId: p.tokenId, action: WS_ACTION[n]!.audit, outcome: 'rate_limited' });
          } catch { /* the audit never changes the answer */ }
        }
        ctx.errorClass = 'rate_limited';
        respond(res, 429, { error: 'rate_limited' }, { 'retry-after': String(retry) });
        return;
      }
    }
    {
      // Every authenticated request is counted (initialize and tools/list too, not only
      // tools/call): one per MCP message, at least one per request.
      const cost = Math.max(1, methodCount(parsed));
      const t = now();
      const checks: Array<[string, number, number]> = [
        [`token:${p.tokenId}`, limits.perToken, cost],
        [`write:${p.tokenId}`, limits.writePerToken, writes],
        ['global', limits.global, cost],
      ];
      const active = checks.filter(([, , cost]) => cost > 0);
      const retry = Math.max(0, ...active.map(([k, lim, cost]) => toolLimiter.retryAfter(k, lim, cost, t)));
      if (retry > 0) {
        ctx.errorClass = 'rate_limited';
        respond(res, 429, { error: 'rate_limited' }, { 'retry-after': String(retry) });
        return;
      }
      for (const [k, , cost] of active) toolLimiter.add(k, cost, t);
      // Only now (the whole request is allowed) the own-workspace write calls count.
      for (const [k, c] of wsAdds) wsLimiter.add(k, c, t);
    }
    if (wsCalls.length > 0 && !o.writes) {
      // A write grant on a server with writes off: the tools answer "not available"; audited here.
      for (const n of new Set(wsCalls)) {
        try {
          o.wsAudit?.({ requestId: ctx.requestId, subject: p.subject ?? null, tenantId: p.tenant, grantId: p.tokenId, action: WS_ACTION[n]!.audit, outcome: 'writes_off' });
        } catch { /* never changes the answer */ }
      }
    }

    const observe: McpDeps['observe'] = (ob) => {
      ctx.hits = (ctx.hits ?? 0) + ob.hitCount;
      ctx.withheld = (ctx.withheld ?? 0) + ob.withheld;
      ctx.redacted = (ctx.redacted ?? 0) + ob.secretWithheld;
      if (ob.error) ctx.errorClass = ob.error;
    };
    const router = o.tenants;
    /**
     * C6 KTD4: this request's session key, lazily (src/workspace-write.ts calls it only for a workspace in
     * verified / on): the request's own OAuth bearer opens its grant's C4 session wrap. No other source.
     */
    const sessionUnlock = (r: IncomingMessage) => () => {
      const v = authorizationValues(r);
      const m = v.length === 1 ? /^(\S+) (\S+)$/.exec(v[0]!) : null;
      if (!m || m[1]!.toLowerCase() !== 'bearer' || !OAUTH_ACCESS_RE.test(m[2]!) || o.oauth?.state !== 'enabled') return null;
      return o.oauth.server.sessionKeyFor(m[2]!);
    };
    /**
     * C7 KTD1 + KTD2: this request's read route, once per request, BEFORE any workspace session: the enc_state
     * (any read failure throws: WORKSPACE_UNAVAILABLE), then readRouteFor; on the sealed route a wrap proof from
     * this request's own bearer (null: WORKSPACE_READ_LOCKED). The proof is disposed when the response closes.
     */
    let routeP: Promise<ReadRoute> | null = null;
    let proof: WrapProof | null = null;
    res.on('close', () => proof?.dispose());
    const readRoute = (r: TenantRoutes): (() => Promise<ReadRoute>) => () => {
      routeP ??= (async (): Promise<ReadRoute> => {
        const st = await r.encState(p.tenant);
        if (st.status !== 'active') throw new Error('workspace not active');
        if (readRouteFor(st.encState) === 'plain') return PLAIN_READ;
        if (!o.cache) throw new Error('no B1 cache on this server');
        proof = proveSessionWrap(sessionUnlock(req), { tenant: p.tenant, grantId: p.tokenId });
        if (!proof) throw new ReadRouteRefused('locked');
        return { kind: 'sealed', proof, cache: o.cache };
      })();
      return routeP;
    };
    const deps: McpDeps = personal && router
      ? {
        env: o.deps.env, home: o.deps.home, readService: o.deps.readService, defaultDays: o.deps.defaultDays, now: o.deps.now,
        searchFn: o.deps.searchFn, serveCheck: o.deps.serveCheck, queryLedgerPath: o.deps.queryLedgerPath,
        workspace: 'personal', tenantRead: () => router.open(p.tenant), readRoute: readRoute(router), toolClass: 'read', tokenId: p.tokenId, observe,
        writeService: undefined, embeddings: () => null,
        ...(ownWrite
          ? {
            workspaceWrite: {
              caller: { tenantId: p.tenant, grantId: p.tokenId, subject: p.subject ?? null, requestId: ctx.requestId, unlock: sessionUnlock(req) },
              writes: o.writes ?? null,
            },
          }
          : { workspaceWritesOn: o.writes !== undefined }),
        feedbackPath: workspaceFeedbackPath(o.deps.feedbackPath ?? defaultFeedbackPath(o.deps.home), p.tenant),
      }
      : { ...o.deps, toolClass: p.cls, tokenId: p.tokenId, observe };
    const server = createZeusiMcpServer(deps, state);
    const transport = new StreamableHTTPServerTransport({
      enableJsonResponse: true, enableDnsRebindingProtection: true, allowedHosts: o.allowedHosts,
    });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, parsed);
  }

  return (req, res) => {
    res.setHeader('strict-transport-security', HSTS_VALUE);
    const ctx: Ctx = {
      requestId: randomUUID(), started: performance.now(), principal: null, tokenId: null, tool: null, hits: null, withheld: null, redacted: null, errorClass: null,
    };
    let logged = false;
    const emit = () => {
      if (logged) return;
      logged = true;
      const status = res.statusCode;
      const errorClass = ctx.errorClass ?? (status >= 500 ? 'internal' : status >= 400 ? 'bad_request' : null);
      log(buildLogLine({
        ts: new Date().toISOString(), request_id: ctx.requestId, token_id: ctx.tokenId,
        assistant: ctx.principal?.assistant ?? null, class: ctx.principal?.cls ?? null, tool: ctx.tool,
        duration_ms: performance.now() - ctx.started, hit_count: ctx.hits, withheld_count: ctx.withheld, redacted_count: ctx.redacted, status, error_class: errorClass,
      }));
    };
    res.on('finish', emit);
    res.on('close', emit);
    handle(req, res, ctx).catch(() => {
      ctx.errorClass = 'internal';
      respond(res, 500, { error: 'internal' });
    });
  };
}
