// OAuth 2.1 authorization server for the hosted MCP endpoint (docs/hosting.md "OAuth for
// MCP clients"), on the same origin as /mcp. It exists so any MCP client with OAuth (claude.ai
// / Claude Desktop, Claude Code, ChatGPT, Cursor, VS Code, Gemini CLI, ...) can use Zeusi with
// just the URL https://mcp.zeusi.dev/mcp. Static bearer tokens (src/mcp-auth.ts) keep working.
//
//   discovery   /.well-known/oauth-protected-resource[/mcp] (RFC 9728) and
//               /.well-known/oauth-authorization-server (RFC 8414). resource is exactly
//               <issuer>/mcp; one authorization server: the issuer.
//   clients     DCR at /register (RFC 7591, JSON, always a PUBLIC client) and CIMD (an https
//               client_id URL whose metadata document is fetched with a public-address-only
//               resolver, no redirects, 5 s, 64 KiB; any failure refuses).
//   redirects   ONLY the exact https URIs in EXACT_REDIRECTS (claude.ai, chatgpt.com,
//               www.cursor.com, vscode.dev, insiders.vscode.dev; each from that client's
//               docs), and loopback http://localhost|127.0.0.1[:port] with path /callback,
//               /oauth/callback or / (port ignored when matching; host and path not). No
//               custom schemes. Everything else is refused before any redirect.
//   authorize   PKCE S256 required (missing, plain or malformed -> refused). The sign-in is
//               bound to the browser by a __Host- cookie; GitHub (src/mcp-oauth-github.ts)
//               proves who it is. Open sign-up (docs/plans/2026-11-18-open-signup-workspaces-plan.md):
//               a operator member reaches the team workspace; every other GitHub identity gets its
//               own personal workspace (src/tenants.ts), created on first sign-in (limited per IP,
//               globally and in total) and reused by GitHub user id; then a Zeusi consent screen.
//               Each outcome is audited (src/signin-audit.ts). Deny issues nothing. Codes are
//               one-time, 5 minutes, memory only; a replayed code revokes the grant it produced.
//   tokens      class "read" and bound to the one workspace decided at sign-in (src/mcp-oauth-store.ts
//               tenant). Scope zeusi.read; a PERSONAL grant signed in while this server has workspace
//               writes on also gets zeusi.workspace_write: write into that same workspace only, after a
//               preview (docs/plans/2026-11-18-workspace-write-import-plan.md KTD1, KTD2). One consent
//               screen covers both; GitHub scopes are unchanged. the team grants stay read-only.
//               Access 1 h, refresh 30 d rotated on every use (src/mcp-oauth-store.ts).
//               /token takes application/x-www-form-urlencoded; errors are RFC 6749 codes.
//   limits      per client IP per minute on every route, plus a global cap on /register; new
//               personal workspaces per client IP and globally per hour (429 + Retry-After).
//   keys        (C4, docs/plans/2026-11-18-c4-enroll.md; only with ZEUSI_WORKSPACE_ENCRYPTION=enroll or on and
//               only for a personal workspace) the consent page can enroll a passkey + recovery code
//               (catalog wraps, enc_state off -> enrolled, or a born-encrypted `on` that stays on, C5; the code shown once) or unlock with a passkey
//               PRF output or the recovery code (5/h per workspace and per IP, persisted, counts-only
//               audit). The unwrapped DEK rides on the one-time code (memory only) and is wrapped under
//               the new tokens at /token (src/mcp-oauth-store.ts session_wraps), rewrapped at refresh.
//               One attempt per sign-in. Nothing is encrypted by C4. Flag off: no change at all.
//               WebAuthn (docs/plans/2026-11-19-c4-webauthn-verify.md): a PRF output is used only after the
//               same POST's attestation (enroll) or assertion (unlock) verified (src/webauthn.ts) against the
//               challenge of this sign-in, the issuer origin and rpId, UP + UV, the stored key and counter.
//               Flag `on` + a born-encrypted workspace with no wrap: a passkey is required (no approve without).
//
// Never: an authless mode, a token in a URL, client_credentials, a write-class (the team) grant, a
// write grant for any workspace but the signer's own, a token / code / verifier / GitHub secret in
// a log line or an HTML page; a DEK, PRF output or recovery code in a log line, a file or a page (the
// recovery code is shown once, on the enrollment page only).

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { BlockList, isIP } from 'node:net';
import { join } from 'node:path';
import { ICON_PNG_PATH, SITE_URL } from './about.ts';
import { readBody } from './http-body.ts';
import type { AuthPrincipal } from './mcp-auth.ts';
import type { ErrorClass } from './mcp-log.ts';
import { githubAuthorizeUrl, isOperatorMember, liveGithubApi, type GithubApi, type GithubIdentity } from './mcp-oauth-github.ts';
import { CLIENT_ID_RE, grantWritesOwn, newToken, OAuthStore, OAuthStoreError, tenantOf, type IssuedTokens, type OAuthStoreOptions } from './mcp-oauth-store.ts';
import {
  CONSENT_SCRIPT_HASH, consentPage, deniedPage, errorPage, LOCAL_HANDOFF_HOSTS, recoveryCodePage, recoveryLimitedPage, signupLimitedPage,
  signupUnavailablePage, type ClientLabel, type ConsentKeysView,
} from './mcp-oauth-views.ts';
import type { AuditAction, AuditOutcome, AuditSink } from './signin-audit.ts';
import type { EnrollAuditAction, EnrollAuditOutcome, EnrollAuditSink } from './enroll-audit.ts';
import { RecoveryAttemptLimiter } from './recovery-limit.ts';
import type { EncryptionView, KeyWrapKind, PasskeyWrapRow, ProvisionResult, RecoveryWrapRow, StoredWrap, TenantStatus } from './tenants.ts';
import {
  enrollmentWraps, formatRecoveryCode, MAX_CREDENTIAL_ID_BYTES, MAX_RECOVERY_ENTRY_CHARS, parseRecoveryCode, PRF_BYTES, PRF_SALT_BYTES,
  openSessionDek, rewrapSession, sealSessionWraps, unlockWithPasskey, unlockWithRecovery, wrapForCredential, type UnlockedDek,
} from './workspace-keys.ts';
import { SlidingWindowLimiter } from './rate-limit.ts';
import {
  MAX_ASSERTION_AUTH_DATA_BYTES, MAX_ATTESTATION_BYTES, MAX_CLIENT_DATA_BYTES, MAX_SIGNATURE_BYTES, verifyAssertion, verifyRegistration,
  WEBAUTHN_CHALLENGE_BYTES, WEBAUTHN_CHALLENGE_TTL_MS, type Expected,
} from './webauthn.ts';
import { WORK_TENANT, TENANT_ID_RE } from './tenant-ddl.ts';

export const CLAUDE_CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
export const CHATGPT_CALLBACK = 'https://chatgpt.com/connector_platform_oauth_redirect';
export const SCOPE_READ = 'zeusi.read';
/** Write into the signer's OWN personal workspace (KTD1). Accepted in a request, never required: the server decides. */
export const SCOPE_WORKSPACE_WRITE = 'zeusi.workspace_write';
export const OFFLINE_ACCESS = 'offline_access';
export const OAUTH_ASSISTANT = 'claude-oauth';
export const GITHUB_CLIENT_ID_ENV = 'ZEUSI_GITHUB_CLIENT_ID';
export const GITHUB_CLIENT_SECRET_ENV = 'ZEUSI_GITHUB_CLIENT_SECRET';
export const SIGNING_KEY_ENV = 'ZEUSI_OAUTH_SIGNING_KEY';
export const OAUTH_ENV_VARS = [GITHUB_CLIENT_ID_ENV, GITHUB_CLIENT_SECRET_ENV, SIGNING_KEY_ENV] as const;
export const MIN_SIGNING_KEY_CHARS = 32;
export const COOKIE_NAME = '__Host-zeusi_oauth';

export const WK_PROTECTED_RESOURCE = '/.well-known/oauth-protected-resource';
export const WK_PROTECTED_RESOURCE_MCP = '/.well-known/oauth-protected-resource/mcp';
export const WK_AUTHORIZATION_SERVER = '/.well-known/oauth-authorization-server';
export const PATHS = {
  authorize: '/authorize', token: '/token', register: '/register', revoke: '/revoke',
  githubCallback: '/oauth/github/callback', consent: '/oauth/consent',
} as const;
export const OAUTH_PATHS: readonly string[] = [WK_PROTECTED_RESOURCE, WK_PROTECTED_RESOURCE_MCP, WK_AUTHORIZATION_SERVER, ...Object.values(PATHS)];

export const TXN_TTL_MS = 10 * 60_000;
export const CODE_TTL_MS = 5 * 60_000;
export const MAX_TXNS = 256;
export const MAX_CODES = 256;
export const MAX_FORM_BYTES = 16 * 1024;
export const FORM_TIMEOUT_MS = 10_000;
export const CIMD_TIMEOUT_MS = 5000;
export const CIMD_MAX_BYTES = 64 * 1024;
export const CIMD_CACHE_MS = 5 * 60_000;

export interface OAuthLimits {
  authorize: number;
  callback: number;
  consent: number;
  token: number;
  register: number;
  registerGlobal: number;
  revoke: number;
  metadata: number;
  /** New personal workspaces per client IP per HOUR. */
  signupPerIp: number;
  /** New personal workspaces per HOUR, all IPs together. */
  signupGlobal: number;
}
/** Per client IP per minute (registerGlobal: all IPs together); signup*: per hour [estimate values]. */
export const OAUTH_LIMITS: OAuthLimits = {
  authorize: 30, callback: 20, consent: 20, token: 60, register: 10, registerGlobal: 30, revoke: 30, metadata: 120,
  signupPerIp: 3, signupGlobal: 20,
};
export const SIGNUP_WINDOW_MS = 60 * 60_000;

/** The sign-up side of src/tenants.ts TenantDirectory (injected; tests may fake it). */
export interface TenantSignup {
  lookup(subject: string): Promise<{ tenantId: string; status: TenantStatus } | null>;
  provision(subject: string): Promise<ProvisionResult>;
  /** Writer role of an active workspace (src/tenants.ts ensureWriter); optional, best effort at sign-in. */
  ensureWriter?(tenantId: string): Promise<'ready' | 'no_login' | 'unknown'>;
}

/** The catalog side of workspace keys (src/tenants.ts TenantDirectory; tests may fake it). C4. */
export interface WrapCatalog {
  encryptionView(tenantId: string): Promise<EncryptionView | null>;
  wrapsFor(tenantId: string, kind: KeyWrapKind): Promise<StoredWrap[]>;
  enroll(tenantId: string, rows: { passkey: PasskeyWrapRow; recovery: RecoveryWrapRow }): Promise<'enrolled' | 'already' | 'unknown'>;
  /** WebAuthn counter compare-and-swap of one passkey wrap (docs/plans/2026-11-19-c4-webauthn-verify.md KTD2). */
  advanceSignCount(tenantId: string, credentialId: Buffer, from: number, to: number): Promise<boolean>;
}

/** Workspace keys on the consent page (C4). Set only when ZEUSI_WORKSPACE_ENCRYPTION=enroll or on (C5). */
export interface OAuthKeysOptions {
  /**
   * The flag value (src/workspace-keys.ts encryptionMode). `on`: a born-encrypted workspace with no wrap must
   * enroll a passkey to get a grant (docs/plans/2026-11-19-c4-webauthn-verify.md KTD7). Required, no default.
   */
  mode: 'enroll' | 'on';
  catalog: WrapCatalog;
  limiter: RecoveryAttemptLimiter;
  audit?: EnrollAuditSink | undefined;
  /** TEST seam (KTD14): the DEK source; production uses the envelope's generateDek. */
  newDek?: (() => Buffer) | undefined;
}

// ---------------------------------------------------------------------------
// Pure checks

/**
 * The exact https redirect URIs Zeusi sends a code to, one per verified client, each from that
 * client's official docs. String equality only (no normalization): no query, fragment,
 * userinfo, explicit port, trailing slash or case variant. A client that is not listed here
 * (and is not a loopback app, below) cannot sign in. No custom URL schemes: no client's
 * official docs state one.
 */
export const EXACT_REDIRECTS: ReadonlyArray<{ uri: string; client: string; doc: string }> = [
  { uri: CLAUDE_CALLBACK, client: 'claude.ai / Claude Desktop / Claude mobile', doc: 'https://claude.com/docs/connectors/building/authentication' },
  { uri: CHATGPT_CALLBACK, client: 'ChatGPT (web)', doc: 'https://developers.openai.com/apps-sdk/build/auth' },
  { uri: 'https://www.cursor.com/agents/mcp/oauth/callback', client: 'Cursor', doc: 'https://cursor.com/docs/context/mcp' },
  { uri: 'https://vscode.dev/redirect', client: 'VS Code (GitHub Copilot)', doc: 'https://github.com/microsoft/vscode/blob/main/src/vs/base/common/oauth.ts' },
  { uri: 'https://insiders.vscode.dev/redirect', client: 'VS Code Insiders (GitHub Copilot)', doc: 'https://github.com/microsoft/vscode/blob/main/src/vs/base/common/oauth.ts' },
];
const EXACT_SET: ReadonlySet<string> = new Set(EXACT_REDIRECTS.map((e) => e.uri));

/**
 * Loopback redirects (RFC 8252 7.3) for apps on the user's own computer: http, host exactly
 * localhost or 127.0.0.1, optional port 1..65535, one of these paths. Claude Code uses
 * /callback, Gemini CLI /oauth/callback, VS Code /, Cursor http://localhost:8787/callback.
 */
export const LOOPBACK_HOSTS = ['localhost', '127.0.0.1'] as const;
export const LOOPBACK_PATHS = ['/callback', '/oauth/callback', '/'] as const;
export const MAX_REDIRECT_CHARS = 2048;

// Anchored, no normalization: an exact host, an optional decimal port without a leading 0 or
// sign, an exact path, and the end of the string (so no query, fragment, userinfo, %, \, space).
const LOOPBACK_RE = /^http:\/\/(localhost|127\.0\.0\.1)(?::([1-9][0-9]{0,4}))?(\/|\/callback|\/oauth\/callback)$/;

interface Loopback { host: string; port: number | null; path: string }

function parseLoopback(uri: string): Loopback | null {
  const m = LOOPBACK_RE.exec(uri);
  if (!m) return null;
  const port = m[2] === undefined ? null : Number(m[2]);
  if (port !== null && port > 65535) return null;
  return { host: m[1]!, port, path: m[3]! };
}

/** A loopback redirect: http, localhost or 127.0.0.1, any port, path /callback, /oauth/callback or /. */
export function isLoopbackRedirect(uri: string): boolean {
  return uri.length <= MAX_REDIRECT_CHARS && parseLoopback(uri) !== null;
}

/** The global redirect allowlist: one of EXACT_REDIRECTS, or a loopback redirect. */
export function redirectAllowed(uri: string): boolean {
  if (typeof uri !== 'string' || uri.length === 0 || uri.length > MAX_REDIRECT_CHARS) return false;
  return EXACT_SET.has(uri) || parseLoopback(uri) !== null;
}

/**
 * Does the requested redirect match one the client declared? Exact, or both loopback with
 * the same host and the same path and the port ignored (RFC 8252 7.3). The host is NOT
 * interchangeable: a client that declared localhost cannot ask for 127.0.0.1, and vice versa.
 */
export function redirectMatches(requested: string, registered: readonly string[]): boolean {
  if (!redirectAllowed(requested)) return false;
  const req = parseLoopback(requested);
  return registered.some((r) => {
    if (!redirectAllowed(r)) return false;
    if (r === requested) return true;
    const reg = parseLoopback(r);
    return req !== null && reg !== null && reg.host === req.host && reg.path === req.path;
  });
}

const DCR_GRANTS: ReadonlySet<string> = new Set(['authorization_code', 'refresh_token']);
const DCR_IGNORED_GRANTS: ReadonlySet<string> = new Set(['urn:ietf:params:oauth:grant-type:device_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);

const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/;

export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/** S256 only: base64url(sha256(verifier)) === challenge, in constant time. */
export function pkceVerify(verifier: unknown, challenge: string): boolean {
  if (typeof verifier !== 'string' || !VERIFIER_RE.test(verifier) || !CHALLENGE_RE.test(challenge)) return false;
  const a = Buffer.from(pkceChallenge(verifier));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Requested scopes: only zeusi.read, zeusi.workspace_write and offline_access exist. null = something
 * else asked. A requested zeusi.workspace_write never grants anything by itself (KTD1).
 */
export function parseScope(scope: string | null): string[] | null {
  if (scope === null || scope.trim() === '') return [SCOPE_READ];
  const parts = scope.split(' ').filter((s) => s !== '');
  if (parts.some((s) => s !== SCOPE_READ && s !== OFFLINE_ACCESS && s !== SCOPE_WORKSPACE_WRITE)) return null;
  return [...new Set(parts)];
}

/** A CIMD client_id: https, DNS host (no IP literal), default port, a path, no query/fragment/userinfo. */
export function cimdUrlOk(clientId: string): boolean {
  if (clientId.length > 512 || !clientId.startsWith('https://')) return false;
  let u: URL;
  try {
    u = new URL(clientId);
  } catch {
    return false;
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.port) return false;
  if (u.pathname === '/' || u.href !== clientId) return false;
  const host = u.hostname;
  if (isIP(host.replace(/^\[|\]$/g, '')) !== 0 || !host.includes('.')) return false;
  return true;
}

export interface CimdClient {
  clientId: string;
  clientName: string | null;
  redirectUris: string[];
}

const CIMD_AUTH_METHODS: ReadonlySet<string> = new Set(['none', 'private_key_jwt']);
function cimdAuthOk(m: unknown): boolean {
  return typeof m === 'string' && CIMD_AUTH_METHODS.has(m);
}

/** Validate a fetched CIMD document against its URL; null when anything is off. */
export function validateCimd(clientId: string, doc: unknown): CimdClient | null {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return null;
  const d = doc as Record<string, unknown>;
  if (d.client_id !== clientId) return null;
  const uris = d.redirect_uris;
  if (!Array.isArray(uris) || uris.length < 1 || uris.length > 10 || !uris.every((u) => typeof u === 'string' && redirectAllowed(u))) return null;
  // Zeusi treats every CIMD client as a PUBLIC client (PKCE, no client authentication) and
  // advertises only `none`. A document may still prefer private_key_jwt (ChatGPT's says
  // private_key_jwt and also lists none); that is not a reason to refuse. Anything else
  // (shared secrets, mTLS, unknown) is refused: an allowlist, not a deny-list.
  const auth = d.token_endpoint_auth_method;
  if (auth !== undefined && !cimdAuthOk(auth)) return null;
  const auths = d.token_endpoint_auth_methods_supported;
  if (auths !== undefined && (!Array.isArray(auths) || !auths.every(cimdAuthOk))) return null;
  const name = d.client_name;
  if (name !== undefined && (typeof name !== 'string' || name.length > 100)) return null;
  return { clientId, clientName: typeof name === 'string' ? name : null, redirectUris: uris as string[] };
}

// ---------------------------------------------------------------------------
// CIMD fetch with SSRF protection

const BLOCKED = new BlockList();
for (const [net, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
] as const) BLOCKED.addSubnet(net, bits, 'ipv4');
for (const [net, bits] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
] as const) BLOCKED.addSubnet(net, bits, 'ipv6');

/** Public unicast only (no loopback, private, link-local, Fly 6PN fdaa::/16, mapped, multicast). */
export function isPublicAddress(address: string): boolean {
  const fam = isIP(address);
  if (fam === 0) return false;
  // IPv4-mapped IPv6 (::ffff:a.b.c.d): judge the embedded IPv4 address. (A ::ffff:0:0/96
  // subnet rule would also match every plain IPv4 address in BlockList.)
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return isPublicAddress(mapped[1]!);
  if (fam === 6 && /^::ffff:/i.test(address)) return false;
  return !BLOCKED.check(address, fam === 4 ? 'ipv4' : 'ipv6');
}

type LookupCb = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

function publicOnlyLookup(hostname: string, options: { all?: boolean } & Record<string, unknown>, cb: LookupCb): void {
  dnsLookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err, '');
    const list = addrs as LookupAddress[];
    if (list.length === 0 || !list.every((a) => isPublicAddress(a.address))) {
      const e = new Error('address not allowed') as NodeJS.ErrnoException;
      e.code = 'EADDRNOTALLOWED';
      return cb(e, '');
    }
    if (options.all) return cb(null, list);
    return cb(null, list[0]!.address, list[0]!.family);
  });
}

export type CimdFetcher = (url: string) => Promise<unknown>;

/** Live CIMD fetch: GET, public addresses only (checked at connect time), no redirect, 5 s, 64 KiB, JSON. */
export const liveCimdFetch: CimdFetcher = (url) => new Promise((resolve, reject) => {
  const req = httpsRequest(url, {
    method: 'GET', lookup: publicOnlyLookup as never, timeout: CIMD_TIMEOUT_MS,
    headers: { accept: 'application/json', 'user-agent': 'zeusi-mcp' },
  }, (res) => {
    if (res.statusCode !== 200) {
      res.resume();
      reject(new Error('cimd status'));
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    res.on('data', (c: Buffer) => {
      size += c.length;
      if (size > CIMD_MAX_BYTES) {
        req.destroy(new Error('cimd too large'));
        return;
      }
      chunks.push(c);
    });
    res.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('cimd json'));
      }
    });
    res.on('error', reject);
  });
  req.on('timeout', () => req.destroy(new Error('cimd timeout')));
  req.on('error', reject);
  req.end();
});

// ---------------------------------------------------------------------------
// Server

export interface OAuthServerOptions {
  /** e.g. https://mcp.zeusi.dev (no trailing slash). The resource is `${issuer}/mcp`. */
  issuer: string;
  githubClientId: string;
  github: GithubApi;
  /** HMAC key for CSRF values and token hashes (>= 32 chars). */
  signingKey: string;
  store: OAuthStore;
  cimdFetch?: CimdFetcher | undefined;
  now?: (() => number) | undefined;
  limits?: Partial<OAuthLimits> | undefined;
  /**
   * Personal workspaces (open sign-up). Unset: a non-operator identity gets the static "not available"
   * page (503) and no grant; operator members are unaffected.
   */
  tenants?: TenantSignup | undefined;
  /** Sign-in audit (src/signin-audit.ts). Unset: no audit line. */
  audit?: AuditSink | undefined;
  /**
   * Workspace writes are on for this server (the writer login passed its startup check). Only then
   * does a personal consent offer, and a personal grant get, zeusi.workspace_write (KTD2).
   */
  workspaceWrite?: boolean | undefined;
  /** C4 workspace keys; unset (flag off): the consent page and every flow are exactly as before. */
  keys?: OAuthKeysOptions | undefined;
}

/**
 * What the consent page offered (C4); the server keeps the salt and the WebAuthn challenges (KTD3), never the
 * client. Enroll: `create` for navigator.credentials.create(), `get` for the get() fallback when create()
 * returned no PRF. `required` (KTD7): no approve without a passkey. `born`: the workspace was born encrypted (enc_state
 * `on`, C5 KTD11), read with the state that chose enroll; it picks the recovery page's wording. Challenges expire at `expires`.
 */
type KeysOffer =
  | { mode: 'enroll'; prfSalt: Buffer; create: string; get: string; required: boolean; born: boolean; expires: number }
  | { mode: 'unlock'; recovery: boolean; challenge: string; expires: number };

interface Txn {
  clientId: string;
  clientLabel: ClientLabel;
  redirectUri: string;
  state: string | null;
  challenge: string;
  offline: boolean;
  cookieHash: string;
  expires: number;
  stage: 'github' | 'consent' | 'continue';
  subject?: string;
  login?: string;
  /** The workspace the grant will read, decided by the server at the GitHub callback. */
  tenant?: string;
  /** Personal workspace only: it was created by this sign-in. */
  created?: boolean;
  /** C4: the passkey block shown on this consent page. */
  keys?: KeysOffer;
  /** C4, stage 'continue' only: the DEK unlocked by the enrollment, waiting for "continue". */
  dek?: UnlockedDek;
}

interface CodeEntry {
  clientId: string;
  redirectUri: string;
  challenge: string;
  subject: string;
  login: string;
  tenant: string;
  /** The consent shown covered writing into this (personal) workspace. */
  workspaceWrite: boolean;
  offline: boolean;
  expires: number;
  used: boolean;
  grantId: string | null;
  /** C4: the unlocked DEK (memory only); wrapped under the tokens at /token, then zeroed. */
  dek: UnlockedDek | null;
}

interface ResolvedClient {
  label: ClientLabel;
  redirectUris: string[];
}

type Handled = ErrorClass | null;

/** A client-declared name for display: printable ASCII only, trimmed, or null. */
function displayName(name: string | null): string | null {
  return name ? name.replace(/[^\x20-\x7e]/g, '').trim().slice(0, 100) || null : null;
}

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' };

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  if (res.headersSent) return;
  res.writeHead(status, { ...NO_STORE, ...headers, 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string, formAction: string[] = [], extra: Record<string, string> = {}, scripts: string[] = []): void {
  if (res.headersSent) return;
  // C4 KTD8: a page with the consent script pins it by hash; every other page keeps no script-src.
  const script = scripts.length > 0 ? `; script-src ${scripts.join(' ')}` : '';
  res.writeHead(status, {
    ...NO_STORE,
    ...extra,
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy': `default-src 'none'; style-src 'unsafe-inline'${script}; form-action 'self'${formAction.map((o) => ` ${o}`).join('')}; frame-ancestors 'none'; base-uri 'none'`,
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  res.end(html);
}

function redirect(res: ServerResponse, location: string, headers: Record<string, string | string[]> = {}): void {
  if (res.headersSent) return;
  res.writeHead(302, { ...NO_STORE, 'referrer-policy': 'no-referrer', ...headers, location });
  res.end();
}

/** Single-valued query/form params; null when any key repeats (RFC 6749 3.1). */
function single(params: URLSearchParams): Map<string, string> | null {
  const out = new Map<string, string>();
  for (const [k, v] of params) {
    if (out.has(k)) return null;
    out.set(k, v);
  }
  return out;
}

function cookieValue(req: IncomingMessage, name: string): string | null {
  const raw = req.headers.cookie;
  if (typeof raw !== 'string') return null;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function contentType(req: IncomingMessage): string {
  return String(req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
}

/** Canonical unpadded base64url of min..max bytes, or null (C4 form fields). */
function b64uBytes(v: string | undefined, min: number, max: number): Buffer | null {
  if (typeof v !== 'string' || v.length === 0 || v.length > Math.ceil((max * 4) / 3) || !/^[A-Za-z0-9_-]+$/.test(v)) return null;
  const b = Buffer.from(v, 'base64url');
  return b.length >= min && b.length <= max && b.toString('base64url') === v ? b : null;
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export class OAuthServer {
  readonly issuer: string;
  readonly resource: string;
  private readonly o: OAuthServerOptions;
  private readonly now: () => number;
  private readonly limits: OAuthLimits;
  private readonly limiter = new SlidingWindowLimiter({ maxKeys: 4096 });
  private readonly signupLimiter = new SlidingWindowLimiter({ windowMs: SIGNUP_WINDOW_MS, maxKeys: 4096 });
  private readonly txns = new Map<string, Txn>();
  private readonly codes = new Map<string, CodeEntry>();
  private readonly cimdCache = new Map<string, { client: CimdClient; expires: number }>();

  constructor(o: OAuthServerOptions) {
    if (!/^https?:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/.test(o.issuer)) throw new Error('issuer must be an origin');
    if (o.signingKey.length < MIN_SIGNING_KEY_CHARS) throw new Error('signing key too short');
    this.o = o;
    this.issuer = o.issuer;
    this.resource = `${o.issuer}/mcp`;
    this.now = o.now ?? Date.now;
    this.limits = { ...OAUTH_LIMITS, ...(o.limits ?? {}) };
  }

  /** WWW-Authenticate for a 401 on /mcp. */
  challenge(): string {
    return `Bearer realm="zeusi", resource_metadata="${this.issuer}${WK_PROTECTED_RESOURCE}", scope="${SCOPE_READ}"`;
  }

  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: this.resource, authorization_servers: [this.issuer], scopes_supported: [SCOPE_READ],
      bearer_methods_supported: ['header'], resource_name: 'Zeusi',
      // RFC 9728 optional documentation URL. No resource_policy_uri / resource_tos_uri: those pages do not exist.
      resource_documentation: SITE_URL,
    };
  }

  authorizationServerMetadata(): Record<string, unknown> {
    const i = this.issuer;
    return {
      issuer: i,
      authorization_endpoint: `${i}${PATHS.authorize}`,
      token_endpoint: `${i}${PATHS.token}`,
      registration_endpoint: `${i}${PATHS.register}`,
      revocation_endpoint: `${i}${PATHS.revoke}`,
      scopes_supported: [SCOPE_READ, OFFLINE_ACCESS],
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'],
      revocation_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
      // RFC 8414 service_documentation. logo_uri is not registered in RFC 8414; MCP clients
      // (ChatGPT, Claude) read it from authorization-server metadata for the connector icon
      // before authenticate. No op_policy_uri / op_tos_uri / policy_uri / tos_uri: those pages do not exist.
      service_documentation: SITE_URL,
      logo_uri: `${this.issuer}${ICON_PNG_PATH}`,
    };
  }

  /** The read-only principal for an OAuth access token, or null. Never throws. */
  principalFor(accessToken: string): AuthPrincipal | null {
    try {
      const g = this.o.store.grantForAccess(accessToken);
      if (!g) return null;
      const tenant = tenantOf(g);
      return {
        tokenId: g.grant_id, assistant: OAUTH_ASSISTANT, cls: 'read', tenant, subject: g.subject,
        ...(grantWritesOwn(g) && TENANT_ID_RE.test(tenant) ? { ownWrite: true as const } : {}),
      };
    } catch {
      return null;
    }
  }

  /**
   * C6 KTD4: the session DEK of a live access token (its grant's C4 session wrap opened with the token
   * itself), or null (unknown / expired / revoked token, no wraps, wrong token). Never throws. The
   * caller (src/workspace-write.ts) checks tenant and grant against the principal and zeroes the DEK.
   * The only unlock path of the workspace write route.
   */
  sessionKeyFor(accessToken: string): { tenant: string; grantId: string; dek: Buffer; keyVersion: number } | null {
    try {
      return openSessionDek(this.o.store, accessToken);
    } catch {
      return null;
    }
  }

  /** C7 KTD4: re-read the store if another process changed it (an offline revoke fires the session-end hook). Never throws. */
  syncStore(): void {
    try {
      this.o.store.sync();
    } catch { /* the next request answers 503 */ }
  }

  private hmac(purpose: string, value: string): string {
    return createHmac('sha256', this.o.signingKey).update(`${purpose}:${value}`, 'utf8').digest('base64url');
  }

  private limited(res: ServerResponse, checks: Array<[string, number]>): boolean {
    const t = this.now();
    const retry = Math.max(0, ...checks.map(([k, lim]) => this.limiter.retryAfter(k, lim, 1, t)));
    if (retry > 0) {
      sendJson(res, 429, { error: 'rate_limited' }, { 'retry-after': String(retry) });
      return true;
    }
    for (const [k] of checks) this.limiter.add(k, 1, t);
    return false;
  }

  private sweep(): void {
    const t = this.now();
    for (const [k, v] of this.txns) if (v.expires <= t) this.dropTxn(k);
    for (const [k, v] of this.codes) if (v.expires <= t) this.dropCode(k);
    for (const [k, v] of this.cimdCache) if (v.expires <= t) this.cimdCache.delete(k);
    while (this.txns.size > MAX_TXNS) this.dropTxn(this.txns.keys().next().value!);
    while (this.codes.size > MAX_CODES) this.dropCode(this.codes.keys().next().value!);
    while (this.cimdCache.size > 64) this.cimdCache.delete(this.cimdCache.keys().next().value!);
  }

  /** Forget an in-flight sign-in; a DEK waiting on it is zeroed (C4). */
  private dropTxn(k: string): void {
    this.txns.get(k)?.dek?.dek.fill(0);
    this.txns.delete(k);
  }

  /** Forget a code; a DEK riding on it is zeroed (C4). */
  private dropCode(k: string): void {
    this.codes.get(k)?.dek?.dek.fill(0);
    this.codes.delete(k);
  }

  /** A DCR client from the store or a CIMD document (fetched, validated); null refuses. */
  private async resolveClient(clientId: string): Promise<ResolvedClient | null> {
    if (CLIENT_ID_RE.test(clientId)) {
      const c = this.o.store.client(clientId);
      return c ? { label: { kind: 'dcr', name: displayName(c.client_name) }, redirectUris: c.redirect_uris } : null;
    }
    if (!cimdUrlOk(clientId)) return null;
    const host = new URL(clientId).hostname;
    const hit = this.cimdCache.get(clientId);
    if (hit && hit.expires > this.now()) return { label: { kind: 'cimd', host, name: displayName(hit.client.clientName) }, redirectUris: hit.client.redirectUris };
    let doc: unknown;
    try {
      doc = await (this.o.cimdFetch ?? liveCimdFetch)(clientId);
    } catch {
      return null;
    }
    const client = validateCimd(clientId, doc);
    if (!client) return null;
    this.cimdCache.set(clientId, { client, expires: this.now() + CIMD_CACHE_MS });
    return { label: { kind: 'cimd', host, name: displayName(client.clientName) }, redirectUris: client.redirectUris };
  }

  /** Is this client still allowed to hold tokens (DCR: registered and not revoked)? */
  private clientActive(clientId: string): boolean {
    if (CLIENT_ID_RE.test(clientId)) return this.o.store.client(clientId) !== null;
    return cimdUrlOk(clientId);
  }

  private redirectWith(res: ServerResponse, redirectUri: string, params: Record<string, string | null>, headers: Record<string, string | string[]> = {}): void {
    const u = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v !== null) u.searchParams.set(k, v);
    u.searchParams.set('iss', this.issuer);
    redirect(res, u.toString(), headers);
  }

  private async readForm(req: IncomingMessage, res: ServerResponse, json = false): Promise<Map<string, string> | Record<string, unknown> | ErrorClass> {
    const want = json ? 'application/json' : 'application/x-www-form-urlencoded';
    if (req.method !== 'POST') {
      sendJson(res, 405, { error: 'invalid_request' }, { allow: 'POST' });
      return 'bad_request';
    }
    if (contentType(req) !== want) {
      sendJson(res, 415, { error: 'invalid_request', error_description: `content-type must be ${want}` });
      return 'bad_request';
    }
    const raw = await readBody(req, MAX_FORM_BYTES, FORM_TIMEOUT_MS);
    if (raw === 'timeout') {
      sendJson(res, 408, { error: 'invalid_request' }, { connection: 'close' });
      req.destroy();
      return 'bad_request';
    }
    if (raw === null) {
      sendJson(res, 413, { error: 'invalid_request' }, { connection: 'close' });
      return 'payload_too_large';
    }
    const text = raw.toString('utf8');
    if (json) {
      try {
        const j = JSON.parse(text) as unknown;
        if (j && typeof j === 'object' && !Array.isArray(j)) return j as Record<string, unknown>;
      } catch { /* below */ }
      sendJson(res, 400, { error: 'invalid_client_metadata', error_description: 'body must be a JSON object' });
      return 'bad_request';
    }
    const m = single(new URLSearchParams(text));
    if (!m) {
      sendJson(res, 400, { error: 'invalid_request', error_description: 'repeated parameter' });
      return 'bad_request';
    }
    return m;
  }

  /**
   * Answer an OAuth route. `path` is one of OAUTH_PATHS. Returns the log error class
   * (null on success). Never throws for a bad request.
   */
  async handle(path: string, req: IncomingMessage, res: ServerResponse, ip: string, requestId: string | null = null): Promise<Handled> {
    this.sweep();
    try {
      switch (path) {
        case WK_PROTECTED_RESOURCE:
        case WK_PROTECTED_RESOURCE_MCP:
        case WK_AUTHORIZATION_SERVER: {
          if (req.method !== 'GET' && req.method !== 'HEAD') {
            sendJson(res, 405, { error: 'method_not_allowed' }, { allow: 'GET' });
            return 'bad_request';
          }
          if (this.limited(res, [[`meta:${ip}`, this.limits.metadata]])) return 'rate_limited';
          const doc = path === WK_AUTHORIZATION_SERVER ? this.authorizationServerMetadata() : this.protectedResourceMetadata();
          if (res.headersSent) return null;
          res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'public, max-age=300', 'access-control-allow-origin': '*' });
          res.end(req.method === 'HEAD' ? undefined : JSON.stringify(doc));
          return null;
        }
        case PATHS.authorize:
          if (this.limited(res, [[`authorize:${ip}`, this.limits.authorize]])) return 'rate_limited';
          return await this.authorize(req, res);
        case PATHS.githubCallback:
          if (this.limited(res, [[`callback:${ip}`, this.limits.callback]])) return 'rate_limited';
          return await this.githubCallback(req, res, ip, requestId);
        case PATHS.consent:
          if (this.limited(res, [[`consent:${ip}`, this.limits.consent]])) return 'rate_limited';
          return await this.consent(req, res, ip, requestId);
        case PATHS.token:
          if (this.limited(res, [[`token:${ip}`, this.limits.token]])) return 'rate_limited';
          return await this.token(req, res);
        case PATHS.register:
          if (this.limited(res, [[`register:${ip}`, this.limits.register], ['register:global', this.limits.registerGlobal]])) return 'rate_limited';
          return await this.register(req, res);
        case PATHS.revoke:
          if (this.limited(res, [[`revoke:${ip}`, this.limits.revoke]])) return 'rate_limited';
          return await this.revoke(req, res);
        default:
          if (!res.headersSent) res.writeHead(404).end();
          return 'bad_request';
      }
    } catch (e) {
      if (e instanceof OAuthStoreError) {
        sendJson(res, 503, { error: 'temporarily_unavailable' });
        return 'not_configured';
      }
      throw e;
    }
  }

  // ---- /authorize --------------------------------------------------------

  private async authorize(req: IncomingMessage, res: ServerResponse): Promise<Handled> {
    if (req.method !== 'GET') {
      sendHtml(res, 405, errorPage('Unsupported request.'));
      return 'bad_request';
    }
    const q = single(new URL(req.url ?? '/', 'http://x').searchParams);
    const clientId = q?.get('client_id') ?? '';
    const redirectUri = q?.get('redirect_uri') ?? '';
    // Until the client and its redirect are proven, errors are a page: never a redirect.
    if (!q || clientId === '' || clientId.length > 512 || redirectUri === '' || redirectUri.length > 512) {
      sendHtml(res, 400, errorPage('The sign-in request is not valid.'));
      return 'bad_request';
    }
    const client = await this.resolveClient(clientId);
    if (!client) {
      sendHtml(res, 400, errorPage('This app is not recognised.'));
      return 'bad_request';
    }
    if (!redirectMatches(redirectUri, client.redirectUris)) {
      sendHtml(res, 400, errorPage('This app asked to send you somewhere Zeusi does not allow.'));
      return 'bad_request';
    }
    const state = q.get('state') ?? null;
    if (state !== null && state.length > 1024) {
      sendHtml(res, 400, errorPage('The sign-in request is not valid.'));
      return 'bad_request';
    }
    const fail = (error: string, description: string): Handled => {
      this.redirectWith(res, redirectUri, { error, error_description: description, state });
      return 'bad_request';
    };
    if (q.get('response_type') !== 'code') return fail('unsupported_response_type', 'response_type must be code');
    const challenge = q.get('code_challenge') ?? '';
    if (!CHALLENGE_RE.test(challenge)) return fail('invalid_request', 'PKCE code_challenge (S256) is required');
    if (q.get('code_challenge_method') !== 'S256') return fail('invalid_request', 'code_challenge_method must be S256');
    const scopes = parseScope(q.get('scope') ?? null);
    if (!scopes) return fail('invalid_scope', 'only zeusi.read and offline_access exist');
    const resource = q.get('resource');
    if (resource !== undefined && resource !== this.resource) return fail('invalid_target', 'unknown resource');

    const txn = randomBytes(32).toString('base64url');
    const cookie = randomBytes(32).toString('base64url');
    this.txns.set(txn, {
      clientId, clientLabel: client.label, redirectUri, state, challenge, offline: scopes.includes(OFFLINE_ACCESS),
      cookieHash: this.hmac('cookie', cookie), expires: this.now() + TXN_TTL_MS, stage: 'github',
    });
    this.sweep();
    redirect(res, githubAuthorizeUrl(this.o.githubClientId, `${this.issuer}${PATHS.githubCallback}`, txn), {
      'set-cookie': `${COOKIE_NAME}=${cookie}; Path=/; Max-Age=${TXN_TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`,
    });
    return null;
  }

  /** The in-flight sign-in for `txnId`, only when this browser's cookie is bound to it. */
  private boundTxn(req: IncomingMessage, txnId: string | undefined): Txn | null {
    if (!txnId || txnId.length > 64) return null;
    const t = this.txns.get(txnId);
    const cookie = cookieValue(req, COOKIE_NAME);
    if (!t || t.expires <= this.now() || !cookie || cookie.length > 64) return null;
    return safeEqual(this.hmac('cookie', cookie), t.cookieHash) ? t : null;
  }

  // ---- /oauth/github/callback --------------------------------------------

  private async githubCallback(req: IncomingMessage, res: ServerResponse, ip: string, requestId: string | null): Promise<Handled> {
    if (req.method !== 'GET') {
      sendHtml(res, 405, errorPage('Unsupported request.'));
      return 'bad_request';
    }
    const q = single(new URL(req.url ?? '/', 'http://x').searchParams);
    const txnId = q?.get('state');
    const t = q ? this.boundTxn(req, txnId) : null;
    if (!q || !t || t.stage !== 'github') {
      sendHtml(res, 400, errorPage('This sign-in expired or is not valid.'));
      return 'bad_request';
    }
    this.txns.delete(txnId!);
    const audit = (who: GithubIdentity | null, action: AuditAction, outcome: AuditOutcome, tenantId: string | null) => {
      try {
        this.o.audit?.({ requestId, githubId: who?.id ?? null, login: who?.login ?? null, tenantId, action, outcome });
      } catch { /* the audit never changes a sign-in */ }
    };
    const code = q.get('code');
    if (q.has('error') || !code || code.length > 256) {
      audit(null, 'error', 'cancelled', null);
      this.redirectWith(res, t.redirectUri, { error: 'access_denied', error_description: 'GitHub sign-in was cancelled', state: t.state });
      return 'unauthorized';
    }
    const ghToken = await this.o.github.exchange(code, `${this.issuer}${PATHS.githubCallback}`);
    const who = ghToken ? await this.o.github.identity(ghToken) : null;
    if (!who) {
      audit(null, 'error', 'failed', null);
      sendHtml(res, 502, errorPage('GitHub sign-in did not complete.'));
      return 'unauthorized';
    }
    let tenant: string;
    let created = false;
    if (isOperatorMember(who)) {
      tenant = WORK_TENANT;
      audit(who, 'signin', 'ok', tenant);
    } else {
      const w = await this.personalWorkspace(res, who, ip, audit);
      if (typeof w === 'string' || w === null) return w;
      tenant = w.tenantId;
      created = w.created;
      if (!created) await this.ensureWriter(tenant);
    }
    // Re-key the sign-in so the GitHub state value is useless from here on.
    const next = randomBytes(32).toString('base64url');
    const offer = await this.keysOffer(tenant, who.login);
    const consent: Txn = {
      ...t, stage: 'consent', subject: `github:${who.id}`, login: who.login, tenant, created, expires: this.now() + TXN_TTL_MS,
      ...(offer ? { keys: offer.offer } : {}),
    };
    this.txns.set(next, consent);
    const target = new URL(t.redirectUri);
    sendHtml(res, 200, consentPage({
      clientLabel: t.clientLabel, redirectHost: target.host, local: target.protocol === 'http:' || LOCAL_HANDOFF_HOSTS.has(target.host), login: who.login,
      txn: next, csrf: this.hmac('consent', next),
      ...(tenant === WORK_TENANT ? {} : { personal: { created, write: this.o.workspaceWrite === true } }),
      ...(offer ? { keys: offer.view } : {}),
    }), [target.origin], {}, offer ? [CONSENT_SCRIPT_HASH] : []);
    return null;
  }

  /**
   * C4: the passkey block for a personal workspace while the flag is `enroll` or `on`. Enroll when the workspace
   * is `off` (or born `on`, C5) with no wrap; unlock when it holds wraps. null (the plain pre-C4 page) for the team, flag off,
   * an unreachable catalog, or any other state. The PRF salt of an enrollment stays in the server's txn.
   */
  private async keysOffer(tenant: string, login: string): Promise<{ offer: KeysOffer; view: ConsentKeysView } | null> {
    const keys = this.o.keys;
    if (!keys || !TENANT_ID_RE.test(tenant)) return null;
    let v: EncryptionView | null;
    try {
      v = await keys.catalog.encryptionView(tenant);
    } catch {
      return null;
    }
    if (!v) return null;
    const rpId = new URL(this.issuer).hostname;
    const challenge = randomBytes(WEBAUTHN_CHALLENGE_BYTES).toString('base64url');
    const expires = this.now() + WEBAUTHN_CHALLENGE_TTL_MS;
    // Enroll: an `off` workspace, or one born encrypted under flag `on` (C5 KTD11), with no wrap yet.
    if ((v.encState === 'off' || v.encState === 'on') && v.passkeys.length === 0 && v.recovery === 0) {
      const prfSalt = randomBytes(PRF_SALT_BYTES);
      const getChallenge = randomBytes(WEBAUTHN_CHALLENGE_BYTES).toString('base64url');
      const userId = createHmac('sha256', this.o.signingKey).update(`webauthn-user:${tenant}`, 'utf8').digest().subarray(0, 16).toString('base64url');
      // KTD7 (C7 review P2-3): flag `on` and born encrypted: every grant without a key is locked, so none is offered.
      const required = keys.mode === 'on' && v.encState === 'on';
      return {
        offer: { mode: 'enroll', prfSalt, create: challenge, get: getChallenge, required, born: v.encState === 'on', expires },
        view: { mode: 'enroll', rpId, userId, userName: login, challenge, challenge2: getChallenge, salt: prfSalt.toString('base64url'), required },
      };
    }
    if (v.passkeys.length > 0 || v.recovery > 0) {
      return {
        offer: { mode: 'unlock', recovery: v.recovery > 0, challenge, expires },
        view: {
          mode: 'unlock', rpId, challenge, recovery: v.recovery > 0,
          creds: v.passkeys.map((p) => ({ id: p.credentialId.toString('base64url'), salt: p.prfSalt.toString('base64url') })),
        },
      };
    }
    return null;
  }

  /**
   * Create-or-reuse the personal workspace of a non-operator GitHub identity (keyed by its numeric id).
   * Returns the workspace, or the log error class after answering with a static page. A new workspace
   * is counted against the per-IP and global hourly limits BEFORE it is provisioned (fail closed: over
   * a limit nothing is created); a returning identity is not.
   */
  private async personalWorkspace(
    res: ServerResponse, who: GithubIdentity, ip: string,
    audit: (who: GithubIdentity | null, action: AuditAction, outcome: AuditOutcome, tenantId: string | null) => void,
  ): Promise<{ tenantId: string; created: boolean } | Handled> {
    const dir = this.o.tenants;
    if (!dir) {
      audit(who, 'denied', 'unavailable', null);
      sendHtml(res, 503, signupUnavailablePage());
      return 'not_configured';
    }
    const subject = `github:${who.id}`;
    const unavailable = (): Handled => {
      audit(who, 'error', 'failed', null);
      sendHtml(res, 503, signupUnavailablePage());
      return 'internal';
    };
    const existing = (tenantId: string, status: TenantStatus): { tenantId: string; created: boolean } | Handled => {
      if (status !== 'active') {
        audit(who, 'denied', 'disabled', tenantId);
        sendHtml(res, 403, deniedPage());
        return 'unauthorized';
      }
      audit(who, 'reuse', 'ok', tenantId);
      return { tenantId, created: false };
    };
    let found: { tenantId: string; status: TenantStatus } | null;
    try {
      found = await dir.lookup(subject);
    } catch {
      return unavailable();
    }
    if (found) return existing(found.tenantId, found.status);
    const now = this.now();
    const checks: Array<[string, number]> = [[`signup:${ip}`, this.limits.signupPerIp], ['signup:global', this.limits.signupGlobal]];
    const retry = Math.max(0, ...checks.map(([k, lim]) => this.signupLimiter.retryAfter(k, lim, 1, now)));
    if (retry > 0) {
      audit(who, 'signup', 'rate_limited', null);
      sendHtml(res, 429, signupLimitedPage(), [], { 'retry-after': String(retry) });
      return 'rate_limited';
    }
    for (const [k] of checks) this.signupLimiter.add(k, 1, now);
    let r: ProvisionResult;
    try {
      r = await dir.provision(subject);
    } catch {
      return unavailable();
    }
    if (r.kind === 'cap_reached') {
      audit(who, 'signup', 'cap_reached', null);
      sendHtml(res, 429, signupLimitedPage(), [], { 'retry-after': String(SIGNUP_WINDOW_MS / 1000) });
      return 'rate_limited';
    }
    if (r.kind === 'existing') return existing(r.tenantId, r.status);
    audit(who, 'signup', 'created', r.tenantId);
    return { tenantId: r.tenantId, created: true };
  }

  /**
   * Upgrade path (KTD2): a returning user signing in again gets the writer role of an older
   * workspace created now (idempotent, src/tenants.ts ensureWriter). Best effort: a failure never
   * changes the sign-in; writes then answer "not available" until the operator backfill.
   */
  private async ensureWriter(tenantId: string): Promise<void> {
    if (this.o.workspaceWrite !== true || !this.o.tenants?.ensureWriter) return;
    try {
      await this.o.tenants.ensureWriter(tenantId);
    } catch { /* best effort */ }
  }

  // ---- /oauth/consent ----------------------------------------------------

  private async consent(req: IncomingMessage, res: ServerResponse, ip: string, requestId: string | null): Promise<Handled> {
    const form = await this.readForm(req, res);
    if (typeof form === 'string') return form;
    const f = form as Map<string, string>;
    const txnId = f.get('txn');
    const t = this.boundTxn(req, txnId);
    const csrf = f.get('csrf') ?? '';
    if (!t || (t.stage !== 'consent' && t.stage !== 'continue') || !t.subject || !t.login || !t.tenant || !safeEqual(csrf, this.hmac('consent', txnId!))) {
      sendHtml(res, 400, errorPage('This sign-in expired or is not valid.'));
      return 'bad_request';
    }
    // Single use, whatever happens next (C4 KTD11: one unlock attempt per sign-in).
    this.txns.delete(txnId!);
    const clear = { 'set-cookie': `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` };
    const decision = f.get('decision');
    if (decision !== 'approve') {
      t.dek?.dek.fill(0);
      this.redirectWith(res, t.redirectUri, { error: 'access_denied', error_description: 'the user denied access', state: t.state }, clear);
      return 'unauthorized';
    }
    if (t.stage === 'continue') return this.issueCode(res, t, t.dek ?? null, clear);
    const enc = f.get('enc') ?? '';
    if (enc === '') {
      // KTD7: the server refuses what the page does not offer (approve without a passkey on a required enroll).
      if (t.keys?.mode === 'enroll' && t.keys.required) {
        this.keyAudit(requestId, t.tenant, 'enroll', 'failed');
        sendHtml(res, 400, errorPage('This workspace needs a passkey to finish signing in. Nothing was shared.'), [], clear);
        return 'unauthorized';
      }
      return this.issueCode(res, t, null, clear);
    }
    const keys = this.o.keys;
    const offer = t.keys;
    if (keys && offer && TENANT_ID_RE.test(t.tenant)) {
      if (enc === 'enroll' && offer.mode === 'enroll') return this.enrollAtConsent(res, t, f, keys, offer, requestId);
      if (enc === 'unlock' && offer.mode === 'unlock') return this.unlockWithPasskeyAtConsent(res, t, f, keys, offer, clear, requestId);
      if (enc === 'recover' && offer.mode === 'unlock' && offer.recovery) return this.unlockWithRecoveryAtConsent(res, t, f, keys, ip, clear, requestId);
    }
    sendHtml(res, 400, errorPage('This sign-in is not valid.'));
    return 'bad_request';
  }

  /** The one-time code for an approved sign-in; `dek` (C4) rides on it in memory until /token. */
  private issueCode(res: ServerResponse, t: Txn, dek: UnlockedDek | null, clear: Record<string, string>): Handled {
    const code = newToken('ac');
    this.codes.set(this.hmac('code', code), {
      clientId: t.clientId, redirectUri: t.redirectUri, challenge: t.challenge, subject: t.subject!, login: t.login!, tenant: t.tenant!,
      workspaceWrite: this.o.workspaceWrite === true && TENANT_ID_RE.test(t.tenant!), offline: t.offline, expires: this.now() + CODE_TTL_MS, used: false, grantId: null,
      dek: dek && TENANT_ID_RE.test(t.tenant!) ? dek : null,
    });
    if (dek && !TENANT_ID_RE.test(t.tenant!)) dek.dek.fill(0);
    this.sweep();
    this.redirectWith(res, t.redirectUri, { code, state: t.state }, clear);
    return null;
  }

  private keyAudit(requestId: string | null, tenantId: string, action: EnrollAuditAction, outcome: EnrollAuditOutcome, count: number | null = null): void {
    try {
      this.o.keys?.audit?.({ requestId, tenantId, action, outcome, count });
    } catch { /* the audit never changes a sign-in */ }
  }

  /** What a WebAuthn response of this sign-in must match (KTD2, KTD3): its challenge, the issuer origin and rpId. */
  private expected(challenge: string): Expected {
    return { challenge, origin: this.issuer, rpId: new URL(this.issuer).hostname };
  }

  /**
   * KTD2 + KTD4 at enroll: the attestation of create() (challenge `create`), and when the PRF came from the get()
   * fallback, that assertion too (challenge `get`) with the just-attested key and counter. null on any failure.
   */
  private verifiedEnrollment(f: Map<string, string>, cred: Buffer, offer: Extract<KeysOffer, { mode: 'enroll' }>): { publicKey: Buffer; signCount: number } | null {
    if (this.now() > offer.expires) return null;
    const cdj = b64uBytes(f.get('cdj'), 1, MAX_CLIENT_DATA_BYTES);
    const att = b64uBytes(f.get('att'), 1, MAX_ATTESTATION_BYTES);
    if (!cdj || !att) return null;
    const reg = verifyRegistration({ clientDataJSON: cdj, attestationObject: att, credentialId: cred, expected: this.expected(offer.create) });
    if (!reg.ok) return null;
    const ad = f.get('ad') ?? '';
    if (ad === '' && (f.get('acdj') ?? '') === '' && (f.get('sig') ?? '') === '') return { publicKey: reg.value.publicKey, signCount: reg.value.signCount };
    const a = this.assertionFields(f);
    if (!a) return null;
    const v = verifyAssertion({ ...a, publicKey: reg.value.publicKey, storedSignCount: reg.value.signCount, expected: this.expected(offer.get) });
    return v.ok ? { publicKey: reg.value.publicKey, signCount: v.value.signCount } : null;
  }

  private assertionFields(f: Map<string, string>): { clientDataJSON: Buffer; authenticatorData: Buffer; signature: Buffer } | null {
    const clientDataJSON = b64uBytes(f.get('acdj'), 1, MAX_CLIENT_DATA_BYTES);
    const authenticatorData = b64uBytes(f.get('ad'), 37, MAX_ASSERTION_AUTH_DATA_BYTES);
    const signature = b64uBytes(f.get('sig'), 1, MAX_SIGNATURE_BYTES);
    return clientDataJSON && authenticatorData && signature ? { clientDataJSON, authenticatorData, signature } : null;
  }

  /** C4 enroll: wraps + enc_state in one catalog transaction, then the recovery code once. */
  private async enrollAtConsent(
    res: ServerResponse, t: Txn, f: Map<string, string>, keys: OAuthKeysOptions, offer: Extract<KeysOffer, { mode: 'enroll' }>, requestId: string | null,
  ): Promise<Handled> {
    const tenant = t.tenant!;
    const prf = b64uBytes(f.get('prf'), PRF_BYTES, PRF_BYTES);
    const cred = b64uBytes(f.get('cred'), 1, MAX_CREDENTIAL_ID_BYTES);
    let e: ReturnType<typeof enrollmentWraps>;
    let webauthn: { publicKey: Buffer; signCount: number } | null = null;
    try {
      if (!prf || !cred) throw new Error('malformed');
      // KTD4: the PRF output is used only once this POST's WebAuthn response verified.
      webauthn = this.verifiedEnrollment(f, cred, offer);
      if (!webauthn) throw new Error('not verified');
      e = enrollmentWraps({ tenant, prfOutput: prf, credentialId: cred, prfSalt: offer.prfSalt, newDek: keys.newDek });
    } catch {
      this.keyAudit(requestId, tenant, 'enroll', 'failed');
      sendHtml(res, 400, errorPage('The passkey step did not complete. Nothing was changed.'));
      return 'bad_request';
    } finally {
      prf?.fill(0);
    }
    const wipe = () => { e.dek.fill(0); e.recoveryCode.fill(0); };
    let r: 'enrolled' | 'already' | 'unknown';
    try {
      r = await keys.catalog.enroll(tenant, { passkey: { ...e.passkey, webauthn }, recovery: e.recovery });
    } catch {
      wipe();
      this.keyAudit(requestId, tenant, 'enroll', 'unavailable');
      sendHtml(res, 503, errorPage('Setting up a passkey is not available right now. Nothing was changed.'));
      return 'internal';
    }
    if (r !== 'enrolled') {
      wipe();
      this.keyAudit(requestId, tenant, 'enroll', r === 'already' ? 'already' : 'failed');
      sendHtml(res, 409, errorPage('This workspace already has a passkey set up, or it is not available. Nothing was changed.'));
      return 'bad_request';
    }
    this.keyAudit(requestId, tenant, 'enroll', 'ok');
    const shown = formatRecoveryCode(e.recoveryCode);
    e.recoveryCode.fill(0);
    const { keys: _offer, ...rest } = t;
    const next = randomBytes(32).toString('base64url');
    this.txns.set(next, { ...rest, stage: 'continue', dek: { dek: e.dek, keyVersion: e.keyVersion }, expires: this.now() + CODE_TTL_MS });
    this.sweep();
    sendHtml(res, 200, recoveryCodePage({ code: shown, txn: next, csrf: this.hmac('consent', next), born: offer.born }), [new URL(t.redirectUri).origin]);
    return null;
  }

  /**
   * C4 unlock with a passkey PRF output (one attempt per sign-in; no other route accepts one). KTD2 + KTD4: the
   * assertion of this POST must verify with the wrap's stored key (challenge of this sign-in, origin, rpId,
   * UP + UV, signature) and its counter must advance (compare-and-swap) BEFORE the PRF output touches the wrap.
   * A wrap without a stored key (enrolled before verification, KTD6) never unlocks by passkey.
   */
  private async unlockWithPasskeyAtConsent(
    res: ServerResponse, t: Txn, f: Map<string, string>, keys: OAuthKeysOptions, offer: Extract<KeysOffer, { mode: 'unlock' }>,
    clear: Record<string, string>, requestId: string | null,
  ): Promise<Handled> {
    const tenant = t.tenant!;
    const prf = b64uBytes(f.get('prf'), PRF_BYTES, PRF_BYTES);
    const cred = b64uBytes(f.get('cred'), 1, MAX_CREDENTIAL_ID_BYTES);
    const a = this.assertionFields(f);
    let u: UnlockedDek | null = null;
    let legacy = false;
    try {
      if (prf && cred && a && this.now() <= offer.expires) {
        const w = wrapForCredential(await keys.catalog.wrapsFor(tenant, 'passkey'), cred);
        if (w && (w.webauthnPublicKey === null || w.webauthnSignCount === null)) legacy = true;
        else if (w && w.webauthnPublicKey && w.webauthnSignCount !== null) {
          const v = verifyAssertion({ ...a, publicKey: w.webauthnPublicKey, storedSignCount: w.webauthnSignCount, expected: this.expected(offer.challenge) });
          if (v.ok && await keys.catalog.advanceSignCount(tenant, cred, w.webauthnSignCount, v.value.signCount)) u = unlockWithPasskey(tenant, w, prf);
        }
      }
    } catch {
      this.keyAudit(requestId, tenant, 'unlock_passkey', 'unavailable');
      sendHtml(res, 503, errorPage('Unlocking is not available right now. Nothing was shared.'));
      return 'internal';
    } finally {
      prf?.fill(0);
    }
    if (!u) {
      this.keyAudit(requestId, tenant, 'unlock_passkey', 'failed');
      sendHtml(res, 400, errorPage(legacy
        ? 'This passkey has to be set up again before it can unlock this workspace. Use your recovery code instead. Nothing was shared.'
        : 'The passkey did not unlock this workspace. Nothing was shared.'));
      return 'unauthorized';
    }
    this.keyAudit(requestId, tenant, 'unlock_passkey', 'ok');
    return this.issueCode(res, t, u, clear);
  }

  /**
   * C4 unlock with the recovery code: counted (per workspace and per IP, persisted) BEFORE it is
   * decoded; a typo fails the check symbol before any KDF; never echoed back.
   */
  private async unlockWithRecoveryAtConsent(
    res: ServerResponse, t: Txn, f: Map<string, string>, keys: OAuthKeysOptions, ip: string, clear: Record<string, string>, requestId: string | null,
  ): Promise<Handled> {
    const tenant = t.tenant!;
    const a = keys.limiter.attempt(tenant, ip);
    if (!a.ok) {
      this.keyAudit(requestId, tenant, 'unlock_recovery', a.reason === 'limited' ? 'rate_limited' : 'unavailable', a.count);
      if (a.reason === 'limited') sendHtml(res, 429, recoveryLimitedPage(), [], { 'retry-after': String(a.retryAfter) });
      else sendHtml(res, 503, errorPage('Recovery is not available right now. Nothing was shared.'));
      return a.reason === 'limited' ? 'rate_limited' : 'internal';
    }
    const raw = f.get('recovery') ?? '';
    const code = raw.length <= MAX_RECOVERY_ENTRY_CHARS ? parseRecoveryCode(raw) : null;
    let u: UnlockedDek | null = null;
    try {
      if (code) u = unlockWithRecovery(tenant, await keys.catalog.wrapsFor(tenant, 'recovery'), code);
    } catch {
      this.keyAudit(requestId, tenant, 'unlock_recovery', 'unavailable', a.count);
      sendHtml(res, 503, errorPage('Recovery is not available right now. Nothing was shared.'));
      return 'internal';
    } finally {
      code?.fill(0);
    }
    if (!u) {
      this.keyAudit(requestId, tenant, 'unlock_recovery', 'failed', a.count);
      sendHtml(res, 400, errorPage('That recovery code did not unlock this workspace. Nothing was shared.'));
      return 'unauthorized';
    }
    this.keyAudit(requestId, tenant, 'unlock_recovery', 'ok', a.count);
    return this.issueCode(res, t, u, clear);
  }

  // ---- /token ------------------------------------------------------------

  private tokenResponse(res: ServerResponse, issued: IssuedTokens): void {
    sendJson(res, 200, {
      access_token: issued.accessToken, token_type: 'Bearer', expires_in: issued.expiresIn,
      refresh_token: issued.refreshToken, scope: issued.grant.scope === SCOPE_READ ? SCOPE_READ : `${SCOPE_READ} ${SCOPE_WORKSPACE_WRITE}`,
    });
  }

  private async token(req: IncomingMessage, res: ServerResponse): Promise<Handled> {
    const form = await this.readForm(req, res);
    if (typeof form === 'string') return form;
    const f = form as Map<string, string>;
    const bad = (status: number, error: string, description?: string): Handled => {
      sendJson(res, status, description ? { error, error_description: description } : { error });
      return status === 401 ? 'unauthorized' : 'bad_request';
    };
    // Public clients only: client_id in the body (or the Basic user name); a secret is ignored.
    let clientId = f.get('client_id') ?? null;
    const basic = /^Basic ([A-Za-z0-9+/=]{1,1024})$/.exec(String(req.headers.authorization ?? ''));
    if (basic) {
      let user: string;
      try {
        user = decodeURIComponent(Buffer.from(basic[1]!, 'base64').toString('utf8').split(':')[0] ?? '');
      } catch {
        return bad(401, 'invalid_client');
      }
      if (clientId !== null && clientId !== user) return bad(401, 'invalid_client');
      clientId = user;
    }
    if (!clientId || clientId.length > 512) return bad(401, 'invalid_client', 'client_id is required');
    const resource = f.get('resource');
    if (resource !== undefined && resource !== this.resource) return bad(400, 'invalid_target');

    const grantType = f.get('grant_type');
    if (grantType === 'authorization_code') {
      const code = f.get('code') ?? '';
      const key = this.hmac('code', code);
      const entry = this.codes.get(key);
      if (!entry || entry.expires <= this.now()) return bad(400, 'invalid_grant');
      if (entry.used) {
        // Replay: the code was already redeemed; revoke what it produced.
        if (entry.grantId) this.o.store.revokeGrant(entry.grantId);
        this.codes.delete(key);
        return bad(400, 'invalid_grant');
      }
      entry.used = true;
      // C4: the DEK leaves the code entry now, whatever happens, and is zeroed after the wraps.
      const dek = entry.dek;
      entry.dek = null;
      try {
        if (entry.clientId !== clientId || f.get('redirect_uri') !== entry.redirectUri || !pkceVerify(f.get('code_verifier'), entry.challenge)) {
          return bad(400, 'invalid_grant');
        }
        if (!this.clientActive(clientId)) return bad(400, 'invalid_grant');
        const tenant = entry.tenant;
        const seal = dek && TENANT_ID_RE.test(tenant)
          ? (grantId: string, access: string, refresh: string) => sealSessionWraps(tenant, grantId, access, refresh, dek.dek, dek.keyVersion)
          : undefined;
        const issued = this.o.store.createGrant({ clientId, subject: entry.subject, login: entry.login, tenant, workspaceWrite: entry.workspaceWrite, seal });
        entry.grantId = issued.grant.grant_id;
        this.tokenResponse(res, issued);
        return null;
      } finally {
        dek?.dek.fill(0);
      }
    }
    if (grantType === 'refresh_token') {
      const scope = f.get('scope');
      if (scope !== undefined && parseScope(scope) === null) return bad(400, 'invalid_scope');
      if (!this.clientActive(clientId)) return bad(400, 'invalid_grant');
      // C4: session wraps are rewrapped from the old refresh token in the same store commit.
      const r = this.o.store.rotate(f.get('refresh_token') ?? '', clientId, (g, oldRefresh, access, refresh) =>
        (g.session_wraps && g.tenant !== undefined ? rewrapSession(g.tenant, g.grant_id, oldRefresh, access, refresh, g.session_wraps) : null));
      if (r === 'invalid') return bad(400, 'invalid_grant');
      this.tokenResponse(res, r);
      return null;
    }
    return bad(400, 'unsupported_grant_type');
  }

  // ---- /register (RFC 7591) ----------------------------------------------

  private async register(req: IncomingMessage, res: ServerResponse): Promise<Handled> {
    const body = await this.readForm(req, res, true);
    if (typeof body === 'string') return body;
    const b = body as Record<string, unknown>;
    const bad = (error: string, description: string): Handled => {
      sendJson(res, 400, { error, error_description: description });
      return 'bad_request';
    };
    const uris = b.redirect_uris;
    if (!Array.isArray(uris) || uris.length < 1 || uris.length > 10 || !uris.every((u) => typeof u === 'string')) {
      return bad('invalid_redirect_uri', 'redirect_uris must list 1..10 URIs');
    }
    if (!uris.every((u) => redirectAllowed(u as string))) return bad('invalid_redirect_uri', 'redirect URI not allowed');
    const grants = b.grant_types ?? ['authorization_code'];
    // Extra grants some clients list by default (VS Code: device_code; ChatGPT, Claude:
    // jwt-bearer) are accepted and ignored: the response grants only these two. Anything
    // else (client_credentials, implicit, password, ...) refuses the registration.
    if (!Array.isArray(grants) || !grants.includes('authorization_code') || !grants.every((g) => typeof g === 'string' && (DCR_GRANTS.has(g) || DCR_IGNORED_GRANTS.has(g)))) {
      return bad('invalid_client_metadata', 'grant_types: authorization_code and refresh_token only');
    }
    const responses = b.response_types ?? ['code'];
    if (!Array.isArray(responses) || !responses.every((r) => r === 'code')) return bad('invalid_client_metadata', 'response_types: code only');
    const auth = b.token_endpoint_auth_method ?? 'none';
    // Always registered as a PUBLIC client (PKCE); a request for a secret method is downgraded.
    if (!['none', 'client_secret_post', 'client_secret_basic'].includes(auth as string)) {
      return bad('invalid_client_metadata', 'token_endpoint_auth_method: none');
    }
    const name = b.client_name;
    if (name !== undefined && (typeof name !== 'string' || name.length > 100)) return bad('invalid_client_metadata', 'client_name: up to 100 characters');
    const clean = typeof name === 'string' ? name.replace(/[^\x20-\x7e]/g, '').trim() || null : null;
    const row = this.o.store.registerClient({ clientName: clean, redirectUris: uris as string[] });
    sendJson(res, 201, {
      client_id: row.client_id, client_id_issued_at: Math.floor(Date.parse(row.created_at) / 1000),
      client_name: row.client_name ?? undefined, redirect_uris: row.redirect_uris,
      grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none',
      scope: `${SCOPE_READ} ${OFFLINE_ACCESS}`,
    });
    return null;
  }

  // ---- /revoke (RFC 7009) ------------------------------------------------

  private async revoke(req: IncomingMessage, res: ServerResponse): Promise<Handled> {
    const form = await this.readForm(req, res);
    if (typeof form === 'string') return form;
    const f = form as Map<string, string>;
    const token = f.get('token') ?? '';
    if (token.length > 0 && token.length < 128) this.o.store.revokeToken(token, f.get('client_id') ?? null);
    sendJson(res, 200, {});
    return null;
  }
}

// ---------------------------------------------------------------------------
// Setup from the environment (Fly secrets)

export type OAuthSetup = { state: 'enabled'; server: OAuthServer } | { state: 'disabled'; reason: string };

export interface OAuthEnvOptions {
  issuer: string;
  dataDir: string;
  /** TEST seams. */
  github?: GithubApi | undefined;
  cimdFetch?: CimdFetcher | undefined;
  now?: (() => number) | undefined;
  uid?: number | undefined;
  /** Personal workspaces (src/tenants.ts); unset: non-operator identities get the "not available" page. */
  tenants?: TenantSignup | undefined;
  audit?: AuditSink | undefined;
  /** Workspace writes on (the writer passed its startup check): personal consents offer them. */
  workspaceWrite?: boolean | undefined;
  /**
   * C4: set ONLY when ZEUSI_WORKSPACE_ENCRYPTION=enroll or on (C5) and personal workspaces are on. The recovery
   * limiter's counts file is <dataDir>/.zeusi/recovery-attempts.json. Unset: no change at all.
   */
  encryption?: { mode: 'enroll' | 'on'; catalog: WrapCatalog; audit?: EnrollAuditSink | undefined } | undefined;
  /**
   * C7 KTD4 (D13): the OAuth store's session-end hook (revoke, client revoke, revokeAll, revokeTenant, a reused
   * refresh, and an offline revoke picked up at the next re-read): src/mcp.ts evicts the B1 cache of that
   * workspace and the grant's feedback memo here.
   */
  onSessionEnded?: OAuthStoreOptions['onSessionEnded'];
}

/**
 * OAuth is ON only when all three secrets are present and the store loads. Otherwise every
 * OAuth route answers 503 and the bearer path is unaffected. Reasons name env vars, never values.
 */
export function oauthFromEnv(env: NodeJS.ProcessEnv, o: OAuthEnvOptions): OAuthSetup {
  const id = env[GITHUB_CLIENT_ID_ENV]?.trim() ?? '';
  const secret = env[GITHUB_CLIENT_SECRET_ENV]?.trim() ?? '';
  const key = env[SIGNING_KEY_ENV]?.trim() ?? '';
  const missing = OAUTH_ENV_VARS.filter((_, i) => [id, secret, key][i] === '');
  if (missing.length > 0) return { state: 'disabled', reason: `${missing.join(', ')} not set` };
  if (key.length < MIN_SIGNING_KEY_CHARS) return { state: 'disabled', reason: `${SIGNING_KEY_ENV} shorter than ${MIN_SIGNING_KEY_CHARS} characters` };
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(id)) return { state: 'disabled', reason: `${GITHUB_CLIENT_ID_ENV} is not a client id` };
  let store: OAuthStore;
  try {
    store = new OAuthStore({ hashKey: key, path: join(o.dataDir, 'mcp-oauth.json'), now: o.now, uid: o.uid, onSessionEnded: o.onSessionEnded });
  } catch (e) {
    return { state: 'disabled', reason: e instanceof OAuthStoreError ? e.message : 'oauth store not usable' };
  }
  return {
    state: 'enabled',
    server: new OAuthServer({
      issuer: o.issuer, githubClientId: id, github: o.github ?? liveGithubApi(id, secret), signingKey: key, store,
      cimdFetch: o.cimdFetch, now: o.now, tenants: o.tenants, audit: o.audit, workspaceWrite: o.workspaceWrite,
      ...(o.encryption ? {
        keys: {
          mode: o.encryption.mode, catalog: o.encryption.catalog, audit: o.encryption.audit,
          limiter: new RecoveryAttemptLimiter({ hashKey: key, file: join(o.dataDir, '.zeusi', 'recovery-attempts.json'), now: o.now }),
        },
      } : {}),
    }),
  };
}
