// GitHub sign-in for the hosted MCP OAuth flow (docs/hosting.md "OAuth for claude.ai").
// GitHub is only the identity check in front of Zeusi's own consent screen: Zeusi asks for
// read:user and user:email, reads the login and the VERIFIED emails once, and drops the
// GitHub token right after (never stored, never logged).
//
// operator membership (docs/plans/2026-11-18-open-signup-workspaces-plan.md R1). A sign-in is a
// OPERATOR MEMBER when EITHER holds (every comparison is case-insensitive):
//   GitHub login   OperatorOwner
//   verified email operator@example.com, owner@example.com
// Nothing else, and nobody is added here for testers: operator members reach the team workspace.
// Every other GitHub identity gets its own personal workspace (src/mcp-oauth.ts, src/tenants.ts),
// keyed by the GitHub user id, never by login or email. The lists are never echoed to anyone.
// allow_signup=false stays: open sign-up means any EXISTING GitHub account, not a new one.

export const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
export const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
export const GITHUB_API = 'https://api.github.com';
export const GITHUB_SCOPES = 'read:user user:email';
export const GITHUB_TIMEOUT_MS = 8000;
const MAX_JSON_BYTES = 256 * 1024;

export const OPERATOR_GITHUB_LOGINS: readonly string[] = ['operatorowner'];
export const OPERATOR_EMAILS: readonly string[] = ['operator@example.com', 'owner@example.com'];

export interface GithubIdentity {
  id: number;
  login: string;
  /** Verified emails only. */
  verifiedEmails: string[];
}

/** The calls Zeusi makes to GitHub (injected in tests; no network there). */
export interface GithubApi {
  /** Code -> GitHub access token, or null on any refusal. */
  exchange(code: string, redirectUri: string): Promise<string | null>;
  /** The signed-in user and their verified emails, or null. */
  identity(githubToken: string): Promise<GithubIdentity | null>;
}

export function githubAuthorizeUrl(clientId: string, redirectUri: string, state: string): string {
  const u = new URL(GITHUB_AUTHORIZE_URL);
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('scope', GITHUB_SCOPES);
  u.searchParams.set('state', state);
  u.searchParams.set('allow_signup', 'false');
  return u.toString();
}

/** operator member check. Only verified emails count; the login check is case-insensitive. */
export function isOperatorMember(who: GithubIdentity): boolean {
  if (OPERATOR_GITHUB_LOGINS.includes(who.login.toLowerCase())) return true;
  return who.verifiedEmails.some((e) => OPERATOR_EMAILS.includes(e.trim().toLowerCase()));
}

type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

async function json(res: Response): Promise<unknown> {
  if (!res.ok) return null;
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_JSON_BYTES) return null;
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    return null;
  }
}

/** Live GitHub calls (fetch, short timeouts, no redirects followed). */
export function liveGithubApi(clientId: string, clientSecret: string, fetchImpl: FetchLike = fetch): GithubApi {
  const call = (url: string, init: RequestInit) => fetchImpl(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS) });
  const api = (path: string, token: string) => call(`${GITHUB_API}${path}`, {
    headers: { accept: 'application/vnd.github+json', authorization: `Bearer ${token}`, 'user-agent': 'zeusi-mcp', 'x-github-api-version': '2022-11-28' },
  }).then(json);
  return {
    async exchange(code, redirectUri) {
      try {
        const body = new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri });
        const j = await call(GITHUB_TOKEN_URL, {
          method: 'POST', body, headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'zeusi-mcp' },
        }).then(json) as { access_token?: unknown } | null;
        return j && typeof j.access_token === 'string' && j.access_token.length > 0 && j.access_token.length < 512 ? j.access_token : null;
      } catch {
        return null;
      }
    },
    async identity(token) {
      try {
        const u = await api('/user', token) as { id?: unknown; login?: unknown } | null;
        if (!u || typeof u.id !== 'number' || !Number.isSafeInteger(u.id) || typeof u.login !== 'string' || !/^[A-Za-z0-9-]{1,39}$/.test(u.login)) return null;
        const e = await api('/user/emails', token);
        const verifiedEmails = Array.isArray(e)
          ? e.filter((x): x is { email: string; verified: true } => !!x && typeof x === 'object' && typeof x.email === 'string' && x.verified === true).map((x) => x.email)
          : [];
        return { id: u.id, login: u.login, verifiedEmails };
      } catch {
        return null;
      }
    },
  };
}
