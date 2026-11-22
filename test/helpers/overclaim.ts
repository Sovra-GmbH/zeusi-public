// The privacy / encryption over-claim ban (docs/plans/site-wow.md check g; review r1 F2 of PR #35), shared by
// test/site.test.ts (shipped site files AND the server's served copy) and test/site-terminal.test.ts (the live
// zeusi_startup reply). Today's truth: another user's Zeusi sign-in cannot read a workspace (src/tenants.ts
// router). With ZEUSI_WORKSPACE_ENCRYPTION=on, a new personal workspace is born encrypted
// (src/mcp.ts tenantSignupSetup, src/tenants.ts provision) and its key opens only with a passkey PRF,
// a recovery code or a live session token (src/workspace-keys.ts; the OAuth store
// keeps only token hashes). The server still decrypts while you are signed in, so nothing is end-to-end encrypted.
// The ONLY encryption wording allowed is: the one negative sentence in ALLOWED_ENCRYPTION (everywhere), and the
// owner-approved line OWNER_ENCRYPTION_LINE (site files only, siteOverclaims). Every other "encrypt" (a "New personal
// workspaces are encrypted.", "All workspaces are encrypted.", "Encrypted at rest.", "... not end-to-end encrypted
// yet.", any paraphrase of the owner line) and every "only you" is an over-claim. No copy may promise more.
import * as about from '../../src/about.ts';
import * as onboarding from '../../src/onboarding.ts';
import * as mcpServer from '../../src/mcp-server.ts';
import * as workspaceWrite from '../../src/workspace-write.ts';
import * as readRoute from '../../src/read-route.ts';

const SUBJECT = String.raw`(?:we|us|our (?:team|staff|engineers|admins?)|staff|operators?|admins?|administrators?|the people who run (?:it|zeusi)|zeusi|team|anyone|no ?one|nobody)`;
const CANT = String.raw`(?:never|do not|don['’]t|does not|doesn['’]t|can ?not|can['’]t|won['’]t|will not|are unable to|is unable to)`;

export const OVERCLAIM: readonly RegExp[] = [
  /encrypt/i, /end[- ]to[- ]end/i, /\bE2EE?\b/i, /zero[- ]knowledge/i, /private by design/i,
  /\bonly (?:to )?you\b/i, // "only you", "only you can", "only you have access", "visible only to you"
  /\b(?:yours|you) alone\b/i, /\bprivate to you\b/i, /\bfor your eyes only\b/i,
  /\bno(?:body|[- ]one) else\b/i, // "nobody else can see/read", "no one else has access"
  new RegExp(String.raw`\b${SUBJECT} ${CANT} (?:even )?(?:see|read|access|look at|view)\b`, 'i'), // "we never see", "operators cannot read", "nobody can see"
  /\b(?:nobody|no[- ]?one)(?: but you)? (?:else )?(?:can|could|will|is able to|has access)\b/i, // "nobody can read it", "no one but you can see it"
  /\bno access to your\b/i, /\bnot even (?:us|we|our|the|zeusi|team|operators?|admins?|staff)\b/i,
  /\bcan(?:not|['’]t| not) (?:see|read|access|view) your\b/i, // "can't see your", "cannot read your"
  /(?<!\bnot )\bhidden from (?:us|everyone|operators?|staff|admins?|the people who run)\b/i,
];

/**
 * The only encryption wording that may ship: exactly this negative sentence, case-sensitive, final period
 * included, at the start of a sentence (start of text, after `.`/`!`/`?` and whitespace, or right after a tag).
 * It is removed before OVERCLAIM runs, so `/encrypt/i` and `/end[- ]to[- ]end/i` still catch every other use,
 * including "... not end-to-end encrypted yet." and "... not end-to-end encrypted, but ...". Shipped in
 * site/index.html ("What not to put in it"); pinned by test/site.test.ts check g.
 */
export const ALLOWED_ENCRYPTION: readonly string[] = [
  'Your workspace is not end-to-end encrypted.',
];

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const ALLOWED_RE = new RegExp(String.raw`(?<=^|[.!?]\s+|>\s*)(?:${ALLOWED_ENCRYPTION.map(escapeRe).join('|')})`, 'g');

/** Every regex in OVERCLAIM that matches `body` (empty = clean), after removing the ALLOWED_ENCRYPTION sentences. */
export function overclaims(body: string): RegExp[] {
  const rest = body.replace(ALLOWED_RE, ' ');
  return OVERCLAIM.filter((re) => re.test(rest));
}

/**
 * The owner-approved encryption line (owner decision 21 Nov 2026 06:50 Europe/Zurich, approved verbatim), shipped on
 * site/index.html ("What not to put in it") and site/security/index.html. Exactly these two sentences, case-sensitive,
 * both periods included, at the start of a sentence and followed by whitespace, a tag or the end. Removed only by
 * siteOverclaims (shipped site files): the server's copy is checked with overclaims() and never gets it. Any variant
 * ("Only you hold the keys.", "...; only you hold the key.", "Only you hold the key, not even ...") is still caught by
 * /encrypt/i or /only you/i.
 */
export const OWNER_ENCRYPTION_LINE = 'Your memory is encrypted. Only you hold the key.';
const OWNER_LINE_RE = new RegExp(String.raw`(?<=^|[.!?]\s+|>\s*)${escapeRe(OWNER_ENCRYPTION_LINE)}(?=\s|<|$)`, 'g');

/** overclaims() for a shipped site file: the exact OWNER_ENCRYPTION_LINE is removed first, nothing else. */
export function siteOverclaims(body: string): RegExp[] {
  return overclaims(body.replace(OWNER_LINE_RE, ' '));
}

/**
 * The sentences that sit with the owner line (PR #56 encline; owner decision 21 Nov 2026 06:50). Each is pinned word for
 * word by test/site.test.ts and test/site-pages.test.ts, so a change on a page or here turns them red.
 * - SIGNED_IN_SENTENCE (index, security): the plan's must-add caveat (docs/plans/2026-11-18-zeusi-workspace-encryption.md
 *   §10: the server decrypts while you are signed in; src/mcp-oauth.ts sessionKeyFor, src/b1-cache.ts proveSessionWrap).
 * - ADMIN_LOGIN_SENTENCE (index, privacy, security): replaces "whoever holds the admin database login can read
 *   workspaces", no longer true for a born-encrypted personal workspace (content columns sealed, src/tenant-overlay.ts
 *   OVERLAY_SPEC + flip CHECKs); the plan §10 metadata line (sizes leak: AES-GCM has no padding).
 * - PRIVACY_KEY_DETAIL (privacy): the owner's factual detail. The wraps are passkey PRF and recovery code
 *   (src/workspace-keys.ts enrollmentWraps; migrations/0014 kind CHECK) and the per-grant session wraps under the live
 *   access / refresh token (sealSessionWraps; the store keeps only token HMACs, src/mcp-oauth-store.ts createGrant).
 */
export const SIGNED_IN_SENTENCE = 'It is not hidden from the people who run Zeusi while you are signed in: the Zeusi server then decrypts your memory to answer your assistant.';
export const ADMIN_LOGIN_SENTENCE = 'Whoever holds the admin database login can see that your workspace exists, how many items it holds, how large they are and when it changes.';
export const PRIVACY_KEY_DETAIL = [
  'The workspace key is opened only by your passkey, your recovery code, or your signed-in session.',
  'While you are signed in, the Zeusi server decrypts your memory to answer your AI assistant.',
] as const;

function strings(v: unknown, out: string[], depth = 0): void {
  if (depth > 4 || v === null || v === undefined) return;
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out, depth + 1);
  else if (typeof v === 'object') for (const x of Object.values(v)) strings(x, out, depth + 1);
}

const EMPTY_STATUS: onboarding.OnboardingStatus = {
  empty: true, scope: null, cap: onboarding.ONBOARDING_COUNT_CAP, rulesByOrigin: { fact: 0, note_lock: 0 },
  counts: Object.fromEntries(onboarding.ONBOARDING_COUNT_KEYS.map((k) => [k, 0])) as onboarding.OnboardingStatus['counts'],
  capped: Object.fromEntries(onboarding.ONBOARDING_COUNT_KEYS.map((k) => [k, false])) as onboarding.OnboardingStatus['capped'],
};

/**
 * The server's user- and model-facing copy as it is served: every exported string (and string inside an
 * exported array / object) of src/about.ts, src/onboarding.ts, src/mcp-server.ts and src/workspace-write.ts
 * (its refusals, C6 KTD14: WORKSPACE_CHANGING, WORKSPACE_LOCKED) and src/read-route.ts (C7 KTD13: WORKSPACE_READ_LOCKED,
 * WORKSPACE_READ_CHANGING), plus the rendered
 * welcome, zeusi://about, MCP instructions, empty states and onboarding status for every connection form.
 */
export function serverCopy(): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const [mod, ns] of [['src/about.ts', about], ['src/onboarding.ts', onboarding], ['src/mcp-server.ts', mcpServer], ['src/workspace-write.ts', workspaceWrite], ['src/read-route.ts', readRoute]] as const) {
    for (const [name, v] of Object.entries(ns)) {
      if (typeof v === 'function') continue;
      const s: string[] = [];
      strings(v, s);
      for (const x of s) out.push([`${mod} ${name}`, x]);
    }
  }
  const bools = [true, false];
  for (const f of bools) out.push([`welcomeMarkdown(fillMemoryLine(${f}))`, about.welcomeMarkdown(about.fillMemoryLine(f))]);
  for (const w of bools) for (const ws of ['team', 'personal'] as const) for (const f of bools) {
    out.push([`aboutMarkdown(${w}, ${ws}, ${f})`, about.aboutMarkdown(w, ws, f)]);
    out.push([`mcpInstructions(${w}, ${ws}, ${f})`, mcpServer.mcpInstructions(w, ws, f)]);
  }
  for (const f of bools) {
    out.push([`personalAboutSections(${f})`, JSON.stringify(about.personalAboutSections(f))]);
    out.push([`aboutSections(${f})`, JSON.stringify(about.aboutSections(f))]);
    out.push([`personalEmptyStates(${f})`, JSON.stringify(mcpServer.personalEmptyStates(f))]);
    out.push([`startupNoRulesMessage(3, false, 0, ${f})`, mcpServer.startupNoRulesMessage(3, false, 0, f)]);
  }
  for (const s of [EMPTY_STATUS, { ...EMPTY_STATUS, empty: false }]) {
    for (const fill of ['on', 'reconnect', 'off'] as const) out.push([`onboardingJson(personal, ${fill}, empty=${s.empty})`, JSON.stringify(onboarding.onboardingJson(s, 'personal', fill))]);
    out.push([`onboardingJson(team, empty=${s.empty})`, JSON.stringify(onboarding.onboardingJson(s, 'team'))]);
  }
  return out;
}
