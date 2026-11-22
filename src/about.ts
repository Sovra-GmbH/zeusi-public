// What Zeusi is (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md U1, KTD1, KTD2). The ONE
// canonical self-description. Every surface derives from it:
//
//   * MCP `instructions`        ABOUT_SUMMARY, prepended (src/mcp-server.ts mcpInstructions);
//   * MCP resource zeusi://about aboutMarkdown(canWrite) (src/mcp-prompts.ts);
//   * zeusi_search `about` list  aboutSections(canWrite), matched lexically in Postgres (searchAbout),
//                                code-shipped: no database row is written for it.
//
// F4 (live finding 17 Nov 2026): every served copy describes only the tools THIS connection can
// call. canWrite is true only when zeusi_log_decision is registered (a non-read token class AND a
// write service). A read connection (read bearer, OAuth zeusi.read, no write service) never names
// the write tool; it gets one honest line that writing is not available on this connection.
// ABOUT_SECTIONS / ABOUT_MARKDOWN are the full (write-capable) text, for docs parity and tests.
// F5: a decision returned by Zeusi is cited context, not permission (section decisions-are-context).
//
// invent=NO: this text describes only what the code does. The tool list is generated from
// ABOUT_TOOLS (keyed by canonical tool name; test/about.test.ts pins it to ALL_TOOL_NAMES).
// KTD2: copies served over MCP name the wall generically (withheld() in src/mcp-wall.ts blocks
// any string that names the walled person); README and the skill keep the explicit wording.
// No secret, host, token or connection string may ever appear here (test/about.test.ts).

import type { Db } from './db.ts';
import { WORKSPACE_PERSON_HANDLE } from './tenants.ts';

export const ABOUT_URI = 'zeusi://about';
/** The ONE server URL every user-facing surface names (site, about, startup, errors). test/one-url.test.ts pins it. */
export const MCP_URL = 'https://mcp.zeusi.dev/mcp';

/** Public website (MCP websiteUrl, OAuth service_documentation / resource_documentation). */
export const SITE_URL = 'https://zeusi.ai';
/** Origin of MCP_URL. Listing icons are served here, unauthenticated, so clients can fetch them from the same host as the connector. */
export const MCP_ORIGIN = new URL(MCP_URL).origin;
/**
 * Short listing blurb for MCP `initialize` serverInfo.description (and for a client to paste into its plugin editor).
 * Describes what the connector is. Does not claim encryption.
 */
export const SERVER_DESCRIPTION =
  'Shared memory for your AI clients: standing rules, decisions and notes, each with its source.';
export const SERVER_TITLE = 'Zeusi';
/** Unauthenticated icon paths on the hosted MCP origin. */
export const ICON_PNG_PATH = '/favicon.png';
export const ICON_SVG_PATH = '/favicon.svg';
export const ICON_PNG_URL = `${MCP_ORIGIN}${ICON_PNG_PATH}`;
export const ICON_SVG_URL = `${MCP_ORIGIN}${ICON_SVG_PATH}`;
/** Same 512 PNG, served by the public site (Vercel). */
export const SITE_ICON_PNG_PATH = '/logo-512.png';
export const SITE_ICON_PNG_URL = `${SITE_URL}${SITE_ICON_PNG_PATH}`;

// ---------------------------------------------------------------------------
// Welcome (personal workspaces; docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md U3, KTD8).
// ONE source: zeusi://about for a personal workspace, zeusi_startup when that workspace is empty, the
// search `about` entries of a personal workspace, and the site guide test (test/site.test.ts). It
// names no person. Form B ("want me to fill your memory now?", docs/plans/2026-11-18-workspace-write-import-plan.md
// KTD9) is shown ONLY when filling is really available on the connection (the server has the writer on
// AND the grant has zeusi.workspace_write): fillMemoryLine(canFill). Everywhere else form A stays.

export const WELCOME_GREETING = 'Hello, I\'m Zeusi.';
export const WELCOME_INTRO =
  'I\'m a shared memory for you and your AI assistant, named after a cat. I keep your rules, locks, focus, decisions and notes, each with its source. '
  + 'I never invent: if I don\'t have something, I say so.';
export const WELCOME_DOES_HEADING = 'What I do for your assistant';
export const WELCOME_DOES: readonly string[] = [
  'At the start of a session, zeusi_startup hands it your standing rules, locks and current focus.',
  'Before a task, zeusi_context_for_task pulls the notes, locks and decisions that apply.',
  'Locks are binding: the assistant follows them instead of guessing.',
  'Every answer cites its source.',
  'A decision on record is not an approval.',
];
export const WELCOME_OWN_HEADING = 'Your own workspace';
// Says only what the tenant router enforces (src/tenants.ts: a grant is bound to one workspace, its session can
// read only that schema). It never claims operator blindness. With ZEUSI_WORKSPACE_ENCRYPTION=on, a new personal
// workspace is born encrypted (src/mcp.ts tenantSignupSetup, src/tenants.ts provision): whoever holds the admin
// database login cannot read its sealed content, but can still
// see its metadata (that it exists, row counts, sizes, times); a workspace in `off` or `enrolled` stays readable by
// that login. Nothing is end-to-end encrypted: the server decrypts while you are signed in. The welcome is served
// for EVERY personal workspace whatever its state (and on a self-hosted server with the flag off), so it carries no
// encryption line, not even the site's owner line (server copy is checked with overclaims(), not siteOverclaims();
// test/helpers/overclaim.ts serverCopy, test/site.test.ts).
export const WELCOME_OWN =
  'This workspace is your own. It starts empty. You signed in with GitHub; no invite is needed, and another user\'s Zeusi sign-in cannot read it.';
export const WELCOME_NEVER_HEADING = 'What I never store';
export const WELCOME_NEVER = 'Secrets (passwords, API keys, tokens) or private client details.';
/** Form A: the fill-your-memory feature is announced, not offered. */
export const FILL_MEMORY_COMING =
  'Filling your memory is coming. Soon I\'ll offer to fill it from your notes, and I\'ll show you a preview before anything is saved. '
  + 'For now your workspace is empty and read-only.';
/** Form B: filling is available on this connection (preview first, nothing saved until yes). */
export const FILL_MEMORY_OFFER =
  'Want me to fill your memory now? I\'ll show a preview first.\n'
  + 'Say "fill my memory" and paste your notes, or point me at an export; nothing is saved until you say yes.';
/** The form A fallback: used wherever filling is not available (writes off, or a read-only grant). */
export const FILL_MEMORY_LINE: string = FILL_MEMORY_COMING;
/** The ONE switch between form A and form B (KTD9). */
export function fillMemoryLine(canFill: boolean): string {
  return canFill ? FILL_MEMORY_OFFER : FILL_MEMORY_LINE;
}
/**
 * A personal connection with a read-only grant while this server can fill workspaces: the upgrade
 * path is one new sign-in (re-consent), never an in-place upgrade.
 */
export const RECONNECT_TO_FILL =
  `To let Zeusi fill your memory, reconnect the Zeusi connector (server ${MCP_URL}) and approve access again; your workspace stays as it is.`;

// How rules and decisions get into a personal workspace (live finding 2026-11-18: notes were
// imported, but nothing said how a rule or a decision comes about). Describes the code only:
// rules = src/note-locks.ts isStandingLock (a `locks:` item its note marks with `standing_locks:`); the
// workspace import carries `locks` / `related` (src/importers/onboard.ts CARRIED_KEYS) and a strictly
// valid `standing_locks` (onboard.ts carriedStandingLocks), the nightly sync keeps the whole frontmatter;
// decisions = src/importers/structured.ts parseEntry (markdown) and src/importers/onboard.ts
// DecisionLine (JSONL), stored for a handle the workspace knows: `me` (src/tenants.ts
// WORKSPACE_PERSON_HANDLE). test/startup-notes-not-empty.test.ts and test/workspace-person.test.ts
// prove each example below.

/** A minimal nightly-sync note (path notes/2026-11-18-release-rules.md) whose one lock is a standing rule (served by zeusi_startup). */
export const RULE_EXAMPLE_PATH = 'notes/2026-11-18-release-rules.md';
export const RULE_EXAMPLE_NOTE =
  '---\nproject: notes\nkind: memory\ndate: 2026-11-18\ntitle: Release rules\nsource: manual\nlocks:\n  - Never deploy on a Friday.\nstanding_locks: [1]\n---\nWhy: weekend cover is thin.\n';
/** A minimal markdown decision-log entry that becomes a decision (format markdown). */
export const DECISION_EXAMPLE_MARKDOWN =
  '## 2026-11-18T10:00:00+01:00 me\nDecision: go\nSaid-at-precision: minute\n\nUse preview first, then one explicit yes, for every import.\n';
/** The same decision as one JSONL line (format jsonl). */
export const DECISION_EXAMPLE_JSONL =
  '{"kind":"go","who":"me","said_at":"2026-11-18T10:00:00+01:00","said_at_precision":"minute","exact_words":"Use preview first, then one explicit yes, for every import."}';
/** How a rule comes about (one paragraph). */
export const RULES_HOWTO =
  'A rule comes from a note: list it under `locks:` in the note\'s front matter and mark it standing with `standing_locks:` (the 1-based number of the lock); '
  + 'a standing lock is served at every session start. The import of a markdown note (zeusi_import_preview, then zeusi_import_commit) and the nightly sync '
  + '(a note in the export layout, path <project>/YYYY-MM-DD-<slug>.md) both keep `locks:` and `standing_locks:`. The import drops a `standing_locks:` that is not a list of '
  + 'lock numbers of that same note, and a note whose front matter trips the safety filter is not imported at all. '
  + 'A lock without the marker is still returned by zeusi_context_for_task when a task matches it.';
/**
 * A personal workspace that does not know its person `me` yet (made before src/tenants.ts personIn, and
 * not backfilled): a headed entry cannot be stored as such (structured.ts writeStructured: unknown_person).
 * Used only where the server has checked that the workspace knows no `me` (preview, commit, startup).
 */
export const PERSONAL_DECISIONS_PENDING =
  'Saving a decision, rule or focus entry as such in this workspace is not available yet: its handle must be a person the workspace knows, and this workspace knows none yet. '
  + 'Such an entry is saved as a searchable note, and the commit result counts it (decisions_kept_as_notes).';
/**
 * The handle rule of a personal workspace (static: the decision format, and the preview / commit when an
 * entry names another handle or the workspace could not be checked). Claims only what writeStructured does.
 */
export const PERSONAL_DECISIONS_HANDLE =
  `In a personal workspace, write \`${WORKSPACE_PERSON_HANDLE}\` as the handle: it is the workspace's own person, so a decision, rule or focus entry with that handle is saved as such. `
  + 'An entry with any other handle, or in a workspace that does not know that person yet, is saved as a searchable note, and the commit result counts it (decisions_kept_as_notes).';
/** The accepted decision-log format (markdown and JSONL), with one example each. */
export const DECISION_FORMAT =
  'A decision-log entry becomes a decision only in this form. Markdown (format markdown): a heading `## <date and time with offset> <handle>` '
  + '(handle: lower-case letters, digits, dot, dash, underscore), directly under it `Decision: go|lock|ruling|stop|park` and `Said-at-precision: minute|day` '
  + '(optional: `Verbatim: yes|no`, `Applies-to: a, b`, `Expires: <date and time>`), then a blank line and the words. Any other markdown entry stays a searchable note, '
  + 'and the preview says why (kept_as_notes).\n\n'
  + `\`\`\`\n${DECISION_EXAMPLE_MARKDOWN}\`\`\`\n\n`
  + 'JSONL (format jsonl): one decision per line with kind, who, said_at, said_at_precision and exact_words (optional: exact_words_verbatim, applies_to, expires_at); '
  + 'a line that does not match is skipped. Without said_at_precision the entry stays a note.\n\n'
  + `\`\`\`\n${DECISION_EXAMPLE_JSONL}\n\`\`\`\n\n${PERSONAL_DECISIONS_HANDLE}`;

/** Own-workspace write tools, described for a personal connection that can use them (KTD9). */
export const WORKSPACE_WRITE_ABOUT: ReadonlyArray<{ name: string; summary: string }> = [
  { name: 'zeusi_import_preview', summary: 'step 1 of filling your memory: a dry run on pasted notes, a decision log or a chat export; shows counts and what would be saved; nothing is saved.' },
  { name: 'zeusi_import_commit', summary: 'step 2: saves exactly the preview you approved into your own workspace, once.' },
  { name: 'zeusi_sync_batch', summary: 'for a nightly routine you set up: adds or updates notes in your own workspace and removes the ones that are gone, through the same safety filters.' },
];
/** The personal write line (replaces NO_WRITE_LINE when filling is available). */
export const PERSONAL_WRITE_LINE =
  'Writing goes only into your own workspace, and only after a preview you approve. Logging decisions in the shared workspace is not available on this connection.';
export const SERVER_LINE = `Server: ${MCP_URL}`;

/** The welcome as markdown (zeusi://about of a personal workspace; zeusi_startup `welcome` when empty). */
export function welcomeMarkdown(fill: string = FILL_MEMORY_LINE): string {
  return [
    `# ${WELCOME_GREETING}`, '', WELCOME_INTRO, '',
    `## ${WELCOME_DOES_HEADING}`, '', ...WELCOME_DOES.map((l) => `- ${l}`), '',
    `## ${WELCOME_OWN_HEADING}`, '', WELCOME_OWN, '',
    `## ${WELCOME_NEVER_HEADING}`, '', WELCOME_NEVER, '',
    fill, '',
    SERVER_LINE,
  ].join('\n');
}
export const WELCOME_MARKDOWN: string = welcomeMarkdown();

/**
 * A personal workspace could not be opened (catalog or session failure). Actionable, names the one
 * URL, never an internal (no SQLSTATE, host, class name or stack). Tool errors and the HTTP 503 body.
 */
export const WORKSPACE_UNAVAILABLE =
  'Zeusi could not open your workspace just now. This is a temporary server problem; nothing was read or changed. '
  + `Retry in a minute. If it keeps failing, reconnect the Zeusi connector (server ${MCP_URL}) and sign in with GitHub again.`;

/** Date of the last change to this text (ISO 8601 with offset). Bump it when the wording changes. */
export const ABOUT_SOURCE_TS = '2026-11-18T12:30:00+01:00';

/**
 * Where rules, facts and focus come from (lock-lifecycle addendum K6). Said plainly on every
 * surface (about, zeusi_startup, zeusi_onboarding_status); describes the code, never a promise.
 */
export const SOURCES_OF_RULES_FACTS_FOCUS =
  'Rules come from locks in notes (standing folders); the structured facts table is empty unless a typed import writes it; '
  + 'current focus comes from the HQ sync once its typed Focus block is exported. A lock stops being current only when a newer note '
  + 'says so explicitly (supersedes:) or its own end time passes (lock_until: / until:); nothing is retired by guessing.';

export interface AboutTool {
  /** read: read-only tool; write: opt-in write; local: a local feedback ledger, no database write. */
  cls: 'read' | 'write' | 'local';
  aliases: readonly string[];
  summary: string;
}

/** Every tool the server registers, keyed by canonical name (aliases share the same handler and gates). */
export const ABOUT_TOOLS: Readonly<Record<string, AboutTool>> = {
  zeusi_startup: {
    cls: 'read', aliases: ['startup'],
    summary: 'call once at session start: standing rules, current focus and the owner\'s recent decisions.',
  },
  zeusi_context_for_task: {
    cls: 'read', aliases: ['context_for_task', 'prime'],
    summary: 'call at the start of every task with a short description of the work: the current decisions, locks and parked items that apply, ranked, cited, with conflicts flagged. An empty list means nothing matched.',
  },
  zeusi_search: {
    cls: 'read', aliases: ['search'],
    summary: 'search notes and current decisions before answering or asking the owner; also returns matching parts of this description.',
  },
  zeusi_search_feedback: {
    cls: 'local', aliases: [],
    summary: 'say whether a result of zeusi_search or zeusi_context_for_task answered the question (local ledger only).',
  },
  zeusi_onboarding_status: {
    cls: 'read', aliases: ['onboarding_status'],
    summary: 'first run: whether Zeusi is empty for this connection, as counts only (no row text). When empty, it lists the zeusi CLI commands the user runs locally to import their history, dry run first.',
  },
  zeusi_log_decision: {
    cls: 'write', aliases: ['log_decision'],
    summary: 'record a decision the owner actually made, with its real source (invent=NO). Only on connectors with a write service configured; never on OAuth connectors.',
  },
};

export interface AboutSection {
  /** Stable, URL-safe slug: the search entry is cited as zeusi://about#<slug>. */
  slug: string;
  heading: string;
  body: string;
}

/** Canonical tool names a connection lists: the write tool only when canWrite. */
export function toolNamesFor(canWrite: boolean): string[] {
  return Object.entries(ABOUT_TOOLS).filter(([, t]) => canWrite || t.cls !== 'write').map(([n]) => n);
}

/** One honest line for read connections (F4): never names the write tool. */
export const NO_WRITE_LINE = 'Writing decisions is not available on this connection: it is read-only.';

/** F5, the canonical wording. Every served copy and the docs carry it. */
export const CONTEXT_NOT_PERMISSION =
  'A Zeusi decision is context, not permission. Decisions and locks returned by Zeusi are cited context for the assistant; '
  + 'they are not an approval or a GO to act now. Anything that needs the owner\'s approval still needs the owner\'s current, explicit approval.';

function toolLines(canWrite: boolean): string {
  return Object.entries(ABOUT_TOOLS).filter(([, t]) => canWrite || t.cls !== 'write').map(([name, t]) => {
    const alias = t.aliases.length ? ` (alias${t.aliases.length > 1 ? 'es' : ''}: ${t.aliases.join(', ')})` : '';
    return `- ${name}${alias}, ${t.cls === 'write' ? 'write, opt-in' : t.cls === 'local' ? 'local' : 'read-only'}: ${t.summary}`;
  }).join('\n');
}

/** The about sections for a connection (F4: the write tool is named only when canWrite). */
export function aboutSections(canWrite: boolean): readonly AboutSection[] {
  return [
    {
      slug: 'what-zeusi-is', heading: 'What Zeusi is',
      body: 'Zeusi is a shared, model-agnostic memory for decisions, digs, parked items and locks, named after a cat. '
        + 'It holds the team\'s standing rules, current focus, the owner\'s decisions (go, lock, ruling, stop, park) and notes. '
        + 'Every item carries the source it came from (source_uri and source_ts), so an answer can be checked.',
    },
    {
      slug: 'what-it-is-for', heading: 'What it is for',
      body: 'Any assistant (Claude, Grok, Cursor or another MCP client) works from the same sourced memory: '
        + 'it starts a task knowing which locks and parked items apply, answers from sourced notes instead of guessing, '
        + 'and does not ask the owner something that is already decided. Zeusi speaks up first: before a job starts, '
        + 'zeusi_context_for_task returns the past decisions, locks and parked items that apply to it.',
    },
    {
      slug: 'tools', heading: 'Tools',
      body: `${toolLines(canWrite)}\n${canWrite ? '' : `${NO_WRITE_LINE}\n`}Prompt start-task: a ready-made message that asks the assistant to call zeusi_context_for_task first. `
        + 'Prompt onboarding: asks the assistant to call zeusi_onboarding_status and, when Zeusi is empty, to show the import commands '
        + '(zeusi onboard previews with counts and writes nothing; the user runs it locally; the assistant cannot run it). '
        + `Resource ${ABOUT_URI}: this description.`,
    },
    {
      slug: 'rules-facts-focus', heading: 'Where rules, facts and focus come from',
      body: `${SOURCES_OF_RULES_FACTS_FOCUS} zeusi_startup returns every current standing rule: served in a compact one-line form within a token budget, or listed in rules_remainder with id, subject and cite (never silently dropped), plus the total; `
        + 'zeusi_onboarding_status counts the same set (rules, rules_by_origin) and the lock items by status (current, superseded, expired). '
        + 'zeusi_context_for_task returns current locks as items and superseded or expired matches separately as history, each with what replaced it or when it ended.',
    },
    {
      slug: 'read-and-write', heading: 'Read-only by default',
      body: 'Zeusi is read-only by default. Every read tool runs as a read-only database login inside a read-only transaction. '
        + (canWrite
          ? 'Writing is opt-in: zeusi_log_decision exists only on a connector whose operator configured a write service, '
          : 'Writing is opt-in and exists only on a connector whose operator configured a write service (this one has none), ')
        + 'and connectors that sign in with OAuth (claude.ai, Claude Desktop) are always read-only. '
        + 'invent=NO: never invent a decision, person, timestamp, quote or GO; log only what the owner actually said, with its real source.',
    },
    {
      slug: 'decisions-are-context', heading: 'A decision is context, not permission',
      body: `${CONTEXT_NOT_PERMISSION} A past GO does not authorise a new action; locks, stops and parked items still limit what you do, `
        + 'but no decision widens it. When in doubt, ask the owner and cite the decision you are asking about.',
    },
    {
      slug: 'how-to-cite', heading: 'How to cite',
      body: 'Cite every item you rely on as <source_uri> @ <source_ts>. For zeusi_context_for_task items also give the decision id, '
        + 'who said it and when (said_at); each item carries a ready cite field. Parts of this description cite as zeusi://about#<section>. '
        + 'If nothing matches, say so plainly, then ask the owner.',
    },
    {
      slug: 'never-store', heading: 'What never to store',
      body: 'Never store or paste secrets, credentials, tokens, one-time or 2FA codes, connection strings, or client personal data. '
        + 'One person\'s content is excluded entirely by a hard wall: do not search for it, store it or paraphrase it. '
        + 'Walled items are left out of every answer and only counted in "withheld".',
    },
    {
      slug: 'what-a-connector-can-do', heading: 'What a connector can and cannot do',
      body: 'A connector cannot force a model to call a tool or run a script. Zeusi can only instruct and offer prompts; '
        + 'your assistant decides whether to follow them. Anything that must happen deterministically, such as importing notes, '
        + 'is done by the zeusi command-line tool, run by a person. First-run import is the same: `zeusi onboard` previews '
        + 'what an import would add (counts only, nothing written), and only `zeusi import ... --real`, run by the user with a write credential, writes.',
    },
  ];
}

/**
 * The about sections of a PERSONAL workspace (read-only; never the shared-workspace description): the welcome,
 * then the tools, decisions-are-context and how-to-cite sections shared with the shared workspace.
 */
export function personalAboutSections(canFill = false): readonly AboutSection[] {
  const shared = new Map(aboutSections(false).map((s) => [s.slug, s]));
  const writeLines = canFill ? WORKSPACE_WRITE_ABOUT.map((t) => `- ${t.name}, writes your own workspace: ${t.summary}`).join('\n') + '\n' : '';
  return [
    // The heading carries the words of "What can Zeusi do?" / "what is zeusi" (lexical match, KTD3).
    { slug: 'hello', heading: `${WELCOME_GREETING.replace(/\.$/, '')}: what Zeusi is and what it can do`, body: WELCOME_INTRO },
    { slug: 'what-i-do', heading: WELCOME_DOES_HEADING, body: WELCOME_DOES.map((l) => `- ${l}`).join('\n') },
    { slug: 'your-workspace', heading: WELCOME_OWN_HEADING, body: WELCOME_OWN },
    { slug: 'never-store', heading: WELCOME_NEVER_HEADING, body: WELCOME_NEVER },
    { slug: 'filling-memory', heading: 'Filling your memory', body: fillMemoryLine(canFill) },
    ...(canFill ? [
      { slug: 'how-rules-come-about', heading: 'How a rule comes about', body: `${RULES_HOWTO} Example (${RULE_EXAMPLE_PATH}):\n\n\`\`\`\n${RULE_EXAMPLE_NOTE}\`\`\`` },
      { slug: 'decision-format', heading: 'Decision log format', body: DECISION_FORMAT },
    ] : []),
    { ...shared.get('tools')!, body: `${toolLines(false)}\n${writeLines}${canFill ? PERSONAL_WRITE_LINE : NO_WRITE_LINE}\nResource ${ABOUT_URI}: this description.` },
    shared.get('decisions-are-context')!,
    shared.get('how-to-cite')!,
  ];
}

/** The full, write-capable sections (docs parity, tests). Served copies use aboutSections(canWrite). */
export const ABOUT_SECTIONS: readonly AboutSection[] = aboutSections(true);

/** The full text served as the zeusi://about resource (text/markdown) for a connection. */
export function aboutMarkdown(canWrite: boolean, workspace: 'team' | 'personal' = 'team', canFill = false): string {
  if (workspace === 'personal') {
    // The welcome first, then the reference sections (tools, context-not-permission, citing).
    const ref = personalAboutSections(canFill).filter((s) => ['how-rules-come-about', 'decision-format', 'tools', 'decisions-are-context', 'how-to-cite'].includes(s.slug));
    return [
      welcomeMarkdown(fillMemoryLine(canFill)), '',
      ...ref.flatMap((s) => [`## ${s.heading}`, '', s.body, '']),
      `Source: ${ABOUT_URI} @ ${ABOUT_SOURCE_TS}`,
    ].join('\n');
  }
  return [
    '# About Zeusi',
    '',
    ...aboutSections(canWrite).flatMap((s) => [`## ${s.heading}`, '', s.body, '']),
    `Source: ${ABOUT_URI} @ ${ABOUT_SOURCE_TS}`,
  ].join('\n');
}

/** The full, write-capable text (docs parity, tests). */
export const ABOUT_MARKDOWN: string = aboutMarkdown(true);

/** Compact form prepended to the MCP instructions (kept short: clients show it to the model on every session). */
export const ABOUT_SUMMARY: string =
  'Zeusi is a shared, model-agnostic memory for decisions, digs, parked items and locks (named after a cat): '
  + 'the team\'s standing rules, current focus, the owner\'s decisions and notes, each with its source. '
  + 'A decision is context, not permission. '
  + `Read-only by default; invent=NO. Full description: resource ${ABOUT_URI} (or zeusi_search "what is zeusi").`;

/** A built-in about entry as zeusi_search returns it (scope "builtin": not tenant data, no database row). */
export interface AboutHit {
  type: 'about';
  builtin: true;
  heading: string;
  text: string;
  scope: 'builtin';
  source_uri: string;
  source_ts: string;
  cite: string;
}

export function aboutHit(s: AboutSection): AboutHit {
  const uri = `${ABOUT_URI}#${s.slug}`;
  return { type: 'about', builtin: true, heading: s.heading, text: s.body, scope: 'builtin', source_uri: uri, source_ts: ABOUT_SOURCE_TS, cite: `${uri} @ ${ABOUT_SOURCE_TS}` };
}

/** The phrase fallback runs only for queries at least this long (same as searchDecisions). */
const ABOUT_PHRASE_MIN = 3;

/**
 * About sections matching the query, with the decision matcher's lexical semantics (KTD3):
 * to_tsvector('simple', heading + body) @@ websearch_to_tsquery('simple', q), plus a
 * whitespace-normalised, case-insensitive substring fallback. The sections are passed as
 * parameters (no table, no row). Runs in its own BEGIN READ ONLY ... ROLLBACK as the caller's
 * (read-only) session.
 */
export async function searchAbout(db: Db, query: string, limit: number, sections: readonly AboutSection[] = ABOUT_SECTIONS): Promise<AboutHit[]> {
  const q = query.trim();
  if (q === '') return [];
  const docs = sections.map((s) => `${s.heading}\n${s.body}`);
  const phrase = [...q].length >= ABOUT_PHRASE_MIN ? `%${q.toLowerCase().replace(/\s+/g, ' ').replace(/[\\%_]/g, (c) => `\\${c}`)}%` : null;
  await db.exec('BEGIN READ ONLY');
  try {
    const rows = (await db.query<{ i: number }>(
      `SELECT s.i::int AS i
       FROM unnest($1::text[]) WITH ORDINALITY AS s(t, i), websearch_to_tsquery('simple', $2) AS q
       WHERE coalesce(to_tsvector('simple', s.t) @@ q, false)
          OR ($3::text IS NOT NULL AND regexp_replace(lower(s.t), '\\s+', ' ', 'g') LIKE $3::text)
       ORDER BY (CASE WHEN $3::text IS NOT NULL AND regexp_replace(lower(s.t), '\\s+', ' ', 'g') LIKE $3::text THEN 1 ELSE 0 END
                 + coalesce(ts_rank_cd(to_tsvector('simple', s.t), q), 0)) DESC, s.i
       LIMIT $4`,
      [docs, q, phrase, limit],
    )).rows;
    return rows.map((r) => aboutHit(sections[r.i - 1]!));
  } finally {
    await db.exec('ROLLBACK').catch(() => {});
  }
}
