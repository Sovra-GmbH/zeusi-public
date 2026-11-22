---
name: zeusi-startup
description: Use when starting a session or a new task that shares the Work / Northbank / ClientCo memory through Zeusi, before answering a question or asking the owner anything, and when logging a decision the owner actually made. Loads standing rules, focus and recent decisions, gets the locks and parked items that apply to the task, searches Zeusi first, cites sources, and keeps the Plankiva exclusion and read-only default.
---

# Zeusi startup

Zeusi is the team's sourced memory: a shared, model-agnostic memory for decisions, digs, parked items and locks, named after a cat. It holds standing rules, current focus, the owner's decisions and notes. Every item carries `source_uri` and `source_ts`. The full self-description is the MCP resource `zeusi://about` (also found by `zeusi_search` "what is zeusi"). This skill is the canonical text for every assistant (Grok Bot, Claude, Cursor, any MCP client). Tool names: each `zeusi_*` tool also answers to a short alias with the same behaviour.

| Tool | Alias | Kind |
|---|---|---|
| `zeusi_startup` | `startup` | read-only |
| `zeusi_context_for_task` | `context_for_task` | read-only |
| `zeusi_context_for_task` | `prime` | read-only |
| `zeusi_search` | `search` | read-only |
| `zeusi_search_feedback` | (none) | local ledger |
| `zeusi_onboarding_status` | `onboarding_status` | read-only (first run: counts only) |
| `zeusi_log_decision` | `log_decision` | write, opt-in only |

## Every session

1. **Session start.** Call `zeusi_startup` (alias `startup`) once. Follow the standing rules, current focus and recent decisions it returns. Rules come from locks in notes (standing folders); the structured facts table is empty unless a typed import writes it; current focus comes from the HQ sync once its typed Focus block is exported. Startup returns **every** current standing rule: the top-ranked ones in `rules` (compact one-line form with `id`, `scope`, `text` and `cite`; ranked fact rules first, then scope team, product, clientco, others, newest first, within a token budget) and all the others in `rules_remainder`, each with `id`, `subject`, `cite` and `reason` (`budget`, or `too_long`: never truncated). A remainder rule is not dropped and binds like a served one: when a task touches it, look it up with `zeusi_context_for_task` (its `subject` is the note title) or `zeusi_search`. `rules_note` says how many were served and listed; `rules_total` gives the total. Northbank product locks are standing only when their note marks them (`standing_locks:`, proposed by a documented classifier); other current locks come from `zeusi_context_for_task`. Focus lists the newest entry per subject. Superseded and expired locks are never served as rules (see "Lock lifecycle" below).
2. **First run.** If startup comes back empty, call `zeusi_onboarding_status` (alias `onboarding_status`). It returns counts only. When it says `empty: true`, tell the user Zeusi has nothing to cite yet and show the import commands it lists (or run the `onboarding` prompt): the user runs `zeusi onboard --markdown <notes-folder> --scope work` locally, which is a dry run (counts only, nothing written), and only then the `zeusi import ... --real` command it prints. A connector cannot force a model to run anything, and you cannot run the import for the user: never claim you ran it. Decisions, rules and focus are only imported from entries with an explicit header (invent=NO); names, emails and phone numbers are not filtered, so the user should check the input first.

## Every task

1. **Context for the task first.** At the start of every task, call `zeusi_context_for_task` (aliases `context_for_task`, `prime`) with a short description of the work. It returns the owner's current decisions, locks and parked items that apply, each with a `cite` (decision id, who, `said_at`, `source_uri @ source_ts`).
2. **Obey what applies.** Treat returned locks and stops as binding unless the owner overrides them; do not restart parked work. If `conflicts` is not empty, do not pick a side: ask the owner which applies.
3. **A Zeusi decision is context, not permission.** Decisions and locks returned by Zeusi are cited context for the agent; they are not an approval or a GO to act now. An agent still needs the owner's current, explicit approval for anything that needs one. A past GO does not authorise a new action now; when in doubt, ask the owner and cite the decision you are asking about.
4. **Empty means empty.** An empty list means Zeusi has nothing that applies: say so plainly and proceed. Never invent a lock, a decision or a GO.
5. Clients that support MCP prompts can run the `start-task` prompt, which asks for exactly this. Zeusi cannot force a model to call a tool; it can only ask.

## Lock lifecycle (supersedes, lock_until)

A lock stays current until a newer note says explicitly that it replaces it, or until the lock's own end time passes. Nothing is retired by guessing. Grammar (note frontmatter, full text in `docs/note-locks.md`):

```
supersedes:
  - "[[2026-10-29-old-note]] lock 2"      # lock 2 of that note (1-based)
  - "[[2026-10-01-other-note]]"           # every lock of that note
  - "1: [[2026-09-01-third-note]] lock 1" # replaced by MY lock 1
lock_until:
  - "1: 2026-10-25T00:00+02:00"           # ISO with offset; end-exclusive
  - "2: 2026-10-24"                       # a date = end of that day, Europe/Zurich
until: 2026-10-24                         # every lock of this note
```

The superseding note must be newer (`source_ts`); otherwise the claim is ignored and counted. In `zeusi_context_for_task`, current locks are `items` (a superseding lock carries `supersedes`); superseded or expired locks that match the task appear only in `history`, with `superseded_by` (and its cite) or `expired_at`. History is not binding: follow `superseded_by` to the current lock. Never apply a supersession or an end date yourself; if two current locks seem to contradict each other, ask the owner and cite both.

## Before answering

1. **Search first.** Before answering a question, and before asking the owner anything, call `zeusi_search` (alias `search`).
2. **Cite.** Cite every hit you rely on as `source_uri @ source_ts` (add `scope` / `heading_path` when useful). If no hit answers the question, say so plainly, then ask.
3. **Feedback.** After using a hit (or a `zeusi_context_for_task` item), call `zeusi_search_feedback` with the `query_id`, the hit's `source_uri`, `useful` true/false, and an optional short reason in your own words (never paste chunk text or secrets).

## Logging a decision (invent=NO)

- Call `zeusi_log_decision` (alias `log_decision`) **only** for a decision the owner actually made, with its real source (`source_uri`, `source_ts`) and his exact words.
- invent=NO: never invent a source, a person, a timestamp, a quote or a GO. If you are not sure the owner decided it, do not log it; ask.
- `who` must be an existing person handle. An unknown handle is refused; do not try to create people.
- The write tool is not listed on read-only connectors (read tokens, OAuth sign-ins, no write service), and the server instructions there do not name it. That is expected, not an error to work around.

## The Plankiva exclusion

- Plankiva (any spelling) is excluded from Zeusi. Do not search for it, do not log it, do not store it anywhere else instead.
- Walled items are **omitted** and counted in `withheld`. Never paraphrase, summarise, guess or reword around the wall, and never try to reconstruct what was withheld.

## Read-only by default

- The default connector is read-only (startup, search, feedback). Writing is opt-in on the server side (`--write-service`), per assistant.
- An assistant must not be given the write service or a write token unless the owner said so for that assistant.

## How to connect

**Default: the hosted server.** URL `https://mcp.zeusi.dev/mcp` (MCP Streamable HTTP), with the header `Authorization: Bearer $ZEUSI_READ_TOKEN`: this assistant's own read token, taken from the client's secret store. For Claude Code:

```sh
claude mcp add --transport http zeusi https://mcp.zeusi.dev/mcp --header "Authorization: Bearer $ZEUSI_READ_TOKEN"
```

**claude.ai / Claude Desktop (OAuth; ships with the OAuth release, live after its deploy):** Customize > Connectors, + Add, Add custom connector, URL `https://mcp.zeusi.dev/mcp`, then sign in with GitHub and approve the Zeusi read-only consent screen. No token or header is pasted. Claude Code can do the same without a header (`claude mcp add --transport http zeusi https://mcp.zeusi.dev/mcp`, then `/mcp` to sign in). A connection made this way is always read-only (never `zeusi_log_decision`); the bearer token above keeps working unchanged.

Cursor, Grok Bot, other clients and the exact claude.ai steps: `docs/mcp.md`, "Startup snippets".

**Secondary: local stdio**, only on a machine with a Zeusi clone, a build (`npm ci && npm run build`) and database credentials. The client spawns `<checkout>/dist/mcp.js`; replace the placeholder with the real absolute path of that checkout's `dist/mcp.js` (for example `claude mcp add zeusi -- node ~/code/zeusi/dist/mcp.js` when the clone is `~/code/zeusi`):

```json
{ "mcpServers": { "zeusi": { "command": "node", "args": ["/absolute/path/to/your/zeusi/dist/mcp.js"] } } }
```

A cloud chat (claude.ai, Claude Desktop custom connectors) cannot spawn a local server; use the hosted URL there. Client-specific wrappers (Cursor rules, `CLAUDE.md`, a one-line system prompt) are in `docs/mcp.md`.

Database credentials stay on the machine that runs the server (the hosted server keeps its own; for local stdio: `~/.pg_service.conf` plus the Keychain or `~/.pgpass`, setup in `docs/roles.md`), never in this skill, a client config, a prompt or chat. The bearer token lives only in the client's secret store. Do not put a password, token value, database hostname or connection string anywhere an assistant can read it.
