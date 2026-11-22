# Zeusi MCP connector

`your-zeusi-mcp` (`node dist/mcp.js`) is a model-agnostic [MCP](https://modelcontextprotocol.io) server built on the official SDK (`@modelcontextprotocol/sdk`). Any MCP client can use it: Claude Code, Claude Desktop, Cursor, Grok Bot, or anything else that speaks MCP. It gives the model Zeusi's standing rules, current focus and recent decisions at session start. It also lets the model search Zeusi before it answers or asks the owner. Code: `src/mcp.ts` (bin), `src/mcp-server.ts` (tools and gates), `src/mcp-wall.ts`, `src/decisions.ts`, `src/feedback.ts`. Tests: `test/mcp.test.ts` (PGlite and fakes only).

The canonical assistant guidance is the skill [`skills/zeusi-startup/SKILL.md`](../skills/zeusi-startup/SKILL.md) (install notes: `skills/README.md`). The hosted, token-authenticated mode (`--hosted`, token CLI `zeusi mcp-token`) is **live** at `https://mcp.zeusi.dev/mcp` (Fly.io `fra`; MCP Streamable HTTP, bearer token per assistant). It is the default way to connect: see "Startup snippets" below. Hosting notes: [`docs/hosting.md`](hosting.md).

It reads through the existing read-only roles and transports. It writes decisions into the existing `zeusi.decisions` table as `zeusi_box_decision`, a narrow decision-only login designed in `migrations/0012_decision_write_role.sql` (**not applied yet**; `docs/roles.md`), or, until 0012 is applied and its password is set, as the transitional `zeusi_box_rw` login.

## Run it

```sh
npm ci && npm run build
node dist/mcp.js                               # stdio, read-only (startup, search, feedback)
node dist/mcp.js --write-service zeusi_decision   # also enables zeusi_log_decision (zeusi_box_decision, after 0012)
node dist/mcp.js --write-service zeusi_rw      # transitional: zeusi_log_decision as zeusi_box_rw until 0012 is applied
node dist/mcp.js --http --port 8787            # streamable HTTP on 127.0.0.1 only (optional)
node dist/mcp.js --hosted --data-dir /data     # authenticated streamable HTTP; what the Fly machine runs (mcp.zeusi.dev)
node dist/mcp.js --help
```

- **stdio** is the binary's default mode and is what a local client spawns. stdout carries the MCP protocol only. One status line goes to stderr, with no secrets and no hosts.
- **Streamable HTTP** is optional and off by default. It is stateless and listens at `http://127.0.0.1:<port>/mcp`. `--host` accepts only `127.0.0.1`, `::1` or `localhost`. Any other address is refused, and DNS-rebinding protection is on. There is no auth layer, so do not expose it beyond the machine. It is unchanged by the hosted mode.
- **Hosted** (`--hosted`) is the separate, authenticated entry point for `mcp.zeusi.dev` (`docs/hosting.md`, "Hosted mode"). Every request needs `Authorization: Bearer <token>` with a token from `zeusi mcp-token mint`. It fails closed: HTTP 503 until a valid tokens file exists, HTTP 401 for any bad, revoked, expired or wrong-class token, HTTP 429 over the limits, and HSTS on every response. Read tokens never see `zeusi_log_decision`; write tokens still need `--write-service` and pass the same write gate. On Fly the write service is an operator opt-in (`ZEUSI_MCP_WRITE_SERVICE` + `ZEUSI_DECISION_PGPASS`; `docs/hosting.md`, Write service). `--hosted` and `--http` exclude each other.
- **Connections** use the same `~/.pg_service.conf` sections as the CLI (template `config/pg_service.example.conf`). Passwords come from the same places as the CLI: Keychain / `~/.pgpass`, and the box-reader password from the same secret store as the CLI (see `.env.example` and `docs/roles.md`). Nothing is read from `.env.local`.
- **`ZEUSI_TRANSPORT=serverless`** sends `zeusi_startup` and `zeusi_search` over the existing wss/443 transport (`src/transport.ts`, read-only logins only). With it unset, they use the TCP default. `zeusi_log_decision` is refused while it is set, because that auth exception is for read-only roles only.
- **Semantic search** needs an OpenAI API key in the server's environment (see `.env.example`). Without it, search is lexical and says so in `notice`. The same local query-spend caps apply (`docs/embeddings.md`).

## Tools

Each main tool also answers to a short alias with the same input schema, handler, gates and walls: `startup` = `zeusi_startup`, `search` = `zeusi_search`, `log_decision` = `zeusi_log_decision`, and `context_for_task` = `prime` = `zeusi_context_for_task`. The `zeusi_*` names stay canonical. `zeusi_search_feedback` has no alias.

| Tool | Kind | Role | What it returns |
|---|---|---|---|
| `zeusi_startup` | read-only | `zeusi_box_ro` / `zeusi_cloud_ro` | `rules` (every current standing rule, served in a compact one-line form `{ id, origin, scope, text, source_uri, source_ts, cite }` within a 16 000-token budget, ranked fact rules first, then scope `work` > `product` > `client` > others, newest first: `facts_current` kind `rule` with `origin: "fact"`, and the CURRENT lock items of the standing notes with `origin: "note_lock"`, after explicit supersession and expiry: see "Rules from note locks" and `docs/note-locks.md`), `rules_remainder` (every other current standing rule, listed with `id`, `subject`, `cite` and `reason` `budget` / `too_long`: never silently dropped), `rules_total` (`{ fact, note_lock, total, visible, capped }`), `rules_served`, `rules_remainder_count`, `rules_budget`, `rules_note`, `sources` (where rules, facts and focus come from), `focus` (`facts_current` kind `state`; when none is visible, `focus_message` says that no current focus is recorded, where it would come from (typed `Type: focus` entries, the HQ sync once its typed Focus block is exported), and that this is not proof there is none), `decisions` (`decisions_current`, `said_at` in the last `days`, default 14, max 90; with `who`, `exact_words`, `applies_to` and the link fields, see "Decision links"). Every item has `source_uri` + `source_ts`; rules also have `cite`. There is also a `withheld` count. Rules have no item cap (budget + remainder); focus: newest per (scope, subject), at most 20, older same-subject rows counted in `focus_older_same_subject`; 50 decisions. |
| `zeusi_context_for_task` | read-only | `zeusi_box_ro` / `zeusi_cloud_ro` | "Zeusi speaks up first": call at the start of every task with `task` (1..4000 characters), optional `scope` and `limit` (1..50, default 10). Returns the current decisions, locks and parked items that apply in `items`, each with `type`, `origin`, `id`, `kind`, `who`, `date` (`said_at`, `source_ts`), `exact_words`, `applies_to`, `expires_at`, `scope`, `source_uri`, `source_ts` and `cite` (decisions also carry the link fields), plus matching CURRENT note locks (`type: "lock"`, `origin: "note_lock"`, `status: "current"`, `id` and `who` null; a superseding lock carries `supersedes`); `history` (only when non-empty: superseded or expired lock matches, with `superseded_by` and its `cite`, or `expired_at`; not binding); `conflicts` between current items; `withheld`; `query_id`. See "Context for a task". |
| `zeusi_search` | read-only | `zeusi_box_ro` / `zeusi_cloud_ro` | The existing `search()` with the same caps: `limit` 1..50 (default 10, per list), `scope` `work`, `product` or `client`, and optional `hybrid` (default `true`: the full-text branch always runs, so a chunk without an embedding is still found when a key is set; `hybrid: false` asks for vector-only). Each chunk hit in `hits` has `source_uri`, `source_ts`, `scope`, `heading_path`, the chunk `text` (never more) and `score`. Matching current decisions come back in `decisions` (see "Search covers decisions"). The response also has a `query_id` for feedback and a `withheld` count (chunks and decisions together). Matching parts of the built-in about text come back in `about` (see "About and prompts"). |
| `zeusi_log_decision` | **write** | `zeusi_box_decision` (0012), or transitional `zeusi_box_rw` | Inserts one sourced decision into `zeusi.decisions`. It takes `kind` (go, lock, ruling, stop or park), `who` (an existing `people.handle`), `said_at`, `exact_words`, `exact_words_verbatim`, `scope`, `source_uri` and `source_ts`, plus optional `applies_to`, `expires_at`, `linked_repo`, `linked_pr` and `links` (up to 20 allowlisted target uris, see "Decision links"; needs 0013 and `zeusi_box_decision`: with links, a session without INSERT on `zeusi.decision_links`, such as the transitional `zeusi_box_rw`, is refused before anything is written). Links are inserted in the same transaction as the decision; a link the database wall rejects is quarantined by uri and hash and counted (`links.withheld`), a link the database CHECK refuses is counted (`links.invalid`); the decision stays. The row gets `source_kind = agent_write`, its own ingest run (importer `mcp`, mode `agent`), and `source_sha256` = sha256 of the canonical decision fields. The response returns ids only and never echoes the words. |
| `zeusi_search_feedback` | local file | none | "Did this hit answer it?" It takes `query_id`, `source_uri`, `useful` (true/false) and an optional `reason` (up to 200 characters). Feedback is appended to `~/.zeusi/search-feedback.jsonl` (dir 0700, tightened on every write if it already exists with looser permissions; file 0600). |
| `zeusi_onboarding_status` | read-only | `zeusi_box_ro` / `zeusi_cloud_ro` | First run (alias `onboarding_status`): optional `scope`. Returns `empty` and capped counts (`facts`, `rules`, `focus`, `notes`, `note_locks`, `note_locks_current`, `note_locks_superseded`, `note_locks_expired`, `chunks`, `decisions`; each at most 10 000, with `capped` flags), `rules_by_origin` (`{ fact, note_lock }`), `rules_definition` and `sources`. `rules` is the same set `zeusi_startup` serves (fact rules + current standing note locks), so it equals startup's `rules_total.total` of what this connection can see under RLS. Never row text, titles or content uris. When empty, `next` lists the local `zeusi onboard` commands (dry run first) and the honest line that the connector cannot run them. See "First-run onboarding". |

### Search covers decisions

`zeusi_search` (and the CLI `search`, which uses the same `search()`) also searches the owner's decisions, so a quote such as "Go for it. Launch it boy" finds the decision that `zeusi_startup` shows.

- **Source:** `zeusi.decisions_current`, the same view `zeusi_startup` reads. Superseded and expired decisions are not returned. The query runs in the same `BEGIN READ ONLY` transaction, as the same read role, after the same read-only session check, so RLS applies: `personal` decisions are never returned, and a `who` whose person row the reader cannot see is `null`. `scope` narrows decisions the same way it narrows chunks.
- **Matching (always lexical):** decisions have no `tsv` or embedding column, and this needs no migration. Two matches are combined:
  - full text: `to_tsvector('simple', exact_words + applies_to)` against `websearch_to_tsquery('simple', query)`, the same config and query syntax as chunk search;
  - phrase: a case-insensitive, whitespace-normalised substring of `exact_words` or of one `applies_to` element (queries of 3+ characters; `%`, `_` and `\` in the query are literal). Phrase matches rank above full-text-only matches (`score` = ts_rank_cd, + 1 for a phrase match).
- **Response shape:** decisions are a separate `decisions` list, at most `limit` items. They are not fused into `hits`, because their lexical scores cannot be compared with cosine or RRF scores, and keeping them apart leaves the chunk hits exactly as they were. In vector or hybrid mode (an OpenAI API key is set in the environment), chunks are semantic and decisions stay lexical.
- **Each decision:** `type: "decision"`, `kind`, `who` (people handle), `said_at`, `exact_words`, `exact_words_verbatim`, `applies_to`, `scope`, `source_uri`, `source_ts`, `cite` (`<source_uri> @ <source_ts>`), `score`, `match` (`phrase` or `fulltext`), and the link fields `linked_repo`, `linked_pr`, `linked_pr_uri`, `source_note` (see "Decision links").
- **Hybrid by default over MCP:** `zeusi_search` defaults `hybrid` to `true`. With an OpenAI API key set in the environment, vector-only search would skip every chunk that has no embedding yet; hybrid fuses the vector and full-text lists (RRF, k = 60), so those chunks still hit. `hybrid: false` is still honoured. Without a key the search is lexical, as before. The CLI `search` default is unchanged (`--hybrid` opts in).
- **Walls:** each decision passes the same output wall as a chunk hit (every string in the item). A decision that trips it is omitted and counted in `withheld`.
- **Feedback:** a decision's `source_uri` is a valid hit for `zeusi_search_feedback` on that `query_id`.
- **CLI:** text output prints a `decisions (lexical, current only)` section after the chunk hits; `--json` adds a `decisions` array with the same fields.

### Context for a task

`zeusi_context_for_task` (aliases `context_for_task`, `prime`) is how Zeusi speaks up first: before an agent starts a job, it gets the owner's decisions, locks and parked items that apply to that job.

- **Source:** `zeusi.decisions_current` (not superseded, not expired: the view decides, nothing reimplements supersession), plus the lock items of every active note (see "Rules from note locks"). Same read gate, read-only session check, `BEGIN READ ONLY … ROLLBACK`, role and RLS as `zeusi_search`; `personal` never comes back; `scope` narrows.
- **Matching (lexical, no OpenAI spend):** the task is reduced to at most 32 terms (NFKC, lower-case, letters and digits only, 2..64 characters, a small English and German stopword list dropped). A decision qualifies when a term is one of its words (`exact_words` + `applies_to`), or one of its `applies_to` targets appears as a whole word or phrase in the task. Terms reach SQL only as a `text[]` parameter compared with `=`.
- **Ranking:** distinct matching terms, plus a bonus per matching `applies_to` target, then kind (lock and stop above park, park above ruling and go), then recency of `said_at`.
- **Note locks:** a lock item qualifies when a task term is a word of its text or of its note's title (same term set, same `text[]` parameter). It is ranked on the same score as decisions (matching terms + the lock kind weight + recency of the note's `source_ts`) and returned as `type: "lock"`, `kind: "lock"`, `origin: "note_lock"`, `id: null`, `who: null`, `date.said_at: null`, `exact_words` = the lock text verbatim, `exact_words_verbatim: null` (the note's words, not a quote of a person), `note_title`, `applies_to: []`, and `cite` (`<source_uri> @ <source_ts> (note lock in "<title>", who not recorded)`). Decision items carry `origin: "decision"`.
- **Conflicts:** (decisions only; note locks have no `applies_to`) two returned items conflict when they share an `applies_to` target and one is a `go` while the other is a `stop`, `lock` or `park`. `conflicts` lists the two ids, their kinds and the shared targets; `conflict_hint` tells the model to ask the owner.
- **Empty means empty (invent=NO):** with no match, `items` and `conflicts` are empty and `message` says so. Nothing is ever invented.
- **Walls and privacy:** every item passes the output wall; a walled item is omitted, counted in `withheld` and never paraphrased, and conflicts never reference it. The response never echoes the task text, and the hosted log records only the tool name and counts.
- **Feedback:** the `query_id` works with `zeusi_search_feedback` for any returned `source_uri`.

### Rules from note locks

No importer writes `facts` kind `rule`, but the vault importer already stores each note's `locks:` frontmatter in `zeusi.notes.frontmatter` (scoped, wall-gated, upserted and marked deleted with the note). The readers take the lock items from there, at read time (`src/note-locks.ts`; no migration, no backfill, nothing written):

- **Items:** active notes only; `locks` as a YAML list, or a single string (one item); blank items are skipped; list order is kept. The text is returned verbatim. `who` is always `null`: a note lock has no recorded speaker, and none is invented.
- **Startup reads the standing set only:** notes whose `vault_path` starts with `Work/ops/` or `Work/handbook/` (`STANDING_LOCK_PREFIXES`), plus any lock its note marks with `standing_locks:` (for example Northbank product rules proposed by `zeusi locks classify`, `docs/locks-classifier.md`). Every one is either served in `rules` (compact: `{ id: "<source_uri>#lock-<ord>", origin: "note_lock", scope, text, source_uri, source_ts, cite }`) or listed in `rules_remainder` (`{ id, origin, scope, subject: <note title>, source_uri, source_ts, cite, reason }`). Ranking, budget and the never-dropped invariant: `docs/note-locks.md`, "Session start: every rule served or listed". Unmarked locks in other folders come back from `zeusi_context_for_task` when the task matches them.
- **Same gates:** the queries run in the read tool's `BEGIN READ ONLY` transaction as the read role, so RLS applies (`personal` never; a reader that cannot see a scope never sees its locks). Every item passes the output wall; a walled lock item is omitted and counted in `withheld`. Note bodies are never returned. The hosted log records counts only.
- **Freshness:** a lock appears once its note is ingested (`zeusi ingest vault`), and disappears when the note is edited or deleted and re-ingested.

### Decision links

Decision items in `zeusi_search`, `zeusi_startup` and `zeusi_context_for_task` carry five additive fields (`src/decision-links.ts`; the first four need no migration, the columns already exist):

- `linked_repo`, `linked_pr`: the stored values (set by `zeusi_log_decision`), or `null`.
- `linked_pr_uri`: `gh:<linked_repo>#<linked_pr>` when both are stored, built from the stored values only; else `null`. PR state is not resolved yet (no GitHub importer fills `zeusi.prs`).
- `source_note`: `{ source_uri, title, source_ts }` of the active note whose `source_uri` equals the decision's `source_uri` without its `#fragment`, read as the caller's role under RLS; `null` when there is none or the reader cannot see it. Never the note body.

- `links` (migration 0013, `zeusi.decision_links`; **design, not applied on Neon**): `[{ target_kind, target_uri, resolved, title? }]`, at most 20 per decision, in the order they were linked. `target_kind` is `pr`, `note`, `repo`, `job` or `uri`. A `note` link is `resolved: true` with the `title` of the active note whose `source_uri` equals the target without its `#fragment` **and** that the caller can see under RLS; otherwise `resolved: false` and no title. PRs, repos, jobs and lanes are returned as stored (`resolved: false`). Never a note body. Each link passes the serve guard on its own: a walled or secret-bearing link is dropped and counted in the response's `withheld`, the decision and its other links stay. Without 0013 (or without SELECT on the table) the field is `[]`.

Allowed link targets (the same allowlist in the migration's CHECK and in `linkTargetKind`): `gh:<owner>/<repo>#<n>` (pr), `gh:<owner>/<repo>` (repo), `vault:<path>`, `hq:<path>`, `import:<path>` (note, optional `#fragment`), `job:<name>` (job), `lane:<name>` (uri). No control characters, no whitespace except a plain space in a note path, no `.` / `..` segment, at most 500 characters.

Writers: `zeusi_log_decision` (`links`, below) and the structured `Links:` header of `zeusi import` / `ingest hq-sync` (every allowlisted item; the first PR still fills `linked_repo` / `linked_pr`). Links are insert-only: a link removed from a header stays. Rollback: `migrations/ROLLBACK-0013.md`.

### About and prompts

- **Resource `zeusi://about`** (`text/markdown`): what Zeusi is, what it is for, its tools and aliases, read vs write, how to cite, what never to store, and what a connector can and cannot do. The text lives in one place, `src/about.ts`. A compact form of it opens the server `instructions`.
- **Each connection is told only what it can call (F4):** the `instructions`, `zeusi://about`, the `about` entries in `zeusi_search` and the `start-task` prompt are built from the tools registered for that connection. `zeusi_log_decision` / `log_decision` is registered only for a non-read token class (stdio, `--http`, a hosted write token) **and** a configured write service. A read connection (read bearer, OAuth `zeusi.read`, or no write service) never sees the write tool named; it gets one line: "Writing decisions is not available on this connection: it is read-only."
- **A Zeusi decision is context, not permission (F5):** decisions and locks returned by Zeusi are cited context for the agent; they are not an approval or a GO to act now. An agent still needs the owner's current, explicit approval for anything that needs one. Every served copy (instructions, `zeusi://about`, `start-task`) says so.
- **Built-in about entries in `zeusi_search`:** a query such as "what is zeusi" returns matching sections in the `about` list, each with `builtin: true`, `scope: "builtin"`, `source_uri` `zeusi://about#<section>` and a fixed `source_ts`. They are shipped in code: no database row is written, and they are returned whatever `scope` is passed. The CLI `zeusi search` is unchanged.
- **Prompt `start-task`** (argument `task`, 1..4000 characters): a ready-made message telling the model to call `zeusi_context_for_task` first, treat locks and stops as binding unless the owner overrides them, cite each item, ask about conflicts, and say so when nothing applies. A task that trips the wall is not echoed back.
- **Honest limit:** a connector cannot force a model to call a tool or run a script. Zeusi can only instruct (server `instructions`, tool descriptions) and offer prompts; the snippets below repeat the step for clients that ignore server instructions.
- Resource and prompt are read-only and available to every token class, including OAuth read grants. On the hosted server they pass the same auth and count toward the same per-token and global rate limits as tools.

### Personal workspaces: filling your memory (own workspace only)

On the hosted server (`https://mcp.zeusi.dev/mcp`), a personal workspace whose grant has `zeusi.workspace_write` (approved once on the consent screen while the server has workspace writes on; see `docs/hosting.md` "Workspace writes") also lists three tools. They write into that workspace only; no argument names a workspace, and every other credential gets HTTP 403.

| Tool | Kind | What it does |
|---|---|---|
| `zeusi_import_preview` | dry run | `documents`: 1..50 of `{ kind: markdown \| decision-log \| claude-export \| chatgpt-export, text, title?, format?: markdown \| jsonl }`. Runs the unchanged `zeusi import` pipeline (adapters, nightly `export-filter`, importer gates incl. quarantine) and saves NOTHING. Returns `preview_id` (30 minutes, this connection only), `counts` (notes, chunks, rules, note_lock_rules, focus, decisions, quarantined, withheld_entries, dropped_files, errors), `items` (title and first line of up to 20 admitted notes) and `next`. |
| `zeusi_import_commit` | write | `preview_id`, `confirm: true`. Saves exactly that preview, once; a repeat returns `already_committed: true` and saves nothing. Only after the user said yes. |
| `zeusi_sync_batch` | write | `items: [{ path: <project>/YYYY-MM-DD-<slug>.md, text }]` (HQ export layout, at most 100) and `deleted: [path]` (at most 200). Same filters as the nightly export; upsert by source uri + hash; removes only the listed synced notes of this workspace. |

The welcome then ends with form B: "Want me to fill your memory now? I'll show a preview first." and how ("Say 'fill my memory' and paste your notes, or point me at an export; nothing is saved until you say yes."). Without the write grant, or while the server has writes off, the welcome keeps form A and the tools are not usable.

### First-run onboarding

A new user who connects to an empty namespace sees nothing. Zeusi cannot fix that from the connector: **a connector cannot force a model to run anything, and Zeusi cannot run the import for the user. To onboard, the user runs `zeusi onboard` locally.**

- **`zeusi_onboarding_status`** (alias `onboarding_status`, read-only, every token class including OAuth read grants and read bearers, same rate limits and log allowlist): `empty` plus capped counts, no row text. The server `instructions` say: if it says empty, offer the onboarding prompt; the import is a CLI the user runs.
- **Prompt `onboarding`** (no arguments): tells the model to call `zeusi_onboarding_status` and, when empty, to explain the import options and show the dry-run commands, and never to claim it ran anything. It names no write tool.
- **CLI** (see README "Commands"): `zeusi onboard <inputs> --scope <scope>` always previews (offline: no database connection, nothing written) and prints the exact `zeusi import ... --real` command to run next. Inputs: `--markdown <folder>` (markdown / Obsidian; the original `locks:` and `related:` frontmatter is carried through, so note locks become rules at read time), `--decision-log <file>` (.md or .jsonl with the `zeusi_log_decision` field names), `--claude-export` / `--chatgpt-export <conversations.json>`, `--git <repo>` (local history only: decision-like commits and PR merges; notes only).
- **Same filters as the nightly export:** every input is staged in the HQ export layout and passes the unchanged `export-filter` (secret and credential scrub, 2FA codes, `requests/`, the Plankiva exclusion, output gate), then the importer's path gate, content gate (incl. the soft IBAN and account-number rules), ClientCo scope rule and the `zeusi_90_wall` trigger, with quarantine by uri and hash only. Names, emails and phone numbers are **not** detected: review the input first.
- **Decisions, rules and focus (invent=NO):** only from markdown / decision-log entries with the explicit header (`## <ISO timestamp> <handle>`, then `Decision: go|lock|ruling|stop|park` + `Said-at-precision: minute|day` [+ `Verbatim`, `Applies-to`, `Links`, `Expires`], or `Type: rule|focus` + `Subject:`). They become `zeusi.decisions` / `zeusi.facts` (`rule` / `state`) rows only when `who` already exists in `zeusi.people` (else skipped and counted `unknown_person`; people are never created). A `Links:` value `gh:<owner>/<repo>#<n>` fills `linked_repo` / `linked_pr`. Dedupe on `(source_uri, source_sha256)`; an edited entry (same who and time, new words) is a `conflict` and is refused (no UPDATE). Entries without the header stay notes. Chat exports and git never produce structured rows. The parser is one module (`src/importers/structured.ts`); `ingest hq-sync` uses the same one for headed HQ decision / memory entries (`docs/hq-sync.md`, "Structured entries").
- **Real write:** `zeusi import ... --scope <s> --real` runs as `zeusi_ingest` (no new role, no migration), direct endpoint, refused unless `ZEUSI_MAIN_ENDPOINT_ID` (from the environment) is set and differs from the service host's endpoint or `--i-know-this-is-main` is passed; lands only in that scope (`team` -> folder `team`, `product` -> `northbank`, `clientco` -> `clientco`); notes are `source_kind manual`, uris `import:<project>/...`; idempotent (a second run inserts nothing), resumable (`ingest_runs`, importer `onboard-import` and `onboard-import-structured`), and never deletes earlier imports. Then `wall audit` must report 0 rows. Production onboarding is an owner-approved step.
- **Startup:** imported note locks are found by `zeusi_context_for_task`; `zeusi_startup` lists only the standing folders' note locks, so imported locks show there only as `Type: rule` facts. Imported decisions older than the startup window (14 days) are reached through search and context_for_task.

### Role gates

- **Read tools.** First, `ZEUSI_TRANSPORT` must be valid. Then the read service's `user=` (an offline parse of the service file) must be `zeusi_box_ro` or `zeusi_cloud_ro`, or the tool is refused before any connection. Next, the existing `connectReadOnly` connects. Finally, the live session is checked: it must not be a superuser and must have no write privilege on any `zeusi` table (`assertReadOnlySession`). Every query runs inside `BEGIN READ ONLY … ROLLBACK`. RLS is unchanged (no `personal`).
- **Write tool.** The checks run in this order, and nothing before step 5 reads a credential:
  1. A write service must be configured (`--write-service` or `ZEUSI_MCP_WRITE_SERVICE`). Without one, the connector is read-only.
  2. That service's `user=` must be `zeusi_box_decision` (preferred, `[zeusi_decision]` in `config/pg_service.example.conf`) or the transitional `zeusi_box_rw`. Any `*_ro` login, the ingest and backup logins, and the owner are all refused.
  3. `ZEUSI_TRANSPORT` must not be `serverless`.
  4. The args must be valid and pass the wall.
  5. `connectService` connects. This is the TCP path with channel binding required, and the password is read here.
  6. The live session's `current_user` must be the same login the service names (one of the two above), not a superuser, with INSERT on `zeusi.decisions`.

  `zeusi_box_decision` has no env-password exception and no serverless exception: its password comes from the Keychain / `~/.pgpass` only, over TCP. The transitional `zeusi_box_rw` path is meant to be dropped once the operator applies 0012 (`docs/roles.md`).

  The tool is refused before any INSERT if any check fails. The DB wall trigger is the backstop: a rejection is recorded in quarantine by uri and hash only.
- **Args.** Every tool schema is strict. Unknown keys and invalid values return an MCP tool error (`isError`). They are never echoed back, and nothing connects.

### Walls on every output

Every item a tool returns passes through `src/mcp-wall.ts`, in this order:

1. **The wall, on the ORIGINAL item.** Items that fail are **omitted and counted in `withheld`**, never paraphrased and never redacted-and-served. The check covers every string in the item, including its uri, heading and text, and applies:
   - the exclusion signal used everywhere else (`mentionsProtectedName`: raw, percent-decoded and normalised);
   - the wall's hard Plankiva class (`plankivaWall`);
   - the seed wall's hard uri rules;
   - database hostnames and connection strings.
2. **The serve-time secret guard** (`docs/secrets.md`), on the items the wall kept: an item is **withheld, never redacted**, when any of its strings trips the shared detector (`strictCredentialSignal`), the `origin/main` credential patterns (kept verbatim, so serve time is never less strict than main), or holds a `[REDACTED:` marker (stored text that was redacted at ingest or by `rescrub` is never served). Served items are byte-for-byte what was stored. Items withheld here are counted in `withheld` and, in the hosted log, in `redacted_count` (a count only).
3. **Fail closed:** if a check throws, the item is withheld.

The wall runs first and on the item as stored, so an exclusion name or a host is always counted as a wall hit (review r1 of PR #23, P1-1).

The same check runs on `zeusi_log_decision` input and on feedback reasons. Input that fails is refused, never stored and never echoed. Error messages have known secrets and hosts masked, and they are replaced entirely when they trip the wall or the secret check.

### Feedback ledger

One JSON line per answer: `ts`, `query_id`, `source_uri`, `useful`, and `reason` when given. The ledger never stores the query text, the chunk text, secrets or walled content.

A hosted **personal workspace** has its own ledger (`<data>/.zeusi/workspaces/<id>/search-feedback.jsonl`) with a different line: `ts`, `query_id`, `uri_hmac`, `uri_key`, `useful`. `uri_hmac` is HMAC-SHA256 of the hit's `source_uri` under a random per-workspace key in `feedback-uri.key` beside the ledger (0600; `uri_key` names it, `c2-file-v1`); the `reason` is accepted but not stored. This keeps file paths out of casual reads of the ledger. It does not stop the operator: whoever can read the data volume has the key, and the database holds every `source_uri`, so the hash can be recomputed and matched. The team-workspace ledger is unchanged.

Feedback is refused when:

- the `query_id` is unknown (query ids live in memory for the server process, last 256 searches);
- the `source_uri` was not a hit of that query;
- the reason trips the wall;
- the reason copies 32 or more characters of a hit's text.

The ledger can be used to measure search-hit usefulness per `source_uri`.

## Startup snippets

**The canonical text is the skill [`skills/zeusi-startup/SKILL.md`](../skills/zeusi-startup/SKILL.md).** Install it as-is where the client supports skills (`skills/README.md`). The client snippets below show how to connect and give short wrappers for clients without skills; when they and the skill differ, the skill wins.

### Connect: the hosted server (default)

The hosted server is live and is the default way to connect:

- **URL:** `https://mcp.zeusi.dev/mcp`. The path must be `/mcp`; `/`, `/sse` and unknown paths answer 404. With the OAuth release (ships in this PR; live after the Fly deploy and the OAuth secrets), the OAuth discovery and sign-in paths also answer (OAuth sign-in below); before that, `/.well-known/*` answers 404.
- **Transport:** MCP Streamable HTTP in JSON response mode (not SSE), stateless (no session id). Pick "HTTP" / "Streamable HTTP" in the client, not "SSE".
- **Auth, two ways:**
  - **Bearer token** (clients without OAuth, Grok Bot, scripts): `Authorization: Bearer <token>` (scheme `Bearer`, one space). Unchanged by OAuth.
  - **OAuth sign-in** (claude.ai / Claude Desktop, Claude Code, ChatGPT, Cursor, VS Code, Gemini CLI, or any MCP client with OAuth 2.1 + PKCE): you paste only the URL; the client discovers the sign-in, you sign in with GitHub (any GitHub account: an operator member reaches the team workspace, anyone else gets their own empty personal workspace; `docs/hosting.md`, "Workspaces") and approve a Zeusi read-only consent screen that names the app asking and where access is sent. Tokens from this flow are **always read-only** (the read tools only, never `log_decision`). Which redirect each client may use: `docs/hosting.md`, "OAuth for MCP clients".
  - A missing, bad, revoked or expired token, or a read token calling the write tool, gets HTTP 401 `{"error":"unauthorized"}`. Today the challenge is `WWW-Authenticate: Bearer realm="zeusi"`; with OAuth on it also carries `resource_metadata="https://mcp.zeusi.dev/.well-known/oauth-protected-resource"` and `scope="zeusi.read"`, which is how a client finds the sign-in.
- **Which token:** the per-assistant **read** token (from 1Password / the operator; `docs/hosting.md`, "Who gets a token"). A read token lists the read tools. Only a write-class token also lists `zeusi_log_decision` / `log_decision`.

The examples below use the placeholder `$ZEUSI_READ_TOKEN` / `${env:ZEUSI_READ_TOKEN}`. **Never paste a token into chat, a skill, a prompt, or a committed file.** No database credential or hostname is needed on the client.

#### Claude Code (CLI)

Official docs: <https://code.claude.com/docs/en/mcp>.

**OAuth (no token in the command; after the OAuth release is deployed):**

```sh
claude mcp add --transport http zeusi https://mcp.zeusi.dev/mcp
```

Then run `/mcp` inside a Claude Code session and choose to authenticate `zeusi` (or run `claude mcp login zeusi`): a browser opens for GitHub sign-in and the Zeusi consent screen (Claude Code uses a `http://localhost:<port>/callback` or `http://127.0.0.1:<port>/callback` redirect, which the server accepts on any port).

**Bearer token (works today, and keeps working):**

```sh
# export ZEUSI_READ_TOKEN first (the per-assistant read token, from 1Password / the operator).
# The shell expands the variable at add time; the token is stored in Claude Code's local config.
# Never paste a token into chat, a skill, a prompt, or a committed file.
claude mcp add --transport http zeusi https://mcp.zeusi.dev/mcp \
  --header "Authorization: Bearer $ZEUSI_READ_TOKEN"
```

- Add `--scope user` to make it available in every project (the default scope is the current project, stored locally).
- Do not commit a project `.mcp.json` with an unexpanded `${ZEUSI_READ_TOKEN}` in the header. Claude Code does not expand credential variables from project or plugin config, so it may send the header empty and every request gets 401. Use the command above (local config) instead.
- Check with `claude mcp list` (or `/mcp` inside a session): `zeusi` should be connected.

#### Cursor

Official docs: <https://cursor.com/docs/context/mcp>, <https://cursor.com/help/customization/mcp>.

**OAuth (no token in the file):** add Zeusi to `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "zeusi": {
      "url": "https://mcp.zeusi.dev/mcp"
    }
  }
}
```

Then open **Customize > MCPs** and follow the sign-in prompt for `zeusi`. Cursor registers itself (DCR) with `https://www.cursor.com/agents/mcp/oauth/callback` and `http://localhost:8787/callback`; Zeusi accepts both.

**Bearer token (clients set up before OAuth):** add `"headers": { "Authorization": "Bearer ${env:ZEUSI_READ_TOKEN}" }` next to `url`. `ZEUSI_READ_TOKEN` must be set in the environment Cursor is launched from; the file itself then holds no token.

#### ChatGPT (web)

Official docs: <https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt>, <https://developers.openai.com/apps-sdk/build/auth>.

1. Open **Plugins**, click **+**, then **Add custom MCP server**.
2. Enter a name (for example `Zeusi`). Under **Connection**, enter the server URL `https://mcp.zeusi.dev/mcp`. Under **Authentication**, choose **OAuth**.
3. Tick **I understand and want to continue**, then **Create as a plugin**.
4. Install the plugin, sign in with GitHub, approve the Zeusi consent screen (it names `chatgpt.com`), and use it in a chat with **@**.

ChatGPT identifies itself with its published client metadata (`https://chatgpt.com/oauth/client.json`) or registers itself; either way the code goes only to `https://chatgpt.com/connector_platform_oauth_redirect`.

#### VS Code (GitHub Copilot)

Official docs: <https://code.visualstudio.com/docs/copilot/customization/mcp-servers>.

1. Run **MCP: Add Server** from the Command Palette (or **Chat: Open Customizations** > **MCP Servers** > **Add Server**).
2. Choose **HTTP**, enter `https://mcp.zeusi.dev/mcp`, and the server ID `zeusi`.
3. Choose **Global**.
4. Sign in when VS Code prompts: GitHub, then the Zeusi consent screen.

VS Code uses its published client metadata (`https://vscode.dev/oauth/client-metadata.json`) or registers itself; the code goes to `http://127.0.0.1:<port>/` or `https://vscode.dev/redirect` (`https://insiders.vscode.dev/redirect` for Insiders).

#### Gemini CLI

Official docs: <https://geminicli.com/docs/tools/mcp-server/>.

```sh
gemini mcp add --transport http zeusi https://mcp.zeusi.dev/mcp
```

Then run `/mcp auth zeusi` inside Gemini CLI: a browser opens for GitHub sign-in and the Zeusi consent screen. Gemini CLI registers itself and uses `http://localhost:<port>/oauth/callback`.

#### claude.ai / Claude Desktop custom connector / Cowork

Custom connectors are reached **from Anthropic's cloud, not from your machine**. That is why the old local command (`claude mcp add zeusi -- node …/dist/mcp.js`) cannot work in a claude.ai or Claude Desktop chat: a cloud chat cannot spawn a local stdio server.

**With OAuth (ships in this PR; live after the Fly deploy and the OAuth secrets).** Steps for Pro and Max plans, with the labels from Anthropic's Help Center (<https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp>):

1. Navigate to **Customize > Connectors**.
2. Click **+ Add**, then **Add custom connector**.
3. Enter a name (for example `Zeusi`) and the URL `https://mcp.zeusi.dev/mcp`. Click **Continue**.
4. Review the authentication settings Claude detected. Click **Continue**.
5. Under **Authentication**, choose **Sign in now** (or **Sign in when needed**).
6. Under **OAuth client**, leave the recommended **Use Claude’s published identity (Recommended)**, or pick **Register automatically**. Both work: Zeusi supports Claude's published client metadata (CIMD) and dynamic registration (DCR). Click **Add**, then sign in.

Sign-in is **Sign in with GitHub**, then a Zeusi consent screen that says "read-only" and names where access is sent (`claude.ai`). Any GitHub account can sign in: an operator member reaches the team workspace; anyone else gets their own personal workspace, separate from every other one and empty at first (`docs/hosting.md`, "Workspaces"; open sign-up: any existing GitHub account can sign in). Repo visibility plays no part. Approve, and the connector lists the 5 read tools. Nothing to paste besides the URL: no token, no header.

- What the server does (for reviewers): RFC 9728 protected-resource metadata at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp` (`resource` exactly `https://mcp.zeusi.dev/mcp`, one authorization server `https://mcp.zeusi.dev`), RFC 8414 metadata at `/.well-known/oauth-authorization-server`, PKCE S256 required, redirect exactly `https://claude.ai/api/mcp/auth_callback` for claude.ai, refresh tokens rotated on every use. Details: `docs/hosting.md`, "OAuth for MCP clients".
- **Request headers** (Anthropic's static-headers connector auth, beta, limited to some organizations) is not needed once OAuth is live. Before that, if the dialog shows **Request headers**, a header `Authorization` with `Bearer <read token>` works (the Claude Max **read** token, never a write token); without it, the connector cannot connect until the OAuth release is deployed.
- Do not put a token in the URL (query strings end up in logs and history), and do not ask for an authless server; neither is supported.

#### Any MCP client / Grok Bot

URL `https://mcp.zeusi.dev/mcp`, Streamable HTTP. With OAuth: the client discovers the sign-in from the 401 and uses OAuth 2.1 + PKCE S256 with its published client metadata (CIMD) or dynamic registration (DCR); a desktop or CLI client must use a loopback redirect (`http://localhost` or `http://127.0.0.1`, any port, path `/callback`, `/oauth/callback` or `/`). Without OAuth: send `Authorization: Bearer $ZEUSI_READ_TOKEN`, a read token from your Zeusi admin, taken from that client's own secret store. Grok Bot and other agentskills.io catalogs: copy `skills/zeusi-startup/` as-is.

### Connect: local stdio (secondary)

Only for a machine that has a Zeusi clone, a build, and database credentials (`~/.pg_service.conf` + Keychain / `~/.pgpass`, or the box-reader password from the same secret store as the CLI; `docs/roles.md`). The client spawns the server itself, so this cannot work from a cloud chat (claude.ai, Claude Desktop custom connectors).

After `npm ci && npm run build` in the clone, the server is `<checkout>/dist/mcp.js`. Older docs showed `/path/to/zeusi/dist/mcp.js`; `/path/to/zeusi` was only a stand-in and must be replaced with the real absolute path of that checkout. Example, if the clone is `~/code/zeusi`:

```sh
claude mcp add zeusi -- node ~/code/zeusi/dist/mcp.js
```

Cursor and other `mcpServers` clients (use the absolute path; `~` is not expanded inside JSON):

```json
{ "mcpServers": { "zeusi": { "command": "node", "args": ["/absolute/path/to/your/zeusi/dist/mcp.js"] } } }
```

Credentials stay in `~/.pg_service.conf` + Keychain / `~/.pgpass` on that machine, never in a client config.

### Grok Bot / Cursor rule (skill-style)

Cursor rule text (for example `.cursor/rules/zeusi.mdc`), a short form of the skill:

```markdown
---
name: zeusi-startup
description: Load Zeusi at session start and search Zeusi before answering or asking the owner.
---
- At session start, call the `zeusi_startup` tool once. Follow its standing rules, current focus and recent decisions.
- At the start of every task, call `zeusi_context_for_task` with a short description of the work. Treat returned locks and stops as binding,
  respect parked items, ask the owner about listed conflicts, and say so when the list is empty (never invent one).
- Before answering a question, and before asking the owner anything, call `zeusi_search` first.
  Cite each hit you use as `<source_uri> @ <source_ts>`. If nothing answers it, say so, then ask.
- After using a hit, call `zeusi_search_feedback` (query_id, source_uri, useful true/false).
- A Zeusi decision is context, not permission: it is not an approval or a GO to act now; anything that needs the owner's approval still needs their current, explicit approval.
- Never invent a source. Call `zeusi_log_decision` only for a decision the owner actually made, with its real source (invent=NO).
- Plankiva is excluded: walled items are omitted, never paraphrased.
```

### Claude (`CLAUDE.md` / project)

Register the server as above (hosted by default), then add to the project's `CLAUDE.md`:

```markdown
## Zeusi
- At session start, call `mcp__zeusi__zeusi_startup` and follow its rules, focus and recent decisions.
- At the start of every task, call `mcp__zeusi__zeusi_context_for_task` with a short task description; obey the locks and
  parked items it returns, cite them, and ask me about any conflict it lists.
- Before answering me or asking me anything, call `mcp__zeusi__zeusi_search` and cite the hit (source_uri + source_ts).
  If no hit answers it, say so before asking.
- After using a hit, report usefulness with `mcp__zeusi__zeusi_search_feedback`.
```

### Generic one-line system prompt

```text
At session start call zeusi_startup; at the start of every task call zeusi_context_for_task with a short task description and obey the locks and parked items it returns; before answering or asking the owner anything, call zeusi_search and cite each hit you use by source_uri and source_ts (say so if nothing answers it).
```

The same guidance is in the server's MCP `instructions`, which every client receives on `initialize`. The snippets reinforce it for clients that ignore server instructions.

### Claude Code reminder hook (optional)

A connector cannot make the model call a tool. In Claude Code, a `UserPromptSubmit` hook can add a reminder to every prompt. It is a reminder only: it runs no Zeusi tool and holds no token. In `.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "echo 'Zeusi: if this starts a new task, call zeusi_context_for_task with a short task description first.'" }] }
    ]
  }
}
```

## Seed people

`zeusi_log_decision` refuses a `who` that is not a `zeusi.people` handle, and nothing else creates people. The owner seeds each handle once with `people add` (owner URL from `.env.local`, direct endpoint):

```sh
# 1. Check offline: validates the flags, prints handle, kind, org, scope, source_uri and a
#    sha prefix. No connection, no write.
node dist/cli.js people add --handle owner --display-name "<name>" --kind human --org work --scope work \
  --source-uri "<where this was said>" --source-ts "<ISO time with zone>" --source-text "<the words, verbatim>" \
  --host mini --dry-run

# 2. Write. Same main-branch guard as prove: on production (Neon main) it needs --i-know-this-is-main.
node dist/cli.js people add ...same flags... --i-know-this-is-main

# 3. Check.
node dist/cli.js people list
```

- invent=NO: every column comes from a flag. `--display-name`, `--kind` (`human|agent|bot`), `--org` (`team|vendor`), `--scope`, `--source-uri`, `--source-ts`, `--source-text` and `--host` (a short label such as `mini`, `[a-z0-9_-]{1,32}`; there is no machine-name default) are required; `--github-login` is optional. There is no default scope.
- **A `personal`-scope person is invisible to the decision writer.** `zeusi_box_decision` and `zeusi_box_rw` read people through `zeusi_read`, whose RLS hides `personal`, so `zeusi_log_decision` refuses that handle as an unknown `who`. `--scope personal` is therefore refused unless `--allow-personal` is also passed.
- `--handle` uses the pattern the tool uses for `who`: `^[a-z0-9][a-z0-9_.-]{0,63}$`.
- One transaction writes an `ingest_runs` row (importer `cli:people-add`, host from `--host`, mode `manual`, status `ok`, counts `{"inserted":1}`) and the person (`source_kind manual`, `source_sha256` = sha256 of `--source-text`). The source text itself is not stored.
- Idempotent: an existing handle prints `exists: <handle> (id n)` and changes nothing (no update, no upsert). Correcting a person is a separate owner decision.
- The wall trigger on `people` still applies. A refused value rolls the whole transaction back (no person, no run) and exits 3 with the rule id only.
- Output never includes URLs, hosts or secrets; `people list` prints `handle`, `kind` and `source_uri` only. An `http://` or `https://` `source_uri` is accepted and stored as given, but `--dry-run` and `people list` print it as `https://…` (scheme only). Prefer a non-URL uri (`manual:`, `zeusi:`, `hq:`, `chat:`), which is printed as is.

## Known limits

These are deliberate in this version; changing any of them is a separate decision.

- `zeusi_log_decision` cannot use the serverless (HTTPS 443) transport, for `zeusi_box_decision` as for `zeusi_box_rw`. It runs over TCP only, so it cannot write from a machine where only 443 egress works.
- `who` must already exist as a handle in `zeusi.people`. An unknown handle is refused (`unknown person`); the connector never creates people. The owner seeds them with `people add` (see "Seed people" below).
- The optional HTTP transport has no authentication. It is protected only by the loopback-only bind and DNS-rebinding protection, so anything that can reach the loopback port can call the tools. The authenticated alternative is `--hosted`, which is what `https://mcp.zeusi.dev/mcp` runs (`docs/hosting.md`).
- `zeusi_box_decision` does not exist on Neon until 0012 is applied and its password is set. Until then, a `[zeusi_decision]` service cannot connect, and the transitional `zeusi_box_rw` service is the working write path.
- Note-lock rules have no speaker (`who: null`) and no `applies_to`, so they never take part in conflicts. Startup lists every current standing rule (notes under the standing folders, plus any lock a note marks with `standing_locks:`). Each one is served in compact form or listed in `rules_remainder`; none is silently dropped.
- Feedback `query_id`s live in memory for the server process only (the last 256 searches). Feedback for a search from an earlier process, or one older than the last 256, is refused as an unknown `query_id`.

## Not in scope

The connector does not cover ingest, migrations, wall administration, owner commands, a box-side install, or the serverless transport for the write role. On a machine where only HTTPS 443 egress works (the box), `zeusi_log_decision` cannot connect: it needs TCP, and serverless is read-only by design. Widening that would need a new decision about the write role's auth.
