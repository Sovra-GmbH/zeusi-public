# Zeusi

Zeusi is a sourced memory for a team and its AI assistants. Standing rules, current focus, decisions, notes and work history live in Postgres with pgvector. Every row carries its source (`source_uri`, `source_ts`, a content hash and the ingest run that wrote it), so an assistant can cite where an answer came from and never has to invent one.

Per-user workspace encryption is enabled by setting `ZEUSI_WORKSPACE_ENCRYPTION=on`; new personal workspaces are then encrypted from sign-up, and you hold the key. On the hosted service at [zeusi.ai](https://zeusi.ai): **Your memory is encrypted. Only you hold the key.** The workspace is not end-to-end encrypted: the server holds sealed data and unlocks it when you sign in.

What it gives you:

- **A schema for sourced memory**: facts, decisions (with the exact words and who said them), episodes, notes and chunks, people, PRs and reviews, routine runs. Supersede functions instead of edits; views for the current state.
- **A wall in the database.** A trigger on every content table runs the same verdict as the importers (`src/wall.ts` == `zeusi.wall_eval()`): hard rules for areas, P&L paths and lanes, and **protected names** (people or companies whose content must never be stored, in any spelling, look-alike or percent-encoding), plus soft content rules that quarantine by uri and hash only. Row-level security hides the `personal` scope from every reader. The example name `plankiva` in this repo is fictional. See [`docs/wall.md`](docs/wall.md).
- **Per-user encryption** when `ZEUSI_WORKSPACE_ENCRYPTION=on`: new personal workspaces are encrypted from sign-up, and you hold the key.
- **Least-privilege roles**, created by SQL with no passwords: an ingest login, a backup login, read-only logins for agents, a narrow decision-write login. See [`docs/roles.md`](docs/roles.md).
- **A vault importer** for markdown notes (read-only on the vault, two wall gates, deletion guard, advisory lock), embeddings with a hard monthly spend cap, and hybrid search (vector + full text).
- **An MCP connector** (`zeusi-mcp`) that any MCP client can use: `zeusi_startup`, `zeusi_search`, `zeusi_search_feedback`, `zeusi_context_for_task`, `zeusi_onboarding_status` and an opt-in `zeusi_log_decision`, with an output wall on every item. A canonical agent skill ships in [`skills/zeusi-startup`](skills/zeusi-startup/SKILL.md).


## What Zeusi is

Zeusi is a sourced memory for a team and its AI assistants. A Zeusi decision is context, not permission. Decisions and locks returned by Zeusi are cited context for the assistant; they are not an approval or a GO to act now. Anything that needs the owner's approval still needs the owner's current, explicit approval.

## Quick start (local stdio MCP)

Requirements: Node.js 22.18+ and PostgreSQL 17+ with the `vector` extension (Neon works out of the box; any Postgres with pgvector works).

```sh
npm ci && npm run build && npm test           # tests run on PGlite, no database needed
```

1. **Database and owner URL.** Create a database. Put the owner connection strings in `.env.local` (gitignored; names in `.env.example`): a pooled `DATABASE_URL` and a direct `DATABASE_URL_UNPOOLED`.
2. **Migrate** as the owner: `npm start -- migrate --dry-run`, then `npm start -- migrate`. On a database that already has migrations, take a snapshot first and pass `--i-took-a-snapshot`.
3. **Role passwords.** The migrations create the login roles without passwords. Set them as the owner (`\password zeusi_box_ro`, ...) and store each one in your password manager, then on the machine that uses it in the macOS Keychain (`zeusi-neon-<role>`) or `~/.pgpass` (0600). See [`docs/roles.md`](docs/roles.md).
4. **Service file.** Copy `config/pg_service.example.conf` to `~/.pg_service.conf`, fill in hosts and database name, `chmod 600`. Check with `npm start -- doctor` and `npm start -- doctor --roles`.
5. **Sources and protected names.** Copy `config/sources.example.toml` to `config/sources.toml` (gitignored) and point it at your vault. Put the people or companies that must stay out under `[wall] protected_names`, then apply their hard rules as the owner: `node dist/cli.js wall seed-sql | psql "<owner URL>"`. Never commit the names. The example name `plankiva` is already seeded.
6. **Ingest and embed.** `npm start -- ingest vault --dry-run` (counts only, no database), then `--real`. Embeddings need an OpenAI key in the macOS Keychain item `zeusi-openai-api-key`: `npm start -- embed --estimate`, `embed --dry-run`, then `embed --real` ([`docs/embeddings.md`](docs/embeddings.md)).
7. **Connect an assistant** over stdio:

   ```json
   { "mcpServers": { "zeusi": { "command": "node", "args": ["/path/to/zeusi/dist/mcp.js"] } } }
   ```

   or `claude mcp add zeusi -- node /path/to/zeusi/dist/mcp.js`. Install the skill from `skills/zeusi-startup/`. Details and client snippets: [`docs/mcp.md`](docs/mcp.md).

Credentials stay on the machine that runs the server (`~/.pg_service.conf` plus Keychain or `~/.pgpass`); they never go into a client config, a skill, a prompt or this repo.

## Hosted mode

The official hosted server is `https://mcp.zeusi.dev/mcp`. To run your own, use `node dist/mcp.js --hosted`. Each assistant gets its own bearer token (`zeusi mcp-token mint|list|revoke`). The server fails closed (HTTP 503 until a valid tokens file exists). See [`docs/hosting.md`](docs/hosting.md). Client snippets are in [`docs/mcp.md`](docs/mcp.md) under "Startup snippets".

## Site

The public site is live at https://zeusi.ai. It is deployed as static files from `site/`. See [`site/README.md`](site/README.md).

## Commands

`npm start -- <command>` (or `node dist/cli.js <command>`); `--help` lists every option.

| Command | Connects as | What it does |
|---|---|---|
| `doctor [--service s]`, `doctor --roles`, `doctor --offline` | role / none | TLS, channel binding, server major, pgvector, migrations; role catalog checks. No hosts or credentials printed. |
| `ingest vault (--dry-run \| --real) [--config f]` | none / `zeusi_ingest` | Import the configured vault notes through both wall gates. Dry run prints counts only. |
| `embed (--estimate \| --dry-run \| --real)` | none / `zeusi_ingest` | Offline cost estimate, or embed pending chunks under a hard monthly cap. |
| `search "<q>" [--limit n] [--scope s] [--hybrid] [--json]` | `zeusi_box_ro`, read-only | Semantic (with the key) or lexical search; every hit cites `source_uri` and `source_ts`. |
| `wall report`, `wall audit` | role | Quarantined items (no content); rows that break the live wall (exit 1 if any). |
| `wall seed-sql [--config f]` | none | Owner SQL for the protected names in the private config. |
| `migrate [--dry-run] [--i-took-a-snapshot]` | **owner**, direct | Apply `migrations/NNNN_*.sql` in order, one transaction each. Refuses edited files. |
| `mcp-token mint\|list\|revoke` | none | Offline token admin for the hosted MCP server. |

## Development

- `npm run typecheck`, `npm run build`, `npm test` (Node's test runner on PGlite; no network, no database).
- `npm run hooks:install` adds a pre-commit hook that runs gitleaks; `npm run secret-scan` scans the history.
- `npm run check` runs typecheck, build, tests, a gitleaks history scan and the repo guards.

## License

MIT. Copyright (c) 2026 Sovra GmbH.
