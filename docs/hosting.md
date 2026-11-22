# Hosting the Zeusi MCP server

The official hosted endpoint is `https://mcp.zeusi.dev/mcp`. Database credentials stay on the host and are not attached to this repo. You can also run your own server with the example Fly.io setup in this repo.


stdio is the default and needs no host: every assistant spawns `node dist/mcp.js` on a machine that has a checkout, a `~/.pg_service.conf` and a database credential. That works for one machine. When several assistants on different machines should share **one** memory without each of them holding a database password, run one authenticated server instead and give each assistant its own bearer token. The server keeps the database roles; the assistants never see them.

This page describes the hosted mode that ships in this repo and an example deployment on Fly.io. Any container host with a persistent volume and TLS termination works the same way.

## Hosted mode

`node dist/mcp.js --hosted` is a separate entry point from `--http` (the two flags exclude each other; `--http` stays loopback-only and unauthenticated). Code: `src/mcp-hosted.ts` (request pipeline), `src/mcp-auth.ts` (token check), `src/mcp-tokens.ts` (format, hashes, tokens file), `src/rate-limit.ts`, `src/mcp-log.ts`, `src/mcp-token-admin.ts` (CLI). Tests: `test/mcp-hosted.test.ts`, `test/mcp-auth.test.ts`, `test/mcp-tokens.test.ts`, `test/mcp-token-cli.test.ts`, `test/fly-config.test.ts`.

- **Listen:** `--bind` all IPv4 interfaces (default) or `::`, `--port` 8080. `--public-host` (repeatable, default the placeholder `mcp.example.com`) lists the Host names the server accepts, for the SDK's DNS-rebinding protection. `--data-dir` (default `/data`) holds the tokens file and the `.zeusi` ledgers; `--tokens-file` or `ZEUSI_MCP_TOKENS_PATH` overrides the tokens path.
- **Fail closed:** a missing, unreadable or invalid tokens file, a file looser than 0600, a directory looser than 0700, or a file not owned by the server user answers **HTTP 503** `{"error":"not_configured"}` to every request, before any token is parsed and without hashing. A valid file with zero usable tokens answers the same generic **HTTP 401** as a bad token, so no response reveals how many tokens exist.
- **Auth order:** one `Authorization: Bearer <token>` header; a success cache by `token_id` (5 minutes, dropped whenever the file changes; a hit still re-checks revoke and expiry); the failed-auth limit (10 / minute per client IP, 60 / minute global; **HTTP 429** without hashing); row lookup; then argon2id and a constant-time compare. At most 8 hashes may be running or queued at once. Unknown, malformed, revoked, expired and wrong-class tokens all get the same 401 with `WWW-Authenticate: Bearer realm="zeusi"`.
- **Client IP:** taken from `Fly-Client-IP` (Fly's proxy overwrites a client-sent value), else the socket peer. Behind another proxy, make sure the per-IP bucket sees a trustworthy address.
- **Token classes:** **read** (`zeusi_startup` / `startup`, `zeusi_search` / `search`, `zeusi_search_feedback`; server role `zeusi_box_ro` or `zeusi_cloud_ro`) and **write** (read plus `zeusi_log_decision` / `log_decision`; server role `zeusi_box_decision` over TCP). The HTTP layer refuses the write tool for a read token (also inside a batch), a read-token server does not register the write tool, and the unchanged write gate still needs `--write-service` (or `ZEUSI_MCP_WRITE_SERVICE`).
- **Request limits:** 60 MCP messages / minute per token, 10 `log_decision` / minute per token, 300 / minute global. Every authenticated MCP message counts. Over a limit: HTTP 429, `Retry-After`, body `{"error":"rate_limited"}`, and no tool runs.
- **Body:** 1 MiB cap (HTTP 413); the whole body must arrive within 10 s, otherwise HTTP 408 and the connection is closed.
- **HSTS:** every response, including 401, 404, 413, 429 and 503, carries `Strict-Transport-Security: max-age=31536000`.
- **Feedback** `query_id`s are bound to the `token_id` that ran the search.

All gates and walls in `src/mcp-server.ts` (offline user check, live session check, output wall, protected names) are unchanged; the auth layer only sits in front of them.

## Tokens

- **Format** `zeusi_<token_id>_<secret>`. The server parses the `token_id`, looks up that one row and slow-hashes only the secret against it.
- **Hashes live on the server's volume**, not in the database and not in the repo: `<data-dir>/mcp-tokens.json`, directory 0700, file 0600, owned by the server user. Each row has `token_id`, `assistant` label, `class`, an argon2id `hash` (per-token salt and parameters stored alongside), `issued_at`, `expires_at` (90 days at most) and `revoked_at`. No plaintext token, database password or API key is stored.
- **One token per assistant**, so one can be revoked without touching the others, and writes and feedback are attributed to a `token_id`. Give an assistant a write token only when you mean it; a write token already includes read.
- **Mint offline, on the machine that holds the volume, as the server user**, to a tmpfs path:

  ```
  node dist/cli.js mcp-token mint --label <assistant> --class read --out /dev/shm/<assistant>.token
  ```

  The `--out` path must be a tmpfs path (`/dev/shm`), never the `/data` volume: a plaintext token left on the volume would outlive the machine and every snapshot of it. The token is never printed: stdout shows the `token_id`, label, class, `expires_at` and the out path. Copy the file into your password manager without printing it, then delete both copies. No `*.token` file should remain on the volume or the machine.
- **Revoke** with `zeusi mcp-token revoke <token_id>`; the server re-reads the tokens file when it changes. `zeusi mcp-token list` shows ids, labels, classes and timestamps, never a hash. Rotate at least every 90 days, and immediately on a suspected leak.
- `.gitleaks.toml` has a rule that blocks any committed `zeusi_<token_id>_<secret>` token.

## TLS

- Terminate TLS at the host's edge with a publicly trusted certificate for your MCP host name.
- **Refuse plain HTTP, do not redirect.** Expose port 443 only. A redirect would arrive only after a client mistakenly configured with `http://` had already sent its bearer token in cleartext.
- Keep `sslmode=verify-full` and `channel_binding=require` on the database leg. Never set `NODE_TLS_REJECT_UNAUTHORIZED=0`.

## Logging: allowlist, no content

One JSON line per request with exactly these fields: timestamp, request id, `token_id`, assistant label, class, tool name, `duration_ms`, `hit_count`, `withheld_count`, HTTP status, error class. Tool names outside the known list are logged as `unknown`.

**Never logged:** query text, chunk text, `exact_words`, tokens, passwords, connection strings, database hostnames, walled content.

## Example: Fly.io

The repo ships an example `fly.toml`, a two-stage `Dockerfile` (`node:24-bookworm-slim`) and `scripts/fly-entrypoint.sh`:

- `fly.toml`: placeholder app name `your-zeusi-mcp`, one always-on `shared-cpu-1x` machine with 512 MB (`auto_stop_machines = "off"`, `min_machines_running = 1`), volume `zeusi_data` at `/data`, and a single `[[services]]` port 443 with `handlers = ["tls", "http"]` (no `[http_service]`, no port 80, no `force_https`). Pick the region closest to your database.
- The entrypoint refuses to start without the `/data` mount, chowns it to `node` with mode 0700, then drops to `node` and runs `node dist/mcp.js --hosted --data-dir /data`, adding one `--public-host` for each name in `ZEUSI_PUBLIC_HOSTS` (comma-separated). It never starts `--http`, and it adds `--write-service` only behind the opt-in described in Write service below.

Steps, in order:

1. `fly apps create <your-app>` and `fly volumes create zeusi_data --size 1 --region <region>`; set `app` and `primary_region` in `fly.toml`.
2. Set `ZEUSI_PUBLIC_HOSTS` (for example `mcp.example.com,<your-app>.fly.dev`) and the read service file plus the read login's secret with `fly secrets set` (never in `fly.toml` or the image).
3. `fly deploy`, then `fly certs add <your MCP host>` and point a CNAME at `<your-app>.fly.dev`. Use `fly certs show <your MCP host>` for any ownership / ACME records the certificate needs.
4. Check that the server answers HTTP 503 with no tokens file, then HTTP 401 for a made-up token. Only then mint tokens (above).

Rough cost at list prices: one `shared-cpu-1x` 512 MB machine plus a 1 GB volume is a few US dollars a month; check Fly's pricing page for your region.

## Write service (opt-in)

The hosted server is **read-only unless the operator turns the write service on**. When it is on, only a **write token** can call `zeusi_log_decision` / `log_decision`, and the server writes only as `zeusi_box_decision` (migration `0012_decision_write_role.sql`) over TCP with `channel_binding=require`. Read tokens are unchanged: the HTTP layer answers the generic **401** for either write name (also inside a batch), and a read-token server does not register the write tool at all.

### Secrets (names only; values never go in the repo, a log, chat or `fly.toml`)

| Secret | Holds | Notes |
|---|---|---|
| `PGSERVICEFILE` | The service file. Either a **path** inside the machine, or the file **content** (the entrypoint writes content, i.e. any value with a newline, to `/run/zeusi/pg_service.conf`, mode 0600, owned by `node`, and points `PGSERVICEFILE` there) | Must have `[zeusi_ro]` (user `zeusi_box_ro`) and, for writes, `[zeusi_decision]`: `user=zeusi_box_decision`, the **same** `host`, `port` and `dbname` as `[zeusi_ro]`, `sslmode=verify-full`, `sslrootcert=system`, `channel_binding=require`. No password or passfile key (both refused). Template: `config/pg_service.example.conf` |
| The read login's env-password secret (name in `docs/roles.md`, "The one env-password exception") | The `zeusi_box_ro` password | Unchanged. Only `zeusi_box_ro` reads it |
| `ZEUSI_MCP_WRITE_SERVICE` | The write service name, for example `zeusi_decision` | The switch. Unset: read-only |
| `ZEUSI_DECISION_PGPASS` | **One** pgpass line: `<host>:5432:<dbname>:zeusi_box_decision:<password>` | Host, port and dbname must match `[zeusi_decision]` (or be `*`). A `:` or `\` in the password is escaped as `\:` / `\\` (libpq pgpass rules) |

There is **no env-password exception** for `zeusi_box_decision`: the app never reads its password from an environment variable. The entrypoint (running as root, before it drops to `node`) writes `ZEUSI_DECISION_PGPASS` with the shell builtin `printf` (never echoed, never on argv) to `/run/zeusi/pgpass` (directory 0700, file 0600, both owned by `node`; the machine's ephemeral root filesystem, **not** the `/data` volume and not next to the tokens file), exports `PGPASSFILE=/run/zeusi/pgpass`, **removes `ZEUSI_DECISION_PGPASS` from the environment**, and execs the server with `--write-service <service>`. The app reads the password from that file (libpq `PGPASSFILE` semantics: a path, same 0600 rule as `~/.pgpass`; `src/keychain.ts`) only inside the write gate's connect step.

### Fail closed: read-only, not a crash

| Configuration | Result |
|---|---|
| `ZEUSI_MCP_WRITE_SERVICE` unset | Read-only. `ZEUSI_DECISION_PGPASS` (if set) is dropped and never written |
| Set, `ZEUSI_DECISION_PGPASS` missing | `fly-entrypoint: write service REFUSED: ... secret is missing; starting read-only` |
| Set, secret not one well-formed line for `zeusi_box_decision` (other login, empty password, missing field, two lines, CR) | `fly-entrypoint: write service REFUSED: ZEUSI_DECISION_PGPASS is not one pgpass line ... (value not shown); starting read-only` |
| Set, not a service name | `fly-entrypoint: write service REFUSED: ZEUSI_MCP_WRITE_SERVICE is not a service name ...; starting read-only` |
| Entrypoint OK, but the node preflight fails (no such service section, its `user=` is not `zeusi_box_decision` (the transitional `zeusi_box_rw` is **not** allowed on the host), `PGPASSFILE` missing / looser than 0600 / no line matching the section's host, port, dbname and user, or `ZEUSI_TRANSPORT=serverless`) | `zeusi-mcp: write service REFUSED at startup: <reason>. Serving read-only.` |

In every refused case the entrypoint also unsets `ZEUSI_MCP_WRITE_SERVICE` before `node` starts, so the app cannot pick it up from the environment. No log line carries a password, a host or the secret line.

**Why read-only and not exit:** the read path does not depend on the write secret. Exiting would turn one wrong write secret into a full outage, and the platform would restart-loop the machine. Read-only keeps reads up and writes refused (a write token gets the existing "this connector is read-only" refusal, never a write as another login), and the log line plus the startup mode line (`(read-only)` instead of `(read + log_decision)`) say exactly what is wrong.

### Turn it on (after 0012 is applied and the `zeusi_box_decision` password is set)

1. Make sure the `PGSERVICEFILE` secret has the `[zeusi_decision]` section above.
2. Set `ZEUSI_DECISION_PGPASS` with `fly secrets set`, giving `-` as its value so flyctl reads the line from stdin (keeps it out of shell history and argv).
3. `fly secrets set ZEUSI_MCP_WRITE_SERVICE=zeusi_decision` (setting secrets restarts the machine with the new environment).

### Verify

- `fly logs`: `fly-entrypoint: write service ON: --write-service zeusi_decision (password file /run/zeusi/pgpass, 0600)`, then `zeusi-mcp: hosted streamable HTTP on port 8080 (read + log_decision); tokens configured`. Any `REFUSED` line means read-only; fix the named item.
- A **read** token: `tools/list` has no `zeusi_log_decision` / `log_decision`; calling either answers HTTP 401.
- A **write** token: `tools/list` has `zeusi_log_decision`; one real, sourced decision returns `status: inserted`. A refusal naming the session check means the live session is not `zeusi_box_decision` with INSERT on `zeusi.decisions`; nothing is written.

### Turn it off

`fly secrets unset ZEUSI_MCP_WRITE_SERVICE` (the machine restarts read-only; the log says `write service off (read-only)`), and `fly secrets unset ZEUSI_DECISION_PGPASS` to drop the credential. Rotate the `zeusi_box_decision` password if it may have leaked (`docs/roles.md`). The database is not touched.

Tests: `test/fly-entrypoint.test.ts` (the entrypoint under `sh` and `dash` with fake `mountpoint` / `chown` / `setpriv`), `test/hosted-write-service.test.ts` (`PGPASSFILE`, startup preflight), `test/mcp-hosted.test.ts` (read token refused with the write service on; the write token reaches the write gate).

## Workspace keys

One server setting, `ZEUSI_WORKSPACE_ENCRYPTION`, turns workspace keys on for personal workspaces. Code: `src/workspace-keys.ts`. Only three values are understood:

| Value | What the server does |
|---|---|
| unset, empty or `off` | The default. No workspace keys. Personal workspaces are provisioned as before. |
| `enroll` | The consent page offers key setup for a personal workspace (a passkey, plus a recovery code shown once). Only the key is set up: the content of an existing workspace stays as it is (`src/mcp-oauth-views.ts`). |
| `on` | Everything `enroll` does, and a NEW personal workspace is provisioned with its content columns sealed from the start (`src/mcp.ts` `tenantSignupSetup`, `src/tenants.ts`). |

Any other value is treated as `off`, with one log line that names the setting and never its value. The setting does not change the team workspace. `fly.toml` does not set it.

For a personal workspace provisioned with `on`, the user-facing wording is exactly the wording of the security page, and nothing more:

Your memory is encrypted. Only you hold the key. It is not hidden from the people who run Zeusi while you are signed in: the Zeusi server then decrypts your memory to answer your assistant. Whoever holds the admin database login can see that your workspace exists, how many items it holds, how large they are and when it changes.

Your workspace is not end-to-end encrypted.

## Rollback

Scale the machine to 0 (`fly scale count 0`) or destroy the app, remove the DNS record, and revoke the tokens. Hosting adds **no migration**; rollback never touches the database. With `ZEUSI_MCP_WRITE_SERVICE` unset the server is read-only. stdio MCP on local machines keeps working unchanged.


## OAuth for MCP clients

The hosted server can offer OAuth for MCP clients (including claude.ai custom connectors). Discovery lives at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`. GitHub is only the identity check: Zeusi asks for `read:user` and `user:email`, reads the login and verified emails once, and drops the GitHub token. Set `ZEUSI_GITHUB_CLIENT_ID`, `ZEUSI_GITHUB_CLIENT_SECRET` and `ZEUSI_OAUTH_SIGNING_KEY` on the host (never in the repo or `fly.toml`). The GitHub callback is `https://mcp.zeusi.dev/oauth/github/callback` on the official host, or `https://<your-host>/oauth/github/callback` on your own. Official clients use `https://claude.ai/api/mcp/auth_callback`. PKCE is S256. Revoke with `zeusi mcp-oauth revoke`. OAuth sign-in is read-only, always.

Operator membership (who reaches the shared team workspace, rather than a new personal workspace) is configured with `ZEUSI_OPERATOR_GITHUB_LOGINS` and `ZEUSI_OPERATOR_EMAILS`. The values in this repo are examples only.
