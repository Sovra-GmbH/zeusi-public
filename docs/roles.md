# Zeusi roles

`migrations/0004_roles.sql` creates every role with SQL. Do not create Zeusi roles in the Neon Console, because console roles get `neon_superuser`. Login roles are created **without passwords**, so nobody can log in as them until a password is set.

| Login | Group | Used for | Can | Cannot |
|---|---|---|---|---|
| (database owner, the direct URL user) | — | the operator, migrations | DDL, wall tables, grants | Not used by any job |
| `zeusi_mini_ingest` | `zeusi_ingest` | ingest and import | Upsert mirrors (notes, prs, routine_runs, people, chunks). Insert facts, decisions, episodes, and reviews. Read the wall rules for pre-checks. Call `quarantine_record` | Write wall tables, read `personal`, update or delete facts or decisions, disable triggers |
| `zeusi_mini_backup` | `zeusi_backup` | backups | Read everything, insert `backup_runs` | Write content |
| `zeusi_box_rw` | `zeusi_agent_write` | general writes | Insert facts, episodes, decisions, routine runs, chunks, and ingest runs. Supersede through functions | Update or delete text, touch the wall |
| `zeusi_box_decision` (0012) | `zeusi_decision_write` | MCP `zeusi_log_decision` | Insert decisions and its own ingest runs (and close them). Supersede a decision, record a wall rejection. Read like `zeusi_read` | Insert facts, episodes, chunks, routine runs, notes, people or PRs; update or delete any text; touch the wall; read or write `personal` |
| `zeusi_box_ro` | `zeusi_read` | read-only clients | Read `work`, `product` and (since 0010) `client` | Write (read-only by default), read `personal` |
| `zeusi_cloud_ro` | `zeusi_read` | cloud agents | Same as `zeusi_box_ro`, with a 15 s statement timeout | Write, long queries |

First-run imports (`zeusi import ... --real`, `docs/mcp.md` "First-run onboarding") run as this same `zeusi_mini_ingest` login through service `zeusi_ingest` on the direct endpoint: notes and chunks (`source_kind manual`), and inserts into `facts` / `decisions` that the grants above already allow. No new role, no new grant, no migration.

Endpoints: the ingest and backup roles (`zeusi_mini_ingest` through service `zeusi_ingest`, `zeusi_mini_backup` through `zeusi_backup`) connect to the **direct** endpoint. The vault importer holds a session advisory lock, which does not hold over the pooler, and `ingest vault --real` refuses a `-pooler` host. The application roles stay on the pooled endpoint. See `docs/neon.md`.

## The decision-write role (0012, design, not applied)

`migrations/0012_decision_write_role.sql` designs a login for one job: the MCP tool `zeusi_log_decision` (`docs/mcp.md`). It is narrower than `zeusi_box_rw` / `zeusi_agent_write`, which can also insert facts, episodes, chunks and routine runs.

| | `zeusi_box_decision` |
|---|---|
| Group | `zeusi_decision_write` (NOLOGIN), which is a member of `zeusi_read` (same read RLS: `work`, `product`, and `client` once 0010 is applied; never `personal`) |
| Grants | `INSERT` on `zeusi.decisions` and `zeusi.ingest_runs`; `UPDATE (finished_at, status, counts)` on `zeusi.ingest_runs`; `USAGE` on `decisions_id_seq` and `ingest_runs_id_seq`; `EXECUTE` on `supersede_decision(bigint, bigint)` and `quarantine_record(...)` |
| RLS | Its own INSERT policy on `decisions`, `decision_write_not_personal` (`scope <> 'personal'`). 0005's `write_not_personal` names only `zeusi_agent_write` and `zeusi_ingest` |
| Attributes | `LOGIN`, no password, `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, `CONNECTION LIMIT 5` |
| Session | `statement_timeout=30s`, `idle_in_transaction_session_timeout=30s`, `search_path=zeusi, public`. Not `default_transaction_read_only` (it writes) |
| Endpoint | Pooled, like the other box roles (`[zeusi_decision]` in `config/pg_service.example.conf`) |
| Password | Out of band, as below: `\password zeusi_box_decision`, a password-manager or Keychain item (service `zeusi-neon-zeusi_box_decision` / account `zeusi_box_decision`), or `~/.pgpass` on the machine that writes. Hosted (Fly): the Fly secret `ZEUSI_DECISION_PGPASS` (one pgpass line), written by the entrypoint to a 0600 file named by `PGPASSFILE` (`docs/hosting.md`, Write service). Still a file, never an env password the app reads |
| Env password | **None.** The `ZEUSI_NEON_BOX_RO_PASSWORD` exception stays `zeusi_box_ro` only (`test/ro-password.test.ts` checks this login too) |
| Serverless | **None.** Writes stay on TCP with `channel_binding=require`; `ZEUSI_TRANSPORT=serverless` refuses `zeusi_log_decision` before any credential read |

0012 depends only on 0001-0005. It does not need 0010 or 0011 (tested on PGlite by applying 0001-0009 + 0012). It is idempotent.

Until 0012 is applied, the MCP write gate also accepts the transitional `zeusi_box_rw` (`src/mcp-server.ts`, `TRANSITIONAL_WRITE_ROLE`).

**Applying it:** dry run first (`npm run migrate -- --dry-run`), take a database snapshot, then apply as the owner over the direct URL. `zeusi migrate` applies **every** pending file in order, so a plain run also applies any other pending migrations. After applying: set the password, store it, add `[zeusi_decision]` to `~/.pg_service.conf` on the machine that writes, run `zeusi doctor --roles`, then point the MCP at `--write-service zeusi_decision`.

## Decision links (0013, design, not applied)

`migrations/0013_decision_links.sql` adds the insert-only table `zeusi.decision_links` (decision -> PR / note / repo / job / lane). It creates no role and changes no existing grant.

| Role / group | `zeusi.decision_links` |
|---|---|
| `zeusi_read` (`zeusi_box_ro`, `zeusi_cloud_ro`, and every writer group through membership) | `SELECT`, RLS `read_allowed_scopes` (work, product, client; never personal) |
| `zeusi_backup` | `SELECT` (RLS `backup_read_all`), `SELECT` on the sequence |
| `zeusi_ingest` (`zeusi_mini_ingest`), `zeusi_decision_write` (`zeusi_box_decision`) | `INSERT` + sequence `USAGE`, RLS `links_insert_not_personal` (`scope <> 'personal'`) |
| `zeusi_agent_write` (`zeusi_box_rw`, transitional) | no `INSERT`: `zeusi_log_decision` refuses links on that login |
| everyone but the owner | no `UPDATE`, `DELETE` or `TRUNCATE` |

`zeusi.decision_links_wall_audit()` (SECURITY DEFINER, same columns as `wall_audit()`, EXECUTE for `zeusi_ingest` and `zeusi_backup` only) re-checks stored links against today's rules; `zeusi wall audit` and the ingest exit code include it once 0013 is applied. `wall_audit()` itself is unchanged.

It depends on 0012 (it grants to `zeusi_decision_write`). Apply with a dry run first, on a scratch branch before main; rollback: `migrations/ROLLBACK-0013.md`. `zeusi prove` reports the 0013 grant matrix when the table exists (skip otherwise). 0013-a (`supersede_fact` for `zeusi_ingest`) is not part of it.

## Setting passwords (the owner, out-of-band)

1. Connect as the owner with `psql` over the direct URL. Do not paste the URL anywhere else.
2. For each login, run `\password zeusi_box_ro` (and the others). Use a generated password of 32 characters or more.
3. Store each password in your password manager, one item per login role.
4. Place machine copies only on the machine that uses them. Use `~/.pgpass` (0600) or the Keychain, outside every repo.

On macOS, the CLI reads the Keychain generic password with service `zeusi-neon-<role>` and account `<role>`. For example, `zeusi-neon-zeusi_mini_ingest` with account `zeusi_mini_ingest`. It reads with `/usr/bin/security find-generic-password -s .. -a .. -w`, over stdout only, and never logs the value. Host, database, and TLS settings come from `~/.pg_service.conf` (template `config/pg_service.example.conf`, see `docs/neon.md`).

### The one env-password exception: `zeusi_box_ro` (U6)

The rule is that role connections never take DB credentials from the environment. There is one deliberate, narrow exception. The read-only search login `zeusi_box_ro` may take its password from the env var `ZEUSI_NEON_BOX_RO_PASSWORD` on the search host, so that a sandboxed agent can run `zeusi search` without a `~/.pgpass`. The limits:

- Only when the service section's `user=` is `zeusi_box_ro`. The match is on the user, not the service name, so a renamed section for another role gets nothing.
- No other role reads it, or any other env password (`PGPASSWORD`, `ZEUSI_NEON_<ROLE>_PASSWORD`, ...). `test/ro-password.test.ts` checks every login.
- It is read only inside `connectService()` (`src/db.ts`). It is passed to the driver as a config field, never in a URL string. It is never printed, logged or written to disk, and it is redacted from connection errors (tested with a client whose error echoes it).
- Everything else stays the same: `sslmode=verify-full`, `sslrootcert=system`, `channel_binding=require` (SCRAM-SHA-256-PLUS) on the default TCP transport, and the **pooled** endpoint (`[zeusi_ro]` in `config/pg_service.example.conf`). Search holds no session state. The one transport-level exception is the next section.
- Without the variable, the password comes from `~/.pgpass` (or the Keychain), as before.

`PGPASSFILE` is not an env password: like libpq, Zeusi treats it as the **path** of the pgpass file to read instead of `~/.pgpass` (same format, same 0600-or-stricter rule). The hosted Fly entrypoint uses it for `zeusi_box_decision`.

`zeusi search` refuses any session that can write (`src/search.ts`). `zeusi doctor --roles --service zeusi_ro` runs the catalog checks as the ro login (tested on PGlite).

### The serverless-transport auth exception: read-only roles, `ZEUSI_TRANSPORT=serverless` only

Why: when TCP 5432 egress to the database is blocked, HTTPS 443 to the same Neon pooled host may still work. `ZEUSI_TRANSPORT=serverless` sends `zeusi search` and read-only `zeusi doctor` through `@neondatabase/serverless` (the Postgres protocol inside a secure WebSocket, port 443). Setup and commands: `docs/neon.md`. Code: `src/transport.ts`.

**The exception, written down:** Neon serverless authentication is the role password sent over a verified TLS (wss) connection to Neon's proxy. It is **not** Postgres SCRAM-SHA-256-PLUS channel binding. This is allowed:

- only on this transport (the default TCP 5432 path keeps `channel_binding=require` and has no switch to turn it off);
- only for the read-only logins `zeusi_box_ro` and `zeusi_cloud_ro` (matched on the service section's `user=`). `zeusi_box_rw`, `zeusi_mini_ingest`, `zeusi_mini_backup`, the owner and any other user are refused after the offline service-file check, **before** a password is read and before any client is created, even with the gate set;
- only when the explicit gate `ZEUSI_TRANSPORT=serverless` is set. Any other value is refused (never ignored). With the gate set, only `search` and `doctor` run; every other command is refused before it connects.

TLS certificate verification is still required: wss only (the socket constructor refuses any other scheme), Neon's default proxy address, no experimental pure-JS TLS, and the CLI refuses to run this transport with `NODE_TLS_REJECT_UNAUTHORIZED=0`. Node's WebSocket verifies the certificate and hostname against Node's trust store. Passwords come from the same places as before: `ZEUSI_NEON_BOX_RO_PASSWORD` (for `zeusi_box_ro` only), or the Keychain / `~/.pgpass`. The password is a driver config field, never part of a URL, never printed, logged or committed, and is redacted from connection errors.

`zeusi doctor` over this transport says so: `transport: serverless`, `TLS: yes (wss, certificate verified)`, `channel binding: no (serverless transport: password over verified TLS, not SCRAM-SHA-256-PLUS; read-only roles only)`. It never claims SCRAM-SHA-256-PLUS. Tests: `test/serverless-transport.test.ts`, `test/cli.test.ts`.

Never put a password in a migration, this repo, a vault note, or a log. Rotate every 90 days, and immediately on any suspected leak (`ALTER ROLE ... PASSWORD`).

## Who reads `client` (0010)

0010 adds scope `client` for ClientCo content. By default, **`client` is readable exactly like `work`**: the read policy `read_allowed_scopes` on all 9 content tables is `scope::text IN ('work', 'product', 'client')` for group `zeusi_read`.

So **every login that reads through `zeusi_read` can read ClientCo content**: `zeusi_box_ro`, `zeusi_cloud_ro`, and, through their group membership, `zeusi_box_rw` and `zeusi_mini_ingest`. `zeusi_mini_backup` reads everything (`USING (true)`), as before. Writers (`zeusi_agent_write`, `zeusi_ingest`) may write `client` rows, as they may write `work` (`scope <> 'personal'`). `personal` stays hidden from every reader and unwritable.

If ClientCo must be narrower than `work` (for example, not the cloud agents), 0010's default is too wide. A follow-up migration would then add a separate group (for example `zeusi_read_client`), take `client` out of `read_allowed_scopes`, and add a `client` read policy for that group only. That needs a new migration. Applied migrations are never edited.

## Backups and RLS

RLS is on for the content tables. `zeusi_backup` has a `USING (true)` read policy. `pg_dump` turns row security off by default, and it errors on RLS tables for non-owners. Run it as:

```sh
pg_dump -Fc --enable-row-security ...   # as zeusi_mini_backup, over the DIRECT URL
```

## Future migrations

New tables need explicit grants, because there are no default privileges. New content tables need four things:

- the provenance block
- the `zeusi_10_provenance` and `zeusi_90_wall` triggers
- a case in `zeusi.wall_content()`
- RLS policies, following `0005_rls.sql`

## Checking the roles

`npm start -- doctor --roles` connects as `zeusi_mini_backup` (service `zeusi_backup`) inside a read-only transaction and checks:

- No Zeusi login is a member of `neon_superuser`.
- Each login has no elevated attributes.
- CONNECTION LIMIT is 4 / 2 / 5 / 5 / 5.
- 0012's `zeusi_box_decision` / `zeusi_decision_write`: if neither exists, one passing line says `not applied`. If either exists, the full checks run (login and NOLOGIN group, no elevated attributes, CONNECTION LIMIT 5, session settings, member of `zeusi_decision_write`, **not** a member of `zeusi_agent_write`, `zeusi_ingest` or `zeusi_backup`, not in `neon_superuser`). A half-applied or widened role fails.
- `statement_timeout`, `default_transaction_read_only`, `idle_in_transaction_session_timeout`, and `search_path` match 0004.
- Each login is in its group.

The same function runs in `npm test` against PGlite.

These scenarios need a Neon branch (owner work) and are not tested live here:

- A cloud query running longer than 15 s is cancelled.
- A sixth concurrent `zeusi_cloud_ro` connection is refused.

The settings that implement them are asserted above.

## Wall functions and the `wall_audit()` grant (review r1 MINOR-4)

| Function | Security | EXECUTE granted to | Why |
|---|---|---|---|
| `zeusi.wall_eval(text, jsonb)` | INVOKER | `zeusi_ingest` | Importer pre-check. Runs with the caller's rights, so it sees only what the caller may see |
| `zeusi.wall_norm(text)`, `zeusi.pct_decode(text)`, `zeusi.pct_decode_once(text)` (0008) | INVOKER, IMMUTABLE | `zeusi_ingest` | Helpers that `wall_eval` calls |
| `zeusi.wall_audit()` | **DEFINER** (runs as the owner, so RLS does not apply) | `zeusi_ingest`, `zeusi_backup` | The nightly audit must see every row, including `personal`, to prove that no blocked content is stored |

None of these is executable by PUBLIC or by the reader roles (`test/roles.test.ts`, `test/wall.test.ts`).

`wall_audit()` is the one grant that lets `zeusi_ingest` reach rows it cannot read directly. 0007 added it (0004 had revoked the function from PUBLIC with no grant). What it returns is limited:

- Only rows that **break** the wall: a hard-rule hit, a soft-rule hit without a pinned allow, or a quarantined (uri, sha) found in content. On a healthy DB it returns 0 rows.
- No content. The columns are `table_name`, `row_ref` (the id), `source_uri`, and `problem` (rule id and kind).
- Since 0008, `source_uri` is replaced by `personal:<masked>` for `scope = 'personal'` rows, unless the calling login (`session_user`) is a member of the function owner (the owner over the owner URL). `zeusi_mini_ingest` and `zeusi_mini_backup` therefore see the table and id of a bad personal row, but not its uri. Since 0009, `row_ref` of a personal `prs` row (`repo#number`) is masked the same way; all other tables' `row_ref` is a numeric id. To see it, the operator runs `SELECT * FROM zeusi.wall_audit()` as the owner (psql over the owner URL; the CLI `wall audit` is a role command).

## `scripts/exclusion-scan.ts` and the roles (0011)

0011 changes no role, grant or policy. The read-only scan `node scripts/exclusion-scan.ts <service>` uses only what the service's role already has: it checks `has_table_privilege(..., 'SELECT')` per table and runs plain `SELECT`s (no `SET ROLE`, no `row_security` change, no function calls, so no `wall_norm` EXECUTE is needed; the matching runs in TypeScript). As `zeusi_backup` (service `zeusi_backup`) it reads every row of every table (SELECT on all tables, RLS policy `backup_read_all`). As a reader role it counts only what RLS shows and reports `quarantine`, `wall_allow` and `wall_denylist` as not readable. It prints table names and counts only.
