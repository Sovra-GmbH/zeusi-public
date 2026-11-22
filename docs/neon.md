# Neon facts and connection setup

Hostnames and passwords are never written here.

## Server

- **PostgreSQL 18.7**, with **pgvector 0.8.7**. The plan assumed PG17 (KTD4 / OD4). Neon runs 18.
- The local test DB is PGlite, which is PostgreSQL 18.6 with pgvector. It is the same major version as Neon.

## U11 backup: pg_dump must be version 18 or newer

`pg_dump` must be at least the server's major version. Neon runs **18**. Install a PostgreSQL 18 client (`pg_dump` / `psql`) before taking a dump. A restore test needs PG 18 with pgvector locally.

## Connection model (KTD10, KTD11)

| Who | How it connects | Where the secret lives |
|---|---|---|
| Role commands (`doctor`, `fact`, `vector-probe`, `wall report`, `wall audit`, later the importers) | A `~/.pg_service.conf` section (or `PGSERVICEFILE`). Template: `config/pg_service.example.conf` | Mini: Keychain item `zeusi-neon-<role>`, account `<role>`, read with `/usr/bin/security`. Box: `~/.pgpass` (0600) |
| Owner commands, owner only (`migrate`, `wall allow`, `prove`, `embed-smoke`) | Owner URL names in `.env.local` (gitignored). The CLI loads `.env.local` only for these commands | 1Password, plus `.env.local` on the machine the operator migrates from |

Every service must have `sslmode=verify-full`, `sslrootcert=system`, and `channel_binding=require`. The CLI enforces this in code:

- It verifies TLS against the trusted root store and checks the hostname.
- It refuses any authentication other than SCRAM-SHA-256-PLUS, **before** the password is sent.
- It refuses a service file that contains `password=`.
- It ignores inherited `PG*` / `DATABASE_URL` environment variables for role connections.

Endpoints:

- `zeusi_ingest` uses the **direct** host (the pooled name without `-pooler`). The vault importer serialises runs with a session-level `pg_try_advisory_lock`. Over the pooler (PgBouncer in transaction mode) consecutive statements can reach different server backends, so the lock would neither exclude a second run nor reliably unlock. `ingest vault --real` therefore refuses a service whose host contains `-pooler` (any letter case), offline, before it reads a password or connects. The error names the service and file, never the host. Only one importer runs at a time, so the direct endpoint's connection limit is not a concern. `doctor`, `wall report` and `wall audit` (default service `zeusi_ingest`) hold no session state and work on the direct host too.
- `zeusi_backup` uses the **direct** host as well. `pg_dump` must not run over the pooler (KTD12).
- `zeusi_rw` and `zeusi_ro` (box) stay on the **pooled** host: short transactions, no session state.

## Serverless transport (wss, port 443) for `search` and read-only `doctor`

Some agent boxes cannot complete a Postgres session on TCP 5432, but HTTPS 443 to the same Neon **pooled** host works. For those, `zeusi search` and `zeusi doctor` can use `@neondatabase/serverless` over a secure WebSocket instead (`src/transport.ts`). It is off by default. TCP 5432 stays the default and does not change.

| | |
|---|---|
| Gate | env `ZEUSI_TRANSPORT=serverless` (exactly that). Unset or empty = TCP. Any other value is refused for every command. |
| Commands | `search` and `doctor` (`--offline`, plain, `--roles`). Every other command (ingest, embed, migrate, prove, embed-smoke, wall, fact, vector-probe, export-filter) is refused under the gate and keeps its TCP / owner path. |
| Roles | `zeusi_box_ro`, `zeusi_cloud_ro` only (service section `user=`). Anything else is refused before a password is read or a client is created. |
| Service file | unchanged: the same `[zeusi_ro]` section (pooled host), with the same three TLS lines, which are still required. There is **no** service-file key for the transport: libpq/psql reject unknown keywords, so a Zeusi-only key would break `psql service=zeusi_ro`. The `port=` line is ignored on this transport (wss uses 443). |
| Password | `ZEUSI_NEON_BOX_RO_PASSWORD` (`zeusi_box_ro` only), else `~/.pgpass` / Keychain. Never in a URL. |
| TLS | wss only, certificate and hostname verified by Node; `NODE_TLS_REJECT_UNAUTHORIZED=0` is refused. |
| Auth | password over verified TLS, **not** SCRAM-SHA-256-PLUS: the documented exception in `docs/roles.md`. |

How an agent on the box runs it (with the ro password in its env as before; no hostnames or passwords on the command line):

```
ZEUSI_TRANSPORT=serverless node dist/cli.js search "<query>" --limit 3
ZEUSI_TRANSPORT=serverless node dist/cli.js doctor --service zeusi_ro
```

`doctor` over this transport runs inside `BEGIN READ ONLY` and prints `transport: serverless` and `channel binding: no (...)`. It exits 0 when TLS is up and pgvector is present.

One transaction: the transport uses one WebSocket `Client` (one server session) per command, never the HTTP one-shot `neon()` API. `search` still runs `BEGIN READ ONLY`, `SET LOCAL hnsw.ef_search = 100`, `SET LOCAL hnsw.iterative_scan = relaxed_order`, its queries and `ROLLBACK` in that one session, so the `SET LOCAL`s apply to the query (tested on PGlite, including a one-shot mutant that the test catches).

## Operator checklist

To make `npm start -- doctor` and `npm start -- doctor --roles` work:

1. Copy `config/pg_service.example.conf` to `~/.pg_service.conf`.
2. Fill in the hosts and database name from your password manager.
3. Run `chmod 600 ~/.pg_service.conf`.
