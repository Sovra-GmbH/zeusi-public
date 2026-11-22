# Embeddings, the $5 cap, and search (U6, KTD5, KTD6, KTD16)

Code: `src/embeddings.ts` (clients), `src/embed.ts` (pipeline and cap), `src/search.ts` (search), `src/estimate.ts` (offline estimate). Tests: `test/embeddings.test.ts`, `test/embed.test.ts`, `test/search.test.ts`, `test/ro-password.test.ts`, `test/estimate.test.ts`, plus additions to `test/cli.test.ts` and `test/roles.test.ts`. Every test uses PGlite and the deterministic fake client. Nothing in this branch has called OpenAI or Neon.

No migration is needed. `zeusi.embed_usage` (0001) already has `month`, `embed_model`, `host`, `tokens` and `est_usd`, and 0004 grants `INSERT, UPDATE` on it to `zeusi_ingest`. **PR B adds no migration.** (0010 and 0011 on main are the wall migrations of #3; `embed` requires them, see below.)

## Model and endpoint

- OpenAI `text-embedding-3-small` at 1536 dims. The value stored in `chunks.embed_model` is `openai/text-embedding-3-small@1536`, the model the partial HNSW index of 0002 covers.
- EU data residency. The base URL defaults to `https://eu.api.openai.com/v1`. `validateBaseUrl()` accepts only https on `eu.api.openai.com`, with no credentials, query or fragment. Any other host needs a code change.
- Price constant: **$0.02 per 1M tokens** (`PRICE_USD_PER_1M_TOKENS`). This is the standard-tier price on OpenAI's pricing page as known on 14 Nov 2026. It is not fetched at runtime. PLAN.md notes that the EU residency uplift applies only to models released on or after 5 Mar 2026, so not to this one. Re-check on the billing page at signup.

## The key

- The key comes **only** from the env var `ZEUSI_OPENAI_API_KEY`. `createOpenAIClient()` reads it, and nothing else does. `OPENAI_API_KEY` and the Keychain are not used by `embed` or `search`. The owner-only `embed-smoke` is unchanged and still uses its Keychain item.
- The key is sent only in the `Authorization` header. It never appears in a URL, a log line or an error. Every failure becomes a fresh `EmbedError` with no `cause` chain, and its message goes through `redactKey()`. Response bodies are never quoted. Only an OpenAI error code matching `/^[a-z0-9_]+$/` is kept, for example `invalid_api_key`. A test feeds the key back through an HTTP body, a network error, non-JSON and a bad shape, and checks message, `String()`, stack and JSON for both the key and its prefix.
- `zeusi embed --real` is refused unless **`--real` is passed and the key is set**. Both checks run before any DB connection. `--real` has never been run.

## Pipeline (`zeusi embed`, role `zeusi_mini_ingest`, service `zeusi_ingest`, direct endpoint)

The importer does not embed. Ingest stays embedding-free, and a test checks that `src/importers/vault.ts` imports neither the embed pipeline nor a client. The pipeline runs in this order and fails closed at each step:

1. It refuses an owner-privileged session (superuser, or a session that can write `wall_allow`).
2. **`zeusi.wall_audit()` must return 0 rows.** No text leaves the box while any stored row breaks the wall, for example after a rule was added after the ingest. Otherwise the status is `wall` and nothing is sent.
3. Only one embed run at a time, enforced by a session advisory lock. The ingest service is on the DIRECT endpoint, as for ingest.
4. It selects chunks whose `embedding IS NULL`. `--limit n` caps how many. RLS means `zeusi_ingest` never sees `personal` rows.
5. **Embedded text** is `chunking.embedText(title, heading_path, text)`, that is `title > heading path`, a blank line, then the chunk. Stored `text` stays the chunk only. Chunks that do not belong to a note use an empty title.
6. **Vector reuse by content hash.** Before any API call, `embed` looks up chunks with the same `text_sha256` and `embed_model` that already have a vector, through the `chunks_text_sha` index. It then compares the sha256 of the exact embedded string, because the same chunk text under another title or heading is a different input. A match gets the vector copied with no API call. Pending chunks with the same embedded string in one run are sent once. Tests show that a re-ingested unchanged chunk is reused, that a chunk with another title is not, and that a second run with nothing pending sends and spends nothing.
7. **Batches** hold at most 128 inputs and at most 200,000 worst-case tokens. Each batch goes through the cap reservation below, then the call, then one transaction that writes the vectors (`WHERE embedding IS NULL AND text_sha256 = ...`) and settles the usage.
8. **Retry and fail closed.** 429, 5xx and network errors are retried up to 5 attempts with capped exponential backoff, honouring `Retry-After`. Any other HTTP error ends the run, and so does a response with the wrong vector count, the wrong dimensions or non-finite values. Earlier batches stay committed.

`--dry-run` connects as ingest and reports the pending count, reuse, unique inputs, estimated and worst-case tokens and cost. It makes no API call and no write. `--estimate` is offline (see below).

## The $5 cap

- `HARD_MONTHLY_CAP_USD = 5.00` is a constant and covers **all hosts together**, per UTC calendar month. `--cap-usd <x>` can only **lower** it. A higher value is an error, not a clamp, so raising the cap needs a code change.
- **Tokens are the truth, not `est_usd`.** `embed_usage.est_usd` is `numeric(10,4)`, so a 1,000-token batch ($0.00002) rounds to $0.0000. The cap is therefore computed as `sum(tokens) × price(model)` over every host and model for the month. `est_usd` is kept for display only and rounded **up**. If a model in this month's usage has no price constant, the run is refused.
- **Worst-case estimator.** For each input, the worst case is its UTF-8 byte length. OpenAI tokenizers are byte-level BPE, so every token covers at least one byte, and the API cannot bill more tokens than bytes. This is about 4 times the usual count for English, which is deliberately pessimistic. The reported estimate uses the chunker's `ceil(code points / 4)`. After each call, the API-reported `usage.total_tokens` is the truth.
- **Atomic reservation.** This holds across crashes and concurrent runs:
  1. In one transaction, `pg_advisory_xact_lock(cap key)` is taken. The month-to-date total across all hosts is read. The batch is refused if month-to-date plus worst case would exceed the cap. Otherwise the worst-case tokens are UPSERT-added to `(month, embed_model, host)`, and the transaction COMMITs **before** the API call.
  2. After the call, a second transaction writes the vectors and adds `actual − reserved`.
  - If the process crashes or the call fails between the two, the worst-case reservation stays. That over-counts, and never under-counts.
  - Concurrent runs on any host serialise on the transaction lock, over the pooler or not, and see each other's committed reservations.
  - If the API returns no usage, the worst case is kept.
- Tests cover these cases:
  - refusal before the call, with no reservation row added
  - a lowered cap that stops the run part-way, with month-to-date ≤ cap
  - the crash case: the reservation is kept and nothing is written
  - the concurrent case: run B reserves while run A is inside its API call. B sees A's reservation and is refused, and the lock statement is observed.
  - an unknown model in this month's usage fails closed

## Search (`zeusi search`, role `zeusi_box_ro`, service `zeusi_ro`, pooled endpoint)

- **Read-only by construction.**
  - Search refuses any session that is superuser or holds INSERT, UPDATE, DELETE or TRUNCATE on any `zeusi` table. So it never runs as `zeusi_box_rw`, ingest, backup or the owner.
  - Every query runs in `BEGIN READ ONLY ... ROLLBACK`.
  - The role default `default_transaction_read_only=on` from 0004 is a second layer.
  - Tests show that `zeusi_box_ro` gets 42501 on INSERT, UPDATE and DELETE, that the read-only transaction gives 25006, and that writer and owner sessions are refused. `zeusi_cloud_ro` can search, lexical only.
- **Vector:** `ORDER BY embedding <=> $q LIMIT n`, filtered by the constant `embed_model` so that the partial HNSW index matches. `SET LOCAL hnsw.ef_search = 100` and `SET LOCAL hnsw.iterative_scan = relaxed_order` (0002, pgvector 0.8).
- **`--hybrid`:** the vector top 50 and the full-text top 50 (`tsv`, `simple` config, `websearch_to_tsquery`) are fused with reciprocal rank fusion, k = 60: score = Σ 1/(60 + rank), with ties broken by chunk id. This is tested both on the function and end to end, where a synonym-only hit and a keyword hit are both found.
- **No key:** search falls back to lexical-only with a clear notice. Cloud agents use this until the MCP phase (KTD16). A failed query embedding and a query-spend cap also fall back to lexical, with a notice.
- **Citations:** every hit has `source_uri`, `source_ts`, `scope`, `heading_path`, a score and per-list ranks. The text is **at most the chunk text**: never the note body or the embedded title prefix. Text mode prints a snippet of at most 240 characters, and `--json` prints the chunk text.
- **Proven on PGlite:** the fixture vault is ingested as ingest, embedded with the fake and searched as `zeusi_box_ro`. A `personal` chunk stored with exactly the query's vector never appears. No quarantined uri, and no walled text, appears in vector, hybrid or lexical results for queries aimed at the walled fixtures.

### Query-embedding spend (honest limits)

Query embeds are billed, but the search role is read-only, so they **cannot** be recorded in `zeusi.embed_usage` and are **not** counted against the $5 DB cap. Instead:

- **A best-effort local ledger** at `~/.zeusi/query-embed-ledger.json` on the machine that runs the search. The file is mode 0600, in a 0700 directory, and is written atomically. It stores per month `{requests, tokens, usd}` and **never the query text**. If the ledger cannot be read, search does not embed (fail closed). If the ledger cannot be written after a call, a notice is shown.
- **A per-process cap:** 20 query embeds or 20,000 worst-case tokens per CLI process.
- **A local monthly cap:** $0.50 per machine, checked against the ledger.
- A query longer than 2,000 characters is not embedded.

These are local and best effort: deleting the file resets the local count. The real safety net is a **separate OpenAI project for the box with its own budget limit**, set in the OpenAI dashboard (KTD16). At the assumed volume, 100 searches a day × 20 tokens, query spend is about $0.0012 a month.

## Read-only role password (narrow exception)

`zeusi_box_ro` and **only** that login can take its password from `ZEUSI_NEON_BOX_RO_PASSWORD`. The match is on the service file's `user=`, not the service name. This is a deliberate exception to "no DB credentials from env", so that a sandboxed agent on the box can search without a `~/.pgpass`. Otherwise `~/.pgpass` or the Keychain is used, as before. See `docs/roles.md`.

## Cost estimate (offline, count-only)

`zeusi embed --estimate [--config f] [--notes-per-day n]` runs the importer's own pipeline in dry-run mode: no DB, no network, files read-only. A numbers-only observer sums the tokens of each admitted chunk's embedded string. Run it on your own vault and config before a real embed. The printed token and USD figures are an estimate only.

- Multiply the estimate by a safety factor (for example 2) when you set an OpenAI project budget.
- **Steady state:** `--notes-per-day` projects ongoing re-embeds. This is an upper bound, because every chunk of a changed note is counted as re-embedded, while unchanged chunks are actually reused.
- **Query embeds** go to the local ledger, not to `embed_usage`. The local and project caps guard against runaway loops, not against normal use.

## What the operator must do before a real run

1. Create an EU data-residency OpenAI project with a project budget limit, then put the key in `ZEUSI_OPENAI_API_KEY` on the machine that embeds (and a separate project and key for hosted search, if you run one).
2. **Prerequisites, in this order** (`embed --dry-run` and `--real` refuse, sending and reading nothing, until the first holds: they run the same wall-readiness check as real ingest, migrations 0006–0011 and every seed rule):
   1. apply migrations 0010 and 0011 (GO, snapshot, branch first; README "Setup");
   2. run the documented Plankiva retraction (`docs/wall.md`, "Retraction of Plankiva rows already ingested"), as the operator;
   3. `node scripts/exclusion-scan.ts zeusi_backup` must print `RESULT: 0 matching rows`;
   4. `zeusi wall audit` must return 0 rows.

   Only then run `zeusi embed --dry-run`, then `zeusi embed --real --limit 50`. Check `embed_usage` against the OpenAI dashboard, then run without `--limit`.
3. For box search: set the `zeusi_box_ro` password (`docs/roles.md`), add the `[zeusi_ro]` section (pooled host), and use `~/.pgpass` or `ZEUSI_NEON_BOX_RO_PASSWORD`.
