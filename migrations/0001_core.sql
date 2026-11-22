-- 0001_core.sql — Zeusi core schema (PLAN.md U2, Schema sketch).
-- Applied over the DIRECT (unpooled) URL by `zeusi migrate`, as the schema owner.
-- The owner is whatever role the direct URL logs in as (Neon default owner).
-- Every content table carries the provenance block (R2, invent=NO): a row
-- without scope, source_kind, source_uri, source_ts, source_sha256 and
-- ingest_run_id cannot be inserted. ingested_at/ingested_by are stamped by a
-- trigger from the server clock and the login role, so a writer cannot fake them.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE SCHEMA IF NOT EXISTS zeusi;

-- Wall by construction (KTD7 type layer): no ClientCo or Plankiva value exists.
CREATE TYPE zeusi.scope AS ENUM ('work', 'product', 'personal');

CREATE TYPE zeusi.source_kind AS ENUM (
  'vault_note', 'lane_md', 'review_ledger', 'github_api', 'runner_log',
  'assistant_memory', 'zeus_memory', 'agent_write', 'manual'
);

CREATE TYPE zeusi.decision_kind AS ENUM ('go', 'lock', 'ruling', 'stop', 'park');
CREATE TYPE zeusi.pr_state      AS ENUM ('draft', 'open', 'merged', 'closed');
CREATE TYPE zeusi.verdict       AS ENUM ('SAFE', 'NOT_SAFE');  -- ledger 'NOT SAFE' normalised

-- Every writer (importer, agent, CLI) opens one run row and points content rows at it.
CREATE TABLE zeusi.ingest_runs (
  id          bigserial PRIMARY KEY,
  importer    text NOT NULL CHECK (btrim(importer) <> ''),   -- 'vault', 'github', 'cli', 'agent:zeus', ...
  host        text NOT NULL CHECK (btrim(host) <> ''),       -- 'mini', 'box', 'cloud', ...
  mode        text NOT NULL CHECK (mode IN ('full', 'incremental', 'agent', 'manual')),
  started_at  timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  status      text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'ok_partial', 'failed')),
  counts      jsonb NOT NULL DEFAULT '{}',                   -- inserted/updated/skipped/quarantined
  started_by  text NOT NULL DEFAULT session_user
);

-- Provenance block "P", repeated verbatim on every content table:
--   scope         zeusi.scope       NOT NULL
--   source_kind   zeusi.source_kind NOT NULL
--   source_uri    text              NOT NULL, non-blank  (vault:Work/..., gh:example-org/repo#12, ledger:...:L42)
--   source_ts     timestamptz       NOT NULL             (when the source said it)
--   source_sha256 bytea             NOT NULL, 32 bytes
--   ingest_run_id bigint            NOT NULL -> ingest_runs
--   ingested_at   timestamptz       NOT NULL (trigger-stamped)
--   ingested_by   text              NOT NULL (trigger-stamped, session_user)

CREATE TABLE zeusi.people (
  id            bigserial PRIMARY KEY,
  handle        text UNIQUE NOT NULL,          -- 'owner', 'assistant', 'reviewer'
  display_name  text NOT NULL,
  kind          text NOT NULL CHECK (kind IN ('human', 'agent', 'bot')),
  org           text NOT NULL CHECK (org IN ('work', 'vendor')),  -- internal actors only
  github_login  text UNIQUE,
  scope         zeusi.scope NOT NULL,
  source_kind   zeusi.source_kind NOT NULL,
  source_uri    text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts     timestamptz NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  ingested_by   text NOT NULL DEFAULT session_user
);

CREATE TABLE zeusi.facts (
  id            bigserial PRIMARY KEY,
  kind          text NOT NULL CHECK (kind IN ('rule', 'preference', 'state', 'config', 'identity', 'other')),
  subject       text,                          -- stable key, e.g. 'merge-gate.vorflux'
  text          text NOT NULL CHECK (length(text) BETWEEN 1 AND 4000),
  superseded_by bigint REFERENCES zeusi.facts(id),
  superseded_at timestamptz,
  scope         zeusi.scope NOT NULL,
  source_kind   zeusi.source_kind NOT NULL,
  source_uri    text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts     timestamptz NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  ingested_by   text NOT NULL DEFAULT session_user,
  CHECK ((superseded_by IS NULL) = (superseded_at IS NULL)),
  CHECK (superseded_by IS DISTINCT FROM id),
  UNIQUE (source_uri, source_sha256)
);

CREATE TABLE zeusi.decisions (
  id                   bigserial PRIMARY KEY,
  kind                 zeusi.decision_kind NOT NULL,
  who_id               bigint NOT NULL REFERENCES zeusi.people(id),
  said_at              timestamptz NOT NULL,
  said_at_precision    text NOT NULL CHECK (said_at_precision IN ('minute', 'day')),
  exact_words          text NOT NULL CHECK (length(exact_words) > 0),
  exact_words_verbatim boolean NOT NULL,       -- true only if the source quotes it
  applies_to           text[] NOT NULL DEFAULT '{}',  -- repos, lanes, products
  expires_at           timestamptz,
  expires_rule         text,                   -- e.g. 'after #1188 and #214 merge'
  linked_repo          text,
  linked_pr            int,
  linked_job           text,
  superseded_by        bigint REFERENCES zeusi.decisions(id),
  superseded_at        timestamptz,
  scope                zeusi.scope NOT NULL,
  source_kind          zeusi.source_kind NOT NULL,
  source_uri           text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts            timestamptz NOT NULL,
  source_sha256        bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id        bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at          timestamptz NOT NULL DEFAULT now(),
  ingested_by          text NOT NULL DEFAULT session_user,
  CHECK ((superseded_by IS NULL) = (superseded_at IS NULL)),
  CHECK (superseded_by IS DISTINCT FROM id),
  UNIQUE (source_uri, source_sha256)
);

CREATE TABLE zeusi.prs (
  repo          text NOT NULL,
  number        int NOT NULL CHECK (number > 0),
  title         text,
  author_login  text,
  base_ref      text,
  head_ref      text,
  head_sha      char(40) NOT NULL CHECK (head_sha ~ '^[0-9a-f]{40}$'),
  state         zeusi.pr_state NOT NULL,
  merged_to     text,
  merge_sha     char(40) CHECK (merge_sha ~ '^[0-9a-f]{40}$'),
  merged_at     timestamptz,
  gh_updated_at timestamptz NOT NULL,
  scope         zeusi.scope NOT NULL,
  source_kind   zeusi.source_kind NOT NULL,
  source_uri    text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts     timestamptz NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  ingested_by   text NOT NULL DEFAULT session_user,
  PRIMARY KEY (repo, number)
);

-- One row per review round and reviewed head.
CREATE TABLE zeusi.pr_reviews (
  id            bigserial PRIMARY KEY,
  repo          text NOT NULL,
  number        int NOT NULL,
  review_round  int NOT NULL CHECK (review_round >= 1),
  verdict       zeusi.verdict NOT NULL,
  verdict_head  char(40) NOT NULL CHECK (verdict_head ~ '^[0-9a-f]{40}$'),
  reviewer      text NOT NULL,                 -- 'opus', 'vorflux', 'human:<handle>'
  review_ref    text,                          -- path of the review file, never its body
  reviewed_at   timestamptz NOT NULL,
  scope         zeusi.scope NOT NULL,
  source_kind   zeusi.source_kind NOT NULL,
  source_uri    text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts     timestamptz NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  ingested_by   text NOT NULL DEFAULT session_user,
  FOREIGN KEY (repo, number) REFERENCES zeusi.prs (repo, number),
  UNIQUE (repo, number, review_round, reviewer, verdict_head)
);

CREATE TABLE zeusi.episodes (
  id            bigserial PRIMARY KEY,
  occurred_at   timestamptz NOT NULL,
  day           date NOT NULL,                 -- Europe/Zurich day, set by the writer
  actor         text NOT NULL,
  lane          text,
  kind          text NOT NULL CHECK (kind IN ('work', 'call', 'incident', 'handoff', 'note')),
  summary       text NOT NULL CHECK (length(summary) > 0),
  links         jsonb NOT NULL DEFAULT '[]',
  scope         zeusi.scope NOT NULL,
  source_kind   zeusi.source_kind NOT NULL,
  source_uri    text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts     timestamptz NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  ingested_by   text NOT NULL DEFAULT session_user,
  UNIQUE (source_uri, source_sha256)
);

CREATE TABLE zeusi.routine_runs (
  id            bigserial PRIMARY KEY,
  routine       text NOT NULL,                 -- e.g. ccr job name
  run_key       text UNIQUE NOT NULL,          -- '<host>:<name>:<start ts>'
  host          text NOT NULL CHECK (host IN ('mini', 'box', 'cloud', 'imac', 'macbook')),
  login_label   text CHECK (login_label IS NULL OR login_label !~ '@'),  -- label only, never an email
  lane          text,
  started_at    timestamptz NOT NULL,
  finished_at   timestamptz,
  exit_code     int,
  status        text NOT NULL CHECK (status IN ('running', 'ok', 'failed', 'unknown')),
  log_ref       text,                          -- path of the log, never its body
  scope         zeusi.scope NOT NULL,
  source_kind   zeusi.source_kind NOT NULL,
  source_uri    text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts     timestamptz NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  ingested_by   text NOT NULL DEFAULT session_user
);

-- Mirror of allowed KnowledgeVault notes (read-only mirror; the vault stays the source of truth).
CREATE TABLE zeusi.notes (
  id              bigserial PRIMARY KEY,
  vault_path      text UNIQUE NOT NULL,        -- relative to the vault root
  title           text NOT NULL,
  note_date       date,
  frontmatter     jsonb NOT NULL DEFAULT '{}',
  body            text NOT NULL,
  file_mtime      timestamptz NOT NULL,
  status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
  deleted_seen_at timestamptz,
  scope           zeusi.scope NOT NULL,
  source_kind     zeusi.source_kind NOT NULL,
  source_uri      text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts       timestamptz NOT NULL,
  source_sha256   bytea NOT NULL CHECK (octet_length(source_sha256) = 32),  -- sha256(body)
  ingest_run_id   bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at     timestamptz NOT NULL DEFAULT now(),
  ingested_by     text NOT NULL DEFAULT session_user
);

-- One searchable chunk per note section / fact / decision / episode.
-- Indexes (HNSW + full text) are created in 0002_search.sql.
CREATE TABLE zeusi.chunks (
  id            bigserial PRIMARY KEY,
  note_id       bigint REFERENCES zeusi.notes(id) ON DELETE CASCADE,
  fact_id       bigint REFERENCES zeusi.facts(id) ON DELETE CASCADE,
  decision_id   bigint REFERENCES zeusi.decisions(id) ON DELETE CASCADE,
  episode_id    bigint REFERENCES zeusi.episodes(id) ON DELETE CASCADE,
  CHECK (num_nonnulls(note_id, fact_id, decision_id, episode_id) = 1),
  chunk_index   int NOT NULL DEFAULT 0 CHECK (chunk_index >= 0),
  heading_path  text,
  text          text NOT NULL CHECK (length(text) > 0),
  text_sha256   bytea NOT NULL CHECK (octet_length(text_sha256) = 32),  -- trigger-computed
  token_count   int NOT NULL CHECK (token_count >= 0),
  embed_model   text,                          -- '<provider>/<model>@<dims>'
  embedding     halfvec(1536),
  embedded_at   timestamptz,
  CHECK ((embedding IS NULL) = (embed_model IS NULL)),
  tsv tsvector GENERATED ALWAYS AS
      (to_tsvector('simple'::regconfig, coalesce(heading_path, '') || ' ' || text)) STORED,
  -- provenance: scope, source_kind, source_ts, source_sha256, ingest_run_id are
  -- copied from the parent row by trigger when omitted; scope must equal the parent's.
  scope         zeusi.scope NOT NULL,
  source_kind   zeusi.source_kind NOT NULL,
  source_uri    text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts     timestamptz NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  ingested_by   text NOT NULL DEFAULT session_user
);

CREATE TABLE zeusi.backup_runs (
  id                bigserial PRIMARY KEY,
  host              text NOT NULL,
  kind              text NOT NULL CHECK (kind IN ('full', 'agent_tables', 'restore_test')),
  started_at        timestamptz NOT NULL,
  finished_at       timestamptz,
  status            text NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
  bytes             bigint,
  ciphertext_sha256 bytea,
  table_counts      jsonb
);

CREATE TABLE zeusi.embed_usage (
  month       date NOT NULL,
  embed_model text NOT NULL,
  host        text NOT NULL,
  tokens      bigint NOT NULL DEFAULT 0,
  est_usd     numeric(10, 4) NOT NULL DEFAULT 0,
  PRIMARY KEY (month, embed_model, host)
);

-- ---------------------------------------------------------------------------
-- Provenance stamping: ingested_at / ingested_by come from the server, not the writer.
CREATE FUNCTION zeusi.stamp_provenance() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
BEGIN
  -- On UPDATE, keep the original stamp unless the source content changed
  -- (a supersede call must not rewrite who ingested the old row).
  IF TG_OP = 'UPDATE' AND NEW.source_sha256 IS NOT DISTINCT FROM OLD.source_sha256 THEN
    NEW.ingested_at := OLD.ingested_at;
    NEW.ingested_by := OLD.ingested_by;
  ELSE
    NEW.ingested_at := now();
    NEW.ingested_by := session_user;
  END IF;
  RETURN NEW;
END $$;

-- Chunks inherit provenance from their single parent; a scope mismatch is refused.
CREATE FUNCTION zeusi.chunks_inherit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
DECLARE
  p_scope zeusi.scope; p_kind zeusi.source_kind; p_uri text;
  p_ts timestamptz; p_sha bytea; p_run bigint;
BEGIN
  IF NEW.note_id IS NOT NULL THEN
    SELECT scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id
      INTO p_scope, p_kind, p_uri, p_ts, p_sha, p_run FROM zeusi.notes WHERE id = NEW.note_id;
  ELSIF NEW.fact_id IS NOT NULL THEN
    SELECT scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id
      INTO p_scope, p_kind, p_uri, p_ts, p_sha, p_run FROM zeusi.facts WHERE id = NEW.fact_id;
  ELSIF NEW.decision_id IS NOT NULL THEN
    SELECT scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id
      INTO p_scope, p_kind, p_uri, p_ts, p_sha, p_run FROM zeusi.decisions WHERE id = NEW.decision_id;
  ELSIF NEW.episode_id IS NOT NULL THEN
    SELECT scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id
      INTO p_scope, p_kind, p_uri, p_ts, p_sha, p_run FROM zeusi.episodes WHERE id = NEW.episode_id;
  END IF;
  IF p_scope IS NULL THEN
    RETURN NEW;  -- no parent found: the FK / num_nonnulls checks reject the row
  END IF;
  IF NEW.scope IS NOT NULL AND NEW.scope <> p_scope THEN
    RAISE EXCEPTION 'zeusi: chunk scope % differs from parent scope %', NEW.scope, p_scope
      USING ERRCODE = 'check_violation';
  END IF;
  NEW.scope         := p_scope;
  NEW.source_kind   := coalesce(NEW.source_kind, p_kind);
  NEW.source_uri    := coalesce(NEW.source_uri, p_uri);
  NEW.source_ts     := coalesce(NEW.source_ts, p_ts);
  NEW.source_sha256 := coalesce(NEW.source_sha256, p_sha);
  NEW.ingest_run_id := coalesce(NEW.ingest_run_id, p_run);
  NEW.text_sha256   := sha256(convert_to(NEW.text, 'UTF8'));
  RETURN NEW;
END $$;

-- Triggers fire in name order: 10 provenance, 20 inherit, (90 wall in 0003).
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.people
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.facts
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.decisions
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.prs
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.pr_reviews
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.episodes
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.routine_runs
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.notes
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.chunks
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_20_inherit BEFORE INSERT OR UPDATE ON zeusi.chunks
  FOR EACH ROW EXECUTE FUNCTION zeusi.chunks_inherit();

-- ---------------------------------------------------------------------------
-- Supersession (R3): the only path that sets superseded_by. Agents have INSERT
-- and no UPDATE on facts/decisions; they call these SECURITY DEFINER functions.
CREATE FUNCTION zeusi.supersede_fact(old_id bigint, new_id bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
DECLARE o zeusi.facts; n zeusi.facts;
BEGIN
  IF old_id IS NULL OR new_id IS NULL OR old_id = new_id THEN
    RAISE EXCEPTION 'zeusi: supersede_fact needs two different ids' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO o FROM zeusi.facts WHERE id = old_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'zeusi: fact % not found', old_id USING ERRCODE = 'no_data_found'; END IF;
  SELECT * INTO n FROM zeusi.facts WHERE id = new_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'zeusi: fact % not found', new_id USING ERRCODE = 'no_data_found'; END IF;
  IF o.scope = 'personal' OR n.scope = 'personal' THEN
    RAISE EXCEPTION 'zeusi: personal scope is not writable in v1' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF o.superseded_by IS NOT NULL THEN
    RAISE EXCEPTION 'zeusi: fact % is already superseded by %', old_id, o.superseded_by USING ERRCODE = 'check_violation';
  END IF;
  IF n.superseded_by IS NOT NULL THEN
    RAISE EXCEPTION 'zeusi: replacement fact % is itself superseded', new_id USING ERRCODE = 'check_violation';
  END IF;
  IF o.subject IS NULL OR o.subject IS DISTINCT FROM n.subject THEN
    RAISE EXCEPTION 'zeusi: facts must share a non-null subject to supersede' USING ERRCODE = 'check_violation';
  END IF;
  IF o.scope <> n.scope THEN
    RAISE EXCEPTION 'zeusi: facts must share scope to supersede' USING ERRCODE = 'check_violation';
  END IF;
  IF n.source_ts <= o.source_ts THEN
    RAISE EXCEPTION 'zeusi: replacement fact must have a later source_ts' USING ERRCODE = 'check_violation';
  END IF;
  UPDATE zeusi.facts SET superseded_by = new_id, superseded_at = now() WHERE id = old_id;
END $$;

CREATE FUNCTION zeusi.supersede_decision(old_id bigint, new_id bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
DECLARE o zeusi.decisions; n zeusi.decisions;
BEGIN
  IF old_id IS NULL OR new_id IS NULL OR old_id = new_id THEN
    RAISE EXCEPTION 'zeusi: supersede_decision needs two different ids' USING ERRCODE = 'check_violation';
  END IF;
  SELECT * INTO o FROM zeusi.decisions WHERE id = old_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'zeusi: decision % not found', old_id USING ERRCODE = 'no_data_found'; END IF;
  SELECT * INTO n FROM zeusi.decisions WHERE id = new_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'zeusi: decision % not found', new_id USING ERRCODE = 'no_data_found'; END IF;
  IF o.scope = 'personal' OR n.scope = 'personal' THEN
    RAISE EXCEPTION 'zeusi: personal scope is not writable in v1' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF o.superseded_by IS NOT NULL THEN
    RAISE EXCEPTION 'zeusi: decision % is already superseded by %', old_id, o.superseded_by USING ERRCODE = 'check_violation';
  END IF;
  IF n.superseded_by IS NOT NULL THEN
    RAISE EXCEPTION 'zeusi: replacement decision % is itself superseded', new_id USING ERRCODE = 'check_violation';
  END IF;
  IF NOT (o.applies_to && n.applies_to) THEN
    RAISE EXCEPTION 'zeusi: decisions must overlap in applies_to to supersede' USING ERRCODE = 'check_violation';
  END IF;
  IF n.source_ts <= o.source_ts THEN
    RAISE EXCEPTION 'zeusi: replacement decision must have a later source_ts' USING ERRCODE = 'check_violation';
  END IF;
  UPDATE zeusi.decisions SET superseded_by = new_id, superseded_at = now() WHERE id = old_id;
END $$;

-- ---------------------------------------------------------------------------
-- Views. security_invoker so RLS of the reading role applies (PG15+).
CREATE VIEW zeusi.facts_current WITH (security_invoker = true) AS
  SELECT f.*, f.source_ts AS learned_at
  FROM zeusi.facts f
  WHERE f.superseded_by IS NULL;

CREATE VIEW zeusi.decisions_current WITH (security_invoker = true) AS
  SELECT d.*
  FROM zeusi.decisions d
  WHERE d.superseded_by IS NULL
    AND (d.expires_at IS NULL OR d.expires_at > now());

-- PR status with the latest review. verdict_is_stale flags a verdict given on a
-- head that is no longer the PR head (force-push / new commits after review).
CREATE VIEW zeusi.pr_status WITH (security_invoker = true) AS
  SELECT p.repo, p.number, p.title, p.state, p.base_ref, p.head_ref, p.head_sha,
         p.merged_to, p.merge_sha, p.merged_at, p.gh_updated_at,
         r.review_round AS last_round,
         r.verdict      AS last_verdict,
         r.verdict_head AS last_verdict_head,
         r.reviewer     AS last_reviewer,
         r.reviewed_at  AS last_reviewed_at,
         r.review_ref   AS last_review_ref,
         (r.id IS NOT NULL)                                       AS has_verdict,
         coalesce(r.verdict_head = p.head_sha, false)             AS verdict_is_current,
         (r.id IS NOT NULL AND r.verdict_head <> p.head_sha)      AS verdict_is_stale,
         (r.verdict = 'SAFE' AND r.verdict_head <> p.head_sha)    AS safe_on_stale_head,
         p.scope, p.source_uri, p.source_ts
  FROM zeusi.prs p
  LEFT JOIN LATERAL (
    SELECT rv.*
    FROM zeusi.pr_reviews rv
    WHERE rv.repo = p.repo AND rv.number = p.number
    ORDER BY rv.reviewed_at DESC, rv.review_round DESC, rv.id DESC
    LIMIT 1
  ) r ON true;
