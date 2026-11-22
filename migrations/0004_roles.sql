-- 0004_roles.sql — least-privilege group and login roles (PLAN.md KTD9, KTD10, U3).
--
-- Created with SQL, never in the Neon Console (console roles get neon_superuser).
-- NO PASSWORDS here. Login roles are created without a password and cannot log
-- in until the owner sets one out-of-band (see docs/roles.md) and stores it in
-- 1Password, one item per login role.
-- Idempotent: safe to re-run on a branch that already has the roles.

DO $$
DECLARE
  g text;
  l record;
BEGIN
  FOREACH g IN ARRAY ARRAY['zeusi_read', 'zeusi_agent_write', 'zeusi_ingest', 'zeusi_backup'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = g) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', g);
    END IF;
  END LOOP;

  FOR l IN SELECT * FROM (VALUES
      ('zeusi_mini_ingest', 'zeusi_ingest',      4),
      ('zeusi_mini_backup', 'zeusi_backup',      2),
      ('zeusi_box_rw',      'zeusi_agent_write', 5),
      ('zeusi_box_ro',      'zeusi_read',        5),
      ('zeusi_cloud_ro',    'zeusi_read',        5)
    ) AS v(login, grp, conn_limit)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = l.login) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %s',
                     l.login, l.conn_limit);
    ELSE
      EXECUTE format('ALTER ROLE %I CONNECTION LIMIT %s', l.login, l.conn_limit);
    END IF;
    IF NOT pg_has_role(l.login, l.grp, 'MEMBER') THEN
      EXECUTE format('GRANT %I TO %I', l.grp, l.login);
    END IF;
  END LOOP;

  -- writer groups read through zeusi_read (and inherit its RLS read policy)
  IF NOT pg_has_role('zeusi_agent_write', 'zeusi_read', 'MEMBER') THEN
    GRANT zeusi_read TO zeusi_agent_write;
  END IF;
  IF NOT pg_has_role('zeusi_ingest', 'zeusi_read', 'MEMBER') THEN
    GRANT zeusi_read TO zeusi_ingest;
  END IF;
END $$;

-- Per-role session defaults (KTD10).
ALTER ROLE zeusi_mini_ingest SET statement_timeout = '120s';
ALTER ROLE zeusi_mini_backup SET statement_timeout = '0';
ALTER ROLE zeusi_box_rw      SET statement_timeout = '30s';
ALTER ROLE zeusi_box_ro      SET statement_timeout = '30s';
ALTER ROLE zeusi_cloud_ro    SET statement_timeout = '15s';
ALTER ROLE zeusi_box_ro      SET default_transaction_read_only = on;
ALTER ROLE zeusi_cloud_ro    SET default_transaction_read_only = on;
ALTER ROLE zeusi_mini_backup SET default_transaction_read_only = off;  -- needs INSERT on backup_runs only
ALTER ROLE zeusi_mini_ingest SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_mini_backup SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_box_rw      SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_box_ro      SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_cloud_ro    SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_mini_ingest SET search_path = zeusi, public;
ALTER ROLE zeusi_mini_backup SET search_path = zeusi, public;
ALTER ROLE zeusi_box_rw      SET search_path = zeusi, public;
ALTER ROLE zeusi_box_ro      SET search_path = zeusi, public;
ALTER ROLE zeusi_cloud_ro    SET search_path = zeusi, public;

-- ---------------------------------------------------------------------------
-- Grants. Start from nothing.
REVOKE ALL ON SCHEMA zeusi FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA zeusi FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA zeusi FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA zeusi FROM PUBLIC;

GRANT USAGE ON SCHEMA zeusi TO zeusi_read, zeusi_backup;

-- Readers: content tables and views. NOT wall_denylist, wall_allow, quarantine.
GRANT SELECT ON
  zeusi.people, zeusi.facts, zeusi.decisions, zeusi.prs, zeusi.pr_reviews,
  zeusi.episodes, zeusi.routine_runs, zeusi.notes, zeusi.chunks,
  zeusi.facts_current, zeusi.decisions_current, zeusi.pr_status,
  zeusi.ingest_runs, zeusi.backup_runs, zeusi.embed_usage
TO zeusi_read;

-- Agents (box): INSERT only on agent-written tables. No UPDATE/DELETE of text.
GRANT INSERT ON zeusi.facts, zeusi.episodes, zeusi.decisions, zeusi.routine_runs,
                zeusi.chunks, zeusi.ingest_runs
TO zeusi_agent_write;
GRANT UPDATE (finished_at, status, counts) ON zeusi.ingest_runs TO zeusi_agent_write;
GRANT USAGE ON SEQUENCE zeusi.facts_id_seq, zeusi.episodes_id_seq, zeusi.decisions_id_seq,
                        zeusi.routine_runs_id_seq, zeusi.chunks_id_seq, zeusi.ingest_runs_id_seq
TO zeusi_agent_write;
GRANT EXECUTE ON FUNCTION zeusi.supersede_fact(bigint, bigint),
                          zeusi.supersede_decision(bigint, bigint)
TO zeusi_agent_write;

-- Ingest (Mini): upsert mirrors; insert-only for facts/decisions/episodes/reviews;
-- delete only chunks (re-chunking a changed note). Never wall writes.
GRANT INSERT, UPDATE ON zeusi.notes, zeusi.prs, zeusi.routine_runs, zeusi.people,
                        zeusi.chunks, zeusi.ingest_runs, zeusi.embed_usage
TO zeusi_ingest;
GRANT INSERT ON zeusi.facts, zeusi.decisions, zeusi.episodes, zeusi.pr_reviews TO zeusi_ingest;
GRANT DELETE ON zeusi.chunks TO zeusi_ingest;
GRANT SELECT ON zeusi.wall_denylist, zeusi.wall_allow, zeusi.quarantine TO zeusi_ingest;  -- importer pre-checks
GRANT USAGE ON ALL SEQUENCES IN SCHEMA zeusi TO zeusi_ingest;
GRANT EXECUTE ON FUNCTION zeusi.wall_content(text, jsonb), zeusi.wall_content_sha256(text, jsonb),
                          zeusi.uri_path(text), zeusi.norm_repo(text), zeusi.glob_to_regex(text, boolean)
TO zeusi_ingest;

-- Both writer groups can record a wall rejection (uri + hash only).
GRANT EXECUTE ON FUNCTION zeusi.quarantine_record(zeusi.source_kind, text, bytea, int, bigint, text, bytea)
TO zeusi_agent_write, zeusi_ingest;

-- Backup: read everything for pg_dump, record its own runs.
GRANT SELECT ON ALL TABLES IN SCHEMA zeusi TO zeusi_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA zeusi TO zeusi_backup;
GRANT INSERT ON zeusi.backup_runs TO zeusi_backup;
GRANT USAGE ON SEQUENCE zeusi.backup_runs_id_seq TO zeusi_backup;
