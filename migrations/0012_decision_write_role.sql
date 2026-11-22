-- 0012_decision_write_role.sql — a narrow write login for zeusi_log_decision (MCP, docs/mcp.md).
--
-- STATUS: DESIGN, NOT APPLIED. Apply with a dry run first
-- (`npm run migrate -- --dry-run`) and a database snapshot.
-- Note: `zeusi migrate` applies EVERY pending file in order. While 0010 / 0011 are pending,
-- a plain run would apply them too. Applying 0012 on its own is a separate operator decision
-- (docs/roles.md).
--
-- Group zeusi_decision_write / login zeusi_box_decision. Narrower than zeusi_agent_write
-- (zeusi_box_rw): it may INSERT decisions and its own ingest runs, close those runs, supersede
-- a decision and record a wall rejection. Nothing else: no facts, episodes, chunks,
-- routine_runs, notes, people or PR writes, no UPDATE / DELETE of any text, no wall tables,
-- never 'personal' (RLS below + the zeusi_read read policy it inherits).
--
-- Depends only on 0001-0005 (tables, functions, zeusi_read, RLS on decisions). It does not
-- need 0010 or 0011: whatever read policy zeusi_read has, this role inherits it.
--
-- Created with SQL, never in the Neon Console (console roles get neon_superuser).
-- NO PASSWORD here. The login is created without one and cannot log in until the owner sets one
-- out of band: `\password zeusi_box_decision` as the owner over the direct URL, stored in
-- a password manager (one item for this login) and, on the machine that writes, in `~/.pgpass`
-- or the Keychain generic password service `zeusi-neon-zeusi_box_decision`, account
-- `zeusi_box_decision`. Pooled endpoint,
-- like the other box roles (docs/neon.md, `[zeusi_decision]` in config/pg_service.example.conf).
-- No env-password exception: only zeusi_box_ro has one (docs/roles.md).
-- Idempotent: safe to re-run on a branch that already has the roles.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_decision_write') THEN
    CREATE ROLE zeusi_decision_write NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_box_decision') THEN
    CREATE ROLE zeusi_box_decision LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5;
  ELSE
    ALTER ROLE zeusi_box_decision CONNECTION LIMIT 5;
  END IF;
  IF NOT pg_has_role('zeusi_box_decision', 'zeusi_decision_write', 'MEMBER') THEN
    GRANT zeusi_decision_write TO zeusi_box_decision;
  END IF;
  -- reads (people handle lookup, RETURNING) through zeusi_read and its RLS read policy
  IF NOT pg_has_role('zeusi_decision_write', 'zeusi_read', 'MEMBER') THEN
    GRANT zeusi_read TO zeusi_decision_write;
  END IF;
END $$;

-- Session defaults, as zeusi_box_rw (0004). Not default_transaction_read_only: it writes.
ALTER ROLE zeusi_box_decision SET statement_timeout = '30s';
ALTER ROLE zeusi_box_decision SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_box_decision SET search_path = zeusi, public;

-- Grants: only these. 0004 revoked everything from PUBLIC; nothing here is granted to PUBLIC.
GRANT INSERT ON zeusi.decisions, zeusi.ingest_runs TO zeusi_decision_write;
GRANT UPDATE (finished_at, status, counts) ON zeusi.ingest_runs TO zeusi_decision_write;
GRANT USAGE ON SEQUENCE zeusi.decisions_id_seq, zeusi.ingest_runs_id_seq TO zeusi_decision_write;
GRANT EXECUTE ON FUNCTION zeusi.supersede_decision(bigint, bigint) TO zeusi_decision_write;
GRANT EXECUTE ON FUNCTION zeusi.quarantine_record(zeusi.source_kind, text, bytea, int, bigint, text, bytea)
TO zeusi_decision_write;

-- RLS: decisions has row security on (0005). The INSERT policy write_not_personal names
-- zeusi_agent_write and zeusi_ingest only, so this group gets its own, with the same check.
DROP POLICY IF EXISTS decision_write_not_personal ON zeusi.decisions;
CREATE POLICY decision_write_not_personal ON zeusi.decisions FOR INSERT TO zeusi_decision_write
  WITH CHECK (scope <> 'personal');
