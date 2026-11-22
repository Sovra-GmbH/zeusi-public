-- 0013_decision_links.sql — typed links from a decision to the PRs, notes, repos and jobs it
-- covers (lanes DIG-startup-links.md D2 step 2; docs/plans/2026-11-17-zeusi-v2-prime-onboard.md,
-- addendum "0013 decision links").
--
-- STATUS: DESIGN, NOT APPLIED. Apply with a dry run first
-- (`npm run migrate -- --dry-run`), on a scratch branch before main, with a snapshot.
-- Rollback: migrations/ROLLBACK-0013.md.
--
-- ADDITIVE ONLY. One new enum, one new insert-only table, its triggers, RLS policies and grants,
-- two new trigger functions and one new audit function (decision_links_wall_audit). No existing
-- table, row, function, policy or grant is changed: wall_eval(), wall_check(), wall_content() and
-- wall_audit() are NOT replaced; the new functions call wall_eval() as it is.
--
-- Why a table and not columns: a decision can cover many PRs and notes; links are added later
-- without UPDATE or supersede, and each link carries its own provenance (who linked it, from
-- what source). applies_to is NOT used for this: it drives supersede overlap and conflicts.
--
-- Target uri allowlist (strict, per kind; no control characters, no whitespace except a plain
-- space inside a note path, no `.` / `..` path segment, 5..500 chars):
--   pr    gh:<owner>/<repo>#<n>
--   repo  gh:<owner>/<repo>
--   note  vault:<path> | hq:<path> | import:<path>
--   job   job:<name>
--   uri   lane:<name>
-- src/decision-links.ts (LINK_TARGET_RES) mirrors this CHECK; test/decision-links.test.ts pins both.
--
-- Grants: SELECT to zeusi_read (readers, and through membership every writer group) and
-- zeusi_backup. INSERT only to zeusi_ingest and zeusi_decision_write (0012). NO UPDATE / DELETE /
-- TRUNCATE for anyone but the owner. zeusi_agent_write (the transitional zeusi_box_rw) gets no
-- INSERT here: zeusi_log_decision refuses links on that login.
--
-- 0013-a (GRANT EXECUTE ON supersede_fact TO zeusi_ingest) is NOT part of this file: a separate
-- migration if focus retirement is ever wanted.
--
-- Depends on 0001-0005 and 0012 (role zeusi_decision_write). Not on 0010 / 0011: the read policy
-- compares scope::text (as 0010 does), so 'client' is only a text literal here.

CREATE TYPE zeusi.link_target_kind AS ENUM ('pr', 'note', 'repo', 'job', 'uri');

CREATE TABLE zeusi.decision_links (
  id            bigserial PRIMARY KEY,
  decision_id   bigint NOT NULL REFERENCES zeusi.decisions(id),
  target_kind   zeusi.link_target_kind NOT NULL,
  target_uri    text NOT NULL,
  -- provenance block P (0001): where and when the LINK was stated
  scope         zeusi.scope NOT NULL,
  source_kind   zeusi.source_kind NOT NULL,
  source_uri    text NOT NULL CHECK (btrim(source_uri) <> ''),
  source_ts     timestamptz NOT NULL,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  ingest_run_id bigint NOT NULL REFERENCES zeusi.ingest_runs(id),
  ingested_at   timestamptz NOT NULL DEFAULT now(),
  ingested_by   text NOT NULL DEFAULT session_user,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT decision_links_target_uri_shape CHECK (
    length(target_uri) BETWEEN 5 AND 500
    AND replace(target_uri, ' ', '') !~ '[[:space:][:cntrl:]]'
    AND target_uri !~ '(^[a-z]+:|/)\.\.?(/|#|$)'
    AND CASE target_kind
      WHEN 'pr'   THEN target_uri ~ '^gh:[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}#[1-9][0-9]{0,8}$'
      WHEN 'repo' THEN target_uri ~ '^gh:[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$'
      WHEN 'note' THEN target_uri ~ '^(vault|hq|import):[^#/ ][^#]*[^# ](#[^#]*[^# ])?$'
      WHEN 'job'  THEN target_uri ~ '^job:[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$'
      WHEN 'uri'  THEN target_uri ~ '^lane:[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$'
      ELSE false END
  ),
  UNIQUE (decision_id, target_uri)
);

CREATE INDEX decision_links_target_uri_idx ON zeusi.decision_links (target_uri);

-- ---------------------------------------------------------------------------
-- A link's scope must equal its decision's scope (like chunks_inherit, 0001). Scope is never
-- copied silently: a missing or different scope is refused. No other column is filled in.
CREATE FUNCTION zeusi.decision_links_inherit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
DECLARE p_scope zeusi.scope;
BEGIN
  SELECT scope INTO p_scope FROM zeusi.decisions WHERE id = NEW.decision_id;
  IF p_scope IS NULL THEN
    RETURN NEW;  -- no parent: the FK rejects the row
  END IF;
  IF NEW.scope IS DISTINCT FROM p_scope THEN
    RAISE EXCEPTION 'zeusi: decision link scope differs from its decision''s scope'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

-- The wall for a link: wall_eval() (0009, unchanged) over a decision-shaped probe. Probe 1 puts
-- the target uri in the uri slot (so hard path / lane / repo rules see the target's path, lane
-- or gh repo) and in the words slot (hard and soft content rules). Probe 2 does the same under
-- the link's own source_uri. Same SQLSTATE ZW001 and DETAIL shape as wall_check(), so writers
-- quarantine it by uri and hash only. A soft hit can be pinned by wall_allow on
-- (target_uri or source_uri, sha256(target_uri), rule_id), like any other row.
CREATE FUNCTION zeusi.decision_link_wall_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
DECLARE
  v record;
  probe jsonb;
BEGIN
  IF TG_TABLE_NAME <> 'decision_links' THEN
    RAISE EXCEPTION 'zeusi wall: decision_link_wall_check attached to unknown table %', TG_TABLE_NAME;
  END IF;
  FOREACH probe IN ARRAY ARRAY[
    jsonb_build_object('source_uri', NEW.target_uri, 'exact_words', NEW.target_uri),
    jsonb_build_object('source_uri', NEW.source_uri, 'exact_words', NEW.target_uri)
  ] LOOP
    SELECT * INTO v FROM zeusi.wall_eval('decisions', probe);
    IF v.rule_id IS NOT NULL THEN
      RAISE EXCEPTION 'zeusi wall: % row rejected by % rule % (%)', TG_TABLE_NAME,
            CASE WHEN v.hard THEN 'hard' ELSE 'content' END, v.rule_id, v.kind
        USING ERRCODE = 'ZW001',
              DETAIL = format('rule_id=%s;hard=%s;source_uri=%s;content_sha256=%s',
                              v.rule_id, v.hard, NEW.source_uri, encode(v.content_sha256, 'hex')),
              HINT = 'Record in zeusi.quarantine by uri and hash only. Never log the text.';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;

-- Triggers fire in name order: 10 provenance, 20 inherit, 90 wall (as on every content table).
CREATE TRIGGER zeusi_10_provenance BEFORE INSERT OR UPDATE ON zeusi.decision_links
  FOR EACH ROW EXECUTE FUNCTION zeusi.stamp_provenance();
CREATE TRIGGER zeusi_20_inherit BEFORE INSERT OR UPDATE ON zeusi.decision_links
  FOR EACH ROW EXECUTE FUNCTION zeusi.decision_links_inherit();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.decision_links
  FOR EACH ROW EXECUTE FUNCTION zeusi.decision_link_wall_check();

REVOKE ALL ON FUNCTION zeusi.decision_links_inherit() FROM PUBLIC;
REVOKE ALL ON FUNCTION zeusi.decision_link_wall_check() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Audit (security review M2): wall_audit() is NOT replaced, so links get their own audit with the
-- same columns and the same rules: every stored link re-checked with wall_eval() on both probes
-- (a rule added after the link was stored), plus a quarantined (uri, sha) found in a link (unless
-- the owner pinned a wall_allow for exactly that quarantined content). Must return zero rows. No text:
-- table, link id, source_uri (masked for personal rows unless the caller is the owner, as 0008),
-- problem. src/wall-admin.ts wallAudit() appends it to wall_audit() when it exists.
CREATE FUNCTION zeusi.decision_links_wall_audit()
RETURNS TABLE (table_name text, row_ref text, source_uri text, problem text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
  WITH owner_call AS (SELECT pg_has_role(session_user, current_user, 'MEMBER') AS ok),
  hits AS (
    SELECT l.id, l.scope, l.source_uri, x.problem
    FROM zeusi.decision_links l
    CROSS JOIN LATERAL (
      SELECT CASE WHEN v.hard THEN 'hard' ELSE 'content' END || ' rule ' || v.rule_id || ' (' || v.kind || ')' AS problem
      FROM unnest(ARRAY[jsonb_build_object('source_uri', l.target_uri, 'exact_words', l.target_uri),
                        jsonb_build_object('source_uri', l.source_uri, 'exact_words', l.target_uri)]) WITH ORDINALITY AS p(probe, n)
      CROSS JOIN LATERAL zeusi.wall_eval('decisions', p.probe) AS v
      WHERE v.rule_id IS NOT NULL
      ORDER BY p.n LIMIT 1) x
    UNION ALL
    SELECT l.id, l.scope, l.source_uri, 'quarantined (uri, sha) present in content'
    FROM zeusi.decision_links l
    JOIN zeusi.quarantine q ON q.source_uri = l.source_uri AND q.source_sha256 = l.source_sha256
    WHERE NOT EXISTS (
      SELECT 1 FROM zeusi.wall_allow a JOIN zeusi.wall_denylist d ON d.id = a.rule_id
      WHERE NOT d.hard AND a.source_uri = q.source_uri
        AND a.content_sha256 = q.content_sha256 AND a.rule_id = q.rule_id)
  )
  SELECT 'decision_links'::text, h.id::text,
         CASE WHEN h.scope = 'personal' AND NOT o.ok THEN 'personal:<masked>' ELSE h.source_uri END,
         h.problem
  FROM hits h CROSS JOIN owner_call o
$$;

REVOKE ALL ON FUNCTION zeusi.decision_links_wall_audit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zeusi.decision_links_wall_audit() TO zeusi_ingest, zeusi_backup;

-- ---------------------------------------------------------------------------
-- RLS, as decisions (0005 + 0010 + 0012). The owner bypasses RLS (no FORCE).
ALTER TABLE zeusi.decision_links ENABLE ROW LEVEL SECURITY;

CREATE POLICY read_allowed_scopes ON zeusi.decision_links FOR SELECT TO zeusi_read
  USING (scope::text IN ('work', 'product', 'client'));
CREATE POLICY backup_read_all ON zeusi.decision_links FOR SELECT TO zeusi_backup
  USING (true);
CREATE POLICY links_insert_not_personal ON zeusi.decision_links FOR INSERT TO zeusi_ingest, zeusi_decision_write
  WITH CHECK (scope <> 'personal');

-- ---------------------------------------------------------------------------
-- Grants: only these. Nothing to PUBLIC. No UPDATE / DELETE / TRUNCATE for any role.
REVOKE ALL ON zeusi.decision_links FROM PUBLIC;
REVOKE ALL ON SEQUENCE zeusi.decision_links_id_seq FROM PUBLIC;
GRANT SELECT ON zeusi.decision_links TO zeusi_read, zeusi_backup;
GRANT SELECT ON SEQUENCE zeusi.decision_links_id_seq TO zeusi_backup;
GRANT INSERT ON zeusi.decision_links TO zeusi_ingest, zeusi_decision_write;
GRANT USAGE ON SEQUENCE zeusi.decision_links_id_seq TO zeusi_ingest, zeusi_decision_write;
