-- 0003_wall.sql — Chinese wall in the database (PLAN.md KTD7, R8–R10, U4).
--
-- Layer 1 (type): zeusi.scope has no ClientCo or Plankiva value (0001).
-- Layer 2 (row):  zeusi.wall_check(), owned by the schema owner, runs
--                 BEFORE INSERT OR UPDATE on every content table.
--                 * hard rules (path_glob, lane, repo, and any rule marked hard)
--                   can never be overridden;
--                 * content rules (regex, term with hard = false) can be
--                   overridden only by a wall_allow row pinned to the exact
--                   sha256 of the row's checked content for that source_uri.
-- Layer 3 (grant): only the owner writes wall tables (0004); RLS on readers (0005).
--
-- Blocked items are recorded in zeusi.quarantine by uri and hash only. The
-- trigger error message carries the table, rule id, and hashes — never content.
-- Seeds below are path/lane/repo NAMES and generic patterns from PLAN.md, not
-- file contents. The client/counterparty term list is left empty for the operator.

CREATE TYPE zeusi.wall_rule_kind AS ENUM ('path_glob', 'lane', 'repo', 'regex', 'term');

CREATE TABLE zeusi.wall_denylist (
  id       serial PRIMARY KEY,
  kind     zeusi.wall_rule_kind NOT NULL,
  hard     boolean NOT NULL,
  pattern  text NOT NULL CHECK (pattern <> ''),
  reason   text NOT NULL,
  added_by text NOT NULL DEFAULT session_user,
  added_at timestamptz NOT NULL DEFAULT now(),
  CHECK (kind IN ('regex', 'term') OR hard),     -- path, lane and repo rules are always hard
  UNIQUE (kind, pattern)
);

-- the owner-reviewed exceptions, content rules only, pinned to an exact content hash.
CREATE TABLE zeusi.wall_allow (
  source_uri     text NOT NULL,
  content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
  rule_id        int NOT NULL REFERENCES zeusi.wall_denylist(id) ON DELETE CASCADE,
  approved_by    text NOT NULL DEFAULT session_user,
  approved_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_uri, content_sha256, rule_id)
);

-- Holds NO content: uri and hashes only.
CREATE TABLE zeusi.quarantine (
  id             bigserial PRIMARY KEY,
  source_kind    zeusi.source_kind NOT NULL,
  source_uri     text NOT NULL,
  source_sha256  bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  content_sha256 bytea CHECK (content_sha256 IS NULL OR octet_length(content_sha256) = 32),
  target_table   text,
  rule_id        int REFERENCES zeusi.wall_denylist(id) ON DELETE SET NULL,
  ingest_run_id  bigint REFERENCES zeusi.ingest_runs(id),
  detected_at    timestamptz NOT NULL DEFAULT now(),
  detected_by    text NOT NULL DEFAULT session_user,
  UNIQUE (source_uri, source_sha256)
);

-- ---------------------------------------------------------------------------
-- Helpers

-- Glob -> anchored ARE. '**/' = any dirs (incl. none), '**' = anything,
-- '*' = within one segment (or anything when star_crosses_slash), '?' = one char.
CREATE FUNCTION zeusi.glob_to_regex(glob text, star_crosses_slash boolean DEFAULT false)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
DECLARE
  i int := 1; n int := length(glob); c text; out text := '^';
BEGIN
  WHILE i <= n LOOP
    c := substr(glob, i, 1);
    IF c = '*' AND substr(glob, i + 1, 1) = '*' THEN
      IF substr(glob, i + 2, 1) = '/' THEN
        out := out || '(.*/)?'; i := i + 3;
      ELSE
        out := out || '.*'; i := i + 2;
      END IF;
      CONTINUE;
    ELSIF c = '*' THEN
      out := out || CASE WHEN star_crosses_slash THEN '.*' ELSE '[^/]*' END;
    ELSIF c = '?' THEN
      out := out || '[^/]';
    ELSIF position(c IN '.^$+()[]{}|\') > 0 THEN
      out := out || '\' || c;
    ELSE
      out := out || c;
    END IF;
    i := i + 1;
  END LOOP;
  RETURN out || '$';
END $$;

-- 'vault:Work/x.md#Heading' -> 'Work/x.md'; 'gh:Org/repo#12' -> 'Org/repo'.
CREATE FUNCTION zeusi.uri_path(uri text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
  SELECT regexp_replace(
           regexp_replace(
             regexp_replace(uri, '#.*$', ''),       -- fragment
           '^[a-z][a-z0-9+.-]*:', ''),              -- scheme
         '^(\./|/)+', '')                           -- leading ./ or /
$$;

-- Repo names without an owner are example-org repos.
CREATE FUNCTION zeusi.norm_repo(repo text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
  SELECT CASE WHEN position('/' IN btrim(repo)) > 0 THEN btrim(repo) ELSE 'example-org/' || btrim(repo) END
$$;

-- The exact text the content rules see for a row, per table. Importers hash the
-- same string (zeusi.wall_content_sha256) to pre-check and to request a wall_allow.
CREATE FUNCTION zeusi.wall_content(tbl text, r jsonb)
RETURNS text LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
  SELECT concat_ws(E'\n', VARIADIC CASE tbl
    WHEN 'facts'        THEN ARRAY[r->>'subject', r->>'text']
    WHEN 'decisions'    THEN ARRAY[r->>'exact_words', r->>'expires_rule', r->>'linked_job']
    WHEN 'episodes'     THEN ARRAY[r->>'actor', r->>'summary', r->>'links']
    WHEN 'notes'        THEN ARRAY[r->>'title', r->>'body', r->>'frontmatter']
    WHEN 'chunks'       THEN ARRAY[r->>'heading_path', r->>'text']
    WHEN 'prs'          THEN ARRAY[r->>'title', r->>'author_login', r->>'head_ref', r->>'base_ref']
    WHEN 'pr_reviews'   THEN ARRAY[r->>'reviewer', r->>'review_ref']
    WHEN 'routine_runs' THEN ARRAY[r->>'routine', r->>'login_label', r->>'log_ref']
    WHEN 'people'       THEN ARRAY[r->>'handle', r->>'display_name', r->>'github_login']
    ELSE ARRAY[]::text[] END)
$$;

CREATE FUNCTION zeusi.wall_content_sha256(tbl text, r jsonb)
RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, zeusi AS $$
  SELECT sha256(convert_to(coalesce(zeusi.wall_content(tbl, r), ''), 'UTF8'))
$$;

-- ---------------------------------------------------------------------------
-- The row-layer trigger.
CREATE FUNCTION zeusi.wall_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
DECLARE
  r        jsonb := to_jsonb(NEW);
  paths    text[];
  lanes    text[];
  repos    text[];
  content  text;
  csha     bytea;
  rule     record;
  hit      text;
BEGIN
  IF TG_TABLE_NAME NOT IN ('facts', 'decisions', 'episodes', 'notes', 'chunks',
                           'prs', 'pr_reviews', 'routine_runs', 'people') THEN
    RAISE EXCEPTION 'zeusi wall: wall_check attached to unknown table %', TG_TABLE_NAME;
  END IF;

  -- Path candidates: the source uri plus path-like columns.
  paths := array_remove(ARRAY[
    zeusi.uri_path(r->>'source_uri'),
    r->>'vault_path', r->>'review_ref', r->>'log_ref'
  ], NULL);

  -- Lane candidates: lane column, applies_to items, lane:<x> or .../lanes/<x>/ in the uri.
  lanes := array_remove(ARRAY[
    r->>'lane',
    substring(r->>'source_uri' FROM '^lane:([^/#]+)'),
    substring(r->>'source_uri' FROM 'lanes/([^/#]+)')
  ], NULL);
  -- Repo candidates: repo / linked_repo columns, applies_to items, gh:<repo> uri.
  repos := array_remove(ARRAY[
    r->>'repo', r->>'linked_repo',
    CASE WHEN r->>'source_uri' LIKE 'gh:%' THEN zeusi.uri_path(r->>'source_uri') END
  ], NULL);
  IF jsonb_typeof(r->'applies_to') = 'array' THEN   -- decisions only
    lanes := lanes || ARRAY(SELECT jsonb_array_elements_text(r->'applies_to'));
    repos := repos || ARRAY(SELECT jsonb_array_elements_text(r->'applies_to'));
  END IF;
  repos := ARRAY(SELECT zeusi.norm_repo(x) FROM unnest(repos) AS x WHERE btrim(x) <> '');

  -- Hard rules first. These ignore wall_allow entirely.
  FOR rule IN
    SELECT id, kind, pattern FROM zeusi.wall_denylist
    WHERE kind IN ('path_glob', 'lane', 'repo') ORDER BY id
  LOOP
    SELECT x INTO hit FROM unnest(CASE rule.kind
        WHEN 'path_glob' THEN paths WHEN 'lane' THEN lanes ELSE repos END) AS x
      WHERE x ~* zeusi.glob_to_regex(rule.pattern, rule.kind = 'repo')
      LIMIT 1;
    IF FOUND THEN
      RAISE EXCEPTION 'zeusi wall: % row rejected by hard rule % (%)', TG_TABLE_NAME, rule.id, rule.kind
        USING ERRCODE = 'ZW001',
              DETAIL = format('rule_id=%s;hard=true;source_uri=%s', rule.id, r->>'source_uri'),
              HINT = 'Record in zeusi.quarantine by uri and hash only. Hard rules cannot be overridden.';
    END IF;
  END LOOP;

  -- Content rules.
  content := coalesce(zeusi.wall_content(TG_TABLE_NAME, r), '');
  csha := sha256(convert_to(content, 'UTF8'));
  FOR rule IN
    SELECT id, kind, hard, pattern FROM zeusi.wall_denylist
    WHERE kind IN ('regex', 'term') ORDER BY id
  LOOP
    IF (rule.kind = 'regex' AND content ~* rule.pattern)
       OR (rule.kind = 'term' AND position(lower(rule.pattern) IN lower(content)) > 0) THEN
      IF rule.hard OR NOT EXISTS (
           SELECT 1 FROM zeusi.wall_allow a
           WHERE a.source_uri = r->>'source_uri' AND a.content_sha256 = csha AND a.rule_id = rule.id) THEN
        RAISE EXCEPTION 'zeusi wall: % row rejected by % rule % (%)', TG_TABLE_NAME,
              CASE WHEN rule.hard THEN 'hard' ELSE 'content' END, rule.id, rule.kind
          USING ERRCODE = 'ZW001',
                DETAIL = format('rule_id=%s;hard=%s;source_uri=%s;content_sha256=%s',
                                rule.id, rule.hard, r->>'source_uri', encode(csha, 'hex')),
                HINT = 'Record in zeusi.quarantine by uri and hash only. Never log the text.';
      END IF;
    END IF;
  END LOOP;

  RETURN NEW;
END $$;

CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.facts        FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.decisions    FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.episodes     FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.notes        FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.chunks       FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.prs          FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.pr_reviews   FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.routine_runs FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();
CREATE TRIGGER zeusi_90_wall BEFORE INSERT OR UPDATE ON zeusi.people       FOR EACH ROW EXECUTE FUNCTION zeusi.wall_check();

-- Guard the wall tables themselves.
CREATE FUNCTION zeusi.wall_rules_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
BEGIN
  IF TG_TABLE_NAME = 'wall_denylist' THEN
    IF TG_OP = 'UPDATE' AND OLD.hard AND NOT NEW.hard THEN
      RAISE EXCEPTION 'zeusi wall: a hard rule cannot be softened (rule %)', OLD.id USING ERRCODE = 'ZW002';
    END IF;
    IF NEW.kind = 'regex' THEN
      PERFORM '' ~* NEW.pattern;   -- fail now on an invalid regex, not on every later insert
    END IF;
  ELSIF TG_TABLE_NAME = 'wall_allow' THEN
    IF EXISTS (SELECT 1 FROM zeusi.wall_denylist d WHERE d.id = NEW.rule_id AND d.hard) THEN
      RAISE EXCEPTION 'zeusi wall: rule % is hard and cannot be allowed', NEW.rule_id USING ERRCODE = 'ZW002';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER zeusi_wall_guard BEFORE INSERT OR UPDATE ON zeusi.wall_denylist
  FOR EACH ROW EXECUTE FUNCTION zeusi.wall_rules_guard();
CREATE TRIGGER zeusi_wall_guard BEFORE INSERT OR UPDATE ON zeusi.wall_allow
  FOR EACH ROW EXECUTE FUNCTION zeusi.wall_rules_guard();

-- Writers record blocked items here (uri + hashes only). SECURITY DEFINER so
-- writer roles need no direct grant on quarantine.
CREATE FUNCTION zeusi.quarantine_record(
  p_source_kind zeusi.source_kind, p_source_uri text, p_source_sha256 bytea,
  p_rule_id int, p_ingest_run_id bigint, p_target_table text DEFAULT NULL,
  p_content_sha256 bytea DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
DECLARE qid bigint;
BEGIN
  INSERT INTO zeusi.quarantine AS q
    (source_kind, source_uri, source_sha256, content_sha256, target_table, rule_id, ingest_run_id)
  VALUES (p_source_kind, p_source_uri, p_source_sha256, p_content_sha256, p_target_table, p_rule_id, p_ingest_run_id)
  ON CONFLICT (source_uri, source_sha256) DO UPDATE
    SET detected_at = now(), rule_id = EXCLUDED.rule_id,
        content_sha256 = coalesce(EXCLUDED.content_sha256, q.content_sha256),
        ingest_run_id = coalesce(EXCLUDED.ingest_run_id, q.ingest_run_id)
  RETURNING q.id INTO qid;
  RETURN qid;
END $$;

-- Audit (U4): content rows that match a hard path/lane/repo rule now, or whose
-- (uri, sha) is quarantined. Must return zero rows.
CREATE FUNCTION zeusi.wall_audit()
RETURNS TABLE (table_name text, row_ref text, source_uri text, problem text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
  WITH content AS (
    SELECT 'facts' AS t, id::text AS ref, source_uri, source_sha256, NULL::text AS lane, NULL::text AS repo FROM zeusi.facts
    UNION ALL SELECT 'decisions', id::text, source_uri, source_sha256, NULL, linked_repo FROM zeusi.decisions
    UNION ALL SELECT 'episodes', id::text, source_uri, source_sha256, lane, NULL FROM zeusi.episodes
    UNION ALL SELECT 'notes', id::text, source_uri, source_sha256, NULL, NULL FROM zeusi.notes
    UNION ALL SELECT 'chunks', id::text, source_uri, source_sha256, NULL, NULL FROM zeusi.chunks
    UNION ALL SELECT 'prs', repo || '#' || number, source_uri, source_sha256, NULL, repo FROM zeusi.prs
    UNION ALL SELECT 'pr_reviews', id::text, source_uri, source_sha256, NULL, repo FROM zeusi.pr_reviews
    UNION ALL SELECT 'routine_runs', id::text, source_uri, source_sha256, lane, NULL FROM zeusi.routine_runs
    UNION ALL SELECT 'people', id::text, source_uri, source_sha256, NULL, NULL FROM zeusi.people
  )
  SELECT c.t, c.ref, c.source_uri, 'hard rule ' || d.id || ' (' || d.kind || ')'
  FROM content c
  JOIN zeusi.wall_denylist d ON
       (d.kind = 'path_glob' AND zeusi.uri_path(c.source_uri) ~* zeusi.glob_to_regex(d.pattern))
    OR (d.kind = 'lane' AND c.lane ~* zeusi.glob_to_regex(d.pattern))
    OR (d.kind = 'repo' AND zeusi.norm_repo(c.repo) ~* zeusi.glob_to_regex(d.pattern, true))
  UNION ALL
  SELECT c.t, c.ref, c.source_uri, 'quarantined (uri, sha) present in content'
  FROM content c
  JOIN zeusi.quarantine q ON q.source_uri = c.source_uri AND q.source_sha256 = c.source_sha256
$$;

-- ---------------------------------------------------------------------------
-- Seeds (PLAN.md "Hard deny rules" and "Content rules").
INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason, added_by) VALUES
  -- vault paths
  ('path_glob', true, 'ClientCo/**',                   'ClientCo vault area',                          'plan-seed'),
  ('path_glob', true, 'plankiva/**',                'Plankiva vault area',                       'plan-seed'),
  ('path_glob', true, 'bot-staged/**',            'deferred: bot-staged',                    'plan-seed'),
  ('path_glob', true, 'raw/**',                   'deferred: raw meetings',                  'plan-seed'),
  ('path_glob', true, 'personal/**',              'personal area',                           'plan-seed'),
  ('path_glob', true, 'canvas/**',                'not ingested',                            'plan-seed'),
  ('path_glob', true, 'bases/**',                 'not ingested',                            'plan-seed'),
  ('path_glob', true, '.obsidian/**',             'Obsidian config',                         'plan-seed'),
  ('path_glob', true, 'Work/ops/attic/**', 'archived ops notes',                      'plan-seed'),
  ('path_glob', true, 'Work/intake/**',          'unreviewed inbox',                        'plan-seed'),
  -- any path whose name contains clientco / plankiva / pnl / p&l (case-insensitive)
  ('path_glob', true, '**clientco**',                  'name contains clientco',                       'plan-seed'),
  ('path_glob', true, '**plankiva**',               'name contains plankiva',                    'plan-seed'),
  ('path_glob', true, '**pnl**',                  'name contains pnl (desk P&L)',            'plan-seed'),
  ('path_glob', true, '**p&l**',                  'name contains p&l (desk P&L)',            'plan-seed'),
  -- outside the vault
  ('path_glob', true, '~/PlankivaVault/**',                 'PlankivaVault',                     'plan-seed'),
  ('path_glob', true, '**/PlankivaVault/**',                'PlankivaVault (absolute path)',     'plan-seed'),
  ('path_glob', true, '~/KnowledgeVault-staging/**', 'staging copy',               'plan-seed'),
  ('path_glob', true, '**/KnowledgeVault-staging/**', 'staging copy (absolute)',    'plan-seed'),
  ('path_glob', true, '~/.assistant/memory/plankiva*',       'Plankiva assistant memory',               'plan-seed'),
  ('path_glob', true, '**/.assistant/memory/plankiva*',      'Plankiva assistant memory (absolute)',    'plan-seed'),
  ('path_glob', true, '**/lanes/desk-pnl/**', 'desk P&L lane',         'plan-seed'),
  ('path_glob', true, '**/lanes/session-pnl/**',  'desk P&L lane',         'plan-seed'),
  -- lanes
  ('lane', true, 'desk-pnl', 'desk P&L lane, hard-denied unread',                'plan-seed'),
  ('lane', true, 'session-pnl',  'desk P&L lane, hard-denied unread',                'plan-seed'),
  ('lane', true, '*pnl*',                'lane name contains pnl',                           'plan-seed'),
  ('lane', true, '*clientco*',                'lane name contains clientco',                           'plan-seed'),
  ('lane', true, '*plankiva*',             'lane name contains plankiva',                        'plan-seed'),
  -- repos (owner/name; bare names are normalised to example-org/<name>)
  ('repo', true, 'example-org/clientco-*',                'ClientCo repos',                             'plan-seed'),
  ('repo', true, 'example-org/*clientco*',                'ClientCo repos',                             'plan-seed'),
  ('repo', true, 'example-org/agent-config-backup*', 'agent config backups (client-walled)',     'plan-seed'),
  ('repo', true, '*plankiva*',                        'repo name contains plankiva',             'plan-seed'),
  ('repo', true, '*/*clientco*',                         'repo name contains clientco (any owner)',    'plan-seed'),
  -- content rules (quarantine unless wall_allow pins the exact content hash)
  ('regex', false, '(USD|EUR|CHF|GBP|JPY)[ ]?[0-9]|\$[ ]?[0-9]',
                   'currency amount', 'plan-seed'),
  ('regex', false, '\m(login|account|acct)\M[^0-9\n]{0,4}[0-9]{5,}',
                   'trading account or login number', 'plan-seed'),
  ('regex', false, '(?c)\m[A-Z]{2}[0-9]{2}[ ]?([A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\M',
                   'IBAN pattern', 'plan-seed'),
  ('regex', false, '(p&l|\mpnl\M|\mbook\M)[^\n]*[0-9]',
                   'P&L / PnL / book line with digits', 'plan-seed');
-- Client and counterparty names: kind = 'term', added by the owner as owner only. Not seeded.
