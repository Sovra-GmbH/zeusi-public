-- 0007_wall_protected_name.sql — Plankiva hard wall + one verdict function (PLAN.md KTD7, U4).
--
-- the owner, 14 Nov 2026 14:17 Zurich: Plankiva has her own vault. Zeusi excludes ALL
-- Plankiva content, including PlankivaVault/requests/ (the earlier requests/ exception
-- is revoked for Zeusi). Any Plankiva path or tag is a hard block; the word "plankiva"
-- (case-insensitive) anywhere in the checked text is a hard block. No wall_allow
-- can override any of these.
--
-- * zeusi.wall_eval(tbl, row jsonb) is the single verdict function. The trigger
--   calls it; src/wall.ts mirrors it exactly (parity test in test/wall.test.ts).
--   Order, first hit wins:
--     1. hard path_glob / lane / repo rules, by id           (as in 0003)
--     2. hard tag rules, by id                               (new)
--        tags = frontmatter "tags" and "tag" (list or string) + inline #tags
--        in the checked text; a tag matches when it contains the pattern (ci).
--     3. hard regex / term rules, by id, over the checked text PLUS source_uri,
--        path, lane and repo candidates                       (new: before soft)
--     4. soft regex / term rules, by id, over the checked text, unless a
--        wall_allow row pins (source_uri, content_sha256, rule_id)  (as in 0003)
-- * wall_check() and wall_audit() are replaced in place (CREATE OR REPLACE keeps
--   the triggers, owner and grants). wall_content() is unchanged, so existing
--   content hashes and wall_allow pins stay valid.
-- * Re-runnable: seeds are idempotent; a pre-existing soft 'plankiva' term is
--   hardened and any wall_allow pinned to a now-hard rule is removed.
-- Requires 0006 (enum value 'tag').

-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION zeusi.wall_eval(tbl text, r jsonb)
RETURNS TABLE (rule_id int, kind zeusi.wall_rule_kind, hard boolean, content_sha256 bytea)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, zeusi AS $$
#variable_conflict use_column
DECLARE
  paths     text[];
  lanes     text[];
  repos     text[];
  tags      text[] := ARRAY[]::text[];
  fm        jsonb;
  v         jsonb;
  k         text;
  content   text;
  hard_text text;
  csha      bytea;
  rl        record;
BEGIN
  IF tbl IS NULL OR tbl NOT IN ('facts', 'decisions', 'episodes', 'notes', 'chunks',
                                'prs', 'pr_reviews', 'routine_runs', 'people') THEN
    RAISE EXCEPTION 'zeusi wall: unknown table %', tbl USING ERRCODE = 'invalid_parameter_value';
  END IF;

  -- Defaults the trigger would see on NEW (importers may omit them).
  IF tbl = 'notes'     AND NOT (r ? 'frontmatter') THEN r := r || '{"frontmatter": {}}'; END IF;
  IF tbl = 'episodes'  AND NOT (r ? 'links')       THEN r := r || '{"links": []}';       END IF;
  IF tbl = 'decisions' AND NOT (r ? 'applies_to')  THEN r := r || '{"applies_to": []}';  END IF;

  content := coalesce(zeusi.wall_content(tbl, r), '');
  csha := sha256(convert_to(content, 'UTF8'));

  paths := array_remove(ARRAY[
    zeusi.uri_path(r->>'source_uri'), r->>'vault_path', r->>'review_ref', r->>'log_ref'
  ], NULL);
  lanes := array_remove(ARRAY[
    r->>'lane',
    substring(r->>'source_uri' FROM '^lane:([^/#]+)'),
    substring(r->>'source_uri' FROM 'lanes/([^/#]+)')
  ], NULL);
  repos := array_remove(ARRAY[
    r->>'repo', r->>'linked_repo',
    CASE WHEN r->>'source_uri' LIKE 'gh:%' THEN zeusi.uri_path(r->>'source_uri') END
  ], NULL);
  IF jsonb_typeof(r->'applies_to') = 'array' THEN
    lanes := lanes || ARRAY(SELECT jsonb_array_elements_text(r->'applies_to'));
    repos := repos || ARRAY(SELECT jsonb_array_elements_text(r->'applies_to'));
  END IF;
  lanes := array_remove(lanes, NULL);
  repos := ARRAY(SELECT zeusi.norm_repo(x) FROM unnest(repos) AS x WHERE btrim(x) <> '');

  -- 1. hard path / lane / repo
  FOR rl IN
    SELECT d.id, d.kind, d.pattern FROM zeusi.wall_denylist d
    WHERE d.kind IN ('path_glob', 'lane', 'repo') ORDER BY d.id
  LOOP
    IF EXISTS (
      SELECT 1 FROM unnest(CASE rl.kind WHEN 'path_glob' THEN paths WHEN 'lane' THEN lanes ELSE repos END) AS x
      WHERE x ~* zeusi.glob_to_regex(rl.pattern, rl.kind = 'repo')
    ) THEN
      rule_id := rl.id; kind := rl.kind; hard := true; content_sha256 := csha;
      RETURN NEXT; RETURN;
    END IF;
  END LOOP;

  -- 2. hard tag rules
  fm := r->'frontmatter';
  IF jsonb_typeof(fm) = 'object' THEN
    FOREACH k IN ARRAY ARRAY['tags', 'tag'] LOOP
      v := fm->k;
      CONTINUE WHEN v IS NULL OR jsonb_typeof(v) = 'null';
      IF jsonb_typeof(v) = 'array' THEN
        tags := tags || ARRAY(
          SELECT CASE WHEN jsonb_typeof(e) = 'string' THEN e #>> '{}' ELSE e::text END
          FROM jsonb_array_elements(v) WITH ORDINALITY AS t(e, n)
          WHERE jsonb_typeof(e) <> 'null' ORDER BY n);
      ELSIF jsonb_typeof(v) = 'string' THEN
        tags := tags || (v #>> '{}');
      ELSE
        tags := tags || v::text;
      END IF;
    END LOOP;
  END IF;
  tags := tags || ARRAY(
    SELECT m[1] FROM regexp_matches(content, '(?:^|[ \t\n\r\f\v])#([A-Za-z0-9_/-]+)', 'g') AS m);

  FOR rl IN
    SELECT d.id, d.kind, d.pattern FROM zeusi.wall_denylist d WHERE d.kind = 'tag' ORDER BY d.id
  LOOP
    IF EXISTS (SELECT 1 FROM unnest(tags) AS t WHERE position(lower(rl.pattern) IN lower(t)) > 0) THEN
      rule_id := rl.id; kind := rl.kind; hard := true; content_sha256 := csha;
      RETURN NEXT; RETURN;
    END IF;
  END LOOP;

  -- 3. hard regex / term over the checked text plus every identifier the row carries
  hard_text := concat_ws(E'\n', content, r->>'source_uri',
                         array_to_string(paths, E'\n'), array_to_string(lanes, E'\n'), array_to_string(repos, E'\n'));
  FOR rl IN
    SELECT d.id, d.kind, d.pattern FROM zeusi.wall_denylist d
    WHERE d.kind IN ('regex', 'term') AND d.hard ORDER BY d.id
  LOOP
    IF (rl.kind = 'regex' AND hard_text ~* rl.pattern)
       OR (rl.kind = 'term' AND position(lower(rl.pattern) IN lower(hard_text)) > 0) THEN
      rule_id := rl.id; kind := rl.kind; hard := true; content_sha256 := csha;
      RETURN NEXT; RETURN;
    END IF;
  END LOOP;

  -- 4. soft content rules, unless pinned by wall_allow to this exact content hash
  FOR rl IN
    SELECT d.id, d.kind, d.pattern FROM zeusi.wall_denylist d
    WHERE d.kind IN ('regex', 'term') AND NOT d.hard ORDER BY d.id
  LOOP
    IF ((rl.kind = 'regex' AND content ~* rl.pattern)
        OR (rl.kind = 'term' AND position(lower(rl.pattern) IN lower(content)) > 0))
       AND NOT EXISTS (
         SELECT 1 FROM zeusi.wall_allow a
         WHERE a.source_uri = r->>'source_uri' AND a.content_sha256 = csha AND a.rule_id = rl.id) THEN
      rule_id := rl.id; kind := rl.kind; hard := false; content_sha256 := csha;
      RETURN NEXT; RETURN;
    END IF;
  END LOOP;

  rule_id := NULL; kind := NULL; hard := NULL; content_sha256 := csha;
  RETURN NEXT;
END $$;

-- ---------------------------------------------------------------------------
-- The row-layer trigger now delegates to wall_eval(). Same SQLSTATE and DETAIL shape.
CREATE OR REPLACE FUNCTION zeusi.wall_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
DECLARE
  r jsonb := to_jsonb(NEW);
  v record;
BEGIN
  IF TG_TABLE_NAME NOT IN ('facts', 'decisions', 'episodes', 'notes', 'chunks',
                           'prs', 'pr_reviews', 'routine_runs', 'people') THEN
    RAISE EXCEPTION 'zeusi wall: wall_check attached to unknown table %', TG_TABLE_NAME;
  END IF;
  SELECT * INTO v FROM zeusi.wall_eval(TG_TABLE_NAME, r);
  IF v.rule_id IS NOT NULL THEN
    RAISE EXCEPTION 'zeusi wall: % row rejected by % rule % (%)', TG_TABLE_NAME,
          CASE WHEN v.hard THEN 'hard' ELSE 'content' END, v.rule_id, v.kind
      USING ERRCODE = 'ZW001',
            DETAIL = format('rule_id=%s;hard=%s;source_uri=%s;content_sha256=%s',
                            v.rule_id, v.hard, r->>'source_uri', encode(v.content_sha256, 'hex')),
            HINT = CASE WHEN v.hard
                     THEN 'Record in zeusi.quarantine by uri and hash only. Hard rules cannot be overridden.'
                     ELSE 'Record in zeusi.quarantine by uri and hash only. Never log the text.' END;
  END IF;
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------------------
-- Audit: every content row re-checked with wall_eval() (hard path/lane/repo/tag/
-- term, and soft rules without a pinned allow), plus quarantined (uri, sha) found
-- in content — by source hash or by content hash — unless the owner pinned a wall_allow
-- for exactly that quarantined content. Must return zero rows. No content returned.
CREATE OR REPLACE FUNCTION zeusi.wall_audit()
RETURNS TABLE (table_name text, row_ref text, source_uri text, problem text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
  WITH content AS (
    SELECT 'facts'::text AS t, x.id::text AS ref, x.source_uri, x.source_sha256, to_jsonb(x) AS r FROM zeusi.facts x
    UNION ALL SELECT 'decisions', x.id::text, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.decisions x
    UNION ALL SELECT 'episodes', x.id::text, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.episodes x
    UNION ALL SELECT 'notes', x.id::text, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.notes x
    UNION ALL SELECT 'chunks', x.id::text, x.source_uri, x.source_sha256, to_jsonb(x) - 'embedding' - 'tsv' FROM zeusi.chunks x
    UNION ALL SELECT 'prs', x.repo || '#' || x.number, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.prs x
    UNION ALL SELECT 'pr_reviews', x.id::text, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.pr_reviews x
    UNION ALL SELECT 'routine_runs', x.id::text, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.routine_runs x
    UNION ALL SELECT 'people', x.id::text, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.people x
  )
  SELECT c.t, c.ref, c.source_uri,
         CASE WHEN v.hard THEN 'hard' ELSE 'content' END || ' rule ' || v.rule_id || ' (' || v.kind || ')'
  FROM content c CROSS JOIN LATERAL zeusi.wall_eval(c.t, c.r) AS v
  WHERE v.rule_id IS NOT NULL
  UNION ALL
  SELECT c.t, c.ref, c.source_uri, 'quarantined (uri, sha) present in content'
  FROM content c
  JOIN zeusi.quarantine q
    ON q.source_uri = c.source_uri
   AND (q.source_sha256 = c.source_sha256 OR q.content_sha256 = zeusi.wall_content_sha256(c.t, c.r))
  WHERE NOT EXISTS (
    SELECT 1 FROM zeusi.wall_allow a JOIN zeusi.wall_denylist d ON d.id = a.rule_id
    WHERE NOT d.hard AND a.source_uri = q.source_uri
      AND a.content_sha256 = q.content_sha256 AND a.rule_id = q.rule_id)
$$;

-- ---------------------------------------------------------------------------
-- Seeds (idempotent). A soft 'plankiva' term added earlier is hardened first.
UPDATE zeusi.wall_denylist
   SET hard = true
 WHERE kind = 'term' AND lower(pattern) = 'plankiva' AND NOT hard;

INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason, added_by) VALUES
  ('tag',  true, 'plankiva', 'Plankiva tag (owner hard rule); no wall_allow', 'plan-seed'),
  ('term', true, 'plankiva', 'the word plankiva anywhere in checked text (owner hard rule); no wall_allow', 'plan-seed')
ON CONFLICT (kind, pattern) DO NOTHING;

-- An allow can never pin a hard rule (the guard refuses new ones); drop any left over.
DELETE FROM zeusi.wall_allow a USING zeusi.wall_denylist d WHERE d.id = a.rule_id AND d.hard;

-- ---------------------------------------------------------------------------
-- Grants. New functions get PUBLIC EXECUTE by default: revoke it.
REVOKE ALL ON FUNCTION zeusi.wall_eval(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zeusi.wall_eval(text, jsonb) TO zeusi_ingest;
REVOKE ALL ON FUNCTION zeusi.wall_audit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zeusi.wall_audit() TO zeusi_ingest, zeusi_backup;
