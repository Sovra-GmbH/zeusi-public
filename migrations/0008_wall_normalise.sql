-- 0008_wall_normalise.sql — review r1 minors (PR #1): wall normalisation,
-- percent-decoding, extra free-text columns, audit masking.
--
-- * MINOR-1  zeusi.wall_norm(text): strip Default_Ignorable / Cf code points
--            (zero-width, soft hyphen, bidi controls, variation selectors, tag
--            characters, ...) → NFKD → strip those + combining marks → NFKC → strip
--            again → apply confusable folds for letters used by the seed hard terms
--            → ASCII lower-case.
--            The hard tag / term / regex rules now match the raw text OR its
--            normalised form; path / lane / repo candidates include the normalised
--            form. Soft content rules are unchanged.
-- * MINOR-2  zeusi.pct_decode(text): %XX decoding repeated until stable (max 8
--            rounds). Path / lane / repo candidates include the decoded uri and
--            paths; the decoded uri is part of the hard text.
-- * MINOR-3  prs.merged_to, routine_runs.run_key and chunks.embed_model join the
--            hard text (hard rules only).
-- * MINOR-4  wall_audit() masks source_uri of scope='personal' rows unless the
--            calling login is a member of the function owner (the owner / migrations).
--
-- wall_content() and wall_content_sha256() are NOT changed: existing content
-- hashes and wall_allow pins stay valid. src/wall.ts mirrors every function here
-- exactly (wallNorm, pctDecode, compileWall); test/wall.test.ts holds the parity
-- tests. CREATE OR REPLACE keeps the same signatures, so the triggers, owner and
-- grants of wall_eval / wall_audit stay. Re-runnable.

-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION zeusi.wall_norm(t text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog AS $$
  SELECT translate(
           translate(
             regexp_replace(
               normalize(
                 regexp_replace(
                   normalize(regexp_replace(t, E'[­͏؀-؅؜۝܏࢐-࢑࣢ᅟ-ᅠ឴-឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ￰-￻\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0000-\U000E0FFF]', '', 'g'), NFKD),
                 E'[­͏؀-؅؜۝܏࢐-࢑࣢ᅟ-ᅠ឴-឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ￰-￻\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0000-\U000E0FFF̀-ͯ᪰-᫿᷀-᷿⃐-⃿︠-︯]', '', 'g'),
               NFKC),
             E'[­͏؀-؅؜۝܏࢐-࢑࣢ᅟ-ᅠ឴-឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ￰-￻\U000110BD\U000110CD\U00013430-\U0001343F\U0001BCA0-\U0001BCA3\U0001D173-\U0001D17A\U000E0000-\U000E0FFF]', '', 'g'),
           E'аАαΑɑᴀсСϲϹᴄɡɢԍԌіІιΙıɪӏӀкКκΚϰᴋʟᴌпΝηɴոռрРρΡᴘνѵѴᴠ',
           'aaaaaacccccggggiiiiiiiikkkkkkllnnnnnnpppppvvvv'),
         'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
$$;

-- One %XX pass. %00 is never decoded (text cannot hold NUL). If the decoded bytes
-- are not valid UTF-8, only the ASCII escapes (%01-%7F) are decoded.
CREATE OR REPLACE FUNCTION zeusi.pct_decode_once(s text)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog AS $$
DECLARE
  out_b   bytea := ''::bytea;
  ascii   text := '';
  i       int := 1;
  n       int := length(s);
  c       text;
  h       text;
  v       int;
BEGIN
  IF position('%' IN s) = 0 THEN RETURN s; END IF;
  WHILE i <= n LOOP
    c := substr(s, i, 1);
    h := substr(s, i + 1, 2);
    IF c = '%' AND h ~ '^[0-9A-Fa-f]{2}$' AND h <> '00' THEN
      v := ('x' || h)::bit(8)::int;
      out_b := out_b || set_byte('\x00'::bytea, 0, v);
      ascii := ascii || CASE WHEN v < 128 THEN chr(v) ELSE '%' || h END;
      i := i + 3;
    ELSE
      out_b := out_b || convert_to(c, 'UTF8');
      ascii := ascii || c;
      i := i + 1;
    END IF;
  END LOOP;
  BEGIN
    RETURN convert_from(out_b, 'UTF8');
  EXCEPTION WHEN character_not_in_repertoire OR untranslatable_character THEN
    RETURN ascii;
  END;
END $$;

CREATE OR REPLACE FUNCTION zeusi.pct_decode(s text)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog, zeusi AS $$
DECLARE
  cur  text := s;
  nxt  text;
BEGIN
  FOR k IN 1..8 LOOP
    nxt := zeusi.pct_decode_once(cur);
    EXIT WHEN nxt = cur;
    cur := nxt;
  END LOOP;
  RETURN cur;
END $$;

-- ---------------------------------------------------------------------------
-- The single verdict function (same signature as 0007; order and stages unchanged).
CREATE OR REPLACE FUNCTION zeusi.wall_eval(tbl text, r jsonb)
RETURNS TABLE (rule_id int, kind zeusi.wall_rule_kind, hard boolean, content_sha256 bytea)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, zeusi AS $$
#variable_conflict use_column
DECLARE
  uri       text;
  uri_d     text;
  paths     text[];
  lanes     text[];
  repos     text[];
  tags      text[] := ARRAY[]::text[];
  fm        jsonb;
  v         jsonb;
  k         text;
  content   text;
  hard_text text;
  norm_text text;
  pnorm     text;
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
  uri := r->>'source_uri';
  uri_d := zeusi.pct_decode(uri);

  -- Candidates: raw, percent-decoded, then the normalised form of each.
  paths := array_remove(ARRAY[
    zeusi.uri_path(uri), zeusi.uri_path(uri_d),
    r->>'vault_path', zeusi.pct_decode(r->>'vault_path'),
    r->>'review_ref', zeusi.pct_decode(r->>'review_ref'),
    r->>'log_ref', zeusi.pct_decode(r->>'log_ref')
  ], NULL);
  paths := paths || ARRAY(SELECT zeusi.wall_norm(x) FROM unnest(paths) WITH ORDINALITY AS t(x, n) ORDER BY n);

  lanes := ARRAY[
    r->>'lane',
    substring(uri FROM '^lane:([^/#]+)'), substring(uri FROM 'lanes/([^/#]+)'),
    substring(uri_d FROM '^lane:([^/#]+)'), substring(uri_d FROM 'lanes/([^/#]+)')
  ];
  repos := ARRAY[
    r->>'repo', r->>'linked_repo',
    CASE WHEN uri LIKE 'gh:%' THEN zeusi.uri_path(uri) END,
    CASE WHEN uri_d LIKE 'gh:%' THEN zeusi.uri_path(uri_d) END
  ];
  IF jsonb_typeof(r->'applies_to') = 'array' THEN
    lanes := lanes || ARRAY(SELECT jsonb_array_elements_text(r->'applies_to'));
    repos := repos || ARRAY(SELECT jsonb_array_elements_text(r->'applies_to'));
  END IF;
  lanes := array_remove(lanes, NULL);
  lanes := lanes || ARRAY(SELECT zeusi.wall_norm(x) FROM unnest(lanes) WITH ORDINALITY AS t(x, n) ORDER BY n);
  repos := array_remove(repos, NULL);
  repos := repos || ARRAY(SELECT zeusi.wall_norm(x) FROM unnest(repos) WITH ORDINALITY AS t(x, n) ORDER BY n);
  repos := ARRAY(SELECT zeusi.norm_repo(x) FROM unnest(repos) WITH ORDINALITY AS t(x, n) WHERE btrim(x) <> '' ORDER BY n);

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

  -- 2. hard tag rules (raw tags lower-cased, OR normalised tags incl. inline #tags
  --    found in the normalised text)
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
    pnorm := zeusi.wall_norm(rl.pattern);
    IF EXISTS (SELECT 1 FROM unnest(tags) AS t WHERE position(lower(rl.pattern) IN lower(t)) > 0)
       OR (pnorm <> '' AND (
             EXISTS (SELECT 1 FROM unnest(tags) AS t WHERE position(pnorm IN zeusi.wall_norm(t)) > 0)
          OR EXISTS (SELECT 1 FROM regexp_matches(zeusi.wall_norm(content), '(?:^|[ \t\n\r\f\v])#([A-Za-z0-9_/-]+)', 'g') AS m
                     WHERE position(pnorm IN zeusi.wall_norm(m[1])) > 0))) THEN
      rule_id := rl.id; kind := rl.kind; hard := true; content_sha256 := csha;
      RETURN NEXT; RETURN;
    END IF;
  END LOOP;

  -- 3. hard regex / term over the checked text, every identifier the row carries,
  --    and the free-text columns outside wall_content; raw OR normalised.
  hard_text := concat_ws(E'\n', content, uri, uri_d, r->>'merged_to', r->>'run_key', r->>'embed_model',
                         array_to_string(paths, E'\n'), array_to_string(lanes, E'\n'), array_to_string(repos, E'\n'));
  norm_text := zeusi.wall_norm(hard_text);
  FOR rl IN
    SELECT d.id, d.kind, d.pattern FROM zeusi.wall_denylist d
    WHERE d.kind IN ('regex', 'term') AND d.hard ORDER BY d.id
  LOOP
    pnorm := zeusi.wall_norm(rl.pattern);
    IF (rl.kind = 'regex' AND (hard_text ~* rl.pattern OR norm_text ~* rl.pattern))
       OR (rl.kind = 'term' AND (position(lower(rl.pattern) IN lower(hard_text)) > 0
                                 OR (pnorm <> '' AND position(pnorm IN norm_text) > 0))) THEN
      rule_id := rl.id; kind := rl.kind; hard := true; content_sha256 := csha;
      RETURN NEXT; RETURN;
    END IF;
  END LOOP;

  -- 4. soft content rules, unless pinned by wall_allow to this exact content hash
  --    (unchanged: raw content only)
  FOR rl IN
    SELECT d.id, d.kind, d.pattern FROM zeusi.wall_denylist d
    WHERE d.kind IN ('regex', 'term') AND NOT d.hard ORDER BY d.id
  LOOP
    IF ((rl.kind = 'regex' AND content ~* rl.pattern)
        OR (rl.kind = 'term' AND position(lower(rl.pattern) IN lower(content)) > 0))
       AND NOT EXISTS (
         SELECT 1 FROM zeusi.wall_allow a
         WHERE a.source_uri = uri AND a.content_sha256 = csha AND a.rule_id = rl.id) THEN
      rule_id := rl.id; kind := rl.kind; hard := false; content_sha256 := csha;
      RETURN NEXT; RETURN;
    END IF;
  END LOOP;

  rule_id := NULL; kind := NULL; hard := NULL; content_sha256 := csha;
  RETURN NEXT;
END $$;

-- ---------------------------------------------------------------------------
-- Audit (same rows as 0007). source_uri of scope='personal' rows is masked unless
-- the calling login (session_user) is a member of the function owner: inside this
-- SECURITY DEFINER function current_user IS the owner. zeusi_ingest needs EXECUTE
-- for the nightly audit but must not learn personal uris (r1 MINOR-4).
CREATE OR REPLACE FUNCTION zeusi.wall_audit()
RETURNS TABLE (table_name text, row_ref text, source_uri text, problem text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, zeusi AS $$
  WITH content AS (
    SELECT 'facts'::text AS t, x.id::text AS ref, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) AS r FROM zeusi.facts x
    UNION ALL SELECT 'decisions', x.id::text, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.decisions x
    UNION ALL SELECT 'episodes', x.id::text, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.episodes x
    UNION ALL SELECT 'notes', x.id::text, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.notes x
    UNION ALL SELECT 'chunks', x.id::text, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) - 'embedding' - 'tsv' FROM zeusi.chunks x
    UNION ALL SELECT 'prs', x.repo || '#' || x.number, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.prs x
    UNION ALL SELECT 'pr_reviews', x.id::text, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.pr_reviews x
    UNION ALL SELECT 'routine_runs', x.id::text, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.routine_runs x
    UNION ALL SELECT 'people', x.id::text, x.scope, x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.people x
  ),
  owner_call AS (SELECT pg_has_role(session_user, current_user, 'MEMBER') AS ok),
  hits AS (
    SELECT c.t, c.ref, c.scope, c.source_uri,
           CASE WHEN v.hard THEN 'hard' ELSE 'content' END || ' rule ' || v.rule_id || ' (' || v.kind || ')' AS problem
    FROM content c CROSS JOIN LATERAL zeusi.wall_eval(c.t, c.r) AS v
    WHERE v.rule_id IS NOT NULL
    UNION ALL
    SELECT c.t, c.ref, c.scope, c.source_uri, 'quarantined (uri, sha) present in content'
    FROM content c
    JOIN zeusi.quarantine q
      ON q.source_uri = c.source_uri
     AND (q.source_sha256 = c.source_sha256 OR q.content_sha256 = zeusi.wall_content_sha256(c.t, c.r))
    WHERE NOT EXISTS (
      SELECT 1 FROM zeusi.wall_allow a JOIN zeusi.wall_denylist d ON d.id = a.rule_id
      WHERE NOT d.hard AND a.source_uri = q.source_uri
        AND a.content_sha256 = q.content_sha256 AND a.rule_id = q.rule_id)
  )
  SELECT h.t, h.ref,
         CASE WHEN h.scope = 'personal' AND NOT o.ok THEN 'personal:<masked>' ELSE h.source_uri END,
         h.problem
  FROM hits h CROSS JOIN owner_call o
$$;

-- ---------------------------------------------------------------------------
-- Grants. New functions get PUBLIC EXECUTE by default: revoke it. zeusi_ingest
-- calls wall_eval() (SECURITY INVOKER) for pre-checks, so it needs the helpers.
REVOKE ALL ON FUNCTION zeusi.wall_norm(text), zeusi.pct_decode_once(text), zeusi.pct_decode(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zeusi.wall_norm(text), zeusi.pct_decode_once(text), zeusi.pct_decode(text) TO zeusi_ingest;
-- Unchanged from 0007 (restated so a re-run cannot widen them).
REVOKE ALL ON FUNCTION zeusi.wall_eval(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zeusi.wall_eval(text, jsonb) TO zeusi_ingest;
REVOKE ALL ON FUNCTION zeusi.wall_audit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zeusi.wall_audit() TO zeusi_ingest, zeusi_backup;
