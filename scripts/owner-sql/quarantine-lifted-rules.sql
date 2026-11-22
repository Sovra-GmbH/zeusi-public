-- quarantine-lifted-rules.sql: clear the stale quarantine rows of lifted soft rules.
--
-- NEEDS THE OPERATOR'S EXPLICIT YES BEFORE IT IS RUN. It is NOT a migration: it lives outside
-- migrations/, so `zeusi migrate` never applies it. the owner's order allows no delete beyond the
-- Plankiva retraction; this delete is a separate decision.
--
-- What the rows are. zeusi.quarantine holds NO content: source_kind, source_uri, source_sha256,
-- content_sha256, target_table, rule_id, ingest_run_id, detected_at, detected_by. 0011 deletes
-- the soft currency rule and the soft P&L / book rule; quarantine.rule_id is ON DELETE SET NULL
-- (0003), so their quarantine rows stay with rule_id NULL (in run 10: the rows of 128
-- content-quarantined notes, a note row plus one row per blocked chunk, real vault: uris).
-- Once a re-ingest admits that content, zeusi.wall_audit() reports each of them as
-- "quarantined (uri, sha) present in content" and `ingest vault --real` exits 1. No wall_allow
-- can clear them (an allow needs a rule id), and neither the importer nor the audit deletes
-- quarantine rows.
--
-- What it deletes (exact predicate), only rows that are ALL of:
--   a. rule_id IS NULL (the rule that quarantined the row has been deleted: the 0011 lift, or a
--      0010 lift; the original rule id is gone, so it cannot be narrowed to the two 0011 rules);
--   b. the same (uri, sha) is now stored as content: a row of a content table with the same
--      source_uri and the same source_sha256 or content sha (exactly wall_audit's
--      "quarantined (uri, sha) present in content" join), i.e. the item is already admitted and
--      readable, so the quarantine row no longer hides anything;
--   c. that content row passes the live wall (zeusi.wall_eval returns no rule).
-- Not deleted: rows with a rule id (every kept rule, every Plankiva row); path-hash rows
-- (vault-path-sha256:..., never stored as content); rule_id NULL rows whose content is not
-- stored (still blocked by another rule, changed since, or not re-ingested yet).
--
-- When. AFTER 0010 + 0011 are applied AND the re-ingest has run (before the re-ingest,
-- condition b matches nothing and it deletes 0 rows). Run as the owner, step 1 first, read the
-- counts, then step 2 in one transaction and COMMIT only if the deleted count equals step 1.
-- Output is counts only, never uris. Tested on PGlite in test/wall-0011-stale-quarantine.test.ts.

-- @step1-dry-run (read-only)
WITH content AS (
  SELECT 'facts'::text AS t, x.source_uri, x.source_sha256, to_jsonb(x) AS r FROM zeusi.facts x
  UNION ALL SELECT 'decisions', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.decisions x
  UNION ALL SELECT 'episodes', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.episodes x
  UNION ALL SELECT 'notes', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.notes x
  UNION ALL SELECT 'chunks', x.source_uri, x.source_sha256, to_jsonb(x) - 'embedding' - 'tsv' FROM zeusi.chunks x
  UNION ALL SELECT 'prs', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.prs x
  UNION ALL SELECT 'pr_reviews', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.pr_reviews x
  UNION ALL SELECT 'routine_runs', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.routine_runs x
  UNION ALL SELECT 'people', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.people x
),
stale AS (
  SELECT q.id, q.target_table FROM zeusi.quarantine q
   WHERE q.rule_id IS NULL
     AND EXISTS (
       SELECT 1 FROM content c
        WHERE c.source_uri = q.source_uri
          AND (c.source_sha256 = q.source_sha256 OR zeusi.wall_content_sha256(c.t, c.r) = q.content_sha256)
          AND NOT EXISTS (SELECT 1 FROM zeusi.wall_eval(c.t, c.r) v WHERE v.rule_id IS NOT NULL))
)
SELECT coalesce(target_table, '(none)') AS target_table, count(*)::int AS rows_to_delete
  FROM stale GROUP BY 1 ORDER BY 1;
-- @end

-- @step2-delete (after the owner's yes; compare the count with step 1 before COMMIT)
BEGIN;
WITH content AS (
  SELECT 'facts'::text AS t, x.source_uri, x.source_sha256, to_jsonb(x) AS r FROM zeusi.facts x
  UNION ALL SELECT 'decisions', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.decisions x
  UNION ALL SELECT 'episodes', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.episodes x
  UNION ALL SELECT 'notes', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.notes x
  UNION ALL SELECT 'chunks', x.source_uri, x.source_sha256, to_jsonb(x) - 'embedding' - 'tsv' FROM zeusi.chunks x
  UNION ALL SELECT 'prs', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.prs x
  UNION ALL SELECT 'pr_reviews', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.pr_reviews x
  UNION ALL SELECT 'routine_runs', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.routine_runs x
  UNION ALL SELECT 'people', x.source_uri, x.source_sha256, to_jsonb(x) FROM zeusi.people x
),
gone AS (
  DELETE FROM zeusi.quarantine q
   WHERE q.rule_id IS NULL
     AND EXISTS (
       SELECT 1 FROM content c
        WHERE c.source_uri = q.source_uri
          AND (c.source_sha256 = q.source_sha256 OR zeusi.wall_content_sha256(c.t, c.r) = q.content_sha256)
          AND NOT EXISTS (SELECT 1 FROM zeusi.wall_eval(c.t, c.r) v WHERE v.rule_id IS NOT NULL))
  RETURNING q.id
)
SELECT count(*)::int AS deleted FROM gone;
SELECT count(*)::int AS audit_rows FROM zeusi.wall_audit();   -- expected 0 if nothing else is wrong
-- COMMIT;   -- type COMMIT only if deleted = step 1 total and audit_rows is what you expect; otherwise ROLLBACK;
-- @end
