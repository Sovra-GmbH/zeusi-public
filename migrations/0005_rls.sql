-- 0005_rls.sql — row-level security on content tables (PLAN.md "RLS", U3).
-- Tables are owned by the migration role, which bypasses RLS (no FORCE), so
-- migrations and owner maintenance are not filtered.
-- Readers see only 'work' and 'product'. Writers can never write 'personal'.
-- zeusi_backup reads everything; pg_dump must run with --enable-row-security.

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['people', 'facts', 'decisions', 'prs', 'pr_reviews',
                           'episodes', 'routine_runs', 'notes', 'chunks'] LOOP
    EXECUTE format('ALTER TABLE zeusi.%I ENABLE ROW LEVEL SECURITY', t);

    EXECUTE format('DROP POLICY IF EXISTS read_allowed_scopes ON zeusi.%I', t);
    EXECUTE format($p$CREATE POLICY read_allowed_scopes ON zeusi.%I FOR SELECT TO zeusi_read
                      USING (scope IN ('work', 'product'))$p$, t);

    EXECUTE format('DROP POLICY IF EXISTS write_not_personal ON zeusi.%I', t);
    EXECUTE format($p$CREATE POLICY write_not_personal ON zeusi.%I FOR INSERT TO zeusi_agent_write, zeusi_ingest
                      WITH CHECK (scope <> 'personal')$p$, t);

    EXECUTE format('DROP POLICY IF EXISTS ingest_update_not_personal ON zeusi.%I', t);
    EXECUTE format($p$CREATE POLICY ingest_update_not_personal ON zeusi.%I FOR UPDATE TO zeusi_ingest
                      USING (scope <> 'personal') WITH CHECK (scope <> 'personal')$p$, t);

    EXECUTE format('DROP POLICY IF EXISTS backup_read_all ON zeusi.%I', t);
    EXECUTE format('CREATE POLICY backup_read_all ON zeusi.%I FOR SELECT TO zeusi_backup USING (true)', t);
  END LOOP;
END $$;

-- Ingest may delete chunks of notes only (re-chunking a changed note).
DROP POLICY IF EXISTS ingest_delete_note_chunks ON zeusi.chunks;
CREATE POLICY ingest_delete_note_chunks ON zeusi.chunks FOR DELETE TO zeusi_ingest
  USING (note_id IS NOT NULL AND scope <> 'personal');
