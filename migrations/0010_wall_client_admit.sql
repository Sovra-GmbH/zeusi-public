-- 0010_wall_client_admit.sql — owner rule:
-- ClientCo and Northbank work goes INTO Zeusi, with its own folders and sections. ONLY
-- Plankiva stays out.
--
-- * scope: new value 'client' (ClientCo content, read from its own vault folder).
--   'product' already exists and is kept. 'personal' stays hidden.
--   A new enum value cannot be USED in the transaction that adds it, and
--   `zeusi migrate` runs each file in one transaction, so nothing below casts
--   'client' to zeusi.scope: the read policy compares scope::text.
-- * wall: the six hard rules that block on the ClientCo name are deleted, by (kind, pattern)
--   so hand-added rules are never touched:
--     path_glob 'ClientCo/**', path_glob '**clientco**', lane '*clientco*',
--     repo 'example-org/clientco-*', repo 'example-org/*clientco*', repo '*/*clientco*'.
--   wall_allow rows pinned to them are removed by ON DELETE CASCADE (none can exist:
--   the guard refuses allows on hard rules). quarantine rows that named one of them
--   keep their uri and hashes; their rule_id becomes NULL (ON DELETE SET NULL).
--   KEPT on purpose: repo 'example-org/agent-config-backup*' (it walls agent config
--   backups, not the ClientCo name; a decision for the operator), every Plankiva rule, every desk
--   P&L rule, the area rules, the soft content rules and the 0009 escape rule.
-- * Plankiva hardening: one new HARD regex rule (no wall_allow) for the word spelled
--   with separators between its letters ("P l a n k i v a", "P.l.a.n.k.i.v.a", "Plan-kiva",
--   "**Plan**kiva") or with leetspeak ("pl4nkiva", "pl@nk1va"). Like every hard regex it
--   is matched over the hard text, raw and normalised (wall_norm: fullwidth "４" is "4").
--   Alternative 1: up to 3 non-alphanumeric, non-space characters between letters.
--   Alternative 2: 1 to 3 non-alphanumeric characters (spaces allowed) between EVERY
--   pair of letters. A single space inside the word ("Plan kiva") is not matched, so
--   "plan kiva boat" and "plankton" pass. Vault dry run: 0 false positives.
-- * wall_eval(), wall_norm(), pct_decode(), wall_content() and wall_audit() carry no
--   ClientCo logic and are NOT replaced: verdict order, normalisation, the undecoded-escape
--   marker and the Plankiva rules are byte-for-byte those of 0009.
--
-- src/wall.ts mirrors the seeds (SEED_RULES = LEGACY_SEED_RULES - LIFTED_0010 +
-- PROTECTED_SPELLING_REGEX). Re-runnable. 0001-0009 are not edited.

-- ---------------------------------------------------------------------------
-- Scope.
ALTER TYPE zeusi.scope ADD VALUE IF NOT EXISTS 'client' AFTER 'product';

-- ---------------------------------------------------------------------------
-- Lift the ClientCo-name hard rules.
DELETE FROM zeusi.wall_denylist d
 USING (VALUES ('path_glob', 'ClientCo/**'),
               ('path_glob', '**clientco**'),
               ('lane',      '*clientco*'),
               ('repo',      'example-org/clientco-*'),
               ('repo',      'example-org/*clientco*'),
               ('repo',      '*/*clientco*')) AS l(kind, pattern)
 WHERE d.kind::text = l.kind AND d.pattern = l.pattern;

-- ---------------------------------------------------------------------------
-- Plankiva: separators / leetspeak (hard, never allowable).
INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason, added_by) VALUES
  ('regex', true,
   'p[^a-z0-9 \t\n\r\f\v]{0,3}l[^a-z0-9 \t\n\r\f\v]{0,3}[a4@][^a-z0-9 \t\n\r\f\v]{0,3}n[^a-z0-9 \t\n\r\f\v]{0,3}k[^a-z0-9 \t\n\r\f\v]{0,3}[i1!|][^a-z0-9 \t\n\r\f\v]{0,3}v[^a-z0-9 \t\n\r\f\v]{0,3}[a4@]|p[^a-z0-9]{1,3}l[^a-z0-9]{1,3}[a4@][^a-z0-9]{1,3}n[^a-z0-9]{1,3}k[^a-z0-9]{1,3}[i1!|][^a-z0-9]{1,3}v[^a-z0-9]{1,3}[a4@]',
   'the word plankiva spelled with separators or leetspeak (owner hard rule, kept by owner-rule); no wall_allow', 'plan-seed')
ON CONFLICT (kind, pattern) DO NOTHING;
DELETE FROM zeusi.wall_allow a USING zeusi.wall_denylist d WHERE d.id = a.rule_id AND d.hard;

-- ---------------------------------------------------------------------------
-- RLS: readers see team, product and clientco (same as team). personal stays
-- hidden. Writers: write_not_personal / ingest_update_not_personal (0005) already
-- admit clientco and are unchanged. zeusi_backup keeps USING (true).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['people', 'facts', 'decisions', 'prs', 'pr_reviews',
                           'episodes', 'routine_runs', 'notes', 'chunks'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS read_allowed_scopes ON zeusi.%I', t);
    EXECUTE format($p$CREATE POLICY read_allowed_scopes ON zeusi.%I FOR SELECT TO zeusi_read
                      USING (scope::text IN ('work', 'product', 'client'))$p$, t);
  END LOOP;
END $$;
