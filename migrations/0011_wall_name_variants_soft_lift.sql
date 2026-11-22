-- 0011_wall_name_variants_soft_lift.sql — the owner's decisions, 15 Nov 2026 01:09 Zurich.
--
-- 1. "Plankiva" (one n) IS Plankiva. One new HARD regex rule (never allowable) for the name
--    and its variants: the letters p l a n k i v a, each written 1 to 3 times (Plankiva, Plankiva,
--    Plaankiva, Plankkiva, Plannkiva, ...), any case, a as 4 or @, i as 1, ! or |,
--    with the two separator forms of 0010:
--      alternative 1: up to 3 non-alphanumeric, non-space characters between letters
--                     ("P-lankiva", "P.l.a.n.k.i.v.a", "**Plan**kiva", or none at all);
--      alternative 2: 1 to 3 non-alphanumeric characters (spaces allowed) between EVERY
--                     pair of letters ("P l a n k i v a").
--    No start anchor: the letters inside a longer token block too ("xPlankivax"). Like every
--    hard regex it is matched over the hard text (checked text, source_uri raw and
--    percent-decoded, paths, lanes, repos, free-text columns), raw and wall_norm()ed, so
--    fullwidth, Cyrillic / Greek / Cherokee / Lisu look-alikes and zero-width or combining
--    characters fold in. That covers path, lane, repo, tag (frontmatter and inline),
--    text and source_uri, as for the 0010 Plankiva spelling regex. Every quantifier is
--    bounded, so matching is linear (timed in test/wall-0011.test.ts on 100k-400k chars).
--    Accepted over-blocks (words that embed the letters, e.g. "mechplankiva", "botplankiva",
--    "Pplankivattacke", "Kplankiva"): none in the vault or the lane notes (docs/wall.md).
--    Every 0003 / 0007 / 0010 Plankiva rule stays as it is.
-- 2. The SOFT currency rule and the SOFT P&L / book rule are deleted, by (kind, pattern)
--    and only while soft, so ClientCo and Northbank content is admitted.
--    FK effects: wall_allow rows pinned to them go by ON DELETE CASCADE. quarantine rows
--    that name them are NOT deleted here (the owner's order allows no delete beyond the Plankiva
--    retraction): quarantine.rule_id is ON DELETE SET NULL (0003), so they stay, with their
--    uri and hashes and rule_id NULL. After a re-ingest admits the same content, wall_audit
--    reports each of them ("quarantined (uri, sha) present in content") and the real
--    ingest exits 1. Clearing them is a separate owner step that needs the owner's explicit yes:
--    scripts/owner-sql/quarantine-lifted-rules.sql (not a migration; docs/wall.md).
-- 3. KEPT (HQ judgement calls, reported to the owner): the soft account / login-number rule, the
--    soft IBAN rule, the hard repo rule 'example-org/agent-config-backup*', the hard desk P&L
--    path and lane rules, the area rules, the undecoded-escape rule, every Plankiva rule. No
--    rule that guards a credential, token, 2FA code or password is touched.
--
-- wall_eval(), wall_norm(), pct_decode(), wall_content(), wall_check() and wall_audit() are
-- NOT replaced: verdict order, normalisation and fail-closed behaviour are those of 0009.
-- src/wall.ts mirrors the seeds (SEED_RULES = LEGACY_SEED_RULES - LIFTED_0010 - LIFTED_0011
-- + PROTECTED_SPELLING_REGEX + PROTECTED_VARIANTS_REGEX). Re-runnable. 0001-0010 are not edited.

-- ---------------------------------------------------------------------------
-- 2. Soft lift: the rules only (allows cascade; quarantine rows keep uri + hashes, rule_id NULL).
DELETE FROM zeusi.wall_denylist d
 USING (VALUES ('regex', '(USD|EUR|CHF|GBP|JPY)[ ]?[0-9]|\$[ ]?[0-9]'),
               ('regex', '(p&l|\mpnl\M|\mbook\M)[^\n]*[0-9]')) AS l(kind, pattern)
 WHERE d.kind::text = l.kind AND d.pattern = l.pattern AND NOT d.hard;

-- ---------------------------------------------------------------------------
-- 1. Plankiva: the name and its variants (hard, never allowable).
INSERT INTO zeusi.wall_denylist (kind, hard, pattern, reason, added_by) VALUES
  ('regex', true,
   'p(?:[^a-z0-9 \t\n\r\f\v]{0,3}p){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}l(?:[^a-z0-9 \t\n\r\f\v]{0,3}l){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}[a4@](?:[^a-z0-9 \t\n\r\f\v]{0,3}[a4@]){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}n(?:[^a-z0-9 \t\n\r\f\v]{0,3}n){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}k(?:[^a-z0-9 \t\n\r\f\v]{0,3}k){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}[i1!|](?:[^a-z0-9 \t\n\r\f\v]{0,3}[i1!|]){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}v(?:[^a-z0-9 \t\n\r\f\v]{0,3}v){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}[a4@](?:[^a-z0-9 \t\n\r\f\v]{0,3}[a4@]){0,2}|p(?:[^a-z0-9]{1,3}p){0,2}[^a-z0-9]{1,3}l(?:[^a-z0-9]{1,3}l){0,2}[^a-z0-9]{1,3}[a4@](?:[^a-z0-9]{1,3}[a4@]){0,2}[^a-z0-9]{1,3}n(?:[^a-z0-9]{1,3}n){0,2}[^a-z0-9]{1,3}k(?:[^a-z0-9]{1,3}k){0,2}[^a-z0-9]{1,3}[i1!|](?:[^a-z0-9]{1,3}[i1!|]){0,2}[^a-z0-9]{1,3}v(?:[^a-z0-9]{1,3}v){0,2}[^a-z0-9]{1,3}[a4@](?:[^a-z0-9]{1,3}[a4@]){0,2}',
   'the name plankiva / plankiva and its variants (repeated letters, separators, leetspeak, look-alikes; the owner hard rule 2026-11-15 01:09: Plankiva IS Plankiva); no wall_allow', 'plan-seed')
ON CONFLICT (kind, pattern) DO NOTHING;
-- A rule with this pattern added earlier by hand is hardened (the guard refuses the reverse).
UPDATE zeusi.wall_denylist SET hard = true
 WHERE kind = 'regex' AND NOT hard
   AND pattern = 'p(?:[^a-z0-9 \t\n\r\f\v]{0,3}p){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}l(?:[^a-z0-9 \t\n\r\f\v]{0,3}l){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}[a4@](?:[^a-z0-9 \t\n\r\f\v]{0,3}[a4@]){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}n(?:[^a-z0-9 \t\n\r\f\v]{0,3}n){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}k(?:[^a-z0-9 \t\n\r\f\v]{0,3}k){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}[i1!|](?:[^a-z0-9 \t\n\r\f\v]{0,3}[i1!|]){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}v(?:[^a-z0-9 \t\n\r\f\v]{0,3}v){0,2}[^a-z0-9 \t\n\r\f\v]{0,3}[a4@](?:[^a-z0-9 \t\n\r\f\v]{0,3}[a4@]){0,2}|p(?:[^a-z0-9]{1,3}p){0,2}[^a-z0-9]{1,3}l(?:[^a-z0-9]{1,3}l){0,2}[^a-z0-9]{1,3}[a4@](?:[^a-z0-9]{1,3}[a4@]){0,2}[^a-z0-9]{1,3}n(?:[^a-z0-9]{1,3}n){0,2}[^a-z0-9]{1,3}k(?:[^a-z0-9]{1,3}k){0,2}[^a-z0-9]{1,3}[i1!|](?:[^a-z0-9]{1,3}[i1!|]){0,2}[^a-z0-9]{1,3}v(?:[^a-z0-9]{1,3}v){0,2}[^a-z0-9]{1,3}[a4@](?:[^a-z0-9]{1,3}[a4@]){0,2}';
-- An allow can never pin a hard rule (the guard refuses new ones); drop any left over.
DELETE FROM zeusi.wall_allow a USING zeusi.wall_denylist d WHERE d.id = a.rule_id AND d.hard;
