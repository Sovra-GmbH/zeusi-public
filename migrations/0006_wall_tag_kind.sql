-- 0006_wall_tag_kind.sql — add the 'tag' wall rule kind (the owner's Plankiva hard rule,
-- 14 Nov 2026 14:17 Zurich). Its own file because a new enum value cannot be used
-- in the transaction that adds it, and `zeusi migrate` runs one transaction per
-- file. 0007_wall_protected_name.sql seeds and uses it.
ALTER TYPE zeusi.wall_rule_kind ADD VALUE IF NOT EXISTS 'tag' AFTER 'repo';
