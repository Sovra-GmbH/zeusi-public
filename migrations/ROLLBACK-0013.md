# Rollback of 0013_decision_links.sql

0013 is additive: one enum, one table (with its sequence, index, triggers, RLS policies and
grants), two trigger functions and one audit function. Nothing else was changed, so dropping exactly these objects
returns the schema to its 0012 state. Run as the **owner** over the **direct** URL, in one
transaction. Take a Neon snapshot first. Not a migration file (`zeusi migrate` only reads
`NNNN_name.sql`), so it never runs by itself.

**Data:** this deletes every row in `zeusi.decision_links`. Decisions, their `linked_repo` /
`linked_pr` columns and every other table are untouched. To keep the links, export them first
(as `zeusi_mini_backup`, which can read every row):

```sh
pg_dump -Fc --enable-row-security -t zeusi.decision_links "service=zeusi_backup" > decision_links-$(date +%Y%m%d).dump
```

## SQL

```sql
BEGIN;
DROP TABLE zeusi.decision_links;                    -- its sequence, index, triggers, policies and grants go with it
DROP FUNCTION zeusi.decision_links_wall_audit();
DROP FUNCTION zeusi.decision_link_wall_check();
DROP FUNCTION zeusi.decision_links_inherit();
DROP TYPE zeusi.link_target_kind;
DELETE FROM zeusi.schema_migrations WHERE filename = '0013_decision_links.sql';
COMMIT;
```

`zeusi.quarantine` rows with `target_table = 'decision_links'` hold only uris and hashes; they
stay (the table has no FK to `decision_links`).

## Check afterwards

```sql
SELECT to_regclass('zeusi.decision_links');                                         -- NULL
SELECT count(*) FROM pg_type WHERE typname = 'link_target_kind';                    -- 0
SELECT count(*) FROM pg_proc WHERE proname IN ('decision_link_wall_check', 'decision_links_inherit', 'decision_links_wall_audit');  -- 0
SELECT max(filename) FROM zeusi.schema_migrations;                                  -- 0012_decision_write_role.sql
```

The application keeps working without the table: every reader checks
`to_regclass('zeusi.decision_links')` and returns `links: []`; `zeusi_log_decision` refuses a
call that carries `links` (nothing written); structured imports count links as `links_skipped`.
`npm run migrate -- --dry-run` lists `0013_decision_links.sql` as pending again.

Tested on PGlite: `test/decision-links.test.ts` ("rollback SQL").
