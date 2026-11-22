# Rollback of 0014_catalog_key_wraps.sql

0014 is additive: one empty table (`zeusi_tenants.key_wraps`) and one column
(`zeusi_tenants.tenants.enc_state`, default `off`). Dropping exactly those returns the catalog to
its pre-C3 shape. Only **while unused**: no wrap row stored, every workspace still `off`. The SQL
refuses otherwise.

Run as the **database owner** over the **direct** URL, in one transaction, when the owner may
`SET ROLE zeusi_tenant_admin` (the catalog stays owned by `zeusi_tenant_admin`). If it may not (the
apply went through the provisioner's ensure path instead, plan "Operator apply" 2b), use the
two-step variant below. Take a Neon snapshot first. Not a migration file (`zeusi migrate` only
reads `NNNN_name.sql`), so it never runs by itself.

**Order:** first deploy code without C3 (revert the C3 commit). The C3 provisioner
(`src/tenants.ts` CONTROL_DDL) re-adds both objects at the next sign-in or workspace command, so a
rollback under C3 code does not stick.

**Data:** none. The guard below proves `key_wraps` is empty and no `enc_state` differs from `off`.
`status`, `members` and every `zt_*` workspace schema are untouched.

## SQL

```sql
BEGIN;
SET LOCAL ROLE zeusi_tenant_admin;
DO $r0014$
BEGIN
  IF EXISTS (SELECT 1 FROM zeusi_tenants.key_wraps) OR EXISTS (SELECT 1 FROM zeusi_tenants.tenants WHERE enc_state <> 'off') THEN
    RAISE EXCEPTION 'ROLLBACK-0014: key_wraps holds rows or a workspace is not off; refusing (not unused)';
  END IF;
END
$r0014$;
DROP TABLE zeusi_tenants.key_wraps;
ALTER TABLE zeusi_tenants.tenants DROP COLUMN enc_state;   -- its CHECK goes with it
RESET ROLE;
DELETE FROM zeusi.schema_migrations WHERE filename = '0014_catalog_key_wraps.sql';
COMMIT;
```

### Variant without the SET ROLE right

1. As `zeusi_tenant_admin` (`psql "service=zeusi_tenant_admin"`): the SQL above from the `DO` block to
   the `ALTER TABLE ... DROP COLUMN`, inside `BEGIN; ... COMMIT;`, without `SET LOCAL ROLE` / `RESET ROLE`.
2. As the database owner: `DELETE FROM zeusi.schema_migrations WHERE filename = '0014_catalog_key_wraps.sql';`

## Check afterwards

```sql
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'key_wraps';                     -- 0
SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'tenants' AND a.attname = 'enc_state' AND NOT a.attisdropped;  -- 0
SELECT count(*) FROM zeusi.schema_migrations WHERE filename = '0014_catalog_key_wraps.sql';  -- 0
```

`test/c3-catalog.test.ts` runs this SQL on PGlite and pins the result.
