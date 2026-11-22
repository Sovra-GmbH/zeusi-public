# Rollback of 0015_key_wraps_credential_unique.sql

0015 is additive: one partial UNIQUE index (`zeusi_tenants.key_wraps_tenant_credential_key`). Dropping
it returns the catalog to its C3 shape. No data changes either way.

Run as the **database owner** over the **direct** URL, when it may `SET ROLE zeusi_tenant_admin` (the
owner already holds that right). Take a Neon snapshot first. Not a migration file, so it never runs by
itself.

**Order:** first deploy code without C4 (revert the C4 commit). The C4 provisioner
(`src/tenants.ts` CONTROL_DDL) re-creates the index at the next catalog ensure (the next personal
sign-in, whatever the flag says), so a rollback under C4 code does not stick.

## SQL

```sql
BEGIN;
SET LOCAL ROLE zeusi_tenant_admin;
DROP INDEX IF EXISTS zeusi_tenants.key_wraps_tenant_credential_key;
RESET ROLE;
DELETE FROM zeusi.schema_migrations WHERE filename = '0015_key_wraps_credential_unique.sql';
COMMIT;
```

## Check afterwards

```sql
SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'key_wraps_tenant_credential_key';   -- 0
SELECT count(*) FROM zeusi.schema_migrations WHERE filename = '0015_key_wraps_credential_unique.sql';  -- 0
```
