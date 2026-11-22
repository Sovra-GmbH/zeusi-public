# Rollback of 0016_catalog_rt_enc_state.sql

0016 is additive: one column privilege, `SELECT (enc_state)` on `zeusi_tenants.tenants` for
`zeusi_tenant_rt`. Revoking it returns the catalog ACL to its C5 shape (the runtime login reads
`tenant_id, status` only). No data changes either way.

**Effect while C6 code is deployed:** `TenantRouter.encState` gets 42501 and every personal-workspace
write is refused (fail closed, `WRITES_OFF`). Reads are unaffected. So revert the C6 code first.

Run as the **database owner** over the **direct** URL, when it may `SET ROLE zeusi_tenant_admin` (the
owner already holds that right). Take a Neon snapshot first. Not a migration file, so it never runs by
itself.

**Order:** first deploy code without C6 (revert the C6 commit). The C6 provisioner
(`src/tenants.ts` CONTROL_DDL) re-grants the column at the next catalog ensure (the next personal
sign-in, whatever the flag says), so a rollback under C6 code does not stick.

## SQL

```sql
BEGIN;
SET LOCAL ROLE zeusi_tenant_admin;
REVOKE SELECT (enc_state) ON zeusi_tenants.tenants FROM zeusi_tenant_rt;
RESET ROLE;
DELETE FROM zeusi.schema_migrations WHERE filename = '0016_catalog_rt_enc_state.sql';
COMMIT;
```

## Check afterwards

```sql
SELECT has_column_privilege('zeusi_tenant_rt', 'zeusi_tenants.tenants', 'enc_state', 'SELECT');        -- false
SELECT has_column_privilege('zeusi_tenant_rt', 'zeusi_tenants.tenants', 'status', 'SELECT');           -- true
SELECT count(*) FROM zeusi.schema_migrations WHERE filename = '0016_catalog_rt_enc_state.sql';           -- 0
```
