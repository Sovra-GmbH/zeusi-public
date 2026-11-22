# Rollback of 0017_key_wraps_webauthn.sql

0017 is additive: two nullable columns (`webauthn_public_key`, `webauthn_sign_count`) and one CHECK
(`key_wraps_webauthn_check`) on `zeusi_tenants.key_wraps`. Dropping them returns the catalog to its
0016 shape.

**Data effect:** the stored WebAuthn public keys and counters are lost. A passkey wrap whose key is
dropped can no longer unlock by passkey under the verifying code (docs/plans/2026-11-19-c4-webauthn-verify.md
KTD6); its recovery wrap still works. Production held 0 rows in `key_wraps` when this was written.

Run as the **database owner** over the **direct** URL, when it may `SET ROLE zeusi_tenant_admin`. Take a
Neon snapshot first. Not a migration file, so it never runs by itself.

**Order:** first deploy code without this change (revert its commit). The verifying provisioner
(`src/tenants.ts` CONTROL_DDL) re-adds the columns at the next catalog ensure (the next personal sign-in,
whatever the flag says), so a rollback under this code does not stick.

## SQL

```sql
BEGIN;
SET LOCAL ROLE zeusi_tenant_admin;
SET LOCAL lock_timeout = '5s';
ALTER TABLE zeusi_tenants.key_wraps
  DROP CONSTRAINT IF EXISTS key_wraps_webauthn_check,
  DROP COLUMN IF EXISTS webauthn_sign_count,
  DROP COLUMN IF EXISTS webauthn_public_key;
RESET ROLE;
DELETE FROM zeusi.schema_migrations WHERE filename = '0017_key_wraps_webauthn.sql';
COMMIT;
```

## Check afterwards

```sql
SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'key_wraps' AND a.attname LIKE 'webauthn_%' AND NOT a.attisdropped;  -- 0
SELECT count(*) FROM zeusi.schema_migrations WHERE filename = '0017_key_wraps_webauthn.sql';                         -- 0
```
