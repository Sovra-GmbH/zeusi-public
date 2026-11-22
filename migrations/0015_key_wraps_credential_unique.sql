-- 0015_key_wraps_credential_unique.sql — C4: one live wrap row per (workspace, passkey credential)
-- (docs/plans/2026-11-18-c4-enroll.md KTD1; parent plan docs/plans/2026-11-18-zeusi-workspace-encryption.md
-- §4.5, D14).
--
-- STATUS: DESIGN, NOT APPLIED. Operator step after review and merge, with the owner's GO: a Neon branch
-- or snapshot first, `npm start -- migrate --dry-run`, then `npm start -- migrate --i-took-a-snapshot`
-- as the database owner over the DIRECT URL. Rollback: migrations/ROLLBACK-0015.md.
--
-- ADDITIVE ONLY. One partial UNIQUE index on zeusi_tenants.key_wraps (tenant_id, credential_id)
-- WHERE credential_id IS NOT NULL: recovery rows (NULL credential id) are not constrained. No row is
-- inserted, updated or deleted; no grant changes; zeusi_tenant_rt keeps SELECT (tenant_id, status)
-- on tenants only and nothing on key_wraps. If two rows already shared a credential id the CREATE
-- fails and nothing is applied (C3 left key_wraps empty, so none can).
--
-- CATALOG DDL, NOT WORKSPACE DDL: listed in TENANT_EXCLUDED_FILES (src/tenant-ddl.ts).
--
-- ENSURE PATH FIRST: once C4 code is deployed, the provisioner's catalog ensure (run at every personal
-- sign-in, whatever ZEUSI_WORKSPACE_ENCRYPTION says) creates this same index on its first run. The
-- recorded apply below then normally records itself as a no-op.
--
-- ROLE: as 0014. Skips when there is no zeusi_tenant_admin role, no catalog, or no key_wraps yet (the
-- provisioner's ensure path, src/tenants.ts CONTROL_DDL, creates the index with the table); refuses
-- unless zeusi_tenant_admin owns zeusi_tenants; no-op when the index exists; otherwise needs SET on
-- zeusi_tenant_admin and builds the index under SET LOCAL ROLE zeusi_tenant_admin, so the catalog
-- owner owns it. test/c4-catalog.test.ts pins: both paths give the same catalog; re-runs are no-ops.

DO $m0015$
DECLARE
  owner_name text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_tenant_admin') THEN
    RAISE NOTICE '0015: no zeusi_tenant_admin role on this database; nothing to do';
    RETURN;
  END IF;
  SELECT r.rolname INTO owner_name
    FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'zeusi_tenants';
  IF owner_name IS NULL THEN
    RAISE NOTICE '0015: zeusi_tenants does not exist yet; nothing to do (the provisioner creates the index)';
    RETURN;
  END IF;
  IF owner_name <> 'zeusi_tenant_admin' THEN
    RAISE EXCEPTION '0015: zeusi_tenants is not owned by zeusi_tenant_admin; refusing';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'key_wraps' AND c.relkind = 'r') THEN
    RAISE NOTICE '0015: zeusi_tenants.key_wraps does not exist yet; nothing to do (the provisioner creates it with the index)';
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'key_wraps_tenant_credential_key') THEN
    RAISE NOTICE '0015: the credential index already exists; nothing to do';
    RETURN;
  END IF;
  IF NOT pg_has_role(current_user, 'zeusi_tenant_admin', 'SET') THEN
    RAISE EXCEPTION '0015: the migration runner cannot SET ROLE zeusi_tenant_admin (the catalog owner); see docs/plans/2026-11-18-c4-enroll.md "Operator apply"';
  END IF;

  SET LOCAL ROLE zeusi_tenant_admin;
  SET LOCAL lock_timeout = '5s';
  CREATE UNIQUE INDEX IF NOT EXISTS key_wraps_tenant_credential_key
    ON zeusi_tenants.key_wraps (tenant_id, credential_id) WHERE credential_id IS NOT NULL;
  RESET ROLE;
END
$m0015$;
