-- 0016_catalog_rt_enc_state.sql — C6: the runtime login may read enc_state (one column grant)
-- (docs/plans/2026-11-19-c6-write-path.md KTD2; parent plan docs/plans/2026-11-18-zeusi-workspace-encryption.md
-- §4.5, §4.7).
--
-- STATUS: DESIGN, NOT APPLIED. Operator step after review and merge, with the owner's GO, BEFORE a C6 build is
-- deployed: a Neon branch or snapshot first, `npm start -- migrate --dry-run`, then
-- `npm start -- migrate --i-took-a-snapshot` as the database owner over the DIRECT URL.
-- Rollback: migrations/ROLLBACK-0016.md.
--
-- ADDITIVE ONLY. One column privilege: GRANT SELECT (enc_state) ON zeusi_tenants.tenants TO
-- zeusi_tenant_rt. No row is inserted, updated or deleted; no other grant changes; the runtime login
-- still has nothing on key_wraps or members and no other column of tenants beyond tenant_id, status
-- and enc_state.
--
-- WHY: the workspace write path routes on enc_state (plain in off / enrolled, sealed in verified / on,
-- refused otherwise). TenantRouter.encState (src/tenants.ts) reads it as the runtime login; without this
-- grant it gets 42501 and EVERY personal-workspace write is refused (fail closed, WRITES_OFF).
--
-- CATALOG DDL, NOT WORKSPACE DDL: listed in TENANT_EXCLUDED_FILES (src/tenant-ddl.ts).
--
-- ENSURE PATH FIRST: once C6 code is deployed, the provisioner's catalog ensure (src/tenants.ts
-- CONTROL_DDL, run at every personal sign-in whatever ZEUSI_WORKSPACE_ENCRYPTION says) grants the same
-- column. The recorded apply below then normally records itself as a no-op.
--
-- ROLE: as 0015. Skips when there is no zeusi_tenant_admin or zeusi_tenant_rt role, no catalog, or no
-- enc_state column yet (the provisioner's ensure path grants it with the column); refuses unless
-- zeusi_tenant_admin owns zeusi_tenants; no-op when the grant exists; otherwise needs SET on
-- zeusi_tenant_admin and grants under SET LOCAL ROLE zeusi_tenant_admin, so the grantor is the catalog
-- owner (the same ACL entry the ensure path makes). test/c6-catalog.test.ts pins: both paths give the
-- same catalog; re-runs are no-ops; ROLLBACK-0016.md restores the C5 ACL.

DO $m0016$
DECLARE
  owner_name text;
  rel oid;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_tenant_admin')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_tenant_rt') THEN
    RAISE NOTICE '0016: no zeusi_tenant_admin or zeusi_tenant_rt role on this database; nothing to do';
    RETURN;
  END IF;
  SELECT r.rolname INTO owner_name
    FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'zeusi_tenants';
  IF owner_name IS NULL THEN
    RAISE NOTICE '0016: zeusi_tenants does not exist yet; nothing to do (the provisioner grants the column)';
    RETURN;
  END IF;
  IF owner_name <> 'zeusi_tenant_admin' THEN
    RAISE EXCEPTION '0016: zeusi_tenants is not owned by zeusi_tenant_admin; refusing';
  END IF;
  -- Catalog lookups by oid only: a runner without USAGE on zeusi_tenants must still reach the no-op.
  SELECT c.oid INTO rel FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'tenants' AND c.relkind = 'r';
  IF rel IS NULL OR NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = rel AND attname = 'enc_state' AND NOT attisdropped) THEN
    RAISE NOTICE '0016: zeusi_tenants.tenants has no enc_state yet; nothing to do (the provisioner grants it with the column)';
    RETURN;
  END IF;
  IF has_column_privilege('zeusi_tenant_rt', rel, 'enc_state', 'SELECT') THEN
    RAISE NOTICE '0016: zeusi_tenant_rt already reads enc_state; nothing to do';
    RETURN;
  END IF;
  IF NOT pg_has_role(current_user, 'zeusi_tenant_admin', 'SET') THEN
    RAISE EXCEPTION '0016: the migration runner cannot SET ROLE zeusi_tenant_admin (the catalog owner); see docs/plans/2026-11-19-c6-write-path.md "Operator"';
  END IF;

  SET LOCAL ROLE zeusi_tenant_admin;
  GRANT SELECT (enc_state) ON zeusi_tenants.tenants TO zeusi_tenant_rt;
  RESET ROLE;
END
$m0016$;
