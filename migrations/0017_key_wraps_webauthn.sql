-- 0017_key_wraps_webauthn.sql — C4 follow-up: the verified WebAuthn credential of a passkey wrap
-- (docs/plans/2026-11-19-c4-webauthn-verify.md KTD5; closes C4 review P2-1 / docs/plans/2026-11-18-c4-enroll.md KTD9).
--
-- STATUS: DESIGN, NOT APPLIED. Operator step after review and merge, with the owner's GO: a Neon branch
-- or snapshot first, `npm start -- migrate --dry-run` (exactly this file), then
-- `npm start -- migrate --i-took-a-snapshot` as the database owner over the DIRECT URL. Rollback:
-- migrations/ROLLBACK-0017.md.
--
-- ADDITIVE ONLY. Two NULLABLE columns on zeusi_tenants.key_wraps (no default: no table rewrite) and one
-- CHECK (validated by one scan of the small catalog table under the ALTER's lock):
--   webauthn_public_key bytea   the COSE public key exactly as attested at enrollment (1..1024 bytes)
--   webauthn_sign_count bigint  the WebAuthn signature counter (0..2^32-1), advanced at each unlock
-- Both NULL (a recovery row, or a passkey row enrolled before this change: it can no longer unlock by
-- passkey, KTD6) or both set on a passkey row. No row is inserted, updated or deleted; no grant changes;
-- zeusi_tenant_rt keeps nothing on key_wraps.
--
-- CATALOG DDL, NOT WORKSPACE DDL: listed in TENANT_EXCLUDED_FILES (src/tenant-ddl.ts).
--
-- ENSURE PATH FIRST: once this code is deployed, the provisioner's catalog ensure (every personal sign-in,
-- whatever ZEUSI_WORKSPACE_ENCRYPTION says) runs the same ALTER (src/tenants.ts KEY_WRAP_WEBAUTHN_ALTER,
-- the identical statement) when the column is missing. The recorded apply below then normally records
-- itself as a no-op.
--
-- ROLE: as 0014 / 0015. Skips when there is no zeusi_tenant_admin role, no catalog, or no key_wraps yet;
-- refuses unless zeusi_tenant_admin owns zeusi_tenants; no-op when the column exists; otherwise needs SET
-- on zeusi_tenant_admin and alters under SET LOCAL ROLE zeusi_tenant_admin (lock wait at most 5 s), then
-- RESETs the role before the runner records this file. test/c4-webauthn-catalog.test.ts pins: both paths
-- give the same catalog; a runner without SET is refused; skip paths; re-runs are no-ops; ROLLBACK-0017.md.

DO $m0017$
DECLARE
  owner_name text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_tenant_admin') THEN
    RAISE NOTICE '0017: no zeusi_tenant_admin role on this database; nothing to do';
    RETURN;
  END IF;
  SELECT r.rolname INTO owner_name
    FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'zeusi_tenants';
  IF owner_name IS NULL THEN
    RAISE NOTICE '0017: zeusi_tenants does not exist yet; nothing to do (the provisioner creates the columns)';
    RETURN;
  END IF;
  IF owner_name <> 'zeusi_tenant_admin' THEN
    RAISE EXCEPTION '0017: zeusi_tenants is not owned by zeusi_tenant_admin; refusing';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'key_wraps' AND c.relkind = 'r') THEN
    RAISE NOTICE '0017: zeusi_tenants.key_wraps does not exist yet; nothing to do (the provisioner creates it with the columns)';
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'key_wraps' AND a.attname = 'webauthn_public_key' AND NOT a.attisdropped) THEN
    RAISE NOTICE '0017: key_wraps already has the WebAuthn columns; nothing to do';
    RETURN;
  END IF;
  IF NOT pg_has_role(current_user, 'zeusi_tenant_admin', 'SET') THEN
    RAISE EXCEPTION '0017: the migration runner cannot SET ROLE zeusi_tenant_admin (the catalog owner); see docs/plans/2026-11-19-c4-webauthn-verify.md';
  END IF;

  SET LOCAL ROLE zeusi_tenant_admin;
  SET LOCAL lock_timeout = '5s';
  ALTER TABLE zeusi_tenants.key_wraps
    ADD COLUMN webauthn_public_key bytea,
    ADD COLUMN webauthn_sign_count bigint,
    ADD CONSTRAINT key_wraps_webauthn_check CHECK (
      (webauthn_public_key IS NULL AND webauthn_sign_count IS NULL)
      OR (kind = 'passkey' AND webauthn_public_key IS NOT NULL AND webauthn_sign_count IS NOT NULL
          AND octet_length(webauthn_public_key) BETWEEN 1 AND 1024
          AND webauthn_sign_count BETWEEN 0 AND 4294967295));
  RESET ROLE;
END
$m0017$;
