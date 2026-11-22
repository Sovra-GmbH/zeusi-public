-- 0014_catalog_key_wraps.sql — C3: catalog zeusi_tenants.key_wraps and tenants.enc_state
-- (docs/plans/2026-11-18-c3-catalog-enc-state.md; parent plan
-- docs/plans/2026-11-18-zeusi-workspace-encryption.md §4.1, §5.2 step 2, §5.2a, §8.2 row C3).
--
-- STATUS: DESIGN, NOT APPLIED. Operator step after review and merge, with the owner's GO: a Neon branch
-- or snapshot first, `npm start -- migrate --dry-run`, then `npm start -- migrate --i-took-a-snapshot`
-- as the database owner over the DIRECT URL. Rollback while unused: migrations/ROLLBACK-0014.md.
--
-- ADDITIVE ONLY. One new empty table (zeusi_tenants.key_wraps) and one new column
-- (zeusi_tenants.tenants.enc_state, NOT NULL DEFAULT 'off': no table rewrite, every existing row
-- reads 'off'; the CHECK is validated by one scan of the small catalog table under the ALTER's lock). No row is inserted, updated or deleted; status, members and every zt_* workspace
-- schema are untouched. No unwrap, no wrap: C3 only makes room for C4.
--
-- CATALOG DDL, NOT WORKSPACE DDL: listed in TENANT_EXCLUDED_FILES (src/tenant-ddl.ts), so it is never
-- replayed into a workspace schema.
--
-- ROLE. zeusi_tenants and its tables are owned by zeusi_tenant_admin
-- (scripts/owner-sql/tenant-roles.sql), and must stay so: the hosted provisioner manages them. The
-- migration runner is the database owner (it records this file in zeusi.schema_migrations, which
-- zeusi_tenant_admin cannot reach). So this block:
--   1. skips when the role zeusi_tenant_admin does not exist (no personal workspaces on this DB);
--   2. skips when zeusi_tenants does not exist yet (the provisioner creates the full C3 shape on
--      first use, src/tenants.ts CONTROL_DDL);
--   3. refuses unless zeusi_tenant_admin owns zeusi_tenants;
--   4. is a no-op when the catalog already has enc_state and key_wraps (the provisioner's ensure path
--      got there first); no role switch is needed then;
--   5. otherwise refuses unless the runner may SET ROLE zeusi_tenant_admin, then applies the same DDL
--      as src/tenants.ts CONTROL_DDL under SET LOCAL ROLE zeusi_tenant_admin, and RESETs the role
--      before the runner writes its schema_migrations row.
-- No superuser is needed and this file grants nothing new. test/c3-catalog.test.ts pins: both paths
-- give the same catalog; a non-superuser runner with SET works; one without SET is refused and
-- nothing changes; re-running is a no-op.
--
-- key_version CHECK 1..32767 = MAX_KEY_VERSION in src/crypto-envelope.ts (the smallint maximum;
-- 32768 is refused by the type). tenant_id, wrap_id and key_version are stored exactly as wrapAad
-- takes them. sealed_dek is a C1 wrapped DEK: 0x01 || nonce(12) || ct(32) || tag(16) = 61 bytes.
-- wrap_id follows the C1 opaque-id rule: 1..255 UTF-8 bytes, no control characters.
-- Privileges: nothing to PUBLIC on key_wraps, no grant to zeusi_tenant_rt / zeusi_tenant_wr / any
-- workspace role; zeusi_tenant_rt keeps SELECT (tenant_id, status) on tenants only.

DO $m0014$
DECLARE
  owner_name text;
  has_col    boolean;
  has_wraps  boolean;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_tenant_admin') THEN
    RAISE NOTICE '0014: no zeusi_tenant_admin role on this database; nothing to do (the provisioner creates the C3 catalog shape)';
    RETURN;
  END IF;
  SELECT r.rolname INTO owner_name
    FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'zeusi_tenants';
  IF owner_name IS NULL THEN
    RAISE NOTICE '0014: zeusi_tenants does not exist yet; nothing to do (the provisioner creates the C3 catalog shape)';
    RETURN;
  END IF;
  IF owner_name <> 'zeusi_tenant_admin' THEN
    RAISE EXCEPTION '0014: zeusi_tenants is not owned by zeusi_tenant_admin; refusing';
  END IF;
  SELECT EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'tenants' AND a.attname = 'enc_state' AND NOT a.attisdropped)
    INTO has_col;
  SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'zeusi_tenants' AND c.relname = 'key_wraps' AND c.relkind = 'r')
    INTO has_wraps;
  IF has_col AND has_wraps THEN
    RAISE NOTICE '0014: catalog already has enc_state and key_wraps; nothing to do';
    RETURN;
  END IF;
  IF NOT pg_has_role(current_user, 'zeusi_tenant_admin', 'SET') THEN
    RAISE EXCEPTION '0014: the migration runner cannot SET ROLE zeusi_tenant_admin (the catalog owner); see docs/plans/2026-11-18-c3-catalog-enc-state.md "Operator apply"';
  END IF;

  SET LOCAL ROLE zeusi_tenant_admin;
  -- ADD COLUMN takes ACCESS EXCLUSIVE on tenants: wait at most 5 s for it (fail cleanly, nothing
  -- applied) rather than queue every hosted router check behind it. Same bound as the ensure path.
  SET LOCAL lock_timeout = '5s';

  CREATE TABLE IF NOT EXISTS zeusi_tenants.tenants (
    tenant_id  text PRIMARY KEY CHECK (tenant_id ~ '^zt_[a-z2-7]{26}$'),
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    enc_state  text NOT NULL DEFAULT 'off' CONSTRAINT tenants_enc_state_check CHECK (enc_state IN ('off', 'enrolled', 'encrypting', 'verified', 'on', 'decrypting', 'decrypted'))
  );
  ALTER TABLE zeusi_tenants.tenants ADD COLUMN IF NOT EXISTS enc_state text NOT NULL DEFAULT 'off'
    CONSTRAINT tenants_enc_state_check CHECK (enc_state IN ('off', 'enrolled', 'encrypting', 'verified', 'on', 'decrypting', 'decrypted'));
  CREATE TABLE IF NOT EXISTS zeusi_tenants.members (
    subject    text PRIMARY KEY CHECK (subject ~ '^github:[0-9]{1,20}$'),
    tenant_id  text NOT NULL UNIQUE REFERENCES zeusi_tenants.tenants(tenant_id),
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE IF NOT EXISTS zeusi_tenants.key_wraps (
    tenant_id     text NOT NULL REFERENCES zeusi_tenants.tenants(tenant_id),
    wrap_id       text NOT NULL CONSTRAINT key_wraps_wrap_id_check CHECK (octet_length(wrap_id) BETWEEN 1 AND 255 AND wrap_id !~ '[\x01-\x1f\x7f]'),
    kind          text NOT NULL CONSTRAINT key_wraps_kind_check CHECK (kind IN ('passkey', 'recovery')),
    key_version   smallint NOT NULL CONSTRAINT key_wraps_key_version_check CHECK (key_version BETWEEN 1 AND 32767),
    sealed_dek    bytea NOT NULL CONSTRAINT key_wraps_sealed_dek_check CHECK (octet_length(sealed_dek) = 61 AND substring(sealed_dek FROM 1 FOR 1) = '\x01'::bytea),
    credential_id bytea,
    prf_salt      bytea,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT key_wraps_pkey PRIMARY KEY (tenant_id, wrap_id),
    CONSTRAINT key_wraps_shape_check CHECK (
      (kind = 'passkey' AND credential_id IS NOT NULL AND prf_salt IS NOT NULL
       AND octet_length(credential_id) BETWEEN 1 AND 1023 AND octet_length(prf_salt) = 32)
      OR (kind = 'recovery' AND credential_id IS NULL AND prf_salt IS NULL))
  );
  REVOKE ALL ON SCHEMA zeusi_tenants FROM PUBLIC;
  REVOKE ALL ON ALL TABLES IN SCHEMA zeusi_tenants FROM PUBLIC;
  REVOKE ALL ON zeusi_tenants.key_wraps FROM PUBLIC;
  GRANT USAGE ON SCHEMA zeusi_tenants TO zeusi_tenant_rt;
  GRANT SELECT (tenant_id, status) ON zeusi_tenants.tenants TO zeusi_tenant_rt;

  RESET ROLE;
END
$m0014$;
