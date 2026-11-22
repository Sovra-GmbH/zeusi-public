-- tenant-writer-role.sql: the writer login behind personal-workspace writes (import preview/commit,
-- nightly sync). docs/plans/2026-11-18-workspace-write-import-plan.md KTD3, KTD4;
-- docs/hosting.md "Workspace writes".
--
-- NOT a migration: it lives outside migrations/, so `zeusi migrate` never applies it, and the
-- workspace DDL (src/tenant-ddl.ts) never sees it. An OPERATOR STEP, in this order:
--   1. take a Neon backup branch (snapshot) first;
--   2. run this file as the database owner, only when the owner says go (after tenant-roles.sql);
--   3. set the zeusi_tenant_wr password OUT OF BAND (1Password item), like the other logins;
--   4. run `zeusi workspaces backfill-writers --admin-service zeusi_tenant_admin` (dry run, then
--      --real): it creates each existing workspace's writer role zt_<id>_w as zeusi_tenant_admin and
--      grants it to zeusi_tenant_wr. New workspaces get theirs at provisioning.
-- Idempotent: safe to re-run. NO PASSWORD here: the login cannot log in until step 3.
--
--   zeusi_tenant_wr  serves workspace writes. NOINHERIT: it never uses a workspace writer role's
--                    privileges implicitly; each session runs SET ROLE zt_<id>_w and is then checked
--                    (src/tenants.ts TenantWriter): exactly that role, USAGE on its own schema only,
--                    none on zeusi, zeusi_tenants or any other zt_* schema, no write privilege outside
--                    its own schema. Not read-only (it writes), low connection limit, statement timeout.
--                    It gets NOTHING on schema zeusi and nothing on schema zeusi_tenants.
--
-- Not a member of zeusi_read, zeusi_ingest, zeusi_agent_write, zeusi_backup, zeusi_decision_write,
-- zeusi_tenant_rt or zeusi_tenant_admin. Requires PostgreSQL 16 or later. No Neon API involved.

DO $$
BEGIN
  IF current_setting('server_version_num')::int < 160000 THEN
    RAISE EXCEPTION 'tenant-writer-role.sql needs PostgreSQL 16 or later';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_tenant_wr') THEN
    CREATE ROLE zeusi_tenant_wr LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 4;
  ELSE
    ALTER ROLE zeusi_tenant_wr LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 4;
  END IF;
  -- Belt and braces: nothing on the workspace catalog, whatever an earlier grant gave.
  IF to_regnamespace('zeusi_tenants') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL ON SCHEMA zeusi_tenants FROM zeusi_tenant_wr';
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA zeusi_tenants FROM zeusi_tenant_wr';
  END IF;
END $$;

ALTER ROLE zeusi_tenant_wr SET statement_timeout = '30s';
ALTER ROLE zeusi_tenant_wr SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_tenant_wr SET default_transaction_read_only = off;

-- Belt and braces: nothing on the zeusi schema, whatever PUBLIC or an earlier grant gave.
REVOKE ALL ON SCHEMA zeusi FROM zeusi_tenant_wr;
REVOKE ALL ON ALL TABLES IN SCHEMA zeusi FROM zeusi_tenant_wr;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA zeusi FROM zeusi_tenant_wr;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zeusi FROM zeusi_tenant_wr;

-- Read-back (run after the file; every row must match the comment on its right):
--   SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolconnlimit
--     FROM pg_roles WHERE rolname = 'zeusi_tenant_wr';
--       -> zeusi_tenant_wr | t | f | f | f | f | f | 4
--   SELECT has_schema_privilege('zeusi_tenant_wr', 'zeusi', 'USAGE') AS team,
--          has_schema_privilege('zeusi_tenant_wr', 'zeusi_tenants', 'USAGE') AS catalog;
--       -> f | f
--   SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
--    WHERE u.rolname = 'zeusi_tenant_wr' AND (r.rolname !~ '^zt_[a-z2-7]{26}_w$' OR m.inherit_option OR NOT m.set_option);
--       -> 0   (only workspace writer roles, each SET TRUE, INHERIT FALSE)
--   SELECT setconfig FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole WHERE r.rolname = 'zeusi_tenant_wr';
--       -> {statement_timeout=30s,idle_in_transaction_session_timeout=30s,default_transaction_read_only=off}
