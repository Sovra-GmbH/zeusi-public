-- tenant-roles.sql: the two logins behind personal workspaces (open sign-up).
-- docs/plans/2026-11-18-open-signup-workspaces-plan.md KTD2, KTD6; docs/hosting.md "Workspaces".
--
-- NOT a migration: it lives outside migrations/, so `zeusi migrate` never applies it, and the
-- workspace DDL (src/tenant-ddl.ts) never sees it. An OPERATOR STEP: run it as the database owner,
-- after a snapshot, only when the owner says go. Idempotent: safe to re-run.
--
-- NO PASSWORDS here. Both logins cannot log in until the operator sets a password out of band
-- (stored in 1Password, one item per login), exactly like the 0004 logins (docs/roles.md).
--
--   zeusi_tenant_admin  provisions personal workspaces: CREATE on this database (its own schemas),
--                       CREATEROLE (PostgreSQL 16+: it can only administer roles it created). It owns
--                       the control schema zeusi_tenants and every zt_* schema. It gets NOTHING on
--                       schema zeusi: no USAGE, no table, no function.
--   zeusi_tenant_rt     serves requests. NOINHERIT: it never uses a workspace role's privileges
--                       implicitly; each session runs SET ROLE <workspace>_r and is then checked
--                       (src/tenants.ts). It gets NOTHING on schema zeusi either.
--
-- Neither is a member of zeusi_read, zeusi_ingest, zeusi_agent_write, zeusi_backup or
-- zeusi_decision_write. Requires PostgreSQL 16 or later (CREATEROLE scoping, membership SET option).
-- No Neon API and no neon_superuser membership is involved.

DO $$
BEGIN
  IF current_setting('server_version_num')::int < 160000 THEN
    RAISE EXCEPTION 'tenant-roles.sql needs PostgreSQL 16 or later';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_tenant_admin') THEN
    CREATE ROLE zeusi_tenant_admin LOGIN NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 2;
  ELSE
    ALTER ROLE zeusi_tenant_admin NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 2;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zeusi_tenant_rt') THEN
    CREATE ROLE zeusi_tenant_rt LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 10;
  ELSE
    ALTER ROLE zeusi_tenant_rt NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 10;
  END IF;
  -- The provisioner creates schemas in this database (zeusi_tenants and zt_*), nothing else.
  EXECUTE format('GRANT CREATE ON DATABASE %I TO zeusi_tenant_admin', current_database());
END $$;

ALTER ROLE zeusi_tenant_admin SET statement_timeout = '60s';
ALTER ROLE zeusi_tenant_admin SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_tenant_rt    SET statement_timeout = '15s';
ALTER ROLE zeusi_tenant_rt    SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE zeusi_tenant_rt    SET default_transaction_read_only = on;

-- Belt and braces: nothing on the zeusi schema, whatever PUBLIC or an earlier grant gave.
REVOKE ALL ON SCHEMA zeusi FROM zeusi_tenant_admin, zeusi_tenant_rt;
REVOKE ALL ON ALL TABLES IN SCHEMA zeusi FROM zeusi_tenant_admin, zeusi_tenant_rt;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA zeusi FROM zeusi_tenant_admin, zeusi_tenant_rt;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA zeusi FROM zeusi_tenant_admin, zeusi_tenant_rt;
