// Role catalog checks (PLAN.md KTD9, KTD10, U3). Read-only: pg_roles + pg_has_role
// only, so `zeusi doctor --roles` can run them as zeusi_mini_backup against Neon.
// Live behaviour (15 s cancel, 6th connection refused) needs a Neon branch; these
// checks assert the settings that implement it.

import type { Db } from './db.ts';

export interface ExpectedLogin {
  role: string;
  group: string;
  connLimit: number;
  /** rolconfig entries that must be present, exactly as Postgres prints them. */
  config: string[];
  /** Groups this login must NOT be a member of (directly or inherited). */
  notMemberOf?: string[];
}

/** A login + group from a migration that may not be applied yet (doctor passes either way). */
export interface OptionalLogin extends ExpectedLogin {
  migration: string;
}

const IDLE = 'idle_in_transaction_session_timeout=30s';
const PATH = 'search_path=zeusi, public';

/** Mirrors migrations/0004_roles.sql. */
export const EXPECTED_LOGINS: readonly ExpectedLogin[] = [
  { role: 'zeusi_mini_ingest', group: 'zeusi_ingest', connLimit: 4, config: ['statement_timeout=120s', IDLE, PATH] },
  { role: 'zeusi_mini_backup', group: 'zeusi_backup', connLimit: 2, config: ['statement_timeout=0', 'default_transaction_read_only=off', IDLE, PATH] },
  { role: 'zeusi_box_rw', group: 'zeusi_agent_write', connLimit: 5, config: ['statement_timeout=30s', IDLE, PATH] },
  { role: 'zeusi_box_ro', group: 'zeusi_read', connLimit: 5, config: ['statement_timeout=30s', 'default_transaction_read_only=on', IDLE, PATH] },
  { role: 'zeusi_cloud_ro', group: 'zeusi_read', connLimit: 5, config: ['statement_timeout=15s', 'default_transaction_read_only=on', IDLE, PATH] },
];

export const EXPECTED_GROUPS = ['zeusi_read', 'zeusi_agent_write', 'zeusi_ingest', 'zeusi_backup'] as const;

/**
 * Mirrors migrations/0012_decision_write_role.sql (NOT applied on Neon yet). When neither the
 * login nor its group exists, doctor reports "not applied" and passes; once either exists, the
 * full checks run (a half-applied role fails).
 */
export const OPTIONAL_LOGINS: readonly OptionalLogin[] = [
  {
    role: 'zeusi_box_decision', group: 'zeusi_decision_write', connLimit: 5, migration: '0012',
    config: ['statement_timeout=30s', IDLE, PATH],
    notMemberOf: ['zeusi_agent_write', 'zeusi_ingest', 'zeusi_backup'],
  },
];

export interface RoleCheck {
  check: string;
  ok: boolean;
  detail: string;
}

interface RoleRow {
  rolname: string;
  rolcanlogin: boolean;
  rolsuper: boolean;
  rolcreaterole: boolean;
  rolcreatedb: boolean;
  rolreplication: boolean;
  rolbypassrls: boolean;
  rolconnlimit: number;
  rolconfig: string[] | null;
}

export async function roleCatalogChecks(db: Db): Promise<RoleCheck[]> {
  const names = [...EXPECTED_LOGINS.map((l) => l.role), ...EXPECTED_GROUPS, ...OPTIONAL_LOGINS.flatMap((l) => [l.role, l.group])];
  const rows = (await db.query<RoleRow>(
    `SELECT rolname, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolconnlimit, rolconfig
     FROM pg_roles WHERE rolname = ANY($1)`,
    [names],
  )).rows;
  const byName = new Map(rows.map((r) => [r.rolname, r]));
  const neonSuper = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_roles WHERE rolname = 'neon_superuser'`)).rows[0]!.n > 0;
  const out: RoleCheck[] = [];
  const add = (check: string, ok: boolean, detail = '') => out.push({ check, ok, detail });

  for (const g of EXPECTED_GROUPS) {
    const r = byName.get(g);
    add(`${g} exists and is NOLOGIN`, !!r && !r.rolcanlogin, r ? (r.rolcanlogin ? 'can log in' : 'nologin') : 'missing');
  }

  const logins: ExpectedLogin[] = [...EXPECTED_LOGINS];
  for (const o of OPTIONAL_LOGINS) {
    if (!byName.has(o.role) && !byName.has(o.group)) {
      add(`${o.role} (${o.migration}) not applied`, true, `absent: ${o.migration} not applied`);
      continue;
    }
    const g = byName.get(o.group);
    add(`${o.group} exists and is NOLOGIN`, !!g && !g.rolcanlogin, g ? (g.rolcanlogin ? 'can log in' : 'nologin') : 'missing');
    logins.push(o);
  }

  for (const l of logins) {
    const r = byName.get(l.role);
    if (!r) {
      add(`${l.role} exists and can log in`, false, 'missing');
      continue;
    }
    add(`${l.role} exists and can log in`, r.rolcanlogin, r.rolcanlogin ? 'login' : 'nologin');
    const elevated = (['rolsuper', 'rolcreaterole', 'rolcreatedb', 'rolreplication', 'rolbypassrls'] as const).filter((k) => r[k]);
    add(`${l.role} has no elevated attributes`, elevated.length === 0, elevated.length ? elevated.join(', ') : 'none');
    add(`${l.role} CONNECTION LIMIT ${l.connLimit}`, r.rolconnlimit === l.connLimit, `rolconnlimit=${r.rolconnlimit}`);
    const cfg = r.rolconfig ?? [];
    const missing = l.config.filter((c) => !cfg.includes(c));
    add(`${l.role} session settings`, missing.length === 0, missing.length ? `missing: ${missing.join('; ')}` : l.config.join('; '));
    const member = (await db.query<{ m: boolean }>(`SELECT pg_has_role($1, $2, 'MEMBER') AS m`, [l.role, l.group])).rows[0]!.m;
    add(`${l.role} is a member of ${l.group}`, member, member ? 'yes' : 'no');
    for (const other of l.notMemberOf ?? []) {
      const m = (await db.query<{ m: boolean }>(
        `SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $2) THEN pg_has_role($1, $2, 'MEMBER') ELSE false END AS m`, [l.role, other])).rows[0]!.m;
      add(`${l.role} is not a member of ${other}`, !m, m ? 'MEMBER' : 'not a member');
    }
    if (neonSuper) {
      const sup = (await db.query<{ m: boolean }>(`SELECT pg_has_role($1, 'neon_superuser', 'MEMBER') AS m`, [l.role])).rows[0]!.m;
      add(`${l.role} is not in neon_superuser`, !sup, sup ? 'MEMBER of neon_superuser' : 'not a member');
    } else {
      add(`${l.role} is not in neon_superuser`, true, 'neon_superuser absent (not a Neon server)');
    }
  }
  return out;
}

export function formatRoleChecks(checks: RoleCheck[]): string {
  const failed = checks.filter((c) => !c.ok).length;
  return [
    ...checks.map((c) => `  ${c.ok ? 'PASS' : 'FAIL'}  ${c.check}${c.detail ? ` — ${c.detail}` : ''}`),
    `roles: ${checks.length - failed}/${checks.length} checks pass`,
  ].join('\n');
}
