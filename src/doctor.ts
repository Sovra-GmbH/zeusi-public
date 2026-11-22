// `zeusi doctor` (PLAN.md U1 verification): connect as the role, print TLS yes/no,
// server major version, pgvector present. Never prints a host, URL, user secret, or
// password. `doctor --roles` adds the read-only role catalog checks (src/roles.ts).
//
// Over the serverless transport (ZEUSI_TRANSPORT=serverless, src/transport.ts) doctor runs
// inside BEGIN READ ONLY and reports honestly: TLS yes (verified wss), channel binding NO
// (password over verified TLS, the documented exception), never "SCRAM-SHA-256-PLUS".

import type { Db } from './db.ts';
import { redact } from './db.ts';

export interface DoctorInfo {
  service: string;
  role: string;
  /** tcp (or absent): pg over 5432 (src/db.ts). serverless: wss over 443 (src/transport.ts). */
  transport?: 'tcp' | 'serverless';
  tls: boolean | null;
  channelBinding: boolean | null;
  serverMajor: number;
  serverVersion: string;
  pgvector: string | null;
  /** null when the role cannot read zeusi.schema_migrations. */
  migrations: string[] | null;
}

export async function collectDoctor(db: Db, service: string): Promise<DoctorInfo> {
  const r = (await db.query<{ role: string; num: string; ver: string }>(
    `SELECT current_user AS role, current_setting('server_version_num') AS num, current_setting('server_version') AS ver`,
  )).rows[0]!;
  const vec = (await db.query<{ v: string }>(`SELECT extversion AS v FROM pg_extension WHERE extname = 'vector'`)).rows[0];
  let migrations: string[] | null = null;
  const can = (await db.query<{ ok: boolean | null }>(
    `SELECT CASE WHEN to_regclass('zeusi.schema_migrations') IS NULL THEN NULL
                 ELSE has_table_privilege('zeusi.schema_migrations', 'SELECT') END AS ok`,
  )).rows[0]!.ok;
  if (can) {
    migrations = (await db.query<{ f: string }>(`SELECT filename AS f FROM zeusi.schema_migrations ORDER BY filename`)).rows.map((x) => x.f);
  }
  return {
    service,
    role: r.role,
    transport: db.transport?.kind ?? 'tcp',
    tls: db.transport?.tls ?? null,
    channelBinding: db.transport?.channelBinding ?? null,
    serverMajor: Math.floor(Number(r.num) / 10000),
    serverVersion: r.ver.split(' ')[0] ?? r.ver,
    pgvector: vec?.v ?? null,
    migrations,
  };
}

const yn = (b: boolean | null) => (b === null ? 'n/a' : b ? 'yes' : 'no');

/** Exit 0 only with TLS, pgvector, and channel binding (TCP) or the serverless exception (verified wss, no channel binding). */
export function doctorExitOk(i: DoctorInfo): boolean {
  return !!i.tls && !!i.pgvector && (i.transport === 'serverless' || !!i.channelBinding);
}

/** Plain `zeusi doctor`. TCP: unchanged. Serverless: inside BEGIN READ ONLY .. ROLLBACK. */
export async function runDoctor(db: Db, service: string): Promise<DoctorInfo> {
  if (db.transport?.kind !== 'serverless') return collectDoctor(db, service);
  await db.exec('BEGIN READ ONLY');
  try {
    return await collectDoctor(db, service);
  } finally {
    await db.exec('ROLLBACK').catch(() => {});
  }
}

export function formatDoctor(i: DoctorInfo): string {
  const sl = i.transport === 'serverless';
  return [
    `service: ${i.service}`,
    `role: ${i.role}`,
    ...(sl ? ['transport: serverless (wss, port 443; ZEUSI_TRANSPORT=serverless)'] : []),
    `TLS: ${yn(i.tls)}${i.tls ? (sl ? ' (wss, certificate verified)' : ' (verify-full)') : ''}`,
    sl
      ? `channel binding: ${yn(i.channelBinding)} (serverless transport: password over verified TLS, not SCRAM-SHA-256-PLUS; read-only roles only)`
      : `channel binding: ${yn(i.channelBinding)}${i.channelBinding ? ' (SCRAM-SHA-256-PLUS)' : ''}`,
    `server major: ${i.serverMajor} (${i.serverVersion})`,
    `pgvector: ${i.pgvector ? `present (${i.pgvector})` : 'MISSING'}`,
    `migrations: ${i.migrations === null ? 'not visible to this role' : `${i.migrations.length} applied${i.migrations.length ? ` (latest ${i.migrations.at(-1)})` : ''}`}`,
  ].join('\n');
}

/** Error text safe to print: known secrets replaced, Neon hosts and URLs masked. */
export function redactError(e: unknown, secrets: Array<string | undefined> = []): string {
  return redact(e instanceof Error ? e.message : String(e), secrets);
}
