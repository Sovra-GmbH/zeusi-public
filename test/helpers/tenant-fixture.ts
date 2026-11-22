// Test-only fixture for personal workspaces (docs/plans/2026-11-18-open-signup-workspaces-plan.md):
// PGlite with every migration, the owner SQL for the two workspace logins, and the shared-schema rows that
// carry a unique marker so a leak is a plain substring match. Logins are emulated with
// SET SESSION AUTHORIZATION, so session_user is the real login and SET ROLE checks real membership
// (a plain SET ROLE from the superuser would allow any role). No network, no Neon.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Db } from '../../src/db.ts';
import { migrate } from '../../src/migrate.ts';
import { pgliteDb } from '../pglite-db.ts';

// PGlite does not honour RESET SESSION AUTHORIZATION (it keeps the set user); naming the
// authenticated superuser does.
const BACK_TO_OWNER = 'RESET ROLE; SET SESSION AUTHORIZATION postgres; RESET search_path; RESET default_transaction_read_only';

export const OWNER_SQL = fileURLToPath(new URL('../../scripts/owner-sql/tenant-roles.sql', import.meta.url));
/** The writer login (PR 2, docs/plans/2026-11-18-workspace-write-import-plan.md KTD3). */
export const WRITER_OWNER_SQL = fileURLToPath(new URL('../../scripts/owner-sql/tenant-writer-role.sql', import.meta.url));
export const SHA = 'ab'.repeat(32);
/** In every planted shared-schema row (note body, chunk, fact rule, focus, decision, lock). One lexical token. */
export const TEAM_MARKER = 'quokkateammarker';
/** The walled name, built at runtime (never a literal in the repo). */
export const WALLED = ['Plan', 'kiva'].join('');
export const TEAM_NOTE_URI = 'vault:Work/research/team-secret-plan.md';
export const TEAM_LOCK_URI = 'vault:Work/ops/team-standing.md';
export const TEAM_DECISION_URI = 'test:team-decision-quokka';

export async function tenantTestDb(o: { writer?: boolean } = {}): Promise<Db & { raw: Awaited<ReturnType<typeof pgliteDb>>['raw'] }> {
  const db = await pgliteDb();
  await migrate(db);
  await db.exec(readFileSync(OWNER_SQL, 'utf8'));
  if (o.writer) await db.exec(readFileSync(WRITER_OWNER_SQL, 'utf8'));
  return db;
}

/**
 * A connect factory that "logs in" as `login` on the shared PGlite session. close() undoes every
 * session setting the code under test may have made. Calls must not overlap (one connection).
 */
export function asLogin(db: Db, login: string, log?: string[]): () => Promise<Db> {
  return async () => {
    log?.push(login);
    await db.exec(`SET SESSION AUTHORIZATION ${login}`);
    return {
      label: `pglite as ${login}`,
      query: db.query.bind(db),
      exec: db.exec.bind(db),
      close: async () => {
        await db.exec('ROLLBACK').catch(() => {});
        await db.exec(BACK_TO_OWNER);
      },
    };
  };
}

/** Run `fn` as the owner (PGlite superuser), whatever session state a failed test left behind. */
export async function asOwner<T>(db: Db, fn: () => Promise<T>): Promise<T> {
  await db.exec('ROLLBACK').catch(() => {});
  await db.exec(BACK_TO_OWNER);
  return fn();
}

export interface PlantedTeam {
  run: number;
  noteId: number;
  decisionId: number;
}

/**
 * the shared rows in schema zeusi, each carrying TEAM_MARKER: a standing lock note (a startup rule), a
 * note with a chunk, a walled chunk (it would be withheld for a team reader: a side channel if it
 * were ever counted for anyone else), a fact rule, a focus fact and a decision. Inserted as the owner
 * with the chunk wall trigger off for the walled row only.
 */
export async function plantTeam(db: Db): Promise<PlantedTeam> {
  return asOwner(db, async () => {
    const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    await db.query(
      `INSERT INTO zeusi.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('Work/ops/team-standing.md', 'the team standing', $1::jsonb, $2, now(), 'work', 'vault_note', $3, now(), decode($4, 'hex'), $5)`,
      [JSON.stringify({ locks: [`never ship on friday ${TEAM_MARKER}`] }), `standing ${TEAM_MARKER}`, TEAM_LOCK_URI, SHA, run]);
    const noteId = (await db.query<{ id: number }>(
      `INSERT INTO zeusi.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('Work/research/team-secret-plan.md', 'the team secret plan', $1, now(), 'work', 'vault_note', $2, now(), decode($3, 'hex'), $4)
       RETURNING id::int AS id`, [`plan body ${TEAM_MARKER}`, TEAM_NOTE_URI, SHA, run])).rows[0]!.id;
    await db.query(
      `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
       VALUES ($1, 0, 'Plan', $2, sha256(convert_to($2, 'UTF8')), 5, $3)`, [noteId, `team chunk ${TEAM_MARKER} launch pricing`, `${TEAM_NOTE_URI}#c0`]);
    await db.exec('ALTER TABLE zeusi.chunks DISABLE TRIGGER zeusi_90_wall');
    try {
      await db.query(
        `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
         VALUES ($1, 1, 'Walled', $2, sha256(convert_to($2, 'UTF8')), 5, $3)`, [noteId, `walled ${TEAM_MARKER} ${WALLED} probe`, `${TEAM_NOTE_URI}#c1`]);
    } finally {
      await db.exec('ALTER TABLE zeusi.chunks ENABLE TRIGGER zeusi_90_wall');
    }
    for (const [kind, subject] of [['rule', 'team.rule'], ['state', 'team.focus']] as const) {
      await db.query(
        `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
         VALUES ($1, $2, $3, 'work', 'manual', $4, now(), decode($5, 'hex'), $6)`,
        [kind, subject, `${kind} ${TEAM_MARKER}`, `test:team-${kind}`, SHA, run]);
    }
    await db.query(
      `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('team-owner', 'the team Owner', 'human', 'work', 'work', 'manual', 'manual:people/team-owner', now(), decode($1, 'hex'), $2)`, [SHA, run]);
    const decisionId = (await db.query<{ id: number }>(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to,
                                    scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('lock', (SELECT id FROM zeusi.people WHERE handle = 'team-owner'), now(), 'minute', $1, true, '{pricing,launch}',
               'work', 'manual', $2, now(), decode($3, 'hex'), $4)
       RETURNING id::int AS id`, [`launch pricing stays ${TEAM_MARKER}`, TEAM_DECISION_URI, SHA, run])).rows[0]!.id;
    return { run, noteId, decisionId };
  });
}

/** One note + chunk inside a workspace schema (as the owner), so a workspace has something of its own. */
export async function plantInWorkspace(db: Db, schema: string, marker: string): Promise<void> {
  await asOwner(db, async () => {
    const run = (await db.query<{ id: number }>(`INSERT INTO ${schema}.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
    const nid = (await db.query<{ id: number }>(
      `INSERT INTO ${schema}.notes (vault_path, title, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('mine/notes.md', 'mine', $1, now(), 'personal', 'manual', $2, now(), decode($3, 'hex'), $4) RETURNING id::int AS id`,
      [`own body ${marker}`, `test:${marker}`, SHA, run])).rows[0]!.id;
    await db.query(
      `INSERT INTO ${schema}.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
       VALUES ($1, 0, 'Mine', $2, sha256(convert_to($2, 'UTF8')), 3, $3)`, [nid, `own chunk ${marker}`, `test:${marker}#c0`]);
  });
}

/**
 * A POOLED "connection" (docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md KTD9): it hands
 * back the shared PGlite session exactly as the previous user left it, and close() does NOTHING, like a
 * transaction pooler giving the server connection to the next client. `dirty` (optional) is run first
 * as that previous user, e.g. `SET ROLE <A>_r; SET search_path = <A>, public`. Calls must not overlap.
 */
export function pooledLogin(db: Db, login: string, o: { dirty?: () => string | null; log?: string[] } = {}): () => Promise<Db> {
  return async () => {
    o.log?.push(login);
    // Log in only when the session is not already that login: SET SESSION AUTHORIZATION also clears
    // SET ROLE, which would hide exactly the leak a pooled server connection carries.
    const su = (await db.query<{ su: string }>('SELECT session_user::text AS su')).rows[0]!.su;
    if (su !== login) await db.exec(`SET SESSION AUTHORIZATION ${login}`);
    const dirt = o.dirty?.();
    if (dirt) await db.exec(dirt);
    return {
      label: `pooled pglite as ${login}`,
      query: db.query.bind(db),
      exec: db.exec.bind(db),
      close: async () => { /* a pooler keeps the server connection: nothing is undone here */ },
    };
  };
}

/** The session state a pooled server connection carries right now (as whoever it is). */
export async function sessionState(db: Db): Promise<{ cu: string; su: string; path: string; ro: string }> {
  return (await db.query<{ cu: string; su: string; path: string; ro: string }>(
    `SELECT current_user::text AS cu, session_user::text AS su, current_setting('search_path') AS path,
            current_setting('default_transaction_read_only') AS ro`)).rows[0]!;
}
