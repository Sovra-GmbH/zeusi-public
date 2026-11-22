// Fix PR A x PR #23: every channel Fix PR A added must pass the serve-time guard (src/mcp-wall.ts
// wallFilter: wall on the original, then withhold on detector / main floor / `[REDACTED:` marker,
// fail closed). Shared by the read-bearer (mcp-hosted.test.ts) and OAuth-read
// (mcp-oauth-hosted.test.ts) tests. Planted rows simulate legacy rows written before the
// ingest-time redaction (DB wall trigger off while planting). All values are synthetic and
// assembled at runtime (test/secret-fixtures.ts); nothing here is or resembles a real key.
import assert from 'node:assert/strict';
import type { Db } from '../../src/db.ts';
import { serveSecretSignal } from '../../src/mcp-wall.ts';
import { fakeMaskedGoogle, P } from '../secret-fixtures.ts';

const TERM = 'kiwiguard';
const SHA = 'ef'.repeat(32);

/** The planted partial-key strings (each one alone must trip the serve check). */
export const planted = () => ({
  lock: `SYNTHETIC GUARD LOCK: ${TERM} deploy key ${fakeMaskedGoogle()}`,
  title: `${TERM} spec key ${fakeMaskedGoogle()}`,
  repo: `team/${fakeMaskedGoogle()}`,
  chunk: `${TERM} chunk key ${fakeMaskedGoogle()}`,
});

export const CLEAN = {
  lock: `SYNTHETIC GUARD LOCK: ${TERM} clean standing rule`,
  titleNoteLock: `SYNTHETIC GUARD LOCK: ${TERM} rule under a planted title`,
  decision: `SYNTHETIC GUARD DECISION: ${TERM} clean control`,
  linked: `SYNTHETIC GUARD DECISION: ${TERM} linked repo carries a key`,
  sourced: `SYNTHETIC GUARD DECISION: ${TERM} source note title carries a key`,
  chunk: `${TERM} chunk clean body`,
};

/** Plant the guard fixtures; returns a cleanup that deletes exactly these rows. */
export async function plantGuardFixtures(db: Db): Promise<() => Promise<void>> {
  const p = planted();
  for (const s of Object.values(p)) assert.ok(serveSecretSignal(s), 'precondition: each planted value trips the serve check');
  const run = (await db.query<{ id: number }>(`INSERT INTO zeusi.ingest_runs (importer, host, mode) VALUES ('test', 'mini', 'manual') RETURNING id::int AS id`)).rows[0]!.id;
  const tables = ['notes', 'decisions', 'chunks'];
  for (const t of tables) await db.exec(`ALTER TABLE zeusi.${t} DISABLE TRIGGER zeusi_90_wall`);
  try {
    const person = (await db.query<{ id: number }>(
      `INSERT INTO zeusi.people (handle, display_name, kind, org, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ('guard-owner', 'Guard Owner', 'human', 'work', 'work', 'manual', 'manual:people/guard-owner', now(), decode($1, 'hex'), $2)
       RETURNING id::int AS id`, [SHA, run])).rows[0]!.id;
    const note = async (path: string, title: string, locks: string[] | null) => (await db.query<{ id: number }>(
      `INSERT INTO zeusi.notes (vault_path, title, frontmatter, body, file_mtime, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1, $2, CASE WHEN $3::jsonb IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('locks', $3::jsonb) END, 'synthetic body', now(),
               'work', 'vault_note', 'vault:' || $1, now(), decode($4, 'hex'), $5) RETURNING id::int AS id`,
      [path, title, locks === null ? null : JSON.stringify(locks), SHA, run])).rows[0]!.id;
    // a lock item carrying a key (and a clean one beside it, served)
    await note('Work/ops/guard-locks.md', 'Guard locks (synthetic)', [CLEAN.lock, p.lock]);
    // a clean lock item under a note TITLE carrying a key (subject / note_title / cite)
    await note('Work/handbook/guard-title.md', p.title, [CLEAN.titleNoteLock]);
    // a decision's source note whose title carries a key (source_note.title); its chunks feed search
    const src = await note('Work/research/guard-src.md', p.title, null);
    const dec = (words: string, uri: string, repo: string | null) => db.query(
      `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, scope, source_kind,
                                    source_uri, source_ts, source_sha256, ingest_run_id, linked_repo, linked_pr)
       VALUES ('lock', $1, now() - interval '1 day', 'minute', $2, false, ARRAY[$3], 'work', 'manual', $4, now() - interval '1 day',
               sha256(convert_to($4 || $2, 'UTF8')), $5, $6, $7)`,
      [person, words, TERM, uri, run, repo, repo === null ? null : 7]);
    await dec(CLEAN.decision, 'test:guard-control', null);
    await dec(CLEAN.linked, 'test:guard-linked', p.repo);
    await dec(CLEAN.sourced, 'vault:Work/research/guard-src.md#d1', null);
    const chunk = (i: number, text: string) => db.query(
      `INSERT INTO zeusi.chunks (note_id, chunk_index, heading_path, text, text_sha256, token_count, source_uri)
       VALUES ($1, $2, 'Guard', $3, sha256(convert_to($3, 'UTF8')), 5, $4)`, [src, i, text, `vault:Work/research/guard-src.md#c${i}`]);
    await chunk(0, CLEAN.chunk);
    await chunk(1, p.chunk);
    return async () => {
      await db.query(`DELETE FROM zeusi.decisions WHERE who_id = $1`, [person]);
      await db.query(`DELETE FROM zeusi.notes WHERE vault_path IN ('Work/ops/guard-locks.md', 'Work/handbook/guard-title.md', 'Work/research/guard-src.md')`);
      await db.query(`DELETE FROM zeusi.people WHERE id = $1`, [person]);
    };
  } finally {
    for (const t of tables) await db.exec(`ALTER TABLE zeusi.${t} ENABLE TRIGGER zeusi_90_wall`);
  }
}

type CallJson = (name: string, args: Record<string, unknown>) => Promise<{ status: number; body: string; json: Record<string, unknown> }>;

const noKey = (body: string, where: string) => {
  assert.ok(!body.includes(P.google), `${where}: no key prefix in the HTTP response`);
  assert.ok(!body.includes('X0X0X'), `${where}: no key tail in the HTTP response`);
};
const mine = (xs: string[]) => xs.filter((x) => x.includes(TERM)).sort();

/**
 * Startup, context_for_task and search over one connection: the clean items are served
 * byte-for-byte, every item with a planted key (lock item, note title, linked field, chunk) is
 * withheld and counted. Returns the number of planted items each tool withheld (for the log check).
 */
export async function assertGuardedChannels(callJson: CallJson): Promise<{ startup: number; context: number; search: number }> {
  // zeusi_startup: standing lock rules (origin note_lock) + decisions with link fields.
  const s = await callJson('zeusi_startup', {});
  assert.equal(s.status, 200, 'startup');
  noKey(s.body, 'startup');
  const rules = s.json['rules'] as Array<{ origin: string; text: string }>;
  assert.deepEqual(mine(rules.filter((r) => r.origin === 'note_lock').map((r) => r.text)), [CLEAN.lock], 'startup lock rules: planted lock item and the lock under a planted title withheld');
  const sd = s.json['decisions'] as Array<{ exact_words: string; linked_repo: unknown; source_note: unknown }>;
  assert.deepEqual(mine(sd.map((d) => d.exact_words)), [CLEAN.decision], 'startup decisions: linked_repo / source_note title with a key withheld');
  assert.ok((s.json['withheld'] as number) >= 4, 'startup counts the withheld items');

  // zeusi_context_for_task: note-lock items (lock text + note title) and decisions with link fields.
  const c = await callJson('zeusi_context_for_task', { task: `${TERM} rollout` });
  assert.equal(c.status, 200, 'context_for_task');
  noKey(c.body, 'context_for_task');
  const items = c.json['items'] as Array<{ origin?: string; type: string; exact_words: string }>;
  assert.deepEqual(mine(items.map((i) => `${i.type}:${i.exact_words}`)), [`decision:${CLEAN.decision}`, `lock:${CLEAN.lock}`].sort());
  assert.equal(c.json['withheld'], 4, 'context_for_task: planted lock, lock under planted title, linked decision, sourced decision');

  // zeusi_search (hybrid default: lexical always runs): chunk hits + decisions with link fields.
  const q = await callJson('zeusi_search', { query: TERM });
  assert.equal(q.status, 200, 'search');
  noKey(q.body, 'search');
  assert.deepEqual(mine((q.json['hits'] as Array<{ text: string }>).map((h) => h.text)), [CLEAN.chunk]);
  assert.deepEqual(mine((q.json['decisions'] as Array<{ exact_words: string }>).map((d) => d.exact_words)), [CLEAN.decision]);
  assert.ok((q.json['withheld'] as number) >= 3, 'search counts the planted chunk and both decisions');
  return { startup: s.json['withheld'] as number, context: 4, search: q.json['withheld'] as number };
}

/** The hosted log: counts only (redacted_count >= the planted items), never a key piece or the planted text. */
export function assertGuardLog(logs: string[]): void {
  const all = logs.join('\n');
  for (const bad of [P.google, 'X0X0X', 'SYNTHETIC GUARD', TERM]) assert.ok(!all.includes(bad), `log holds no ${bad.slice(0, 6)}`);
  const lines = logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => typeof l['redacted_count'] === 'number');
  const total = lines.reduce((n, l) => n + (l['redacted_count'] as number), 0);
  assert.ok(total >= 4 + 4 + 3, `redacted_count counts every planted item (got ${total})`);
}
