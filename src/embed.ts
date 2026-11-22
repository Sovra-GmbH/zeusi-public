// `zeusi embed` (PLAN.md U6, R6, R17; KTD2, KTD5). Role: zeusi_mini_ingest.
//
// Embeds chunks whose embedding IS NULL. The importer never calls this: ingest stays
// embedding-free and `embed` is its own command.
//
// Order of work, fail closed at every step:
//   1. Refuse an owner-privileged session (superuser, or can write wall_allow).
//   2. Wall readiness: the same check as real ingest (wall.ts wallReadiness: migrations
//      0006-0011 applied, seed rules intact), for --dry-run and --real alike. Then
//      zeusi.wall_audit() must return 0 rows: no text leaves the box while any stored
//      row breaks the wall (e.g. a rule added after the ingest).
//   3. One embed run at a time (session advisory lock; the ingest service is DIRECT).
//   4. Pending chunks (RLS: zeusi_ingest never sees `personal`). The embedded string
//      is chunking.embedText(title, heading_path, text); stored text stays the chunk.
//   5. Reuse: a chunk whose exact embedded string already has a vector for this
//      embed_model gets that vector copied (lookup through the (text_sha256,
//      embed_model) index, then the embedded-string sha256 is compared, because the
//      same chunk text under another title or heading is a different input).
//      Same-run duplicates are sent once.
//   6. Batches. Before each one, reserveTokens(): ONE transaction holding
//      pg_advisory_xact_lock(cap key) reads the month-to-date usage of every host and
//      model, refuses if month-to-date + worst-case > cap, else UPSERT-adds the
//      worst-case tokens, and COMMITs, all BEFORE the API call. After the call a
//      second transaction writes the vectors and settles the row to the API-reported
//      tokens (adds actual - reserved). A crash in between leaves the worst-case
//      reservation in place (over-counts, never under-counts). Concurrent runs, on
//      any host and over the pooler or not, serialise on the xact lock and see each
//      other's committed reservations.
//
// Cost truth is TOKENS. embed_usage.est_usd is numeric(10,4), which rounds a small
// batch to $0.0000, so it is kept only for display (rounded UP); the cap is computed
// as sum(tokens) x price.

import { createHash } from 'node:crypto';
import { embedText, estimateTokens } from './chunking.ts';
import type { Db } from './db.ts';
import { asPgError } from './db.ts';
import type { EmbeddingsClient } from './embeddings.ts';
import { EMBED_DIMS, INDEXED_EMBED_MODEL } from './facts.ts';
import { importerLockKey } from './ingest-run.ts';
import { TENANT_ADMIN_ROLE, TENANT_RT_ROLE, TENANT_WR_ROLE } from './tenants.ts';
import { wallReadiness } from './wall.ts';

/** `<provider>/<model>@<dims>`, the value stored in chunks.embed_model. */
export const EMBED_MODEL_LABEL = INDEXED_EMBED_MODEL;

/**
 * USD per 1M input tokens. text-embedding-3-small: $0.02 / 1M tokens (standard tier,
 * OpenAI pricing page as known on 2026-11-14; not fetched at runtime). The EU
 * data-residency uplift applies only to models released on or after 5 Mar 2026, so
 * not to this one (PLAN.md). Re-check on the billing page at signup.
 */
export const PRICE_USD_PER_1M_TOKENS: Readonly<Record<string, number>> = {
  'openai/text-embedding-3-small@1536': 0.02,
};

/** Hard monthly cap, all hosts together. Config may LOWER it; raising it needs a code change. */
export const HARD_MONTHLY_CAP_USD = 5.0;

export const DEFAULT_BATCH = { maxInputs: 128, maxWorstTokens: 200_000 };
const CAP_LOCK_KEY = importerLockKey('embed-cap');
const RUN_LOCK_NAME = 'embed';

export class EmbedRefused extends Error {
  override name = 'EmbedRefused';
}

export function effectiveCapUsd(override?: number): number {
  if (override === undefined) return HARD_MONTHLY_CAP_USD;
  if (!Number.isFinite(override) || override <= 0) throw new EmbedRefused('the embed cap override must be a positive number of USD');
  if (override > HARD_MONTHLY_CAP_USD) {
    throw new EmbedRefused(`the embed cap override can only lower the hard cap of $${HARD_MONTHLY_CAP_USD.toFixed(2)}; raising it needs a code change`);
  }
  return override;
}

/**
 * Worst-case tokens for one input: its UTF-8 byte length. OpenAI's tokenizers are
 * byte-level BPE, so every token covers at least one byte; the API cannot bill more
 * tokens than bytes. (~4x the usual count for English: deliberately pessimistic.)
 */
export function worstCaseTokens(s: string): number {
  return Buffer.byteLength(s, 'utf8');
}

export function usdForTokens(tokens: number, model: string = EMBED_MODEL_LABEL): number {
  const p = PRICE_USD_PER_1M_TOKENS[model];
  if (p === undefined) throw new EmbedRefused(`unknown embed_model ${JSON.stringify(model)}: no price constant (fail closed)`);
  return (tokens * p) / 1_000_000;
}

/** First day of the UTC month, 'YYYY-MM-01'. */
export function monthOf(d: Date): string {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-01`;
}

export function embedKey(title: string, headingPath: string | null, text: string): string {
  return createHash('sha256').update(embedText(title, headingPath, text), 'utf8').digest('hex');
}

export interface MonthToDate {
  tokens: number;
  usd: number;
}

/** Month-to-date spend over every host and model. Throws EmbedRefused on a model without a price. */
export async function monthToDate(db: Db, month: string): Promise<MonthToDate> {
  const rows = (await db.query<{ embed_model: string; tokens: string }>(
    `SELECT embed_model, sum(tokens)::text AS tokens FROM zeusi.embed_usage WHERE month = $1::date GROUP BY embed_model`, [month],
  )).rows;
  let tokens = 0;
  let usd = 0;
  for (const r of rows) {
    const t = Number(r.tokens);
    tokens += t;
    usd += usdForTokens(t, r.embed_model);
  }
  return { tokens, usd };
}

export interface ReserveInput {
  month: string;
  model: string;
  host: string;
  tokens: number;
  capUsd: number;
}

export type ReserveResult = { ok: true; mtdUsd: number } | { ok: false; mtdUsd: number; reason: string };

/** Atomic check-and-reserve under the cap lock (see header). Commits before returning ok. */
export async function reserveTokens(db: Db, r: ReserveInput): Promise<ReserveResult> {
  await db.exec('BEGIN');
  try {
    await db.query(`SELECT pg_advisory_xact_lock($1::bigint)`, [CAP_LOCK_KEY]);
    let mtd: MonthToDate;
    try {
      mtd = await monthToDate(db, r.month);
    } catch (e) {
      await db.exec('ROLLBACK');
      return { ok: false, mtdUsd: Number.NaN, reason: e instanceof Error ? e.message : String(e) };
    }
    const worst = usdForTokens(r.tokens, r.model);
    if (mtd.usd + worst > r.capUsd) {
      await db.exec('ROLLBACK');
      return {
        ok: false, mtdUsd: mtd.usd,
        reason: `monthly embed cap: month-to-date $${mtd.usd.toFixed(6)} + worst-case batch $${worst.toFixed(6)} would exceed the cap $${r.capUsd.toFixed(2)}`,
      };
    }
    await addUsage(db, r.month, r.model, r.host, r.tokens);
    await db.exec('COMMIT');
    return { ok: true, mtdUsd: mtd.usd + worst };
  } catch (e) {
    await db.exec('ROLLBACK').catch(() => {});
    throw e;
  }
}

/** UPSERT-add tokens (may be negative to settle a reservation); est_usd recomputed, rounded up. */
async function addUsage(db: Db, month: string, model: string, host: string, tokens: number): Promise<void> {
  const price = PRICE_USD_PER_1M_TOKENS[model]!;
  await db.query(
    `INSERT INTO zeusi.embed_usage AS u (month, embed_model, host, tokens, est_usd)
     VALUES ($1::date, $2, $3, $4::bigint, ceil($4::numeric * $5::numeric / 100) / 10000)
     ON CONFLICT (month, embed_model, host) DO UPDATE SET
       tokens = u.tokens + EXCLUDED.tokens,
       est_usd = ceil((u.tokens + EXCLUDED.tokens)::numeric * $5::numeric / 100) / 10000`,
    [month, model, host, tokens, price],
  );
}

export interface EmbedOptions {
  db: Db;
  client: EmbeddingsClient;
  /** embed_usage.host (default 'mini'). A label, not a hostname. */
  host?: string;
  /** Max pending chunks considered this run. */
  limit?: number;
  dryRun?: boolean;
  /** Lower-only override of HARD_MONTHLY_CAP_USD. */
  capUsd?: number;
  batch?: Partial<typeof DEFAULT_BATCH>;
  now?: () => Date;
  log?: (line: string) => void;
}

export interface EmbedCounts {
  /** Pending chunks considered (embedding IS NULL, visible to the role). */
  pending: number;
  /** Chunks that got a copied vector (no API call). */
  reused: number;
  /** Pending chunks whose embedded string equals another pending one (sent once). */
  sameRunDuplicates: number;
  /** Unique strings sent (dry run: would be sent). */
  apiInputs: number;
  apiCalls: number;
  /** Chunks written with a new or copied vector. */
  embedded: number;
  /** chunking.estimateTokens over the inputs sent (dry run: would be sent). */
  estTokens: number;
  /** Worst-case (UTF-8 bytes) over the inputs. */
  worstTokens: number;
  /** API-reported tokens (worst case where the API gave none). */
  billedTokens: number;
  mtdUsdBefore: number;
  capUsd: number;
}

export interface EmbedRunResult {
  status: 'ok' | 'capped' | 'failed' | 'locked' | 'wall';
  counts: EmbedCounts;
  /** Safe message: counts, rule ids, error classes. Never text, paths or keys. */
  error?: string;
}

interface PendingRow {
  id: number;
  sha: string;
  title: string | null;
  heading_path: string | null;
  text: string;
}

/** The refusal for a personal-workspace target (security bootstrap §7 item 11). Safe text, no value. */
export const EMBED_WORKSPACE_REFUSED =
  'embed refused: the target is a personal workspace (a zt_* schema or role, or a workspace login). Personal workspaces are never embedded. Nothing read or sent.';

/** A login / role / service name that belongs to the personal workspaces (zt_* or a workspace login). */
export function workspaceEmbedName(name: string): boolean {
  const n = name.trim().toLowerCase();
  return n.startsWith('zt_') || [TENANT_ADMIN_ROLE, TENANT_RT_ROLE, TENANT_WR_ROLE].includes(n);
}

/**
 * Step 0 of every embed run (docs/plans/2026-11-18-c2-log-disk-hygiene.md KTD7): the chunks this
 * session would read must be the team's `zeusi.chunks`, read as a non-workspace role. A workspace session
 * (src/tenants.ts schemaTranslatingDb rewrites `zeusi.` to its `zt_*` schema) or a workspace login is
 * refused, as is any failure of the probe. Nothing else is read before this passes.
 */
export async function assertTeamEmbedTarget(db: Db): Promise<void> {
  let r: { nsp: string; su: string; cu: string } | undefined;
  try {
    r = (await db.query<{ nsp: string; su: string; cu: string }>(
      `SELECT n.nspname::text AS nsp, session_user::text AS su, current_user::text AS cu
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.oid = 'zeusi.chunks'::regclass`,
    )).rows[0];
  } catch {
    throw new EmbedRefused(EMBED_WORKSPACE_REFUSED);
  }
  if (!r || r.nsp !== 'zeusi' || workspaceEmbedName(r.su) || workspaceEmbedName(r.cu)) throw new EmbedRefused(EMBED_WORKSPACE_REFUSED);
}

export async function runEmbed(opts: EmbedOptions): Promise<EmbedRunResult> {
  const { db, client } = opts;
  const now = opts.now ?? (() => new Date());
  const host = opts.host ?? 'mini';
  const capUsd = effectiveCapUsd(opts.capUsd);
  const batch = { ...DEFAULT_BATCH, ...(opts.batch ?? {}) };
  const model = `openai/${client.model}@${client.dims}`;
  if (model !== EMBED_MODEL_LABEL || client.dims !== EMBED_DIMS) {
    throw new EmbedRefused(`client model ${model} does not match the indexed model ${EMBED_MODEL_LABEL}`);
  }
  const counts: EmbedCounts = {
    pending: 0, reused: 0, sameRunDuplicates: 0, apiInputs: 0, apiCalls: 0, embedded: 0,
    estTokens: 0, worstTokens: 0, billedTokens: 0, mtdUsdBefore: 0, capUsd,
  };

  // 0. never a personal workspace (§7 item 11): before anything is read
  await assertTeamEmbedTarget(db);

  // 1. never as the owner
  const priv = (await db.query<{ su: boolean; owner_like: boolean }>(
    `SELECT coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false) AS su,
            has_table_privilege('zeusi.wall_allow', 'INSERT') AS owner_like`,
  )).rows[0]!;
  if (priv.su || priv.owner_like) throw new EmbedRefused('embed runs as zeusi_ingest (service zeusi_ingest), never as the owner');

  // 2a. the same wall readiness as real ingest (0006-0011 + seed rules): wall_audit()
  //     only checks rows against the rules IN the database, so an older wall (e.g.
  //     0009, blind to "Plankiva") would audit clean and let that text leave the box.
  const ready = await wallReadiness(db);
  if (ready.problems.length) {
    throw new EmbedRefused(`embed refused (nothing read or sent; apply the wall migrations first):\n  - ${ready.problems.join('\n  - ')}`);
  }

  // 2b. wall audit must be clean
  const bad = (await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM zeusi.wall_audit()`)).rows[0]!.n;
  if (bad > 0) return { status: 'wall', counts, error: `wall audit reports ${bad} row(s); nothing embedded (run \`zeusi wall audit\`)` };

  const month = monthOf(now());
  try {
    counts.mtdUsdBefore = (await monthToDate(db, month)).usd;
  } catch (e) {
    return { status: 'capped', counts, error: e instanceof Error ? e.message : String(e) };
  }

  // 3. one run at a time
  let locked = false;
  if (!opts.dryRun) {
    const ok = (await db.query<{ ok: boolean }>(`SELECT pg_try_advisory_lock($1::bigint) AS ok`, [importerLockKey(RUN_LOCK_NAME)])).rows[0]?.ok === true;
    if (!ok) return { status: 'locked', counts, error: 'another embed run holds the lock; nothing done' };
    locked = true;
  }
  try {
    // 4. pending
    const rows = (await db.query<PendingRow>(
      `SELECT c.id::int AS id, encode(c.text_sha256, 'hex') AS sha, n.title, c.heading_path, c.text
       FROM zeusi.chunks c LEFT JOIN zeusi.notes n ON n.id = c.note_id
       WHERE c.embedding IS NULL
       ORDER BY c.id
       LIMIT $1`,
      [opts.limit ?? null],
    )).rows;
    counts.pending = rows.length;
    if (rows.length === 0) return { status: 'ok', counts };

    // group by exact embedded string
    const groups = new Map<string, { input: string; sha: string; ids: number[] }>();
    for (const r of rows) {
      const input = embedText(r.title ?? '', r.heading_path, r.text);
      const key = createHash('sha256').update(input, 'utf8').digest('hex');
      const g = groups.get(key);
      if (g) {
        g.ids.push(r.id);
        counts.sameRunDuplicates++;
      } else groups.set(key, { input, sha: r.sha, ids: [r.id] });
    }

    // 5. reuse donors: same text_sha256 + embed_model (index), then exact embedded-string match
    const shas = [...new Set(rows.map((r) => r.sha))];
    const donors = (await db.query<PendingRow>(
      `SELECT c.id::int AS id, encode(c.text_sha256, 'hex') AS sha, n.title, c.heading_path, c.text
       FROM zeusi.chunks c LEFT JOIN zeusi.notes n ON n.id = c.note_id
       WHERE c.text_sha256 = ANY (SELECT decode(x, 'hex') FROM unnest($1::text[]) AS x)
         AND c.embed_model = $2 AND c.embedding IS NOT NULL`,
      [shas, model],
    )).rows;
    const donorFor = new Map<string, number>();
    for (const d of donors) {
      const k = embedKey(d.title ?? '', d.heading_path, d.text);
      if (!donorFor.has(k)) donorFor.set(k, d.id);
    }
    const toSend: Array<{ key: string; input: string; sha: string; ids: number[] }> = [];
    for (const [key, g] of groups) {
      const donor = donorFor.get(key);
      if (donor === undefined) {
        toSend.push({ key, ...g });
        continue;
      }
      if (opts.dryRun) {
        counts.reused += g.ids.length;
        continue;
      }
      const n = (await db.query<{ id: number }>(
        `UPDATE zeusi.chunks t SET embed_model = s.embed_model, embedding = s.embedding, embedded_at = now()
         FROM zeusi.chunks s
         WHERE t.id = ANY($1::bigint[]) AND s.id = $2 AND t.embedding IS NULL
           AND t.text_sha256 = s.text_sha256 AND s.embed_model = $3 AND s.embedding IS NOT NULL
         RETURNING t.id::int AS id`,
        [g.ids, donor, model],
      )).rows.length;
      counts.reused += n;
      counts.embedded += n;
    }

    for (const s of toSend) {
      counts.estTokens += estimateTokens(s.input);
      counts.worstTokens += worstCaseTokens(s.input);
    }
    counts.apiInputs = toSend.length;
    if (opts.dryRun) {
      const wouldUsd = usdForTokens(counts.worstTokens, model);
      return counts.mtdUsdBefore + wouldUsd > capUsd
        ? { status: 'capped', counts, error: `dry run: worst-case $${wouldUsd.toFixed(6)} on top of month-to-date $${counts.mtdUsdBefore.toFixed(6)} would exceed the cap $${capUsd.toFixed(2)}` }
        : { status: 'ok', counts };
    }

    // 6. batches
    const batches: Array<typeof toSend> = [];
    let cur: typeof toSend = [];
    let curWorst = 0;
    for (const s of toSend) {
      const w = worstCaseTokens(s.input);
      if (cur.length && (cur.length >= batch.maxInputs || curWorst + w > batch.maxWorstTokens)) {
        batches.push(cur);
        cur = [];
        curWorst = 0;
      }
      cur.push(s);
      curWorst += w;
    }
    if (cur.length) batches.push(cur);

    for (const b of batches) {
      const worst = b.reduce((n, s) => n + worstCaseTokens(s.input), 0);
      const res = await reserveTokens(db, { month, model, host, tokens: worst, capUsd });
      if (!res.ok) return { status: 'capped', counts, error: res.reason };
      let out;
      try {
        out = await client.embed(b.map((s) => s.input));
      } catch (e) {
        // The reservation stays (the request may have been billed). Message from the client is already key-free.
        return { status: 'failed', counts, error: `embedding call failed: ${e instanceof Error ? e.message : 'unknown error'}` };
      }
      counts.apiCalls++;
      if (out.vectors.length !== b.length || out.vectors.some((v) => v.length !== EMBED_DIMS || !v.every(Number.isFinite))) {
        return { status: 'failed', counts, error: 'embedding response failed the shape check; nothing written for this batch' };
      }
      const billed = out.totalTokens ?? worst;
      try {
        await db.exec('BEGIN');
        let written = 0;
        for (let i = 0; i < b.length; i++) {
          const s = b[i]!;
          written += (await db.query<{ id: number }>(
            `UPDATE zeusi.chunks SET embed_model = $2, embedding = $3::halfvec(${EMBED_DIMS}), embedded_at = now()
             WHERE id = ANY($1::bigint[]) AND embedding IS NULL AND text_sha256 = decode($4, 'hex')
             RETURNING id::int AS id`,
            [s.ids, model, `[${out.vectors[i]!.join(',')}]`, s.sha],
          )).rows.length;
        }
        if (billed !== worst) await addUsage(db, month, model, host, billed - worst);
        await db.exec('COMMIT');
        counts.embedded += written;
        counts.billedTokens += billed;
        if (billed > worst) opts.log?.(`warning: API-reported tokens (${billed}) exceeded the worst-case bound (${worst}) for one batch`);
      } catch (e) {
        await db.exec('ROLLBACK').catch(() => {});
        return { status: 'failed', counts, error: `writing vectors failed (${asPgError(e).code ?? 'error'}); reservation kept` };
      }
    }
    return { status: 'ok', counts };
  } finally {
    if (locked) await db.query(`SELECT pg_advisory_unlock($1::bigint)`, [importerLockKey(RUN_LOCK_NAME)]).catch(() => {});
  }
}

/** Counts-only summary for the CLI. */
export function formatEmbedResult(r: EmbedRunResult, dryRun: boolean): string {
  const c = r.counts;
  const lines = [
    `embed ${dryRun ? '(dry run: no API call, no write)' : ''}: status ${r.status}`,
    `  pending chunks considered: ${c.pending}`,
    `  vectors reused (copied, no API): ${c.reused}; same-run duplicates sent once: ${c.sameRunDuplicates}`,
    `  ${dryRun ? 'would send' : 'sent'}: ${c.apiInputs} input(s)${dryRun ? '' : ` in ${c.apiCalls} call(s); chunks written: ${c.embedded}`}`,
    `  tokens: estimated ${c.estTokens}, worst case ${c.worstTokens}${dryRun ? '' : `, billed ${c.billedTokens}`}`,
    `  cost: ${dryRun ? `worst case $${usdForTokens(c.worstTokens).toFixed(6)}` : `billed $${usdForTokens(c.billedTokens).toFixed(6)}`}; month-to-date before run $${c.mtdUsdBefore.toFixed(6)}; cap $${c.capUsd.toFixed(2)}`,
  ];
  if (r.error) lines.push(`  ${r.error}`);
  return lines.join('\n');
}
