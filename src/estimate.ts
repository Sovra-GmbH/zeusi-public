// `zeusi embed --estimate` (U6): offline, count-only embedding cost estimate.
// No database, no network: the vault importer runs in DRY-RUN mode (files opened
// read-only) and a numbers-only observer sums the tokens of each admitted chunk's
// embedded string (title > heading path + chunk, the same string `embed` sends).
//
//   (a) base       the configured sources under the current seed wall (this branch = main).
//   (b) clientcoExtra   the same run with any ClientCo-named hard rules lifted (seed hard rules
//                  whose PATTERN names clientco) and a ClientCo/**/*.md source added, minus (a).
//                  Written before 0010; 0010 + 0011 are now on main and the seed wall
//                  has no ClientCo-named hard rule, so (b) lifts nothing and adds nothing
//                  when the config already has a ClientCo source. Every other rule (Plankiva /
//                  Plankiva, agent-config-backup, the soft rules) applies as in (a).
//
// Output: counts, tokens and dollars only. No path, title or text.

import { HARD_MONTHLY_CAP_USD, usdForTokens } from './embed.ts';
import { importVault, type VaultFs } from './importers/vault.ts';
import type { SourcesConfig } from './sources.ts';
import { compileWall, seedRulesWithIds, type Wall } from './wall.ts';

/** Assumed new or changed vault notes per day from nightly journal / HQ chat / project syncs. */
export const DEFAULT_NOTES_PER_DAY = 10;
/** Assumed semantic searches per day (query embeds, tracked in the local ledger). */
export const DEFAULT_QUERIES_PER_DAY = 100;
export const QUERY_TOKENS_ASSUMED = 20;
export const SAFETY_FACTOR = 2;

export interface Bucket {
  notes: number;
  chunks: number;
  /** chunking.estimateTokens (ceil(code points / 4)). */
  estTokens: number;
  /** UTF-8 bytes (the cap's worst-case bound). */
  worstTokens: number;
  usd: number;
  usdWorst: number;
}

const bucket = (notes: number, chunks: number, estTokens: number, worstTokens: number): Bucket => ({
  notes, chunks, estTokens, worstTokens, usd: usdForTokens(estTokens), usdWorst: usdForTokens(worstTokens),
});

/** Seed hard rules whose pattern names clientco (fresh-DB ids). */
export function clientcoRuleIds(): number[] {
  return seedRulesWithIds().filter((r) => r.hard && /clientco/i.test(r.pattern)).map((r) => r.id);
}

export function clientcoAdmittedWall(): Wall {
  const lift = new Set(clientcoRuleIds());
  return compileWall(seedRulesWithIds().filter((r) => !lift.has(r.id)), []);
}

export function withClientcoSource(config: SourcesConfig): SourcesConfig {
  const v = config.sources.find((s) => s.kind === 'vault_note');
  if (!v) return config;
  return {
    ...config,
    sources: [...config.sources, { name: 'vault-client-estimate', kind: 'vault_note', scope: 'work', root: v.root, include: ['ClientCo/**/*.md'], exclude: [] }],
  };
}

async function measure(config: SourcesConfig, home: string | undefined, wall: Wall | undefined, fs: VaultFs | undefined): Promise<Bucket & { quarantined: number }> {
  let notes = 0, chunks = 0, est = 0, worst = 0;
  const r = await importVault({
    config, mode: 'full', dryRun: true, logPaths: false,
    ...(home ? { home } : {}), ...(wall ? { dryRunWall: wall } : {}), ...(fs ? { fs } : {}),
    dryRunObserver: (o) => {
      notes++;
      for (const c of o.chunks) {
        chunks++;
        est += c.estTokens;
        worst += c.worstTokens;
      }
    },
  });
  if (r.status !== 'ok') throw new Error(`dry run failed: ${r.error ?? r.status}`);
  return { ...bucket(notes, chunks, est, worst), quarantined: r.counts.quarantined };
}

export interface EstimateReport {
  base: Bucket & { quarantined: number };
  clientcoExtra: Bucket;
  total: Bucket;
  totalWithSafety: { estTokens: number; usd: number };
  capUsd: number;
  clientcoRuleIds: number[];
  steady: {
    notesPerDay: number;
    chunksPerNote: number;
    tokensPerChunk: number;
    monthlyTokens: number;
    monthlyUsd: number;
    queriesPerDay: number;
    queryMonthlyUsd: number;
  };
}

export async function estimateReport(opts: { config: SourcesConfig; home?: string; fs?: VaultFs; notesPerDay?: number; queriesPerDay?: number }): Promise<EstimateReport> {
  const base = await measure(opts.config, opts.home, undefined, opts.fs);
  const prof = await measure(withClientcoSource(opts.config), opts.home, clientcoAdmittedWall(), opts.fs);
  const clientcoExtra = bucket(prof.notes - base.notes, prof.chunks - base.chunks, prof.estTokens - base.estTokens, prof.worstTokens - base.worstTokens);
  const total = bucket(prof.notes, prof.chunks, prof.estTokens, prof.worstTokens);
  const n = opts.notesPerDay ?? DEFAULT_NOTES_PER_DAY;
  const q = opts.queriesPerDay ?? DEFAULT_QUERIES_PER_DAY;
  const chunksPerNote = total.notes ? total.chunks / total.notes : 0;
  const tokensPerChunk = total.chunks ? total.estTokens / total.chunks : 0;
  const monthlyTokens = Math.ceil(n * 30 * chunksPerNote * tokensPerChunk);
  return {
    base, clientcoExtra, total,
    totalWithSafety: { estTokens: SAFETY_FACTOR * total.estTokens, usd: SAFETY_FACTOR * total.usd },
    capUsd: HARD_MONTHLY_CAP_USD,
    clientcoRuleIds: clientcoRuleIds(),
    steady: {
      notesPerDay: n, chunksPerNote, tokensPerChunk, monthlyTokens, monthlyUsd: usdForTokens(monthlyTokens),
      queriesPerDay: q, queryMonthlyUsd: usdForTokens(q * 30 * QUERY_TOKENS_ASSUMED),
    },
  };
}

const usd = (x: number) => `$${x.toFixed(6)}`;

export function formatEstimate(r: EstimateReport): string {
  const row = (label: string, b: Bucket) =>
    `  ${label}: ${b.notes} notes, ${b.chunks} chunks, ~${b.estTokens} tokens (worst case ${b.worstTokens}) = ${usd(b.usd)} (worst case ${usd(b.usdWorst)})`;
  const s = r.steady;
  return [
    'embedding cost estimate (offline dry run: no database, no network; counts only) at $0.02 / 1M tokens',
    row('(a) current wall', r.base),
    `      (quarantined by the current wall in this dry run: ${r.base.quarantined})`,
    row(`(b) upper bound, notes admitted once ClientCo-named hard rules [${r.clientcoRuleIds.join(', ')}] are lifted`, r.clientcoExtra),
    row('(a)+(b)', r.total),
    `  total with safety factor ${SAFETY_FACTOR}: ~${r.totalWithSafety.estTokens} tokens = ${usd(r.totalWithSafety.usd)} = ${((100 * r.totalWithSafety.usd) / r.capUsd).toFixed(4)}% of the $${r.capUsd.toFixed(2)} monthly cap`,
    `  steady state: +${s.notesPerDay} new/changed notes per day x ${s.chunksPerNote.toFixed(2)} chunks x ${s.tokensPerChunk.toFixed(1)} tokens x 30 days = ~${s.monthlyTokens} tokens = ${usd(s.monthlyUsd)} / month (upper bound: every chunk of a changed note re-embedded)`,
    `  query embeds: ${s.queriesPerDay} searches/day x ${QUERY_TOKENS_ASSUMED} tokens x 30 = ${usd(s.queryMonthlyUsd)} / month (local ledger, not in embed_usage)`,
  ].join('\n');
}
