// Test-only fixture for the C7 read path (docs/plans/2026-11-19-c7-read-path.md): a SYNTHETIC workspace
// corpus (notes with headings, lock notes with supersession / expiry / a standing marker, fact rules and
// focus with a repeated subject, headed decisions with applies_to and Links, an expired decision, HQ sync
// notes and one sync deletion), written through the REAL write route (WorkspaceWrites.commit + sync, as
// /mcp does), plus an in-process MCP client (SDK Client over InMemoryTransport) on a personal connection,
// a recording Db and the output normaliser the parity tests compare with. No network, no Neon, no real
// workspace or key; every word is synthetic (no private term, no personal name).
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { Db } from '../../src/db.ts';
import { createMcpState, createZeusiMcpServer, type McpDeps, type McpState } from '../../src/mcp-server.ts';
import type { PreviewDocument, SyncItem, WorkspaceCaller } from '../../src/workspace-write.ts';
import { ABOUT_SOURCE_TS } from '../../src/about.ts';
import { commitDocs, decisionLog, factEntry, hqItem, type C6Fixture } from './c6-fixture.ts';
import { safeMkdtemp } from './safe-tmp.ts';

/**
 * Dates. Notes carry FIXED past dates (their import uri hashes the date, so it stays the same on every run).
 * Decisions and facts must lie in the past (the importer refuses a future timestamp) and inside the default
 * 14-day startup window (`said_at >= now()` in SQL), so they are relative to the day the test runs:
 * C7_DAYS[k] = k days before today (UTC). C7_NOW (the tools' clock: lock expiry, recency) is today 12:00 UTC.
 */
const TODAY_MS = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate());
export const C7_DAYS: readonly string[] = Array.from({ length: 15 }, (_, k) => new Date(TODAY_MS - k * 86_400_000).toISOString().slice(0, 10));
export const C7_NOW = new Date(TODAY_MS + 12 * 3_600_000);

/**
 * The year of the notes that carry LOCKS (the markdown 'Release rules' note and the HQ lock items). Note-lock
 * recency (src/note-locks.ts rankLocksForTask) is 0.3 * exp(-age / 90) with age = C7_NOW - the note's fixed date:
 * with a recent fixed date that term moved every day (scores, and in time the order against the decisions, whose
 * dates move with C7_NOW). At more than 2500 days old it is below 1e-11 and rounds to exactly 0 at the scorer's
 * 1e-6, so the scores and the order are the same on every run day. Still a FIXED date (stable import uris).
 * The recency term itself is pinned at a fixed clock in test/c7-golden-date-stable.test.ts.
 */
export const C7_FIXED_LOCK_YEAR = '2019';
/** The paths the second sync deletes (a plain note and a lock note). */
export const C7_SYNC_DELETED: readonly string[] = ['beta/2026-10-17-kw.md', `gamma/${C7_FIXED_LOCK_YEAR}-10-06-kt.md`];

// A small deterministic PRNG (mulberry32) for the generated notes: same corpus every run.
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const VOCAB = [
  'harbor', 'lantern', 'meadow', 'copper', 'river', 'falcon', 'pricing', 'launch', 'deploy', 'release', 'budget', 'invoice',
  'backup', 'schema', 'router', 'cache', 'index', 'shard', 'ledger', 'review', 'friday', 'weekend', 'staging', 'canary',
  'rollback', 'pipeline', 'storage', 'quota', 'alpha', 'beta', 'gamma', 'delta', 'orbit', 'pebble', 'willow', 'ember',
  'Harbor', 'LAUNCH', 'Pricing', '2026', '42', 'v2', 'q3', 'x9', 'node22', 'plan', 'notes', 'zeta',
];
const PUNCT = [' ', ' ', ' ', ' ', ', ', '; ', ': ', '! ', '? ', ' (', ') ', '. ', '\n', '  '];

function sentence(r: () => number, n: number): string {
  let s = '';
  for (let i = 0; i < n; i++) s += VOCAB[Math.floor(r() * VOCAB.length)]! + PUNCT[Math.floor(r() * PUNCT.length)]!;
  return s.trim();
}

/** About 40 markdown notes: generated ones with headings, plus the lock notes. */
export function c7Notes(): PreviewDocument[] {
  const r = prng(7);
  const out: PreviewDocument[] = [];
  for (let i = 0; i < 34; i++) {
    const sections = 1 + Math.floor(r() * 3);
    let text = `---\ndate: 2026-10-${String(1 + (i % 28)).padStart(2, '0')}\n---\n# Note ${i} ${sentence(r, 2)}\n\n${sentence(r, 6 + Math.floor(r() * 20))}\n`;
    for (let s = 0; s < sections; s++) text += `\n## Part ${s} ${sentence(r, 2)}\n\n${sentence(r, 10 + Math.floor(r() * 40))}\n`;
    out.push({ kind: 'markdown', title: `Synthetic note ${i}`, text });
  }
  const lockNote = (title: string, fm: string, body: string): PreviewDocument => ({ kind: 'markdown', title, text: `---\ntitle: ${title}\n${fm}---\n${body}\n` });
  out.push(
    lockNote('Release rules', `date: ${C7_FIXED_LOCK_YEAR}-10-10\nlocks:\n  - "never deploy on friday"\n  - "release notes before every launch"\nstanding_locks: [2]\n`,
      '# Release rules\n\nWhy: the release pipeline needs a quiet weekend.'),
    lockNote('Cache plan', 'date: 2026-10-11\n', '# Cache plan\n\n## Shards\n\nThe cache keeps one shard per index. "Quoted words" and it\'s fine.\n\n## Router\n\nThe router reads the ledger, then the cache.'),
  );
  return out;
}

/**
 * A headed decision entry (src/importers/structured.ts grammar) whose Links: header comes FIRST and names neutral
 * targets: the parity corpus stays inside the lexer's parity class (KTD9). Link uris are compound tokens for the
 * Postgres parser (paths, hosts); placed before every query word they only shift later positions by a constant,
 * which ts_rank_cd ignores. test/c7-parity.test.ts pins the divergence when a link uri holds a query word.
 */
function entry(words: string, o: { at: string; kind?: string; links?: string[]; applies?: string[]; expires?: string }): string {
  return `## ${o.at} me\nDecision: ${o.kind ?? 'go'}\nSaid-at-precision: minute\n${o.links ? `Links: ${o.links.join(', ')}\n` : ''}`
    + `${o.expires ? `Expires: ${o.expires}\n` : ''}${o.applies ? `Applies-to: ${o.applies.join(', ')}\n` : ''}\n${words}\n`;
}

/** k days before today, at hh:00 UTC (always in the past for k >= 1). */
const AT = (k: number, hh = 10) => `${C7_DAYS[k]!}T${String(hh).padStart(2, '0')}:00:00+00:00`;

/**
 * The decision log: decisions and facts inside the last 14 days (see C7_DAYS), one decision with an expiry in
 * the past (not current), facts with a repeated subject. Note links point at the HQ sync notes (fixed uris).
 */
export function c7DecisionLog(): PreviewDocument {
  const entries = [
    entry('We launch the beta on the harbor router after the budget review.', { at: AT(2), applies: ['launch', 'harbor router'], links: ['gh:Synthetic-Org/zz#12', 'hq:alpha/2026-10-15-kx.md#Kx'] }),
    entry('Pricing stays frozen; no invoice changes this quarter.', { at: AT(3), kind: 'lock', applies: ['pricing', 'invoice'] }),
    entry('Deploy the canary to staging every weekend.', { at: AT(4), kind: 'park', applies: ['deploy', 'staging'], links: ['gh:Synthetic-Org/zz', 'job:nightly'] }),
    entry('The cache index uses one shard per workspace.', { at: AT(5), applies: ['cache'] }),
    entry('Rollback the pipeline if the ledger review fails.', { at: AT(6), kind: 'stop', applies: ['rollback', 'pipeline'], links: ['lane:qq'] }),
    entry('Old storage quota decision that has expired.', { at: AT(7), applies: ['storage'], expires: '2001-01-01T00:00:00Z' }),
    // Applies-to of stopwords only: a task matches it through a_hit alone (no task term is in the decision).
    entry('Keep the backlog short.', { at: AT(10), applies: ['to do'] }),
    entry('Harbor pricing launch plan for q3 2026.', { at: AT(8), applies: ['pricing', 'launch'], links: ['hq:alpha/2026-10-16-ky.md', 'hq:alpha/missing-kz.md'] }),
  ];
  const facts = [
    factEntry('rule', 'deploys', 'Deploys need a green canary first.', AT(1, 9)),
    factEntry('rule', 'pricing', 'Pricing changes need a ledger entry.', AT(2, 9)),
    factEntry('focus', 'launch', 'Focus: the beta launch on the harbor router.', AT(3, 9)),
    factEntry('focus', 'launch', 'Older focus on the launch budget.', AT(5, 9)),
    factEntry('focus', 'storage', 'Storage quota review this week.', AT(4, 9)),
  ];
  return decisionLog(`# Decisions\n\n${[...entries, ...facts].join('\n')}`);
}

const lockItem = (file: string, title: string, fm: string, body: string): SyncItem =>
  ({ path: `gamma/${file}`, text: `---\nproject: gamma\nkind: memory\ndate: ${file.slice(0, 10)}\ntitle: ${title}\nsource: assistant\n${fm}---\n${body}\n` });

/** HQ sync items (hq: notes); 'Gone note' and 'Gone lock' are deleted by the second sync. */
export function c7Sync(): SyncItem[] {
  return [
    hqItem('alpha', '2026-10-15-kx.md', 'Harbor launch', '# Harbor launch\n\nThe harbor launch needs the router and the cache.'),
    hqItem('alpha', '2026-10-16-ky.md', 'Ledger review', '# Ledger review\n\nThe ledger review checks every invoice.'),
    hqItem('beta', '2026-10-17-kw.md', 'Gone note', '# Gone note\n\nThis meadow note is deleted by the next sync.'),
    // Lock notes with the lifecycle keys (the HQ sync keeps supersedes / until; the markdown import does not).
    lockItem(`${C7_FIXED_LOCK_YEAR}-10-01-kp.md`, 'Old pricing lock', 'locks:\n  - "pricing frozen until the budget review"\n', '# Pricing\n\nThe pricing lock of the first quarter.'),
    lockItem(`${C7_FIXED_LOCK_YEAR}-10-12-kq.md`, 'New pricing lock', 'locks:\n  - "pricing changes need a ledger entry"\nsupersedes:\n  - "[[Old pricing lock]]"\n', '# Pricing\n\nReplaces the old pricing lock.'),
    lockItem(`${C7_FIXED_LOCK_YEAR}-10-05-kr.md`, 'Storage lock', 'locks:\n  - "no storage quota raise"\nuntil: "2026-10-15T00:00:00+01:00"\n', '# Storage\n\nAn expired storage lock.'),
    lockItem(`${C7_FIXED_LOCK_YEAR}-10-06-kt.md`, 'Gone lock', 'locks:\n  - "meadow lock of a deleted note"\n', '# Gone lock\n\nDeleted by the next sync: its lock must never be served.'),
    // A decision note: its decision's source_note resolves to this note (source_uri without the #fragment).
    {
      path: 'alpha/2026-10-18-kv.md',
      text: `---\nproject: alpha\nkind: decision\ndate: 2026-10-18\ntitle: Router decision\nsource: assistant\n---\n${
        entry('Ship the harbor router behind the cache flag.', { at: AT(9), applies: ['harbor router', 'cache'], links: ['hq:alpha/2026-10-16-ky.md#Ky'] })}`,
    },
  ];
}

/** Search queries in the parity class (ASCII words, phrases, or, negation, mixed case, digits). */
export const C7_QUERIES: readonly string[] = [
  'harbor', 'harbor router', '"harbor router"', 'pricing or invoice', 'launch -pricing', 'LAUNCH', 'Pricing ledger', 'cache shard',
  '"the cache"', 'deploy friday', 'release notes', 'budget review', 'q3 x9', '42', 'v2 node22', 'meadow', 'canary staging weekend',
  'rollback pipeline', 'storage quota', 'falcon or ember or willow', '-harbor', 'copper river', '"pricing frozen"', 'alpha beta gamma',
  'it\'s fine', 'quoted words', 'zeta', 'orbit pebble', 'review', 'lantern meadow copper', 'what is zeusi', 'invoice',
];

/** context_for_task tasks. */
export const C7_TASKS: readonly string[] = [
  'deploy the canary on friday', 'change the pricing', 'pricing frozen budget review', 'meadow lock deleted note', 'launch the harbor router', 'review the ledger', 'raise the storage quota',
  'rollback the pipeline', 'update the cache shard', 'write release notes', 'plan q3 2026', 'budget review for the launch',
  'harbor router pricing launch', 'staging weekend deploy', 'to do list', 'nothing matches xylophone', 'invoice changes', 'the cache index',
];

/** Fill one workspace with the whole corpus through the real write route; returns the commit / sync results. */
export async function fillC7(f: C6Fixture, c: WorkspaceCaller): Promise<void> {
  const notes = c7Notes();
  // Two previews (the preview caps), then the decision log, then sync + a sync deletion.
  for (const part of [notes.slice(0, 20), notes.slice(20), [c7DecisionLog()]]) {
    const r = await commitDocs(f, c, part);
    assert.equal((r as { status?: string }).status ?? 'ok', 'ok', JSON.stringify(r));
  }
  const s1 = await f.ww.sync(c, c7Sync(), []);
  assert.ok(s1.status === 'ok', JSON.stringify(s1));
  const s2 = await f.ww.sync(c, [], [...C7_SYNC_DELETED]);
  assert.ok(s2.status === 'ok', JSON.stringify(s2));
}

export interface Recorded { sql: string; params: unknown[] }

/** A Db that records every statement and its parameters (the off-route golden, the "no user text to Postgres" check). */
export function recordingDb(db: Db, log: Recorded[]): Db {
  return {
    label: db.label, ...(db.transport ? { transport: db.transport } : {}),
    query: (sql, params) => {
      log.push({ sql, params: params ? [...params] : [] });
      return db.query(sql, params);
    },
    exec: (sql) => {
      log.push({ sql, params: [] });
      return db.exec(sql);
    },
    close: () => db.close(),
  };
}

export interface ToolCall { isError: boolean; text: string; json: Record<string, unknown> | null }
export interface McpHarness { call: (name: string, args?: Record<string, unknown>) => Promise<ToolCall>; close: () => Promise<void> }

/** An in-process MCP client on `deps` (one server per call, like the stateless hosted handler). */
export async function mcpHarness(deps: () => McpDeps, state: McpState = createMcpState()): Promise<McpHarness> {
  return {
    call: async (name, args = {}) => {
      const server = createZeusiMcpServer(deps(), state);
      const [a, b] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'c7-test', version: '0' });
      await Promise.all([server.connect(a), client.connect(b)]);
      try {
        const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ type: string; text?: string }> };
        const text = r.content.map((x) => x.text ?? '').join('\n');
        let json: Record<string, unknown> | null = null;
        try {
          json = JSON.parse(text) as Record<string, unknown>;
        } catch { /* a plain-text refusal */ }
        return { isError: r.isError === true, text, json };
      } finally {
        await client.close();
        await server.close();
      }
    },
    close: async () => {},
  };
}

/** Personal-workspace deps as src/mcp-hosted.ts builds them (read grant, no embeddings), with a fixed clock. */
export function personalDeps(o: { tenantRead: () => Promise<Db>; home?: string; extra?: Partial<McpDeps> }): McpDeps {
  const home = o.home ?? safeMkdtemp(join(tmpdir(), 'zeusi-c7-home-'));
  return {
    env: { HOME: home }, home, readService: 'zeusi_ro', workspace: 'personal', tenantRead: o.tenantRead, toolClass: 'read', tokenId: 'grant-c7',
    writeService: undefined, embeddings: () => null, now: () => C7_NOW,
    feedbackPath: join(home, '.zeusi', 'fb.jsonl'), queryLedgerPath: join(home, '.zeusi', 'ql.json'), ...(o.extra ?? {}),
  };
}

/** A tool output without the per-call fields (query_id, generated_at). */
export function normalised(j: Record<string, unknown> | null): unknown {
  if (j === null) return null;
  const { query_id: _q, generated_at: _g, ...rest } = j;
  return rest;
}

/** Every read tool call the parity / golden tests make, in a fixed order. */
export function readCalls(): Array<[string, Record<string, unknown>]> {
  return [
    ['zeusi_startup', {}],
    ['zeusi_startup', { days: 90 }],
    ['zeusi_onboarding_status', {}],
    ['zeusi_onboarding_status', { scope: 'work' }],
    ...C7_QUERIES.map((q): [string, Record<string, unknown>] => ['zeusi_search', { query: q }]),
    ['zeusi_search', { query: 'harbor', limit: 3 }],
    ['zeusi_search', { query: 'pricing', scope: 'work', limit: 5 }],
    ['zeusi_search', { query: 'pricing', scope: 'client' }],
    ...C7_TASKS.map((t): [string, Record<string, unknown>] => ['zeusi_context_for_task', { task: t }]),
    ['zeusi_context_for_task', { task: 'pricing launch', limit: 2 }],
  ];
}

/**
 * Replace the run-day dependent parts (C7_DAYS dates, the hashes derived from them) with stable tokens.
 * ABOUT_SOURCE_TS (a fixed stamp in src/about.ts) is tokenised FIRST, as the whole timestamp: while it
 * lies inside the rolling C7_DAYS window, a date-only rewrite would turn it into D-<k> with k growing
 * by one every day. Only the full stamp is replaced, never its bare date, which a fixture decision can
 * share on some run days.
 */
export function stable(v: unknown, days: readonly string[] = C7_DAYS): unknown {
  if (typeof v === 'string') {
    let s = v.split(ABOUT_SOURCE_TS).join('ABOUT_TS');
    days.forEach((d, k) => { s = s.split(d).join(`D-${k}`); });
    return s.replace(/(D-\d+-(?:decision|memory|chat))-[0-9a-f]{8}/g, '$1-HASH').replace(/\/entry\/[0-9a-f]{16}/g, '/entry/HASH');
  }
  if (Array.isArray(v)) return v.map((x) => stable(x, days));
  if (v && typeof v === 'object' && !(v instanceof Date)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, stable(x, days)]));
  if (v instanceof Date) return stable(v.toISOString(), days);
  return v;
}

export interface GoldenCall { tool: string; args: Record<string, unknown>; statements: Recorded[]; output: unknown; isError: boolean }

/** Run every read call on the P workspace (off) with `extra` deps; one recording per call. */
export async function runCalls(fx: C6Fixture, tenant: string, extra: Parameters<typeof personalDeps>[0]['extra'] = {}): Promise<GoldenCall[]> {
  const out: GoldenCall[] = [];
  let log: Recorded[] = [];
  const h = await mcpHarness(() => personalDeps({ tenantRead: async () => recordingDb(await fx.router.open(tenant), log), extra }));
  for (const [tool, args] of readCalls()) {
    log = [];
    const r = await h.call(tool, args);
    out.push({ tool, args, statements: stable(log) as Recorded[], output: stable(normalised(r.json)), isError: r.isError });
  }
  return out;
}

