// Count-only comparison of the walls, using the vault importer's own pipeline offline
// (importVault dry run: path gate + wall gate per note and per chunk). Used by
// `wall-dryrun.ts --compare-old` and by test/wall-compare.test.ts.
//
// Walls: 0009 (ingest run 10 ran with it), 0010 (head of PR #3 before 0011: ClientCo lifted,
// soft currency / P&L still on, no Plankiva rule) and 0011 (the seed wall: Plankiva variants
// hard rule, soft currency / P&L lifted).
//
// READ-ONLY (O_RDONLY opens through the importer and the walks below). No database, no
// network. The returned report holds counts and rule ids / kinds / short labels only:
// never a path, a title, a tag or any text. plankivaFalsePositives() also returns the
// matched tokens (the word the rule matched, nothing around it), on request only.

import { closeSync, constants, openSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { importVault, scopeFor, type VaultDryRunObservation, type VaultFs } from '../src/importers/vault.ts';
import { mentionsProtectedName, parseToml, validateSources, type SourceSpec } from '../src/sources.ts';
import {
  PROTECTED_VARIANTS_REGEX, PROTECTED_SPELLING_REGEX, compileWall, LIFTED_0011, legacySeedWall, pctDecode, pgRegexToJs, seedRulesWithIds,
  seedWall, WALL_CONFUSABLES, wall0010SeedWall, wallNorm, type Wall, type WallRule,
} from '../src/wall.ts';

/** Production ingest_runs id 10 (14 Nov 2026), as reported by HQ. Ran with the 0009 wall. */
export const RUN10 = { admitted: 294, chunks: 1876, quarantined: 199, pathGated: 12, content: 187 };

/**
 * Rules HQ decided to KEEP (not named by the owner), reported per rule for ClientCo / Northbank notes:
 * soft account / login number, soft IBAN, the agent-config repo rule, the desk P&L path / lane rules.
 */
export const KEPT_JUDGEMENT_RULES: ReadonlyArray<Pick<WallRule, 'kind' | 'pattern'>> = [
  { kind: 'regex', pattern: '\\m(login|account|acct)\\M[^0-9\\n]{0,4}[0-9]{5,}' },
  { kind: 'regex', pattern: '(?c)\\m[A-Z]{2}[0-9]{2}[ ]?([A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\\M' },
  { kind: 'repo', pattern: 'example-org/agent-config-backup*' },
  { kind: 'path_glob', pattern: '**pnl**' },
  { kind: 'path_glob', pattern: '**p&l**' },
  { kind: 'path_glob', pattern: '**/lanes/desk-pnl/**' },
  { kind: 'path_glob', pattern: '**/lanes/session-pnl/**' },
  { kind: 'lane', pattern: '*pnl*' },
  { kind: 'lane', pattern: 'desk-pnl' },
  { kind: 'lane', pattern: 'session-pnl' },
];

export interface CompareInput {
  vault: string;
  /** A sources TOML (default config/sources.example.toml). Only vault_note sources are used; their root becomes `vault`. */
  configPath: string;
  home: string;
  fs?: VaultFs;
}

type Obs = VaultDryRunObservation;
interface Run {
  obs: Obs[];
  admitted: Map<string, Extract<Obs, { outcome: 'admitted' }>>;
  content: Map<string, Extract<Obs, { outcome: 'content' }>>;
  pathGated: Array<Extract<Obs, { outcome: 'path_gated' }>>;
  errors: number;
  chunks: number;
  status: string;
}

export interface RunSummary {
  admitted: number; content: number; pathGated: number; errors: number; chunks: number; status: string;
  byScope: Record<string, number>;
  /** Quarantined (content: first rule; path-gated: the gating rule), by rule label. */
  quarantinedByRule: Record<string, number>;
  /** Quarantined by scope (path-gated entries by the scope their path maps to). */
  quarantinedByScope: Record<string, number>;
}

export interface Reconstruction {
  contentNowAdmitted: number;
  contentStillQuarantined: Record<string, number>;
  pathEntriesNowOpen: number;
  pathEntriesStillGated: Record<string, number>;
  notesUnderOpenedEntriesAdmitted: number;
  notesUnderOpenedEntriesQuarantined: number;
  /** Of the run-10 quarantined (content notes + notes under opened path entries): admitted now. */
  quarantinedNowAdmitted: number;
  /** Notes run 10 admitted that this wall blocks, by rule (the Plankiva rule: notes that newly carry an Plankiva hit). */
  admittedNowBlocked: Record<string, number>;
}

export interface CompareResult {
  vaultMdFiles: number;
  vaultSymlinks: number;
  runs: Record<'run10Old' | 'run10Head' | 'run10New' | 'cfgHead' | 'cfgNew' | 'fullHead' | 'fullNew', RunSummary>;
  /** Run 10 (0009 wall, reconstructed) vs the 0010 wall and vs the 0011 wall, same config. */
  run10To0010: Reconstruction;
  run10To0011: Reconstruction;
  /** D vs C and E vs E0 (0010 -> 0011): newly admitted by the 0010 rule that blocked them; newly blocked by the 0011 rule. */
  newlyAdmittedByHeadRule: { cfg: Record<string, number>; full: Record<string, number> };
  newlyBlockedByNewRule: { cfg: Record<string, number>; full: Record<string, number> };
  /** Each lifted soft rule on its own: how many newly admitted notes (E) it would block. */
  newlyAdmittedAnyLiftedRule: Record<string, number>;
  /** Kept judgement rules, ClientCo / Northbank notes (E, 0011 wall): blocked by the rule on its own; admitted if only that rule were lifted. */
  keptRules: Array<{ rule: string; clientcoBlocks: number; northbankBlocks: number; clientcoOnlyBlocker: number; northbankOnlyBlocker: number }>;
  plankivaProof: {
    admittedChecked: number; chunksChecked: number;
    /** Independent scanner (independentPlankivaSignal: own decoding, folding and letter-stream checks). */
    admittedNotesWithSignal: number; admittedChunksWithSignal: number;
    /** Second opinion with the gate function (mentionsProtectedName). */
    admittedNotesWithGateSignal: number; admittedChunksWithGateSignal: number;
    rawFilesWithSignal: number; rawFilesWithSignalAdmitted: number;
  };
}

const SHORT: Record<string, string> = {
  [PROTECTED_VARIANTS_REGEX]: 'Plankiva variants regex (0011)',
  [PROTECTED_SPELLING_REGEX]: 'Plankiva spelling regex (0010)',
};
export const label = (rules: readonly WallRule[], id: number | null | undefined) => {
  if (id === null || id === undefined) return 'no rule (symlink leaving the vault / dangling)';
  const r = rules.find((x) => x.id === id);
  if (!r) return `rule ${id}`;
  return `rule ${r.id} ${r.kind}${r.hard ? ' (hard)' : ' (soft)'} ${SHORT[r.pattern] ?? JSON.stringify(r.pattern)}`;
};
const bump = (m: Record<string, number>, k: string) => {
  m[k] = (m[k] ?? 0) + 1;
};
const under = (rel: string, entry: string) => rel === entry || rel.startsWith(`${entry}/`);

/** Every string leaf of a row (frontmatter values, tags, links included). */
function strings(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.flatMap(strings);
  if (v && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => [k, ...strings(x)]);
  return [];
}

function* walkMd(dir: string, rel = ''): Generator<{ rel: string; abs: string; link: boolean }> {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith('.') || e.name === 'node_modules') continue;
    const r = rel ? `${rel}/${e.name}` : e.name;
    const abs = join(dir, e.name);
    if (e.isDirectory()) yield* walkMd(abs, r);
    else if (e.name.endsWith('.md') && (e.isFile() || e.isSymbolicLink())) yield { rel: r, abs, link: e.isSymbolicLink() };
  }
}

function readOnly(p: string): string {
  const fd = openSync(p, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

// ---------------------------------------------------------------------------
// Independent Plankiva scanner for the proof. It does NOT use the wall regexes:
// own percent-decoding, own Unicode folding (NFKD, marks / format / ignorable code points
// dropped, NFKC, lower case, the shared look-alike table), leetspeak (4 @ -> a, 1 ! | -> i),
// then two letter-stream checks for p+l+a+n+k+i+v+a+:
//   tight:  every character that is not a letter or whitespace removed (any number of
//           separators, embedded in longer words);
//   spaced: runs of single-letter tokens joined ("p l a n k i v a", "P. L. A. N. K. I. V. A.").
// It is broader than the wall rule (no 3-separator limit), so it errs on flagging.

function decodeAll(s: string): string {
  let cur = s;
  for (let i = 0; i < 10; i++) {
    let next: string;
    try {
      next = decodeURIComponent(cur);
    } catch {
      next = cur.replace(/%([0-9A-Fa-f]{2})/g, (m, h: string) => {
        const c = parseInt(h, 16);
        return c < 0x80 ? String.fromCharCode(c) : m;
      });
    }
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

function fold(s: string): string {
  let t = s.normalize('NFKD').replace(/[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}]/gu, '').normalize('NFKC');
  t = [...t].map((c) => WALL_CONFUSABLES.get(c) ?? c).join('').toLowerCase();
  return t.replace(/[4@]/g, 'a').replace(/[1!|]/g, 'i');
}

const LETTERS = /p+l+a+n+k+i+v+a+/;
export function independentPlankivaSignal(s: string): boolean {
  for (const x of new Set([s, decodeAll(s)])) {
    const f = fold(x);
    if (LETTERS.test(f.replace(/[^a-z\s]/g, ''))) return true;
    const singles: string[] = [];
    for (const tok of f.split(/\s+/)) {
      const letters = tok.replace(/[^a-z]/g, '');
      if (letters.length === 1) singles.push(letters);
      else {
        if (LETTERS.test(singles.join(''))) return true;
        singles.length = 0;
      }
    }
    if (LETTERS.test(singles.join(''))) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------

export async function compareCounts(input: CompareInput): Promise<CompareResult> {
  const t = parseToml(readFileSync(input.configPath, 'utf8'));
  const raw = Array.isArray(t['source']) ? (t['source'] as Array<Record<string, unknown>>) : [];
  t['source'] = raw.filter((s) => s['kind'] === 'vault_note').map((s) => ({ ...s, root: input.vault })) as never;
  delete t['github'];
  const cfg = validateSources(t, seedWall(), { home: input.home });
  const gh = { org: 'example-org', repos: [], northbankRepos: [] };
  const run10Sources = cfg.sources.filter((s) => s.scope !== 'client'); // ingest run 10 had no clientco source
  const clientcoSources = cfg.sources.filter((s) => s.scope === 'client');
  const fullSources: SourceSpec[] = [
    { name: 'full-vault', kind: 'vault_note', scope: 'work', root: input.vault, include: ['**/*.md'], exclude: [] },
    ...clientcoSources,
  ];

  const w09 = legacySeedWall();
  const w10 = wall0010SeedWall();
  const w11 = seedWall();
  const runOnce = async (sources: SourceSpec[], wall: Wall): Promise<Run> => {
    const obs: Obs[] = [];
    const r = await importVault({
      config: { sources, github: gh }, mode: 'full', dryRun: true, home: input.home, ...(input.fs ? { fs: input.fs } : {}),
      logPaths: false, dryRunWall: wall, dryRunObserve: (o) => obs.push(o),
    });
    const run: Run = { obs, admitted: new Map(), content: new Map(), pathGated: [], errors: 0, chunks: 0, status: r.status };
    for (const o of obs) {
      if (o.outcome === 'admitted') {
        run.admitted.set(o.rel, o);
        run.chunks += o.chunks.length;
      } else if (o.outcome === 'content') run.content.set(o.rel, o);
      else if (o.outcome === 'path_gated') run.pathGated.push(o);
      else run.errors++;
    }
    return run;
  };
  const run10Old = await runOnce(run10Sources, w09);
  const run10Head = await runOnce(run10Sources, w10);
  const run10New = await runOnce(run10Sources, w11);
  const cfgHead = await runOnce(cfg.sources, w10);
  const cfgNew = await runOnce(cfg.sources, w11);
  const fullHead = await runOnce(fullSources, w10);
  const fullNew = await runOnce(fullSources, w11);

  const firstRule = (c: Extract<Obs, { outcome: 'content' }>) => c.ruleIds.find((x) => x !== null) ?? null;
  const summary = (r: Run, wall: Wall): RunSummary => {
    const byScope: Record<string, number> = {};
    const quarantinedByRule: Record<string, number> = {};
    const quarantinedByScope: Record<string, number> = {};
    for (const a of r.admitted.values()) bump(byScope, a.scope);
    for (const c of r.content.values()) {
      bump(quarantinedByRule, label(wall.rules, firstRule(c)));
      bump(quarantinedByScope, c.scope);
    }
    for (const p of r.pathGated) {
      bump(quarantinedByRule, label(wall.rules, p.ruleId));
      bump(quarantinedByScope, scopeFor(p.rel, []));
    }
    return { admitted: r.admitted.size, content: r.content.size, pathGated: r.pathGated.length, errors: r.errors, chunks: r.chunks, status: r.status, byScope, quarantinedByRule, quarantinedByScope };
  };

  const reconstruct = (old: Run, now: Run, wall: Wall): Reconstruction => {
    const rec: Reconstruction = {
      contentNowAdmitted: 0, contentStillQuarantined: {}, pathEntriesNowOpen: 0, pathEntriesStillGated: {},
      notesUnderOpenedEntriesAdmitted: 0, notesUnderOpenedEntriesQuarantined: 0, quarantinedNowAdmitted: 0, admittedNowBlocked: {},
    };
    for (const [rel] of old.content) {
      if (now.admitted.has(rel)) rec.contentNowAdmitted++;
      else {
        const c = now.content.get(rel);
        bump(rec.contentStillQuarantined, c ? label(wall.rules, firstRule(c)) : 'path-gated or error now');
      }
    }
    for (const e of old.pathGated) {
      const still = now.pathGated.find((x) => x.rel === e.rel);
      if (still) {
        bump(rec.pathEntriesStillGated, label(wall.rules, still.ruleId));
        continue;
      }
      rec.pathEntriesNowOpen++;
      for (const rel of now.admitted.keys()) if (under(rel, e.rel)) rec.notesUnderOpenedEntriesAdmitted++;
      for (const rel of now.content.keys()) if (under(rel, e.rel)) rec.notesUnderOpenedEntriesQuarantined++;
    }
    rec.quarantinedNowAdmitted = rec.contentNowAdmitted + rec.notesUnderOpenedEntriesAdmitted;
    for (const rel of old.admitted.keys()) {
      if (now.admitted.has(rel)) continue;
      const c = now.content.get(rel);
      const p = now.pathGated.find((e) => under(rel, e.rel));
      bump(rec.admittedNowBlocked, c ? label(wall.rules, firstRule(c)) : p ? label(wall.rules, p.ruleId) : 'error');
    }
    return rec;
  };

  /** Why `old` did not admit rel: its content rule, or the path rule of the gated entry above it. */
  const oldRuleOf = (rel: string, old: Run): number | null | 'admitted' | 'not a candidate' => {
    const c = old.content.get(rel);
    if (c) return firstRule(c);
    const p = old.pathGated.find((e) => under(rel, e.rel));
    if (p) return p.ruleId;
    return old.admitted.has(rel) ? 'admitted' : 'not a candidate';
  };
  const newlyAdmitted = (head: Run, now: Run) => {
    const m: Record<string, number> = {};
    for (const rel of now.admitted.keys()) {
      if (head.admitted.has(rel)) continue;
      const why = oldRuleOf(rel, head);
      bump(m, typeof why === 'string' ? why : label(w10.rules, why));
    }
    return m;
  };
  const newlyBlocked = (head: Run, now: Run) => {
    const m: Record<string, number> = {};
    for (const rel of head.admitted.keys()) {
      if (now.admitted.has(rel)) continue;
      const c = now.content.get(rel);
      const p = now.pathGated.find((e) => under(rel, e.rel));
      bump(m, c ? label(w11.rules, firstRule(c)) : p ? label(w11.rules, p.ruleId) : 'error');
    }
    return m;
  };

  const liftedRules = w10.rules.filter((r) => LIFTED_0011.some((l) => l.kind === r.kind && l.pattern === r.pattern));
  const newlyAdmittedAnyLiftedRule: Record<string, number> = Object.fromEntries(liftedRules.map((r) => [label(w10.rules, r.id), 0]));
  const single = liftedRules.map((r) => ({ r, w: compileWall([r], []) }));
  for (const [rel, a] of fullNew.admitted) {
    if (fullHead.admitted.has(rel)) continue;
    for (const { r, w } of single) {
      if (w.check('notes', a.note).blocked || a.chunks.some((c) => w.check('chunks', c).blocked)) newlyAdmittedAnyLiftedRule[label(w10.rules, r.id)]!++;
    }
  }

  // ---- kept judgement rules: ClientCo / Northbank notes (full vault, 0011 wall)
  const scopeOfObs = (o: Obs) => ('scope' in o ? o.scope : scopeFor(o.rel, []));
  const blockedNotes = (run: Run) => {
    const out: Array<{ rel: string; scope: string }> = [];
    for (const c of run.content.values()) out.push({ rel: c.rel, scope: c.scope });
    for (const p of run.pathGated) out.push({ rel: p.rel, scope: scopeOfObs(p) });
    return out;
  };
  const keptRules: CompareResult['keptRules'] = [];
  const allIds = seedRulesWithIds();
  // Notes the importer refuses with no wall rule at all (the Plankiva path gate, symlinks): not a rule's doing.
  const baseline = new Set(blockedNotes(await runOnce(fullSources, compileWall([], []))).map((b) => b.rel));
  for (const k of KEPT_JUDGEMENT_RULES) {
    const rule = w11.rules.find((r) => r.kind === k.kind && r.pattern === k.pattern);
    if (!rule) continue;
    const alone = await runOnce(fullSources, compileWall([rule], []));
    const without = await runOnce(fullSources, compileWall(allIds.filter((r) => r.id !== rule.id), []));
    const row = { rule: label(w11.rules, rule.id), clientcoBlocks: 0, northbankBlocks: 0, clientcoOnlyBlocker: 0, northbankOnlyBlocker: 0 };
    for (const b of blockedNotes(alone)) {
      if (baseline.has(b.rel)) continue;
      if (b.scope === 'client') row.clientcoBlocks++;
      if (b.scope === 'product') row.northbankBlocks++;
    }
    for (const [rel, a] of without.admitted) {
      if (fullNew.admitted.has(rel)) continue;
      if (a.scope === 'client') row.clientcoOnlyBlocker++;
      if (a.scope === 'product') row.northbankOnlyBlocker++;
    }
    keptRules.push(row);
  }

  // ---- Plankiva proof: no admitted note or chunk carries any signal (0011 runs)
  const proof: CompareResult['plankivaProof'] = {
    admittedChecked: 0, chunksChecked: 0, admittedNotesWithSignal: 0, admittedChunksWithSignal: 0,
    admittedNotesWithGateSignal: 0, admittedChunksWithGateSignal: 0, rawFilesWithSignal: 0, rawFilesWithSignalAdmitted: 0,
  };
  const anyOf = (xs: string[], f: (s: string) => boolean) => xs.some(f) || f(xs.join('\n'));
  for (const run of [run10New, cfgNew, fullNew]) {
    for (const a of run.admitted.values()) {
      proof.admittedChecked++;
      const ns = [a.rel, ...strings(a.note)];
      if (anyOf(ns, independentPlankivaSignal)) proof.admittedNotesWithSignal++;
      if (anyOf(ns, mentionsProtectedName)) proof.admittedNotesWithGateSignal++;
      for (const ch of a.chunks) {
        proof.chunksChecked++;
        const cs = strings(ch);
        if (anyOf(cs, independentPlankivaSignal)) proof.admittedChunksWithSignal++;
        if (anyOf(cs, mentionsProtectedName)) proof.admittedChunksWithGateSignal++;
      }
    }
  }
  let vaultMdFiles = 0;
  let vaultSymlinks = 0;
  for (const f of walkMd(input.vault)) {
    vaultMdFiles++;
    if (f.link) {
      vaultSymlinks++;
      continue; // never followed here; the importer re-gates symlinks on their real path
    }
    let text: string;
    try {
      text = readOnly(f.abs);
    } catch {
      continue;
    }
    if (independentPlankivaSignal(f.rel) || independentPlankivaSignal(text) || mentionsProtectedName(f.rel) || mentionsProtectedName(text)) {
      proof.rawFilesWithSignal++;
      if (fullNew.admitted.has(f.rel) || cfgNew.admitted.has(f.rel)) proof.rawFilesWithSignalAdmitted++;
    }
  }

  return {
    vaultMdFiles, vaultSymlinks,
    runs: {
      run10Old: summary(run10Old, w09), run10Head: summary(run10Head, w10), run10New: summary(run10New, w11),
      cfgHead: summary(cfgHead, w10), cfgNew: summary(cfgNew, w11), fullHead: summary(fullHead, w10), fullNew: summary(fullNew, w11),
    },
    run10To0010: reconstruct(run10Old, run10Head, w10),
    run10To0011: reconstruct(run10Old, run10New, w11),
    newlyAdmittedByHeadRule: { cfg: newlyAdmitted(cfgHead, cfgNew), full: newlyAdmitted(fullHead, fullNew) },
    newlyBlockedByNewRule: { cfg: newlyBlocked(cfgHead, cfgNew), full: newlyBlocked(fullHead, fullNew) },
    newlyAdmittedAnyLiftedRule, keptRules, plankivaProof: proof,
  };
}

export function formatCompare(r: CompareResult): string {
  const L: string[] = [];
  const kv = (m: Record<string, number>, ind = '    ') => {
    const e = Object.entries(m).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
    if (!e.length) L.push(`${ind}(none)`);
    for (const [k, v] of e) L.push(`${ind}${k}: ${v}`);
  };
  const sc = (m: Record<string, number>) => Object.entries(m).sort().map(([k, v]) => `${k} ${v}`).join(', ') || 'none';
  const run = (name: string, x: RunSummary) =>
    L.push(`  ${name}: admitted ${x.admitted} (${x.chunks} chunks; ${sc(x.byScope)}), quarantined ${x.content + x.pathGated} (path-gated ${x.pathGated}, content ${x.content}; by scope: ${sc(x.quarantinedByScope)}), errors ${x.errors}, status ${x.status}`);
  L.push('wall compare (offline reconstruction, count-only, read-only; no database): 0009 (run 10) / 0010 (head) / 0011 walls');
  L.push(`  vault: ${r.vaultMdFiles} .md files (${r.vaultSymlinks} symlinks), dot folders skipped`);
  L.push('importer dry runs (importVault: path gate + wall gate per note and chunk):');
  run('A  run-10 config, 0009 wall', r.runs.run10Old);
  run('B  run-10 config, 0010 wall', r.runs.run10Head);
  run('B2 run-10 config, 0011 wall', r.runs.run10New);
  run('C  new config (+vault-client), 0010 wall', r.runs.cfgHead);
  run('D  new config (+vault-client), 0011 wall', r.runs.cfgNew);
  run('E0 full vault (**/*.md) + vault-client, 0010 wall', r.runs.fullHead);
  run('E  full vault (**/*.md) + vault-client, 0011 wall', r.runs.fullNew);
  const a = r.runs.run10Old;
  L.push(`ingest run 10 (prod, 0009 wall): admitted ${RUN10.admitted}, chunks ${RUN10.chunks}, quarantined ${RUN10.quarantined} (path-gated ${RUN10.pathGated}, content ${RUN10.content})`);
  const d = (x: number) => `${x >= 0 ? '+' : ''}${x}`;
  L.push(`  offline A vs prod: admitted ${d(a.admitted - RUN10.admitted)}, chunks ${d(a.chunks - RUN10.chunks)}, path-gated ${d(a.pathGated - RUN10.pathGated)}, content ${d(a.content - RUN10.content)}`);
  for (const [name, rec] of [['0010 wall (B)', r.run10To0010], ['0011 wall (B2)', r.run10To0011]] as const) {
    L.push(`  run 10 under the ${name}: of A's ${a.content + a.pathGated} quarantined, notes admitted: ${rec.quarantinedNowAdmitted} (content ${rec.contentNowAdmitted} of ${a.content}; under opened path entries ${rec.notesUnderOpenedEntriesAdmitted})`);
    L.push('    content still quarantined, by first rule:');
    kv(rec.contentStillQuarantined, '      ');
    L.push(`    path entries open: ${rec.pathEntriesNowOpen} of ${a.pathGated} (notes under them content-quarantined: ${rec.notesUnderOpenedEntriesQuarantined}); still gated, by rule:`);
    kv(rec.pathEntriesStillGated, '      ');
    L.push(`    notes A admitted that this wall blocks, by rule:`);
    kv(rec.admittedNowBlocked, '      ');
  }
  L.push('0010 -> 0011, newly admitted, by the 0010 rule that blocked them:');
  L.push('  D vs C:');
  kv(r.newlyAdmittedByHeadRule.cfg);
  L.push('  E vs E0:');
  kv(r.newlyAdmittedByHeadRule.full);
  L.push('  each lifted soft rule on its own, newly admitted notes it would block (E):');
  kv(r.newlyAdmittedAnyLiftedRule);
  L.push('0010 -> 0011, newly blocked (admitted by the 0010 wall, not by 0011), by the 0011 rule:');
  L.push('  D vs C:');
  kv(r.newlyBlockedByNewRule.cfg);
  L.push('  E vs E0:');
  kv(r.newlyBlockedByNewRule.full);
  L.push('still quarantined under 0011, by rule (D):');
  kv(r.runs.cfgNew.quarantinedByRule);
  L.push('still quarantined under 0011, by rule (E):');
  kv(r.runs.fullNew.quarantinedByRule);
  L.push('kept judgement rules (HQ, not lifted), ClientCo / Northbank notes in E: blocked by the rule on its own / admitted if only this rule were lifted:');
  for (const k of r.keptRules) L.push(`    ${k.rule}: clientco ${k.clientcoBlocks} / ${k.clientcoOnlyBlocker}, product ${k.northbankBlocks} / ${k.northbankOnlyBlocker}`);
  const p = r.plankivaProof;
  L.push(`Plankiva proof (B2, D, E): admitted notes checked ${p.admittedChecked}, chunks checked ${p.chunksChecked}`);
  L.push(`  independent scanner (own decoding + folding, letter streams; not the wall regexes): admitted notes with a signal ${p.admittedNotesWithSignal}, admitted chunks with a signal ${p.admittedChunksWithSignal}`);
  L.push(`  gate function (mentionsProtectedName): admitted notes with a signal ${p.admittedNotesWithGateSignal}, admitted chunks with a signal ${p.admittedChunksWithGateSignal}`);
  L.push(`  raw vault files with any signal (path or file text, either scanner): ${p.rawFilesWithSignal}; of them admitted (D or E): ${p.rawFilesWithSignalAdmitted}`);
  const zero = p.admittedNotesWithSignal + p.admittedChunksWithSignal + p.admittedNotesWithGateSignal + p.admittedChunksWithGateSignal + p.rawFilesWithSignalAdmitted === 0;
  L.push(`  RESULT: ${zero ? 'PASS (0 Plankiva items admitted)' : 'FAIL (Plankiva signal admitted: BLOCKER)'}`);
  return L.join('\n');
}

export async function compareOld(input: CompareInput): Promise<string> {
  return formatCompare(await compareCounts(input));
}

// ---------------------------------------------------------------------------
// False-positive measurement for the Plankiva rule over a folder of .md files.

const PROTECTED_VARIANTS_RE = pgRegexToJs(PROTECTED_VARIANTS_REGEX);
const PROTECTED_SPELLING_RE = pgRegexToJs(PROTECTED_SPELLING_REGEX);
/** The Plankiva signal as it was before 0011 (term "plankiva" + the 0010 spelling regex; raw, decoded, normalised). */
function pre0011Plankiva(s: string): boolean {
  return [s, pctDecode(s)].some((x) => {
    const n = wallNorm(x);
    return /plankiva/i.test(x) || n.includes('plankiva') || PROTECTED_SPELLING_RE.test(x) || PROTECTED_SPELLING_RE.test(n);
  });
}

export interface FalsePositiveReport {
  files: number;
  /** Files (path or text) the Plankiva rule matches (raw, decoded or normalised). */
  ruleHits: number;
  /** Of them: files where the pre-0011 Plankiva terms do not match (the rule alone flags them). */
  ruleOnly: number;
  /** Distinct matched tokens of the rule-only files (the word around the match, lower case), with file counts. */
  tokens: Record<string, number>;
}

export function plankivaFalsePositives(dir: string): FalsePositiveReport {
  const g = new RegExp(PROTECTED_VARIANTS_RE.source, 'gis');
  const rep: FalsePositiveReport = { files: 0, ruleHits: 0, ruleOnly: 0, tokens: {} };
  for (const f of walkMd(dir)) {
    if (f.link) continue;
    rep.files++;
    let text: string;
    try {
      text = readOnly(f.abs);
    } catch {
      continue;
    }
    const forms = [f.rel, text].flatMap((x) => [x, pctDecode(x)]).flatMap((x) => [x, wallNorm(x)]);
    if (!forms.some((x) => PROTECTED_VARIANTS_RE.test(x))) continue;
    rep.ruleHits++;
    if (pre0011Plankiva(f.rel) || pre0011Plankiva(text)) continue;
    rep.ruleOnly++;
    const seen = new Set<string>();
    for (const x of forms) {
      for (const m of x.matchAll(g)) {
        const before = /[\p{L}\p{N}_]*$/u.exec(x.slice(0, m.index))![0];
        const after = /^[\p{L}\p{N}_]*/u.exec(x.slice(m.index + m[0].length))![0];
        seen.add(`${before}${m[0]}${after}`.toLowerCase());
      }
    }
    for (const s of seen) bump(rep.tokens, s);
  }
  return rep;
}

export function formatFalsePositives(dir: string, r: FalsePositiveReport): string {
  const L = [`Plankiva rule false-positive scan (read-only, count-only; tokens are the matched word only): ${dir}`];
  L.push(`  .md files: ${r.files}; files the Plankiva rule matches: ${r.ruleHits}; of them with no pre-0011 Plankiva term (rule-only): ${r.ruleOnly}`);
  L.push('  distinct matched tokens in rule-only files (file count):');
  const e = Object.entries(r.tokens).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  if (!e.length) L.push('    (none)');
  for (const [k, v] of e) L.push(`    ${JSON.stringify(k)}: ${v}`);
  return L.join('\n');
}
