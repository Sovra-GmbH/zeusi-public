// Count-only wall dry run over a vault folder (the owner's Plankiva rule impact report).
//
//   node scripts/wall-dryrun.ts --vault ~/KnowledgeVault --sub Work
//   node scripts/wall-dryrun.ts --vault ~/KnowledgeVault --compare-old [--config config/sources.example.toml]
//   node scripts/wall-dryrun.ts --plankiva-fp ~/KnowledgeVault [--plankiva-fp ~/agent-runner/lanes]
//
// READ-ONLY: files are opened for reading only. Nothing is written, nothing is sent
// anywhere, no database is touched (rules come from SEED_RULES in src/wall.ts).
// OUTPUT IS COUNTS ONLY: rule ids/kinds/patterns and numbers. It never prints a
// path, a title, a tag, or any note text.
//
// --compare-old (0010, owner rule): runs the vault importer's OWN pipeline
// offline (importVault dry run: sourcePathGate + wall gate per note and per chunk),
// once with the 0009 wall (legacySeedWall) and once with the current wall, and
// compares. This is an offline reconstruction from the vault as it is now; it does
// not read the production database. Since 0011 it compares the 0009 wall (run 10), the
// 0010 wall (head before 0011) and the 0011 wall, and adds an independent Plankiva
// proof scan (scripts/wall-compare.ts).
//
// --plankiva-fp <dir> (0011): false-positive scan of the Plankiva variants rule over a folder of
// .md files: files it matches, files only it matches (no pre-0011 Plankiva term), and the
// distinct matched tokens (the matched word only, never the text around it).

import { openSync, readFileSync, readdirSync, closeSync, constants } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, basename } from 'node:path';
import { parseArgs } from 'node:util';
import { PROTECTED_VARIANTS_REGEX, PROTECTED_SPELLING_REGEX, compileWall, seedRulesWithIds, seedWall, type Row } from '../src/wall.ts';
import { plankivaFalsePositives, compareOld, formatFalsePositives, label as ruleLabel } from './wall-compare.ts';

const { values } = parseArgs({
  options: {
    vault: { type: 'string' }, sub: { type: 'string', default: 'Work' },
    'compare-old': { type: 'boolean', default: false }, config: { type: 'string', default: 'config/sources.example.toml' },
    'plankiva-fp': { type: 'string', multiple: true },
  },
});
const tilde = (p: string) => p.replace(/^~(?=\/|$)/, homedir());
if (values['plankiva-fp']?.length) {
  for (const d of values['plankiva-fp']) console.log(formatFalsePositives(d, plankivaFalsePositives(tilde(d))));
  process.exit(0);
}
const vault = tilde(values.vault ?? join(homedir(), 'KnowledgeVault'));
if (values['compare-old']) {
  console.log(await compareOld({ vault, configPath: values.config!, home: homedir() }));
  process.exit(0);
}
const start = join(vault, values.sub ?? 'Work');

function* walk(dir: string): Generator<string> {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.isFile() && e.name.endsWith('.md')) yield p;
  }
}

function readOnly(p: string): string {
  const fd = openSync(p, constants.O_RDONLY);
  try {
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

/** Minimal frontmatter: title, tags/tag (inline list, scalar, or block list). Approximate, for counts. */
function splitNote(text: string): { fm: Record<string, unknown>; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) return { fm: {}, body: text };
  const raw = m[1]!;
  const fm: Record<string, unknown> = { _raw: raw };
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const kv = /^(title|tags|tag):\s*(.*)$/.exec(lines[i]!);
    if (!kv) continue;
    const [, key, val] = kv as unknown as [string, string, string];
    const v = val.trim();
    if (v.startsWith('[')) fm[key] = v.replace(/^\[|\]$/g, '').split(',').map((s) => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
    else if (v === '') {
      const items: string[] = [];
      while (i + 1 < lines.length && /^\s*-\s+/.test(lines[i + 1]!)) items.push(lines[++i]!.replace(/^\s*-\s+/, '').replace(/^["']|["']$/g, ''));
      fm[key] = items;
    } else fm[key] = v.replace(/^["']|["']$/g, '');
  }
  return { fm, body: text.slice(m[0].length) };
}

const wall = seedWall();
const plankivaTerm = wall.rules.find((r) => r.kind === 'term' && r.pattern === 'plankiva')!;
const plankivaTag = wall.rules.find((r) => r.kind === 'tag' && r.pattern === 'plankiva')!;
// (c) = the Plankiva content rules: the term and, since 0010, the spelling regex (which also matches the plain word),
// and since 0011 the Plankiva variants regex.
const plankivaSpelling = wall.rules.find((r) => r.kind === 'regex' && r.pattern === PROTECTED_SPELLING_REGEX);
const plankivaVariants = wall.rules.find((r) => r.kind === 'regex' && r.pattern === PROTECTED_VARIANTS_REGEX);
const cIds = new Set([plankivaTerm.id, plankivaSpelling?.id, plankivaVariants?.id]);
const wallWithoutC = compileWall(seedRulesWithIds().filter((r) => !cIds.has(r.id)), []);
const label = new Map(wall.rules.map((r) => [r.id, ruleLabel(wall.rules, r.id)]));

let total = 0;
const firstHit = new Map<number, number>();
let pass = 0;
let anyPlankivaText = 0; // the word appears anywhere in checked text (c would match on its own)
let anyPlankivaTag = 0;
let firstByC = 0; // (c) is the first hit (no hard path/tag rule blocks the note)
let onlyByC = 0; // (c) is the ONLY reason: without it the note would pass every rule

for (const p of walk(start)) {
  total++;
  const rel = relative(vault, p);
  const { fm, body } = splitNote(readOnly(p));
  const row: Row = {
    vault_path: rel, title: typeof fm['title'] === 'string' ? fm['title'] : basename(p, '.md'), body, frontmatter: fm,
    source_uri: `vault:${rel}`, source_kind: 'vault_note', scope: 'work',
  };
  const v = wall.check('notes', row);
  if (!v.blocked) pass++;
  else firstHit.set(v.ruleId!, (firstHit.get(v.ruleId!) ?? 0) + 1);

  const hardTextHasPlankiva = /plankiva/i.test([row['title'], body, JSON.stringify(fm), rel].join('\n'));
  if (hardTextHasPlankiva) anyPlankivaText++;
  if (v.blocked && v.ruleId === plankivaTag.id) anyPlankivaTag++;
  if (v.blocked && cIds.has(v.ruleId!)) {
    firstByC++;
    if (!wallWithoutC.check('notes', row).blocked) onlyByC++;
  }
}

const pct = (n: number) => (total ? `${((100 * n) / total).toFixed(1)}%` : 'n/a');
console.log(`wall dry run (count-only, read-only): ${total} notes under <vault>/${values.sub}`);
console.log(`  pass (would be ingested): ${pass} (${pct(pass)})`);
console.log(`  blocked, by first-hit rule:`);
for (const [id, n] of [...firstHit.entries()].sort((a, b) => a[0] - b[0])) console.log(`    ${label.get(id)}: ${n} (${pct(n)})`);
console.log(`  Plankiva rule (c), hard term, first hit (no hard path/tag rule blocks them): ${firstByC} (${pct(firstByC)})`);
console.log(`  Plankiva rule (c) is the ONLY reason (would pass every other rule): ${onlyByC} (${pct(onlyByC)})`);
console.log(`  notes mentioning "plankiva" anywhere (c matches, whichever rule hits first): ${anyPlankivaText} (${pct(anyPlankivaText)})`);
console.log(`  Plankiva rule (b), hard tag, first hit: ${anyPlankivaTag} (${pct(anyPlankivaTag)})`);
console.log(`  over-block threshold for (c) (~15%): ${firstByC / Math.max(total, 1) > 0.15 || anyPlankivaText / Math.max(total, 1) > 0.15 ? 'EXCEEDED — flag for the operator' : 'not exceeded'}`);
