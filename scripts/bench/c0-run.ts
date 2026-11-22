// C0 driver: runs every c0-measure.ts scenario in its own child process that models the Fly
// shared-cpu-1x 512 MB machine (docs/plans/2026-11-18-c0-measure.md D-b, D-c):
//   * node --max-old-space-size=256 [estimate of V8's default heap on a 512 MB VM; the image sets no flag]
//   * peak RSS from /usr/bin/time -l (macOS: "maximum resident set size", bytes)
//   * cpu "p": default scheduling (M4 Pro P-cores); cpu "e": `taskpolicy -b` (background QoS, E-cores)
// Credentials are scrubbed from the child env (as scripts/test-hermetic.ts does). Synthetic data only.
//
//   node scripts/bench/c0-run.ts [--only baseline,index,cache,cache500,wal,waldelta,encrypt] [--out FILE] [--append]
import { spawnSync } from 'node:child_process';
import { appendFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { safeMkdtemp } from '../../test/helpers/safe-tmp.ts';

const argv = process.argv.slice(2);
const opt = (n: string, d: string) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1]! : d; };
const only = new Set(opt('only', 'baseline,index,cache,wal,waldelta,encrypt').split(','));
const outFile = opt('out', 'docs/bench/2026-11-18-c0-raw.jsonl');
const HEAP = '256';
// wal and encrypt run PGlite (a whole WASM Postgres) inside the same process; its JS side (bytea passes
// through hex strings) does not exist on Fly, where the DB is remote. Those runs get a larger heap, and
// their RSS is reported as "bench process incl. PGlite", never as app memory.
const DB_HEAP = '2048';
const SCRUB = /^(PG|DATABASE_URL)|PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PGPASS/i;
const env: NodeJS.ProcessEnv = {};
for (const [k, v] of Object.entries(process.env)) if (!SCRUB.test(k)) env[k] = v;
const script = join(import.meta.dirname, 'c0-measure.ts');
if (!argv.includes('--append')) writeFileSync(outFile, '');

function run(cpu: 'p' | 'e', args: string[]): Record<string, unknown> | null {
  const heap = args[0] === 'wal' || args[0] === 'encrypt' ? DB_HEAP : HEAP;
  const cmd = ['/usr/bin/time', '-l', ...(cpu === 'e' ? ['/usr/sbin/taskpolicy', '-b'] : []), process.execPath, `--max-old-space-size=${heap}`, '--expose-gc', script, ...args];
  const t0 = Date.now();
  const r = spawnSync(cmd[0]!, cmd.slice(1), { env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const maxRss = Number(/(\d+)\s+maximum resident set size/.exec(r.stderr)?.[1] ?? NaN);
  const line = r.stdout.trim().split('\n').filter((l) => l.startsWith('{')).pop();
  const rec: Record<string, unknown> = { cpu, heapFlagMiB: Number(heap), args: args.join(' '), exit: r.status, maxRssBytes: maxRss, maxRssMiB: Math.round((maxRss / 1048576) * 10) / 10, driverWallMs: Date.now() - t0 };
  if (line) Object.assign(rec, JSON.parse(line) as object);
  else rec['error'] = (/(FATAL ERROR[^\n]*|Error[^\n]*)/.exec(r.stderr)?.[1] ?? `exit ${r.status}`).slice(0, 200);
  appendFileSync(outFile, `${JSON.stringify(rec)}\n`);
  process.stderr.write(`${cpu} ${args.join(' ')} -> exit ${r.status} rss ${rec['maxRssMiB']} MiB ${rec['error'] ?? ''}\n`);
  return rec;
}

const MIBS = [1, 10, 50];
const SHARDS = [100, 250, 500, 1000, 0];
const tmp = safeMkdtemp(join(tmpdir(), 'zeusi-c0-idx-'));
try {
  if (only.has('baseline')) for (let i = 0; i < 3; i++) run('p', ['baseline']);
  for (const cpu of ['p', 'e'] as const) {
    if (only.has('index')) {
      for (const mib of MIBS) {
        for (const s of SHARDS) run(cpu, ['index', '--mib', String(mib), '--shard', String(s), '--deflate', '0', '--out', join(tmp, `${cpu}-${mib}-${s}`)]);
        run(cpu, ['index', '--mib', String(mib), '--shard', '250', '--deflate', '1', '--out', join(tmp, `${cpu}-${mib}-250z`)]);
      }
    }
    if (only.has('cache')) {
      for (const mib of MIBS) {
        for (const s of ['250', '1000', '0', '250z']) {
          const dir = join(tmp, `p-${mib}-${s}`);
          for (const form of ['packed', 'map']) {
            const copies = cpu === 'p' && s === '250' ? [1, 2, 3] : [1];
            for (const c of copies) run(cpu, ['cache', '--dir', dir, '--copies', String(c), '--form', form]);
          }
        }
      }
    }
  }
  if (only.has('wal')) for (const mib of [10, 50]) for (const s of SHARDS) run('p', ['wal', '--mib', String(mib), '--shard', String(s), '--deflate', '0']);
  // 500-note shards (the recommended size): index + packed cache, 1-3 copies on p, 1 copy on e
  if (only.has('cache500')) {
    for (const mib of [10, 50]) {
      const dir = join(tmp, `p-${mib}-500`);
      run('p', ['index', '--mib', String(mib), '--shard', '500', '--deflate', '0', '--out', dir]);
      for (const c of [1, 2, 3]) run('p', ['cache', '--dir', dir, '--copies', String(c), '--form', 'packed']);
      run('e', ['cache', '--dir', dir, '--copies', '1', '--form', 'packed']);
    }
  }
  // delta variant (appends to the tail shard, updates to one delta shard + tombstones, then a compaction)
  if (only.has('waldelta')) for (const mib of [10, 50]) for (const sh of [100, 250, 500]) run('p', ['wal', '--mib', String(mib), '--shard', String(sh), '--deflate', '0', '--delta', '1']);
  if (only.has('encrypt')) {
    for (const cpu of ['p', 'e'] as const) for (const b of [262144, 1048576, 2097152]) run(cpu, ['encrypt', '--mib', '50', '--batch-bytes', String(b), '--shard', '250']);
    run('p', ['encrypt', '--mib', '50', '--batch-bytes', '2097152', '--shard', '0', '--max-calls', '3']);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
