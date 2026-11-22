// The environment `npm test` (scripts/test-hermetic.ts) hands to node --test: everything except
// credential-bearing variables. One source of truth for the URL names: src/config.ts reads the owner
// database URL (with an inline password) from POOLED_URL_NAMES / DIRECT_URL_NAMES, so exactly those
// are dropped, plus libpq PG* and anything named like a password, secret, token or key
// (#14 review P2-3: the old regex kept ZEUSI_DATABASE_URL, POSTGRES_URL, NEON_DATABASE_URL, DIRECT_URL, ...).
import { DIRECT_URL_NAMES, POOLED_URL_NAMES } from '../src/config.ts';

const NAMED: ReadonlySet<string> = new Set([...POOLED_URL_NAMES, ...DIRECT_URL_NAMES]);
const PATTERN = /^(PG|DATABASE_URL)|PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PGPASS|ACCESS_KEY|PRIVATE_KEY|_KEY$/i;

/** True when `name` must not reach a test process. */
export function scrubbedName(name: string): boolean {
  return NAMED.has(name) || PATTERN.test(name);
}

/** A copy of `env` without credential-bearing variables. */
export function hermeticEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) if (!scrubbedName(k)) out[k] = v;
  return out;
}
