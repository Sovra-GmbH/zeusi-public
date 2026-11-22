// Guard `hermetic-npm-test`: `npm test` (and so `npm run check` and CI) runs through scripts/test-hermetic.ts,
// and no npm script runs `node --test` around it.
//
// Past mistake: until #14 (b15f177), 77b63d4:package.json had "test": "node --test test/*.test.ts", which
// inherited the developer's real HOME, PG* and credential env; a test then read a real Keychain item.
// The hermetic runner gives every test a temp HOME, a scrubbed env and ZEUSI_TEST_NO_REAL_CREDS=1.
import type { SourceFile, Violation } from './lib.ts';

export const RULE = 'hermetic-npm-test';
export const RUNNER = 'node scripts/test-hermetic.ts';

export function check(files: readonly SourceFile[]): Array<Violation & { text: string }> {
  const out: Array<Violation & { text: string }> = [];
  for (const f of files) {
    const lines = f.text.split('\n');
    const at = (name: string) => {
      const i = lines.findIndex((l) => new RegExp(`^\\s*"${name}"\\s*:`).test(l));
      return i < 0 ? 1 : i + 1;
    };
    const scripts = (JSON.parse(f.text) as { scripts?: Record<string, string> }).scripts ?? {};
    const push = (name: string, message: string) => out.push({ rule: RULE, path: f.path, line: at(name), text: lines[at(name) - 1]!.trim(), message });
    const t = scripts['test'];
    if (t === undefined || !(t === RUNNER || t.startsWith(`${RUNNER} `))) {
      push('test', `"test" must be "${RUNNER}" (temp HOME, scrubbed credential env, ZEUSI_TEST_NO_REAL_CREDS=1); a plain node --test reads the real HOME and env (#14)`);
    }
    for (const [name, cmd] of Object.entries(scripts)) {
      if (name !== 'test' && /\bnode\b[^&|;]*\s--test\b/.test(cmd)) push(name, `"${name}" runs node --test outside the hermetic runner; use "${RUNNER} <files>" (#14)`);
    }
  }
  return out;
}

export function files(): string[] {
  return ['package.json'];
}
