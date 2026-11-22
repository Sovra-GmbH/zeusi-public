// Every guard `npm run guards` runs. A guard owns one rule id, the files it scans, and a pure check.
import { listFiles, type SourceFile, type Violation } from './lib.ts';
import * as safeTmp from './safe-tmp.ts';
import * as secretAssert from './secret-assert.ts';
import * as hermeticNpmTest from './hermetic-npm-test.ts';

export interface Guard {
  RULE: string;
  files(): string[];
  check(files: readonly SourceFile[]): Array<Violation & { text: string }>;
}

/** A guard that scans every file under `dirs` passing `keep`. */
export function scanning(m: { RULE: string; DIRS: readonly string[]; keep: (p: string) => boolean; check: Guard['check'] }): Guard {
  return { RULE: m.RULE, files: () => listFiles(m.DIRS, m.keep), check: m.check };
}

export const GUARDS: readonly Guard[] = [
  scanning(safeTmp),
  scanning(secretAssert),
  { RULE: hermeticNpmTest.RULE, files: hermeticNpmTest.files, check: hermeticNpmTest.check },
];
