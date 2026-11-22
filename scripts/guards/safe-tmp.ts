// Guard `safe-tmp`: no raw mkdtemp / mkdtempSync in test/, scripts/ or src/.
//
// Past mistakes: #12 (17564c7) a random mkdtemp suffix spelled a walled term ("...-PnLTJL" hit the hard
// path_glob **pnl**) and fixtures failed closed at random on main; after #12, a branch of #16 (15403da)
// re-added `mkdtempSync(join(tmpdir(), ...))` in test/search-decisions.test.ts. The old in-test scan only
// covered test/*.ts. The supported way is safeMkdtemp()/safeTmpDir() in test/helpers/safe-tmp.ts, which
// re-rolls any name a wall rule would match.
import type { SourceFile, Violation } from './lib.ts';

export const RULE = 'safe-tmp';
export const OWNER = 'test/helpers/safe-tmp.ts';
export const DIRS = ['test', 'scripts', 'src'] as const;
export const keep = (p: string) => /\.(ts|mts|js|mjs)$/.test(p) && p !== OWNER;

// A call, or an import / destructuring alias that would hide the name at the call site.
const CALL = /\bmkdtemp(?:Sync)?\s*\(|\bmkdtemp(?:Sync)?\s+as\s+[\w$]+|\bmkdtemp(?:Sync)?\s*:\s*[\w$]+\s*[,}]/;

/**
 * Blank out // and /* *\/ comments, keeping line numbers. String and template literals are skipped, so a
 * glob such as 'team/*.md' or a URL never opens a comment (that hid real calls from the first version).
 */
export function stripComments(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < text.length && text[j] !== c && !(c !== '`' && text[j] === '\n')) j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end < 0 ? text.length : end + 2;
      out += text.slice(i, stop).replace(/[^\n]/g, ' ');
      i = stop;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

export function check(files: readonly SourceFile[]): Array<Violation & { text: string }> {
  const out: Array<Violation & { text: string }> = [];
  for (const f of files) {
    const raw = f.text.split('\n');
    stripComments(f.text).split('\n').forEach((l, i) => {
      if (!CALL.test(l)) return;
      out.push({
        rule: RULE, path: f.path, line: i + 1, text: raw[i]!.trim(),
        message: f.path.startsWith('src/')
          ? 'raw mkdtemp in runtime code: its random suffix can spell a walled term and fail a wall-gated path at random (#12). Use gatedRunDir(parent, prefix, runDirGate(...)) from src/run-dir.ts (see AGENTS.md rule safe-tmp)'
          : `raw mkdtemp: its random suffix can spell a walled term and fail closed at random (#12). Use safeMkdtemp(prefix) or safeTmpDir(name) from ${OWNER}`,
      });
    });
  }
  return out;
}
