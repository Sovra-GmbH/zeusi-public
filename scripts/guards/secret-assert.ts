// Guard `secret-assert`: a test never compares a credential with a plain node:assert equality/match.
//
// node:assert prints both values when it fails. Past mistake (#14, b15f177): the hosted-write test
// (77b63d4:test/hosted-write-service.test.ts) did `assert.equal(seen.password, PW)` and
// `assert.equal(await readRolePassword(...), PW)`; when the lookup reached the real Keychain the failing
// assert printed a real password. #14 moved every credential compare in ~14 files to the fingerprinting
// helpers; nothing stopped the next test from doing it again. Use assertSecretEqual / assertSecretsEqual /
// assertRejectsRedacted / assertThrowsRedacted from test/redact.ts (failures show sha256 + length only).
import type { SourceFile, Violation } from './lib.ts';
import { stripComments } from './safe-tmp.ts';

export const RULE = 'secret-assert';
export const DIRS = ['test'] as const;
export const keep = (p: string) => /\.(ts|mts|js|mjs)$/.test(p);

const ASSERT = /\bassert\s*\.\s*(equal|strictEqual|deepEqual|deepStrictEqual|notEqual|notStrictEqual|notDeepEqual|notDeepStrictEqual|match|doesNotMatch)\s*\(/g;
// The head noun (last word) of the name must be a credential: `seen.password`, `client_secret`, `refreshToken`,
// `readRolePassword(...)`, `PW`. Not: `token_endpoint`, `secretWithheld`, `tokenCount` (a credential is a modifier).
const CRED_WORDS = new Set(['password', 'passwd', 'pw', 'pwd', 'secret', 'token', 'authorization', 'bearer', 'apikey', 'passphrase']);
// A call whose name starts with a predicate verb returns a verdict, not the credential (verifySecret(...) -> boolean).
const PREDICATE = new Set(['verify', 'is', 'has', 'check', 'validate', 'looks', 'mentions', 'contains', 'count', 'redact', 'fingerprint']);

/** camelCase / snake_case / UPPER words of an identifier, lower-cased ("readRolePassword" -> read, role, password). */
export function words(id: string): string[] {
  return id.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2').split(/[\s_$-]+/).filter(Boolean).map((w) => w.toLowerCase());
}

/** True when an identifier names a credential value (its head noun is a credential word). */
export function credentialName(id: string, isCall = false): boolean {
  const w = words(id);
  if (isCall && PREDICATE.has(w[0]!)) return false;
  return CRED_WORDS.has(w.at(-1)!) || (w.length >= 2 && w.at(-2) === 'api' && w.at(-1) === 'key');
}

/** The top-level comma-separated arguments of the call whose '(' is at `open`; null when unbalanced. */
export function callArgs(src: string, open: number): string[] | null {
  const args: string[] = [];
  let depth = 0;
  let cur = '';
  for (let i = open + 1; i < src.length; i++) {
    const c = src[i]!;
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < src.length && src[j] !== c) j += src[j] === '\\' ? 2 : 1;
      cur += src.slice(i, j + 1);
      i = j;
      continue;
    }
    if (c === '/' && /[(,=:[!&|?{};]$/.test(cur.trim() || '(')) { // a regex literal
      let j = i + 1;
      let cls = false;
      while (j < src.length && (cls || src[j] !== '/')) {
        if (src[j] === '\\') j++;
        else if (src[j] === '[') cls = true;
        else if (src[j] === ']') cls = false;
        if (src[j] === '\n') break;
        j++;
      }
      cur += src.slice(i, j + 1);
      i = j;
      continue;
    }
    if ('([{'.includes(c)) depth++;
    if (')]}'.includes(c)) {
      if (depth === 0) {
        args.push(cur.trim());
        return args;
      }
      depth--;
    }
    if (c === ',' && depth === 0) {
      args.push(cur.trim());
      cur = '';
      continue;
    }
    cur += c;
  }
  return null;
}

/**
 * The name an argument expression "ends in": `seen.password` -> password, `x['token']` -> token,
 * `await readRolePassword(a, b)` -> readRolePassword, `f(...)!.dek` -> dek, `PW` -> PW.
 */
export function leafName(expr: string): { name: string; call: boolean } | null {
  let e = expr.replace(/^await\s+/, '').trim().replace(/[!\s]+$/, '');
  let call = false;
  const open = /\)$/.test(e) ? matchingOpen(e) : -1;
  if (open > 0) {
    e = e.slice(0, open).replace(/[!?.\s]+$/, '');
    call = true;
  }
  const m = /(?:\[\s*['"]([\w$-]+)['"]\s*\]|([A-Za-z_$][\w$]*))\s*$/.exec(e);
  const name = m ? (m[1] ?? m[2]) : undefined;
  return name ? { name, call } : null;
}

function matchingOpen(e: string): number {
  let depth = 0;
  for (let i = e.length - 1; i >= 0; i--) {
    if (e[i] === ')') depth++;
    else if (e[i] === '(' && --depth === 0) return i;
  }
  return -1;
}

export function check(files: readonly SourceFile[]): Array<Violation & { text: string }> {
  const out: Array<Violation & { text: string }> = [];
  for (const f of files) {
    if (f.path === 'test/redact.ts') continue; // the helpers themselves
    const src = stripComments(f.text);
    const raw = f.text.split('\n');
    for (const m of src.matchAll(ASSERT)) {
      const open = m.index! + m[0].length - 1;
      const args = callArgs(src, open);
      if (!args || args.length < 2) continue;
      // Compared with a number or boolean literal: the value is a count or a flag, not a credential.
      if (args.slice(0, 2).some((x) => /^(?:-?\d+(?:\.\d+)?|true|false|[^?]+\?\s*-?\d+\s*:\s*-?\d+)$/.test(x))) continue;
      const exprs = args.slice(0, 2).flatMap((x) => (/^\[[\s\S]*\]$/.test(x) ? (callArgs(`${x.slice(1)}`, -1) ?? [x]) : [x])); // [a, b]: each element
      const hit = exprs.map(leafName).find((n) => n !== null && credentialName(n.name, n.call))?.name;
      if (!hit) continue;
      const line = src.slice(0, m.index).split('\n').length;
      out.push({
        rule: RULE, path: f.path, line, text: raw[line - 1]!.trim(),
        message: `assert.${m[1]} on credential-like value "${hit}": node:assert prints both values on failure (#14 printed a real password). Use assertSecretEqual / assertSecretsEqual (or assertRejectsRedacted / assertThrowsRedacted) from test/redact.ts`,
      });
    }
  }
  return out;
}
