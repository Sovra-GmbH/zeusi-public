// FROZEN copy of the vault frontmatter parser as it was before the lock-lifecycle fix (24a9f24,
// src/importers/vault.ts parseFrontmatter / unquote / inlineList). Used ONLY by `zeusi locks lint`
// to show what the old parser stored versus the new one (docs/note-locks.md). Never used to store.
// Known defects kept on purpose: `\s+#.*$` is stripped as a comment (so "Close #1157; ..." became
// "Close"), and a list item with indented continuation lines makes the whole block a raw string.

import type { Frontmatter } from './vault.ts';

function unquote(v: string): string {
  const s = v.trim();
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1).replace(/\\(["\\])/g, '$1');
  if (s.length >= 2 && s.startsWith("'") && s.endsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
  return s.replace(/\s+#.*$/, '');
}

function inlineList(v: string): string[] {
  const inner = v.trim().slice(1, -1);
  const out: string[] = [];
  let cur = '';
  let q: string | null = null;
  for (const c of inner) {
    if (q) {
      if (c === q) q = null;
      cur += c;
    } else if (c === '"' || c === "'") {
      q = c;
      cur += c;
    } else if (c === ',') {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out.map(unquote).filter((x) => x !== '');
}

export function parseFrontmatterLegacy(raw: string): Frontmatter {
  const fm: Frontmatter = {};
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*(#|$)/.test(line)) continue;
    const kv = /^([A-Za-z0-9_][A-Za-z0-9_ -]*?)\s*:(?:\s+(.*))?$/.exec(line);
    if (!kv) continue;
    const key = kv[1]!;
    const val = (kv[2] ?? '').trim();
    const block: string[] = [];
    while (i + 1 < lines.length && (/^\s+\S/.test(lines[i + 1]!) || /^-\s/.test(lines[i + 1]!) || lines[i + 1] === '')) {
      if (lines[i + 1] === '' && !(i + 2 < lines.length && /^\s+\S/.test(lines[i + 2]!))) break;
      block.push(lines[++i]!);
    }
    if (val === '|' || val === '>' || /^[|>][+-]?$/.test(val)) {
      const body = block.map((l) => l.replace(/^\s+/, ''));
      fm[key] = val.startsWith('|') ? body.join('\n') : body.join(' ');
    } else if (val.startsWith('[') && val.endsWith(']')) {
      fm[key] = inlineList(val);
    } else if (val !== '') {
      fm[key] = unquote(val);
    } else if (block.length && block.every((l) => /^\s*-(\s|$)/.test(l) || l === '')) {
      fm[key] = block.filter((l) => l !== '').map((l) => unquote(l.replace(/^\s*-\s*/, '')));
    } else if (block.length) {
      fm[key] = block.join('\n');
    } else fm[key] = '';
  }
  return fm;
}

