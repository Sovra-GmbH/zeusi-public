// The site's startup terminal (site/index.html #first-run-demo) as lines: the one rendering rule shared by
// test/site.test.ts (offline, from the exported constants) and test/site-terminal.test.ts (the live reply).
// Line 1 is the user's prompt; line 2 names real keys and values of the reply; then `message` and `welcome`
// verbatim, split on newlines. Nothing is paraphrased.
import { readFileSync } from 'node:fs';

export interface StartupReply { workspace: unknown; empty: unknown; rules_served: unknown; message: unknown; welcome: unknown }

export function terminalLines(j: StartupReply): string[] {
  return [
    '› Run zeusi_startup',
    `zeusi_startup → workspace: ${JSON.stringify(j.workspace)}, empty: ${String(j.empty)}, rules_served: ${String(j.rules_served)}`,
    'message:', ...String(j.message).split('\n'),
    '', 'welcome:', ...String(j.welcome).split('\n'),
  ];
}

/** The lines of the static, accessible copy in site/index.html (entities decoded). */
export function siteTerminalLines(): string[] {
  const html = readFileSync(new URL('../../site/index.html', import.meta.url), 'utf8');
  const start = html.indexOf('<section id="first-run-demo"');
  const section = html.slice(start, html.indexOf('</section>', start));
  const pre = /<pre class="term-full"><code>([\s\S]*?)<\/code><\/pre>/.exec(section)?.[1] ?? '';
  return [...pre.matchAll(/<span class="tl[^"]*">([\s\S]*?)<\/span>/g)]
    .map((m) => m[1]!.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&'));
}
