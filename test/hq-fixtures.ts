// Synthetic Zeus HQ export notes for tests (docs/hq-sync.md format).

export function hqNote(o: { project: string; date?: string; kind?: string; title?: string; tags?: string[]; thread?: string }, entries: Array<[string, string]>, preamble = ''): string {
  const date = o.date ?? '2026-11-13';
  const fm = [
    '---',
    `title: "${o.title ?? `${o.project} ${o.kind ?? 'chat'} ${date}`}"`,
    `date: ${date}`,
    'source: zeus-hq',
    `project: ${o.project}`,
    `thread_id: ${o.thread ?? 't-0001'}`,
    `kind: ${o.kind ?? 'chat'}`,
    `tags: [${(o.tags ?? ['hq-sync']).join(', ')}]`,
    '---',
    '',
  ].join('\n');
  return fm + preamble + entries.map(([h, b]) => `## ${h}\n\n${b}\n`).join('\n');
}
