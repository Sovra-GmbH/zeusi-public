// Markdown chunker (PLAN.md "Chunking", U5).
//
// * Split on H1-H3 headings (ATX `#`, `##`, `###`), outside fenced code blocks.
//   H4+ stay inside their section. The heading line itself is not part of the
//   stored text; it lives in heading_path ("H1 > H2 > H3"), which the full-text
//   index also covers.
// * A section of at most CHUNK.max tokens is one chunk. A longer section is packed
//   by paragraph (paragraphs longer than CHUNK.targetMax are cut at word
//   boundaries) into pieces of at most CHUNK.targetMax tokens; every piece after
//   the first opens with the last ~CHUNK.overlap tokens of the previous one. So
//   overlap exists only inside long sections, and no chunk exceeds
//   targetMax + overlap + 1 = 661 < CHUNK.max.
// * Token estimator: ceil(Unicode code points / 4). This is the usual rule of
//   thumb for OpenAI BPE on English prose; German and code run a little denser,
//   which the 800-token cap absorbs (text-embedding-3-small accepts 8,191). It is
//   deterministic and dependency-free; U6 records real token usage from the API.
// * Chunk uris are `vault:<rel>#c<index>` (importer). No uri is derived from
//   heading text: a walled heading would otherwise land in quarantine.source_uri
//   (review r1 MAJOR-1, R10).
// * Embedded text (U6) is `title > heading path` plus the chunk; the stored text
//   is the chunk only. embedText() is the single definition of that string.

export const CHUNK = { targetMin: 400, targetMax: 600, max: 800, overlap: 60 };

/** Estimated tokens: ceil(code points / 4). */
export function estimateTokens(text: string): number {
  let n = 0;
  for (const _ of text) n++;
  return Math.ceil(n / 4);
}

export interface Chunk {
  index: number;
  /** "H1 > H2 > H3", or null before the first heading. */
  headingPath: string | null;
  text: string;
  tokenCount: number;
}

const HEADING = /^ {0,3}(#{1,3})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$/;
const FENCE = /^ {0,3}(`{3,}|~{3,})/;

interface Section {
  path: string[];
  lines: string[];
}

function sections(body: string): Section[] {
  const out: Section[] = [{ path: [], lines: [] }];
  const levels: Array<string | undefined> = [];
  let fence: string | null = null;
  for (const line of body.split(/\r?\n/)) {
    const f = FENCE.exec(line);
    if (f) {
      const mark = f[1]!;
      if (fence === null) fence = mark;
      else if (mark[0] === fence[0] && mark.length >= fence.length) fence = null;
      out[out.length - 1]!.lines.push(line);
      continue;
    }
    const h = fence === null ? HEADING.exec(line) : null;
    if (h && h[2]!.trim() !== '') {
      const level = h[1]!.length;
      levels.length = level - 1;
      levels[level - 1] = h[2]!.trim();
      out.push({ path: levels.filter((x): x is string => x !== undefined), lines: [] });
      continue;
    }
    out[out.length - 1]!.lines.push(line);
  }
  return out;
}

interface Unit {
  text: string;
  /** Separator to put before this unit when it follows another one. */
  sep: string;
}

/** Cut text at whitespace into pieces of at most maxTokens (a single over-long word is cut by characters). */
function splitWords(text: string, maxTokens: number): string[] {
  const maxChars = maxTokens * 4;
  const out: string[] = [];
  let cur = '';
  for (const w of text.split(/\s+/).filter(Boolean)) {
    if (estimateTokens(w) > maxTokens) {
      if (cur) out.push(cur);
      cur = '';
      const cps = [...w];
      for (let i = 0; i < cps.length; i += maxChars) out.push(cps.slice(i, i + maxChars).join(''));
      continue;
    }
    const cand = cur ? `${cur} ${w}` : w;
    if (estimateTokens(cand) > maxTokens) {
      out.push(cur);
      cur = w;
    } else cur = cand;
  }
  if (cur) out.push(cur);
  return out;
}

/** The last ~CHUNK.overlap tokens of text, starting at a word boundary. */
function tail(text: string): string {
  const cps = [...text];
  const maxChars = CHUNK.overlap * 4;
  if (cps.length <= maxChars) return text;
  const t = cps.slice(cps.length - maxChars).join('');
  const ws = t.search(/\s/);
  return (ws === -1 ? t : t.slice(ws)).trim();
}

function splitLong(text: string): string[] {
  const units: Unit[] = [];
  for (const para of text.split(/\n[ \t]*\n+/).map((p) => p.trim()).filter(Boolean)) {
    if (estimateTokens(para) <= CHUNK.targetMax) units.push({ text: para, sep: '\n\n' });
    else splitWords(para, CHUNK.targetMax).forEach((p, i) => units.push({ text: p, sep: i === 0 ? '\n\n' : ' ' }));
  }
  const out: string[] = [];
  let cur = '';
  let fresh = true; // cur holds only the overlap tail (or nothing)
  for (const u of units) {
    const cand = cur ? `${cur}${u.sep}${u.text}` : u.text;
    if (fresh || estimateTokens(cand) <= CHUNK.targetMax) {
      cur = cand;
      fresh = false;
      continue;
    }
    out.push(cur);
    const t = tail(cur);
    cur = t ? `${t}${u.sep}${u.text}` : u.text;
  }
  if (cur && !fresh) out.push(cur);
  return out;
}

/** Split a note body (frontmatter already removed) into chunks. */
export function chunkMarkdown(body: string): Chunk[] {
  const chunks: Chunk[] = [];
  for (const s of sections(body)) {
    const text = s.lines.join('\n').trim();
    if (text === '') continue;
    const pieces = estimateTokens(text) <= CHUNK.max ? [text] : splitLong(text);
    for (const p of pieces) {
      chunks.push({
        index: chunks.length,
        headingPath: s.path.length ? s.path.join(' > ') : null,
        text: p,
        tokenCount: estimateTokens(p),
      });
    }
  }
  return chunks;
}

/** The text U6 embeds for a chunk: "title > heading path", a blank line, then the chunk. */
export function embedText(title: string, headingPath: string | null, text: string): string {
  return `${[title, headingPath].filter((x) => x).join(' > ')}\n\n${text}`;
}
