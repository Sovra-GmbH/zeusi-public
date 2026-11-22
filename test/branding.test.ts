// Connector listing metadata (MCP initialize serverInfo, OAuth discovery, site icons).
// ChatGPT's Plugins directory listing itself is filled in Plugin Creator / a plugin ZIP, not
// from these fields; these are what a client can read from our server and site.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';
import {
  ICON_PNG_PATH, ICON_PNG_URL, ICON_SVG_PATH, ICON_SVG_URL, MCP_ORIGIN, MCP_URL,
  SERVER_DESCRIPTION, SERVER_TITLE, SITE_ICON_PNG_PATH, SITE_ICON_PNG_URL, SITE_URL,
} from '../src/about.ts';
import { ICON_PNG_BYTES, ICON_SVG_BYTES } from '../src/brand-icons.ts';
import { overclaims } from './helpers/overclaim.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const sitePng = readFileSync(`${ROOT}site/logo-512.png`);
const siteSvg = readFileSync(`${ROOT}site/favicon.svg`, 'utf8');

function pngIhdr(buf: Buffer): { width: number; height: number; bit: number; color: number } {
  assert.equal(buf.subarray(0, 8).toString('binary'), '\x89PNG\r\n\x1a\n');
  assert.equal(buf.subarray(12, 16).toString('ascii'), 'IHDR');
  return {
    width: buf.readUInt32BE(16),
    height: buf.readUInt32BE(20),
    bit: buf[24]!,
    color: buf[25]!,
  };
}

/** First and last pixels of an 8-bit RGBA PNG (filter 0 or 1 on those rows is fine; we only need corners). */
function pngCorners(buf: Buffer): { tl: [number, number, number, number]; br: [number, number, number, number] } {
  const ihdr = pngIhdr(buf);
  assert.equal(ihdr.color, 6, 'RGBA');
  assert.equal(ihdr.bit, 8);
  const chunks: Buffer[] = [];
  let off = 8;
  while (off + 8 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const typ = buf.subarray(off + 4, off + 8).toString('ascii');
    const data = buf.subarray(off + 8, off + 8 + len);
    if (typ === 'IDAT') chunks.push(data);
    if (typ === 'IEND') break;
    off += 12 + len;
  }
  const raw = inflateSync(Buffer.concat(chunks));
  const stride = ihdr.width * 4;
  const rowSize = 1 + stride;
  assert.equal(raw.length, rowSize * ihdr.height);
  const unfilter = (row: Buffer, prev: Buffer | null): Buffer => {
    const typ = row[0]!;
    const out = Buffer.alloc(stride);
    for (let i = 0; i < stride; i++) {
      const x = row[i + 1]!;
      const a = i >= 4 ? out[i - 4]! : 0;
      const b = prev ? prev[i]! : 0;
      const c = prev && i >= 4 ? prev[i - 4]! : 0;
      const pa = Math.abs(b - c), pb = Math.abs(a - c), pc = Math.abs(a + b - 2 * c);
      const pr = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      out[i] = (x + (typ === 0 ? 0 : typ === 1 ? a : typ === 2 ? b : typ === 3 ? ((a + b) >> 1) : typ === 4 ? pr : 0)) & 255;
    }
    return out;
  };
  let prev: Buffer | null = null;
  let first: Buffer | null = null;
  let last: Buffer | null = null;
  for (let y = 0; y < ihdr.height; y++) {
    const row = unfilter(raw.subarray(y * rowSize, (y + 1) * rowSize), prev);
    if (y === 0) first = row;
    if (y === ihdr.height - 1) last = row;
    prev = row;
  }
  const px = (row: Buffer, x: number): [number, number, number, number] => [
    row[x * 4]!, row[x * 4 + 1]!, row[x * 4 + 2]!, row[x * 4 + 3]!,
  ];
  return { tl: px(first!, 0), br: px(last!, ihdr.width - 1) };
}

test('listing constants: site and MCP origins, no encryption claim, icon URLs on the connector host', () => {
  assert.equal(SITE_URL, 'https://zeusi.ai');
  assert.equal(MCP_ORIGIN, 'https://mcp.zeusi.dev');
  assert.equal(new URL(MCP_URL).origin, MCP_ORIGIN);
  assert.equal(SERVER_TITLE, 'Zeusi');
  assert.match(SERVER_DESCRIPTION, /shared memory/i);
  assert.match(SERVER_DESCRIPTION, /AI clients/i);
  assert.doesNotMatch(SERVER_DESCRIPTION, /encrypt/i);
  assert.deepEqual(overclaims(SERVER_DESCRIPTION), []);
  assert.equal(ICON_PNG_PATH, '/favicon.png');
  assert.equal(ICON_SVG_PATH, '/favicon.svg');
  assert.equal(ICON_PNG_URL, 'https://mcp.zeusi.dev/favicon.png');
  assert.equal(ICON_SVG_URL, 'https://mcp.zeusi.dev/favicon.svg');
  assert.equal(SITE_ICON_PNG_PATH, '/logo-512.png');
  assert.equal(SITE_ICON_PNG_URL, 'https://zeusi.ai/logo-512.png');
});

test('listing icons: site/logo-512.png is a 512×512 RGBA PNG of the site mark (transparent corners), and brand-icons serves those bytes', () => {
  const ihdr = pngIhdr(sitePng);
  assert.deepEqual(ihdr, { width: 512, height: 512, bit: 8, color: 6 });
  assert.ok(sitePng.length > 8_000 && sitePng.length < 64_000, `png size ${sitePng.length}`);
  const { tl, br } = pngCorners(sitePng);
  assert.equal(tl[3], 0, 'top-left corner is transparent (rounded rect)');
  assert.equal(br[3], 0, 'bottom-right corner is transparent');
  assert.ok(siteSvg.includes('#10141d'), 'navy');
  assert.ok(siteSvg.includes('#fef7ed'), 'cream');
  assert.equal(Buffer.compare(ICON_PNG_BYTES, sitePng), 0);
  assert.equal(ICON_SVG_BYTES.toString('utf8'), siteSvg);
});
