// The listing icons served unauthenticated at GET /favicon.png and /favicon.svg on the hosted
// MCP origin (src/mcp-hosted.ts). Bytes come from site/ in a checkout (tests, dev) and from
// /app/brand in the Fly image (Dockerfile copies just these two files). Paths of a failed
// lookup are never returned to a client.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

function load(name: 'logo-512.png' | 'favicon.svg'): Buffer {
  const candidates = [
    join(HERE, '..', 'brand', name), // Fly image: /app/dist -> /app/brand
    join(HERE, '..', 'site', name),  // tests and a source checkout: src/ or dist/ -> site/
  ];
  for (const p of candidates) {
    try {
      return readFileSync(p);
    } catch {
      // try the next location
    }
  }
  throw new Error('brand icon missing');
}

export const ICON_PNG_BYTES = load('logo-512.png');
export const ICON_SVG_BYTES = load('favicon.svg');
