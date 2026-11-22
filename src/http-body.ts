// Bounded request-body reader shared by the hosted MCP endpoint (src/mcp-hosted.ts) and the
// OAuth routes (src/mcp-oauth.ts).

import type { IncomingMessage } from 'node:http';

/**
 * The body; null once it exceeds `max` (reading stops; the caller answers 413); 'timeout'
 * when it has not fully arrived within `timeoutMs` (slow-body clients; the caller answers 408).
 */
export function readBody(req: IncomingMessage, max: number, timeoutMs: number): Promise<Buffer | null | 'timeout'> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const timer = setTimeout(() => {
      req.off('data', onData);
      resolve('timeout');
    }, timeoutMs);
    const onData = (c: Buffer) => {
      size += c.length;
      if (size > max) {
        clearTimeout(timer);
        req.off('data', onData);
        req.resume();
        resolve(null);
        return;
      }
      chunks.push(c);
    };
    req.on('data', onData);
    req.on('end', () => { clearTimeout(timer); resolve(size > max ? null : Buffer.concat(chunks)); });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}
