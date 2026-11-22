// `zeusi mcp-token mint|list|revoke` (docs/hosting.md): offline admin for the hosted MCP
// tokens file. No database, no network, no .env.local.
//
// mint writes the plaintext token ONCE, to a caller-supplied --out file (O_NOFOLLOW, created
// or replaced with mode 0600), and never to stdout or stderr. The hash row is appended first;
// if the out file cannot be written, the row is removed again so no orphan hash remains.

import { constants, closeSync, fchmodSync, fsyncSync, lstatSync, openSync, realpathSync, statSync, writeSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import {
  DEFAULT_TOKENS_PATH, generateToken, hashSecret, LABEL_RE, MAX_EXPIRES_DAYS, TOKEN_CLASSES, TOKEN_ID_RE, TOKENS_PATH_ENV,
  readTokenFile, withTokenFile, type HashChoice, type TokenClass, type TokenRow,
} from './mcp-tokens.ts';

export class McpTokenError extends Error {
  override name = 'McpTokenError';
}

/** --file, then ZEUSI_MCP_TOKENS_PATH, then /data/mcp-tokens.json. */
export function resolveTokensPath(flag: string | undefined, env: NodeJS.ProcessEnv = process.env): string {
  return flag ?? (env[TOKENS_PATH_ENV] || undefined) ?? DEFAULT_TOKENS_PATH;
}

export interface MintOptions {
  file: string;
  out: string;
  label: string | undefined;
  cls: string | undefined;
  expiresDays?: number | undefined;
  now?: Date | undefined;
  /** TEST seam only: faster hash parameters. */
  hash?: HashChoice | undefined;
}

export interface MintResult {
  tokenId: string;
  label: string;
  cls: TokenClass;
  expiresAt: string;
  out: string;
}

const DAY_MS = 86_400_000;

/** Absolute path with the parent's symlinks resolved (the leaf itself is not followed). */
function canonical(p: string): string {
  const abs = resolve(p);
  try {
    return join(realpathSync(dirname(abs)), basename(abs));
  } catch {
    return abs;
  }
}

function checkOut(out: string, file: string): string {
  const abs = resolve(out);
  let parent;
  try {
    parent = statSync(dirname(abs));
  } catch {
    throw new McpTokenError('--out: parent directory does not exist; nothing written');
  }
  if (!parent.isDirectory()) throw new McpTokenError('--out: parent is not a directory; nothing written');
  const c = canonical(abs);
  const f = canonical(file);
  if (c === f || c === `${f}.lock` || c.startsWith(`${f}.tmp-`)) throw new McpTokenError('--out must not be the tokens file; nothing written');
  try {
    const st = lstatSync(abs);
    if (st.isSymbolicLink()) throw new McpTokenError('--out is a symlink; refusing (nothing written)');
    if (!st.isFile()) throw new McpTokenError('--out exists and is not a regular file; nothing written');
  } catch (e) {
    if (e instanceof McpTokenError) throw e;
    // ENOENT: will be created
  }
  return abs;
}

function writeOut(path: string, token: string): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o600);
  try {
    fchmodSync(fd, 0o600);
    writeSync(fd, `${token}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export async function mintToken(o: MintOptions): Promise<MintResult> {
  if (!o.label || !LABEL_RE.test(o.label)) throw new McpTokenError('--label is required: lowercase [a-z0-9][a-z0-9_.-]{0,63}');
  if (!o.cls || !(TOKEN_CLASSES as readonly string[]).includes(o.cls)) throw new McpTokenError(`--class must be ${TOKEN_CLASSES.join(' or ')}`);
  const cls = o.cls as TokenClass;
  const days = o.expiresDays ?? MAX_EXPIRES_DAYS;
  if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRES_DAYS) throw new McpTokenError(`--expires-days must be 1..${MAX_EXPIRES_DAYS}`);
  if (!o.out) throw new McpTokenError('--out <file> is required (the token is written only there, mode 0600)');
  const out = checkOut(o.out, o.file);

  const now = o.now ?? new Date();
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + days * DAY_MS).toISOString();
  let g = generateToken();
  await withTokenFile(o.file, async (doc) => {
    // A 60-bit id collision is practically impossible; regenerate rather than overwrite a row.
    while (doc.tokens.some((t) => t.token_id === g.tokenId)) g = generateToken();
    const hash = await hashSecret(g.tokenId, g.secret, o.hash);
    return { ...doc, tokens: [...doc.tokens, row(g.tokenId, o.label!, cls, hash, issuedAt, expiresAt)] };
  });
  const tokenId = g.tokenId;
  try {
    writeOut(out, g.token);
  } catch (e) {
    await withTokenFile(o.file, (doc) => ({ ...doc, tokens: doc.tokens.filter((t) => t.token_id !== tokenId) }));
    const code = String((e as { code?: unknown })?.code ?? 'unknown').replace(/[^A-Z0-9_]/g, '');
    throw new McpTokenError(`--out could not be written (${code || 'unknown'}); the hash row was removed again`);
  }
  return { tokenId, label: o.label, cls, expiresAt, out };
}

function row(tokenId: string, label: string, cls: TokenClass, hash: TokenRow['hash'], issuedAt: string, expiresAt: string): TokenRow {
  return { token_id: tokenId, assistant: label, class: cls, hash, issued_at: issuedAt, expires_at: expiresAt, revoked_at: null };
}

export type ListedToken = Pick<TokenRow, 'token_id' | 'assistant' | 'class' | 'issued_at' | 'expires_at' | 'revoked_at'>;

/** The R23 fields only: never the hash, salt or digest. */
export function listTokens(file: string): ListedToken[] {
  return readTokenFile(file).tokens.map((t) => ({
    token_id: t.token_id, assistant: t.assistant, class: t.class, issued_at: t.issued_at, expires_at: t.expires_at, revoked_at: t.revoked_at,
  }));
}

export function formatTokenList(rows: readonly ListedToken[]): string {
  const head = ['token_id', 'assistant', 'class', 'issued_at', 'expires_at', 'revoked_at'];
  const lines = rows.map((r) => [r.token_id, r.assistant, r.class, r.issued_at, r.expires_at, r.revoked_at ?? '-'].join('  '));
  return [head.join('  '), ...lines, `${rows.length} token(s)`].join('\n');
}

export async function revokeToken(file: string, tokenId: string | undefined, now: Date = new Date()): Promise<{ tokenId: string; revokedAt: string }> {
  if (!tokenId || !TOKEN_ID_RE.test(tokenId)) throw new McpTokenError('usage: mcp-token revoke <token_id> (12 characters a-z, 2-7)');
  let revokedAt = '';
  await withTokenFile(file, (doc) => {
    const t = doc.tokens.find((x) => x.token_id === tokenId);
    if (!t) throw new McpTokenError(`unknown token_id ${tokenId}; nothing changed`);
    revokedAt = t.revoked_at ?? now.toISOString();
    return { ...doc, tokens: doc.tokens.map((x) => (x.token_id === tokenId ? { ...x, revoked_at: revokedAt } : x)) };
  });
  return { tokenId, revokedAt };
}
