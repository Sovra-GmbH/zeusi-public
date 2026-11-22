// Connection config. Reads env var NAMES written by `neon deploy` (into .env.local)
// and never prints their values. Direct (unpooled) URL for migrations, pooled
// URL for ordinary CLI queries. TLS is mandatory.

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

/** Names checked, in order, for the pooled URL. */
export const POOLED_URL_NAMES = ['ZEUSI_DATABASE_URL', 'DATABASE_URL', 'POSTGRES_URL', 'NEON_DATABASE_URL'] as const;

/** Names checked, in order, for the direct (unpooled) URL. */
export const DIRECT_URL_NAMES = [
  'ZEUSI_DIRECT_URL',
  'DATABASE_URL_UNPOOLED',
  'DIRECT_URL',
  'POSTGRES_URL_NON_POOLING',
  'DATABASE_URL_DIRECT',
  'NEON_DATABASE_URL_UNPOOLED',
] as const;

export const ENV_FILES = ['.env.local', '.env'] as const;

export type UrlKind = 'pooled' | 'direct';

export interface ResolvedUrl {
  kind: UrlKind;
  url: string;
  /** Env var name the URL came from, or a note on how it was derived. Safe to print. */
  sourceName: string;
}

/** Load .env.local / .env from the project root into process.env (existing vars win). */
export function loadEnvFiles(root: string = process.cwd()): string[] {
  const loaded: string[] = [];
  for (const name of ENV_FILES) {
    const path = resolve(root, name);
    if (existsSync(path)) {
      process.loadEnvFile(path);
      loaded.push(name);
    }
  }
  return loaded;
}

function firstSet(names: readonly string[], env: NodeJS.ProcessEnv): { name: string; value: string } | undefined {
  for (const name of names) {
    const value = env[name];
    if (value && value.trim() !== '') return { name, value: value.trim() };
  }
  return undefined;
}

/**
 * Neon convention: the pooled host is the direct host with "-pooler" appended to
 * the endpoint id. Used only when no direct URL name is set.
 */
export function deriveDirectFromPooled(pooled: string): string | undefined {
  let u: URL;
  try {
    u = new URL(pooled);
  } catch {
    return undefined;
  }
  const [first, ...rest] = u.hostname.split('.');
  if (!first || !first.endsWith('-pooler')) return undefined;
  u.hostname = [first.slice(0, -'-pooler'.length), ...rest].join('.');
  return u.toString();
}

export function resolveUrl(kind: UrlKind, env: NodeJS.ProcessEnv = process.env): ResolvedUrl {
  if (kind === 'direct') {
    const direct = firstSet(DIRECT_URL_NAMES, env);
    if (direct) return { kind, url: direct.value, sourceName: direct.name };
    const pooled = firstSet(POOLED_URL_NAMES, env);
    if (pooled) {
      const derived = deriveDirectFromPooled(pooled.value);
      if (derived) return { kind, url: derived, sourceName: `${pooled.name} (derived: -pooler removed)` };
    }
    throw new ConfigError(
      `No direct (unpooled) database URL. Set one of: ${DIRECT_URL_NAMES.join(', ')} ` +
        `(run \`npm run neon:init\` then \`npm run neon:deploy\` to write .env.local).`,
    );
  }
  const pooled = firstSet(POOLED_URL_NAMES, env);
  if (pooled) return { kind, url: pooled.value, sourceName: pooled.name };
  throw new ConfigError(
    `No pooled database URL. Set one of: ${POOLED_URL_NAMES.join(', ')} ` +
      `(run \`npm run neon:init\` then \`npm run neon:deploy\` to write .env.local).`,
  );
}

/** Which known names are present (names only, never values). */
export function presentEnvNames(env: NodeJS.ProcessEnv = process.env): string[] {
  return [...POOLED_URL_NAMES, ...DIRECT_URL_NAMES].filter((n) => !!env[n] && env[n]!.trim() !== '');
}

export class ConfigError extends Error {
  override name = 'ConfigError';
}

/** Host + database only, for logs. Never user, password, or query params. */
export function describeUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.hostname}${u.pathname}`;
  } catch {
    return '<unparseable url>';
  }
}

/**
 * Strip TLS query params from the URL (the driver gets an explicit TLS config
 * instead) and refuse URLs that ask for TLS to be disabled or weakened.
 */
export function prepareUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new ConfigError('Database URL is not a valid URL (value not shown).');
  }
  if (u.protocol !== 'postgres:' && u.protocol !== 'postgresql:') {
    throw new ConfigError(`Database URL must use postgres:// or postgresql:// (got ${u.protocol}).`);
  }
  const sslmode = u.searchParams.get('sslmode');
  if (sslmode && ['disable', 'allow', 'prefer'].includes(sslmode)) {
    throw new ConfigError(`Refusing sslmode=${sslmode}: TLS is required.`);
  }
  for (const p of ['sslmode', 'channel_binding', 'sslrootcert', 'sslcert', 'sslkey', 'ssl', 'uselibpqcompat']) {
    u.searchParams.delete(p);
  }
  return u.toString();
}
