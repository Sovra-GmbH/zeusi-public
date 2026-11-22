// Owner-path guard for commands that WRITE probe rows (prove, embed-smoke).
// Review r1 MINOR-5 + the brief's "never write test rows into Neon main".
//
// Fail closed, offline (no connection): the command runs only when the owner URL's
// endpoint is provably NOT the default branch's endpoint, i.e. ZEUSI_MAIN_ENDPOINT_ID
// (the endpoint id of the default/main branch, e.g. "ep-xxx-123"; not a secret) is
// set and differs from the URL's endpoint, or when --i-know-this-is-main is passed.
// The configured id is normalised like the URL's (ep-x, ep-x-pooler and the full
// hostname are the same id); a value that is not an endpoint id is refused (r2 MINOR-A).
// Messages never include the host, endpoint id or URL.

import { ConfigError } from './config.ts';

export const MAIN_ENDPOINT_ENV = 'ZEUSI_MAIN_ENDPOINT_ID';
export const I_KNOW_MAIN_FLAG = '--i-know-this-is-main';

/** Neon endpoint id of a postgres URL: the first host label without "-pooler". */
export function endpointIdOf(url: string): string | undefined {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return undefined;
  }
  const first = host.split('.')[0];
  if (!first) return undefined;
  return first.replace(/-pooler$/, '').toLowerCase();
}

const ENDPOINT_ID_RE = /^ep-[a-z0-9-]+$/;

/**
 * The configured ZEUSI_MAIN_ENDPOINT_ID, normalised exactly like the target (r2
 * MINOR-A): trimmed, lower-cased, first host label, "-pooler" stripped. So the bare
 * id, the pooled id and the full (pooled or direct) hostname all give the same id.
 * Returns undefined when the result is not a Neon endpoint id (^ep-[a-z0-9-]+$).
 */
export function normaliseMainEndpointId(value: string): string | undefined {
  const first = value.trim().toLowerCase().split('.')[0] ?? '';
  const id = first.replace(/-pooler$/, '');
  return ENDPOINT_ID_RE.test(id) ? id : undefined;
}

export class MainBranchRefused extends ConfigError {
  override name = 'MainBranchRefused';
}

/**
 * Throws MainBranchRefused unless the target is provably not main, or the caller
 * passed --i-know-this-is-main. Returns whether the run targets (or may target) main.
 */
export function mainBranchGuard(url: string, env: NodeJS.ProcessEnv, iKnowThisIsMain: boolean): { onMain: boolean } {
  if (iKnowThisIsMain) return { onMain: true };
  const raw = (env[MAIN_ENDPOINT_ENV] ?? '').trim();
  const tail = `Point the owner URL at a Neon branch, or pass ${I_KNOW_MAIN_FLAG} (writes and deletes probe rows on main). No connection made.`;
  if (!raw) {
    throw new MainBranchRefused(
      `refused: cannot tell whether the target is Neon main: set ${MAIN_ENDPOINT_ENV} (endpoint id of the default branch, not a secret) in .env.local. ${tail}`,
    );
  }
  // Fail closed: a value we cannot read as an endpoint id could be main in any form.
  const main = normaliseMainEndpointId(raw);
  if (!main) {
    throw new MainBranchRefused(
      `refused: ${MAIN_ENDPOINT_ENV} is not a Neon endpoint id (expected ep-..., the pooled id or the endpoint hostname; value not shown). ${tail}`,
    );
  }
  const target = endpointIdOf(url);
  if (!target) throw new MainBranchRefused(`refused: cannot read the endpoint id from the owner URL (value not shown). ${tail}`);
  if (target === main) throw new MainBranchRefused(`refused: the owner URL targets the default branch (main) endpoint. ${tail}`);
  return { onMain: false };
}

/**
 * Host-based entry (PR2 KTD14) for role-service writes (`zeusi import --real`, as zeusi_ingest):
 * the same rule as mainBranchGuard, for a service file's host= instead of the owner URL. Offline,
 * fail closed, reads ZEUSI_MAIN_ENDPOINT_ID from the given environment only (it never loads
 * .env.local). Messages never include the host, the endpoint id or the service file path.
 */
export function mainBranchGuardForHost(host: string, env: NodeJS.ProcessEnv, iKnowThisIsMain: boolean): { onMain: boolean } {
  if (iKnowThisIsMain) return { onMain: true };
  const raw = (env[MAIN_ENDPOINT_ENV] ?? '').trim();
  const tail = `Point the write service at a Neon branch, or pass ${I_KNOW_MAIN_FLAG} (an owner-approved write to main). No connection made.`;
  if (!raw) {
    throw new MainBranchRefused(`refused: cannot tell whether the target is Neon main: set ${MAIN_ENDPOINT_ENV} (endpoint id of the default branch, not a secret) in the environment. ${tail}`);
  }
  const main = normaliseMainEndpointId(raw);
  if (!main) throw new MainBranchRefused(`refused: ${MAIN_ENDPOINT_ENV} is not a Neon endpoint id (value not shown). ${tail}`);
  const target = normaliseMainEndpointId(host);
  if (!target) throw new MainBranchRefused(`refused: cannot read a Neon endpoint id from the service host (value not shown). ${tail}`);
  if (target === main) throw new MainBranchRefused(`refused: the write service targets the default branch (main) endpoint. ${tail}`);
  return { onMain: false };
}
