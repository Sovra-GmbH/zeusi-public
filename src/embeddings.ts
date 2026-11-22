// Embeddings clients (PLAN.md U6, KTD5, KTD16).
//
// * EmbeddingsClient: the seam. Tests and CI use FakeEmbeddingsClient (deterministic,
//   no network). The real client is created only by createOpenAIClient().
// * The OpenAI key comes ONLY from the env var ZEUSI_OPENAI_API_KEY, read inside
//   createOpenAIClient(). It is sent only in the Authorization header. It is never put
//   in a URL, a log line, or an error: every error is a fresh EmbedError (no cause
//   chain) whose message passes through redactKey(). Response bodies are never
//   quoted; only a safe error code (/^[a-z0-9_]+$/) is kept.
// * EU data residency: the base URL must be https on eu.api.openai.com (default
//   https://eu.api.openai.com/v1). Another host needs a code change.
// * Fail closed: 429, 5xx and network errors are retried with capped exponential
//   backoff (Retry-After honoured); anything else, and a response with the wrong
//   count, dims or non-finite values, throws.

import { createHash } from 'node:crypto';
import { estimateTokens } from './chunking.ts';

export const OPENAI_KEY_ENV = 'ZEUSI_OPENAI_API_KEY';
export const DEFAULT_EMBED_BASE_URL = 'https://eu.api.openai.com/v1';
export const EU_EMBED_HOSTS = ['eu.api.openai.com'] as const;
export const OPENAI_EMBED_MODEL = 'text-embedding-3-small';
export const OPENAI_EMBED_DIMS = 1536;

export interface EmbedResult {
  /** One vector per input, in input order. */
  vectors: number[][];
  /** API-reported usage (the billing truth), or null when the response carried none. */
  totalTokens: number | null;
}

export interface EmbeddingsClient {
  /** Provider model id, e.g. text-embedding-3-small. */
  readonly model: string;
  readonly dims: number;
  /** 'fake' never leaves the process; 'openai' is billed. */
  readonly kind: 'fake' | 'openai';
  embed(inputs: string[]): Promise<EmbedResult>;
}

export class EmbedError extends Error {
  override name = 'EmbedError';
  readonly status: number | undefined;
  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** Remove every occurrence of the key (and long prefixes of it) and anything that looks like an API key. */
export function redactKey(message: string, key: string | undefined): string {
  let out = message;
  if (key && key.length >= 8) {
    out = out.split(key).join('<redacted>');
    out = out.split(key.slice(0, 12)).join('<redacted>');
  }
  return out.replace(/sk-[A-Za-z0-9_-]{6,}/g, '<redacted>').replace(/Bearer\s+\S+/gi, 'Bearer <redacted>');
}

export function validateBaseUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new EmbedError('embed base URL is not a valid URL');
  }
  if (u.protocol !== 'https:') throw new EmbedError('embed base URL must use https');
  if (u.username || u.password) throw new EmbedError('embed base URL must not hold credentials');
  if (u.search || u.hash) throw new EmbedError('embed base URL must not have a query or fragment');
  if (!(EU_EMBED_HOSTS as readonly string[]).includes(u.hostname.toLowerCase())) {
    throw new EmbedError(`embed base URL host must be the OpenAI EU endpoint (${EU_EMBED_HOSTS.join(', ')}); another host needs a code change`);
  }
  return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
}

export interface OpenAIClientOptions {
  env?: NodeJS.ProcessEnv;
  baseUrl?: string;
  fetch?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  /** Total attempts per request (default 5). */
  maxAttempts?: number;
  /** Per-request timeout (default 60 s). */
  timeoutMs?: number;
}

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const SAFE_CODE = /^[a-z0-9_]{1,64}$/;

function backoffMs(attempt: number, retryAfter: string | null): number {
  const ra = retryAfter === null ? NaN : Number(retryAfter);
  if (Number.isFinite(ra) && ra >= 0) return Math.min(ra, 60) * 1000;
  const base = Math.min(500 * 2 ** attempt, 20_000);
  return base + Math.floor(Math.random() * 250);
}

/** The real, billed client. Refuses unless ZEUSI_OPENAI_API_KEY is set. Never exercised in tests against the network. */
export function createOpenAIClient(opts: OpenAIClientOptions = {}): EmbeddingsClient {
  const env = opts.env ?? process.env;
  const key = env[OPENAI_KEY_ENV];
  if (!key || key.trim() === '') throw new EmbedError(`${OPENAI_KEY_ENV} is not set; real embedding calls are refused`);
  const k = key.trim();
  const base = validateBaseUrl(opts.baseUrl ?? DEFAULT_EMBED_BASE_URL);
  const host = new URL(base).hostname;
  const url = `${base}/embeddings`;
  const doFetch: FetchLike = opts.fetch ?? ((u, i) => fetch(u, i));
  const sleep = opts.sleep ?? realSleep;
  const maxAttempts = Math.max(1, opts.maxAttempts ?? 5);
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const fail = (msg: string, status?: number): never => {
    throw new EmbedError(redactKey(msg, k), status);
  };

  return {
    model: OPENAI_EMBED_MODEL,
    dims: OPENAI_EMBED_DIMS,
    kind: 'openai',
    async embed(inputs: string[]): Promise<EmbedResult> {
      if (inputs.length === 0) return { vectors: [], totalTokens: 0 };
      const body = JSON.stringify({ model: OPENAI_EMBED_MODEL, input: inputs, dimensions: OPENAI_EMBED_DIMS, encoding_format: 'float' });
      let last = '';
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        let res: Response;
        try {
          res = await doFetch(url, {
            method: 'POST',
            headers: { Authorization: `Bearer ${k}`, 'Content-Type': 'application/json' },
            body,
            signal: AbortSignal.timeout(timeoutMs),
          });
        } catch (e) {
          // Network error / timeout: retryable. Only the error NAME is kept (messages can echo request data).
          last = `network error (${e instanceof Error ? e.name : 'unknown'}) talking to ${host}`;
          if (attempt + 1 < maxAttempts) await sleep(backoffMs(attempt, null));
          continue;
        }
        if (res.status === 429 || res.status >= 500) {
          last = `OpenAI embeddings HTTP ${res.status} from ${host}`;
          await res.body?.cancel().catch(() => {});
          if (attempt + 1 < maxAttempts) await sleep(backoffMs(attempt, res.headers.get('retry-after')));
          continue;
        }
        let json: unknown;
        try {
          json = await res.json();
        } catch {
          json = undefined;
        }
        if (!res.ok) {
          const code = (json as { error?: { code?: unknown } } | undefined)?.error?.code;
          return fail(`OpenAI embeddings HTTP ${res.status} from ${host}${typeof code === 'string' && SAFE_CODE.test(code) ? ` (${code})` : ''}`, res.status);
        }
        if (json === undefined) return fail(`OpenAI embeddings: response from ${host} is not JSON`);
        return parseResponse(json, inputs.length, fail);
      }
      return fail(`${last}; gave up after ${maxAttempts} attempt(s)`);
    },
  };
}

function parseResponse(json: unknown, n: number, fail: (m: string) => never): EmbedResult {
  const b = json as { data?: unknown; usage?: { total_tokens?: unknown; prompt_tokens?: unknown } };
  if (!Array.isArray(b.data) || b.data.length !== n) {
    return fail(`OpenAI embeddings: expected ${n} vector(s) for ${n} input(s), got ${Array.isArray(b.data) ? b.data.length : 'none'}`);
  }
  const vectors: number[][] = new Array(n);
  for (const d of b.data as Array<{ index?: unknown; embedding?: unknown }>) {
    const i = d.index;
    if (typeof i !== 'number' || !Number.isInteger(i) || i < 0 || i >= n || vectors[i]) return fail('OpenAI embeddings: bad or duplicate data[].index');
    const e = d.embedding;
    if (!Array.isArray(e) || e.length !== OPENAI_EMBED_DIMS) return fail(`OpenAI embeddings: expected ${OPENAI_EMBED_DIMS} dimensions`);
    if (!e.every((x) => typeof x === 'number' && Number.isFinite(x))) return fail('OpenAI embeddings: non-finite vector value');
    vectors[i] = e as number[];
  }
  const t = b.usage?.total_tokens ?? b.usage?.prompt_tokens;
  const totalTokens = typeof t === 'number' && Number.isInteger(t) && t >= 0 ? t : null;
  return { vectors, totalTokens };
}

/**
 * Deterministic fake for tests and CI: feature-hashed bag of words (sha256 of each
 * lower-cased word picks a dimension and a sign), L2-normalised. Similar wording ->
 * closer vectors. Usage = sum of estimateTokens(input). Records every call.
 */
export class FakeEmbeddingsClient implements EmbeddingsClient {
  readonly model = OPENAI_EMBED_MODEL;
  readonly kind = 'fake' as const;
  readonly calls: string[][] = [];
  /** Optional: throw on the n-th call (1-based) to test fail-closed paths. */
  failOnCall?: number;
  /** Optional: report this many tokens instead of the estimate (null = no usage). */
  reportTokens?: (inputs: string[]) => number | null;
  /** Optional synonym map: word -> canonical word (lets a test prove semantic-not-lexical hits). */
  synonyms: Record<string, string>;

  readonly dims: number;

  constructor(dims = OPENAI_EMBED_DIMS, opts: { synonyms?: Record<string, string> } = {}) {
    this.dims = dims;
    this.synonyms = opts.synonyms ?? {};
  }

  vector(text: string): number[] {
    const v = new Array<number>(this.dims).fill(0);
    const words = text.toLowerCase().match(/[\p{L}\p{N}]+/gu) ?? [];
    for (const w0 of words) {
      const w = this.synonyms[w0] ?? w0;
      const h = createHash('sha256').update(w).digest();
      const i = h.readUInt32BE(0) % this.dims;
      v[i]! += h[4]! & 1 ? 1 : -1;
    }
    let n = Math.sqrt(v.reduce((s, x) => s + x * x, 0));
    if (n === 0) {
      v[0] = 1;
      n = 1;
    }
    return v.map((x) => x / n);
  }

  async embed(inputs: string[]): Promise<EmbedResult> {
    this.calls.push([...inputs]);
    if (this.failOnCall !== undefined && this.calls.length === this.failOnCall) throw new EmbedError('fake client: injected failure', 503);
    const est = inputs.reduce((s, x) => s + estimateTokens(x), 0);
    return { vectors: inputs.map((x) => this.vector(x)), totalTokens: this.reportTokens ? this.reportTokens(inputs) : est };
  }
}
