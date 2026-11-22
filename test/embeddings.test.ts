// U6a: embeddings clients. No network: the OpenAI client gets an injected fetch;
// the key is a synthetic string assembled at runtime and must never surface.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createOpenAIClient, EmbedError, FakeEmbeddingsClient, OPENAI_KEY_ENV, DEFAULT_EMBED_BASE_URL, validateBaseUrl,
  type FetchLike,
} from '../src/embeddings.ts';
import { assertSecretEqual } from './redact.ts';

const KEY = ['sk-', 'proj-', 'FAKE', 'never-print-', 'x9z8'].join('');
const env = { [OPENAI_KEY_ENV]: KEY };
const noSleep = async () => {};

function vec(dims: number, seed: number): number[] {
  return Array.from({ length: dims }, (_, i) => ((i + seed) % 7) / 7);
}

function okFetch(calls: { url: string; init: RequestInit }[] = [], tokens = 11): FetchLike {
  return async (url, init) => {
    calls.push({ url: String(url), init: init! });
    const body = JSON.parse(String(init!.body)) as { input: string[] };
    return new Response(JSON.stringify({
      model: 'text-embedding-3-small',
      data: body.input.map((_, i) => ({ index: i, embedding: vec(1536, i) })).reverse(),
      usage: { prompt_tokens: tokens, total_tokens: tokens },
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

function assertNoKey(e: unknown) {
  const all = [String(e), (e as Error).message, (e as Error).stack ?? '', JSON.stringify(e), String((e as { cause?: unknown }).cause ?? '')].join('\n');
  assert.ok(!all.includes(KEY), 'the key never appears in an error');
  assert.ok(!all.includes(KEY.slice(0, 12)), 'no key prefix either');
}

test('OpenAI client: refuses without the env key; never reads any other var', () => {
  assert.throws(() => createOpenAIClient({ env: {} }), /ZEUSI_OPENAI_API_KEY is not set/);
  assert.throws(() => createOpenAIClient({ env: { OPENAI_API_KEY: KEY } }), /ZEUSI_OPENAI_API_KEY is not set/);
});

test('OpenAI client: EU endpoint by default, key only in the Authorization header, order by index', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const c = createOpenAIClient({ env, fetch: okFetch(calls), sleep: noSleep });
  const r = await c.embed(['a', 'b', 'c']);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, `${DEFAULT_EMBED_BASE_URL}/embeddings`);
  assert.equal(DEFAULT_EMBED_BASE_URL, 'https://eu.api.openai.com/v1');
  assert.ok(!calls[0]!.url.includes(KEY));
  assertSecretEqual((calls[0]!.init.headers as Record<string, string>)['Authorization'], `Bearer ${KEY}`, 'Authorization header');
  const sent = JSON.parse(String(calls[0]!.init.body));
  assert.deepEqual(sent, { model: 'text-embedding-3-small', input: ['a', 'b', 'c'], dimensions: 1536, encoding_format: 'float' });
  assert.ok(!String(calls[0]!.init.body).includes(KEY));
  assert.equal(r.vectors.length, 3);
  assert.deepEqual(r.vectors[1], vec(1536, 1), 'reordered by data[].index');
  assert.equal(r.totalTokens, 11);
});

test('base URL: https EU OpenAI host only, no credentials/query', () => {
  assert.equal(validateBaseUrl('https://eu.api.openai.com/v1/'), 'https://eu.api.openai.com/v1');
  assert.throws(() => validateBaseUrl('http://eu.api.openai.com/v1'), /https/);
  assert.throws(() => validateBaseUrl('https://api.openai.com/v1'), /EU/);
  assert.throws(() => validateBaseUrl('https://eu.api.openai.com.evil.example/v1'), /EU/);
  assert.throws(() => validateBaseUrl('https://u:p@eu.api.openai.com/v1'), /credentials/);
  assert.throws(() => validateBaseUrl('https://eu.api.openai.com/v1?k=1'), /query/);
});

test('retry: 429 and 5xx are retried with backoff (Retry-After honoured), then succeed', async () => {
  const statuses = [429, 503, 200];
  const sleeps: number[] = [];
  let n = 0;
  const f: FetchLike = async (url, init) => {
    const s = statuses[n++]!;
    if (s !== 200) return new Response('{}', { status: s, headers: s === 429 ? { 'retry-after': '2' } : {} });
    return okFetch()(url, init);
  };
  const c = createOpenAIClient({ env, fetch: f, sleep: async (ms) => { sleeps.push(ms); } });
  const r = await c.embed(['x']);
  assert.equal(n, 3);
  assert.equal(r.vectors.length, 1);
  assert.equal(sleeps.length, 2);
  assert.equal(sleeps[0], 2000, 'Retry-After seconds');
  assert.ok(sleeps[1]! >= 500);
});

test('retry: gives up after maxAttempts (fail closed), 4xx is not retried', async () => {
  let n = 0;
  const c = createOpenAIClient({ env, fetch: async () => { n++; return new Response('{}', { status: 500 }); }, sleep: noSleep, maxAttempts: 3 });
  await assert.rejects(c.embed(['x']), (e: unknown) => e instanceof EmbedError && /HTTP 500/.test(e.message) && /3 attempt/.test(e.message));
  assert.equal(n, 3);
  n = 0;
  const c2 = createOpenAIClient({ env, fetch: async () => { n++; return new Response('{}', { status: 400 }); }, sleep: noSleep });
  await assert.rejects(c2.embed(['x']), /HTTP 400/);
  assert.equal(n, 1);
});

test('a thrown error never contains the key (HTTP body, network error, bad JSON, bad shape)', async () => {
  const cases: FetchLike[] = [
    async () => new Response(JSON.stringify({ error: { message: `Incorrect API key provided: ${KEY}`, code: 'invalid_api_key' } }), { status: 401 }),
    async () => { throw new TypeError(`fetch failed for Bearer ${KEY}`); },
    async () => new Response(`not json ${KEY}`, { status: 200 }),
    async () => new Response(JSON.stringify({ data: [{ index: 0, embedding: [KEY] }], usage: { total_tokens: 1 } }), { status: 200 }),
    async () => new Response(JSON.stringify({ data: [{ index: 0, embedding: [1, 2] }], model: KEY }), { status: 200 }),
  ];
  for (const f of cases) {
    const c = createOpenAIClient({ env, fetch: f, sleep: noSleep, maxAttempts: 2 });
    let caught: unknown;
    try {
      await c.embed(['hello']);
    } catch (e) {
      caught = e;
    }
    assert.ok(caught instanceof EmbedError, 'fails closed with EmbedError');
    assertNoKey(caught);
  }
  // the safe error code is kept, the message is not
  const c = createOpenAIClient({ env, fetch: cases[0]!, sleep: noSleep });
  await assert.rejects(c.embed(['x']), /HTTP 401.*invalid_api_key/);
});

test('shape checks: wrong count, wrong dims, non-finite values fail closed', async () => {
  const bad = (data: unknown) => createOpenAIClient({ env, sleep: noSleep, fetch: async () => new Response(JSON.stringify({ data, usage: { total_tokens: 1 } }), { status: 200 }) });
  await assert.rejects(bad([]).embed(['x']), /1 input/);
  await assert.rejects(bad([{ index: 0, embedding: [1, 2, 3] }]).embed(['x']), /dimensions/);
  await assert.rejects(bad([{ index: 0, embedding: vec(1535, 0).concat([Number.NaN]) }]).embed(['x']), /dimensions|finite/);
});

test('missing usage: totalTokens is null (caller keeps the worst-case reservation)', async () => {
  const c = createOpenAIClient({ env, sleep: noSleep, fetch: async () => new Response(JSON.stringify({ data: [{ index: 0, embedding: vec(1536, 0) }] }), { status: 200 }) });
  assert.equal((await c.embed(['x'])).totalTokens, null);
});

test('fake client: deterministic, 1536 dims, unit length, similar text is closer', async () => {
  const f = new FakeEmbeddingsClient();
  const [a, a2, b] = (await f.embed(['deploy the connector', 'deploy the connector', 'banana smoothie recipe'])).vectors;
  assert.deepEqual(a, a2);
  assert.equal(a!.length, 1536);
  const norm = Math.sqrt(a!.reduce((s, x) => s + x * x, 0));
  assert.ok(Math.abs(norm - 1) < 1e-9);
  const [c] = (await f.embed(['connector deploy steps'])).vectors;
  const dot = (x: number[], y: number[]) => x.reduce((s, v, i) => s + v * y[i]!, 0);
  assert.ok(dot(a!, c!) > dot(a!, b!));
  assert.equal(f.calls.length, 2);
  assert.deepEqual(f.calls[0], ['deploy the connector', 'deploy the connector', 'banana smoothie recipe']);
});
