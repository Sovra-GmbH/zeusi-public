// One-shot text-embedding-3-small smoke: one API call, store, cosine query, cleanup.
// The OpenAI key is read from the macOS Keychain, never from .env, argv, or logs.

import { createHash, randomBytes } from 'node:crypto';
import { readKeychainPassword } from './keychain.ts';
import { asPgError, type Db } from './db.ts';
import {
  EMBED_DIMS,
  INDEXED_EMBED_MODEL,
  insertFact,
  vectorQuery,
} from './facts.ts';

export const OPENAI_KEYCHAIN_SERVICE = 'zeusi-openai-api-key';
const EU_EMBEDDINGS = 'https://eu.api.openai.com/v1/embeddings';
const SMOKE_TEXT = 'Zeusi keychain embedding smoke, 14 Nov 2026.';

export interface EmbedSmokeResult {
  ok: boolean;
  lines: string[];
}

function sha256Hex(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

function vecLiteral(values: number[]): string {
  return `[${values.join(',')}]`;
}

async function embedOnce(key: string, input: string): Promise<{ values: number[]; model: string; endpoint: string }> {
  const res = await fetch(EU_EMBEDDINGS, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'text-embedding-3-small',
      input,
      dimensions: EMBED_DIMS,
      encoding_format: 'float',
    }),
  });
  const endpoint = 'eu.api.openai.com';
  if (!res.ok) {
    // Do not print the body; it might echo request metadata.
    throw new Error(`OpenAI embeddings HTTP ${res.status} from ${endpoint}`);
  }
  const body = (await res.json()) as {
    data?: { embedding?: number[] }[];
    model?: string;
  };
  const values = body.data?.[0]?.embedding;
  if (!Array.isArray(values)) throw new Error('OpenAI response missing embedding array');
  return { values, model: body.model ?? 'text-embedding-3-small', endpoint };
}

export async function embedSmoke(db: Db): Promise<EmbedSmokeResult> {
  const lines: string[] = [];
  const token = `zeusi-embed-smoke-${randomBytes(6).toString('hex')}`;
  const sourceUri = `zeusi:embed-smoke/${token}`;
  const runIds: number[] = [];
  let ok = false;

  const cleanup = async () => {
    const like = `%${token}%`;
    await db.query('DELETE FROM zeusi.chunks WHERE source_uri LIKE $1', [like]);
    await db.query('DELETE FROM zeusi.facts WHERE source_uri LIKE $1', [like]);
    if (runIds.length) await db.query('DELETE FROM zeusi.ingest_runs WHERE id = ANY($1::bigint[])', [runIds]);
    const left = await db.query<{ n: string }>(
      `SELECT (SELECT count(*) FROM zeusi.facts WHERE source_uri LIKE $1)
            + (SELECT count(*) FROM zeusi.chunks WHERE source_uri LIKE $1)
            + (SELECT count(*) FROM zeusi.ingest_runs WHERE id = ANY($2::bigint[])) AS n`,
      [like, runIds],
    );
    return Number(left.rows[0]!.n);
  };

  try {
    const key = await readKeychainPassword(OPENAI_KEYCHAIN_SERVICE);
    lines.push(`keychain: ${OPENAI_KEYCHAIN_SERVICE} present length=${key.length}`);

    const { values, model, endpoint } = await embedOnce(key, SMOKE_TEXT);
    const dimOk = values.length === EMBED_DIMS;
    lines.push(`embed: model=${model} endpoint=${endpoint} dimensions=${values.length} expected=${EMBED_DIMS} ${dimOk ? 'PASS' : 'FAIL'}`);
    if (!dimOk) {
      await cleanup();
      return { ok: false, lines };
    }

    const now = new Date().toISOString();
    const sha = sha256Hex(SMOKE_TEXT);
    const ins = await insertFact(
      db,
      {
        kind: 'other',
        text: SMOKE_TEXT,
        scope: 'work',
        sourceKind: 'manual',
        sourceUri,
        sourceTs: now,
        sourceSha256: sha,
      },
      { importer: 'embed-smoke', mode: 'manual' },
    );
    if (ins.status !== 'inserted') {
      lines.push(`fact insert: ${ins.status} (unexpected)`);
      runIds.push(ins.runId);
      const left = await cleanup();
      lines.push(`cleanup: ${left} rows left`);
      return { ok: false, lines };
    }
    runIds.push(ins.runId);
    lines.push(`stored: fact id ${ins.id}`);

    const vec = vecLiteral(values);
    const ch = await db.query<{ id: string }>(
      `INSERT INTO zeusi.chunks (fact_id, chunk_index, text, text_sha256, token_count, embed_model, embedding, embedded_at, source_uri)
       VALUES ($1, 0, $2, decode($3, 'hex'), $4, $5, $6::halfvec(${EMBED_DIMS}), now(), $7) RETURNING id`,
      [ins.id, SMOKE_TEXT, sha, SMOKE_TEXT.split(/\s+/).length, INDEXED_EMBED_MODEL, vec, sourceUri],
    );
    const chunkId = Number(ch.rows[0]!.id);
    const hits = await vectorQuery(db, vec, 5);
    const top = hits[0];
    const found = !!top && top.id === chunkId && top.distance < 1e-3 && top.source_uri === sourceUri;
    lines.push(
      found
        ? `query: found chunk ${chunkId} distance=${top!.distance.toFixed(6)} source_uri=${sourceUri} PASS`
        : `query: FAIL top=${top ? `chunk ${top.id} d=${top.distance}` : 'none'} expected chunk ${chunkId}`,
    );

    const left = await cleanup();
    const cleaned = left === 0;
    lines.push(`cleanup: ${left} rows left ${cleaned ? 'PASS' : 'FAIL'}`);
    ok = dimOk && found && cleaned;
    if (ok) lines.push('EMBED SMOKE PASS (1 call, no importers)');
    else lines.push('EMBED SMOKE FAIL');
    return { ok, lines };
  } catch (e) {
    try {
      const left = await cleanup();
      lines.push(`cleanup after error: ${left} rows left`);
    } catch (ce) {
      const pe = asPgError(ce);
      lines.push(`cleanup error${pe.code ? ` [${pe.code}]` : ''}: ${pe.message.slice(0, 200)}`);
    }
    const pe = asPgError(e);
    lines.push(`error${pe.code ? ` [${pe.code}]` : ''}: ${pe.message.slice(0, 200)}`);
    lines.push('EMBED SMOKE FAIL');
    return { ok: false, lines };
  }
}
