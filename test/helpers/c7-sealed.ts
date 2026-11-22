// Test-only helpers for the C7 sealed read route: workspaces in each encrypted state filled through the real
// write route with the REAL B1 index hook (src/b1-index.ts), a wrap proof from a FIXED test DEK, and personal
// deps on the sealed route. No network, no Neon, no real workspace or key.
import assert from 'node:assert/strict';
import { B1Cache, proveSessionWrap, type WrapProof } from '../../src/b1-cache.ts';
import { b1IndexHook, type HookStats } from '../../src/b1-index.ts';
import type { Db } from '../../src/db.ts';
import type { McpDeps } from '../../src/mcp-server.ts';
import { PLAIN_READ, readRouteFor, type ReadRoute } from '../../src/read-route.ts';
import { OVERLAY_SPEC, SEALED_DIGEST_TABLES } from '../../src/tenant-overlay.ts';
import type { EncState } from '../../src/tenants.ts';
import { openedRow, WorkspaceKey } from '../../src/workspace-seal.ts';
import { c6Fixture, callerOf, newWorkspace, TEST_DEK, type C6Fixture } from './c6-fixture.ts';
import { fillC7, personalDeps } from './c7-fixture.ts';
import { asOwner } from './tenant-fixture.ts';

export interface C7World { f: C6Fixture; stats: HookStats; cache: B1Cache }

export async function c7World(): Promise<C7World> {
  const stats: HookStats = { segments: 0, rebuilds: 0, compactions: 0, skippedNoTable: 0 };
  const f = await c6Fixture({ indexHook: (key) => b1IndexHook(key, stats) });
  return { f, stats, cache: new B1Cache() };
}

/** The grant id callerOf() gives a workspace (the proof must be for the same grant). */
export const grantOf = (t: string) => `grant-${t.slice(3, 12)}`;

/** A proof for workspace `t` from the test DEK (as OAuthServer.sessionKeyFor(bearer) would unwrap it). */
export function proofFor(t: string, o: { dek?: Buffer; keyVersion?: number; grant?: string } = {}): WrapProof {
  const p = proveSessionWrap(() => ({ tenant: t, grantId: o.grant ?? grantOf(t), dek: Buffer.from(o.dek ?? TEST_DEK), keyVersion: o.keyVersion ?? 1 }), { tenant: t, grantId: o.grant ?? grantOf(t) });
  assert.ok(p, 'a proof');
  return p;
}

/**
 * Personal deps whose read route is computed like src/mcp-hosted.ts: enc_state via the router, then readRouteFor,
 * then (sealed) a fresh proof per call from the test DEK. `log` records the workspace session's statements.
 */
export function routedDeps(w: C7World, t: string, o: { tenantRead?: () => Promise<Db>; proof?: () => WrapProof | null; extra?: Partial<McpDeps> } = {}): () => McpDeps {
  return () => {
    let proof: WrapProof | null = null;
    const readRoute = async (): Promise<ReadRoute> => {
      const st = await w.f.router.encState(t);
      if (readRouteFor(st.encState) === 'plain') return PLAIN_READ;
      proof = o.proof ? o.proof() : proofFor(t);
      if (!proof) throw new (await import('../../src/read-route.ts')).ReadRouteRefused('locked');
      return { kind: 'sealed', proof, cache: w.cache };
    };
    return personalDeps({ tenantRead: o.tenantRead ?? (() => w.f.router.open(t)), extra: { readRoute, ...(o.extra ?? {}) } });
  };
}

/** A workspace in `state`, filled with the C7 corpus through the real write route (sealed for verified / on). */
export async function filledWorkspace(w: C7World, state: 'off' | 'on' | 'verified'): Promise<string> {
  const t = await newWorkspace(w.f, state);
  await fillC7(w.f, callerOf(t));
  return t;
}

/**
 * D: a born-on workspace relaxed to decrypting, with every row of an EVEN id decrypted by a decrypt-shaped UPDATE
 * as the owner (plain columns from the opened values, every _ct / _hmac NULL, key_version NULL): the mixed shape a
 * C8b run leaves mid-way. The C8 tool does not exist; this is test-only owner SQL.
 */
export async function decryptingWorkspace(w: C7World): Promise<string> {
  const t = await filledWorkspace(w, 'on');
  assert.equal((await w.f.dir.overlayStep(t, 'relax', { dryRun: false })).outcome, 'applied');
  const key = WorkspaceKey.fromUnlocked({ dek: Buffer.from(TEST_DEK), keyVersion: 1 }, t);
  try {
    await asOwner(w.f.db, async () => {
      for (const spec of OVERLAY_SPEC) {
        const cols = spec.columns.map((c) => c.plain);
        const sel = [...cols, ...cols.map((c) => `${c}_ct`)].join(', ');
        const rows = (await w.f.db.query<Record<string, unknown>>(`SELECT id, key_version, ${sel} FROM "${t}".${spec.table} WHERE id % 2 = 0 AND key_version IS NOT NULL`)).rows;
        for (const r of rows) {
          const o = openedRow(key, spec.table, r, cols);
          const sets = cols.map((c, i) => `${c} = $${i + 2}${c === 'frontmatter' ? '::jsonb' : c === 'applies_to' ? '::text[]' : ''}`);
          const vals = cols.map((c) => (c === 'frontmatter' ? JSON.stringify(o[c]) : o[c]));
          const nulls = [...cols.map((c) => `${c}_ct = NULL`), ...spec.columns.filter((c) => c.hmac).map((c) => `${c.plain}_hmac = NULL`), 'key_version = NULL'];
          const derived = spec.table === 'chunks' ? [`text_sha256 = sha256(convert_to($${cols.indexOf('text') + 2}, 'UTF8'))`] : [];
          // C8-0: a decrypted row carries no sealed digest copy (the plain-side CHECK); its plain digest comes back from it.
          const copy = SEALED_DIGEST_TABLES.includes(spec.table)
            ? (await w.f.db.query<{ c: Uint8Array | null }>(`SELECT source_sha256_ct AS c FROM "${t}".${spec.table} WHERE id = $1`, [r['id']])).rows[0]?.c ?? null
            : null;
          const digest = copy ? [`source_sha256 = decode('${key.open(spec.table, 'source_sha256', Number(r['id']), copy)}', 'hex')`, 'source_sha256_ct = NULL'] : [];
          await w.f.db.query(`UPDATE "${t}".${spec.table} SET ${[...sets, ...nulls, ...derived, ...digest].join(', ')} WHERE id = $1`, [r['id'], ...vals]);
        }
      }
    });
  } finally {
    key.dispose();
  }
  return t;
}

export const setEnc = (w: C7World, t: string, s: EncState) => asOwner(w.f.db, async () => {
  await w.f.db.query(`UPDATE zeusi_tenants.tenants SET enc_state = $2 WHERE tenant_id = $1`, [t, s]);
});
