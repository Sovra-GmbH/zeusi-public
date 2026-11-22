// The hosted wiring of "born encrypted" (C5 KTD13): src/mcp.ts tenantSignupSetup builds the sign-up TenantDirectory
// with bornEncrypted = (ZEUSI_WORKSPACE_ENCRYPTION is exactly `on`). Every other hosted harness builds its own
// directory (test/helpers/hosted-tenants.ts), so without this file the expression in tenantSignupSetup could be
// replaced by a constant and the suite stayed green (independent review of PR #56). This goes through the REAL
// exported setup function and its real directory: PGlite with the real migrations and tenant logins, synthetic
// service file and pgpass (never resolvable host). No network, no Neon, no real workspace, no key.
// Mutants (each turns this red): `bornEncrypted: false` and `bornEncrypted: true` in tenantSignupSetup.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Db } from '../src/db.ts';
import { tenantSignupSetup } from '../src/mcp.ts';
import { readOverlayState } from '../src/tenant-overlay.ts';
import { TENANT_ADMIN_ROLE, TENANT_RT_ROLE } from '../src/tenants.ts';
import { ENCRYPTION_FLAG_ENV } from '../src/workspace-keys.ts';
import { safeMkdtemp } from './helpers/safe-tmp.ts';
import { asLogin, asOwner, tenantTestDb } from './helpers/tenant-fixture.ts';

const HOST = ['ep-fake-778', '.example.invalid'].join('');
const PW = ['Synthetic', 'WiringPw', '7Qx'].join('-');
const svc = (name: string, user: string) =>
  `[${name}]\nhost=${HOST}\nport=5432\ndbname=zeusi\nuser=${user}\nsslmode=verify-full\nsslrootcert=system\nchannel_binding=require\n`;
const ARGS = { tenantService: 'zeusi_tenant_rt', tenantAdminService: 'zeusi_tenant_admin' };

/** A hosted env whose two workspace services pass hostedTenantPreflight, plus the flag (undefined = unset). */
function hostedEnv(flag: string | undefined): NodeJS.ProcessEnv {
  const home = safeMkdtemp(join(tmpdir(), 'zeusi-bew-'));
  const run = safeMkdtemp(join(tmpdir(), 'zeusi-bew-run-'));
  const services = join(run, 'pg_service.conf');
  writeFileSync(services, [svc('zeusi_tenant_rt', TENANT_RT_ROLE), svc('zeusi_tenant_admin', TENANT_ADMIN_ROLE)].join('\n'));
  const pgpass = join(run, 'pgpass');
  writeFileSync(pgpass, [`${HOST}:5432:zeusi:${TENANT_RT_ROLE}:${PW}`, `${HOST}:5432:zeusi:${TENANT_ADMIN_ROLE}:${PW}x`, ''].join('\n'));
  chmodSync(pgpass, 0o600);
  const env: NodeJS.ProcessEnv = { HOME: home, PGSERVICEFILE: services, PGPASSFILE: pgpass };
  if (flag !== undefined) env[ENCRYPTION_FLAG_ENV] = flag;
  return env;
}

let db: Db;
before(async () => {
  db = await tenantTestDb({ writer: true });
});
after(async () => {
  await db.close();
});

/** The real setup's connect: each service name maps to its login on the shared PGlite session. */
const connect = (seen: string[]) => (service: string): Promise<Db> => {
  seen.push(service);
  if (service === ARGS.tenantAdminService) return asLogin(db, TENANT_ADMIN_ROLE)();
  if (service === ARGS.tenantService) return asLogin(db, TENANT_RT_ROLE)();
  throw new Error('unexpected service');
};

let n = 0;
/** Sign up one fresh subject through the directory tenantSignupSetup built; the catalog state and schema shape after. */
async function signUp(flag: string | undefined): Promise<{ encState: string; routed: string; prepared: boolean; flipChecks: number }> {
  const seen: string[] = [];
  const setup = tenantSignupSetup(ARGS, hostedEnv(flag), connect(seen));
  assert.equal(setup.signup, 'on (personal workspaces)', `flag ${String(flag)}: sign-up on`);
  assert.deepEqual(seen, [], 'startup never connects');
  const r = await setup.tenants!.dir.provision(`github:${7700 + ++n}`);
  assert.equal(r.kind, 'created');
  const tenantId = (r as { tenantId: string }).tenantId;
  const encState = await asOwner(db, async () =>
    (await db.query<{ s: string }>('SELECT enc_state AS s FROM zeusi_tenants.tenants WHERE tenant_id = $1', [tenantId])).rows[0]!.s);
  const shape = await asOwner(db, async () => readOverlayState(db, tenantId));
  const routed = (await setup.tenants!.router.encState(tenantId)).encState;
  return { encState, routed, prepared: shape.prepared, flipChecks: shape.flipChecks };
}

test('born-encrypted wiring: with ZEUSI_WORKSPACE_ENCRYPTION=on the hosted sign-up directory provisions prepare + flip and enc_state on', async () => {
  // Mutant `bornEncrypted: false` in src/mcp.ts tenantSignupSetup -> this reads off / not prepared: red.
  const on = await signUp('on');
  assert.equal(on.encState, 'on', 'catalog: born on');
  assert.equal(on.routed, 'on', 'the router of the same setup reads on');
  assert.equal(on.prepared, true, 'prepare overlay applied at provisioning');
  assert.equal(on.flipChecks, 5, 'flip overlay applied at provisioning (all five _enc_flipped CHECKs)');
});

test('born-encrypted wiring: with the flag off, enroll, unset or not understood, the hosted sign-up directory provisions plain (enc_state off, no overlay)', async () => {
  // Mutant `bornEncrypted: true` in src/mcp.ts tenantSignupSetup -> each of these reads on / prepared: red.
  for (const flag of ['off', 'enroll', undefined, '', 'ON', 'yes']) {
    const r = await signUp(flag);
    assert.deepEqual(r, { encState: 'off', routed: 'off', prepared: false, flipChecks: 0 }, `flag ${JSON.stringify(flag)}`);
  }
});
