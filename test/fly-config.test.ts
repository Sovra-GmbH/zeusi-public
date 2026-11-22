// Fly packaging for the hosted MCP server (Dockerfile, fly.toml, scripts/fly-entrypoint.sh,
// .dockerignore; docs/hosting.md). Static checks only: nothing is built, pushed or deployed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const read = (f: string) => readFileSync(`${ROOT}${f}`, 'utf8');
/** The file without comment lines (so a comment cannot satisfy or break a config check). */
const code = (t: string) => t.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

test('fly.toml: app your-zeusi-mcp in fra, shared-cpu-1x 512 MB, one always-on machine, volume zeusi_data at /data, port 443 only', () => {
  const raw = read('fly.toml');
  const t = code(raw);
  assert.match(t, /^app = "your-zeusi-mcp"$/m);
  assert.match(t, /^primary_region = "fra"$/m);
  assert.match(t, /size = "shared-cpu-1x"/);
  assert.match(t, /memory = "512mb"/);
  assert.match(t, /min_machines_running = 1/);
  assert.match(t, /auto_stop_machines = "off"/);
  assert.match(t, /auto_start_machines = false/);
  assert.match(t, /\[mounts\]\n\s*source = "zeusi_data"\n\s*destination = "\/data"/);
  assert.match(t, /internal_port = 8080/);
  assert.deepEqual([...t.matchAll(/^\s*port = (\d+)/gm)].map((m) => m[1]), ['443'], 'exactly one public port, 443');
  assert.match(t, /handlers = \["tls", "http"\]/);
  assert.doesNotMatch(t, /port = 80\b/);
  assert.doesNotMatch(t, /force_https/);
  assert.doesNotMatch(t, /\[http_service\]/);
  assert.doesNotMatch(t, /--http\b/);
  assert.doesNotMatch(t, /\[env\]/, 'no env values (secrets are a deploy-time step)');
  assert.match(raw, /--hosted/, 'documents the hosted command the image runs');
  assert.match(raw, /PLAN ONLY/);
});

test('Dockerfile: two stages, entrypoint, no native build tools at runtime, no ENV naming a password, key or host', () => {
  const t = code(read('Dockerfile'));
  const stages = t.split(/^FROM /m).slice(1);
  assert.equal(stages.length, 2);
  assert.match(stages[0]!, /^node:24-bookworm-slim AS build/);
  assert.match(stages[1]!, /^node:24-bookworm-slim\n/);
  const runtime = stages[1]!;
  assert.doesNotMatch(runtime, /node-gyp|python3|\bmake\b|build-essential|apt-get/);
  assert.match(runtime, /npm ci --omit=dev --ignore-scripts/);
  assert.match(runtime, /ENTRYPOINT \["\/app\/scripts\/fly-entrypoint\.sh"\]/);
  for (const line of t.split('\n').filter((l) => /^\s*ENV\s/.test(l))) {
    assert.doesNotMatch(line, /PASS|SECRET|KEY|TOKEN|HOST|NEON|OPENAI|PG/i, line);
  }
  assert.doesNotMatch(t, /--http\b/);
  // Open sign-up builds personal workspaces from the migration SQL at runtime.
  assert.match(runtime, /^COPY migrations \.\/migrations$/m);
  assert.match(runtime, /^COPY site\/favicon\.svg site\/logo-512\.png \.\/brand\/$/m, 'listing icons only, not the rest of site/');
  assert.ok(!read('.dockerignore').split('\n').map((l) => l.trim()).includes('migrations'), 'migrations reach the build context');
  const ignore = read('.dockerignore').split('\n').map((l) => l.trim());
  assert.ok(ignore.includes('site/assets'), 'the site film stays out of the image context');
  assert.ok(!ignore.includes('site/favicon.svg') && !ignore.includes('site/logo-512.png'));
});

test('entrypoint: refuses without the /data mount, chowns + tightens it, then execs setpriv into node --hosted (never --http; --write-service only behind the opt-in)', () => {
  const t = read('scripts/fly-entrypoint.sh');
  assert.match(t, /^#!\/bin\/sh\n/);
  assert.match(t, /set -eu/);
  assert.match(t, /mountpoint -q "\$DATA_DIR"/);
  assert.match(t, /chown node:node "\$DATA_DIR"/);
  assert.match(t, /chmod 700 "\$DATA_DIR"/);
  const c = code(t);
  assert.match(c, /^set -- node \/app\/dist\/mcp\.js --hosted --data-dir "\$DATA_DIR"$/m);
  const lines = c.trim().split('\n');
  assert.equal(lines.at(-1), 'exec setpriv --reuid=node --regid=node --init-groups -- "$@"');
  assert.doesNotMatch(c, /--http\b/);
  assert.equal([...c.matchAll(/--write-service "/g)].length, 1, 'one place adds --write-service');
  assert.match(c, /if \[ "\$WRITE" = yes \]; then\n\s*PGPASSFILE="\$RUN_DIR\/pgpass"\n\s*export PGPASSFILE\n\s*set -- "\$@" --write-service "\$SVC"/);
  assert.match(c, /^unset ZEUSI_DECISION_PGPASS\b/m, 'the password never reaches node\'s environment');
  assert.equal([...c.matchAll(/set -- "\$@" --tenant-service /g)].length, 1, 'one place adds the tenant flags');
  assert.match(c, /if \[ "\$TENANTS" = yes \]; then\n\s*PGPASSFILE="\$RUN_DIR\/pgpass"\n\s*export PGPASSFILE\n\s*set -- "\$@" --tenant-service zeusi_tenant_rt --tenant-admin-service zeusi_tenant_admin/);
  assert.match(c, /^unset ZEUSI_TENANT_RT_PGPASS ZEUSI_TENANT_ADMIN_PGPASS\b/m, 'the tenant passwords never reach node\'s environment');
  assert.doesNotMatch(c, /echo "\$ZEUSI_TENANT/, 'never echoes a tenant secret');
  assert.doesNotMatch(c, /set -x|echo "\$ZEUSI_DECISION_PGPASS|echo "\$v"/, 'never echoes the secret');
  assert.ok((statSync(`${ROOT}scripts/fly-entrypoint.sh`).mode & 0o111) !== 0, 'executable');
});

test('.dockerignore keeps secrets and local state out of the build context', () => {
  const lines = read('.dockerignore').split('\n').map((l) => l.trim());
  for (const p of ['.env*', '.pg_service.conf', '*.pgpass', 'config/sources.toml', 'node_modules', 'dist', '.git', 'test', 'docs', 'mcp-tokens.json', '*.token']) {
    assert.ok(lines.includes(p), p);
  }
});

test('.gitleaks.toml has the zeusi-mcp-token rule with the exact token pattern', () => {
  const t = read('.gitleaks.toml');
  assert.match(t, /id = "zeusi-mcp-token"/);
  assert.ok(t.includes("regex = '''zeusi_[a-z2-7]{12}_[A-Za-z0-9_-]{43}'''"));
});
