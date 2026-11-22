#!/usr/bin/env node
// zeusi — thin v1 CLI. Never prints connection strings, hosts, passwords, or tokens.
//
// Two connection paths (PLAN.md KTD11):
//   * ROLE commands connect through a pg_service.conf section (default zeusi_ingest)
//     with the password from the Keychain item zeusi-neon-<role> or ~/.pgpass.
//   * OWNER commands (owner only: migrate, prove, embed-smoke, wall allow) read the
//     owner URL from .env.local. .env.local is loaded ONLY for these commands.
//
// Opt-in transport (src/transport.ts): ZEUSI_TRANSPORT=serverless sends `search` and
// `doctor` over wss/443 (@neondatabase/serverless) as zeusi_box_ro / zeusi_cloud_ro only.
// It is checked first, before any other work; every other command is refused under it.

import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { ConfigError, loadEnvFiles, resolveUrl, DIRECT_URL_NAMES, POOLED_URL_NAMES } from './config.ts';
import { asPgError, ConnectError, connectOwner, connectService, INSECURE_NO_CB_FLAG, type Db } from './db.ts';
import { I_KNOW_MAIN_FLAG, MAIN_ENDPOINT_ENV, mainBranchGuard, mainBranchGuardForHost } from './owner-guard.ts';
import { migrate, listMigrations } from './migrate.ts';
import {
  dummyVector, getFact, hnswIndexInfo, insertFact, vectorQuery, vectorQueryUsesHnsw, ValidationError,
  type FactInput,
} from './facts.ts';
import { formatReport, prove } from './prove.ts';
import { embedSmoke } from './embed-smoke.ts';
import { KeychainError } from './keychain.ts';
import { collectDoctor, doctorExitOk, formatDoctor, runDoctor } from './doctor.ts';
import { assertTransportAllowed, connectReadOnly, SERVERLESS_ROLES, TRANSPORT_ENV } from './transport.ts';
import { formatRoleChecks, roleCatalogChecks } from './roles.ts';
import { connectDirectService, requireDirectEndpoint } from './endpoint-guard.ts';
import { assertScope, executeImport, formatPreview, formatRealResult, IMPORT_SCOPES, prepareImport, previewJson, type ImportScope } from './import-run.ts';
import { ImportInputError, INPUT_KINDS, type ImportInput, type InputKind } from './importers/onboard.ts';
import { DEFAULT_SERVICE, ROLES_SERVICE, SEARCH_SERVICE, serviceFilePath } from './service.ts';
import { createOpenAIClient, EmbedError, OPENAI_KEY_ENV, type EmbeddingsClient } from './embeddings.ts';
import { EMBED_MODEL_LABEL, EMBED_WORKSPACE_REFUSED, effectiveCapUsd, EmbedRefused, formatEmbedResult, runEmbed, workspaceEmbedName } from './embed.ts';
import { estimateReport, formatEstimate } from './estimate.ts';
import { defaultLedgerPath, formatSearch, LEXICAL_ONLY_NOTICE, MAX_LIMIT, QueryLedger, search, SEARCH_SCOPES, SearchRefused } from './search.ts';
import { formatAudit, formatReport as formatWallReport, ownerActionLine, realIngestExitCode, wallAllow, wallAudit, wallReport, WallAdminError } from './wall-admin.ts';
import { loadWall, seedWall, WallRuleError } from './wall.ts';
import { loadSources } from './sources.ts';
import { formatLint, lintVault } from './locks-lint.ts';
import { applyStandingMarkers, classifyVault, formatClassify, previewDifferences, savedPreview } from './locks-classify.ts';
import { formatReparse, runReparse } from './locks-reparse.ts';
import { assertIngestReady, formatVaultResult, HQ_PROFILE, importVault, IngestNotReady, VAULT_PROFILE, VaultRunError, type VaultDryRunObservation } from './importers/vault.ts';
import {
  extractHqStructured, formatHqStructuredPreview, formatHqStructuredResult, hqNoteFromObservation, previewHqStructured, type HqNoteInput,
} from './importers/hq-structured.ts';
import { ExportFilterError, ExportFilterIoError, ExportFilterUnsafeError, formatExportResult, runExportFilter } from './hq-export.ts';
import { formatTokenList, listTokens, McpTokenError, mintToken, resolveTokensPath, revokeToken } from './mcp-token-admin.ts';
import { DEFAULT_TOKENS_PATH, MAX_EXPIRES_DAYS, TokenFileError, TOKENS_PATH_ENV } from './mcp-tokens.ts';
import { OAuthStore, OAuthStoreError } from './mcp-oauth-store.ts';
import { formatRescrub, RescrubRefused, runRescrub } from './rescrub.ts';
import { resolveService } from './service.ts';
import { OVERLAY_STEPS, TENANT_ADMIN_ROLE, TENANT_WR_ROLE, TenantDirectory, TenantError, TenantRefused, type OverlayStep } from './tenants.ts';
import { formatOverlayStep } from './tenant-overlay.ts';
import { encryptStatus, EncryptStatusRefused, formatEncryptStatus, runEncryptStatusAll } from './encrypt-status.ts';
import { TENANT_ID_RE } from './tenant-ddl.ts';
import { wsAuditSink } from './workspace-audit.ts';
import { runWorkspaceDelete, WorkspaceDeleteRefused } from './workspace-delete.ts';
import { addPerson, formatPeopleList, formatPlan, listPeople, PeopleRefused, PERSON_KINDS, PERSON_ORGS, validatePerson } from './people.ts';

/** The hosted OAuth store: `zeusi mcp-oauth` and `zeusi workspaces delete` must default to the same file. */
const DEFAULT_OAUTH_STORE = '/data/mcp-oauth.json';

const HELP = `zeusi — Zeusi v1 CLI (Neon Postgres + pgvector)

Usage: npm start -- <command> [options]

Role commands (service from ~/.pg_service.conf, password from the Keychain item
zeusi-neon-<role> or ~/.pgpass; --service <name> overrides the default ${DEFAULT_SERVICE}):
  doctor [--service <name>]
        Connect as the role. Print TLS yes/no, channel binding, server major,
        pgvector present, migrations visible. No hosts or credentials.
  doctor --roles [--service <name>]
        Read-only role catalog checks (default service ${ROLES_SERVICE}): no login
        role in neon_superuser, CONNECTION LIMIT and session settings as designed.
  doctor --offline
        No connection: service file present?, migration files.
  fact add --text <t> --source-uri <uri> --source-ts <iso> --source-sha256 <hex>
           [--kind other] [--subject <key>] [--scope work|product|client] [--source-kind manual]
        Insert one sourced fact. The wall pre-check (src/wall.ts) quarantines a
        blocked fact (uri + hash only) before sending; exit code 3.
  fact get <id>
  vector-probe
        Check the HNSW index and run a dummy-vector query (no embedding provider).
  ingest vault [--full|--incremental] --dry-run [--config <sources.toml>]
        Walk the configured vault globs read-only, apply both wall gates, parse and
        chunk. No database (seed wall rules). Prints counts only (by scope, rule,
        quarantine): no paths, no text. Default config: config/sources.toml.
  ingest vault [--full|--incremental] --real [--config <f>] [--service <name>] [--verbose]
        Real ingest as zeusi_ingest (service ${DEFAULT_SERVICE}, DIRECT endpoint: a pooled host is
        refused offline, the run holds a session advisory lock). Refused without --real
        (before any connection), for owner-privileged sessions, and unless wall
        migrations 0006-0011 are applied. Writes notes/chunks (no embeddings: U6),
        quarantine (uri + hash only) and one ingest_runs row, then runs
        wall audit (exit 1 unless 0 rows).
  ingest vault --reparse-frontmatter [--scope work|product|client] [--config <f>] [--service <name>]
               [--real [${I_KNOW_MAIN_FLAG}]]
        Re-parse the frontmatter of UNCHANGED vault files (the importer skips them by sha, so a
        parser fix never reaches stored frontmatter). Same walk and gates as ingest vault. DRY RUN
        by default: as zeusi_ingest inside BEGIN READ ONLY, zero writes, counts only (notes scanned,
        frontmatter changed, lock items and current/superseded/expired before and after). --real
        updates ONLY notes.frontmatter (no body, chunk, embedding, quarantine, insert or delete;
        DIRECT endpoint, importer lock, main-branch guard). docs/note-locks.md.
  locks lint --vault <root> [--all] [--json]
        Offline, read-only (no database): parse the standing folders (Work/ops, Work/handbook;
        --all: every folder under Work/) with the old and the new frontmatter parser. Prints counts,
        every changed lock item as vault_path:ord with old / new text (local output only), the
        supersedes / lock_until resolution, and CANDIDATES (same-subject pairs, time-box language
        without lock_until) for a human to confirm. Never opens a walled or Plankiva path.
  locks classify --vault <root> [--json] [--show-text] [--save-preview <file>] | --real --from <file>
        OFFLINE. Proposes which Northbank product locks are durable standing rules
        (docs/locks-classifier.md): promote / skip / reason, counts. DRY RUN by
        default (opens files read-only); --save-preview writes the preview (refs + file
        sha256) to <file>. --real --from <file> adds ONLY a standing_locks: line to the
        promoted notes, and refuses (writes nothing) unless a fresh classification equals
        that saved preview exactly. Vault files only, no database; then zeusi ingest vault.
  ingest hq-sync [--full|--incremental] (--dry-run | --real) [--config <f>] [--service <name>] [--verbose]
        The same importer, gates and refusals for the Zeus HQ export folder (the
        zeus_memory sources: <root>/<project>/YYYY-MM-DD-<slug>.md, docs/hq-sync.md).
        source_kind zeus_memory, uris hq:<project>/<file>, ingest_runs importer hq-sync.
        Then decision / memory entries WITH the explicit header block (Decision: / Type: rule|focus)
        become zeusi.decisions / zeusi.facts rows (importer hq-sync-structured, uris hq:<project>/entry/<id>):
        the person must already exist (else unknown_person), an edited entry is a conflict (no update),
        entries without a header stay notes. --dry-run prints the would-insert counts.
  onboard <inputs> --scope ${IMPORT_SCOPES.join('|')} [--json]
        First run. Always a dry run: offline (no database connection, nothing written).
        Prints the preview (counts per input and per target: notes, chunks, rules, focus,
        decisions, withheld, quarantined) and the exact \`zeusi import ... --real\` command to
        run next. Never writes. Inputs (repeatable, at least one):
          --markdown <folder>        markdown / Obsidian notes (\`locks:\` lists become rules)
          --decision-log <file>      decision log, .md or .jsonl (zeusi_log_decision field names)
          --claude-export <file>     Claude conversations.json
          --chatgpt-export <file>    ChatGPT conversations.json
          --git <repo>               local git history: decision-like commits and PR merges
        Every input passes the nightly export-filter, then the importer's wall gates.
  import <inputs> --scope <scope> [--real [--service <name>] [${I_KNOW_MAIN_FLAG}]] [--json]
        Without --real: the same dry run as onboard. With --real: prints the same preview,
        then writes as zeusi_ingest (service ${DEFAULT_SERVICE}, DIRECT endpoint) into that scope only:
        notes/chunks (source_kind manual, uris import:<project>/...), and decisions / facts
        (rule, focus) only from entries with an explicit header whose \`who\` already exists
        in zeusi.people. Idempotent, resumable (ingest_runs), never deletes. Refused unless
        ${MAIN_ENDPOINT_ENV} (from the environment) is set and differs from the service's
        endpoint, or ${I_KNOW_MAIN_FLAG} is passed. Then wall audit (exit 1 unless 0 rows).
  export-filter --in <staging dir> --out <source folder> [--report] [--config <sources.toml>]
        Offline (no database, no network). Withholds every H2 entry with an Plankiva
        signal, a requests/ path or a credential pattern (marker line only), drops whole
        notes whose path / frontmatter trip, writes clean notes to --out (never to --in),
        re-checks the output with the wall and refuses otherwise. Counts only.
        --config limits the project folders to the zeus_memory sources' project keys.
  embed --estimate [--config <sources.toml>] [--notes-per-day <n>]
        Offline, count-only cost estimate: dry-run importer over the vault (read-only,
        no DB, no network): (a) current wall, (b) upper bound with the ClientCo-named hard
        rules lifted, total x2 safety factor vs the $5 cap, monthly steady state.
  embed --dry-run [--limit <n>] [--cap-usd <x>] [--service <name>]
        Connect as zeusi_ingest: pending chunks, reuse, tokens and worst-case cost. No
        API call, no write.
  embed --real [--limit <n>] [--cap-usd <x>] [--host <label>] [--service <name>]
        Embed chunks whose embedding IS NULL with OpenAI text-embedding-3-small (1536,
        EU endpoint https://eu.api.openai.com/v1). Key ONLY from ${OPENAI_KEY_ENV}.
        Refused without --real AND the key (before any connection). Hard monthly cap
        $5.00 for all hosts (--cap-usd may only lower it), reserved atomically before
        every batch. Refused while \`wall audit\` reports rows. Never run by ingest.
  search "<query>" [--limit <n>] [--scope work|product|client] [--hybrid] [--json] [--service <name>]
        Read-only search as zeusi_box_ro (service ${SEARCH_SERVICE}, pooled; password from
        ~/.pgpass or ZEUSI_NEON_BOX_RO_PASSWORD, ro only). Semantic with ${OPENAI_KEY_ENV},
        else lexical-only with a notice. --hybrid fuses vector + full text (RRF k=60).
        Hits cite source_uri, source_ts, scope, heading path; text is at most the chunk.
  rescrub [--real [${I_KNOW_MAIN_FLAG}] [--skip-embed] [--cap-usd <x>] [--host <label>]] [--service <name>]
        Re-scrub already-ingested rows with the shared credential detector (src/secrets.ts):
        notes (title, body, frontmatter), chunks (heading, text), facts, decisions. DRY RUN by
        default: one READ ONLY transaction, counts only (rows matched/scanned, secrets by
        kind), zero rows written. --real (as zeusi_ingest, DIRECT endpoint, ingest locks
        held) rewrites matched notes and chunks with [REDACTED:<kind>] in place, clears the
        embedding of every changed chunk, then (unless --skip-embed, and only with
        ${OPENAI_KEY_ENV} set) prints the embed cost estimate and re-embeds through the
        existing embed path under the same $5 cap. Facts / decisions are insert-only for the
        ingest role: listed by id for the owner. Neon main is refused unless
        ${MAIN_ENDPOINT_ENV} proves the service is a branch, or ${I_KNOW_MAIN_FLAG} is passed.
        Idempotent. Never prints text, titles or the matched characters.
  wall report [--since-days <n>]
        Quarantined items by uri, rule id and hash. No content.
  wall audit
        Content rows that match a hard rule (or a content rule without a pinned
        allow), and quarantined (uri, sha) present in content. Exit 1 if any.

Hosted MCP token admin (offline: no database, no network; docs/hosting.md). Tokens file:
--file, else ${TOKENS_PATH_ENV}, else ${DEFAULT_TOKENS_PATH} (file 0600, dir 0700, hashes only):
  mcp-token mint --label <assistant> --class read|write --out <file> [--file <f>] [--expires-days <n>]
        Generate one token, append its argon2id hash row, and write the token ONLY to
        --out (created or replaced, mode 0600, never a symlink). The token is never
        printed; stdout shows token_id, label, class, expires_at and the out path.
        --expires-days 1..${MAX_EXPIRES_DAYS} (default ${MAX_EXPIRES_DAYS}).
  mcp-token list [--file <f>]
        token_id, assistant, class, issued_at, expires_at, revoked_at. No hashes.
  mcp-token revoke <token_id> [--file <f>]
        Set revoked_at (kept if already set). The hosted server re-reads the file on change.

Hosted MCP OAuth admin (claude.ai connector sign-ins; offline; docs/hosting.md). Store:
--file, else ${DEFAULT_OAUTH_STORE} (0600, dir 0700, token hashes only):
  mcp-oauth list [--file <f>]
        DCR clients and grants: ids, client, GitHub login, dates. No hashes, no tokens.
  mcp-oauth revoke --grant <grant_id> | --client <client_id> | --all [--file <f>]
        Revoke one grant, one client (and all its grants) or every grant. The hosted
        server re-reads the file on change, so access stops at the next request.

Personal-workspace writer roles (operator; docs/hosting.md "Workspace writes"):
  workspaces backfill-writers [--admin-service <name>] [--real]
        Give every active personal workspace its writer role zt_<id>_w (own schema only) and
        grant it to zeusi_tenant_wr, as zeusi_tenant_admin (default service zeusi_tenant_admin).
        Dry run by default (counts only); --real changes roles. Idempotent. Counts only, no ids.
  workspaces backfill-people [--admin-service <name>] [--real]
        Give every active personal workspace that lacks it its own person (handle "me"), so a
        decision written as "me" is stored as a decision. As zeusi_tenant_admin (the schema
        owner); no new privilege. Dry run by default (active N, missing person M, nothing
        changed); --real creates the missing rows (ready / failed). Idempotent. No ids.
  workspaces encrypt-status --tenant <zt_id> [--admin-service <name>]
        Before encrypting one workspace (operator, no key): its enc_state, wrap counts per
        kind, and per table the rows and non-NULL plain-text values per content column
        (plus quarantine and wall_allow rows). Counts only, never a value. Read-only as
        zeusi_tenant_admin; never writes, not even the catalog. Refuses a malformed id.
  workspaces encrypt-status --all [--expect-no-plain] [--admin-service <name>]
        Every personal workspace, counts only (no id, no title, no value): workspaces per
        enc_state, workspaces with 0 key wraps, digest_column_missing (active prepared workspaces
        without the sealed digest copy column) and digest_missing (sealed rows of active
        workspaces without a copy).
        One short read-only catalog transaction, then one read-only transaction per workspace.
        --expect-no-plain: exit 3 when any workspace is off or enrolled. Not with --tenant.
  workspaces overlay prepare|flip|relax|rollback-start|unflip --tenant <zt_id> [--admin-service <name>]
                     [--real --i-took-a-snapshot]
        The encryption schema overlay of one workspace (C5, docs/plans/2026-11-19-c5-tenant-ddl.md;
        operator, no key, reads no content). prepare: nullable ciphertext / HMAC columns, the
        enc_progress table (state off or enrolled; no state move). flip: verified -> on (refused
        while any plain-text row is left). relax: on -> decrypting. rollback-start: encrypting or
        verified -> decrypting (before a flip). unflip: decrypted -> off (refused while any
        ciphertext is left). relax and rollback-start --real are refused offline until a
        decrypt run exists (C8-0: they would leave the workspace unable to save). Dry run by default (state, counts, would apply / refusal reason);
        --real needs --i-took-a-snapshot (take a Neon snapshot or branch first). One transaction:
        a failure rolls back everything and the state does not move. Counts only, never a value.
  workspaces delete <zt_id> [--admin-service <name>] [--file <oauth store>] [--audit-file <f>]
                    [--apply --confirm <zt_id> --i-took-a-snapshot [--i-know-this-is-main]]
        Remove ONE personal workspace (operator; docs/hosting.md step 8c). Never team or
        zeusi: refused, like any id that is not zt_ + 26 base32, before anything is read. Dry run
        by default: OAuth grants to revoke, its zeusi_tenants rows, schema tables and rows, roles;
        counts and names only, nothing changed. --apply (with --confirm <zt_id>, or the id typed
        at a terminal, and --i-took-a-snapshot; the main-branch guard as for import --real, with
        .env.local loaded) revokes its OAuth grants in the store (--file, default
        ${DEFAULT_OAUTH_STORE}, must exist), then in ONE transaction as zeusi_tenant_admin deletes
        its zeusi_tenants rows and drops its schema and roles zt_<id>_r / zt_<id>_w (rolled back
        if anything outside the schema would go too), then revokes again. Idempotent. Assistant
        tokens are never touched. One audit line on stderr (--audit-file appends it too).

Owner commands (owner only; owner URL from .env.local):
  migrate [--dry-run] [--i-took-a-snapshot]
        Apply migrations/NNNN_*.sql over the DIRECT URL. --i-took-a-snapshot is
        required once the DB already has migrations (take the Neon snapshot first).
  wall allow <uri> <content-sha256> [--rule <id>]
        Pin one exact content hash for one CONTENT rule. Refused for hard rules.
  prove [${I_KNOW_MAIN_FLAG}]
        Full proof with probe rows and cleanup. Refused offline, before connecting,
        unless ${MAIN_ENDPOINT_ENV} is set and the owner URL is a different
        (branch) endpoint, or ${I_KNOW_MAIN_FLAG} is passed.
  embed-smoke [${I_KNOW_MAIN_FLAG}]
        One text-embedding-3-small call; key from Keychain item zeusi-openai-api-key.
        Same main-branch guard as prove.
  people add --handle <h> --display-name <n> --kind ${PERSON_KINDS.join('|')} --org ${PERSON_ORGS.join('|')}
             --scope <scope> --source-uri <uri> --source-ts <iso> --source-text <text>
             --host <label> [--github-login <l>] [--allow-personal] [--dry-run] [${I_KNOW_MAIN_FLAG}]
        Seed one zeusi.people row (zeusi_log_decision refuses an unknown \`who\`) over the
        DIRECT URL, in one transaction with its own ingest_runs row (cli:people-add,
        manual, host = --host, required); source_sha256 = sha256(--source-text). An
        existing handle is reported and left unchanged. Same main-branch guard as prove.
        --scope personal is refused unless --allow-personal is also given: a personal
        person is INVISIBLE to the decision writer (zeusi_read RLS), so zeusi_log_decision
        can never name it as \`who\`. --dry-run validates and prints the row (sha prefix,
        no display name or text) with no connection. Exit 3 when the wall refuses
        (rolled back, nothing written).
  people list
        handle, kind, source_uri of every person (read-only, DIRECT URL). --dry-run and
        list print an http(s) source_uri as https://… (never the URL).
  Owner commands accept ${INSECURE_NO_CB_FLAG} (local debugging only); the
  old ZEUSI_CHANNEL_BINDING=off alone is refused.

Serverless transport (box egress where TCP 5432 does not complete; docs/neon.md):
  ${TRANSPORT_ENV}=serverless node dist/cli.js search "<query>" --limit 3
  ${TRANSPORT_ENV}=serverless node dist/cli.js doctor --service zeusi_ro
        search and doctor only, over wss (port 443), as ${SERVERLESS_ROLES.join(' / ')} only.
        Auth is the role password over verified TLS, not SCRAM-SHA-256-PLUS (the documented
        exception, docs/roles.md). Any other ${TRANSPORT_ENV} value, any other command and
        any other role are refused before connecting. Unset = TCP 5432, unchanged.

Owner URL env names: pooled ${POOLED_URL_NAMES.join(', ')}; direct ${DIRECT_URL_NAMES.join(', ')}
`;

async function withService<T>(name: string, fn: (db: Db) => Promise<T>, connect: (name: string) => Promise<Db> = connectService): Promise<T> {
  const db = await connect(name);
  try {
    return await fn(db);
  } finally {
    await db.close();
  }
}

interface OwnerFlags {
  insecureNoChannelBinding?: boolean;
  /** Commands that write rows: refuse Neon main unless the flag is set. */
  mainGuard?: { iKnowThisIsMain: boolean; warning?: string };
}

/** Owner-only: the ONLY place .env.local (the owner URL) is loaded. */
async function withOwner<T>(kind: 'pooled' | 'direct', fn: (db: Db) => Promise<T>, flags: OwnerFlags = {}): Promise<T> {
  loadEnvFiles();
  if (flags.mainGuard) {
    // Offline, before connecting: throws MainBranchRefused (exit 2).
    const g = mainBranchGuard(resolveUrl(kind, process.env).url, process.env, flags.mainGuard.iKnowThisIsMain);
    if (g.onMain) {
      console.error(`WARNING: ${I_KNOW_MAIN_FLAG}: ${flags.mainGuard.warning ?? 'probe rows will be written to (and deleted from) a target that may be Neon main.'}`);
    }
  }
  const db = await connectOwner(kind, process.env, { insecureNoChannelBinding: flags.insecureNoChannelBinding === true });
  try {
    return await fn(db);
  } finally {
    await db.close();
  }
}

/** C8-0 KTD-C: the overlay steps refused with --real until a decrypt run exists, and the one refusal text. */
const OVERLAY_REAL_REFUSED: readonly string[] = ['relax', 'rollback-start'];
const OVERLAY_REAL_REFUSAL = 'relax / rollback-start would leave the workspace unable to save: no decrypt run exists on this server yet; nothing changed.';

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  // Transport gate first: an invalid value, or serverless for any other command, is refused here.
  assertTransportAllowed(cmd);
  const readOnly = (name: string) => connectReadOnly(name);

  switch (cmd) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(HELP);
      return 0;

    case 'doctor': {
      const { values } = parseArgs({
        args: rest,
        options: { service: { type: 'string' }, roles: { type: 'boolean', default: false }, offline: { type: 'boolean', default: false } },
      });
      if (values.offline) {
        const f = serviceFilePath();
        console.log(`service file: ${existsSync(f) ? 'present' : 'MISSING'} (${f})`);
        console.log(`migrations: ${listMigrations().map((m) => m.name).join(', ')}`);
        return 0;
      }
      if (values.roles) {
        const svc = values.service ?? ROLES_SERVICE;
        return withService(svc, async (db) => {
          await db.exec('BEGIN READ ONLY');
          try {
            const info = await collectDoctor(db, svc);
            console.log(formatDoctor(info));
            const checks = await roleCatalogChecks(db);
            console.log(formatRoleChecks(checks));
            return checks.every((c) => c.ok) ? 0 : 1;
          } finally {
            await db.exec('ROLLBACK');
          }
        }, readOnly);
      }
      const svc = values.service ?? DEFAULT_SERVICE;
      return withService(svc, async (db) => {
        const info = await runDoctor(db, svc);
        console.log(formatDoctor(info));
        return doctorExitOk(info) ? 0 : 1;
      }, readOnly);
    }

    case 'migrate': {
      const { values } = parseArgs({
        args: rest,
        options: {
          'dry-run': { type: 'boolean', default: false },
          'i-took-a-snapshot': { type: 'boolean', default: false },
          'insecure-no-channel-binding': { type: 'boolean', default: false },
        },
      });
      return withOwner('direct', async (db) => {
        console.log(`migrate over ${db.label} (owner)`);
        const r = await migrate(db, { dryRun: values['dry-run'], tookSnapshot: values['i-took-a-snapshot'], log: (l) => console.log(l) });
        console.log(`applied ${r.applied.length}, already applied ${r.alreadyApplied.length}, pending ${r.pending.length - r.applied.length}`);
        return 0;
      }, { insecureNoChannelBinding: values['insecure-no-channel-binding'] });
    }

    case 'fact': {
      const [sub, ...args] = rest;
      if (sub === 'add') {
        const { values } = parseArgs({
          args,
          options: {
            service: { type: 'string' },
            text: { type: 'string' },
            subject: { type: 'string' },
            kind: { type: 'string', default: 'other' },
            scope: { type: 'string', default: 'work' },
            'source-kind': { type: 'string', default: 'manual' },
            'source-uri': { type: 'string' },
            'source-ts': { type: 'string' },
            'source-sha256': { type: 'string' },
          },
        });
        const input = {
          kind: values.kind, subject: values.subject, text: values.text, scope: values.scope,
          sourceKind: values['source-kind'], sourceUri: values['source-uri'], sourceTs: values['source-ts'],
          sourceSha256: values['source-sha256'],
        } as Partial<FactInput>;
        return withService(values.service ?? DEFAULT_SERVICE, async (db) => {
          const r = await insertFact(db, input);
          if (r.status === 'inserted') {
            console.log(`inserted fact ${r.id} (ingest run ${r.runId})`);
            return 0;
          }
          console.log(`QUARANTINED by wall rule ${r.ruleId ?? '?'} (quarantine id ${r.quarantineId}); text not stored`);
          return 3;
        });
      }
      if (sub === 'get') {
        const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { service: { type: 'string' } } });
        const id = Number(positionals[0]);
        if (!Number.isInteger(id) || id <= 0) throw new ValidationError('usage: fact get <id>');
        return withService(values.service ?? DEFAULT_SERVICE, async (db) => {
          const f = await getFact(db, id);
          if (!f) {
            console.log(`fact ${id} not found (or not visible to this role)`);
            return 1;
          }
          console.log(JSON.stringify(f, null, 2));
          return 0;
        });
      }
      throw new ValidationError('usage: fact add ... | fact get <id>');
    }

    case 'vector-probe': {
      const { values } = parseArgs({ args: rest, options: { service: { type: 'string' } } });
      return withService(values.service ?? DEFAULT_SERVICE, async (db) => {
        const idx = await hnswIndexInfo(db);
        console.log(`index chunks_hnsw_te3s: ${idx.exists ? `${idx.method} ${idx.opclass} [${idx.options.join(', ')}] where ${idx.predicate}` : 'MISSING'}`);
        const vec = dummyVector(7);
        const hits = await vectorQuery(db, vec, 5);
        console.log(`dummy-vector query: ${hits.length} row(s)`);
        for (const h of hits) console.log(`  chunk ${h.id} d=${h.distance.toFixed(4)} ${h.source_uri} @ ${new Date(h.source_ts).toISOString()}`);
        const plan = await vectorQueryUsesHnsw(db, vec);
        console.log(`planner uses HNSW index: ${plan.used ? 'yes' : 'no'}`);
        return idx.exists && plan.used ? 0 : 1;
      });
    }

    case 'ingest': {
      const [sub, ...args] = rest;
      const usage = 'usage: ingest vault|hq-sync [--full|--incremental] (--dry-run | --real) [--config <sources.toml>] [--service <name>] [--verbose]';
      if (sub !== 'vault' && sub !== 'hq-sync') throw new ValidationError(usage);
      const profile = sub === 'hq-sync' ? HQ_PROFILE : VAULT_PROFILE;
      if (args.includes('--reparse-frontmatter')) {
        if (sub !== 'vault') throw new ValidationError('--reparse-frontmatter is for ingest vault only');
        const { values: v } = parseArgs({
          args, strict: true, allowPositionals: false,
          options: {
            'reparse-frontmatter': { type: 'boolean', default: false }, real: { type: 'boolean', default: false }, 'dry-run': { type: 'boolean', default: false },
            config: { type: 'string' }, service: { type: 'string' }, scope: { type: 'string' }, 'i-know-this-is-main': { type: 'boolean', default: false },
          },
        });
        if (v.real && v['dry-run']) throw new ValidationError('--dry-run and --real exclude each other');
        if (!v.real && v['i-know-this-is-main']) throw new ValidationError(`${I_KNOW_MAIN_FLAG} applies to --real only (the dry run writes nothing)`);
        const scopes = ['work', 'product', 'client'] as const;
        if (v.scope !== undefined && !(scopes as readonly string[]).includes(v.scope)) throw new ValidationError(`--scope must be one of ${scopes.join('|')}`);
        const cfgPath = v.config ?? 'config/sources.toml';
        if (!existsSync(cfgPath)) throw new ConfigError(`sources config ${cfgPath} not found (template: config/sources.example.toml); pass --config <file>`);
        const config = loadSources(cfgPath);
        const service = v.service ?? DEFAULT_SERVICE;
        // Offline, before any password is read: DIRECT endpoint (session advisory lock), then for --real the main-branch guard.
        const svc = requireDirectEndpoint(service);
        if (v.real) {
          const g = mainBranchGuardForHost(svc.host, process.env, v['i-know-this-is-main']);
          if (g.onMain) console.error(`WARNING: ${I_KNOW_MAIN_FLAG}: notes.frontmatter will be rewritten on a target that may be Neon main.`);
        }
        return withService(service, async (db) => {
          await assertIngestReady(db); // never as the owner; wall migrations applied
          const r = await runReparse({ db, config, real: v.real, ...(v.scope ? { scope: v.scope as (typeof scopes)[number] } : {}) });
          console.log(formatReparse(r));
          if (r.status === 'locked') return 0;
          return r.status === 'ok' && r.write_errors === 0 ? 0 : 1;
        }, (name) => connectDirectService(name));
      }
      const { values } = parseArgs({
        args,
        options: {
          full: { type: 'boolean', default: false },
          incremental: { type: 'boolean', default: false },
          'dry-run': { type: 'boolean', default: false },
          real: { type: 'boolean', default: false },
          config: { type: 'string' },
          service: { type: 'string' },
          verbose: { type: 'boolean', default: false },
        },
      });
      if (values.full && values.incremental) throw new ValidationError('pass either --full or --incremental, not both');
      if (values['dry-run'] && values.real) throw new ValidationError('--dry-run and --real exclude each other');
      if (!values['dry-run'] && !values.real) {
        throw new ValidationError('write mode needs --real (a owner-approved real ingest); use --dry-run for counts only (no connection made).');
      }
      const mode = values.incremental ? 'incremental' : 'full';
      const cfgPath = values.config ?? 'config/sources.toml';
      if (!existsSync(cfgPath)) throw new ConfigError(`sources config ${cfgPath} not found (template: config/sources.example.toml); pass --config <file>`);
      const config = loadSources(cfgPath);
      const hq = sub === 'hq-sync';
      if (values['dry-run']) {
        // hq-sync (Fix PR B): the structured-entry preview reads the admitted notes in memory only.
        const admitted: HqNoteInput[] = [];
        const r = await importVault({
          config, mode, dryRun: true, profile,
          ...(hq ? { dryRunObserve: (o: VaultDryRunObservation) => { const n = hqNoteFromObservation(o); if (n) admitted.push(n); } } : {}),
        });
        console.log(formatVaultResult(r, seedWall().rules, true, profile));
        if (hq && r.status === 'ok') console.log(formatHqStructuredPreview(previewHqStructured(admitted, seedWall())));
        return r.status === 'ok' ? 0 : 1;
      }
      return withService(values.service ?? DEFAULT_SERVICE, async (db) => {
        await assertIngestReady(db);
        const r = await importVault({ db, config, mode, verbose: values.verbose, log: (l) => console.log(l), profile });
        console.log(formatVaultResult(r, (await loadWall(db)).rules, false, profile));
        if (r.status === 'locked') return 0; // another run is in progress: nothing done, not an error
        // hq-sync (Fix PR B): headed decision / memory entries of the admitted notes -> decisions / facts.
        const s = hq && r.status === 'ok' ? await extractHqStructured(db, { mode: r.mode, host: 'testhost' }) : null;
        if (s) {
          console.log(formatHqStructuredResult(s));
          if (s.status === 'ok_partial') console.log('\n*** OWNER: some headed entries were skipped (unknown_person: add the person with zeusi people add; conflict: an entry was edited after it was stored, or entries were reordered; nothing was updated). ***');
        }
        const audit = await wallAudit(db); // must be 0 rows after every run
        console.log(formatAudit(audit));
        const owner = ownerActionLine(audit);
        if (owner) console.log(`\n*** ${owner} ***`);
        // ok_partial (unknown_person / conflict) keeps exit 0: the notes landed and the owner line says what to do.
        return realIngestExitCode(s?.status === 'failed' ? 'failed' : r.status, audit);
      }, (name) => connectDirectService(name)); // r2: direct endpoint only (session advisory lock); pooled is refused offline
    }

    case 'locks': {
      const [sub, ...args] = rest;
      if (sub === 'classify') {
        const cusage = 'usage: locks classify --vault <root> [--json] [--show-text] [--save-preview <file>] | locks classify --vault <root> --real --from <saved preview> [--json]';
        let cv;
        try {
          ({ values: cv } = parseArgs({ args, strict: true, allowPositionals: false, options: {
            vault: { type: 'string' }, json: { type: 'boolean', default: false }, 'show-text': { type: 'boolean', default: false },
            real: { type: 'boolean', default: false }, from: { type: 'string' }, 'save-preview': { type: 'string' },
          } }));
        } catch {
          throw new ValidationError(cusage);
        }
        if (!cv.vault || (cv.real && !cv.from) || (!cv.real && cv.from) || (cv.real && cv['save-preview'])) throw new ValidationError(cusage);
        const home = process.env['HOME'] ?? '~';
        const croot = cv.vault.replace(/^~(?=\/|$)/, home).replace(/\/+$/, '');
        if (/plankiva/i.test(croot)) throw new ValidationError('locks classify: refused (walled path)');
        if (!existsSync(croot)) throw new ValidationError('locks classify: --vault does not exist');
        const cr = classifyVault({ root: croot });
        let applied;
        if (cv.real) {
          // --real writes ONLY when a fresh classification equals the saved dry-run preview (same ids,
          // same file hashes); any difference refuses the whole run and nothing is written.
          let saved: unknown;
          try {
            saved = JSON.parse(readFileSync(cv.from!.replace(/^~(?=\/|$)/, home), 'utf8'));
          } catch {
            throw new ValidationError('locks classify: --from is not a readable saved preview (run the dry run with --save-preview first)');
          }
          const diff = previewDifferences(cr, saved);
          if (diff.length) {
            console.error(`locks classify: REFUSED, nothing written: the vault no longer matches the saved preview (${diff.length} difference(s)); run the dry run again and review it.`);
            for (const d of diff.slice(0, 50)) console.error(`  ${d}`);
            return 1;
          }
          applied = applyStandingMarkers(croot, cr);
        } else if (cv['save-preview']) {
          writeFileSync(cv['save-preview'].replace(/^~(?=\/|$)/, home), `${JSON.stringify(savedPreview(cr), null, 2)}\n`, { flag: 'wx' });
        }
        const { plan: _plan, ...out } = cr;
        const text = cv.json
          ? JSON.stringify({ ...out, items: cv['show-text'] ? out.items : out.items.map(({ text: _t, ...i }) => i), dry_run: !cv.real, ...(applied ? { applied } : {}) }, null, 2)
          : formatClassify(cr, { showText: cv['show-text'], ...(applied ? { real: applied } : {}) });
        // Flushed before returning: main() ends in process.exit, which would cut a large piped stdout.
        await new Promise<void>((resolve) => process.stdout.write(`${text}\n`, () => resolve()));
        return applied && applied.refused.length ? 1 : 0;
      }
      const usage = 'usage: locks lint --vault <root> [--all] [--json] | locks classify --vault <root> [--json] [--show-text] [--real]';
      if (sub !== 'lint') throw new ValidationError(usage);
      let values;
      try {
        ({ values } = parseArgs({ args, strict: true, allowPositionals: false, options: { vault: { type: 'string' }, all: { type: 'boolean', default: false }, json: { type: 'boolean', default: false } } }));
      } catch {
        throw new ValidationError(usage);
      }
      if (!values.vault) throw new ValidationError(usage);
      const root = values.vault.replace(/^~(?=\/|$)/, process.env['HOME'] ?? '~').replace(/\/+$/, '');
      if (/plankiva/i.test(root)) throw new ValidationError('locks lint: refused (walled path)');
      if (!existsSync(root)) throw new ValidationError('locks lint: --vault does not exist');
      const r = lintVault({ root, all: values.all });
      console.log(values.json ? JSON.stringify(r, null, 2) : formatLint(r));
      return 0;
    }

    case 'export-filter': {
      const { values } = parseArgs({
        args: rest,
        options: { in: { type: 'string' }, out: { type: 'string' }, report: { type: 'boolean', default: false }, config: { type: 'string' } },
      });
      if (!values.in || !values.out) throw new ValidationError('usage: export-filter --in <staging dir> --out <source folder> [--report] [--config <sources.toml>]');
      let projects: string[] | undefined;
      let held: string[] | undefined;
      if (values.config !== undefined) {
        let cfg: ReturnType<typeof loadSources>;
        try {
          cfg = loadSources(values.config);
        } catch (err) {
          if (err instanceof ConfigError) throw err;
          // Node's message carries the absolute path: print the code only (m4).
          const code = String((err as { code?: unknown })?.code ?? 'unknown').replace(/[^A-Z0-9_]/g, '');
          throw new ValidationError(`--config could not be read (${code || 'unknown'})`);
        }
        projects = cfg.sources.filter((x) => x.kind === 'zeus_memory' && x.project !== undefined).map((x) => x.project!);
        if (projects.length === 0) throw new ConfigError('no zeus_memory source with a project key in the config');
        held = cfg.hqExport?.held;
      }
      const r = runExportFilter({ inDir: values.in, outDir: values.out, ...(projects ? { projects } : {}), ...(held ? { held } : {}) });
      console.log(formatExportResult(r, values.report));
      return r.status === 'ok' ? 0 : 1;
    }

    case 'import':
    case 'onboard': {
      const usage = `usage: ${cmd} (--markdown <dir> | --decision-log <file> | --claude-export <file> | --chatgpt-export <file> | --git <repo>)... `
        + `--scope ${IMPORT_SCOPES.join('|')}${cmd === 'import' ? ` [--real [--service <name>] [${I_KNOW_MAIN_FLAG}]]` : ''} [--json]`;
      let values;
      try {
        ({ values } = parseArgs({
          args: rest, strict: true, allowPositionals: false,
          options: {
            markdown: { type: 'string', multiple: true }, 'decision-log': { type: 'string', multiple: true },
            'claude-export': { type: 'string', multiple: true }, 'chatgpt-export': { type: 'string', multiple: true },
            git: { type: 'string', multiple: true }, scope: { type: 'string' }, real: { type: 'boolean', default: false },
            service: { type: 'string' }, 'i-know-this-is-main': { type: 'boolean', default: false }, json: { type: 'boolean', default: false },
          },
        }));
      } catch {
        throw new ValidationError(usage);
      }
      // Offline validation first: nothing is read before every flag is valid.
      if (cmd === 'onboard' && (values.real || values.service !== undefined || values['i-know-this-is-main'])) {
        throw new ValidationError('onboard never writes: it previews and prints the import command to run next (drop --real / --service / --i-know-this-is-main).');
      }
      if (!values.real && (values.service !== undefined || values['i-know-this-is-main'])) throw new ValidationError('--service and --i-know-this-is-main only apply with --real');
      if (values.scope === undefined) throw new ValidationError(`--scope is required (${IMPORT_SCOPES.join('|')}); an import lands only in that scope. ${usage}`);
      const scope: ImportScope = assertScope(values.scope);
      const inputs: ImportInput[] = [];
      const flagOf: Record<InputKind, keyof typeof values> = {
        markdown: 'markdown', 'decision-log': 'decision-log', 'claude-export': 'claude-export', 'chatgpt-export': 'chatgpt-export', git: 'git',
      };
      for (const kind of INPUT_KINDS) for (const path of (values[flagOf[kind]] as string[] | undefined) ?? []) inputs.push({ kind, path });
      if (inputs.length === 0) throw new ValidationError(`give at least one input. ${usage}`);
      // Paths are echoed only in the next-command line: refuse control characters (no terminal escapes).
      if (inputs.some((i) => /[\u0000-\u001f\u007f]/.test(i.path))) throw new ImportInputError('import: an input path contains a control character');

      const prepared = await prepareImport({ inputs, scope });
      // M2: Ctrl-C / kill during a run removes the private work dir before exiting.
      const onSignal = (sig: NodeJS.Signals) => {
        prepared.cleanup();
        process.exit(sig === 'SIGINT' ? 130 : 143);
      };
      process.once('SIGINT', onSignal);
      process.once('SIGTERM', onSignal);
      try {
        const p = prepared.preview;
        const quote = (x: string) => (/^[A-Za-z0-9_./:@%+=,-]+$/.test(x) ? x : `'${x.replace(/'/g, `'\\''`)}'`);
        const next = ['zeusi import', ...inputs.map((i) => `--${i.kind} ${quote(i.path)}`), `--scope ${scope}`, '--real'].join(' ');
        const ok = p.error === undefined;
        if (!values.real) {
          if (values.json) console.log(JSON.stringify({ ...previewJson(p), ...(ok ? { next_command: next } : {}) }, null, 2));
          else {
            console.log(formatPreview(p));
            if (ok) {
              if (p.structured.handles_named > 0) {
                console.log(`\nStructured entries name ${p.structured.handles_named} people handle(s). The real run skips (and counts) any handle that is not in zeusi.people yet; add a missing person first with \`zeusi people add --handle <h> ...\` (owner command). People are never created by an import.`);
              }
              console.log(`\nNext, after reviewing the preview (writes as zeusi_ingest; needs ${MAIN_ENDPOINT_ENV} or ${I_KNOW_MAIN_FLAG} for a main-branch target):\n  ${next}`);
            }
          }
          return ok ? 0 : p.filter.status === 'refused' ? 3 : 1;
        }
        // --real: the preview is always printed first.
        console.log(values.json ? JSON.stringify(previewJson(p), null, 2) : formatPreview(p));
        if (!ok) return p.filter.status === 'refused' ? 3 : 1;
        const service = values.service ?? DEFAULT_SERVICE;
        // Offline, before any password is read: direct endpoint only, then the main-branch guard.
        const svc = requireDirectEndpoint(service);
        const g = mainBranchGuardForHost(svc.host, process.env, values['i-know-this-is-main']);
        if (g.onMain) console.error(`WARNING: ${I_KNOW_MAIN_FLAG}: imported rows will be written to a target that may be Neon main.`);
        return await withService(service, async (db) => {
          await assertIngestReady(db);
          const r = await executeImport(prepared, db);
          console.log(values.json ? JSON.stringify({ dry_run: false, ...r }, null, 2) : formatRealResult(r));
          if (r.status === 'locked') return 0; // another import holds the lock: nothing done
          const audit = await wallAudit(db);
          console.log(formatAudit(audit));
          const owner = ownerActionLine(audit);
          if (owner) console.log(`\n*** ${owner} ***`);
          return realIngestExitCode(r.status === 'ok_partial' ? 'ok' : r.status, audit);
        }, (name) => connectDirectService(name));
      } finally {
        process.off('SIGINT', onSignal);
        process.off('SIGTERM', onSignal);
        prepared.cleanup();
      }
    }

    case 'embed': {
      const { values } = parseArgs({
        args: rest,
        options: {
          limit: { type: 'string' },
          'dry-run': { type: 'boolean', default: false },
          real: { type: 'boolean', default: false },
          estimate: { type: 'boolean', default: false },
          'cap-usd': { type: 'string' },
          host: { type: 'string', default: 'mini' },
          service: { type: 'string' },
          config: { type: 'string' },
          'notes-per-day': { type: 'string' },
        },
      });
      if (values.estimate) {
        const cfgPath = values.config ?? (existsSync('config/sources.toml') ? 'config/sources.toml' : 'config/sources.example.toml');
        if (!existsSync(cfgPath)) throw new ConfigError(`sources config ${cfgPath} not found; pass --config <file>`);
        const npd = values['notes-per-day'] === undefined ? undefined : Number(values['notes-per-day']);
        if (npd !== undefined && (!Number.isInteger(npd) || npd < 0)) throw new ValidationError('--notes-per-day must be a non-negative integer');
        const rep = await estimateReport({ config: loadSources(cfgPath), ...(npd !== undefined ? { notesPerDay: npd } : {}) });
        console.log(formatEstimate(rep));
        return 0;
      }
      if (values['dry-run'] && values.real) throw new ValidationError('--dry-run and --real exclude each other');
      if (!values['dry-run'] && !values.real) {
        throw new ValidationError('write mode needs --real (billed OpenAI calls, owner-approved); use --dry-run or --estimate (no API call). No connection made.');
      }
      const capUsd = values['cap-usd'] === undefined ? undefined : effectiveCapUsd(Number(values['cap-usd']));
      const limit = values.limit === undefined ? undefined : Number(values.limit);
      if (limit !== undefined && (!Number.isInteger(limit) || limit <= 0)) throw new ValidationError('--limit must be a positive integer');
      if (!/^[a-z0-9_-]{1,32}$/.test(values.host)) throw new ValidationError('--host must be a short label ([a-z0-9_-], not a hostname)');
      // Never a personal workspace (§7 item 11): a zt_* or workspace-login service is refused before any connection.
      if (workspaceEmbedName(values.service ?? DEFAULT_SERVICE)) throw new EmbedRefused(EMBED_WORKSPACE_REFUSED);
      // Real client BEFORE any connection: refused without the key. Dry run: a client that can never call out.
      const client: EmbeddingsClient = values.real
        ? createOpenAIClient()
        : { model: 'text-embedding-3-small', dims: 1536, kind: 'fake', embed: async () => { throw new EmbedError('dry run: no API call'); } };
      return withService(values.service ?? DEFAULT_SERVICE, async (db) => {
        const r = await runEmbed({
          db, client, host: values.host, dryRun: values['dry-run'], log: (l) => console.log(l),
          ...(limit !== undefined ? { limit } : {}), ...(capUsd !== undefined ? { capUsd } : {}),
        });
        console.log(formatEmbedResult(r, values['dry-run']));
        console.log(`  model: ${EMBED_MODEL_LABEL}`);
        return r.status === 'ok' || r.status === 'locked' ? 0 : 1;
      }, (name) => connectDirectService(name)); // same DIRECT endpoint as ingest (session lock)
    }

    case 'search': {
      const { values, positionals } = parseArgs({
        args: rest, allowPositionals: true,
        options: {
          limit: { type: 'string', default: '10' },
          scope: { type: 'string' },
          hybrid: { type: 'boolean', default: false },
          json: { type: 'boolean', default: false },
          service: { type: 'string' },
        },
      });
      const query = positionals.join(' ').trim();
      if (!query) throw new ValidationError('usage: search "<query>" [--limit n] [--scope s] [--hybrid] [--json]');
      const limit = Number(values.limit);
      if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) throw new ValidationError(`--limit must be 1..${MAX_LIMIT}`);
      if (values.scope !== undefined && !(SEARCH_SCOPES as readonly string[]).includes(values.scope)) {
        throw new ValidationError(`--scope must be one of ${SEARCH_SCOPES.join('|')}`);
      }
      const hasKey = !!process.env[OPENAI_KEY_ENV]?.trim();
      if (!hasKey) console.error(LEXICAL_ONLY_NOTICE);
      const client = hasKey ? createOpenAIClient() : null;
      return withService(values.service ?? SEARCH_SERVICE, async (db) => {
        const r = await search({
          db, query, limit, hybrid: values.hybrid, client, ledger: new QueryLedger(defaultLedgerPath()),
          ...(values.scope !== undefined ? { scope: values.scope } : {}),
        });
        if (!hasKey && !values.json) delete r.notice; // already printed
        console.log(formatSearch(r, { json: values.json }));
        return 0;
      }, readOnly);
    }

    case 'rescrub': {
      const { values } = parseArgs({
        args: rest, strict: true, allowPositionals: false,
        options: {
          real: { type: 'boolean', default: false },
          'i-know-this-is-main': { type: 'boolean', default: false },
          'skip-embed': { type: 'boolean', default: false },
          'cap-usd': { type: 'string' },
          host: { type: 'string', default: 'mini' },
          service: { type: 'string' },
        },
      });
      if (!/^[a-z0-9_-]{1,32}$/.test(values.host)) throw new ValidationError('--host must be a short label ([a-z0-9_-], not a hostname)');
      const service = values.service ?? DEFAULT_SERVICE;
      const capUsd = values['cap-usd'] === undefined ? undefined : effectiveCapUsd(Number(values['cap-usd']));
      let client: EmbeddingsClient | null = null;
      if (values.real) {
        // Offline, before any connection: Neon main is refused unless proven a branch or acknowledged.
        const host = resolveService(service).host;
        const g = mainBranchGuard(`postgresql://u@${host}/x`, process.env, values['i-know-this-is-main']);
        if (g.onMain) console.error(`WARNING: ${I_KNOW_MAIN_FLAG}: matched notes and chunks will be rewritten (redacted in place) on a target that may be Neon main.`);
        if (!values['skip-embed'] && process.env[OPENAI_KEY_ENV]?.trim()) client = createOpenAIClient();
      } else if (values['i-know-this-is-main'] || values['skip-embed'] || values['cap-usd'] !== undefined) {
        throw new ValidationError(`${I_KNOW_MAIN_FLAG}, --skip-embed and --cap-usd apply to --real only (the dry run writes nothing)`);
      }
      return withService(service, async (db) => {
        await assertIngestReady(db); // never as the owner; wall migrations applied
        const r = await runRescrub({ db, real: values.real, host: values.host });
        console.log(formatRescrub(r));
        if (r.status !== 'ok') return r.status === 'locked' ? 0 : 1;
        if (!values.real || r.counts.chunks_flagged_reembed === 0) return r.counts.write_errors > 0 ? 1 : 0;
        const fake: EmbeddingsClient = { model: 'text-embedding-3-small', dims: 1536, kind: 'fake', embed: async () => { throw new EmbedError('dry run: no API call'); } };
        const limit = r.counts.chunks_flagged_reembed;
        const est = await runEmbed({ db, client: fake, host: values.host, dryRun: true, limit, ...(capUsd !== undefined ? { capUsd } : {}) });
        console.log('re-embed cost estimate (no API call):');
        console.log(formatEmbedResult(est, true));
        if (!client) {
          console.log(`re-embed pending: ${limit} chunk(s) have no embedding (lexical search still finds them). Run \`embed --real\` with ${OPENAI_KEY_ENV} set${values['skip-embed'] ? '' : ' (not set now)'}.`);
          return r.counts.write_errors > 0 ? 1 : 0;
        }
        const e = await runEmbed({ db, client, host: values.host, dryRun: false, limit, log: (l) => console.log(l), ...(capUsd !== undefined ? { capUsd } : {}) });
        console.log(formatEmbedResult(e, false));
        console.log(`  model: ${EMBED_MODEL_LABEL}`);
        return e.status === 'ok' && r.counts.write_errors === 0 ? 0 : 1;
      }, (name) => connectDirectService(name)); // DIRECT endpoint: the importer locks are session advisory locks
    }

    case 'wall': {
      const [sub, ...args] = rest;
      if (sub === 'report') {
        const { values } = parseArgs({ args, options: { service: { type: 'string' }, 'since-days': { type: 'string' } } });
        const since = values['since-days'] === undefined ? undefined : Number(values['since-days']);
        if (since !== undefined && (!Number.isInteger(since) || since <= 0)) throw new ValidationError('--since-days must be a positive integer');
        return withService(values.service ?? DEFAULT_SERVICE, async (db) => {
          console.log(formatWallReport(await wallReport(db, since === undefined ? {} : { sinceDays: since })));
          return 0;
        });
      }
      if (sub === 'audit') {
        const { values } = parseArgs({ args, options: { service: { type: 'string' } } });
        return withService(values.service ?? DEFAULT_SERVICE, async (db) => {
          const rows = await wallAudit(db);
          console.log(formatAudit(rows));
          return rows.length === 0 ? 0 : 1;
        });
      }
      if (sub === 'allow') {
        const { values, positionals } = parseArgs({
          args, allowPositionals: true,
          options: { rule: { type: 'string' }, 'insecure-no-channel-binding': { type: 'boolean', default: false } },
        });
        const [uri, sha] = positionals;
        if (!uri || !sha) throw new ValidationError('usage: wall allow <uri> <content-sha256> [--rule <id>]');
        const rule = values.rule === undefined ? undefined : Number(values.rule);
        if (rule !== undefined && !Number.isInteger(rule)) throw new ValidationError('--rule must be an integer rule id');
        // Refuse what can be refused offline BEFORE any owner connection is opened.
        if (!/^[0-9a-f]{64}$/i.test(sha)) throw new ValidationError('content sha256 must be 64 hex characters');
        const offline = seedWall().checkUri(uri);
        if (offline.blocked) {
          throw new WallAdminError(`refused: ${uri} hits hard rule ${offline.ruleId} (${offline.kind}) offline; hard rules cannot be allowed (no connection made)`);
        }
        return withOwner('direct', async (db) => {
          const a = await wallAllow(db, uri, sha, rule);
          console.log(`allowed ${a.sourceUri} content_sha256=${a.contentSha256} for content rule ${a.ruleId}`);
          return 0;
        }, { insecureNoChannelBinding: values['insecure-no-channel-binding'] });
      }
      throw new ValidationError('usage: wall report | wall audit | wall allow <uri> <sha>');
    }

    case 'mcp-token': {
      const [sub, ...args] = rest;
      const usage = 'usage: mcp-token mint --label <l> --class read|write --out <file> [--file <f>] [--expires-days <n>] | mcp-token list [--file <f>] | mcp-token revoke <token_id> [--file <f>]';
      const parse = <P extends boolean>(positionals: P) => {
        try {
          return parseArgs({
            args, allowPositionals: positionals, strict: true,
            options: { file: { type: 'string' }, label: { type: 'string' }, class: { type: 'string' }, out: { type: 'string' }, 'expires-days': { type: 'string' } },
          });
        } catch {
          throw new McpTokenError(usage);
        }
      };
      if (sub === 'mint') {
        const { values } = parse(false);
        const days = values['expires-days'] === undefined ? undefined : Number(values['expires-days']);
        const r = await mintToken({
          file: resolveTokensPath(values.file), out: values.out ?? '', label: values.label, cls: values.class, expiresDays: days,
        });
        // The token itself went to --out only. Never print it.
        console.log(`minted token_id=${r.tokenId} assistant=${r.label} class=${r.cls} expires_at=${r.expiresAt}`);
        console.log(`token written to ${r.out} (mode 0600); move it into the secret store, then delete the file`);
        return 0;
      }
      if (sub === 'list') {
        const { values } = parse(false);
        console.log(formatTokenList(listTokens(resolveTokensPath(values.file))));
        return 0;
      }
      if (sub === 'revoke') {
        const { values, positionals } = parse(true);
        if (positionals.length !== 1) throw new McpTokenError(usage);
        const r = await revokeToken(resolveTokensPath(values.file), positionals[0]);
        console.log(`revoked token_id=${r.tokenId} revoked_at=${r.revokedAt}`);
        return 0;
      }
      throw new McpTokenError(usage);
    }

    case 'mcp-oauth': {
      const [sub, ...args] = rest;
      const usage = 'usage: mcp-oauth list [--file <f>] | mcp-oauth revoke --grant <id> | --client <id> | --all [--file <f>]';
      let values;
      try {
        ({ values } = parseArgs({
          args, allowPositionals: false, strict: true,
          options: { file: { type: 'string' }, grant: { type: 'string' }, client: { type: 'string' }, all: { type: 'boolean', default: false } },
        }));
      } catch {
        throw new ValidationError(usage);
      }
      const store = new OAuthStore({ path: values.file ?? DEFAULT_OAUTH_STORE });
      if (sub === 'list') {
        const l = store.list();
        console.log('clients: client_id  client_name  redirect_uris  created_at');
        for (const c of l.clients) console.log(`  ${c.client_id}  ${c.client_name ?? '-'}  ${c.redirect_uris.join(',')}  ${c.created_at}`);
        console.log('grants: grant_id  client_id  login  created_at  refresh_expires_at');
        for (const g of l.grants) console.log(`  ${g.grant_id}  ${g.client_id}  ${g.login}  ${g.created_at}  ${g.refresh_expires_at}`);
        return 0;
      }
      if (sub === 'revoke') {
        const picked = [values.grant !== undefined, values.client !== undefined, values.all].filter(Boolean).length;
        if (picked !== 1) throw new ValidationError(usage);
        if (values.all) {
          console.log(`revoked ${store.revokeAll()} grant(s)`);
          return 0;
        }
        const ok = values.grant !== undefined ? store.revokeGrant(values.grant) : store.revokeClient(values.client!);
        if (!ok) throw new ValidationError('no live grant or client with that id');
        console.log(values.grant !== undefined ? `revoked grant_id=${values.grant}` : `revoked client_id=${values.client} and its grants`);
        return 0;
      }
      throw new ValidationError(usage);
    }

    case 'workspaces': {
      const [sub, ...args] = rest;
      if (sub === 'overlay') return workspacesOverlay(args);
      if (sub === 'delete') return workspacesDelete(args);
      const usage = 'usage: workspaces backfill-writers|backfill-people [--admin-service <name>] [--real] | workspaces encrypt-status --tenant <id> | --all [--expect-no-plain] [--admin-service <name>]'
        + ' | workspaces delete <zt_id> [--apply --confirm <zt_id> --i-took-a-snapshot]';
      let values;
      try {
        ({ values } = parseArgs({ args, allowPositionals: false, strict: true, options: {
          'admin-service': { type: 'string' }, real: { type: 'boolean', default: false }, tenant: { type: 'string' },
          all: { type: 'boolean', default: false }, 'expect-no-plain': { type: 'boolean', default: false } } }));
      } catch {
        throw new ValidationError(usage);
      }
      if (sub !== 'backfill-writers' && sub !== 'backfill-people' && sub !== 'encrypt-status') throw new ValidationError(usage);
      // encrypt-status (C3): one workspace, counts only, never writes; the id is checked before any connection.
      if (sub === 'encrypt-status') {
        if (values.real) throw new ValidationError('workspaces encrypt-status is a dry run only (no --real)');
        // C8-0 KTD-B: --all and --tenant are exclusive; --expect-no-plain only with --all. All before any connection.
        if (values.all && values.tenant !== undefined) throw new ValidationError('workspaces encrypt-status: --all and --tenant are exclusive');
        if (values['expect-no-plain'] && !values.all) throw new ValidationError('workspaces encrypt-status: --expect-no-plain goes with --all');
        if (!values.all) {
          if (values.tenant === undefined) throw new ValidationError(usage);
          if (!TENANT_ID_RE.test(values.tenant)) throw new ValidationError('--tenant: not a workspace id (zt_ + 26 base32)');
        }
      } else if (values.tenant !== undefined || values.all || values['expect-no-plain']) {
        throw new ValidationError(usage);
      }
      const service = values['admin-service'] ?? TENANT_ADMIN_ROLE;
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(service)) throw new ValidationError('--admin-service: letters, digits, _ and - only');
      if (resolveService(service).user !== TENANT_ADMIN_ROLE) throw new ValidationError(`--admin-service must log in as ${TENANT_ADMIN_ROLE}`);
      const dir = new TenantDirectory({ connectAdmin: () => connectService(service) });
      if (sub === 'encrypt-status' && values.all) {
        try {
          return await runEncryptStatusAll(dir, { expectNoPlain: values['expect-no-plain'] }, (line) => console.log(line));
        } catch (e) {
          if (e instanceof EncryptStatusRefused) {
            console.error(`workspaces encrypt-status: ${e.message}`);
            return 1;
          }
          throw e;
        }
      }
      if (sub === 'encrypt-status') {
        let st;
        try {
          st = await encryptStatus(dir, values.tenant!);
        } catch (e) {
          if (e instanceof EncryptStatusRefused) {
            console.error(`workspaces encrypt-status: ${e.message}`);
            return 1;
          }
          throw e;
        }
        for (const line of formatEncryptStatus(st)) console.log(line);
        return 0;
      }
      if (sub === 'backfill-people') {
        const p = await dir.backfillPeople({ dryRun: !values.real });
        console.log(`workspaces backfill-people (${values.real ? 'real' : 'dry run, nothing changed'}): active ${p.active}, missing person ${p.missing_person}`
          + (values.real ? `, ready ${p.ready}, failed ${p.failed}` : ''));
        return p.failed > 0 ? 1 : 0;
      }
      const r = await dir.backfillWriters({ dryRun: !values.real });
      console.log(`workspaces backfill-writers (${values.real ? 'real' : 'dry run, nothing changed'}): active ${r.active}, missing writer role ${r.missing_role}`
        + (values.real ? `, ready ${r.ready}, role ready but no ${TENANT_WR_ROLE} login yet ${r.no_login}, failed ${r.failed}` : ''));
      return r.failed > 0 ? 1 : 0;
    }

    case 'people': {
      const [sub, ...args] = rest;
      const usage = 'usage: people add --handle <h> --display-name <n> --kind human|agent|bot --org work|vendor --scope <scope> '
        + '--source-uri <uri> --source-ts <iso> --source-text <text> --host <label> [--github-login <l>] [--allow-personal] [--dry-run] [--i-know-this-is-main] | people list';
      const parse = () => {
        try {
          return parseArgs({
            args, strict: true, allowPositionals: false,
            options: {
              handle: { type: 'string' }, 'display-name': { type: 'string' }, kind: { type: 'string' }, org: { type: 'string' },
              scope: { type: 'string' }, 'source-uri': { type: 'string' }, 'source-ts': { type: 'string' }, 'source-text': { type: 'string' },
              'github-login': { type: 'string' }, host: { type: 'string' },
              'allow-personal': { type: 'boolean', default: false },
              'dry-run': { type: 'boolean', default: false },
              'i-know-this-is-main': { type: 'boolean', default: false },
              'insecure-no-channel-binding': { type: 'boolean', default: false },
            },
          });
        } catch {
          throw new ValidationError(usage);
        }
      };
      if (sub === 'add') {
        const { values } = parse();
        // Offline first: every refusal here happens before .env.local is read or a connection opened.
        const person = validatePerson({
          handle: values.handle, displayName: values['display-name'], kind: values.kind, org: values.org, scope: values.scope,
          sourceUri: values['source-uri'], sourceTs: values['source-ts'], sourceText: values['source-text'],
          githubLogin: values['github-login'], host: values.host, allowPersonal: values['allow-personal'],
        });
        if (values['dry-run']) {
          console.log(formatPlan(person));
          return 0;
        }
        return withOwner('direct', async (db) => {
          const r = await addPerson(db, person);
          if (r.status === 'exists') {
            console.log(`exists: ${person.handle} (id ${r.id}); nothing changed`);
            return 0;
          }
          console.log(`inserted person ${person.handle} (id ${r.id}, ingest run ${r.runId}, source_sha256 ${r.sha256.slice(0, 12)}...)`);
          return 0;
        }, {
          insecureNoChannelBinding: values['insecure-no-channel-binding'],
          mainGuard: { iKnowThisIsMain: values['i-know-this-is-main'], warning: 'one zeusi.people row and its ingest_runs row will be written to a target that may be Neon main.' },
        });
      }
      if (sub === 'list') {
        const { values } = parse();
        return withOwner('direct', async (db) => {
          console.log(formatPeopleList(await listPeople(db)));
          return 0;
        }, { insecureNoChannelBinding: values['insecure-no-channel-binding'] });
      }
      throw new ValidationError(usage);
    }

    case 'prove':
    case 'embed-smoke': {
      const { values } = parseArgs({
        args: rest,
        options: {
          'i-know-this-is-main': { type: 'boolean', default: false },
          'insecure-no-channel-binding': { type: 'boolean', default: false },
        },
      });
      const flags: OwnerFlags = {
        insecureNoChannelBinding: values['insecure-no-channel-binding'],
        mainGuard: { iKnowThisIsMain: values['i-know-this-is-main'] },
      };
      if (cmd === 'prove') {
        return withOwner('pooled', async (db) => {
          const r = await prove(db);
          console.log(formatReport(r, db.label));
          return r.ok ? 0 : 1;
        }, flags);
      }
      return withOwner('pooled', async (db) => {
        const r = await embedSmoke(db);
        console.log(r.lines.join('\n'));
        return r.ok ? 0 : 1;
      }, flags);
    }

    default:
      process.stderr.write(`unknown command: ${cmd}\n\n${HELP}`);
      return 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e: unknown) => {
    // export-filter: an unsafe --in/--out tree (overlap, a symlink or non-directory below --out).
    if (e instanceof ExportFilterUnsafeError) {
      console.error(`error: ${e.message}`);
      process.exit(4);
    }
    // export-filter: a filesystem error (code only, no path); not an output-gate refusal.
    if (e instanceof ExportFilterIoError) {
      console.error(`error: ${e.message}`);
      process.exit(3);
    }
    // people add: the wall trigger refused the row (rolled back; rule id only, never the value).
    if (e instanceof PeopleRefused) {
      console.error(`error: ${e.message}`);
      process.exit(3);
    }
    if (e instanceof ConfigError || e instanceof ValidationError || e instanceof KeychainError
        || e instanceof ConnectError || e instanceof WallAdminError || e instanceof WallRuleError
        || e instanceof IngestNotReady || e instanceof VaultRunError || e instanceof ExportFilterError
        || e instanceof EmbedError || e instanceof EmbedRefused || e instanceof SearchRefused
        || e instanceof McpTokenError || e instanceof TokenFileError || e instanceof OAuthStoreError || e instanceof RescrubRefused
        || e instanceof ImportInputError) {
      console.error(`error: ${e.message}`);
      process.exit(2);
    }
    // Print code + message only. pg errors carry no credentials; never print the error object or config.
    const pe = asPgError(e);
    console.error(`error${pe.code ? ` [${pe.code}]` : ''}: ${pe.message}`);
    process.exit(1);
  },
);

/** `zeusi workspaces overlay <step> --tenant <id> ...` (C5 KTD14). Every refusal before a connection is offline. */
async function workspacesOverlay(args: string[]): Promise<number> {
  const usage = `usage: workspaces overlay ${OVERLAY_STEPS.join('|')} --tenant <zt_id> [--admin-service <name>] [--real --i-took-a-snapshot]`;
  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({ args, allowPositionals: true, strict: true, options: {
      'admin-service': { type: 'string' }, tenant: { type: 'string' }, real: { type: 'boolean', default: false },
      'i-took-a-snapshot': { type: 'boolean', default: false } } }));
  } catch {
    throw new ValidationError(usage);
  }
  const step = positionals[0];
  if (positionals.length !== 1 || !(OVERLAY_STEPS as readonly string[]).includes(step!)) throw new ValidationError(usage);
  if (values.tenant === undefined) throw new ValidationError(usage);
  if (!TENANT_ID_RE.test(values.tenant)) throw new ValidationError('--tenant: not a workspace id (zt_ + 26 base32)');
  // C8-0 U3 (docs/plans/2026-11-21-c8-refresh.md KTD-C): no code moves a workspace out of `decrypting` yet, so a real
  // relax / rollback-start would leave it readable but unable to save, for good. Refused offline, before any
  // connection; the dry runs still report. C8b removes this together with the decrypt move (one-rule).
  if (values.real && OVERLAY_REAL_REFUSED.includes(step!)) {
    console.error(`workspaces overlay ${step}: ${OVERLAY_REAL_REFUSAL}`);
    return 1;
  }
  if (values.real && !values['i-took-a-snapshot']) {
    throw new ValidationError('workspaces overlay --real needs --i-took-a-snapshot: take a Neon snapshot or branch of this database first');
  }
  if (!values.real && values['i-took-a-snapshot']) throw new ValidationError('--i-took-a-snapshot goes with --real');
  const service = values['admin-service'] ?? TENANT_ADMIN_ROLE;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(service)) throw new ValidationError('--admin-service: letters, digits, _ and - only');
  if (resolveService(service).user !== TENANT_ADMIN_ROLE) throw new ValidationError(`--admin-service must log in as ${TENANT_ADMIN_ROLE}`);
  const dir = new TenantDirectory({ connectAdmin: () => connectService(service) });
  try {
    const r = await dir.overlayStep(values.tenant, step as OverlayStep, { dryRun: !values.real });
    for (const line of formatOverlayStep(values.tenant, r)) console.log(line);
    return r.outcome === 'refused' ? 1 : 0;
  } catch (e) {
    if (e instanceof TenantError || e instanceof TenantRefused) {
      console.error(`workspaces overlay ${step}: ${e.message}`);
      return 1;
    }
    throw e;
  }
}

/**
 * `zeusi workspaces delete <zt_id> ...` (docs/plans/2026-11-20-workspaces-delete.md U5). Strict parsing here (a usage
 * error exits 2 with no audit line); every rule, gate and the order of work lives in src/workspace-delete.ts. The
 * preflight runs only after the offline gates: .env.local (for ZEUSI_MAIN_ENDPOINT_ID; the owner URL in it is never
 * read), the admin service (the provisioner, on a direct host), and the main-branch guard for --apply.
 */
async function workspacesDelete(args: string[]): Promise<number> {
  const usage = 'usage: workspaces delete <zt_id> [--admin-service <name>] [--file <oauth store>] [--audit-file <f>] '
    + '[--apply --confirm <zt_id> --i-took-a-snapshot [--i-know-this-is-main]]';
  let values;
  let positionals;
  try {
    ({ values, positionals } = parseArgs({ args, allowPositionals: true, strict: true, options: {
      'admin-service': { type: 'string' }, file: { type: 'string' }, 'audit-file': { type: 'string' },
      apply: { type: 'boolean', default: false }, confirm: { type: 'string' },
      'i-took-a-snapshot': { type: 'boolean', default: false }, 'i-know-this-is-main': { type: 'boolean', default: false } } }));
  } catch {
    throw new ValidationError(usage);
  }
  if (positionals.length !== 1) throw new ValidationError(usage);
  const adminService = values['admin-service'];
  return runWorkspaceDelete({
    tenantId: positionals[0]!, apply: values.apply, confirm: values.confirm, iTookASnapshot: values['i-took-a-snapshot'],
    iKnowThisIsMain: values['i-know-this-is-main'], storePath: values.file ?? DEFAULT_OAUTH_STORE,
  }, {
    preflight: (o) => deletePreflight(adminService, o),
    interactive: process.stdin.isTTY === true,
    ask: askLine,
    // OAuthStore's own notion of missing (stat fails, a dangling symlink too): it reads that as an EMPTY store (KTD10).
    // Anything that exists goes to OAuthStore, which refuses a symlink or a non-regular file with its own reason.
    storeExists: (p) => {
      try {
        statSync(p);
        return true;
      } catch {
        return false;
      }
    },
    openStore: (p) => new OAuthStore({ path: p }),
    audit: wsAuditSink({ file: values['audit-file'] }),
    out: (line) => console.log(line),
    err: (line) => console.error(line),
  });
}

/** The delete's offline preflight (KTD9). Config refusals carry no host, URL or password: they are printed as they are. */
function deletePreflight(adminService: string | undefined, o: { apply: boolean; iKnowThisIsMain: boolean }) {
  const service = adminService ?? TENANT_ADMIN_ROLE;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(service)) throw new WorkspaceDeleteRefused('--admin-service: letters, digits, _ and - only');
  try {
    loadEnvFiles();
    // The provisioner session holds its transaction on one server connection: the direct endpoint, never the pooler.
    const svc = requireDirectEndpoint(service);
    if (svc.user !== TENANT_ADMIN_ROLE) throw new WorkspaceDeleteRefused(`--admin-service must log in as ${TENANT_ADMIN_ROLE}`);
    const warnings: string[] = [];
    if (o.apply) {
      const g = mainBranchGuardForHost(svc.host, process.env, o.iKnowThisIsMain);
      if (g.onMain) warnings.push(`WARNING: ${I_KNOW_MAIN_FLAG}: this workspace will be deleted from a target that may be Neon main.`);
    }
    return { directory: new TenantDirectory({ connectAdmin: () => connectService(service) }), warnings };
  } catch (e) {
    if (e instanceof ConfigError) throw new WorkspaceDeleteRefused(e.message);
    throw e;
  }
}

/** One line from the terminal (stdin is a TTY): the answer without its line terminator, or null at end of input. */
async function askLine(question: string): Promise<string | null> {
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  try {
    return await new Promise<string | null>((resolve) => {
      rl.once('close', () => resolve(null));
      // Ctrl-C at the prompt is no answer (refused, audited), not a silent exit.
      rl.once('SIGINT', () => rl.close());
      rl.question(question, (answer) => resolve(answer));
    });
  } finally {
    rl.close();
  }
}
