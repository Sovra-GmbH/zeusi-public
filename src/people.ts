// `zeusi people add|list` (owner): seed zeusi.people so zeusi_log_decision can name a `who`.
// invent=NO: every column comes from a flag, including the ingest_runs host (--host is required;
// nothing is derived from the machine name).
//
// Scope `personal` needs --allow-personal as well: zeusi_read RLS hides personal rows, so the
// decision writer (zeusi_box_decision / zeusi_box_rw, both read through zeusi_read) cannot see
// such a person, and zeusi_log_decision would refuse it as an unknown `who`.
//
// Output: --dry-run and `people list` never echo an http(s) URL. An http:// or https:// source_uri
// is printed as `https://…` (scheme only, see displayUri); other schemes (manual:, zeusi:, hq:,
// chat:) are printed as stored. The stored value is never changed.
//
// add runs in ONE transaction: an ingest_runs row (importer cli:people-add, mode manual,
// status ok, finished_at now(), counts {inserted:1}) and the people row (source_kind manual,
// source_sha256 = sha256(source text)). An existing handle is reported and left unchanged (no
// update, no upsert). The wall trigger zeusi_90_wall on people is the backstop: a ZW001
// refusal rolls the whole transaction back (no run row, no person) and is surfaced as
// PeopleRefused with the rule id only, never the refused value.

import { createHash } from 'node:crypto';
import type { Db } from './db.ts';
import { WHO_HANDLE_RE } from './decisions.ts';
import { parseWallError, SCOPES, ValidationError, type Scope } from './facts.ts';

export const PEOPLE_IMPORTER = 'cli:people-add';
/** The same pattern zeusi_log_decision uses for `who`. */
export const HANDLE_RE = WHO_HANDLE_RE;
export const PERSON_KINDS = ['human', 'agent', 'bot'] as const;
export const PERSON_ORGS = ['work', 'vendor'] as const;
const GITHUB_LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const HOST_LABEL_RE = /^[a-z0-9_-]{1,32}$/;
/** ISO 8601 with a date, a time and an explicit zone (Z or +hh:mm), so the instant is unambiguous. */
const ISO_TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})$/;

export interface PersonInput {
  handle: string;
  displayName: string;
  kind: (typeof PERSON_KINDS)[number];
  org: (typeof PERSON_ORGS)[number];
  scope: Scope;
  sourceUri: string;
  sourceTs: string;
  sourceText: string;
  githubLogin?: string | undefined;
  /** ingest_runs.host label (--host, required). */
  host: string;
}

export interface RawPersonFlags {
  handle?: string | undefined;
  displayName?: string | undefined;
  kind?: string | undefined;
  org?: string | undefined;
  scope?: string | undefined;
  sourceUri?: string | undefined;
  sourceTs?: string | undefined;
  sourceText?: string | undefined;
  githubLogin?: string | undefined;
  host?: string | undefined;
  /** Required together with scope personal (that person is invisible to the decision writer). */
  allowPersonal?: boolean | undefined;
}

export class PeopleRefused extends Error {
  override name = 'PeopleRefused';
  readonly ruleId: number | null;
  constructor(message: string, ruleId: number | null) {
    super(message);
    this.ruleId = ruleId;
  }
}

const blank = (v: string | undefined) => typeof v !== 'string' || v.trim() === '';

/** Offline validation (no connection). Throws ValidationError naming the flag, never echoing free text. */
export function validatePerson(f: RawPersonFlags): PersonInput {
  const missing: string[] = [];
  const req: Array<[Exclude<keyof RawPersonFlags, 'allowPersonal' | 'githubLogin'>, string]> = [
    ['handle', '--handle'], ['displayName', '--display-name'], ['kind', '--kind'], ['org', '--org'], ['scope', '--scope'],
    ['sourceUri', '--source-uri'], ['sourceTs', '--source-ts'], ['sourceText', '--source-text'], ['host', '--host'],
  ];
  for (const [k, flag] of req) if (blank(f[k])) missing.push(flag);
  if (missing.length) throw new ValidationError(`missing or empty: ${missing.join(', ')} (invent=NO); nothing written`);
  if (!HANDLE_RE.test(f.handle!)) throw new ValidationError('--handle must match ^[a-z0-9][a-z0-9_.-]{0,63}$ (the decision tool\'s `who` pattern); nothing written');
  if (!(PERSON_KINDS as readonly string[]).includes(f.kind!)) throw new ValidationError(`--kind must be ${PERSON_KINDS.join('|')}`);
  if (!(PERSON_ORGS as readonly string[]).includes(f.org!)) throw new ValidationError(`--org must be ${PERSON_ORGS.join('|')}`);
  // No default scope. `personal` only with --allow-personal: zeusi_read RLS hides that person from
  // the decision writer, so zeusi_log_decision could never name it as `who`.
  if (!(SCOPES as readonly string[]).includes(f.scope!)) throw new ValidationError(`--scope must be ${SCOPES.join('|')} (no default)`);
  if (f.scope === 'personal' && f.allowPersonal !== true) {
    throw new ValidationError('--scope personal needs --allow-personal: a personal-scope person is invisible to the decision writer (zeusi_read RLS), so zeusi_log_decision cannot use it as `who`; nothing written');
  }
  if (f.displayName!.length > 200) throw new ValidationError('--display-name is longer than 200 characters');
  if (!ISO_TS_RE.test(f.sourceTs!) || Number.isNaN(Date.parse(f.sourceTs!))) {
    throw new ValidationError('--source-ts must be ISO 8601 with a zone, e.g. 2026-11-17T03:13:00+01:00');
  }
  if (f.githubLogin !== undefined && !GITHUB_LOGIN_RE.test(f.githubLogin)) throw new ValidationError('--github-login is not a GitHub login');
  // --host is required (no os.hostname() default, invent=NO) and must be a short label.
  const host = f.host!;
  if (!HOST_LABEL_RE.test(host)) throw new ValidationError('--host must be a short label ([a-z0-9_-], not a hostname)');
  return {
    handle: f.handle!, displayName: f.displayName!, kind: f.kind as PersonInput['kind'], org: f.org as PersonInput['org'],
    scope: f.scope as Scope, sourceUri: f.sourceUri!, sourceTs: f.sourceTs!, sourceText: f.sourceText!,
    githubLogin: f.githubLogin, host,
  };
}

/** sha256 (hex) of the source text, the bytes the operator cites as the source of this row. */
export function sourceSha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** A source_uri safe to print: an http(s) URL becomes `<scheme>://…`; any other value is unchanged. */
export function displayUri(uri: string): string {
  const m = /^\s*(https?):\/\//i.exec(uri);
  return m ? `${m[1]!.toLowerCase()}://…` : uri;
}

/** The --dry-run summary: no display name, no source text, a sha prefix only, no http(s) URL. */
export function formatPlan(p: PersonInput): string {
  return [
    'dry run: would insert into zeusi.people (nothing written, no connection made)',
    `  handle=${p.handle} kind=${p.kind} org=${p.org} scope=${p.scope}`,
    `  source_uri=${displayUri(p.sourceUri)} source_sha256=${sourceSha256(p.sourceText).slice(0, 12)}...`,
    `  ingest run: importer=${PEOPLE_IMPORTER} mode=manual status=ok counts={"inserted":1}`,
  ].join('\n');
}

export type AddPersonResult =
  | { status: 'inserted'; id: number; runId: number; sha256: string }
  | { status: 'exists'; id: number };

async function rollback(db: Db): Promise<void> {
  await db.exec('ROLLBACK').catch(() => {});
}

export async function addPerson(db: Db, p: PersonInput): Promise<AddPersonResult> {
  const sha = sourceSha256(p.sourceText);
  await db.exec('BEGIN');
  try {
    const existing = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.people WHERE handle = $1`, [p.handle])).rows[0];
    if (existing) {
      await db.exec('ROLLBACK');
      return { status: 'exists', id: Number(existing.id) };
    }
    const runId = Number((await db.query<{ id: number }>(
      `INSERT INTO zeusi.ingest_runs (importer, host, mode, status, finished_at, counts)
       VALUES ($1, $2, 'manual', 'ok', now(), $3::jsonb) RETURNING id::int AS id`,
      [PEOPLE_IMPORTER, p.host, JSON.stringify({ inserted: 1 })],
    )).rows[0]!.id);
    const id = Number((await db.query<{ id: number }>(
      `INSERT INTO zeusi.people (handle, display_name, kind, org, github_login, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
       VALUES ($1, $2, $3, $4, $5, $6::zeusi.scope, 'manual', $7, $8::timestamptz, decode($9, 'hex'), $10)
       RETURNING id::int AS id`,
      [p.handle, p.displayName, p.kind, p.org, p.githubLogin ?? null, p.scope, p.sourceUri, p.sourceTs, sha, runId],
    )).rows[0]!.id);
    await db.exec('COMMIT');
    return { status: 'inserted', id, runId, sha256: sha };
  } catch (e) {
    await rollback(db);
    const wall = parseWallError(e);
    if (wall) {
      throw new PeopleRefused(
        `refused by the wall (rule ${wall.ruleId ?? '?'}${wall.hard ? ', hard' : ''}); transaction rolled back, nothing written (no person, no ingest run)`,
        wall.ruleId,
      );
    }
    throw e;
  }
}

export interface ListedPerson {
  handle: string;
  kind: string;
  source_uri: string;
}

/** handle, kind, source_uri only (formatPeopleList redacts http(s) source_uris). */
export async function listPeople(db: Db): Promise<ListedPerson[]> {
  return (await db.query<ListedPerson>(`SELECT handle, kind, source_uri FROM zeusi.people ORDER BY handle`)).rows;
}

export function formatPeopleList(rows: readonly ListedPerson[]): string {
  return ['handle  kind  source_uri', ...rows.map((r) => `${r.handle}  ${r.kind}  ${displayUri(r.source_uri)}`), `${rows.length} person(s)`].join('\n');
}
