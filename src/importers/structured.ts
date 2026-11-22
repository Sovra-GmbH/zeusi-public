// Structured entries: the ONE parser and writer for explicitly headed decision / memory entries
// (lanes DIG-startup-links.md D1 "explicit structure, then insert"; PR2 amendment P1). Used by
// `zeusi import` (src/import-run.ts, uris import:...) and by `ingest hq-sync`
// (src/importers/hq-structured.ts, uris hq:..., Fix PR B): one grammar, one writer, no second copy.
//
// invent=NO: a row is produced only from an entry that states every required field itself.
// Nothing is classified from free text; no who, timestamp, kind, focus or subject is guessed.
//
// Entry shape (one H2 section of a note, as split by splitEntries in src/hq-export.ts):
//
//   ## 2026-11-16T20:27:00+01:00 owner          <- H2: an ISO timestamp with offset, then ONE handle
//   Decision: go                               <- header block: "Key: value" lines, no blank line
//   Said-at-precision: minute                     inside; ends at the first blank line
//   Verbatim: no
//   Applies-to: zeusi, oss
//   Links: gh:example-org/zeusi#11, vault:Work/x.md
//   Expires: 2026-12-01T00:00:00Z               (ISO -> expires_at; other text -> expires_rule)
//
//   <entry text, verbatim>                      <- exact_words (decision) / text (fact)
//
// Links (0013): every item of `Links:` that is on the decision_links allowlist (src/decision-links.ts
// linkTargetKind: gh:<owner>/<repo>#<n>, gh:<owner>/<repo>, vault:, hq:, import:, job:, lane:) is
// carried as `links` (<= MAX_LINKS, in order, duplicates dropped; other items are ignored, as before).
// The first PR link still fills linked_repo / linked_pr. `links` is NOT part of recordSha256, so a
// record parsed before 0013 keeps its sha (no false conflict). On a real run the links of an inserted
// OR already stored (deduped) decision are inserted into zeusi.decision_links when 0013 is applied
// (ON CONFLICT DO NOTHING; never UPDATE / DELETE: a link removed from the header stays), else
// counted links_skipped.
//
// Memory deltas: `Type: rule|focus` + `Subject: <key>` (+ the same H2) become facts kind rule /
// state. `Type: retire` is not supported (zeusi_ingest cannot supersede facts) and is counted invalid.
//
// Required: decision -> Decision + Said-at-precision; fact -> Type + Subject. Verbatim defaults to
// "no" (never claims a quote). An entry whose FIRST line after the H2 is not a known header key is
// "unstructured" (it stays a note only). An entry with a header block that is incomplete, has an
// unknown key, a bad value or mixes decision and fact keys is "invalid" (also a note only).
//
// Writing (real runs only): `who` must already exist in zeusi.people (else skipped, counted
// unknown_person; people are never created). Dedupe on (source_uri, source_sha256): the same entry
// again is "deduped"; the same source_uri with a DIFFERENT sha (an edited entry) is a "conflict" and
// is refused (no UPDATE, no second current row). The wall pre-check and the zeusi_90_wall trigger
// quarantine by uri and hash only. Counts only leave this module, never text.
//
// Secrets (#23, the ONE shared detector src/secrets.ts, no copy here): a headed entry whose lines
// trip the serve-time secret check (src/mcp-wall.ts serveSecretSignal: the shared detector and its
// withhold floor, origin/main's patterns, or a [REDACTED: marker the importer left in a stored
// body) never becomes a record: it is counted `secret` and stays a note only, where the importer
// redacts it before insert like every other note. The export filter withholds such an entry
// upstream already; this is the same verdict at the record level, so a record is never stored raw
// and never stored in a shape the serve guard would withhold. writeStructured checks each record
// again (defence in depth) and counts `secret_withheld`; no quarantine row (no hash of a
// secret-bearing text is ever recorded).

import { createHash } from 'node:crypto';
import { asPgError, type Db } from '../db.ts';
import { DECISION_KINDS, WHO_HANDLE_RE } from '../decisions.ts';
import { canInsertLinks, insertDecisionLinks, linkTargetKind, MAX_LINKS } from '../decision-links.ts';
import { PLAIN_ROUTE, sealedTx, type SealedRoute, type WriteRoute } from '../write-route.ts';
import { nextId, sealedInsertSql, sealRow, type SqlCol } from '../workspace-seal.ts';
import { parseWallError } from '../facts.ts';
import { splitEntries } from '../hq-export.ts';
import { serveSecretSignal } from '../mcp-wall.ts';
import { recordQuarantine, type Wall } from '../wall.ts';

/** `## <ISO timestamp with offset> <handle>` and nothing else on the line. */
export const STRUCTURED_H2_RE =
  /^ {0,3}##[ \t]+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2}))[ \t]+([a-z0-9][a-z0-9_.-]{0,63})[ \t]*\r?$/;

export const HEADER_KEYS = ['decision', 'said-at-precision', 'verbatim', 'applies-to', 'links', 'expires', 'type', 'subject'] as const;
type HeaderKey = (typeof HEADER_KEYS)[number];
const HEADER_LINE_RE = /^([A-Za-z][A-Za-z-]{0,31}):[ \t]*(.*?)[ \t]*\r?$/;
/** gh:<owner>/<repo>#<n>: the only link form that fills linked_repo / linked_pr. */
export const GH_LINK_RE = /^gh:([A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100})#([1-9]\d{0,8})$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})$/;

export const MAX_STRUCTURED_TEXT = 4000;
export const MAX_APPLIES_TO = 20;
export const MAX_APPLIES_TO_ITEM = 200;
export const MAX_SUBJECT = 200;
export const MAX_EXPIRES_RULE = 200;
/**
 * Security review (Fix PR B, M1): an H2 timestamp more than this far in the future is invalid.
 * Startup orders focus and decisions newest first and ingest cannot supersede, so a far-future
 * date would pin a record on top for good. 36 h covers time zones and clock skew.
 */
export const MAX_FUTURE_SKEW_MS = 36 * 3600 * 1000;

export interface DecisionRecord {
  type: 'decision';
  who: string;
  /** ISO timestamp as written in the H2 (normalised with toISOString). */
  saidAt: string;
  /**
   * 1, 2, ... for the 2nd, 3rd, ... record of a note body with the same (type, who, said_at,
   * subject) key (security review M2: two decisions in the same minute, or on the same day with
   * day precision). Absent for the first one, so its uri and sha stay as before.
   */
  ordinal?: number;
  saidAtPrecision: 'minute' | 'day';
  kind: (typeof DECISION_KINDS)[number];
  verbatim: boolean;
  appliesTo: string[];
  linkedRepo: string | null;
  linkedPr: number | null;
  expiresAt: string | null;
  expiresRule: string | null;
  text: string;
  /** 0013 decision_links targets from the Links: header (absent when none). Not hashed. */
  links?: string[];
}

export interface FactRecord {
  type: 'fact';
  who: string;
  saidAt: string;
  ordinal?: number;
  factKind: 'rule' | 'state';
  subject: string;
  text: string;
}

export type StructuredRecord = DecisionRecord | FactRecord;

export interface StructuredParseCounts {
  /** H2 entries seen. */
  entries: number;
  /** H2 entries without a header block (notes only). */
  unstructured: number;
  /** Header present but incomplete / unknown key / bad value (notes only). */
  invalid: number;
  /** Headed entries the shared secret detector (or a [REDACTED: marker) withholds (notes only, redacted there). */
  secret: number;
}

export function emptyParseCounts(): StructuredParseCounts {
  return { entries: 0, unstructured: 0, invalid: 0, secret: 0 };
}

const iso = (s: string): string | null => {
  if (!ISO_RE.test(s)) return null;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return null;
  // Date rolls an impossible calendar day over (2026-02-30 -> 2026-03-02): refuse it instead.
  const day = s.slice(0, 10);
  if (new Date(`${day}T00:00:00Z`).toISOString().slice(0, 10) !== day) return null;
  const off = /([+-])(\d{2}):(\d{2})$/.exec(s);
  if (off && (Number(off[2]) > 14 || Number(off[3]) > 59)) return null;
  return d.toISOString();
};

/**
 * Why a headed entry stayed a note (the first rule it broke, in parse order). Reported by the import
 * preview so a user can fix the entry (live finding 2026-11-18); the texts state the parser's rules.
 */
export const KEPT_AS_NOTE_REASONS = {
  heading: 'no timestamped heading: the heading must be exactly `## <date and time with offset> <handle>`, e.g. `## 2026-11-18T10:00:00+01:00 me`',
  no_header: 'no header: put `Decision: <kind>` and `Said-at-precision: minute|day` directly under the heading, before any blank line',
  decision_kind: 'missing or unknown Decision: kind (one of go, lock, ruling, stop, park)',
  said_at_precision: 'missing or unknown Said-at-precision: (minute or day)',
  other: 'invalid header or text: an unknown or repeated header key, a bad value, no text after the blank line, a timestamp in the future, or Decision mixed with Type',
  secret: 'withheld by the secret detector (kept as a redacted note)',
} as const;
export type KeptAsNoteReason = keyof typeof KEPT_AS_NOTE_REASONS;
type Skip = { skip: 'unstructured' | 'invalid'; why: KeptAsNoteReason };
const skip = (s: Skip['skip'], why: KeptAsNoteReason = s === 'unstructured' ? 'no_header' : 'other'): Skip => ({ skip: s, why });

/** Parse one entry (its raw lines, H2 first). null + why when it yields no record. */
export function parseEntry(lines: readonly string[], now: Date = new Date()): { record: StructuredRecord } | Skip {
  const h = STRUCTURED_H2_RE.exec(lines[0] ?? '');
  if (!h) return skip('unstructured', 'heading');
  const saidAt = iso(h[1]!);
  const who = h[2]!;
  if (saidAt === null || !WHO_HANDLE_RE.test(who)) return skip('invalid', 'heading');
  if (new Date(saidAt).getTime() > now.getTime() + MAX_FUTURE_SKEW_MS) return skip('invalid');

  let i = 1;
  const hdr = new Map<HeaderKey, string>();
  for (; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === '') break;
    const m = HEADER_LINE_RE.exec(line);
    const key = m?.[1]?.toLowerCase() as HeaderKey | undefined;
    if (!m || !key || !(HEADER_KEYS as readonly string[]).includes(key)) {
      // The first line decides: no known key at all means a plain entry (note only).
      return skip(hdr.size === 0 ? 'unstructured' : 'invalid');
    }
    if (hdr.has(key)) return skip('invalid');
    hdr.set(key, m[2]!);
  }
  if (hdr.size === 0) return skip('unstructured');
  const text = lines.slice(i).join('\n').trim();
  if (text === '' || text.length > MAX_STRUCTURED_TEXT) return skip('invalid');

  const isDecision = hdr.has('decision');
  const isFact = hdr.has('type');
  if (isDecision === isFact) return skip('invalid');

  if (isFact) {
    for (const k of ['decision', 'verbatim', 'applies-to', 'links', 'expires'] as const) if (hdr.has(k)) return skip('invalid');
    const t = hdr.get('type')!.toLowerCase();
    const subject = hdr.get('subject') ?? '';
    if ((t !== 'rule' && t !== 'focus') || subject === '' || subject.length > MAX_SUBJECT) return skip('invalid');
    if (hdr.has('said-at-precision') && !['minute', 'day'].includes(hdr.get('said-at-precision')!)) return skip('invalid');
    return { record: { type: 'fact', who, saidAt, factKind: t === 'rule' ? 'rule' : 'state', subject, text } };
  }

  if (hdr.has('type') || hdr.has('subject')) return skip('invalid');
  const kind = hdr.get('decision')!.toLowerCase();
  if (!(DECISION_KINDS as readonly string[]).includes(kind)) return skip('invalid', 'decision_kind');
  const precision = hdr.get('said-at-precision');
  if (precision !== 'minute' && precision !== 'day') return skip('invalid', 'said_at_precision');
  let verbatim = false;
  if (hdr.has('verbatim')) {
    const v = hdr.get('verbatim')!.toLowerCase();
    if (v === 'yes' || v === 'true') verbatim = true;
    else if (v !== 'no' && v !== 'false') return skip('invalid');
  }
  const appliesTo = (hdr.get('applies-to') ?? '').split(',').map((x) => x.trim()).filter((x) => x !== '');
  if (appliesTo.length > MAX_APPLIES_TO || appliesTo.some((x) => x.length > MAX_APPLIES_TO_ITEM)) return skip('invalid');
  let linkedRepo: string | null = null;
  let linkedPr: number | null = null;
  const links: string[] = [];
  for (const l of (hdr.get('links') ?? '').split(',').map((x) => x.trim())) {
    const g = GH_LINK_RE.exec(l);
    if (g && linkedRepo === null) {
      linkedRepo = g[1]!; // the first PR fills linked_repo / linked_pr (one PR column per decision)
      linkedPr = Number(g[2]);
    }
    if (links.length < MAX_LINKS && !links.includes(l) && linkTargetKind(l) !== null) links.push(l);
  }
  let expiresAt: string | null = null;
  let expiresRule: string | null = null;
  const ex = hdr.get('expires');
  if (ex !== undefined) {
    if (ex === '' || ex.length > MAX_EXPIRES_RULE) return skip('invalid');
    expiresAt = iso(ex);
    if (expiresAt === null) {
      if (ISO_RE.test(ex)) return skip('invalid');
      expiresRule = ex;
    }
  }
  return {
    record: {
      type: 'decision', who, saidAt, saidAtPrecision: precision, kind: kind as DecisionRecord['kind'], verbatim, appliesTo,
      linkedRepo, linkedPr, expiresAt, expiresRule, text, ...(links.length > 0 ? { links } : {}),
    },
  };
}

/** Every structured record of a note body (H2 entries only; the preamble never yields one). */
export function parseStructuredBody(body: string, now: Date = new Date()): {
  records: StructuredRecord[]; counts: StructuredParseCounts; keptAsNote: Partial<Record<KeptAsNoteReason, number>>;
} {
  const counts = emptyParseCounts();
  const keptAsNote: Partial<Record<KeptAsNoteReason, number>> = {};
  const kept = (w: KeptAsNoteReason) => { keptAsNote[w] = (keptAsNote[w] ?? 0) + 1; };
  const records: StructuredRecord[] = [];
  const keys = new Map<string, number>();
  for (const e of splitEntries(body)) {
    if (!e.heading) continue;
    counts.entries++;
    const r = parseEntry(e.lines, now);
    if ('record' in r && entrySecretSignal(e.lines)) {
      counts.secret++;
      kept('secret');
    }
    else if ('record' in r) {
      const k = uriKey(r.record);
      const n = keys.get(k) ?? 0;
      keys.set(k, n + 1);
      records.push(n === 0 ? r.record : { ...r.record, ordinal: n });
    } else {
      counts[r.skip]++;
      kept(r.why);
    }
  }
  return { records, counts, keptAsNote };
}

/** The serve-time secret check (shared detector + floor + marker) over an entry's lines; a throw counts as a hit (fail closed). */
export function entrySecretSignal(lines: readonly string[]): boolean {
  try {
    return lines.some((l) => serveSecretSignal(l)) || serveSecretSignal(lines.join('\n'));
  } catch {
    return true;
  }
}

/** The same check over every string field of a record (writer defence in depth). */
export function recordSecretSignal(r: StructuredRecord): boolean {
  const strings = Object.values(r).flatMap((v) => (typeof v === 'string' ? [v] : Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []));
  return entrySecretSignal(strings);
}

const uriKey = (r: StructuredRecord): string => JSON.stringify([r.type, r.who, r.saidAt, r.type === 'fact' ? r.subject : null]);

/**
 * Stable source_uri of a record: `<prefix><project>/entry/<16 hex>` from (type, who, said_at,
 * subject) and, for a repeated key in one note, its ordinal. Not from the text: an edited entry
 * keeps its uri, so a changed sha is a conflict.
 */
export function recordUri(prefix: string, project: string, r: StructuredRecord): string {
  const key = r.ordinal ? JSON.stringify([uriKey(r), r.ordinal]) : uriKey(r);
  const id = createHash('sha256').update(key, 'utf8').digest('hex').slice(0, 16);
  return `${prefix}${project}/entry/${id}`;
}

/**
 * sha256 (hex) of the whole record: any edit of any field changes it. `links` (0013) is left out,
 * so records stored before 0013 keep their sha; links carry their own sha (linkSha256).
 */
export function recordSha256(r: StructuredRecord): string {
  const { links: _links, ...rest } = r as DecisionRecord;
  void _links;
  return createHash('sha256').update(JSON.stringify(r.type === 'decision' ? rest : r), 'utf8').digest('hex');
}

export interface StructuredWriteCounts {
  decisions_inserted: number;
  rules_inserted: number;
  focus_inserted: number;
  deduped: number;
  conflict: number;
  unknown_person: number;
  quarantined: number;
  /** Records the shared secret detector withheld at write time (never inserted, no quarantine hash). */
  secret_withheld: number;
  /** 0013 decision_links rows inserted (for new and already stored decisions). */
  links_inserted: number;
  /** Links rejected by the wall (pre-check or trigger); recorded by uri and hash only. */
  links_quarantined: number;
  /** Links not written because 0013 is not applied (or this login has no INSERT on decision_links). */
  links_skipped: number;
  /** Links the database CHECK refused (shape, or the stored decision is in another scope); counted, never fatal. */
  links_invalid: number;
}

export function emptyWriteCounts(): StructuredWriteCounts {
  return {
    decisions_inserted: 0, rules_inserted: 0, focus_inserted: 0, deduped: 0, conflict: 0, unknown_person: 0, quarantined: 0, secret_withheld: 0,
    links_inserted: 0, links_quarantined: 0, links_skipped: 0, links_invalid: 0,
  };
}

export interface StructuredWriteOptions {
  scope: 'work' | 'product' | 'client';
  sourceKind: 'manual' | 'zeus_memory';
  /** source_uri prefix, e.g. `import:`. */
  uriPrefix: string;
  runId: number;
  /** The live wall (pre-check); the trigger stays the backstop. */
  wall: Wall;
  /**
   * C6 (docs/plans/2026-11-19-c6-write-path.md KTD7, U7): the write route, default PLAIN_ROUTE (today's
   * autocommit INSERTs, unchanged). Sealed: dedupe on (source_uri_hmac, keyed sha), one sealed
   * transaction per record (record, read-back, its links, enc_progress, index hook), quarantine by HMAC.
   */
  route?: WriteRoute;
}

/** The wall row of a record exactly as it will be inserted (for the pre-check and the dry-run preview). */
export function recordRow(r: StructuredRecord, uri: string, scope: string, sourceKind: string, sha: string): Record<string, unknown> {
  return r.type === 'decision'
    ? {
      kind: r.kind, said_at: r.saidAt, said_at_precision: r.saidAtPrecision, exact_words: r.text, exact_words_verbatim: r.verbatim,
      applies_to: r.appliesTo, expires_at: r.expiresAt, expires_rule: r.expiresRule, linked_repo: r.linkedRepo, linked_pr: r.linkedPr,
      scope, source_kind: sourceKind, source_uri: uri, source_ts: r.saidAt, source_sha256: sha,
    }
    : { kind: r.factKind, subject: r.subject, text: r.text, scope, source_kind: sourceKind, source_uri: uri, source_ts: r.saidAt, source_sha256: sha };
}

/**
 * Insert the records (real runs only). Autocommit per record; never UPDATE; never creates people.
 * Must run as the ingest login (INSERT on facts/decisions, SELECT through zeusi_read, quarantine_record).
 */
export async function writeStructured(db: Db, items: ReadonlyArray<{ record: StructuredRecord; project: string }>, o: StructuredWriteOptions): Promise<StructuredWriteCounts> {
  const c = emptyWriteCounts();
  const route = o.route ?? PLAIN_ROUTE;
  const sealed = route.kind === 'sealed' ? route : null;
  let linksOk: boolean | undefined; // checked once, on the first record that carries links
  /** Links of a stored decision (inserted now or deduped). `inTx`: already inside the record's sealed transaction. */
  const writeLinks = async (r: DecisionRecord, decisionId: number, uri: string, inTx = false): Promise<void> => {
    const targets = r.links ?? [];
    if (targets.length === 0) return;
    linksOk ??= await canInsertLinks(db);
    if (!linksOk) {
      c.links_skipped += targets.length;
      return;
    }
    const input = { decisionId, scope: o.scope, sourceKind: o.sourceKind, sourceUri: uri, sourceTs: r.saidAt, runId: o.runId, targets, wall: o.wall };
    const l = !sealed
      ? await insertDecisionLinks(db, input)
      : inTx
        ? await insertDecisionLinks(db, { ...input, inTransaction: true, route: sealed })
        : await sealedTx(db, sealed, () => insertDecisionLinks(db, { ...input, inTransaction: true, route: sealed }));
    c.links_inserted += l.inserted;
    c.links_quarantined += l.quarantined;
    c.links_invalid += l.invalid;
  };
  for (const { record: r, project } of items) {
    if (recordSecretSignal(r)) {
      c.secret_withheld++; // before any query: no secret-bearing value reaches the database
      continue;
    }
    const table = r.type === 'decision' ? 'decisions' : 'facts';
    const uri = recordUri(o.uriPrefix, project, r);
    const sha = recordSha256(r);
    const who = (await db.query<{ id: number }>(`SELECT id::int AS id FROM zeusi.people WHERE handle = $1`, [r.who])).rows[0];
    if (!who) {
      c.unknown_person++;
      continue;
    }
    const seen = sealed
      ? (await db.query<{ id: number; sha: string }>(
        `SELECT id::int AS id, encode(source_sha256, 'hex') AS sha FROM zeusi.${table} WHERE source_uri_hmac = $1::bytea`, [sealed.key.indexHmac('uri', uri)])).rows
      : (await db.query<{ id: number; sha: string }>(`SELECT id::int AS id, encode(source_sha256, 'hex') AS sha FROM zeusi.${table} WHERE source_uri = $1`, [uri])).rows;
    // A sealed row stores the keyed digest (C6 KTD5); the plain digest stays in memory.
    const storedSha = sealed ? sealed.key.keyedSha('source_sha256', sha).toString('hex') : sha;
    const same = seen.find((x) => x.sha === storedSha);
    if (same) {
      c.deduped++;
      if (r.type === 'decision') await writeLinks(r, Number(same.id), uri); // links stated after the first import
      continue;
    }
    if (seen.length > 0) {
      c.conflict++;
      continue;
    }
    const row = recordRow(r, uri, o.scope, o.sourceKind, sha);
    const v = o.wall.check(table, row);
    const quarantine = (ruleId: number | null, contentSha: string | null) => recordQuarantine(db, {
      sourceKind: o.sourceKind, sourceUri: uri, sourceSha256: sha, ruleId, ingestRunId: o.runId, table, contentSha256: contentSha,
    }, route);
    if (v.blocked) {
      await quarantine(v.ruleId, v.contentSha256);
      c.quarantined++;
      continue;
    }
    if (sealed) {
      try {
        await writeSealedRecord(db, sealed, r, { uri, sha, scope: o.scope, sourceKind: o.sourceKind, runId: o.runId, whoId: Number(who.id) },
          (d, id) => writeLinks(d, id, uri, true));
        if (r.type === 'decision') c.decisions_inserted++;
        else if (r.factKind === 'rule') c.rules_inserted++;
        else c.focus_inserted++;
      } catch (e) {
        if (asPgError(e).code === '23505') {
          c.deduped++; // (source_uri_hmac, keyed sha) already stored: a concurrent run
          continue;
        }
        throw e;
      }
      continue;
    }
    try {
      if (r.type === 'decision') {
        const ins = await db.query<{ id: number }>(
          `INSERT INTO zeusi.decisions (kind, who_id, said_at, said_at_precision, exact_words, exact_words_verbatim, applies_to, expires_at,
                                        expires_rule, linked_repo, linked_pr, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
           VALUES ($1::zeusi.decision_kind, $2, $3::timestamptz, $4, $5, $6, $7::text[], $8::timestamptz, $9, $10, $11, $12::zeusi.scope,
                   $13::zeusi.source_kind, $14, $3::timestamptz, decode($15, 'hex'), $16)
           RETURNING id::int AS id`,
          [r.kind, who.id, r.saidAt, r.saidAtPrecision, r.text, r.verbatim, r.appliesTo, r.expiresAt, r.expiresRule, r.linkedRepo, r.linkedPr,
            o.scope, o.sourceKind, uri, sha, o.runId],
        );
        c.decisions_inserted++;
        await writeLinks(r, Number(ins.rows[0]!.id), uri);
      } else {
        await db.query(
          `INSERT INTO zeusi.facts (kind, subject, text, scope, source_kind, source_uri, source_ts, source_sha256, ingest_run_id)
           VALUES ($1, $2, $3, $4::zeusi.scope, $5::zeusi.source_kind, $6, $7::timestamptz, decode($8, 'hex'), $9)`,
          [r.factKind, r.subject, r.text, o.scope, o.sourceKind, uri, r.saidAt, sha, o.runId],
        );
        if (r.factKind === 'rule') c.rules_inserted++;
        else c.focus_inserted++;
      }
    } catch (e) {
      const w = parseWallError(e);
      if (w) {
        await quarantine(w.ruleId, w.contentSha256);
        c.quarantined++;
        continue;
      }
      if (asPgError(e).code === '23505') {
        c.deduped++; // a concurrent run inserted the same (source_uri, source_sha256)
        continue;
      }
      throw e;
    }
  }
  return c;
}

/**
 * C6 KTD7 (U7): one structured record in one sealed transaction: pre-allocated id, every content column
 * sealed (decisions.applies_to as a JSON array, KTD6), keyed source_sha256, the read-back, the
 * decision's links (inside the same transaction), and the index hook. Counts nothing itself.
 */
async function writeSealedRecord(
  db: Db, route: SealedRoute, r: StructuredRecord,
  o: { uri: string; sha: string; scope: string; sourceKind: string; runId: number; whoId: number },
  links: (r: DecisionRecord, id: number) => Promise<void>,
): Promise<void> {
  const key = route.key;
  const table = r.type === 'decision' ? 'decisions' : 'facts';
  await sealedTx(db, route, async () => {
    const id = (await nextId(db, table))[0]!;
    const prov: SqlCol[] = [
      ['scope', o.scope, 'zeusi.scope'], ['source_kind', o.sourceKind, 'zeusi.source_kind'], ['source_ts', r.saidAt, 'timestamptz'],
      ['source_sha256', key.keyedSha('source_sha256', o.sha), 'bytea'], ['ingest_run_id', o.runId, 'bigint'],
    ];
    if (r.type === 'decision') {
      const cols = [
        ...sealRow(key, 'decisions', id, {
          exact_words: r.text, applies_to: JSON.stringify(r.appliesTo), expires_rule: r.expiresRule ?? null, linked_repo: r.linkedRepo ?? null,
          linked_job: null, source_uri: o.uri,
        }),
        key.sealDigest('decisions', id, o.sha), // C8-0 KTD-A
      ];
      const ins = sealedInsertSql('decisions', [
        ['id', id, 'bigint'], ['kind', r.kind, 'zeusi.decision_kind'], ['who_id', o.whoId, 'bigint'], ['said_at', r.saidAt, 'timestamptz'],
        ['said_at_precision', r.saidAtPrecision], ['exact_words_verbatim', r.verbatim, 'boolean'], ['expires_at', r.expiresAt, 'timestamptz'],
        ['linked_pr', r.linkedPr, 'int'], ...prov,
      ], cols);
      await db.query(ins.sql, ins.params);
      const rb = (await db.query<{ ct: Uint8Array | null }>(`SELECT exact_words_ct AS ct FROM zeusi.decisions WHERE id = $1`, [id])).rows[0];
      if (!rb?.ct || key.open('decisions', 'exact_words', id, rb.ct) !== r.text) throw new Error('sealed record read-back failed');
      await route.index.onRecordWritten(db, { table: 'decisions', id });
      await links(r, id);
    } else {
      const cols = [...sealRow(key, 'facts', id, { subject: r.subject ?? null, text: r.text, source_uri: o.uri }), key.sealDigest('facts', id, o.sha)]; // C8-0 KTD-A
      const ins = sealedInsertSql('facts', [['id', id, 'bigint'], ['kind', r.factKind], ...prov], cols);
      await db.query(ins.sql, ins.params);
      const rb = (await db.query<{ ct: Uint8Array | null }>(`SELECT text_ct AS ct FROM zeusi.facts WHERE id = $1`, [id])).rows[0];
      if (!rb?.ct || key.open('facts', 'text', id, rb.ct) !== r.text) throw new Error('sealed record read-back failed');
      await route.index.onRecordWritten(db, { table: 'facts', id });
    }
  });
}
