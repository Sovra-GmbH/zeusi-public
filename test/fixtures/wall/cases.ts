// Shared wall fixture table (synthetic only — never real desk, client, or Plankiva data).
// Used by the parity test: src/wall.ts and the SQL trigger / zeusi.wall_eval() must
// give the same verdict (blocked?, rule id, hard?, content sha) on every row here.
//
// Each case is a full row as it will be stored (wall-relevant defaults included),
// shaped like to_jsonb(row): snake_case columns, arrays as arrays, jsonb as objects.

export interface Ctx {
  run: number;
  personId: number;
  noteId: number;
}

export interface WallCase {
  name: string;
  table: 'facts' | 'decisions' | 'episodes' | 'notes' | 'chunks' | 'prs' | 'pr_reviews' | 'routine_runs' | 'people';
  row: Record<string, unknown>;
  /** Expected outcome, independent of rule ids: 'pass', 'hard:<kind>', 'soft:<kind>'. */
  expect: string;
}

const SHA = 'cd'.repeat(32);
const HEAD = 'a'.repeat(40);
const TS = '2026-11-10T09:00:00Z';

const P = (ctx: Ctx, uri: string, kind = 'manual') => ({
  scope: 'work',
  source_kind: kind,
  source_uri: uri,
  source_ts: TS,
  source_sha256: SHA,
  ingest_run_id: ctx.run,
});

export function wallCases(ctx: Ctx): WallCase[] {
  const fact = (name: string, uri: string, text: string, expect: string, subject: string | null = null): WallCase => ({
    name, table: 'facts', expect,
    row: { kind: 'other', subject, text, ...P(ctx, uri) },
  });
  const note = (name: string, path: string, title: string, body: string, frontmatter: unknown, expect: string): WallCase => ({
    name, table: 'notes', expect,
    row: { vault_path: path, title, body, frontmatter, file_mtime: TS, status: 'active', ...P(ctx, `vault:${path}`, 'vault_note') },
  });
  return [
    // --- clean rows pass
    fact('clean fact', 'vault:Work/ops/merge-gate-lock.md#Lock', 'merge gate needs opus SAFE on the current head', 'pass', 'merge-gate.test'),
    note('clean note', 'Work/ops/clean-note.md', 'Clean note', '## Plan\nShip U4 with #ops tag.', { tags: ['ops', 'zeusi'], date: '2026-11-10' }, 'pass'),
    { name: 'clean pr', table: 'prs', expect: 'pass',
      row: { repo: 'example-org/ops-console', number: 102, title: 'Fix rounding in report', author_login: 'dev1', base_ref: 'main', head_ref: 'fix/rounding',
             head_sha: HEAD, state: 'open', gh_updated_at: TS, ...P(ctx, 'gh:example-org/ops-console#102', 'github_api') } },

    // --- plan U4 scenarios
    // 0010 (the owner 14 Nov 2026 19:12): ClientCo is no longer walled.
    note('ClientCo vault path', 'ClientCo/clients/overview.md', 'Overview', 'synthetic', {}, 'pass'),
    fact('PnL in path', 'vault:Work/ops/Desk-PnL-weekly.md', 'synthetic text', 'hard:path_glob'),
    // 0011 (the owner 15 Nov 2026 01:09): the soft currency and P&L rules are lifted.
    fact('synthetic currency amount', 'zeusi:test/currency', 'synthetic amount USD 12,345 noted', 'pass'),
    fact('synthetic account number', 'zeusi:test/acct', 'acct 1234567 is a fake number', 'soft:regex'),
    fact('synthetic IBAN (doc example)', 'zeusi:test/iban', 'pay to CH93 0076 2011 6238 5295 7 please', 'soft:regex'),
    { name: 'ClientCo repo PR', table: 'prs', expect: 'pass',
      row: { repo: 'example-org/clientco-hedging-engine', number: 5, title: 'x', author_login: null, base_ref: 'main', head_ref: 'x',
             head_sha: HEAD, state: 'open', gh_updated_at: TS, ...P(ctx, 'gh:example-org/clientco-hedging-engine#5', 'github_api') } },
    { name: 'desk P&L lane episode', table: 'episodes', expect: 'hard:lane',
      row: { occurred_at: TS, day: '2026-11-10', actor: 'zeus', lane: 'session-pnl', kind: 'note', summary: 'synthetic', links: [],
             ...P(ctx, 'zeusi:test/lane-episode') } },

    // --- Plankiva (a): paths, lanes, repos
    fact('PlankivaVault requests path (~)', 'file:~/PlankivaVault/requests/form-001.md', 'synthetic request text', 'hard:path_glob'),
    fact('PlankivaVault requests path (absolute)', 'file:/Users/someone/PlankivaVault/requests/form-002.md', 'synthetic', 'hard:path_glob'),
    fact('plankiva substring in vault path', 'vault:Work/notes/Sync-PLANKIVA-weekly.md', 'synthetic', 'hard:path_glob'),
    note('plankiva folder in vault', 'plankiva/requests/r1.md', 'r1', 'synthetic', {}, 'hard:path_glob'),
    { name: 'plankiva lane routine run', table: 'routine_runs', expect: 'hard:lane',
      row: { routine: 'sync', run_key: 'mini:sync:2026-11-10T09:00', host: 'mini', login_label: 'work', lane: 'plankiva-sync',
             started_at: TS, finished_at: null, exit_code: 0, status: 'ok', log_ref: 'logs/sync-1.log', ...P(ctx, 'run:mini:sync:1', 'runner_log') } },
    { name: 'plankiva in decision applies_to', table: 'decisions', expect: 'hard:lane',
      row: { kind: 'go', who_id: ctx.personId, said_at: TS, said_at_precision: 'minute', exact_words: 'GO', exact_words_verbatim: true,
             applies_to: ['plankiva-requests'], expires_at: null, expires_rule: null, linked_repo: null, linked_pr: null, linked_job: null,
             ...P(ctx, 'zeusi:test/dec-a1', 'lane_md') } },
    { name: 'plankiva repo PR', table: 'prs', expect: 'hard:path_glob',
      row: { repo: 'example-org/plankiva-site', number: 6, title: 'x', author_login: null, base_ref: 'main', head_ref: 'x',
             head_sha: HEAD, state: 'open', gh_updated_at: TS, ...P(ctx, 'gh:example-org/plankiva-site#6', 'github_api') } },

    // agent-config-backup* is kept by 0010 (not a ClientCo-name rule; flagged for the operator).
    { name: 'agent-config-backup repo only in linked_repo', table: 'decisions', expect: 'hard:repo',
      row: { kind: 'go', who_id: ctx.personId, said_at: TS, said_at_precision: 'minute', exact_words: 'GO', exact_words_verbatim: true,
             applies_to: [], expires_at: null, expires_rule: null, linked_repo: 'agent-config-backup-clientco-walled', linked_pr: 3, linked_job: null,
             ...P(ctx, 'zeusi:test/dec-repo', 'lane_md') } },
    { name: 'plankiva repo only in review repo column', table: 'pr_reviews', expect: 'hard:repo',
      row: { repo: 'example-org/plankiva-site', number: 6, review_round: 1, verdict: 'SAFE', verdict_head: HEAD, reviewer: 'opus',
             review_ref: null, reviewed_at: TS, ...P(ctx, 'ledger:rounds-ledger.tsv:L3', 'review_ledger') } },

    // --- Plankiva (b): tags
    note('frontmatter tags list contains Plankiva', 'Work/ops/tag-list.md', 'Tagged', 'synthetic body', { tags: ['ops', 'Plankiva'] }, 'hard:tag'),
    note('frontmatter tags string contains plankiva', 'Work/ops/tag-string.md', 'Tagged', 'synthetic body', { tags: 'team/plankiva-requests' }, 'hard:tag'),
    note('frontmatter tag key (singular)', 'Work/ops/tag-singular.md', 'Tagged', 'synthetic body', { tag: '#PLANKIVA' }, 'hard:tag'),
    note('inline #plankiva tag in a heading', 'Work/ops/inline-tag.md', 'Inline', '## Weekly sync #plankiva\nsynthetic', {}, 'hard:tag'),
    { name: 'inline tag in chunk heading text', table: 'chunks', expect: 'hard:tag',
      row: { note_id: ctx.noteId, chunk_index: 0, heading_path: 'Weekly', text: 'see #Plankiva-requests for details', token_count: 6,
             embed_model: null, embedding: null, embedded_at: null, ...P(ctx, 'vault:Work/ops/parent.md#Weekly', 'vault_note') } },

    // --- Plankiva (c): the word anywhere in checked text
    note('plankiva in note body', 'Work/ops/body-word.md', 'Body', 'Met plankiva about the form.', {}, 'hard:term'),
    note('plankiva in note title', 'Work/ops/title-word.md', 'Call with Plankiva', 'synthetic body', {}, 'hard:term'),
    note('plankiva in other frontmatter field', 'Work/ops/fm-word.md', 'FM', 'synthetic body', { related: ['[[Plankiva notes]]'] }, 'hard:term'),
    { name: 'PLANKIVA in chunk text', table: 'chunks', expect: 'hard:term',
      row: { note_id: ctx.noteId, chunk_index: 1, heading_path: 'Notes', text: 'PLANKIVA asked for an update', token_count: 5,
             embed_model: null, embedding: null, embedded_at: null, ...P(ctx, 'vault:Work/ops/parent.md#Notes', 'vault_note') } },
    { name: 'Plankiva in PR title', table: 'prs', expect: 'hard:term',
      row: { repo: 'example-org/team-hq', number: 7, title: 'Plankiva request form fix', author_login: 'dev1', base_ref: 'main', head_ref: 'fix/form',
             head_sha: HEAD, state: 'open', gh_updated_at: TS, ...P(ctx, 'gh:example-org/team-hq#7', 'github_api') } },
    { name: 'plankiva in person display name', table: 'people', expect: 'hard:term',
      row: { handle: 'person-x', display_name: 'Plankiva X', kind: 'human', org: 'work', github_login: null, ...P(ctx, 'zeusi:test/people-x') } },
    fact('plankiva only in uri fragment', 'vault:Work/ops/sync.md#Plankiva', 'synthetic', 'hard:term'),
    fact('hard plankiva wins over a soft currency hit', 'zeusi:test/both', 'USD 500 for plankiva', 'hard:term'),
    { name: 'plankiva in episode links', table: 'episodes', expect: 'hard:term',
      row: { occurred_at: TS, day: '2026-11-10', actor: 'zeus', lane: null, kind: 'note', summary: 'synthetic', links: ['https://example.invalid/plankiva'],
             ...P(ctx, 'zeusi:test/links') } },
    { name: 'plankiva in decision exact words', table: 'decisions', expect: 'hard:term',
      row: { kind: 'go', who_id: ctx.personId, said_at: TS, said_at_precision: 'minute', exact_words: 'GO for the Plankiva form', exact_words_verbatim: true,
             applies_to: [], expires_at: null, expires_rule: null, linked_repo: null, linked_pr: null, linked_job: null,
             ...P(ctx, 'zeusi:test/dec-word', 'lane_md') } },
    { name: 'plankiva in review ref', table: 'pr_reviews', expect: 'hard:path_glob',
      row: { repo: 'example-org/ops-console', number: 101, review_round: 1, verdict: 'SAFE', verdict_head: HEAD, reviewer: 'opus',
             review_ref: 'reviews/plankiva-review-out.md', reviewed_at: TS, ...P(ctx, 'ledger:rounds-ledger.tsv:L9', 'review_ledger') } },

    // --- r1 MINOR-1: invisible / look-alike Unicode (0008 normalisation). Escapes keep the
    //     fixture source readable; every row is synthetic.
    note('plankiva with zero-width space in body', 'Work/ops/zw-body.md', 'ZW', 'Met Plan\u200Bkiva today.', {}, 'hard:term'),
    { name: 'plankiva with soft hyphen in chunk text', table: 'chunks', expect: 'hard:term',
      row: { note_id: ctx.noteId, chunk_index: 2, heading_path: 'Shy', text: 'ask Plan\u00ADkiva later', token_count: 3,
             embed_model: null, embedding: null, embedded_at: null, ...P(ctx, 'vault:Work/ops/parent.md#Shy', 'vault_note') } },
    { name: 'fullwidth A plankiva in PR title', table: 'prs', expect: 'hard:term',
      row: { repo: 'example-org/team-hq', number: 8, title: '\uFF30lankiva form fix', author_login: 'dev1', base_ref: 'main', head_ref: 'fix/form2',
             head_sha: HEAD, state: 'open', gh_updated_at: TS, ...P(ctx, 'gh:example-org/team-hq#8', 'github_api') } },
    fact('Cyrillic A plankiva in fact text', 'zeusi:test/cyr-a', 'note for Pl\u0410nkiva only', 'hard:term'),
    { name: 'Cyrillic and Greek look-alikes plankiva in person display name', table: 'people', expect: 'hard:term',
      row: { handle: 'person-y', display_name: 'pl\u0430n\u03BA\u0456va', kind: 'human', org: 'work', github_login: null,
             ...P(ctx, 'zeusi:test/people-y') } },
    fact('combining diaeresis plankiva', 'zeusi:test/comb', 'Pla\u0308nkiva wrote', 'hard:term'),
    fact('word joiner + variation selector plankiva', 'zeusi:test/wj', 'Pl\u2060an\uFE0Fkiva wrote', 'hard:term'),
    fact('tag-character plankiva (U+E0041)', 'zeusi:test/tagchar', 'Plan\u{E0041}kiva wrote', 'hard:term'),
    note('frontmatter tag with zero-width space', 'Work/ops/zw-tag.md', 'Tagged', 'synthetic body', { tags: ['ops', 'Plan\u200Bkiva'] }, 'hard:tag'),
    note('frontmatter tag with Cyrillic a', 'Work/ops/cyr-tag.md', 'Tagged', 'synthetic body', { tags: 'team/pl\u0430nkiva' }, 'hard:tag'),
    note('inline fullwidth #plankiva tag', 'Work/ops/fw-inline.md', 'Inline', '## Sync #\uFF30lankiva\nsynthetic', {}, 'hard:tag'),
    note('Cyrillic plankiva in vault path', 'Work/notes/Pl\u0410nkiva-sync.md', 'Sync', 'synthetic', {}, 'hard:path_glob'),
    note('fullwidth ClientCo in vault path', '\uFF36\uFF23\uFF27/clients.md', 'Clients', 'synthetic', {}, 'pass'),
    // clean look-alike / invisible rows still pass
    fact('zero-width chars in clean text', 'zeusi:test/zw-clean', 'hello\u200Bworld, see you', 'pass'),
    fact('Cyrillic name Anna (not the hard word)', 'zeusi:test/cyr-clean', '\u0410\u043D\u043D\u0430 Karenina review', 'pass'),

    // --- r1 MINOR-2: percent-encoded uris and paths (decoded, bounded, before path rules)
    fact('percent-encoded PlankivaVault uri', 'vault:Work/%50lankivaVault/requests/x.md', 'synthetic', 'hard:path_glob'),
    fact('double percent-encoded PlankivaVault uri', 'file:~/%2550lankivaVault/requests/y.md', 'synthetic', 'hard:path_glob'),
    fact('percent-encoded ClientCo path', 'vault:%43lientCo/x.md', 'synthetic', 'pass'),
    fact('percent-encoded plankiva with invalid UTF-8 byte', 'vault:Work/%FF%50lankiva.md', 'synthetic', 'hard:path_glob'),
    note('percent-encoded plankiva in vault_path only', 'Work/ops/%70lankiva.md', 'P', 'synthetic', {}, 'hard:path_glob'),
    // uri_path of the decoded lane: uri is checked first, so the **plankiva** path rule wins.
    { name: 'percent-encoded plankiva lane in uri', table: 'episodes', expect: 'hard:path_glob',
      row: { occurred_at: TS, day: '2026-11-10', actor: 'zeus', lane: null, kind: 'note', summary: 'synthetic', links: [],
             ...P(ctx, 'lane:%70lankiva-sync') } },
    { name: 'percent-encoded ClientCo repo in gh uri', table: 'prs', expect: 'pass',
      row: { repo: 'example-org/team-hq', number: 9, title: 'x', author_login: null, base_ref: 'main', head_ref: 'x',
             head_sha: HEAD, state: 'open', gh_updated_at: TS, ...P(ctx, 'gh:example-org/%63lientco-engine#9', 'github_api') } },
    fact('clean percent-encoded path', 'vault:Work/ops/a%20b.md', 'synthetic', 'pass'),

    // --- r1 MINOR-3: free-text columns outside wall_content (checked by the hard rules only)
    { name: 'plankiva in prs.merged_to', table: 'prs', expect: 'hard:term',
      row: { repo: 'example-org/team-hq', number: 10, title: 'merge', author_login: 'dev1', base_ref: 'main', head_ref: 'x',
             head_sha: HEAD, state: 'merged', merged_to: 'plankiva-branch', merge_sha: 'b'.repeat(40), merged_at: TS,
             gh_updated_at: TS, ...P(ctx, 'gh:example-org/team-hq#10', 'github_api') } },
    { name: 'plankiva in routine_runs.run_key', table: 'routine_runs', expect: 'hard:term',
      row: { routine: 'sync', run_key: 'mini:plankiva-export:2026-11-10T09:00', host: 'mini', login_label: 'work', lane: null,
             started_at: TS, finished_at: null, exit_code: 0, status: 'ok', log_ref: 'logs/sync-2.log', ...P(ctx, 'run:mini:sync:2', 'runner_log') } },

    // --- r2 MINOR-B: Cherokee / Lisu look-alikes (0009 fold list)
    fact('Cherokee GO (U+13AA) plankiva', 'zeusi:test/chr-a', '\u13E2lankiva wrote', 'hard:term'),
    fact('Cherokee small GO (U+AB7A) plankiva', 'zeusi:test/chr-a-small', 'Pl\uAB7Ankiva wrote', 'hard:term'),
    fact('Cherokee V (U+13A5) as i in plankiva', 'zeusi:test/chr-i', 'Plank\u13A5va wrote', 'hard:term'),
    fact('Cherokee TSO (U+13E6) as k in plankiva', 'zeusi:test/chr-k', 'Plan\u13E6iva wrote', 'hard:term'),
    fact('Lisu A (U+A4EE) plankiva', 'zeusi:test/lisu-a', 'Pl\uA4EEnkiva wrote', 'hard:term'),
    fact('all-Lisu plankiva', 'zeusi:test/lisu-all', '\uA4D1\uA4E1\uA4EE\uA4E0\uA4D7\uA4F2\uA4E6\uA4EE', 'hard:term'),
    note('frontmatter tag with Lisu A', 'Work/ops/lisu-tag.md', 'Tagged', 'synthetic body', { tags: ['Pl\uA4EEnkiva'] }, 'hard:tag'),
    note('Cherokee clean word in vault path', 'Work/\u13E2\u13AA\u13DF\u13E6/x.md', 'X', 'synthetic', {}, 'pass'),
    note('Lisu PNL in vault path', 'Work/\uA4D1\uA4E0\uA4E1-q3.md', 'X', 'synthetic', {}, 'hard:path_glob'),
    fact('Cherokee and Lisu words that are not a hard term', 'zeusi:test/chr-clean', '\u13A0\u13CF\u13EF \uA4D0\uA4F0\uA4E3', 'pass'),

    // --- r2 MINOR-B: a %XX escape left after the 8 decode rounds is a hard block
    fact('9-fold percent-encoded PlankivaVault uri', `vault:Work/%${'25'.repeat(8)}50lankivaVault/requests/x.md`, 'synthetic', 'hard:term'),
    fact('undecodable %00 escape in uri', 'vault:Work/ops/x%00.md', 'synthetic', 'hard:term'),
    fact('Cyrillic a hidden behind an invalid UTF-8 escape', 'vault:Work/Pl%D0%90nkiva%FF.md', 'synthetic', 'hard:term'),
    note('undecodable escape in vault_path only', 'Work/ops/y%C3.md', 'Y', 'synthetic', {}, 'hard:term'),
    { name: 'undecodable escape in pr_reviews.review_ref', table: 'pr_reviews', expect: 'hard:term',
      row: { repo: 'example-org/ops-console', number: 101, review_round: 2, verdict: 'SAFE', verdict_head: HEAD, reviewer: 'opus',
             review_ref: 'reviews/r2%FE-out.md', reviewed_at: TS, ...P(ctx, 'ledger:rounds-ledger.tsv:L10', 'review_ledger') } },
    fact('8-fold percent-encoded clean uri still decodes and passes', `vault:Work/ops/a%${'25'.repeat(7)}20b.md`, 'synthetic', 'pass'),
    fact('percent signs that are not escapes pass', 'vault:Work/ops/100%-done%zz.md', 'synthetic', 'pass'),
    fact('%XX in body text is not decoded and passes', 'zeusi:test/pct-body', 'rate went 10%AB up; see %41 note', 'pass'),

    // --- 0010 (the owner 14 Nov 2026 19:12): ClientCo and Northbank are admitted, with scope clientco for ClientCo.
    //     Every row is synthetic. The Plankiva rows are exclusion probes only.
    clientco(note('ClientCo folder note with scope clientco', 'ClientCo/clientco-erp/overview.md', 'ClientCo ERP overview', 'ClientCo ERP plan, synthetic.', { tags: ['client', 'erp'] }, 'pass')),
    clientco(fact('ClientCo fact with scope clientco', 'vault:ClientCo/clientco-360/x.md', 'ClientCo 360 synthetic fact', 'pass')),
    { name: 'clientco lane episode', table: 'episodes', expect: 'pass',
      row: { occurred_at: TS, day: '2026-11-10', actor: 'zeus', lane: 'clientco-offsite', kind: 'note', summary: 'synthetic ClientCo offsite', links: [],
             ...P(ctx, 'lane:clientco-offsite', 'lane_md'), scope: 'client' } },
    { name: 'clientco in decision applies_to and linked_repo', table: 'decisions', expect: 'pass',
      row: { kind: 'go', who_id: ctx.personId, said_at: TS, said_at_precision: 'minute', exact_words: 'GO for ClientCo ERP', exact_words_verbatim: true,
             applies_to: ['clientco-erp'], expires_at: null, expires_rule: null, linked_repo: 'clientco-erp', linked_pr: 4, linked_job: null,
             ...P(ctx, 'zeusi:test/dec-clientco', 'lane_md'), scope: 'client' } },
    { name: 'clientco routine run (lane, log_ref, run_key)', table: 'routine_runs', expect: 'pass',
      row: { routine: 'clientco-sync', run_key: 'mini:clientco-sync:2026-11-10T09:00', host: 'mini', login_label: 'work', lane: 'clientco-sync',
             started_at: TS, finished_at: null, exit_code: 0, status: 'ok', log_ref: 'logs/clientco-sync-1.log', ...P(ctx, 'run:mini:clientco-sync:1', 'runner_log'), scope: 'client' } },
    { name: 'clientco repo review row', table: 'pr_reviews', expect: 'pass',
      row: { repo: 'example-org/ops-console', number: 101, review_round: 3, verdict: 'SAFE', verdict_head: HEAD, reviewer: 'opus',
             review_ref: 'reviews/clientco-erp-review-out.md', reviewed_at: TS, ...P(ctx, 'ledger:rounds-ledger.tsv:L11', 'review_ledger') } },
    note('Northbank product note', 'Work/product/clientco-northbank-shortlist.md', 'Shortlist', 'Northbank for ClientCo, synthetic.', {}, 'pass'),
    // Plankiva stays out, also inside ClientCo folders, lanes and repos.
    clientco(note('plankiva file under ClientCo folder', 'ClientCo/plankiva-sync.md', 'Sync', 'synthetic', {}, 'hard:path_glob')),
    clientco(note('PlankivaVault requests under ClientCo folder', 'ClientCo/PlankivaVault/requests/x.md', 'X', 'synthetic', {}, 'hard:path_glob')),
    clientco(fact('mixed-case percent-encoded plankiva under ClientCo', 'vault:ClientCo/requests/%50LANKIVA-form.md', 'synthetic', 'hard:path_glob')),
    clientco(fact('double-encoded plankiva requests under ClientCo', 'vault:ClientCo/requests/%2570lankiva.md', 'synthetic', 'hard:path_glob')),
    clientco(note('ClientCo note that also mentions plankiva', 'ClientCo/clientco-erp/sync.md', 'ClientCo ERP sync', 'ClientCo ERP sync, then Plankiva joined.', {}, 'hard:term')),
    clientco(note('ClientCo note with an plankiva tag', 'ClientCo/clientco-erp/tagged.md', 'Tagged', 'synthetic', { tags: ['client', 'Plankiva'] }, 'hard:tag')),
    { name: 'clientco lane plus plankiva in applies_to', table: 'decisions', expect: 'hard:lane',
      row: { kind: 'go', who_id: ctx.personId, said_at: TS, said_at_precision: 'minute', exact_words: 'GO', exact_words_verbatim: true,
             applies_to: ['clientco-erp', 'plankiva-requests'], expires_at: null, expires_rule: null, linked_repo: null, linked_pr: null, linked_job: null,
             ...P(ctx, 'zeusi:test/dec-clientco-a', 'lane_md'), scope: 'client' } },
    { name: 'clientco applies_to plus plankiva linked_repo', table: 'decisions', expect: 'hard:repo',
      row: { kind: 'go', who_id: ctx.personId, said_at: TS, said_at_precision: 'minute', exact_words: 'GO', exact_words_verbatim: true,
             applies_to: ['clientco-erp'], expires_at: null, expires_rule: null, linked_repo: 'plankiva-site', linked_pr: 2, linked_job: null,
             ...P(ctx, 'zeusi:test/dec-clientco-r', 'lane_md'), scope: 'client' } },
    { name: 'clientco-plankiva lane episode', table: 'episodes', expect: 'hard:lane',
      row: { occurred_at: TS, day: '2026-11-10', actor: 'zeus', lane: 'clientco-PLANKIVA', kind: 'note', summary: 'synthetic', links: [],
             ...P(ctx, 'zeusi:test/lane-clientco-a'), scope: 'client' } },
    { name: 'clientco-plankiva repo PR', table: 'prs', expect: 'hard:path_glob',
      row: { repo: 'example-org/clientco-plankiva-tools', number: 11, title: 'x', author_login: null, base_ref: 'main', head_ref: 'x',
             head_sha: HEAD, state: 'open', gh_updated_at: TS, ...P(ctx, 'gh:example-org/clientco-plankiva-tools#11', 'github_api'), scope: 'client' } },
    // 0010 hardening: separators between the letters, and leetspeak (hard regex rule). FP 0 on the vault dry run.
    fact('spaced plankiva', 'zeusi:test/sep-space', 'Met P l a n k i v a today', 'hard:regex'),
    fact('dotted plankiva', 'zeusi:test/sep-dot', 'cc P.l.a.n.k.i.v.a.', 'hard:regex'),
    fact('hyphen inside plankiva', 'zeusi:test/sep-hyphen', 'see Plan-kiva notes', 'hard:regex'),
    fact('markdown bold inside plankiva', 'zeusi:test/sep-bold', 'ask **Plan**kiva', 'hard:regex'),
    fact('leetspeak pl4nkiva', 'zeusi:test/leet-4', 'ping pl4nkiva', 'hard:regex'),
    fact('leetspeak pl@nk1va', 'zeusi:test/leet-at', 'ping pl@nk1va', 'hard:regex'),
    fact('fullwidth leetspeak', 'zeusi:test/leet-fw', 'ping ｐｌ４ｎｋｉｖａ', 'hard:regex'),
    clientco(note('separated plankiva in a ClientCo path', 'ClientCo/p-l-a-n-k-i-v-a.md', 'X', 'synthetic', {}, 'hard:regex')),
    note('separated plankiva in a frontmatter tag', 'Work/ops/sep-tag.md', 'Tagged', 'synthetic', { tags: ['P_l_a_n_k_i_v_a'] }, 'hard:regex'),
    { name: 'leetspeak plankiva in a clientco lane', table: 'episodes', expect: 'hard:regex',
      row: { occurred_at: TS, day: '2026-11-10', actor: 'zeus', lane: 'clientco-pl4nkiva', kind: 'note', summary: 'synthetic', links: [],
             ...P(ctx, 'zeusi:test/lane-leet'), scope: 'client' } },
    // clean rows near the pattern must still pass (over-block guard)
    fact('names that run into the letters', 'zeusi:test/sep-clean-1', 'plan and kiva met plankton in a lava plan', 'pass'),
    fact('spaced letters that are not the word', 'zeusi:test/sep-clean-2', 'a n n e x, k a n n a, 4 n n 1 x', 'pass'),

    // --- 0011 (the owner 15 Nov 2026 01:09 Zurich): "Plankiva" (one n) IS Plankiva. One hard regex (no wall_allow)
    //     for plankiva / plaankiva / plankkiva ..., separators and leetspeak like 0010,
    //     raw and normalised, embedded in longer tokens too. Synthetic exclusion probes only.
    fact('Plankiva in fact text', 'zeusi:test/w11-1', 'Met Plankiva today', 'hard:term'),
    note('Plaankiva in note title', 'Work/ops/title-1n.md', 'Call with Plaankiva', 'synthetic body', {}, 'hard:regex'),
    note('plaankiva in a frontmatter tag', 'Work/ops/fm-tag-1n.md', 'Tagged', 'synthetic body', { tags: ['ops', 'team/plaankiva'] }, 'hard:regex'),
    note('inline #Plaankiva tag', 'Work/ops/inline-1n.md', 'Inline', '## Weekly sync #Plaankiva\nsynthetic', {}, 'hard:regex'),
    note('Plaankiva in vault path', 'Work/notes/Plaankiva-sync.md', 'Sync', 'synthetic', {}, 'hard:regex'),
    fact('Plaankiva only in uri fragment', 'vault:Work/ops/sync.md#Plaankiva', 'synthetic', 'hard:regex'),
    fact('percent-encoded Plaankiva in uri', 'vault:Work/%50laankiva-notes.md', 'synthetic', 'hard:regex'),
    { name: 'plaankiva lane episode', table: 'episodes', expect: 'hard:regex',
      row: { occurred_at: TS, day: '2026-11-10', actor: 'zeus', lane: 'plaankiva-sync', kind: 'note', summary: 'synthetic', links: [],
             ...P(ctx, 'zeusi:test/w11-2') } },
    { name: 'plaankiva repo PR', table: 'prs', expect: 'hard:regex',
      row: { repo: 'example-org/plaankiva-site', number: 12, title: 'x', author_login: null, base_ref: 'main', head_ref: 'x',
             head_sha: HEAD, state: 'open', gh_updated_at: TS, ...P(ctx, 'gh:example-org/plaankiva-site#12', 'github_api') } },
    { name: 'plaankiva repo only in review repo column', table: 'pr_reviews', expect: 'hard:regex',
      row: { repo: 'example-org/plaankiva-site', number: 12, review_round: 1, verdict: 'SAFE', verdict_head: HEAD, reviewer: 'opus',
             review_ref: null, reviewed_at: TS, ...P(ctx, 'ledger:rounds-ledger.tsv:L12', 'review_ledger') } },
    { name: 'plaankiva in decision applies_to', table: 'decisions', expect: 'hard:regex',
      row: { kind: 'go', who_id: ctx.personId, said_at: TS, said_at_precision: 'minute', exact_words: 'GO', exact_words_verbatim: true,
             applies_to: ['plaankiva-requests'], expires_at: null, expires_rule: null, linked_repo: null, linked_pr: null, linked_job: null,
             ...P(ctx, 'zeusi:test/w11-3', 'lane_md') } },
    { name: 'Plaankiva in person display name', table: 'people', expect: 'hard:regex',
      row: { handle: 'person-z', display_name: 'Plaankiva Z', kind: 'human', org: 'work', github_login: null, ...P(ctx, 'zeusi:test/w11-4') } },
    { name: 'PLAANKIVA in chunk text', table: 'chunks', expect: 'hard:regex',
      row: { note_id: ctx.noteId, chunk_index: 3, heading_path: 'Notes', text: 'PLAANKIVA asked for an update', token_count: 5,
             embed_model: null, embedding: null, embedded_at: null, ...P(ctx, 'vault:Work/ops/parent.md#Notes2', 'vault_note') } },
    { name: 'plaankiva in routine_runs.run_key', table: 'routine_runs', expect: 'hard:regex',
      row: { routine: 'sync', run_key: 'mini:plaankiva-export:2026-11-10T09:00', host: 'mini', login_label: 'work', lane: null,
             started_at: TS, finished_at: null, exit_code: 0, status: 'ok', log_ref: 'logs/sync-3.log', ...P(ctx, 'run:mini:sync:3', 'runner_log') } },
    { name: 'plaankiva in prs.merged_to', table: 'prs', expect: 'hard:regex',
      row: { repo: 'example-org/team-hq', number: 13, title: 'merge', author_login: 'dev1', base_ref: 'main', head_ref: 'x',
             head_sha: HEAD, state: 'merged', merged_to: 'plaankiva-branch', merge_sha: 'b'.repeat(40), merged_at: TS,
             gh_updated_at: TS, ...P(ctx, 'gh:example-org/team-hq#13', 'github_api') } },
    fact('Plaankiva', 'zeusi:test/w11-5', 'ping Plaankiva', 'hard:regex'),
    fact('Plannkiva', 'zeusi:test/w11-6', 'ping Plannkiva', 'hard:regex'),
    fact('Plankkiva', 'zeusi:test/w11-7', 'ping Plankkiva', 'hard:regex'),
    fact('Plannnkiva', 'zeusi:test/w11-8', 'ping Plannnkiva', 'hard:regex'),
    fact('Aplaankiva', 'zeusi:test/w11-9', 'ping Aplaankiva', 'hard:regex'),
    fact('plankiva embedded in a longer token', 'zeusi:test/w11-10', 'see xPlaankivax-board', 'hard:regex'),
    fact('hyphenated P-l-a-a-n-k-i-v-a', 'zeusi:test/w11-11', 'cc P-l-a-a-n-k-i-v-a', 'hard:regex'),
    fact('spaced P l a a n k i v a', 'zeusi:test/w11-12', 'cc P l a a n k i v a', 'hard:regex'),
    fact('leetspeak pl4aank1v@', 'zeusi:test/w11-13', 'ping pl4aank1v@', 'hard:regex'),
    fact('fullwidth plankiva', 'zeusi:test/w11-14', 'ping \uFF30\uFF4C\uFF41\uFF41\uFF4E\uFF4B\uFF49\uFF56\uFF41', 'hard:regex'),
    fact('Cyrillic A plankiva', 'zeusi:test/w11-15', 'note for Pl\u0410ankiva only', 'hard:regex'),
    fact('zero-width space inside plankiva', 'zeusi:test/w11-16', 'note for Plaa\u200Bnkiva only', 'hard:regex'),
    fact('combining acute plankiva', 'zeusi:test/w11-17', 'note for Plaa\u0301nkiva only', 'hard:regex'),
    fact('Cherokee GO plankiva', 'zeusi:test/w11-18', '\u13E2laankiva wrote', 'hard:regex'),
    clientco(note('ClientCo note that mentions Plaankiva', 'ClientCo/clientco-erp/sync-2.md', 'ClientCo ERP sync', 'ClientCo ERP sync, then Plaankiva joined.', {}, 'hard:regex')),
    note('Northbank note that mentions Plaankiva', 'Work/product/sync-1n.md', 'Northbank sync', 'Northbank call with Plaankiva.', {}, 'hard:regex'),
    // clean names close to the letters still pass (over-block guard)
    fact('names that are not the word (0011)', 'zeusi:test/w11-19', 'plan, kiva and plankton met; a plan kiva boat', 'pass'),
    // 0011 soft lift: currency amounts and P&L / book lines are admitted, ClientCo and Northbank included.
    fact('synthetic dollar amount', 'zeusi:test/w11-20', 'list price $ 49 per seat', 'pass'),
    fact('synthetic P&L line', 'zeusi:test/w11-21', 'P&L 2025: +3.2 on the synthetic book', 'pass'),
    fact('synthetic pnl and book line', 'zeusi:test/w11-22', 'pnl 42, book 7 trades', 'pass'),
    clientco(note('ClientCo note with currency and P&L', 'ClientCo/clientco-erp/budget-2.md', 'Budget', 'CHF 1200 budget; P&L 2025 up 3%.', {}, 'pass')),
    note('Northbank note with a price', 'Work/product/price-2.md', 'Price', 'EUR 49 per seat.', {}, 'pass'),
    // kept (HQ judgement call): account / login number and IBAN stay soft
    clientco(fact('ClientCo account number still soft', 'vault:ClientCo/clientco-erp/acct.md', 'acct 1234567 is a fake number', 'soft:regex')),
  ];
}

/** A case whose row uses scope clientco (0010). */
function clientco(c: WallCase): WallCase {
  return { ...c, row: { ...c.row, scope: 'client' } };
}
