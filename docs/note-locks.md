# Note locks: rules, supersession and expiry

Status: built on branch `fix/zeusi-lock-lifecycle` (plan: `docs/plans/2026-11-17-zeusi-v2-prime-onboard.md`, addendum "Lock lifecycle"). PGlite-tested. No migration: everything is derived at read time from `zeusi.notes.frontmatter`.

## Where rules, facts and focus come from

Rules come from locks in notes (standing folders); the structured facts table is empty unless a typed import writes it; current focus comes from the HQ sync once its typed Focus block is exported.

- **Rules.** Every `locks:` item of an active note in a standing folder (`Work/ops/`, `Work/handbook/`), or one its note marks standing with `standing_locks:` (see "Standing marker"), that is **current** (not superseded, not expired), plus any `facts_current` row of kind `rule`. There is one definition, shared by `zeusi_startup` and `zeusi_onboarding_status` (`RULES_DEFINITION` in `src/onboarding.ts`).
- **Facts (`zeusi.facts`).** These are written only by typed imports: `zeusi import` / `zeusi onboard` of entries with an explicit header (`Type: rule|focus`), `ingest hq-sync` of headed HQ entries (Fix PR B), and the manual `zeusi fact add`. The vault importer writes no facts. A table that is empty in prod is expected until one of these runs.
- **Focus (`facts_current` kind `state`).** Focus comes only from `Type: focus` entries. The HQ routine change that exports the typed Focus block, and the ingest schedule for it, are both still waiting for the owner's GO (`docs/hq-sync.md`). Until then focus is empty, and `focus_message` says so and says where focus would come from. It never claims there is no focus.

## What each tool reports

| Tool | Field | Meaning |
|---|---|---|
| `zeusi_startup` | `rules` | the served standing rules, compact one-line form (see "Session start: every rule served or listed") |
| | `rules_remainder` | every other current standing rule, `{ id, origin, scope, subject, source_uri, source_ts, cite, reason }`, in rank order; `reason` is `budget` or `too_long` |
| | `rules_total` | `{ fact, note_lock, total, visible, capped }`: the whole current set; `visible` = after the output wall (`withheld` counts the rest) |
| | `rules_served`, `rules_remainder_count`, `rules_unlisted` | `rules_served + rules_remainder_count (+ rules_unlisted) = rules_total.visible` |
| | `rules_budget` | `{ tokens, used, estimate, text_max_chars }` |
| | `rules_note` | what was served, what was listed, how to look a remainder entry up |
| | `supersedes` on a rule | the ids of the locks this one replaces (their text: `zeusi_context_for_task` `history`) |
| | `expires_at` on a rule | the lock's `until`, only when one is set |
| `zeusi_onboarding_status` | `counts.rules` | the same set as `rules_total.total` |
| | `rules_by_origin` | `{ fact, note_lock }` |
| | `counts.note_locks` | every lock item of every active note (all folders) |
| | `counts.note_locks_current / _superseded / _expired` | these three add up to `note_locks` |
| `zeusi_context_for_task` | `items` | current locks (status `current`) and current decisions |
| | `history` | superseded or expired locks that match the task, with `superseded_by` (including its `cite`) or `expired_at`; not binding |

Every tool runs as the caller's read-only login inside `BEGIN READ ONLY`, so RLS decides which notes exist for the caller. At most `LOCK_NOTES_CAP` (5000) lifecycle notes are read, newest first; beyond that, `capped` is set. The hosted log gets counts only, never lock text.

## Session start: every rule served or listed

Before 18 Nov 2026 `zeusi_startup` cut the rules at 50. With 93 current standing rules, the 43 oldest were missing from the payload and only counted. Now (plan `docs/plans/2026-11-18-session-start-gaps-plan.md`, `src/startup-rules.ts`):

- **Every current standing rule is in exactly one list.** It is either served in `rules`, or listed in `rules_remainder` with lookup ids. The only exceptions are a rule the output wall withholds (counted in `withheld`, in neither list) and, beyond 2000 remainder entries, `rules_unlisted` (a count said in `rules_note`). The output wall runs on the full items, title included, **before** ranking, so a remainder entry never carries a walled id or title. Tests: `test/startup-rules.test.ts` (seeded property test, 400 cases) and `test/note-locks.test.ts` "startup U2 (reviewer check a)".
- **Ranking (stable):** fact rules first (typed, explicit); then scope `work`, `product`, `client`, then any other scope A-Z; then `source_ts` newest first. Ties keep the note order (newest note first, then in-note lock order).
- **Budget:** 16 000 estimated tokens (`STARTUP_RULES_BUDGET_TOKENS`). The estimate is `ceil(JSON characters / 4)` per served rule. Measured offline on the standing folders at about 114 tokens per compact rule [estimate], so today's 93 rules (about 10.6k) fit, with room for about 140. The served list is the longest ranked prefix that fits. Everything after the first rule that does not fit goes to the remainder (`reason: "budget"`).
- **Compact one-line form:** `{ id, origin, scope, text, source_uri, source_ts, cite }`, plus `expires_at` and `supersedes` (ids) only when set. `id` is `<source_uri>#lock-<ord>` or `<source_uri>#fact-<id>`. `text` has its whitespace runs collapsed to one space and is never cut. A text over 600 characters goes to the remainder with `reason: "too_long"` instead of being truncated. `who` (always null for a lock), `ord` (in `id`) and `subject` (in the remainder entry) are not repeated.
- **Looking a remainder entry up:** call `zeusi_context_for_task` with its `subject` (the note title, which it matches), or `zeusi_search` with the file name from its `id`. A listed rule binds exactly like a served one.
- **Read-only:** same `openRead`, read-only session check, `BEGIN READ ONLY` and RLS as before. `READ_ROLES` is unchanged.

## Standing marker (`standing_locks:`)

```
standing_locks: [1, 3]      # locks 1 and 3 of this note are standing rules (or a block list, or "1, 3")
```

- Any note can mark its own locks as standing, whatever its folder. The marker lists ordinals (1-based, as in `locks:`). An ordinal the note does not have is ignored and counted (`standing_marker_invalid`). Nothing is inferred.
- A marked lock follows the lifecycle like any other: if it is superseded or expired, it is not served.
- `STANDING_LOCK_PREFIXES` stays `Work/ops/`, `Work/handbook/`. Northbank locks become standing only through this marker. `zeusi locks classify` proposes the marker from a documented classifier, with a dry-run preview and an exact write (`docs/locks-classifier.md`). Unmarked current locks are still returned by `zeusi_context_for_task` for a matching task.
- Read at query time from `notes.frontmatter` (`src/lock-lifecycle.ts`, `STANDING_MARKER_KEY`); no migration. The marker reaches Zeusi through the normal `zeusi ingest vault` (the file sha changes).

## Grammar

All keys are flat and parser-friendly: a YAML list, or a single string where noted. Quote list items that start with a digit and a colon.

### `supersedes:` (a list, or one string)

```
supersedes:
  - "[[2026-10-29-workstation-alpha-assistant-3-weekly-notes]] lock 2"
  - "[[Work/handbook/old-note]]"
  - "1: [[2026-09-01-other-note]] lock 3"
```

- **Shape:** `[<own ord>:] [[<target>]] [lock <N>]`. `locks <N>` is accepted too. A `|alias` or `#heading` inside the link is ignored.
- **Target:** the note whose `vault_path` (with or without `.md`), file name without `.md`, or title equals the target, ignoring case. Exactly one match among the caller's visible lifecycle notes is required. Zero matches, more than one match, or a `lock N` the target doesn't have counts as `supersede_unresolved`. Nothing is guessed. Give the full vault path to disambiguate.
- **Lock or note:** `lock N` (1-based, as in the `locks:` list) supersedes that one lock. Without it, the claim covers every lock of the target note.
- **Superseding side:** `<own ord>:` says which of this note's locks replaces the target; that lock carries `supersedes`. Without the prefix the claim belongs to the whole note, and every lock of the note carries it. A note with no locks of its own can still retire locks; it is then cited by title.
- **Newer only:** the superseding note's `source_ts` must be strictly newer than the target's. Otherwise the claim is ignored and counted as `supersede_invalid`, and so are malformed items, self claims and an `<own ord>` the note doesn't have.
- **Chains:** only the newest lock in a chain is current. Each superseded lock points one step forward (`superseded_by`), and each superseding lock one step back (`supersedes`).
- **Visibility:** if the caller can't see the superseding note (RLS), the claim doesn't exist for that caller and the old lock stays current.

### `lock_until:` (a list, or one string) and `until:`

```
lock_until:
  - "1: 2026-10-25T00:00+02:00"
  - "2: 2026-10-24"
until: 2026-10-24
```

- **Values:** `<ord>: <until>`, where `<until>` is an ISO timestamp **with an offset** (or `Z`), or a date `YYYY-MM-DD`. A date means the end of that day in Europe/Zurich, which is 00:00 of the next day there. Example: `2026-10-24` becomes 2026-10-25T00:00+02:00. On the DST day, `2026-10-25` becomes 2026-10-26T00:00+01:00.
- **End-exclusive:** a lock is expired when `now >= until`.
- **`until:`** applies to every lock of the note. A `lock_until` entry for an ordinal wins over it.
- **Invalid entries:** a timestamp without an offset, an impossible date or an ordinal the note doesn't have counts as `until_invalid`. Such a lock stays current.
- **Precedence:** a lock that is both superseded and past its `until` counts as superseded.

## Parser notes (vault frontmatter)

`src/importers/vault.ts` `parseFrontmatter` deliberately deviates from strict YAML in two ways:

- A `#` starts a comment only at the start of a value, or after whitespace, AND only when whitespace or the end of the line follows it (`# comment`). So `Close #1157`, `#tag` and `C#` stay text. Inside quotes a `#` is always text.
- A `- ` list item whose following lines are indented deeper continues onto those lines. They are joined with one space into ONE item.

The old parser (frozen in `src/importers/frontmatter-legacy.ts`, used only by lint) stored `Close #1157; ...` as `Close`.

## CLI

- `zeusi locks lint --vault <root> [--all] [--json]` is offline and read-only. It parses the standing folders (with `--all`, every `Work/` folder) with the old and the new parser. Walled and Plankiva paths are never opened.
  - It prints counts, plus the changed items as `vault_path:ord` with the old and new text. The lock text is the owner's own words; it is printed locally only and never logged by the hosted server.
  - It also prints the lifecycle resolution counts and two candidate lists for a human to confirm. Nothing is applied. The two lists are:
    - same-subject pairs: shared distinctive terms, newer vs older, standing folders only;
    - locks whose text has time-box language but no `lock_until`.
- `zeusi ingest vault --reparse-frontmatter [--scope <s>] [--config <f>] [--real [--service <name>] [--i-know-this-is-main]]` is a DRY RUN by default. The normal importer skips files whose sha is unchanged, so a parser fix alone never re-parses stored frontmatter.
  - This command re-parses the frontmatter of unchanged files and, with `--real`, updates ONLY `notes.frontmatter`. Bodies, chunks and embeddings are untouched, and nothing is inserted or deleted.
  - Same gates as the importer: path gate, content wall, the `zeusi_90_wall` trigger and secret redaction.
  - Same guards: `zeusi_ingest`, DIRECT endpoint, `assertIngestReady`, the main-branch guard, and the vault importer's advisory lock.
  - Output: counts only (notes scanned, frontmatter changed, lock items before/after, current/superseded/expired before/after).
