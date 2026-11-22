# Northbank standing-rule classifier (`zeusi locks classify`)

Status: built on branch `feat/session-start-gaps` (plan: `docs/plans/2026-11-18-session-start-gaps-plan.md`, U4). Offline. Not applied to any live vault or database.

## Why

`zeusi_startup` serves the **standing** rules: the current locks of notes under `STANDING_LOCK_PREFIXES` (`Work/ops/`, `Work/handbook/`), plus any lock whose note marks it with `standing_locks:` (see `docs/note-locks.md`, "Standing marker"). Northbank product locks (`Work/product/`, `Work/products/product/`, scope `product`) are none of these, so none of them appears at session start. Some are durable product rules ("never show raw venue codes"). Others are one-off PR, staging or approval decisions. Promoting all of them, or broadening the standing folders to all of Northbank, would put one-off decisions at the top of every session. The classifier proposes only the durable ones, using signals a reviewer can check.

## What it does

`zeusi locks classify --vault <root>` walks the vault offline. It uses the same walker as `locks lint`, so it never opens dot entries, symlinks, names of the walled person or seed-wall paths, and it skips hard links and files over 8 MiB. It resolves the lock lifecycle over every `Work/` note, so a supersession from any Work note counts. Then it classifies each lock item of a Northbank note. The first rule that matches decides:

| # | Rule | Decision / reason |
|---|---|---|
| 1 | the lock is superseded or expired | skip `not_current:<status>` |
| 2 | the lock is already standing (standing folder, or listed in `standing_locks:`) | `already_standing` (no change) |
| 3 | the note's `status:` is not exactly `locked` or `lock` (case-insensitive) | skip `note_status:<value>` (for example `parked`, `shipped`, `research`, `call-brief`, `approved`, `greenlit`, `locked (staging only; ...)`) |
| 4 | the lock text has one-off, time-bound or instance-specific wording (`ONE_OFF_PATTERNS`, any match) | skip `one_off:<classes>` |
| 5 | the lock text has durable, normative wording (`DURABLE_PATTERNS`, any match) | **promote** `durable:<signal>` |
| 6 | anything else | skip `no_standing_signal` |

One-off classes (rule 4; all listed in the reason when several match):

- `dated`: an ISO date, `5 Nov` / `Nov 5`, a weekday, or a clock time.
- `timebox`: the `locks lint` time-box phrases, plus until / till / today / tonight / tomorrow / for now / temporary / interim / pilot / later / this or next week / waits for.
- `pr_or_merge`: `#123`, PR, pull request, merge, branch, draft, revert, commit, or a version such as `v2` or `v2.1`.
- `event`: something that happened once, such as approved, greenlit, decided, deployed, shipped, removed, created, merged, done, kept or revised.
- `go`: `GO` or `GO'd` (upper case), go-ahead.
- `open`: a `?`, TBD, to settle, pending, proposal, idea, maybe, could or might.
- `staging`: any mention of staging.
- `scoped_to_now`: "for this ...", already, currently, right now, as of.
- `sequence`: the text starts with then, next, first, second or after that.
- `specific`: an IP address, a number of 4 or more digits (logins, accounts; not a date), a decimal, or a currency amount.
- `cross_scope`: the text names ClientCo. ClientCo work stays in scope `clientco`, and no Northbank rule is promoted on its account.

Durable signals (rule 5):

- `never_always`: never, always.
- `every_each`: every, each.
- `must_only`: must, only, mandatory, required, forbidden, prohibited.
- `prohibition`: do not / don't / does not / may not / cannot / no one, or a text starting with `No `.
- `source_of_truth`: "source of truth".

The rules favour precision over recall. A durable rule that also matches a one-off pattern stays unpromoted. It remains available through `zeusi_context_for_task` (which matches every current lock by task terms), and the owner can still mark it by hand with `standing_locks:`. Nothing is promoted from a guess (invent=NO). The constants are exported from `src/locks-classify.ts` and pinned by `test/locks-classify.test.ts`.

## Preview (dry run, the default)

```
zeusi locks classify --vault ~/KnowledgeVault            # counts, reasons, the promote list (refs only)
zeusi locks classify --vault ~/KnowledgeVault --show-text  # also the lock text (local only; redacted; the walled name withheld)
zeusi locks classify --vault ~/KnowledgeVault --json
zeusi locks classify --vault ~/KnowledgeVault --save-preview ~/classify-preview.json   # the reviewed preview (refs + file sha256)
```

The preview opens files read-only and writes nothing. Each item is reported as `<vault_path>:<ord>` (the `locks lint` ref).

## Write (`--real --from <saved preview>`: an operator step, owner GO)

```
zeusi locks classify --vault ~/KnowledgeVault --real --from ~/classify-preview.json
```

`--real` requires the preview file the owner reviewed. It classifies again and compares the result with that file: the same promote ids, and the same sha256 for every file to be written. On **any** difference (a note edited or added since the dry run, a supersession or an `until` that changed the outcome) it refuses the whole run, writes nothing and exits 1. Only on an exact match does it call `applyStandingMarkers()`. For each note with promoted locks, that function:

- re-opens the file `O_NOFOLLOW` and refuses symlinks and hard links;
- refuses a file whose bytes no longer hash to what was read;
- writes only a `standing_locks: [<ordinals>]` line into the frontmatter. An existing marker is merged in place; otherwise the line goes before the closing `---`. Every other byte is kept, and CRLF files stay CRLF. An existing marker with a non-ordinal entry is refused, never silently rewritten;
- checks, before writing, that the new frontmatter parses back to the same keys plus the marked ordinals;
- replaces the note atomically: it writes a new file in the same folder in full, then renames it over the note. A crash never leaves a truncated note.

The write set is the saved preview set: same ids, same order. Tests in `test/locks-classify.test.ts`:

- "--real marks EXACTLY the previewed set";
- "--real --from <saved preview> writes exactly that set";
- "a note edited or added after the saved dry run refuses the whole --real run". A second run writes nothing. The write touches **vault files only, never a database**. After it, the normal `zeusi ingest vault` (dry run first, then `--real` as today) carries the marker into `zeusi.notes.frontmatter`, because the file sha changed. `zeusi_startup` then serves those locks: they are ranked in scope `product` after `team`, within the token budget, or listed in `rules_remainder` (`docs/note-locks.md`). Unpromoted current locks stay available through `zeusi_context_for_task`.

To undo a promotion, delete the ordinal (or the whole `standing_locks:` line) from the note and re-ingest.

## Not done here

- No `--real` run against the live vault, and no ingest of a marker into the hosted database. The operator steps and the preview counts are in the PR body.
- ClientCo locks are not classified (report only, scope `clientco`).
