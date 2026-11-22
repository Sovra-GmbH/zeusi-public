# The Zeusi wall

PLAN.md KTD7, R8–R10, U4. The Plankiva hard rule comes from the owner, 14 Nov 2026 14:17 Zurich. **15 Nov 2026 01:09 Zurich (the owner): "Plankiva" (one n) IS Plankiva, and the soft currency and P&L rules are lifted** (migration `0011_wall_name_variants_soft_lift.sql`, see "0011" below).

**The rule since 14 Nov 2026 19:12 Zurich (the owner, rule owner-rule): ClientCo and Northbank work goes INTO Zeusi, each in its own section. ONLY Plankiva stays out.** Migration `0010_wall_client_admit.sql` applies it:

- **ClientCo is admitted.** The six hard rules that blocked on the ClientCo name are deleted (see "0010" below). ClientCo notes are read from their own vault folder (`ClientCo/`) and stored with the new scope `clientco`. Northbank keeps its scope `product`.
- **Plankiva stays out, with no Plankiva provisions.** There is no Plankiva folder, scope, namespace, tag, config entry or example. Every Plankiva exclusion rule is kept unchanged. 0010 adds one more hard rule for spellings with separators or leetspeak, and **0011** adds a hard rule for "Plankiva" and its variants (repeated letters, separators, leetspeak, look-alikes; no `wall_allow`, ever). An Plankiva or Plankiva signal inside a ClientCo folder, lane or repo is still a hard block.
- **0011 lifts the soft currency rule and the soft P&L / book rule** (the owner), so ClientCo and Northbank notes with amounts or P&L lines are admitted, each in its own scope.
- **What is not lifted** (after 0011):
  - **Every credential and secret guard.** No rule that guards a credential, token, 2FA code or password is touched: 0011 deletes exactly two soft content rules and adds one hard rule; every other rule is byte-identical, with the same id (test `0011 upgrade from a 0010 database`).
  - **HQ judgement calls, kept and reported to the owner** (the owner named only the two soft rules): the soft account / login-number rule (id 34), the soft IBAN rule (id 35), the hard repo rule `example-org/agent-config-backup*` (id 30, it guards agent-config credentials), and the hard desk P&L path / lane rules `**pnl**` (13), `**p&l**` (14), the paths of the two named desk P&L lanes (21, 22), lane `*pnl*` (25) and the two named desk P&L lanes (23, 24). What each one still blocks of ClientCo / Northbank is in "0011" below. Each is a decision for the operator.
  - The area rules (`raw/`, `bot-staged/`, `personal/`, `canvas/`, `bases/`, `.obsidian/`, `Work/intake/`, `Work/ops/attic/`, the staging copies), the undecoded-escape rule, and every Plankiva rule.

## Three layers

1. **Type.** `zeusi.scope` is `team`, `product`, `clientco` (0010) and `personal`. It has no Plankiva value. `personal` is never written in v1 and is hidden from every reader.
2. **Row.** The `zeusi_90_wall` trigger runs on all 9 content tables and calls `zeusi.wall_eval()` (0007, replaced in place by 0008 and 0009). `src/wall.ts` gives the same verdict in TypeScript. Importers call `wallGate()` first and quarantine a blocked item before anything is sent. The trigger is the backstop.
3. **Grant.** Only the owner writes `wall_denylist`, `wall_allow`, and `quarantine`. Writers record blocked items only through `zeusi.quarantine_record()`, which stores uri and hashes, never text. RLS hides `personal` from every reader.

## Verdict order

The first rule that matches wins. The order is the same in SQL and TS.

| Stage | Rules | Text checked | wall_allow? |
|---|---|---|---|
| 1 | hard `path_glob`, `lane`, `repo` (by id) | path candidates: uri path, `vault_path`, `review_ref`, `log_ref`. Lanes: `lane`, `lane:` / `lanes/` in the uri, `applies_to`. Repos: `repo`, `linked_repo`, `gh:` uri, `applies_to`. **0008:** each candidate also in its percent-decoded form (uri and paths) and its normalised form | never |
| 2 | hard `tag` (by id) | frontmatter `tags` and `tag` (list or string), plus inline `#tags` in the checked text. A tag matches when it contains the pattern (case-insensitive). **0008:** or when its normalised form contains the normalised pattern; inline `#tags` are also read from the normalised text | never |
| 3 | hard `regex` / `term` (by id) | the checked text, **plus** `source_uri`, the decoded uri, `prs.merged_to`, `routine_runs.run_key`, `chunks.embed_model` (0008), and every path, lane, and repo candidate. **0008:** raw text OR its normalised form. **0009:** plus the marker `zeusi-wall:undecoded-percent-escape` when a decoded uri / path still holds a `%XX` escape | never |
| 4 | soft `regex` / `term` (by id) | the checked text (`zeusi.wall_content`) | only a row pinned to (source_uri, content_sha256, rule_id) |

The "checked text" depends on the table:

- notes: title, body, frontmatter
- chunks: heading path, text
- prs: title, author, refs
- facts: subject, text
- decisions: exact words, expiry rule, job
- episodes: actor, summary, links
- people: handle, display name, GitHub login
- routine_runs and pr_reviews: their reference columns

The checked text (`zeusi.wall_content`) is what `wall_allow` pins, and 0008 does not change it. The extra free-text columns of 0008 (`merged_to`, `run_key`, `embed_model`) are only in the hard text, so existing content hashes and allow pins stay valid. Every other text column of the content tables is either in the checked text, a path / lane / repo candidate, or constrained by a CHECK to a fixed set (`kind`, `status`, `host`, `org`, `said_at_precision`, enums). `ingested_by` is stamped by the server.

## Normalisation and decoding (0008, review r1)

The hard rules also match a normalised form of the text, so invisible or look-alike characters do not slip past them. `zeusi.wall_norm()` in SQL and `wallNorm()` in `src/wall.ts` do the same steps:

1. Strip Default_Ignorable and format (Cf) code points: zero-width space / joiners, soft hyphen, word joiner, bidi controls, BOM, variation selectors, tag characters (U+E0000–E0FFF), Hangul fillers and others. The list is `WALL_IGNORABLE_RANGES`.
2. NFKD, then strip ignorables and combining marks (U+0300–036F and the other combining blocks), so `Ä` becomes `A`.
3. NFKC, so fullwidth `Ａ`, circled `Ⓐ` and mathematical `𝐀` become `A`. Then strip ignorables again.
4. Apply confusable folds for letters used by the seed hard terms to ASCII (`WALL_CONFUSABLES`). For example Cyrillic `А`/`а`/`і`/`к`, Greek `Α`/`ι`/`κ`/`ν`, palochka `Ӏ` → i. **0009** (review r2) adds Cherokee capitals and their small forms (`Ꭺ`/`ꭺ` → a, `Ꮯ` → c, `Ꮐ` → g, `Ꭵ` → i, `Ꮶ` → k, `Ꮮ` → l, `Ꮲ` → p, `Ꮩ` → v) and Lisu (`ꓮ` → a, `ꓚ` → c, `ꓖ` → g, `ꓲ` → i, `ꓗ` → k, `ꓡ` → l, `ꓠ` → n, `ꓑ` → p, `ꓦ` → v).
5. Lower-case ASCII only, the same on both sides.

The normalised form is used only for matching. Nothing stored changes.

`zeusi.pct_decode()` / `pctDecode()` decode `%XX`, repeated until the text stops changing (at most 8 rounds, so `%2541` → `%41` → `A`). `%00` is never decoded. If the decoded bytes are not valid UTF-8, only the ASCII escapes are decoded. The uri and the path columns are matched raw **and** decoded.

**Left-over escapes (0009, review r2).** If the decoded uri, `vault_path`, `review_ref` or `log_ref` still contains a `%XX` escape, the row is a hard block. The hard `term` rule `zeusi-wall:undecoded-percent-escape` matches a marker that `wall_eval()` / `wall.ts` add to the hard text. This happens with more than 8 levels of encoding, with `%00`, and with escapes whose bytes are not valid UTF-8 (which could otherwise hide an encoded look-alike). `%` that is not followed by two hex digits (`100%`, `%zz`) is not an escape. `%XX` in body text is not decoded and does not trigger the rule. The vault dry run gives 0 hits for it.

**Config and importer paths.** `validateSources()` and the importer gate `sourcePathGate()` (`src/sources.ts`) apply the same decoding and normalisation to the Plankiva check. They also resolve symlinks: an existing root, the literal prefix of every include (up to its first glob segment), and every file the gate is asked about are checked on the logical path **and** on the real path. A symlink from `~/KnowledgeVault` into `~/PlankivaVault/requests/` is refused.

**Not covered** (documented limits, all hard to do without over-blocking):

- Separators and leetspeak are covered since 0010 (and for "Plankiva" and its variants since 0011), with one exception: a single whitespace break inside the word (`Plan kiva`, `Plank iva`). Matching it would also block ordinary phrases such as "plan kiva boat". Leetspeak covers only `a` → `4` / `@` and `i` → `1` / `!` / `|`. Other substitutions (`|<` for k, `/\/` for n) are not covered.
- HTML character references (`&#80;lankiva`, `&#x50;lankiva`, named entities) and base64. Markdown viewers such as Obsidian render the references as the plain name, so this matters for the Zeus HQ export (`docs/hq-sync.md`), which inherits the limit unchanged (review C r1 m5). 0010 and 0011 did not add this; suggested hardening for `mentionsProtectedName`: decode `&#NN;`, `&#xNN;` and named references before matching.
- Look-alikes outside the fold list (other scripts, letters not in the hard terms). The list is explicit; it is not the full Unicode confusables table.
- More than 8 levels of percent-encoding are not decoded (the round bound). Since 0009 such a value is a hard block instead of a silent pass, so the bound limits what is *decoded*, not what gets through.
- Text inside images or attachments. Zeusi stores no binaries.
- The soft content rules (account / login number and IBAN since 0011) match the raw text only.

## Plankiva

the owner's rule covers all Plankiva content in Zeusi, including `PlankivaVault/requests/`. The earlier `requests/` exception is revoked. The 19:12 ClientCo lift (owner-rule) changes nothing here.

- **(a) Paths, lanes, repos.** The existing rules already cover every case: `**plankiva**`, `plankiva/**`, `~/PlankivaVault/**`, `**/PlankivaVault/**`, lane `*plankiva*`, repo `*plankiva*`, and `~/.assistant/memory/plankiva*`. Tests cover `~/PlankivaVault/requests/...`, absolute `.../PlankivaVault/requests/...`, mixed case, and `plankiva/requests/...`.
- **(b) Tags.** A hard `tag` rule with pattern `plankiva` (0006 adds the kind, 0007 seeds the rule).
- **(c) Content.** A hard `term` rule with pattern `plankiva`. It matches the substring anywhere in the checked text, the uri (including its `#fragment`), or any identifier. **0010** adds a hard `regex` rule for the same word with separators between its letters or with leetspeak (`PROTECTED_SPELLING_REGEX` in `src/wall.ts`):
  - up to 3 non-alphanumeric, non-space characters between letters: `Plan-kiva`, `P.l.a.n.k.i.v.a`, `**Plan**kiva`, `PLAN_KIVA`;
  - 1 to 3 non-alphanumeric characters, spaces allowed, between **every** pair of letters: `P l a n k i v a`, `p - l - a - n - k - i - v - a`;
  - `a` as `4` / `@` and `i` as `1` / `!` / `|`: `pl4nkiva`, `pl@nk1va`, fullwidth `ｐｌ４ｎｋｉｖａ` (after `wall_norm`).

  Like every hard regex, it is matched on the hard text (checked text, uri, paths, lanes, repos), raw and normalised. That covers frontmatter tags, inline `#tags` and path names too. It is checked after the `plankiva` term (higher id), so the plain word is still reported as the term rule.
- **(d) "Plankiva" IS Plankiva (0011, the owner 15 Nov 2026 01:09).** A hard `regex` rule (`PROTECTED_VARIANTS_REGEX`, id 41 on a fresh database) for the letters p l a n k i v a with each letter written 1 to 3 times: `Plankiva`, `Plaankiva`, `Plankkiva`, `Plannnkiva`, `Pplankiva`, any case; `a` as `4` / `@`, `i` as `1` / `!` / `|`; with the two separator forms of 0010 (`P-lankiva`, `P.l.a.n.k.i.v.a`, `**Plan**kiva`, `P l a n k i v a`). There is **no start anchor**: the letters inside a longer token block too (`xPlankivax`, `Plankivas`). Like every hard regex it is matched over the hard text (checked text, uri raw and decoded, paths, lanes, repos, free-text columns), raw and normalised, so it acts at path, lane, repo, tag (frontmatter and inline), text and `source_uri` level, and fullwidth, Cyrillic / Greek / Cherokee / Lisu look-alikes, zero-width and combining characters fold in. It is a superset of the 0010 spelling regex; the older rules stay and keep their ids. `mentionsProtectedName()` (config validation, the importer path gate, the dry-run proof) uses it too. Accepted over-blocks: common words that embed the letters, for example `mechplankiva`, `botplankiva`, `titplankiva`, `Pplankivattacke`, `orgplankiva`. Run the false-positive scan below on your own vault before you rely on the rule.
- **None of these can be overridden.** The `wall_allow` guard refuses hard rules (ZW002). `zeusi wall allow` refuses them offline, before it connects. 0007 hardens any soft `plankiva` term that already exists and deletes allows that point at hard rules.
- **Config.** `loadSources()` refuses any string containing `plankiva`, including names, excludes, and `.../requests/`. Since 0010 this also covers the separator and leetspeak spellings (`mentionsProtectedName()` uses the same regex), since 0011 "plankiva" and every variant of the 0011 rule, and the same applies to the importer's path gate. `config/sources.example.toml` does not contain the word.
- **Zeus HQ export (source side).** `zeusi export-filter` applies the same exclusion before anything reaches the Zeusi source folder. It builds its rules from this wall: the hard rules whose normalised pattern names the person, plus the undecoded-escape rule, compiled by `compileWall`. It adds `mentionsProtectedName()`, the `requests/` family and credential shapes. It withholds single H2 entries, using a content-free marker line, and drops whole notes when the path or frontmatter trips. It re-checks its own output and refuses when anything is found. It never follows a symlink below `--out` (exit 4). It inherits this wall's "Not covered" list unchanged. The importer's wall stays the backstop. Details: `docs/hq-sync.md`.
- **Removing ClientCo cannot weaken Plankiva.** Tests cover a note that mentions both ClientCo and Plankiva (blocked by the term rule), an `plankiva` file and an `PlankivaVault/requests/` path under `ClientCo/`, mixed-case and (double) percent-encoded Plankiva names under `ClientCo/`, a `clientco` lane with `plankiva-...` in `applies_to`, `clientco` `applies_to` with an `plankiva` linked repo, a `clientco-PLANKIVA` lane, and a `clientco-plankiva-...` repo. All are hard blocks in `wall.ts`, `wall_eval()` and the trigger (`test/fixtures/wall/cases.ts`, `test/wall-0010.test.ts`, `test/vault-import.test.ts`).

### Dry run on your vault

`npm run wall:dryrun -- --vault ~/KnowledgeVault --sub Work` reads files read-only and prints counts only. It never prints paths or text. It uses the seed rules and parses frontmatter approximately. Run it on your own vault before you apply a wall migration, and treat the counts as a review queue: anything the soft rules quarantine is for you to allow or leave out.

## 0010: ClientCo and Northbank admitted (owner rule)

**Rules lifted** (deleted by `(kind, pattern)`; ids are those of a fresh database):

| id | kind | pattern |
|---|---|---|
| 1 | path_glob | `ClientCo/**` |
| 11 | path_glob | `**clientco**` |
| 26 | lane | `*clientco*` |
| 28 | repo | `example-org/clientco-*` |
| 29 | repo | `example-org/*clientco*` |
| 32 | repo | `*/*clientco*` |

ClientCo had no tag, term or regex rule. `wall_eval()`, `wall_norm()`, `pct_decode()`, `wall_content()` and `wall_audit()` have no ClientCo logic in their bodies, so 0010 does not replace them: the verdict order, the normalisation (including the v / c / g look-alike folds), the undecoded-escape marker and every Plankiva rule stay byte-for-byte as in 0009. `wall_allow` rows pinned to a lifted rule are removed by `ON DELETE CASCADE`; none can exist, because the guard refuses allows on hard rules. Quarantine rows that named a lifted rule keep their uri and hashes, and their `rule_id` becomes NULL (`ON DELETE SET NULL`). Path-hash quarantine rows (`vault-path-sha256:...`) can never collide with an admitted note in `wall audit`.

**Kept on purpose:** repo `example-org/agent-config-backup*` (id 30, reason "agent config backups (client-walled)"). It walls backups of agent configuration, which may hold credentials. It is not a rule on the ClientCo name. **Decision for the operator:** lift it or keep it.

**Scope `client`.** `ALTER TYPE zeusi.scope ADD VALUE 'client'`. `zeusi migrate` runs each file in one transaction, and Postgres cannot use a new enum value in the transaction that adds it. So 0010 never casts `'client'` to `zeusi.scope`: the read policy compares `scope::text IN ('work', 'product', 'client')`. A PGlite test runs 0010 through `migrate()` on a 0009 database, then inserts and reads `client` rows as every role. The writer policies (`scope <> 'personal'`, 0005) already admit `client`. The importer maps the `ClientCo/` folder (case-insensitive) or a source with `scope = "client"` to `client`. `config/sources.example.toml` has a `vault-client` source (`ClientCo/**/*.md`). Real ingest (`--real`) is refused until 0010 is applied.

**Check after applying** (owner, read-only): `SELECT id, kind, hard, pattern FROM zeusi.wall_denylist WHERE pattern ~* 'client'` must return 0 rows. A rule the owner added by hand is never deleted by 0010; this query shows any such rule.

### Dry run: 0009 wall vs 0010 wall

`npm run wall:dryrun -- --vault ~/KnowledgeVault --compare-old` runs the **vault importer's own pipeline** offline: `importVault` dry run, with `sourcePathGate` plus the hard path rules on every directory and file, and the wall check on every note and chunk. It runs once with the 0009 wall (`legacySeedWall()`) and once with the 0010 wall. It reads files read-only, prints counts and rule ids only, and never touches a database. Production is not read.

Use it to confirm, on your own tree, that ClientCo notes are admitted, that no Plankiva signal is admitted (`RESULT: FAIL` if the proof is non-zero), and that anything still quarantined by a soft rule is a review queue (`wall report`, then `wall allow` per exact hash). Nothing already quarantined is admitted by applying 0010 alone: quarantined items are not re-read until the importer runs again.

## 0011: "Plankiva" IS Plankiva; soft currency and P&L lifted (the owner Zurich)

`migrations/0011_wall_name_variants_soft_lift.sql`. 0011 replaces no function (`wall_eval`, `wall_norm`, `pct_decode`, `wall_content`, `wall_check`, `wall_audit` stay as in 0009, so the verdict order, the normalisation and fail-closed behaviour are unchanged) and touches no type, policy or grant.

**Added:** one hard `regex` rule, the Plankiva variants rule (see "Plankiva" (d); `PROTECTED_VARIANTS_REGEX` in `src/wall.ts`, id 41 on a fresh database). It can never be allowed (ZW002) or softened (ZW002). 0011 also deletes any `wall_allow` row that points at a hard rule, like 0007, 0009 and 0010.

**Lifted** (deleted by `(kind, pattern)` and only while soft; ids are those of a fresh database):

| id | kind | pattern |
|---|---|---|
| 33 | regex (soft) | `(USD\|EUR\|CHF\|GBP\|JPY)[ ]?[0-9]\|\$[ ]?[0-9]` (currency amount) |
| 36 | regex (soft) | `(p&l\|\mpnl\M\|\mbook\M)[^\n]*[0-9]` (P&L / PnL / book line with digits) |

**FK effects.** `wall_allow` rows pinned to the two rules are removed by `ON DELETE CASCADE`. **0011 deletes no `quarantine` row** (the owner's order allows no delete beyond the Plankiva retraction). `quarantine.rule_id` is `ON DELETE SET NULL` (0003), so deleting the rules cannot fail on that FK (checked on PGlite): their quarantine rows stay, with their uri and hashes and `rule_id` NULL. Content-quarantined notes keep such rows (a note row plus a row per blocked chunk), with `vault:` uris, not path hashes. The rows hold no content (uri and hashes only).

**What the audit does with them** (measured, `test/wall-0011-stale-quarantine.test.ts`). Right after 0011 nothing collides: `wall_audit()` = 0. After a re-ingest admits the same content at the same hash, `wall_audit()` reports every such row as `quarantined (uri, sha) present in content` (note row and chunk rows; in the test 4 rows, notes 2 + chunks 2, for 2 admitted notes), so `wall audit` exits 1 and `ingest vault --real` exits 1 with the OWNER ACTION NEEDED line. A row whose content is still blocked by another rule is re-pinned to that rule by the next run (`quarantine_record` upserts on (uri, sha)) and is not flagged. Nothing clears the flagged rows by itself: the importer only upserts quarantine rows, the audit only reads, and no `wall_allow` can match a NULL `rule_id`.

**Cleanup: separate owner SQL, waiting for the owner's yes.** `scripts/owner-sql/quarantine-lifted-rules.sql` (outside `migrations/`, so `migrate` never applies it). Run it as the owner only after the owner's explicit yes, after 0010 + 0011 and the re-ingest. Step 1 is a count-only dry run (by target table); step 2 deletes inside `BEGIN`, prints the deleted count and the audit count, and is committed by hand only if the count equals step 1. It deletes exactly the quarantine rows that are all of: (a) `rule_id IS NULL` (their rule was deleted; after `SET NULL` the original id is gone, so this also covers rows of a 0010 lift; those are path-hash rows and never match (b)); (b) the same (uri, sha) is stored as content (the audit's own join: same `source_uri`, and the same `source_sha256` or content sha); (c) that stored row passes the live wall (`wall_eval` returns no rule). Rows with a rule id, path-hash rows and NULL rows whose content is not stored stay. Tested on PGlite (same test file): it deletes the 4 flagged rows, the audit goes to 0 and the exit code to 0; the kept rows stay.

**Re-runnable.** A second run changes nothing (test). A rule with the Plankiva pattern added earlier by hand is hardened.

**Readiness gate.** `ingest vault --real` (`assertIngestReady`) now requires 0006-0011: the hard Plankiva rule present and neither lifted rule present while soft, besides every seed rule (SEED_RULES).

**Check after applying** (owner, read-only):

```sql
SELECT id, kind, hard FROM zeusi.wall_denylist WHERE NOT hard ORDER BY id;   -- 2 rows: 34, 35 (account number, IBAN)
SELECT id, hard FROM zeusi.wall_denylist WHERE kind = 'regex' AND reason LIKE 'the name plankiva%';   -- 1 row, hard
SELECT count(*) FROM zeusi.wall_audit();   -- before the retraction: the Plankiva rows already stored (3 notes expected)
```

### Rules kept on purpose (HQ judgement calls), and what they still block

the owner named only the two soft rules, so HQ kept the rules below and reports what they block. "Alone" = ClientCo / Northbank notes the rule blocks on its own (importer dry run with only that rule; notes the importer refuses without any rule are not counted). "Only blocker" = notes that would be admitted if only that rule were lifted (dry run with every 0011 rule except it). Full vault plus `vault-client`, 15 Nov 2026:

| Rule (fresh-DB id) | clientco alone / only blocker | product alone / only blocker |
|---|---|---|
| soft account / login number (34) | 0 / 0 | 7 / 6 |
| soft IBAN (35) | 0 / 0 | 0 / 0 |
| hard repo `example-org/agent-config-backup*` (30) | 0 / 0 | 0 / 0 |
| hard path `**pnl**` (13) | 0 / 0 | 3 / 3 (path entries) |
| hard path `**p&l**` (14) | 0 / 0 | 0 / 0 |
| hard paths of the two desk P&L lanes (21, 22) | 0 / 0 | 0 / 0 |
| hard lane `*pnl*` (25), lanes `desk-pnl` (23), `session-pnl` (24) | 0 / 0 | 0 / 0 |

Lanes and repos are not vault notes, so the lane and repo rules block no vault note; they act on lane, episode, decision and PR rows.

### False positives of the Plankiva rule (measured before seeding, read-only, count-only)

`npm run wall:dryrun -- --plankiva-fp ~/KnowledgeVault --plankiva-fp ~/agent-runner/lanes`. "Rule-only" = files the rule matches (path or text; raw, decoded or normalised) where no pre-0011 Plankiva term matches (the term `plankiva` or the 0010 spelling regex). Tokens are the matched word only. Run this on your own folders and review any rule-only token that is not the protected name itself (accepted over-blocks such as `mechplankiva`).

### ReDoS

Every quantifier in the rule is bounded (`{0,2}`, `{0,3}`, `{1,3}`), so matching is linear. `test/wall-0011.test.ts` times 20 adversarial near-miss inputs (runs of `@`, `@!|`, `a-`, separated letters that end one letter short, ...) at 100k and 400k characters: worst case **JS 36 ms, Postgres 6 ms** for the regex; the full verdict on a 400k-character near-miss row takes JS 38 ms and Postgres (`wall_eval`) 344 ms. The test fails above 1.5 s (JS) / 3 s (PG).

### Dry run: 0010 wall vs 0011 wall

`npm run wall:dryrun -- --vault ~/KnowledgeVault --compare-old` (offline reconstruction, the importer's own pipeline, count-only; production is not read). Use it to confirm that the 0011 variants rule blocks every form you care about, that the lifted currency and P&L rules admit the notes you expect, and that the independent Plankiva proof stays at 0 (`RESULT: FAIL` otherwise). Anything newly blocked that was already ingested must be retracted (below). Applying 0011 alone does not re-read quarantined items.

### Retraction of Plankiva rows already ingested (documentation only; the operator runs it)

Not part of a migration. 0011 stops new Plankiva rows; any rows already ingested stay stored until you retract them. Where note text lives (from `0001_core.sql`):

- `zeusi.notes`: `title`, `body`, `frontmatter`, `vault_path`, `source_uri`.
- `zeusi.chunks`: `text`, `heading_path`, `embedding` (halfvec, NULL today), `tsv` (generated from the text), `source_uri` (`vault:<path>#c<n>`). `note_id` is `ON DELETE CASCADE`, so deleting a note deletes its chunks, embeddings and tsv.
- `zeusi.facts`, `decisions`, `episodes`, `prs`, `pr_reviews`, `routine_runs`, `people`: their own text, and a `source_uri` that can point at a note (`vault:<path>` or `vault:<path>#...`). Chunks of facts / decisions / episodes cascade too.
- `zeusi.quarantine` and `zeusi.wall_allow`: no text, but a content-quarantine uri is `vault:<path>` and can carry the name in the path (path-gated rows are `vault-path-sha256:<hash>`).
- `zeusi.ingest_runs.counts`, `backup_runs`, `embed_usage`: numbers only.
- Outside the tables: `pg_dump` files made by `zeusi_backup` before the retraction, and database history (point-in-time restore window, branches) still hold the rows. **Decision for the operator.**

After 0011 is applied, `zeusi.wall_audit()` lists every stored row the live wall rejects, by table and id. The retraction deletes the rows it reports for an Plankiva rule, then rows that point into a retracted note, then quarantine / allow rows whose uri carries the name. Run it as the owner, in one transaction, and read the counts before `COMMIT`. A foreign key error (for example a fact whose `superseded_by` points at a retracted fact, or a decision by a retracted person) aborts the transaction with nothing deleted; resolve that row by hand. `test/exclusion-scan.test.ts` runs this exact block on PGlite against synthetic rows.

```sql
-- zeusi:retraction-0011 (owner, after 0011 is applied)
BEGIN;
CREATE TEMP TABLE plankiva_rules ON COMMIT DROP AS
  SELECT id, kind::text AS kind, pattern FROM zeusi.wall_denylist
   WHERE hard AND (pattern ILIKE '%plankiva%' OR reason ~* 'plankiva');
CREATE TEMP TABLE plankiva_rows ON COMMIT DROP AS
  SELECT a.table_name, a.row_ref, a.source_uri
    FROM zeusi.wall_audit() a JOIN plankiva_rules r ON a.problem = 'hard rule ' || r.id || ' (' || r.kind || ')';
SELECT table_name, count(*) FROM plankiva_rows GROUP BY 1 ORDER BY 1;   -- review before COMMIT
DELETE FROM zeusi.chunks t USING plankiva_rows x WHERE x.table_name = 'chunks' AND t.id = x.row_ref::bigint;
DELETE FROM zeusi.notes t USING plankiva_rows x WHERE x.table_name = 'notes' AND t.id = x.row_ref::bigint;
DELETE FROM zeusi.pr_reviews t USING plankiva_rows x WHERE x.table_name = 'pr_reviews' AND t.id = x.row_ref::bigint;
DELETE FROM zeusi.prs t USING plankiva_rows x WHERE x.table_name = 'prs' AND t.repo || '#' || t.number = x.row_ref;
DELETE FROM zeusi.routine_runs t USING plankiva_rows x WHERE x.table_name = 'routine_runs' AND t.id = x.row_ref::bigint;
DELETE FROM zeusi.episodes t USING plankiva_rows x WHERE x.table_name = 'episodes' AND t.id = x.row_ref::bigint;
DELETE FROM zeusi.facts t USING plankiva_rows x WHERE x.table_name = 'facts' AND t.id = x.row_ref::bigint;
DELETE FROM zeusi.decisions t USING plankiva_rows x WHERE x.table_name = 'decisions' AND t.id = x.row_ref::bigint;
DELETE FROM zeusi.people t USING plankiva_rows x WHERE x.table_name = 'people' AND t.id = x.row_ref::bigint;
-- rows that point into a retracted note
DELETE FROM zeusi.facts t USING plankiva_rows x
 WHERE x.table_name = 'notes' AND (t.source_uri = x.source_uri OR t.source_uri LIKE x.source_uri || '#%');
DELETE FROM zeusi.decisions t USING plankiva_rows x
 WHERE x.table_name = 'notes' AND (t.source_uri = x.source_uri OR t.source_uri LIKE x.source_uri || '#%');
DELETE FROM zeusi.episodes t USING plankiva_rows x
 WHERE x.table_name = 'notes' AND (t.source_uri = x.source_uri OR t.source_uri LIKE x.source_uri || '#%');
-- uri-only tables: a uri that carries the name (raw, decoded or normalised)
DELETE FROM zeusi.wall_allow t USING plankiva_rules r
 WHERE r.kind IN ('regex', 'term')
   AND (t.source_uri ~* r.pattern OR zeusi.wall_norm(zeusi.pct_decode(t.source_uri)) ~* r.pattern);
DELETE FROM zeusi.quarantine t USING plankiva_rules r
 WHERE r.kind IN ('regex', 'term')
   AND (t.source_uri ~* r.pattern OR zeusi.wall_norm(zeusi.pct_decode(t.source_uri)) ~* r.pattern);
SELECT count(*) AS left_over FROM zeusi.wall_audit() a JOIN plankiva_rules r ON a.problem = 'hard rule ' || r.id || ' (' || r.kind || ')';   -- must be 0
COMMIT;
```

The `term` rows match by regex here only because their pattern (`plankiva`) is a plain word. Then, as `zeusi_backup`: `node scripts/exclusion-scan.ts zeusi_backup` must print `RESULT: 0 matching rows` (it also checks `ingest_runs`, `backup_runs`, `embed_usage` and every other table it can read).

## Commands

- `zeusi wall report [--since-days n]`: quarantined items by uri, rule id, and hash. Runs as `zeusi_mini_ingest`.
- `zeusi wall audit`: must return 0 rows, and exits 1 otherwise. It re-checks every content row with `wall_eval()`. It also reports any quarantined (uri, source sha) or (uri, content sha) found in content, unless the owner pinned a `wall_allow` for exactly that quarantined content. Runs as `zeusi_mini_ingest` or `zeusi_mini_backup`. The CLI prints table, row id and problem only, never the uri (a vault uri is a path and may carry a word a later rule walls; U5 review r1). The uri stays available to the owner via `SELECT * FROM zeusi.wall_audit()` over the owner URL.
- `zeusi wall allow <uri> <content-sha256> [--rule id]`: owner only. It pins one content hash for one **soft** rule. It is refused for hard rules, for uris that hit a hard rule, and for unknown hashes without `--rule`.
- `node scripts/exclusion-scan.ts <service>` (0011): read-only, count-only. Plain `SELECT` of every `zeusi` table as the service's role (except `wall_denylist` and `schema_migrations`, which hold the rule patterns and file names), counting rows whose strings carry any Plankiva signal (`mentionsProtectedName()`). Prints table names and counts only; exit 0 only when every table was readable and every count is 0. The operator runs it as `zeusi_backup` after the retraction.
- `npm run wall:dryrun -- --plankiva-fp <dir>` (0011): false-positive scan of the Plankiva rule over a folder of `.md` files (files it matches, files only it matches, the matched tokens only).

## Parity limits (wall.ts vs SQL)

The two sides agree on all 145 shared fixture rows: rule id, kind, content sha, and the real trigger outcome (`test/wall.test.ts`). 0008 added 26 rows (22 blocking rows that all passed under 0007, plus 4 clean look-alike / encoded rows). 0009 added 18 rows (14 blocking: Cherokee / Lisu look-alikes and left-over escapes; 4 clean). 0010 flipped 6 ClientCo rows to pass and added 29 rows: 7 ClientCo / Northbank rows that pass (some with scope `clientco`), 20 Plankiva rows that still block (under ClientCo folders, lanes and repos; separators; leetspeak), and 2 clean near-miss names that must pass. 0011 flipped the currency row to pass and added 38 rows: 31 Plankiva rows that block (every content table; title, body, frontmatter and inline tags, vault path, uri fragment, percent-encoded uri, lane, repo, `applies_to`, `merged_to`, `run_key`; repeated letters, embedded, separators, leetspeak, fullwidth, Cyrillic, zero-width, combining, Cherokee; under ClientCo and Northbank), 6 currency / P&L rows that now pass (ClientCo and Northbank included), 1 ClientCo account-number row that stays soft, and 1 clean near-miss row. `test/wall-0011.test.ts` adds a second seeded fuzz (300 generated Plankiva spellings that must block, 200 random strings and 200 one- or two-character mutants of them; verdicts equal on both sides) and a variants x placements matrix. A seeded fuzz test (400 random strings mixing ASCII, every fold entry, ignorables, combining marks and `%XX` fragments, plus every fold spelled into `plankiva`; since 0010 also separator / leetspeak atoms and spellings, plain and under `ClientCo/`) compares `wall_norm`, `pct_decode` and the full verdict on both sides. `wall_norm` and `pct_decode` are also compared directly on every boundary of every ignorable and mark range, on every look-alike in the fold list, and on edge cases of the decoder. Known limits:

- **Non-ASCII matching.** Case folding and the word characters used by `\m` / `\M` follow the server locale in Postgres and ASCII in JS. Every seeded rule is ASCII. The normalised side lower-cases ASCII only, so it is the same everywhere.
- **Unicode version.** NFKC/NFKD follow each side's Unicode tables: Node's ICU and the server's PostgreSQL build. They differ only for code points added in the newest releases. The ignorable and fold lists are explicit, so they are identical.
- **Regex subset.** `wall.ts` translates a subset of Postgres ARE syntax. On anything else (POSIX classes, `\y`, back-references, other embedded options) it fails closed and refuses to build the wall. An importer then stops instead of guessing.
- **jsonb numbers.** Numbers are rendered like Postgres `numeric`. JS numbers lose precision beyond 2^53, so frontmatter with such numbers can produce a different content sha in TS. The trigger still decides correctly.

## Embeddings and the wall (U6)

`zeusi embed` (dry run and real) first runs the same wall-readiness check as real ingest (`wall.ts` `wallReadiness`: migrations 0006–0011 applied, every seed rule present as seeded) and refuses before reading any chunk otherwise: `wall_audit()` only checks rows against the rules in the database, so on a 0009 wall it would audit "Plankiva" text clean. Then it sends chunk text to OpenAI only when `zeusi.wall_audit()` returns 0 rows. If any stored row breaks the wall, the whole run stops before a single input is sent (status `wall`). Quarantined content is never stored, so it is never embedded and never found by `zeusi search`. `test/search.test.ts` checks this on the fixture vault for vector, hybrid and lexical search. The `--estimate` (b) profile lifts ClientCo-named hard rules; since 0010 there are none, so it lifts nothing. See `docs/embeddings.md`.
