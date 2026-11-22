# AGENTS.md

Rules for anyone (agent or human) changing this repo. Each rule exists because the mistake happened in at least two PRs; the evidence is the tests named in the table below.

## The one command

```sh
npm ci
npm run check   # typecheck, build, npm test (hermetic), gitleaks history scan, repo guards
```

CI (`.github/workflows/ci.yml`) runs exactly `npm run check` on every pull request and on every push to `main`. If it passes locally it passes in CI, and the other way round. Do not add CI-only steps beyond machine setup.

## Rule table

| Id | Rule | Enforcer | Level | Proof (test name in `test/`) |
|---|---|---|---|---|
| check | Every gate runs on every PR, the same way locally and in CI. | `scripts/check.ts`, `.github/workflows/ci.yml` | architecture | the PR's CI run; `correct-guards.test.ts` "allowlist: only shrinks ..." |
| safe-tmp | No raw `mkdtemp` / `mkdtempSync` (or an alias of it). In tests and scripts use `safeMkdtemp(prefix)` / `safeTmpDir(name)` from `test/helpers/safe-tmp.ts`; a random suffix can spell a walled term. In `src/` use `gatedRunDir(parent, prefix, runDirGate(walls, home, subPaths))` from `src/run-dir.ts`, with the walls and sub-paths of every gate that later checks the dir. | `scripts/guards/safe-tmp.ts` | lint | `correct-guards.test.ts` "safe-tmp: RED on the real past mistakes ..."; `run-dir.test.ts` "#55 CI shape: ..." |
| secret-assert | Never compare a password, secret, token or Authorization value with `assert.equal` / `deepEqual` / `notEqual` / `match`; node:assert prints both values. Use `assertSecretEqual`, `assertSecretsEqual`, `assertRejectsRedacted`, `assertThrowsRedacted` from `test/redact.ts`. | `scripts/guards/secret-assert.ts` | lint | `correct-guards.test.ts` "secret-assert: RED on the #14 incident lines ..." |
| hermetic-npm-test | `npm test` is `node scripts/test-hermetic.ts` (temp HOME, credential env scrubbed using the URL names in `src/config.ts`, `ZEUSI_TEST_NO_REAL_CREDS=1`). In test mode `src/keychain.ts` refuses the real Keychain, `~/.pgpass` and `~/.pg_service.conf`; inject runners and paths. A test of the macOS Keychain branch pins the platform with `withPlatform('darwin', ...)` from `test/helpers/platform.ts` (CI runs on Linux). | `scripts/guards/hermetic-npm-test.ts`, `scripts/hermetic-env.ts`, `src/keychain.ts` | architecture + lint | `correct-guards.test.ts` "hermetic-npm-test: ...", "hermetic env: ..."; `hermetic-creds.test.ts` |
| no-skip | No skipped or todo tests: a test that skips cannot fail. Make it run (install what it needs) or delete it. | `scripts/test-hermetic.ts` (fails the run when the TAP summary counts a skipped or todo test, or on any TAP `# SKIP` / `# TODO` directive line, which also covers skipped and todo suites such as `describe.skip`) | test runner | `correct-guards.test.ts` "no-skip: RED on the b52fde9 secret-scan shape ...", "no-skip: RED on a skipped or todo suite ..." |
| overclaim | No privacy or encryption claim in the site or in served copy (welcome, about, MCP instructions, empty states) beyond what shipped code makes true. | `test/helpers/overclaim.ts` via `site.test.ts`, `site-terminal.test.ts` | test | `site.test.ts` "site (wow, check g): no encryption or operator-blindness claim ..." |
| mutant-proof | Every safety claim in a PR body, RESULT or doc names the test that pins it and a mutant that turns that test red. A test that stays green when the guarded line is deleted is not a proof. | none (judgment) | review | - |
| one-rule | One function owns each rule that two paths share (startup vs onboarding status, preview vs commit, import vs sync, TS vs SQL). Call it; never re-implement it. | none (judgment) | review | - |
| served-is-checked | The wall and the secret check run on exactly the string that is served (after any collapsing or redaction), via `src/mcp-wall.ts`. | none (judgment) | review | - |
| fresh-claims | Counts, sizes, test totals and "not deployed"-style status in docs and PR bodies are re-derived from the code at the commit, not copied from an earlier note. | none (judgment) | review | - |
| private-terms | Never spell a wall-protected private term, or an owner's personal name, in a new file, fixture, temp name or test title. Refer to them as "the private hard terms". | none (judgment) | review | - |

## Exceptions

An existing offending line sits in `scripts/guards/allowlist.json`. An entry covers one occurrence of that exact line in that file, so a second identical copy is a new violation. That list may only shrink: the guard run fails on an entry the base revision did not have, or on an entry that no longer matches anything.

A new exception goes on the offending line (or the line above it), with all three fields and a human's GitHub login:

```ts
// correct-allow: <rule-id> reason=<why> expires=<YYYY-MM-DD> approved-by=<human GitHub login>
```

A missing field, a malformed or past expiry, or a bot/agent approver fails the guard. Never fill in `approved-by` yourself.

## Dropping a rule

Remove a row once its mistake can no longer be written (for example when a type makes it a compile error), together with the enforcer it names.
