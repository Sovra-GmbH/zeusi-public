# Contributing to Zeusi

Thanks for helping. This page says how to get a change in.

## Set up

You need Node.js 22.18+ and [gitleaks](https://github.com/gitleaks/gitleaks) (CI pins 8.30.1).

```sh
git clone https://github.com/Sovra-GmbH/zeusi-public.git zeusi && cd zeusi
npm ci
npm run hooks:install   # pre-commit hook that runs gitleaks
npm run check           # typecheck, build, tests, gitleaks history scan and repo guards
```

The tests are hermetic: they run on PGlite with a temporary home folder. They need no network, no database and no real credentials.

## Make a change

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Work on a branch and open a pull request to `main`.
3. Run `npm run check` before you push. CI runs exactly this command on every pull request, so if it passes locally it passes in CI.
4. Fill in the pull request template: what changed, why, and the test that proves it.

## House rules

The full rules, with the guard or test that enforces each one, are in [`AGENTS.md`](AGENTS.md). The short version:

- **No secrets, ever.** No passwords, tokens, keys or connection strings with a password in code, tests, docs or commit messages. The gitleaks hook and CI scan the whole history.
- **No skipped tests.** A skipped or todo test fails the run. Make it run or delete it.
- **Claims match the code.** Docs, site copy and pull request descriptions say only what the code at that commit does. Every safety claim names the test that pins it.
- **One function per rule.** When two paths share a rule (preview and commit, import and sync, TypeScript and SQL), call the one function that owns it. Do not copy it.
- **Use the safe helpers.** In tests, use the temp-dir and redacted-assert helpers named in `AGENTS.md`.
- **Never write a protected private term** in a new file, fixture, temp name or test title.

## Migrations

Migrations in `migrations/` are applied in order and must never be edited once merged. A new change gets a new numbered file. Test it with `npm start -- migrate --dry-run` first.

## Code of Conduct

By taking part you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
