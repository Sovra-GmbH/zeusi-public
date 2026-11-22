# Security policy

## Report a problem

Please **do not** open a public issue, discussion or pull request for a security problem.

Write to **[hello@sovra.ch](mailto:hello@sovra.ch)** and start the subject with `Security:`. Please include:

- what you found and where (file, endpoint or tool),
- the steps to reproduce it,
- what an attacker could do with it.

Do not include real tokens, passwords or other people's data in the report. If you need to show a secret leaked, show only its first few characters.

We will reply as soon as we can. Sovra GmbH runs Zeusi from Cham, Switzerland.

## What is in scope

- The code in this repository.
- The hosted server at `https://mcp.zeusi.dev/mcp` and the site at `https://zeusi.ai`.

Please test only against your own account and workspace. Do not access other users' data, and do not run tests that degrade the service.

## How Zeusi is run

[zeusi.ai/security](https://zeusi.ai/security) says how the hosted service runs today: where it runs, sign-in, what the people who run it can see, and what is logged.
