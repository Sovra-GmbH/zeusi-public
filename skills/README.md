# Skills

Agent skills that ship with Zeusi. Each skill is a directory with a `SKILL.md` (agentskills.io format: YAML frontmatter `name` + `description`, then Markdown).

| Skill | Use |
|---|---|
| [`zeusi-startup`](zeusi-startup/SKILL.md) | Session start, search-before-answer, citing, feedback, logging owner decisions, Plankiva exclusion, read-only default. Canonical text for every assistant that uses the Zeusi MCP connector (`docs/mcp.md`). |

## Installing a skill

Copy the skill directory as-is into the client's skill location. Do not rename it, do not edit the text per client, and do not invent a new registry.

- **Claude Code:** copy `skills/zeusi-startup/` to `~/.claude/skills/zeusi-startup/` (user) or `.claude/skills/zeusi-startup/` (project).
- **Grok Bot / other agentskills.io catalogs:** add the `zeusi-startup/` directory to the bot's existing skill catalog.
- **Cursor or clients without skills:** paste the body of `SKILL.md` into a rule file (for example `.cursor/rules/zeusi.mdc`), or use the short wrappers in `docs/mcp.md`.

The skill expects the Zeusi MCP server to be registered in the same client: by default the hosted server `https://mcp.zeusi.dev/mcp` with a bearer token from the client's secret store, or local stdio (`docs/mcp.md`, "Startup snippets"). The skill names only that public URL and the `$ZEUSI_READ_TOKEN` placeholder; it contains no credentials, database hostnames or token values, and none may be added to it. `test/skill-startup.test.ts` checks that.

Installing into a live bot catalog is a separate step after review; this repo only carries the text.
