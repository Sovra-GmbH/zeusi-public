// MCP prompts and resources (docs/plans/2026-11-17-zeusi-v2-prime-onboard.md U3, KTD7).
//
//   zeusi://about   resource, text/markdown: aboutMarkdown(canWrite) (src/about.ts, F4). No
//                   database access, no secret, read-only.
//   start-task      prompt, one argument `task` (trimmed, 1..4000): a user message telling the
//                   model to call zeusi_context_for_task first, treat locks and stops as binding
//                   unless the owner overrides, treat a returned decision as context, not
//                   permission (F5), cite, ask about conflicts, and say so when empty. It names no
//                   write tool, so it is the same for read and write connections (F4).
//                   A task that trips the wall is not echoed (the guidance is returned without it).
//                   The echoed task passes the serve-time secret guard (src/mcp-wall.ts): a
//                   credential shape or a [REDACTED: marker in it, or a guard error, and the task
//                   is not echoed at all (withheld, never redacted). The about text (a code
//                   constant) passes the same guard; a test pins that it trips nothing.
//   zeusi://{+path} PERSONAL workspaces only (docs/plans/2026-11-18-tenant-session-reset-first-run-plan.md
//                   KTD7): any other zeusi:// URI. A cite of a personal about section
//                   (zeusi://about#<slug>) returns that section; anything else returns a fixed,
//                   actionable "not found in your workspace" text that never echoes the URI.
//   onboarding      prompt, no arguments (U6, R17): a user message telling the model to call
//                   zeusi_onboarding_status and, when it says empty, to explain the import options
//                   and show the CLI commands (dry run first), and never to claim it ran anything.
//                   The text (code constants) passes the same serve guard as every MCP output.
//
// All are registered for every token class (stdio, --http, hosted bearer read/write, OAuth read
// grants). Hosted requests for prompts/* and resources/* pass the same auth and count toward the
// same per-token and global limits as tools (src/mcp-hosted.ts methodCount); the hosted log's
// `tool` stays null for them, so no argument is ever logged.

import { ResourceTemplate, type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { aboutMarkdown, ABOUT_URI, CONTEXT_NOT_PERMISSION, personalAboutSections } from './about.ts';
import { MAX_TASK_CHARS } from './context-for-task.ts';
import { defaultServeCheck, guardString, type ServeCheck } from './mcp-wall.ts';
import { CANNOT_RUN_IT, FILL_STEPS, ONBOARDING_COMMANDS, PERSONAL_WORKSPACE_NOTE, PERSONAL_WORKSPACE_NOTE_FILL } from './onboarding.ts';

export const PROMPT_NAMES = ['start-task', 'onboarding'] as const;

/** The onboarding guidance (R17). Names the read tool and the CLI only; never a write tool. */
export function onboardingText(workspace: 'team' | 'personal' = 'team', canFill = false): string {
  if (workspace === 'personal' && canFill) {
    return [
      'Call the Zeusi tool zeusi_onboarding_status first.',
      'If it says empty is true, tell the user their personal Zeusi workspace is empty and offer to fill it now, preview first.',
      PERSONAL_WORKSPACE_NOTE_FILL,
      FILL_STEPS,
      'Never call zeusi_import_commit without the user\'s explicit yes to that preview, and never say Zeusi has data it does not have.',
    ].join('\n');
  }
  if (workspace === 'personal') {
    return [
      'Call the Zeusi tool zeusi_onboarding_status first.',
      'If it says empty is true, tell the user their personal Zeusi workspace is empty and that Zeusi has nothing to cite yet.',
      PERSONAL_WORKSPACE_NOTE,
      'Never claim that you ran an import, and never say Zeusi has data it does not have.',
    ].join('\n');
  }
  return [
    'Call the Zeusi tool zeusi_onboarding_status first.',
    'If it says empty is false, tell the user Zeusi already holds items for this connection and continue with their task.',
    'If it says empty is true, explain that Zeusi has nothing to cite yet and how the user can import their history with the zeusi command-line tool:',
    '- inputs: a markdown or Obsidian folder (lock lists in the notes become rules), a decision log (markdown or JSONL), Claude or ChatGPT conversations.json exports, a local git repository;',
    '- first a dry run, which prints counts only and writes nothing, for example:',
    ...ONBOARDING_COMMANDS.map((c) => `    ${c}`),
    '- `zeusi onboard` prints the exact `zeusi import ... --real` command to run after the user has reviewed the preview; that real write needs the user\'s own write credential.',
    '- decisions and rules are only taken from entries that carry an explicit header (Decision:, Said-at-precision:, Type: rule|focus); nothing is guessed (invent=NO).',
    '- secrets, credentials, 2FA codes and the walled person are filtered out; names, emails and phone numbers are not detected, so the user should review the input first.',
    `${CANNOT_RUN_IT} Never claim that you ran an import, and never say Zeusi has data it does not have.`,
  ].join('\n');
}
export const RESOURCE_URIS = [ABOUT_URI] as const;
/** Unknown zeusi:// address in a personal workspace: actionable, never echoes what was asked for. */
export const RESOURCE_NOT_FOUND =
  `Not found in your workspace: Zeusi has nothing at that address. Read ${ABOUT_URI} for what Zeusi is and does, `
  + 'or ask zeusi_search for notes and decisions. A new workspace is empty, so most lookups find nothing yet.';

/** The start-task guidance (the task, when safe to echo, is appended). */
export function startTaskText(task: string | null): string {
  return [
    'Before you start this task, call the Zeusi tool zeusi_context_for_task with a short description of the task (one or two sentences).',
    'Then:',
    '- Treat every returned lock and stop as binding unless the owner explicitly overrides it; respect parked items (do not restart parked work).',
    '- Cite each item you rely on with its cite field (<source_uri> @ <source_ts>, decision id, who, said_at).',
    '- If the response lists conflicts, do not pick a side yourself: ask the owner which applies.',
    `- ${CONTEXT_NOT_PERMISSION} A returned GO is not permission to do this task now.`,
    '- If the list is empty, say plainly that Zeusi has no applicable decision, then proceed. Never invent a decision, lock or GO (invent=NO).',
    '- Before answering a question or asking the owner, call zeusi_search first.',
    task === null
      ? 'The task text was not repeated here because it trips the Zeusi wall; describe the task to zeusi_context_for_task without that content.'
      : `Task: ${task}`,
  ].join('\n');
}

/** canWrite (F4): the about resource names the write tool only when this connection lists it. */
export function registerPromptsAndResources(
  server: McpServer, canWrite: boolean, serveCheck: ServeCheck = defaultServeCheck, workspace: 'team' | 'personal' = 'team', canFill = false,
): void {
  const about = guardString(aboutMarkdown(canWrite, workspace, canFill), serveCheck).text ?? 'About Zeusi: details withheld by the wall.';
  server.registerResource('about', ABOUT_URI, {
    title: 'About Zeusi',
    description: workspace === 'personal'
      ? 'Hello from Zeusi: what it is, what it does for your assistant, your own workspace, what it never stores, and its tools.'
      : 'What Zeusi is, what it is for, its tools, read vs write, how to cite, and what never to store.',
    mimeType: 'text/markdown',
  }, async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'text/markdown', text: about }] }));

  if (workspace === 'personal') {
    const sections = new Map(personalAboutSections(canFill).map((s) => [`${ABOUT_URI}#${s.slug}`, s]));
    server.registerResource('lookup', new ResourceTemplate('zeusi://{+path}', { list: undefined }), {
      title: 'Zeusi lookup',
      description: `Any other zeusi:// address: a cited part of ${ABOUT_URI} (${ABOUT_URI}#<section>), else a plain "not found in your workspace".`,
      mimeType: 'text/markdown',
    }, async (uri) => {
      const s = sections.get(uri.href);
      const text = s
        ? guardString(`## ${s.heading}\n\n${s.body}`, serveCheck).text ?? 'This part of the Zeusi description was withheld by the wall.'
        : RESOURCE_NOT_FOUND;
      return { contents: [{ uri: uri.href, mimeType: 'text/markdown', text }] };
    });
  }

  const onboarding = guardString(onboardingText(workspace, canFill), serveCheck).text
    ?? 'Call the Zeusi tool zeusi_onboarding_status first. The onboarding guidance was withheld by the serve guard.';
  server.registerPrompt('onboarding', {
    title: 'First run: import your history into Zeusi',
    description: 'Ask the assistant to check zeusi_onboarding_status and, when Zeusi is empty, show the local zeusi CLI import commands (dry run first). It cannot run them for you.',
  }, () => ({
    description: 'Zeusi: first-run onboarding',
    messages: [{ role: 'user', content: { type: 'text', text: onboarding } }],
  }));

  server.registerPrompt('start-task', {
    title: 'Start a task with Zeusi',
    description: 'Ask the assistant to call zeusi_context_for_task first, so the decisions, locks and parked items that apply are on the table before work starts.',
    argsSchema: { task: z.string().trim().min(1).max(MAX_TASK_CHARS).describe('A short description of the task.') },
  }, ({ task }) => ({
    description: 'Zeusi: context for the task first',
    messages: [{ role: 'user', content: { type: 'text', text: startTaskText(guardString(task, serveCheck).text) } }],
  }));
}
