// zeusi.ai (site/): the "Connect your AI" section names only the public MCP URL, gives exact
// steps per MCP client (labels from each vendor's docs), keeps the hero and logo, names no
// person, and stays secret-free with one same-origin enhancement script and no third party.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DECISION_EXAMPLE_JSONL, FILL_MEMORY_OFFER, fillMemoryLine, MCP_URL, RULE_EXAMPLE_NOTE, RULE_EXAMPLE_PATH, WELCOME_GREETING, WELCOME_MARKDOWN, welcomeMarkdown,
} from '../src/about.ts';
import { HQ_PROFILE } from '../src/importers/profile.ts';
import { personalEmptyStates } from '../src/mcp-server.ts';
import {
  ADMIN_LOGIN_SENTENCE, ALLOWED_ENCRYPTION, OVERCLAIM, OWNER_ENCRYPTION_LINE, overclaims, PRIVACY_KEY_DETAIL, serverCopy, SIGNED_IN_SENTENCE, siteOverclaims,
} from './helpers/overclaim.ts';
import { terminalLines } from './helpers/site-terminal.ts';
import { hasNonRoleOperatorAddress } from './helpers/owner-terms.ts';

const SITE = fileURLToPath(new URL('../site/', import.meta.url));
const html = readFileSync(join(SITE, 'index.html'), 'utf8');
const js = readFileSync(join(SITE, 'connect.js'), 'utf8');
const wow = readFileSync(join(SITE, 'wow.js'), 'utf8');
const css = readFileSync(join(SITE, 'styles.css'), 'utf8');
const URL_ = 'https://mcp.zeusi.dev/mcp';
const FILM_FILES = ['zeusi-poster.jpg', 'zeusi-hero-loop-720p.webm', 'zeusi-hero-loop-720p.mp4', 'zeusi-explainer-full-1080p.mp4'];
// The full film (data-sound-src) is the ONE absolute media URL: its public Vercel Blob object (the same bytes as
// site/assets/film/zeusi-explainer-full-1080p.mp4, sha256 fee0b96a…8b8d, 39,406,821 bytes). Why not the same-origin
// path: a <video> fetches with HTTP Range (Safari: bytes=0-1, then bytes=0-39406820, then bytes=2-…), and a
// same-origin Vercel rewrite to Blob let the CDN cache ONE range slice and replay it for every later Range request
// (206 bytes 0-1/39406821), so iOS Safari (and desktop Chrome) failed with "The film could not be loaded.". The Blob
// URL answers each Range exactly. Never reintroduce that rewrite; pin this exact URL; refuse any other absolute URL.
const FILM_SOUND_URL = 'https://mwukcp9aqefvqnk6.public.blob.vercel-storage.com/assets/film/zeusi-explainer-full-1080p.mp4';
const FILM_SOUND_ATTR = ` data-sound-src="${FILM_SOUND_URL}"`;
/** index.html without the one pinned absolute media attribute (asserted present exactly once). */
const htmlNoSound = () => {
  assert.equal(html.split(FILM_SOUND_ATTR).length - 1, 1, 'the Blob URL appears exactly once, as data-sound-src');
  return html.replace(FILM_SOUND_ATTR, '');
};
const plain = (s: string) => s.replace(/<[^>]+>/g, ' ').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&').replace(/&rsquo;/g, '’')
  .replace(/&ldquo;|&rdquo;/g, '"').replace(/&quot;/g, '"').replace(/\s+/g, ' ');
const text = plain(html);
const sectionOf = (id: string) => {
  const start = html.indexOf(`<section id="${id}"`);
  assert.ok(start >= 0, id);
  return html.slice(start, html.indexOf('</section>', start));
};
const connect = sectionOf('connect');
const connectText = plain(connect);

function panel(id: string): { html: string; text: string } {
  const start = connect.indexOf(`<div class="panel" id="panel-${id}"`);
  assert.ok(start >= 0, `panel ${id}`);
  const next = connect.indexOf('<div class="panel" ', start + 1);
  const end = next >= 0 ? next : connect.indexOf('<h3>What happens when you sign in</h3>');
  const h = connect.slice(start, end);
  return { html: h, text: plain(h) };
}

function inOrder(hay: string, needles: string[], what: string): void {
  let at = 0;
  for (const n of needles) {
    const i = hay.indexOf(n, at);
    assert.ok(i >= 0, `${what}: missing or out of order: ${n}`);
    at = i + n.length;
  }
}

function siteFiles(dir = SITE): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? siteFiles(p) : [p];
  });
}

const CLIENTS = [
  ['claude', 'Claude'], ['claude-code', 'Claude Code'], ['chatgpt', 'ChatGPT'], ['cursor', 'Cursor'], ['vscode', 'VS Code'], ['gemini', 'Gemini CLI'], ['any', 'Any MCP client'],
] as const;

test('site: hero and logo kept; the section and the hero button say Connect your AI', () => {
  assert.match(html, /<section class="hero"/);
  assert.match(html, /<svg [^>]*class="logo"/);
  assert.match(html, /assets\/hero\.avif/);
  assert.match(html, /<h2 id="connect-title">Connect your AI<\/h2>/);
  assert.match(html, /<a class="btn btn-primary" href="#connect">Connect your AI<\/a>/);
  assert.doesNotMatch(html, /Connect to Claude/);
  assert.match(connectText, /Zeusi works with any assistant that speaks MCP, the open standard for AI connectors\./);
});

test('site: one copyable server URL, with a Copy button hidden until the script runs, and a live region', () => {
  assert.equal((connect.match(/<code id="mcp-url" class="url">https:\/\/mcp\.zeusi\.dev\/mcp<\/code>/g) ?? []).length, 1);
  assert.match(connect, /<button type="button" class="copy copy-url" data-copy="mcp-url" hidden>Copy<\/button>/);
  assert.match(connect, /id="copy-status" role="status" aria-live="polite"/);
  for (const b of connect.match(/<button[^>]*class="copy[^"]*"[^>]*>/g) ?? []) assert.match(b, / hidden>$/, b);
  for (const id of connect.match(/data-copy="([^"]+)"/g) ?? []) {
    const target = id.slice('data-copy="'.length, -1);
    assert.match(connect, new RegExp(`<code id="${target}"`), `copy target ${target} exists`);
  }
});

test('site: WAI-ARIA tabs, one per client, each controlling a panel that has its own heading (all panels shown without JS)', () => {
  assert.match(connect, /<div class="tablist" role="tablist" aria-labelledby="pick-title" hidden>/);
  const tabs = connect.match(/<button type="button" role="tab"[^>]*>.*?<\/button>/g) ?? [];
  assert.equal(tabs.length, CLIENTS.length);
  CLIENTS.forEach(([id, name], i) => {
    const tab = tabs[i]!;
    assert.match(tab, new RegExp(`id="tab-${id}" aria-controls="panel-${id}" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}"`), id);
    assert.ok(plain(tab).includes(name), `${id} tab names ${name}`);
    const p = panel(id);
    assert.match(p.html, new RegExp(`role="tabpanel" aria-labelledby="tab-${id}" tabindex="0"`), id);
    assert.doesNotMatch(p.html.slice(0, p.html.indexOf('>')), /hidden/, `${id} panel is not hidden in the markup`);
    assert.match(p.html, /<h3 class="panel-title">/, `${id} has its own heading`);
    const steps = (p.html.match(/<ol class="steps">([\s\S]*?)<\/ol>/)?.[1] ?? '').match(/<li>/g) ?? [];
    assert.ok(steps.length >= 3 && steps.length <= 4, `${id}: 3-4 steps, got ${steps.length}`);
  });
  assert.doesNotMatch(connect, /<section[^>]*role="tabpanel"/, 'panels are divs (no nested section)');
});

test('site: Claude (web & Desktop) steps use the Help Center labels in order (Customize > Connectors, not Settings)', () => {
  const { text: t } = panel('claude');
  inOrder(t, ['Customize > Connectors', '+ Add', 'Add custom connector', URL_, 'Continue', 'Authentication', 'Sign in now', 'OAuth client',
    'Use Claude’s published identity (Recommended)', 'Register automatically', 'Add'], 'claude');
  assert.doesNotMatch(connectText, /\bSettings\b/);
});

test('site: Claude Code, ChatGPT, Cursor, VS Code, Gemini CLI and any-client steps match the vendor docs', () => {
  const cc = panel('claude-code');
  assert.match(cc.html, /<code id="cmd-claude-code">claude mcp add --transport http zeusi https:\/\/mcp\.zeusi\.dev\/mcp<\/code>/);
  inOrder(cc.text, ['/mcp', 'claude mcp login zeusi'], 'claude code');

  inOrder(panel('chatgpt').text, ['Plugins', '+', 'Add custom MCP server', 'Connection', 'Authentication', 'OAuth', 'I understand and want to continue', 'Create as a plugin', '@'], 'chatgpt');

  const cursor = panel('cursor');
  assert.ok(cursor.text.includes('~/.cursor/mcp.json'));
  const json = /<code id="cmd-cursor">([\s\S]*?)<\/code>/.exec(cursor.html)![1]!.replace(/&quot;/g, '"');
  assert.deepEqual(JSON.parse(json), { mcpServers: { zeusi: { url: URL_ } } }, 'Cursor: OAuth, url only');
  assert.doesNotMatch(cursor.html, /headers|Authorization/, 'no bearer-header snippet for Cursor');
  inOrder(cursor.text, ['Customize > MCPs', 'sign-in prompt'], 'cursor');

  inOrder(panel('vscode').text, ['MCP: Add Server', 'Chat: Open Customizations', 'MCP Servers', 'Add Server', 'HTTP', 'zeusi', 'Global'], 'vscode');

  const gem = panel('gemini');
  assert.match(gem.html, /<code id="cmd-gemini">gemini mcp add --transport http zeusi https:\/\/mcp\.zeusi\.dev\/mcp<\/code>/);
  assert.match(gem.html, /<code id="cmd-gemini-auth">\/mcp auth zeusi<\/code>/);

  const any = panel('any');
  inOrder(any.text, [URL_, 'Streamable HTTP', 'OAuth', 'OAuth 2.1', 'No OAuth?', 'Authorization: Bearer $ZEUSI_READ_TOKEN', 'Zeusi admin'], 'any');
});

test('site: "What happens when you sign in" (GitHub, which app and where, read-only) and three example prompts', () => {
  const signin = /<ol class="signin">([\s\S]*?)<\/ol>/.exec(connect)![1]!;
  assert.equal((signin.match(/<li>/g) ?? []).length, 3);
  inOrder(plain(signin), ['Sign in with GitHub', 'Zeusi shows which app is asking', 'where access goes', 'You approve access once', 'writes into your own workspace only after you approve a preview', 'You never paste a token'], 'signin');
  // Open sign-up (docs/plans/2026-11-18-open-signup-workspaces-plan.md R18): any GitHub account, its own empty workspace.
  assert.match(plain(signin), /Any GitHub account works\. You get your own workspace\. It is separate from everyone else.s and starts empty\./);
  assert.doesNotMatch(connect, /invited|allowlist|Only invited/i, 'no invited-only wording left');
  const prompts = connect.slice(connect.indexOf('<ul class="prompts">'));
  assert.equal((prompts.match(/<li>/g) ?? []).length, 3);
  for (const p of ['What standing rules should I follow today?', 'What has been decided about promoting Northbank to prod?', 'What is currently locked or parked?']) {
    assert.ok(text.includes(p), p);
  }
  assert.match(connectText, /decisions, digs, parked items and locks/);
});

test('site: no personal name anywhere in site/ (copy, README, CSS comments, SVG titles)', () => {
  for (const f of siteFiles()) {
    if (/\.(avif|webp|jpg|png|mp4|webm)$/.test(f)) continue;
    assert.equal(hasNonRoleOperatorAddress(readFileSync(f, 'utf8')), false, f);
  }
});

test('site: the only scripts are connect.js and wow.js (same origin, defer); no network, eval, HTML injection, inline script or style', () => {
  const scripts = html.match(/<script\b[^>]*>[\s\S]*?<\/script>/gi) ?? [];
  assert.deepEqual(scripts, ['<script src="connect.js" defer></script>', '<script src="wow.js" defer></script>']);
  assert.doesNotMatch(html, /\bon[a-z]+="/i, 'no inline handlers');
  assert.doesNotMatch(html, /\sstyle="/i, 'no inline style attribute (CSP without unsafe-inline)');
  assert.doesNotMatch(html, /<style\b/i, 'no inline style block');
  for (const [name, src] of [['connect.js', js], ['wow.js', wow]] as const) {
    assert.doesNotMatch(src, /fetch|XMLHttpRequest|sendBeacon|WebSocket|eval|innerHTML|outerHTML|insertAdjacentHTML|document\.write|import\(|new Function|https?:\/\/|setAttribute\('style'|\.cssText|localStorage|sessionStorage|document\.cookie/, name);
  }
  assert.match(js, /navigator\.clipboard/);
  assert.match(js, /aria-selected/);
  for (const key of ['ArrowRight', 'ArrowLeft', 'Home', 'End']) assert.ok(js.includes(`'${key}'`), key);
  assert.match(js, /prefers-reduced-motion/);
});

test('site: no stdio checkout path, no token or secret, no infra ids, no third-party request or vendor logo', () => {
  assert.ok(!html.includes('/path/to/zeusi'));
  assert.ok(!html.includes('dist/mcp.js'));
  assert.doesNotMatch(html, /Bearer zeusi_/);
  assert.doesNotMatch(html + js, /zeusi_[a-z2-7]{12}_[A-Za-z0-9_-]{43}|zeusi_(at|rt|ac)_[A-Za-z0-9_-]{20,}/);
  assert.doesNotMatch(html, /Bearer\s+(?![$<])[A-Za-z0-9._~+/-]{12,}/, 'only the $ZEUSI_READ_TOKEN placeholder');
  assert.ok(!html.includes(['hotmail', '.com'].join('')));
  assert.doesNotMatch(html, /neon\.tech|postgres(ql)?:\/\/|fly\.dev|\bvol_|\bprj_|\bteam_/i);
  assert.doesNotMatch(html, /<iframe/i);
  // Only the pinned film URL is absolute, and it is requested only on "Watch with sound" (see FILM_SOUND_URL).
  assert.doesNotMatch(htmlNoSound(), /(src|href|srcset)="(https?:)?\/\//i, 'no third-party request');
  assert.doesNotMatch(html, /github\.com\/the team|repo(sitory)? is public|open source/i, 'no claim about the repo');
  const imgs = [...htmlNoSound().matchAll(/(?:src|srcset)="([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(imgs.filter((s) => !/^assets\/(hero\.(avif|webp|jpg)|film\/(zeusi-poster\.jpg|zeusi-hero-loop-720p\.(webm|mp4)|zeusi-explainer-full-1080p\.mp4))$/.test(s!) && s !== 'connect.js' && s !== 'wow.js'), [], 'no vendor logo images');
  assert.deepEqual(readdirSync(join(SITE, 'assets')).sort(), ['film', 'hero.avif', 'hero.jpg', 'hero.webp']);
  assert.deepEqual(readdirSync(join(SITE, 'assets', 'film')).sort(), FILM_FILES.slice().sort(), 'only the four delivered film files');
});

test('site: a "What Zeusi is" section after Connect, with "speaks up first" and the honest "cannot force" line; no claim it runs tools by itself', () => {
  const start = html.indexOf('<section id="about"');
  assert.ok(start > html.indexOf('<section id="connect"'), '#about comes after #connect');
  const about = sectionOf('about');
  const aboutText = plain(about);
  assert.match(about, /<h2 id="about-title">What Zeusi is<\/h2>/);
  assert.match(aboutText, /decisions, digs, parked items and locks, named after a cat/);
  assert.match(aboutText, /Zeusi speaks up first/);
  assert.match(aboutText, /A connector cannot force a model to call a tool or run a script/);
  assert.match(aboutText, /read-only by default/);
  // F5: a decision is context, not permission
  assert.match(aboutText, /A Zeusi decision is context, not permission/);
  assert.match(aboutText, /not an approval or a GO to act now/);
  assert.match(aboutText, /current, explicit approval/);
  assert.doesNotMatch(aboutText, /automatically (calls|runs)|always calls|will run|runs it for you/i, 'suggestion only');
  assert.doesNotMatch(about, /plankiva|plankiva/i);
});

test('site (PR2 U10): a short first-run note inside #about: dry run first, "cannot run the import for you", no --real command, no path or secret', () => {
  const start = html.indexOf('<section id="about"');
  const about = html.slice(start, html.indexOf('</section>', start));
  const aboutText = about.replace(/<[^>]+>/g, ' ').replace(/&rsquo;/g, '’').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/\s+/g, ' ');
  assert.match(about, /<h3>First run: an empty Zeusi<\/h3>/);
  assert.match(aboutText, /dry run/);
  assert.match(aboutText, /cannot run the import for you/);
  assert.match(aboutText, /a connector cannot force a model to run anything/);
  assert.match(aboutText, /zeusi onboard --markdown <notes-folder> --scope work/);
  assert.match(aboutText, /Names, emails and phone numbers are not filtered out/);
  assert.doesNotMatch(html, /--real/, 'the site never shows a writing command');
  assert.doesNotMatch(about, /\/Users\/|~\/|neon\.tech|Bearer\s+[A-Za-z0-9]/);
});

test('site (first run, U5): a numbered "Your first 5 minutes" guide between Connect and About, matching what the server says', () => {
  const g = sectionOf('first-5-minutes');
  const gText = plain(g);
  const at = html.indexOf('<section id="first-5-minutes"');
  assert.ok(at > html.indexOf('<section id="connect"') && at < html.indexOf('<section id="about"'), 'after Connect, before About');
  assert.match(g, /<h2 id="guide-title">Your first 5 minutes<\/h2>/);
  const steps = (/<ol class="guide-steps">([\s\S]*?)<\/ol>/.exec(g)?.[1] ?? '').match(/<li>/g) ?? [];
  assert.equal(steps.length, 5, 'five numbered steps');
  inOrder(gText, [
    `Add ${MCP_URL} as a connector`, 'Connect your AI',
    'Sign in with GitHub and approve', 'No invite needed', 'your own workspace', 'starts empty',
    '"Run zeusi_startup"', `"${WELCOME_GREETING.replace(/\.$/, '').replace("'", '’')}"`,
    '"What can Zeusi do?"', 'zeusi://about',
    'Fill your memory', 'fill my memory', 'paste your notes', 'export', 'preview first', 'nothing is saved until you say yes',
    'Never paste secrets', 'private client details',
  ], 'guide');
  // The site promises exactly what the server sends (src/about.ts is the one source; form B, PR 2).
  assert.ok(WELCOME_MARKDOWN.startsWith(`# ${WELCOME_GREETING}`));
  assert.match(FILL_MEMORY_OFFER, /^Want me to fill your memory now\? I'll show a preview first\./);
  assert.match(FILL_MEMORY_OFFER, /"fill my memory" and paste your notes, or point me at an export; nothing is saved until you say yes\.$/);
  assert.match(g, /<a href="#connect">Connect your AI<\/a>/, 'reuses the app-specific steps above (same page)');
  assert.equal(hasNonRoleOperatorAddress(gText), false, 'no non-role operator address');
  assert.doesNotMatch(g, /Bearer|zeusi_[a-z2-7]{12}_|postgres|neon|fly\.dev|<script|https?:\/\/(?!mcp\.zeusi\.dev\/mcp)/i, 'no secret, infra or other URL');
});

test('site (review P2-6 of #31): the connect intro promises filling only for a personal workspace, only after a preview you approve', () => {
  assert.match(plain(connect), /In a personal workspace it can also fill it: it writes only into that workspace, and only after you approve a preview\./);
  assert.doesNotMatch(plain(connect), /reads your workspace and writes only into it/, 'no unconditional write promise');
});

test('site (one URL): every MCP URL on the page is https://mcp.zeusi.dev/mcp', () => {
  // The full film's Blob URL is the one non-MCP absolute URL (pinned in the film test), so it is left out here.
  const urls = [...htmlNoSound().matchAll(/https?:\/\/[^\s"<]+/g)].map((m) => m[0]).filter((u) => !u.startsWith('http://www.w3.org/'));
  assert.ok(urls.length >= 6);
  assert.deepEqual([...new Set(urls)], [MCP_URL]);
});

// ---------------------------------------------------------------------------------------------------
// The "wow" layer (docs/plans/site-wow.md): honesty, secrets, the film config point, the terminal and
// the example cards. The terminal's drift against the live server is test/site-terminal.test.ts.

/** Every shipped text file (README.md is not deployed, but it is checked too). */
const shipped = () => siteFiles().filter((f) => !/\.(avif|webp|jpg|png|mp4|webm)$/.test(f)).map((f) => [f, readFileSync(f, 'utf8')] as const);

// The site's isolation and encryption note ("What not to put in it"): the owner-approved line (owner decision 21 Nov
// 2026 06:50, verbatim; test/helpers/overclaim.ts OWNER_ENCRYPTION_LINE), the signed-in caveat, what the admin database
// login can see, and the one negative sentence (ALLOWED_ENCRYPTION).
const NOTE = 'Your workspace is kept apart from other users: another user’s Zeusi sign-in cannot read it.'
  + ` ${OWNER_ENCRYPTION_LINE} ${SIGNED_IN_SENTENCE} ${ADMIN_LOGIN_SENTENCE}`
  + ' Your workspace is not end-to-end encrypted.';

test('site (wow, check g): no encryption claim beyond the owner line; the isolation note; no operator-blindness claim in the shipped HTML / JS / CSS / SVG', () => {
  // Today: another user's Zeusi sign-in cannot read a workspace (src/tenants.ts router). With
  // ZEUSI_WORKSPACE_ENCRYPTION=on, a new personal workspace is born encrypted (src/mcp.ts tenantSignupSetup,
  // src/tenants.ts provision); its key opens only with a passkey, the recovery code or a live session (no operator path).
  // The server decrypts while you are signed in: nothing is end-to-end encrypted. Say no more than that. The list is
  // test/helpers/overclaim.ts (also run over the server's copy below and the live reply).
  // The one site exemption: the exact owner line (siteOverclaims).
  for (const [f, body] of shipped()) assert.deepEqual(siteOverclaims(body), [], f);
  // The same check on the plain text (entities and tags removed), so markup between words cannot hide a phrase.
  assert.deepEqual(siteOverclaims(text), [], 'index.html as text');
  // The #53 claim and the pre-encryption caveat are gone from every shipped file and from the text.
  const GONE = /New personal workspaces are encrypted|switched on|born encrypted|can read workspaces|before encryption/i;
  for (const [f, body] of shipped()) assert.doesNotMatch(body, GONE, f);
  assert.doesNotMatch(text, GONE, 'index.html as text');
  // The whole note is there, word for word, exactly once; the owner line exactly once, in it.
  assert.equal(text.split(NOTE).length - 1, 1, 'the isolation note, word for word, once');
  assert.equal(text.split(OWNER_ENCRYPTION_LINE).length - 1, 1, 'the owner line once');
  assert.ok(html.includes(`cannot read it. ${OWNER_ENCRYPTION_LINE} It is not hidden`), 'the owner line, plain text, right after the isolation sentence');
  assert.match(text, /another user’s Zeusi sign-in cannot read it/);
  assert.equal(text.split('admin database login').length - 1, 1, 'admin login named once, in the note');
  // "decrypt" only in the signed-in caveat.
  assert.equal(text.split(/decrypt/i).length - 1, 1, 'decrypt once');
  assert.ok(text.includes(SIGNED_IN_SENTENCE), 'decrypt only in the signed-in caveat');
  // "end-to-end" appears once, and only inside the one allowed negative sentence; "encrypt" only there and in the owner line.
  assert.equal(text.split('end-to-end').length - 1, 1, 'end-to-end once');
  assert.equal(text.split(ALLOWED_ENCRYPTION[0]!).length - 1, 1, 'the allowed sentence once');
  assert.doesNotMatch(text.replace(ALLOWED_ENCRYPTION[0]!, ' ').replace(OWNER_ENCRYPTION_LINE, ' '), /end[- ]to[- ]end|encrypt|only you/i, 'no other end-to-end, encrypt or only-you');
  // No the team or team-workspace mention in or next to the owner line (owner decision): the whole note names neither.
  assert.doesNotMatch(NOTE, /team|team|operator/i, 'the note names no the team or team workspace');
  // The recovery code is named only in the exact Privacy key detail (owner decision; pinned in site-pages.test.ts).
  const KEY_DETAIL_FILE = join(SITE, 'privacy', 'index.html');
  for (const [f, body] of shipped()) {
    const rest = f === KEY_DETAIL_FILE ? body.split(PRIVACY_KEY_DETAIL[0]).join(' ') : body;
    assert.doesNotMatch(rest, /recover(y)? code/i, f);
  }
  assert.ok(readFileSync(KEY_DETAIL_FILE, 'utf8').split(PRIVACY_KEY_DETAIL[0]).length - 1 === 1, 'the key detail once on Privacy');
  assert.doesNotMatch(text, /recover(y)? code/i, 'index.html as text');
});

test('site (wow, check g, review r1 F2): the over-claim list catches the brief\'s phrases and close variants, and lets the honest wording through', () => {
  const BAD = [
    'Your notes are encrypted.', 'Encrypted at rest.', 'End-to-end protected.', 'E2E by default.', 'E2EE.', 'Zero knowledge.', 'Zero-knowledge storage.',
    'Only you.', 'Only you can see it.', 'Only you can read it.', 'Only you have access.', 'Visible only to you.', 'Yours alone.', 'It is yours alone.',
    'Your memory is private to you.', 'Private by design.', 'For your eyes only.',
    'Nobody else can see it.', 'Nobody else can read it.', 'No one else can see your workspace.', 'No-one else can read it.', 'No one else has access.',
    'We can\'t see your data.', 'We can’t see your data.', 'We cannot read your workspace.', 'We never see your notes.', 'We do not read your notes.',
    'Operators cannot read it.', 'Operators can\'t see it.', 'Our team cannot access it.', 'Our staff never see it.', 'Not even our team can read it.',
    'Not even us.', 'Not even Zeusi can read it.', 'Zeusi cannot see your notes.', 'Nobody can read it.', 'We have no access to your data.',
    'Admins can\'t see your workspace.', 'They can\'t see your notes.', 'It cannot read your notes.', 'Hidden from us.', 'Hidden from operators.',
    // Every positive "encrypted" other than the exact owner line is an over-claim, including the #53 sentences.
    'All workspaces are encrypted.', 'Every workspace is encrypted.', 'Existing workspaces are encrypted.', 'Your existing workspace is encrypted.',
    'The team workspace is encrypted.', 'team workspaces are encrypted.', 'Your workspace is encrypted.', 'Your memory is stored encrypted.',
    'New personal workspaces are encrypted end-to-end.', 'New personal workspaces are encrypted at rest and in backups.',
    'new personal workspaces are encrypted.', 'All New personal workspaces are encrypted.', 'Backups are encrypted.',
    'New personal workspaces are encrypted. Only you can read them.', 'A workspace made before encryption was switched on is not encrypted, but yours is encrypted.',
    'New personal workspaces are encrypted.', '<strong>New personal workspaces are encrypted.</strong>',
    'A workspace made before encryption was switched on is not encrypted: whoever holds the admin database login can read it.',
    'New personal workspaces are born encrypted.',
    // Only the exact negative sentence, final period included, is allowed: no "yet", no "but", no follow-up claim.
    'Your workspace is not end-to-end encrypted yet.', 'Your workspace is not end-to-end encrypted, but it is encrypted at rest.',
    'Your workspace is not end-to-end encrypted. It is encrypted at rest.', 'your workspace is not end-to-end encrypted.',
    // Only the exact owner line (both sentences, both periods, this case) is allowed, and only on the site: every
    // paraphrase, half, reorder or addition is caught, also by siteOverclaims.
    'Your memory is encrypted.', 'Only you hold the key.', 'Only you hold the key. Your memory is encrypted.',
    'Your memory is encrypted; only you hold the key.', 'Your memory is encrypted, only you hold the key.', 'your memory is encrypted. Only you hold the key.',
    'Your memory is encrypted. only you hold the key.', 'Your memory is encrypted. Only You hold the key.', 'Your memory is encrypted.  Only you hold the key.',
    'Your memory is encrypted. Only you hold the keys.', 'Your memory is encrypted. Only you hold a key.', 'Your memory is encrypted. Only you can hold the key.',
    'Your memory is encrypted. Only you hold the key, not even the team.', 'Your memory is encrypted. Only you hold the key and nobody else.',
    'Your memory is fully encrypted. Only you hold the key.', 'Your notes are encrypted. Only you hold the key.', 'Your workspace is encrypted. Only you hold the key.',
    'Your memory is encrypted end-to-end. Only you hold the key.', 'Your memory is always encrypted. Only you hold the key.',
    'Your memory is encrypted. Only you hold the key. All workspaces are encrypted.', 'Your memory is encrypted. Only you hold the key. Every workspace is encrypted.',
    'Your memory is encrypted. Only you hold the key. Not even the team can read it.', 'Your memory is encrypted. Only you hold the key. Nobody else can read it.',
    'Your memory is encrypted. Only you hold the key. It is zero-knowledge.', 'Your memory is encrypted. Only you hold the key.the team cannot read it.',
    'Your memory is encrypted. Only you hold the key. the team cannot read it.', 'Even Your memory is encrypted. Only you hold the key.',
  ];
  for (const b of BAD) {
    assert.ok(overclaims(b).length > 0, `not caught: ${b}`);
    assert.ok(siteOverclaims(b).length > 0, `not caught on the site: ${b}`);
  }
  // The owner line is a site exemption only: the server-copy check still catches it.
  assert.ok(overclaims(OWNER_ENCRYPTION_LINE).length > 0, 'the server-copy check never gets the owner line');
  assert.deepEqual(siteOverclaims(OWNER_ENCRYPTION_LINE), [], 'the exact owner line passes on the site');
  assert.deepEqual(siteOverclaims(`<p>${OWNER_ENCRYPTION_LINE}</p>`), [], 'the owner line in its own paragraph');
  const OK = [
    'This workspace is your own. It starts empty. You signed in with GitHub; no invite is needed, and another user\'s Zeusi sign-in cannot read it.',
    'It is not hidden from the people who run Zeusi: whoever holds its admin database login can read every workspace.',
    NOTE, 'Your workspace is not end-to-end encrypted.',
    'Secrets (passwords, API keys, tokens) or private client details.', 'writing only into that workspace and only after a preview you approve.',
    'Zeusi cannot force you to call a tool; it can only ask.', 'nothing is saved until you say yes',
  ];
  for (const o of OK) assert.deepEqual(siteOverclaims(o), [], `false positive: ${o}`);
  assert.ok(OVERCLAIM.length >= 10);
});

test('site (wow, check g, review r1 F2): the server\'s served copy (welcome, zeusi://about, MCP instructions, empty states, onboarding status) makes no over-claim either', () => {
  const copy = serverCopy();
  assert.ok(copy.length > 100, `collected ${copy.length} server strings`);
  // The collector really reaches the served text (a mutant there must be seen).
  assert.ok(copy.some(([, s]) => s.includes(WELCOME_MARKDOWN)), 'welcome');
  assert.ok(copy.some(([n]) => n === 'src/about.ts ABOUT_SUMMARY'), 'ABOUT_SUMMARY');
  assert.ok(copy.some(([n, s]) => n.startsWith('mcpInstructions(') && s.includes('zeusi_startup')), 'instructions');
  for (const [name, body] of copy) assert.deepEqual(overclaims(body), [], name);
  // The site's encryption sentences are site-only: the server's copy carries none of them (not broadened).
  for (const [name, body] of copy) for (const a of [...ALLOWED_ENCRYPTION, OWNER_ENCRYPTION_LINE]) assert.ok(!body.includes(a), `${name}: ${a}`);
});

test('site (wow, check a/e): no owner name, personal login, email, secret, token, key or internal host in any shipped file', () => {
  for (const [f, body] of shipped()) {
    assert.equal(hasNonRoleOperatorAddress(body), false, `${f}: non-role operator address`);
    assert.doesNotMatch(body, /zeusi_[a-z2-7]{12}_[A-Za-z0-9_-]{43}|zeusi_(at|rt|ac)_[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN/, `${f}: token or key`);
    assert.doesNotMatch(body, /neon\.tech|postgres(ql)?:\/\/|fly\.dev|\.internal\b|localhost|127\.0\.0\.1|\bvol_|\bprj_|\bteam_|org-[a-z]+-[a-z]+-\d+/i, `${f}: infra`);
    assert.doesNotMatch(body, /google-analytics|googletagmanager|gtag\(|plausible|segment\.|hotjar|fonts\.googleapis|cdn\.|unpkg|jsdelivr/i, `${f}: tracker, font or CDN`);
  }
  // The only absolute origins in shipped files: the MCP URL, the SVG namespace and (index.html only, once) the
  // full film's Blob URL.
  for (const [f, body] of shipped()) {
    if (f.endsWith('README.md')) continue;
    const origins = [...body.matchAll(/https?:\/\/[^\s"'<)]+/g)].map((m) => m[0]);
    const allowed = (u: string) => u === MCP_URL || u === 'http://www.w3.org/2000/svg' || (f.endsWith('index.html') && u === FILM_SOUND_URL);
    assert.deepEqual(origins.filter((u) => !allowed(u)), [], f);
    if (!f.endsWith('index.html')) assert.ok(!body.includes('blob.vercel-storage.com'), `${f}: the Blob host only in index.html`);
  }
});

test('site (wow, film): ONE config point (the data-*-src paths on #film); poster, loops and captions same-origin in assets/film/, the full film from its pinned Blob URL; no <video> in the markup', () => {
  const film = /<div class="film" id="film"[^>]*>/.exec(html)?.[0] ?? '';
  const at = (n: string) => new RegExp(`\\s${n}="([^"]*)"`).exec(film)?.[1];
  // The four delivered files, pinned by path (swap a file in assets/film/ under the same name and nothing else changes).
  assert.equal(at('data-poster-src'), 'assets/film/zeusi-poster.jpg');
  assert.equal(at('data-loop-webm-src'), 'assets/film/zeusi-hero-loop-720p.webm');
  assert.equal(at('data-loop-mp4-src'), 'assets/film/zeusi-hero-loop-720p.mp4');
  // The full film: the exact public Blob URL (HTTP Range answered exactly; see FILM_SOUND_URL for why it is not the
  // same-origin path behind a rewrite). The canonical bytes stay in site/assets/film/ under the same name.
  assert.equal(at('data-sound-src'), FILM_SOUND_URL);
  assert.ok(statSync(join(SITE, 'assets', 'film', 'zeusi-explainer-full-1080p.mp4')).size === 39_406_821, 'the canonical full-film bytes stay in the repo');
  assert.equal(at('data-captions-src'), '');
  assert.equal(at('data-video-src'), undefined, 'the old single-URL attribute is retired');
  // Every other media path on #film (and every src anywhere) is a same-origin relative path or empty: no other
  // absolute, `//` or third-party URL.
  const media = [...film.matchAll(/\s(data-[a-z0-9-]*src)="([^"]*)"/g)].map((m) => [m[1]!, m[2]!] as const);
  assert.equal(media.length, 5);
  for (const [n, v] of media.filter(([n]) => n !== 'data-sound-src')) {
    assert.ok(v === '' || /^assets\/film\/[a-z0-9][a-z0-9._-]*\.(jpg|webm|mp4|vtt)$/i.test(v), `${n}: same-origin relative path or empty: ${v}`);
  }
  assert.doesNotMatch(film.replace(FILM_SOUND_ATTR, ''), /(https?:)?\/\//i, 'no other absolute or protocol-relative URL on #film');
  for (const [, v] of media.filter(([n, v]) => n !== 'data-sound-src' && v)) assert.ok(statSync(join(SITE, v)).isFile(), `exists: ${v}`);
  // The visible poster is the same file, with its real size (no layout shift), lazy.
  assert.match(html, /<img class="film-poster" src="assets\/film\/zeusi-poster\.jpg" width="1920" height="1080" alt="" loading="lazy" decoding="async">/);
  assert.equal(/<img class="film-poster" src="([^"]+)"/.exec(html)![1], at('data-poster-src'), 'the <img> and data-poster-src name the same poster');
  // No media element in the markup: nothing can preload; wow.js makes them when wanted.
  assert.doesNotMatch(html, /<video|<source[^>]*\.(mp4|webm)|<track|<link[^>]*(film\/|\.mp4|\.webm|as="video")/i, 'no media element and no film preload in the markup');
  assert.doesNotMatch(html.replace(film, '') + wow + css, /zeusi-explainer|1080p/, 'the full film path appears only in data-sound-src, never in a preload, a <source>, CSS or the script');
  assert.match(html, /<p class="film-soon">Film coming soon<\/p>/);
  assert.match(html, /<button type="button" class="film-play" hidden>Watch with sound<\/button>/, 'shown by wow.js only when data-sound-src is set');
  assert.match(css, /\.film\[data-sound-src\]:not\(\[data-sound-src=""\]\) \.film-soon \{ display: none; \}/, 'empty sound path: "Film coming soon"');
  assert.match(css, /aspect-ratio: 16 \/ 9/, 'reserved box: no layout shift');
});

test('site (wow, film, Range fix): no same-origin rewrite to Blob ships; first load stays well under 2 MB; the README says why', () => {
  // The bug was a deploy-only vercel.json rewrite of the same-origin film path to the Blob object: the CDN cached
  // one byte-range slice of it and replayed it for every Range request. No deploy config ships with the site, and
  // none in the repo may rewrite or proxy to Blob.
  const repo = fileURLToPath(new URL('../', import.meta.url));
  for (const f of ['vercel.json', join('site', 'vercel.json'), join('site', '_redirects'), join('site', 'middleware.js')]) {
    assert.throws(() => statSync(join(repo, f)), `${f} must not exist: no rewrite or proxy of the film`);
  }
  assert.ok(!siteFiles().some((f) => /vercel\.json$|_redirects$|middleware\.[jt]s$/.test(f)), 'no deploy config or edge proxy in site/');
  // First load: the page, its CSS and scripts, the logo and favicon, the largest hero variant and the lazy poster.
  // No film video is in it (no <video>, no preload; the full film only on "Watch with sound").
  const first = ['index.html', 'styles.css', 'connect.js', 'wow.js', 'logo.svg', 'favicon.svg', 'assets/hero.jpg', 'assets/film/zeusi-poster.jpg']
    .reduce((n, f) => n + statSync(join(SITE, f)).size, 0);
  assert.ok(first < 1_000_000, `first-load bytes ${first} stay well under 2 MB`);
  assert.doesNotMatch(html, /<link[^>]*(preload|prefetch|preconnect|dns-prefetch)[^>]*(blob\.vercel-storage|film\/|\.mp4)/i, 'no preload or preconnect of the film');
  // The README documents the one absolute URL and why the rewrite must not ship.
  const readme = readFileSync(join(SITE, 'README.md'), 'utf8');
  assert.ok(readme.includes(FILM_SOUND_URL), 'README names the Blob URL');
  assert.match(readme, /Range/);
  assert.match(readme, /must not ship/i);
});

test('site (wow, film): the muted loop lists WebM before MP4, never the full film; the full film is made only by "Watch with sound"', () => {
  const body = /\(function film\(\) \{([\s\S]*?)\n {2}\}\)\(\);/.exec(wow)![1]!;
  // Loop: WebM first, then MP4, as <source> children; preload none; muted; only on scroll-in with motion allowed.
  assert.match(body, /var loopSrcs = \[\[attr\('data-loop-webm-src'\), 'video\/webm'\], \[attr\('data-loop-mp4-src'\), 'video\/mp4'\]\]/);
  const makeLoop = /function makeLoop\(\) \{([\s\S]*?)\n {4}\}/.exec(body)![1]!;
  assert.match(makeLoop, /preload = 'none'/);
  assert.match(makeLoop, /v\.muted = true;/);
  assert.match(makeLoop, /createElement\('source'\)/);
  assert.doesNotMatch(makeLoop, /soundSrc|v\.src\s*=/, 'the loop element never carries the full film');
  assert.match(body, /if \(reduce \|\| saveData \|\| !hasIO \|\| loopSrcs\.length === 0\) return;\n/, 'no preview under reduced motion, Save-Data or without IntersectionObserver');
  assert.ok(body.indexOf('if (reduce || saveData') < body.indexOf('new IntersectionObserver'), 'the preview is only started from the observer, after the guard');
  // The full film: soundSrc is assigned in makeFull only, and makeFull is called only from the button's click handler.
  assert.equal((body.match(/soundSrc/g) ?? []).length, 5, 'declared, guard, button visibility, click guard, makeFull');
  const makeFull = /function makeFull\(\) \{([\s\S]*?)\n {4}\}/.exec(body)![1]!;
  assert.match(makeFull, /preload = 'none'/);
  assert.match(makeFull, /v\.controls = true;/);
  assert.match(makeFull, /v\.src = soundSrc;/);
  assert.match(makeFull, /track\.kind = 'captions'/);
  assert.equal((body.match(/makeFull\(\)/g) ?? []).length, 2, 'defined once, called once');
  const click = /button\.addEventListener\('click', function \(\) \{([\s\S]*?)\n {4}\}\);/.exec(body)![1]!;
  assert.match(click, /var v = makeFull\(\);/);
  assert.match(click, /if \(failed \|\| !soundSrc\) return;/);
  assert.match(click, /dropLoop\(\);[\s\S]*makeFull/, 'the preview is dropped (not unmuted) before the full film starts');
  assert.match(click, /v\.muted = false;/);
  assert.doesNotMatch(click, /loop\.muted|makeLoop/, '"Watch with sound" never just unmutes the loop');
  assert.match(body, /button\.hidden = !soundSrc;/, 'empty sound path: no button');
  assert.match(body, /if \(!soundSrc && loopSrcs\.length === 0\) return;/, 'nothing configured: nothing runs');
});

test('site (wow, film, review r1 F1/F3): every video goes below the overlay; the preview has an always-visible pause control', () => {
  // Review r1 F1: the overlay stacks above the video, and the video is inserted below the overlay, so
  // "Watch with sound" stays the hit target and its focus ring stays visible while the preview plays.
  const rule = (sel: string) => [...css.matchAll(new RegExp(`(?:^|\\n)${sel.replace(/[.]/g, '\\.')} \\{([^}]*)\\}`, 'g'))].map((m) => m[1]!).join(';');
  const z = (sel: string) => Number(/z-index:\s*(-?\d+)/.exec(rule(sel))?.[1] ?? 'NaN');
  assert.ok(z('.film-overlay') >= 1, '.film-overlay has a z-index');
  assert.match(rule('.film-overlay'), /position: absolute/);
  assert.doesNotMatch(css, /\.film-video[^{]*\{[^}]*z-index/, 'the video never stacks itself above the overlay');
  assert.doesNotMatch(css, /\.film-poster, \.film-video \{[^}]*z-index/);
  assert.doesNotMatch(css, /\.film-overlay[^{]*\{[^}]*(pointer-events: none|opacity: 0|visibility: hidden)/, 'the overlay is never click-through or invisible while the preview plays');
  assert.doesNotMatch(css, /\.film-playing[^{]*\.film-overlay/, 'no hover-only reveal of the overlay during the preview');
  assert.match(wow, /function below\(v\) \{ frame\.insertBefore\(v, overlay/, 'videos go in before (below) the overlay');
  assert.equal((wow.match(/below\(v\);/g) ?? []).length, 2, 'both the loop and the full film use below()');
  assert.doesNotMatch(wow, /(frame|root)\.appendChild\(/, 'never appended after the overlay');
  // Review r1 F3 (WCAG 2.2.2): a labelled, keyboard-reachable pause control while the muted preview plays;
  // always visible (not only on hover), above the overlay, hidden until a preview exists and once sound plays.
  assert.match(html, /<button type="button" class="film-pause" hidden>Pause preview<\/button>\n {8}<\/div>/, 'a native button inside .film-frame, after the overlay, hidden without JS');
  assert.ok(z('.film-pause') > z('.film-overlay'), '.film-pause stacks above the overlay');
  assert.match(css, /\.film-pause\[hidden\] \{ display: none; \}/);
  assert.doesNotMatch(css, /\.film-pause[^{]*\{[^}]*(opacity: 0|visibility: hidden|pointer-events: none)/, 'never hidden by hover-only styles');
  assert.doesNotMatch(css, /\.film-playing[^{]*\.film-pause/, 'not tied to the overlay\'s hover reveal');
  assert.match(wow, /pause\.textContent = loop && !loop\.paused \? 'Pause preview' : 'Play preview';/, 'label follows the real state');
  assert.match(wow, /pause\.hidden = !loop \|\| failed \|\| root\.classList\.contains\('film-sound'\);/);
  assert.match(wow, /v\.addEventListener\('pause', sync\)/);
  assert.match(wow, /userPaused = true;\n {10}loop\.pause\(\);/);
  assert.match(wow, /if \(root\.classList\.contains\('film-sound'\) \|\| userPaused\) return;/, 'a preview the user paused stays paused on scroll-in');
});

test('site (wow, terminal): the static copy is the reply the server builds for a new, empty personal workspace (form B); reduced motion and screen readers handled', () => {
  const g = sectionOf('first-run-demo');
  const pre = /<pre class="term-full"><code>([\s\S]*?)<\/code><\/pre>/.exec(g)![1]!;
  const lines = [...pre.matchAll(/<span class="tl[^"]*">([\s\S]*?)<\/span>/g)].map((m) => m[1]!.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'));
  // Offline check against the exported constants (the live handler check is test/site-terminal.test.ts).
  assert.deepEqual(lines, terminalLines({ workspace: 'personal', empty: true, rules_served: 0, message: personalEmptyStates(true).startup, welcome: welcomeMarkdown(fillMemoryLine(true)) }));
  assert.match(g, /class="term-bar" aria-hidden="true"/);
  // Review r1 F6: <figcaption> is the first child of the figure (valid HTML), and still names it.
  assert.match(g, /<figure class="term" data-term>\s*<figcaption class="sr-only">The zeusi_startup reply for a new, empty workspace<\/figcaption>\s*<div class="term-bar"/);
  assert.equal((g.match(/<figcaption/g) ?? []).length, 1);
  // Review r1 F5: the lead says what is verbatim (message, welcome) and what is not (the first two lines).
  const lead = plain(/<p class="lead">([\s\S]*?)<\/p>/.exec(g)![1]!).trim();
  assert.equal(lead, 'In a new, empty personal workspace with filling on, zeusi_startup replies with a message and a welcome . Both are copied below, word for word, from the server. The first two lines are not part of the reply: they show your request and three fields of the reply ( workspace , empty , rules_served ). The reply has more fields. Your assistant shows it in its own way.');
  assert.deepEqual([lines[0], lines[1]!.split(' → ')[0], lines[2]], ['› Run zeusi_startup', 'zeusi_startup', 'message:'], 'line 1 is the request, line 2 the three fields, then message');
  assert.doesNotMatch(g, /This is the reply[^.]*word for word/, 'no claim that the whole strip is the reply');
  assert.doesNotMatch(g, /class="term-typed"/, 'the typed overlay is made by wow.js, aria-hidden');
  assert.match(wow, /overlay\.setAttribute\('aria-hidden', 'true'\)/);
  assert.match(wow, /if \(!term \|\| reduce\) return;/, 'reduced motion: no typing, the full text shows');
  assert.match(css, /\.typing \.term-full code, \.typing \.term-full \.tl \{ color: transparent; \}/, 'the static copy stays in the a11y tree while typing');
  assert.doesNotMatch(css, /\.typing \.term-full[^{]*\{[^}]*(visibility: hidden|display: none)/);
});

const pawsSrc = (): string => {
  const a = wow.indexOf('(function paws() {');
  const b = wow.indexOf('})();', a);
  assert.ok(a > 0 && b > a, 'paws() exists');
  return wow.slice(a, b);
};

test('site (wow, paws): fine pointers leave a trail page-wide (not only on the CTAs), throttled and capped, nodes removed, layer never takes input', () => {
  const p = pawsSrc();
  assert.doesNotMatch(p, /pointer: fine|hover: hover/, 'no fine-pointer early return: touch gets its own path');
  assert.doesNotMatch(p, /querySelectorAll|btn-primary/, 'not bound to the CTAs any more');
  assert.match(p, /document\.addEventListener\('pointermove', move, passive\);/, 'page-wide pointermove');
  assert.match(p, /function fine\(ev\) \{ return ev\.pointerType === 'mouse' \|\| ev\.pointerType === 'pen'; \}/);
  assert.match(p, /function move\(ev\) \{\n {6}if \(!fine\(ev\)\) \{/, 'a finger drag never takes the trail path');
  assert.match(p, /var MAX = 12;/);
  assert.match(p, /var STEP = 26;/);
  assert.match(p, /if \(dx \* dx \+ dy \* dy < STEP \* STEP\) return;/, 'throttled by distance');
  assert.match(p, /while \(layer\.childNodes\.length >= MAX\) layer\.removeChild\(layer\.firstChild\);/, 'capped');
  assert.match(p, /left = !left;/, 'alternates left/right');
  assert.match(p, /node\.addEventListener\('animationend', gone\);/);
  assert.match(p, /window\.setTimeout\(gone, 1500\);/, 'timer backstop');
  assert.match(p, /removeChild\(node\)/);
  assert.match(p, /layer\.setAttribute\('aria-hidden', 'true'\);/);
  assert.doesNotMatch(p, /tabindex|tabIndex|focus\(/, 'never focusable, never moves focus');
  assert.match(css, /\.paw-layer \{ position: fixed; inset: 0; z-index: 50; pointer-events: none;/);
  assert.match(css, /\.paw \{[^}]*pointer-events: none;/);
  assert.match(css, /\.paw-glow \{[^}]*pointer-events: none;/);
  assert.match(css, /\.paw-glow \{[^}]*position: absolute;/, 'out of flow: no layout shift');
  assert.equal((html.match(/<a class="btn btn-primary" href="#connect">Connect your AI<\/a>/g) ?? []).length, 2, 'hero and terminal CTAs');
});

test('site (wow, paws): every touch tap flashes one paw with a soft amber glow; scrolls and cancels never stamp; nothing is blocked', () => {
  const p = pawsSrc();
  assert.match(p, /var TAP = 1[2-6];/, 'tap threshold about 12-16 px');
  assert.match(p, /document\.addEventListener\('pointerdown', press, passive\);/);
  assert.match(p, /document\.addEventListener\('pointerup', release, passive\);/);
  assert.match(p, /document\.addEventListener\('pointercancel', function \(\) \{ down = null; \}, passive\);/, 'pointercancel resets');
  assert.match(p, /down = \(fine\(ev\) \|\| ev\.isPrimary === false\) \? null : \{ id: ev\.pointerId, x: ev\.clientX, y: ev\.clientY \};/, 'touch / non-mouse-non-pen only');
  assert.match(p, /if \(mx \* mx \+ my \* my > TAP \* TAP\) down = null;/, 'moving past the threshold (a scroll) drops the tap');
  assert.match(p, /if \(!d \|\| fine\(ev\) \|\| ev\.pointerId !== d\.id\) return;/, 'a mouse click never flashes a tap paw');
  assert.match(p, /if \(dx \* dx \+ dy \* dy > TAP \* TAP\) return;\n {6}tap\(ev\.clientX, ev\.clientY\);/, 'one stamp at the tap point');
  assert.match(p, /place\(print\('paw-glow'\), x, y, 0\);\n {6}place\(print\('paw paw-tap'\), x, y,/, 'glow then one paw, both at the point');
  // Never blocks: no cancelling, no stopping, no touch-action/overflow changes; every listener passive.
  assert.doesNotMatch(p, /preventDefault|stopPropagation|stopImmediatePropagation|touch-action|touchAction|overflow/);
  assert.match(p, /var passive = \{ passive: true \};/);
  const adds = p.match(/addEventListener\([^\n]*\n?/g) ?? [];
  const docAdds = adds.filter((l) => l.startsWith("addEventListener('pointer"));
  assert.equal(docAdds.length, 5, 'pointermove, pointerdown, pointerup, pointercancel, pointerout');
  for (const l of docAdds) assert.match(l, /, passive\);\n?$/, `passive: ${l.trim()}`);
  // Amber glow from the existing palette, no image or extra request.
  assert.match(css, /\.paw-glow \{[^}]*background: radial-gradient\(circle, var\(--orange\) 0%, transparent 70%\);/);
  assert.match(css, /\.paw-glow \{[^}]*animation: paw-glow 0\.6s ease-out forwards;/);
  assert.match(css, /@keyframes paw-glow \{\n {2}0% \{ opacity: 0\.5;[^}]*\}\n {2}100% \{ opacity: 0;/, 'glow fades out');
  assert.match(css, /\.paw-tap \{[^}]*animation: paw-tap 0\.7s ease-out forwards;/);
  assert.match(css, /@keyframes paw-tap \{[\s\S]*?100% \{ opacity: 0;/, 'tap paw fades out');
  assert.doesNotMatch(css.slice(css.indexOf('.paw-layer'), css.indexOf('What Zeusi remembers')), /url\(/, 'no image request');
});

test('site (wow, paws): reduced motion early-returns (no trail, no tap paw, no glow) and CSS hides the effect', () => {
  const p = pawsSrc();
  assert.match(p, /^\(function paws\(\) \{\n {4}if \(reduce\) return;\n/, 'first statement');
  const rm = css.slice(css.indexOf('@media (prefers-reduced-motion: reduce)'));
  assert.match(rm, /\.paw, \.paw-glow \{ animation: none; \}/);
  assert.match(rm, /\.paw-layer \{ display: none; \}/);
});

test('site (wow, remembers): example cards labelled as not real, values from the server\'s own documented examples and wire field names', () => {
  const r = sectionOf('remembers');
  const rText = plain(r);
  assert.ok(html.indexOf('<section id="remembers"') > html.indexOf('<section id="first-5-minutes"') && html.indexOf('<section id="remembers"') < html.indexOf('<section id="about"'));
  assert.match(r, /<p class="example-flag">Example &mdash; not real data<\/p>/);
  const d = JSON.parse(DECISION_EXAMPLE_JSONL) as { kind: string; who: string; said_at: string; exact_words: string };
  inOrder(rText, ['Decision', d.exact_words, 'kind', d.kind, 'who', d.who, 'said_at', d.said_at, 'source_uri', 'source_ts'], 'decision card');
  const lock = /locks:\n {2}- (.+)\n/.exec(RULE_EXAMPLE_NOTE)![1]!;
  const uri = `${HQ_PROFILE.storedPrefix}${RULE_EXAMPLE_PATH}`;
  inOrder(rText, ['Lock (standing rule)', lock, 'origin', 'note_lock', 'id', `${uri}#lock-1`, 'zeusi_startup'], 'lock card');
  const title = /title: (.+)\n/.exec(RULE_EXAMPLE_NOTE)![1]!;
  const why = /---\n(Why: .+)\n$/.exec(RULE_EXAMPLE_NOTE)![1]!;
  inOrder(rText, ['Source', title, why, 'path', RULE_EXAMPLE_PATH, 'source_uri', uri, 'cite', '<source_uri> @ <source_ts>'], 'source card');
  assert.doesNotMatch(r, /Northbank|the team|Plankiva|Plankiva/i, 'no real company or customer data');
  assert.match(wow, /if \(cards\.length === 0 \|\| reduce \|\| !hasIO\) return;/, 'static under reduced motion / no IO');
  assert.doesNotMatch(html, /class="[^"]*reveal-ready/, 'hidden state only ever added by wow.js');
});
