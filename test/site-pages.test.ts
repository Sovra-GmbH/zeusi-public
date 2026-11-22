// zeusi.ai trust pages (owner brief of 2026-11-21): the operator line and the Privacy / Terms / Security links
// in a footer on EVERY site page; /privacy, /terms and /security as directory indexes (site/<page>/index.html),
// so Vercel serves them from the static files with no vercel.json; every page passes the no-name, wall,
// over-claim and no-pricing checks, as raw bytes and as text; the facts on the pages are pinned to the code
// constants they quote, so a change in the code turns this file red until the page is updated.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_EMBED_BASE_URL, OPENAI_EMBED_MODEL } from '../src/embeddings.ts';
import { LOG_FIELDS } from '../src/mcp-log.ts';
import { ALL_TOOL_NAMES } from '../src/mcp-server.ts';
import { GITHUB_SCOPES } from '../src/mcp-oauth-github.ts';
import { ACCESS_TTL_MS, REFRESH_TTL_MS } from '../src/mcp-oauth-store.ts';
import { COOKIE_NAME, TXN_TTL_MS } from '../src/mcp-oauth.ts';
import { wallSignal } from '../src/mcp-wall.ts';
import { AUDIT_FIELDS } from '../src/signin-audit.ts';
import { ENROLL_AUDIT_ACTIONS, ENROLL_AUDIT_FIELDS } from '../src/enroll-audit.ts';
import { RECOVERY_LIMIT, RECOVERY_WINDOW_MS, RecoveryAttemptLimiter } from '../src/recovery-limit.ts';
import { KEY_WRAP_KINDS } from '../src/tenants.ts';
import { WS_AUDIT_ACTIONS, WS_AUDIT_FIELDS } from '../src/workspace-audit.ts';
import { PREVIEW_TTL_MS } from '../src/workspace-write.ts';
import {
  ADMIN_LOGIN_SENTENCE, ALLOWED_ENCRYPTION, OWNER_ENCRYPTION_LINE, overclaims, PRIVACY_KEY_DETAIL, SIGNED_IN_SENTENCE, siteOverclaims,
} from './helpers/overclaim.ts';
import { hasNonRoleOperatorAddress, ROLE_EMAIL } from './helpers/owner-terms.ts';
import { safeTmpDir } from './helpers/safe-tmp.ts';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const SITE = join(ROOT, 'site');
const PAGES = ['privacy', 'terms', 'security'] as const;
// Owner correction, 21 Nov 2026: the registered seat is Cham (canton of Zug); sovra.ch footer and contact.
const OPERATOR = 'Zeusi is run by Sovra GmbH, Cham, Switzerland.';
/** The imprint block on Privacy and Terms, as text (sovra.ch: address, UID and the one mailto, checked 21 Nov 2026). */
const IMPRINT = 'Imprint Sovra GmbH Sinserstrasse 65 6330 Cham Switzerland Registered seat: Cham (canton of Zug) UID: CHE-370.623.395 Email: hello@sovra.ch';

function htmlFiles(dir = SITE): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? htmlFiles(p) : p.endsWith('.html') ? [p] : [];
  });
}
const rel = (f: string) => relative(SITE, f).split('\\').join('/');
const read = (page: string) => readFileSync(join(SITE, page, 'index.html'), 'utf8');
/** Visible text: comments and tags removed, the entities the pages use decoded, whitespace collapsed. */
const plain = (s: string) => s.replace(/<!--[\s\S]*?-->/g, ' ').replace(/<[^>]+>/g, ' ')
  .replace(/&rsquo;/g, '’').replace(/&ldquo;|&rdquo;/g, '"').replace(/&quot;/g, '"').replace(/&mdash;/g, '—')
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
const all = () => htmlFiles().map((f) => [rel(f), readFileSync(f, 'utf8')] as const);

test('site pages: /privacy, /terms and /security are directory indexes; no vercel.json anywhere', () => {
  for (const p of PAGES) assert.ok(existsSync(join(SITE, p, 'index.html')), `site/${p}/index.html`);
  assert.deepEqual(all().map(([f]) => f).sort(), ['index.html', 'privacy/index.html', 'security/index.html', 'terms/index.html']);
  // Vercel serves site/<page>/index.html at /<page> with no config; a flat privacy.html would need cleanUrls.
  assert.ok(!existsSync(join(ROOT, 'vercel.json')) && !existsSync(join(SITE, 'vercel.json')), 'no vercel.json');
  for (const p of PAGES) assert.ok(!existsSync(join(SITE, `${p}.html`)), `no flat ${p}.html`);
});

test('site pages: every page ends with the footer: the operator line and the Privacy, Terms and Security links', () => {
  for (const [f, h] of all()) {
    assert.equal(h.split('<footer').length - 1, 1, `${f}: one footer`);
    const m = /<\/main>\s*(<footer class="site-footer">[\s\S]*?<\/footer>)\s*<\/body>\s*<\/html>\s*$/.exec(h);
    assert.ok(m, `${f}: the footer comes right after </main> and is the last thing in <body>`);
    const footer = m![1]!;
    assert.ok(plain(footer).includes(OPERATOR), `${f}: operator line`);
    assert.equal(plain(footer).trim(), `${OPERATOR} Privacy Terms Security`, `${f}: the footer says exactly the operator line and the links`);
    const links = [...footer.matchAll(/<a href="([^"]+)"[^>]*>([^<]+)<\/a>/g)].map((x) => [x[1], x[2]]);
    assert.deepEqual(links, [['/privacy', 'Privacy'], ['/terms', 'Terms'], ['/security', 'Security']], `${f}: links`);
    assert.match(footer, /<nav aria-label="Legal">/, `${f}: a labelled nav`);
  }
  // The old city in the operator line is gone from the whole site (owner correction, 21 Nov 2026): the seat is
  // Cham, and no other office is named. Built from fragments, so this file does not spell it either.
  const OLD_CITY = new RegExp(`z(?:u|ü|&uuml;)${['ri', 'ch'].join('')}`, 'i');
  for (const f of [...htmlFiles(), join(SITE, 'README.md')]) assert.doesNotMatch(readFileSync(f, 'utf8'), OLD_CITY, `${rel(f)}: only Cham`);
  // The current page is marked in its own footer.
  for (const p of PAGES) assert.match(read(p), new RegExp(`<a href="/${p}" aria-current="page">`), p);
});

test('site pages: no person, login or email address, and nothing the wall would hold back, on any page', () => {
  for (const [f, h] of all()) {
    for (const body of [h, plain(h)]) {
      assert.equal(hasNonRoleOperatorAddress(body), false, `${f}: non-role operator address`);
      // The only address allowed is the role address on the live sovra.ch; any other address is red.
      for (const m of body.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g)) assert.equal(m[0], ROLE_EMAIL, `${f}: only ${ROLE_EMAIL}`);
    }
    assert.equal(wallSignal([plain(h)]), false, `${f}: the wall`);
  }
  // The operator domain: exactly the role address passes; any other local part (an invented security@,
  // a longer local part ending in hello) is still caught. Ordinary words are not denied.
  assert.equal(hasNonRoleOperatorAddress('hello world zeusi postgres assistant'), false, 'ordinary words are not denied');
  for (const ok of [ROLE_EMAIL, `write to ${ROLE_EMAIL}.`, `<a href="mailto:${ROLE_EMAIL}">${ROLE_EMAIL}</a>`]) assert.equal(hasNonRoleOperatorAddress(ok), false, ok);
  for (const bad of ['security@sovra.ch', 'privacy@sovra.ch', 'x.hello@sovra.ch', 'hello2@sovra.ch', 'write to info@sovra.ch.']) assert.equal(hasNonRoleOperatorAddress(bad), true, bad);
  // The role address is shown where it belongs: contact on Privacy and Terms, deletion and rights on Privacy, reports on Security.
  for (const p of PAGES) assert.ok(read(p).includes(`<a href="mailto:${ROLE_EMAIL}">${ROLE_EMAIL}</a>`), `${p}: ${ROLE_EMAIL}`);
  // The wall check really runs (a mutant that stubs it out must be seen): the seed rules hold back a connection string.
  assert.equal(wallSignal(['postgresql://user@host/db']), true, 'wall reaches its host rules');
});

/**
 * The visible blocks (p, li, h1-h3) inside <main>, in order, as text: the owner line's neighbours are the blocks around it.
 * The site footer (operator line, outside <main>, on every page) is not a neighbour; the PR body flags it for the owner.
 */
const blocks = (h: string) => [...(/<main\b[\s\S]*?<\/main>/.exec(h)?.[0] ?? '').replace(/<!--[\s\S]*?-->/g, ' ').matchAll(/<(p|li|h[1-3])\b[^>]*>([\s\S]*?)<\/\1>/g)].map((m) => plain(m[2]!).trim());

test('site pages: the owner encryption line, word for word, on the landing and Security pages; the key detail on Privacy; no other encryption or operator-blindness claim', () => {
  for (const [f, h] of all()) {
    assert.deepEqual(siteOverclaims(h), [], `${f}: bytes`);
    assert.deepEqual(siteOverclaims(plain(h)), [], `${f}: text`);
    // The encryption-proof marker is gone from every page (the owner approved the line, 21 Nov 2026 06:50).
    assert.ok(!h.includes('TODO(encryption-proof)') && !/encryption-proof/i.test(h), `${f}: no encryption-proof marker`);
  }
  // The owner line: exactly once on index and Security, plain text, never on Privacy or Terms.
  const where: Record<string, number> = { 'index.html': 1, 'security/index.html': 1, 'privacy/index.html': 0, 'terms/index.html': 0 };
  for (const [f, h] of all()) {
    assert.equal(plain(h).split(OWNER_ENCRYPTION_LINE).length - 1, where[f], `${f}: the owner line count`);
    assert.equal(h.split(OWNER_ENCRYPTION_LINE).length - 1, where[f], `${f}: the owner line in the bytes, unbroken by markup`);
  }
  assert.ok(read('security').includes(`<p>${OWNER_ENCRYPTION_LINE}</p>`), 'security: the line is its own plain paragraph');
  // No the team or team-workspace mention in or next to the line (owner decision): the block holding it and the blocks
  // right before and after it name neither.
  for (const f of ['index.html', 'security/index.html']) {
    const b = blocks(readFileSync(join(SITE, f), 'utf8'));
    const i = b.findIndex((x) => x.includes(OWNER_ENCRYPTION_LINE));
    assert.ok(i >= 0, `${f}: the line is in a block`);
    for (const x of b.slice(Math.max(0, i - 1), i + 2)) assert.doesNotMatch(x, /team|team|operator/i, `${f}: no the team or team workspace next to the line: ${x}`);
  }
  // Security: the section, word for word, in this order.
  const sec = plain(read('security'));
  assert.ok(sec.includes(`What the people who run Zeusi can see Your workspace is kept apart from other users. ${OWNER_ENCRYPTION_LINE} ${SIGNED_IN_SENTENCE} ${ADMIN_LOGIN_SENTENCE} ${ALLOWED_ENCRYPTION[0]} They can also see`), 'security: the section');
  // Privacy: the owner's factual key detail, word for word, then what the admin login can see, then the negative sentence.
  const pri = plain(read('privacy'));
  assert.ok(pri.includes(`Who can read your workspace Your workspace is kept apart from other users: another user’s Zeusi sign-in cannot read it. ${PRIVACY_KEY_DETAIL.join(' ')} ${ADMIN_LOGIN_SENTENCE} ${ALLOWED_ENCRYPTION[0]} More on this`), 'privacy: the section');
  assert.doesNotMatch(blocks(read('privacy')).find((x) => x.startsWith(PRIVACY_KEY_DETAIL[0]))!, /team|team|operator/i, 'privacy: the key detail names no the team or team workspace');
  // Every encryption-adjacent sentence: each pinned one appears exactly where it belongs, and nowhere else.
  for (const [f, h] of all()) {
    const t = plain(h);
    const n = (x: string) => t.split(x).length - 1;
    assert.equal(n(ALLOWED_ENCRYPTION[0]!), f === 'terms/index.html' ? 0 : 1, `${f}: the negative sentence`);
    assert.equal(n(ADMIN_LOGIN_SENTENCE), f === 'terms/index.html' ? 0 : 1, `${f}: the admin-login sentence`);
    assert.equal(n(SIGNED_IN_SENTENCE), where[f], `${f}: the signed-in caveat sits with the owner line`);
    assert.equal(t.split(/decrypt/i).length - 1, f === 'terms/index.html' ? 0 : 1, `${f}: decrypt once, in the pinned sentence`);
    assert.doesNotMatch(t, /can read workspaces|admin database login can read/i, `${f}: the old admin-login sentence is gone`);
    assert.match(t, f === 'terms/index.html' ? /./ : /another user’s Zeusi sign-in cannot read it|Another user’s Zeusi sign-in cannot read it/, `${f}: isolation`);
  }
  // The exemption is exact and site-only: a variant, or a claim after the line, is still caught.
  assert.ok(overclaims(OWNER_ENCRYPTION_LINE).length > 0, 'the server-copy check never gets the exemption');
  for (const bad of [
    'All workspaces are encrypted.', 'It is zero-knowledge.', 'Only you can read it.', 'E2EE.', 'Operators cannot read it.',
    'Your memory is encrypted. Only you hold the keys.', 'Your data is encrypted. Only you hold the key.', `${OWNER_ENCRYPTION_LINE} Nobody else can read it.`,
    `<p>${OWNER_ENCRYPTION_LINE}</p><p>Every workspace is encrypted.</p>`, 'Your memory is encrypted and only you hold the key.',
  ]) assert.ok(siteOverclaims(bad).length > 0, bad);
});

test('site pages: no page says "draft" in its <title>, meta description or visible text (owner, 21 Nov 2026 07:44)', () => {
  // The draft status is gone; search results and link previews (meta description, og/twitter tags) must not say it either.
  for (const [f, h] of all()) {
    const title = /<title>([\s\S]*?)<\/title>/.exec(h);
    assert.ok(title, `${f}: has a <title>`);
    const desc = /<meta name="description" content="([^"]*)">/.exec(h);
    assert.ok(desc, `${f}: has a meta description`);
    const metas = [...h.matchAll(/<meta\b[^>]*\bcontent="([^"]*)"/g)].map((m) => m[1]!);
    for (const [where, s] of [['title', title![1]!], ['meta description', desc![1]!], ...metas.map((m) => ['meta content', m]), ['visible text', plain(h)]] as const) {
      assert.doesNotMatch(s, /\bdraft\b/i, `${f}: no "draft" in the ${where}`);
    }
  }
});

test('site pages: no pricing, plan or business-model words on any page', () => {
  const PRICING = /\bpric(?:e|es|ed|ing)\b|\bfree\b|\bcosts?\b|\bsubscri|\bbilling\b|\bbilled\b|\bpaid\b|\bpayment|\btrial\b|\bpremium\b|\bpro plan\b|\bCHF\b|\bUSD\b|\bEUR\b|[$€£]\s?\d|\bper (?:month|year|seat|user)\b/i;
  for (const [f, h] of all()) assert.doesNotMatch(plain(h), PRICING, f);
});

test('site pages: no draft line on any page (owner, 21 Nov 2026 07:44); every unknown is a visible [TODO: …]', () => {
  // The owner removed the visible "Draft — under review" box from Privacy and Terms; it must not come back on any page.
  // The [TODO: …] and [Open question: …] markers below stay: they are the honest unknowns.
  for (const [f, h] of all()) {
    assert.doesNotMatch(h, /class="[^"]*\bdraft\b/, `${f}: no draft box`);
    assert.doesNotMatch(plain(h), /\bDraft\s*[—–-]\s*under review\b|\bunder review\b|This text is not final/i, `${f}: no draft line`);
  }
  for (const p of ['privacy', 'terms'] as const) assert.match(read(p), /<main class="connect legal" id="[a-z]+">\s*<h1>/, `${p}: the page opens with its heading`);
  // Fix r2: the owner filled the legal defaults (21 Nov 2026). What is left is exactly the genuinely unknown.
  const NEED: Record<(typeof PAGES)[number], string[]> = {
    privacy: [
      'legal review: data processing agreements with each provider, and the legal basis for transfers outside Switzerland and the EU',
      'retention periods for workspaces, sign-in records, write records, logs and feedback',
      'how long Fly.io keeps snapshots of the Zeusi server’s disk',
      'when these snapshots and branches are removed',
    ],
    terms: [],
    security: [],
  };
  for (const p of PAGES) {
    const h = read(p);
    const todos = [...plain(h).matchAll(/\[TODO: ([^\]]+)\]/g)].map((m) => m[1]!);
    assert.deepEqual(todos, NEED[p], `${p}: the open TODOs`);
    // Every placeholder is visible and styled: inside <span class="todo">, never in a comment or an attribute.
    assert.equal(h.split('[TODO:').length - 1, h.split('<span class="todo">[TODO:').length - 1, `${p}: every [TODO: is a visible span`);
  }
  // The EU-representative question stays a visible, flagged open question: nobody is appointed or named.
  assert.ok(read('privacy').includes('<p><span class="todo">[Open question: is an EU representative under GDPR art. 27 needed?]</span></p>'), 'privacy: art. 27 open question');
  for (const p of PAGES) assert.doesNotMatch(plain(read(p)), /\bEU representative is\b|\bour EU representative\b|\brepresentative in the EU is\b/i, `${p}: no representative appointed`);
});

test('site pages: static only (no script, no inline style), the landing stylesheet, same-origin links', () => {
  for (const p of PAGES) {
    const h = read(p);
    assert.doesNotMatch(h, /<script\b/i, `${p}: no script`);
    assert.doesNotMatch(h, /\sstyle="|<style\b|\bon[a-z]+="/i, `${p}: no inline style or handler`);
    assert.match(h, /<link rel="stylesheet" href="\.\.\/styles\.css">/, `${p}: styles.css`);
    assert.match(h, /<link rel="icon" href="\.\.\/favicon\.svg" type="image\/svg\+xml">/, `${p}: favicon`);
    assert.match(h, /<a class="brand" href="\/" aria-label="zeusi home">/, `${p}: home link`);
    for (const m of h.matchAll(/(?:href|src)="([^"]+)"/g)) {
      if (m[1] === `mailto:${ROLE_EMAIL}`) continue; // the one role address, and no other mailto
      assert.match(m[1]!, /^(?:\/(?!\/)|\.\.\/)/, `${p}: ${m[1]} is same-origin`);
    }
  }
});

test('site pages: the facts on the pages match the code they quote', () => {
  const privacy = plain(read('privacy'));
  const security = plain(read('security'));
  // GitHub sign-in scopes (src/mcp-oauth-github.ts).
  for (const s of GITHUB_SCOPES.split(' ')) assert.ok(privacy.includes(s), `scope ${s}`);
  assert.equal(GITHUB_SCOPES.split(' ').length, 2);
  // Lifetimes (src/mcp-oauth.ts, src/mcp-oauth-store.ts, src/workspace-write.ts).
  assert.equal(TXN_TTL_MS, 10 * 60_000);
  assert.equal(PREVIEW_TTL_MS, 30 * 60_000);
  assert.equal(ACCESS_TTL_MS, 60 * 60_000);
  assert.equal(REFRESH_TTL_MS, 30 * 86_400_000);
  for (const t of ['sign-in cookie after 10 minutes', 'a preview after 30 minutes', 'an access token after 1 hour', 'a refresh token after 30 days', 'sets one cookie for 10 minutes', 'keeps it for up to 30 minutes']) {
    assert.ok(privacy.includes(t), t);
  }
  for (const t of ['An access token lasts 1 hour.', 'lasts 30 days']) assert.ok(security.includes(t), t);
  // OpenAI embeddings: the model and the EU endpoint (src/embeddings.ts).
  assert.ok(privacy.includes(OPENAI_EMBED_MODEL), 'embedding model');
  assert.equal(new URL(DEFAULT_EMBED_BASE_URL).host, 'eu.api.openai.com');
  assert.ok(privacy.includes('No text from a personal workspace is sent to OpenAI.'));
  // Logs and sign-in records hold no text, no email, no IP (src/mcp-log.ts, src/signin-audit.ts).
  assert.ok(!LOG_FIELDS.some((f) => /query|text|body|email|ip/i.test(f)), 'request log fields');
  assert.ok(!AUDIT_FIELDS.some((f) => /email|ip/i.test(f)), 'sign-in record fields');
  assert.deepEqual([...AUDIT_FIELDS], ['ts', 'request_id', 'github_id', 'login', 'tenant_id', 'action', 'outcome']);
  // Hosting: Fly region fra = Frankfurt (fly.toml).
  assert.match(readFileSync(join(ROOT, 'fly.toml'), 'utf8'), /^primary_region = "fra"$/m);
  for (const t of [privacy, security]) assert.ok(t.includes('Fly.io') && t.includes('Frankfurt'), 'Fly in Frankfurt');
  // Request log: every field is described (src/mcp-log.ts LOG_FIELDS, in order).
  assert.deepEqual([...LOG_FIELDS], ['ts', 'request_id', 'token_id', 'assistant', 'class', 'tool', 'duration_ms', 'hit_count', 'withheld_count', 'redacted_count', 'status', 'error_class']);
  const REQ = 'the time, a request id, an access id, a label for the kind of access, the tool, how long it took, counts, the status and the kind of error.';
  assert.ok(privacy.includes(`One line per request: ${REQ}`), 'privacy: request log');
  assert.ok(security.includes(`one log line per request: ${REQ}`), 'security: request log');
  // Sign-in record: every field is described (src/signin-audit.ts AUDIT_FIELDS, pinned above).
  const SIGNIN = 'the time, a request id, your GitHub user id, your GitHub login, your workspace id, the kind of sign-in and the result.';
  assert.ok(privacy.includes(`One record per sign-in: ${SIGNIN} No email address and no IP address.`), 'privacy: sign-in record');
  assert.ok(security.includes(`Each sign-in writes one record: ${SIGNIN} It holds no email address and no IP address.`), 'security: sign-in record');
  // Write record (src/workspace-audit.ts; docs/hosting.md "Audit"): its fields, kept on the Fly volume next to
  // the sign-in records, and NOT removed by the operator's workspace delete (which appends its own line to it).
  assert.deepEqual([...WS_AUDIT_FIELDS], ['ts', 'request_id', 'github_subject', 'tenant_id', 'grant_hash', 'action', 'outcome', 'counts']);
  assert.deepEqual([...WS_AUDIT_ACTIONS], ['import_preview', 'import_commit', 'sync', 'workspace_delete']);
  assert.ok(!WS_AUDIT_FIELDS.some((f) => /text|title|path|preview|email|ip|login/i.test(f)), 'write record fields');
  const mcp = readFileSync(join(ROOT, 'src', 'mcp.ts'), 'utf8');
  assert.match(mcp, /const ledgers = join\(a\.dataDir!, '\.zeusi'\);/, 'ledgers on the data volume');
  for (const l of ['signin-audit.jsonl', 'workspace-write-audit.jsonl', 'search-feedback.jsonl']) assert.ok(mcp.includes(`join(ledgers, '${l}')`), l);
  const WRITE = 'the time, a request id, your GitHub user id, your workspace id, a short hash of your access, what was done, the result and counts.';
  assert.ok(privacy.includes(`Write records. One line per import preview, import and sync: ${WRITE} Never the text, a title or a file path.`), 'privacy: write record');
  assert.ok(security.includes(`Each import preview, import and sync writes one record: ${WRITE} It never holds the text, a title or a file path.`), 'security: write record');
  assert.ok(security.includes('the sign-in, write and key-setup records described below'), 'security: operator sees the write records');
  // Where things are kept, and what a delete leaves behind.
  assert.ok(privacy.includes('Fly.io : runs the Zeusi server in Frankfurt, Germany. Your assistant’s access, the sign-in records, the write records, the feedback lines, previews (for up to 30 minutes) and the server’s logs are kept there. When someone sets up or uses a workspace key, the key-setup records, the recovery-attempt counter and the wrapped keys beside your assistant’s access are kept there too.'), 'privacy: Fly line');
  assert.ok(privacy.includes('Some things can remain after that: the sign-in records, the write records, the key-setup records, the recovery-attempt counter (until its times are older than one hour and the next attempt is counted), the server’s logs, the feedback file (unless it is removed by hand), the database’s restore points (for 6 hours) and any snapshots of the Zeusi server’s disk.'), 'privacy: what can remain');
  assert.ok(privacy.includes('the preview’s filtered text is kept on the Zeusi server for that time.'), 'privacy: preview kept on the server');
  assert.ok(privacy.includes('each sync batch is kept on the Zeusi server only while it runs.'), 'privacy: sync staging');
  assert.ok(privacy.includes('Your assistant’s access. For each assistant you connect: your GitHub user id and login, your workspace id, the name the assistant app gave itself, and hashes of its tokens.'), 'privacy: grant file');
  assert.ok(privacy.includes('with a list that links your GitHub user id to your workspace and, once a workspace key is set up, the wrapped key rows.'), 'privacy: workspace catalog');
  // Email: read once for the team check, never stored (verifiedEmails is used only in src/mcp-oauth-github.ts).
  assert.ok(privacy.includes('It reads your verified email addresses once, to check whether you belong to the operator’s team, and does not store them.'), 'privacy: email not stored');
  // Retention: none set yet (no purge job).
  assert.ok(privacy.includes('No fixed retention period is set yet. Zeusi has no job that deletes workspaces or records on a schedule.'), 'privacy: retention');
  // Team members reach the team workspace, everyone else a personal one (src/mcp-oauth-github.ts).
  assert.ok(security.includes('Each GitHub account outside the operator’s team gets its own workspace.'), 'security: own workspace');
  assert.ok(!security.includes('Each GitHub account gets its own workspace.'), 'security: not every account');
  // Deletion: no self-serve button (no delete tool on the MCP server).
  assert.ok(privacy.includes('There is no self-serve delete button yet. To have your workspace deleted, write to'));
  assert.ok(ALL_TOOL_NAMES.length > 5 && !ALL_TOOL_NAMES.some((t) => /delete|remove|erase|purge|drop/i.test(t)), 'no delete tool for a user');
});

test('site pages (fix r2): the imprint, the owner-chosen legal defaults (21 Nov 2026) and the restore window, word for word', () => {
  const privacy = plain(read('privacy'));
  const terms = plain(read('terms'));
  const security = plain(read('security'));
  // Imprint on Privacy and Terms (sovra.ch footer/contact, checked by curl 21 Nov 2026). No person is named.
  for (const [p, t] of [['privacy', privacy], ['terms', terms]] as const) {
    assert.ok(t.includes(IMPRINT), `${p}: imprint`);
    assert.match(read(p), /<h2 id="imprint">Imprint<\/h2>/, `${p}: imprint anchor`);
    assert.doesNotMatch(t, /managing director|Geschäftsführ|director:/i, `${p}: no person in the imprint`);
  }
  assert.ok(!security.includes('Imprint'), 'security: no imprint (it links to Privacy and Terms)');
  // Controller (FADP; GDPR where it applies).
  assert.ok(privacy.includes('Sovra GmbH is the controller of your personal data under the Swiss Federal Act on Data Protection (FADP). Where the EU General Data Protection Regulation (GDPR) applies, Sovra GmbH is the controller under it too.'), 'privacy: controller');
  // Deletion requests: by email, within 30 days.
  assert.ok(privacy.includes(`There is no self-serve delete button yet. To have your workspace deleted, write to ${ROLE_EMAIL} . Sovra GmbH handles a deletion request within 30 days.`), 'privacy: deletion request');
  // Rights and the supervisory authority (the EU authority only where the GDPR applies).
  assert.ok(privacy.includes(`Under the FADP, and where it applies the GDPR, you can ask for access to your data, for its correction or deletion, and for a copy in a portable format. You can also object to how it is used. Write to ${ROLE_EMAIL} .`), 'privacy: rights');
  assert.ok(privacy.includes('You can complain to the Federal Data Protection and Information Commissioner (FDPIC). Where the GDPR applies, you can also complain to the data protection authority in your EU country.'), 'privacy: authority');
  // Breach: FADP art. 24, no promise beyond the law (no hour count, no "always").
  const BREACH = 'If a breach of your data is likely to lead to a high risk for you, Sovra GmbH reports it to the FDPIC as soon as possible, as FADP art. 24 requires. Sovra GmbH also informs the people affected where the law requires it.';
  for (const [p, t] of [['privacy', privacy], ['security', security]] as const) {
    assert.ok(t.includes(BREACH), `${p}: breach`);
    assert.doesNotMatch(t, /\b\d+ hours? of (?:a|the) breach|\bwithin \d+ (?:hours|days) of (?:a|the|learning)/i, `${p}: no breach deadline promised`);
  }
  // Changes and the date.
  for (const [p, t] of [['privacy', privacy], ['terms', terms]] as const) {
    assert.ok(t.includes('Sovra GmbH announces changes on this page. Last updated: 21 November 2026.'), `${p}: changes`);
  }
  // Terms: content, acceptable use and suspension, as-is, liability (CO art. 100), law and venue.
  for (const t of [
    'You own your content. You give Sovra GmbH a licence to store and process it and to serve it back to you, only to run Zeusi.',
    'Do not use Zeusi to: store illegal content; attack, abuse or overload Zeusi or anyone else; get around Zeusi’s limits or its walls; store other people’s data without the right to.',
    'If you break these rules, Sovra GmbH may suspend or end your access.',
    'Zeusi is provided "as is". There is no service level agreement and no guaranteed availability.',
    'Sovra GmbH excludes its liability as far as the law allows. This never covers intent or gross negligence (art. 100 of the Swiss Code of Obligations).',
    'These terms are governed by Swiss law. The place of jurisdiction is the seat of Sovra GmbH, Cham (canton of Zug), subject to mandatory consumer rules.',
  ]) assert.ok(terms.includes(t), `terms: ${t}`);
  // Restore window: the hosted database keeps 6 hours of history (read-only Neon API read, 21 Nov 2026).
  assert.ok(privacy.includes('The database keeps restore points for 6 hours.'), 'privacy: restore window');
  assert.ok(privacy.includes('the feedback file (unless it is removed by hand), the database’s restore points (for 6 hours) and'), 'privacy: restore points remain for 6 hours');
  // The delete runbook takes a snapshot or branch first (src/workspace-delete.ts refuses --apply without --i-took-a-snapshot).
  assert.match(readFileSync(join(ROOT, 'src', 'workspace-delete.ts'), 'utf8'), /--apply needs --i-took-a-snapshot/, 'delete needs a snapshot');
  assert.ok(privacy.includes('The operator’s delete steps take a snapshot or branch of the database first. It holds a copy of the workspace until it is removed.'), 'privacy: pre-delete snapshot');
  // Neon: the region the repo proves, and no cloud-region id (owner decision).
  for (const t of [privacy, security]) assert.doesNotMatch(t, /eu-central-1|\bAWS\b/i, 'no cloud region id');
  // No DPA is claimed as signed.
  for (const p of PAGES) assert.doesNotMatch(plain(read(p)), /\b(?:DPAs?|data processing agreements?)\b[^.]*\b(?:signed|in place|concluded)\b/i, `${p}: no DPA claim`);
});

test('site pages (fix r2, review r2 F6–F8): the remaining privacy and security claims are pinned word for word', () => {
  const privacy = plain(read('privacy'));
  const security = plain(read('security'));
  // F6: each sentence, so a reworded (false) version turns this red.
  for (const t of [privacy, security]) assert.ok(t.includes('not keep your GitHub token.'), 'GitHub token not kept');
  assert.ok(privacy.includes('It does not keep your GitHub token.'), 'privacy: token');
  assert.ok(security.includes('Zeusi does not keep your GitHub token.'), 'security: token');
  for (const t of [
    'This website ( zeusi.ai ) sets no cookies and has no analytics or trackers.',
    'Zeusi does not train AI models on your data. Zeusi’s code has no training step.',
    'Names, emails and phone numbers are not filtered out, so check your files first.',
    'Neon : the database, in Frankfurt (EU).',
    'only for the operator’s own team workspace.',
    'GitHub : sign-in. GitHub is a US company.',
  ]) assert.ok(privacy.includes(t), `privacy: ${t}`);
  for (const t of [
    'The database is Neon Postgres, in Frankfurt (EU).',
    'The server has no plain-HTTP port',
    'An item that fails a check is held back. Zeusi sends an item whole or not at all.',
  ]) assert.ok(security.includes(t), `security: ${t}`);
  // The opposite claims never appear.
  for (const t of [privacy, security]) {
    assert.doesNotMatch(t, /\bkeeps your GitHub token\b|\bstores your GitHub token\b/i, 'no token kept');
    assert.doesNotMatch(t, /\bmay train\b|\bwill train\b|(?<!\bnot )\btrains? (?:AI )?models on your\b/i, 'no training');
    assert.doesNotMatch(t, /\bNames, emails and phone numbers are (?:also )?filtered\b|\bfiltered out too\b/i, 'no PII-filter overclaim');
    assert.doesNotMatch(t, /\bsent with a warning\b|\bpartly redacted\b/i, 'held back whole');
    assert.doesNotMatch(t, /\b(?:Virginia|Oregon|Ohio|US East|US West)\b/i, 'Neon not in the US');
    assert.doesNotMatch(t, /\bfor every workspace\b|\bfor all workspaces\b/i, 'OpenAI not for every workspace');
  }
  // Every sentence about cookies, exactly: zeusi.ai none; only the sign-in page sets one (TXN_TTL_MS, pinned above).
  const cookieLines = privacy.split(/(?<=\.)\s+/).filter((x) => /cookie/i.test(x)).map((x) => x.replace(/^.*?(?=A cookie is|This website|The sign-in page|Some things expire)/, ''));
  assert.deepEqual(cookieLines, [
    'A cookie is a small text file that your browser stores for a website.',
    'This website ( zeusi.ai ) sets no cookies and has no analytics or trackers.',
    'The sign-in page on mcp.zeusi.dev sets one cookie for 10 minutes, only to finish your sign-in.',
    'Some things expire by design: the sign-in cookie after 10 minutes, a preview after 30 minutes, an access token after 1 hour and a refresh token after 30 days.',
  ], 'privacy: the cookie sentences');
  // The code behind them: the only fly.toml service is HTTPS 443 (no port 80 handler).
  const fly = readFileSync(join(ROOT, 'fly.toml'), 'utf8');
  assert.deepEqual([...fly.matchAll(/^\s*port = (\d+)$/gm)].map((m) => m[1]), ['443'], 'fly.toml: the only public port is 443');
  // F7 (corrected for the live workspace-key flag, 21 Nov 2026): the IP address is used in memory for rate limits
  // (src/mcp-hosted.ts clientIp, src/mcp-auth.ts, src/mcp-oauth.ts); the raw address is never stored (no IP field in a
  // log or record); the recovery limiter stores only HMAC(signing key, "ip:" + ip) with its attempt times (pinned in the
  // flag-on test below); the hosts see it.
  assert.ok(privacy.includes('The Zeusi server uses your IP address in memory, to limit how many requests and sign-ups it accepts. It does not store the address itself. One limit stores a keyed hash of it: when someone uses the recovery option to unlock a workspace key, the server keeps a keyed hash (HMAC-SHA-256) of the IP address with the times of the attempts in the last hour, to allow 5 attempts per hour. The hash is dropped once its times are older than one hour, the next time an attempt is counted. Fly.io and Vercel see your IP address when they pass on your request, and may log it under their own terms.'), 'privacy: IP');
  assert.doesNotMatch(privacy, /in memory only|It does not store it\./, 'privacy: the old IP sentence is gone');
  const hosted = readFileSync(join(ROOT, 'src', 'mcp-hosted.ts'), 'utf8');
  assert.match(hosted, /function clientIp\(req: IncomingMessage\): string \{\n\s*const h = req\.headers\['fly-client-ip'\];/, 'clientIp from Fly-Client-IP');
  const auth = readFileSync(join(ROOT, 'src', 'mcp-auth.ts'), 'utf8');
  assert.match(auth, /this\.limiter\.add\(`ip:\$\{ip\}`, 1, now\);/, 'failed auth counted per IP');
  assert.match(auth, /new SlidingWindowLimiter\(/, 'mcp-auth uses the in-memory limiter');
  const oauth = readFileSync(join(ROOT, 'src', 'mcp-oauth.ts'), 'utf8');
  assert.match(oauth, /\[`signup:\$\{ip\}`, this\.limits\.signupPerIp\]/, 'sign-ups counted per IP');
  for (const l of ['limiter', 'signupLimiter']) assert.match(oauth, new RegExp(`private readonly ${l} = new SlidingWindowLimiter\\(`), `mcp-oauth ${l} is the in-memory limiter`);
  const rl = readFileSync(join(ROOT, 'src', 'rate-limit.ts'), 'utf8');
  assert.doesNotMatch(rl, /from 'node:fs'|writeFile|appendFile/, 'the limiter never writes to disk');
  assert.ok(!LOG_FIELDS.some((f) => /ip|addr/i.test(f)) && !AUDIT_FIELDS.some((f) => /ip|addr/i.test(f)) && !WS_AUDIT_FIELDS.some((f) => /ip|addr/i.test(f)), 'no IP field in a log or record');
  // F8: the operator also sees the connected assistants (src/mcp-oauth-store.ts list).
  assert.ok(security.includes('They can also see that a workspace exists, when it was made, its status, how many items it holds, which assistants are connected to it (with your GitHub login), and the sign-in, write and key-setup records described below.'), 'security: operator view');
});

test('site pages: README lists the pages, the routing and the footer', () => {
  const r = readFileSync(join(SITE, 'README.md'), 'utf8');
  for (const p of PAGES) assert.ok(r.includes(`\`${p}/index.html\``), p);
  assert.match(r, /no `vercel\.json`/);
  assert.match(r, /footer/i);
  // Review r3 F10: the README names the remaining unknowns, not the ones the owner has since filled.
  assert.doesNotMatch(r, /every unknown \(contact address/, 'README: no stale unknowns list');
  assert.ok(r.includes('The remaining unknowns (data processing agreements and transfers, retention periods, how long Fly.io keeps disk snapshots, removal of pre-delete snapshots, and the EU-representative question)'), 'README: remaining unknowns');
});

test('site pages (review r3 F9): the last unpinned sentences, word for word; the provider list is exactly these five', () => {
  const privacy = plain(read('privacy'));
  const security = plain(read('security'));
  // S1: Vercel serves only the website and the film; it does not hold a workspace.
  assert.ok(privacy.includes('Vercel : serves this website and the film file.'), 'privacy: Vercel line');
  // S2, S3: what Zeusi does not control, and that removing the connector keeps the workspace.
  assert.ok(privacy.includes('Zeusi does not control what happens to it there.'), 'privacy: assistant company');
  assert.ok(privacy.includes('You can stop using Zeusi at any time by removing the connector from your assistant. That does not delete your workspace.'), 'privacy: stop');
  // S4: the team workspace is separate (src/tenants.ts: `team` vs `zt_*` schemas).
  assert.ok(security.includes('The operator’s own team workspace is separate from user workspaces.'), 'security: team workspace separate');
  // S6: HSTS on both hosts (live headers, PR body row 5).
  assert.ok(security.includes('Both zeusi.ai and mcp.zeusi.dev tell browsers to use HTTPS only (HSTS).'), 'security: HSTS on both');
  // S5: the service providers, exactly; a new one (an error tracker, a mailer) needs a code source and this list.
  const h = read('privacy');
  const list = /<h2>Who else handles your data<\/h2>[\s\S]*?<ul>([\s\S]*?)<\/ul>/.exec(h);
  assert.ok(list, 'privacy: provider list');
  assert.deepEqual([...list![1]!.matchAll(/<li><strong>([^<]+)<\/strong>/g)].map((m) => m[1]), ['GitHub', 'Fly.io', 'Neon', 'Vercel', 'OpenAI'], 'privacy: providers');
});

test('site pages (LEXR reuse): the counsel v0.1 structure on Privacy, only with what Zeusi does; the template-only categories are gone', () => {
  const h = read('privacy');
  const privacy = plain(h);
  // The section order follows the LEXR v0.1 privacy policy, adapted (dropped sections are not on the page).
  const heads = [...h.matchAll(/<h2[^>]*>([^<]+)<\/h2>/g)].map((m) => m[1]!.replace(/&rsquo;/g, '’'));
  assert.deepEqual(heads, [
    'Who runs Zeusi', 'Imprint', 'What Zeusi stores', 'How Zeusi gets this data', 'Why Zeusi uses your data', 'Your IP address',
    'Cookies and tracking', 'Who else handles your data', 'Data outside Switzerland and the EU', 'When Sovra GmbH may disclose your data',
    'Your AI assistant', 'AI training', 'What the import filters out', 'Who can read your workspace', 'How your data is protected',
    'How long data is kept', 'Deleting your data', 'Your rights', 'If there is a breach', 'Changes to this page', 'Contact',
  ], 'privacy: sections');
  for (const t of [
    // About us (LEXR §About us).
    'This policy explains how Sovra GmbH uses and protects your personal data when you use Zeusi: this website ( zeusi.ai ) and the Zeusi server ( mcp.zeusi.dev ). Words such as "personal data" and "controller" mean what they mean in the FADP or the GDPR.',
    // What we collect (LEXR §What personal data we collect, last paragraph): sign-in is needed (src/mcp-oauth-github.ts).
    'You do not have to give Zeusi any personal data. But without a GitHub sign-in, Zeusi cannot give you a workspace.',
    // How we collect (LEXR §How we collect personal data): GitHub (src/mcp-oauth-github.ts), the client name (dynamic client
    // registration, src/mcp-oauth-store.ts), items and feedback (src/workspace-write.ts, src/feedback.ts), the ledgers (src/mcp.ts).
    'From GitHub , when you sign in: your GitHub user id, your login and, once, your verified email addresses.',
    'From your assistant app , when you connect it: the name it gives itself.',
    'From you, through your assistant : the items you add, and your "Did this answer it?" answers.',
    'Automatically , while you use Zeusi: the sign-in records, the write records and the request logs; and, only when someone sets up or uses a workspace key, the key-setup records and the recovery-attempt counter.',
    // Why (LEXR §Why we collect personal data): purposes with GDPR art. 6 bases (owner/counsel wording; see PR body).
    'Sovra GmbH uses your data for the purposes below. Where the GDPR applies, the legal basis is given for each.',
    'To run Zeusi for you : to sign you in, keep your workspace, show previews and send answers to your assistant. Legal basis: the contract with you (GDPR art. 6(1)(b)).',
    'To keep Zeusi secure : to find and stop attacks and abuse, with the request logs, the sign-in and write records, and the limits that use your IP address. Legal basis: legitimate interests (GDPR art. 6(1)(f)).',
    'To make search better : to see whether an answer helped, with your "Did this answer it?" answers. Legal basis: legitimate interests (GDPR art. 6(1)(f)).',
    'To meet legal duties : to answer requests about your rights and to report breaches where the law requires it. Legal basis: legal obligations (GDPR art. 6(1)(c)).',
    // Cookies (LEXR §Cookies): the one sign-in cookie, by name; nothing similar on either site.
    'Its name is __Host-zeusi_oauth . Sign-in does not work without it.',
    'Neither site uses local storage, tracking pixels or fingerprinting.',
    // Sharing, transfers, disclosure (LEXR §With whom do we share, §Third-country transfers, §Data disclosure).
    'Sovra GmbH uses these service providers to run Zeusi:',
    'The Zeusi server and the database are in Frankfurt, Germany (EU). GitHub, which handles sign-in, is a US company, and so are some of the other service providers above.',
    'Where data goes to a country without an adequate level of data protection and without suitable safeguards, authorities there may be able to access it, and you may not be able to enforce your rights there.',
    'Sovra GmbH may disclose your personal data where it believes in good faith that this is needed: to meet a legal obligation, for example a valid order from a court or an authority; to protect the security of Zeusi and to defend the rights of Sovra GmbH; to prevent or look into wrongdoing in connection with Zeusi.',
    // Safety (LEXR §How we keep the personal data safe): no absolute promise.
    'Sovra GmbH takes technical and organisational measures to protect your data against loss, change and access by others. The measures in place today are on the Security page. No way of sending or storing data over the internet is completely safe, so Sovra GmbH cannot promise absolute security.',
    // Rights (LEXR §Your rights): restriction only where the GDPR applies; objection to legitimate interests; identity check.
    'Where the GDPR applies, you can also ask Sovra GmbH to restrict how it uses your data. You can object in particular where Sovra GmbH relies on its legitimate interests. Sovra GmbH may ask you to show who you are before it answers.',
    // Changes and contact (LEXR §Changes, §Contact us).
    'Sovra GmbH may update this policy. A change takes effect when it is posted on this page.',
    `Questions about this policy: write to ${ROLE_EMAIL} , or to Sovra GmbH, Sinserstrasse 65, 6330 Cham, Switzerland.`,
    // Review r3 F11: the Fly volume has snapshots (docs/hosting.md:143); their retention is unknown (visible TODO).
    'and any snapshots of the Zeusi server’s disk.',
  ]) assert.ok(privacy.includes(t), `privacy: ${t}`);
  // The lists are closed: an added source, purpose or recipient needs a code source and a change here.
  const items = (head: string) => {
    const m = new RegExp(`<h2>${head}</h2>[\\s\\S]*?<ul>([\\s\\S]*?)</ul>`).exec(h);
    assert.ok(m, `privacy: list under ${head}`);
    return [...m![1]!.matchAll(/<li>([\s\S]*?)<\/li>/g)].map((x) => plain(x[1]!).trim());
  };
  assert.deepEqual(items('How Zeusi gets this data'), [
    'From GitHub , when you sign in: your GitHub user id, your login and, once, your verified email addresses.',
    'From your assistant app , when you connect it: the name it gives itself.',
    'From you, through your assistant : the items you add, and your "Did this answer it?" answers.',
    'Automatically , while you use Zeusi: the sign-in records, the write records and the request logs; and, only when someone sets up or uses a workspace key, the key-setup records and the recovery-attempt counter.',
  ], 'privacy: sources');
  assert.deepEqual(items('Why Zeusi uses your data').map((x) => x.split(' : ')[0]), ['To run Zeusi for you', 'To keep Zeusi secure', 'To make search better', 'To meet legal duties'], 'privacy: purposes');
  assert.deepEqual(items('When Sovra GmbH may disclose your data'), [
    'to meet a legal obligation, for example a valid order from a court or an authority;',
    'to protect the security of Zeusi and to defend the rights of Sovra GmbH;',
    'to prevent or look into wrongdoing in connection with Zeusi.',
  ], 'privacy: disclosures');
  // The facts behind them.
  assert.equal(COOKIE_NAME, '__Host-zeusi_oauth', 'cookie name (src/mcp-oauth.ts)');
  assert.match(readFileSync(join(ROOT, 'docs', 'hosting.md'), 'utf8'), /would outlive the machine and every snapshot of it/, 'the /data volume has snapshots');
  const browserStore = /\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b|document\.cookie/;
  for (const f of [...htmlFiles(), join(SITE, 'connect.js'), join(SITE, 'wow.js')]) assert.doesNotMatch(readFileSync(f, 'utf8'), browserStore, `${rel(f)}: no browser storage`);
  for (const f of readdirSync(join(ROOT, 'src')).filter((x) => x.endsWith('.ts'))) assert.doesNotMatch(readFileSync(join(ROOT, 'src', f), 'utf8'), browserStore, `src/${f}: no browser storage on the sign-in pages`);
  // Zeusi gives no consent-based purpose, so the page must not invent one (no consent banner exists).
  assert.doesNotMatch(privacy, /\bconsent\b/i, 'privacy: no consent basis');
  // Template-only categories, roles and placeholders from the counsel draft never reach a Zeusi page.
  const DROPPED = /biometric|genetic|\bhealth\b|sexual|\btrading\b|\bbroker|credit card|credit scor|bank account|\bnewsletter|\bsurvey|social (?:media|network)|geolocation|\blocation data\b|\bshipping\b|\bsensors?\b|profiling|automated decision|advertis|marketing|contact form|Data Protection Officer|\bDPO\b|Swiss representative|art(?:icle|\.) 14 FADP|\bappointed\b|\[ADD MORE|XXXX|\bprocessor\b|\bas (?:a )?processor\b/i;
  for (const p of PAGES) assert.doesNotMatch(plain(read(p)), DROPPED, `${p}: no template-only category`);
  for (const bad of ['biometric data', 'bank account details', 'credit card information', 'our newsletter', 'our Data Protection Officer', 'We have appointed an EU representative', 'Swiss representative', '[ADD MORE AS APPLICABLE]', 'XXXX', 'profiling activities']) {
    assert.match(bad, DROPPED, `ban reaches: ${bad}`);
  }
});

// When ZEUSI_WORKSPACE_ENCRYPTION is on, workspace-key records exist in the hosted code paths
// (src/mcp.ts tenantSignupSetup). They are created only when someone sets up or uses a workspace key.
// The pages list them by the code's own fields and say nothing about what they protect.
test('site pages (flag-on records): the workspace-key records, word for word, match the code that writes them', () => {
  const h = read('privacy');
  const privacy = plain(h);
  const security = plain(read('security'));
  // Key-setup records: src/enroll-audit.ts, the file beside the other ledgers (src/mcp.ts).
  assert.deepEqual([...ENROLL_AUDIT_FIELDS], ['ts', 'request_id', 'tenant_id', 'action', 'outcome', 'count']);
  assert.deepEqual([...ENROLL_AUDIT_ACTIONS], ['enroll', 'unlock_passkey', 'unlock_recovery']);
  assert.ok(!ENROLL_AUDIT_FIELDS.some((f) => /ip|addr|code|key|dek|prf|cred|token|login|github|text/i.test(f)), 'key-setup fields: counts only');
  const mcp = readFileSync(join(ROOT, 'src', 'mcp.ts'), 'utf8');
  assert.ok(mcp.includes(`enrollAuditSink({ file: join(ledgers, 'enroll-audit.jsonl') })`), 'enroll-audit.jsonl on the volume');
  // Recovery-attempt counter: src/recovery-limit.ts, keyed with the OAuth signing key (src/mcp-oauth.ts oauthFromEnv).
  assert.equal(RECOVERY_LIMIT, 5);
  assert.equal(RECOVERY_WINDOW_MS, 60 * 60_000);
  const oauth = readFileSync(join(ROOT, 'src', 'mcp-oauth.ts'), 'utf8');
  assert.ok(oauth.includes(`new RecoveryAttemptLimiter({ hashKey: key, file: join(o.dataDir, '.zeusi', 'recovery-attempts.json'), now: o.now })`), 'recovery-attempts.json, keyed with the signing key');
  const rl = readFileSync(join(ROOT, 'src', 'recovery-limit.ts'), 'utf8');
  assert.ok(rl.includes("createHmac('sha256', this.o.hashKey).update(`ip:${ip}`, 'utf8').digest('hex')"), 'HMAC-SHA-256 of the IP');
  // The real limiter on a temp file: no raw IP in it, the keyed hash and the workspace's times are; an entry older than
  // the window is dropped at the next counted attempt, not before.
  const dir = safeTmpDir('zeusi-site-flag-');
  try {
    const file = join(dir, 'recovery-attempts.json');
    let now = 1_800_000_000_000;
    const lim = new RecoveryAttemptLimiter({ hashKey: 'k'.repeat(48), file, now: () => now });
    const A = `zt_${'a'.repeat(26)}`;
    const B = `zt_${'b'.repeat(26)}`;
    const IP = '203.0.113.77';
    for (let i = 0; i < RECOVERY_LIMIT; i++) assert.equal(lim.attempt(A, IP).ok, true);
    assert.equal(lim.attempt(A, IP).ok, false, '5 per hour');
    const doc1 = JSON.parse(readFileSync(file, 'utf8')) as { tenants: Record<string, number[]>; ips: Record<string, number[]> };
    assert.deepEqual(Object.keys(doc1).sort(), ['ips', 'tenants', 'version']);
    assert.ok(!readFileSync(file, 'utf8').includes(IP), 'no raw IP in the file');
    assert.deepEqual(Object.keys(doc1.tenants), [A]);
    assert.equal(Object.keys(doc1.ips).length, 1);
    assert.match(Object.keys(doc1.ips)[0]!, /^[0-9a-f]{64}$/, 'a keyed hash');
    now += RECOVERY_WINDOW_MS + 1;
    assert.deepEqual(Object.keys((JSON.parse(readFileSync(file, 'utf8')) as typeof doc1).tenants), [A], 'old times stay until the next counted attempt');
    assert.equal(lim.attempt(B, '198.51.100.9').ok, true);
    const doc2 = JSON.parse(readFileSync(file, 'utf8')) as typeof doc1;
    assert.deepEqual(Object.keys(doc2.tenants), [B], 'the old workspace entry is dropped at the next counted attempt');
    assert.equal(Object.keys(doc2.ips).length, 1, 'the old IP hash is dropped too');
    assert.ok(!(Object.keys(doc1.ips)[0]! in doc2.ips));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  // Wrapped key rows in the database (src/tenants.ts key_wraps) and their removal by the operator's delete.
  assert.deepEqual([...KEY_WRAP_KINDS], ['passkey', 'recovery']);
  const tenants = readFileSync(join(ROOT, 'src', 'tenants.ts'), 'utf8');
  const ddl = /CREATE TABLE IF NOT EXISTS \$\{CONTROL_SCHEMA\}\.key_wraps \(([\s\S]*?)\n\);/.exec(tenants);
  assert.ok(ddl, 'key_wraps DDL');
  const cols = [...ddl![1]!.matchAll(/^\s{2}([a-z_]+)\s+(?:text|smallint|bytea|timestamptz)\b/gm)].map((m) => m[1]);
  assert.deepEqual(cols, ['tenant_id', 'wrap_id', 'kind', 'key_version', 'sealed_dek', 'credential_id', 'prf_salt', 'created_at'], 'key_wraps columns');
  assert.ok(tenants.includes('ADD COLUMN webauthn_public_key bytea,\n    ADD COLUMN webauthn_sign_count bigint,'), 'passkey public key and counter');
  assert.ok(tenants.includes(`VALUES ($1, $2, 'recovery', $3, $4)`) && tenants.split(`'recovery', $3, $4)`).length === 2, 'one recovery row, written at setup');
  assert.ok(tenants.includes("const keyWraps = await del('key_wraps');"), 'delete removes the key rows');
  // Wrapped keys beside an assistant's access (src/mcp-oauth-store.ts session_wraps): removed on every revoke.
  const store = readFileSync(join(ROOT, 'src', 'mcp-oauth-store.ts'), 'utf8');
  assert.match(store, /session_wraps: z\.strictObject\(\{\n\s*key_version: [^\n]+\n\s*access: [^\n]+\n\s*refresh: [^\n]+\n\s*\}\)\.optional\(\),/, 'session_wraps fields');
  assert.equal(store.split('{ ...withoutWraps(g), revoked_at: at }').length - 1, 3, 'every revoke drops the wraps');
  // The page, word for word.
  for (const t of [
    'The records below are created only when someone sets up or uses a workspace key on the sign-in page:',
    'Key-setup records. One line per key setup or unlock: the time ( ts ), a request id ( request_id ), your workspace id ( tenant_id ), what was done ( action : enroll , unlock_passkey or unlock_recovery ), the result ( outcome ) and a count ( count : the recovery attempts for your workspace in the last hour, for unlock_recovery only). Counts only: no key, no code, no token, no IP address and no text.',
    'Recovery-attempt counter. For each workspace, and for each keyed hash of an IP address, the times of the recovery attempts in the last hour. It is used to allow 5 attempts per hour for each. An entry is dropped once its times are older than one hour, the next time an attempt is counted.',
    'Your wrapped workspace key, in the database. One row per passkey and one recovery row ( key_wraps ): your workspace id, a wrap id, the kind ( passkey or recovery ), a key version, the wrapped key ( sealed_dek ) and the time it was made. A passkey row also holds the passkey’s credential id and a salt, and can hold its public key and signature counter.',
    'Your wrapped workspace key, beside your assistant’s access. When a sign-in unlocks the workspace key, that assistant’s access also holds the key wrapped under its current access token and under its current refresh token ( session_wraps ), with a key version. They are replaced when the tokens are renewed, and removed when the access is revoked or removed from the file.',
    'The tool also removes the wrapped key rows from the database and the wrapped keys beside the workspace’s access.',
  ]) assert.ok(privacy.includes(t), `privacy: ${t}`);
  assert.ok(security.includes('Only when someone sets up or uses a workspace key: each key setup or unlock writes one record: the time, a request id, your workspace id, what was done, the result and a count of recovery attempts. It holds no key, no code, no token, no IP address and no text.'), 'security: key-setup record');
  // The key list is closed: exactly these four records.
  const m = /<p>The records below are created only when someone sets up or uses a workspace key on the sign-in page:<\/p>\s*<ul>([\s\S]*?)<\/ul>/.exec(h);
  assert.ok(m, 'privacy: key list');
  assert.deepEqual([...m![1]!.matchAll(/<li><strong>([^<]+)<\/strong>/g)].map((x) => x[1]!.replace(/&rsquo;/g, '’')), [
    'Key-setup records.', 'Recovery-attempt counter.', 'Your wrapped workspace key, in the database.', 'Your wrapped workspace key, beside your assistant’s access.',
  ], 'privacy: the four key records');
  // Say nothing about what these records protect, on any page; and the claim bans still hold for sentences that use
  // the same words (passkey, workspace key, wrapped, recovery).
  const KEY_WORDS = /workspace key|passkey|wrapped|recovery/i;
  const PROTECTS = /protect|secur|\bsafe|private|unreadable|can(?:not|['’]t| not) (?:be )?(?:read|open|recover|see)|cannot be recovered|lost for good|no way to recover|\block(?:s|ed)? (?:away|up)\b/i;
  for (const p of PAGES) {
    for (const sentence of plain(read(p)).split(/(?<=[.:])\s+/).filter((x) => KEY_WORDS.test(x))) assert.doesNotMatch(sentence, PROTECTS, `${p}: ${sentence}`);
  }
  for (const bad of [
    'Your passkey means only you can read your workspace.', 'With a workspace key, your workspace is encrypted.', 'The wrapped key means nobody else can open it.',
    'Once a passkey is set up, we cannot read your workspace.', 'Your workspace key is end-to-end.', 'Zeusi never sees your recovery code.',
  ]) assert.ok(overclaims(bad).length > 0 || /recover(y)? code/i.test(bad), `claim ban reaches: ${bad}`);
  for (const bad of ['The wrapped key protects your workspace.', 'Without the passkey your notes cannot be read.', 'A lost recovery option cannot be recovered.', 'Your workspace key keeps it private.']) {
    assert.match(bad, PROTECTS, `protect ban reaches: ${bad}`);
  }
});
