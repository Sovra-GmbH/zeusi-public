// HTML for the hosted MCP OAuth flow: consent, access denied, sign-up limited / unavailable, error.
// Self-contained (inline CSS only, no third-party asset, no external request). Every dynamic value is
// HTML-escaped. Nothing here ever carries a token, an OAuth code, a secret, the team member list or a
// workspace id.
//
// Script: none, EXCEPT the one constant inline CONSENT_SCRIPT on a consent page for a personal
// workspace while ZEUSI_WORKSPACE_ENCRYPTION=enroll (C4, docs/plans/2026-11-18-c4-enroll.md KTD8).
// The server pins it by hash in the CSP (CONSENT_SCRIPT_HASH); `default-src 'none'` still forbids any
// request from it. It only calls WebAuthn and fills hidden fields of the same-origin consent form. With
// the flag off the consent page is byte-for-byte what it was before C4. It also posts the WebAuthn
// attestation / assertion the server verifies (docs/plans/2026-11-19-c4-webauthn-verify.md). No page ever echoes a PRF
// output or a submitted recovery code; the recovery code is shown once, on recoveryCodePage only.

import { createHash } from 'node:crypto';

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

const STYLE = `
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#10141d;color:#fef7ed;
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:30rem;padding:2rem;border:1px solid #2a3142;border-radius:12px;background:#151a25}
h1{font-size:1.4rem;margin:0 0 1rem}
code{background:#0c0f16;padding:.1rem .35rem;border-radius:4px}
.big{display:block;margin:.25rem 0 .1rem;padding:.5rem .75rem;font-size:1.25rem;font-weight:600;overflow-wrap:anywhere}
.label{margin:1rem 0 0;font-size:.85rem;text-transform:uppercase;letter-spacing:.06em;color:#b9b2a6}
.note{margin:0;color:#b9b2a6;font-size:.95rem}
ul{padding-left:1.2rem}
.warn{color:#f5c27a}
.row{display:flex;gap:.75rem;margin-top:1.5rem}
button{font:inherit;padding:.6rem 1.2rem;border-radius:8px;border:1px solid #3a4256;background:#1d2331;color:#fef7ed;cursor:pointer}
button.primary{background:#4f5d42;border-color:#4f5d42}
`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)} · zeusi</title><style>${STYLE}</style></head>
<body><main>${body}</main></body></html>
`;
}

/**
 * Who asks. CIMD: the host of the client_id URL (proven: Zeusi fetched the document from it)
 * plus the client_name that host declares. DCR: only a name the app chose for itself.
 */
export type ClientLabel = { kind: 'cimd'; host: string; name: string | null } | { kind: 'dcr'; name: string | null };

/**
 * Only verified identities get the prominent style: a CIMD client_id host (here) and the
 * redirect host (in consentPage, checked against the allowlist). A DCR client's name is
 * whatever it typed at /register (it could say "chatgpt.com"), so it is shown small and muted,
 * never in `.big` or `<strong>`.
 */
function who(c: ClientLabel): string {
  if (c.kind === 'cimd') {
    const name = c.name ? `<p class="note">Calls itself <strong>${esc(c.name)}</strong> (declared by <code>${esc(c.host)}</code>).</p>` : '';
    return `<p class="label">App asking</p>\n<code class="big">${esc(c.host)}</code>${name}`;
  }
  return c.name
    ? `<p class="note">Name it gave itself: &quot;${esc(c.name)}&quot; (not verified). This app registered itself; Zeusi cannot verify who made it.</p>`
    : `<p class="note">The app registered itself without a name (not verified).</p>`;
}

export interface ConsentView {
  clientLabel: ClientLabel;
  /** Host of the redirect URI the code goes to. */
  redirectHost: string;
  /**
   * true when the code ends up with a program on this computer: a loopback redirect, or
   * https://vscode.dev/redirect / https://insiders.vscode.dev/redirect (they hand the code on
   * to a local VS Code via loopback or vscode://).
   */
  local: boolean;
  login: string;
  txn: string;
  csrf: string;
  /** C4, flag `enroll` and a personal workspace only. Absent: the page is exactly the pre-C4 page. */
  keys?: ConsentKeysView | undefined;
  /**
   * Personal workspace (open sign-up) only: whether it was just created. Absent for a operator member,
   * whose consent screen is unchanged.
   */
  personal?: { created: boolean; write?: boolean | undefined } | undefined;
}

/** Hosted redirect pages that forward the code to a program on this computer. */
export const LOCAL_HANDOFF_HOSTS: ReadonlySet<string> = new Set(['vscode.dev', 'insiders.vscode.dev']);

/** The personal-workspace block of the consent page (empty for a operator member). No id is shown. */
function personal(p: ConsentView['personal']): string {
  if (!p) return '';
  return `<p class="label">Workspace</p>
<p><strong>Your personal workspace</strong>${p.created ? ' (new, empty)' : ''}. It is separate from every other Zeusi workspace: nothing in it is shared, and nothing from anyone else's workspace is visible in it.</p>
`;
}

/**
 * The passkey block of a flag-on consent page (C4). Every value is base64url or the GitHub login; none
 * is secret (the PRF salts and credential ids are public by design; the challenge is random).
 */
export type ConsentKeysView =
  | {
    mode: 'enroll'; rpId: string; userId: string; userName: string; challenge: string; salt: string;
    /** The challenge of the get() fallback (docs/plans/2026-11-19-c4-webauthn-verify.md KTD3). */
    challenge2: string;
    /** KTD7: flag `on`, born encrypted, no wrap: no approve without a passkey. */
    required: boolean;
  }
  | { mode: 'unlock'; rpId: string; challenge: string; creds: Array<{ id: string; salt: string }>; recovery: boolean };

/**
 * The one script (KTD8). Reads its inputs from #zeusi-keys data attributes; on click it creates (enroll)
 * or asserts (unlock) a passkey with the PRF extension and submits the consent form with the PRF output
 * and credential id in hidden fields. Enroll without a PRF result from create() calls get() at once
 * with the same salt (parent plan §4.1). No network call of its own (the CSP forbids it anyway).
 */
export const CONSENT_SCRIPT = `(function () {
  'use strict';
  var box = document.getElementById('zeusi-keys');
  var form = document.getElementById('zeusi-consent');
  var go = document.getElementById('zeusi-keys-go');
  var approve = document.getElementById('zeusi-approve');
  var status = document.getElementById('zeusi-keys-status');
  if (!box || !form || !go || !approve) return;
  function fromB64u(s) {
    s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s); var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function toB64u(buf) {
    var b = new Uint8Array(buf); var s = '';
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }
  function say(msg) { if (status) { status.textContent = msg; status.hidden = false; } }
  function prfOf(c) {
    var ext = c && typeof c.getClientExtensionResults === 'function' ? c.getClientExtensionResults() : {};
    var r = ext && ext.prf && ext.prf.results;
    return r && r.first ? r.first : null;
  }
  function asserted(a) {
    return { id: a.rawId, prf: prfOf(a), acdj: toB64u(a.response.clientDataJSON), ad: toB64u(a.response.authenticatorData), sig: toB64u(a.response.signature) };
  }
  var mode = box.getAttribute('data-mode');
  var rp = box.getAttribute('data-rp');
  var required = box.getAttribute('data-required') === 'yes';
  if (typeof window.PublicKeyCredential === 'undefined' || !navigator.credentials) {
    go.disabled = true;
    say(required
      ? 'This sign-in needs a passkey, and this browser cannot use one here. Start the sign-in again on a device or browser that supports passkeys.'
      : 'This browser cannot use a passkey here. You can still approve.');
    return;
  }
  go.addEventListener('click', function () {
    go.disabled = true;
    var p;
    if (mode === 'enroll') {
      var salt = fromB64u(box.getAttribute('data-salt'));
      var name = box.getAttribute('data-name');
      p = navigator.credentials.create({ publicKey: {
        rp: { id: rp, name: 'Zeusi' },
        user: { id: fromB64u(box.getAttribute('data-user')), name: name, displayName: name },
        challenge: fromB64u(box.getAttribute('data-challenge')),
        pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none',
        extensions: { prf: { eval: { first: salt } } }
      } }).then(function (c) {
        var reg = { id: c.rawId, prf: prfOf(c), att: toB64u(c.response.attestationObject), cdj: toB64u(c.response.clientDataJSON) };
        if (reg.prf) return reg;
        return navigator.credentials.get({ publicKey: {
          rpId: rp, challenge: fromB64u(box.getAttribute('data-challenge2')), userVerification: 'required',
          allowCredentials: [{ type: 'public-key', id: c.rawId }],
          extensions: { prf: { eval: { first: salt } } }
        } }).then(function (a) { var r = asserted(a); r.att = reg.att; r.cdj = reg.cdj; return r; });
      });
    } else {
      var pairs = String(box.getAttribute('data-creds') || '').split(' ').filter(Boolean).map(function (x) {
        var y = x.split('.'); return { id: y[0], salt: y[1] };
      });
      var byCred = {};
      pairs.forEach(function (c) { byCred[c.id] = { first: fromB64u(c.salt) }; });
      p = navigator.credentials.get({ publicKey: {
        rpId: rp, challenge: fromB64u(box.getAttribute('data-challenge')), userVerification: 'required',
        allowCredentials: pairs.map(function (c) { return { type: 'public-key', id: fromB64u(c.id) }; }),
        extensions: { prf: { evalByCredential: byCred } }
      } }).then(asserted);
    }
    p.then(function (r) {
      if (!r || !r.prf) {
        go.disabled = false;
        say(required
          ? 'This passkey cannot be used for this sign-in. Try another passkey or device.'
          : 'This passkey cannot do this here. You can still approve' + (mode === 'enroll' ? '.' : ', or use your recovery code.'));
        return;
      }
      var v = { enc: mode, cred: toB64u(r.id), prf: toB64u(r.prf), att: r.att || '', cdj: r.cdj || '', acdj: r.acdj || '', ad: r.ad || '', sig: r.sig || '' };
      Object.keys(v).forEach(function (k) { form.elements.namedItem(k).value = v[k]; });
      form.requestSubmit(approve);
    }, function () {
      go.disabled = false;
      say(required ? 'The passkey step did not complete. You can try again.' : 'The passkey step did not complete. You can try again, or approve without it.');
    });
  });
})();`;

/** The CSP source that pins CONSENT_SCRIPT ('sha256-<base64>'). */
export const CONSENT_SCRIPT_HASH = `'sha256-${createHash('sha256').update(CONSENT_SCRIPT, 'utf8').digest('base64')}'`;

function keysBlock(k: ConsentKeysView): string {
  if (k.mode === 'enroll') {
    const attrs = `data-mode="enroll" data-rp="${esc(k.rpId)}" data-user="${esc(k.userId)}" data-name="${esc(k.userName)}" data-challenge="${esc(k.challenge)}" data-challenge2="${esc(k.challenge2)}" data-salt="${esc(k.salt)}"`;
    if (k.required) {
      return `<section id="zeusi-keys" ${attrs} data-required="yes">
<p class="label">Passkey (needed)</p>
<p>This workspace needs a passkey before an app can use it. Set one up now to finish signing in.</p>
<p class="note">You will see a recovery code once. Keep it somewhere safe: it is the way back in if you lose every passkey.</p>
<p class="note warn" id="zeusi-keys-status" hidden></p>
</section>
`;
    }
    return `<section id="zeusi-keys" ${attrs}>
<p class="label">Passkey (optional)</p>
<p>You can set up a passkey for this workspace now. It prepares a protection feature that is not switched on yet: today nothing changes in how your workspace is stored.</p>
<p class="note">You will see a recovery code once. Keep it somewhere safe: once the protection is on, it is the way back in if you lose every passkey.</p>
<p class="note warn" id="zeusi-keys-status" hidden></p>
</section>
`;
  }
  return `<section id="zeusi-keys" data-mode="unlock" data-rp="${esc(k.rpId)}" data-challenge="${esc(k.challenge)}" data-creds="${esc(k.creds.map((c) => `${c.id}.${c.salt}`).join(' '))}">
<p class="label">Passkey</p>
<p>This workspace has a passkey set up. Unlock it with your passkey${k.recovery ? ' or your recovery code' : ''}, or approve without unlocking.</p>
<p class="note warn" id="zeusi-keys-status" hidden></p>
</section>
`;
}

export function consentPage(v: ConsentView): string {
  const handoff = LOCAL_HANDOFF_HOSTS.has(v.redirectHost);
  const local = !v.local
    ? ''
    : handoff
      ? `<p class="warn">This sign-in is handed to an app on this computer through <code>${esc(v.redirectHost)}</code>. Approve only if you just started this sign-in from an app on this computer that you trust.</p>`
      : `<p class="warn">This sends access to a program on this computer (<code>${esc(v.redirectHost)}</code>). Approve only if you just started this sign-in from an app on this computer that you trust.</p>`;
  // One consent for a personal workspace with writes on (docs/plans/2026-11-18-workspace-write-import-plan.md
  // KTD2): reading it AND writing into it, nothing else. Every other consent is unchanged (read-only).
  const write = v.personal?.write === true;
  const scope = write
    ? `<ul>
<li>Read: search, standing rules and current decisions in your workspace, with citations.</li>
<li>Write: only into your own workspace, and only after it shows you a preview and you say yes (filling your memory, and a nightly sync you set up).</li>
<li>It can never change anyone else's workspace, and it cannot log the team decisions.</li>
</ul>`
    : `<ul>
<li>Read-only: search, standing rules and current decisions, with citations.</li>
<li>It cannot log decisions or change anything in Zeusi.</li>
</ul>`;
  const head = `
<h1>${write ? 'Allow access to your Zeusi workspace?' : 'Allow read-only access to Zeusi?'}</h1>
<p class="label">Access is sent to</p>
<code class="big">${esc(v.redirectHost)}</code>
${who(v.clientLabel)}
<p>It asks to use Zeusi as <code>${esc(v.login)}</code>.</p>
${personal(v.personal)}${scope}
${local}`;
  const k = v.keys;
  if (!k) {
    return page('Allow access', `${head}
<form method="post" action="/oauth/consent">
<input type="hidden" name="txn" value="${esc(v.txn)}">
<input type="hidden" name="csrf" value="${esc(v.csrf)}">
<div class="row">
<button class="primary" type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button>
</div>
</form>`);
  }
  const goLabel = k.mode === 'enroll' ? 'Set up a passkey and approve' : 'Unlock with your passkey and approve';
  // docs/plans/2026-11-19-c4-webauthn-verify.md KTD7: no visible approve without a passkey (the server refuses it
  // too); the hidden submitter only carries the script's requestSubmit after a verified passkey step.
  const required = k.mode === 'enroll' && k.required;
  const recovery = k.mode === 'unlock' && k.recovery
    ? `
<form method="post" action="/oauth/consent" id="zeusi-recover">
<p class="label">Or use your recovery code</p>
<input type="hidden" name="txn" value="${esc(v.txn)}">
<input type="hidden" name="csrf" value="${esc(v.csrf)}">
<input type="hidden" name="enc" value="recover">
<input name="recovery" aria-label="Recovery code" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="64" required>
<div class="row">
<button type="submit" name="decision" value="approve">Unlock with the recovery code and approve</button>
</div>
</form>`
    : '';
  return page('Allow access', `${head}
${keysBlock(k)}<form method="post" action="/oauth/consent" id="zeusi-consent">
<input type="hidden" name="txn" value="${esc(v.txn)}">
<input type="hidden" name="csrf" value="${esc(v.csrf)}">
<input type="hidden" name="enc" value="">
<input type="hidden" name="cred" value="">
<input type="hidden" name="prf" value="">
<input type="hidden" name="att" value="">
<input type="hidden" name="cdj" value="">
<input type="hidden" name="acdj" value="">
<input type="hidden" name="ad" value="">
<input type="hidden" name="sig" value="">
<div class="row">
<button class="primary" type="button" id="zeusi-keys-go">${goLabel}</button>
</div>
<div class="row">
${required
    ? '<button type="submit" name="decision" value="approve" id="zeusi-approve" hidden>Approve</button>'
    : `<button type="submit" name="decision" value="approve" id="zeusi-approve">Approve${k.mode === 'enroll' ? ' without a passkey' : ' without unlocking'}</button>`}
<button type="submit" name="decision" value="deny">Deny</button>
</div>
</form>${recovery}
<script>${CONSENT_SCRIPT}</script>`);
}

/**
 * Shown once, right after enrollment (C4 KTD2): the recovery code in its display form and a
 * continuation form that finishes the sign-in. No script. The code is never shown again by Zeusi.
 * The warning follows the workspace's real state (src/mcp-oauth.ts enrollAtConsent, offer.born):
 * - born encrypted (enc_state `on`, C5 KTD11; the enroll keeps `on`): its content is sealed, and a sign-in
 *   unlocks it only with a passkey or this code (C7 KTD7: a grant without the key is locked).
 * - otherwise (enc_state `off` -> `enrolled`, flag `enroll` or `on`): only the key is set up; the content
 *   stays plain, so the warning names the key, not the workspace.
 * Either way the key's only wraps are the passkeys and this code (src/tenants.ts KEY_WRAP_KINDS; per-grant
 * session wraps exist only under that grant's live tokens), so Zeusi cannot get it back. No encryption
 * wording: this page is under the server-copy over-claim ban (test/helpers/overclaim.ts overclaims).
 */
export const RECOVERY_WARNING_BORN =
  'You need this code or one of your passkeys to unlock this workspace when you sign in. If you lose all of them, Zeusi cannot get it back for you.';
export const RECOVERY_WARNING_KEY =
  'You need this code or one of your passkeys to unlock your workspace key when you sign in. If you lose all of them, Zeusi cannot get the key back for you.';
export function recoveryCodePage(v: { code: string; txn: string; csrf: string; born: boolean }): string {
  return page('Your recovery code', `
<h1>Your recovery code</h1>
<p>Your passkey is set up. Write this recovery code down now and keep it somewhere safe. It is shown only this once.</p>
<p class="label">Recovery code</p>
<code class="big" id="zeusi-recovery-code">${esc(v.code)}</code>
<p class="note warn">${esc(v.born ? RECOVERY_WARNING_BORN : RECOVERY_WARNING_KEY)}</p>
<form method="post" action="/oauth/consent">
<input type="hidden" name="txn" value="${esc(v.txn)}">
<input type="hidden" name="csrf" value="${esc(v.csrf)}">
<div class="row">
<button class="primary" type="submit" name="decision" value="approve">I saved it, continue</button>
</div>
</form>`);
}

/** 429 for recovery-code attempts (C4 KTD4). Says nothing about the code or counts. */
export function recoveryLimitedPage(): string {
  return page('Try again later', `
<h1>Too many recovery attempts</h1>
<p>This workspace had too many recovery-code attempts in the last hour. Nothing was shared.</p>
<p>Try again later from the app you were connecting.</p>`);
}

export function deniedPage(): string {
  return page('Access denied', `
<h1>Access denied</h1>
<p>This account is not allowed to use Zeusi. Nothing was shared.</p>`);
}

/** 429: the new-workspace limit was reached. Static; says nothing about other users or counts. */
export function signupLimitedPage(): string {
  return page('Try again later', `
<h1>Too many new workspaces right now</h1>
<p>Zeusi limits how many new workspaces are created. Nothing was created and nothing was shared.</p>
<p>Try again later from the app you were connecting.</p>`);
}

/** 503: this server does not create personal workspaces (not configured, or the directory is down). */
export function signupUnavailablePage(): string {
  return page('Not available', `
<h1>New workspaces are not available</h1>
<p>This Zeusi server is not creating personal workspaces right now. Nothing was created and nothing was shared.</p>
<p>Try again later from the app you were connecting.</p>`);
}

export function errorPage(message: string): string {
  return page('Sign-in failed', `
<h1>Sign-in failed</h1>
<p>${esc(message)}</p>
<p>Start again from the app you were connecting.</p>`);
}
