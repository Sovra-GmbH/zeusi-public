// The shared credential detector (src/secrets.ts; security P0, 17 Nov 2026).
// Every value here is SYNTHETIC and built at runtime from pieces (repeated X / 0 patterns), so no
// literal in this file is a key and gitleaks does not fire on the source.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { credentialSignal, findSecrets, redactDeep, redactSecrets, STORAGE_SKIP, strictCredentialSignal, type SecretKind } from '../src/secrets.ts';
import { credentialSignal as exportSignal } from '../src/hq-export.ts';

import { fakeGoogleKey, fakeMaskedGoogle, j, P, X0 } from './secret-fixtures.ts';

const ELL = '\u2026';

const kindsOf = (s: string) => findSecrets(s).map((m) => m.kind);

const POSITIVE: Array<[string, string, SecretKind]> = [
  // full keys
  ['google full', fakeGoogleKey(), 'google_api_key'],
  ['openai project key', j(P.openaiProj, X0(24)), 'openai_key'],
  ['openai legacy key', j(P.openai, X0(24)), 'openai_key'],
  ['anthropic key', j(P.anthropic, 'api03-', X0(30)), 'anthropic_key'],
  ['github classic', j(P.ghp, X0(18)), 'github_token'],
  ['github server', j(P.ghs, X0(18)), 'github_token'],
  ['github fine-grained', j(P.ghPat, '11', X0(20)), 'github_token'],
  ['slack bot', j(P.slack, '1234567890-', X0(8)), 'slack_token'],
  ['aws akia', j(P.akia, 'X0X0X0X0X0X0X0X0'), 'aws_key_id'],
  ['aws asia', j(P.asia, 'XXXXYYYYZZZZWWWW'), 'aws_key_id'],
  ['stripe live', j(P.stripe, X0(12)), 'stripe_key'],
  ['stripe restricted', j(P.stripeR, X0(12)), 'stripe_key'],
  ['fly org token', j(P.fly, X0(20)), 'fly_token'],
  ['fly macaroon', j(P.flyV1, X0(30)), 'fly_token'],
  ['neon password', j(P.neon, X0(8)), 'neon_password'],
  ['jwt', j('ey', 'J', 'X'.repeat(12), '.ey', 'J', 'X'.repeat(12), '.', 'X'.repeat(12)), 'jwt'],
  ['pem', j('-----BEGIN ', 'RSA PRIVATE', ' KEY-----\n', 'X'.repeat(40), '\n-----END ', 'RSA PRIVATE', ' KEY-----'), 'private_key'],
  ['url password', j('https://', 'user', ':', 'X0X0X0pw', '@', 'example.invalid/x'), 'url_password'],
  ['bearer', j('Authorization: Bear', 'er ', X0(14)), 'bearer'],
  // partial / truncated: real prefix + at least 6 key characters
  ['google truncated', j(P.google, 'SyX0X0'), 'google_api_key'],
  ['anthropic truncated', j(P.anthropic, 'X0X0X0'), 'anthropic_key'],
  ['github truncated', j(P.ghp, 'X0X0X0'), 'github_token'],
  ['openai project truncated', j(P.openaiProj, 'X0X0X0'), 'openai_key'],
  // masked: real prefix + mask + key characters
  ['google masked (the leaked shape)', fakeMaskedGoogle(), 'masked_google_api_key'],
  ['google masked ascii dots', j(P.google, '...', 'X0X0X'), 'masked_google_api_key'],
  ['google masked head and tail', j(P.google, 'Sy', '****', 'X0X0'), 'masked_google_api_key'],
  ['openai masked', j(P.openaiProj, ELL, 'X0X0'), 'masked_openai_key'],
  ['openai legacy masked', j(P.openai, '...', 'X0X'), 'masked_openai_key'],
  ['github masked bullets', j(P.ghp, '••••', '0X0X'), 'masked_github_token'],
  ['slack masked', j(P.slack, ELL, 'X0X0X0'), 'masked_slack_token'],
  ['aws masked', j(P.akia, '****', 'X0X0'), 'masked_aws_key_id'],
  // keyword = value
  ['env assignment', j('GEMINI_API', '_KEY=', 'zz', X0(8)), 'keyword_value'],
  ['yaml password', j('pass', 'word: ', 'not-a-real-pw-77'), 'keyword_value'],
  ['json client secret', j('"client', '_secret": "', X0(10), '"'), 'keyword_value'],
  ['otp code', j('Your 2FA ', 'code is ', '48', '29', '13'), 'otp_code'],
];

const BENIGN: string[] = [
  j(P.google, ELL), // a prefix alone is not a secret
  j(P.google, '...'),
  j('Google keys start with ', P.google, ' and are 39 characters long'),
  j(P.openai, '...'),
  j(P.google, ELL, 'X'), // one visible character after the mask
  j(P.openai, ELL, 'ab'), // prefix + 2 = 5 visible: too short
  'risk-assessment for the quarter',
  'we use sk-learn and sk-image',
  'sk-spinner sk-learning',
  'ASIAPACIFIC region and ASIA-PACIFIC',
  'task-1234567 and disk-backup2026',
  'ghost_writer is not a token',
  j('xo', 'xo-hugsandkisses'), // built at runtime: the gitleaks partial rule has no digit check
  'FlyV1 tokens are documented in docs/fly.md',
  'AKIA is the AWS key-id prefix',
  'token: <your-token-here>',
  j('api_key=', '${GEMINI_API', '_KEY}'),
  j('pass', 'word: process.env.ZEUSI_PW'),
  'we rotated the password yesterday',
  'the password lives in 1Password, ask the owner.',
  j('ey', 'JhbGciOiJIUzI1NiJ9 is only a JWT header'),
  '-----BEGIN PUBLIC KEY-----',
  'PR #1188 merged at 10:42',
  'api_key: [REDACTED:google_api_key]',
  'Aizawl is a city; AIzawl is a typo',
];

test('detector: full, partial, masked and keyword=value secrets are found with their kind', () => {
  for (const [name, s, kind] of POSITIVE) {
    assert.ok(credentialSignal(s), `${name}: signal`);
    assert.ok(kindsOf(s).includes(kind), `${name}: kind ${kind}, got ${kindsOf(s).join(',')}`);
  }
});

test('detector: a real value starting with $, < or {{ is still a secret; only whole-value placeholders are skipped', () => {
  // Synthetic values built at runtime (never a real password).
  for (const lead of ['$', '$$', '<', '{{', '${']) {
    const s = j('db pass', 'word: ', lead, 'Fake9', X0(3));
    assert.ok(credentialSignal(s), `lead ${lead.length} chars: signal`);
    const r = redactSecrets(s);
    assert.equal(r.text, 'db password: [REDACTED:keyword_value]', `lead ${lead.length} chars: redacted`);
  }
  for (const s of ['token: <your-token-here>', j('api_key=', '${GEMINI_API', '_KEY}'), j('pass', 'word: $ZEUSI_DB_PW'), j('secret: {{', 'vault_secret}}')]) {
    assert.equal(credentialSignal(s), false, `placeholder of length ${s.length} is not a secret`);
  }
});

test('detector: benign look-alikes are not secrets (bounded false positives)', () => {
  const fp = BENIGN.filter((s) => credentialSignal(s));
  assert.deepEqual(fp.map((s) => s.length), [], 'no benign string trips (lengths of offenders shown, not text)');
});

test('redaction: replaces only the secret with [REDACTED:<kind>], keeps the rest, never leaves key characters, is idempotent', () => {
  for (const [name, s, kind] of POSITIVE) {
    // An unquoted keyword value runs to the end of its line (review r2 P1-1): the text after it goes on the next line.
    const sep = kind === 'keyword_value' ? '\n' : ' ';
    const line = `before ${s}${sep}after`;
    const r = redactSecrets(line);
    assert.ok(r.count >= 1, name);
    assert.ok(r.text.startsWith('before ') || kind === 'keyword_value' || kind === 'bearer', name);
    assert.ok(r.text.endsWith(`${sep}after`) || kind === 'private_key', name);
    assert.ok(r.text.includes(`[REDACTED:${kind}]`), `${name}: marker`);
    assert.ok(!r.text.includes('X0X0'), `${name}: no key characters left`);
    assert.equal(credentialSignal(r.text), false, `${name}: redacted text is clean`);
    assert.equal(redactSecrets(r.text).count, 0, `${name}: idempotent`);
    assert.equal(r.text, redactSecrets(r.text).text);
  }
});

test('the leaked shape in context: backticks, a keyword on the line, the rest of the note kept', () => {
  const note = `## Phase 0b\n\n- Gemini key in use: \`${fakeMaskedGoogle()}\` (the owner's AI Studio project)\n- Next: avatar rig.\n`;
  const r = redactSecrets(note);
  assert.equal(r.count, 1);
  assert.deepEqual(r.byKind, { masked_google_api_key: 1 });
  assert.equal(r.text, "## Phase 0b\n\n- Gemini key in use: `[REDACTED:masked_google_api_key]` (the owner's AI Studio project)\n- Next: avatar rig.\n");
  assert.ok(!r.text.includes(P.google));
});

test('split and hidden keys: across a line break, inside markdown, with zero-width characters', () => {
  // A key wrapped over two lines: the first line still holds prefix + >= 6 key characters.
  const wrapped = j(P.google, 'SyX0X0X0', '\n', X0(12));
  assert.ok(credentialSignal(wrapped));
  assert.ok(!redactSecrets(wrapped).text.includes('SyX0X0X0'));
  // Markdown emphasis and code around the key.
  for (const s of [`**${fakeGoogleKey()}**`, `\`${fakeGoogleKey()}\``, `[key](${fakeGoogleKey()})`, `_${j(P.anthropic, X0(8))}_`]) {
    assert.ok(credentialSignal(s), 'wrapped in markdown');
    assert.ok(!redactSecrets(s).text.includes('X0X0X0'));
  }
  // Zero-width space and soft hyphen pasted into the key.
  const zw = j(P.google, '​', 'Sy', X0(4), '­', X0(10));
  assert.ok(credentialSignal(zw));
  const r = redactSecrets(zw);
  assert.equal(r.count, 1);
  assert.ok(!r.text.includes('X0X0'));
});

test('redactDeep: every string of a JSON-like value (keys kept), counts by kind; storage skips one-time codes', () => {
  const item = { text: `a ${fakeGoogleKey()} b`, nested: { list: ['clean', fakeMaskedGoogle()], n: 3, ok: true, none: null } };
  const r = redactDeep(item);
  assert.equal(r.count, 2);
  assert.deepEqual(r.byKind, { google_api_key: 1, masked_google_api_key: 1 });
  assert.equal(r.value.nested.n, 3);
  assert.ok(!JSON.stringify(r.value).includes(P.google));
  assert.ok(JSON.stringify(item).includes(P.google), 'the input is not mutated');
  const otp = j('login code ', '48', '29', '13');
  assert.equal(redactSecrets(otp).count, 1);
  assert.equal(redactSecrets(otp, { skip: STORAGE_SKIP }).count, 0, 'stored notes keep numbers next to "login"');
  assert.equal(redactSecrets(fakeMaskedGoogle(), { skip: STORAGE_SKIP }).count, 1, 'provider kinds are never skipped');
});

test('the export filter uses the shared detector in its WITHHOLD form (detector + pre-detector floor, never looser)', () => {
  assert.equal(exportSignal, strictCredentialSignal);
  assert.ok(exportSignal(fakeMaskedGoogle()));
  // Everything the shared detector finds, the withhold check finds.
  for (const [name, s] of POSITIVE) assert.ok(exportSignal(s), name);
});

// ---------------------------------------------------------------------------
// Review r1 (PR #23) P2-1..P2-4

test('P2-1: a key split after <= 5 body characters (line break, quote, markdown) is found and fully redacted', () => {
  const rest = j('Sy', X0(16)); // the remaining key characters, no prefix of their own
  const shapes: Array<[string, string]> = [
    ['newline after prefix + 3', j(P.google, 'X0X', '\n', rest)],
    ['newline right after prefix', j(P.google, '\n', rest)],
    ['CRLF + indentation', j(P.google, 'X0', '\r\n    ', rest)],
    ['blockquote continuation', j('> ', P.google, 'X0X0X', '\n> ', rest)],
    ['backtick right after the prefix', j('`', P.google, '`', rest, '`')],
    ['bold split', j(P.google, '**', rest, '**')],
    ['strike split', j(P.anthropic, '~~', X0(10))],
    ['github split', j(P.ghp, 'X0', '\n', X0(16))],
  ];
  for (const [name, s] of shapes) {
    assert.ok(credentialSignal(s), `${name}: signal`);
    const r = redactSecrets(`before ${s} after`);
    assert.ok(r.count >= 1, name);
    assert.ok(!r.text.includes('X0X0') && !r.text.includes(P.google) && !r.text.includes(P.anthropic) && !r.text.includes(P.ghp), `${name}: no key characters left`);
    assert.equal(redactSecrets(r.text).count, 0, `${name}: idempotent`);
  }
});

test('P2-1: single-asterisk / single-bullet and spaced masks are found', () => {
  const shapes: Array<[string, string]> = [
    ['single asterisk', j(P.google, '*', 'X0X0X')],
    ['single asterisk with head', j(P.google, 'Sy', '*', 'X0X0')],
    ['single bullet', j(P.ghp, '\u2022', 'X0X0X0')],
    ['spaced ellipsis', j(P.google, ' ', ELL, ' ', 'X0X0X')],
    ['spaced ascii dots', j(P.google, ' ... ', 'X0X0X')],
    ['ellipsis spaced after', j(P.openaiProj, ELL, ' ', 'X0X0')],
    ['nbsp around mask', j(P.google, '\u00a0', ELL, '\u00a0', 'X0X0X')],
  ];
  for (const [name, s] of shapes) {
    assert.ok(credentialSignal(s), `${name}: signal`);
    const r = redactSecrets(`k ${s} end`);
    assert.ok(/\[REDACTED:masked_/.test(r.text), `${name}: masked kind`);
    assert.ok(!r.text.includes('X0X0'), `${name}: no key characters left`);
  }
});

test('P2-1: benign look-alikes of the new split / mask rules stay clean (bounded false positives)', () => {
  const benign = [
    j('Google keys start with ', P.google, '\nand are long'), // prefix at end of line, a word next
    j('Google keys start with ', P.google, '\nconfigurationmanagement'), // a long word, no digit
    j(P.google, ' ... and so on'), // spaced mask, prose tail
    j(P.google, ' ', ELL, ' tbd'),
    j('*', P.google, '* is the prefix'), // markdown emphasis around the prefix alone
    j('`', P.google, '` prefix, `', P.openai, '` prefix'),
    j('we use ', P.openai, '*learn* a lot'),
    j(P.openai, '\nlearn more'),
    'a * b * c and 3 * 4 = 12',
    'see https://example.invalid/docs ... more',
    '**bold** and ~~strike~~ and `code`',
  ];
  const fp = benign.filter((s) => credentialSignal(s));
  assert.deepEqual(fp.map((s) => s.length), [], 'no benign string trips (lengths only)');
});

test('P2-2: a zero-width-hidden key is redacted even when a visible secret sits in the same text (ingest + rescrub path)', () => {
  const hidden = j(P.google, '\u200b', 'Sy', X0(4), '\u200c', X0(10), '\u00ad', 'X');
  const visible = j(P.anthropic, X0(10));
  for (const s of [`a ${visible} b ${hidden} c`, `a ${hidden} b ${visible} c`, `${visible}\u200b${hidden}`]) {
    const r = redactSecrets(s, { skip: STORAGE_SKIP });
    assert.ok(r.count >= 1, 'redacted'); // adjacent keys merge into one marker once the invisible is gone
    assert.equal(s.startsWith('a ') ? r.count : 2, 2, 'two separate keys: two markers');
    assert.ok(!r.text.includes('X0X0') && !r.text.includes('Sy'), 'no key characters left');
    assert.equal(credentialSignal(r.text), false);
    assert.equal(redactSecrets(r.text).count, 0, 'idempotent: a second pass (rescrub) has nothing to do');
  }
  // A visible key right after a zero-width character touching a letter (it stops matching once
  // the invisible is removed) is still redacted together with a hidden one.
  const touching = `x\u200b${visible} and ${hidden}`;
  const r = redactSecrets(touching);
  assert.ok(!r.text.includes('X0X0'), 'neither key survives');
  // redactDeep (frontmatter, rescrub facts/decisions) goes through the same path.
  const d = redactDeep({ a: `${visible} ${hidden}` });
  assert.equal(d.count, 2);
});

test('P2-3: the detector is linear on long unbroken runs (no quadratic backtracking)', () => {
  const units = ['a_', 'a-', 'aa_', 'a.', j(P.google, '-'), j(P.google, '_'), j(P.openai), j(P.slack), j(P.ghp), j(P.fly), j(P.neon), 'token_', 'x://'];
  const time = (n: number) => {
    let worst = 0;
    for (const u of units) {
      const s = u.repeat(Math.ceil(n / u.length));
      const t = performance.now();
      redactSecrets(s);
      strictCredentialSignal(s);
      worst = Math.max(worst, performance.now() - t);
    }
    return worst;
  };
  time(20_000); // warm up
  const small = time(50_000);
  const big = time(400_000);
  // Before the fix: 400 KB of `a_` took ~2 minutes (quadratic). Linear: 8x the input, about 8x the time.
  assert.ok(big < 3000, `400 KB run worst case ${Math.round(big)} ms`);
  assert.ok(big < Math.max(50, small) * 40, `scales linearly (50 KB ${Math.round(small)} ms, 400 KB ${Math.round(big)} ms)`);
});

test('P2-4: the withhold check is never looser than the pre-detector export rules (placeholders, hyphen-JWT, digit-free Slack)', () => {
  const jwt = j('ey', 'J', 'X'.repeat(12), '.ey', 'J', 'X'.repeat(12), '.', 'X'.repeat(12));
  const strictOnly = [
    'api_key: <your-key-here>', // the shared detector skips placeholders (not rewritten) ...
    j('api_key=', '${GEMINI_API', '_KEY}'),
    j('pass', 'word: $ZEUSI_DB_PW'),
    j('pass', 'word: process.env.ZEUSI_PW'),
    j('secret: {{', 'vault_secret}}'),
    j('pass', 'word: xxxxxxxx'),
    j(P.slack, 'abcdefghijk'),
  ];
  for (const s of strictOnly) assert.ok(strictCredentialSignal(s), `withheld (length ${s.length})`); // ... but the withhold check still withholds
  // A JWT right after "-" is a JWT for both (the old export rule used \b).
  assert.ok(credentialSignal(`-${jwt}`));
  assert.equal(redactSecrets(`x -${jwt} y`).text, 'x -[REDACTED:jwt] y');
  // The floor never fires on already-redacted text (a redacted served item is not withheld for it).
  for (const s of ['password: [REDACTED:keyword_value]', 'https://u:[REDACTED:url_password]@example.invalid', 'Bearer [REDACTED:bearer]']) {
    assert.equal(strictCredentialSignal(s), false, `redacted marker (length ${s.length})`);
  }
  // Benign prose stays clean for the withhold check too.
  for (const s of ['we rotated the password yesterday', 'the password lives in 1Password, ask the owner.', 'PR #1188 merged at 10:42']) {
    assert.equal(strictCredentialSignal(s), false);
  }
});

test('findSecrets reports kinds and offsets only', () => {
  const s = `x ${fakeMaskedGoogle()} y`;
  const m = findSecrets(s);
  assert.equal(m.length, 1);
  assert.deepEqual(Object.keys(m[0]!).sort(), ['end', 'kind', 'start']);
  assert.equal(s.slice(m[0]!.start, m[0]!.end), fakeMaskedGoogle());
});
