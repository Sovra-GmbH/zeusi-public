// Synthetic credential SHAPES shared by the detector, storage and serve-time tests (security
// P0, PR #23). Every value piece carries VW, so "no value piece survives" is one substring
// check. All values are assembled at runtime; nothing here is or resembles a real key.
import { j, P } from './secret-fixtures.ts';

/** Every value piece holds this marker: none may survive any path. */
export const VW = j('vq', 'zw');
export const survives = (s: string) => s.includes(VW);
export const MARK = '[REDACTED:keyword_value]';

// Every keyword form the detector knows: bare, case variants, prefixed and compound.
export const KEYWORDS = [
  'password', 'Password', 'PASSWORD', 'passwd', 'pwd', 'passphrase', 'secret', 'my-secret', 'admin-password',
  'db_password', 'DB_PASSWORD', 'ZEUSI_DB_PASSWORD', 'api_key', 'api-key', 'apikey', 'GEMINI_API_KEY', 'OPENAI_API_KEY',
  'token', 'Token', 'GITHUB_TOKEN', 'access_token', 'auth_token', 'refresh_token', 'fly-api-token',
  'private_key', 'secret_key', 'AWS_SECRET_ACCESS_KEY', 'access_key', 'client_secret',
];

export const SINGLE = j(VW, 'Solo9', 'Xx');
export const MULTI = [j(VW, 'alpha7'), j(VW, 'b'), j(VW, 'charlie'), j(VW, 'd4')].join(' ');
export const VALUES: Array<[string, string]> = [['single', SINGLE], ['multi', MULTI]];

/** Quoting / assignment styles. `keep` is text on the same line that is NOT part of the value. */
export const STYLES: Array<[string, (k: string, v: string) => string, string?]> = [
  ['colon', (k, v) => `${k}: ${v}`],
  ['equals', (k, v) => `${k}=${v}`],
  ['spaced equals', (k, v) => `${k} = ${v}`],
  ['comment after', (k, v) => `${k}: ${v} # rotate monthly`],
  // Fix round 2 (simplified): quoted or not, the value runs to the line end; text after a
  // closing quote on the same line is redacted too (over-redaction on purpose).
  ['double quoted', (k, v) => `${k}="${v}" trailing`],
  ['single quoted', (k, v) => `${k}: '${v}' trailing`],
  ['json', (k, v) => `{"${k}": "${v}", "other": 1}`],
  ['yaml quoted key', (k, v) => `'${k}': ${v}`],
  ['backticks', (k, v) => `\`${k}=${v}\` trailing`],
  ['colon equals', (k, v) => `${k} := ${v}`],
  ['fat arrow', (k, v) => `'${k}' => '${v}',`],
  // Self-review fix2c (Medium): quoting that continues straight after a closing quote.
  ['doubled single quotes', (k, v) => `${k}: '${v}''${v}'`],
  ['doubled double quotes', (k, v) => `${k}: "${v}""${v}"`],
  ['doubled backticks', (k, v) => `${k}=\`${v}\`\`${v}\``],
  ['shell quote-joining', (k, v) => `export ${k}='${v}'"'"'${v}'`],
  ['plus concatenation', (k, v) => `${k} = "${v}" + "${v}"`],
  ['plus concatenation, single', (k, v) => `${k} = '${v}'+'${v}';`],
  ['quoted then bare', (k, v) => `${k}="${v}"${v}`],
  ['unclosed quote', (k, v) => `${k}: "${v}`],
  ['table cell', (k, v) => `| ${k}: ${v} | keeptc |`, 'keeptc'],
  ['settings list (over-redacted to the line end)', (k, v) => `${k}=${v}, other=1`],
  // Security review r2b: a `;Name=` / `,name=` inside a value is part of it (connection strings).
  ['connection string', (k, v) => `${k}: ${v};SharedAccessKeyName=Root;SharedAccessKey=${v}`],
  ['comma setting inside', (k, v) => `${k}=${v},k=${v}`],
  ['value on next line', (k, v) => `${k}:\n  ${v}`],
  // Self-review r2 (Medium): a value with `|`, an escaped quote, `, ` or `; ` INSIDE it must
  // be redacted whole (the span used to end there and serve / store the rest).
  ['bar inside', (k, v) => `${k}: ${v}|${v}`],
  ['bar inside, table cell', (k, v) => `| svc | ${k}: ${v}|${v} | keeptb |`, 'keeptb'],
  ['escaped quote, json', (k, v) => `{"${k}": "${v}\\"${v}", "other": 1}`],
  ['escaped quote, double quoted', (k, v) => `${k}="${v}\\"${v}" trailing`],
  ['quoted bar, table cell', (k, v) => `| svc | ${k}: '${v}|${v}' | keepqt |`, 'keepqt'],
  ['comma inside', (k, v) => `${k}=${v}, ${v}`],
  ['semicolon inside', (k, v) => `${k}: ${v}; ${v}`],
  // Fix round 2 finish: a ` |` ends an unquoted value ONLY on a markdown table row. On any
  // other line the value runs to the line end (`password: <a> |<b>` served `<b>`).
  ['spaced bar, not a table row', (k, v) => `${k}: ${v} |${v}`],
  ['spaced bars, not a table row', (k, v) => `${k}=${v} | ${v} | ${v}`],
  ['bar first, not a table row', (k, v) => `${k}: | ${v}`],
  ['indented table row', (k, v) => `  | ${k}: ${v} | keepit |`, 'keepit'],
];

export interface KeywordCase { name: string; line: string; keep?: string | undefined }
export const KEYWORD_CASES: KeywordCase[] = [];
for (const k of KEYWORDS) for (const [vn, v] of VALUES) for (const [sn, f, keep] of STYLES) {
  KEYWORD_CASES.push({ name: `${k.length}-char keyword #${KEYWORDS.indexOf(k)} / ${vn} / ${sn}`, line: f(k, v), keep });
}


export const pw = (n: string) => j(VW, n, '9k');
export const b64 = (n: string) => j(VW, n, 'AbCdEfGh0123456789');
export const BEGIN = (t: string) => j('-----BEGIN ', t, ' PRIVATE KEY', t === 'PGP' ? ' BLOCK' : '', '-----');
export const END = (t: string) => j('-----END ', t, ' PRIVATE KEY', t === 'PGP' ? ' BLOCK' : '', '-----');

export interface ValueCase { name: string; text: string; keep: string; kind: string }
/** Each case is one text; `keep` must survive it (the text around the credential is kept). */
export const VALUE_CASES: ValueCase[] = [
  // url_password: `@` inside the password, every scheme the review named, the last `@` ends it.
  ...['https', 'redis', 'amqp', 'mongodb+srv', 'smtp', 'mysql'].map((sch, i) => ({
    name: `url ${sch}: p1@p2@host`, kind: 'url_password', keep: `keepu${i}`,
    text: `${sch}://admin:${pw('a')}@${pw('b')}@cache${i}.example.com/db keepu${i}`,
  })),
  { name: 'url: three @ and a colon in the password', kind: 'url_password', keep: 'keepu7', text: `redis://u:${pw('a')}:${pw('b')}@${pw('c')}@${pw('d')}@h.example.com keepu7` },
  { name: 'url: empty user (redis://:pw@host)', kind: 'url_password', keep: 'keepu8', text: `redis://:${pw('a')}@${pw('b')}@h.example.com:6379 keepu8` },
  { name: 'url: in markdown parens', kind: 'url_password', keep: 'keepu9', text: `see (amqp://svc:${pw('a')}@${pw('b')}@mq.example.com) keepu9` },
  // private_key: blank line inside (PGP armor, encrypted PEM), END line kept out of the text after.
  {
    name: 'PGP armored private key (headers, blank line, body, checksum)', kind: 'private_key', keep: 'keeppgp',
    text: [BEGIN('PGP'), 'Version: synthetic 1', 'Comment: test', '', b64('l1'), b64('l2'), `=${VW}cs`, END('PGP'), 'keeppgp'].join('\n'),
  },
  {
    name: 'encrypted PEM (Proc-Type, DEK-Info, blank line, body)', kind: 'private_key', keep: 'keeppem',
    text: [BEGIN('RSA'), 'Proc-Type: 4,ENCRYPTED', 'DEK-Info: AES-128-CBC,00FF', '', b64('l1'), '', b64('l2'), END('RSA'), 'keeppem'].join('\n'),
  },
  {
    name: 'OpenSSH key with blank lines between body lines', kind: 'private_key', keep: 'keepssh',
    text: ['before keepssh', BEGIN('OPENSSH'), b64('l1'), '', b64('l2'), '   ', b64('l3'), END('OPENSSH')].join('\n'),
  },
  // bearer: a character outside token68 inside the token.
  { name: 'bearer with %-encoded tail', kind: 'bearer', keep: 'keepb1', text: `Authorization: Bearer ${j('abcdefghij', 'klmnopqrstuv')}%2F${VW}tail keepb1` },
  { name: 'bearer with , and ! inside', kind: 'bearer', keep: 'keepb2', text: `curl -H "Authorization: Bearer ${j('Zyxwvutsrq', 'ponmlkjihg')},${VW}x!${VW}y" keepb2` },
  // masked provider fragment with more than one mask.
  { name: 'masked key, two masks', kind: 'masked_google_api_key', keep: 'keepm1', text: `key ${P.google}Sy12\u2026${VW}9\u2026${VW}8 keepm1` },
  { name: 'masked key, three masks (dots, stars)', kind: 'masked_openai_key', keep: 'keepm2', text: `old ${P.openaiProj}ab12...${VW}c3****${VW}d4...${VW}e5 keepm2` },
  // keyword = YAML block scalar.
  { name: 'yaml | block', kind: 'keyword_value', keep: 'keepy1', text: ['config:', '  password: |', `    ${pw('a')} ${pw('b')}`, `    ${pw('c')}`, '  host: keepy1'].join('\n') },
  { name: 'yaml >- block with a blank line inside', kind: 'keyword_value', keep: 'keepy2', text: ['GITHUB_TOKEN: >-', `  ${pw('a')}`, '', `  ${pw('b')}`, 'next: keepy2'].join('\n') },
  { name: 'yaml |+ block in a list item, with a comment', kind: 'keyword_value', keep: 'keepy3', text: ['- client_secret: |+ # rotate', `    ${pw('a')}`, `    ${pw('b')} ${pw('c')}`, '- name: keepy3'].join('\n') },
];


/**
 * Keys and bearer tokens hard-wrapped over several lines (self-review fix2e): every body line
 * carries VW. `keep` is the prose line after the credential (must survive storage).
 */
export interface WrappedCase { name: string; text: string; keep: string }
const line = (n: string, len: number) => j(VW, n, 'Ab3'.repeat(Math.ceil(len / 3))).slice(0, len);
const wrapIt = (head: string, lines: number, width: number, indent = '') =>
  [j(head, line('h', width)), ...Array.from({ length: lines - 1 }, (_, i) => j(indent, line(`l${i}`, width)))].join('\n');
export const WRAPPED_CASES: WrappedCase[] = [
  ...[2, 3, 4, 6].flatMap((n) => [
    { name: `openai project key over ${n} lines`, text: `${wrapIt(P.openaiProj, n, 40)}\nkeepw${n}a next`, keep: `keepw${n}a` },
    { name: `anthropic key over ${n} lines, indented`, text: `key:\n  ${wrapIt(P.anthropic, n, 30, '  ')}\nkeepw${n}b`, keep: `keepw${n}b` },
    { name: `google key over ${n} lines, quoted (>)`, text: `> ${wrapIt(P.google, n, 24, '> ')}\nkeepw${n}c`, keep: `keepw${n}c` },
    { name: `github token over ${n} lines`, text: `${wrapIt(P.ghp, n, 20)}\nkeepw${n}d`, keep: `keepw${n}d` },
    { name: `bearer over ${n} lines`, text: `Authorization: Bearer ${wrapIt('', n, 30)}\nkeepw${n}e`, keep: `keepw${n}e` },
    { name: `bearer over ${n} lines, CRLF`, text: `curl -H Bearer ${wrapIt('', n, 26).replace(/\n/g, '\r\n')}\r\nkeepw${n}f`, keep: `keepw${n}f` },
  ]),
];

/**
 * Residue shapes an older head may have STORED (a marker, then key characters on the next
 * lines). The serve guard must withhold every one (marker check), whatever the detector does.
 */
export const RESIDUE_CASES: string[] = [
  `[REDACTED:openai_key]\n${line('r1', 40)}\n${line('r2', 40)}`,
  `Bearer [REDACTED:bearer]\n${line('r3', 30)}`,
  `key: [REDACTED:anthropic_key]\n  ${line('r4', 12)}`,
  `x [REDACTED:google_api_key] ${line('r5', 9)}`,
  `password: [REDACTED:keyword_value]\n${line('r6', 16)}`,
];
