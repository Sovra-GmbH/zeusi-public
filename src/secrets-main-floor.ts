// The serve-time MAIN FLOOR (PR #23 final design, docs/secrets.md "Serve time: withhold"):
// the credential patterns `origin/main` (6bbe8fa..fd8f076) used in its MCP output wall
// (src/hq-export.ts CREDENTIAL_PATTERNS + credentialSignal), copied VERBATIM. The serve
// guard (src/mcp-wall.ts) withholds an item when the shared detector, this floor, or a
// `[REDACTED:` marker fires, so serve-time strictness is never below main by construction:
// anything main withheld is still withheld. Do not edit these patterns to "fix" a false
// positive; they are pinned by test/secret-serve-withhold.test.ts. Booleans only.

export const MAIN_CREDENTIAL_PATTERNS: readonly RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----/, // PEM / OpenSSH / PGP private keys
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{30,}/, // GitHub tokens
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/, // OpenAI / Anthropic style keys
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/, // Slack
  /\bnpg_[A-Za-z0-9]{12,}/, // Neon role passwords
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, // JWT
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"`]+:[^\s/@'"`]+@/i, // URL with an inline password
  /\b(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']?[^\s"']{6,}/i,
  /\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*/i,
  new RegExp(String.raw`\b(?:2fa|mfa|otp|totp|one[- ]time|verification|verify|security|sign[- ]?in|log[- ]?in|auth(?:entication|enticator)?|passcode|recovery)\b[^\n]{0,32}?` + otpCode(), 'i'),
  new RegExp(String.raw`\bcode\b\s*(?:[:=#]|is\b|was\b)?\s*` + otpCode(), 'i'),
];

function otpCode(): string {
  const date = String.raw`(?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?!\d)`;
  const unit = String.raw`\s*(?:%|(?:ms|msec|µs|us|ns|s|secs?|seconds?|mins?|minutes?|h|hrs?|hours?|days?|[kmgt]i?b|bytes?|px|rps|qps|tokens?|rows?|lines?|chars?)\b)`;
  return String.raw`(?<![A-Za-z0-9_])(?<!\d[.,:/ -])(?!${date})(?:\d{6,8}|\d{3,4}[ -]\d{3,4})(?!\d)(?![.,:/ -]\d)(?!${unit})`;
}

/** origin/main's credentialSignal, verbatim. */
export function mainCredentialSignal(s: string): boolean {
  if (typeof s !== 'string' || s === '') return false;
  return MAIN_CREDENTIAL_PATTERNS.some((re) => re.test(s));
}
