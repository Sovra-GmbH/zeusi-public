// Credential-safe assertions. A failure message must never contain a password, secret or token
// (incident: an assert.strictEqual on a resolved password printed a real Keychain value).
// Compare with booleans; on failure show only a short sha256 fingerprint and the length.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

/** Non-reversible label for a value: `sha256:<12 hex> len=<n>` (or the type when not a string). */
export function fingerprint(v: unknown): string {
  if (typeof v !== 'string') return `<${v === null ? 'null' : typeof v}>`;
  return `sha256:${createHash('sha256').update(v).digest('hex').slice(0, 12)} len=${v.length}`;
}

/** Replace every occurrence of each secret in `text` with its fingerprint. */
export function redact(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const s of secrets) if (s !== '') out = out.split(s).join(`[REDACTED ${fingerprint(s)}]`);
  return out;
}

/** actual === expected, for a credential. The failure names fingerprints, never values. */
export function assertSecretEqual(actual: unknown, expected: string, label = 'secret'): void {
  assert.ok(actual === expected, `${label}: values differ (actual ${fingerprint(actual)}, expected ${fingerprint(expected)})`);
}

/** Element-wise assertSecretEqual for a list of credentials (e.g. passwords a fake client saw). */
export function assertSecretsEqual(actual: readonly unknown[], expected: readonly string[], label = 'secrets'): void {
  const ok = actual.length === expected.length && actual.every((v, i) => v === expected[i]);
  assert.ok(ok, `${label}: values differ (actual [${actual.map(fingerprint).join(', ')}], expected [${expected.map(fingerprint).join(', ')}])`);
}

/**
 * Like assert.rejects with a validation function, but the caught error is never printed raw:
 * fails if the message contains any of `secrets`, then checks `check` and shows a redacted message.
 */
export async function assertRejectsRedacted(
  p: Promise<unknown>,
  check: (e: Error) => boolean,
  secrets: readonly string[],
  label = 'rejection',
): Promise<void> {
  let err: unknown;
  let rejected = false;
  try {
    await p;
  } catch (e) {
    err = e;
    rejected = true;
  }
  assert.ok(rejected, `${label}: expected a rejection, the promise resolved`);
  const e = err instanceof Error ? err : new Error(String(err));
  const msg = `${e.name}: ${e.message}`;
  const leaked = secrets.filter((s) => s !== '' && msg.includes(s));
  assert.ok(leaked.length === 0, `${label}: error message contains secret value(s) ${leaked.map(fingerprint).join(', ')}`);
  assert.ok(check(e), `${label}: unexpected error: ${redact(msg, secrets)}`);
}

/** Synchronous twin of assertRejectsRedacted (for assert.throws with a validation function). */
export function assertThrowsRedacted(fn: () => unknown, check: (e: Error) => boolean, secrets: readonly string[], label = 'throw'): void {
  let err: unknown;
  let threw = false;
  try {
    fn();
  } catch (e) {
    err = e;
    threw = true;
  }
  assert.ok(threw, `${label}: expected a throw, the call returned`);
  const e = err instanceof Error ? err : new Error(String(err));
  const msg = `${e.name}: ${e.message}`;
  const leaked = secrets.filter((s) => s !== '' && msg.includes(s));
  assert.ok(leaked.length === 0, `${label}: error message contains secret value(s) ${leaked.map(fingerprint).join(', ')}`);
  assert.ok(check(e), `${label}: unexpected error: ${redact(msg, secrets)}`);
}
