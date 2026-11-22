// Tests that exercise the macOS Keychain branch (with an injected `security` runner) must not depend on
// the host: src/keychain.ts readRolePassword asks the Keychain only when process.platform is 'darwin', so
// on a Linux CI runner the same test silently took the ~/.pgpass branch and failed (or, worse, would
// pass without ever reaching the code it names). withPlatform pins the platform for one test body.
export async function withPlatform<T>(platform: NodeJS.Platform, fn: () => Promise<T>): Promise<T> {
  const desc = Object.getOwnPropertyDescriptor(process, 'platform');
  if (!desc) throw new Error('process.platform has no own property descriptor');
  Object.defineProperty(process, 'platform', { ...desc, value: platform });
  try {
    return await fn();
  } finally {
    Object.defineProperty(process, 'platform', desc);
  }
}
