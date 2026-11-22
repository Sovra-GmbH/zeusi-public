// Child process for test/fatal.test.ts: crashes in the way argv[2] names, with a canary (argv[3]) in
// the message, under the real handlers of src/fatal.ts.
import { runMain } from '../../src/fatal.ts';

class RowValueError extends Error {
  override name = 'RowValueError';
}
class SafeArgsError extends Error {
  override name = 'SafeArgsError';
}

const [mode, canary] = [process.argv[2], process.argv[3] ?? ''];
runMain('zeusi-mcp', async () => {
  if (mode === 'throw') setTimeout(() => { throw new RowValueError(`duplicate key value (body)=(${canary})`); }, 1);
  else if (mode === 'reject') void Promise.reject(new TypeError(`cannot parse ${canary}`));
  else if (mode === 'reject-string') void Promise.reject(`raw ${canary}`);
  else if (mode === 'main') throw new RowValueError(`row ${canary}`);
  else if (mode === 'main-safe') throw new SafeArgsError('--port must be a number');
  // keep the event loop alive long enough for the async crashes
  await new Promise((r) => setTimeout(r, 200));
}, { safeMessage: (e) => e instanceof SafeArgsError });
