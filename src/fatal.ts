// Top-level error handling for the MCP server process (docs/plans/2026-11-18-c2-log-disk-hygiene.md
// KTD6). A crash must not print row values: an uncaught exception's message or stack can carry
// whatever the failing statement or parser held. So an uncaught exception, an unhandled rejection and
// a failed start print ONE line with the error CLASS only (the constructor name), never the message
// or the stack. A failed start keeps its message only for errors the caller marks as safe (argument
// and config errors that exist to tell the operator what to fix; they may name operator config, never
// workspace data).
//
// Written with fs.writeSync(2): synchronous on every platform, so the line is out before exit.

import { writeSync } from 'node:fs';

const IDENT = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/;

/** The error's class name (constructor name), or `Error`; `non-error` for a thrown non-Error value. */
export function errorClass(e: unknown): string {
  if (!(e instanceof Error)) return 'non-error';
  try {
    const n = (e.constructor as { name?: unknown } | undefined)?.name;
    return typeof n === 'string' && IDENT.test(n) ? n : 'Error';
  } catch {
    return 'Error';
  }
}

export interface FatalIo {
  write?: ((line: string) => void) | undefined;
  exit?: ((code: number) => void) | undefined;
}

const stderrLine = (line: string) => {
  try {
    writeSync(2, line);
  } catch { /* nothing else to do */ }
};

/** uncaughtException / unhandledRejection: `<prog>: fatal: <class>`, exit 1. */
export function installFatalHandlers(prog: string, io: FatalIo = {}): void {
  const write = io.write ?? stderrLine;
  const exit = io.exit ?? ((code: number) => process.exit(code));
  const fatal = (e: unknown) => {
    write(`${prog}: fatal: ${errorClass(e)}\n`);
    exit(1);
  };
  process.on('uncaughtException', fatal);
  process.on('unhandledRejection', fatal);
}

/**
 * Install the handlers, then run `main`. A rejection prints `<prog>: error: <message>` only when
 * `safeMessage(e)` says the message is safe to print, else `<prog>: error: <class>`; exit 2.
 */
export function runMain(prog: string, main: () => Promise<void>, o: FatalIo & { safeMessage?: ((e: unknown) => boolean) | undefined } = {}): void {
  installFatalHandlers(prog, o);
  const write = o.write ?? stderrLine;
  const exit = o.exit ?? ((code: number) => process.exit(code));
  main().catch((e: unknown) => {
    let safe = false;
    try {
      safe = o.safeMessage?.(e) === true && e instanceof Error;
    } catch { /* not safe */ }
    write(`${prog}: error: ${safe ? (e as Error).message : errorClass(e)}\n`);
    exit(2);
  });
}
