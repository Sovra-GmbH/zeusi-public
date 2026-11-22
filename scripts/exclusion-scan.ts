// Read-only, count-only Plankiva scan (src/exclusion-scan.ts) over one role service.
//
//   node scripts/exclusion-scan.ts <service>        e.g. zeusi_backup (HQ, after retraction)
//
// Connects through the named pg_service.conf section (password from the Keychain item or
// ~/.pgpass, as every role command), runs plain SELECTs as that role, and prints table
// names and counts only: never text, uris, paths, ids, hosts or connection details.
// Exit 0 when every readable table has 0 matching rows and every table was readable;
// exit 1 otherwise; exit 2 on usage or connection errors (the error names no secret).

import { parseArgs } from 'node:util';
import { exclusionScan, formatExclusionScan } from '../src/exclusion-scan.ts';
import { connectService } from '../src/db.ts';

const { positionals } = parseArgs({ allowPositionals: true, options: {} });
if (positionals.length !== 1 || !/^[A-Za-z0-9_.-]+$/.test(positionals[0]!)) {
  console.error('usage: node scripts/exclusion-scan.ts <service>   (a pg_service.conf section, e.g. zeusi_backup)');
  process.exit(2);
}
const service = positionals[0]!;
let db;
try {
  db = await connectService(service);
} catch (e) {
  console.error(`exclusion scan: could not connect with service "${service}" (${(e as Error).name})`);
  process.exit(2);
}
try {
  const r = await exclusionScan(db);
  console.log(`service: ${service}`);
  console.log(formatExclusionScan(r));
  process.exitCode = r.total === 0 && r.unreadable === 0 ? 0 : 1;
} finally {
  await db.close();
}
