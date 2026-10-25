// Checks src/pbkdf2.ts against Node's PBKDF2 (including Vaultwarden's 600000 rounds) and times it.
// Usage: npm run test:pbkdf2   (Node 23.6+ runs the .ts file directly)

import { pbkdf2Sync, randomBytes } from "node:crypto";
import { pbkdf2Sha256 } from "../src/pbkdf2.ts";

let failures = 0;
for (const [plen, slen, iterations] of [[3, 8, 1], [44, 64, 2], [44, 64, 1000], [100, 16, 10], [64, 64, 5], [65, 32, 3], [44, 64, 600000]]) {
  const password = randomBytes(plen), salt = randomBytes(slen);
  const t0 = performance.now();
  const mine = Buffer.from(pbkdf2Sha256(password, salt, iterations));
  const ms = performance.now() - t0;
  const ok = mine.equals(pbkdf2Sync(password, salt, iterations, 32, "sha256"));
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  password ${plen} B, salt ${slen} B, ${iterations} rounds (${ms.toFixed(0)} ms)`);
}
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
