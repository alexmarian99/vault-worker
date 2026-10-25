// Tests the daily cleanup (the Worker's `scheduled` handler) against a local dev server
// started with:  npx wrangler dev --ip 127.0.0.1 --port 8787 --local-protocol https --test-scheduled --var CLEANUP_GRACE_SECONDS:0
// It sets up old and recent data through the API, backdates rows with `wrangler d1 execute --local`,
// fires the cron, and checks what was removed from D1 and R2 and what was kept.
//
// The server doesn't look inside encrypted fields, so placeholder strings stand in for real ciphertext.
//
// Usage: npm run test:cleanup

import { execFileSync } from "node:child_process";

const BASE = process.argv[2] ?? "https://127.0.0.1:8787";
if (/^https:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(BASE)) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const WRANGLER = new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const ENC = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

let failures = 0;
const check = (ok, what) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${what}`);
  if (!ok) failures++;
};

async function api(path, init = {}) {
  const res = await fetch(BASE + path, init).catch((e) => {
    if (e.cause?.code !== "ECONNRESET") throw e;
    return fetch(BASE + path, init);
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body };
}

const wrangler = (...args) =>
  execFileSync(process.execPath, [WRANGLER, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, CI: "1" } });
const sql = (q) => wrangler("d1", "execute", "DB", "--local", "--json", "--command", q);
const rows = (q) => JSON.parse(sql(q))[0].results;
const r2Exists = (key) => {
  try { wrangler("r2", "object", "get", `vault-files/${key}`, "--local", "--pipe"); return true; } catch { return false; }
};
const daysAgo = (n) => new Date(Date.now() - n * 86400_000).toISOString();

// ---- an account with a token
const email = `cleanup-${Date.now()}@example.com`;
const hash = "cleanup-test-master-password-hash";
await api("/identity/accounts/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email, masterPasswordHash: hash, userSymmetricKey: ENC, kdf: 0, kdfIterations: 600000 }),
});
const tok = await api("/identity/connect/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ grant_type: "password", username: email, password: hash, scope: "api offline_access", client_id: "cli", device_identifier: crypto.randomUUID() }),
});
const H = { Authorization: `Bearer ${tok.body.access_token}`, "Content-Type": "application/json" };
check(tok.status === 200, "test account logged in");

const note = async () => (await api("/api/ciphers", { method: "POST", headers: H, body: JSON.stringify({ type: 2, name: ENC, secureNote: { type: 0 } }) })).body.id;
async function attach(cipherId, upload = true) {
  const slot = await api(`/api/ciphers/${cipherId}/attachment/v2`, { method: "POST", headers: H, body: JSON.stringify({ fileName: ENC, key: ENC, fileSize: 64 }) });
  if (upload) {
    const fd = new FormData();
    fd.append("data", new Blob([new Uint8Array(64).fill(7)]), "x");
    await fetch(`${BASE}/api${slot.body.url}`, { method: "POST", headers: { Authorization: H.Authorization }, body: fd });
  }
  return { id: slot.body.attachmentId, key: `attachments/${cipherId}/${slot.body.attachmentId}` };
}
async function fileSend() {
  const r = await api("/api/sends/file/v2", {
    method: "POST", headers: H,
    body: JSON.stringify({ type: 1, name: ENC, key: ENC, file: { fileName: ENC }, fileLength: 64, deletionDate: new Date(Date.now() + 86400_000).toISOString() }),
  });
  const fd = new FormData();
  fd.append("data", new Blob([new Uint8Array(64).fill(9)]), "x");
  await fetch(`${BASE}/api${r.body.url}`, { method: "POST", headers: { Authorization: H.Authorization }, body: fd });
  return { id: r.body.sendResponse.id, key: `sends/${r.body.sendResponse.id}/${r.body.sendResponse.file.id}` };
}

// ---- the situations
const oldTrash = await note();
const oldTrashAtt = await attach(oldTrash);
await api(`/api/ciphers/${oldTrash}/delete`, { method: "PUT", headers: H });
sql(`UPDATE ciphers SET deleted_at = '${daysAgo(40)}' WHERE id = '${oldTrash}'`);

const recentTrash = await note();
const recentTrashAtt = await attach(recentTrash);
await api(`/api/ciphers/${recentTrash}/delete`, { method: "PUT", headers: H });

const live = await note();
const liveAtt = await attach(live);
const staleSlot = await attach(live, false);
sql(`UPDATE attachments SET created_at = '${daysAgo(2)}' WHERE id = '${staleSlot.id}'`);
const freshSlot = await attach(live, false);

const orphan = await attach(live);
sql(`DELETE FROM attachments WHERE id = '${orphan.id}'`);

const expired = await fileSend();
sql(`UPDATE sends SET deletion_date = '${daysAgo(1)}' WHERE id = '${expired.id}'`);
const current = await fileSend();

check(r2Exists(oldTrashAtt.key) && r2Exists(orphan.key) && r2Exists(expired.key), "setup: files are in R2 before the cleanup");

// ---- fire the cron (wrangler dev --test-scheduled)
const fired = await fetch(`${BASE}/cdn-cgi/handler/scheduled?cron=${encodeURIComponent("17 3 * * *")}`)
  .then((r) => r.status)
  .catch(() => 0);
const viaLegacy = fired === 200 ? 200 : (await fetch(`${BASE}/__scheduled?cron=${encodeURIComponent("17 3 * * *")}`)).status;
check(viaLegacy === 200, "scheduled handler fired");
await new Promise((r) => setTimeout(r, 1500)); // the cleanup runs in waitUntil

// ---- what went, what stayed
const ids = (q) => rows(q).map((r) => r.id);
check(!ids(`SELECT id FROM ciphers WHERE id = '${oldTrash}'`).length, "trash older than 30 days deleted");
check(!r2Exists(oldTrashAtt.key) && !ids(`SELECT id FROM attachments WHERE id = '${oldTrashAtt.id}'`).length, "...with its attachment, row and R2 file");
check(ids(`SELECT id FROM ciphers WHERE id = '${recentTrash}'`).length === 1 && r2Exists(recentTrashAtt.key), "recent trash and its file kept (can still be restored)");
check(ids(`SELECT id FROM ciphers WHERE id = '${live}'`).length === 1 && r2Exists(liveAtt.key), "live item and its attachment untouched");
check(!ids(`SELECT id FROM attachments WHERE id = '${staleSlot.id}'`).length, "upload slot without a file, older than a day, removed");
check(ids(`SELECT id FROM attachments WHERE id = '${freshSlot.id}'`).length === 1, "fresh upload slot kept (upload may still be coming)");
check(!r2Exists(orphan.key), "orphaned R2 file (no row) removed");
check(!ids(`SELECT id FROM sends WHERE id = '${expired.id}'`).length && !r2Exists(expired.key), "expired file send and its file removed");
check(ids(`SELECT id FROM sends WHERE id = '${current.id}'`).length === 1 && r2Exists(current.key), "current send kept");

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
