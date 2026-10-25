// End-to-end test against `wrangler dev` (http://localhost:8787 by default):
// registers an account with the same key derivation the Bitwarden clients use,
// then drives the official Bitwarden CLI (`bw`) through login, folders, items,
// trash/restore and sync, checking it decrypts what it stored.
//
// Usage: npm test   (with `npm run dev` running)

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { passwordGrant, registerPayload, rewrapForPassword, step, totp } from "./bwcrypto.mjs";

// Bitwarden clients require HTTPS, so run `wrangler dev --local-protocol https`.
const BASE = process.argv[2] ?? "https://127.0.0.1:8787";
// wrangler's local certificate is self-signed; accept it only for a local server.
const LOCAL_TLS = /^https:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(BASE);
if (LOCAL_TLS) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

let failures = 0;
const check = (ok, what) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${what}`);
  if (!ok) failures++;
};

async function api(path, init = {}) {
  // wrangler dev drops idle keep-alive sockets; retry once on a reset.
  const res = await fetch(BASE + path, init).catch((e) => {
    if (e.cause?.code !== "ECONNRESET") throw e;
    return fetch(BASE + path, init);
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body };
}

// ---- Bitwarden CLI, isolated from any real bw config ----
const appData = mkdtempSync(join(tmpdir(), "bw-e2e-"));
let session = "";
function bw(...args) {
  const env = { ...process.env, BITWARDENCLI_APPDATA_DIR: appData, BW_NOINTERACTION: "true", NODE_NO_WARNINGS: "1" };
  if (LOCAL_TLS) env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  if (session) env.BW_SESSION = session;
  return execFileSync(process.execPath, [BW_JS, ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
const bwJson = (...args) => JSON.parse(bw(...args));
const encodeJson = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64");
// The CLI: `npm install --no-save @bitwarden/cli`, or point BW_JS at another bw.js.
const BW_JS = process.env.BW_JS ?? new URL("../node_modules/@bitwarden/cli/build/bw.js", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

try {
  const email = `test-${Date.now()}@example.com`;
  const password = "correct horse battery staple 42";

  // 1. Registration (send-verification-email hands the token back, no mail).
  const tok = await api("/identity/accounts/register/send-verification-email", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ email, name: "E2E Test" }),
  });
  check(tok.status === 200 && typeof tok.body === "string", "send-verification-email returns a token");

  const p = await registerPayload(email, password);
  const reg = await api("/identity/accounts/register/finish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email,
      emailVerificationToken: tok.body,
      masterPasswordHash: p.masterPasswordHash,
      masterPasswordHint: "test hint",
      userSymmetricKey: p.protectedKey,
      userAsymmetricKeys: { publicKey: p.publicKey, encryptedPrivateKey: p.encryptedPrivateKey },
      kdf: 0,
      kdfIterations: p.iterations,
    }),
  });
  check(reg.status === 200, `register/finish (${reg.status})`);

  const dup = await api("/identity/accounts/register/send-verification-email", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  check(dup.status === 400, "registering the same email again is refused");

  const pre = await api("/identity/accounts/prelogin", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  check(pre.body.kdf === 0 && pre.body.kdfIterations === 600000, "prelogin reports PBKDF2 600000");

  const unauth = await api("/api/sync");
  check(unauth.status === 401, "sync without a token is 401");

  // 2. The official CLI.
  bw("config", "server", BASE);
  let wrong = "";
  try { bw("login", email, "wrong password", "--raw"); } catch (e) { wrong = String(e.stderr ?? e.message); }
  check(/incorrect/i.test(wrong), "bw login with a wrong password is rejected by the server");

  session = bw("login", email, password, "--raw");
  check(session.length > 20, "bw login succeeds (user key decrypted by the client)");

  const status = bwJson("status");
  check(status.status === "unlocked" && status.userEmail === email, `bw status: ${status.status}`);

  const folder = bwJson("create", "folder", encodeJson({ name: "Work" }));
  check(!!folder.id && folder.name === "Work", "create folder");

  const item = bwJson("create", "item", encodeJson({
    type: 1,
    name: "Example login",
    notes: "secret note",
    folderId: folder.id,
    favorite: true,
    login: { username: "alice", password: "S3cret!pass", uris: [{ match: null, uri: "https://example.com" }], totp: null },
    fields: [{ name: "pin", value: "1234", type: 1 }],
  }));
  check(!!item.id, "create login item");

  bw("sync");
  const got = bwJson("get", "item", item.id);
  check(got.login.password === "S3cret!pass" && got.login.username === "alice", "item decrypts after sync (username/password)");
  check(got.notes === "secret note" && got.fields?.[0]?.value === "1234", "notes and custom field decrypt");
  check(got.folderId === folder.id && got.favorite === true, "folder and favorite kept");
  check(got.login.uris?.[0]?.uri === "https://example.com", "URI kept");

  got.login.password = "Changed#2";
  bwJson("edit", "item", item.id, encodeJson(got));
  bw("sync");
  check(bwJson("get", "item", item.id).login.password === "Changed#2", "edit item");

  bwJson("create", "item", encodeJson({ type: 2, name: "A note", notes: "note body", secureNote: { type: 0 } }));
  bw("sync");
  check(bwJson("list", "items").length === 2, "two items listed");

  bw("delete", "item", item.id);
  bw("sync");
  const trash = bwJson("list", "items", "--trash");
  check(trash.length === 1 && trash[0].id === item.id, "soft delete moves the item to trash");

  bw("restore", "item", item.id);
  bw("sync");
  check(bwJson("list", "items").length === 2, "restore brings it back");

  bw("delete", "item", item.id, "--permanent");
  bw("sync");
  check(bwJson("list", "items").length === 1 && bwJson("list", "items", "--trash").length === 0, "permanent delete");

  bw("delete", "folder", folder.id);
  bw("sync");
  check(bwJson("list", "folders").every((f) => f.id !== folder.id), "delete folder");

  // 3. Tokens: raw grant, refresh, tampering, and isolation between users.
  const raw = await api("/identity/connect/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password", username: email, password: p.masterPasswordHash, scope: "api offline_access",
      client_id: "cli", device_identifier: crypto.randomUUID(), device_name: "e2e", device_type: "8",
    }),
  });
  check(raw.status === 200 && raw.body.Key === p.protectedKey, "token response carries the wrapped user key");
  const refreshed = await api("/identity/connect/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: raw.body.refresh_token, client_id: "cli" }),
  });
  check(refreshed.status === 200 && !!refreshed.body.access_token, "refresh token grant");
  const forged = raw.body.access_token.slice(0, -4) + "AAAA";
  check((await api("/api/sync", { headers: { Authorization: `Bearer ${forged}` } })).status === 401, "tampered JWT rejected");

  const email2 = `other-${Date.now()}@example.com`;
  const p2 = await registerPayload(email2, "another long password 7");
  await api("/identity/accounts/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: email2, masterPasswordHash: p2.masterPasswordHash, userSymmetricKey: p2.protectedKey,
      userAsymmetricKeys: { publicKey: p2.publicKey, encryptedPrivateKey: p2.encryptedPrivateKey }, kdf: 0, kdfIterations: p2.iterations,
    }),
  });
  const t2 = await api("/identity/connect/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: email2, password: p2.masterPasswordHash, scope: "api offline_access", client_id: "cli", device_identifier: crypto.randomUUID() }),
  });
  const auth2 = { Authorization: `Bearer ${t2.body.access_token}`, "Content-Type": "application/json" };
  const noteId = bwJson("list", "items")[0].id;
  const sync2 = await api("/api/sync", { headers: auth2 });
  check(sync2.status === 200 && sync2.body.ciphers.length === 0, "second user's sync shows none of the first user's items");
  check((await api(`/api/ciphers/${noteId}`, { headers: auth2 })).status === 404, "second user can't read the first user's item");
  check((await api(`/api/ciphers/${noteId}`, { method: "DELETE", headers: auth2 })).status === 404, "second user can't delete it");
  check(bwJson("list", "items").length === 1, "first user's item is still there");

  // 4. Attachments, through the CLI (encrypted client-side, stored in R2).
  const work = mkdtempSync(join(tmpdir(), "bw-files-"));
  const original = Buffer.from(`attachment body ${Date.now()}\n`.repeat(200));
  writeFileSync(join(work, "notes.txt"), original);
  bw("create", "attachment", "--file", join(work, "notes.txt"), "--itemid", noteId);
  bw("sync");
  const withAtt = bwJson("get", "item", noteId);
  check(withAtt.attachments?.length === 1 && withAtt.attachments[0].fileName === "notes.txt", "attachment listed with its decrypted name");
  bw("get", "attachment", "notes.txt", "--itemid", noteId, "--output", join(work, "back.txt"));
  check(readFileSync(join(work, "back.txt")).equals(original), "attachment downloads and decrypts to the same bytes");
  const attUrl = (await api("/api/sync", { headers: { Authorization: `Bearer ${raw.body.access_token}` } })).body.ciphers.find((c) => c.id === noteId).attachments[0].url;
  check((await api(new URL(attUrl).pathname)).status === 401, "attachment URL without its token is refused");
  check((await api(new URL(attUrl).pathname + "?token=" + raw.body.access_token)).status === 401, "a login token can't be used as a file token");
  const attId = withAtt.attachments[0].id;
  check((await api(`/api/ciphers/${noteId}/attachment/${attId}`, { headers: auth2 })).status === 404, "second user can't get the attachment");
  bw("delete", "attachment", attId, "--itemid", noteId);
  bw("sync");
  check(!bwJson("get", "item", noteId).attachments?.length, "delete attachment");

  // 5. Send: text (with and without password) and file, created and opened with the CLI.
  const textSend = bwJson("send", "-n", "Text send", "hello from send");
  check(!!textSend.accessUrl, "create text send");
  const received = bw("send", "receive", textSend.accessUrl);
  check(received === "hello from send", `receive text send (${JSON.stringify(received).slice(0, 40)})`);

  const pwSend = bwJson("send", "-n", "Locked send", "--password", "open sesame", "locked text");
  let noPw = "";
  try { bw("send", "receive", pwSend.accessUrl); } catch (e) { noPw = String(e.stderr ?? e.stdout ?? e.message); }
  check(noPw !== "locked text", "password-protected send needs its password");
  check(bw("send", "receive", pwSend.accessUrl, "--password", "open sesame") === "locked text", "receive with the password");

  writeFileSync(join(work, "file-send.bin"), original);
  const fileSend = bwJson("send", "-n", "File send", "-f", join(work, "file-send.bin"));
  check(!!fileSend.accessUrl && fileSend.type === 1, "create file send");
  bw("send", "receive", fileSend.accessUrl, "--output", join(work, "received.bin"));
  check(readFileSync(join(work, "received.bin")).equals(original), "receive file send, same bytes");

  const limited = bwJson("send", "-n", "Once", "--maxAccessCount", "1", "one time");
  bw("send", "receive", limited.accessUrl);
  let second = "";
  try { second = bw("send", "receive", limited.accessUrl); } catch { second = "refused"; }
  check(second !== "one time", "max access count is enforced");
  check(bwJson("send", "list").length === 4, "four sends listed");
  for (const s of bwJson("send", "list")) bw("send", "delete", s.id);
  check(bwJson("send", "list").length === 0, "delete sends");
  rmSync(work, { recursive: true, force: true });

  // 6. Two-factor (TOTP): enable through the API, then log in with the CLI using a code.
  const auth1 = { Authorization: `Bearer ${raw.body.access_token}`, "Content-Type": "application/json" };
  const setup = await api("/api/two-factor/get-authenticator", { method: "POST", headers: auth1, body: JSON.stringify({ masterPasswordHash: p.masterPasswordHash }) });
  check(setup.status === 200 && /^[A-Z2-7]{32}$/.test(setup.body.key), "get-authenticator returns a new secret");
  const enable = await api("/api/two-factor/authenticator", {
    method: "POST", headers: auth1,
    body: JSON.stringify({ key: setup.body.key, token: await totp(setup.body.key, step()), userVerificationToken: setup.body.userVerificationToken }),
  });
  check(enable.status === 200 && enable.body.enabled === true, "enable TOTP with a valid code");
  const challenge = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash));
  check(challenge.status === 400 && challenge.body.TwoFactorProviders?.[0] === "0", "password-only login now asks for 2FA");
  const badCode = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { fields: { two_factor_provider: "0", two_factor_token: "000000" } }));
  check(badCode.status === 400 && !badCode.body.access_token, "wrong TOTP code refused");

  bw("logout");
  // Codes from the next step are accepted too; using one marks that step as spent.
  const loginStep = step() + 1;
  session = bw("login", email, password, "--method", "0", "--code", await totp(setup.body.key, loginStep), "--raw");
  check(session.length > 20, "bw login with password + TOTP code");
  bw("sync");
  check(bwJson("list", "items").length === 1, "vault readable after 2FA login");

  // Remember-me token, then the recovery code (which switches 2FA off).
  const dev = crypto.randomUUID();
  // A spent step can't be reused: wait until loginStep is current, then use the step after it.
  await new Promise((r) => setTimeout(r, Math.max(0, loginStep * 30000 - Date.now() + 200)));
  const rem = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { device: dev, fields: { two_factor_provider: "0", two_factor_token: await totp(setup.body.key, loginStep + 1), two_factor_remember: "1" } }));
  check(rem.status === 200 && !!rem.body.TwoFactorToken, "login with remember=1 returns a remember token");
  const remLogin = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { device: dev, fields: { two_factor_provider: "5", two_factor_token: rem.body.TwoFactorToken } }));
  check(remLogin.status === 200, "remember token logs in on the same device");
  const remOther = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { fields: { two_factor_provider: "5", two_factor_token: rem.body.TwoFactorToken } }));
  check(remOther.status === 400, "remember token is refused on another device");
  const authRem = { Authorization: `Bearer ${rem.body.access_token}`, "Content-Type": "application/json" };
  const rc = await api("/api/two-factor/get-recover", { method: "POST", headers: authRem, body: JSON.stringify({ masterPasswordHash: p.masterPasswordHash }) });
  check(rc.status === 200 && /^[A-Z2-7]{32}$/.test(rc.body.code), "get-recover returns the recovery code");
  const rec = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { fields: { two_factor_provider: "8", two_factor_token: rc.body.code } }));
  check(rec.status === 200, "recovery code logs in");
  const after = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash));
  check(after.status === 200, "and switches 2FA off");

  // 7. Master password change: same user key, new wrapping; old sessions end.
  const newPassword = "a brand new master password 99";
  const rew = await rewrapForPassword(email, newPassword, p.userKey);
  const authAfter = { Authorization: `Bearer ${after.body.access_token}`, "Content-Type": "application/json" };
  const change = await api("/api/accounts/password", {
    method: "POST", headers: authAfter,
    body: JSON.stringify({ masterPasswordHash: p.masterPasswordHash, newMasterPasswordHash: rew.masterPasswordHash, key: rew.key, masterPasswordHint: "new hint" }),
  });
  check(change.status === 200, `change master password (${change.status})`);
  check((await api("/api/sync", { headers: authAfter })).status === 401, "old access token stops working");
  bw("logout");
  let oldPw = "";
  try { bw("login", email, password, "--raw"); } catch (e) { oldPw = String(e.stderr ?? e.message); }
  check(/incorrect/i.test(oldPw), "old master password no longer logs in");
  session = bw("login", email, newPassword, "--raw");
  bw("sync");
  check(bwJson("get", "item", noteId).notes === "note body", "new password logs in and the vault still decrypts");

  // 8. Icons: fetched from public sites only.
  check((await api("/icons/localhost/icon.png")).status === 404, "icon for localhost refused");
  check((await api("/icons/127.0.0.1/icon.png")).status === 404, "icon for an IP refused");
  const icon = await fetch(BASE + "/icons/github.com/icon.png");
  check(icon.status === 200 && /^image\//.test(icon.headers.get("content-type") ?? ""), `icon for github.com (${icon.status})`);

  bw("logout");
} catch (e) {
  failures++;
  console.log("FAIL  unexpected error:", e.stderr?.toString() || e.message, e.cause ?? "");
} finally {
  rmSync(appData, { recursive: true, force: true });
}

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
