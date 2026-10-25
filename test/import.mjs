// Tests tools/import_vaultwarden.py end to end, without real data: builds a synthetic
// Vaultwarden database (its real schema, test/fixtures/vaultwarden-schema.sql) holding an
// account encrypted the way the clients do it, imports it into the local D1, and logs in
// with the official Bitwarden CLI using the same master password and a TOTP code.
//
// Usage: npm run test:import   (with `npm run dev` running)

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { b64, encString, passwordGrant, pbkdf2, registerPayload, step, totp } from "./bwcrypto.mjs";
import { createSoftKey } from "./softkey.mjs";

const BASE = process.argv[2] ?? "https://127.0.0.1:8787";
const LOCAL_TLS = /^https:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(BASE);
if (LOCAL_TLS) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const here = (p) => new URL(p, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const BW_JS = process.env.BW_JS ?? here("../node_modules/@bitwarden/cli/build/bw.js");

let failures = 0;
const check = (ok, what) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${what}`);
  if (!ok) failures++;
};

const work = mkdtempSync(join(tmpdir(), "vw-import-test-"));
const appData = mkdtempSync(join(tmpdir(), "bw-import-"));
let session = "";
const bw = (...args) => {
  const env = { ...process.env, BITWARDENCLI_APPDATA_DIR: appData, BW_NOINTERACTION: "true", NODE_NO_WARNINGS: "1" };
  if (LOCAL_TLS) env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  if (session) env.BW_SESSION = session;
  return execFileSync(process.execPath, [BW_JS, ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
};

try {
  // ---- a Vaultwarden database with one account, two items, TOTP and WebAuthn 2FA
  const email = `imported-${Date.now()}@example.com`;
  const password = "the same master password after the move";
  const p = await registerPayload(email, password);
  const encKey = p.userKey.slice(0, 32), macKey = p.userKey.slice(32);
  const e = (text) => encString(new TextEncoder().encode(text), encKey, macKey);

  const vwDb = new DatabaseSync(join(work, "db.sqlite3"));
  vwDb.exec(readFileSync(here("./fixtures/vaultwarden-schema.sql"), "utf8"));
  const salt = crypto.getRandomValues(new Uint8Array(64));
  // Vaultwarden's server-side hash: PBKDF2-HMAC-SHA256(client hash, salt, 600000), raw bytes.
  const serverHash = await pbkdf2(new TextEncoder().encode(p.masterPasswordHash), salt, 600_000);
  const userId = crypto.randomUUID();
  const ts = "2026-10-19 19:33:25.494692428";
  vwDb.prepare(`INSERT INTO users (uuid, created_at, updated_at, email, name, password_hash, salt, password_iterations, password_hint,
      akey, private_key, public_key, totp_secret, totp_recover, security_stamp, equivalent_domains, excluded_globals, client_kdf_type,
      client_kdf_iter, enabled, stamp_exception, client_kdf_memory, client_kdf_parallelism)
    VALUES (?, ?, ?, ?, ?, ?, ?, 600000, NULL, ?, ?, ?, NULL, ?, ?, '[]', '[]', 0, 600000, 1, NULL, NULL, NULL)`)
    .run(userId, ts, ts, email, "Imported User", serverHash, salt, p.protectedKey, p.encryptedPrivateKey, p.publicKey,
      "RECOVERYCODEFORTESTS234567ABCDEF", crypto.randomUUID());

  const loginId = crypto.randomUUID();
  const loginData = JSON.stringify({ Username: await e("imported-user"), Password: await e("imported-pass!"), Uris: [{ Uri: await e("https://imported.example"), Match: null }], Totp: null });
  const cipherSql = `INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, notes, fields, data, password_history, deleted_at, reprompt, key)
    VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, NULL, NULL, 0, NULL)`;
  // PascalCase keys and a string field type, as older Vaultwarden rows can have.
  vwDb.prepare(cipherSql).run(loginId, ts, ts, userId, 1, await e("Imported login"), await e("imported notes"),
    JSON.stringify([{ Name: await e("pin"), Value: await e("4321"), Type: "0" }]), loginData);
  const noteId = crypto.randomUUID();
  vwDb.prepare(cipherSql).run(noteId, ts, ts, userId, 2, await e("Imported note"), await e("note text"), null, JSON.stringify({ Type: 0 }));
  vwDb.prepare("INSERT INTO favorites (user_uuid, cipher_uuid) VALUES (?, ?)").run(userId, loginId);

  const totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const tfSql = "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?, ?, ?, ?, ?, ?)";
  vwDb.prepare(tfSql).run(crypto.randomUUID(), userId, 0, 1, totpSecret, 0);
  // A WebAuthn key as Vaultwarden stores it (webauthn-rs Passkey), same shape as a real one.
  const softKey = await createSoftKey();
  const vwWebauthn = [{
    id: 1, name: "Imported key", migrated: false,
    credential: { cred: {
      cred_id: softKey.credentialId,
      cred: { type_: "ES256", key: { EC_EC2: { curve: "SECP256R1", x: softKey.jwk.x, y: softKey.jwk.y } } },
      counter: 0, transports: null, user_verified: false, backup_eligible: false, backup_state: false,
      registration_policy: "discouraged", extensions: { cred_protect: "NotRequested", hmac_create_secret: "NotRequested", appid: "NotRequested", cred_props: "Ignored" },
      attestation: { data: "None", metadata: "None" }, attestation_format: "none",
    } },
  }];
  vwDb.prepare(tfSql).run(crypto.randomUUID(), userId, 7, 1, JSON.stringify(vwWebauthn), 0);
  vwDb.prepare(tfSql).run(crypto.randomUUID(), userId, 1004, 0, "{}", 0); // a stale login challenge: not moved
  vwDb.close();

  // ---- import into the local D1
  const out = execFileSync("python", ["-I", here("../tools/import_vaultwarden.py"), work, "--apply", "local", "--out", join(work, "import.sql")],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  check(/prepared: 1 users, 0 folders, 2 ciphers/.test(out) && /2 twofactors/.test(out), "importer prepared 1 user, 2 items, TOTP + WebAuthn");
  check(/moved 1 WebAuthn key/.test(out), "importer converts the WebAuthn key");
  check(/imported into the local database/.test(out), "importer applied to the local D1");
  let again = "";
  try { execFileSync("python", ["-I", here("../tools/import_vaultwarden.py"), work, "--apply", "local", "--out", join(work, "again.sql")], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); }
  catch (err) { again = String(err.stderr); }
  check(/already exists/.test(again), "a second import of the same account is refused");

  // ---- log in with the old master password + TOTP, read the items
  bw("config", "server", BASE);
  let noCode = "";
  try { bw("login", email, password, "--raw"); } catch (err) { noCode = String(err.stderr ?? err.message); }
  check(noCode.length > 0, "imported TOTP 2FA still applies (login without a code fails)");
  session = bw("login", email, password, "--method", "0", "--code", await totp(totpSecret, step()), "--raw");
  check(session.length > 20, "logs in with the same master password and a TOTP code");
  bw("sync");
  const items = JSON.parse(bw("list", "items"));
  const login = items.find((i) => i.id === loginId);
  check(items.length === 2, "both items imported");
  check(login?.name === "Imported login" && login.login.username === "imported-user" && login.login.password === "imported-pass!", "login decrypts (name, username, password)");
  check(login?.login.uris?.[0]?.uri === "https://imported.example", "PascalCase keys from older rows normalised (URI)");
  check(login?.fields?.[0]?.value === "4321" && login.fields[0].type === 0, "custom field decrypts, string type fixed");
  check(login?.favorite === true, "favourite kept");
  check(items.find((i) => i.id === noteId)?.notes === "note text", "secure note decrypts");

  // The Vaultwarden security key works after the move (same origin).
  const need = await fetch(BASE + "/identity/connect/token", passwordGrant(email, p.masterPasswordHash)).then((r) => r.json());
  const opts = need.TwoFactorProviders2?.["7"];
  check(need.TwoFactorProviders?.includes("7") && opts?.allowCredentials?.[0]?.id === softKey.credentialId, "imported WebAuthn key offered at login");
  const viaKey = await fetch(BASE + "/identity/connect/token", passwordGrant(email, p.masterPasswordHash, {
    fields: { two_factor_provider: "7", two_factor_token: await softKey.assert(opts, new URL(BASE).origin) },
  }));
  check(viaKey.status === 200, "logs in with the imported security key");

  // The first login moved the hash from Vaultwarden's 600000 rounds to this server's own;
  // the same password keeps working afterwards.
  const wranglerJs = here("../node_modules/wrangler/bin/wrangler.js");
  const after = JSON.parse(execFileSync(process.execPath, [wranglerJs, "d1", "execute", "DB", "--local", "--json", "--command",
    `SELECT password_iterations AS n FROM users WHERE email = '${email}'`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, CI: "1" } }))[0].results[0].n;
  check(after === 100000, `hash re-done at login (600000 -> ${after} rounds)`);
  bw("logout");
  session = bw("login", email, password, "--method", "0", "--code", await totp(totpSecret, step() + 1), "--raw");
  check(session.length > 20, "same master password logs in after the re-hash");
  bw("logout");
} catch (err) {
  failures++;
  console.log("FAIL  unexpected error:", err.stderr?.toString() || err.message);
} finally {
  rmSync(work, { recursive: true, force: true });
  rmSync(appData, { recursive: true, force: true });
}

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
