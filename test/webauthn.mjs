// WebAuthn two-factor against `npm run dev`, with a software authenticator: registration,
// login, and the checks that must reject (origin, replay, forged signature, cloned key).
// The Bitwarden CLI has no WebAuthn, so this drives the API the way the web vault does.
//
// Usage: npm run test:webauthn

import { passwordGrant, registerPayload, step, totp } from "./bwcrypto.mjs";
import { createSoftKey } from "./softkey.mjs";

const BASE = process.argv[2] ?? "https://127.0.0.1:8787";
if (/^https:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(BASE)) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const ORIGIN = new URL(BASE).origin;

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
const post = (path, auth, body, method = "POST") => api(path, { method, headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify(body) });

try {
  const email = `webauthn-${Date.now()}@example.com`;
  const p = await registerPayload(email, "webauthn test master password");
  await post("/identity/accounts/register", {}, {
    email, masterPasswordHash: p.masterPasswordHash, userSymmetricKey: p.protectedKey,
    userAsymmetricKeys: { publicKey: p.publicKey, encryptedPrivateKey: p.encryptedPrivateKey }, kdf: 0, kdfIterations: p.iterations,
  });
  const login0 = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash));
  const A = { Authorization: `Bearer ${login0.body.access_token}` };
  check(login0.status === 200, "account without 2FA logs in");

  // ---- registration
  const key = await createSoftKey();
  const listed = await post("/api/two-factor/get-webauthn", A, { masterPasswordHash: p.masterPasswordHash });
  check(listed.status === 200 && listed.body.enabled === false && !!listed.body.userVerificationToken, "get-webauthn: none yet, verification token issued");
  check((await post("/api/two-factor/get-webauthn", A, { masterPasswordHash: "wrong" })).status === 400, "get-webauthn needs the master password");

  const ch1 = await post("/api/two-factor/get-webauthn-challenge", A, { userVerificationToken: listed.body.userVerificationToken });
  // The web vault builds navigator.credentials.create() options from the top level of this response.
  check(ch1.status === 200 && ch1.body.challenge && ch1.body.rp?.id === new URL(BASE).hostname && ch1.body.user?.id, "registration challenge for this host, at the top level like the web vault reads it");
  const badOrigin = await post("/api/two-factor/webauthn", A, {
    id: 1, name: "Evil", userVerificationToken: listed.body.userVerificationToken,
    deviceResponse: await key.register(ch1.body, "https://evil.example"),
  });
  check(badOrigin.status === 400 && /origin/i.test(JSON.stringify(badOrigin.body)), "registration from another origin refused");

  const ch2 = await post("/api/two-factor/get-webauthn-challenge", A, { userVerificationToken: listed.body.userVerificationToken });
  const reg = await post("/api/two-factor/webauthn", A, {
    id: 1, name: "Test key", userVerificationToken: listed.body.userVerificationToken,
    deviceResponse: await key.register(ch2.body, ORIGIN),
  }, "PUT");
  check(reg.status === 200 && reg.body.enabled === true && reg.body.keys?.[0]?.name === "Test key", "key registered");
  const again = await post("/api/two-factor/webauthn", A, {
    id: 2, name: "Replay", userVerificationToken: listed.body.userVerificationToken,
    deviceResponse: await key.register(ch2.body, ORIGIN),
  });
  check(again.status === 400, "registration challenge can't be reused");
  const prov = await api("/api/two-factor", { headers: A });
  check(prov.body.data?.some((x) => x.type === 7), "two-factor list shows WebAuthn");

  // ---- login
  const need = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash));
  const opts = need.body.TwoFactorProviders2?.["7"];
  check(need.status === 400 && need.body.TwoFactorProviders?.includes("7") && opts?.allowCredentials?.[0]?.id === key.credentialId, "password login now asks for the security key");
  const answer = await key.assert(opts, ORIGIN);
  const ok = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { fields: { two_factor_provider: "7", two_factor_token: answer } }));
  check(ok.status === 200 && !!ok.body.access_token, "login with the security key");
  const replay = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { fields: { two_factor_provider: "7", two_factor_token: answer } }));
  check(replay.status === 400, "the same assertion can't be replayed");

  const fresh = async () => (await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash))).body.TwoFactorProviders2["7"];
  const tryLogin = async (token) => (await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { fields: { two_factor_provider: "7", two_factor_token: token } }))).status;
  check(await tryLogin(await key.assert(await fresh(), ORIGIN, { tamper: true })) === 400, "forged signature refused");
  check(await tryLogin(await key.assert(await fresh(), "https://evil.example")) === 400, "assertion from another origin refused");
  check(await tryLogin(await key.assert(await fresh(), ORIGIN, { rpId: "evil.example" })) === 400, "assertion for another RP ID refused");
  const other = await createSoftKey();
  check(await tryLogin(await other.assert(await fresh(), ORIGIN)) === 400, "an unregistered key refused");

  // Security keys count signatures up; going backwards means a cloned key.
  key.useCounter = true;
  check(await tryLogin(await key.assert(await fresh(), ORIGIN)) === 200, "counting key: first login (counter 1)");
  check(await tryLogin(await key.assert(await fresh(), ORIGIN)) === 200, "counting key: second login (counter 2)");
  check(await tryLogin(await key.assert(await fresh(), ORIGIN, { counterOverride: 1 })) === 400, "counter going backwards (cloned key) refused");

  // ---- WebAuthn and TOTP together, then removing the key
  const B = { Authorization: `Bearer ${ok.body.access_token}` };
  const setup = await post("/api/two-factor/get-authenticator", B, { masterPasswordHash: p.masterPasswordHash });
  await post("/api/two-factor/authenticator", B, { key: setup.body.key, token: await totp(setup.body.key, step()), userVerificationToken: setup.body.userVerificationToken });
  const both = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash));
  check(JSON.stringify(both.body.TwoFactorProviders?.slice().sort()) === '["0","7"]', "both providers offered");
  const viaTotp = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { fields: { two_factor_provider: "0", two_factor_token: await totp(setup.body.key, step() + 1) } }));
  check(viaTotp.status === 200, "TOTP still works next to WebAuthn");

  const tok = (await post("/api/two-factor/get-webauthn", B, { masterPasswordHash: p.masterPasswordHash })).body.userVerificationToken;
  const del = await post("/api/two-factor/webauthn", B, { id: 1, userVerificationToken: tok }, "DELETE");
  check(del.status === 200 && del.body.enabled === false, "remove the security key");
  const after = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash));
  check(JSON.stringify(after.body.TwoFactorProviders) === '["0"]', "only TOTP left");
  const totpOff = await post("/api/two-factor/authenticator", B, { key: setup.body.key, userVerificationToken: setup.body.userVerificationToken }, "DELETE");
  check(totpOff.status === 200 && (await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash))).status === 200, "turning TOTP off leaves no 2FA");
} catch (e) {
  failures++;
  console.log("FAIL  unexpected error:", e.message);
}

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
