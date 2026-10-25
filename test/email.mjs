// Email features against `npm run dev`: email two-step login (setup, login codes, wrong and
// reused codes, resend limit), the password hint and security notices. wrangler dev doesn't
// send mail: it writes each message to a .eml file and logs the path, which this test reads.
//
// Usage: npm run test:email

import { readFileSync } from "node:fs";
import { passwordGrant, registerPayload } from "./bwcrypto.mjs";

const BASE = process.argv[2] ?? "https://127.0.0.1:8787";
if (/^https:\/\/(127\.0\.0\.1|localhost)(:|\/|$)/.test(BASE)) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const LOG = new URL("../wrangler-dev.log", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

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

// Messages written since `since` (count of "Email:" lines seen before), decoded.
const mailLines = () => readFileSync(LOG, "utf8").split(/\r?\n/).filter((l) => l.startsWith("Email: ") && l.endsWith(".eml"));
function mailsSince(n) {
  return mailLines().slice(n).map((l) => {
    const raw = readFileSync(l.slice(7), "utf8");
    const [head, ...rest] = raw.split("\r\n\r\n");
    const subject = /^Subject: (.*)$/m.exec(head)?.[1] ?? "";
    const to = /^To: <(.*)>$/m.exec(head)?.[1] ?? "";
    const from = /^From: .*<(.*)>$/m.exec(head)?.[1] ?? "";
    return { subject, to, from, text: Buffer.from(rest.join("").replace(/\s/g, ""), "base64").toString("utf8") };
  });
}
const settle = () => new Promise((r) => setTimeout(r, 400)); // the log line lands just after the response
const codeIn = (m) => /\b(\d{6})\b/.exec(m?.text ?? "")?.[1];

try {
  const email = `mail-${Date.now()}@example.com`;
  const p = await registerPayload(email, "email test master password");
  await post("/identity/accounts/register", {}, {
    email, masterPasswordHash: p.masterPasswordHash, masterPasswordHint: "the usual one", userSymmetricKey: p.protectedKey,
    userAsymmetricKeys: { publicKey: p.publicKey, encryptedPrivateKey: p.encryptedPrivateKey }, kdf: 0, kdfIterations: p.iterations,
  });

  // A first login from a new device sends a notice.
  let seen = mailLines().length;
  const login = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash));
  const A = { Authorization: `Bearer ${login.body.access_token}` };
  await settle();
  const notice = mailsSince(seen).find((m) => m.subject === "New login to your vault");
  check(login.status === 200 && notice?.to === email && /^[^@\s]+@[^@\s]+$/.test(notice.from), "new-device login notice sent from MAIL_FROM");
  check(/IP address:/.test(notice?.text ?? ""), "notice names the IP address");

  // ---- setup
  const info = await post("/api/two-factor/get-email", A, { masterPasswordHash: p.masterPasswordHash });
  check(info.status === 200 && info.body.enabled === false && info.body.email === null && !!info.body.userVerificationToken, "get-email: off, top-level fields like the web vault reads");
  seen = mailLines().length;
  const sent = await post("/api/two-factor/send-email", A, { email, userVerificationToken: info.body.userVerificationToken });
  await settle();
  const setupMail = mailsSince(seen)[0];
  const setupCode = codeIn(setupMail);
  check(sent.status === 200 && setupMail?.to === email && !!setupCode, "setup code mailed");
  check((await post("/api/two-factor/send-email", A, { email, userVerificationToken: info.body.userVerificationToken })).status === 400, "asking again within 30 s is refused");
  const wrongSetup = await post("/api/two-factor/email", A, { email, token: setupCode === "000000" ? "111111" : "000000", userVerificationToken: info.body.userVerificationToken }, "PUT");
  check(wrongSetup.status === 400, "wrong setup code refused");
  const on = await post("/api/two-factor/email", A, { email, token: setupCode, userVerificationToken: info.body.userVerificationToken }, "PUT");
  check(on.status === 200 && on.body.enabled === true && on.body.email === email, "email two-step login turned on");
  check((await api("/api/two-factor", { headers: A })).body.data?.some((x) => x.type === 1), "two-factor list shows email");

  // ---- login with an emailed code
  const need = await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash));
  check(need.status === 400 && need.body.TwoFactorProviders?.includes("1") && /^ma\*+@example\.com$/.test(need.body.TwoFactorProviders2?.["1"]?.Email ?? ""), "login asks for an email code, address obscured");
  check((await post("/api/two-factor/send-email-login", {}, { email, masterPasswordHash: "wrong" })).status === 400, "login code needs the right password");
  seen = mailLines().length;
  const askCode = await post("/api/two-factor/send-email-login", {}, { email, masterPasswordHash: p.masterPasswordHash, deviceIdentifier: crypto.randomUUID() });
  await settle();
  const loginCode = codeIn(mailsSince(seen)[0]);
  check(askCode.status === 200 && !!loginCode, "login code mailed");
  const grant = (code, extra = {}) => api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash, { fields: { two_factor_provider: "1", two_factor_token: code }, ...extra }));
  check((await grant(loginCode === "123456" ? "654321" : "123456")).status === 400, "wrong login code refused");
  const ok = await grant(loginCode);
  check(ok.status === 200 && !!ok.body.access_token, "login with the emailed code");
  check((await grant(loginCode)).status === 400, "a used code can't be used again");

  // Three wrong tries spend the code.
  await new Promise((r) => setTimeout(r, 31_000)); // the resend limit
  seen = mailLines().length;
  await post("/api/two-factor/send-email-login", {}, { email, masterPasswordHash: p.masterPasswordHash });
  await settle();
  const burnt = codeIn(mailsSince(seen)[0]);
  const other = burnt === "000001" ? "000002" : "000001";
  for (let i = 0; i < 3; i++) await grant(other);
  check((await grant(burnt)).status === 400, "after three wrong tries the right code no longer works");

  // ---- password hint (same answer for unknown accounts)
  seen = mailLines().length;
  const hint = await post("/api/accounts/password-hint", {}, { email });
  const unknown = await post("/api/accounts/password-hint", {}, { email: "nobody@example.com" });
  await settle();
  const hintMails = mailsSince(seen);
  check(hint.status === 200 && unknown.status === 200, "hint request answers the same for known and unknown accounts");
  check(hintMails.length === 1 && hintMails[0].to === email && /the usual one/.test(hintMails[0].text), "hint mailed only for the real account");

  // ---- turning it off sends a notice and lifts the code step
  const B = { Authorization: `Bearer ${ok.body.access_token}` };
  const info2 = await post("/api/two-factor/get-email", B, { masterPasswordHash: p.masterPasswordHash });
  check(info2.body.enabled === true && info2.body.email === email, "get-email shows it on, with the address");
  seen = mailLines().length;
  const off = await post("/api/two-factor/email", B, { userVerificationToken: info2.body.userVerificationToken }, "DELETE");
  await settle();
  check(off.status === 200 && mailsSince(seen).some((m) => /removed/.test(m.subject)), "turn off, with a notice");
  check((await api("/identity/connect/token", passwordGrant(email, p.masterPasswordHash))).status === 200, "login no longer needs a code");
} catch (e) {
  failures++;
  console.log("FAIL  unexpected error:", e.message);
}

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
