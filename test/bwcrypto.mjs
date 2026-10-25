// Bitwarden client-side crypto for tests: account keys the way the clients derive them,
// and TOTP codes. Shared by test/e2e.mjs and test/import.mjs.

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
export const b64 = (buf) => Buffer.from(buf).toString("base64");
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

// ---- Bitwarden key derivation (PBKDF2 account) ----
export async function pbkdf2(password, salt, iterations) {
  const key = await subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
}
async function hmac(key, data) {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}
// HKDF-Expand with one block, as the clients stretch the master key.
const hkdfExpand32 = (prk, info) => hmac(prk, Buffer.concat([enc.encode(info), Buffer.from([1])]));

export async function encString(data, encKey, macKey) {
  const iv = rand(16);
  const k = await subtle.importKey("raw", encKey, "AES-CBC", false, ["encrypt"]);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, k, data));
  const mac = await hmac(macKey, Buffer.concat([iv, ct]));
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

export async function registerPayload(email, password, iterations = 600_000) {
  const masterKey = await pbkdf2(enc.encode(password), enc.encode(email), iterations);
  const masterPasswordHash = b64(await pbkdf2(masterKey, enc.encode(password), 1));
  const stretchedEnc = await hkdfExpand32(masterKey, "enc");
  const stretchedMac = await hkdfExpand32(masterKey, "mac");
  const userKey = rand(64);
  const protectedKey = await encString(userKey, stretchedEnc, stretchedMac);
  const pair = await subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
    true,
    ["encrypt", "decrypt"],
  );
  const publicKey = b64(await subtle.exportKey("spki", pair.publicKey));
  const privateDer = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
  const encryptedPrivateKey = await encString(privateDer, userKey.slice(0, 32), userKey.slice(32));
  return { masterPasswordHash, protectedKey, publicKey, encryptedPrivateKey, iterations, userKey };
}

// A new master password wraps the same user key, as the clients do on a password change.
export async function rewrapForPassword(email, password, userKey, iterations = 600_000) {
  const masterKey = await pbkdf2(enc.encode(password), enc.encode(email), iterations);
  const masterPasswordHash = b64(await pbkdf2(masterKey, enc.encode(password), 1));
  const key = await encString(userKey, await hkdfExpand32(masterKey, "enc"), await hkdfExpand32(masterKey, "mac"));
  return { masterPasswordHash, key };
}

// RFC 6238 TOTP for a base32 secret, at a given 30-second step.
export async function totp(secretB32, step) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const out = [];
  for (const ch of secretB32.replace(/=+$/, "")) {
    value = ((value << 5) | A.indexOf(ch)) & 0xffff;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const k = await subtle.importKey("raw", Uint8Array.from(out), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const h = new Uint8Array(await subtle.sign("HMAC", k, msg));
  const o = h[19] & 15;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1_000_000).padStart(6, "0");
}
export const step = () => Math.floor(Date.now() / 30000);

export const form = (fields) => ({
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(fields),
});
export const passwordGrant = (email, hash, extra = {}) => form({
  grant_type: "password", username: email, password: hash, scope: "api offline_access",
  client_id: "cli", device_identifier: extra.device ?? crypto.randomUUID(), device_name: "e2e", device_type: "8", ...extra.fields,
});

