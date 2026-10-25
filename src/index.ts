// A Bitwarden-compatible server for Cloudflare Workers + D1, for local testing.
//
// The API mirrors what Vaultwarden implements for current clients (web vault
// 2026.x, desktop, CLI): registration, password login with refresh tokens,
// sync, ciphers, folders, attachments, Send, TOTP, WebAuthn and email two-factor, master password
// and KDF changes, and website icons. Organizations, emergency access and push
// notifications are not implemented.
//
// All vault data arrives encrypted by the client; the server stores and
// returns it as opaque strings.

import { EmailMessage } from "cloudflare:email";
import { pbkdf2Sha256 } from "./pbkdf2";

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  FILES: R2Bucket; // attachments/<cipher>/<id>, sends/<send>/<file>
  JWT_SECRET: string;
  SIGNUPS_ALLOWED?: string;
  // Seconds an R2 file or upload slot must exist before the cleanup may remove it (default 1 h).
  CLEANUP_GRACE_SECONDS?: string;
  // WebAuthn relying party, e.g. https://vault.example.com; "auto" or unset: the request's origin.
  WEBAUTHN_ORIGIN?: string;
  // Email Routing: the send_email binding and the address mail comes from (unset = no email).
  MAIL?: SendEmail;
  MAIL_FROM?: string;
}

// Server-side hashing of the client's master password hash (Vaultwarden uses
// 600k; lower here so a login stays within Workers CPU limits).
const SERVER_PBKDF2_ITERATIONS = 100_000;
const ACCESS_TOKEN_SECONDS = 2 * 3600;
const REGISTER_TOKEN_SECONDS = 30 * 60;
const DEFAULT_KDF = { kdf: 0, iterations: 600_000, memory: null, parallelism: null };
// Clients gate features on this; keep it close to the Bitwarden server version.
const SERVER_VERSION = "2026.6.0";

// ---------------------------------------------------------------- helpers

class HttpError extends Error {
  constructor(public status: number, message: string, public extra: Record<string, unknown> = {}) {
    super(message);
  }
}

const nowIso = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();

function json(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function errorBody(message: string, extra: Record<string, unknown> = {}) {
  // The shape the Bitwarden server returns; clients read different fields.
  return {
    message,
    error: "",
    error_description: "",
    validationErrors: { "": [message] },
    errorModel: { message, object: "error" },
    ErrorModel: { Message: message, Object: "error" },
    exceptionMessage: null,
    exceptionStackTrace: null,
    innerExceptionMessage: null,
    object: "error",
    ...extra,
  };
}

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

const randomToken = (n = 48) => b64url(crypto.getRandomValues(new Uint8Array(n)));

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Workers' WebCrypto stops at 100000 PBKDF2 rounds; hashes imported from Vaultwarden
// (600000) are checked in JavaScript instead, and re-hashed at the next login.
const WEBCRYPTO_MAX_PBKDF2 = 100_000;

async function hashPassword(clientHash: string, salt: string, iterations = SERVER_PBKDF2_ITERATIONS): Promise<string> {
  if (iterations > WEBCRYPTO_MAX_PBKDF2) {
    return b64url(pbkdf2Sha256(new TextEncoder().encode(clientHash), fromB64url(salt), iterations));
  }
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(clientHash), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromB64url(salt), iterations },
    key,
    256,
  );
  return b64url(bits);
}

// ---------------------------------------------------------------- JWT (HS256)

async function hmacKey(secret: string) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
    "verify",
  ]);
}

async function signJwt(env: Env, claims: Record<string, unknown>): Promise<string> {
  const head = b64url(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64url(new TextEncoder().encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env.JWT_SECRET), new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(sig)}`;
}

async function verifyJwt(env: Env, token: string, iss: string): Promise<Record<string, any> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const ok = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(env.JWT_SECRET),
    fromB64url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!ok) return null;
  const claims = JSON.parse(new TextDecoder().decode(fromB64url(parts[1])));
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== iss || typeof claims.exp !== "number" || claims.exp < now || (claims.nbf ?? 0) > now + 60) return null;
  return claims;
}

// ---------------------------------------------------------------- data access

type User = {
  id: string;
  email: string;
  name: string | null;
  password_hash: string;
  password_salt: string;
  password_hint: string | null;
  akey: string;
  private_key: string | null;
  public_key: string | null;
  kdf: number;
  kdf_iterations: number;
  kdf_memory: number | null;
  kdf_parallelism: number | null;
  security_stamp: string;
  avatar_color: string | null;
  equivalent_domains: string;
  created_at: string;
  updated_at: string;
  revision_date: number;
  key_id: string | null;
  totp_recover: string | null;
  password_iterations: number;
};

type CipherRow = {
  id: string;
  user_id: string;
  folder_id: string | null;
  type: number;
  name: string | null;
  notes: string | null;
  key: string | null;
  reprompt: number;
  favorite: number;
  data: string;
  fields: string | null;
  password_history: string | null;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
  archived_at: string | null;
};

const userByEmail = (env: Env, email: string) =>
  env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email.trim().toLowerCase()).first<User>();

const touchUser = (env: Env, userId: string) =>
  env.DB.prepare("UPDATE users SET revision_date = ?, updated_at = ? WHERE id = ?").bind(Date.now(), nowIso(), userId).run();

// ---------------------------------------------------------------- JSON shapes

function kdfJson(u: User) {
  return { kdfType: u.kdf, iterations: u.kdf_iterations, memory: u.kdf_memory, parallelism: u.kdf_parallelism };
}

function accountKeysJson(u: User) {
  if (!u.private_key) return null;
  return {
    publicKeyEncryptionKeyPair: {
      wrappedPrivateKey: u.private_key,
      publicKey: u.public_key,
      signedPublicKey: null,
      object: "publicKeyEncryptionKeyPair",
    },
    securityState: null,
    signatureKeyPair: null,
    object: "privateKeys",
  };
}

function profileJson(u: User, twoFactorEnabled = false) {
  return {
    _status: 0,
    accountKeys: accountKeysJson(u),
    id: u.id,
    name: u.name,
    email: u.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    culture: "en-US",
    twoFactorEnabled,
    key: u.akey,
    privateKey: u.private_key,
    securityStamp: u.security_stamp,
    organizations: [],
    organizationsNew: [],
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: u.avatar_color,
    usesKeyConnector: false,
    creationDate: u.created_at,
    object: "profile",
  };
}

const TYPE_KEYS: Record<number, string> = {
  1: "login",
  2: "secureNote",
  3: "card",
  4: "identity",
  5: "sshKey",
  6: "bankAccount",
  7: "driversLicense",
  8: "passport",
};

function cipherJson(c: CipherRow, attachments: unknown[] | null = null) {
  const typeKey = TYPE_KEYS[c.type];
  const out: Record<string, unknown> = {
    object: "cipherDetails",
    id: c.id,
    type: c.type,
    creationDate: c.created_at,
    revisionDate: c.updated_at,
    deletedDate: c.deleted_at,
    archivedDate: c.archived_at,
    reprompt: c.reprompt === 1 ? 1 : 0,
    organizationId: null,
    key: c.key,
    attachments: attachments && attachments.length ? attachments : null,
    organizationUseTotp: true,
    collectionIds: [],
    name: c.name,
    notes: c.notes,
    fields: c.fields ? JSON.parse(c.fields) : null,
    passwordHistory: c.password_history ? JSON.parse(c.password_history) : null,
    folderId: c.folder_id,
    favorite: c.favorite === 1,
    edit: true,
    viewPassword: true,
    permissions: { delete: true, restore: true },
    login: null,
    secureNote: null,
    card: null,
    identity: null,
    sshKey: null,
    bankAccount: null,
    driversLicense: null,
    passport: null,
  };
  if (typeKey) {
    const data = JSON.parse(c.data);
    if (c.type === 1 && data && typeof data === "object") {
      // Upstream always has a `uri` alongside `uris`.
      data.uri = Array.isArray(data.uris) && data.uris.length ? data.uris[0].uri ?? null : null;
    }
    if (c.type === 2 && (!data || typeof data !== "object")) out.secureNote = { type: 0 };
    else out[typeKey] = data;
  }
  return out;
}

const folderJson = (f: { id: string; name: string; updated_at: string }) => ({
  id: f.id,
  revisionDate: f.updated_at,
  name: f.name,
  object: "folder",
});

const list = (data: unknown[], extra: Record<string, unknown> = {}) => ({
  data,
  object: "list",
  continuationToken: null,
  ...extra,
});

// ---------------------------------------------------------------- auth

async function requireUser(env: Env, req: Request): Promise<User> {
  const header = req.headers.get("Authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const claims = token ? await verifyJwt(env, token, "vault-worker|login") : null;
  if (!claims) throw new HttpError(401, "Unauthorized");
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(claims.sub).first<User>();
  // A changed security stamp (password change, "log out all") invalidates old tokens.
  if (!user || user.security_stamp !== claims.sstamp) throw new HttpError(401, "Unauthorized");
  return user;
}

async function issueTokens(env: Env, user: User, device: { id: string; type: number | null; refresh_token: string }, clientId: string) {
  const now = Math.floor(Date.now() / 1000);
  const access = await signJwt(env, {
    nbf: now,
    exp: now + ACCESS_TOKEN_SECONDS,
    iss: "vault-worker|login",
    sub: user.id,
    premium: true,
    name: user.name ?? "",
    email: user.email,
    email_verified: true,
    sstamp: user.security_stamp,
    device: device.id,
    devicetype: String(device.type ?? ""),
    client_id: clientId,
    scope: ["api", "offline_access"],
    amr: ["Application"],
  });
  return { access_token: access, expires_in: ACCESS_TOKEN_SECONDS, token_type: "Bearer", refresh_token: device.refresh_token };
}

async function connectToken(env: Env, req: Request): Promise<Response> {
  // Field names vary by client (two_factor_token, twoFactorToken, ...): match ignoring case and underscores.
  const fields = new Map<string, string>();
  for (const [k, v] of new URLSearchParams(await req.text())) fields.set(k.replace(/_/g, "").toLowerCase(), v);
  const get = (k: string) => fields.get(k.replace(/_/g, "").toLowerCase());
  const grant = get("grant_type");
  const invalid = (msg: string) =>
    json(errorBody(msg, { error: "invalid_grant", error_description: "invalid_username_or_password" }), 400);

  if (grant === "refresh_token") {
    const rt = get("refresh_token");
    const device = rt
      ? await env.DB.prepare("SELECT * FROM devices WHERE refresh_token = ?").bind(rt).first<any>()
      : null;
    if (!device) return json({ error: "invalid_grant" }, 400);
    const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(device.user_id).first<User>();
    if (!user) return json({ error: "invalid_grant" }, 400);
    await env.DB.prepare("UPDATE devices SET updated_at = ? WHERE id = ?").bind(nowIso(), device.id).run();
    const tokens = await issueTokens(env, user, device, get("client_id") ?? "");
    return json({ ...tokens, scope: "api offline_access" });
  }

  if (grant === "send_access") {
    // A short token for opening one Send; a password-protected Send needs password_hash_b64.
    const id = sendIdFromAccess(get("send_id") ?? "");
    const send = id ? await env.DB.prepare("SELECT * FROM sends WHERE id = ?").bind(id).first<SendRow>() : null;
    const sendError = (status: number, error: string, type: string) =>
      json({ error, send_access_error_type: type, error_description: type }, status);
    if (!send || !sendAccessible(send)) return sendError(400, "invalid_grant", "send_id_invalid");
    const pw = get("password_hash_b64");
    if (send.password_hash && !pw) return sendError(400, "invalid_request", "password_hash_b64_required");
    if (!(await sendPasswordOk(send, pw))) return sendError(400, "invalid_grant", "password_hash_b64_invalid");
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(env, { iss: "vault-worker|send", sub: send.id, nbf: now, exp: now + 120 });
    return json({ access_token: token, expires_in: 120, token_type: "Bearer", scope: "api.send.access" });
  }

  if (grant !== "password") return json(errorBody("Unsupported grant type", { error: "unsupported_grant_type" }), 400);

  const email = (get("username") ?? "").trim().toLowerCase();
  const clientHash = get("password") ?? "";
  const user = email ? await userByEmail(env, email) : null;
  if (!user || !timingSafeEqual(await hashPassword(clientHash, user.password_salt, user.password_iterations), user.password_hash)) {
    return invalid("Username or password is incorrect. Try again");
  }
  if (user.password_iterations !== SERVER_PBKDF2_ITERATIONS) {
    // The password just checked out: move the hash to this server's round count.
    const salt = randomToken(16);
    const hash = await hashPassword(clientHash, salt);
    await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ? WHERE id = ?")
      .bind(hash, salt, SERVER_PBKDF2_ITERATIONS, user.id).run();
    Object.assign(user, { password_hash: hash, password_salt: salt, password_iterations: SERVER_PBKDF2_ITERATIONS });
  }

  const deviceId = get("device_identifier") || uuid();
  const deviceType = Number(get("device_type") ?? "") || null;
  const known = await env.DB.prepare("SELECT * FROM devices WHERE id = ?").bind(deviceId).first<any>();
  // A "remember me" token only counts on the device (and account) it was issued to.
  let remember: string | null = known && known.user_id === user.id ? known.twofactor_remember : null;
  let newRemember: string | null = null;

  const totp = await totpRow(env, user.id);
  const wkeys = await webauthnKeys(env, user.id);
  const mail2fa = mailEnabled(env) ? await emailTwoFactor(env, user.id) : null;
  if (totp || wkeys.length || mail2fa) {
    const provider = Number(get("two_factor_provider") ?? "");
    const code = (get("two_factor_token") ?? "").trim();
    const challenge = async (msg: string) => {
      const providers: Record<string, unknown> = {};
      if (totp) providers[String(TF_AUTHENTICATOR)] = null;
      if (mail2fa) providers[String(TF_EMAIL)] = { Email: obscureEmail(mail2fa.email) };
      if (wkeys.length) providers[String(TF_WEBAUTHN)] = await webauthnLoginOptions(env, req, user.id, wkeys);
      return json({
        ...errorBody(msg),
        error: "invalid_grant",
        error_description: "Two factor required.",
        TwoFactorProviders: Object.keys(providers),
        TwoFactorProviders2: providers,
        MasterPasswordPolicy: null,
      }, 400);
    };
    if (!code) return challenge("Two factor required.");
    if (provider === TF_REMEMBER) {
      if (!remember || !timingSafeEqual(code, remember)) return challenge("Two factor remember token expired");
    } else if (provider === TF_RECOVERY) {
      // The recovery code turns 2FA off, like the Bitwarden server.
      if (!user.totp_recover || !timingSafeEqual(code.replace(/\s/g, "").toUpperCase(), user.totp_recover)) {
        return invalid("Recovery code is incorrect. Try again");
      }
      await env.DB.batch([
        env.DB.prepare("DELETE FROM twofactors WHERE user_id = ?").bind(user.id),
        env.DB.prepare("UPDATE devices SET twofactor_remember = NULL WHERE user_id = ?").bind(user.id),
        env.DB.prepare("UPDATE users SET totp_recover = NULL WHERE id = ?").bind(user.id),
      ]);
      remember = null;
      await notify(env, user, "Two-step login turned off with the recovery code",
        `The recovery code was used to log in, which turned two-step login off for your vault.\n\n${clientDescription(req, get("device_name"))}`);
    } else if (mail2fa && provider === TF_EMAIL) {
      if (!(await checkEmailCode(env, user.id, TF_EMAIL, code, true))) return invalid("Invalid or expired email code");
    } else if (totp && (provider === TF_AUTHENTICATOR || Number.isNaN(provider))) {
      if (!(await checkTotp(env, user.id, totp.data, code))) return invalid("Invalid TOTP code");
    } else if (wkeys.length && provider === TF_WEBAUTHN) {
      if (!(await verifyWebauthnLogin(env, req, user.id, code))) return invalid("Security key verification failed");
    } else {
      return challenge("Invalid two factor provider");
    }
    if (get("two_factor_remember") === "1" && provider !== TF_RECOVERY) newRemember = randomToken(32);
  }

  if (!known || known.user_id !== user.id) {
    await notify(env, user, "New login to your vault", `Your vault was just opened from a device it hasn't seen before.\n\n${clientDescription(req, get("device_name"))}`);
  }

  // One row per device identifier; a new login on the same device rotates its refresh token.
  const refresh = randomToken();
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO devices (id, user_id, name, type, refresh_token, twofactor_remember, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, name = excluded.name, type = excluded.type,
       refresh_token = excluded.refresh_token, twofactor_remember = excluded.twofactor_remember, updated_at = excluded.updated_at`,
  )
    .bind(deviceId, user.id, get("device_name") ?? null, deviceType, refresh, newRemember ?? remember, now, now)
    .run();

  const tokens = await issueTokens(env, user, { id: deviceId, type: deviceType, refresh_token: refresh }, get("client_id") ?? "");
  const unlock = {
    Kdf: { KdfType: user.kdf, Iterations: user.kdf_iterations, Memory: user.kdf_memory, Parallelism: user.kdf_parallelism },
    MasterKeyEncryptedUserKey: user.akey,
    MasterKeyWrappedUserKey: user.akey,
    Salt: user.email,
  };
  return json({
    ...tokens,
    Key: user.akey,
    PrivateKey: user.private_key,
    Kdf: user.kdf,
    KdfIterations: user.kdf_iterations,
    KdfMemory: user.kdf_memory,
    KdfParallelism: user.kdf_parallelism,
    ResetMasterPassword: false,
    ForcePasswordReset: false,
    MasterPasswordPolicy: null,
    scope: "api offline_access",
    unofficialServer: true,
    AccountKeys: accountKeysJson(user),
    UserDecryptionOptions: { HasMasterPassword: true, MasterPasswordUnlock: unlock, Object: "userDecryptionOptions" },
    ...(newRemember ? { TwoFactorToken: newRemember } : {}),
  });
}

// ---------------------------------------------------------------- registration

async function prelogin(env: Env, req: Request): Promise<Response> {
  const body = await req.json<any>().catch(() => ({}));
  const user = body.email ? await userByEmail(env, String(body.email)) : null;
  const k = user
    ? { kdf: user.kdf, iterations: user.kdf_iterations, memory: user.kdf_memory, parallelism: user.kdf_parallelism }
    : DEFAULT_KDF;
  return json({
    kdf: k.kdf,
    kdfIterations: k.iterations,
    kdfMemory: k.memory,
    kdfParallelism: k.parallelism,
    kdfSettings: { kdfType: k.kdf, iterations: k.iterations, memory: k.memory, parallelism: k.parallelism },
    salt: null,
  });
}

async function sendVerificationEmail(env: Env, req: Request): Promise<Response> {
  if (env.SIGNUPS_ALLOWED !== "true") throw new HttpError(400, "Registration not allowed");
  const body = await req.json<any>();
  const email = String(body.email ?? "").trim().toLowerCase();
  if (!email.includes("@")) throw new HttpError(400, "Invalid email");
  if (await userByEmail(env, email)) throw new HttpError(400, "Registration not allowed or user already exists");
  // No mail here: like Vaultwarden without SMTP, hand the token straight back.
  const now = Math.floor(Date.now() / 1000);
  const token = await signJwt(env, { iss: "vault-worker|register", sub: email, name: body.name ?? null, nbf: now, exp: now + REGISTER_TOKEN_SECONDS });
  const wantsJson = (req.headers.get("Accept") ?? "").includes("application/json");
  return wantsJson ? json(token) : new Response(token, { headers: { "Content-Type": "text/plain" } });
}

async function registerFinish(env: Env, req: Request, requireToken: boolean): Promise<Response> {
  if (env.SIGNUPS_ALLOWED !== "true") throw new HttpError(400, "Registration not allowed");
  const b = await req.json<any>();
  const email = String(b.email ?? "").trim().toLowerCase();

  let name: string | null = b.name ?? null;
  if (requireToken || b.emailVerificationToken) {
    const claims = await verifyJwt(env, String(b.emailVerificationToken ?? ""), "vault-worker|register");
    if (!claims || claims.sub !== email) throw new HttpError(400, "Invalid or expired registration token");
    name = name ?? claims.name ?? null;
  }

  // Two request shapes: the older flat one, and the 2025+ one with separate
  // authentication and unlock data (which must agree on KDF and salt).
  let hash: string, key: string, kdf: any;
  if (b.masterPasswordAuthentication && b.masterPasswordUnlock) {
    const auth = b.masterPasswordAuthentication;
    const unlock = b.masterPasswordUnlock;
    hash = auth.masterPasswordAuthenticationHash ?? auth.hash;
    key = unlock.masterKeyWrappedUserKey ?? unlock.key;
    kdf = auth.kdf;
    const k2 = unlock.kdf;
    const same =
      kdf && k2 && kdf.kdfType === k2.kdfType && kdf.iterations === k2.iterations &&
      (kdf.memory ?? null) === (k2.memory ?? null) && (kdf.parallelism ?? null) === (k2.parallelism ?? null);
    if (!same || String(auth.salt).toLowerCase() !== email || String(unlock.salt).toLowerCase() !== email) {
      throw new HttpError(422, "KDF settings and salt must match the email");
    }
    kdf = { kdf: kdf.kdfType, iterations: kdf.iterations, memory: kdf.memory ?? null, parallelism: kdf.parallelism ?? null };
  } else {
    hash = b.masterPasswordHash;
    key = b.userSymmetricKey ?? b.key;
    kdf = { kdf: b.kdf ?? 0, iterations: b.kdfIterations ?? 600_000, memory: b.kdfMemory ?? null, parallelism: b.kdfParallelism ?? null };
  }
  if (!email.includes("@") || !hash || !key) throw new HttpError(400, "Missing registration data");
  if (kdf.kdf === 0 && kdf.iterations < 100_000) throw new HttpError(400, "PBKDF2 iterations must be at least 100000");
  if (await userByEmail(env, email)) throw new HttpError(400, "User already exists");

  const keys = b.userAsymmetricKeys ?? b.keys ?? null;
  const salt = randomToken(16);
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO users (id, email, name, password_hash, password_salt, password_hint, akey, private_key, public_key,
       kdf, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, created_at, updated_at, revision_date)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      uuid(), email, name, await hashPassword(hash, salt), salt, b.masterPasswordHint ?? null, key,
      keys?.encryptedPrivateKey ?? null, keys?.publicKey ?? null,
      kdf.kdf, kdf.iterations, kdf.memory, kdf.parallelism, uuid(), now, now, Date.now(),
    )
    .run();
  return json({ object: "register", captchaBypassToken: "" });
}

// ---------------------------------------------------------------- ciphers

function cipherFields(body: any) {
  const c = body.cipher ?? body; // POST /ciphers/create wraps it
  const type = Number(c.type);
  const typeKey = TYPE_KEYS[type];
  if (!typeKey) throw new HttpError(400, "Invalid cipher type");
  return {
    type,
    folder_id: c.folderId ?? null,
    name: c.name ?? null,
    notes: c.notes ?? null,
    key: c.key ?? null,
    reprompt: Number(c.reprompt ?? 0) === 1 ? 1 : 0,
    favorite: c.favorite ? 1 : 0,
    data: JSON.stringify(c[typeKey] ?? null),
    fields: c.fields ? JSON.stringify(c.fields) : null,
    password_history: c.passwordHistory ? JSON.stringify(c.passwordHistory) : null,
  };
}

async function ownedCipher(env: Env, user: User, id: string): Promise<CipherRow> {
  const c = await env.DB.prepare("SELECT * FROM ciphers WHERE id = ? AND user_id = ?").bind(id, user.id).first<CipherRow>();
  if (!c) throw new HttpError(404, "Cipher doesn't exist");
  return c;
}

async function checkFolder(env: Env, user: User, folderId: string | null) {
  if (!folderId) return;
  const f = await env.DB.prepare("SELECT id FROM folders WHERE id = ? AND user_id = ?").bind(folderId, user.id).first();
  if (!f) throw new HttpError(400, "Invalid folder");
}

async function createCipher(env: Env, user: User, body: any): Promise<CipherRow> {
  const f = cipherFields(body);
  await checkFolder(env, user, f.folder_id);
  const id = uuid();
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO ciphers (id, user_id, folder_id, type, name, notes, key, reprompt, favorite, data, fields, password_history, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(id, user.id, f.folder_id, f.type, f.name, f.notes, f.key, f.reprompt, f.favorite, f.data, f.fields, f.password_history, now, now)
    .run();
  await touchUser(env, user.id);
  return ownedCipher(env, user, id);
}

async function updateCipher(env: Env, user: User, id: string, body: any): Promise<CipherRow> {
  await ownedCipher(env, user, id);
  const f = cipherFields(body);
  await checkFolder(env, user, f.folder_id);
  await env.DB.prepare(
    `UPDATE ciphers SET folder_id = ?, type = ?, name = ?, notes = ?, key = ?, reprompt = ?, favorite = ?, data = ?,
       fields = ?, password_history = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
  )
    .bind(f.folder_id, f.type, f.name, f.notes, f.key, f.reprompt, f.favorite, f.data, f.fields, f.password_history, nowIso(), id, user.id)
    .run();
  await touchUser(env, user.id);
  return ownedCipher(env, user, id);
}

async function setDeleted(env: Env, user: User, ids: string[], deleted: boolean) {
  const now = nowIso();
  for (const id of ids) {
    await env.DB.prepare("UPDATE ciphers SET deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ?")
      .bind(deleted ? now : null, now, id, user.id)
      .run();
  }
  await touchUser(env, user.id);
}

async function hardDelete(env: Env, user: User, ids: string[]) {
  await deleteAttachmentsOf(env, user.id, ids);
  for (const id of ids) await env.DB.prepare("DELETE FROM ciphers WHERE id = ? AND user_id = ?").bind(id, user.id).run();
  await touchUser(env, user.id);
}

async function setArchived(env: Env, user: User, ids: string[], archived: boolean) {
  const now = nowIso();
  for (const id of ids) {
    await env.DB.prepare("UPDATE ciphers SET archived_at = ?, updated_at = ? WHERE id = ? AND user_id = ?")
      .bind(archived ? now : null, now, id, user.id)
      .run();
  }
  await touchUser(env, user.id);
}

async function ciphersByIds(env: Env, req: Request, user: User, ids: string[]) {
  const rows = [];
  for (const id of ids) rows.push(await ownedCipher(env, user, id));
  return renderCiphers(env, req, rows);
}

async function importVault(env: Env, user: User, body: any) {
  // Folders first, then each cipher placed via folderRelationships (cipher index -> folder index).
  const folderIds: string[] = [];
  const now = nowIso();
  for (const f of body.folders ?? []) {
    const id = uuid();
    await env.DB.prepare("INSERT INTO folders (id, user_id, name, updated_at) VALUES (?, ?, ?, ?)").bind(id, user.id, f.name, now).run();
    folderIds.push(id);
  }
  const folderOf = new Map<number, string>();
  for (const r of body.folderRelationships ?? []) folderOf.set(Number(r.key), folderIds[Number(r.value)]);
  const ciphers: any[] = body.ciphers ?? [];
  for (let i = 0; i < ciphers.length; i++) {
    await createCipher(env, user, { ...ciphers[i], folderId: folderOf.get(i) ?? null });
  }
  await touchUser(env, user.id);
}

// ---------------------------------------------------------------- attachments

type AttachmentRow = { id: string; cipher_id: string; user_id: string; file_name: string; file_size: number; akey: string | null };
const FILE_URL_SECONDS = 5 * 60;
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // the Workers request body limit

function displaySize(n: number): string {
  const units = ["Bytes", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${i ? Number(v.toFixed(2)) : v} ${units[i]}`;
}

// Short-lived signed links, so a download needs no Authorization header.
async function fileUrl(env: Env, req: Request, path: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const t = await signJwt(env, { iss: "vault-worker|file", sub: path, nbf: now, exp: now + FILE_URL_SECONDS });
  return `${new URL(req.url).origin}/${path}?token=${t}`;
}

async function attachmentJson(env: Env, req: Request, a: AttachmentRow) {
  return {
    id: a.id,
    url: await fileUrl(env, req, `attachments/${a.cipher_id}/${a.id}`),
    fileName: a.file_name,
    size: String(a.file_size),
    sizeName: displaySize(a.file_size),
    key: a.akey,
    object: "attachment",
  };
}

async function renderCiphers(env: Env, req: Request, rows: CipherRow[]) {
  if (!rows.length) return [];
  const { results } = await env.DB.prepare("SELECT * FROM attachments WHERE user_id = ? AND uploaded = 1").bind(rows[0].user_id).all<AttachmentRow>();
  const byCipher = new Map<string, AttachmentRow[]>();
  for (const a of results) byCipher.set(a.cipher_id, [...(byCipher.get(a.cipher_id) ?? []), a]);
  return Promise.all(rows.map(async (c) =>
    cipherJson(c, await Promise.all((byCipher.get(c.id) ?? []).map((a) => attachmentJson(env, req, a))))));
}

const renderOne = async (env: Env, req: Request, row: CipherRow) => (await renderCiphers(env, req, [row]))[0];

// Removes attachment rows and their R2 objects: for the given ciphers, or all of the user's.
async function deleteAttachmentsOf(env: Env, userId: string, cipherIds: string[] | null) {
  const rows: AttachmentRow[] = [];
  if (cipherIds) {
    for (const id of cipherIds) {
      rows.push(...(await env.DB.prepare("SELECT * FROM attachments WHERE cipher_id = ? AND user_id = ?").bind(id, userId).all<AttachmentRow>()).results);
    }
  } else {
    rows.push(...(await env.DB.prepare("SELECT * FROM attachments WHERE user_id = ?").bind(userId).all<AttachmentRow>()).results);
  }
  for (const a of rows) {
    await env.FILES.delete(`attachments/${a.cipher_id}/${a.id}`);
    await env.DB.prepare("DELETE FROM attachments WHERE id = ?").bind(a.id).run();
  }
}

// The file part ("data") of a multipart upload, checked against the announced size.
async function uploadedFile(req: Request, expectedSize?: number): Promise<{ file: File; key: string | null }> {
  const form = await req.formData();
  const file = form.get("data");
  if (!file || typeof file === "string") throw new HttpError(400, "No file uploaded");
  if (file.size > MAX_UPLOAD_BYTES) throw new HttpError(400, "File too large");
  // Encryption adds a little; Vaultwarden allows the same leeway.
  if (expectedSize !== undefined && Math.abs(file.size - expectedSize) > 1024) {
    throw new HttpError(400, "Uploaded file size doesn't match the announced size");
  }
  const key = form.get("key");
  return { file, key: typeof key === "string" ? key : null };
}

// ---------------------------------------------------------------- two-factor (TOTP)

const TF_AUTHENTICATOR = 0;
const TF_REMEMBER = 5;
const TF_RECOVERY = 8;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = ((value << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(s: string): Uint8Array | null {
  const clean = s.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const i = B32.indexOf(ch);
    if (i < 0) return null;
    value = ((value << 5) | i) & 0xffff;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

async function totpAt(secret: Uint8Array, step: number): Promise<string> {
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(step));
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const o = h[19] & 15;
  const code = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1_000_000;
  return String(code).padStart(6, "0");
}

// Accepts the current 30 s step and one either side; a used step can't be replayed.
async function checkTotp(env: Env, userId: string, secretB32: string, code: string): Promise<boolean> {
  const secret = base32Decode(secretB32);
  if (!secret || !/^\d{6}$/.test(code)) return false;
  const row = await env.DB.prepare("SELECT last_used FROM twofactors WHERE user_id = ? AND type = ?")
    .bind(userId, TF_AUTHENTICATOR).first<{ last_used: number }>();
  const lastUsed = row?.last_used ?? 0;
  const now = Math.floor(Date.now() / 30000);
  for (const step of [now - 1, now, now + 1]) {
    if (step > lastUsed && timingSafeEqual(await totpAt(secret, step), code)) {
      await env.DB.prepare(
        `INSERT INTO twofactors (user_id, type, data, enabled, last_used) VALUES (?, ?, ?, 0, ?)
         ON CONFLICT(user_id, type) DO UPDATE SET last_used = excluded.last_used`,
      ).bind(userId, TF_AUTHENTICATOR, secretB32, step).run();
      return true;
    }
  }
  return false;
}

const totpRow = (env: Env, userId: string) =>
  env.DB.prepare("SELECT * FROM twofactors WHERE user_id = ? AND type = ? AND enabled = 1")
    .bind(userId, TF_AUTHENTICATOR).first<{ data: string }>();

const hasTwoFactor = async (env: Env, userId: string) =>
  !!(await env.DB.prepare("SELECT 1 FROM twofactors WHERE user_id = ? AND type IN (0, 1, 7) AND enabled = 1").bind(userId).first());

// Sensitive actions confirm the master password ("masterPasswordHash").
async function verifySecret(u: User, body: any) {
  const h = String(body?.masterPasswordHash ?? "");
  if (!h || !timingSafeEqual(await hashPassword(h, u.password_salt, u.password_iterations), u.password_hash)) throw new HttpError(400, "Invalid password");
}

// Binds the secret shown on the setup screen to this user for a few minutes.
async function authenticatorToken(env: Env, userId: string, key: string) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(env, { iss: "vault-worker|2fa-setup", sub: userId, key, nbf: now, exp: now + 15 * 60 });
}

async function checkAuthenticatorToken(env: Env, userId: string, key: string, token: string) {
  const c = await verifyJwt(env, String(token ?? ""), "vault-worker|2fa-setup");
  if (!c || c.sub !== userId || c.key !== key) throw new HttpError(400, "Invalid or expired verification; enter your master password again");
}

// ---------------------------------------------------------------- two-factor (WebAuthn)
//
// Security keys and passkeys as a second factor, verified here with WebCrypto:
// ES256 (P-256), RS256 and EdDSA (Ed25519). Attestation isn't checked ("none"),
// as with Vaultwarden. Registrations live in `twofactors` (type 7) as JSON;
// pending challenges in types 1003 (register) and 1004 (login).

const TF_WEBAUTHN = 7;
const TF_WEBAUTHN_REGISTER = 1003;
const TF_WEBAUTHN_LOGIN = 1004;
const WEBAUTHN_CHALLENGE_SECONDS = 5 * 60;

type WebauthnKey = {
  id: number;            // the slot number the client picked (1..5)
  name: string;
  credentialId: string;  // base64url
  alg: number;           // COSE: -7 ES256, -257 RS256, -8 EdDSA
  jwk: JsonWebKey;
  counter: number;
  backupEligible?: boolean;
  backupState?: boolean;
  migrated?: boolean;    // came over from U2F in Vaultwarden
};

// Minimal CBOR decoder: what attestation objects and COSE keys use.
function cborDecode(buf: Uint8Array): unknown {
  let pos = 0;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const need = (n: number) => { if (pos + n > buf.length) throw new HttpError(400, "Truncated CBOR"); };
  const length = (info: number): number => {
    if (info < 24) return info;
    if (info === 24) { need(1); return buf[pos++]; }
    if (info === 25) { need(2); const v = view.getUint16(pos); pos += 2; return v; }
    if (info === 26) { need(4); const v = view.getUint32(pos); pos += 4; return v; }
    if (info === 27) { need(8); const v = Number(view.getBigUint64(pos)); pos += 8; return v; }
    throw new HttpError(400, "Unsupported CBOR length");
  };
  const item = (depth: number): unknown => {
    if (depth > 16) throw new HttpError(400, "CBOR nested too deeply");
    need(1);
    const b = buf[pos++];
    const major = b >> 5, info = b & 31;
    switch (major) {
      case 0: return length(info);
      case 1: return -1 - length(info);
      case 2: { const n = length(info); need(n); const v = buf.slice(pos, pos + n); pos += n; return v; }
      case 3: { const n = length(info); need(n); const v = new TextDecoder().decode(buf.subarray(pos, pos + n)); pos += n; return v; }
      case 4: { const n = length(info); const a = []; for (let i = 0; i < n; i++) a.push(item(depth + 1)); return a; }
      case 5: { const n = length(info); const m = new Map<unknown, unknown>(); for (let i = 0; i < n; i++) { const k = item(depth + 1); m.set(k, item(depth + 1)); } return m; }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22 || info === 23) return null;
        throw new HttpError(400, "Unsupported CBOR value");
      default: throw new HttpError(400, "Unsupported CBOR type");
    }
  };
  const v = item(0);
  (cborDecode as any).consumed = pos;
  return v;
}

// A COSE public key as a JWK WebCrypto can import.
function coseToJwk(m: Map<unknown, unknown>): { alg: number; jwk: JsonWebKey } {
  const kty = m.get(1), alg = Number(m.get(3));
  const bytes = (k: number) => { const v = m.get(k); if (!(v instanceof Uint8Array)) throw new HttpError(400, "Malformed public key"); return b64url(v); };
  if (kty === 2 && alg === -7 && m.get(-1) === 1) return { alg, jwk: { kty: "EC", crv: "P-256", x: bytes(-2), y: bytes(-3) } };
  if (kty === 3 && alg === -257) return { alg, jwk: { kty: "RSA", n: bytes(-1), e: bytes(-2) } };
  if (kty === 1 && alg === -8 && m.get(-1) === 6) return { alg, jwk: { kty: "OKP", crv: "Ed25519", x: bytes(-2) } };
  throw new HttpError(400, "Unsupported key type; use ES256, RS256 or EdDSA");
}

type AuthData = { rpIdHash: Uint8Array; flags: number; counter: number; credentialId?: Uint8Array; publicKey?: Map<unknown, unknown> };
const FLAG_UP = 0x01, FLAG_AT = 0x40, FLAG_BE = 0x08, FLAG_BS = 0x10;

function parseAuthData(d: Uint8Array): AuthData {
  if (d.length < 37) throw new HttpError(400, "Authenticator data too short");
  const out: AuthData = { rpIdHash: d.slice(0, 32), flags: d[32], counter: new DataView(d.buffer, d.byteOffset).getUint32(33) };
  if (out.flags & FLAG_AT) {
    if (d.length < 55) throw new HttpError(400, "Attested credential data too short");
    const len = (d[53] << 8) | d[54];
    out.credentialId = d.slice(55, 55 + len);
    out.publicKey = cborDecode(d.slice(55 + len)) as Map<unknown, unknown>;
  }
  return out;
}

const sha256 = async (data: Uint8Array | string) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", typeof data === "string" ? new TextEncoder().encode(data) : data));

function sameBytes(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// The relying party is WEBAUTHN_ORIGIN, or with "auto" (local dev) the request's own origin.
function webauthnOrigin(env: Env, req: Request) {
  const pinned = env.WEBAUTHN_ORIGIN && env.WEBAUTHN_ORIGIN !== "auto" ? env.WEBAUTHN_ORIGIN : null;
  const origin = pinned ?? new URL(req.url).origin;
  return { origin, rpId: new URL(origin).hostname };
}

// clientDataJSON: right ceremony, our challenge, our origin.
function checkClientData(raw: Uint8Array, type: string, challenge: string, origin: string) {
  let c: any;
  try { c = JSON.parse(new TextDecoder().decode(raw)); } catch { throw new HttpError(400, "Malformed client data"); }
  if (c.type !== type) throw new HttpError(400, "Wrong WebAuthn ceremony");
  if (typeof c.challenge !== "string" || !timingSafeEqual(c.challenge.replace(/=+$/, ""), challenge)) throw new HttpError(400, "WebAuthn challenge mismatch");
  if (c.origin !== origin) throw new HttpError(400, `WebAuthn origin mismatch (${c.origin})`);
}

// ECDSA signatures arrive DER-encoded; WebCrypto wants r||s.
function derToRaw(der: Uint8Array): Uint8Array {
  let p = 2;
  if (der[0] !== 0x30) throw new HttpError(400, "Malformed signature");
  if (der[1] & 0x80) p += der[1] & 0x7f;
  const int = () => {
    if (der[p++] !== 0x02) throw new HttpError(400, "Malformed signature");
    let len = der[p++];
    let v = der.slice(p, p + len);
    p += len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = int(), s = int();
  return Uint8Array.from([...r, ...s]);
}

async function verifySignature(k: WebauthnKey, data: Uint8Array, sig: Uint8Array): Promise<boolean> {
  if (k.alg === -7) {
    const key = await crypto.subtle.importKey("jwk", k.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(sig), data);
  }
  if (k.alg === -257) {
    const key = await crypto.subtle.importKey("jwk", k.jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
  }
  if (k.alg === -8) {
    const key = await crypto.subtle.importKey("jwk", k.jwk, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify("Ed25519", key, sig, data);
  }
  return false;
}

async function webauthnKeys(env: Env, userId: string): Promise<WebauthnKey[]> {
  const row = await env.DB.prepare("SELECT data FROM twofactors WHERE user_id = ? AND type = ? AND enabled = 1")
    .bind(userId, TF_WEBAUTHN).first<{ data: string }>();
  return row ? JSON.parse(row.data) : [];
}

async function saveWebauthnKeys(env: Env, userId: string, keys: WebauthnKey[]) {
  if (!keys.length) {
    await env.DB.prepare("DELETE FROM twofactors WHERE user_id = ? AND type = ?").bind(userId, TF_WEBAUTHN).run();
    return;
  }
  await env.DB.prepare(
    `INSERT INTO twofactors (user_id, type, data, enabled, last_used) VALUES (?, ?, ?, 1, 0)
     ON CONFLICT(user_id, type) DO UPDATE SET data = excluded.data, enabled = 1`,
  ).bind(userId, TF_WEBAUTHN, JSON.stringify(keys)).run();
}

async function storeChallenge(env: Env, userId: string, type: number, challenge: string) {
  const data = JSON.stringify({ challenge, expires: Date.now() + WEBAUTHN_CHALLENGE_SECONDS * 1000 });
  await env.DB.prepare(
    `INSERT INTO twofactors (user_id, type, data, enabled, last_used) VALUES (?, ?, ?, 0, 0)
     ON CONFLICT(user_id, type) DO UPDATE SET data = excluded.data`,
  ).bind(userId, type, data).run();
}

// One use only: the challenge is deleted as it's read.
async function takeChallenge(env: Env, userId: string, type: number): Promise<string> {
  const row = await env.DB.prepare("SELECT data FROM twofactors WHERE user_id = ? AND type = ?").bind(userId, type).first<{ data: string }>();
  await env.DB.prepare("DELETE FROM twofactors WHERE user_id = ? AND type = ?").bind(userId, type).run();
  const c = row ? JSON.parse(row.data) : null;
  if (!c || c.expires < Date.now()) throw new HttpError(400, "WebAuthn challenge expired; try again");
  return c.challenge;
}

const webauthnKeysJson = (keys: WebauthnKey[]) => keys.map((k) => ({ id: k.id, name: k.name, migrated: !!k.migrated }));

function webauthnState(keys: WebauthnKey[]) {
  const s = { enabled: keys.length > 0, keys: webauthnKeysJson(keys), object: "twoFactorWebAuthn" };
  return { ...s, webAuthn: { enabled: s.enabled, keys: s.keys } };
}

// Proof of the master password for the settings screen, bound to the current key list.
async function webauthnToken(env: Env, userId: string, keys: WebauthnKey[]) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(env, { iss: "vault-worker|webauthn-setup", sub: userId, keys: keys.map((k) => k.id).sort(), nbf: now, exp: now + 15 * 60 });
}

async function checkWebauthnToken(env: Env, userId: string, keys: WebauthnKey[], token: string) {
  const c = await verifyJwt(env, String(token ?? ""), "vault-worker|webauthn-setup");
  const ids = keys.map((k) => k.id).sort();
  if (!c || c.sub !== userId || JSON.stringify(c.keys) !== JSON.stringify(ids)) {
    throw new HttpError(400, "Invalid or expired verification; enter your master password again");
  }
}

const b64any = (s: unknown): Uint8Array => {
  if (typeof s !== "string") throw new HttpError(400, "Missing WebAuthn field");
  return fromB64url(s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
};

// Registration ceremony result -> a stored key.
async function finishRegistration(env: Env, req: Request, userId: string, body: any, existing: WebauthnKey[]): Promise<WebauthnKey> {
  const { origin, rpId } = webauthnOrigin(env, req);
  const challenge = await takeChallenge(env, userId, TF_WEBAUTHN_REGISTER);
  const r = body.deviceResponse ?? {};
  const resp = r.response ?? {};
  checkClientData(b64any(resp.clientDataJson ?? resp.clientDataJSON), "webauthn.create", challenge, origin);
  const att = cborDecode(b64any(resp.attestationObject ?? resp.AttestationObject)) as Map<unknown, unknown>;
  const authData = att instanceof Map ? att.get("authData") : null;
  if (!(authData instanceof Uint8Array)) throw new HttpError(400, "Malformed attestation");
  const ad = parseAuthData(authData);
  if (!sameBytes(ad.rpIdHash, await sha256(rpId))) throw new HttpError(400, "Key registered for another site");
  if (!(ad.flags & FLAG_UP)) throw new HttpError(400, "User presence missing");
  if (!ad.credentialId || !ad.publicKey) throw new HttpError(400, "No credential in attestation");
  const credentialId = b64url(ad.credentialId);
  if (existing.some((k) => k.credentialId === credentialId)) throw new HttpError(400, "This key is already registered");
  const { alg, jwk } = coseToJwk(ad.publicKey);
  const id = Number(body.id);
  if (!Number.isInteger(id) || id < 1 || id > 20) throw new HttpError(400, "Invalid key slot");
  return {
    id, name: String(body.name ?? "Key").slice(0, 100), credentialId, alg, jwk, counter: ad.counter,
    backupEligible: !!(ad.flags & FLAG_BE), backupState: !!(ad.flags & FLAG_BS),
  };
}

// Options for the login ceremony; the challenge is kept for the answer.
async function webauthnLoginOptions(env: Env, req: Request, userId: string, keys: WebauthnKey[]) {
  const { origin, rpId } = webauthnOrigin(env, req);
  const challenge = randomToken(32);
  await storeChallenge(env, userId, TF_WEBAUTHN_LOGIN, challenge);
  return {
    challenge,
    timeout: 60000,
    rpId,
    allowCredentials: keys.map((k) => ({ type: "public-key", id: k.credentialId })),
    userVerification: "discouraged",
    extensions: { appid: `${origin}/app-id.json` },
    status: "ok",
    errorMessage: "",
  };
}

// The login answer (two_factor_token is the PublicKeyCredential as JSON).
async function verifyWebauthnLogin(env: Env, req: Request, userId: string, token: string): Promise<boolean> {
  const { origin, rpId } = webauthnOrigin(env, req);
  let cred: any;
  try { cred = JSON.parse(token); } catch { return false; }
  const challenge = await takeChallenge(env, userId, TF_WEBAUTHN_LOGIN).catch(() => null);
  if (!challenge) return false;
  const keys = await webauthnKeys(env, userId);
  const rawId = b64url(b64any(cred.rawId ?? cred.id));
  const key = keys.find((k) => timingSafeEqual(k.credentialId, rawId));
  if (!key) return false;
  const resp = cred.response ?? {};
  const clientData = b64any(resp.clientDataJson ?? resp.clientDataJSON);
  try { checkClientData(clientData, "webauthn.get", challenge, origin); } catch { return false; }
  const authData = b64any(resp.authenticatorData);
  const ad = parseAuthData(authData);
  // Keys migrated from U2F were registered under the app-id URL.
  const rpOk = sameBytes(ad.rpIdHash, await sha256(rpId)) || sameBytes(ad.rpIdHash, await sha256(`${origin}/app-id.json`));
  if (!rpOk || !(ad.flags & FLAG_UP)) return false;
  const signed = new Uint8Array([...authData, ...(await sha256(clientData))]);
  if (!(await verifySignature(key, signed, b64any(resp.signature)))) return false;
  // A counter that doesn't move forward means a cloned authenticator; 0/0 is what passkeys send.
  if ((ad.counter !== 0 || key.counter !== 0) && ad.counter <= key.counter) return false;
  key.counter = ad.counter;
  key.backupEligible = key.backupEligible || !!(ad.flags & FLAG_BE);
  key.backupState = !!(ad.flags & FLAG_BS);
  await saveWebauthnKeys(env, userId, keys);
  return true;
}

// ---------------------------------------------------------------- email (Cloudflare Email Routing)
//
// Sent through the Worker's send_email binding, from MAIL_FROM (an address on a domain with
// Email Routing). Cloudflare only delivers to verified destination addresses, which suits a
// personal vault: 2FA codes, new-device alerts, the password hint and security notices.

const TF_EMAIL = 1;
const TF_EMAIL_SETUP = 1002;
const EMAIL_CODE_SECONDS = 10 * 60;
const EMAIL_CODE_ATTEMPTS = 3;
const EMAIL_RESEND_SECONDS = 30;

const mailEnabled = (env: Env) => !!env.MAIL && !!env.MAIL_FROM;

function mimeWord(s: string) {
  return /^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${btoa(String.fromCharCode(...new TextEncoder().encode(s)))}?=`;
}

// A plain-text message, base64 body (safe for any language), as the binding wants it: raw MIME.
function buildMime(from: string, to: string, subject: string, text: string): string {
  const domain = from.split("@")[1] ?? "localhost";
  const bytes = new TextEncoder().encode(text.replace(/\r?\n/g, "\r\n"));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const body = btoa(bin).replace(/.{1,76}/g, "$&\r\n");
  return [
    `From: ${mimeWord("Vault")} <${from}>`,
    `To: <${to}>`,
    `Subject: ${mimeWord(subject)}`,
    `Date: ${new Date().toUTCString().replace("GMT", "+0000")}`,
    `Message-ID: <${uuid()}@${domain}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: base64",
    "",
    body,
  ].join("\r\n");
}

async function sendMail(env: Env, to: string, subject: string, text: string) {
  if (!mailEnabled(env)) throw new HttpError(400, "Email isn't set up on this server");
  try {
    await env.MAIL!.send(new EmailMessage(env.MAIL_FROM!, to, buildMime(env.MAIL_FROM!, to, subject, text)));
  } catch (e) {
    console.error("send_email failed:", e);
    throw new HttpError(400, `Couldn't send email to ${to}. Is it a verified destination address in Cloudflare Email Routing?`);
  }
}

// Security notices never block what triggered them.
async function notify(env: Env, u: User, subject: string, text: string) {
  if (!mailEnabled(env)) return;
  try {
    await sendMail(env, u.email, subject, `${text}\n\nIf this wasn't you, change your master password at ${env.WEBAUTHN_ORIGIN && env.WEBAUTHN_ORIGIN !== "auto" ? env.WEBAUTHN_ORIGIN : "your vault"} and review your two-step login settings.\n`);
  } catch (e) {
    console.error("notice not sent:", e);
  }
}

function clientDescription(req: Request, deviceName?: string | null) {
  const cf = (req as any).cf ?? {};
  const where = [cf.city, cf.region, cf.country].filter(Boolean).join(", ");
  const ip = req.headers.get("CF-Connecting-IP") ?? "unknown";
  return `Device: ${deviceName || "unknown"}\nIP address: ${ip}${where ? ` (${where})` : ""}\nTime: ${new Date().toUTCString()}`;
}

const obscureEmail = (e: string) => {
  const [name, domain] = e.split("@");
  return `${name.slice(0, Math.min(2, name.length))}${"*".repeat(Math.max(1, name.length - 2))}@${domain}`;
};

const sixDigits = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, "0");
const codeHash = async (code: string) => b64url(await sha256(code));

type EmailCode = { email: string; code?: string | null; sent?: number; attempts?: number };

async function emailRow(env: Env, userId: string, type: number): Promise<EmailCode | null> {
  const r = await env.DB.prepare("SELECT data FROM twofactors WHERE user_id = ? AND type = ?").bind(userId, type).first<{ data: string }>();
  return r ? JSON.parse(r.data) : null;
}

async function putEmailRow(env: Env, userId: string, type: number, data: EmailCode, enabled: boolean) {
  await env.DB.prepare(
    `INSERT INTO twofactors (user_id, type, data, enabled, last_used) VALUES (?, ?, ?, ?, 0)
     ON CONFLICT(user_id, type) DO UPDATE SET data = excluded.data, enabled = excluded.enabled`,
  ).bind(userId, type, JSON.stringify(data), enabled ? 1 : 0).run();
}

// Mints a code into the row (hashed), mails it, and refuses to resend too quickly.
async function mailCode(env: Env, userId: string, type: number, row: EmailCode, enabled: boolean, purpose: string) {
  if (row.sent && Date.now() - row.sent < EMAIL_RESEND_SECONDS * 1000) {
    throw new HttpError(400, "A code was just sent; wait a few seconds before asking for another");
  }
  const code = sixDigits();
  await putEmailRow(env, userId, type, { email: row.email, code: await codeHash(code), sent: Date.now(), attempts: 0 }, enabled);
  await sendMail(env, row.email, `Your vault verification code: ${code}`,
    `Your verification code ${purpose} is:\n\n    ${code}\n\nIt expires in ${EMAIL_CODE_SECONDS / 60} minutes. Don't share it with anyone.\n`);
}

// One-time check: right code, not expired, at most three wrong tries per code.
async function checkEmailCode(env: Env, userId: string, type: number, code: string, enabledAfter: boolean): Promise<EmailCode | null> {
  const row = await emailRow(env, userId, type);
  if (!row?.code || !row.sent) return null;
  const expired = Date.now() - row.sent > EMAIL_CODE_SECONDS * 1000;
  const ok = !expired && /^\d{6}$/.test(code.trim()) && timingSafeEqual(await codeHash(code.trim()), row.code);
  if (ok) {
    await putEmailRow(env, userId, type, { email: row.email }, enabledAfter);
    return row;
  }
  const attempts = (row.attempts ?? 0) + 1;
  const spent = expired || attempts >= EMAIL_CODE_ATTEMPTS;
  await putEmailRow(env, userId, type, spent ? { email: row.email } : { ...row, attempts }, type === TF_EMAIL);
  return null;
}

const emailTwoFactor = async (env: Env, userId: string) => {
  const r = await env.DB.prepare("SELECT data FROM twofactors WHERE user_id = ? AND type = ? AND enabled = 1").bind(userId, TF_EMAIL).first<{ data: string }>();
  return r ? (JSON.parse(r.data) as EmailCode) : null;
};

// Proof of the master password for the email setup screen, bound to the address.
async function emailToken(env: Env, userId: string, email: string | null) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(env, { iss: "vault-worker|email-setup", sub: userId, email, nbf: now, exp: now + 15 * 60 });
}

async function checkEmailSetup(env: Env, u: User, b: any, email: string | null) {
  if (b.userVerificationToken) {
    const c = await verifyJwt(env, String(b.userVerificationToken), "vault-worker|email-setup");
    if (c && c.sub === u.id && (email === null || c.email === null || c.email === email)) return;
    throw new HttpError(400, "Invalid or expired verification; enter your master password again");
  }
  await verifySecret(u, b);
}

// ---------------------------------------------------------------- sends

type SendRow = {
  id: string; user_id: string; type: number; name: string; notes: string | null; data: string; akey: string;
  password_hash: string | null; password_salt: string | null; max_access_count: number | null; access_count: number;
  expiration_date: string | null; deletion_date: string; disabled: number; hide_email: number; emails: string | null;
  revision_date: string;
};
const SEND_TEXT = 0;
const SEND_FILE = 1;

// Clients address a Send by its UUID bytes, base64url-encoded.
const sendAccessId = (id: string) => b64url(Uint8Array.from(id.replace(/-/g, "").match(/../g)!.map((h) => parseInt(h, 16))));
function sendIdFromAccess(accessId: string): string | null {
  try {
    const b = fromB64url(accessId);
    if (b.length !== 16) return null;
    const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  } catch {
    return null;
  }
}

const parseSendData = (s: SendRow) => {
  const data = JSON.parse(s.data);
  if (data && typeof data.size === "number") data.size = String(data.size);
  return data;
};

function sendJson(s: SendRow) {
  const data = parseSendData(s);
  return {
    id: s.id,
    accessId: sendAccessId(s.id),
    type: s.type,
    name: s.name,
    notes: s.notes,
    text: s.type === SEND_TEXT ? data : null,
    file: s.type === SEND_FILE ? data : null,
    key: s.akey,
    maxAccessCount: s.max_access_count,
    accessCount: s.access_count,
    password: s.password_hash,
    authType: s.password_hash ? 1 : 2,
    emails: s.emails,
    disabled: s.disabled === 1,
    hideEmail: s.hide_email === 1,
    revisionDate: s.revision_date,
    expirationDate: s.expiration_date,
    deletionDate: s.deletion_date,
    object: "send",
  };
}

function sendAccessible(s: SendRow) {
  const now = Date.now();
  return s.disabled !== 1 &&
    (!s.expiration_date || Date.parse(s.expiration_date) > now) &&
    Date.parse(s.deletion_date) > now &&
    (s.max_access_count === null || s.access_count < s.max_access_count);
}

async function sendPasswordOk(s: SendRow, password: string | undefined | null) {
  if (!s.password_hash) return true;
  if (!password || !s.password_salt) return false;
  return timingSafeEqual(await hashPassword(password, s.password_salt), s.password_hash);
}

// Counts a view; false when the access limit was reached in the meantime.
async function registerSendAccess(env: Env, s: SendRow): Promise<boolean> {
  const r = await env.DB.prepare(
    "UPDATE sends SET access_count = access_count + 1, revision_date = ? WHERE id = ? AND (max_access_count IS NULL OR access_count < max_access_count)",
  ).bind(nowIso(), s.id).run();
  await touchUser(env, s.user_id);
  return (r.meta.changes ?? 0) > 0;
}

async function sendAccessJson(env: Env, s: SendRow) {
  const data = parseSendData(s);
  const creator = s.hide_email === 1
    ? null
    : (await env.DB.prepare("SELECT email FROM users WHERE id = ?").bind(s.user_id).first<{ email: string }>())?.email ?? null;
  return {
    id: sendAccessId(s.id),
    type: s.type,
    name: s.name,
    text: s.type === SEND_TEXT ? data : null,
    file: s.type === SEND_FILE ? data : null,
    expirationDate: s.expiration_date,
    creatorIdentifier: creator,
    object: "send-access",
  };
}

// Columns shared by create and update; `data` only for text Sends (files are set at upload).
async function sendFields(body: any, existing?: SendRow): Promise<Record<string, any>> {
  const type = Number(body.type);
  if (type !== SEND_TEXT && type !== SEND_FILE) throw new HttpError(400, "Invalid send type");
  if (existing && existing.type !== type) throw new HttpError(400, "Send type can't be changed");
  const deletion = Date.parse(body.deletionDate);
  if (!Number.isFinite(deletion)) throw new HttpError(400, "Invalid deletion date");
  if (deletion > Date.now() + 31 * 86400_000) throw new HttpError(400, "Deletion date can't be more than 31 days in the future");
  const max = body.maxAccessCount;
  const out: Record<string, any> = {
    name: String(body.name ?? ""),
    notes: body.notes ?? null,
    akey: String(body.key ?? existing?.akey ?? ""),
    max_access_count: max === null || max === undefined || max === "" ? null : Number(max),
    expiration_date: body.expirationDate ? new Date(body.expirationDate).toISOString() : null,
    deletion_date: new Date(deletion).toISOString(),
    disabled: body.disabled ? 1 : 0,
    hide_email: body.hideEmail ? 1 : 0,
    emails: body.emails ?? null,
    password_hash: existing?.password_hash ?? null,
    password_salt: existing?.password_salt ?? null,
  };
  if (type === SEND_TEXT) out.data = JSON.stringify(body.text ?? {});
  if (body.password) {
    out.password_salt = randomToken(16);
    out.password_hash = await hashPassword(String(body.password), out.password_salt);
  }
  return out;
}

async function ownedSend(env: Env, u: User, id: string): Promise<SendRow> {
  const s = await env.DB.prepare("SELECT * FROM sends WHERE id = ? AND user_id = ?").bind(id, u.id).first<SendRow>();
  if (!s) throw new HttpError(404, "Send not found");
  return s;
}

async function deleteSend(env: Env, s: SendRow) {
  if (s.type === SEND_FILE) {
    const fileId = JSON.parse(s.data)?.id;
    if (fileId) await env.FILES.delete(`sends/${s.id}/${fileId}`);
  }
  await env.DB.prepare("DELETE FROM sends WHERE id = ?").bind(s.id).run();
}

async function purgeExpiredSends(env: Env, userId: string) {
  const { results } = await env.DB.prepare("SELECT * FROM sends WHERE user_id = ? AND deletion_date < ?").bind(userId, nowIso()).all<SendRow>();
  for (const s of results) await deleteSend(env, s);
}

async function insertSend(env: Env, u: User, f: Record<string, any>, type: number, data: string) {
  const id = uuid();
  await env.DB.prepare(
    `INSERT INTO sends (id, user_id, type, name, notes, data, akey, password_hash, password_salt, max_access_count, access_count,
       expiration_date, deletion_date, disabled, hide_email, emails, revision_date)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)`,
  ).bind(id, u.id, type, f.name, f.notes, data, f.akey, f.password_hash, f.password_salt, f.max_access_count,
    f.expiration_date, f.deletion_date, f.disabled, f.hide_email, f.emails, nowIso()).run();
  await touchUser(env, u.id);
  return ownedSend(env, u, id);
}

// ---------------------------------------------------------------- router

type Handler = (env: Env, req: Request, params: string[]) => Promise<Response>;
const routes: [string, RegExp, Handler][] = [];
const route = (method: string, path: string, h: Handler) =>
  routes.push([method, new RegExp("^" + path.replace(/:[a-z_]+/gi, "([^/]+)") + "/?$"), h]);
const authed = (h: (env: Env, req: Request, user: User, params: string[]) => Promise<Response>): Handler =>
  async (env, req, params) => h(env, req, await requireUser(env, req), params);

const empty = () => json({});
const ids = async (req: Request): Promise<string[]> => ((await req.json<any>()).ids ?? []).map(String);

// Misc / config
route("GET", "/alive", async () => json(nowIso()));
route("GET", "/api/alive", async () => json(nowIso()));
route("GET", "/api/now", async () => json(nowIso()));
route("GET", "/api/version", async () => json(SERVER_VERSION));
route("GET", "/api/config", async (env, req) => {
  const origin = new URL(req.url).origin;
  return json({
    version: SERVER_VERSION,
    gitHash: null,
    server: { name: "vault-worker", url: "https://developers.cloudflare.com/workers/" },
    settings: { disableUserRegistration: env.SIGNUPS_ALLOWED !== "true", suppressOnboardingInterstitials: true },
    environment: {
      vault: origin,
      api: `${origin}/api`,
      identity: `${origin}/identity`,
      notifications: `${origin}/notifications`,
      sso: "",
      cloudRegion: null,
    },
    push: { pushTechnology: 0, vapidPublicKey: null },
    featureStates: {},
    communication: null,
    object: "config",
  });
});

// Identity
route("POST", "/identity/connect/token", (env, req) => connectToken(env, req));
route("POST", "/identity/accounts/prelogin", (env, req) => prelogin(env, req));
route("POST", "/identity/accounts/prelogin/password", (env, req) => prelogin(env, req));
route("POST", "/api/accounts/prelogin", (env, req) => prelogin(env, req));
route("POST", "/identity/accounts/register/send-verification-email", (env, req) => sendVerificationEmail(env, req));
route("POST", "/identity/accounts/register/finish", (env, req) => registerFinish(env, req, true));
route("POST", "/identity/accounts/register", (env, req) => registerFinish(env, req, false));
route("POST", "/api/accounts/register", (env, req) => registerFinish(env, req, false));

// Accounts
route("GET", "/api/accounts/profile", authed(async (env, req, u) => json(profileJson(u, await hasTwoFactor(env, u.id)))));
const putProfile = authed(async (env, req, u) => {
  const b = await req.json<any>();
  await env.DB.prepare("UPDATE users SET name = ?, password_hint = ?, updated_at = ? WHERE id = ?")
    .bind(b.name ?? u.name, b.masterPasswordHint ?? u.password_hint, nowIso(), u.id)
    .run();
  await touchUser(env, u.id);
  return json(profileJson((await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(u.id).first<User>())!, await hasTwoFactor(env, u.id)));
});
route("PUT", "/api/accounts/profile", putProfile);
route("POST", "/api/accounts/profile", putProfile);
route("PUT", "/api/accounts/avatar", authed(async (env, req, u) => {
  const b = await req.json<any>();
  await env.DB.prepare("UPDATE users SET avatar_color = ? WHERE id = ?").bind(b.avatarColor ?? null, u.id).run();
  return json(profileJson({ ...u, avatar_color: b.avatarColor ?? null }, await hasTwoFactor(env, u.id)));
}));
route("GET", "/api/accounts/revision-date", authed(async (env, req, u) => json(u.revision_date)));
route("GET", "/api/accounts/keys", authed(async (env, req, u) => json({ privateKey: u.private_key, publicKey: u.public_key, object: "keys" })));
route("POST", "/api/accounts/keys", authed(async (env, req, u) => {
  const b = await req.json<any>();
  await env.DB.prepare("UPDATE users SET private_key = ?, public_key = ? WHERE id = ?").bind(b.encryptedPrivateKey, b.publicKey, u.id).run();
  return json({ privateKey: b.encryptedPrivateKey, publicKey: b.publicKey, object: "keys" });
}));
route("POST", "/api/accounts/key-management/user-key-id", authed(async (env, req, u) => {
  if (u.key_id) throw new HttpError(422, "Unexpected data");
  const b = await req.json<any>();
  await env.DB.prepare("UPDATE users SET key_id = ? WHERE id = ?").bind(String(b.userKeyId ?? ""), u.id).run();
  return empty();
}));
route("POST", "/api/accounts/verify-password", authed(async (env, req, u) => {
  const b = await req.json<any>();
  if (!timingSafeEqual(await hashPassword(String(b.masterPasswordHash ?? ""), u.password_salt, u.password_iterations), u.password_hash)) {
    throw new HttpError(400, "Invalid password");
  }
  return json({ masterPasswordPolicy: null, object: "masterPasswordPolicy" });
}));
route("POST", "/api/accounts/security-stamp", authed(async (env, req, u) => {
  await env.DB.prepare("UPDATE users SET security_stamp = ? WHERE id = ?").bind(uuid(), u.id).run();
  await env.DB.prepare("DELETE FROM devices WHERE user_id = ?").bind(u.id).run();
  return empty();
}));
const deleteAccount = authed(async (env, req, u) => {
  const b = await req.json<any>();
  if (!timingSafeEqual(await hashPassword(String(b.masterPasswordHash ?? ""), u.password_salt, u.password_iterations), u.password_hash)) {
    throw new HttpError(400, "Invalid password");
  }
  await deleteAttachmentsOf(env, u.id, null);
  for (const s of (await env.DB.prepare("SELECT * FROM sends WHERE user_id = ?").bind(u.id).all<SendRow>()).results) await deleteSend(env, s);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM ciphers WHERE user_id = ?").bind(u.id),
    env.DB.prepare("DELETE FROM folders WHERE user_id = ?").bind(u.id),
    env.DB.prepare("DELETE FROM devices WHERE user_id = ?").bind(u.id),
    env.DB.prepare("DELETE FROM twofactors WHERE user_id = ?").bind(u.id),
    env.DB.prepare("DELETE FROM users WHERE id = ?").bind(u.id),
  ]);
  return empty();
});
route("DELETE", "/api/accounts", deleteAccount);
route("POST", "/api/accounts/delete", deleteAccount);

// Devices
route("GET", "/api/devices/knowndevice", async (env, req) => {
  const raw = req.headers.get("X-Request-Email") ?? "";
  const deviceId = req.headers.get("X-Device-Identifier") ?? "";
  let email = "";
  try { email = new TextDecoder().decode(fromB64url(raw)).trim().toLowerCase(); } catch { /* bad header: unknown */ }
  const row = email && deviceId
    ? await env.DB.prepare("SELECT d.id FROM devices d JOIN users u ON u.id = d.user_id WHERE u.email = ? AND d.id = ?").bind(email, deviceId).first()
    : null;
  return json(!!row);
});
route("GET", "/api/devices", authed(async (env, req, u) => {
  const { results } = await env.DB.prepare("SELECT * FROM devices WHERE user_id = ?").bind(u.id).all<any>();
  return json(list(results.map((d) => ({ id: d.id, name: d.name, type: d.type, identifier: d.id, creationDate: d.created_at, isTrusted: false, object: "device" }))));
}));
for (const m of ["PUT", "POST"]) {
  route(m, "/api/devices/identifier/:id/token", authed(async () => empty()));
  route(m, "/api/devices/identifier/:id/clear-token", authed(async () => empty()));
}

// Sync
route("GET", "/api/sync", authed(async (env, req, u) => {
  await purgeExpiredSends(env, u.id);
  const [ciphers, folders, sends, twoFactor] = await Promise.all([
    env.DB.prepare("SELECT * FROM ciphers WHERE user_id = ?").bind(u.id).all<CipherRow>(),
    env.DB.prepare("SELECT * FROM folders WHERE user_id = ?").bind(u.id).all<any>(),
    env.DB.prepare("SELECT * FROM sends WHERE user_id = ?").bind(u.id).all<SendRow>(),
    hasTwoFactor(env, u.id),
  ]);
  const excludeDomains = new URL(req.url).searchParams.get("excludeDomains") === "true";
  return json({
    profile: profileJson(u, twoFactor),
    folders: folders.results.map(folderJson),
    collections: [],
    policies: [],
    policiesNew: [],
    ciphers: await renderCiphers(env, req, ciphers.results),
    domains: excludeDomains ? null : { equivalentDomains: JSON.parse(u.equivalent_domains), globalEquivalentDomains: [], object: "domains" },
    sends: sends.results.map(sendJson),
    userDecryption: {
      masterPasswordUnlock: {
        kdf: kdfJson(u),
        masterKeyEncryptedUserKey: u.akey,
        masterKeyWrappedUserKey: u.akey,
        salt: u.email,
      },
      userKeyId: u.key_id,
    },
    object: "sync",
  });
}));

// Ciphers
route("GET", "/api/ciphers", authed(async (env, req, u) => {
  const { results } = await env.DB.prepare("SELECT * FROM ciphers WHERE user_id = ?").bind(u.id).all<CipherRow>();
  return json(list(await renderCiphers(env, req, results)));
}));
route("POST", "/api/ciphers", authed(async (env, req, u) => json(await renderOne(env, req, await createCipher(env, u, await req.json())))));
route("POST", "/api/ciphers/create", authed(async (env, req, u) => json(await renderOne(env, req, await createCipher(env, u, await req.json())))));
route("POST", "/api/ciphers/import", authed(async (env, req, u) => { await importVault(env, u, await req.json()); return empty(); }));
route("PUT", "/api/ciphers/delete", authed(async (env, req, u) => { await setDeleted(env, u, await ids(req), true); return empty(); }));
route("POST", "/api/ciphers/delete", authed(async (env, req, u) => { await hardDelete(env, u, await ids(req)); return empty(); }));
route("DELETE", "/api/ciphers", authed(async (env, req, u) => { await hardDelete(env, u, await ids(req)); return empty(); }));
route("PUT", "/api/ciphers/restore", authed(async (env, req, u) => {
  const list_ = await ids(req);
  await setDeleted(env, u, list_, false);
  return json(list(await ciphersByIds(env, req, u, list_)));
}));
for (const m of ["PUT", "POST"]) {
  route(m, "/api/ciphers/move", authed(async (env, req, u) => {
    const b = await req.json<any>();
    await checkFolder(env, u, b.folderId ?? null);
    const now = nowIso();
    for (const id of b.ids ?? []) {
      await env.DB.prepare("UPDATE ciphers SET folder_id = ?, updated_at = ? WHERE id = ? AND user_id = ?").bind(b.folderId ?? null, now, id, u.id).run();
    }
    await touchUser(env, u.id);
    return empty();
  }));
}
route("PUT", "/api/ciphers/archive", authed(async (env, req, u) => {
  const list_ = await ids(req);
  await setArchived(env, u, list_, true);
  return json(list(await ciphersByIds(env, req, u, list_)));
}));
route("PUT", "/api/ciphers/unarchive", authed(async (env, req, u) => {
  const list_ = await ids(req);
  await setArchived(env, u, list_, false);
  return json(list(await ciphersByIds(env, req, u, list_)));
}));
route("POST", "/api/ciphers/purge", authed(async (env, req, u) => {
  const b = await req.json<any>();
  if (!timingSafeEqual(await hashPassword(String(b.masterPasswordHash ?? ""), u.password_salt, u.password_iterations), u.password_hash)) {
    throw new HttpError(400, "Invalid password");
  }
  await deleteAttachmentsOf(env, u.id, null);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM ciphers WHERE user_id = ?").bind(u.id),
    env.DB.prepare("DELETE FROM folders WHERE user_id = ?").bind(u.id),
  ]);
  await touchUser(env, u.id);
  return empty();
}));
route("GET", "/api/ciphers/:id", authed(async (env, req, u, [id]) => json(await renderOne(env, req, await ownedCipher(env, u, id)))));
route("GET", "/api/ciphers/:id/details", authed(async (env, req, u, [id]) => json(await renderOne(env, req, await ownedCipher(env, u, id)))));
for (const m of ["PUT", "POST"]) {
  route(m, "/api/ciphers/:id", authed(async (env, req, u, [id]) => json(await renderOne(env, req, await updateCipher(env, u, id, await req.json())))));
  route(m, "/api/ciphers/:id/partial", authed(async (env, req, u, [id]) => {
    const b = await req.json<any>();
    await ownedCipher(env, u, id);
    await checkFolder(env, u, b.folderId ?? null);
    await env.DB.prepare("UPDATE ciphers SET folder_id = ?, favorite = ?, updated_at = ? WHERE id = ? AND user_id = ?")
      .bind(b.folderId ?? null, b.favorite ? 1 : 0, nowIso(), id, u.id)
      .run();
    await touchUser(env, u.id);
    return json(await renderOne(env, req, await ownedCipher(env, u, id)));
  }));
}
route("PUT", "/api/ciphers/:id/delete", authed(async (env, req, u, [id]) => { await ownedCipher(env, u, id); await setDeleted(env, u, [id], true); return empty(); }));
route("POST", "/api/ciphers/:id/delete", authed(async (env, req, u, [id]) => { await ownedCipher(env, u, id); await hardDelete(env, u, [id]); return empty(); }));
route("DELETE", "/api/ciphers/:id", authed(async (env, req, u, [id]) => { await ownedCipher(env, u, id); await hardDelete(env, u, [id]); return empty(); }));
route("PUT", "/api/ciphers/:id/restore", authed(async (env, req, u, [id]) => {
  await ownedCipher(env, u, id);
  await setDeleted(env, u, [id], false);
  return json(await renderOne(env, req, await ownedCipher(env, u, id)));
}));
route("PUT", "/api/ciphers/:id/archive", authed(async (env, req, u, [id]) => {
  await ownedCipher(env, u, id);
  await setArchived(env, u, [id], true);
  return json(await renderOne(env, req, await ownedCipher(env, u, id)));
}));
route("PUT", "/api/ciphers/:id/unarchive", authed(async (env, req, u, [id]) => {
  await ownedCipher(env, u, id);
  await setArchived(env, u, [id], false);
  return json(await renderOne(env, req, await ownedCipher(env, u, id)));
}));

// Folders
route("GET", "/api/folders", authed(async (env, req, u) => {
  const { results } = await env.DB.prepare("SELECT * FROM folders WHERE user_id = ?").bind(u.id).all<any>();
  return json(list(results.map(folderJson)));
}));
route("POST", "/api/folders", authed(async (env, req, u) => {
  const b = await req.json<any>();
  const f = { id: uuid(), name: String(b.name ?? ""), updated_at: nowIso() };
  await env.DB.prepare("INSERT INTO folders (id, user_id, name, updated_at) VALUES (?, ?, ?, ?)").bind(f.id, u.id, f.name, f.updated_at).run();
  await touchUser(env, u.id);
  return json(folderJson(f));
}));
const ownedFolder = async (env: Env, u: User, id: string) => {
  const f = await env.DB.prepare("SELECT * FROM folders WHERE id = ? AND user_id = ?").bind(id, u.id).first<any>();
  if (!f) throw new HttpError(404, "Folder doesn't exist");
  return f;
};
route("GET", "/api/folders/:id", authed(async (env, req, u, [id]) => json(folderJson(await ownedFolder(env, u, id)))));
for (const m of ["PUT", "POST"]) {
  route(m, "/api/folders/:id", authed(async (env, req, u, [id]) => {
    await ownedFolder(env, u, id);
    const b = await req.json<any>();
    const now = nowIso();
    await env.DB.prepare("UPDATE folders SET name = ?, updated_at = ? WHERE id = ?").bind(String(b.name ?? ""), now, id).run();
    await touchUser(env, u.id);
    return json(folderJson(await ownedFolder(env, u, id)));
  }));
}
const deleteFolder = authed(async (env, req, u, [id]) => {
  await ownedFolder(env, u, id);
  await env.DB.batch([
    env.DB.prepare("UPDATE ciphers SET folder_id = NULL WHERE folder_id = ? AND user_id = ?").bind(id, u.id),
    env.DB.prepare("DELETE FROM folders WHERE id = ?").bind(id),
  ]);
  await touchUser(env, u.id);
  return empty();
});
route("DELETE", "/api/folders/:id", deleteFolder);
route("POST", "/api/folders/:id/delete", deleteFolder);

// Attachments: the client asks for a slot (v2), then uploads the encrypted file to it.
route("POST", "/api/ciphers/:id/attachment/v2", authed(async (env, req, u, [id]) => {
  const c = await ownedCipher(env, u, id);
  const b = await req.json<any>();
  const size = Number(b.fileSize);
  if (!Number.isFinite(size) || size < 0) throw new HttpError(400, "Invalid file size");
  if (size > MAX_UPLOAD_BYTES) throw new HttpError(400, "Max file size is 100 MB");
  const attId = randomToken(16);
  await env.DB.prepare("INSERT INTO attachments (id, cipher_id, user_id, file_name, file_size, akey, uploaded, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)")
    .bind(attId, c.id, u.id, String(b.fileName ?? ""), size, b.key ?? null, nowIso()).run();
  return json({
    object: "attachment-fileUpload",
    attachmentId: attId,
    url: `/ciphers/${c.id}/attachment/${attId}`,
    fileUploadType: 0,
    [b.adminRequest ? "cipherMiniResponse" : "cipherResponse"]: await renderOne(env, req, c),
  });
}));
route("POST", "/api/ciphers/:id/attachment/:att", authed(async (env, req, u, [id, attId]) => {
  const c = await ownedCipher(env, u, id);
  const a = await env.DB.prepare("SELECT * FROM attachments WHERE id = ? AND cipher_id = ? AND user_id = ?").bind(attId, c.id, u.id).first<AttachmentRow>();
  if (!a) throw new HttpError(404, "Attachment doesn't exist");
  const { file } = await uploadedFile(req, a.file_size);
  await env.FILES.put(`attachments/${c.id}/${a.id}`, file.stream());
  await env.DB.prepare("UPDATE attachments SET file_size = ?, uploaded = 1 WHERE id = ?").bind(file.size, a.id).run();
  await env.DB.prepare("UPDATE ciphers SET updated_at = ? WHERE id = ?").bind(nowIso(), c.id).run();
  await touchUser(env, u.id);
  return empty();
}));
// Older clients upload in one request: the file plus its key.
route("POST", "/api/ciphers/:id/attachment", authed(async (env, req, u, [id]) => {
  const c = await ownedCipher(env, u, id);
  const { file, key } = await uploadedFile(req);
  const attId = randomToken(16);
  await env.FILES.put(`attachments/${c.id}/${attId}`, file.stream());
  await env.DB.prepare("INSERT INTO attachments (id, cipher_id, user_id, file_name, file_size, akey, uploaded, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)")
    .bind(attId, c.id, u.id, file.name, file.size, key, nowIso()).run();
  await env.DB.prepare("UPDATE ciphers SET updated_at = ? WHERE id = ?").bind(nowIso(), c.id).run();
  await touchUser(env, u.id);
  return json(await renderOne(env, req, await ownedCipher(env, u, id)));
}));
route("GET", "/api/ciphers/:id/attachment/:att", authed(async (env, req, u, [id, attId]) => {
  const a = await env.DB.prepare("SELECT * FROM attachments WHERE id = ? AND cipher_id = ? AND user_id = ?").bind(attId, id, u.id).first<AttachmentRow>();
  if (!a) throw new HttpError(404, "Attachment doesn't exist");
  return json(await attachmentJson(env, req, a));
}));
const deleteAttachment = authed(async (env, req, u, [id, attId]) => {
  const a = await env.DB.prepare("SELECT * FROM attachments WHERE id = ? AND cipher_id = ? AND user_id = ?").bind(attId, id, u.id).first<AttachmentRow>();
  if (!a) throw new HttpError(404, "Attachment doesn't exist");
  await env.FILES.delete(`attachments/${a.cipher_id}/${a.id}`);
  await env.DB.prepare("DELETE FROM attachments WHERE id = ?").bind(a.id).run();
  await env.DB.prepare("UPDATE ciphers SET updated_at = ? WHERE id = ?").bind(nowIso(), id).run();
  await touchUser(env, u.id);
  return json({ cipher: await renderOne(env, req, await ownedCipher(env, u, id)) });
});
route("DELETE", "/api/ciphers/:id/attachment/:att", deleteAttachment);
route("POST", "/api/ciphers/:id/attachment/:att/delete", deleteAttachment);

// Signed download links for attachments and Send files.
// The token is bound to the URL path; `key` is where the bytes live in R2.
async function serveFile(env: Env, req: Request, key: string): Promise<Response> {
  const url = new URL(req.url);
  const token = url.searchParams.get("token") ?? url.searchParams.get("t") ?? "";
  const c = await verifyJwt(env, token, "vault-worker|file");
  if (!c || c.sub !== url.pathname.slice(1)) return new Response("Invalid or expired link", { status: 401 });
  const obj = await env.FILES.get(key);
  if (!obj) return new Response("Not found", { status: 404 });
  return new Response(obj.body, { headers: { "Content-Type": "application/octet-stream", "Content-Length": String(obj.size) } });
}
route("GET", "/attachments/:cipher/:att", (env, req, [cid, aid]) => serveFile(env, req, `attachments/${cid}/${aid}`));
route("GET", "/api/sends/:send/:file", (env, req, [sid, fid]) => serveFile(env, req, `sends/${sid}/${fid}`));

// Send: recipient side (before the owner routes, whose /sends/:id/... patterns would also match "access"). Current clients first get a short token from
// /identity/connect/token (grant_type=send_access), older ones post the password here.
async function sendFromBearer(env: Env, req: Request): Promise<SendRow> {
  const auth = req.headers.get("Authorization") ?? "";
  const c = await verifyJwt(env, auth.replace(/^Bearer /, ""), "vault-worker|send");
  const s = c ? await env.DB.prepare("SELECT * FROM sends WHERE id = ?").bind(c.sub).first<SendRow>() : null;
  if (!s || !sendAccessible(s)) throw new HttpError(404, "Send does not exist or is no longer available");
  return s;
}
async function sendByAccessId(env: Env, accessId: string): Promise<SendRow> {
  const id = sendIdFromAccess(accessId);
  const s = id ? await env.DB.prepare("SELECT * FROM sends WHERE id = ?").bind(id).first<SendRow>() : null;
  if (!s || !sendAccessible(s)) throw new HttpError(404, "Send does not exist or is no longer available");
  return s;
}
const UNAVAILABLE = "Send does not exist or is no longer available";
async function accessText(env: Env, s: SendRow) {
  if (s.type === SEND_TEXT && !(await registerSendAccess(env, s))) throw new HttpError(404, UNAVAILABLE);
  return json(await sendAccessJson(env, s));
}
async function accessFile(env: Env, req: Request, s: SendRow, fileId: string) {
  const data = JSON.parse(s.data);
  if (s.type !== SEND_FILE || data?.id !== fileId) throw new HttpError(404, UNAVAILABLE);
  if (!(await registerSendAccess(env, s))) throw new HttpError(404, UNAVAILABLE);
  return json({ object: "send-fileDownload", id: fileId, url: await fileUrl(env, req, `api/sends/${s.id}/${fileId}`) });
}
route("POST", "/api/sends/access", async (env, req) => accessText(env, await sendFromBearer(env, req)));
route("POST", "/api/sends/access/file/:file", async (env, req, [fileId]) => accessFile(env, req, await sendFromBearer(env, req), fileId));
route("POST", "/api/sends/access/:accessId", async (env, req, [accessId]) => {
  const s = await sendByAccessId(env, accessId);
  const b = await req.json<any>().catch(() => ({}));
  if (!(await sendPasswordOk(s, b.password))) throw new HttpError(s.password_hash && !b.password ? 401 : 400, "Invalid password");
  return accessText(env, s);
});
route("POST", "/api/sends/:id/access/file/:file", async (env, req, [id, fileId]) => {
  const s = await env.DB.prepare("SELECT * FROM sends WHERE id = ?").bind(id).first<SendRow>();
  if (!s || !sendAccessible(s)) throw new HttpError(404, UNAVAILABLE);
  const b = await req.json<any>().catch(() => ({}));
  if (!(await sendPasswordOk(s, b.password))) throw new HttpError(400, "Invalid password");
  return accessFile(env, req, s, fileId);
});

// Send: owner side.
route("GET", "/api/sends", authed(async (env, req, u) => {
  await purgeExpiredSends(env, u.id);
  const { results } = await env.DB.prepare("SELECT * FROM sends WHERE user_id = ?").bind(u.id).all<SendRow>();
  return json(list(results.map(sendJson)));
}));
route("POST", "/api/sends", authed(async (env, req, u) => {
  const b = await req.json<any>();
  if (Number(b.type) === SEND_FILE) throw new HttpError(400, "File sends are created with /sends/file/v2");
  const f = await sendFields(b);
  return json(sendJson(await insertSend(env, u, f, SEND_TEXT, f.data)));
}));
route("POST", "/api/sends/file/v2", authed(async (env, req, u) => {
  const b = await req.json<any>();
  if (Number(b.type) !== SEND_FILE) throw new HttpError(400, "Send content is not a file");
  const size = Number(b.fileLength);
  if (!Number.isFinite(size) || size < 0 || size > MAX_UPLOAD_BYTES) throw new HttpError(400, "Invalid send length");
  const f = await sendFields(b);
  const fileId = randomToken(16);
  const data = { ...(b.file ?? {}), id: fileId, size, sizeName: displaySize(size) };
  const s = await insertSend(env, u, f, SEND_FILE, JSON.stringify(data));
  return json({ fileUploadType: 0, object: "send-fileUpload", url: `/sends/${s.id}/file/${fileId}`, sendResponse: sendJson(s) });
}));
route("POST", "/api/sends/:id/file/:file", authed(async (env, req, u, [id, fileId]) => {
  const s = await ownedSend(env, u, id);
  const data = JSON.parse(s.data);
  if (s.type !== SEND_FILE || data?.id !== fileId) throw new HttpError(404, "Send file not found");
  const { file } = await uploadedFile(req, Number(data.size));
  await env.FILES.put(`sends/${s.id}/${fileId}`, file.stream());
  return empty();
}));
route("GET", "/api/sends/:id", authed(async (env, req, u, [id]) => json(sendJson(await ownedSend(env, u, id)))));
route("PUT", "/api/sends/:id", authed(async (env, req, u, [id]) => {
  const s = await ownedSend(env, u, id);
  const f = await sendFields(await req.json<any>(), s);
  await env.DB.prepare(
    `UPDATE sends SET name = ?, notes = ?, data = ?, akey = ?, password_hash = ?, password_salt = ?, max_access_count = ?,
       expiration_date = ?, deletion_date = ?, disabled = ?, hide_email = ?, emails = ?, revision_date = ? WHERE id = ?`,
  ).bind(f.name, f.notes, f.data ?? s.data, f.akey, f.password_hash, f.password_salt, f.max_access_count, f.expiration_date,
    f.deletion_date, f.disabled, f.hide_email, f.emails, nowIso(), s.id).run();
  await touchUser(env, u.id);
  return json(sendJson(await ownedSend(env, u, id)));
}));
route("PUT", "/api/sends/:id/remove-password", authed(async (env, req, u, [id]) => {
  const s = await ownedSend(env, u, id);
  await env.DB.prepare("UPDATE sends SET password_hash = NULL, password_salt = NULL, revision_date = ? WHERE id = ?").bind(nowIso(), s.id).run();
  await touchUser(env, u.id);
  return json(sendJson(await ownedSend(env, u, id)));
}));
route("DELETE", "/api/sends/:id", authed(async (env, req, u, [id]) => {
  await deleteSend(env, await ownedSend(env, u, id));
  await touchUser(env, u.id);
  return empty();
}));

// Two-factor: authenticator app (TOTP) plus the recovery code.
route("GET", "/api/two-factor", authed(async (env, req, u) => {
  const providers = [];
  if (await totpRow(env, u.id)) providers.push({ enabled: true, type: TF_AUTHENTICATOR, object: "twoFactorProvider" });
  if ((await webauthnKeys(env, u.id)).length) providers.push({ enabled: true, type: TF_WEBAUTHN, object: "twoFactorProvider" });
  if (await emailTwoFactor(env, u.id)) providers.push({ enabled: true, type: TF_EMAIL, object: "twoFactorProvider" });
  return json(list(providers));
}));
route("POST", "/api/two-factor/get-authenticator", authed(async (env, req, u) => {
  await verifySecret(u, await req.json<any>());
  const existing = await totpRow(env, u.id);
  const key = existing?.data ?? base32Encode(crypto.getRandomValues(new Uint8Array(20)));
  return json({
    enabled: !!existing,
    key,
    authenticator: { enabled: !!existing, key },
    userVerificationToken: await authenticatorToken(env, u.id, key),
    object: "twoFactorAuthenticator",
  });
}));
const enableAuthenticator = authed(async (env, req, u) => {
  const b = await req.json<any>();
  const key = String(b.key ?? "").toUpperCase();
  if (b.userVerificationToken) await checkAuthenticatorToken(env, u.id, key, b.userVerificationToken);
  else await verifySecret(u, b);
  if (base32Decode(key)?.length !== 20) throw new HttpError(400, "Invalid TOTP secret");
  if (!(await checkTotp(env, u.id, key, String(b.token ?? "")))) throw new HttpError(400, "Invalid TOTP code");
  await env.DB.prepare(
    `INSERT INTO twofactors (user_id, type, data, enabled, last_used) VALUES (?, ?, ?, 1, 0)
     ON CONFLICT(user_id, type) DO UPDATE SET data = excluded.data, enabled = 1`,
  ).bind(u.id, TF_AUTHENTICATOR, key).run();
  if (!u.totp_recover) {
    await env.DB.prepare("UPDATE users SET totp_recover = ? WHERE id = ?").bind(base32Encode(crypto.getRandomValues(new Uint8Array(20))), u.id).run();
  }
  await notify(env, u, "Authenticator app added to two-step login", "An authenticator app was set up for your vault's two-step login.");
  return json({ enabled: true, key, authenticator: { enabled: true, key }, object: "twoFactorAuthenticator" });
});
route("POST", "/api/two-factor/authenticator", enableAuthenticator);
route("PUT", "/api/two-factor/authenticator", enableAuthenticator);
// Removes one kind of 2FA; "remember this device" tokens go too, so the change takes effect.
const TF_LABELS: Record<number, string> = { 0: "authenticator app", 1: "email", 7: "passkey / security key" };

async function disableTwoFactor(env: Env, u: User, type: number) {
  const types = type === TF_WEBAUTHN ? [TF_WEBAUTHN, TF_WEBAUTHN_REGISTER, TF_WEBAUTHN_LOGIN]
    : type === TF_EMAIL ? [TF_EMAIL, TF_EMAIL_SETUP] : [type];
  await env.DB.batch([
    ...types.map((t) => env.DB.prepare("DELETE FROM twofactors WHERE user_id = ? AND type = ?").bind(u.id, t)),
    env.DB.prepare("UPDATE devices SET twofactor_remember = NULL WHERE user_id = ?").bind(u.id),
  ]);
  await notify(env, u, "Two-step login method removed", `The ${TF_LABELS[type] ?? "two-step"} method was removed from your vault's two-step login.`);
}
route("DELETE", "/api/two-factor/authenticator", authed(async (env, req, u) => {
  const b = await req.json<any>();
  const key = String(b.key ?? "").toUpperCase();
  if (b.userVerificationToken) await checkAuthenticatorToken(env, u.id, key, b.userVerificationToken);
  else await verifySecret(u, b);
  const tf = await totpRow(env, u.id);
  if (tf && tf.data !== key) throw new HttpError(400, "TOTP key doesn't match the active one");
  await disableTwoFactor(env, u, TF_AUTHENTICATOR);
  return json({ enabled: false, type: TF_AUTHENTICATOR, object: "twoFactorProvider" });
}));
for (const m of ["PUT", "POST"]) {
  route(m, "/api/two-factor/disable", authed(async (env, req, u) => {
    const b = await req.json<any>();
    await verifySecret(u, b);
    const type = Number(b.type ?? TF_AUTHENTICATOR);
    if (type !== TF_AUTHENTICATOR && type !== TF_WEBAUTHN && type !== TF_EMAIL) throw new HttpError(400, "Unknown two-factor type");
    await disableTwoFactor(env, u, type);
    return json({ enabled: false, type, object: "twoFactorProvider" });
  }));
}
// WebAuthn keys: list (with a fresh verification token), register, remove.
route("POST", "/api/two-factor/get-webauthn", authed(async (env, req, u) => {
  await verifySecret(u, await req.json<any>());
  const keys = await webauthnKeys(env, u.id);
  return json({ ...webauthnState(keys), userVerificationToken: await webauthnToken(env, u.id, keys) });
}));
route("POST", "/api/two-factor/get-webauthn-challenge", authed(async (env, req, u) => {
  const b = await req.json<any>();
  const keys = await webauthnKeys(env, u.id);
  if (b.userVerificationToken) await checkWebauthnToken(env, u.id, keys, b.userVerificationToken);
  else await verifySecret(u, b);
  const { rpId } = webauthnOrigin(env, req);
  const challenge = randomToken(32);
  await storeChallenge(env, u.id, TF_WEBAUTHN_REGISTER, challenge);
  const userHandle = b64url(Uint8Array.from(u.id.replace(/-/g, "").match(/../g)!.map((h) => parseInt(h, 16))));
  const options = {
    rp: { name: "vault-worker", id: rpId },
    user: { id: userHandle, name: u.email, displayName: u.name ?? u.email },
    challenge,
    pubKeyCredParams: [-7, -257, -8].map((alg) => ({ type: "public-key", alg })),
    timeout: 60000,
    excludeCredentials: keys.map((k) => ({ type: "public-key", id: k.credentialId })),
    authenticatorSelection: { residentKey: "discouraged", requireResidentKey: false, userVerification: "discouraged" },
    attestation: "none",
    status: "ok",
    errorMessage: "",
  };
  // The web vault (2026.x) reads these at the top level; newer Vaultwarden nests them in `options`.
  return json({ ...options, options });
}));
const activateWebauthn = authed(async (env, req, u) => {
  const b = await req.json<any>();
  const keys = await webauthnKeys(env, u.id);
  if (b.userVerificationToken) await checkWebauthnToken(env, u.id, keys, b.userVerificationToken);
  else await verifySecret(u, b);
  const key = await finishRegistration(env, req, u.id, b, keys);
  const next = [...keys.filter((k) => k.id !== key.id), key];
  await saveWebauthnKeys(env, u.id, next);
  await notify(env, u, "Passkey added to two-step login", `The key "${key.name}" was added to your vault's two-step login.`);
  if (!u.totp_recover) {
    await env.DB.prepare("UPDATE users SET totp_recover = ? WHERE id = ?").bind(base32Encode(crypto.getRandomValues(new Uint8Array(20))), u.id).run();
  }
  return json(webauthnState(next));
});
route("POST", "/api/two-factor/webauthn", activateWebauthn);
route("PUT", "/api/two-factor/webauthn", activateWebauthn);
route("DELETE", "/api/two-factor/webauthn/all", authed(async (env, req, u) => {
  const b = await req.json<any>();
  const keys = await webauthnKeys(env, u.id);
  await checkWebauthnToken(env, u.id, keys, b.userVerificationToken);
  await disableTwoFactor(env, u, TF_WEBAUTHN);
  return json(webauthnState([]));
}));
route("DELETE", "/api/two-factor/webauthn", authed(async (env, req, u) => {
  const b = await req.json<any>();
  const keys = await webauthnKeys(env, u.id);
  await checkWebauthnToken(env, u.id, keys, b.userVerificationToken);
  const next = keys.filter((k) => k.id !== Number(b.id));
  if (next.length === keys.length) throw new HttpError(400, "WebAuthn key not found");
  if (next.length) await saveWebauthnKeys(env, u.id, next);
  else await disableTwoFactor(env, u, TF_WEBAUTHN);
  return json(webauthnState(next));
}));
// Email two-step login. The web vault reads `enabled` and `email` at the top level.
route("POST", "/api/two-factor/get-email", authed(async (env, req, u) => {
  if (!mailEnabled(env)) throw new HttpError(400, "Email two-step login isn't available on this server.");
  await verifySecret(u, await req.json<any>());
  const tf = await emailTwoFactor(env, u.id);
  return json({ enabled: !!tf, email: tf?.email ?? null, object: "twoFactorEmail", userVerificationToken: await emailToken(env, u.id, tf?.email ?? null) });
}));
route("POST", "/api/two-factor/send-email", authed(async (env, req, u) => {
  const b = await req.json<any>();
  const email = String(b.email ?? "").trim().toLowerCase();
  if (!email.includes("@")) throw new HttpError(400, "Invalid email address");
  await checkEmailSetup(env, u, b, null);
  const pending = await emailRow(env, u.id, TF_EMAIL_SETUP);
  await mailCode(env, u.id, TF_EMAIL_SETUP, { ...(pending?.email === email ? pending : {}), email }, false, "to turn on email two-step login");
  return empty();
}));
route("PUT", "/api/two-factor/email", authed(async (env, req, u) => {
  const b = await req.json<any>();
  const email = String(b.email ?? "").trim().toLowerCase();
  await checkEmailSetup(env, u, b, null);
  const pending = await emailRow(env, u.id, TF_EMAIL_SETUP);
  if (!pending || pending.email !== email) throw new HttpError(400, "Send a code to this address first");
  if (!(await checkEmailCode(env, u.id, TF_EMAIL_SETUP, String(b.token ?? ""), false))) throw new HttpError(400, "Invalid or expired code");
  await env.DB.prepare("DELETE FROM twofactors WHERE user_id = ? AND type = ?").bind(u.id, TF_EMAIL_SETUP).run();
  await putEmailRow(env, u.id, TF_EMAIL, { email }, true);
  if (!u.totp_recover) {
    await env.DB.prepare("UPDATE users SET totp_recover = ? WHERE id = ?").bind(base32Encode(crypto.getRandomValues(new Uint8Array(20))), u.id).run();
  }
  await notify(env, u, "Email added to two-step login", `Codes sent to ${email} now work as a second step when you log in.`);
  return json({ enabled: true, email, object: "twoFactorEmail" });
}));
route("DELETE", "/api/two-factor/email", authed(async (env, req, u) => {
  const b = await req.json<any>();
  await checkEmailSetup(env, u, b, (await emailTwoFactor(env, u.id))?.email ?? null);
  await disableTwoFactor(env, u, TF_EMAIL);
  return json({ enabled: false, email: null, object: "twoFactorEmail" });
}));
// The login screen asks for a code once the password checked out.
route("POST", "/api/two-factor/send-email-login", async (env, req) => {
  const b = await req.json<any>();
  const user = b.email ? await userByEmail(env, String(b.email)) : null;
  const pwOk = user && b.masterPasswordHash &&
    timingSafeEqual(await hashPassword(String(b.masterPasswordHash), user.password_salt, user.password_iterations), user.password_hash);
  if (!user || !pwOk) throw new HttpError(400, "Username or password is incorrect. Try again");
  const tf = await emailTwoFactor(env, user.id);
  if (!tf) throw new HttpError(400, "Email two-step login isn't on for this account");
  await mailCode(env, user.id, TF_EMAIL, tf, true, "to log in to your vault");
  return empty();
});

// Password hint, by email. The answer is the same whether or not the account exists.
route("POST", "/api/accounts/password-hint", async (env, req) => {
  const b = await req.json<any>().catch(() => ({}));
  const user = b.email ? await userByEmail(env, String(b.email)) : null;
  if (user && mailEnabled(env)) {
    const text = user.password_hint
      ? `You asked for the hint to your vault's master password:\n\n    ${user.password_hint}\n`
      : "You asked for your master password hint, but none is set for this vault.\n";
    try { await sendMail(env, user.email, "Your master password hint", text); } catch (e) { console.error("hint not sent:", e); }
  }
  return empty();
});

// Providers this server doesn't offer: say so, instead of a 404 the web vault shows as a generic error.
for (const [name, paths] of [
  ["Duo", ["get-duo", "duo"]],
  ["YubiKey OTP", ["get-yubikey", "yubikey"]],
] as const) {
  for (const p of paths) {
    for (const m of ["POST", "PUT", "DELETE"]) {
      route(m, `/api/two-factor/${p}`, async () => {
        throw new HttpError(400, `${name} two-step login isn't available on this server. Use an authenticator app or a passkey / security key.`);
      });
    }
  }
}
route("POST", "/api/two-factor/get-recover", authed(async (env, req, u) => {
  await verifySecret(u, await req.json<any>());
  return json({ code: u.totp_recover, object: "twoFactorRecover" });
}));

// Master password and KDF changes: the client re-wraps the same user key, so
// vault data stays as is. Rotating the security stamp signs out every session.
function newCredentials(u: User, b: any) {
  const auth = b.authenticationData;
  const unlock = b.unlockData;
  if (auth && unlock) {
    const a = auth.kdf ?? {}, k = unlock.kdf ?? {};
    const same = (a.kdfType ?? a.kdf) === (k.kdfType ?? k.kdf) && (a.iterations ?? a.kdfIterations) === (k.iterations ?? k.kdfIterations) &&
      (a.memory ?? a.kdfMemory ?? null) === (k.memory ?? k.kdfMemory ?? null) && (a.parallelism ?? a.kdfParallelism ?? null) === (k.parallelism ?? k.kdfParallelism ?? null);
    if (!same) throw new HttpError(400, "KDF settings must be equal for authentication and unlock");
    if (String(auth.salt).toLowerCase() !== u.email || String(unlock.salt).toLowerCase() !== u.email) throw new HttpError(400, "Invalid master password salt");
    return {
      hash: String(auth.masterPasswordAuthenticationHash),
      key: String(unlock.masterKeyWrappedUserKey),
      kdf: { kdf: k.kdfType ?? k.kdf, iterations: k.iterations ?? k.kdfIterations, memory: k.memory ?? k.kdfMemory ?? null, parallelism: k.parallelism ?? k.kdfParallelism ?? null },
    };
  }
  if (b.newMasterPasswordHash && b.key) {
    return { hash: String(b.newMasterPasswordHash), key: String(b.key), kdf: null };
  }
  throw new HttpError(400, "Invalid request");
}
function checkKdf(k: { kdf: number; iterations: number; memory: number | null; parallelism: number | null }) {
  if (k.kdf === 0 && !(k.iterations >= 100_000)) throw new HttpError(400, "PBKDF2 KDF iterations must be at least 100000");
  if (k.kdf === 1) {
    if (!(k.iterations >= 1)) throw new HttpError(400, "Argon2 KDF iterations must be at least 1");
    if (!(k.memory !== null && k.memory >= 15 && k.memory <= 1024)) throw new HttpError(400, "Argon2 memory must be between 15 MB and 1024 MB");
    if (!(k.parallelism !== null && k.parallelism >= 1 && k.parallelism <= 16)) throw new HttpError(400, "Argon2 parallelism must be between 1 and 16");
  } else if (k.kdf !== 0) {
    throw new HttpError(400, "Unknown KDF type");
  }
}
async function savePassword(env: Env, u: User, hash: string, key: string, hint: string | null | undefined, kdf: any) {
  const salt = randomToken(16);
  const k = kdf ?? { kdf: u.kdf, iterations: u.kdf_iterations, memory: u.kdf_memory, parallelism: u.kdf_parallelism };
  checkKdf(k);
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, akey = ?, password_hint = ?, kdf = ?,
         kdf_iterations = ?, kdf_memory = ?, kdf_parallelism = ?, security_stamp = ?, updated_at = ?, revision_date = ? WHERE id = ?`,
    ).bind(await hashPassword(hash, salt), salt, SERVER_PBKDF2_ITERATIONS, key, hint === undefined ? u.password_hint : hint, k.kdf, k.iterations,
      k.memory, k.parallelism, uuid(), nowIso(), Date.now(), u.id),
    env.DB.prepare("DELETE FROM devices WHERE user_id = ?").bind(u.id),
  ]);
}
route("POST", "/api/accounts/password", authed(async (env, req, u) => {
  const b = await req.json<any>();
  await verifySecret(u, b);
  const c = newCredentials(u, b);
  await savePassword(env, u, c.hash, c.key, b.masterPasswordHint ?? null, c.kdf);
  await notify(env, u, "Your master password was changed", "The master password of your vault was changed. Every device was signed out.");
  return empty();
}));
route("POST", "/api/accounts/kdf", authed(async (env, req, u) => {
  const b = await req.json<any>();
  await verifySecret(u, b);
  const c = newCredentials(u, b);
  if (!c.kdf) throw new HttpError(400, "Missing KDF settings");
  await savePassword(env, u, c.hash, c.key, undefined, c.kdf);
  return empty();
}));

// Website icons: fetched from the site itself and cached at the edge.
route("GET", "/icons/:domain/icon.png", async (env, req, [domain]) => {
  const host = domain.toLowerCase();
  // Public host names only: no IPs, localhost or single-label names.
  if (!/^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host) || /^\d+(\.\d+)+$/.test(host) || host.endsWith(".local") || host.endsWith(".internal")) {
    return new Response(null, { status: 404 });
  }
  const cache = (caches as any).default as Cache;
  const cacheKey = new Request(`https://icons.vault-worker.invalid/${host}`);
  const hit = await cache.match(cacheKey);
  if (hit) return hit;
  for (const url of [`https://${host}/favicon.ico`, `https://www.${host}/favicon.ico`]) {
    try {
      const r = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(4000), headers: { "User-Agent": "Mozilla/5.0 vault-worker icon fetch" } });
      const type = r.headers.get("Content-Type") ?? "";
      if (!r.ok || !/^image\//.test(type)) continue;
      const body = await r.arrayBuffer();
      if (!body.byteLength || body.byteLength > 512 * 1024) continue;
      const res = new Response(body, { headers: { "Content-Type": type, "Cache-Control": "public, max-age=604800" } });
      await cache.put(cacheKey, res.clone());
      return res;
    } catch {
      // try the next candidate
    }
  }
  return new Response(null, { status: 404, headers: { "Cache-Control": "public, max-age=86400" } });
});

// Settings and features this server doesn't have: answer with empty data so clients carry on.
route("GET", "/api/settings/domains", authed(async (env, req, u) =>
  json({ equivalentDomains: JSON.parse(u.equivalent_domains), globalEquivalentDomains: [], object: "domains" })));
for (const m of ["PUT", "POST"]) {
  route(m, "/api/settings/domains", authed(async (env, req, u) => {
    const b = await req.json<any>();
    const eq = JSON.stringify(b.equivalentDomains ?? []);
    await env.DB.prepare("UPDATE users SET equivalent_domains = ? WHERE id = ?").bind(eq, u.id).run();
    await touchUser(env, u.id);
    return json({ equivalentDomains: JSON.parse(eq), globalEquivalentDomains: [], object: "domains" });
  }));
}
for (const p of ["/api/tasks", "/api/auth-requests", "/api/auth-requests/pending", "/api/collections", "/api/emergency-access/trusted", "/api/emergency-access/granted", "/api/webauthn"]) {
  route("GET", p, authed(async () => json(list([]))));
}
route("GET", "/api/organizations/connections/enabled", async () => json(false));

// ---------------------------------------------------------------- entry

// The desktop app and browser extension call from their own origins.
function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin");
  if (!origin) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": req.headers.get("Access-Control-Request-Headers") ?? "*",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

async function handle(env: Env, req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/{2,}/g, "/");
  if (req.method === "OPTIONS") return new Response(null, { status: 204 });

  let methodMismatch = false;
  for (const [method, re, h] of routes) {
    const m = re.exec(path);
    if (!m) continue;
    if (method !== req.method) { methodMismatch = true; continue; }
    try {
      return await h(env, req, m.slice(1).map(decodeURIComponent));
    } catch (e) {
      if (e instanceof HttpError) return json(errorBody(e.message, e.extra), e.status);
      if (e instanceof SyntaxError) return json(errorBody("Invalid JSON"), 400);
      console.error(e);
      return json(errorBody("Internal error"), 500);
    }
  }
  if (path.startsWith("/notifications/")) return new Response(null, { status: 404 });
  console.warn(`unhandled ${req.method} ${path}`);
  return json({ error: { code: methodMismatch ? 405 : 404, reason: "Not Found" } }, methodMismatch ? 405 : 404);
}

// ---------------------------------------------------------------- daily cleanup (Cron Trigger)

const TRASH_DAYS = 30;
const CLEANUP_BATCH = 500; // rows per step and run, to stay well inside one invocation's limits

// Trash older than 30 days, expired Sends, upload slots that never got a file,
// and R2 objects nothing refers to any more.
async function cleanup(env: Env) {
  const now = Date.now();
  const grace = Number(env.CLEANUP_GRACE_SECONDS ?? 3600) * 1000;
  const counts = { trash: 0, sends: 0, slots: 0, orphans: 0 };

  const trashCutoff = new Date(now - TRASH_DAYS * 86400_000).toISOString();
  const { results: old } = await env.DB.prepare("SELECT id, user_id FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ? LIMIT ?")
    .bind(trashCutoff, CLEANUP_BATCH).all<{ id: string; user_id: string }>();
  const byUser = new Map<string, string[]>();
  for (const c of old) byUser.set(c.user_id, [...(byUser.get(c.user_id) ?? []), c.id]);
  for (const [userId, ids] of byUser) {
    await deleteAttachmentsOf(env, userId, ids);
    for (const id of ids) await env.DB.prepare("DELETE FROM ciphers WHERE id = ? AND user_id = ?").bind(id, userId).run();
    await touchUser(env, userId);
    counts.trash += ids.length;
  }

  const { results: expired } = await env.DB.prepare("SELECT * FROM sends WHERE deletion_date < ? LIMIT ?")
    .bind(new Date(now).toISOString(), CLEANUP_BATCH).all<SendRow>();
  for (const s of expired) {
    await deleteSend(env, s);
    await touchUser(env, s.user_id);
    counts.sends++;
  }

  const slotCutoff = new Date(now - Math.max(grace, 86400_000)).toISOString();
  const { results: slots } = await env.DB.prepare(
    "SELECT * FROM attachments WHERE uploaded = 0 AND (created_at IS NULL OR created_at < ?) LIMIT ?",
  ).bind(slotCutoff, CLEANUP_BATCH).all<AttachmentRow>();
  for (const a of slots) {
    await env.FILES.delete(`attachments/${a.cipher_id}/${a.id}`);
    await env.DB.prepare("DELETE FROM attachments WHERE id = ?").bind(a.id).run();
    counts.slots++;
  }

  // Orphans: walk the bucket and keep only keys a row still points at. The grace
  // period protects uploads that are written to R2 just before their row.
  let cursor: string | undefined;
  do {
    const page = await env.FILES.list({ cursor, limit: 1000 });
    const dead: string[] = [];
    for (const obj of page.objects) {
      if (now - obj.uploaded.getTime() < grace) continue;
      const [kind, parent, id] = obj.key.split("/");
      let alive = false;
      if (kind === "attachments" && parent && id) {
        alive = !!(await env.DB.prepare("SELECT 1 FROM attachments WHERE id = ? AND cipher_id = ?").bind(id, parent).first());
      } else if (kind === "sends" && parent && id) {
        const s = await env.DB.prepare("SELECT data FROM sends WHERE id = ? AND type = ?").bind(parent, SEND_FILE).first<{ data: string }>();
        alive = !!s && JSON.parse(s.data)?.id === id;
      }
      if (!alive) dead.push(obj.key);
    }
    if (dead.length) await env.FILES.delete(dead);
    counts.orphans += dead.length;
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);

  console.log(`cleanup: ${counts.trash} trashed items, ${counts.sends} expired sends, ${counts.slots} abandoned uploads, ${counts.orphans} orphaned files removed`);
  return counts;
}

export default {
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(cleanup(env));
  },

  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const isApi = /^\/(api|identity|notifications|icons|attachments)(\/|$)|^\/alive$/.test(url.pathname);
    if (!isApi) return env.ASSETS.fetch(req);
    if (!env.JWT_SECRET) return json(errorBody("JWT_SECRET is not set (.dev.vars)"), 500);
    const res = await handle(env, req);
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(corsHeaders(req))) out.headers.set(k, v);
    out.headers.set("Cache-Control", "no-store");
    return out;
  },
} satisfies ExportedHandler<Env>;
