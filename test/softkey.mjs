// A software WebAuthn authenticator (ES256), standing in for a security key in tests:
// answers registration and login ceremonies the way a browser + key would.

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
const b64u = (b) => Buffer.from(b).toString("base64url");
const sha256 = async (d) => new Uint8Array(await subtle.digest("SHA-256", typeof d === "string" ? enc.encode(d) : d));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// Just enough CBOR to write attestation objects and COSE keys.
function cbor(v) {
  const head = (major, n) => {
    if (n < 24) return Uint8Array.of((major << 5) | n);
    if (n < 256) return Uint8Array.of((major << 5) | 24, n);
    if (n < 65536) return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
    return Uint8Array.of((major << 5) | 26, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255);
  };
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const b = enc.encode(v); return concat(head(3, b.length), b); }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (v instanceof Map) return concat(head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)]));
  throw new Error("cbor: unsupported value");
}

// r||s from WebCrypto -> DER, as authenticators send it.
function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = concat(Uint8Array.of(0), v);
    return concat(Uint8Array.of(2, v.length), v);
  };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

export async function createSoftKey() {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await subtle.exportKey("jwk", pair.publicKey);
  const credentialId = crypto.getRandomValues(new Uint8Array(16));
  let counter = 0;
  const key = {
    credentialId: b64u(credentialId),
    jwk,
    get counter() { return counter; },
    set counter(v) { counter = v; },
    useCounter: false, // passkeys send 0; security keys count up

    // Answer to navigator.credentials.create(), shaped like the Bitwarden clients send it.
    async register(options, origin) {
      const clientData = enc.encode(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin, crossOrigin: false }));
      const bytes = (s) => Uint8Array.from(Buffer.from(s, "base64url"));
      const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, bytes(jwk.x)], [-3, bytes(jwk.y)]]); // EC2, ES256, P-256
      const authData = concat(await sha256(options.rp.id), Uint8Array.of(0x41), Uint8Array.of(0, 0, 0, 0), new Uint8Array(16),
        Uint8Array.of(credentialId.length >> 8, credentialId.length & 255), credentialId, cbor(cose));
      const att = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
      // The web vault's encoding: standard base64, "AttestationObject", and rawId = btoa(id).
      const b64 = (b) => Buffer.from(b).toString("base64");
      return { id: b64u(credentialId), rawId: btoa(b64u(credentialId)), type: "public-key", extensions: {}, response: { AttestationObject: b64(att), clientDataJson: b64(clientData) } };
    },

    // Answer to navigator.credentials.get(), as the JSON string sent in two_factor_token.
    async assert(options, origin, { rpId = options.rpId, tamper = false, counterOverride } = {}) {
      if (key.useCounter) counter++;
      const c = counterOverride ?? counter;
      const clientData = enc.encode(JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin, crossOrigin: false }));
      const authData = concat(await sha256(rpId), Uint8Array.of(0x01), Uint8Array.of(c >>> 24, (c >> 16) & 255, (c >> 8) & 255, c & 255));
      const raw = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, concat(authData, await sha256(clientData))));
      if (tamper) raw[10] ^= 1;
      return JSON.stringify({
        id: b64u(credentialId), rawId: b64u(credentialId), type: "public-key", extensions: {},
        response: { authenticatorData: b64u(authData), clientDataJson: b64u(clientData), signature: b64u(rawToDer(raw)), userHandle: null },
      });
    },
  };
  return key;
}
