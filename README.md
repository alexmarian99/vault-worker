# vault-worker

A self-hosted, Bitwarden-compatible password manager server that runs entirely on Cloudflare:
**Workers** for the API, **D1** for the database, **R2** for attachments and Send files, and the
official Bitwarden **web vault** served as static assets. No VM, no container, no database server to
look after, and for one person or a family it costs roughly nothing beyond the $5 Workers plan.

The official Bitwarden apps (browser extension, desktop, mobile, CLI) connect to it as a
self-hosted server. Everything in a vault is encrypted on your devices before it reaches the server;
the server only ever stores ciphertext.

> **Unofficial.** This project is not associated with Bitwarden Inc. or with Vaultwarden. It uses
> Vaultwarden's API behaviour as a reference. Run it for yourself and the people you trust, and
> keep backups (see [Backups](#backups)).

## Features

- Accounts, password login, refresh tokens, sync, profile
- Items: logins (passkeys included), secure notes, cards, identities, SSH keys; folders, favourites,
  trash and restore, archive, import
- Attachments (R2), downloaded through short-lived signed links
- Send: text and file, password, access limit, expiry and deletion date
- Two-step login: authenticator app (TOTP), passkeys / security keys (WebAuthn: ES256, RS256,
  EdDSA, with clone detection), email codes, "remember this device", recovery code
- Master password and KDF changes
- Email (optional, through Cloudflare Email Routing): 2FA codes, new-device login alerts, the
  master password hint, security notices
- Website icons, fetched from public sites only
- Daily cleanup (Cron Trigger): old trash, expired Sends, abandoned uploads, orphaned files
- A migration tool from **Vaultwarden** that keeps master passwords and 2FA working

**Not implemented:** organizations and sharing, emergency access, key rotation, push
notifications (the apps fall back to periodic sync), log in with passkey instead of the master
password, Duo and YubiKey OTP.

## What it costs

| | |
|---|---|
| Workers Paid plan | **$5/month**, recommended: password checks (PBKDF2) need more CPU than the free plan's 10 ms per request |
| D1, R2, static assets, Cron | within the amounts the plans include, for personal use |
| Email Routing | free |

## Requirements

- A Cloudflare account with **Workers Paid**, and **R2** enabled (Dashboard → R2)
- A domain on Cloudflare: passkeys (WebAuthn) and email need a real host name
- Node.js 24+ and Python 3.12+ on the machine you deploy from

## Deploy

```sh
git clone <this repository> vault-worker && cd vault-worker
npm install
npm run setup:webvault                  # downloads the web vault (checksum-pinned) into public/ and adapts it
cp wrangler.example.jsonc wrangler.jsonc
npx wrangler login
npx wrangler d1 create vault            # copy the database_id it prints
npx wrangler r2 bucket create vault-files
```

Edit **`wrangler.jsonc`** (it stays out of git):

| Setting | Value |
|---|---|
| `database_id` (both places) | the id from `d1 create` |
| `routes[0].pattern` | your vault's host name, e.g. `vault.example.com` (no DNS record may exist for it yet) |
| `WEBAUTHN_ORIGIN` | `https://` + that host name. Passkeys are bound to it, so don't change it later |
| `MAIL_FROM` | an address on a domain with Email Routing, e.g. `vault@example.com` (or remove `MAIL_FROM` and `send_email` to run without email) |
| `allowed_destination_addresses` | your own address(es), verified in Email Routing → Destination addresses |

Then:

```sh
npm run migrate:remote                                   # creates the tables in D1
node -e "process.stdout.write(require('crypto').randomBytes(32).toString('base64url'))" | npx wrangler secret put JWT_SECRET
npm run deploy
```

### Create your account

New accounts are refused by default (`SIGNUPS_ALLOWED: "false"`). For your first account:

1. Set `"SIGNUPS_ALLOWED": "true"` in `wrangler.jsonc` and `npm run deploy`.
2. Open `https://<your host>`, create the account(s) you need.
3. Set it back to `"false"` and `npm run deploy` again.

### Connect the apps

In any Bitwarden app, before logging in: **Region / Logging in on → Self-hosted → Server URL**:
`https://<your host>`. Then log in as usual.

## Moving from Vaultwarden

Copy Vaultwarden's data folder (with `db.sqlite3`, and `attachments/`, `sends/` if you have them),
then:

```sh
python -I tools/import_vaultwarden.py <data folder>                 # dry run: what would move
python -I tools/import_vaultwarden.py <data folder> --apply remote  # into your deployed D1 and R2
```

Master passwords keep working: the server-side hash moves with Vaultwarden's round count and is
re-hashed at the first login. Items (with passkeys), folders, favourites, attachments, Sends,
authenticator-app and WebAuthn 2FA and recovery codes move; WebAuthn keys keep working only if the
vault stays on the same domain. Organizations and devices don't move (everyone logs in again).
The generated `import.sql` holds password hashes and keys: delete it afterwards.

## Backups

D1 keeps point-in-time history (Time Travel, see the Cloudflare docs for how far back on your plan).
For your own copies:

```sh
npx wrangler d1 export vault --remote --output vault-backup.sql
```

Attachments and Send files live in the `vault-files` R2 bucket. Keep exports somewhere safe: they
are encrypted vault data, but they also contain password hashes and 2FA secrets.

## Updating

```sh
git pull && npm install
npm run migrate:remote && npm run deploy
```

Changing `JWT_SECRET` signs everyone out. The web vault version is pinned in
`tools/fetch_webvault.py`; newer versions can change what they expect from the server, so update it
together with the server code.

## Local development

```sh
npm run setup:webvault
cp wrangler.example.jsonc wrangler.jsonc        # the "dev" environment works with the placeholders
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('base64url'))" > .dev.vars
npm run migrate                                  # local D1 in .wrangler/state
npm run dev                                      # https://127.0.0.1:8787, self-signed certificate
```

`npm run dev` uses the `dev` environment: sign-ups open, WebAuthn and links from the request's own
origin, email written to files instead of sent. Test passkeys in a browser at
`https://localhost:8787` (browsers refuse WebAuthn on an IP address).

### Tests

With `npm run dev` running:

| | |
|---|---|
| `npm test` | end to end with the official Bitwarden CLI: login, items, attachments, Send, TOTP, password change, icons, isolation between users |
| `npm run test:webauthn` | security keys with a software authenticator, including forged, replayed and cloned-key cases |
| `npm run test:email` | email 2FA, hint and notices, reading the messages wrangler dev writes |
| `npm run test:import` | the Vaultwarden migration on a synthetic database |
| `npm run test:pbkdf2` | the JavaScript PBKDF2 (used above WebCrypto's 100000-round limit) against Node's |
| `npm run check` | TypeScript |

The cleanup job: `npm run dev:cron` (scheduled handler exposed, no grace period), then
`npm run test:cleanup`.

## How it fits together

- `src/index.ts`: the API (identity, accounts, sync, ciphers, folders, attachments, Send, 2FA,
  email, icons) and the daily cleanup; `src/pbkdf2.ts`: PBKDF2 for imported hashes
- `migrations/`: the D1 schema
- `public/`: the web vault (downloaded, not in git); `tools/patch_webvault.py` builds its
  `css/vaultwarden.css` from Vaultwarden's template and adjusts a few strings
- `tools/import_vaultwarden.py`: the migration tool

## Credits and license

- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (AGPL-3.0): the reference for the API,
  and the source of `tools/vaultwarden.scss.hbs`.
- [Bitwarden clients](https://github.com/bitwarden/clients) (GPL-3.0): the web vault, in
  [Vaultwarden's build](https://github.com/dani-garcia/bw_web_builds), downloaded at setup.

This project is licensed under the **GNU Affero General Public License v3.0 or later**: see
[LICENSE](LICENSE). Bitwarden is a trademark of Bitwarden Inc.
