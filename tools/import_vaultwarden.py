"""Copy a Vaultwarden database into vault-worker's D1 database (and its files into R2).

Everything in a vault is encrypted by the Bitwarden clients, so rows move as they are and
users keep their master password. The server-side password hash moves too, with
Vaultwarden's PBKDF2 round count, so logins verify without anyone re-registering.

Moved:   users, ciphers (with folders, favourites, archive state), folders, attachments,
         sends, authenticator-app (TOTP) and WebAuthn 2FA, and the 2FA recovery code.
         WebAuthn keys keep working only if the vault stays on the same domain.
Skipped: organizations and their items, devices (everyone logs in again), email, Duo and
         YubiKey 2FA, emergency access, events.

Usage:
  python -I tools/import_vaultwarden.py <vaultwarden data dir> [--apply local|remote] [--out import.sql]

Without --apply it only writes the SQL file and prints what it would upload. Secrets are
never printed. Existing accounts with the same email are not touched: the import stops.
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from base64 import urlsafe_b64encode
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WRANGLER = ROOT / "node_modules" / "wrangler" / "bin" / "wrangler.js"
TF_AUTHENTICATOR = 0
TF_WEBAUTHN = 7
TF_NAMES = {1: "email", 2: "Duo", 3: "YubiKey", 4: "U2F", 6: "organization Duo"}
# webauthn-rs COSE algorithm names -> COSE numbers
WEBAUTHN_ALGS = {"ES256": -7, "RS256": -257, "EDDSA": -8}


def convert_webauthn(data):
    """Vaultwarden keeps webauthn-rs `Passkey` structs; turn each into {credentialId, alg, jwk, ...}."""
    keys, skipped = [], 0
    for reg in json.loads(data):
        cred = reg["credential"]["cred"]
        alg = WEBAUTHN_ALGS.get(str(cred["cred"].get("type_", "")).upper())
        key = cred["cred"]["key"]
        jwk = None
        if alg == -7 and "EC_EC2" in key and key["EC_EC2"].get("curve") == "SECP256R1":
            jwk = {"kty": "EC", "crv": "P-256", "x": key["EC_EC2"]["x"], "y": key["EC_EC2"]["y"]}
        elif alg == -257 and "RSA" in key:
            jwk = {"kty": "RSA", "n": key["RSA"]["n"], "e": key["RSA"]["e"]}
        elif alg == -8 and "EC_OKP" in key and str(key["EC_OKP"].get("curve", "")).upper() == "ED25519":
            jwk = {"kty": "OKP", "crv": "Ed25519", "x": key["EC_OKP"]["x"]}
        if jwk is None:
            skipped += 1
            continue
        keys.append({
            "id": reg["id"], "name": reg["name"], "credentialId": cred["cred_id"].rstrip("="), "alg": alg, "jwk": jwk,
            "counter": cred.get("counter", 0), "backupEligible": bool(cred.get("backup_eligible")),
            "backupState": bool(cred.get("backup_state")), "migrated": bool(reg.get("migrated")),
        })
    return keys, skipped


def b64url(b):
    return None if b is None else urlsafe_b64encode(bytes(b)).decode().rstrip("=")


def iso(ts):
    """Vaultwarden keeps naive UTC text like '2026-10-19 19:33:25.494692428'."""
    if ts is None:
        return None
    s = str(ts).replace("T", " ").rstrip("Z")
    date, _, frac = s.partition(".")
    dt = datetime.strptime(date, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    ms = int((frac + "000")[:3]) if frac else 0
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


def lower_keys(v):
    """Vaultwarden lowercases the first letter of every key on output; do the same once here."""
    if isinstance(v, dict):
        return {(k[:1].lower() + k[1:]): lower_keys(x) for k, x in v.items()}
    if isinstance(v, list):
        return [lower_keys(x) for x in v]
    return v


def json_or_none(text, fix=None):
    if text is None:
        return None
    v = lower_keys(json.loads(text))
    if fix:
        v = fix(v)
    return json.dumps(v, separators=(",", ":"))


def fix_fields(fields):
    # Some clients break on a string field type.
    for f in fields or []:
        if isinstance(f, dict) and isinstance(f.get("type"), str):
            f["type"] = int(f["type"]) if f["type"].isdigit() else 1
    return fields


def sql_value(v):
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def insert(table, row):
    cols = ", ".join(row)
    vals = ", ".join(sql_value(v) for v in row.values())
    return f"INSERT INTO {table} ({cols}) VALUES ({vals});"


def has_table(db, name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def wrangler(*args):
    return subprocess.run(["node", str(WRANGLER), *args], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env={**os.environ, "CI": "1"}).stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data_dir", help="Vaultwarden data folder (db.sqlite3, attachments/, sends/)")
    ap.add_argument("--apply", choices=["local", "remote"])
    ap.add_argument("--out", default=str(ROOT / "import.sql"))
    a = ap.parse_args()

    data = Path(a.data_dir)
    src = data / "db.sqlite3"
    if not src.exists():
        sys.exit(f"no db.sqlite3 in {data}")

    # Read a copy, so the WAL is folded in and the original stays untouched.
    tmp = Path(tempfile.mkdtemp(prefix="vw-import-"))
    for ext in ("", "-wal", "-shm"):
        if (data / f"db.sqlite3{ext}").exists():
            shutil.copy(data / f"db.sqlite3{ext}", tmp / f"db.sqlite3{ext}")
    db = sqlite3.connect(tmp / "db.sqlite3")
    db.row_factory = sqlite3.Row

    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    stmts, files, notes = [], [], []

    users = db.execute("SELECT * FROM users").fetchall()
    for u in users:
        if not u["enabled"]:
            notes.append(f"skipped a disabled user")
            continue
        if u["password_hash"] is None or len(u["password_hash"]) == 0:
            notes.append("skipped an invited user without a password")
            continue
        stmts.append(insert("users", {
            "id": u["uuid"],
            "email": u["email"].strip().lower(),
            "name": u["name"],
            "password_hash": b64url(u["password_hash"]),
            "password_salt": b64url(u["salt"]),
            "password_iterations": u["password_iterations"],
            "password_hint": u["password_hint"],
            "akey": u["akey"],
            "private_key": u["private_key"],
            "public_key": u["public_key"],
            "kdf": u["client_kdf_type"],
            "kdf_iterations": u["client_kdf_iter"],
            "kdf_memory": u["client_kdf_memory"],
            "kdf_parallelism": u["client_kdf_parallelism"],
            "security_stamp": u["security_stamp"],
            "avatar_color": u["avatar_color"],
            "equivalent_domains": u["equivalent_domains"] or "[]",
            "created_at": iso(u["created_at"]),
            "updated_at": iso(u["updated_at"]),
            "revision_date": now_ms,
            "key_id": u["key_id"] if "key_id" in u.keys() else None,
            "totp_recover": u["totp_recover"],
        }))
    user_ids = {u["uuid"] for u in users if u["enabled"] and u["password_hash"]}

    folders = [f for f in db.execute("SELECT * FROM folders").fetchall() if f["user_uuid"] in user_ids]
    for f in folders:
        stmts.append(insert("folders", {"id": f["uuid"], "user_id": f["user_uuid"], "name": f["name"], "updated_at": iso(f["updated_at"])}))
    folder_owner = {f["uuid"]: f["user_uuid"] for f in folders}

    folder_of = {}
    for r in db.execute("SELECT * FROM folders_ciphers"):
        folder_of[r["cipher_uuid"]] = r["folder_uuid"]
    favorites = {(r["user_uuid"], r["cipher_uuid"]) for r in db.execute("SELECT * FROM favorites")}
    archived = {}
    if has_table(db, "archives"):
        cols = [c[1] for c in db.execute("PRAGMA table_info(archives)")]
        if {"user_uuid", "cipher_uuid", "archived_at"} <= set(cols):
            for r in db.execute("SELECT user_uuid, cipher_uuid, archived_at FROM archives"):
                archived[(r[0], r[1])] = iso(r[2])

    org_items = 0
    cipher_ids = set()
    for c in db.execute("SELECT * FROM ciphers").fetchall():
        if c["organization_uuid"] or c["user_uuid"] not in user_ids:
            org_items += 1
            continue
        owner = c["user_uuid"]
        folder = folder_of.get(c["uuid"])
        stmts.append(insert("ciphers", {
            "id": c["uuid"],
            "user_id": owner,
            "folder_id": folder if folder_owner.get(folder) == owner else None,
            "type": c["atype"],
            "name": c["name"],
            "notes": c["notes"],
            "key": c["key"],
            "reprompt": 1 if c["reprompt"] == 1 else 0,
            "favorite": 1 if (owner, c["uuid"]) in favorites else 0,
            "data": json_or_none(c["data"]) or "null",
            "fields": json_or_none(c["fields"], fix_fields),
            "password_history": json_or_none(c["password_history"]),
            "created_at": iso(c["created_at"]),
            "updated_at": iso(c["updated_at"]),
            "deleted_at": iso(c["deleted_at"]),
            "archived_at": archived.get((owner, c["uuid"])),
        }))
        cipher_ids.add((c["uuid"], owner))
    if org_items:
        notes.append(f"skipped {org_items} organization item(s): organizations aren't supported")
    owner_of = dict((cid, uid) for cid, uid in cipher_ids)

    for at in db.execute("SELECT * FROM attachments"):
        owner = owner_of.get(at["cipher_uuid"])
        if not owner:
            continue
        path = data / "attachments" / at["cipher_uuid"] / at["id"]
        if not path.exists():
            notes.append("skipped an attachment whose file is missing from the data folder")
            continue
        stmts.append(insert("attachments", {
            "id": at["id"], "cipher_id": at["cipher_uuid"], "user_id": owner, "file_name": at["file_name"],
            "file_size": at["file_size"], "akey": at["akey"], "uploaded": 1, "created_at": iso(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
        }))
        files.append((f"attachments/{at['cipher_uuid']}/{at['id']}", path))

    for s in db.execute("SELECT * FROM sends"):
        if s["organization_uuid"] or s["user_uuid"] not in user_ids:
            continue
        if s["password_hash"] is not None and s["password_iter"] not in (None, 100000):
            notes.append("skipped a password-protected send with an unexpected PBKDF2 round count")
            continue
        if s["atype"] == 1:
            file_id = json.loads(s["data"]).get("id")
            path = data / "sends" / s["uuid"] / str(file_id)
            if not file_id or not path.exists():
                notes.append("skipped a file send whose file is missing from the data folder")
                continue
            files.append((f"sends/{s['uuid']}/{file_id}", path))
        stmts.append(insert("sends", {
            "id": s["uuid"], "user_id": s["user_uuid"], "type": s["atype"], "name": s["name"], "notes": s["notes"],
            "data": json_or_none(s["data"]), "akey": s["akey"], "password_hash": b64url(s["password_hash"]),
            "password_salt": b64url(s["password_salt"]), "max_access_count": s["max_access_count"],
            "access_count": s["access_count"], "expiration_date": iso(s["expiration_date"]),
            "deletion_date": iso(s["deletion_date"]), "disabled": 1 if s["disabled"] else 0,
            "hide_email": 1 if s["hide_email"] else 0, "emails": None, "revision_date": iso(s["revision_date"]),
        }))

    skipped_2fa = {}
    for t in db.execute("SELECT * FROM twofactor"):
        if t["user_uuid"] not in user_ids or t["atype"] >= 1000:  # >= 1000: pending challenges
            continue
        if t["atype"] == TF_AUTHENTICATOR:
            stmts.append(insert("twofactors", {
                "user_id": t["user_uuid"], "type": TF_AUTHENTICATOR, "data": t["data"],
                "enabled": 1 if t["enabled"] else 0, "last_used": t["last_used"] or 0,
            }))
        elif t["atype"] == TF_WEBAUTHN and t["enabled"]:
            keys, bad = convert_webauthn(t["data"])
            if bad:
                notes.append(f"skipped {bad} WebAuthn key(s) with an unsupported key type")
            if keys:
                stmts.append(insert("twofactors", {
                    "user_id": t["user_uuid"], "type": TF_WEBAUTHN, "data": json.dumps(keys, separators=(",", ":")),
                    "enabled": 1, "last_used": 0,
                }))
                notes.append(f"moved {len(keys)} WebAuthn key(s); they work only on the same domain as before")
        elif t["enabled"]:
            name = TF_NAMES.get(t["atype"], f"type {t['atype']}")
            skipped_2fa[name] = skipped_2fa.get(name, 0) + 1
    for name, n in skipped_2fa.items():
        notes.append(f"skipped {n} {name} 2FA registration(s): not supported here (authenticator-app 2FA still applies)")

    Path(a.out).write_text("\n".join(stmts) + "\n", encoding="utf-8")
    counts = {t: sum(1 for x in stmts if x.startswith(f"INSERT INTO {t} ")) for t in
              ("users", "folders", "ciphers", "attachments", "sends", "twofactors")}
    print("prepared:", ", ".join(f"{n} {t}" for t, n in counts.items()))
    print(f"SQL written to {a.out} (contains password hashes and keys: delete it after importing)")
    for n in notes:
        print("note:", n)

    if not a.apply:
        if files:
            print(f"{len(files)} file(s) would be uploaded to R2")
        return

    flag = f"--{a.apply}"
    # Never merge into an existing account.
    emails = [u["email"].strip().lower() for u in users if u["uuid"] in user_ids]
    for e in emails:
        out = json.loads(wrangler("d1", "execute", "DB", flag, "--json", "--command",
                                  f"SELECT COUNT(*) AS n FROM users WHERE email = {sql_value(e)}"))
        if out[0]["results"][0]["n"]:
            sys.exit("an account with an imported email already exists in the target; nothing was imported")
    wrangler("d1", "execute", "DB", flag, "--file", a.out)
    for key, path in files:
        wrangler("r2", "object", "put", f"vault-files/{key}", "--file", str(path), flag)
    print(f"imported into the {a.apply} database" + (f", {len(files)} file(s) uploaded" if files else ""))
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
