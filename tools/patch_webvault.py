"""Adapt the Vaultwarden build of the Bitwarden web vault (public/) to this server.

1. css/vaultwarden.css: Vaultwarden renders it at runtime from a template; here it's built
   once from tools/vaultwarden.scss.hbs (copied from Vaultwarden) with this server's feature
   set. Without it the login page shows the SSO email field next to the normal one, and
   providers this server lacks (email 2FA, YubiKey OTP, passkey login, emergency access...)
   show up.
2. "Don't ask again on this device for 30 days" -> "Don't ask again on this device":
   remember-me tokens don't expire here (they end when 2FA or the password changes).

Run after replacing public/ with a new web vault build:  python -I tools/patch_webvault.py
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"

# What this server offers, in the template's terms.
FLAGS = {
    "sso_enabled": False,
    "sso_only": False,
    "signup_disabled": True,
    "remember_2fa_disabled": False,
    "mail_2fa_enabled": True,     # sent through Cloudflare Email Routing
    "yubico_enabled": False,
    "webauthn_2fa_supported": True,
    "emergency_access_allowed": False,
    "sends_allowed": True,
    "password_hints_allowed": True,   # the hint goes out by email
    "email_change_allowed": False,
    "load_user_scss": False,
}


def web_version():
    v = json.loads((PUBLIC / "version.json").read_text(encoding="utf-8")).get("version", "0")
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def condition(expr):
    """The template's handful of helper forms: name, (not x), (or a b), (webver "<x.y.z")."""
    expr = expr.strip()
    m = re.fullmatch(r'\(webver "<([\d.]+)"\)', expr)
    if m:
        return web_version() < tuple(int(x) for x in m.group(1).split("."))
    m = re.fullmatch(r"\(not (\w+)\)", expr)
    if m:
        return not FLAGS[m.group(1)]
    m = re.fullmatch(r"\(or (.+)\)", expr)
    if m:
        parts = re.findall(r"\(not \w+\)|\w+", m.group(1))
        return any(condition(p) for p in parts)
    if expr in FLAGS:
        return FLAGS[expr]
    sys.exit(f"unknown template condition: {expr}")


def render(text):
    """Expand {{#if}}/{{#unless}} ... {{else}} ... blocks, innermost first."""
    block = re.compile(r"\{\{#(if|unless) ([^}]+)\}\}((?:(?!\{\{#(?:if|unless) ).)*?)\{\{/\1\}\}", re.S)
    while True:
        m = block.search(text)
        if not m:
            break
        kind, expr, body = m.groups()
        yes, _, no = body.partition("{{else}}")
        take = condition(expr) if kind == "if" else not condition(expr)
        text = text[: m.start()] + (yes if take else no) + text[m.end():]
    text = re.sub(r"\{\{> [^}]+\}\}", "", text)  # the optional user stylesheet: not used
    if "{{" in text:
        sys.exit("template still has unrendered tags")
    return text


def build_css():
    scss = render((ROOT / "tools" / "vaultwarden.scss.hbs").read_text(encoding="utf-8"))
    out = PUBLIC / "css" / "vaultwarden.css"
    out.parent.mkdir(exist_ok=True)
    sass = ROOT / "node_modules" / "sass" / "sass.js"
    css = subprocess.run(["node", str(sass), "--stdin", "--no-source-map", "--style=expanded"], input=scss,
                         capture_output=True, text=True, encoding="utf-8", check=True).stdout
    out.write_text(css, encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)} ({len(css)} bytes)")


def patch_locales():
    old = "Don't ask again on this device for 30 days"
    new = "Don't ask again on this device"
    changed = 0
    for f in sorted((PUBLIC / "locales").glob("*/messages.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        entry = data.get("dontAskAgainOnThisDeviceFor30Days")
        # Only languages that show the English text; translated ones keep theirs.
        if entry and entry.get("message") == old:
            entry["message"] = new
            f.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            changed += 1
    print(f"remember-me text changed in {changed} locale(s)")


if __name__ == "__main__":
    build_css()
    patch_locales()
