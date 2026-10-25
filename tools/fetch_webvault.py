"""Download the Bitwarden web vault (Vaultwarden's build, dani-garcia/bw_web_builds) into public/
and adapt it to this server (tools/patch_webvault.py).

The archive is checked against a pinned SHA-256 before anything is extracted. To move to a
newer web vault, update VERSION and SHA256 from the release's sha256sums.txt, then re-run the
tests: the web vault's API expectations can change between versions.

Usage: python -I tools/fetch_webvault.py
"""

import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "2026.7.0"
SHA256 = "002e972bf0d0487ec0324b06d916de33e29de4c29bffd92ee3b843084c300570"
URL = f"https://github.com/dani-garcia/bw_web_builds/releases/download/v{VERSION}/bw_web_v{VERSION}.tar.gz"

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"


def main():
    tmp = Path(tempfile.mkdtemp(prefix="webvault-"))
    archive = tmp / "web.tar.gz"
    print(f"downloading web vault {VERSION} ...")
    with urllib.request.urlopen(URL, timeout=120) as r, open(archive, "wb") as f:
        shutil.copyfileobj(r, f)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != SHA256:
        shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(f"checksum mismatch: expected {SHA256}, got {digest}; nothing was changed")

    out = tmp / "x"
    with tarfile.open(archive) as t:
        members = [m for m in t.getmembers() if not m.name.endswith(".map")]  # source maps: not needed
        t.extractall(out, members=members, filter="data")  # "data": no links out, no absolute paths
    src = out / "web-vault"
    if not (src / "index.html").exists():
        sys.exit("unexpected archive layout (no web-vault/index.html)")

    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    shutil.move(str(src), PUBLIC)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"web vault {VERSION} in {PUBLIC.relative_to(ROOT)}/ ({sum(1 for p in PUBLIC.rglob('*') if p.is_file())} files)")

    subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "patch_webvault.py")], check=True)


if __name__ == "__main__":
    main()
