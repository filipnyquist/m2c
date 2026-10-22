"""Vendor the web UI's JavaScript dependencies (development only; the UI needs no build step and no Node).

    python scripts/vendor_ui.py          # download the pinned versions, check them, write src/m2c/ui/vendor/
    python scripts/vendor_ui.py --check  # only verify the vendored files against CHECKSUMS

Each npm tarball is checked against the integrity hash pinned below before anything is read from it. Only the
listed files are taken (read in memory, never extracted to disk). Bare `from "preact"` imports become relative
paths, because the UI's CSP (script-src 'self') forbids the inline import map that bare specifiers would need.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

VENDOR = Path(__file__).resolve().parents[1] / "src" / "m2c" / "ui" / "vendor"
PACKAGES = {
    "preact": {
        "version": "10.29.8",
        "integrity": "sha512-ej2aVZ+vZ8WO7tvlQWRM9N63A0KzF9q4mWJfDUHgYaIofWY9hu74QdnQrjoPMmZi2/nZ5gN0bJCQF49xQqx09Q==",
        "files": {"package/dist/preact.module.js": "preact.mjs", "package/hooks/dist/hooks.module.js": "hooks.mjs"},
    },
    "htm": {
        "version": "3.1.1",
        "integrity": "sha512-983Vyg8NwUE7JkZ6NmOqpCZ+sh1bKv2iYTlUkzlWmA5JD2acKoxd4KVxbMmxX/85mtfdnDmTFoNKcg5DGAvxNQ==",
        "files": {"package/dist/htm.module.js": "htm.mjs"},
    },
}
BARE = re.compile(r"""from\s*(["'])preact\1""")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch() -> None:
    VENDOR.mkdir(parents=True, exist_ok=True)
    checksums: dict = {}
    for name, pkg in PACKAGES.items():
        url = f"https://registry.npmjs.org/{name}/-/{name}-{pkg['version']}.tgz"
        with urllib.request.urlopen(url, timeout=60) as res:
            tgz = res.read()
        algo, _, want = pkg["integrity"].partition("-")
        got = base64.b64encode(hashlib.new(algo, tgz).digest()).decode()
        if got != want:
            sys.exit(f"{name}@{pkg['version']}: integrity mismatch ({algo} {got} != {want})")
        with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tar:
            for member, out in pkg["files"].items():
                f = tar.extractfile(member)
                if f is None:
                    sys.exit(f"{name}: {member} missing from the tarball")
                text = BARE.sub('from"./preact.mjs"', f.read().decode("utf-8"))
                text = re.sub(r"\n?//# sourceMappingURL=\S+\s*$", "\n", text)  # the maps aren't vendored
                if re.search(r"""from\s*["'][^./]""", text):
                    sys.exit(f"{name}: {member} still has a bare import")
                data = text.encode("utf-8")
                (VENDOR / out).write_bytes(data)
                checksums[out] = {"package": name, "version": pkg["version"], "integrity": pkg["integrity"], "source": member,
                                  "sha256": _sha256(data)}
    (VENDOR / "CHECKSUMS.json").write_text(json.dumps(checksums, indent=1) + "\n")
    print(f"wrote {', '.join(checksums)} to {VENDOR}")


def check() -> bool:
    sums = json.loads((VENDOR / "CHECKSUMS.json").read_text())
    ok = True
    for out, meta in sums.items():
        if _sha256((VENDOR / out).read_bytes()) != meta["sha256"]:
            print(f"{out}: does not match CHECKSUMS.json", file=sys.stderr)
            ok = False
    return ok


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(0 if check() else 1)
    fetch()
