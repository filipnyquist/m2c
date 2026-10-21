#!/usr/bin/env bash
# Build a relocatable Linux bundle: a standalone CPython (python-build-standalone, as managed by uv) with
# m2c, mitmproxy and chDB installed into it, plus bin/m2c. Untar it anywhere on a glibc >= 2.17 system,
# or COPY it into an existing image.
#
#   packaging/bundle.sh                  -> dist/m2c-<version>-linux-<arch>.tar.zst
#   packaging/bundle.sh --no-tar DIR     -> the unpacked bundle in DIR (used by the Dockerfile)
#
# chDB is installed without its pandas/pyarrow/numpy dependencies (m2c never uses them): ~240 MB smaller.
set -euo pipefail
cd "$(dirname "$0")/.."

TAR=1
DEST=""
if [[ "${1:-}" == "--no-tar" ]]; then TAR=0; DEST="${2:?--no-tar needs a directory}"; fi
PY_VERSION="${M2C_PY_VERSION:-3.12}"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)
ARCH=$(uname -m)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BUNDLE="${DEST:-$WORK/m2c}"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/bin"

uv python install -q "$PY_VERSION"
PY=$(uv python find --managed-python "$PY_VERSION")
PYHOME=$(dirname "$(dirname "$(readlink -f "$PY")")")
cp -a "$PYHOME" "$BUNDLE/python"
find "$BUNDLE/python/lib" -maxdepth 2 -name EXTERNALLY-MANAGED -delete
BPY="$BUNDLE/python/bin/python3"

# Exactly the versions in uv.lock (a fresh resolve once picked up a mitmproxy release nobody had tested), without
# chDB's DataFrame dependencies.
uv export -q --frozen --no-dev --no-emit-project --no-hashes -o "$WORK/requirements.txt"
grep -viE '^(pandas|pyarrow|numpy|python-dateutil|six|tzdata)==' "$WORK/requirements.txt" > "$WORK/requirements-bundle.txt"
uv build -q --wheel -o "$WORK/wheel" .
uv pip install -q --python "$BPY" --break-system-packages --no-deps -r "$WORK/requirements-bundle.txt" "$WORK"/wheel/*.whl
"$BPY" -I -c 'import m2c.cli, m2c.recorder, chdb.session'  # every import resolves

# Trim what a proxy never needs.
SITE=$("$BPY" -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])')
rm -rf "$SITE"/{test,idlelib,tkinter,turtledemo,ensurepip,lib2to3} "$SITE"/../tcl* "$BUNDLE/python/share" 2>/dev/null || true
find "$BUNDLE/python" -name "*.a" -delete

# The console scripts uv put in python/bin (mitmdump, mitmproxy, m2c, ...) start with "#!$BPY", a path that is gone
# once the bundle moves (or right away: $WORK is deleted). Make each run the python3 next to itself instead, with
# the sh/Python polyglot header pip uses for relocatable scripts.
"$BPY" -I - "$BUNDLE/python/bin" <<'PY'
import os, sys

bindir = sys.argv[1]
q = b"'" * 3
stub = b"#!/bin/sh\n" + q + b"exec' \"$(dirname -- \"$(readlink -f -- \"$0\")\")/python3\" \"$0\" \"$@\"\n' " + q + b"\n"
for name in sorted(os.listdir(bindir)):
    path = os.path.join(bindir, name)
    if os.path.islink(path) or not os.path.isfile(path):
        continue
    with open(path, "rb") as f:
        lines = f.read().split(b"\n")
    if lines[0] == b"#!/bin/sh" and lines[1].startswith(q + b"exec'") and lines[2] == b"' " + q:
        body = lines[3:]  # uv writes this header itself when the path is too long for a shebang, but with that path
    elif lines[0].startswith(b"#!") and b"/python/bin/python" in lines[0]:
        body = lines[1:]
    else:
        continue
    with open(path, "wb") as f:
        f.write(stub + b"\n".join(body))
PY

# -P: `-m`/`-c` would put the working directory first on sys.path, so a json.py planted there would run inside m2c
# (which reads the secret).
cat > "$BUNDLE/bin/m2c" <<'SH'
#!/bin/sh
here=$(dirname "$(readlink -f "$0")")
exec "$here/../python/bin/python3" -P -m m2c.cli "$@"
SH
cat > "$BUNDLE/bin/mitmdump" <<'SH'
#!/bin/sh
here=$(dirname "$(readlink -f "$0")")
exec "$here/../python/bin/python3" -P -c 'import sys; from mitmproxy.tools.main import mitmdump; sys.argv[0] = "mitmdump"; sys.exit(mitmdump())' "$@"
SH
chmod +x "$BUNDLE/bin/m2c" "$BUNDLE/bin/mitmdump"
"$BUNDLE/bin/m2c" --help > /dev/null
"$BUNDLE/python/bin/mitmdump" --version > /dev/null
echo "$VERSION" > "$BUNDLE/VERSION"

if [[ $TAR == 1 ]]; then
  mkdir -p dist
  OUT="dist/m2c-$VERSION-linux-$ARCH.tar.zst"
  tar -C "$WORK" --zstd -cf "$OUT" m2c
  echo "$OUT ($(du -h "$OUT" | cut -f1); unpacked $(du -sh "$BUNDLE" | cut -f1))"
else
  echo "$BUNDLE ($(du -sh "$BUNDLE" | cut -f1))"
fi
