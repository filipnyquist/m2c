"""The web UI's files: vendored code matches its checksums, every import resolves, nothing inline or unsafe."""

import re
import subprocess
import sys
from importlib import resources
from pathlib import Path

UI = Path(str(resources.files("m2c").joinpath("ui")))
REPO = Path(__file__).resolve().parents[2]
IMPORT = re.compile(r"""(?:^|[;\s])(?:import|export)\s[^"']*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)""", re.M)


def sources():
    return [p for p in UI.rglob("*.js") if "vendor" not in p.parts]


def test_vendored_files_match_their_checksums():
    out = subprocess.run([sys.executable, "-I", str(REPO / "scripts" / "vendor_ui.py"), "--check"], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_every_import_resolves_to_a_shipped_file():
    files = sources() + list((UI / "vendor").glob("*.mjs"))
    assert len(files) > 10
    for f in files:
        for a, b in IMPORT.findall(f.read_text()):
            spec = a or b
            assert spec.startswith("."), f"{f.name}: bare import {spec!r} (the CSP allows no import map)"
            assert (f.parent / spec).resolve().is_file(), f"{f.name}: {spec} not found"


def test_no_inline_code_and_no_html_sinks():
    page = (UI / "index.html").read_text()
    assert "<style" not in page and " style=" not in page
    assert re.findall(r"<script\b[^>]*>", page) == ['<script type="module" src="app.js">']
    for f in sources():
        text = f.read_text()
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "dangerouslySetInnerHTML", "eval(", "new Function", "document.write"):
            assert sink not in text, f"{f.name} uses {sink}"
