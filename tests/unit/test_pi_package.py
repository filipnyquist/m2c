"""The pi package: the root manifest and the one in integrations/pi must stay in step.

`pi install git:github.com/filipnyquist/m2c` installs the repository root, so the root manifest is what pi
reads; `pi install ./integrations/pi` installs the directory itself. Both must load the same extension and the
same skill, and every path they name must exist in the repository.
"""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "package.json"
PI_PACKAGE = ROOT / "integrations" / "pi" / "package.json"
HOST_PACKAGES = ("@earendil-works/pi-coding-agent",)


def _manifest(path: Path) -> dict:
    return json.loads(path.read_text())


def _resources(manifest: dict) -> list[str]:
    pi = manifest.get("pi", {})
    return [*(pi.get("extensions") or []), *(pi.get("skills") or [])]


@pytest.mark.parametrize("package", [PACKAGE, PI_PACKAGE])
def test_manifest_names_resources_that_exist(package):
    manifest = _manifest(package)
    resources = _resources(manifest)
    assert resources, f"{package.name} declares no extension or skill"
    for resource in resources:
        assert (package.parent / resource).exists(), f"{package.name} names a missing {resource}"


@pytest.mark.parametrize("package", [PACKAGE, PI_PACKAGE])
def test_manifest_declares_the_host_packages_as_peers(package):
    manifest = _manifest(package)
    assert not manifest.get("dependencies"), "the host provides the packages the extension imports"
    for host in HOST_PACKAGES:
        assert manifest.get("peerDependencies", {}).get(host) == "*"


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_both_manifests_load_the_same_extension_and_skill():
    root = _manifest(PACKAGE)
    pi = _manifest(PI_PACKAGE)
    assert root["pi"]["extensions"] == ["./integrations/pi/extensions/m2c-bridge.ts"]
    assert root["pi"]["skills"] == ["./integrations/pi/skills/m2c-traffic"]
    assert pi["pi"]["extensions"] == ["./extensions/m2c-bridge.ts"]
    assert pi["pi"]["skills"] == ["./skills/m2c-traffic"]
    assert _tree(ROOT / "integrations" / "pi" / "extensions") == _tree(PI_PACKAGE.parent / "extensions")
    assert _tree(ROOT / "integrations" / "pi" / "skills") == _tree(PI_PACKAGE.parent / "skills")


def test_skill_has_frontmatter():
    text = (ROOT / "integrations" / "pi" / "skills" / "m2c-traffic" / "SKILL.md").read_text()
    assert text.startswith("---\n")
    frontmatter = text.split("---", 2)[1]
    assert "name: m2c-traffic" in frontmatter
    assert "description:" in frontmatter
