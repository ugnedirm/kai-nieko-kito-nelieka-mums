"""Things a download or a store listing depends on (found missing or wrong once; pinned now)."""

import json
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from threadvault import schemas

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "extension"


def test_the_built_package_ships_the_schemas() -> None:
    """The wheel once lacked its schema files, so an installed copy crashed on first use."""
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    forced = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert forced == {"schemas": "threadvault/_schemas"}
    assert schemas.SCHEMA_DIR.is_dir() and len(list(schemas.SCHEMA_DIR.glob("*.schema.json"))) >= 10


def test_version_is_the_same_everywhere() -> None:
    py = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    for f in ("manifest.json", "manifest.firefox.json", "package.json"):
        assert json.loads((EXT / f).read_text())["version"] == py, f


@pytest.mark.parametrize("manifest", ["manifest.json", "manifest.firefox.json"])
def test_manifests_declare_icons_that_exist(manifest: str) -> None:
    m = json.loads((EXT / manifest).read_text())
    assert set(m["icons"]) >= {"16", "48", "128"}  # sizes the stores ask for
    for path in [*m["icons"].values(), *m["action"]["default_icon"].values()]:
        data = (EXT / path).read_bytes()
        assert data.startswith(b"\x89PNG\r\n\x1a\n"), path


def test_firefox_id_is_not_the_placeholder_and_declares_no_data_collection() -> None:
    gecko = json.loads((EXT / "manifest.firefox.json").read_text())["browser_specific_settings"]["gecko"]
    assert "example.invalid" not in gecko["id"] and gecko["id"].startswith("{")
    assert gecko["data_collection_permissions"] == {"required": ["none"]}


def test_store_and_release_documents_exist_and_do_not_overclaim() -> None:
    privacy = (ROOT / "docs" / "PRIVACY.md").read_text()
    assert "nothing" in privacy.lower() and "127.0.0.1" in privacy
    for phrase in ("chatgpt.com", "claude.ai", "storage"):
        assert phrase in privacy
    releasing = (ROOT / "docs" / "RELEASING.md").read_text()
    assert "Not done yet" in releasing and "LICENSE" in releasing  # open items stay visible


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_install_script_is_valid_shell_and_refuses_old_python_gracefully() -> None:
    script = ROOT / "scripts" / "install.sh"
    assert subprocess.run(["sh", "-n", str(script)], check=False).returncode == 0
    text = script.read_text()
    assert "set -eu" in text and "sudo" not in text and "--uninstall" in text
    assert "3, 11" in text  # checks for Python 3.11 or newer


def test_workflows_check_the_tag_and_build_the_package() -> None:
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "does not match version" in release and "SHA256SUMS" in release
    assert "package_extension.py" in release and "python -m build" in release
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "package:" in ci and "/tmp/clean/bin/thread init" in ci


def test_the_project_is_mit_licensed_consistently() -> None:
    text = (ROOT / "LICENSE").read_text()
    assert text.startswith("MIT License") and "Copyright (c) 2026" in text
    assert "THE SOFTWARE IS PROVIDED \"AS IS\"" in text  # the standard no-warranty clause
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["license"] == "MIT" and project["license-files"] == ["LICENSE"]
    assert "## License" in (ROOT / "README.md").read_text()


def test_the_tests_cannot_touch_the_real_home(tmp_path: Path) -> None:
    """The autouse fixture in conftest gives every test a throwaway home."""
    import os
    assert "THREADVAULT_DIR" not in os.environ
    assert Path.home().name.startswith("home") and Path.home() != Path("/")  # pytest's temp "home"
