"""Extension audit and contract tests (THREAT_MODEL T10, T11).

Permission and no-remote-code checks need no Node. The contract test and the JS unit tests run
only if `node` is installed (CI should install it: see the PR notes).
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.test_fixtures import VAULT
from threadvault import schemas
from threadvault.connector.ingest import IngestService
from threadvault.core.accesslog import MemoryAccessLog
from threadvault.core.vault import FixtureVault

EXT = Path(__file__).resolve().parents[1] / "extension"
MANIFESTS = ["manifest.json", "manifest.firefox.json"]
CHAT_SITES = {"https://chatgpt.com/*", "https://chat.openai.com/*", "https://claude.ai/*"}
ALLOWED_HOST_PERMISSIONS = CHAT_SITES | {"http://127.0.0.1/*"}
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


def run_node(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, **kw)


def manifest(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXT / name).read_text())
    return data


@pytest.mark.parametrize("name", MANIFESTS)
def test_permissions_are_minimal(name: str) -> None:
    m = manifest(name)
    assert m["manifest_version"] == 3
    assert m["permissions"] == ["storage"]
    assert set(m["host_permissions"]) == ALLOWED_HOST_PERMISSIONS
    assert [set(c["matches"]) for c in m["content_scripts"]] == [CHAT_SITES]
    assert all(c.get("all_frames") is False for c in m["content_scripts"])
    for forbidden in ("web_accessible_resources", "externally_connectable", "optional_permissions",
                      "optional_host_permissions", "commands", "devtools_page", "sandbox"):
        assert forbidden not in m


@pytest.mark.parametrize("name", MANIFESTS)
def test_csp_has_no_unsafe_or_remote_sources(name: str) -> None:
    csp = manifest(name)["content_security_policy"]["extension_pages"]
    assert "unsafe-eval" not in csp and "unsafe-inline" not in csp and "wasm" not in csp
    assert re.search(r"script-src 'self'(;|$)", csp)
    assert "https:" not in csp and "*" not in csp.replace("127.0.0.1:*", "")
    assert "connect-src http://127.0.0.1:*" in csp


@pytest.mark.parametrize("name", MANIFESTS)
def test_every_referenced_file_exists(name: str) -> None:
    m = manifest(name)
    files = [f for c in m["content_scripts"] for f in c["js"]]
    files += m["background"].get("scripts", [m["background"].get("service_worker")])
    files += [m["action"]["default_popup"], m["options_ui"]["page"]]
    assert all((EXT / f).is_file() for f in files)


def test_allowed_hosts_constant_matches_manifest() -> None:
    src = (EXT / "src/lib/constants.js").read_text()
    hosts = set(re.search(r"ALLOWED_HOSTS: \[(.*?)\]", src, re.DOTALL).group(1).replace('"', "").replace(" ", "").split(","))  # type: ignore[union-attr]
    assert {f"https://{h}/*" for h in hosts} == CHAT_SITES


def js_files() -> list[Path]:
    return [p for p in EXT.rglob("*") if p.suffix in {".js", ".html"} and "dist" not in p.parts
            and "test" not in p.parts and "node_modules" not in p.parts]


def test_no_remote_code_or_html_injection() -> None:
    banned = ["eval(", "new Function", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
              "setTimeout(\"", "javascript:", "importScripts(\"http", "<script src=\"http",
              "unsafe_allow_html"]
    for p in js_files():
        text = p.read_text()
        for b in banned:
            assert b not in text, f"{p.name} contains {b}"
        if p.suffix == ".html":
            assert not re.search(r"<script(?![^>]*\bsrc=)", text), f"inline script in {p.name}"
            assert not re.search(r"\son\w+=", text), f"inline handler in {p.name}"


def test_only_background_talks_to_the_network() -> None:
    net = re.compile(r"\bfetch\b\s*[(,)]|XMLHttpRequest|sendBeacon|WebSocket|EventSource")
    offenders = [p.name for p in js_files() if net.search(p.read_text())]
    # content.js has ONE guarded fetch (pictures and files already shown in the person's chat)
    assert offenders == ["background.js", "content.js"], offenders
    content = (EXT / "src/content.js").read_text()
    assert len(re.findall(r"\bfetch\(", content)) == 1
    guard, call = content.index("TV.files.urlAllowed(url, location.origin)"), content.index("await fetch(url")
    assert guard < call, "the URL guard must run before the fetch"
    tail = content[call:call + 200]
    assert 'credentials: "same-origin"' in tail and 'redirect: "error"' in tail
    assert not net.search((EXT / "src/lib/files.js").read_text())
    # ingest.js only receives fetch as a parameter and builds 127.0.0.1 URLs
    assert "http://${C.API_HOST}" in (EXT / "src/lib/ingest.js").read_text()
    assert 'API_HOST: "127.0.0.1"' in (EXT / "src/lib/constants.js").read_text()


def test_file_attach_listeners_only_react_to_real_user_actions() -> None:
    content = (EXT / "src/content.js").read_text()
    assert "if (e.isTrusted) fn(e)" in content  # page scripts cannot fake a trusted event
    for event in ("change", "drop", "paste"):
        assert re.search(rf'addEventListener\("{event}", trusted\(', content), event
    # nothing is saved without consent: "ask" shows a button, only "auto" saves silently
    assert 'settings.attachMode === "auto"' in content and "Save a copy" in content
    # the page cannot make the extension save: only the content script's own listeners send it
    assert content.count('type: "attach_file"') == 1


def test_continue_here_fills_but_never_sends() -> None:
    """The extension may type text into the chat box and pick files; the person presses send."""
    for name in ("src/content.js", "src/adapters/base.js", "src/adapters/chatgpt.js", "src/adapters/claude.js"):
        code = (EXT / name).read_text()
        assert not re.search(r"requestSubmit|\.submit\(|\.click\(|KeyboardEvent|keydown|dispatchEvent\(new (?:Mouse|Pointer)", code), name
    content = (EXT / "src/content.js").read_text()
    assert 'msg.type === "fill_continue"' in content
    # only the extension's own pages may start it; a chat page cannot (background.js)
    bg = (EXT / "src/background.js").read_text()
    assert 'msg.type === "continue_start"' in bg and "fromExtensionPage(sender)" in bg
    assert bg.index("fromExtensionPage(sender)") < bg.index('msg.type === "continue_start"')


@needs_node
def test_js_unit_tests_pass() -> None:
    r = run_node(["node", "--test", *map(str, sorted((EXT / "test").glob("*.test.js")))],
                       capture_output=True, text=True, cwd=EXT, timeout=120)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]


@needs_node
def test_generated_prompt_is_in_sync() -> None:
    r = run_node(["node", "-e", 'import("./tools/build.mjs").then(m=>process.stdout.write(m.promptSource()))'],
                       capture_output=True, text=True, cwd=EXT, timeout=60)
    assert r.returncode == 0, r.stderr
    assert (EXT / "src/generated/prompt.js").read_text() == r.stdout, "run `node tools/build.mjs`"


@needs_node
def test_requests_built_by_the_extension_are_valid_and_ingest() -> None:
    r = run_node(["node", "test/emit_requests.js"], capture_output=True, text=True, cwd=EXT, timeout=60)
    assert r.returncode == 0, r.stderr
    reqs = json.loads(r.stdout)
    for name, req in reqs.items():
        assert schemas.errors("ingest_request", req) == [], name
    policy = json.loads((VAULT / "policy.json").read_text())
    svc = IngestService(FixtureVault(), policy, MemoryAccessLog())
    assert svc.handle(reqs["handover"])["status"] == "accepted"
    assert svc.handle(reqs["messages"])["status"] == "accepted"
    assert svc.handle(reqs["file"])["status"] == "accepted"
    assert svc.handle(reqs["unreviewed"])["status"] == "rejected"  # SPEC 8.5a
