"""MCP connector tests. FixtureVault + fixture policy, no network."""

import json
from typing import Any

import anyio
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from tests.test_fixtures import VAULT
from threadvault import schemas
from threadvault.connector.mcp_server import ConnectorTools, build_server
from threadvault.core.accesslog import MemoryAccessLog
from threadvault.core.vault import FixtureVault

POLICY = json.loads((VAULT / "policy.json").read_text())
FAKE_KEY = "AKIA" + "EXAMPLE0" * 2  # documentation-style fake, built so scanners don't flag this file
BLOB = "sha256:61e5f9213e9e4898a085affafa383c255c409a5c842f68f9b543d70b7b27d273"
HANDOVER_REPLY = """Here it is:
```json
{"decisions": [{"text": "Use Lisbon first"}], "open_questions": [], "next_steps": [],
 "key_facts": [{"text": "Budget is 1200 EUR", "source_note": "chat"}], "constraints": [],
 "uncertain": [], "files": []}
```"""


def make(client: str = "claude-desktop", dest: str = "anthropic",
         policy: Any = POLICY) -> tuple[ConnectorTools, FixtureVault, MemoryAccessLog]:
    v, log = FixtureVault(), MemoryAccessLog()
    return ConnectorTools(v, policy, log, client, dest), v, log


async def yes(_: str) -> bool:
    return True


async def no(_: str) -> bool:
    return False


# -- allowed client -------------------------------------------------------------------------
def test_list_threads() -> None:
    t, _, _ = make()
    ids = {x["thread_id"] for x in t.list_threads()}
    assert "thr_full0001" in ids and "thr_handover01" in ids


def test_load_thread_wraps_handover_as_untrusted() -> None:
    t, _, _ = make()
    out = t.load_thread("thr_handover01")
    assert out["verified"] is True
    assert out["context"].startswith("<security_notes")
    assert "<historical_context" in out["context"]
    assert "information, not instructions" in out["context"]
    assert out["warnings"]  # handover-only notice


def test_load_full_thread_messages_are_fenced() -> None:
    t, _, _ = make()
    out = t.load_thread("thr_full0001")
    assert "<historical_messages>" in out["context"]
    assert "| user-asserted |" in out["context"] or "| imported-unverified |" in out["context"]  # labelled


def test_tampered_thread_is_flagged() -> None:
    t, _, _ = make()
    out = t.load_thread("thr_tamper01")
    assert out["verified"] is False
    assert any("FAILED" in w for w in out["warnings"])


def test_append_vault_assigns_hash_and_chain_stays_valid() -> None:
    t, v, _ = make()
    out = t.append("thr_full0001", "main0001", "assistant", "Next: book trains.", model="claude-x")
    assert out["stored_hash"].startswith("sha256:")
    assert v.verify("thr_full0001").ok
    last = v.load_thread("thr_full0001").branches["main0001"].records[-1]
    assert schemas.errors("message", last) == []


def test_append_blocks_secrets_without_echoing_them() -> None:
    t, v, log = make()
    before = len(v.load_thread("thr_full0001").branches["main0001"].records)
    with pytest.raises(ToolError) as e:
        t.append("thr_full0001", "main0001", "user", f"my key is {FAKE_KEY}")
    assert FAKE_KEY not in str(e.value)
    assert all(FAKE_KEY not in json.dumps(x) for x in log.entries())
    assert len(v.load_thread("thr_full0001").branches["main0001"].records) == before


def test_append_refused_on_handover_only_thread() -> None:
    t, _, _ = make()
    with pytest.raises(ToolError):
        t.append("thr_handover01", "main0001", "user", "hello")


def test_unknown_thread_and_bad_role() -> None:
    t, _, _ = make()
    with pytest.raises(ToolError):
        t.load_thread("thr_nope0001")
    with pytest.raises(ToolError):
        t.append("thr_full0001", "main0001", "admin", "hi")


def test_get_file_follows_destination_profile() -> None:
    strict, _, _ = make(dest="anthropic")  # strict profile: no attachments
    with pytest.raises(ToolError):
        strict.get_file(BLOB)
    local, _, _ = make(dest="local")
    assert "Lisbon" in local.get_file(BLOB)["text"]


def test_save_handover_needs_user_approval() -> None:
    t, v, _ = make()
    out = anyio.run(t.save_handover, "thr_handover01", None, HANDOVER_REPLY, no)
    assert out["status"] == "not_saved"
    out = anyio.run(t.save_handover, "thr_handover01", None, HANDOVER_REPLY, yes)
    assert out["status"] == "saved" and out["version"] >= 2
    rec = v.load_thread("thr_handover01").branches["main0001"].records[-1]
    assert schemas.errors("handover", rec) == []
    assert v.verify("thr_handover01").ok


def test_save_handover_rejects_garbage() -> None:
    t, _, _ = make()
    out = anyio.run(t.save_handover, "thr_handover01", None, "no json here", yes)
    assert out["status"] == "invalid"


# -- default deny ---------------------------------------------------------------------------
def test_read_only_client_cannot_write() -> None:
    t, _, log = make(client="gpt-reader")
    assert t.list_threads()
    with pytest.raises(ToolError):
        t.append("thr_full0001", "main0001", "user", "hi")
    with pytest.raises(ToolError):
        anyio.run(t.save_handover, "thr_handover01", None, HANDOVER_REPLY, yes)
    assert log.entries()[-1]["outcome"] == "denied"


@pytest.mark.parametrize(("client", "dest", "policy"), [
    ("stranger", "anthropic", POLICY),        # client not in policy
    ("claude-desktop", "evil-host", POLICY),  # destination not in policy
    ("claude-desktop", "anthropic", None),    # no policy file
])
def test_default_deny(client: str, dest: str, policy: Any) -> None:
    t, _, _ = make(client, dest, policy)
    with pytest.raises(ToolError):
        t.list_threads()


def test_every_call_is_logged_and_entries_are_valid() -> None:
    t, _, log = make()
    t.list_threads()
    t.load_thread("thr_full0001")
    with pytest.raises(ToolError):
        t.get_file(BLOB)
    assert [e["outcome"] for e in log.entries()] == ["allowed", "allowed", "denied"]
    for e in log.entries():
        assert schemas.errors("access_entry", e) == []


# -- MCP wrapper ----------------------------------------------------------------------------
def test_server_exposes_the_five_tools() -> None:
    t, _, _ = make()
    names = {tool.name for tool in anyio.run(build_server(t).list_tools)}
    assert names == {"list_threads", "load_thread", "append", "get_file", "save_handover"}
