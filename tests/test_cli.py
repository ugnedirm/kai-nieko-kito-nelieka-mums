import json
import shutil
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.test_fixtures import EXPECTED, VAULT
from threadvault.cli.main import app
from threadvault.cli.safe import terminal_safe

runner = CliRunner()
V = ["--vault", str(VAULT)]


@pytest.fixture(autouse=True)
def _vault_copy(tmp_path: Path) -> None:
    """The CLI writes (access log, handovers): run every test on a copy of the sample vault."""
    copy = tmp_path / "vault"
    shutil.copytree(VAULT, copy)
    V[1] = str(copy)


def test_terminal_safe_strips_escapes() -> None:
    bad = "\x1b[31m\x1b]0;x\x07\u202e\u200b"
    out = terminal_safe("a" + bad + "\nok\t")
    assert out == "a" + "\ufffd" + "[31m" + "\ufffd" + "]0;x" + "\ufffd" * 3 + "\nok\t"


def test_verify_all_matches_expected_exit_code() -> None:
    r = runner.invoke(app, [*V, "verify"])
    assert r.exit_code == 1  # the sample vault contains a tampered thread
    assert "thr_tamper01: FAILED" in r.output
    assert "thr_full0001: ok" in r.output
    assert "hash_mismatch" in r.output or "prev_mismatch" in r.output
    assert EXPECTED  # fixture sanity


def test_verify_single_ok_and_handover_notice() -> None:
    r = runner.invoke(app, [*V, "verify", "thr_handover01"])
    assert r.exit_code == 0 and "No message history stored" in r.output


def test_unknown_thread_is_clean_error() -> None:
    r = runner.invoke(app, [*V, "show", "thr_nope"])
    assert r.exit_code == 1 and "no such thread" in r.output


def test_show_and_pack() -> None:
    assert runner.invoke(app, [*V, "show", "thr_full0001"]).exit_code == 0
    r = runner.invoke(app, [*V, "pack", "thr_handover01", "--max-tokens", "500"])
    assert r.exit_code == 0 and "<historical_context" in r.output


def test_import_chatgpt_and_refusal(tmp_path: Path) -> None:
    good = tmp_path / "conversations.json"
    good.write_text(json.dumps([{"title": "T\x1b[2J", "current_node": "a", "mapping": {
        "a": {"id": "a", "parent": None, "message": {
            "author": {"role": "user"}, "create_time": 1700000000,
            "content": {"parts": ["hello"]}}}}}]))
    r = runner.invoke(app, ["import", "chatgpt", str(good)])
    assert r.exit_code == 0 and "1 messages" in r.output and "\x1b" not in r.output
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    r = runner.invoke(app, ["import", "chatgpt", str(bad)])
    assert r.exit_code == 1 and "invalid_json" in r.output


GOOD_REPLY = json.dumps({
    "decisions": [{"text": "Use trains"}], "open_questions": [], "next_steps": [],
    "key_facts": [{"text": "Budget 1200 EUR", "source_note": "user said so"}],
    "constraints": [], "uncertain": [], "files": []})


def test_handover_add_saves_reviewed(tmp_path: Path) -> None:
    p = tmp_path / "reply.txt"
    p.write_text("```json\n" + GOOD_REPLY + "\n```")
    r = runner.invoke(app, [*V, "handover", "add", "thr_full0001", str(p), "--yes"])
    assert r.exit_code == 0 and "saved handover v" in r.output


def test_handover_add_declined_and_blocked(tmp_path: Path) -> None:
    p = tmp_path / "reply.txt"
    p.write_text(GOOD_REPLY)
    r = runner.invoke(app, [*V, "handover", "add", "thr_full0001", str(p)], input="n\n")
    assert r.exit_code == 1 and "not saved" in r.output
    secret = json.loads(GOOD_REPLY)
    secret["decisions"] = [{"text": "key AKIAIOSFODNN7EXAMPLE"}]
    p.write_text(json.dumps(secret))
    r = runner.invoke(app, [*V, "handover", "add", "thr_full0001", str(p), "--yes"])
    assert r.exit_code == 1 and "secret" in r.output and "AKIAIOSFODNN7EXAMPLE" not in r.output
    p.write_text("no json here")
    assert runner.invoke(app, [*V, "handover", "add", "thr_full0001", str(p), "--yes"]).exit_code == 1


def test_export_refuses_unlisted_destination(tmp_path: Path) -> None:
    out = tmp_path / "x.txt"
    r = runner.invoke(app, [*V, "export", "thr_full0001", "evil-ai", str(out)])
    assert r.exit_code == 1 and not out.exists()
    assert runner.invoke(app, ["export", "thr_full0001", "local", str(out)]).exit_code == 1  # no policy


def test_export_redacts_and_blocks(tmp_path: Path) -> None:
    out = tmp_path / "x.txt"
    r = runner.invoke(app, [*V, "export", "thr_full0001", "local", str(out)])
    assert r.exit_code == 0 and out.exists()
    if sys.platform != "win32":  # Windows has no POSIX permission bits to check
        assert out.stat().st_mode & 0o777 == 0o600
    again = runner.invoke(app, [*V, "export", "thr_full0001", "local", str(out)])
    assert again.exit_code == 1  # never overwrite
    r = runner.invoke(app, [*V, "export", "thr_secrets01", "openai", str(tmp_path / "y.txt")])
    assert r.exit_code == 1 and "secrets" in r.output


def test_apply_profile_redacts_email() -> None:
    from threadvault.cli.redact import apply_profile
    prof = {"redact": ["email"], "block_on_secrets": False}
    assert apply_profile("mail a.b@example.com now", prof) == "mail [REDACTED:email] now"


def test_yes_flag_saves_handover_as_unreviewed(tmp_path: Path) -> None:
    p = tmp_path / "reply.txt"
    p.write_text(GOOD_REPLY)
    r = runner.invoke(app, [*V, "handover", "add", "thr_full0001", str(p), "--yes"])
    assert r.exit_code == 0 and "saved as unreviewed" in r.output


def test_export_always_redacts_secret_kinds() -> None:
    from threadvault.cli.redact import apply_profile
    prof = {"redact": [], "block_on_secrets": False}  # profile forgot to list api_key
    out = apply_profile("key AKIAIOSFODNN7EXAMPLE end", prof)
    assert "AKIAIOSFODNN7EXAMPLE" not in out and "[REDACTED:api_key]" in out


def test_imports_persist_between_invocations(tmp_path: Path) -> None:
    src = tmp_path / "t.md"
    src.write_text("User: hello\n\nAssistant: hi there\n")
    own = ["--vault", str(tmp_path / "fresh")]
    assert runner.invoke(app, [*own, "import", "markdown", str(src)]).exit_code == 0
    r = runner.invoke(app, [*own, "list"])
    assert r.exit_code == 0 and r.output.count("thr_") == 1
    tid = r.output.split()[0]
    assert runner.invoke(app, [*own, "verify", tid]).exit_code == 0
    assert "hello" in runner.invoke(app, [*own, "show", tid]).output


def test_fork_creates_current_branch() -> None:
    r = runner.invoke(app, [*V, "fork", "thr_full0001", "--label", "alt"])
    assert r.exit_code == 0 and "forked thr_full0001 as branch br_" in r.output
    assert runner.invoke(app, [*V, "verify", "thr_full0001"]).exit_code == 0
    r = runner.invoke(app, [*V, "fork", "thr_nope"])
    assert r.exit_code == 1 and "Traceback" not in r.output
    r = runner.invoke(app, [*V, "fork", "thr_full0001", "--at-hash", "sha256:" + "0" * 64])
    assert r.exit_code == 1 and "cannot fork" in r.output


def test_open_refuses_when_service_is_not_running(tmp_path: Path) -> None:
    r = runner.invoke(app, ["--vault", str(tmp_path / "v"), "open", "--port", "1"])
    assert r.exit_code == 1 and "not running" in r.output


def test_setup_creates_vault_and_installs_autostart_only_when_asked(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from threadvault.cli import autostart, main

    calls: list[str] = []
    monkeypatch.setattr(autostart, "supported", lambda: True)
    monkeypatch.setattr(autostart, "install", lambda root, port: calls.append("install") or "ok")
    monkeypatch.setattr(main, "_alive", lambda port: False)
    v = ["--vault", str(tmp_path / "v")]
    r = runner.invoke(app, [*v, "setup"], input="n\n")  # the person declines
    assert r.exit_code == 0 and calls == [] and (tmp_path / "v" / "policy.json").exists()
    r = runner.invoke(app, [*v, "setup", "--yes"])
    assert r.exit_code == 0 and calls == ["install"]


def test_file_add_cleans_and_asks_before_keeping_hidden_data(tmp_path: Path) -> None:
    own = ["--vault", str(tmp_path / "v")]
    src = tmp_path / "t.md"
    src.write_text("User: hi\n\nAssistant: hello\n")
    runner.invoke(app, [*own, "import", "markdown", str(src)])
    tid = runner.invoke(app, [*own, "list"]).output.split()[0]
    note = tmp_path / "notes.txt"
    note.write_text("my notes\n")
    r = runner.invoke(app, [*own, "file", "add", tid, str(note)])
    assert r.exit_code == 0 and "attached notes.txt" in r.output
    odd = tmp_path / "odd.bin"
    odd.write_bytes(b"\x00\x01opaque\xff")
    r = runner.invoke(app, [*own, "file", "add", tid, str(odd)], input="n\n")
    assert r.exit_code == 1 and "hidden details" in r.output and "not attached" in r.output
    r = runner.invoke(app, [*own, "file", "add", tid, str(odd), "--yes"])
    assert r.exit_code == 0 and "attached odd.bin" in r.output
    assert runner.invoke(app, [*own, "file", "add", "thr_nope", str(note)]).exit_code == 1
    assert runner.invoke(app, [*own, "file", "add", tid, str(tmp_path / "missing")]).exit_code == 1


def test_merge_command(tmp_path: Path) -> None:
    own = ["--vault", str(tmp_path / "v")]
    for name in ("a.md", "b.md"):
        (tmp_path / name).write_text("User: hi\n\nAssistant: hello\n")
        runner.invoke(app, [*own, "import", "markdown", str(tmp_path / name)])
    ids = [line.split()[0] for line in runner.invoke(app, [*own, "list"]).output.splitlines()]
    r = runner.invoke(app, [*own, "merge", ids[0], ids[1]])
    assert r.exit_code == 1 and "saved text" in r.output  # both hold messages: refused
    assert runner.invoke(app, [*own, "merge", "thr_nope", ids[1]]).exit_code == 1


def _thread_with_file(tmp_path: Path) -> tuple[list[str], str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    own = ["--vault", str(tmp_path / "v")]
    src = tmp_path / "t.md"
    src.write_text("User: hi\n\nAssistant: hello\n")
    runner.invoke(app, [*own, "import", "markdown", str(src)])
    tid = runner.invoke(app, [*own, "list"]).output.split()[0]
    note = tmp_path / "plan.txt"
    note.write_text("plan\n")
    assert runner.invoke(app, [*own, "file", "add", tid, str(note)]).exit_code == 0
    return own, tid


def test_forget_expire_sweep_delete_and_log(tmp_path: Path) -> None:
    own, tid = _thread_with_file(tmp_path)
    r = runner.invoke(app, [*own, "forget", tid, "plan.txt"], input="n\n")
    assert r.exit_code == 1 and "not deleted" in r.output
    assert runner.invoke(app, [*own, "forget", tid, "nope.txt", "--yes"]).exit_code == 1
    r = runner.invoke(app, [*own, "forget", tid, "plan.txt", "--yes"])
    assert r.exit_code == 0 and "forgotten" in r.output
    assert "plan.txt" not in runner.invoke(app, [*own, "show", tid]).output  # gone from the thread

    assert runner.invoke(app, [*own, "expire", tid]).exit_code == 1  # needs one option
    assert runner.invoke(app, [*own, "expire", tid, "--in", "soon"]).exit_code == 1
    r = runner.invoke(app, [*own, "expire", tid, "--in", "7d"])
    assert r.exit_code == 0 and "will be deleted at" in r.output
    assert runner.invoke(app, [*own, "expire", tid, "--never"]).exit_code == 0
    runner.invoke(app, [*own, "expire", tid, "--at", "2020-01-01T00:00:00Z"])
    r = runner.invoke(app, [*own, "sweep"])
    assert r.exit_code == 0 and "removed 1" in r.output
    assert runner.invoke(app, [*own, "list"]).output.strip() == ""

    own2, tid2 = _thread_with_file(tmp_path / "second")
    assert runner.invoke(app, [*own2, "delete", tid2], input="n\n").exit_code == 1
    assert runner.invoke(app, [*own2, "delete", tid2, "--yes"]).exit_code == 0
    assert runner.invoke(app, [*own2, "delete", tid2, "--yes"]).exit_code == 1
    out = runner.invoke(app, [*own2, "log"]).output
    assert "chain: ok" in out and "sweep" in out


def _inited(tmp_path: Path) -> list[str]:
    own = ["--vault", str(tmp_path / "v")]
    assert runner.invoke(app, [*own, "init"]).exit_code == 0
    return own


def test_policy_show_allow_revoke(tmp_path: Path) -> None:
    own = _inited(tmp_path)
    out = runner.invoke(app, [*own, "policy", "show"]).output
    assert "browser-extension" in out and "chatgpt" in out and "blocks secrets" in out
    assert runner.invoke(app, [*own, "policy", "allow", "claude-desktop", "teleport"]).exit_code == 1
    r = runner.invoke(app, [*own, "policy", "allow", "claude-desktop", "read", "append"])
    assert r.exit_code == 0 and "append, read" in r.output
    assert (tmp_path / "v" / "policy.json.bak").exists()
    assert "claude-desktop: append, read" in runner.invoke(app, [*own, "policy", "show"]).output
    assert runner.invoke(app, [*own, "policy", "revoke", "claude-desktop", "append"]).exit_code == 0
    assert "claude-desktop: read" in runner.invoke(app, [*own, "policy", "show"]).output
    assert runner.invoke(app, [*own, "policy", "revoke", "claude-desktop"]).exit_code == 0
    assert "claude-desktop" not in runner.invoke(app, [*own, "policy", "show"]).output
    assert runner.invoke(app, [*own, "policy", "revoke", "nobody"]).exit_code == 1


def test_init_update_policy_keeps_a_backup(tmp_path: Path) -> None:
    own = _inited(tmp_path)
    pol = tmp_path / "v" / "policy.json"
    pol.write_text('{"spec_version": "1", "type": "policy", "default_profile": "strict", "clients": [],'
                   ' "destinations": [], "profiles": {"strict": {"redact": [], "pseudonymize": false,'
                   ' "block_on_secrets": true, "allow_attachments": false, "strip_file_metadata": true}}}')
    assert "left unchanged" in runner.invoke(app, [*own, "init"]).output
    assert runner.invoke(app, [*own, "init", "--update-policy"]).exit_code == 0
    assert (tmp_path / "v" / "policy.json.bak").exists() and "chatgpt" in pol.read_text()


def test_plugin_pin_check_unpin(tmp_path: Path) -> None:
    own = _inited(tmp_path)
    plug = tmp_path / "myplug.py"
    plug.write_text("VALUE = 1\n")
    assert "no plugins are pinned" in runner.invoke(app, [*own, "plugin", "list"]).output
    assert runner.invoke(app, [*own, "plugin", "check", "myplug", str(plug)]).exit_code == 1  # unpinned
    r = runner.invoke(app, [*own, "plugin", "pin", "myplug", str(plug)], input="n\n")
    assert r.exit_code == 1 and "not pinned" in r.output
    assert runner.invoke(app, [*own, "plugin", "pin", "myplug", str(plug), "--yes"]).exit_code == 0
    assert runner.invoke(app, [*own, "plugin", "check", "myplug", str(plug)]).exit_code == 0
    plug.write_text("VALUE = 2  # edited after pinning\n")
    r = runner.invoke(app, [*own, "plugin", "check", "myplug", str(plug)])
    assert r.exit_code == 1 and "changed since it was pinned" in r.output
    assert runner.invoke(app, [*own, "plugin", "unpin", "myplug"]).exit_code == 0
    assert runner.invoke(app, [*own, "plugin", "unpin", "myplug"]).exit_code == 1


def test_mcp_config_prints_a_working_setting_and_can_allow_the_client(tmp_path: Path) -> None:
    own = _inited(tmp_path)
    out = runner.invoke(app, [*own, "mcp-config"]).output
    assert '"mcpServers"' in out and '"mcp"' in out and "gets nothing until you allow it" in out
    runner.invoke(app, [*own, "mcp-config", "--allow"])
    assert "claude-desktop: append, read, save_handover" in runner.invoke(
        app, [*own, "policy", "show"]).output
