import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from tests.test_fixtures import EXPECTED, VAULT
from threadvault.cli.main import app
from threadvault.cli.safe import terminal_safe

runner = CliRunner()
V = ["--vault", str(VAULT)]


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
