"""Privacy: detection, redaction, pseudonymization, per-destination profiles. Fictional data only."""

import json
from pathlib import Path

import pytest

from tests.test_fixtures import VAULT
from threadvault.connector.mcp_server import ConnectorTools
from threadvault.core.accesslog import MemoryAccessLog
from threadvault.core.vault import FixtureVault
from threadvault.privacy.detect import baltic_id_ok, detect, iban_ok
from threadvault.privacy.outbound import (
    Refused,
    prepare_file,
    prepare_handover,
    prepare_text,
    preview,
)
from threadvault.privacy.redact import PseudonymMap, redact_record, redact_text

POLICY = json.loads((VAULT / "policy.json").read_text(encoding="utf-8"))
STRICT = POLICY["profiles"]["strict"]
OPEN = POLICY["profiles"]["open"]
ALL = ["email", "phone", "api_key", "secret", "person", "address", "national_id", "iban"]

# Documentation-example values (not real people, accounts or keys).
IBAN = "GB82 WEST 1234 5698 7654 32"
LT_ID = "38703181745"  # valid checksum, fictional
AWS = "AKIAIOSFODNN7EXAMPLE"
DB = "postgres://admin:hunter2@db.example.com/app"


def kinds(text: str) -> list[str]:
    return [s.kind for s in detect(text, ALL)]


@pytest.mark.parametrize("text,kind", [
    ("write to jonas@example.com", "email"),
    ("call +370 612 34567 today", "phone"),
    (f"key {AWS}", "api_key"),
    (f"db {DB}", "secret"),
    ("password: correct-horse-battery", "secret"),
    (f"pay to {IBAN}", "iban"),
    (f"asmens kodas {LT_ID}", "national_id"),
    ("my name is Jonas Petraitis", "person"),
    ("lives at 221 Baker Street", "address"),
    ("Gedimino pr. 9", "address"),
])
def test_detects(text: str, kind: str) -> None:
    assert kind in kinds(text)


def test_checksums_avoid_false_alarms() -> None:
    assert iban_ok(IBAN) and not iban_ok("GB82 WEST 1234 5698 7654 33")
    assert baltic_id_ok(LT_ID) and not baltic_id_ok("38703181746")
    assert kinds("order 38703181746 shipped") == []


def test_findings_never_contain_the_value() -> None:
    r = redact_text(f"mail jonas@example.com key {AWS}", STRICT, PseudonymMap())
    dumped = json.dumps([f.to_schema() for f in r.findings])
    assert "jonas@" not in dumped and AWS not in dumped
    assert "jonas@" not in r.text and AWS not in r.text


def test_pseudonyms_are_stable_and_reversible() -> None:
    m = PseudonymMap()
    a = redact_text("my name is Jonas Petraitis, mail jonas@example.com", STRICT, m).text
    b = redact_text("Jonas Petraitis wrote again", STRICT, m).text  # known name, no cue
    assert "[PERSON_1]" in a and "[EMAIL_1]" in a and "[PERSON_1]" in b
    assert "Jonas" not in a + b
    assert m.rehydrate(a) == "my name is Jonas Petraitis, mail jonas@example.com"
    assert m.rehydrate("[PERSON_9] unknown stays") == "[PERSON_9] unknown stays"


def test_secrets_are_never_reversible() -> None:
    m = PseudonymMap()
    r = redact_text(f"key {AWS}", STRICT, m)
    assert r.text == "key [API_KEY]" and len(m) == 0


def test_map_file_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "pseudonyms.json"
    redact_text("my name is Ona Kazlauskienė", STRICT, PseudonymMap(p))
    again = PseudonymMap(p)
    assert again.rehydrate("[PERSON_1]") == "Ona Kazlauskienė"
    assert again.token("person", "Someone Else") == "[PERSON_2]"


def test_map_file_rejects_garbage(tmp_path: Path) -> None:
    p = tmp_path / "m.json"
    p.write_text('{"format": "threadvault-pseudonyms-1", "entries": '
                 '[{"kind": "api_key", "token": "[API_KEY_1]", "value": "x"}]}', encoding="utf-8")
    with pytest.raises(ValueError):
        PseudonymMap(p)


def test_open_profile_changes_nothing() -> None:
    text = "mail jonas@example.com"
    assert redact_text(text, OPEN).text == text


def test_redact_record_keeps_ids_and_hashes() -> None:
    obj = {"thread_id": "thr_x", "sha256": "sha256:" + "a" * 64,
           "items": [{"text": "mail jonas@example.com"}]}
    out, found = redact_record(obj, STRICT, PseudonymMap())
    assert out["thread_id"] == "thr_x" and out["sha256"] == obj["sha256"]
    assert "jonas@" not in json.dumps(out) and found[0].path == "$.items[0].text"


def test_destination_rules() -> None:
    text = "mail jonas@example.com"
    assert prepare_text(POLICY, "local", text).text == text
    assert "jonas@" not in prepare_text(POLICY, "anthropic", text, PseudonymMap()).text
    with pytest.raises(Refused):
        prepare_text(POLICY, "unknown-ai", text)
    with pytest.raises(Refused):
        prepare_text(None, "local", text)


def test_unredactable_secret_blocks() -> None:
    profile = {**STRICT, "redact": ["email"]}  # secrets not redacted, but blocking is on
    policy = {**POLICY, "profiles": {**POLICY["profiles"], "strict": profile}}
    out = prepare_text(policy, "anthropic", f"key {AWS}")
    assert out.blocked and preview(out)["text"] == "" and not preview(out)["will_send"]


def test_preview_shows_counts_not_values() -> None:
    out = prepare_text(POLICY, "anthropic", f"a@example.com b@example.com {AWS}", PseudonymMap())
    p = preview(out)
    assert p["hidden"] == {"api_key": 1, "email": 2} and p["will_send"]
    assert "a@example.com" not in json.dumps(p)


def test_handover_is_wrapped_after_redaction() -> None:
    empty = {k: [] for k in ("decisions", "open_questions", "next_steps", "key_facts",
                             "constraints", "uncertain", "files")}
    h = {"thread_id": "thr_x", "version": 1,
         "content": {**empty, "decisions": [{"text": "Send invoice to jonas@example.com",
                                             "source_note": "msg 3"}]}}
    out = prepare_handover(POLICY, "anthropic", h, verified=True, mapping=PseudonymMap())
    assert out.text.startswith("<historical_context") and "jonas@" not in out.text


def test_files_follow_attachment_rule() -> None:
    with pytest.raises(Refused):
        prepare_file(POLICY, "anthropic", b"hello")
    assert prepare_file(POLICY, "local", b"hello").text == "hello"
    assert prepare_file(POLICY, "local", b"\xff\xfe\x00").blocked


# -- connected to the MCP plug -------------------------------------------------------------
def tools(dest: str = "anthropic", m: PseudonymMap | None = None) -> ConnectorTools:
    return ConnectorTools(FixtureVault(), POLICY, MemoryAccessLog(), "claude-desktop", dest, m)


def test_plug_hides_secrets_for_strict_destination() -> None:
    out = tools().load_thread("thr_secrets01")
    assert AWS not in out["context"] and "hunter2" not in out["context"]
    assert "PRIVATE KEY" not in out["context"] and out["hidden"]


def test_plug_sends_everything_to_local() -> None:
    out = tools("local").load_thread("thr_secrets01")
    assert out["hidden"] == {}


def test_plug_stores_real_name_when_ai_uses_token() -> None:
    m = PseudonymMap()
    t = tools(m=m)
    tok = m.token("person", "Jonas Petraitis")
    t.append("thr_full0001", "main0001", "assistant", f"Thanks {tok}")
    last = t._vault.load_thread("thr_full0001").branches["main0001"].records[-1]
    assert last["content"] == "Thanks Jonas Petraitis"
