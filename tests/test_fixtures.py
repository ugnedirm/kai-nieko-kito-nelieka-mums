"""Checks the sample vault against the schemas and with an independent mini-verifier.

The mini-verifier is deliberately tiny and separate from Person A's real `verify`: if A's verify
disagrees with `expected.json`, one of them has a bug.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.test_schemas import validator
from threadvault.core.hashing import record_hash

REPO = Path(__file__).parent.parent
VAULT = REPO / "tests" / "fixtures" / "vault"
EXPECTED = json.loads((VAULT / "expected.json").read_text())


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def verify_chain(records: list[dict[str, Any]], start_prev: str | None) -> tuple[bool, int | None]:
    """Returns (ok, index_of_first_bad_record)."""
    prev = start_prev
    for i, rec in enumerate(records):
        if rec["prev_hash"] != prev or rec["hash"] != record_hash(rec):
            return False, i
        prev = rec["hash"]
    return True, None


def test_generator_is_deterministic() -> None:
    before = {p: p.read_bytes() for p in VAULT.rglob("*") if p.is_file()}
    subprocess.run([sys.executable, str(REPO / "tools" / "make_fixtures.py")], check=True, cwd=REPO)
    after = {p: p.read_bytes() for p in VAULT.rglob("*") if p.is_file()}
    assert before == after


@pytest.mark.parametrize("tid", sorted(EXPECTED))
def test_every_record_matches_its_schema(tid: str) -> None:
    base = VAULT / "threads" / tid
    validator("manifest").validate(json.loads((base / "manifest.json").read_text()))
    for b in (base / "branches").glob("*.json"):
        validator("branch").validate(json.loads(b.read_text()))
    for chain in (base / "chains").glob("*.jsonl"):
        for rec in read_jsonl(chain):
            validator(rec["type"]).validate(rec)


@pytest.mark.parametrize("tid", sorted(EXPECTED))
def test_verify_matches_expected(tid: str) -> None:
    base = VAULT / "threads" / tid
    exp = EXPECTED[tid]
    results = []
    for b in sorted((base / "branches").glob("*.json")):
        branch = json.loads(b.read_text())
        records = read_jsonl(base / "chains" / f"{branch['branch_id']}.jsonl")
        start = branch["parent"]["fork_point"].get("hash") if branch["parent"] else None
        results.append(verify_chain(records, start))
    if exp["verify"] == "ok":
        assert all(ok for ok, _ in results)
    else:
        bad = [(ok, i) for ok, i in results if not ok]
        assert bad, "tampered thread must fail verification"
        records = read_jsonl(base / "chains" / "main0001.jsonl")
        assert records[bad[0][1]]["seq"] == exp["at_seq"]


def test_files_and_tombstones_are_consistent() -> None:
    blobs = {p.name for p in (VAULT / "blobs").iterdir()}
    for p in (VAULT / "blobs").iterdir():
        assert hashlib.sha256(p.read_bytes()).hexdigest() == p.name
    for tid, exp in EXPECTED.items():
        manifest = json.loads((VAULT / "threads" / tid / "manifest.json").read_text())
        for f in manifest["files"]:
            assert f["sha256"].removeprefix("sha256:") in blobs
        for sha in exp.get("tombstoned_files", []):
            assert sha.removeprefix("sha256:") not in blobs


def test_fork_shares_history_with_parent() -> None:
    base = VAULT / "threads" / "thr_forked01"
    main = read_jsonl(base / "chains" / "main0001.jsonl")
    fork_branch = json.loads((base / "branches" / "fork0001.json").read_text())
    fork_hash = fork_branch["parent"]["fork_point"]["hash"]
    assert fork_hash in {r["hash"] for r in main}
    assert read_jsonl(base / "chains" / "fork0001.jsonl")[0]["prev_hash"] == fork_hash


def test_access_log_chain_and_schema() -> None:
    entries = read_jsonl(VAULT / "access.jsonl")
    for e in entries:
        validator("access_entry").validate(e)
    assert verify_chain(entries, None) == (True, None)
    assert any(e["outcome"] == "denied" for e in entries)


def test_policy_matches_schema() -> None:
    validator("policy").validate(json.loads((VAULT / "policy.json").read_text()))


def test_planted_secrets_present_where_expected() -> None:
    text = (VAULT / "threads" / "thr_secrets01" / "chains" / "main0001.jsonl").read_text()
    for needle in ["AKIAIOSFODNN7EXAMPLE", "maria.jonaityte@example.com", "BEGIN RSA PRIVATE KEY",
                   "postgres://admin:hunter2", "Ignore all previous instructions"]:
        assert needle in text
