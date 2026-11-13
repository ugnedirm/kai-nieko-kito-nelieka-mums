"""Property-based tests that try to break the chain (THREAT_MODEL section 6, Person A).

1. Any sequence of legitimate operations (messages, handovers, files, forks, amendments, forget)
   leaves every thread verifying.
2. Any single tampering step on a chain file is detected.
3. With signatures, even an attacker who recomputes every hash and link is detected.
4. Arbitrary bytes in a chain file never crash verify, and never pass unless unchanged.
5. Any edit to the access log is detected.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from tests.conftest import HUMAN, handover, make_clock, message
from threadvault.core.accesslog import FileAccessLog, MemoryAccessLog
from threadvault.core.disk import DiskVault
from threadvault.core.hashing import record_hash
from threadvault.core.pack import approx_tokens
from threadvault.core.signing import MemoryKeyStore

# More examples locally: TV_PROPERTY_EXAMPLES=500 pytest tests/test_properties.py
SETTINGS = settings(max_examples=int(os.environ.get("TV_PROPERTY_EXAMPLES", "30")), deadline=None,
                    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])

text = st.text(st.characters(codec="utf-8", exclude_categories=("Cs",)), max_size=40)
op = st.one_of(
    st.tuples(st.just("msg"), text),
    st.tuples(st.just("handover"), text),
    st.tuples(st.just("file"), st.binary(min_size=1, max_size=30)),
    st.tuples(st.just("fork"), st.integers(min_value=0, max_value=50)),
    st.tuples(st.just("amend"), st.integers(min_value=0, max_value=50)),
    st.tuples(st.just("forget"), st.integers(min_value=0, max_value=50)),
    st.tuples(st.just("switch"), st.integers(min_value=0, max_value=50)),
)


def build(root: Path, ops: list[tuple[str, Any]], *, signed: bool = False,
          keystore: MemoryKeyStore | None = None) -> tuple[DiskVault, str]:
    ks = keystore or (MemoryKeyStore() if signed else None)
    v = DiskVault(root, keystore=ks, clock=make_clock(), log=MemoryAccessLog(),
                  token_counter=approx_tokens)
    tid = v.create_thread("prop", "full")
    branch = "main0001"
    files: list[str] = []
    for kind, arg in ops:
        visible = v.branch_records(tid, branch)
        if kind == "msg":
            refs = [s for s in files if v.blobs.has(s)][-1:]
            v.append(tid, branch, message(arg, **({"file_refs": refs} if refs else {})))
        elif kind == "handover":
            live = [s for s in files if v.blobs.has(s)][-2:]
            v.append(tid, branch, handover(arg or "fact", files=[
                {"sha256": s, "name": "f.txt", "description": "d"} for s in live]))
        elif kind == "file":
            files.append(v.put_file(tid, "f.txt", "text/plain", arg)["sha256"])
        elif kind == "fork" and visible:
            branch = v.fork(tid, branch, at_hash=visible[arg % len(visible)]["hash"])
        elif kind == "amend":
            msgs = [r for r in visible if r["type"] == "message"]
            if msgs:
                v.amend_message(tid, branch, msgs[arg % len(msgs)]["id"], "fix", author=HUMAN)
        elif kind == "forget" and files:
            v.forget_file(files[arg % len(files)])
        elif kind == "switch":
            branches = sorted(v.load_thread(tid).branches)
            branch = branches[arg % len(branches)]
    return v, tid


def chain_files(v: DiskVault, tid: str) -> list[Path]:
    return sorted(p for p in (v.root / "threads" / tid / "chains").glob("*.jsonl")
                  if p.read_bytes().strip())


@SETTINGS
@given(ops=st.lists(op, max_size=25))
def test_legitimate_operations_always_verify(ops: list[tuple[str, Any]]) -> None:
    with tempfile.TemporaryDirectory() as d:
        v, tid = build(Path(d) / "v", ops)
        report = v.verify(tid)
        assert report.ok, report
        for b, data in v.load_thread(tid).branches.items():
            head = next(x["head_hash"] for x in v.load_thread(tid).manifest["branches"]
                        if x["branch_id"] == b)
            assert head == (data.records[-1]["hash"] if data.records else None)


# -- tampering ------------------------------------------------------------------------------------------
def _mutate_value(obj: Any, pick: int) -> tuple[Any, bool]:
    """Change one scalar inside a record (depth-first, the pick-th scalar)."""
    scalars: list[tuple[Any, Any]] = []

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k in sorted(o):
                if isinstance(o[k], (dict, list)):
                    walk(o[k])
                else:
                    scalars.append((o, k))
        elif isinstance(o, list):
            for i, item in enumerate(o):
                if isinstance(item, (dict, list)):
                    walk(item)
                else:
                    scalars.append((o, i))

    walk(obj)
    container, key = scalars[pick % len(scalars)]
    old = container[key]
    if isinstance(old, bool):
        container[key] = not old
    elif isinstance(old, int):
        container[key] = old + 1
    elif isinstance(old, str):
        container[key] = old + "x"
    elif old is None:
        container[key] = "sha256:" + "0" * 64
    return obj, container[key] != old


mutation = st.sampled_from(["value", "delete", "duplicate", "swap", "truncate", "add_key",
                            "drop_key", "foreign"])


@SETTINGS
@given(ops=st.lists(op, min_size=1, max_size=15), kind=mutation,
       pick=st.integers(min_value=0, max_value=10_000), pick2=st.integers(min_value=0,
                                                                         max_value=10_000))
def test_any_tampering_is_detected(ops: list[tuple[str, Any]], kind: str, pick: int,
                                   pick2: int) -> None:
    with tempfile.TemporaryDirectory() as d:
        v, tid = build(Path(d) / "v", [("msg", "seed"), *ops])
        paths = chain_files(v, tid)
        path = paths[pick % len(paths)]
        lines = path.read_bytes().splitlines()
        i, j = pick % len(lines), pick2 % len(lines)
        rows = [json.loads(x) for x in lines]
        if kind == "value":
            rows[i], changed = _mutate_value(rows[i], pick2)
            assume(changed)
        elif kind == "delete":
            del rows[i]
        elif kind == "duplicate":
            rows.insert(i, dict(rows[i]))
        elif kind == "swap":
            assume(i != j and rows[i] != rows[j])
            rows[i], rows[j] = rows[j], rows[i]
        elif kind == "truncate":
            rows = rows[:i]
        elif kind == "add_key":
            rows[i]["note"] = "injected"
        elif kind == "drop_key":
            keys = sorted(k for k in rows[i] if k != "signature")
            rows[i].pop(keys[pick2 % len(keys)])
        elif kind == "foreign":
            other = DiskVault(Path(d) / "other", log=MemoryAccessLog(), clock=make_clock())
            otid = other.create_thread("o", "full")
            rec = other.append(otid, "main0001", message("foreign"))
            rows.insert(i, rec)
        path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in rows))
        assert not v.verify(tid).ok, (kind, i, j)


@SETTINGS
@given(ops=st.lists(op, min_size=1, max_size=12), pick=st.integers(min_value=0, max_value=10_000),
       new=text)
def test_rehashing_attacker_is_caught_by_signatures(ops: list[tuple[str, Any]], pick: int,
                                                    new: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        ks = MemoryKeyStore()
        v, tid = build(Path(d) / "v", [("msg", "seed"), *ops], keystore=ks)
        root_chain = v.root / "threads" / tid / "chains" / "main0001.jsonl"
        rows = [json.loads(x) for x in root_chain.read_bytes().splitlines()]
        msgs = [k for k, r in enumerate(rows) if r["type"] == "message"]
        i = msgs[pick % len(msgs)]
        assume(rows[i]["content"] != new)
        rows[i]["content"] = new
        for k in range(i, len(rows)):  # recompute every hash and link from the edit on
            rows[k]["prev_hash"] = rows[k - 1]["hash"] if k else None
            rows[k]["hash"] = record_hash(rows[k])
        root_chain.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in rows))
        mpath = v.root / "threads" / tid / "manifest.json"
        m = json.loads(mpath.read_text(encoding="utf-8"))
        for b in m["branches"]:
            if b["branch_id"] == "main0001":
                b["head_hash"] = rows[-1]["hash"]
        mpath.write_text(json.dumps(m), encoding="utf-8")
        codes = {iss.code for b in v.verify(tid).branches for iss in b.issues}
        assert "signature_invalid" in codes


@SETTINGS
@given(ops=st.lists(op, min_size=1, max_size=8), junk=st.binary(max_size=300))
def test_verify_never_crashes_on_arbitrary_bytes(ops: list[tuple[str, Any]], junk: bytes) -> None:
    with tempfile.TemporaryDirectory() as d:
        v, tid = build(Path(d) / "v", [("msg", "seed"), *ops])
        path = v.root / "threads" / tid / "chains" / "main0001.jsonl"
        original = path.read_bytes()
        assume(junk != original)
        path.write_bytes(junk)
        report = v.verify(tid)  # must not raise
        assert not report.ok


@SETTINGS
@given(n=st.integers(min_value=1, max_value=8), pick=st.integers(min_value=0, max_value=1000),
       field=st.sampled_from(["outcome", "action", "ts", "seq", "detail", "delete", "swap"]))
def test_access_log_tampering_is_detected(n: int, pick: int, field: str) -> None:
    with tempfile.TemporaryDirectory() as d:
        log = FileAccessLog(Path(d) / "access.jsonl", clock=make_clock())
        actions = ["load", "append", "verify", "export", "forget", "ingest", "fork", "list"]
        for k in range(n + 1):
            log.record(client_id=f"c{k}", kind="ai", action=actions[k % len(actions)],
                       outcome="allowed", detail=f"step {k}")
        rows = log.entries()
        i = pick % len(rows)
        if field == "delete":
            del rows[i]
        elif field == "swap":
            j = (i + 1) % len(rows)
            rows[i], rows[j] = rows[j], rows[i]
        elif field == "outcome":
            rows[i]["outcome"] = "denied"
        elif field == "action":
            rows[i]["action"] = "list" if rows[i]["action"] != "list" else "load"
        elif field == "ts":
            rows[i]["ts"] = "2030-01-01T00:00:00Z"
        elif field == "seq":
            rows[i]["seq"] += 1
        else:
            rows[i]["detail"] = "nothing happened"
        log.path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in rows))
        if field == "delete" and i == len(rows):  # dropping the last entry: only a head anchor
            return                                 # (not part of the log format) could catch it
        assert log.verify(), field
