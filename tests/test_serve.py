"""The extension-facing HTTP service, over a real socket on 127.0.0.1 with a temporary vault."""

import http.client
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from threadvault.cli import serve as serve_mod
from threadvault.cli.main import STARTER_POLICY, app
from threadvault.core.accesslog import FileAccessLog
from threadvault.core.disk import DiskVault
from threadvault.core.vault import Vault

ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
TS = "2026-11-14T09:00:00Z"
CLIENT = {"client_id": "browser-extension", "version": "0.1",
          "adapter": {"site": "chatgpt", "version": "1"}}


class Env:
    def __init__(self, server: serve_mod.IngestServer, root: Path, vault: Vault) -> None:
        self.server, self.root, self.vault = server, root, vault
        self.port = server.server_address[1]
        self.token = server.token

    def call(self, method: str, path: str, body: Any = None, *, token: str | None = "",
             host: str | None = None, origin: str | None = None,
             ctype: str | None = "application/json", raw: bytes | None = None,
             headers: dict[str, str] | None = None) -> tuple[int, Any, dict[str, str]]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h: dict[str, str] = {"Host": host or f"127.0.0.1:{self.port}"}
        use = self.token if token == "" else token
        if use:
            h["Authorization"] = f"Bearer {use}"
        if origin:
            h["Origin"] = origin
        if ctype:
            h["Content-Type"] = ctype
        h.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        conn.request(method, path, body=data, headers=h)
        resp = conn.getresponse()
        text = resp.read()
        out = json.loads(text) if text else None
        result = (resp.status, out, {k.lower(): v for k, v in resp.getheaders()})
        conn.close()
        return result


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    root = tmp_path / "v"
    vault = DiskVault(root)
    token = serve_mod.ensure_token(root)
    server = serve_mod.serve(vault, STARTER_POLICY, FileAccessLog(root / "access.jsonl"), token,
                             {ORIGIN}, 0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield Env(server, root, vault)
    server.shutdown()
    server.server_close()


def handover(fact: str = "Budget is fixed") -> dict[str, Any]:
    return {"kind": "handover",
            "content": {"decisions": [], "open_questions": [], "next_steps": [], "files": [],
                        "key_facts": [{"text": fact, "source_note": "chat"}], "constraints": [],
                        "uncertain": []},
            "metadata": {"author": {"kind": "ai"}, "created_at": TS, "prompt_version": "1",
                         "provenance": "provider-verified", "thread_state": {"source": "live-chat"}}}


def request(payload: dict[str, Any], rid: str = "req_00000001", **over: Any) -> dict[str, Any]:
    req: dict[str, Any] = {
        "spec_version": "1", "type": "ingest_request", "request_id": rid, "client": CLIENT,
        "captured_at": TS, "user_reviewed": True,
        "target": {"new_thread": {"title": "From web", "mode": "full"}}, "payload": payload}
    return req | over


def test_token_is_private_and_stable(tmp_path: Path) -> None:
    t1 = serve_mod.ensure_token(tmp_path / "x")
    assert len(t1) >= 32 and serve_mod.ensure_token(tmp_path / "x") == t1
    if os.name == "posix":
        assert ((tmp_path / "x" / "token").stat().st_mode & 0o077) == 0


def test_health_needs_no_token_but_checks_host(env: Env) -> None:
    code, body, _ = env.call("GET", "/v1/health", token=None, ctype=None)
    assert code == 200 and body == {"spec_version": "1"}
    code, _, _ = env.call("GET", "/v1/health", token=None, ctype=None, host="evil.example")
    assert code == 403


def test_token_required_and_wrong_token_logged(env: Env) -> None:
    for tok in (None, "wrong-token-wrong-token-wrong-token-xx"):
        code, _, _ = env.call("POST", "/v1/ingest", request(handover()), token=tok)
        assert code == 401
    log = (env.root / "access.jsonl").read_text()
    assert '"outcome":"denied"' in log and env.token not in log


def test_host_and_origin_checks(env: Env) -> None:
    body = request(handover())
    assert env.call("POST", "/v1/ingest", body, host="rebind.example:80")[0] == 403
    assert env.call("POST", "/v1/ingest", body, origin="https://evil.example")[0] == 403
    assert env.call("POST", "/v1/ingest", body, origin="chrome-extension://other")[0] == 403
    code, _, hdrs = env.call("POST", "/v1/ingest", body, origin=ORIGIN)
    assert code == 200 and hdrs["access-control-allow-origin"] == ORIGIN
    code, _, hdrs = env.call("GET", "/v1/threads", ctype=None)  # no Origin header: allowed
    assert code == 200 and "access-control-allow-origin" not in hdrs
    assert env.call("OPTIONS", "/v1/ingest", token=None, origin="https://evil.example")[0] == 403
    code, _, hdrs = env.call("OPTIONS", "/v1/ingest", token=None, origin=ORIGIN)
    assert code == 204 and hdrs["access-control-allow-origin"] == ORIGIN


def test_json_only_and_limits(env: Env) -> None:
    assert env.call("POST", "/v1/ingest", raw=b"{}", ctype="text/plain")[0] == 415
    assert env.call("POST", "/v1/ingest", raw=b"{nope")[0] == 400
    assert env.call("POST", "/v1/ingest", raw=b'{"a": 1.5}')[0] == 400  # floats are refused
    big = {"Content-Length": str(serve_mod.MAX_BODY_BYTES + 1)}
    assert env.call("POST", "/v1/ingest", raw=b"", headers=big)[0] == 413
    assert env.call("POST", "/v1/nope", {})[0] == 404


def test_schema_violation_is_rejected_without_echo(env: Env) -> None:
    code, body, _ = env.call("POST", "/v1/ingest", {"type": "ingest_request", "x": "SECRET-ish"})
    assert code == 400 and body["status"] == "rejected" and "SECRET-ish" not in json.dumps(body)


def test_handover_saved_end_to_end_and_idempotent(env: Env) -> None:
    code, body, _ = env.call("POST", "/v1/ingest", request(handover()))
    assert code == 200 and body["status"] == "accepted"
    tid = body["thread_id"]
    assert env.vault.verify(tid).ok
    assert "Budget is fixed" in env.vault.render_text(tid)
    # provenance is assigned by the vault, not the client
    assert isinstance(env.vault, DiskVault)
    stored = [r for r in env.vault.branch_records(tid) if r["type"] == "handover"]
    assert [r["metadata"]["provenance"] for r in stored] == ["ai-summary-user-saved"]
    again = env.call("POST", "/v1/ingest", request(handover()))[1]
    assert again == body and len(env.vault.list_threads()) == 1
    code, _, _ = env.call("POST", "/v1/ingest", request(handover("Different")))
    assert code == 400
    code, threads, _ = env.call("GET", "/v1/threads", ctype=None)
    assert code == 200 and threads == [{"thread_id": tid, "title": "From web"}]


def test_messages_saved_as_unverified(env: Env) -> None:
    msgs = {"kind": "messages", "messages": [
        {"role": "user", "author": {"kind": "human"}, "created_at": TS, "content": "hello"},
        {"role": "assistant", "author": {"kind": "ai"}, "created_at": TS, "content": "hi"}]}
    code, body, _ = env.call("POST", "/v1/ingest", request(msgs))
    assert code == 200, body
    assert env.vault.verify(body["thread_id"]).ok
    assert isinstance(env.vault, DiskVault)
    recs = env.vault.branch_records(body["thread_id"])
    assert [r["provenance"] for r in recs if r["type"] == "message"] == ["imported-unverified"] * 2


def test_secret_blocked_and_pii_needs_confirmation(env: Env) -> None:
    code, body, _ = env.call("POST", "/v1/ingest", request(handover("key AKIAIOSFODNN7EXAMPLE")))
    assert code == 400 and body["error"] == "blocked by policy"
    assert env.vault.list_threads() == []
    pii = request(handover("write to jane.doe@example.com"), rid="req_00000002")
    code, body, _ = env.call("POST", "/v1/ingest", pii)
    assert code == 200 and body["status"] == "needs_confirmation" and env.vault.list_threads() == []
    assert "jane.doe" not in json.dumps(body)
    code, body, _ = env.call("POST", "/v1/ingest", pii | {"acknowledged_findings": True})
    assert body["status"] == "accepted"


def test_unreviewed_handover_and_unlisted_client_refused(env: Env) -> None:
    assert env.call("POST", "/v1/ingest", request(handover(), user_reviewed=False))[0] == 400
    stranger = request(handover(), client=CLIENT | {"client_id": "rogue-app"})
    code, body, _ = env.call("POST", "/v1/ingest", stranger)
    assert code == 400 and body["error"] == "not permitted by policy"
    assert env.vault.list_threads() == []


def test_no_policy_means_nothing_is_allowed(tmp_path: Path) -> None:
    root = tmp_path / "v"
    server = serve_mod.serve(DiskVault(root), None, FileAccessLog(root / "access.jsonl"),
                             serve_mod.ensure_token(root), set(), 0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        e = Env(server, root, DiskVault(root))
        assert e.call("GET", "/v1/threads", ctype=None)[0] == 403
        assert e.call("POST", "/v1/ingest", request(handover()))[1]["status"] == "rejected"
    finally:
        server.shutdown()
        server.server_close()


def test_rate_limit(env: Env) -> None:
    env.server.limiter = serve_mod._RateLimiter(3, 60.0)
    codes = [env.call("GET", "/v1/threads", ctype=None)[0] for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_init_and_token_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    v = ["--vault", str(tmp_path / "v")]
    r = runner.invoke(app, [*v, "init"])
    assert r.exit_code == 0 and (tmp_path / "v" / "policy.json").exists()
    tok = runner.invoke(app, [*v, "token", "show"]).output.strip()
    assert tok == serve_mod.read_token(tmp_path / "v")
    again = runner.invoke(app, [*v, "init"])
    assert "left unchanged" in again.output
    bad = runner.invoke(app, [*v, "serve", "--origin", "https://evil.example"])
    assert bad.exit_code == 1
