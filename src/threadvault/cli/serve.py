"""Local ingest HTTP service for the browser extension (SPEC.md section 8).

A thin HTTP layer around `connector.ingest.IngestService`. It owns the transport checks the
service leaves out: 127.0.0.1 bind, bearer token (constant-time), `Host` and `Origin` checks, JSON
only, body limit and a rate limit. Every other decision (policy, scanning, provenance, ids and
hashes) is made by `IngestService` and the vault. Nothing here logs request content.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from threadvault.connector.ingest import IngestService
from threadvault.core.accesslog import AccessLog
from threadvault.core.jsonio import StrictJSONError, loads
from threadvault.core.vault import Vault
from threadvault.policy.engine import decide
from threadvault.policy.engine import load_policy as load_policy_file
from threadvault.types import Record

MAX_BODY_BYTES = 70 * 1024 * 1024
RATE_LIMIT = 120  # requests per window, per token
RATE_WINDOW_S = 60.0
CLIENT_ID = "browser-extension"  # the policy entry that governs the extension
ORIGIN_PREFIXES = ("chrome-extension://", "moz-extension://")
TOKEN_FILE = "token"


def read_token(root: Path) -> str | None:
    try:
        token = (root / TOKEN_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token if len(token) >= 32 else None


def ensure_token(root: Path) -> str:
    """The install's 256-bit token, created (mode 0600) on first use."""
    existing = read_token(root)
    if existing:
        return existing
    root.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    path = root / TOKEN_FILE
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # present but too short: replace it
        path.unlink()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    return token


def valid_origin(origin: str) -> bool:
    return origin.startswith(ORIGIN_PREFIXES) and 0 < len(origin) <= 200 and origin.isprintable()


class _RateLimiter:
    def __init__(self, limit: int, window: float) -> None:
        self._limit, self._window = limit, window
        self._hits: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._hits and now - self._hits[0] > self._window:
                self._hits.popleft()
            if len(self._hits) >= self._limit:
                return False
            self._hits.append(now)
            return True


class IngestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, vault: Vault, policy: Record | None, log: AccessLog, token: str,
                 origins: set[str], port: int = 8765) -> None:
        super().__init__(("127.0.0.1", port), _Handler)
        bound = self.server_address[1]
        self.token = token
        self.origins = frozenset(origins)
        self.hosts = frozenset({f"127.0.0.1:{bound}", f"localhost:{bound}"})
        self.vault, self.policy, self.log = vault, policy, log
        self.service = IngestService(vault, policy, log)
        self.lock = threading.Lock()  # the vault and the service are used by one request at a time
        self.limiter = _RateLimiter(RATE_LIMIT, RATE_WINDOW_S)


class _Handler(BaseHTTPRequestHandler):
    server: IngestServer
    server_version = "threadvault"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    # -- plumbing ----------------------------------------------------------------------------------
    def _send(self, code: int, body: Any, origin: str | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if origin and origin in self.server.origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        if code >= 400:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def _deny(self, code: int, why: str, action: str = "ingest", note: str = "denied") -> None:
        # A logging failure must not turn a denial into a different answer.
        with contextlib.suppress(Exception):
            self.server.log.record(client_id="unknown", kind="extension", action=action,
                                   outcome="denied", detail=note)
        self._send(code, {"error": why})

    def _gate(self, *, health: bool) -> str | None:
        """Host, Origin and token checks. Returns the (allowlisted) Origin or '' when it passes;
        None when the request was already answered."""
        if self.headers.get("Host", "") not in self.server.hosts:
            self._deny(403, "forbidden", note="bad host header")
            return None
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.origins:
            self._deny(403, "forbidden", note="origin not allowed")
            return None
        if health:
            return origin or ""
        auth = self.headers.get("Authorization", "")
        supplied = auth[7:] if auth.startswith("Bearer ") else ""
        if not hmac.compare_digest(supplied.encode(), self.server.token.encode()):
            self._deny(401, "unauthorized", note="missing or wrong token")
            return None
        if not self.server.limiter.allow():
            self._send(429, {"error": "too many requests"}, origin)
            return None
        return origin or ""

    # -- verbs -------------------------------------------------------------------------------------
    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin")
        if self.headers.get("Host", "") not in self.server.hosts or origin not in self.server.origins:
            self._deny(403, "forbidden", note="preflight refused")
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin or "")
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/v1/health":
            origin = self._gate(health=True)
            if origin is not None:
                self._send(200, {"spec_version": "1"}, origin)
            return
        if path != "/v1/threads":
            self._send(404, {"error": "not found"})
            return
        origin = self._gate(health=False)
        if origin is None:
            return
        pol = self.server.policy
        if not any(decide(pol, CLIENT_ID, cap).allowed for cap in ("append", "save_handover")):
            self._deny(403, "forbidden", action="list", note="not permitted by policy")
            return
        with self.server.lock:
            threads = [{"thread_id": t.thread_id, "title": t.title}
                       for t in self.server.vault.list_threads()]
        self._send(200, threads, origin)

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/v1/ingest":
            self._send(404, {"error": "not found"})
            return
        origin = self._gate(health=False)
        if origin is None:
            return
        ctype = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            self._send(415, {"error": "JSON only"}, origin)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send(411, {"error": "length required"}, origin)
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(413, {"error": "body too large"}, origin)
            return
        raw = self.rfile.read(length)
        try:
            request = loads(raw)
        except (StrictJSONError, UnicodeDecodeError, RecursionError):
            self._send(400, {"error": "invalid JSON"}, origin)
            return
        with self.server.lock:
            try:
                response = self.server.service.handle(request)
            except Exception:  # noqa: BLE001 - never echo internals (could contain content)
                self._send(500, {"error": "internal error"}, origin)
                return
        self._send(400 if response["status"] == "rejected" else 200, response, origin)


def serve(vault: Vault, policy: Record | None, log: AccessLog, token: str, origins: set[str],
          port: int) -> IngestServer:
    """Build the server (not yet serving); the caller runs `serve_forever()`."""
    return IngestServer(vault, policy, log, token, origins, port)


def load_policy(root: Path) -> tuple[Record | None, list[str]]:
    loaded = load_policy_file(root / "policy.json")
    return loaded.policy, loaded.problems
