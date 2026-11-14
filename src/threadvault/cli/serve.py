"""Local HTTP service for the browser extension and the browser vault pages (SPEC.md section 8).

Two audiences, two kinds of authentication:
- The extension API (`/v1/ingest`, `/v1/threads`, `/v1/open`) uses a bearer token (constant-time
  compare), plus `Host` and `Origin` checks, JSON only, a body limit and a rate limit.
- The vault pages (`/`, `/t/<id>`) are for the person: they need a session cookie obtained from a
  one-time sign-in link (`/s/<code>`), made by `thread open` or by the extension via `/v1/open`.
- Pairing: an extension asks to connect (`/v1/pair/request`); the person approves it on `/pair`
  with a click (single-use CSRF token, same-origin POST); only the requester, proven by a secret
  poll id and its Origin, receives the token, once.

Policy, scanning, provenance, ids and hashes remain the job of `IngestService` and the vault.
Nothing here logs request content, tokens or message text.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from threadvault.cli import attach, lifecycle, share, viewer
from threadvault.connector.ingest import MAX_FILE_BYTES, IngestService
from threadvault.core.accesslog import AccessLog, FileAccessLog
from threadvault.core.jsonio import StrictJSONError, loads
from threadvault.core.vault import Vault
from threadvault.policy.engine import decide
from threadvault.policy.engine import load_policy as load_policy_file
from threadvault.types import Record

MAX_BODY_BYTES = 70 * 1024 * 1024
MAX_FORM_BYTES = 4096
RATE_LIMIT = 120  # requests per window, per token
RATE_WINDOW_S = 60.0
LOGIN_TTL_S = 120.0
SESSION_TTL_S = 2 * 3600.0  # short: cookies are shared by every port on 127.0.0.1
PAIR_TTL_S = 300.0
MAX_PENDING_PAIRS = 3
CLIENT_ID = "browser-extension"  # the policy entry that governs the extension
ORIGIN_PREFIXES = ("chrome-extension://", "moz-extension://")
TOKEN_FILE = "token"
ORIGINS_FILE = "origins.json"
LOGIN_DIR = "logins"
THREAD_PATH = re.compile(r"^/t/([A-Za-z0-9_-]{8,64})$")
FORGET_PATH = re.compile(r"^/forget/([A-Za-z0-9_-]{8,64})/([0-9a-f]{64})$")
DELETE_PATH = re.compile(r"^/delete/([A-Za-z0-9_-]{8,64})$")
EXPIRE_PATH = re.compile(r"^/expire/([A-Za-z0-9_-]{8,64})$")
MERGE_PATH = re.compile(r"^/merge/([A-Za-z0-9_-]{8,64})/([A-Za-z0-9_-]{8,64})$")
FILE_UPLOAD = re.compile(r"^/f/([A-Za-z0-9_-]{8,64})$")
FILE_PATH = re.compile(r"^/f/([A-Za-z0-9_-]{8,64})/([0-9a-f]{64})$")
CSP = ("default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


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


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def make_login_code(root: Path) -> str:
    """A one-time sign-in code for the vault pages, valid for two minutes. Used by `thread open`
    (a separate process): the running server finds the code by its hash in `logins/`."""
    code = secrets.token_urlsafe(24)
    d = root / LOGIN_DIR
    d.mkdir(parents=True, exist_ok=True)
    fd = os.open(d / _digest(code), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(str(int(time.time() + LOGIN_TTL_S)))
    return code


def read_origins(root: Path) -> set[str]:
    try:
        data = json.loads((root / ORIGINS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {o for o in data if isinstance(o, str) and valid_origin(o)} if isinstance(data, list) \
        else set()


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


@dataclass
class _Pairing:
    request_id: str
    origin: str
    created: float
    state: str = "pending"  # pending | approved | denied


class IngestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, vault: Vault, policy: Record | None, log: AccessLog, token: str,
                 origins: set[str], port: int = 8765, root: Path | None = None) -> None:
        super().__init__(("127.0.0.1", port), _Handler)
        bound = self.server_address[1]
        self.port = bound
        self.token = token
        self.root = root
        self.origins: set[str] = set(origins) | (read_origins(root) if root else set())
        self.hosts = frozenset({f"127.0.0.1:{bound}", f"localhost:{bound}"})
        self.own_origins = frozenset({f"http://127.0.0.1:{bound}", f"http://localhost:{bound}"})
        self.vault, self.policy, self.log = vault, policy, log
        self.service = IngestService(vault, policy, log)
        self.lock = threading.Lock()  # the vault and the service are used by one request at a time
        self.limiter = _RateLimiter(RATE_LIMIT, RATE_WINDOW_S)
        self.pair_limiter = _RateLimiter(20, 60.0)
        self._stop = threading.Event()
        self.state_lock = threading.Lock()  # guards the dicts below and `origins`
        self.sessions: dict[str, float] = {}
        self.logins: dict[str, float] = {}
        self.pairings: dict[str, _Pairing] = {}  # sha256(poll secret) -> pairing
        self.csrf: dict[str, float] = {}

    # -- state helpers (all take `state_lock`) --------------------------------------------------
    def _purge(self, now: float) -> None:
        for d in (self.sessions, self.logins, self.csrf):
            for k in [k for k, exp in d.items() if exp < now]:
                del d[k]
        for k in [k for k, p in self.pairings.items() if p.created + PAIR_TTL_S < now]:
            del self.pairings[k]

    def new_login(self) -> str:
        code = secrets.token_urlsafe(24)
        with self.state_lock:
            self._purge(time.time())
            self.logins[_digest(code)] = time.time() + LOGIN_TTL_S
        return code

    def consume_login(self, code: str) -> bool:
        key = _digest(code)
        now = time.time()
        with self.state_lock:
            self._purge(now)
            if self.logins.pop(key, 0) > now:
                return True
        if self.root is not None:
            path = self.root / LOGIN_DIR / key
            try:
                expiry = int(path.read_text(encoding="utf-8"))
                path.unlink()
            except (OSError, ValueError):
                return False
            return expiry > now
        return False

    def new_session(self) -> str:
        sid = secrets.token_urlsafe(32)
        with self.state_lock:
            self._purge(time.time())
            self.sessions[sid] = time.time() + SESSION_TTL_S
        return sid

    def session_ok(self, sid: str) -> bool:
        with self.state_lock:
            return self.sessions.get(sid, 0) > time.time()

    def new_csrf(self) -> str:
        t = secrets.token_urlsafe(24)
        with self.state_lock:
            self._purge(time.time())
            self.csrf[t] = time.time() + PAIR_TTL_S
        return t

    def use_csrf(self, t: str) -> bool:
        with self.state_lock:
            return self.csrf.pop(t, 0) > time.time()

    def add_origin(self, origin: str) -> None:
        with self.state_lock:
            self.origins.add(origin)
            snapshot = sorted(self.origins)
        if self.root is not None:
            tmp = self.root / (ORIGINS_FILE + ".tmp")
            tmp.write_text(json.dumps(snapshot), encoding="utf-8")
            os.replace(tmp, self.root / ORIGINS_FILE)

    def is_allowed_origin(self, origin: str) -> bool:
        with self.state_lock:
            return origin in self.origins


    def start_sweeper(self, interval: float = 900.0) -> None:
        """Delete expired threads and files now and then, so "delete after 7 days" really happens."""
        def loop() -> None:
            while True:
                with contextlib.suppress(Exception), self.lock:
                    self.vault.sweep_expired()
                if self._stop.wait(interval):
                    return
        threading.Thread(target=loop, daemon=True).start()

    def server_close(self) -> None:
        self._stop.set()
        super().server_close()


class _Handler(BaseHTTPRequestHandler):
    server: IngestServer
    server_version = "threadvault"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30  # a request that stalls (slow or never-ending body) is dropped, not held forever
    _body_read = False

    def log_message(self, format: str, *args: Any) -> None:
        return

    # -- plumbing ----------------------------------------------------------------------------------
    def _headers_common(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")  # "no-referrer" makes browsers send Origin: null

    def _finish(self, code: int, data: bytes, ctype: str, extra: dict[str, str] | None = None,
                origin: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self._headers_common()
        if origin and self.server.is_allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        # An unread request body would be parsed as the next request on a kept-alive connection.
        unread = self.command == "POST" and not self._body_read
        if code >= 400 or unread:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def _send(self, code: int, body: Any, origin: str | None = None) -> None:
        self._finish(code, json.dumps(body).encode(), "application/json", origin=origin)

    def _html(self, code: int, text: str, extra: dict[str, str] | None = None) -> None:
        self._finish(code, text.encode(), "text/html; charset=utf-8",
                     {"Content-Security-Policy": CSP, "X-Frame-Options": "DENY", **(extra or {})})

    def _redirect(self, location: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self._headers_common()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _record(self, action: str, outcome: str, note: str, kind: str = "extension",
                thread_id: str | None = None) -> None:
        # A logging failure must not turn an answer into a different answer.
        with contextlib.suppress(Exception):
            self.server.log.record(client_id="unknown", kind=kind, action=action,
                                   outcome=outcome, thread_id=thread_id, detail=note)

    def _deny(self, code: int, why: str, action: str = "ingest", note: str = "denied") -> None:
        self._record(action, "denied", note)
        self._send(code, {"error": why})

    def _host_ok(self) -> bool:
        if self.headers.get("Host", "") in self.server.hosts:
            return True
        self._deny(403, "forbidden", note="bad host header")
        return False

    def _gate(self, *, health: bool) -> str | None:
        """Host, Origin and token checks for the extension API. Returns the Origin ('' if none)
        when it passes; None when the request was already answered."""
        if not self._host_ok():
            return None
        origin = self.headers.get("Origin")
        # Health returns nothing but the spec version, so any extension may ask whether the vault
        # is running (an unpaired extension needs that); everything else needs an allowed origin.
        known = origin is None or self.server.is_allowed_origin(origin) \
            or origin in self.server.own_origins or (health and valid_origin(origin))
        if not known:
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

    def _has_session(self) -> bool:
        raw = self.headers.get("Cookie", "")
        try:
            jar = SimpleCookie(raw)
        except Exception:  # noqa: BLE001 - a malformed cookie is simply "no session"
            return False
        morsel = jar.get("tv_session")
        return bool(morsel and self.server.session_ok(morsel.value))

    def _read_body(self, limit: int) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send(411, {"error": "length required"})
            return None
        if length < 0 or length > limit:
            self._send(413, {"error": "body too large"})
            return None
        self._body_read = True
        return self.rfile.read(length)

    # -- verbs -------------------------------------------------------------------------------------
    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin")
        if (self.headers.get("Host", "") not in self.server.hosts or origin is None
                or not self.server.is_allowed_origin(origin)):
            self._deny(403, "forbidden", note="preflight refused")
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        path, _, query = self.path.partition("?")
        if path == "/v1/health":
            origin = self._gate(health=True)
            if origin is not None:
                self._send(200, {"spec_version": "1"}, origin)
        elif path == "/v1/threads":
            self._api_threads()
        elif path == "/v1/pair/status":
            self._pair_status(query)
        elif path == "/static/viewer.css":
            self._finish(200, viewer.CSS.encode(), "text/css; charset=utf-8")
        elif path == "/static/viewer.js":
            self._finish(200, viewer.JS.encode(), "text/javascript; charset=utf-8")
        elif path == "/pair":
            self._page_pair()
        elif path.startswith("/s/"):
            self._sign_in(path[3:])
        elif path == "/" or THREAD_PATH.match(path):
            self._page_vault(path, query)
        elif FILE_PATH.match(path):
            self._download(path)
        elif path == "/log":
            self._page_log()
        elif path == "/compare":
            self._page_compare(query)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/v1/ingest":
            self._api_ingest()
        elif path == "/v1/open":
            self._api_open()
        elif path == "/v1/ping":
            self._api_ping()
        elif path == "/v1/continue":
            self._api_continue()
        elif path == "/v1/pair/request":
            self._pair_request()
        elif path == "/pair/decide":
            self._pair_decide()
        elif FILE_UPLOAD.match(path):
            self._upload(path)
        elif MERGE_PATH.match(path):
            self._merge(path)
        elif FORGET_PATH.match(path) or DELETE_PATH.match(path) or EXPIRE_PATH.match(path):
            self._lifecycle(path)
        else:
            self._send(404, {"error": "not found"})

    # -- extension API -----------------------------------------------------------------------------
    def _api_threads(self) -> None:
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

    def _api_ping(self) -> None:
        """Does the whole save path work for this browser (token AND approved origin)? A POST on
        purpose: it carries the same Origin header a real save does."""
        origin = self._gate(health=False)
        if origin is None:
            return
        if origin == "":  # no Origin header: not a browser extension, so not a pairing
            self._send(200, {"ok": True})
            return
        self._send(200, {"ok": True}, origin)

    def _api_continue(self) -> None:
        """Text and files of one thread, prepared for a destination ("Continue here" in the
        extension). Needs the `export` capability in policy.json and the destination's profile."""
        origin = self._gate(health=False)
        if origin is None:
            return
        raw = self._read_body(4096)
        if raw is None:
            return
        try:
            req = loads(raw)
        except (StrictJSONError, UnicodeDecodeError):
            self._send(400, {"error": "invalid JSON"}, origin)
            return
        tid = req.get("thread_id") if isinstance(req, dict) else None
        dest = req.get("destination") if isinstance(req, dict) else None
        if not (isinstance(tid, str) and isinstance(dest, str)
                and re.fullmatch(r"[A-Za-z0-9_-]{8,64}", tid)
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", dest)):
            self._send(400, {"error": "bad request"}, origin)
            return
        if not decide(self.server.policy, CLIENT_ID, "export").allowed:
            self._deny(403, "forbidden", action="export", note="export not permitted by policy")
            return
        with self.server.lock:
            try:
                prepared = share.prepare(self.server.vault, self.server.policy, tid, dest)
            except (KeyError, ValueError, OSError):
                self._send(404, {"error": "no such thread"}, origin)
                return
            if prepared.problem:
                self._record("export", "denied", "blocked for the destination", thread_id=tid)
                self._send(409, {"error": prepared.problem}, origin)
                return
            self._record("export", "allowed", f"continue in {dest[:64]}", thread_id=tid)
        self._send(200, {"text": prepared.text, "hidden": prepared.hidden, "files": prepared.files,
                         "skipped": prepared.skipped}, origin)

    def _api_open(self) -> None:
        """Give the extension a one-time link that signs the person in to the vault pages."""
        origin = self._gate(health=False)
        if origin is None:
            return
        code = self.server.new_login()
        self._send(200, {"url": f"http://127.0.0.1:{self.server.port}/s/{code}"}, origin)

    def _api_ingest(self) -> None:
        origin = self._gate(health=False)
        if origin is None:
            return
        ctype = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            self._send(415, {"error": "JSON only"}, origin)
            return
        raw = self._read_body(MAX_BODY_BYTES)
        if raw is None:
            return
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

    # -- pairing -----------------------------------------------------------------------------------
    def _pair_origin(self) -> str | None:
        """Pairing endpoints take no token: the caller must be a browser extension (its Origin
        header cannot be forged by a web page)."""
        if not self._host_ok():
            return None
        origin = self.headers.get("Origin", "")
        if not valid_origin(origin):
            self._deny(403, "forbidden", action="pair", note="pairing needs an extension origin")
            return None
        if not self.server.pair_limiter.allow():
            self._send(429, {"error": "too many requests"})
            return None
        return origin

    def _pair_request(self) -> None:
        origin = self._pair_origin()
        if origin is None:
            return
        poll = secrets.token_urlsafe(32)
        srv = self.server
        with srv.state_lock:
            srv._purge(time.time())
            for k in [k for k, p in srv.pairings.items()
                      if p.origin == origin and p.state == "pending"]:
                del srv.pairings[k]  # pressing Connect again replaces the earlier request
            if sum(1 for p in srv.pairings.values() if p.state == "pending") >= MAX_PENDING_PAIRS:
                full = True
            else:
                full = False
                srv.pairings[_digest(poll)] = _Pairing(secrets.token_urlsafe(12), origin, time.time())
        if full:
            self._send(429, {"error": "too many pending requests"})
            return
        self._record("pair", "allowed", "pairing requested")
        self._send(200, {"poll": poll, "approve_url": f"http://127.0.0.1:{srv.port}/pair"})

    def _pair_status(self, query: str) -> None:
        # A GET may carry no Origin header (browsers differ), so the 256-bit poll secret, known
        # only to the extension that asked, is what authorises this; an Origin, if sent, must match.
        if not self._host_ok():
            return
        if not self.server.pair_limiter.allow():
            self._send(429, {"error": "too many requests"})
            return
        origin = self.headers.get("Origin")
        poll = (parse_qs(query).get("poll") or [""])[0]
        srv = self.server
        key = _digest(poll)
        with srv.state_lock:
            srv._purge(time.time())
            p = srv.pairings.get(key)
            if p is None or (origin is not None and p.origin != origin):
                status = "expired"
            else:
                status = p.state
                if status != "pending":
                    del srv.pairings[key]  # the answer is delivered once
        if status == "approved":
            self._send(200, {"status": "approved", "token": srv.token})
        else:
            self._send(200, {"status": status})

    def _page_pair(self) -> None:
        if not self._host_ok():
            return
        srv = self.server
        with srv.state_lock:
            srv._purge(time.time())
            now = time.time()
            pending = [(p.request_id, p.origin, int(now - p.created)) for p in srv.pairings.values()
                       if p.state == "pending"]
        self._html(200, viewer.pairing(pending, srv.new_csrf()))

    def _pair_decide(self) -> None:
        if not self._host_ok():
            return
        if self.headers.get("Origin") not in self.server.own_origins:
            self._record("pair", "denied", "decision from a foreign origin", kind="ui")
            self._html(403, viewer.message("Not allowed", "This request did not come from this page."))
            return
        raw = self._read_body(MAX_FORM_BYTES)
        if raw is None:
            return
        form = parse_qs(raw.decode("utf-8", errors="replace"))
        csrf = (form.get("csrf") or [""])[0]
        rid = (form.get("id") or [""])[0]
        decision = (form.get("decision") or [""])[0]
        srv = self.server
        if not srv.use_csrf(csrf) or decision not in ("allow", "deny"):
            self._html(400, viewer.message("Expired", "Reload the page and try again."))
            return
        with srv.state_lock:
            target = next((p for p in srv.pairings.values()
                           if p.request_id == rid and p.state == "pending"), None)
            if target is not None:
                target.state = "approved" if decision == "allow" else "denied"
                origin = target.origin
        if target is None:
            self._html(404, viewer.message("Expired", "That request is no longer waiting."))
            return
        if decision == "allow":
            srv.add_origin(origin)
            self._record("pair", "allowed", "extension approved", kind="ui")
            self._html(200, viewer.message("Connected", "You can close this tab and go back to "
                                           "your chat. Saving will now work."))
        else:
            self._record("pair", "denied", "extension refused by the user", kind="ui")
            self._html(200, viewer.message("Not connected", "The extension was not allowed."))

    # -- vault pages -------------------------------------------------------------------------------
    def _download(self, path: str) -> None:
        """A stored file, as a download only: never rendered, never given a guessable type."""
        if not self._host_ok():
            return
        if not self._has_session():
            self._html(401, viewer.locked())
            return
        m = FILE_PATH.match(path)
        assert m is not None
        thread_id, digest = m.group(1), "sha256:" + m.group(2)
        with self.server.lock:
            try:
                files = self.server.vault.load_thread(thread_id).manifest.get("files", [])
                entry = next((f for f in files if f.get("sha256") == digest), None)
                data = self.server.vault.get_file(digest) if entry else None
            except (KeyError, ValueError, OSError):
                entry, data = None, None
            if entry is None or data is None:
                self._html(404, viewer.message("Not found", "That file does not exist."))
                return
            self._record("get_file", "allowed", "file download", kind="ui", thread_id=thread_id)
        safe = re.sub(r"[^A-Za-z0-9._ -]", "_", str(entry.get("name", "file")))[:100].strip(" .") or "file"
        self._finish(200, data, "application/octet-stream", {
            "Content-Disposition": f'attachment; filename="{safe}"',
            "Content-Security-Policy": "sandbox; default-src 'none'", "X-Frame-Options": "DENY"})

    def _merge(self, path: str) -> None:
        """Fold a files-only thread into another (the person pressed Merge). Same guards as an
        upload: session cookie, same-origin request and a custom header."""
        if not self._host_ok():
            return
        if not self._has_session():
            self._html(401, viewer.locked())
            return
        if self.headers.get("Origin") not in self.server.own_origins \
                or self.headers.get("X-Merge") != "yes":
            self._record("append", "denied", "merge not from the vault page", kind="ui")
            self._send(403, {"error": "forbidden"})
            return
        m = MERGE_PATH.match(path)
        assert m is not None
        with self.server.lock:
            try:
                moved = self.server.vault.merge_files(m.group(1), m.group(2))
            except KeyError:
                self._send(404, {"error": "no such thread"})
                return
            except ValueError as e:
                self._send(409, {"error": str(e)[:200]})
                return
        self._send(200, {"moved": moved})

    def _lifecycle(self, path: str) -> None:
        """Forget a file, delete a thread or set its expiry, because the person pressed the button.
        Same guards as an upload: session cookie, same-origin request and a custom header."""
        if not self._host_ok():
            return
        if not self._has_session():
            self._html(401, viewer.locked())
            return
        expire = EXPIRE_PATH.match(path)
        header = "X-Expire" if expire else "X-Action"
        if self.headers.get("Origin") not in self.server.own_origins or header not in self.headers:
            self._record("forget", "denied", "change not from the vault page", kind="ui")
            self._send(403, {"error": "forbidden"})
            return
        vault = self.server.vault
        with self.server.lock:
            try:
                if (m := FORGET_PATH.match(path)) is not None:
                    files = vault.load_thread(m.group(1)).manifest["files"]
                    if not any(f["sha256"] == "sha256:" + m.group(2) for f in files):
                        raise KeyError("file")
                    vault.forget_file("sha256:" + m.group(2))
                elif (m := DELETE_PATH.match(path)) is not None:
                    vault.delete_thread(m.group(1))
                elif expire is not None:
                    choice = self.headers.get("X-Expire", "")
                    if choice not in lifecycle.CHOICES:
                        self._send(400, {"error": "unknown choice"})
                        return
                    when = None if choice == "never" else lifecycle.expires_in(choice)
                    vault.set_expiry(expire.group(1), when)
                    self._record("append", "allowed", "auto-delete time changed", kind="ui",
                                 thread_id=expire.group(1))
            except (KeyError, ValueError, OSError):
                self._send(404, {"error": "not found"})
                return
        self._send(200, {"ok": True})

    def _page_compare(self, query: str) -> None:
        if not self._host_ok():
            return
        if not self._has_session():
            self._html(401, viewer.locked())
            return
        q = parse_qs(query)
        with self.server.lock:
            try:
                text = viewer.compare(self.server.vault, (q.get("a") or [""])[0],
                                      (q.get("b") or [""])[0])
            except (KeyError, ValueError, OSError):
                self._html(500, viewer.message("Problem", "These threads could not be compared."))
                return
        self._html(200, text)

    def _page_log(self) -> None:
        if not self._host_ok():
            return
        if not self._has_session():
            self._html(401, viewer.locked())
            return
        log = FileAccessLog(self.server.root / "access.jsonl") if self.server.root else None
        if log is None:
            self._html(404, viewer.message("Not available", "This vault has no access log file."))
            return
        with self.server.lock:
            entries = log.entries()
            issues = len(log.verify())
        self._html(200, viewer.access_log(entries[-200:], issues, len(entries)))

    def _upload(self, path: str) -> None:
        """The person attaches a file from the vault page. Needs the session cookie, a same-origin
        request and a custom header (which a foreign page cannot send without a preflight)."""
        if not self._host_ok():
            return
        if not self._has_session():
            self._html(401, viewer.locked())
            return
        if self.headers.get("Origin") not in self.server.own_origins \
                or "X-Filename" not in self.headers:
            self._record("append", "denied", "upload not from the vault page", kind="ui")
            self._send(403, {"error": "forbidden"})
            return
        m = FILE_UPLOAD.match(path)
        assert m is not None
        thread_id = m.group(1)
        raw = self._read_body(MAX_FILE_BYTES)
        if raw is None:
            return
        from urllib.parse import unquote
        name = attach.clean_name(unquote(self.headers.get("X-Filename", "")))
        try:
            prepared = attach.prepare(raw, name)
        except attach.TooLarge:
            self._send(413, {"error": "file too large"})
            return
        if not prepared.complete and self.headers.get("X-Confirm") != "yes":
            self._send(409, {"error": "may carry hidden data", "notes": prepared.notes})
            return
        with self.server.lock:
            try:
                ref = self.server.vault.put_file(thread_id, name, prepared.media_type,
                                                 prepared.cleaned)
            except (KeyError, ValueError, OSError):
                self._send(404, {"error": "no such thread"})
                return
            self._record("append", "allowed", "file attached on the vault page", kind="ui",
                         thread_id=thread_id)
        self._send(200, {"name": str(ref["name"]), "size": int(ref["size"])})

    def _sign_in(self, code: str) -> None:
        if not self._host_ok():
            return
        if not code or not self.server.consume_login(code):
            self._record("load", "denied", "bad or used sign-in link", kind="ui")
            self._html(403, viewer.locked())
            return
        sid = self.server.new_session()
        cookie = f"tv_session={sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age={int(SESSION_TTL_S)}"
        self._redirect("/", {"Set-Cookie": cookie})

    def _page_vault(self, path: str, query: str = "") -> None:
        if not self._host_ok():
            return
        if not self._has_session():
            self._html(401, viewer.locked())
            return
        m = THREAD_PATH.match(path)
        with self.server.lock:
            if m is None:
                text = viewer.home(self.server.vault.list_threads(),
                                   viewer.merge_hints(self.server.vault))
                self._record("list", "allowed", "vault page", kind="ui")
            else:
                dest = (parse_qs(query).get("dest") or [""])[0]
                dest = dest if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", dest) else ""
                try:
                    text = viewer.thread(self.server.vault, m.group(1), self.server.policy, dest or None)
                except KeyError:
                    self._html(404, viewer.message("Not found", "That thread does not exist."))
                    return
                except Exception:  # noqa: BLE001 - never show internals or content in an error
                    self._html(500, viewer.message("Problem", "This thread could not be shown."))
                    return
                self._record("load", "allowed", "vault page", kind="ui", thread_id=m.group(1))
                shown = dest or viewer.default_destination(self.server.policy)
                if shown:
                    self._record("export", "allowed", f"text prepared for {shown[:64]}", kind="ui",
                                 thread_id=m.group(1))
        self._html(200, text)


def serve(vault: Vault, policy: Record | None, log: AccessLog, token: str, origins: set[str],
          port: int, root: Path | None = None) -> IngestServer:
    """Build the server (not yet serving); the caller runs `serve_forever()`."""
    return IngestServer(vault, policy, log, token, origins, port, root)


def load_policy(root: Path) -> tuple[Record | None, list[str]]:
    loaded = load_policy_file(root / "policy.json")
    return loaded.policy, loaded.problems
