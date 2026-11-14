"""Policy decisions (SPEC.md section 10). Default deny: anything not listed is refused.

`load_policy` is the only way a policy file should be read: a missing, unreadable, invalid or
inconsistent file gives `None`, and `None` means nobody gets anything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from threadvault import schemas
from threadvault.types import Decision, Record

MAX_POLICY_BYTES = 1024 * 1024


@dataclass
class PolicyLoad:
    policy: Record | None
    problems: list[str] = field(default_factory=list)


def check_policy(doc: object) -> list[str]:
    """Schema errors plus the cross-references the schema cannot express."""
    problems = schemas.errors("policy", doc)
    if problems or not isinstance(doc, dict):
        return problems or ["policy must be an object"]
    profiles = doc["profiles"]
    if doc["default_profile"] not in profiles:
        problems.append("default_profile names a profile that does not exist")
    seen: set[str] = set()
    for c in doc["clients"]:
        if c["client_id"] in seen:
            problems.append(f"client '{c['client_id'][:64]}' is listed twice")
        seen.add(c["client_id"])
    seen = set()
    for d in doc["destinations"]:
        did = d["destination_id"][:64]
        if d["destination_id"] in seen:
            problems.append(f"destination '{did}' is listed twice")
        seen.add(d["destination_id"])
        if d["profile"] not in profiles:
            problems.append(f"destination '{did}' uses a profile that does not exist")
        if d["kind"] == "cloud-llm" and not d.get("allow_hosts"):
            problems.append(f"destination '{did}' is a cloud AI but lists no allow_hosts")
    return problems


def load_policy(path: Path) -> PolicyLoad:
    if not path.is_file():
        return PolicyLoad(None, ["no policy file: no client is allowed"])
    if path.stat().st_size > MAX_POLICY_BYTES:
        return PolicyLoad(None, ["policy file is too large"])
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return PolicyLoad(None, ["policy file is not readable JSON"])
    problems = check_policy(doc)
    return PolicyLoad(None if problems else doc, problems)


def decide(policy: Record | None, client_id: str, capability: str) -> Decision:
    if policy is None:
        return Decision(allowed=False, reason="no policy file: no client is allowed")
    for client in policy["clients"]:
        if client["client_id"] == client_id:
            if capability in client["capabilities"]:
                return Decision(allowed=True, reason="granted by policy")
            return Decision(allowed=False, reason=f"capability '{capability}' not granted")
    return Decision(allowed=False, reason="client not listed in policy")


def _destination(policy: Record | None, destination_id: str) -> Record | None:
    if policy is None:
        return None
    for dest in policy["destinations"]:
        if dest["destination_id"] == destination_id:
            found: Record = dest
            return found
    return None


def destination_profile(policy: Record | None, destination_id: str) -> Record | None:
    """Redaction profile for a destination, or None if the destination is not allowed."""
    dest = _destination(policy, destination_id)
    if dest is None or policy is None:
        return None
    profile: Record | None = policy["profiles"].get(dest["profile"])
    return profile


def check_url(policy: Record | None, destination_id: str, url: str) -> Decision:
    """May data for `destination_id` be sent to `url`? HTTPS and an exact allow_hosts match only."""
    dest = _destination(policy, destination_id)
    if dest is None:
        return Decision(allowed=False, reason="destination not listed in policy")
    if dest["kind"] == "local":
        return Decision(allowed=False, reason="local destination: nothing is sent over the network")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        _ = parts.port  # raises on a malformed port
    except ValueError:
        return Decision(allowed=False, reason="malformed URL")
    if parts.scheme != "https":
        return Decision(allowed=False, reason="only https is allowed")
    if parts.username is not None or parts.password is not None:
        return Decision(allowed=False, reason="URL must not contain credentials")
    allowed = {h.lower() for h in dest.get("allow_hosts", [])}
    if host not in allowed:
        return Decision(allowed=False, reason="host not in allow_hosts for this destination")
    return Decision(allowed=True, reason="host allowed by policy")


def default_profile(policy: Record) -> Record:
    profile: Record = policy["profiles"][policy["default_profile"]]
    return profile
