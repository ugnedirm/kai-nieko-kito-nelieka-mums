"""Policy decisions (SPEC.md section 10). Default deny: anything not listed is refused."""

from __future__ import annotations

from threadvault.types import Decision, Record


def decide(policy: Record | None, client_id: str, capability: str) -> Decision:
    if policy is None:
        return Decision(allowed=False, reason="no policy file: no client is allowed")
    for client in policy["clients"]:
        if client["client_id"] == client_id:
            if capability in client["capabilities"]:
                return Decision(allowed=True, reason="granted by policy")
            return Decision(allowed=False, reason=f"capability '{capability}' not granted")
    return Decision(allowed=False, reason="client not listed in policy")


def destination_profile(policy: Record | None, destination_id: str) -> Record | None:
    """Redaction profile for a destination, or None if the destination is not allowed."""
    if policy is None:
        return None
    for dest in policy["destinations"]:
        if dest["destination_id"] == destination_id:
            profile: Record | None = policy["profiles"].get(dest["profile"])
            return profile
    return None


def default_profile(policy: Record) -> Record:
    profile: Record = policy["profiles"][policy["default_profile"]]
    return profile
