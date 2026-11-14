"""Plugin hash-pinning (plan: "plugin signing and hash-pinning; refuse unsigned").

Real signatures are out of scope for spec v1 (SPEC section 13), so trust is a local pin list:
the user approves a plugin once, its SHA-256 is written to `plugins.json`, and from then on
only that exact file is loaded. Unknown name, changed file, or broken pin list: refused.

A pin proves *which code* runs, not *what it may do*: a loaded plugin still acts as a policy
client (`plugin:<name>`) and needs capabilities in policy.json like anyone else.

The file is hashed and executed from the same bytes, so it cannot be swapped in between.
"""

from __future__ import annotations

import hashlib
import json
import re
import types
from dataclasses import dataclass
from pathlib import Path

import jsonschema

from threadvault.types import Decision

PINS_FORMAT = "threadvault-plugins-1"
MAX_PLUGIN_BYTES = 1024 * 1024
_NAME = r"^[a-z][a-z0-9_-]{0,63}$"

PINS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["format", "plugins"],
    "properties": {
        "format": {"const": PINS_FORMAT},
        "plugins": {
            "type": "array",
            "maxItems": 256,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "sha256"],
                "properties": {
                    "name": {"type": "string", "pattern": _NAME},
                    "sha256": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                    "note": {"type": "string", "maxLength": 200},
                },
            },
        },
    },
}


class PluginRefused(Exception):
    """Raised instead of loading. The message never contains file contents."""


def client_id(name: str) -> str:
    return f"plugin:{name}"


def file_hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Pins:
    by_name: dict[str, str]

    @classmethod
    def empty(cls) -> Pins:
        return cls({})

    @classmethod
    def parse(cls, doc: object) -> Pins:
        try:
            jsonschema.validate(doc, PINS_SCHEMA)
        except jsonschema.ValidationError:
            raise PluginRefused("plugin pin list is invalid") from None
        assert isinstance(doc, dict)
        by_name: dict[str, str] = {}
        for p in doc["plugins"]:
            if p["name"] in by_name:
                raise PluginRefused("plugin pin list names a plugin twice")
            by_name[p["name"]] = p["sha256"]
        return cls(by_name)

    @classmethod
    def load(cls, path: Path) -> Pins:
        """Missing file = nothing pinned = every plugin refused."""
        if not path.is_file():
            return cls.empty()
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise PluginRefused("plugin pin list is not readable JSON") from None
        return cls.parse(doc)

    def check(self, name: str, data: bytes) -> Decision:
        if not re.match(_NAME, name):
            return Decision(allowed=False, reason="invalid plugin name")
        pinned = self.by_name.get(name)
        if pinned is None:
            return Decision(allowed=False, reason="plugin is not pinned (unsigned): refused")
        if len(data) > MAX_PLUGIN_BYTES:
            return Decision(allowed=False, reason="plugin file is too large")
        if file_hash(data) != pinned:
            return Decision(allowed=False, reason="plugin file changed since it was pinned: refused")
        return Decision(allowed=True, reason="plugin matches its pinned hash")


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise PluginRefused("plugin must be a regular file")
    with path.open("rb") as fh:
        data = fh.read(MAX_PLUGIN_BYTES + 1)
    return data


def load_plugin(pins: Pins, name: str, path: Path) -> types.ModuleType:
    """Run a plugin only if it matches its pin. The checked bytes are the executed bytes."""
    data = _read(path)
    decision = pins.check(name, data)
    if not decision.allowed:
        raise PluginRefused(decision.reason)
    module = types.ModuleType(f"threadvault_plugin_{name.replace('-', '_')}")
    module.__file__ = str(path)
    code = compile(data, str(path), "exec")
    exec(code, module.__dict__)  # noqa: S102 - bytes were verified against the user's pin
    return module


def pin_entry(name: str, path: Path, note: str = "") -> dict[str, str]:
    """What the user adds to plugins.json after reviewing a plugin."""
    if not re.match(_NAME, name):
        raise PluginRefused("invalid plugin name")
    entry = {"name": name, "sha256": file_hash(_read(path))}
    if note:
        entry["note"] = note[:200]
    return entry
