"""Load and apply the JSON Schemas in `schemas/`.

Error messages deliberately contain only the location and the rule, never the offending value,
because the value may be a secret (see SPEC.md section 9).
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

# An installed package carries the schemas as `threadvault/_schemas` (see pyproject force-include);
# a development checkout reads them from the repository's `schemas/` folder.
_PACKAGED = Path(__file__).resolve().parent / "_schemas"
SCHEMA_DIR = _PACKAGED if _PACKAGED.is_dir() else Path(__file__).resolve().parents[2] / "schemas"


@lru_cache(maxsize=1)
def _all() -> dict[str, dict[str, Any]]:
    return {p.name.removesuffix(".schema.json"): json.loads(p.read_text())
            for p in SCHEMA_DIR.glob("*.schema.json")}


@lru_cache(maxsize=1)
def _registry() -> Registry:
    reg: Registry = Registry()
    for s in _all().values():
        reg = reg.with_resource(s["$id"], Resource.from_contents(s, default_specification=DRAFT202012))
    return reg


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(_all()[name], registry=_registry(), format_checker=FormatChecker())


def errors(name: str, doc: Any) -> list[str]:
    """Human-readable problems, without echoing any values from `doc`."""
    out = []
    for e in validator(name).iter_errors(doc):
        where = "/".join(str(p) for p in e.absolute_path) or "(root)"
        out.append(f"{where}: violates '{e.validator}'")
    return sorted(out)


def errors_at(name: str, pointer: str, doc: Any) -> list[str]:
    """Like `errors`, but against a definition inside a schema, e.g. ('handover', '#/$defs/content')."""
    sub = {"$ref": _all()[name]["$id"] + pointer}
    v = Draft202012Validator(sub, registry=_registry(), format_checker=FormatChecker())
    return sorted(f"{'/'.join(str(x) for x in e.absolute_path) or '(root)'}: violates '{e.validator}'"
                  for e in v.iter_errors(doc))


def is_valid(name: str, doc: Any) -> bool:
    return not errors(name, doc)


def is_valid_id(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_-]{8,64}", value) is not None
