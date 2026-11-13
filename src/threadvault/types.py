"""Shared types. The contract between A, B and C. Change only by PR with all three approving.

Records (handover, message, tombstone, manifest, ...) stay plain dicts validated by the JSON
Schemas in `schemas/`; the models below are for results that code passes around.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

Record = dict[str, Any]
Severity = Literal["low", "medium", "high"]

# Finding kinds that block a handoff when the profile has block_on_secrets.
SECRET_KINDS = frozenset({"api_key", "secret", "connection_string", "private_key"})


class Finding(BaseModel):
    """Scanner/redaction result. MUST NOT contain the matched value, only where it was found."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str
    severity: Severity
    path: str
    start: int | None = None
    end: int | None = None
    detail: str | None = None

    def to_schema(self) -> Record:
        return self.model_dump(exclude_none=True)


class VerifyIssue(BaseModel):
    code: str  # see SPEC.md section 6
    branch_id: str
    index: int  # position in the chain file, -1 if not tied to a record
    seq: int | None = None
    version: int | None = None


class BranchReport(BaseModel):
    branch_id: str
    ok: bool
    issues: list[VerifyIssue] = []
    unverified_after: int | None = None  # records after the first bad one are not trusted


class VerifyReport(BaseModel):
    thread_id: str
    mode: Literal["handover", "full"]
    ok: bool
    branches: list[BranchReport]
    notices: list[str] = []


class ThreadInfo(BaseModel):
    thread_id: str
    title: str
    mode: Literal["handover", "full"]
    branches: list[str]
    updated_at: str


class BranchData(BaseModel):
    branch: Record
    records: list[Record]


class ThreadData(BaseModel):
    manifest: Record
    branches: dict[str, BranchData]


class Decision(BaseModel):
    allowed: bool
    reason: str
