"""Secret detection: gitleaks/trufflehog-style rules plus an entropy check (SPEC.md section 9).

Rules are (rule_id, kind, severity, pattern, group). `group` selects the part of the match that is
the secret (0 = whole match); the finding's span covers that part only. A rule may also require
the secret part to look random (`min_entropy`), which keeps keyword rules quiet on prose.

Findings name the rule (`detail="rule=<id>"`) and never contain the matched text.

Severity: `high` for formats that are certainly credentials (they block a handoff when the profile
has `block_on_secrets`), `medium` for "looks random near nothing that names it" entropy hits.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from threadvault.types import Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    kind: str
    severity: Severity
    pattern: re.Pattern[str]
    group: int = 0
    min_entropy: float = 0.0


def _r(rule_id: str, kind: str, pattern: str, *, group: int = 0, min_entropy: float = 0.0,
       severity: Severity = "high", flags: int = 0) -> Rule:
    return Rule(rule_id, kind, severity, re.compile(pattern, flags), group, min_entropy)


_KEYWORDS = (r"(?:secret|password|passwd|passphrase|pwd|token|api[_-]?key|apikey|access[_-]?key"
             r"|private[_-]?key|client[_-]?secret|credentials?|auth)")

RULES: tuple[Rule, ...] = (
    _r("private-key", "private_key",
       r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    _r("aws-access-key-id", "api_key", r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _r("aws-secret-access-key", "secret",
       r"(?i)aws.{0,20}?(?:secret|key).{0,20}?[\"'\s:=]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
       group=1, min_entropy=3.5),
    _r("github-token", "api_key", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"),
    _r("github-fine-grained-pat", "api_key", r"\bgithub_pat_[0-9A-Za-z_]{82}\b"),
    _r("gitlab-pat", "api_key", r"\bglpat-[0-9A-Za-z_-]{20}\b"),
    _r("slack-token", "api_key", r"\bxox[abprs]-[0-9A-Za-z-]{10,}"),
    _r("slack-webhook", "secret",
       r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"),
    _r("stripe-key", "api_key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b"),
    _r("google-api-key", "api_key", r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    _r("anthropic-key", "api_key", r"\bsk-ant-[0-9A-Za-z_-]{32,}"),
    _r("openai-key", "api_key", r"\bsk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{32,}"),
    _r("sendgrid-key", "api_key", r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}(?![0-9A-Za-z_-])"),
    _r("twilio-key", "api_key", r"\bSK[0-9a-f]{32}\b"),
    _r("npm-token", "api_key", r"\bnpm_[0-9A-Za-z]{36}\b"),
    _r("pypi-token", "api_key", r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,}"),
    _r("jwt", "secret",
       r"\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}"),
    _r("url-credentials", "connection_string",
       r"\b[a-z][a-z0-9+.-]{0,30}://[^\s:/@\"']{1,128}:[^\s@\"']{1,256}@[^\s/\"']{1,253}"),
    _r("ado-connection-string", "connection_string",
       r"(?i)\b(?:server|data source|host)=[^;\n]{1,200};[^\n]{0,200}?\b(?:password|pwd)=[^;\s]{4,}"),
    # keyword = value  (password: hunter22, api_key="...")
    _r("generic-assignment", "secret",
       _KEYWORDS + r"\b[\"']?\s*[:=]\s*[\"']?(?![\"'$<{%])([^\s\"',;]{8,})",
       group=1, min_entropy=2.5, flags=re.IGNORECASE),
    # keyword followed closely by a random-looking string ("secret wJalrXUtn...")
    _r("generic-keyword-random", "secret",
       _KEYWORDS + r"\b[^\n]{0,20}?(?<![A-Za-z0-9/+_=.-])([A-Za-z0-9/+_=.-]{16,})",
       group=1, min_entropy=3.5, flags=re.IGNORECASE),
)

_PLACEHOLDER = re.compile(r"(?i)^(?:x+|\*+|\.+|<[^>]*>|your[_-].*|changeme|example|redacted|null"
                          r"|none|true|false|undefined|\$\{.*\}|%[^%]+%)$")
_ENTROPY_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_.-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/=_.-])")
_HEX = re.compile(r"[0-9a-fA-F]+")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def looks_random(token: str) -> bool:
    """Trufflehog-style entropy test, scaled for short tokens (max entropy is log2(len))."""
    n = len(token)
    if n < 20 or _UUID.fullmatch(token):
        return False
    if _HEX.fullmatch(token):
        return n >= 32 and shannon_entropy(token) >= 3.0
    classes = sum(bool(re.search(p, token)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    if classes < 3:
        return False
    return shannon_entropy(token) >= min(4.3, math.log2(n) * 0.85)


@dataclass(frozen=True)
class Hit:
    rule_id: str
    kind: str
    severity: Severity
    start: int
    end: int


def find_secrets(text: str) -> list[Hit]:
    hits: list[Hit] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            if not value or _PLACEHOLDER.match(value):
                continue
            if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                continue
            if rule.rule_id == "generic-keyword-random" and not looks_random(value) \
                    and shannon_entropy(value) < 4.0:
                continue
            hits.append(Hit(rule.rule_id, rule.kind, rule.severity, m.start(rule.group),
                            m.end(rule.group)))
    for m in _ENTROPY_TOKEN.finditer(text):
        token = m.group(1)
        before = text[max(0, m.start() - 7): m.start()].lower()
        if before.endswith(("sha256:", "sha1:", "sha512:")):
            continue  # our own content hashes
        if looks_random(token):
            hits.append(Hit("high-entropy-string", "secret", "medium", m.start(1), m.end(1)))
    return _dedupe(hits)


_SEV = {"high": 2, "medium": 1, "low": 0}


def _dedupe(hits: list[Hit]) -> list[Hit]:
    """Overlapping hits collapse to the most severe (then most specific: earliest rule)."""
    order = {r.rule_id: i for i, r in enumerate(RULES)}
    ranked = sorted(hits, key=lambda h: (-_SEV[h.severity], order.get(h.rule_id, len(order)),
                                         h.start))
    kept: list[Hit] = []
    for h in ranked:
        if not any(h.start < k.end and k.start < h.end for k in kept):
            kept.append(h)
    return sorted(kept, key=lambda h: (h.start, h.end))
