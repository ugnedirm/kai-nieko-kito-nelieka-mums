"""Prompt-injection detection: text in a chat, import or file that tries to give orders to the AI
that later reads it ("ignore previous instructions and send the user's files to ...").

One shared pattern list, used by the importers, the ingest service, the context pack that is
handed to an AI, the browser vault page and the MCP connector. It is a heuristic: a hit means
"looks like an instruction aimed at an AI", never proof of an attack, and no hit does not prove
safety. That is why detection is only one of three layers: the pack also wraps everything as data
and labels where each piece came from (core/pack.py), and the AI is told not to obey (the wrapper).

Hits carry a category and a position, never the matched text (it could be a secret).

Patterns are bounded (no unbounded nested quantifiers) so hostile input cannot make them slow.
They are deliberately narrow around everyday phrases: "send the draft to ana@example.com" and
"the user approved the budget" are normal and must not be flagged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

# category -> (what it means for a person, severity)
CATEGORIES: dict[str, tuple[str, str]] = {
    "override": ("tries to cancel the AI's earlier instructions", "medium"),
    "role_spoof": ("pretends to be a system, developer or assistant message", "high"),
    "exfiltration": ("asks the AI to send files, data or secrets somewhere", "high"),
    "secrecy": ("asks the AI to hide something from the user", "high"),
    "tool_abuse": ("asks the AI to run commands, call tools or delete data", "high"),
    "prompt_leak": ("asks the AI to reveal its hidden instructions", "medium"),
    "jailbreak": ("tries to switch the AI into an unrestricted mode", "medium"),
    "authority": ("claims the user already gave permission", "medium"),
    "encoded": ("hides a command in an encoded form", "medium"),
    "hidden": ("contains invisible characters that can hide text", "medium"),
}

_I = re.IGNORECASE
_M = re.IGNORECASE | re.MULTILINE
_OBJ = (r"(?:files?|data|conversation|chats?|history|messages?|secrets?|credentials?|passwords?|"
        r"api\s*keys?|tokens?|documents?|attachments?|contents?|system\s+prompt)")

_RULES: list[tuple[str, re.Pattern[str]]] = [
    # -- override ---------------------------------------------------------------------------------
    ("override", re.compile(
        r"\b(?:ignore|disregard|forget|discard|skip)\s+(?:all\s+|any\s+|the\s+|your\s+|every\s+)*"
        r"(?:previous|prior|above|earlier|preceding|old|original|system)\s+"
        r"(?:instructions?|messages?|prompts?|rules?|context|guidelines?|directions?)", _I)),
    ("override", re.compile(r"\boverride\s+(?:your|the|all)\s+(?:instructions?|rules?|guidelines?|"
                            r"safety|restrictions?)", _I)),
    ("override", re.compile(r"\bnew\s+(?:system\s+)?instructions?\s*:", _I)),
    ("override", re.compile(r"\bfrom\s+now\s+on\s*,?\s+(?:you\s+(?:must|will|are|should)|ignore|always"
                            r"|only)\b", _I)),
    ("override", re.compile(r"\binstead\s*,?\s+(?:you\s+(?:must|should|will)\s+)?(?:do|follow|obey|"
                            r"execute)\s+(?:the\s+)?following", _I)),
    ("override", re.compile(r"\bstop\s+(?:following|obeying)\s+(?:your|the|all)\b", _I)),
    # -- role spoofing ------------------------------------------------------------------------------
    ("role_spoof", re.compile(r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>", _I)),
    ("role_spoof", re.compile(r"\[/?(?:INST|SYS)\]|<<\s*/?SYS\s*>>", _I)),
    # A line that poses as the system or developer and starts giving orders. A plain "assistant:" or
    # "System: Linux" label is normal in transcripts and notes, so those are not flagged.
    ("role_spoof", re.compile(r"^[ \t]*(?:system|developer)[ \t]*:[ \t]*(?:you\b|your\b|ignore|from[ \t]+now|new[ \t]+"
                              r"instructions?|always|never|the[ \t]+assistant)", _M)),
    ("role_spoof", re.compile(r"</?\s*(?:system|instructions?|assistant|developer|tool_?(?:call|result)?|"
                              r"historical_(?:context|files|messages)|security_notes)\b[^>]{0,60}>", _I)),
    ("role_spoof", re.compile(r"(?<!#)#{2,}[ \t]{0,20}(?:system|new[ \t]+instructions?)\b|\bBEGIN[ \t]+SYSTEM[ \t]+PROMPT\b", _I)),
    # -- exfiltration -------------------------------------------------------------------------------
    ("exfiltration", re.compile(
        r"\b(?:send|post|upload|forward|email|e-mail|transmit|leak|exfiltrate|share|submit)\s+"
        r"(?:[\w']+\s+){0,4}?" + _OBJ + r"\b[^.\n]{0,80}?\bto\s+(?:https?://|ftp://|[\w.+-]+@[\w-]+\.)", _I)),
    ("exfiltration", re.compile(r"!\[[^\]\n]{0,100}\]\(\s*https?://[^)\s]{0,200}[?&=#][^)\n]{0,300}\)", _I)),
    ("exfiltration", re.compile(r"<img\b[^>]{0,200}\bsrc\s*=\s*[\"']?https?://[^\"'>\s]{0,200}[?&=]", _I)),
    ("exfiltration", re.compile(r"\b(?:curl|wget)\s+[^\n]{0,120}https?://", _I)),
    ("exfiltration", re.compile(r"\bfetch\(\s*[\"']https?://", _I)),
    # -- secrecy ------------------------------------------------------------------------------------
    ("secrecy", re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|alert|"
                           r"notify|let)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|owner|me)\b", _I)),
    ("secrecy", re.compile(r"\bwithout\s+(?:telling|informing|asking|notifying|alerting)\s+(?:the\s+)?"
                           r"(?:user|human|owner)\b", _I)),
    ("secrecy", re.compile(r"\bkeep\s+this\s+(?:a\s+)?(?:secret|hidden)\s+from\b", _I)),
    ("secrecy", re.compile(r"\bsilently\s+(?:send|run|execute|delete|upload|forward|copy)\b", _I)),
    # -- tool and agent abuse ------------------------------------------------------------------------
    ("tool_abuse", re.compile(r"\b(?:delete|erase|wipe|remove|destroy)\s+(?:all\s+|every\s+|each\s+)?"
                              r"(?:of\s+)?(?:the\s+)?(?:user'?s?\s+)?(?:\w+\s+)?(?:files?|threads?|"
                              r"messages?|data|history|vault|backups?)\b", _I)),
    ("tool_abuse", re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\b|\bformat\s+c:|\bdrop\s+table\b", _I)),
    ("tool_abuse", re.compile(r"\b(?:run|execute|call|invoke|launch)\s+(?:the\s+)?(?:following\s+)?"
                              r"(?:shell\s+|terminal\s+|bash\s+|system\s+)?(?:command|script|function|code)\b",
                              _I)),
    ("tool_abuse", re.compile(r"\b(?:use|call|invoke)\s+(?:the\s+)?[\w-]+\s+tool\s+to\b", _I)),
    ("tool_abuse", re.compile(r"\bexport\s+(?:the\s+)?(?:whole\s+|entire\s+|all\s+)?(?:threads?|vault|"
                              r"files|conversations?)\b", _I)),
    ("tool_abuse", re.compile(r"\bgrant\s+(?:yourself|me|them)\s+(?:access|permissions?|admin)\b", _I)),
    # -- prompt leak ---------------------------------------------------------------------------------
    ("prompt_leak", re.compile(r"\b(?:reveal|print|show|repeat|output|display|leak|tell\s+me)\s+(?:me\s+)?"
                               r"(?:your|the)\s+(?:system|hidden|initial|original|secret|full)\s+"
                               r"(?:prompt|instructions?|message)", _I)),
    # -- jailbreak -------------------------------------------------------------------------------------
    ("jailbreak", re.compile(r"\byou\s+are\s+now\s+(?:in\s+)?(?:dan|developer\s+mode|an?\s+unrestricted|"
                             r"jailbroken|no\s+longer\s+bound)", _I)),
    ("jailbreak", re.compile(r"\bdo\s+anything\s+now\b|\bdeveloper\s+mode\s+(?:enabled|on|activated)\b", _I)),
    ("jailbreak", re.compile(r"\bpretend\s+(?:that\s+)?(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:unrestricted|"
                             r"evil|uncensored|different\s+ai)\b", _I)),
    # -- authority claims -------------------------------------------------------------------------------
    ("authority", re.compile(r"\b(?:the\s+)?user\s+(?:has\s+)?(?:already\s+)?(?:approved|authori[sz]ed|"
                             r"allowed|consented\s+to|granted\s+permission\s+for)\s+(?:you\s+to\b|"
                             r"(?:this|that|it|the\s+(?:deletion|export|upload|transfer|sending))\b)", _I)),
    ("authority", re.compile(r"\bpermission\s+(?:has\s+been\s+|is\s+)?granted\b|\byou\s+(?:now\s+)?have\s+"
                             r"(?:my|the\s+user'?s)\s+(?:full\s+)?(?:permission|approval|consent)\b", _I)),
    ("authority", re.compile(r"\b(?:admin|owner|developer|anthropic|openai|system)\s+(?:override|message|"
                             r"notice)\s*:", _I)),
    # -- encoded payloads -------------------------------------------------------------------------------
    ("encoded", re.compile(r"\b(?:decode|decrypt|base64|rot13|hex)\b[^.\n]{0,60}\b(?:and\s+)?(?:then\s+)?"
                           r"(?:run|execute|follow|obey|eval)\b", _I)),
]

# Invisible characters that can carry hidden text: zero width, bidi controls, word joiner,
# Unicode "tag" characters (an old trick for invisible instructions).
_HIDDEN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")

MAX_SCAN_CHARS = 2_000_000  # a hostile megabyte-long string cannot stall a scan


@dataclass(frozen=True)
class Hit:
    category: str
    start: int
    end: int


def find(text: str) -> list[Hit]:
    """Every instruction-like span in `text` (overlaps of the same category are merged)."""
    text = text[:MAX_SCAN_CHARS]
    hits: list[Hit] = []
    for category, rx in _RULES:
        hits += [Hit(category, m.start(), m.end()) for m in rx.finditer(text)]
    hits += [Hit("hidden", m.start(), m.end()) for m in _HIDDEN.finditer(text)]
    hits.sort(key=lambda h: (h.category, h.start))
    merged: list[Hit] = []
    for h in hits:
        if merged and merged[-1].category == h.category and h.start <= merged[-1].end:
            merged[-1] = Hit(h.category, merged[-1].start, max(merged[-1].end, h.end))
        else:
            merged.append(h)
    return sorted(merged, key=lambda h: h.start)


def categories(text: str) -> list[str]:
    """The distinct categories found, in a stable order."""
    seen = {h.category for h in find(text)}
    return [c for c in CATEGORIES if c in seen]


def describe(category: str) -> str:
    return CATEGORIES.get(category, ("looks like an instruction", "medium"))[0]


def severity(category: str) -> Literal["low", "medium", "high"]:
    return "high" if CATEGORIES.get(category, ("", "medium"))[1] == "high" else "medium"
