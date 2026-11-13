"""Live smoke test of the handover agent against the real Claude API. COSTS REAL MONEY (one or two calls).

    export ANTHROPIC_API_KEY=...        # in your own shell; never paste it into chat or commit it
    python tools/handover_smoke.py path/to/conversation.txt [--policy path/to/policy.json] [--ack]

Prints the draft handover, warnings, findings (kinds only) and token usage. Saves nothing.
Use a FICTIONAL or non-sensitive conversation: its text is sent to the Anthropic API.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from threadvault.agent.generate import HandoverError, generate_handover
from threadvault.core.accesslog import MemoryAccessLog

DEFAULT_POLICY = Path(__file__).parent.parent / "tests" / "fixtures" / "vault" / "policy.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("conversation", type=Path)
    ap.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    ap.add_argument("--ack", action="store_true", help="acknowledge non-blocking findings and send anyway")
    args = ap.parse_args()

    policy = json.loads(args.policy.read_text())
    try:
        res = generate_handover(args.conversation.read_text(), policy=policy, log=MemoryAccessLog(),
                                acknowledged_findings=args.ack)
    except HandoverError as e:
        print(f"NOT SENT / FAILED: {e}", file=sys.stderr)
        for f in getattr(e, "findings", []):
            print(f"  finding: {f.kind} ({f.severity}) at {f.path}", file=sys.stderr)
        for p in getattr(e, "problems", []):
            print(f"  problem: {p}", file=sys.stderr)
        return 1

    print(json.dumps(res.content, indent=2, ensure_ascii=False))
    print(f"\nmodel={res.model} calls={res.calls} in={res.input_tokens} out={res.output_tokens} "
          f"request_id={res.request_id}", file=sys.stderr)
    for w in res.warnings:
        print(f"  warning: {w}", file=sys.stderr)
    for f in res.output_findings:
        print(f"  REVIEW: summary contains {f.kind} at {f.path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
