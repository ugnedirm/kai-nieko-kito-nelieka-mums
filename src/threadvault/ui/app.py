"""Streamlit compare page: `streamlit run src/threadvault/ui/app.py -- --vault <dir>`.

Shows two threads or branches side by side with provenance badges and verify warnings, and a
diff between handover versions. All chat text is rendered with `st.text`/`st.code` (never as
Markdown or HTML) after control characters are stripped.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from typing import Any

from threadvault.cli.context import open_vault
from threadvault.cli.safe import terminal_safe
from threadvault.ui.compare_data import ThreadView, build_view, first_divergence, handover_diff

st: Any = importlib.import_module("streamlit")  # optional extra: pip install -e '.[ui]'


def _args() -> Path | None:
    p = argparse.ArgumentParser()
    p.add_argument("--vault", type=Path, default=None)
    vault: Path | None = p.parse_args(sys.argv[1:]).vault
    return vault


def _column(view: ThreadView, diverge: int | None) -> None:
    st.text(terminal_safe(view.title)[:100])
    st.text(terminal_safe(f"{view.thread_id} / {view.branch_id}"))
    (st.success if view.verified else st.error)("verify: ok" if view.verified else "verify: FAILED")
    for w in view.warnings:
        st.text(terminal_safe("WARNING: " + w))
    for i, row in enumerate(view.rows):
        marker = "  <-- first difference" if i == diverge else ""
        st.text(terminal_safe(f"#{row.seq} {row.role} / {row.who}  [{row.badge}]{marker}"))
        st.text(terminal_safe(row.text))


def main() -> None:
    st.set_page_config(page_title="threadvault compare", layout="wide")
    vault = open_vault(_args())
    threads = vault.list_threads()
    if not threads:
        st.info("The vault has no threads.")
        return
    ids = [t.thread_id for t in threads]
    left, right = st.columns(2)
    sel = []
    for col, default in ((left, 0), (right, min(1, len(ids) - 1))):
        with col:
            tid = st.selectbox("Thread", ids, index=default, key=f"t{default}")
            branches = next(t.branches for t in threads if t.thread_id == tid)
            sel.append((tid, st.selectbox("Branch", branches, key=f"b{default}")))
    views = [build_view(vault, tid, bid) for tid, bid in sel]
    diverge = first_divergence(views[0], views[1])
    for col, view in zip((left, right), views, strict=True):
        with col:
            _column(view, diverge)
    st.divider()
    st.header("Handover versions")
    tid, bid = sel[0]
    versions = views[0].handover_versions
    if len(versions) >= 2:
        a, b = st.select_slider("Compare versions", versions, value=(versions[-2], versions[-1]))
        for mark, line in handover_diff(vault, tid, a, b, bid):
            st.text(terminal_safe(f"{mark} {line}"))
    else:
        st.caption("Fewer than two handover versions in the left thread.")


main()
