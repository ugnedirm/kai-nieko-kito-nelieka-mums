from threadvault.core.vault import FixtureVault
from threadvault.ui.compare_data import build_view, diff_text, first_divergence, handover_diff


def test_view_flags_tamper_and_badges() -> None:
    v = FixtureVault()
    bad = build_view(v, "thr_tamper01")
    assert not bad.verified and any("mismatch" in w for w in bad.warnings)
    full = build_view(v, "thr_full0001")
    assert full.verified and full.rows and all(r.badge for r in full.rows)


def test_fork_view_includes_parent_history() -> None:
    v = FixtureVault()
    main, fork = build_view(v, "thr_forked01", "main0001"), build_view(v, "thr_forked01", "fork0001")
    assert len(fork.rows) >= 1 and fork.rows[0].text == main.rows[0].text
    assert first_divergence(main, fork) is not None or len(main.rows) != len(fork.rows)


def test_diff_text() -> None:
    assert diff_text("a\nb", "a\nc") == [(" ", "a"), ("-", "b"), ("+", "c")]


def test_handover_diff_between_versions() -> None:
    v = FixtureVault()
    for t in v.list_threads():
        vers = build_view(v, t.thread_id).handover_versions
        if len(vers) >= 2:
            assert handover_diff(v, t.thread_id, vers[0], vers[-1])
            return


def test_compare_page_renders_untrusted_data_as_plain_text_only() -> None:
    """Streamlit's subheader/caption/warning/markdown/write parse Markdown (images, links)."""
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "src/threadvault/ui/app.py").read_text()
    markdown_calls = re.findall(r"st\.(markdown|write|subheader|caption|warning|info|error|success|"
                                r"title|header|latex|html)\(([^\n]*)", src)
    for name, args in markdown_calls:
        assert not re.search(r"view\.|row\.|\bw\b|title|who", args), f"st.{name} fed untrusted data"
    assert "unsafe_allow_html" not in src
