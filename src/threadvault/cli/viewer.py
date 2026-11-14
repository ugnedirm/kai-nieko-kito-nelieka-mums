"""HTML for the local vault pages (viewer and extension approval), served by `cli/serve.py`.

Security: every value that came from a chat, import or the vault is escaped with `html.escape`
and stripped of control characters; pages carry no inline script or style (the CSP in serve.py
allows only same-origin files); nothing here talks to the network or changes the vault.
"""

from __future__ import annotations

import html
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from threadvault.cli.safe import terminal_safe
from threadvault.core.render import handover_text
from threadvault.core.vault import Vault
from threadvault.policy.engine import destination_profile
from threadvault.privacy.outbound import prepare_text
from threadvault.scanners import injection
from threadvault.scanners.engine import scan_text
from threadvault.types import SECRET_KINDS, Record, ThreadInfo
from threadvault.ui.compare_data import (
    ThreadView,
    build_view,
    diff_text,
    first_divergence,
    latest_handover,
)

CSS = """
:root{color-scheme:light dark;--accent:#6A31A6;--accent-hover:#58288b;--accent-text:#6A31A6;
--accent-soft:#f3edf9;--code:#4b2178;--ink:#1d1a22;--muted:#6f6a78;--line:#e7e4ec;--bg:#fbfafc;
--card:#fff;--bad:#b3261e;--bad-soft:#fcefee;--warn-soft:#fbf6ea;--warn-line:#c99a2e}
@media (prefers-color-scheme:dark){:root{--accent-hover:#7c40bd;--accent-text:#c3a2e8;
--accent-soft:#2a2135;--code:#d9c4f2;--ink:#ebe8f0;--muted:#9a94a5;--line:#2c2933;--bg:#141218;
--card:#1b1920;--bad:#f2928b;--bad-soft:#3a1f1e;--warn-soft:#2e2717;--warn-line:#b8923f}}
*{box-sizing:border-box}
body{font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;
background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased}
header{max-width:860px;margin:0 auto;padding:28px 20px 0;display:flex;align-items:baseline;
gap:28px;flex-wrap:wrap}
header b{font-weight:600;font-size:15px;letter-spacing:-.01em;color:var(--ink)}
header b::before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;
background:var(--accent);margin-right:10px;vertical-align:2px}
header a{color:var(--muted);text-decoration:none;font-size:14px;margin-right:18px}
header a:hover{color:var(--accent-text)}
main{max-width:860px;margin:0 auto;padding:24px 20px 64px}
h1{font-size:26px;font-weight:600;letter-spacing:-.02em;margin:24px 0 16px}
h2{font-size:16px;font-weight:600;margin:0 0 8px}h3{font-size:14px;font-weight:600}
a{color:var(--accent-text)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 22px;
margin:12px 0}
.card a{color:var(--ink);font-weight:500;text-decoration:none;font-size:16px}
.card a:hover{color:var(--accent-text)}
.card a.btn{color:#fff;font-size:14px}.card a.btn.secondary{color:var(--ink)}
.muted{color:var(--muted);font-size:13px}
.ok{color:var(--accent-text);font-weight:500}.bad{color:var(--bad);font-weight:500}
.warn{background:var(--warn-soft);border-left:2px solid var(--warn-line);padding:10px 14px;border-radius:4px}
.card.warn{border-left:2px solid var(--warn-line)}
pre{white-space:pre-wrap;word-wrap:break-word;background:var(--bg);border:1px solid var(--line);
border-radius:8px;padding:14px;font:13px/1.6 ui-monospace,"SF Mono",Consolas,monospace}
textarea{width:100%;height:220px;font:13px/1.5 ui-monospace,Consolas,monospace;padding:12px;
border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
button,.btn{background:var(--accent);color:#fff;border:1px solid var(--accent);border-radius:7px;
padding:8px 16px;font:inherit;font-size:14px;font-weight:500;cursor:pointer;text-decoration:none;
display:inline-block;transition:background .15s}
button:hover,.btn:hover{background:var(--accent-hover)}
button.secondary,.btn.secondary{background:var(--card);color:var(--ink);border-color:var(--line)}
button.secondary:hover,.btn.secondary:hover{border-color:var(--accent);color:var(--accent-text)}
input,select{font:inherit;font-size:14px;padding:6px 8px;border:1px solid var(--line);
border-radius:6px;background:var(--card);color:var(--ink)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);
padding:8px 10px;text-align:left;vertical-align:top}th{color:var(--muted);font-weight:500}
tr.bad td{background:var(--bad-soft)}
.diff{font:13px/1.6 ui-monospace,Consolas,monospace;margin-top:12px}
.diff>div{display:grid;grid-template-columns:22px minmax(0,1fr);gap:6px;padding:2px 10px;
border-radius:4px}
.diff .t{white-space:pre-wrap;word-wrap:break-word}.diff .t:empty::after{content:"\00a0"}
.diff .m{color:var(--muted);user-select:none;text-align:center}
.diff .add{background:var(--accent-soft)}.diff .del{background:var(--bad-soft)}
.diff .same{color:var(--muted)}
.addmark{background:var(--accent-soft);padding:1px 6px;border-radius:4px}
.delmark{background:var(--bad-soft);padding:1px 6px;border-radius:4px}
.pick{display:grid;grid-template-columns:1fr 1fr;gap:14px 20px;align-items:end}
.field-col{display:flex;flex-direction:column;gap:6px;font-size:13px;color:var(--muted)}
.field-col select{width:100%;font-size:14px;color:var(--ink);padding:8px 10px}
.pick-go{grid-column:1 / -1}
.section-title{margin:32px 0 4px;font-size:16px;font-weight:600}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start}.col{min-width:0}
.col h2{font-size:18px;margin:8px 0 2px;line-height:1.3}.col>p{margin:4px 0}
@media (max-width:700px){.cols,.pick{grid-template-columns:1fr}}
select{max-width:100%}
details{margin:10px 0}summary{cursor:pointer}
code{background:var(--accent-soft);color:var(--code);padding:1px 6px;border-radius:4px;font-size:.9em}
"""

JS = """
function tvPost(url, headers, then) {
  fetch(url, { method: 'POST', headers: headers, credentials: 'same-origin' }).then(function (r) {
    if (r.ok) { then(); } else { window.alert('That did not work (' + r.status + ').'); } });
}
document.addEventListener('click', function (e) {
  var f = e.target.closest('button[data-forget]');
  if (f && window.confirm('Delete this file from EVERY thread that has it? This cannot be undone.')) {
    tvPost('/forget/' + f.getAttribute('data-forget'), { 'X-Action': 'yes' }, function () { location.reload(); });
  }
  var d = e.target.closest('button[data-delete]');
  if (d && window.confirm('Delete this whole thread and its files now? This cannot be undone.')) {
    tvPost('/delete/' + d.getAttribute('data-delete'), { 'X-Action': 'yes' }, function () { location.href = '/'; });
  }
});
document.addEventListener('change', function (e) {
  var s = e.target.closest('select[data-expire]');
  if (s && s.value) {
    tvPost('/expire/' + s.getAttribute('data-expire'), { 'X-Expire': s.value }, function () { location.reload(); });
  }
});

document.addEventListener('click', function (e) {
  var b = e.target.closest('button[data-merge-from]');
  if (!b) return;
  var sel = b.getAttribute('data-merge-select') && document.getElementById(b.getAttribute('data-merge-select'));
  var into = sel ? sel.value : b.getAttribute('data-merge-into');
  var label = sel ? sel.options[sel.selectedIndex].text : (b.getAttribute('data-merge-label') || 'the other thread');
  if (!into || !window.confirm('Move the files into "' + label + '" and remove this files-only thread?')) return;
  fetch('/merge/' + b.getAttribute('data-merge-from') + '/' + into, { method: 'POST',
    headers: { 'X-Merge': 'yes' }, credentials: 'same-origin' }).then(function (r) {
      if (r.ok) { location.href = '/t/' + into; } else { b.textContent = 'Could not merge'; } });
});

document.addEventListener('click', function (e) {
  var b = e.target.closest('button[data-attach]');
  if (!b) return;
  var input = document.getElementById('attach-file'), msg = document.getElementById('attach-msg');
  var f = input && input.files && input.files[0];
  if (!f) { msg.textContent = 'Choose a file first.'; return; }
  var send = function (confirmed) {
    var h = { 'X-Filename': encodeURIComponent(f.name), 'Content-Type': 'application/octet-stream' };
    if (confirmed) h['X-Confirm'] = 'yes';
    msg.textContent = 'Attaching...';
    return fetch('/f/' + b.getAttribute('data-attach'), { method: 'POST', headers: h, body: f,
      credentials: 'same-origin' }).then(function (r) { return r.json().then(function (j) {
        return { status: r.status, body: j }; }); });
  };
  send(false).then(function (r) {
    if (r.status === 409) {
      var notes = (r.body.notes || []).join('\\n');
      if (window.confirm('This file may still contain hidden details:\\n\\n' + notes +
          '\\n\\nAttach it anyway?')) return send(true);
      msg.textContent = 'Not attached.';
      return null;
    }
    return r;
  }).then(function (r) {
    if (!r) return;
    if (r.status === 200) { location.reload(); } else { msg.textContent = 'Could not attach: ' + (r.body.error || r.status); }
  }).catch(function () { msg.textContent = 'Could not attach the file.'; });
});

document.addEventListener('click', function (e) {
  var b = e.target.closest('button[data-copy]');
  if (!b) return;
  var t = document.getElementById(b.getAttribute('data-copy'));
  if (!t) return;
  t.select();
  var done = function () { b.textContent = 'Copied! Now paste it into the other AI.'; };
  if (navigator.clipboard) { navigator.clipboard.writeText(t.value).then(done, function () {
    document.execCommand('copy'); done(); }); } else { document.execCommand('copy'); done(); }
});
"""


def esc(value: object) -> str:
    return html.escape(terminal_safe(str(value)), quote=True)


def page(title: str, body: str, *, nav: bool = True) -> str:
    links = ('<a href="/">My saved threads</a> <a href="/compare">Compare</a> '
             '<a href="/log">Access log</a>') if nav else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{esc(title)}</title>"
        '<link rel="stylesheet" href="/static/viewer.css"></head><body>'
        f"<header><b>When nothing else is left</b> <nav>{links}</nav></header><main>{body}</main>"
        '<script src="/static/viewer.js"></script></body></html>'
    )


def locked() -> str:
    return page("When nothing else is left", """
<div class="card"><h2>Your vault is locked</h2>
<p>For your safety this page only opens from a link made just for you.</p>
<p><b>Easiest:</b> click the extension icon in your browser toolbar, then
<b>Open my saved threads</b>.</p>
<p class="muted">Or, in a terminal, run <code>thread open</code>.</p></div>""", nav=False)


@dataclass
class MergeHint:
    source_id: str
    source_title: str
    files: int
    target_id: str
    target_title: str
    minutes: int


MERGE_WINDOW = timedelta(minutes=30)


def _when(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _has_text(vault: Vault, thread_id: str) -> bool:
    return any(b.records for b in vault.load_thread(thread_id).branches.values())


def merge_hints(vault: Vault) -> list[MergeHint]:
    """A thread holding only files (made when you attached a file to a chat) probably belongs to
    the thread saved from that chat shortly afterwards. Suggest it; the person decides."""
    rows = []
    for t in vault.list_threads():
        try:
            data = vault.load_thread(t.thread_id)
            rows.append((t, data.manifest, _has_text(vault, t.thread_id)))
        except (KeyError, ValueError, OSError):
            continue
    hints: list[MergeHint] = []
    for st, sm, s_text in rows:
        if s_text or not sm["files"]:
            continue
        best: tuple[timedelta, ThreadInfo] | None = None
        for tt, tm, t_text in rows:
            gap = _when(tm["created_at"]) - _when(sm["created_at"])
            if tt.thread_id != st.thread_id and t_text and timedelta(0) <= gap <= MERGE_WINDOW \
                    and (best is None or gap < best[0]):
                best = (gap, tt)
        if best:
            hints.append(MergeHint(st.thread_id, st.title, len(sm["files"]), best[1].thread_id,
                                   best[1].title, int(best[0].total_seconds() // 60)))
    return hints


def _hint_card(h: MergeHint) -> str:
    n = f"{h.files} file" + ("" if h.files == 1 else "s")
    when = "a minute or less" if h.minutes < 1 else f"{h.minutes} min"
    return (f"<div class='card warn'><b>These may be the same chat.</b> "
            f"<b>{esc(h.source_title)}</b> holds only {esc(n)}. "
            f"<b>{esc(h.target_title)}</b> was saved {esc(when)} later. "
            f"<p><button type='button' data-merge-from='{esc(h.source_id)}' "
            f"data-merge-into='{esc(h.target_id)}' data-merge-label='{esc(h.target_title)}'>"
            "Merge them</button></p></div>")


def home(threads: Sequence[ThreadInfo], hints: Sequence[MergeHint] = ()) -> str:
    if not threads:
        body = ("<div class='card'><h2>Nothing saved yet</h2><p>Open a ChatGPT or Claude chat, click "
                "the extension icon and choose <b>Save this chat's summary</b>.</p></div>")
    else:
        rows = []
        for t in sorted(threads, key=lambda x: x.updated_at, reverse=True):
            kind = "summary + full conversation" if t.mode == "full" else "summary only"
            rows.append(
                f"<div class='card'><a href='/t/{esc(t.thread_id)}'>{esc(t.title) or 'Untitled'}</a>"
                f"<div class='muted'>{esc(kind)} &middot; saved {esc(t.updated_at)}</div></div>")
        body = "".join(rows)
    cards = "".join(_hint_card(h) for h in hints)
    return page("My saved threads", "<h1>My saved threads</h1>" + cards + body)


def security_findings(vault: Vault, thread_id: str) -> list[tuple[str, list[str]]]:
    """Where stored text looks like an instruction aimed at an AI: (place, categories)."""
    out: list[tuple[str, list[str]]] = []
    for branch in vault.load_thread(thread_id).branches.values():
        for r in branch.records:
            if r["type"] == "message":
                where = f"message {int(r['seq'])} ({r.get('provenance', 'unknown')})"
                cats = injection.categories(r["content"])
            elif r["type"] == "handover":
                where, cats = f"handover v{int(r['version'])}", injection.categories(handover_text(r))
            else:
                continue
            if cats:
                out.append((where, cats))
    return out


def _security_card(findings: Sequence[tuple[str, list[str]]]) -> str:
    if not findings:
        return ("<div class='card'><h2>Security check</h2><p class='ok'>&#10003; No text that looks like "
                "an instruction to an AI was found.</p><p class='muted'>This is a heuristic, not a "
                "guarantee. Whatever an AI loads from the vault is wrapped as data, labelled with who "
                "wrote each part, and told not to obey it.</p></div>")
    rows = "".join(f"<li><b>{esc(w)}</b>: {esc(', '.join(injection.describe(c) for c in cats))}</li>"
                   for w, cats in findings[:30])
    return ("<div class='card warn'><h2>&#9888; Possible hidden instructions</h2>"
            f"<p>{len(findings)} place(s) contain text that looks like orders to an AI. This can be an "
            "attempt to make an AI misbehave when it reads this thread, or a false alarm.</p>"
            f"<ul>{rows}</ul><p class='muted'>When this thread is given to an AI, the vault wraps it "
            "as data, labels who wrote each message, flags these parts and tells the AI not to act "
            "on them. Read them before you share.</p></div>")


def default_destination(policy: Record | None) -> str | None:
    """The first destination that is not 'local' (hiding applies), else the first one."""
    choices = share_choices(policy)
    for d, _, kind in choices:
        if kind != "local":
            return d
    return choices[0][0] if choices else None


def share_choices(policy: Record | None) -> list[tuple[str, str, str]]:
    """(destination id, label, kind) the person may paste into, from policy.json."""
    if not policy:
        return []
    return [(d["destination_id"], str(d["destination_id"]), str(d["kind"]))
            for d in policy.get("destinations", [])]


def share_text(vault: Vault, policy: Record | None, thread_id: str,
               dest: str) -> tuple[str | None, dict[str, int], str | None]:
    """The text to paste into `dest`: redacted by that destination's profile, or refused. Secrets
    block the handoff (profile `block_on_secrets`) BEFORE anything is shown for copying."""
    profile = destination_profile(policy, dest)
    if profile is None:
        return None, {}, "That destination is not allowed by your policy.json."
    pack = vault.pack(thread_id, 8000)
    if profile.get("block_on_secrets"):
        kinds = sorted({f.kind for f in scan_text(pack) if f.kind in SECRET_KINDS})
        if kinds:
            return None, {}, ("Blocked: this thread contains what looks like a secret ("
                              + ", ".join(kinds) + "). Remove it from the thread before sharing.")
    out = prepare_text(policy, dest, pack)
    if out.blocked:
        return None, {}, "Blocked: " + (out.reason or "contains secrets")
    return out.text, out.counts(), None


def _share_card(thread_id: str, policy: Record | None, dest: str, text: str | None,
                counts: dict[str, int], problem: str | None) -> str:
    choices = share_choices(policy)
    links = " ".join(
        f"<a class='btn{'' if d == dest else ' secondary'}' href='/t/{esc(thread_id)}?dest={esc(d)}'>"
        f"{esc(d)}</a>" for d, _, _ in choices)
    if not choices:
        return ("<div class='card'><h2>Continue in another AI</h2><p class='warn'>No destinations are "
                "set up in your policy.json, so nothing may be shared. Run <code>thread init "
                "--update-policy</code>.</p></div>")
    kind = next((k for d, _, k in choices if d == dest), "")
    if problem:
        body = f"<p class='bad'>{esc(problem)}</p>"
    else:
        shown = ", ".join(f"{n} {esc(k)}" for k, n in counts.items())
        note = (f"<p class='ok'>Hidden before sharing: {shown}.</p>" if counts else
                ("<p class='muted'>Nothing needed hiding.</p>" if kind != "local" else
                 "<p class='warn'>Nothing is hidden for this choice: use it only on this computer.</p>"))
        body = (f"{note}<textarea id='pack' readonly>{esc(text or '')}</textarea><p>"
                "<button type='button' data-copy='pack'>Copy for another AI</button></p>")
    return ("<div class='card'><h2>Continue in another AI</h2><p>Where will you paste it? The text is "
            "cleaned for that place (emails, phone numbers, names and keys hidden) and wrapped so the "
            f"AI treats it as background, not as instructions.</p><p>{links}</p>{body}</div>")


def thread(vault: Vault, thread_id: str, policy: Record | None = None, dest: str | None = None) -> str:
    info = next((t for t in vault.list_threads() if t.thread_id == thread_id), None)
    if info is None:
        raise KeyError(thread_id)
    report = vault.verify(thread_id)
    badge = ("<span class='ok'>&#10003; Not changed since it was saved</span>" if report.ok
             else "<span class='bad'>&#9888; This thread was changed after saving. "
                  "Do not trust it.</span>")
    notes = "".join(f"<li>{esc(n)}</li>" for n in report.notices)
    details = f"<details><summary class='muted'>Technical details</summary><ul>{notes}</ul></details>"
    data = vault.load_thread(thread_id)
    files = data.manifest.get("files", [])
    merge_card = ""
    if files and not any(b.records for b in data.branches.values()):
        opts = "".join(f"<option value='{esc(t.thread_id)}'>{esc(t.title)}</option>"
                       for t in vault.list_threads()
                       if t.thread_id != thread_id and _has_text(vault, t.thread_id))
        if opts:
            merge_card = ("<div class='card'><h2>Belongs to another thread?</h2>"
                          "<p class='muted'>This thread only holds files. Move them into the thread "
                          "for the same chat; this one is then removed.</p>"
                          f"<p><select id='merge-target'>{opts}</select> "
                          f"<button type='button' data-merge-from='{esc(thread_id)}' "
                          "data-merge-select='merge-target'>Move the files there</button></p></div>")
    full = esc(vault.render_text(thread_id))
    expires = data.manifest.get("expires_at")
    lifecycle_card = (
        "<div class='card'><h2>Keep or delete</h2>"
        f"<p class='muted'>{'This thread deletes itself on ' + esc(expires) + '.' if expires else 'This thread is kept until you delete it.'}</p>"
        f"<p><label>Delete this thread automatically after "
        f"<select id='expire-choice' data-expire='{esc(thread_id)}'>"
        "<option value=''>(choose)</option><option value='never'>never</option><option value='1d'>1 day</option>"
        "<option value='7d'>7 days</option><option value='30d'>30 days</option></select></label></p>"
        f"<p><button type='button' class='secondary' data-delete='{esc(thread_id)}'>Delete this thread now"
        "</button></p></div>")
    dest = dest or default_destination(policy)
    text, counts, problem = (share_text(vault, policy, thread_id, dest) if dest
                             else (None, {}, None))
    share = _share_card(thread_id, policy, dest or "", text, counts, problem)
    security = _security_card(security_findings(vault, thread_id))
    body = f"""
<p><a href="/">&larr; All threads</a></p>
<h1>{esc(info.title) or 'Untitled'}</h1>
<p>{badge}</p>
{security}
{share}
{files_card(thread_id, files)}
{merge_card}
{lifecycle_card}
<div class="card"><h2>Attach a file</h2>
<p class="muted">Add a document or picture to this thread yourself. Hidden details (like the location
inside a photo or an author name) are removed where possible; you are told if anything may remain.</p>
<p><input type="file" id="attach-file"> <button type="button" data-attach="{esc(thread_id)}">Attach</button></p>
<p id="attach-msg" class="muted"></p></div>
<div class="card"><h2>What was saved</h2><pre>{full}</pre></div>
{details}"""
    return page(info.title, body)


def _size(n: int) -> str:
    return f"{n} bytes" if n < 1024 else f"{n / 1024:.0f} KB" if n < 1048576 else f"{n / 1048576:.1f} MB"


def files_card(thread_id: str, files: Sequence[dict[str, object]]) -> str:
    if not files:
        return ""
    rows = []
    for f in files:
        digest = str(f.get("sha256", "")).removeprefix("sha256:")
        size = f.get("size", 0)
        exp = f" &middot; deletes itself {esc(f['expires_at'])}" if f.get("expires_at") else ""
        rows.append(f"<li><a href='/f/{esc(thread_id)}/{esc(digest)}'>{esc(f.get('name', 'file'))}</a> "
                    f"<span class='muted'>{esc(_size(size if isinstance(size, int) else 0))}{exp}</span> "
                    f"<button type='button' class='secondary' data-forget='{esc(thread_id)}/{esc(digest)}'>"
                    "Forget this file</button></li>")
    return ("<div class='card'><h2>Files</h2><p class='muted'>Downloads are never opened in the "
            "browser. Open them only if you trust where they came from. <b>Forget</b> deletes a file "
            "from every thread that holds it.</p><ul>"
            + "".join(rows) + "</ul></div>")


def access_log(entries: Sequence[Record], issues: int, total: int) -> str:
    status = ("<p class='ok'>&#10003; The log is intact: no entry has been changed or removed.</p>"
              if issues == 0 else
              "<p class='bad'>&#9888; The log was changed or is damaged. Entries after the first "
              "problem cannot be trusted.</p>")
    rows = []
    for e in reversed(list(entries)):
        actor = e.get("actor") or {}
        bad = " class='bad'" if e.get("outcome") == "denied" else ""
        rows.append(f"<tr{bad}><td>{esc(e.get('ts', ''))}</td><td>{esc(actor.get('client_id', ''))}"
                    f" ({esc(actor.get('kind', ''))})</td><td>{esc(e.get('action', ''))}</td>"
                    f"<td>{esc(e.get('outcome', ''))}</td><td>{esc(e.get('thread_id', ''))}</td>"
                    f"<td>{esc(e.get('detail', ''))}</td></tr>")
    table = ("<table><tr><th>When</th><th>Who</th><th>What</th><th>Result</th><th>Thread</th>"
             "<th>Note</th></tr>" + "".join(rows) + "</table>") if rows else "<p>Nothing recorded yet.</p>"
    return page("Access log", "<h1>Access log</h1><p class='muted'>Who opened, saved, shared or "
                f"deleted what, and when. It never contains message text, files or keys. Showing "
                f"the newest {len(rows)} of {total}.</p>" + status + table)


def _compare_column(view: ThreadView, diverge: int | None) -> str:
    status = ("<span class='ok'>&#10003; not changed</span>" if view.verified
              else "<span class='bad'>&#9888; changed after saving</span>")
    warns = "".join(f"<p class='warn'>{esc(w)}</p>" for w in view.warnings
                    if not w.startswith(("No trusted keys", "Signatures were checked",
                                         "No message history stored")))
    rows = []
    for i, r in enumerate(view.rows):
        cats = injection.categories(r.text)
        flag = (f" <span class='bad'>[!] looks like instructions to an AI: {esc(', '.join(cats))}</span>"
                if cats else "")
        first = " <b class='bad'>&larr; first difference</b>" if i == diverge else ""
        rows.append(f"<div class='card'><div class='muted'>#{r.seq} {esc(r.role)} / {esc(r.who)} "
                    f"&middot; {esc(r.badge)}{first}{flag}</div><pre>{esc(r.text)}</pre></div>")
    return (f"<div class='col'><h2>{esc(view.title) or 'Untitled'}</h2>"
            f"<p class='muted'>{esc(view.thread_id)} / {esc(view.branch_id)}</p><p>{status}</p>"
            f"{warns}{''.join(rows) or '<p class=muted>Summary only: no messages were saved for this thread.</p>'}</div>")


def compare(vault: Vault, left: str | None, right: str | None) -> str:
    """Two threads or branches side by side. Choices are 'thread-id|branch-id'."""
    threads = vault.list_threads()
    if not threads:
        return page("Compare", "<h1>Compare</h1><p>Save at least one thread first.</p>")
    options = [(t.thread_id + "|" + b, f"{t.title} ({b})") for t in threads for b in t.branches]
    valid = {v for v, _ in options}
    a = left if left in valid else options[0][0]
    b = right if right in valid else options[min(1, len(options) - 1)][0]

    def select(name: str, chosen: str) -> str:
        opts = "".join(f"<option value='{esc(v)}'{' selected' if v == chosen else ''}>{esc(lab)}</option>"
                       for v, lab in options)
        return f"<select name='{name}'>{opts}</select>"

    views = []
    for choice in (a, b):
        tid, bid = choice.split("|", 1)
        views.append(build_view(vault, tid, bid))
    diverge = first_divergence(views[0], views[1])
    summaries = [latest_handover(vault, *choice.split("|", 1)) for choice in (a, b)]
    form = (f"<form method='get' action='/compare' class='card pick'>"
            f"<label class='field-col'><span>Left</span>{select('a', a)}</label>"
            f"<label class='field-col'><span>Right</span>{select('b', b)}</label>"
            "<div class='pick-go'><button>Compare</button></div></form>")
    note = ("<p class='muted'>Compare two threads or branches: the same question asked to two AIs, or a "
            "thread and its fork (<code>thread fork</code>). Two unrelated chats will simply differ "
            "everywhere.</p>")
    messages = ("<h2 class='section-title'>Messages</h2><div class='cols'>"
                + _compare_column(views[0], diverge) + _compare_column(views[1], diverge) + "</div>")
    return page("Compare", "<h1>Compare</h1>" + note + form + _summary_compare(summaries[0], summaries[1])
                + messages)


def _summary_compare(left: tuple[int, str] | None, right: tuple[int, str] | None) -> str:
    """What differs between the latest summary of each side (line by line), then both in full."""
    if left is None and right is None:
        return "<div class='card'><p class='muted'>Neither side has a summary (handover) yet.</p></div>"
    ltext = left[1] if left else ""
    rtext = right[1] if right else ""
    full = (f"<details class='card'><summary>Show both summaries in full</summary><div class='cols'>"
            f"<div class='col'><h3>Left{f' (v{left[0]})' if left else ''}</h3>"
            f"<pre>{esc(ltext) or '(none)'}</pre></div>"
            f"<div class='col'><h3>Right{f' (v{right[0]})' if right else ''}</h3>"
            f"<pre>{esc(rtext) or '(none)'}</pre></div></div></details>")
    if ltext == rtext:
        return ("<div class='card'><h2>Summaries</h2><p class='ok'>&#10003; The two summaries are "
                f"identical.</p></div>{full}")
    lines = diff_text(ltext, rtext)
    shown = lines[:400]
    css = {"+": "add", "-": "del", " ": "same"}
    rows = "".join(f"<div class='{css[m]}'><span class='m'>{esc(m if m != ' ' else '')}</span>"
                   f"<span class='t'>{esc(text)}</span></div>" for m, text in shown)
    more = f"<p class='muted'>... {len(lines) - 400} more lines</p>" if len(lines) > 400 else ""
    changed = sum(1 for m, _ in lines if m != " ")
    return (f"<div class='card'><h2>What differs between the summaries</h2><p class='muted'>"
            f"<span class='delmark'>- only on the left</span> &nbsp; <span class='addmark'>+ only on "
            f"the right</span> &nbsp; {changed} changed line(s)</p><div class='diff'>{rows}</div>"
            f"{more}</div>{full}")


def pairing(pending: Sequence[tuple[str, str, int]], csrf: str) -> str:
    """`pending` is (request id, extension origin, seconds since asked) waiting for a decision."""
    if not pending:
        body = ("<div class='card'><h2>Nothing to approve</h2><p>In the browser extension, "
                "click <b>Connect to my vault</b>, then come back to this page and reload it.</p>"
                "</div>")
    else:
        cards = []
        for rid, origin, age in pending:
            short = origin.split("://", 1)[-1]
            cards.append(f"""<div class="card"><h2>Allow this browser extension?</h2>
<p>An extension is asking to save to your vault. Only allow it if you just clicked
<b>Connect to my vault</b> in the extension yourself.</p>
<p class="muted">Extension id: <code>{esc(short)}</code> &middot; asked {esc(age)} seconds ago.
If you did not click Connect in the last minute, choose <b>Don't allow</b>.</p>
<form method="post" action="/pair/decide">
<input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="id" value="{esc(rid)}">
<button name="decision" value="allow">Allow</button>
<button class="secondary" name="decision" value="deny">Don't allow</button></form></div>""")
        body = "".join(cards)
    return page("Connect the extension", "<h1>Connect the extension</h1>" + body, nav=False)


def message(title: str, text: str) -> str:
    return page(title, f"<div class='card'><h2>{esc(title)}</h2><p>{esc(text)}</p>"
                       "<p><a class='btn' href='/'>My saved threads</a></p></div>")
