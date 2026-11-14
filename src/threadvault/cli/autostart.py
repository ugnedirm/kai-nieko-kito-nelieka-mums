"""Start `thread serve` automatically at login (macOS launchd, Linux systemd --user).

Only writes one small service file in the user's own home and asks the OS to load it; nothing
needs administrator rights. `remove` undoes both. The service runs the same `thread serve` the
person could run by hand, bound to 127.0.0.1.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path

LABEL = "com.threadvault.serve"


class AutostartError(Exception):
    pass


def _thread_command() -> str:
    candidate = Path(sys.executable).parent / "thread"
    if candidate.exists():
        return str(candidate)
    raise AutostartError("cannot find the `thread` program next to this Python")


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def _plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / "threadvault.service"


def supported() -> bool:
    return sys.platform == "darwin" or sys.platform.startswith("linux")


def install(vault_root: Path, port: int) -> str:
    cmd = [_thread_command(), "--vault", str(vault_root), "serve", "--port", str(port)]
    if sys.platform == "darwin":
        path = _plist_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        log = vault_root / "service.log"
        path.write_bytes(plistlib.dumps({
            "Label": LABEL, "ProgramArguments": cmd, "RunAtLoad": True, "KeepAlive": True,
            "StandardOutPath": str(log), "StandardErrorPath": str(log)}))
        uid = str(os.getuid())
        _run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"])  # replace an older copy, if any
        done = _run(["launchctl", "bootstrap", f"gui/{uid}", str(path)])
        if done.returncode != 0:
            raise AutostartError("launchctl could not load the service")
        return f"installed {path}"
    if sys.platform.startswith("linux"):
        path = _unit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        quoted = " ".join(f'"{c}"' for c in cmd)
        path.write_text("[Unit]\nDescription=threadvault local service\n\n[Service]\n"
                        f"ExecStart={quoted}\nRestart=on-failure\n\n"
                        "[Install]\nWantedBy=default.target\n", encoding="utf-8")
        _run(["systemctl", "--user", "daemon-reload"])
        done = _run(["systemctl", "--user", "enable", "--now", "threadvault.service"])
        if done.returncode != 0:
            raise AutostartError("systemctl could not start the service")
        return f"installed {path}"
    raise AutostartError("automatic start is not supported on this system")


def remove() -> str:
    if sys.platform == "darwin":
        _run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"])
        _plist_path().unlink(missing_ok=True)
        return "removed the login service"
    if sys.platform.startswith("linux"):
        _run(["systemctl", "--user", "disable", "--now", "threadvault.service"])
        _unit_path().unlink(missing_ok=True)
        return "removed the login service"
    raise AutostartError("automatic start is not supported on this system")
