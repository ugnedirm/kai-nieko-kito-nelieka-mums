"""Zip the built extension for the browser stores: `python tools/package_extension.py`.

Run `cd extension && npm run build` first. Writes, to `extension/dist/release/`:
  when-nothing-else-is-left-chrome-<version>.zip    (Chrome Web Store, Edge)
  when-nothing-else-is-left-firefox-<version>.zip   (Firefox Add-ons)
The zips are reproducible (sorted entries, fixed timestamps), with manifest.json at the top level.
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

EXT = Path(__file__).resolve().parents[1] / "extension"
STAMP = (2026, 1, 1, 0, 0, 0)  # fixed, so the same source gives byte-identical zips


def package(target: str) -> Path:
    src = EXT / "dist" / target
    manifest = src / "manifest.json"
    if not manifest.is_file():
        sys.exit(f"{src} is missing: run `cd extension && npm run build` first")
    version = json.loads(manifest.read_text())["version"]
    out = EXT / "dist" / "release"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"when-nothing-else-is-left-{target}-{version}.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(p for p in src.rglob("*") if p.is_file()):
            info = zipfile.ZipInfo(f.relative_to(src).as_posix(), STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, f.read_bytes())
    return path


def main() -> None:
    for target in ("chrome", "firefox"):
        path = package(target)
        print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
