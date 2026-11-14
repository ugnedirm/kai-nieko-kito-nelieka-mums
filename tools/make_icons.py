"""Generate the extension icons (purple rounded square with a white dot) using only the standard
library: `python tools/make_icons.py`. Output: extension/icons/icon-<size>.png (committed)."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

PURPLE = (0x6A, 0x31, 0xA6)
WHITE = (0xFF, 0xFF, 0xFF)
SIZES = (16, 32, 48, 128)
SS = 4  # supersampling, for smooth edges


def _inside_rounded_square(x: float, y: float, size: float, radius: float) -> bool:
    cx = min(max(x, radius), size - radius)
    cy = min(max(y, radius), size - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius**2


def _pixel(px: int, py: int, size: int) -> tuple[int, int, int, int]:
    """RGBA of one output pixel, averaged over SS x SS samples."""
    r = g = b = a = 0
    for sy in range(SS):
        for sx in range(SS):
            x = px + (sx + 0.5) / SS
            y = py + (sy + 0.5) / SS
            if not _inside_rounded_square(x, y, size, size * 0.22):
                continue
            white = (x - size / 2) ** 2 + (y - size / 2) ** 2 <= (size * 0.2) ** 2
            cr, cg, cb = WHITE if white else PURPLE
            r, g, b, a = r + cr, g + cg, b + cb, a + 1
    if a == 0:
        return (0, 0, 0, 0)
    return (r // a, g // a, b // a, round(255 * a / (SS * SS)))


def _png(size: int) -> bytes:
    raw = b"".join(b"\x00" + bytes(v for px in range(size) for v in _pixel(px, py, size))
                   for py in range(size))

    def chunk(kind: bytes, body: bytes) -> bytes:
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "extension" / "icons"
    out.mkdir(exist_ok=True)
    for size in SIZES:
        (out / f"icon-{size}.png").write_bytes(_png(size))
        print("wrote", out / f"icon-{size}.png")


if __name__ == "__main__":
    main()
