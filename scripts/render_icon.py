#!/usr/bin/env python3
"""Render logo.svg to resources/icons/rustvpn.png with rsvg-convert.

The SVG is scaled to 256x256 and is not recolored. When ImageMagick's
magick is on PATH, also write a multi-size resources/icons/rustvpn.ico.
If magick is missing, the ico embeds the PNG and the script still exits 0.
"""

import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SVG = ROOT / "logo.svg"
ICON_DIR = ROOT / "resources" / "icons"
PNG = ICON_DIR / "rustvpn.png"
ICO = ICON_DIR / "rustvpn.ico"
SIZE = 256


def png_dimensions(path: Path):
    data = path.read_bytes()
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    return width, height


def write_png_ico(png: Path, ico: Path) -> None:
    """Vista-style ICO: one 256x256 image stored as the PNG bytes."""
    data = png.read_bytes()
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(data), 22)
    ico.write_bytes(header + entry + data)


def main() -> int:
    rsvg = shutil.which("rsvg-convert")
    if rsvg is None:
        print(
            "rsvg-convert is not on PATH. Install librsvg2-bin on Debian/Ubuntu, or librsvg on macOS.",
            file=sys.stderr,
        )
        return 1
    if not SVG.is_file():
        print(f"logo not found: {SVG}", file=sys.stderr)
        return 1

    ICON_DIR.mkdir(parents=True, exist_ok=True)
    rendered = subprocess.run(
        [
            rsvg,
            "--format",
            "png",
            "--width",
            str(SIZE),
            "--height",
            str(SIZE),
            "--output",
            str(PNG),
            str(SVG),
        ],
        check=False,
    )
    if rendered.returncode != 0:
        return rendered.returncode

    dims = png_dimensions(PNG)
    if dims != (SIZE, SIZE):
        print(f"expected {SIZE}x{SIZE} PNG, got {dims}", file=sys.stderr)
        return 1
    print(f"wrote {PNG.relative_to(ROOT)}")

    magick = shutil.which("magick")
    if magick is None:
        write_png_ico(PNG, ICO)
        print(f"wrote {ICO.relative_to(ROOT)}")
        return 0

    ico = subprocess.run(
        [
            magick,
            str(PNG),
            "-define",
            "icon:auto-resize=256,128,64,48,32,16",
            str(ICO),
        ],
        check=False,
    )
    if ico.returncode != 0:
        return ico.returncode
    print(f"wrote {ICO.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
