#!/usr/bin/env python3
"""Capture a screenshot of the sample HTML report, or write a placeholder PNG.

Never invokes Docker. Prefers Edge/Chrome/Chromium headless when available.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = REPO_ROOT / "examples" / "sample-report.html"
OUT_PATH = REPO_ROOT / "docs" / "images" / "sample-container-security-report.png"
WIDTH = 1440
HEIGHT = 1000


def _verify_synthetic(html: str) -> None:
    if "SYNTHETIC" not in html.upper():
        raise SystemExit("error: sample-report.html is not marked synthetic; refusing screenshot")


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def write_placeholder_png(path: Path, width: int = 120, height: int = 120) -> None:
    """Write a minimal valid PNG documenting that no browser was available."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Solid muted green fill (RGB)
    row = b"\x00" + (b"\x0b\x6e\x4f" * width)
    raw = row * height
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n"
    png += _png_chunk(b"IHDR", ihdr)
    png += _png_chunk(b"IDAT", zlib.compress(raw, 9))
    # tEXt comment
    text = b"Comment\x00browser not available - placeholder"
    png += _png_chunk(b"tEXt", text)
    png += _png_chunk(b"IEND", b"")
    path.write_bytes(png)


def _find_browser() -> list[str] | None:
    candidates = [
        "msedge",
        "chrome",
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
    ]
    # Windows common paths
    win_paths = [
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    ]
    for wp in win_paths:
        if wp.is_file():
            return [str(wp)]
    for name in candidates:
        found = shutil.which(name)
        if found:
            return [found]
    return None


def _try_browser_screenshot(browser: list[str], html: Path, out: Path) -> bool:
    out.parent.mkdir(parents=True, exist_ok=True)
    uri = html.resolve().as_uri()
    cmd = [
        *browser,
        "--headless=new",
        "--disable-gpu",
        f"--window-size={WIDTH},{HEIGHT}",
        f"--screenshot={out}",
        uri,
    ]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and out.is_file() and out.stat().st_size > 0


def main() -> int:
    if not HTML_PATH.is_file():
        print(
            "error: examples/sample-report.html missing; run generate-sample-reports.py first",
            file=sys.stderr,
        )
        return 1
    html = HTML_PATH.read_text(encoding="utf-8")
    _verify_synthetic(html)

    browser = _find_browser()
    if browser and _try_browser_screenshot(browser, HTML_PATH, OUT_PATH):
        print(f"Wrote screenshot via {browser[0]}: {OUT_PATH.relative_to(REPO_ROOT)}")
    else:
        write_placeholder_png(OUT_PATH)
        print(f"browser not available - wrote placeholder PNG: {OUT_PATH.relative_to(REPO_ROOT)}")

    if not OUT_PATH.is_file() or OUT_PATH.stat().st_size == 0:
        print("error: output PNG is missing or empty", file=sys.stderr)
        return 1
    # Verify PNG magic
    magic = OUT_PATH.read_bytes()[:8]
    if magic != b"\x89PNG\r\n\x1a\n":
        print("error: output is not a valid PNG", file=sys.stderr)
        return 1
    print(f"OK: PNG size={OUT_PATH.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
