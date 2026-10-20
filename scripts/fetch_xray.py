#!/usr/bin/env python3
"""Download the pinned Xray-core binary into resources/xray/<target>/.

Читает тег из resources/xray/VERSION (сейчас v26.3.27).
Кладёт бинарник в resources/xray/<target>/.
Сверяет SHA-256 архива с resources/xray/SHA256SUMS до распаковки.
Повторный запуск пропускает загрузку, если бинарник уже есть и записанный хеш архива совпал.
ios завершается с кодом 1: готовый бинарник Xray-core для iOS скрипт не качает.
Поиск файла в рантайме делает rvpn_xray::locate_binary: XRAY_BIN, затем xray рядом с rustvpn, затем resources/xray этой платформы.
"""

import hashlib
import io
import platform
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_PATH = ROOT / "resources" / "xray" / "VERSION"
SUMS_PATH = ROOT / "resources" / "xray" / "SHA256SUMS"
VERSION = VERSION_PATH.read_text().strip()
BASE = f"https://github.com/XTLS/Xray-core/releases/download/{VERSION}"

TARGETS = {
    ("linux", "x86_64"): ("Xray-linux-64.zip", "linux-x64", "xray"),
    ("linux", "aarch64"): ("Xray-linux-arm64-v8a.zip", "linux-arm64", "xray"),
    ("android", "x86_64"): ("Xray-android-amd64.zip", "android-x64", "xray"),
    ("android", "aarch64"): ("Xray-android-arm64-v8a.zip", "android-arm64", "xray"),
    ("windows", "x86_64"): ("Xray-windows-64.zip", "windows-x64", "xray.exe"),
    ("windows", "aarch64"): ("Xray-windows-arm64-v8a.zip", "windows-arm64", "xray.exe"),
    ("darwin", "x86_64"): ("Xray-macos-64.zip", "macos-x64", "xray"),
    ("darwin", "aarch64"): ("Xray-macos-arm64-v8a.zip", "macos-arm64", "xray"),
}

IOS_MESSAGE = (
    "Xray-core does not publish an iOS binary. "
    "Build it separately and place it at resources/xray/ios-arm64/xray."
)


def select_target(system: str, machine: str):
    """Return the archive triple, 'ios', or 'unsupported'."""
    system = system.lower()
    machine = machine.lower()
    if system == "linux" and machine in ("amd64", "x64"):
        machine = "x86_64"
    if system == "darwin" and machine == "arm64":
        machine = "aarch64"
    if system == "ios":
        return "ios"
    return TARGETS.get((system, machine), "unsupported")


def expected_hash(sums_text: str, archive: str):
    for line in sums_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[-1] == archive:
            return parts[0].lower()
    return None


def stamp_path(dest: Path) -> Path:
    return dest.parent / f"{dest.name}.sha256"


def already_present(dest: Path, expected: str) -> bool:
    stamp = stamp_path(dest)
    if not dest.is_file() or not stamp.is_file():
        return False
    return stamp.read_text().strip().lower() == expected.lower()


def apply_archive(payload: bytes, expected: str, binary_name: str, dest: Path) -> None:
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected.lower():
        raise ValueError(f"sha256 mismatch for {binary_name}")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        body = archive.read(binary_name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(body)
    dest.chmod(0o755)
    stamp_path(dest).write_text(digest + "\n")


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    system = args[0] if args else platform.system().lower()
    machine = args[1] if len(args) > 1 else platform.machine().lower()
    selected = select_target(system, machine)
    if selected == "ios":
        print(IOS_MESSAGE, file=sys.stderr)
        return 1
    if selected == "unsupported":
        print(f"unsupported target {system}/{machine}", file=sys.stderr)
        return 1
    archive, folder, binary = selected
    sums_text = SUMS_PATH.read_text() if SUMS_PATH.is_file() else ""
    expected = expected_hash(sums_text, archive)
    if expected is None:
        print(f"no sha256 for {archive} in {SUMS_PATH.name}", file=sys.stderr)
        return 1
    dest = ROOT / "resources" / "xray" / folder / binary
    if already_present(dest, expected):
        print(f"skip {dest}")
        return 0
    url = f"{BASE}/{archive}"
    print(f"fetch {url}")
    with urllib.request.urlopen(url, timeout=120) as response:
        payload = response.read()
    try:
        apply_archive(payload, expected, binary, dest)
    except (ValueError, KeyError, zipfile.BadZipFile) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"wrote {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
