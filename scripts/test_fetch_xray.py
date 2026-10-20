#!/usr/bin/env python3
"""Argument parsing, iOS refusal, and local archive checks for fetch_xray."""

import hashlib
import io
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fetch_xray


class FetchXrayTests(unittest.TestCase):
    def test_linux_amd64_and_darwin_arm64_aliases(self):
        self.assertEqual(
            fetch_xray.select_target("linux", "amd64"),
            ("Xray-linux-64.zip", "linux-x64", "xray"),
        )
        self.assertEqual(
            fetch_xray.select_target("darwin", "arm64"),
            ("Xray-macos-arm64-v8a.zip", "macos-arm64", "xray"),
        )

    def test_ios_refuses_without_network(self):
        self.assertEqual(fetch_xray.select_target("ios", "arm64"), "ios")
        self.assertEqual(fetch_xray.main(["ios", "arm64"]), 1)

    def test_hash_gates_extract_and_skips_a_second_time(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("xray", b"fake-xray")
        body = payload.getvalue()
        digest = hashlib.sha256(body).hexdigest()
        root = Path(__file__).resolve().parents[1] / ".tmp" / "fetch-xray"
        dest = root / "resources" / "xray" / "linux-x64" / "xray"
        if dest.exists():
            dest.unlink()
        stamp = fetch_xray.stamp_path(dest)
        if stamp.exists():
            stamp.unlink()
        with self.assertRaises(ValueError):
            fetch_xray.apply_archive(body, "0" * 64, "xray", dest)
        self.assertFalse(dest.exists())
        fetch_xray.apply_archive(body, digest, "xray", dest)
        sums = f"{digest}  Xray-linux-64.zip\n"
        self.assertEqual(fetch_xray.expected_hash(sums, "Xray-linux-64.zip"), digest)
        self.assertTrue(fetch_xray.already_present(dest, digest))
        self.assertIsNone(fetch_xray.expected_hash("# empty\n", "Xray-linux-64.zip"))


if __name__ == "__main__":
    unittest.main()
