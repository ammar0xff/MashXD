#!/usr/bin/env python3
"""Smoke-test the freshly built PyInstaller binary (push through workflows)."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "dist" / ("MashXD.exe" if os.name == "nt" else "MashXD")
LIST = ROOT / "samples" / "Mal-Hashes.txt"
TARGET = ROOT / "samples" / "Task2.zip"


def main():
    if not EXE.is_file():
        sys.exit(f"[!] binary not found: {EXE}")
    subprocess.run([str(EXE), "--help"], check=True,
                   stdout=subprocess.DEVNULL)
    proc = subprocess.run(
        [str(EXE), "-l", str(LIST), "-f", str(TARGET), "--json"],
        capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        sys.exit(f"[!] scan failed ({proc.returncode}):\n{proc.stderr[-2000:]}")
    data = json.loads(proc.stdout)
    mal = [f for f in data["findings"] if f["grade"] == "MALWARE"]
    if not mal:
        sys.exit("[!] scan produced no MALWARE detections (expected hits)")
    print(f"binary smoke OK: {EXE.name} -> {len(mal)} MALWARE detections")


if __name__ == "__main__":
    main()