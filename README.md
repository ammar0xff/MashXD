# MashXD

[![CI](https://github.com/ammar0xff/MashXD/actions/workflows/ci.yml/badge.svg)](https://github.com/ammar0xff/MashXD/actions/workflows/ci.yml)

A malware **triage engine** based on hash-list comparison, upgraded with
on-the-fly static analysis. It unwraps a ZIP/RAR archive (or walks a whole
directory - nested archives included) and gives every file a full pass **in
memory**: nothing is ever extracted to disk, so samples and zip-slip attacks
stay harmless.

Made by ammar0xff.

## Capabilities

| pass | what it tells you |
|------|-------------------|
| **signatures** | CRC32 + 12 crypto hashes (MD5, SHA-1/2/3, BLAKE2) against your hash list |
| **file type** | magic-byte sniffing: PE / ELF / Mach-O / PDF / archives / scripts |
| **entropy** | Shannon bits-per-byte - high entropy flags packed/encrypted payloads |
| **indicator strings** | URLs, IPs, `.onion`, base64 blobs, injection APIs, LOLBin commands (`powershell`, `certutil`, `mshta`...), persistence strings |
| **PE deep-dive** | with `pefile`: machine type, sections, UPX packing, suspicious imports |

Each file gets a weighted risk **score** and a verdict:
`MALWARE` / `SUSPICIOUS` / `CLEAN`. A hash-list hit is an instant `MALWARE`,
but files are also flagged heuristically even when no hash matches - that is
the point over a plain hash matcher.

## Setup

```sh
pip install -r requirements.txt

# only needed if you scan .rar containers:
#   Linux : apt install unrar        (or: pkg install unrar on Termux)
#   macOS : brew install unrar
# pefile is optional as a runtime dependency, but it is what unlocks the
# deep PE analysis - keep it installed.
```

## Usage

```sh
python MashXD.py -l Mal-Hashes.txt -f Task2.zip
```

- `-l <file>` - hash list (one hash per line; blank lines / `#` comments ignored).
- `-f <path>` - archive (`.zip`/`.rar`) **or a directory** to scan recursively.
- `--json` - machine-readable JSON results.
- `--html out.html` - also write a standalone HTML report.
- `--max-depth N` - nested archive depth (default 6).
- `-v` / `--verbose` - one report line per scanned file.

### Examples

```sh
python MashXD.py -l samples/Mal-Hashes.txt -f samples/Task2.zip
python MashXD.py -l samples/Mal-Hashes.txt -f samples/Task2.zip --html report.html
python MashXD.py -l samples/Mal-Hashes.txt -f ./scan-drop --max-depth 8
python MashXD.py -l samples/Mal-Hashes.txt -f samples/Task2.zip --json
```

## How it works

1. Normalizes the hash list (stripped, lowercased, deduped, comments allowed).
2. Loads the target into memory (a file, an archive, or every file under a dir).
3. Recursively unwraps ZIP/RAR by magic bytes - extensions don't matter, and a
   nested archive inside an archive is scanned too.
4. Per file, in a single byte-pass: all 13 digests, entropy, string indicators,
   and (for PE files) the pefile deep-dive.
5. Accumulates weighted evidence into a score and grades the file.
6. Reports a human report, JSON, and/or a self-contained HTML page.

## Downloads

Prebuilt binaries are attached to every [GitHub Release](https://github.com/ammar0xff/MashXD/releases):
an AppImage and a `.deb` (Debian/Ubuntu), a `.exe` (Windows, zipped), and a
zipped macOS binary. CI builds and smoke-tests each artifact from the tagged
source - nothing runs here. `.rar` containers still need the `unrar` binary on
the machine that runs MashXD.

## Tests

```sh
python -m unittest discover -s tests -v
```

The suite covers hashing, magic sniffing, provenance/depth, heuristic grading
(no hash match), zip-slip name sanitization, JSON purity, the HTML report, and
an integration check against `samples/Task2.zip` (skipped if the samples
directory is absent). CI runs the full suite on **Linux and Windows** across
Python 3.11 and 3.13, lints with ruff, and uploads an HTML report artifact;
`unrar` is installed on Linux so `.rar` members get exercised too.

## Sample output

```
Findings:
------------------------------------------------------------------
sample.exe  [70]
      in     : Task2.zip -> Task2/4132356.zip -> sample.exe
      size   : 24,576 Bytes
      type   : PE executable (MZ)
      entropy: 7.81 / 8.0
      hash   : crc32     6b2f6458
      pe     : machine 0x14c, sections .text .rdata .data UPX1
               UPX detected
```

## Notes

- Scores are **heuristics**, not forensic conclusions - a `SUSPICIOUS` tag just
  means the file earned weight from indicators. Read the clues before acting.
- `.rar` members need the `unrar` binary; without it they are skipped with a
  hint instead of crashing.
- Reading is in-memory by design; keep individual scans to a sensible size.