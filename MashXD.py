#!/usr/bin/env python3
"""MashXD - a malware triage engine based on hash-list comparison.

Scans a ZIP/RAR archive (or a whole directory), unwraps nested archives and
gives every file a static-analysis pass in memory:

    * signature comparison   CRC32 / MD5 / SHA-1/2/3 / BLAKE2 vs hash list
    * file-type magic        PE / ELF / Mach-O / PDF / archives / scripts
    * Shannon entropy        high entropy => packed / encrypted payload
    * indicator strings      URLs, IPs, .onion, base64 blobs, injection APIs,
                             LOLBin commands, persistence strings
    * optional PE deep-dive  sections, imports, UPX packing (needs 'pefile')

Nothing is ever extracted to disk (zip-slip safe).

Usage:
    MashXD.py -l <list.txt> -f <file.zip>
    MashXD.py -l <list.txt> -f samples/ --json
    MashXD.py -l <list.txt> -f <file.zip> --html report.html
"""

import argparse
import binascii
import html
import hashlib
import io
import json
import math
import re
import sys
import zipfile
from pathlib import Path

try:
    import pyfiglet
except ImportError:  # pyfiglet is optional
    pyfiglet = None

try:
    from termcolor import colored
except ImportError:  # termcolor is optional
    def colored(text, color="white"):
        return text

try:
    import pefile
except ImportError:  # pefile is optional (deep PE analysis)
    pefile = None

try:
    import rarfile
except ImportError:  # rarfile only needed for .rar containers
    rarfile = None
    RAR_RUNTIME_HINT = "pip install rarfile (plus the 'unrar' binary on your system)"
else:
    RAR_RUNTIME_HINT = "install the 'unrar' binary (e.g. apt install unrar / pkg install unrar)"

# ---------------------------------------------------------------------------
# hashing --------------------------------------------------------------------
# ---------------------------------------------------------------------------

HASH_ALGORITHMS = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b", "blake2s",
]

RAR_MAGIC = b"Rar!\x1a\x07"

MAX_DEPTH_DEFAULT = 6

# grades / scores
HASH_HIT_SCORE = 100          # any hash-list match
PE_SUSPECT_IMPORTS_SCORE = 40
PACKED_SCORE = 25
HIGH_ENTROPY_SCORE = 20
ONSUSPICIOUS_PER_GROUP = {"url": 10, "ip": 10, "onion": 15, "api": 20,
                          "cmd": 20, "persist": 12, "base64": 15}
GROUP_CAP = {"url": 3, "ip": 2, "onion": 1, "api": 3, "cmd": 2,
             "persist": 3, "base64": 1}
SUSPICIOUS_GRADE_SCORE = 20
MALWARE_GRADE_SCORE = 50
HIGH_ENTROPY = 6.9


def digests(data):
    """Return {algorithm: hexdigest} for every supported algorithm."""
    out = {}
    for name in HASH_ALGORITHMS:
        out[name] = hashlib.new(name, data).hexdigest()
    out["crc32"] = "%08x" % (binascii.crc32(data) & 0xFFFFFFFF)
    return out


# ---------------------------------------------------------------------------
# hash list -----------------------------------------------------------------
# ---------------------------------------------------------------------------

def load_hash_list(path):
    """Read a hash list into a normalized set (stripped, lowercased, deduped)."""
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise SystemExit(f"[!] cannot read hash list '{path}': {error}")

    signatures = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            signatures.add(line)

    if not signatures:
        raise SystemExit(f"[!] '{path}' contains no hashes to compare against.")
    return signatures


# ---------------------------------------------------------------------------
# file introspection ---------------------------------------------------------
# ---------------------------------------------------------------------------

MAGIC_RULES = [
    (b"MZ", "PE executable (MZ)"),
    (b"\x7fELF", "ELF executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary (thin/universal)"),
    (b"PK\x03\x04", "ZIP archive"),
    (RAR_MAGIC, "RAR archive"),
    (b"%PDF", "PDF document"),
    (b"\x1f\x8b", "GZIP/GZ data"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x89PNG", "PNG image"),
    (b"\x7f\xc7", "7-Zip archive"),
    (b"\xAC\xED", "Java serialized object"),
]

SHEBANG = re.compile(rb"^#![ \t]*([^\r\n]+)")


def sniff_type(data, filename=""):
    """Return a human-readable file type from magic bytes."""
    for magic, label in MAGIC_RULES:
        if data.startswith(magic):
            return label
    if SHEBANG.search(data):
        lang = SHEBANG.search(data).group(1).decode("utf-8", errors="replace").strip()
        return f"script ({lang})"
    ext = Path(filename).suffix.lower()
    if ext:
        return f"data file (.{ext.lstrip('.')})"
    return "unknown / data"


def shannon_entropy(data):
    """Shannon entropy in bits per byte (0..8). Higher usually = packed/encrypted."""
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


# ---------------------------------------------------------------------------
# indicator strings ----------------------------------------------------------
# ---------------------------------------------------------------------------

STRING_RUN = re.compile(rb"[\x20-\x7e]{5,}")

INDICATORS = {
    "url":        re.compile(rb"https?://[^\s\"'<>]+"),
    "ip":         re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "onion":      re.compile(rb"\b[a-z2-7]{16}\.onion\b"),
    "base64":     re.compile(rb"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
    "api":        re.compile(rb"\b(?:VirtualAlloc|VirtualProtect|WriteProcessMemory"
                             rb"|ReadProcessMemory|CreateRemoteThread|CreateThread"
                             rb"|GetProcAddress|LoadLibrary|ZwAllocateVirtualMemory"
                             rb"|MiniDumpWriteDump|SetWindowsHookEx|GetAsyncKeyState"
                             rb"|kernel32|ntdll|DebugActiveProcess|OpenProcess)\b"),
    "cmd":        re.compile(rb"\b(?:powershell|cmd\.exe|curl\.exe|certutil|mshta"
                             rb"|regsvr32|rundll32|schtasks|wmic|bitsadmin"
                             rb"|Invoke-Expression|IEX\b)\b", re.IGNORECASE),
    "persist":    re.compile(rb"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|AppInit_DLLs"
                             rb"|Run\b|Startup|schtasks|CreateService|SetWindowsHookEx"
                             rb"|CurrentVersion|Explorer\.Run)\b", re.IGNORECASE),
}

LABELS = {
    "url": "URL(s)", "ip": "IP address(es)", "onion": ".onion host(s)",
    "base64": "base64 blob(s)", "api": "suspicious API(call)",
    "cmd": "LOLBin/attack command", "persist": "persistence indicator",
}


def find_indicators(data):
    """Return {group: {"count": n, "cards": [..up to 12 unique examples..]}}."""
    results = {}
    seen = {group: set() for group in INDICATORS}
    for match in STRING_RUN.finditer(data):
        run = match.group()
        for group, pattern in INDICATORS.items():
            for hit in pattern.finditer(run):
                token = hit.group(0).decode("utf-8", errors="replace")
                if token in seen[group]:
                    continue
                seen[group].add(token)
                results.setdefault(group, {"count": 0, "cards": []})
                results[group]["count"] += 1
                if len(results[group]["cards"]) < 12:
                    results[group]["cards"].append(token[:80])
    return results


# ---------------------------------------------------------------------------
# PE deep-dive (optional pefile) ---------------------------------------------
# ---------------------------------------------------------------------------

SUSPECT_IMPORTS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateThread", "GetProcAddress", "LoadLibrary",
    "LoadLibraryA", "SetWindowsHookEx", "GetAsyncKeyState", "MiniDumpWriteDump",
    "OpenProcess", "CloseHandle", "CreateProcess", "WinExec",
}

UPX_SECTIONS = {"UPX0", "UPX1", "UPX2"}


def is_pe(data):
    return data.startswith(b"MZ") and data.find(b"PE\x00\x00", 0x40, 0x400) != -1


def pe_analysis(data, name):
    """Deep PE look: machine, sections, UPX, suspicious imports (pefile)."""
    if pefile is None:
        return {"note": "install 'pefile' for deep PE analysis"}
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as error:  # PEParseError etc.
        return {"note": f"cannot parse PE: {error}"}

    report = {"machine": hex(pe.FILE_HEADER.Machine or 0)}

    section_names = []
    max_entropy = (0.0, None)
    for section in getattr(pe, "sections", []):
        sec_name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        section_names.append(sec_name)
        ent = section.get_entropy() or 0.0
        if ent > max_entropy[0]:
            max_entropy = (ent, sec_name)
    report["sections"] = section_names
    report["max_section_entropy"] = round(max_entropy[0], 2)

    if any(name in UPX_SECTIONS for name in section_names) or b"UPX" in pe.__data__[:4096]:
        report["packed"] = "UPX detected"

    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                imports.append(imp.name.decode("utf-8", errors="replace"))
            else:
                imports.append(f"ord({imp.ordinal})")
    report["imports"] = imports
    suspects = sorted(set(imports) & SUSPECT_IMPORTS)
    report["suspicious_imports"] = suspects
    report["upx_sections"] = [n for n in section_names if n in UPX_SECTIONS]
    return report


# ---------------------------------------------------------------------------
# evaluation / scoring -------------------------------------------------------
# ---------------------------------------------------------------------------

def evaluate(name, provenance, size, payload, signatures):
    """Full static pass over one file -> evidence dict + grade."""
    evidence = {"name": name, "in": provenance, "size": size}
    clues = []
    score = 0

    # --- signature list ------------------------------------------------------
    ds = digests(payload)
    matched = [algo for algo, value in ds.items() if value in signatures]
    if matched:
        evidence["hashes"] = [(algo, ds[algo]) for algo in matched]
        score += HASH_HIT_SCORE * len(matched)
        clues.append("signature match in malware list")

    # --- type / entropy ------------------------------------------------------
    evidence["type"] = sniff_type(payload, name)
    evidence["entropy"] = shannon_entropy(payload)
    if evidence["entropy"] >= HIGH_ENTROPY and size >= 1024:
        evidence["high_entropy"] = True
        score += HIGH_ENTROPY_SCORE
        clues.append(f"high entropy {evidence['entropy']} (packed/encrypted?)")

    # --- indicators ----------------------------------------------------------
    indicators = find_indicators(payload)
    if indicators:
        evidence["indicators"] = {g: {"count": v["count"], "cards": v["cards"]}
                                  for g, v in indicators.items()}
        for group, info in indicators.items():
            weight = ONSUSPICIOUS_PER_GROUP[group]
            cap = GROUP_CAP[group]
            score += weight * min(info["count"], cap)
            clues.append(f"{LABELS[group]}: {info['count']}")

    # --- PE deep dive ---------------------------------------------------------
    if is_pe(payload):
        pe = pe_analysis(payload, name)
        evidence["pe"] = pe
        if pe.get("packed"):
            score += PACKED_SCORE
            clues.append("packed (UPX-style)")
        suspects = pe.get("suspicious_imports", [])
        if pe.get("note") is None and suspects:
            score += PE_SUSPECT_IMPORTS_SCORE
            clues.append(f"suspicious imports: {', '.join(suspects[:5])}")

    evidence["score"] = score
    evidence["grade"] = ("MALWARE" if (score >= MALWARE_GRADE_SCORE or matched)
                         else "SUSPICIOUS" if score >= SUSPICIOUS_GRADE_SCORE
                         else "CLEAN")
    evidence["clues"] = clues
    return evidence


# ---------------------------------------------------------------------------
# archive walking (in memory, no extraction) ---------------------------------
# ---------------------------------------------------------------------------

def is_zip(data):
    return data.startswith(b"PK\x03\x04")


def is_rar(data):
    return data.startswith(RAR_MAGIC)


def members_of(data, label):
    stream = io.BytesIO(data)
    if is_zip(data):
        with zipfile.ZipFile(stream) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                yield info.filename, info.file_size, archive.read(info)
        return

    if rarfile is None:
        raise RuntimeError(RAR_RUNTIME_HINT)

    try:
        with rarfile.RarFile(stream) as archive:
            for info in archive.infolist():
                if info.isdir():
                    continue
                yield info.filename, info.file_size, archive.read(info)
    except rarfile.RarCannotExec:
        raise RuntimeError(RAR_RUNTIME_HINT)
    except rarfile.BadRarFile as error:
        raise RuntimeError(f"corrupt rar '{label}': {error}")


def normalize_member_name(name):
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return "/".join(parts)


def scan(data, origin, names, signatures, max_depth, verbose, depth=0, findings=None):
    """Recursive walk over one container; append findings for every file."""
    if findings is None:
        findings = []
    if depth > max_depth:
        if verbose:
            print(colored(f"[!] depth limit ({max_depth}) reached inside '{origin}'.",
                          "yellow"))
        return findings

    if not (is_zip(data) or (is_rar(data) and rarfile is not None)):
        return findings

    try:
        members = list(members_of(data, origin))
    except RuntimeError as error:
        if verbose:
            print(colored(f"[!] cannot read '{origin}' ({error}) - skipped.", "yellow"))
        return findings

    for name, size, payload in members:
        member_name = normalize_member_name(name)
        if not member_name:
            continue
        here = "/".join(names + [member_name])

        evidence = evaluate(member_name, here, size, payload, signatures)
        findings.append(evidence)
        if verbose:
            tag = {"MALWARE": "light_red", "SUSPICIOUS": "yellow",
                   "CLEAN": "green"}[evidence["grade"]]
            print(colored(f"[*] {here} ", "light_blue") +
                  colored(f"({size:,} B, {evidence['type']}, "
                          f"entropy {evidence['entropy']}) -> ", "yellow") +
                  colored(evidence["grade"], tag))

        if is_zip(payload) or (is_rar(payload) and rarfile is not None):
            scan(payload, here, names + [member_name], signatures, max_depth,
                 verbose, depth + 1, findings)
    return findings


def scan_path(path, signatures, max_depth, verbose):
    """Scan one file, or recursively scan every file in a directory."""
    path = Path(path)
    findings = []
    if path.is_dir():
        for file in sorted(path.rglob("*")):
            if not file.is_file():
                continue
            data = file.read_bytes()
            here = str(file.relative_to(path))
            evidence = evaluate(file.name, here, len(data), data, signatures)
            findings.append(evidence)
            if is_zip(data) or (is_rar(data) and rarfile is not None):
                scan(data, here, [here], signatures, max_depth, verbose, findings=findings)
        return findings

    data = path.read_bytes()
    if is_zip(data) or (is_rar(data) and rarfile is not None):
        return scan(data, path.name, [], signatures, max_depth, verbose)
    if is_rar(data) and rarfile is None and verbose:
        print(colored(f"[!] '{path.name}' is a RAR but rarfile/unrar is missing "
                      f"- scanning it as a raw file.", "yellow"))
    evidence = evaluate(path.name, path.name, len(data), data, signatures)
    return [evidence]


# ---------------------------------------------------------------------------
# output --------------------------------------------------------------------
# ---------------------------------------------------------------------------

def banner():
    if pyfiglet is not None:
        print(colored(pyfiglet.figlet_format("MashXD"), "magenta") +
              colored("## Made By ammar0xff ##\n", "light_green"))
    else:
        print(colored("MashXD - ## Made By ammar0xff ##\n", "magenta"))


GRADE_COLOR = {"MALWARE": "light_red", "SUSPICIOUS": "yellow", "CLEAN": "green"}


def print_detections(input_label, findings, signatures):
    malwares = [f for f in findings if f["grade"] == "MALWARE"]
    suspicious = [f for f in findings if f["grade"] == "SUSPICIOUS"]

    print("\n" + colored("Findings:", "cyan"))
    print(colored("-" * 66, "cyan"))

    for level, items in (("MALWARE", malwares), ("SUSPICIOUS", suspicious)):
        if not items:
            continue
        for f in items:
            head = colored(f['name'], GRADE_COLOR[level])
            if f["grade"] == "MALWARE":
                head += colored(f"  [{f['score']}]", "magenta")
            print(head)
            print(f"      in     : {f['in']}")
            print(f"      size   : {f['size']:,} Bytes")
            print(f"      type   : {f['type']}")
            print(f"      entropy: {f['entropy']} / 8.0")
            for algo, value in f.get("hashes", []):
                print(colored(f"      hash   : {algo:<8} {value}", "blue"))
            pe = f.get("pe")
            if pe and not pe.get("note"):
                print(f"      pe     : machine {pe['machine']}, "
                      f"sections {', '.join(pe['sections'][:8])}")
                if pe.get("packed"):
                    print(colored(f"               {pe['packed']}", "yellow"))
                if pe.get("suspicious_imports"):
                    print(colored("               imports: "
                                  + ", ".join(pe["suspicious_imports"][:8]), "yellow"))
            for group, info in (f.get("indicators") or {}).items():
                cards = ", ".join(info["cards"][:4])
                print(colored(f"      ind    : {LABELS[group]} -> {info['count']} "
                              f"({cards})", "yellow"))
            print()

    if not malwares and not suspicious:
        print(colored("  nothing suspicious found.", "green"))
        return

    total_sigs = len(signatures)
    verdict = ("MALWARE FOUND" if malwares
               else "SUSPICIOUS FILES PRESENT (no hash match)")
    print(colored("-" * 66, "cyan"))
    print(f"[*] {len(findings)} file(s) scanned against {total_sigs} "
          f"signature(s) -> {colored(verdict, GRADE_COLOR['MALWARE' if malwares else 'SUSPICIOUS'])}")
    summary = ", ".join(f"{g}: {sum(1 for x in findings if x['grade'] == g)}"
                        for g in ("MALWARE", "SUSPICIOUS", "CLEAN"))
    print(f"[*] breakdown {summary}")
    print(colored("# Made By ammar0xff #", "magenta"))


def render_html(path, findings, signatures):
    rows = []
    for f in findings:
        clues = "</li><li>".join(html.escape(c) for c in f["clues"]) or "&nbsp;"
        rows.append(f"""
      <div class="card {f['grade'].lower()}">
        <div class="top">
          <span class="name">{html.escape(f['name'])}</span>
          <span class="grade">{f['grade']} <small>{f['score']}</small></span>
        </div>
        <div class="meta">
          in: {html.escape(f['in'])} &middot; {f['size']:,} B &middot;
          {html.escape(f['type'])} &middot; entropy {f['entropy']}/8
        </div>
        {('<div class="clues">' + clues + '</div>') if f['clues'] else ''}
      </div>""")

    mal = sum(1 for x in findings if x["grade"] == "MALWARE")
    sus = sum(1 for x in findings if x["grade"] == "SUSPICIOUS")

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MashXD - scan report</title>
<style>
  body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background: #0d1117; color: #c9d1d9; margin: 0; padding: 2rem; }}
  h1 {{ color: #e6edf3; margin-bottom: .2rem; }}
  .scores {{ display: flex; gap: 1rem; margin: 1rem 0 2rem; }}
  .pill {{ padding: .35rem .8rem; border-radius: 999px; font-weight: 700; }}
  .malware {{ background:#b5322d; }} .suspicious {{ background:#d29922; }}
  .clear {{ background:#238636; }}
  .card {{ border: 1px solid #30363d; border-left: 4px solid #30363d;
          border-radius: 8px; padding: .8rem 1rem; margin-bottom: .8rem; }}
  .card.malware {{ border-left-color: #f85149; }}
  .card.suspicious {{ border-left-color: #d29922; }}
  .top {{ display: flex; justify-content: space-between; align-items: center; }}
  .name {{ font-weight: 700; color: #e6edf3; }}
  .grade {{ font-size: .9rem; }} .grade small {{ color: #8b949e; }}
  .meta {{ color: #8b949e; font-size: .85rem; margin: .4rem 0; }}
  .clues {{ background: #161b22; border-radius: 6px; padding: .5rem .8rem;
           font-size: .85rem; color: #ffa657; }}
  .clues li {{ margin: .15rem 0; }}
</style></head><body>
  <h1>MashXD <span style="color:#8b949e;font-size:.9rem">scan report</span></h1>
  <div class="scores">
    <span class="pill malware">MALWARE {mal}</span>
    <span class="pill suspicious">SUSPICIOUS {sus}</span>
    <span class="pill clear">CLEAN {len(findings) - mal - sus}</span>
    <span style="align-self:center;color:#8b949e">{len(signatures)} signatures &middot;
     {len(findings)} files</span>
  </div>
  {''.join(rows)}
  <p style="color:#8b949e;font-size:.8rem">Generated by MashXD &middot; Made By ammar0xff</p>
</body></html>"""
    Path(path).write_text(document, encoding="utf-8")
    print(colored("[*] html report written to ", "light_blue") + colored(path, "green"))


# ---------------------------------------------------------------------------
# CLI -----------------------------------------------------------------------
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="MashXD",
        description="Malware triage engine: hash-list comparison plus "
                    "type/entropy/indicator/PE static analysis. "
                    "In-memory only, nothing is written to disk.",
        epilog="examples:\n"
               "  MashXD.py -l samples/Mal-Hashes.txt -f samples/Task2.zip\n"
               "  MashXD.py -l Mal-Hashes.txt -f ./malware_samples --json\n"
               "  MashXD.py -l Mal-Hashes.txt -f samples/Task2.zip --html report.html",
        usage="MashXD.py -l <list.txt> -f <file.zip|dir> [--json|--html out.html]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-l", metavar="LIST", dest="hash_list", required=True,
                        help="path to the list of known-bad hashes")
    parser.add_argument("-f", metavar="PATH", dest="target", required=True,
                        help="archive (.zip/.rar) or directory to scan")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of the report")
    parser.add_argument("--html", metavar="OUT",
                        help="also write a standalone HTML report to OUT")
    parser.add_argument("--max-depth", type=int, default=MAX_DEPTH_DEFAULT,
                        metavar="N", help=f"nested archive depth (default: "
                                          f"{MAX_DEPTH_DEFAULT})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="report one line per scanned file")
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.json:
        banner()

    target = Path(args.target)
    if not target.exists():
        raise SystemExit(f"[!] '{args.target}' not found.")

    signatures = load_hash_list(args.hash_list)

    if target.is_dir() or target.is_file():
        if not args.json:
            print(colored("[*] ", "light_blue") +
                  colored("scanning ", "light_green") +
                  colored(str(target), "magenta") +
                  colored(f" ({len(signatures)} signatures, depth {args.max_depth})",
                          "yellow"))
        findings = scan_path(target, signatures, args.max_depth, args.verbose)
    else:
        raise SystemExit(f"[!] '{args.target}' is not a file or directory.")

    if args.json:
        print(json.dumps({"target": str(target),
                          "signatures": sorted(signatures),
                          "findings": findings}, indent=2))
        return

    print_detections(str(target), findings, signatures)
    if args.html:
        render_html(args.html, findings, signatures)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\ninterrupted. Made By ammar0xff", "red"))
        sys.exit(130)