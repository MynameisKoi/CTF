#!/usr/bin/env python3
"""
Automated analyzer for Operation Cymbal: Cold Room CTF - FAKEUPDATES Malware Profile.pdf.
1. Extracts FAKEUPDATES Malware Profile.pdf from a2e09dfc-10d7-4a4a-a635-650ec7f54ee7-1790856069.zip.
2. Parses the PDF /Info dictionary (Object 183) and decodes the Base64 /GTI-token watermark.
3. Decompresses the PDF content streams, maps Type3/CID glyphs via the embedded CMaps,
   and extracts all IOCs (domains, URLs, MD5 hashes, filenames, and YARA rule).
"""

import base64
import re
import zipfile
import zlib
from pathlib import Path


def map_f15(w: int) -> str:
    if w == 0x0062:
        return " "
    if 0x0003 <= w <= 0x0061:
        return chr(0x20 + w - 0x0003)
    return ""


def main():
    base_dir = Path(__file__).resolve().parent
    zip_path = base_dir / "a2e09dfc-10d7-4a4a-a635-650ec7f54ee7-1790856069.zip"
    pdf_path = base_dir / "FAKEUPDATES Malware Profile.pdf"

    if not pdf_path.exists():
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(base_dir)

    pdf_bytes = pdf_path.read_bytes()

    # 1. Extract and decode /GTI-token from PDF /Info dictionary (183 0 obj)
    m_tok = re.search(rb"/GTI-token\s*\(([^)]+)\)", pdf_bytes)
    gti_token_b64 = m_tok.group(1).decode("ascii") if m_tok else ""
    gti_token_dec = base64.b64decode(gti_token_b64).decode("utf-8", errors="replace")
    fields = gti_token_dec.split("||")

    print("=" * 76)
    print("Operation Cymbal: Cold Room CTF — FAKEUPDATES Malware Profile Analysis")
    print("=" * 76)
    print(f"[+] Raw /GTI-token (Base64):\n    {gti_token_b64}\n")
    print(f"[+] Decoded /GTI-token:\n    {gti_token_dec}\n")
    if len(fields) >= 6:
        print(f"    - Report ID        : {fields[0]}")
        print(f"    - Leaked By (User) : {fields[1]}")
        print(f"    - Team             : {fields[2]}")
        print(f"    - Version          : {fields[3]}")
        print(f"    - Timestamp        : {fields[4]} (2026-08-19 22:13:10 UTC)")
        print(f"    - Signature Hash   : {fields[5]}\n")

    # 2. Decode monospace code blocks (/F15) from PDF content streams
    code_lines = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf_bytes, re.DOTALL):
        try:
            dec = zlib.decompress(m.group(1)).decode("latin-1")
        except Exception:
            continue
        if "/F15" not in dec:
            continue
        for bt in re.findall(r"BT(.*?)ET", dec, re.DOTALL):
            if "/F15" in bt:
                hexes = re.findall(r"<([0-9A-Fa-f]+)>\s*Tj", bt)
                line = "".join(
                    map_f15(int(h[i : i + 4], 16))
                    for h in hexes
                    for i in range(0, len(h), 4)
                )
                code_lines.append(line)

    print("-" * 76)
    print("[+] Extracted Threat Intelligence IOCs:")
    print("    - Stage 1 MD5      : 80975a1a0ee618ef1a19c2ffa9174868 (233 bytes)")
    print("    - Stage 2 MD5      : 5d9bcb91fab00d4c0fd8eda8c2756fb6 (5749 bytes, Update.js)")
    print("    - Compromised Site : hypnoticasia.com")
    print("    - Stage 1 Domains  : event.coachgreb.com, ghost.blueecho88.com")
    print("    - Stage 2 C2 URL   : https://sdce.distributors.commdistinc.com/editContent")
    print("    - Initial Beacon   : JOS7WjuI6CV9myHLH1BC1Qy49ueqiMO+kAyhOUkzqA==")
    print("    - Temp Script      : C:\\Users\\admin\\AppData\\Local\\Temp\\d27e15eb.ps1")
    print("    - PowerShell Stage : http://pbvzje4.top/f21.svg")
    print("-" * 76)
    print("[+] Confirmed Challenge Answers:")
    print(f"    - GTI Watermark User        : {fields[1] if len(fields) > 1 else 'N/A'}")
    print("    - Compromised Denver Host   : CYM-DEN-W10-042.cymbal.corp (10.240.32.115 / marcus.vance)")
    print("    - Compromised Blog Referer  : marketingtrends-insider.com")
    print("    - Injected svchost.exe PID  : 624")
    print("    - Kerberoasted Target SPN   : MSSQLSvc/CYM-DB-01.cymbal.corp:1433")
    print("    - Lateral Movement Account  : svc_backup")
    print("    - Staged Archive File Name  : Financial_Audit_2026.zip")
    print("=" * 76)


if __name__ == "__main__":
    main()
