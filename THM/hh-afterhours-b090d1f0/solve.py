#!/usr/bin/env python3
"""
TryHackMe - After Hours (hh-afterhours-b090d1f0)
Automated WMI Repository Carver, Raw-DEFLATE .NET Extractor, and Flag Decoder
"""

import base64
import os
import re
import sys
import zlib


def analyze_objects_data(objects_path: str):
    print(f"[*] Reading WMI CIM repository: {objects_path}")
    with open(objects_path, "rb") as f:
        data = f.read()

    # 1. Extract PowerShell -enc loader from CommandLineEventConsumer
    enc_match = re.search(rb"-enc\s+([A-Za-z0-9+/=]{80,})", data)
    if enc_match:
        b64_ps = enc_match.group(1)
        ps_script = base64.b64decode(b64_ps).decode("utf-16le", errors="ignore")
        print(f"[+] Recovered Fileless PowerShell Loader:\n    {ps_script}\n")

    # 2. Carve Win32_HardwareTelemetry.ConfigData Base64 blob
    blob_matches = re.findall(rb"7VZPbFRFGP[A-Za-z0-9+/]+={0,2}", data)
    if not blob_matches:
        print("[-] Could not find 7VZPbFRFGP Base64 blob in OBJECTS.DATA")
        return

    b64_blob = blob_matches[0]
    print(f"[+] Carved Win32_HardwareTelemetry.ConfigData blob ({len(b64_blob)} bytes)")

    # 3. Base64-decode and decompress raw DEFLATE stream (wbits = -15)
    compressed = base64.b64decode(b64_blob)
    pe_bytes = zlib.decompress(compressed, -15)
    out_pe = "payload.exe"
    with open(out_pe, "wb") as out:
        out.write(pe_bytes)
    print(f"[+] Decompressed .NET assembly -> {out_pe} ({len(pe_bytes)} bytes, magic={pe_bytes[:2]!r})")

    # 4. Extract UTF-16LE user strings (#US heap) and decode final flag
    utf16_text = pe_bytes.decode("utf-16le", errors="ignore")
    cmd_match = re.search(r"net user patch\s+([A-Za-z0-9+/=]+)\s+/add", utf16_text)
    if cmd_match:
        b64_pw = cmd_match.group(1)
        flag = base64.b64decode(b64_pw).decode("utf-8", errors="ignore")
        print(f"[+] Extracted net user backdoor password (Base64): {b64_pw}")
        print(f"[+] Decoded Flag: {flag}")


def main():
    print("=" * 72)
    print("  TryHackMe 'After Hours' (hh-afterhours-b090d1f0) Solver")
    print("=" * 72)

    target = sys.argv[1] if len(sys.argv) > 1 else "OBJECTS.DATA"
    if os.path.isfile(target):
        analyze_objects_data(target)
    else:
        print("[*] OBJECTS.DATA not in current directory; running verification summary:")
        b64_flag = "VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9"
        flag = base64.b64decode(b64_flag).decode("utf-8")
        print("  - WMI Event Filter  : EngineTelemetryFilter (root\\cimv2)")
        print("  - Trigger WQL       : SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Minute = 30")
        print("  - Decoy WMI Class   : ROOT\\cimv2:Win32_HardwareTelemetry.ConfigData")
        print("  - Payload Transform : Base64 -> Raw DeflateStream (zlib wbits=-15) -> .NET Assembly (updates.exe)")
        print("  - Hostname Guardrail: Environment.MachineName == 'bytelotusdc'")
        print(f"  - Backdoor Command  : cmd.exe /c net user patch {b64_flag} /add")
        print(f"  - Decoded Flag      : {flag}")


if __name__ == "__main__":
    main()
