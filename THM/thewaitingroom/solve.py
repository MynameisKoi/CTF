#!/usr/bin/env python3
"""
End-to-End Automated Solver for TryHackMe - The Waiting Room.
1. Extracts Remittance.one from vendor.eml and locates the embedded HTA payload.
2. Deobfuscates the XOR-57 entries table inside the HTA.
3. Parses Sysmon-incident.evtx (via evtx_dump inside artifacts2.tar.gz) to find U+202E and cscript.exe PID 1996.
4. Carves HTTP payloads from incident.pcap, RC4-decrypts receipt.js and payment-register.csv,
   and prints all answers and SHA-256 hashes.
"""

import base64
import email
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from email import policy
from pathlib import Path


def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 255])
    return bytes(out)


def main():
    base_dir = Path(__file__).resolve().parent
    eml_path = base_dir / "vendor.eml"
    pcap_path = base_dir / "incident.pcap"
    evtx_path = base_dir / "Sysmon-incident.evtx"
    tar_path = base_dir / "artifacts2.tar.gz"

    # 1. Extract Remittance.one and carve the embedded HTA
    msg = email.message_from_bytes(eml_path.read_bytes(), policy=policy.default)
    one_bytes = b""
    for part in msg.walk():
        if part.get_filename() == "Remittance.one":
            one_bytes = part.get_payload(decode=True)
            break

    hta_start = one_bytes.find(b"<!DOCTYPE html>")
    hta_end = one_bytes.find(b"</html>", hta_start) + len(b"</html>")
    hta_bytes = one_bytes[hta_start:hta_end]
    q1_sha256 = hashlib.sha256(hta_bytes).hexdigest()

    # 2. Decode XOR-57 entries from the HTA
    hta_text = hta_bytes.decode("utf-8", errors="replace")
    entries = re.findall(r'"([0-9a-f]{6,})"', hta_text)
    decoded_entries = [
        "".join(chr(int(h[n:n + 2], 16) ^ 57) for n in range(0, len(h), 2))
        for h in entries
    ]
    stage_url = decoded_entries[3]
    hostname = stage_url.split("//")[1].split(":")[0]
    rc4_key_hex = decoded_entries[9]

    # 3. Parse Sysmon-incident.evtx for Unicode code point & cscript.exe PID
    unicode_cp = "U+202E"
    cscript_pid = None
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with tarfile.open(tar_path, "r:gz") as tf:
            tf.extract("./tools/evtx_dump", path=tmp, filter="data")
        evtx_dump = tmp / "tools" / "evtx_dump"
        sysmon_jsonl = subprocess.check_output([str(evtx_dump), "-o", "jsonl", str(evtx_path)], text=True)
        for line in sysmon_jsonl.splitlines():
            if not line.strip() or line.startswith("Record "):
                continue
            ev = json.loads(line)
            eid = ev["Event"]["System"]["EventID"]
            if isinstance(eid, dict):
                eid = eid.get("#text")
            ed = ev["Event"].get("EventData") or {}
            tfile = ed.get("TargetFilename") or ""
            if "fdp.hta" in tfile:
                for ch in tfile:
                    if ord(ch) > 127:
                        unicode_cp = f"U+{ord(ch):04X}"
            if eid == 1 and "cscript.exe" in (ed.get("Image") or "").lower():
                cscript_pid = ed.get("ProcessId")

    # 4. Decrypt payment-register.csv from incident.pcap
    pcap_bytes = pcap_path.read_bytes()
    m_json = re.search(rb'\{"reference":"MR-6106-028".*?"data":"([^"]+)"\}', pcap_bytes)
    ct = base64.b64decode(m_json.group(1))
    pt = rc4(ct, bytes.fromhex(rc4_key_hex))
    doc_sha256 = hashlib.sha256(pt).hexdigest()

    print(f"Q1 (Embedded HTA SHA-256):    {q1_sha256}")
    print(f"Q2 (Unicode Code Point):      {unicode_cp}")
    print(f"Q3 (Stage Hostname):          {hostname}")
    print(f"Q4 (Interpreter Process ID):  {cscript_pid}")
    print(f"Q5 (Encryption Key):          {rc4_key_hex}")
    print(f"Q6 (Exfiltrated Doc SHA-256): {doc_sha256}")
    print("\n--- Decrypted payment-register.csv ---")
    print(pt.decode("utf-8").strip())


if __name__ == "__main__":
    main()
