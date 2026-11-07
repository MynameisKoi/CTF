#!/usr/bin/env python3
"""
Automated solver for TryHackMe - Handbook for the Recently Compromised.
Extracts artifacts.tar.gz, converts .evtx logs using the bundled evtx_dump tool,
reconstructs the intrusion timeline, and decodes the Base64 flag.
"""

import base64
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path


def main():
    base_dir = Path(__file__).resolve().parent
    tar_path = base_dir / "artifacts.tar.gz"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with tarfile.open(tar_path, "r:gz") as tf:
            tf.extractall(tmp, filter="data")

        evtx_dump = tmp / "artifacts" / "tools" / "evtx_dump"
        sysmon_evtx = tmp / "artifacts" / "Microsoft-Windows-Sysmon%4Operational.evtx"
        ps_evtx = tmp / "artifacts" / "PowerShell-Operational.evtx"

        sysmon_out = subprocess.check_output([str(evtx_dump), "-o", "jsonl", str(sysmon_evtx)], text=True)
        ps_out = subprocess.check_output([str(evtx_dump), "-o", "jsonl", str(ps_evtx)], text=True)

        print("=== INTRUSION PROCESS TIMELINE (SYSMON EID 1) ===")
        for line in sysmon_out.splitlines():
            if not line.strip() or line.startswith("Record "):
                continue
            ev = json.loads(line)
            eid = ev["Event"]["System"]["EventID"]
            if isinstance(eid, dict):
                eid = eid.get("#text")
            ed = ev["Event"].get("EventData") or {}
            cmd = ed.get("CommandLine", "")
            if eid == 1 and any(k in cmd.lower() for k in ("mshta", "certu", "pipeline-sync", "schtasks")):
                ts = ev["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"]
                print(f"[{ts}] {ed.get('Image')}\n  Cmd: {cmd}")

        print("\n=== POWERSHELL SCRIPT BLOCK (EID 4104) & FLAG ===")
        for line in ps_out.splitlines():
            if not line.strip() or line.startswith("Record "):
                continue
            ev = json.loads(line)
            ed = ev["Event"].get("EventData") or {}
            sb = ed.get("ScriptBlockText") or ""
            if "$blob" in sb:
                print(sb.strip())
                blob_line = [l for l in sb.splitlines() if "$blob" in l][0]
                parts = re.findall(r"'([^']+)'", blob_line)
                b64_str = "".join(parts)
                flag = base64.b64decode(b64_str).decode("utf-8")
                print(f"\n[+] Concatenated Base64: {b64_str}")
                print(f"[+] Decoded Flag:        {flag}")


if __name__ == "__main__":
    main()
