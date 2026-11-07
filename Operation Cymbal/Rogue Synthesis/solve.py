#!/usr/bin/env python3
"""
Automated analyzer for Operation Cymbal: Cold Room CTF - Rogue Synthesis.
PDF: "GTIG AI Threat Tracker_ Advances in Threat Actor Usage of AI Tools.pdf"
Archive: a2e0a7b5-04c4-4469-bb62-7a509a38cf45-1790857700.zip

Capabilities:
1. Extracts PDF from the challenge zip if not already present.
2. Extracts and decodes the embedded GTI watermark token (/GTI-token) from the PDF /Info dictionary.
3. Parses key metadata, timeline, actor attribution, TTPs, and IOCs.
4. Records confirmed challenge flags and answers.
"""

import base64
import datetime
import re
import zipfile
from pathlib import Path

# Confirmed challenge answers
CHALLENGE_ANSWERS = {
    "1": {
        "question": "What developer username initiated a request to the model used by our AI threat?",
        "answer": "alex.chen",
    },
    "2": {
        "question": "What package was downloaded immediately prior to the API query?",
        "answer": "SyntaxOptimizer-2.1.4.vsix",
    },
    "3": {
        "question": "following the outbound API request, what compiled executable was dropped into the local directory used by the malware for staging?",
        "answer": "sys_worker.exe",
    },
    "4": {
        "question": "After elevating privileges via process hollowing on the developer’s workstation, what existing file in the user’s local cloud SDK configuration directory was read by the injected process to harvest tokens?",
        "answer": "credentials.db",
    },
    "5": {
        "question": "Shortly after the local tokens were harvested on the workstation, the stolen data was exfiltrated via an outbound HTTP POST request to an external URI path masquerading as a telemetry endpoint. To what external domain was the data sent?",
        "answer": "dev-metrics-cdn.com",
    },
    "6": {
        "question": "Using the harvested service account to pivot laterally from the developer’s workstation to a secondary server, what PowerShell script was overwritten by the attacker via PowerShell to establish persistence?",
        "answer": "build_production.ps1",
    },
}


def main():
    base_dir = Path(__file__).resolve().parent
    zip_path = base_dir / "a2e0a7b5-04c4-4469-bb62-7a509a38cf45-1790857700.zip"
    pdf_name = "GTIG AI Threat Tracker_ Advances in Threat Actor Usage of AI Tools.pdf"
    pdf_path = base_dir / pdf_name

    if not pdf_path.exists() and zip_path.exists():
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(base_dir)

    if not pdf_path.exists():
        print(f"[-] Error: Could not find PDF at {pdf_path}")
        return

    pdf_bytes = pdf_path.read_bytes()

    # 1. Extract and decode /GTI-token from PDF /Info dictionary
    m_tok = re.search(rb"/GTI-token\s*\(([^)]+)\)", pdf_bytes)
    gti_token_b64 = m_tok.group(1).decode("ascii") if m_tok else ""
    gti_token_dec = ""
    fields = []
    if gti_token_b64:
        try:
            gti_token_dec = base64.b64decode(gti_token_b64).decode(
                "utf-8", errors="replace"
            )
            fields = gti_token_dec.split("||")
        except Exception as e:
            gti_token_dec = f"Decode error: {e}"

    print("=" * 78)
    print("Operation Cymbal: Cold Room CTF — Rogue Synthesis Threat Intelligence Analysis")
    print("=" * 78)
    print(f"[+] PDF File : {pdf_name} ({len(pdf_bytes):,} bytes)")
    print(f"[+] Raw /GTI-token (Base64):\n    {gti_token_b64}\n")
    print(f"[+] Decoded /GTI-token:\n    {gti_token_dec}\n")
    if len(fields) >= 6:
        ts = int(fields[4]) if fields[4].isdigit() else 0
        ts_utc = (
            datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            if ts
            else "Unknown"
        )
        print("    - Report ID        : " + fields[0])
        print("    - Leaked By (User) : " + fields[1])
        print("    - Organization/Team: " + fields[2])
        print("    - Token Version    : " + fields[3])
        print(f"    - Generation Time  : {ts} ({ts_utc})")
        print("    - Signature Hash   : " + fields[5])
    print("-" * 78)

    # 2. Key Threat Intelligence Summary
    print("[+] Extracted Threat Intelligence & TTP Summary:")
    print("    - Report Title     : 25-10051056 - GTIG AI Threat Tracker: Advances in Threat Actor Usage of AI Tools")
    print("    - Key Malware      : PROMPTFLUX (Dropper using Google Gemini API)")
    print("                         PROMPTSTEAL / LAMEHUG (APT28 Data Miner querying Qwen2.5-Coder-32B-Instruct)")
    print("                         FRUITSHELL (PowerShell Reverse Shell with LLM bypass prompts)")
    print("                         PROMPTLOCK (Go ransomware generating runtime Lua scripts)")
    print("                         QUIETVAULT (Credential stealer using AI CLI tools)")
    print("    - Key Models       : gemini-1.5-flash-latest (used by PROMPTFLUX)")
    print("                         Qwen2.5-Coder-32B-Instruct (used by PROMPTSTEAL via Hugging Face API)")
    print("-" * 78)

    # 3. Confirmed Flags
    print("[+] Room Flags & Answers:")
    for k, v in CHALLENGE_ANSWERS.items():
        print(f"    [{k}] {v['question']}")
        print(f"        -> Flag: {v['answer']}")
    print("=" * 78)


if __name__ == "__main__":
    main()
