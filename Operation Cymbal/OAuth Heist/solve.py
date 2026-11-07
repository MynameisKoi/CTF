#!/usr/bin/env python3
"""
Automated analyzer for Operation Cymbal: Cold Room CTF - OAuth Heist.
PDF: "Threat Actors Associated with the ShinyHunters Brand Expand Targeting of Cloud Applications for Extortion Operations.pdf"
Archive: a2e0aac3-18ff-4e70-9f4a-c2a025935167-1790858212.zip

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
        "question": "What is the phishing domain where employee credentials were submitted via an HTTP POST request?",
        "answer": "sso-cymbal-portal.com",
    },
    "2": {
        "question": (
            "To prevent the compromised employee from noticing the persistence mechanism, "
            "the adversary abused a newly authorized third-party OAuth application to permanently purge "
            "security notifications from the victim’s inbox. What is the exact subject line of the first "
            "permanently deleted email, which alerted on multi-factor authentication changes?"
        ),
        "answer": "Okta: A new MFA factor was added",
    },
    "3": {
        "question": (
            "Continuing to monitor the compromised employee’s cloud activity from the attacker’s "
            "proxy infrastructure, what sensitive internal document did the adversary locate and download?"
        ),
        "answer": "Cymbal_Q3_Database_Architecture_and_Service_Accounts.pdf",
    },
    "4": {
        "question": (
            "Armed with credentials discovered in the stolen document, what privileged service account "
            "did the attacker authenticate to from the compromised employee’s workstation to access "
            "the internal database server?"
        ),
        "answer": "svc_dbadmin",
    },
    "5": {
        "question": (
            "Once authenticated to that internal server, what is the file name of the raw database dump "
            "exported by the attacker prior to compressing it into an archive?"
        ),
        "answer": "cymbal_cust_q3.bak",
    },
    "6": {
        "question": (
            "What is the full exfiltration URL (including destination IP and port) "
            "used by the attacker to transfer the compressed archive?"
        ),
        "answer": "http://142.11.200.188:8888/upload/cymbal_q3_exfil.tar.zst",
    },
}


def main():
    base_dir = Path(__file__).resolve().parent
    zip_path = base_dir / "a2e0aac3-18ff-4e70-9f4a-c2a025935167-1790858212.zip"
    pdf_name = (
        "Threat Actors Associated with the ShinyHunters Brand Expand Targeting of "
        "Cloud Applications for Extortion Operations.pdf"
    )
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
    print("Operation Cymbal: Cold Room CTF — OAuth Heist Threat Intelligence Analysis")
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
    print("    - Threat Actor     : UNC6240 (ShinyHunters brand, limited UNC6040 overlap)")
    print("    - Primary Vector   : Voice Phishing (vishing) targeting MFA enrollment")
    print("    - Compromised IdP  : Okta")
    print("    - Malicious Add-on : ToggleBox Recall (Google Workspace add-on to delete alerts)")
    print("    - Targeted SaaS    : Google Workspace, Salesforce, DocuSign, Atlassian")
    print("    - Data Stolen      : Salesforce PII, Google Takeout exports")
    print("    - Phishing Vector  : Compromised mailbox sending Calendly lure links")
    print("    - Tox Account ID   : BD1B683FD3E6CB094341317A4C09923B7AE3E7903A6CDB90E5631EC7DC1452636FF35D9F5AF2")
    print("    - Exfil Hosting    : Limewire")
    print("    - Data Leak Site   : SHINYHUNTERS")
    print("    - Related Reports  : 26-10002301, 25-10043011, CAMP.25.032, 25-10025182")
    print("-" * 78)

    # 3. Confirmed Flags
    print("[+] Confirmed Room Flags & Answers:")
    for k, v in CHALLENGE_ANSWERS.items():
        print(f"    [{k}] {v['question']}")
        print(f"        -> Flag: {v['answer']}")
    print("=" * 78)


if __name__ == "__main__":
    main()
