# TryHackMe — Carnage (`c2carnage`) Network Forensics Write-Up

## Overview
- **Room**: Carnage ([`c2carnage`](https://tryhackme.com/r/room/c2carnage))
- **Difficulty**: Medium
- **Category**: Digital Forensics & Incident Response (DFIR) / Network Traffic Analysis
- **Artifacts**: `carnage.pcap`
- **Scenario**: An employee was tricked by a targeted phishing lure, leading to malicious document downloads and post-compromise command-and-control (C2) activity. Our objective is to dissect the packet capture (`carnage.pcap`), identify the initial access payload, uncover HTTP redirect chains and external IP lookups, isolate Cobalt Strike C2 beacons, and map out the adversary infrastructure.

---

## Summary of Answers

| Task | Question | Answer |
|---|---|---|
| **2.1** | What was the date and time for the first HTTP connection to the malicious IP? | `2021-09-24 16:44:38` |
| **2.2** | What is the name of the zip file that was downloaded? | `documents.zip` |
| **2.3** | What was the domain hosting the malicious zip file? | `attirenepal.com` |
| **2.4** | Without downloading the file, what is the name of the file in the zip file? | `chart-1530076591.xls` |
| **2.5** | What is the name of the webserver of the malicious IP from which the zip file was downloaded? | `LiteSpeed` |
| **2.6** | What is the version of the webserver from the previous question? | `PHP/7.2.34` |
| **2.7** | What was the domain queried to detect the external IP address? | `api.ipify.org` |
| **2.8** | What was the date and time of the DNS query for external IP detection? | `2021-09-24 16:45:22` |
| **2.9** | What are the two IP addresses of the Cobalt Strike servers? | `185.106.96.158, 185.125.204.174` |
| **2.10**| What is the Host header for the first Cobalt Strike IP (`185.106.96.158`)? | `ocsp.verisign.com` |
| **2.11**| What is the domain name associated with the first Cobalt Strike IP? | `survmeter.live` |
| **2.12**| What is the domain name of the second Cobalt Strike server (`185.125.204.174`)? | `securitybusinpuff.com` |

---

## Step-by-Step Investigation Walkthrough

### Phase 1: Initial Payload Drop & HTTP Analysis

1. **Configure Timestamp Display**:
   In Wireshark, set timestamps to UTC:
   `View` &rarr; `Time Display Format` &rarr; `UTC Date and Time of Day`.

2. **Filter HTTP Traffic**:
   ```wireshark
   http.request.method == "GET"
   ```
   The first packet at `2021-09-24 16:44:38 UTC` targets:
   - **Host**: `attirenepal.com`
   - **Request URI**: `/incidunt-consequatur/documents.zip`

3. **Carve Archive Metadata from TCP Stream**:
   Right-click packet &rarr; `Follow` &rarr; `TCP Stream`.
   - Inspect the server response headers:
     - `Server: LiteSpeed`
     - `X-Powered-By: PHP/7.2.34`
   - Inspect the PK zip header payload bytes:
     The archive records `chart-1530076591.xls` (a malicious Excel macro document).

---

### Phase 2: External IP Discovery & Post-Exploitation Beacons

1. **External IP Detection**:
   Adversaries frequently query public IP lookup services to verify egress connectivity.
   Filter for DNS requests:
   ```wireshark
   dns.qry.name contains "ipify"
   ```
   At `2021-09-24 16:45:22 UTC`, the infected machine queries `api.ipify.org` over DNS and subsequently connects via HTTPS to discover its public facing address.

2. **Isolating Cobalt Strike C2 Beacons**:
   Filter for high-frequency periodic HTTP traffic with suspicious Host headers:
   ```wireshark
   http.request and not http.host contains "attirenepal"
   ```
   - Target IP 1: `185.106.96.158`
     - Uses Host header: `ocsp.verisign.com` (Cobalt Strike malleable C2 profile spoofing OCSP validation)
     - Associated domain: `survmeter.live`
   - Target IP 2: `185.125.204.174`
     - Associated domain: `securitybusinpuff.com`
