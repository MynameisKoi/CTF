# TryHackMe — Warzone 1 (`warzoneone`) Write-Up

## Overview
- **Room**: Warzone 1 (`warzoneone`)
- **Artifact**: `Zone1.pcap`
- **Scenario**: You received an IDS/IPS alert during your SOC shift. Triage the network capture (`Zone1.pcap`) using Brim/Suricata, Wireshark/`tshark`, and VirusTotal OSINT to reconstruct the multi-stage attack chain and determine that the alert is a true positive.

---

## Summary of Answers

| # | Question | Answer |
|---|---|---|
| **1** | What was the alert signature for Malware Command and Control Activity Detected? | `ET MALWARE MirrorBlast CnC Activity M3` |
| **2** | What is the source IP address? Enter your answer in a defanged format. | `172[.]16[.]1[.]102` |
| **3** | What IP address was the destination IP in the alert? Enter your answer in a defanged format. | `169[.]239[.]128[.]11` |
| **4** | Still in VirusTotal, under Community, what threat group is attributed to this IP address? | `TA505` |
| **5** | What is the malware family? | `MirrorBlast` |
| **6** | Do a search in VirusTotal for the domain from question 4. What was the majority file type listed under Communicating Files? | `Windows Installer` |
| **7** | Inspect the web traffic for the flagged IP address; what is the user-agent in the traffic? | `REBOL View 2.7.8.3.1` |
| **8** | Retrace the attack; there were multiple IP addresses associated with this attack. What were two other IP addresses? Enter the IP addressed defanged and in numerical order. | `185[.]10[.]68[.]235,192[.]36[.]27[.]92` |
| **9** | What were the file names of the downloaded files? Enter the answer in the order to the IP addresses from the previous question. | `filter.msi,10opd3r_load.msi` |
| **10** | Inspect the traffic for the first downloaded file from the previous question. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? | `C:\ProgramData\001\arab.bin,C:\ProgramData\001\arab.exe` |
| **11** | Now do the same and inspect the traffic from the second downloaded file. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? | `C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb` |

---

## Detailed Step-by-Step Analysis

### 1. Alert Triage: Signature, Source IP, and Destination IP (Questions 1–3)

#### Using Brim / Suricata
When loading `Zone1.pcap` into **Brim** (or running Suricata against the PCAP) and querying Suricata alerts by category:
```zq
event_type=="alert" | count() by alert.signature, alert.category
```
Looking under the category **`Malware Command and Control Activity Detected`**, we find the Emerging Threats signature triggered by the C2 beacon traffic:
- **Alert Signature**: `ET MALWARE MirrorBlast CnC Activity M3`
- **Source IP**: `172.16.1.102` (Defanged: `172[.]16[.]1[.]102`)
- **Destination IP**: `169.239.128.11` (Defanged: `169[.]239[.]128[.]11`)

#### Verifying with `tshark`
We can list all HTTP requests in `Zone1.pcap` using `tshark`:
```bash
tshark -r Zone1.pcap -Y "http.request" -T fields \
  -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri -e http.user_agent
```
Output excerpt:
```text
552   172.16.1.102  185.10.68.235   185.10.68.235   GET  /                  Windows Installer
767   172.16.1.102  185.183.96.147  185.183.96.147  GET  /?data=STOCKIT...  Mozilla/4.0 ...
774   172.16.1.102  192.36.27.92    192.36.27.92    GET  /10opd3r_load.msi  Windows Installer
1479  172.16.1.102  169.239.128.11  fidufagios.com  GET  /r?x=bmFtZT1TV...  REBOL View 2.7.8.3.1
```

- **Answer 1**: `ET MALWARE MirrorBlast CnC Activity M3`
- **Answer 2**: `172[.]16[.]1[.]102`
- **Answer 3**: `169[.]239[.]128[.]11`

---

### 2. Threat Intelligence & VirusTotal OSINT (Questions 4–6)

1. Search the destination IP `169.239.128.11` on **VirusTotal** and navigate to the **Community** tab.
   - Community threat intelligence reports link `169.239.128.11` (and its associated domain `fidufagios.com`) to a campaign attributed to the threat actor group **`TA505`**.
   - Both the Suricata signature (`ET MALWARE MirrorBlast CnC Activity M3`) and the community comments identify the malware family as **`MirrorBlast`**.
2. Search the associated domain discovered in the Community comments / HTTP `Host` header (`fidufagios.com` or related TA505 MirrorBlast staging domains) in VirusTotal and inspect the **Relations -> Communicating Files** section.
   - The majority of communicating files interacting with the infrastructure are **`.msi` (`Windows Installer`)** packages.

- **Answer 4**: `TA505`
- **Answer 5**: `MirrorBlast`
- **Answer 6**: `Windows Installer`

---

### 3. Inspecting C2 Web Traffic (Question 7)

Filtering for HTTP traffic to the flagged C2 IP (`ip.addr == 169.239.128.11 && http`):
```bash
tshark -r Zone1.pcap -Y "ip.dst == 169.239.128.11 and http.request" -T fields -e http.host -e http.request.uri -e http.user_agent | head -n 5
```
Output:
```text
fidufagios.com  /r?x=bmFtZT1TVE9DS0lURk9SVVNcZHdpZ2h0Lm1vcmFsZXMmb3M9MTAuMCZhcmNoPXg4NiZidWlsZD0xLjAuMg==  REBOL View 2.7.8.3.1
fidufagios.com  /m?x=dXVpZD1mMzI3YjViNy02NWVhLTRmNTctYjMyMy1hMjc4ZjE2MzdmYjg=                               REBOL View 2.7.8.3.1
fidufagios.com  /p?x=dXVpZD1mMzI3YjViNy02NWVhLTRmNTctYjMyMy1hMjc4ZjE2MzdmYjg=                               REBOL View 2.7.8.3.1
```
Decoding the Base64 query parameter in `/r?x=...`:
- `bmFtZT1TVE9DS0lURk9SVVNcZHdpZ2h0Lm1vcmFsZXMmb3M9MTAuMCZhcmNoPXg4NiZidWlsZD0xLjAuMg==` -> `name=STOCKITFORUS\dwight.morales&os=10.0&arch=x86&build=1.0.2`
- `dXVpZD1mMzI3YjViNy02NWVhLTRmNTctYjMyMy1hMjc4ZjE2MzdmYjg=` -> `uuid=f327b5b7-65ea-4f57-b323-a278f1637fb8`

The `User-Agent` header in all C2 requests is **`REBOL View 2.7.8.3.1`**.

- **Answer 7**: `REBOL View 2.7.8.3.1`

---

### 4. Retracing the Attack Chain & Downloaded Payloads (Questions 8–9)

Looking back at the HTTP requests prior to the C2 beacons, the victim (`172.16.1.102`) made two `Windows Installer` (`application/x-msi`) HTTP requests to two distinct IP addresses:

```bash
tshark -r Zone1.pcap -Y "http.user_agent == \"Windows Installer\" or http.content_type == \"application/x-msi\"" \
  -T fields -e tcp.stream -e ip.src -e ip.dst -e http.request.uri -e http.response.line
```

1. **TCP Stream 14 (`185.10.68.235`)**:
   - Request: `GET / HTTP/1.1` (`Host: 185.10.68.235`, `User-Agent: Windows Installer`)
   - Response Header: `Content-Disposition: attachment; filename=filter.msi` (`Content-Type: application/x-msi`, `188416` bytes)
2. **TCP Stream 17 (`192.36.27.92`)**:
   - Request: `GET /10opd3r_load.msi HTTP/1.1` (`Host: 192.36.27.92`, `User-Agent: Windows Installer`)
   - Response Header: `Content-Type: application/x-msi` (`561152` bytes)

Placing the two IP addresses in numerical order and defanging them:
- First IP: `185[.]10[.]68[.]235` -> File: `filter.msi`
- Second IP: `192[.]36[.]27[.]92` -> File: `10opd3r_load.msi`

- **Answer 8**: `185[.]10[.]68[.]235,192[.]36[.]27[.]92`
- **Answer 9**: `filter.msi,10opd3r_load.msi`

---

### 5. Inspecting Dropped Files in `filter.msi` and `10opd3r_load.msi` (Questions 10–11)

Exporting the HTTP objects from `Zone1.pcap` using `tshark`:
```bash
mkdir -p exported_http
tshark -r Zone1.pcap --export-objects http,exported_http
```
This exports:
- `exported_http/%2f` (`filter.msi`, 188,416 bytes)
- `exported_http/10opd3r_load.msi` (`10opd3r_load.msi`, 561,152 bytes)

#### Question 10: First Downloaded File (`filter.msi`)
Inspecting the strings at the end of `filter.msi` (or following the TCP stream in Wireshark):
```bash
strings -n 5 exported_http/%2f | tail -n 15
```
Relevant MSI metadata strings:
```text
Component.CommonAppDataFolder{DEA88988-9EB8-4997-B469-14BBA2A13D95}CommonAppDataFolder
Component.INSTALLDIR{DEA88988-9EB8-4997-B469-14BB177F6F37}INSTALLDIR
Component.arab.bin{DEA88988-9EB8-4997-B469-14BB85EDB3C2}arab.bin
Component.arab.exe{DEA88988-9EB8-4997-B469-14BBE3B5B3B3}arab.exe
Action1_arab.exe
C:\ProgramData\001\arab.bin
001
WKIX32_WKIX32
```
Checking the embedded cabinet (`_645645_.cab`) with `7z l exported_http/%2f` confirms it contains `arab.bin` (a tokenized KiXtart script) and `arab.exe` (`WKIX32.EXE`, the KiXtart interpreter), which are extracted to `C:\ProgramData\001\`.

- **Answer 10**: `C:\ProgramData\001\arab.bin,C:\ProgramData\001\arab.exe`

#### Question 11: Second Downloaded File (`10opd3r_load.msi`)
Inspecting the strings at the end of `10opd3r_load.msi`:
```bash
strings -n 5 exported_http/10opd3r_load.msi | tail -n 15
```
Relevant MSI metadata and Run key strings:
```text
Component.CommonAppDataFolder{7DAD0B07-2406-4203-AE21-B3164EF4C02F}CommonAppDataFolder
Component.Local{7DAD0B07-2406-4203-AE21-B316AC8C445A}CommonAppDataFolder.Local
Component.INSTALLDIR{7DAD0B07-2406-4203-AE21-B316C3D2F2D1}INSTALLDIR
Component.exemple.rb{7DAD0B07-2406-4203-AE21-B3165A3BDAD7}exemple.rb
Component.rebol_view_278_3_1.exe{7DAD0B07-2406-4203-AE21-B316DBE7EA0A}rebol_view_278_3_1.exe
Action1_rebol_view_278_3_1.exe-w -i -s C:/ProgramData/Local/Google/exemple.rb
Package38yhbxk2.exe|rebol-view-278-3-1.exe
RegValueSoftware\Microsoft\Windows\CurrentVersion\RunGoogle  Chrome
C:\ProgramData\Local\Google\rebol-view-278-3-1.exe -w -i -s C:\ProgramData\Local\Google\exemple.rb
```
The second MSI drops **`C:\ProgramData\Local\Google\rebol-view-278-3-1.exe`** and the malicious REBOL C2 script **`C:\ProgramData\Local\Google\exemple.rb`**, and establishes persistence via `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`.

- **Answer 11**: `C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb`

---

## Automated Solver
Run [`solve.py`](./solve.py) to automatically parse `Zone1.pcap` and output all 11 answers:
```bash
python3 solve.py
```
