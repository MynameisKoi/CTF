# Reconstructing Enterprise Breaches in Google SecOps: Solving All 18 Challenges in Operation Cymbal: Cold Room CTF

*How our team achieved a 100% clear (18/18) in Google Cloud Security × Hack The Box’s premiere enterprise threat-hunting competition.*

---

## Introduction: The "Cold Room"

In late October 2026, **Google Cloud Security** partnered with **Hack The Box** to host **Operation Cymbal: Cold Room**, an intense 72-hour threat-hunting and digital forensics competition.

The premise was straight out of an incident responder's playbook:
> *Cymbal Investments collapsed following three seemingly unrelated security breaches. Its entire digital environment has been frozen and sealed inside a forensic "Cold Room." As reconstructors operating in Google Security Operations (Google SecOps / Chronicle SIEM), our goal was to comb through raw telemetry, disentangle concurrent attacker activities, and piece together the end-to-end intrusion kill chains before rival investigators beat us to the truth.*

Competing under the handle **Khoi Duong** with team **BoizAllVuln**, we achieved a **100% completion rate, solving all 18 challenges across all 3 breach tracks (2,075 points)**, finishing **458th out of 1,716 teams worldwide**.

In this article, I will break down the investigation methodology, the Unified Data Model (UDM) queries used in Chronicle SIEM, and the anatomy of the three concurrent attacks—from classic drive-by malware to cutting-edge AI-enabled payloads querying the Google Gemini API mid-execution.

---

## The Investigation Engine: Google SecOps (Chronicle SIEM)

Modern security operations centers (SOCs) drown in telemetry. Sifting through billions of daily events across endpoint sensors (Sysmon), cloud proxies (Zscaler), identity providers (Okta), SaaS audit logs (Google Workspace), and cloud control planes (GCP) requires unified normalization.

Chronicle SIEM achieves this through its **Unified Data Model (UDM)**. Rather than writing brittle regex against disparate log formats, analysts query semantic fields such as:
- `principal.user.userid`: The acting identity.
- `target.process.command_line`: Exact command-line strings.
- `target.file.full_path`: File creation, modification, and access paths.
- `target.url`: Full HTTP/HTTPS request URIs.

This schema allowed us to pivot seamlessly from network proxies to endpoint execution and cloud audit logs in fractions of a second.

---

## Breach Track 1: Deceptive Click (SocGholish / FAKEUPDATES)

### 1. The Incident Narrative
The first investigation involved an initial compromise on a corporate endpoint in Cymbal's Denver office (`CYM-DEN-W10-042.cymbal.corp`). The user fell victim to **FAKEUPDATES** (also known as **SocGholish**), a prevalent malware framework that infects legitimate content management systems (WordPress) and displays deceptive browser-update lures.

### 2. Forensic Pivot & Findings
1. **Initial Vector**: Examining proxy logs revealed a compromised blog referer (`marketingtrends-insider.com`) delivering obfuscated JavaScript lures to employee Marcus Vance (`10.240.32.115`).
2. **Process Injection**: Upon downloading the fake update payload, the script executed a secondary executable (`d27e15eb.exe`) which performed process hollowing into a legitimate Windows `svchost.exe` process (Target Process ID: `624`).
3. **Internal Reconnaissance & Kerberoasting**: From the hollowed process, the attacker queried Active Directory and executed a Kerberoasting attack against Domain Controller `CYM-DC-01`, requesting a service ticket (TGS) for:
   ```text
   MSSQLSvc/CYM-DB-01.cymbal.corp:1433
   ```
4. **Lateral Movement & Staging**: Using the compromised service credentials (`svc_backup`), the adversary moved laterally to the database server and staged corporate financial data into an archive named:
   ```text
   Financial_Audit_2026.zip
   ```

---

## Breach Track 2: OAuth Heist (ShinyHunters / UNC6240 Cloud Extortion)

### 1. The Incident Narrative
The second breach tracked an extortion campaign attributed to threat group **UNC6240** (associated with the **ShinyHunters** brand). Rather than relying on traditional malware, this actor exploited modern cloud identity vectors: credential phishing, OAuth grant abuse, and SaaS inbox manipulation.

### 2. Forensic Pivot & Findings
1. **Phishing & MFA Tampering**: The adversary deployed a reverse-proxy phishing portal hosted at `sso-cymbal-portal.com` to capture Okta credentials and bypass MFA prompts.
2. **Inbox Blindfolding via Malicious OAuth**: To prevent the employee from noticing security alerts, the attacker authorized a malicious Google Workspace OAuth application named *ToggleBox Recall*. The app immediately accessed the victim’s Gmail inbox via API and permanently deleted the critical alert:
   ```text
   "Okta: A new MFA factor was added"
   ```
3. **Internal Architecture Theft**: Browsing Google Drive via the compromised account, the adversary located and downloaded:
   ```text
   Cymbal_Q3_Database_Architecture_and_Service_Accounts.pdf
   ```
4. **Database Dumping & High-Speed Exfiltration**: Armed with plaintext credentials from the PDF, the attacker authenticated to the database server as `svc_dbadmin`, exported a raw SQL dump:
   ```text
   cymbal_cust_q3.bak
   ```
   The dump was compressed using `zstd` into `cymbal_q3_exfil.tar.zst` and exfiltrated via HTTP POST to the attacker's drop server:
   ```text
   http://142.11.200.188:8888/upload/cymbal_q3_exfil.tar.zst
   ```

---

## Breach Track 3: Rogue Synthesis (AI Threat — PROMPTFLUX)

### 1. The Incident Narrative
The third and most technically fascinating track investigated an intrusion incorporating threat intelligence from Google's recent **GTIG AI Threat Tracker** report (*"Advances in Threat Actor Usage of AI Tools"*). The attacker deployed an emerging malware family called **PROMPTFLUX**, which abuses generative AI developer APIs at runtime.

### 2. Forensic Pivot & Findings
1. **Developer Lure via Typo-squatted Extension**: Developer `alex.chen` searched the Visual Studio Marketplace for code linters and downloaded a malicious `.vsix` extension package hosted on a typosquatted CDN:
   ```text
   SyntaxOptimizer-2.1.4.vsix
   ```
2. **Just-in-Time AI Payload Synthesis**: Once installed, the extension host (`node.exe`) executed background code that queried the **Google Gemini Developer API**:
   ```http
   https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=AIzaSyD8x9L2M1N4P7Q0R3S6T9U2V5W8X1Y4Z7
   ```
   The model response was logged to `%TEMP%\thinking_robot_log.txt` and dynamically synthesized into a C source file:
   ```text
   C:\Users\alex.chen\AppData\Local\Temp\cache_worker.c
   ```
3. **On-Host Compilation**: Rather than downloading a pre-compiled binary that static signatures could detect, the malware compiled the code locally using MinGW GCC:
   ```cmd
   gcc.exe -O2 C:\Users\alex.chen\AppData\Local\Temp\cache_worker.c -o C:\Users\alex.chen\AppData\Local\Temp\sys_worker.exe
   ```
4. **Cloud SDK Token Harvesting**: Following execution, the staged executable hollowed into system processes and read the local Google Cloud SDK authentication database:
   ```cmd
   cmd.exe /c "type C:\Users\alex.chen\.gcloud\credentials.db"
   ```
5. **Telemetry-Masqueraded Exfiltration**: The harvested cloud tokens were exfiltrated via an outbound HTTP POST request disguised as an application telemetry endpoint:
   ```text
   https://dev-metrics-cdn.com/api/v2/telemetry
   ```
6. **Lateral Pivot & CI/CD Persistence**: Using the stolen service account permissions, the attacker pivoted to a secondary build runner (`BuildRunner`) and backdoored the automated build pipeline by overwriting:
   ```text
   C:\BuildRunner\scripts\build_production.ps1
   ```

---

## Summary Matrix of Challenge Answers

| Track | Challenge Question | Answer / Flag |
| :--- | :--- | :--- |
| **Track 1** | Compromised Endpoint in Denver Office | `CYM-DEN-W10-042.cymbal.corp` |
| **Track 1** | Compromised Blog Referer Domain | `marketingtrends-insider.com` |
| **Track 1** | Injected Target Process ID (`svchost.exe`) | `624` |
| **Track 1** | Kerberoasted Service Principal Name | `MSSQLSvc/CYM-DB-01.cymbal.corp:1433` |
| **Track 1** | Lateral Movement Account Identity | `svc_backup` |
| **Track 1** | Staged Financial Audit Archive Name | `Financial_Audit_2026.zip` |
| **Track 2** | Credential Harvesting Phishing Domain | `sso-cymbal-portal.com` |
| **Track 2** | Permanently Deleted MFA Alert Subject | `Okta: A new MFA factor was added` |
| **Track 2** | Internal Architecture PDF Downloaded | `Cymbal_Q3_Database_Architecture_and_Service_Accounts.pdf` |
| **Track 2** | Privileged Database Account Authenticated | `svc_dbadmin` |
| **Track 2** | Raw Database Dump File Name | `cymbal_cust_q3.bak` |
| **Track 2** | Full Archive Exfiltration URL | `http://142.11.200.188:8888/upload/cymbal_q3_exfil.tar.zst` |
| **Track 3** | Developer Initiating Model Request | `alex.chen` |
| **Track 3** | Malicious Package Downloaded | `SyntaxOptimizer-2.1.4.vsix` |
| **Track 3** | Dropped Compiled Staging Binary | `sys_worker.exe` |
| **Track 3** | Harvested Cloud SDK Token File | `credentials.db` |
| **Track 3** | Masqueraded Exfiltration Domain | `dev-metrics-cdn.com` |
| **Track 3** | Overwritten Persistence PowerShell Script | `build_production.ps1` |

---

## Key Lessons for Modern Blue Teams

1. **Identity is the Perimeter**: Attackers rarely "hack" their way in when they can log in. Tracking OAuth token grants and SaaS inbox modification rules is just as critical as monitoring endpoint process launches.
2. **Prepare for Just-in-Time AI Threats**: As demonstrated by PROMPTFLUX, static hashing and file reputation checks are insufficient against malware that generates source code on demand. SOCs must focus on behavioral telemetry—such as unusual developer toolchain invocations (`gcc` compiling out of `%TEMP%`) and atypical outbound LLM API traffic.
3. **SIEM Normalization Accelerates Response**: During complex multi-vector incidents, being able to pivot instantly between endpoint process trees and cloud authentication logs within a single Unified Data Model is the difference between containing a breach and suffering total enterprise compromise.

---

## Artifacts & GitHub Repository

The complete technical write-ups, PDF metadata extraction scripts, and automated Python solvers for all challenges are published open-source on GitHub:

🔗 **GitHub Repository**: [https://github.com/MynameisKoi/CTF](https://github.com/MynameisKoi/CTF)  
📂 **Operation Cymbal Directory**: [https://github.com/MynameisKoi/CTF/tree/main/Operation%20Cymbal](https://github.com/MynameisKoi/CTF/tree/main/Operation%20Cymbal)

*Happy threat hunting!*
