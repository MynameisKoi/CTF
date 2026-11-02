# 🎯 100% Cleared: 18/18 in Google Cloud Security × Hack The Box — Operation Cymbal: Cold Room! 🛡️

Over the weekend, I participated in **Operation Cymbal: Cold Room (2026 CTF)**, a premiere cloud security and DFIR competition hosted by **Google Cloud Security** in partnership with **Hack The Box**.

Competing as team **BoizAllVuln**, I am thrilled to share that we achieved a **100% completion rate (18/18 challenges solved, 2,075 points)**, placing **458th out of 1,716 teams worldwide**! 🚀

---

### 🔍 The Scenario
Cymbal Investments collapsed following three seemingly unrelated security breaches, leaving its digital infrastructure sealed in a forensic "Cold Room." Operating as reconstructors in **Google Security Operations (Google SecOps / Chronicle SIEM)**, our mission was to hunt through telemetry, untangle concurrent adversary behaviors, and reconstruct each intrusion lifecycle end-to-end:

1️⃣ **Track 1: Deceptive Click (SocGholish / FAKEUPDATES)**
Investigated a drive-by compromise initiated via a compromised WordPress site delivering malicious fake browser updates. Traced process hollowing into `svchost.exe`, internal Active Directory reconnaissance, Kerberoasting of MSSQL Service Principal Names (`MSSQLSvc/CYM-DB-01`), and staging of financial audit archives.

2️⃣ **Track 2: OAuth Heist (ShinyHunters / UNC6240 Cloud Extortion)**
Tracked a credential phishing attack targeting Okta SSO, followed by the weaponization of an authorized third-party OAuth app (ToggleBox) that systematically purged MFA change notification emails from the victim's Google Workspace inbox. Uncovered the theft of internal cloud architecture docs, unauthorized database access via `svc_dbadmin`, and compressed exfiltration via `zstd`.

3️⃣ **Track 3: Rogue Synthesis (AI-Augmented Threat — PROMPTFLUX)**
The most cutting-edge track of the event! Dissected a developer endpoint compromise where a typosquatted VS Code extension (`SyntaxOptimizer`) queried the **Google Gemini API (`gemini-1.5-flash-latest`)** to dynamically synthesize malicious C source code (`cache_worker.c`) in `%TEMP%` at runtime. Tracked local compilation via `gcc` into `sys_worker.exe`, token harvesting from `.gcloud\credentials.db`, telemetry-masqueraded exfiltration, and lateral persistence by backdooring CI/CD scripts (`build_production.ps1`).

---

### 💡 Key Takeaways
* **Google SecOps & UDM Search**: Querying high-volume logs with Chronicle’s Unified Data Model (UDM) enabled sub-second correlation between Zscaler proxy events, Windows Sysmon process launches, and Google Workspace audit trails.
* **The Rise of "Just-in-Time" AI Threats**: Seeing adversaries weaponize LLM APIs for on-the-fly payload generation and polymorphic obfuscation underscores why runtime behavioral detection is vital.

A massive thank you to **Google Cloud Security** and **Hack The Box** for designing such a realistic, high-fidelity threat-hunting battlefield!

👉 **Full Technical Write-Ups & Python Solvers**: https://github.com/MynameisKoi/CTF/tree/main/Operation%20Cymbal

#GoogleCloudSecurity #HackTheBox #GoogleSecOps #ChronicleSIEM #DFIR #ThreatHunting #Cybersecurity #CTF #InfoSec #AIthreats #CloudSecurity #IncidentResponse
