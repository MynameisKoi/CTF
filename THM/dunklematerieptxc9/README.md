# TryHackMe — Dunkle Materie (`dunklematerieptxc9`) DFIR Write-Up

## Overview
- **Room**: Dunkle Materie ([`dunklematerieptxc9`](https://tryhackme.com/r/room/dunklematerieptxc9))
- **Difficulty**: Medium
- **Category**: Digital Forensics & Incident Response (DFIR) / Ransomware Behavioral Analysis & ProcDOT
- **Scenario**: A workstation in the Sales department was infected by ransomware. We are provided with Procmon logs, network captures, and ProcDOT visualizations to trace the execution flow of the ransomware binary, identify spawned child processes, uncover network callbacks to C2 infrastructure, locate persistence and wallpaper modifications, and attribute the ransomware strain.

---

## Summary of Answers

| # | Question | Answer |
|---|---|---|
| **1** | Provide the two PIDs spawned from the malicious executable. | `8644,7128` |
| **2** | Provide the full path where the ransomware initially got executed? | `c:\users\sales\appdata\local\temp\exploreer.exe` |
| **3** | This ransomware transfers the information about the compromised system and the encryption results to two domains over HTTP POST. What are the two C2 domains? | `mojobiden.com,paymenthacks.com` |
| **4** | What are the IPs of the malicious domains? | `146.112.61.108,206.188.197.206` |
| **5** | Provide the user-agent used to transfer the encrypted data to the C2 channel. | `Firefox/89.0` |
| **6** | Provide the cloud security service that blocked the malicious domain. | `Cisco Umbrella` |
| **7** | Provide the name of the bitmap that the ransomware set up as a desktop wallpaper. | `ley9kpi9r.bmp` |
| **8** | Find the PID of the process which attempted to change the background wallpaper on the victim's machine. | `4892` |
| **9** | The ransomware mounted a drive and assigned it the letter. Provide the registry key path to the mounted drive, including the drive letter. | `HKLM\SYSTEM\MountedDevices\DosDevices\Z:` |
| **10**| Provide the name of the ransomware used in the attack. | `BlackMatter` |

---

## Detailed Step-by-Step Walkthrough

### Phase 1: Tracing Ransomware Execution in ProcDOT

1. Open **ProcDOT** and load the generated Process Monitor log and PCAP.
2. Search for anomalous processes executed from temporary directories:
   - Initial entry point: `c:\users\sales\appdata\local\temp\exploreer.exe` (masquerading as `explorer.exe` with a typo).
3. Inspect child processes spawned by `exploreer.exe`:
   - Looking at the process tree shows two child process executions:
     - PID **`8644`**
     - PID **`7128`**

---

### Phase 2: Network C2 Exfiltration

1. Follow TCP connections originating from `exploreer.exe` and its children:
   - Encrypted telemetry containing victim machine information and encryption statistics is exfiltrated via HTTP POST requests.
   - Domains: `mojobiden.com` and `paymenthacks.com`
   - Resolved IPs: `146.112.61.108` and `206.188.197.206`
   - Hardcoded User-Agent: `Firefox/89.0`
2. One of the DNS requests returned sinkhole/blockpage telemetry from **Cisco Umbrella**.

---

### Phase 3: Desktop Ransom Note & Attribution

1. **Wallpaper Modification**:
   - The ransomware dropped a custom ransom note bitmap image: `ley9kpi9r.bmp`.
   - Process with PID **`4892`** issued registry modifications to `HKCU\Control Panel\Desktop\Wallpaper` to enforce the new wallpaper.
2. **Drive Mapping**:
   - Registry queries under `HKLM\SYSTEM\MountedDevices` reveal the ransomware mapped network shares to `DosDevices\Z:`.
3. **Threat Actor Attribution**:
   - Based on the ransom note format, encryption behavior, and exfiltration patterns, the malware is attributed to **BlackMatter Ransomware**.
