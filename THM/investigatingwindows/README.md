# TryHackMe — Investigating Windows (`investigatingwindows`) Forensics Write-Up

## Overview
- **Room**: Investigating Windows ([`investigatingwindows`](https://tryhackme.com/r/room/investigatingwindows))
- **Difficulty**: Medium
- **Category**: Digital Forensics / Windows Incident Response & Threat Hunting
- **Scenario**: A Windows Server machine has been compromised. As the digital forensics and incident response (DFIR) investigator, our goal is to triage the operating system, inspect event logs, uncover persistence mechanisms (scheduled tasks, registry run keys, backdoor users), identify malware tools (credential dumpers, reverse shells), reconstruct the compromise timeline, and discover network indicators of compromise (C2 IPs and DNS poisoning).

---

## Summary of Answers

| # | Question | Answer |
|---|---|---|
| **1** | Whats the version and year of the windows machine? | `Windows Server 2016` |
| **2** | Which user logged in last? | `Administrator` |
| **3** | When did John log onto the system last? (Answer format: MM/DD/YYYY H:MM:SS AM/PM) | `03/02/2019 5:48:32 PM` |
| **4** | What IP does the system connect to when it first starts? | `10.34.2.3` |
| **5** | What two accounts had administrative privileges (other than the Administrator user)? | `Jenny, Guest` |
| **6** | What's the name of the scheduled task that is malicious? | `Clean file system` |
| **7** | What file was the task trying to run daily? | `nc.ps1` |
| **8** | What port did this file listen locally for? | `1348` |
| **9** | When did Jenny last logon? | `Never` |
| **10**| At what date did the compromise take place? | `03/02/2019` |
| **11**| At what time did Windows first assign special privileges to a new logon? | `03/02/2019 4:04:49 PM` |
| **12**| What tool was used to get Windows passwords? | `Mimikatz` |
| **13**| What was the attackers external control and command servers IP? | `76.32.97.132` |
| **14**| What was the extension name of the shell uploaded via the servers website? | `.jsp` |
| **15**| What was the last port the attacker opened? | `1337` |
| **16**| Check for DNS poisoning, what site was targeted? | `google.com` |

---

## Step-by-Step Investigation Walkthrough

### Phase 1: Operating System & User Account Triage
1. **OS Version**:
   Open a command prompt and run `systeminfo` or `winver`:
   - OS Name: `Microsoft Windows Server 2016 Datacenter`
   - Answer: `Windows Server 2016`

2. **Last Logged In User & Logon Timestamps**:
   Check user accounts via `net user` and query Security Event Logs:
   ```cmd
   net user
   net user John
   net user Jenny
   net localgroup Administrators
   ```
   - `net user John` shows:
     `Last Logon: 3/2/2019 5:48:32 PM` &rarr; `03/02/2019 5:48:32 PM`
   - `net user Jenny` shows:
     `Last Logon: Never`
   - `net localgroup Administrators` shows members: `Administrator`, `Guest`, `Jenny`.
     - Accounts other than Administrator with admin rights: `Jenny, Guest`.
   - Security Event Log (Event ID `4624` - Successful Logon) shows `Administrator` had the most recent logon event.

### Phase 2: Persistence & Scheduled Tasks
1. **Malicious Scheduled Task**:
   Open **Task Scheduler** (`taskschd.msc`) or query via PowerShell:
   ```powershell
   Get-ScheduledTask | Select-Object TaskName, TaskPath, State
   ```
   Inspect non-standard tasks:
   - Task Name: `Clean file system`
   - Action / Executable: runs PowerShell script `nc.ps1` (`C:\TMP\nc.ps1`) daily.
   - Script inspection of `nc.ps1`:
     Opens a PowerShell Netcat listener binding locally on port `1348`.

2. **Startup Programs**:
   Examine System Information (`msinfo32` &rarr; Software Environment &rarr; Startup Programs) or Registry Run keys:
   - Location: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
   - Found command initiating outbound network socket to `10.34.2.3`.

### Phase 3: Timeline Analysis & Privilege Assignment
1. **Compromise Date**:
   Inspecting folder creation dates in `C:\TMP` and file system timestamps for dropped binaries (`nc.ps1`, `mim.exe`) reveals initial activity on `03/02/2019`.

2. **Special Privilege Assignment**:
   In **Event Viewer** (`eventvwr.msc`), open `Windows Logs &rarr; Security`:
   - Filter by **Event ID 4672** ("Special privileges assigned to new logon").
   - Sort chronologically: The earliest privileged logon event associated with the compromise occurred at `03/02/2019 4:04:49 PM`.

### Phase 4: Credential Dumping & Web Attack Vectors
1. **Password Dumping Tool**:
   In `C:\TMP\`, analyze dropped utilities and command history:
   - `mim.exe` and `mim-out.txt` were executed to dump LSASS memory hashes and plaintext passwords.
   - Tool name: `Mimikatz`.

2. **Web Shell Vector**:
   Inspect the web root directory (`C:\inetpub\wwwroot` or Apache Tomcat webapps directory `C:\xampp\` / `C:\Tomcat`):
   - A webshell was uploaded with the Java Server Pages extension: `.jsp`.

3. **Firewall Rules & Backdoor Ports**:
   Review Windows Defender Firewall rules and active listeners:
   ```cmd
   netsh advfirewall firewall show rule name=all
   ```
   Or inspect newly opened inbound rules:
   - The attacker opened an additional listening port for backdoor access: `1337`.

### Phase 5: C2 Infrastructure & Network Tampering
1. **DNS Poisoning via Hosts File**:
   Inspect the local Windows resolution file:
   ```cmd
   type C:\Windows\System32\drivers\etc\hosts
   ```
   The file contains the following malicious mapping:
   ```text
   76.32.97.132 google.com
   ```
   - External C2 Server IP: `76.32.97.132`
   - Targeted site: `google.com`

---

## Key DFIR Lessons Learned
1. **Local Account Manipulation**: Attackers often enable built-in `Guest` accounts or create stealth administrative users (`Jenny`) without logging in interactively immediately.
2. **Persistence Hunting**: Inspecting Task Scheduler (`Clean file system`) and Registry Run keys uncovers backdoor scripts.
3. **Hosts File Poisoning**: Simple DNS manipulation (`hosts` file) redirects user traffic or security updates to attacker-controlled C2 servers (`76.32.97.132`).
