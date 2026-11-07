# TryHackMe — Disk Analysis & Autopsy (`autopsy2ze0`) Forensics Write-Up

## Overview
- **Room**: Disk Analysis & Autopsy ([`autopsy2ze0`](https://tryhackme.com/r/room/autopsy2ze0))
- **Difficulty**: Medium
- **Category**: Digital Forensics / Windows Disk Image Analysis
- **Artifacts**: `HASAN2.E01` (Expert Witness Format forensic disk image)
- **Scenario**: We are tasked with investigating a Windows 10 workstation forensic image (`HASAN2.E01`) using **Autopsy Digital Forensics**. Our goal is to extract machine and user account metadata, locate network configuration parameters and network monitoring tools, analyze browser bookmarks, recover deleted wallpaper artifacts, and inspect PowerShell history logs to retrieve hidden flags.

---

## Summary of Answers

| # | Question | Answer |
|---|---|---|
| **1** | What is the MD5 hash of the E01 image? | `3f08c518adb3b5c1359849657a9b2079` |
| **2** | What is the computer account name? | `DESKTOP-0R59DJ3` |
| **3** | List all the user accounts. (alphabetical order) | `H4S4N,joshwa,keshav,sandhya,shreya,sivapriya,srini,suba` |
| **4** | Who was the last user to log into the computer? | `sivapriya` |
| **5** | What was the IP address of the computer? | `192.168.130.216` |
| **6** | What was the MAC address of the computer? (XX-XX-XX-XX-XX-XX) | `08-00-27-2C-C4-B9` |
| **7** | What is the name of the network card on this computer? | `Intel(R) PRO/1000 MT Desktop Adapter` |
| **8** | What is the name of the network monitoring tool? | `Look@LAN` |
| **9** | A user bookmarked a Google Maps location. What are the coordinates of the location? | `12°52'23.0"N 80°13'25.0"E` |
| **10**| A user has his full name printed on his desktop wallpaper. What is the user's full name? | `Anto Joshwa` |
| **11**| A user had a file on her desktop. It had a flag but she changed the flag using PowerShell. What was the first flag? | `flag{HarleyQuinnForQueen}` |

---

## Step-by-Step Investigation Walkthrough

### Phase 1: Case Creation & Image Ingestion
1. Launch **Autopsy** and create a new case.
2. Ingest `HASAN2.E01` as a Disk Image or VM file data source.
3. Select the data source root node in the tree viewer to view image properties:
   - **MD5 Hash**: `3f08c518adb3b5c1359849657a9b2079`

### Phase 2: Operating System & User Account Triage
1. Under `Results` &rarr; `Operating System Information`:
   - Hostname: `DESKTOP-0R59DJ3`
2. Under `Results` &rarr; `Operating System User Accounts`:
   - Enumerate all SAM accounts: `H4S4N,joshwa,keshav,sandhya,shreya,sivapriya,srini,suba`.
   - Sort by **Date Accessed** column to find the most recent interactive session: `sivapriya`.

### Phase 3: Network Interfaces & Installed Software
1. Browse to `Vol3/Program Files (x86)/Look@LAN`:
   - Tool name: `Look@LAN`
   - Open `irunin.ini` to extract active interface details:
     - IP Address: `192.168.130.216`
     - MAC Address: `08-00-27-2C-C4-B9`
2. Check the registry hive at `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards`:
   - Adapter description: `Intel(R) PRO/1000 MT Desktop Adapter`

### Phase 4: Artifact Analysis & Flag Recovery
1. **Browser Bookmarks**:
   Navigate to `Results` &rarr; `Extracted Content` &rarr; `Web Bookmarks`.
   Inspect the Chrome/Edge bookmark URL to extract the Google Maps lat/long coordinates:
   `12°52'23.0"N 80°13'25.0"E`.
2. **Wallpaper Analysis**:
   Inspect image thumbnails under `Views` &rarr; `File Types` &rarr; `By Extension` &rarr; `Images`.
   Open the custom desktop wallpaper image found under user `joshwa`'s files:
   Full name printed: `Anto Joshwa`.
3. **PowerShell History & Flag Recovery**:
   Navigate to `Users/sivapriya/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`.
   Review command history:
   The user initially set `flag{HarleyQuinnForQueen}` in a file before modifying it.
