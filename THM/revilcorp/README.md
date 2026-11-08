# TryHackMe — REvil Corp (`revilcorp`) Incident Response Write-Up

## Overview
- **Room**: REvil Corp ([`revilcorp`](https://tryhackme.com/r/room/revilcorp))
- **Difficulty**: Medium
- **Category**: Digital Forensics & Incident Response (DFIR) / Ransomware Triage
- **Primary Tool**: Mandiant Redline (`AnalysisSession1`)
- **Scenario**: An employee at Lockman Group reported that all files on their workstation were encrypted and appended with an unfamiliar extension. As the incident responder, you are provided with an endpoint triage image loaded in Mandiant Redline to analyze the compromise timeline, pinpoint the malicious executable, trace user download activity, and uncover ransomware artifacts.

---

## Summary of Answers

| # | Question | Answer | Redline Location |
|---|---|---|---|
| **1** | What is the compromised employee's full name? | `John Coleman` | `System Information` &rarr; `User Information` |
| **2** | What is the operating system of the compromised host? | `Windows 7 Home Premium 7601 Service Pack 1` | `System Information` &rarr; `Operating System Information` |
| **3** | What is the name of the malicious executable that the user opened? | `WinRAR2021.exe` | `File Download History` |
| **4** | What is the full URL that the user visited to download the malicious binary? (include the binary as well) | `http://192.168.75.129:4748/Documents/WinRAR2021.exe` | `File Download History` (Source URL) |
| **5** | What is the MD5 hash of the binary? | `890a58f200dfff23165df9e1b088e58f` | `File System` &rarr; `WinRAR2021.exe` Details |
| **6** | What is the size of the binary in kilobytes? | `164` | `File System` &rarr; File Properties (`164 KB`) |
| **7** | What is the extension to which the user's files got renamed? | `.t48s39la` | `File System` &rarr; Desktop/Documents encrypted files |
| **8** | What is the number of files that got renamed and changed to that extension? | `48` | `File System` &rarr; Filter by `.t48s39la` (Count: 48) |
| **9** | What is the full path to the wallpaper that got changed by an attacker, including the image name? | `C:\Users\John Coleman\AppData\Local\Temp\hk8.bmp` | `File System` &rarr; `AppData\Local\Temp\` (`.bmp` image) |
| **10**| The attacker left a note for the user on the Desktop; provide the name of the note with the extension. | `t48s39la-readme.txt` | `File System` &rarr; `C:\Users\John Coleman\Desktop\` |
| **11**| The attacker created a folder "Links for United States" under `C:\Users\John Coleman\Favorites\` and left a file there. Provide the name of the file. | `GobiernoUSA.gov.url.t48s39la` | `File System` &rarr; `Favorites\Links for United States\` |
| **12**| There is a hidden file that was created on the user's Desktop that has 0 bytes. Provide the name of the hidden file. | `d60dff40.lock` | `File System` &rarr; Desktop (Filter: Size = 0) |
| **13**| The user downloaded a decryptor hoping to decrypt all the files, but he failed. Provide the MD5 hash of the decryptor file. | `f617af8c0d276682fdf528bb3e72560b` | `File System` &rarr; Decryptor executable &rarr; MD5 |
| **14**| In the ransomware note, the attacker provided a URL that is accessible through the normal browser in order to decrypt one of the encrypted files for free. The user attempted to visit it. Provide the full URL path. | `http://decryptor.top/644E7C8EFA02FBB7` | `Browser URL History` (Filter: `decryptor`) |
| **15**| What are some three names associated with the malware which infected this host? (enter the names in alphabetical order) | `REvil, Sodin, Sodinokibi` *(or `REvil,Sodin,Sodinokibi`)* | Threat Intelligence / VirusTotal family aliases |

---

## Step-by-Step Investigation Walkthrough

### Phase 1: Ingesting the Triage Package into Redline
1. Start the machine on TryHackMe.
2. Open the **Analysis File** folder located on the Desktop and open **`AnalysisSession1`**.
3. Allow Mandiant Redline to load the pre-collected memory and file audit data.

---

### Phase 2: Host Triage & User Information
1. **System & User Identification**:
   - In the left pane, navigate to **System Information** &rarr; **User Information**.
   - Username: `John Coleman`.
   - In **Operating System Information**:
     - OS: `Windows 7 Home Premium 7601 Service Pack 1`.

---

### Phase 3: Initial Infection Vector Analysis
1. **File Download History**:
   - Navigate to **File Download History** in Redline.
   - Look for recent downloads initiated by user `John Coleman`.
   - Entry found:
     - **File Name**: `WinRAR2021.exe`
     - **Source URL**: `http://192.168.75.129:4748/Documents/WinRAR2021.exe`
2. **Binary Characteristics**:
   - Go to **File System** and search for `WinRAR2021.exe`.
   - Properties:
     - **MD5 Hash**: `890a58f200dfff23165df9e1b088e58f`
     - **Size**: `164 KB` (167,936 bytes)

---

### Phase 4: Ransomware Behavior & Encryption Artifacts
1. **Encrypted Extension & File Count**:
   - Inspect files under `C:\Users\John Coleman\Desktop` and `Documents`.
   - Files are renamed with a random 8-character extension: `.t48s39la`.
   - Filter the **File System** view with the search filter `.t48s39la`:
     - Exactly **48** files match the extension.
2. **Desktop Ransom Note & Wallpaper**:
   - On the Desktop: `t48s39la-readme.txt`.
   - REvil drops a custom bitmap image replacing the desktop background:
     - Check `C:\Users\John Coleman\AppData\Local\Temp\`:
     - Path: `C:\Users\John Coleman\AppData\Local\Temp\hk8.bmp`.
3. **Favorites & Lock Files**:
   - Check `C:\Users\John Coleman\Favorites\Links for United States\`:
     - File: `GobiernoUSA.gov.url.t48s39la`.
   - Under `C:\Users\John Coleman\Desktop\`, filter by **Size = 0 bytes** and enable hidden files:
     - Lock file: `d60dff40.lock`.

---

### Phase 5: Post-Infection Activity & Decryptor Analysis
1. **Victim Browsing Activity**:
   - Open **Browser URL History** in Redline.
   - Filter for `decryptor` or look for outgoing HTTP requests following the infection timeline:
     - Visited URL: `http://decryptor.top/644E7C8EFA02FBB7`.
2. **Failed Decryptor Artifact**:
   - The user downloaded a binary attempting to decrypt the data.
   - Search the file system for the downloaded decryptor utility:
     - **MD5 Hash**: `f617af8c0d276682fdf528bb3e72560b`.
3. **Malware Threat Intelligence**:
   - Searching the MD5 `890a58f200dfff23165df9e1b088e58f` on VirusTotal or MITRE ATT&CK identifies the ransomware family:
     - **Associated Names (Alphabetical)**: `REvil, Sodin, Sodinokibi`.

---

## Key DFIR Lessons Learned
1. **Redline Triage Speed**: Mandiant Redline provides unified views into download history, web history, and file system timelines without requiring a full manual raw disk mount.
2. **REvil / Sodinokibi Signatures**:
   - Randomized 8-character extensions per victim machine (`.<random_8>`).
   - Matching `<random_8>-readme.txt` ransom instructions on every affected folder.
   - Temporary zero-byte `.lock` files used for process mutual exclusion.
   - Replacement of the Windows desktop wallpaper with a rendered BMP from `%TEMP%`.
