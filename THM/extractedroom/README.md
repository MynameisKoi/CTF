# TryHackMe — Extracted (`extractedroom`) Forensics Write-Up

## Overview
- **Room**: Extracted (`extractedroom`)
- **Artifact**: `file-1693277727739.zip` (containing `traffic.pcapng`, 392 MB)
- **Scenario**: Analyze the captured network traffic (`traffic.pcapng`) to understand how the attacker exfiltrated data from a compromised Windows workstation, reconstruct the exfiltrated KeePass process dump (`1337.dmp`) and KeePass database (`Database1337.kdbx`), exploit **CVE-2023-32784** (`keepass-password-dumper`) to recover the master password from memory, crack the missing character, and unlock the KeePass database to retrieve the flag.

---

## Summary of Answers

| # | Question | Answer |
|---|---|---|
| **1** | What's the initial part of the password? | `NoWaYIcanF0rGetThis123` |
| **2** | Find the missing character in the password. | `?` |
| **3** | What's the flag? | `THM{B3tt3r_Upd4t3_Y0ur_K33p455}` |

---

## Detailed Step-by-Step Analysis

### Step 1: Unpack the Artifact & Inspect TCP Conversations

1. Unzip `file-1693277727739.zip` to extract `traffic.pcapng`:
   ```bash
   unzip file-1693277727739.zip
   ```
2. List the TCP conversations in `traffic.pcapng` using `tshark` (or Wireshark `Statistics -> Conversations -> TCP`):
   ```bash
   tshark -r traffic.pcapng -q -z conv,tcp
   ```
   Output:
   ```text
   10.10.45.95:50357 <-> 10.10.94.106:1337   23728 frames (1.3 MB) | 29586 frames (389 MB) | Total: 53314 frames (390 MB)
   10.10.45.95:50356 <-> 10.10.94.106:1339       6 frames (11 kB)  |     5 frames (462 B)  | Total:    11 frames (12 kB)
   10.10.45.95:50358 <-> 10.10.94.106:1338       4 frames (228 B)  |     5 frames (2,970 B)| Total:     9 frames (3,198 B)
   ```
   There are three distinct TCP streams between the victim (`10.10.45.95`) and the attacker host (`10.10.94.106`):
   - **TCP Stream 0 (`Port 1339`)**: HTTP download of `/xxxmmdcclxxxiv.ps1` (`11,195` bytes).
   - **TCP Stream 1 (`Port 1337`)**: Raw TCP upload of a ~389 MB Base64 payload.
   - **TCP Stream 2 (`Port 1338`)**: Raw TCP upload of a `2,688`-byte Base64 payload.

---

### Step 2: Analyze the Exfiltration Script (`xxxmmdcclxxxiv.ps1`)

Export the HTTP object from TCP Stream 0 (`File -> Export Objects -> HTTP...` in Wireshark or via `tshark`):
```bash
mkdir -p http_objects
tshark -r traffic.pcapng --export-objects http,http_objects
grep -v '^#' http_objects/xxxmmdcclxxxiv.ps1
```
Notice the filename `xxxmmdcclxxxiv.ps1`: in Roman numerals, `XXX` = `30` and `MMDCCLXXXIV` = `2784` -> **`32784`**, a direct reference to **CVE-2023-32784** (the KeePass 2.x Master Password memory dump vulnerability).

Reading the deobfuscated PowerShell script reveals the exact exfiltration logic:
1. **KeePass Process Dump (`Port 1337`)**:
   - Checks if `KeePass` is running (`Get-Process -Name 'KeePass'`).
   - Downloads Sysinternals `procdump.exe` to `C:\Tools\procdump.exe` and dumps the `KeePass` process memory to `Desktop\1337.dmp`:
     ```powershell
     procdump.exe -accepteula -ma <KeePass_PID> C:\Users\...\Desktop\1337.dmp
     ```
   - Reads all bytes of `1337.dmp`, **XORs every byte with `0x41`**, Base64-encodes the result, saves it as `539.dmp`, and sends it over a raw TCP socket to `0xa0a5e6a` (`10.10.94.106`) on **port `1337`**.

2. **KeePass Database Exfiltration (`Port 1338`)**:
   - Checks for `Desktop\Database1337.kdbx`.
   - Reads all bytes of `Database1337.kdbx`, **XORs every byte with `0x42`**, Base64-encodes the result, and sends it over a raw TCP socket to `0xa0a5e6a` (`10.10.94.106`) on **port `1338`**.

---

### Step 3: Reconstruct `1337.dmp` & Recover the Initial Password (Question 1)

1. **Reconstruct `1337.dmp` and `Database1337.kdbx`**:
   - Extract the raw payload from **TCP Stream 1 (`Port 1337`)**, Base64-decode it, and XOR every byte with `0x41` (or in CyberChef: `From Base64 -> XOR({'option':'Hex','string':'41'})`) to recover `1337.dmp`.
   - Extract the raw payload from **TCP Stream 2 (`Port 1338`)**, Base64-decode it, and XOR every byte with `0x42` (`From Base64 -> XOR({'option':'Hex','string':'42'})`) to recover `Database1337.kdbx`.

2. **Exploit CVE-2023-32784 on `1337.dmp`**:
   - When a user types their master password into KeePass's `SecureTextBoxEx` control, leftover managed strings remain in memory for each keystroke in the form of `N` bullet characters (`●`, Unicode `U+25CF` / UTF-16LE `0xCF 0x25`) followed by the newly typed UTF-16LE character:
     - Position 2: `●N`
     - Position 3: `●●o`
     - Position 4: `●●●W`
     - ...
   - Running `keepass-password-dumper` (`dotnet run 1337.dmp`) or scanning `1337.dmp` for UTF-16LE `(0xCF 0x25)+` patterns yields:
     ```text
     Pos 1  (●):                      N
     Pos 2  (●●):                     o
     Pos 3  (●●●):                    W
     Pos 4  (●●●●):                   a
     Pos 5  (●●●●●):                  Y
     Pos 6  (●●●●●●):                 I
     Pos 7  (●●●●●●●):                c
     Pos 8  (●●●●●●●●):               a
     Pos 9  (●●●●●●●●●):              n
     Pos 10 (●●●●●●●●●●):             F
     Pos 11 (●●●●●●●●●●●):            0
     Pos 12 (●●●●●●●●●●●●):           r
     Pos 13 (●●●●●●●●●●●●●):          G
     Pos 14 (●●●●●●●●●●●●●●):         e
     Pos 15 (●●●●●●●●●●●●●●●):        t
     Pos 16 (●●●●●●●●●●●●●●●●):       T
     Pos 17 (●●●●●●●●●●●●●●●●●):      h
     Pos 18 (●●●●●●●●●●●●●●●●●●):     i
     Pos 19 (●●●●●●●●●●●●●●●●●●●):    s
     Pos 20 (●●●●●●●●●●●●●●●●●●●●):   1
     Pos 21 (●●●●●●●●●●●●●●●●●●●●●):  2
     Pos 22 (●●●●●●●●●●●●●●●●●●●●●●): 3
     ```
   - Combining positions 1 through 22 gives the known password suffix: **`NoWaYIcanF0rGetThis123`**.

- **Answer 1**: `NoWaYIcanF0rGetThis123`

---

### Step 4: Crack the Missing First Character (Question 2)

Because CVE-2023-32784 relies on at least one preceding `●` character to identify remnants in memory, the **first character** of the password (`●NoWaYIcanF0rGetThis123`) is unknown.

1. Generate a candidate wordlist prepending every printable ASCII character (`0x20`–`0x7e`) to `NoWaYIcanF0rGetThis123`:
   ```python
   suffix = "NoWaYIcanF0rGetThis123"
   with open("wordlist.txt", "w") as f:
       for c in range(32, 127):
           f.write(chr(c) + suffix + "\n")
   ```
2. Extract the hash of `Database1337.kdbx` with `keepass2john` and crack it with John the Ripper:
   ```bash
   keepass2john Database1337.kdbx > kdbx.hash
   john --wordlist=wordlist.txt kdbx.hash
   john --show kdbx.hash
   ```
   Output:
   ```text
   Database1337:?NoWaYIcanF0rGetThis123

   1 password hash cracked, 0 left
   ```
   The missing first character is **`?`**, making the complete KeePass master password **`?NoWaYIcanF0rGetThis123`**.

- **Answer 2**: `?`

---

### Step 5: Open `Database1337.kdbx` & Retrieve the Flag (Question 3)

Open `Database1337.kdbx` in KeePassXC (or decrypt it via [`solve.py`](./solve.py)) using the master password **`?NoWaYIcanF0rGetThis123`**.

Inside the `Database1337` root group is an entry titled **`You win!`**:
- **Title**: `You win!`
- **Password**: `xWjy8SqH2CDDw76ptmvP`
- **Notes**: `THM{B3tt3r_Upd4t3_Y0ur_K33p455}`

- **Answer 3**: `THM{B3tt3r_Upd4t3_Y0ur_K33p455}`

---

## Automated Solver
Run [`solve.py`](./solve.py) to automatically parse `file-1693277727739.zip`, recover the password from the KeePass memory dump, crack the missing character, and decrypt `Database1337.kdbx` to print all 3 answers:
```bash
python3 solve.py
```
