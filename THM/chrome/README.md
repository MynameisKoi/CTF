# TryHackMe — Chrome (`chrome`) Forensics Write-Up

## Overview
- **Room**: Chrome (`chrome`)
- **Artifact**: `chromefiles-1697949492677.zip` (containing `traffic.pcapng`, 76.3 MB)
- **Objective**: Analyze the captured network traffic (`traffic.pcapng`) to recover exfiltrated files over SMB2, reverse engineer the `.NET` encryption binary (`transfer.exe`), decrypt the exfiltrated `AppData` archive (`encrypted_files`), crack the Windows DPAPI MasterKey, decrypt Chrome's `Local State` AES-256-GCM key, and decrypt the saved credentials inside Chrome's `Login Data` SQLite database.

---

## Summary of Answers

| # | Question | Answer |
|---|---|---|
| **1** | What is the first password that we find? | `bubbles` |
| **2** | What is the URL found in the first index? Fully defang the URL | `hxxps[://]mysecuresite[.]thm/` |
| **3** | What is the password found in the first index? | `Sup3rPaS$w0rd1` |
| **4** | What is the URL found in the second index? Fully defang the URL | `hxxps[://]worksite[.]thm/` |
| **5** | What is the password found in the second index? | `Sup3rSecuR3!` |

---

## Detailed Step-by-Step Analysis

### Step 1: Unpack the Artifact & Inspect `traffic.pcapng`

First, unzip `chromefiles-1697949492677.zip` to extract `traffic.pcapng` and inspect its protocol hierarchy using `tshark`:
```bash
unzip chromefiles-1697949492677.zip
tshark -r traffic.pcapng -q -z io,phs
```
Nearly all of the capture volume (`63.7 MB` out of `76.1 MB`) is **SMB2** traffic between `10.0.2.19` and `10.0.2.36:445`.

Export all SMB objects from `traffic.pcapng` using Wireshark (`File -> Export Objects -> SMB...`) or `tshark`:
```bash
mkdir -p smb_objects
tshark -r traffic.pcapng --export-objects smb,smb_objects
ls -la smb_objects/
```
Two key files are recovered from the SMB share:
1. **`%5ctransfer.exe`** (`transfer.exe`, `5,632` bytes): A 32-bit `.NET` console executable (`PE32 executable (console) Intel 80386 Mono/.Net assembly`).
2. **`%5cencrypted_files`** (`encrypted_files`, `75,361,952` bytes): A large encrypted data blob.

---

### Step 2: Reverse Engineer `transfer.exe` & Decrypt `encrypted_files`

Inspect the ASCII and UTF-16LE strings inside `transfer.exe` (or decompile with `ilspycmd` / `dnSpy`):
```bash
strings -e l -n 4 smb_objects/%5ctransfer.exe
```
Output:
```text
PjoM95MpBdz85Kk7ewcXSLWCoAr7mRj1
lR3soZqkaWZ9ojTX
C:\Users\hadri\Downloads\files.zip
C:\Users\hadri\Downloads\encrypted_files
File encrypted and saved successfully.
Error:
```
`transfer.exe` reads `C:\Users\hadri\Downloads\files.zip`, encrypts it using **AES-256-CBC** with:
- **AES-256 Key (32 bytes)**: `PjoM95MpBdz85Kk7ewcXSLWCoAr7mRj1`
- **AES IV (16 bytes)**: `lR3soZqkaWZ9ojTX`

and writes the output to `encrypted_files`.

We can decrypt `encrypted_files` back into `files.zip` using Python (or CyberChef `AES Decrypt` in `CBC` mode):
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"PjoM95MpBdz85Kk7ewcXSLWCoAr7mRj1"
iv = b"lR3soZqkaWZ9ojTX"

with open("smb_objects/%5cencrypted_files", "rb") as f:
    ciphertext = f.read()

decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
plaintext = decryptor.update(ciphertext)

with open("files.zip", "wb") as f:
    f.write(plaintext)
```
Unzipping `files.zip` extracts an `AppData/` directory tree containing:
- `AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580` (Windows DPAPI MasterKey file)
- `AppData/Local/Google/Chrome/User Data/Local State` (Chrome JSON state file containing the DPAPI-protected AES key under `os_crypt.encrypted_key`)
- `AppData/Local/Google/Chrome/User Data/Default/Login Data` (Chrome SQLite credential store)

---

### Step 3: Crack the DPAPI MasterKey Password (Question 1)

Google Chrome on Windows encrypts saved passwords in `Login Data` using an AES-256-GCM key stored in `Local State` (`os_crypt.encrypted_key`), which is itself encrypted via **Windows DPAPI** using the user's DPAPI MasterKey (`8c6b6187-8eaa-48bd-be16-98212a441580`). The DPAPI MasterKey is protected by the user's Windows login password and SID (`S-1-5-21-3854677062-280096443-3674533662-1001`).

1. Extract the DPAPI MasterKey hash for John the Ripper using `DPAPImk2john.py`:
   ```bash
   unzip -q files.zip -d extracted_appdata
   DPAPImk2john.py \
     --masterkey="extracted_appdata/AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580" \
     --sid="S-1-5-21-3854677062-280096443-3674533662-1001" \
     --context=local > dpapi.hash
   ```
2. Crack `dpapi.hash` with John the Ripper and `rockyou.txt`:
   ```bash
   john --wordlist=/usr/share/wordlists/rockyou.txt dpapi.hash
   john --show dpapi.hash
   ```
   John cracks the password:
   ```text
   bubbles          (?)
   ```

- **Answer 1**: `bubbles`

---

### Step 4: Decrypt the DPAPI MasterKey & Chrome `Local State` Key

1. **Decrypt the DPAPI MasterKey** using `impacket-dpapi` with the user SID and cracked password `bubbles`:
   ```bash
   impacket-dpapi masterkey \
     -file "extracted_appdata/AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580" \
     -sid "S-1-5-21-3854677062-280096443-3674533662-1001" \
     -password "bubbles"
   ```
   Output:
   ```text
   Decrypted key with User Key (SHA1)
   Decrypted key: 0xca4387eb0a71fc0eea23e27f54b9ae240379c9e82a05d6fca73ecee13ca2e0e4d98390844697d8ed10715415c56152653edf460a47b70ddb868a03ee6a3f9840
   ```

2. **Decrypt Chrome's `Local State` `os_crypt.encrypted_key`**:
   - Read `os_crypt.encrypted_key` from `AppData/Local/Google/Chrome/User Data/Local State`.
   - Base64-decode it and strip the first 5 bytes (`DPAPI`).
   - Decrypt the DPAPI blob using the MasterKey `0xca4387eb...` to obtain Chrome's 32-byte AES-256-GCM key:
     `9a3094f1bfe3e19d5d039fb569d35d49ad083ac34dbcd5d9e42a506b8d4a192c`

---

### Step 5: Query & Decrypt Chrome's `Login Data` SQLite Database (Questions 2–5)

Query the `logins` table in `AppData/Local/Google/Chrome/User Data/Default/Login Data` and decrypt `password_value` using AES-256-GCM (`v10` prefix = 3 bytes, `nonce` = 12 bytes, `ciphertext + tag` = remaining bytes):

```python
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

chrome_aes_key = bytes.fromhex(
    "9a3094f1bfe3e19d5d039fb569d35d49ad083ac34dbcd5d9e42a506b8d4a192c"
)

conn = sqlite3.connect(
    "extracted_appdata/AppData/Local/Google/Chrome/User Data/Default/Login Data"
)
cur = conn.cursor()
cur.execute("SELECT id, origin_url, username_value, password_value FROM logins ORDER BY id")

for row_id, origin_url, username, pw_blob in cur.fetchall():
    nonce = pw_blob[3:15]
    ct_tag = pw_blob[15:]
    password = AESGCM(chrome_aes_key).decrypt(nonce, ct_tag, None).decode()
    print(f"Index {row_id}: URL={origin_url} | Username={username} | Password={password}")
```
Output:
```text
Index 1: URL=https://mysecuresite.thm/ | Username=Administrator | Password=Sup3rPaS$w0rd1
Index 2: URL=https://worksite.thm/     | Username=chrome        | Password=Sup3rSecuR3!
```

Fully defanging both URLs (`https://` -> `hxxps[://]`, `.` -> `[.]`):
- **Index 1 URL (Q2)**: `hxxps[://]mysecuresite[.]thm/`
- **Index 1 Password (Q3)**: `Sup3rPaS$w0rd1`
- **Index 2 URL (Q4)**: `hxxps[://]worksite[.]thm/`
- **Index 2 Password (Q5)**: `Sup3rSecuR3!`

---

## Automated Solver
Run [`solve.py`](./solve.py) to execute the entire forensic pipeline automatically from `chromefiles-1697949492677.zip`:
```bash
python3 solve.py
```
