# TryHackMe — Block (`blockroom`) Forensics Write-Up

## Overview
- **Room**: Block ([`blockroom`](https://tryhackme.com/r/room/blockroom))
- **Difficulty**: Medium
- **Category**: Digital Forensics & Incident Response (DFIR) / Blue Team
- **Artifacts**: `evidence.zip` (containing `traffic.pcapng` and `lsass.DMP`)
- **Scenario**: A junior system administrator forgot to deactivate corporate accounts for two recently terminated employees. Management suspects these former employees logged back into the internal server over SMB to steal sensitive corporate documents. Our mission is to analyze the network packet capture (`traffic.pcapng`) and the Windows Local Security Authority Subsystem Service memory dump (`lsass.DMP`), identify the intruders, recover their credentials, decrypt their encrypted SMB3 sessions, and retrieve the accessed flags.

---

## Summary of Answers

| # | Question | Answer |
|---|---|---|
| **1** | What is the username of the first person who accessed our server? | `mrealman` |
| **2** | What is the password of the user in question 1? | `Blockbuster1` |
| **3** | What is the flag that the first user got access to? | `THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}` |
| **4** | What is the username of the second person who accessed our server? | `eshellstrop` |
| **5** | What is the hash of the user in question 4? | `3f29138a04aadc19214e9c04028bf381` |
| **6** | What is the flag that the second user got access to? | `THM{No_PasSw0Rd?_No_Pr0bl3m}` |

---

## Detailed Step-by-Step Walkthrough

### Phase 1: Unpacking the Evidence & Scoping

1. Extract the challenge archive:
   ```bash
   unzip evidence.zip
   ```
2. The archive provides two critical artifacts:
   - **`traffic.pcapng`**: Packet capture of network communication targeting the corporate file share on port 445 (SMB).
   - **`lsass.DMP`**: Full process memory dump of `lsass.exe` taken from the affected server.

---

### Phase 2: Investigating the First Intruder (`mrealman`)

#### Step 1: Identifying the First Username (Question 1)
1. Open `traffic.pcapng` in **Wireshark**.
2. Apply the SMB2 display filter to locate authentication and session setup requests:
   ```wireshark
   smb2.cmd == 1
   ```
   *(Or filter for NTLM traffic using `ntlmssp`)*.
3. Inspect the very first session setup sequence:
   - Expand **SMB2 (Server Message Block Protocol Version 2)** &rarr; **SMB2 Header** &rarr; **Session Setup Request**.
   - Expand **Security Blob** &rarr; **GSS-API** &rarr; **SPNEGO** &rarr; **negTokenResp** &rarr; **NTLMSSP_AUTH**.
   - Under the NTLM Authentication attributes, inspect the user credentials:
     - **Domain name**: `BLOCK`
     - **User name**: `mrealman`
4. **Answer 1**: `mrealman`

---

#### Step 2: Extracting and Cracking the Password (Question 2)
1. Process the `lsass.DMP` minidump using [`pypykatz`](https://github.com/skelsec/pypykatz) (Python implementation of Mimikatz):
   ```bash
   pypykatz lsa minidump lsass.DMP
   ```
2. Look for the logon session associated with `mrealman`:
   ```text
   Username: mrealman
   Domain: BLOCK
   NT: 1f9175a516211660c7a8143b0f36ab44
   SHA1: e58d348a0322306d8a39a2599fa0e8544d6db2be
   ```
3. Save the NT hash to `mrealman_hash.txt`:
   ```text
   1f9175a516211660c7a8143b0f36ab44
   ```
4. Crack the NT hash using **John the Ripper** with `rockyou.txt` (or via Hashcat / CrackStation):
   ```bash
   john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt mrealman_hash.txt
   ```
   *Output*:
   ```text
   Blockbuster1     (mrealman)
   ```
5. **Answer 2**: `Blockbuster1`

---

#### Step 3: Decrypting the First SMB3 Session & Retrieving Flag 1 (Question 3)
1. In the packet capture, packets following the Session Setup response are encapsulated inside **Encrypted SMB3 (`SMB2 Transform Header`)**, preventing direct inspection of file transfers.
2. In accordance with the Microsoft NTLM protocol specification ([MS-NLMP]), the random session key used to generate the SMB3 decryption key is derived using:
   - User: `mrealman`
   - Domain: `BLOCK`
   - NT Hash: `1f9175a516211660c7a8143b0f36ab44` (or password `Blockbuster1`)
   - `NTProofStr`: Extracted from the `NTLMSSP_AUTH` packet in Wireshark.
   - `Encrypted session key`: Extracted from the `NTLMSSP_AUTH` packet in Wireshark.
3. Compute the session key using the formula:
   $$\text{ResponseKeyNT} = \text{HMAC-MD5}_{\text{NT-Hash}}(\text{UTF16LE}(\text{toUpperCase}(\text{Username}) + \text{Domain}))$$
   $$\text{KeyExchangeKey} = \text{HMAC-MD5}_{\text{ResponseKeyNT}}(\text{NTProofStr})$$
   $$\text{RandomSessionKey} = \text{RC4}_{\text{KeyExchangeKey}}(\text{EncryptedSessionKey})$$
4. Load the derived session key into Wireshark:
   - Navigate to **Edit** &rarr; **Preferences** &rarr; **Protocols** &rarr; **SMB2**.
   - Click **Edit...** next to **Secret session keys for decryption**.
   - Add a new entry with the **Session ID** (e.g. `0x0000000000000010` from packet details) and the calculated **Session Key**.
5. Once Wireshark decrypts the packets, navigate to:
   - **File** &rarr; **Export Objects** &rarr; **SMB...**
   - Locate the downloaded file: `clients156.csv`
   - Save and inspect `clients156.csv`:
     ```text
     id,name,email,flag
     1,Alice,alice@corp.thm,THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}
     ```
6. **Answer 3**: `THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}`

---

### Phase 3: Investigating the Second Intruder (`eshellstrop`)

#### Step 4: Identifying the Second Username (Question 4)
1. Return to the Wireshark filter `smb2.cmd == 1` and examine the subsequent session setup exchange.
2. Under the second `NTLMSSP_AUTH` packet:
   - **Domain name**: `BLOCK`
   - **User name**: `eshellstrop`
3. **Answer 4**: `eshellstrop`

---

#### Step 5: Finding the Second User's Hash (Question 5)
1. Inspect the `pypykatz` output previously generated from `lsass.DMP` for `eshellstrop`:
   ```text
   Username: eshellstrop
   Domain: BLOCK
   NT: 3f29138a04aadc19214e9c04028bf381
   SHA1: c58434a9497e59fdbb7d90d0b04b4d7f5dafe084
   ```
2. The NT hash extracted from LSASS memory is `3f29138a04aadc19214e9c04028bf381`.
3. **Answer 5**: `3f29138a04aadc19214e9c04028bf381`

---

#### Step 6: Decrypting Flag 2 Without Password Cracking (Question 6)
1. Attempting to crack `eshellstrop`'s hash with standard wordlists fails.
2. **Key Protocol Insight**: In NTLMv2 authentication, calculating `ResponseKeyNT` requires **only the NT hash**, not the cleartext password!
   ```python
   # Only requires NT hash, username, and domain
   response_key_nt = hmac.new(nt_hash, (username.upper() + domain).encode('utf-16le'), hashlib.md5).digest()
   ```
3. Extract `eshellstrop`'s `NTProofStr` and `Encrypted session key` from their Session Setup Request packet.
4. Run the derivation helper ([`solve.py`](./solve.py)) to compute the session key directly from `3f29138a04aadc19214e9c04028bf381`.
5. Add `eshellstrop`'s **Session ID** and newly calculated **Session Key** into Wireshark's SMB2 decryption table.
6. Export the decrypted SMB object for `eshellstrop` (**File** &rarr; **Export Objects** &rarr; **SMB...**) and view the contents:
   ```text
   THM{No_PasSw0Rd?_No_Pr0bl3m}
   ```
7. **Answer 6**: `THM{No_PasSw0Rd?_No_Pr0bl3m}`

---

## Defensive Recommendations & Hardening

1. **Strict Offboarding & Deprovisioning**:
   - Establish automated offboarding scripts tied to HR systems to disable Active Directory accounts immediately upon employee departure.
2. **SMB Encryption Enforcement**:
   - Require SMB encryption and SMB signing domain-wide (`Set-SmbServerConfiguration -EncryptData $True`) to prevent unauthorized eavesdropping.
3. **Credential Guard & LSASS Protection**:
   - Enable **Windows Defender Credential Guard** (Virtualization-based security) and **RunAsPPL** (`Protected Process Light`) on `lsass.exe` to block unauthorized memory access and minidump creation.
