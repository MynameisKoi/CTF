# TryHackMe: Directory (directorydfirroom) - Writeup & Forensic Analysis

## Overview

- **Room**: Directory (`directorydfirroom`)
- **Platform**: TryHackMe
- **Artifact Provided**: `traffic-1725627206938.pcap` (Network Packet Capture, ~81.5 MB)
- **Target Network / Domain**: `DIRECTORY.THM` (`10.0.2.75` - Active Directory Domain Controller / Server)
- **Attacker IP**: `10.0.2.74`

---

## Executive Summary & Challenge Answers

| # | Question | Answer |
|---|---|---|
| **1** | What ports did the threat actor initially find open? | `53,80,88,135,139,389,445,464,593,636,3268,3269,5357` |
| **2** | The threat actor found four valid usernames, but only one username allowed the attacker to achieve a foothold on the server. What was the username? | `DIRECTORY.THM\larry.doe` |
| **3** | The threat actor captured a hash from the user in question 2. What are the last 30 characters of that hash? | `55616532b664cd0b50cda8d4ba469f` |
| **4** | What is the user's password? | `Password1!` |
| **5** | What were the second and third commands that the threat actor executed on the system? | `reg save HKLM\SYSTEM C:\SYSTEM,reg save HKLM\SAM C:\SAM` |
| **6** | What is the flag? | `THM{Ya_G0t_R0aSt3d!}` |

---

## Detailed Technical Walkthrough

### 1. Initial Reconnaissance & Port Scanning (Question 1)

The packet capture begins with network reconnaissance initiated by the attacker (`10.0.2.74`) scanning the target Active Directory server (`10.0.2.75`).

To identify open ports found by the threat actor, we filter for TCP SYN-ACK packets returned by the server (`10.0.2.75`) in response to TCP SYN probes:

```bash
tshark -r traffic-1725627206938.pcap \
  -Y "ip.src == 10.0.2.75 and ip.dst == 10.0.2.74 and tcp.flags == 0x012" \
  -T fields -e tcp.srcport | sort -nu | paste -sd,
```

**Results:**
```text
53,80,88,135,139,389,445,464,593,636,3268,3269,5357
```

Services exposed:
- `53`: DNS
- `80`: HTTP
- `88`: Kerberos
- `135`: MSRPC / Endpoint Mapper
- `139`: NetBIOS Session Service
- `389`: LDAP
- `445`: SMB
- `464`: Kerberos Password Change (`kpasswd`)
- `593`: RPC over HTTP
- `636`: LDAPS
- `3268`: Global Catalog LDAP
- `3269`: Global Catalog LDAPS
- `5357`: Web Services for Devices (WSDAPI)

---

### 2. Active Directory Enumeration & Kerberos AS-REP Roasting (Questions 2 & 3)

Following the port scan, the attacker conducted Kerberos user enumeration (e.g., using `kerbrute` or `GetNPUsers.py`) targeting the `DIRECTORY.THM` realm.

Filtering for Kerberos AS-REQ and AS-REP packets reveals four valid usernames queried by the attacker:
1. `john.doe`
2. `ranith.kays`
3. `john.ray`
4. `larry.doe`

For `john.doe`, `ranith.kays`, and `john.ray`, the Domain Controller replied with `KRB-ERROR: KDC_ERR_PREAUTH_REQUIRED (25)`, indicating that Kerberos pre-authentication is enforced.

However, for user `larry.doe` (Frame 4816 / 4817), the account has the `DONT_REQ_PREAUTH` (UF_DONT_REQUIRE_PREAUTH) flag enabled. The KDC immediately responded with an **AS-REP** packet (Frame 4817) containing an encrypted Ticket-Granting Ticket (TGT) and encrypted session data (`etype 23: eTYPE-ARCFOUR-HMAC-MD5`).

```bash
tshark -r traffic-1725627206938.pcap \
  -Y "frame.number == 4817" -O kerberos
```

#### Extracting the Hashcat / John AS-REP Roast Hash

The AS-REP response (etype 23) in Frame 4817 contains the encrypted KDCREP data cipher:
```text
encryptedKDCREPData_cipher:
f8716efbaa984508ddde606756441480805ab8be8cfb018a282718f7c040cd43924c6f9afeb6171230bbd3dccc79294dcf2f877a44c1a0981aadb7bb7a9510dd52d8dda4039ef4dcb444f18c9902be1623035e10aebf16ce4bdf5f7064f480e67e96ec2eb32bad95c5a1247bd7a241273fe80e281f4e6a99926f7969fcf803190c7096b947a33407f8578d4c0fb8b52d2aa8d0405a44b72bd21e014563cb71e82aee0e12538d0d440c930b98abf766e18ddc99a964e6e812ecf8dc8994a912a02074d40e5e6906915c1d216653d45df88636b51656f2c37de2020a2fd86ee7ecf6f0afe3f509fd31144e1573f9587155616532b664cd0b50cda8d4ba469f
```

The standard Hashcat format (`-m 18200`) for Kerberos 5 AS-REP (etype 23) is:
```text
$krb5asrep$23$username@realm:checksum$cipher
```
Where `checksum` is the first 16 bytes (32 hex characters) and `cipher` is the remaining encrypted blob:

```text
$krb5asrep$23$larry.doe@DIRECTORY.THM:f8716efbaa984508ddde606756441480$805ab8be8cfb018a282718f7c040cd43924c6f9afeb6171230bbd3dccc79294dcf2f877a44c1a0981aadb7bb7a9510dd52d8dda4039ef4dcb444f18c9902be1623035e10aebf16ce4bdf5f7064f480e67e96ec2eb32bad95c5a1247bd7a241273fe80e281f4e6a99926f7969fcf803190c7096b947a33407f8578d4c0fb8b52d2aa8d0405a44b72bd21e014563cb71e82aee0e12538d0d440c930b98abf766e18ddc99a964e6e812ecf8dc8994a912a02074d40e5e6906915c1d216653d45df88636b51656f2c37de2020a2fd86ee7ecf6f0afe3f509fd31144e1573f9587155616532b664cd0b50cda8d4ba469f
```

Taking the **last 30 characters** of the captured hash:
```text
55616532b664cd0b50cda8d4ba469f
```

---

### 3. Cracking the Password (Question 4)

We save the extracted hash to `larry.hash` and run `hashcat` or `john` using the standard `rockyou.txt` wordlist:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt larry.hash
```

**Output:**
```text
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23)
Password1!       ($krb5asrep$23$larry.doe@DIRECTORY.THM)
```

- **Cracked Password**: `Password1!`

---

### 4. Foothold & Decrypting WinRM Traffic (Questions 5 & 6)

Immediately following the AS-REP roast, the attacker establishes a remote PowerShell management session over **WinRM (HTTP port 5985)** using `evil-winrm` authenticated as `DIRECTORY.THM\larry.doe` with `Password1!`.

WinRM encapsulates remote PowerShell Protocol (PSRP) XML payloads inside MIME multipart messages (`application/HTTP-SPNEGO-session-encrypted`). The traffic is encrypted using session keys derived from NTLMSSP.

Using Jordan Borean's `decrypt-winrm.py` script:
```bash
python3 decrypt-winrm.py -p 'Password1!' traffic-1725627206938.pcap > decrypted_winrm.txt
```

#### Reconstructing Attacker Commands

Parsing the decrypted PSRP XML blocks (`<rsp:CommandLine>` and `<rsp:Arguments>`) reveals the exact sequence of interactive commands entered by the threat actor:

1. **Attacker Reconnaissance**:
   ```powershell
   whoami /all
   ```
   *Analysis*: Output reveals `larry.doe` belongs to `BUILTIN\Backup Operators` (`S-1-5-32-551`) and holds `SeBackupPrivilege`.

2. **Second Command**:
   ```powershell
   reg save HKLM\SYSTEM C:\SYSTEM
   ```

3. **Third Command**:
   ```powershell
   reg save HKLM\SAM C:\SAM
   ```

4. **Fourth Command**:
   ```powershell
   reg save HKLM\SECURITY C:\SECURITY
   ```

5. **Hive Exfiltration**:
   The attacker downloads the saved registry hives (`C:\SAM` and `C:\SYSTEM`) in 1 MB chunks to extract local account secrets and password hashes offline.

6. **Desktop Traversal & Flag Creation**:
   Towards the conclusion of the session (Command 34 & 36):
   ```powershell
   cd ..\Desktop\
   echo "THM{Ya_G0t_R0aSt3d!}" > note.txt
   ```

- **Second and Third Commands**: `reg save HKLM\SYSTEM C:\SYSTEM,reg save HKLM\SAM C:\SAM`
- **Flag**: `THM{Ya_G0t_R0aSt3d!}`

---

## Verification Script

An automated solution script is provided at [`solve.py`](solve.py). Run it using:

```bash
python3 solve.py [optional_pcap_path]
```
