# TryHackMe: Scripting

## Overview

- **Room**: Scripting
- **Platform**: TryHackMe
- **Tasks Covered**:
  - Task 1: [Easy] Base64
  - Task 2: [Medium] Gotta Catch 'em All
  - Task 3: [Hard] Encrypted Server Chit Chat

---

## Challenge Answers Summary

| Task | Challenge Question | Answer |
|---|---|---|
| **Task 1: [Easy] Base64** | What is the final string? | `HackBack2019=` |
| **Task 2: [Medium] Gotta Catch 'em All** | Once you have done all operations, what number do you get (rounded to 2 decimal places at the end of your calculation)? | `344769.12` |
| **Task 3: [Hard] Encrypted Server Chit Chat** | What is the flag? | `THM{eW-sCrIpTiNg-AnD-cRyPtO}` |

---

## Task 1: [Easy] Base64

### Overview
- **Artifact**: `b64_1550406728131.txt` (~33.7 MB)
- **Description**: This file has been Base64 encoded 50 consecutive times. Write a script to retrieve the flag.

### The Math Behind the File Size
Base64 encoding expands raw data by a factor of $\approx 4/3$ per iteration:
$$\text{Encoded Size} \approx \text{Original Size} \times \left(\frac{4}{3}\right)^n$$

For $n = 50$:
$$\left(\frac{4}{3}\right)^{50} \approx 1,765,852.88$$

Dividing the file size (33,715,532 bytes) by $1.76 \times 10^6$ gives $\approx 19$ bytes, yielding the 13-character string:
`HackBack2019=`

### Solution Scripts
- Python solver: [`solve.py`](solve.py)
  ```bash
  python3 solve.py
  ```
- Bash solver: [`solve.sh`](solve.sh)
  ```bash
  ./solve.sh
  ```

---

## Task 2: [Medium] Gotta Catch 'em All

### Overview
- **Target URL**: `http://<machine_ip>:3010`
- **Initial Port**: `1337`
- **Termination Port**: `9765` (Response: `STOP`)
- **Mechanics**:
  1. Each port runs an HTTP web server displaying an instruction in the format:
     `operation number next_port` (e.g. `add 900 23456`)
  2. The calculation begins with an initial total of `0`.
  3. Supported operations: `add`, `minus`, `multiply`, `divide`.
  4. Each port is live for only **4 seconds** before closing and cycling to the next port.
  5. The sequence terminates when port `9765` responds with `STOP`.

### Step-by-Step Calculation Trace

| Step | Port | Server Instruction | Operation | Running Total | Next Port |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **01** | `1337` | `add 900 23456` | $0.0000 + 900.0$ | `900.0000` | `23456` |
| **02** | `23456` | `minus 2 8888` | $900.0000 - 2.0$ | `898.0000` | `8888` |
| **03** | `8888` | `multiply 4 9823` | $898.0000 \times 4.0$ | `3592.0000` | `9823` |
| **04** | `9823` | `divide 2 9887` | $3592.0000 / 2.0$ | `1796.0000` | `9887` |
| **05** | `9887` | `add 456 7823` | $1796.0000 + 456.0$ | `2252.0000` | `7823` |
| **06** | `7823` | `minus 43 10456` | $2252.0000 - 43.0$ | `2209.0000` | `10456` |
| **07** | `10456` | `divide 0.5 10457` | $2209.0000 / 0.5$ | `4418.0000` | `10457` |
| **08** | `10457` | `add 877 40000` | $4418.0000 + 877.0$ | `5295.0000` | `40000` |
| **09** | `40000` | `add 9 40200` | $5295.0000 + 9.0$ | `5304.0000` | `40200` |
| **10** | `40200` | `multiply 34 8743` | $5304.0000 \times 34.0$ | `180336.0000` | `8743` |
| **11** | `8743` | `minus 5 63890` | $180336.0000 - 5.0$ | `180331.0000` | `63890` |
| **12** | `63890` | `divide 1 38721` | $180331.0000 / 1.0$ | `180331.0000` | `38721` |
| **13** | `38721` | `add 43 6632` | $180331.0000 + 43.0$ | `180374.0000` | `6632` |
| **14** | `6632` | `minus 22 29932` | $180374.0000 - 22.0$ | `180352.0000` | `29932` |
| **15** | `29932` | `divide 3 29132` | $180352.0000 / 3.0$ | `60117.3333` | `29132` |
| **16** | `29132` | `multiply 9 8773` | $60117.3333 \times 9.0$ | `541056.0000` | `8773` |
| **17** | `8773` | `minus 1200 1338` | $541056.0000 - 1200.0$ | `539856.0000` | `1338` |
| **18** | `1338` | `add 12 1876` | $539856.0000 + 12.0$ | `539868.0000` | `1876` |
| **19** | `1876` | `divide 1 34232` | $539868.0000 / 1.0$ | `539868.0000` | `34232` |
| **20** | `34232` | `multiply 1 6783` | $539868.0000 \times 1.0$ | `539868.0000` | `6783` |
| **21** | `6783` | `add -100 4040` | $539868.0000 + (-100.0)$ | `539768.0000` | `4040` |
| **22** | `4040` | `multiply -2 5050` | $539768.0000 \times (-2.0)$ | `-1079536.0000` | `5050` |
| **23** | `5050` | `add 300 9898` | $-1079536.0000 + 300.0$ | `-1079236.0000` | `9898` |
| **24** | `9898` | `divide 10 3232` | $-1079236.0000 / 10.0$ | `-107923.6000` | `3232` |
| **25** | `3232` | `minus 10 10321` | $-107923.6000 - 10.0$ | `-107933.6000` | `10321` |
| **26** | `10321` | `add 130 7709` | $-107933.6000 + 130.0$ | `-107803.6000` | `7709` |
| **27** | `7709` | `multiply 4 9872` | $-107803.6000 \times 4.0$ | `-431214.4000` | `9872` |
| **28** | `9872` | `multiply -12 32424` | $-431214.4000 \times (-12.0)$ | `5174572.8000` | `32424` |
| **29** | `32424` | `divide 3 65513` | $5174572.8000 / 3.0$ | `1724857.6000` | `65513` |
| **30** | `65513` | `minus 1000 3459` | $1724857.6000 - 1000.0$ | `1723857.6000` | `3459` |
| **31** | `3459` | `add 23 7832` | $1723857.6000 + 23.0$ | `1723880.6000` | `7832` |
| **32** | `7832` | `divide 5 1111` | $1723880.6000 / 5.0$ | `344776.1200` | `1111` |
| **33** | `1111` | `minus 8 2222` | $344776.1200 - 8.0$ | `344768.1200` | `2222` |
| **34** | `2222` | `add 1 9765` | $344768.1200 + 1.0$ | `344769.1200` | `9765` |
| **End** | `9765` | `STOP` | *Sequence terminated* | **`344769.12`** | — |

### Solution Script
The automated Python solution is available at [`solve_task2.py`](solve_task2.py):
```bash
python3 solve_task2.py <machine_ip>
```

---

## Task 3: [Hard] Encrypted Server Chit Chat

### Overview
- **Protocol / Port**: UDP `4000`
- **Cipher**: AES-GCM (Galois/Counter Mode)
- **Protocol Flow**:
  1. Client sends `hello` to port `4000`. Server responds confirming connection and instructing to send `ready`.
  2. Client sends `ready`. Server returns:
     - AES Key (24 bytes / 192-bit AES): `thisisaverysecretkeyl337`
     - Nonce / IV (12 bytes / 96-bit GCM IV): `secureivl337`
     - Target SHA256 checksum (32 raw bytes):
       `5d77f018d2bf777860548655d84d7382dc27d6ce816ede68f65d72621463d9da`
     - Instruction to send `final` to receive all candidate encrypted flags.
  3. Client sends `final`. Server streams 32 sequential UDP packets containing 16 candidate flags in pairs:
     - `Packet 2n`: Encrypted ciphertext
     - `Packet 2n + 1`: 16-byte GCM authentication tag
  4. In PyCA cryptography (`AESGCM`), decryption takes `ciphertext + tag`.
  5. The decrypted plaintext whose SHA256 matches the target checksum is the authentic flag:
     `THM{eW-sCrIpTiNg-AnD-cRyPtO}`

### Solution Script
The automated Python solution is available at [`solve_task3.py`](solve_task3.py):
```bash
python3 solve_task3.py <machine_ip>
```
