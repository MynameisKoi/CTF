# TryHackMe: Scripting - Task 1: [Easy] Base64

## Overview

- **Room**: Scripting
- **Task**: 1 - [Easy] Base64
- **Platform**: TryHackMe
- **Artifact**: `b64_1550406728131.txt` (~33.7 MB)
- **Challenge Description**: This file has been Base64 encoded 50 consecutive times. Write a script to retrieve the flag.

---

## Challenge Answer

| Challenge / Question | Answer |
|---|---|
| What is the final string? | `HackBack2019=` |

---

## Technical Analysis

### 1. The Math Behind the File Size

Base64 encoding represents binary data using an ASCII character set, expanding the data size by approximately a factor of $4/3$ (~133.3%):

$$\text{Encoded Size} \approx \text{Original Size} \times \left(\frac{4}{3}\right)^n$$

For $n = 50$ iterations:
$$\left(\frac{4}{3}\right)^{50} \approx 1,765,852.88$$

Given an initial file size of **33,715,532 bytes** (~33.7 MB), peeling back 50 layers reveals an original payload of:
$$\frac{33,715,532}{1,765,852.88} \approx 19 \text{ bytes}$$

Indeed, the 50th decode produces the 13-character flag string:
`HackBack2019=`

---

## Implementations

### General Methodology
1. **Read input from the file**: Load the initial Base64 text.
2. **Define a decoding function**: Isolate the Base64 decode logic into a dedicated function.
3. **Execute in a loop**: Repeat the decoding function for 50 iterations.

---

### Python Implementation ([`solve.py`](solve.py))

```python
#!/usr/bin/env python3
import sys
import base64
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent / "b64_1550406728131.txt"

def decode_base64(data: bytes) -> bytes:
    """Decodes a single layer of base64 data."""
    return base64.b64decode(data.strip())

def solve(input_path: Path, iterations: int = 50) -> str:
    """Reads input file and repeatedly applies base64 decoding."""
    with open(input_path, "rb") as f:
        data = f.read()

    for i in range(1, iterations + 1):
        data = decode_base64(data)

    return data.decode("utf-8", errors="replace").strip()

if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FILE
    flag = solve(target, iterations=50)
    print(f"Final Decoded String: {flag}")
```

#### Run:
```bash
python3 solve.py
```

---

### Bash Implementation ([`solve.sh`](solve.sh))

A streaming pipeline dynamically built in Bash streams the data through 50 decoding stages without disk I/O bottlenecks:

```bash
#!/usr/bin/env bash
set -euo pipefail

INPUT_FILE="${1:-"b64_1550406728131.txt"}"

decode_base64() {
    base64 -d
}

# Construct a 50-stage pipeline
cmd="cat \"$INPUT_FILE\""
for i in {1..50}; do
    cmd="$cmd | decode_base64"
done

final_string=$(eval "$cmd")
echo "Final Decoded String: $final_string"
```

#### Run:
```bash
chmod +x solve.sh
./solve.sh
```
