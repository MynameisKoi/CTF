# TryHackMe — Mr. Phisher (Complete Technical Write-Up)

- **Room**: [Mr. Phisher](https://tryhackme.com/room/mrphisher)
- **Category**: Malware Analysis / Office VBA Macro Deobfuscation (`[MS-OVBA]`)
- **Difficulty**: Easy
- **Artifacts in Repo**:
  - [`mr-phisher.zip`](./mr-phisher.zip) (`58,947` bytes)
  - [`MrPhisher.docm`](./MrPhisher.docm) (`63,346` bytes)
  - [`solve.py`](./solve.py) (Full MS-OVBA stream decompressor + XOR flag decoder)

---

## 1. Environment & Artifact Extraction

In this room, the TryHackMe target machine (`<TARGET_IP>`) is a GUI-only Linux instance containing `MrPhisher.docm` and `mr-phisher.zip` without inbound SSH credentials or an open web server hosting the files.

The challenge artifacts (`MrPhisher.docm` and `mr-phisher.zip`) were transferred from the GUI lab instance to the local analysis workspace for examination.

---

## 2. Step 1 — Unpacking the `.docm` and `.zip` Containers & Strings Triage

First, we extracted `MrPhisher.docm` as a ZIP archive (since Office Open XML `.docm` files are ZIP containers), checked the contents of `mr-phisher.zip`, and ran `strings` on `word/vbaProject.bin`:

### Command Executed
```bash
mkdir -p mrphisher_work \
  && cd mrphisher_work \
  && unzip -o ../MrPhisher.docm -d docm_extracted 2>&1 || true \
  && unzip -l ../mr-phisher.zip 2>&1 || true \
  && strings -n 4 docm_extracted/word/vbaProject.bin 2>/dev/null
```

### Output
```text
total 132
drwxrwxr-x 2 kali kali  4096 Oct 26 18:30 .
drwxrwxr-x 6 kali kali  4096 Oct 26 12:29 ..
-rw-r--r-- 1 kali kali 63346 Oct 26 18:30 MrPhisher.docm
-rw-r--r-- 1 kali kali 58947 Oct 26 18:30 mr-phisher.zip
Archive:  ../MrPhisher.docm
  inflating: docm_extracted/[Content_Types].xml  
  inflating: docm_extracted/_rels/.rels  
  inflating: docm_extracted/word/document.xml  
  inflating: docm_extracted/word/_rels/document.xml.rels  
  inflating: docm_extracted/word/vbaProject.bin  
 extracting: docm_extracted/word/media/image1.jpeg  
  inflating: docm_extracted/word/theme/theme1.xml  
  inflating: docm_extracted/word/_rels/vbaProject.bin.rels  
  inflating: docm_extracted/word/vbaData.xml  
  inflating: docm_extracted/word/settings.xml  
  inflating: docm_extracted/word/styles.xml  
  inflating: docm_extracted/word/webSettings.xml  
  inflating: docm_extracted/word/fontTable.xml  
  inflating: docm_extracted/docProps/core.xml  
  inflating: docm_extracted/docProps/app.xml  
Archive:  ../mr-phisher.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    63346  2022-01-29 15:48   MrPhisher.docm
---------                     -------
    63346                     1 file
Attribut
e VB_Nam
e = "Thi
sDocumen
...
Attribut
e VB_Nam
e = "New
Macros"
Sub For
mat()
im a
 b A
pArray(
102, 109
53, B6
>5, 5
*6Z1
+114
18, 3
0 To UB@ound(a
	b & Chr
(a(i) Xo
Next@
End 
...
[Workspace]
ThisDocument=0, 0, 0, 0, C
NewMacros=26, 26, 1614, 711,
```

### What `strings` Revealed
1. `mr-phisher.zip` simply wraps the exact same `63,346`-byte `MrPhisher.docm` file.
2. Inside `docm_extracted/word/vbaProject.bin`, there are two VBA modules: `ThisDocument` and `NewMacros`.
3. Because `vbaProject.bin` compresses VBA source code using Microsoft's **MS-OVBA LZ-based compression algorithm (`[MS-OVBA] Section 2.4.1`)**, `strings` only shows fragmented tokens (`Attribut`, `e VB_Nam`, `Sub For`, `pArray(`, `102, 109`, `0 To UB@ound(a`, `b & Chr`, `(a(i) Xo`) interleaved with LZ copy-token flag bytes.

---

## 3. Step 2 — Writing a Custom MS-OVBA Decompressor in Python

Since `oletools`/`olevba` was not pre-installed on the VM, we implemented the `[MS-OVBA] 2.4.1` decompression algorithm directly in Python to reconstruct the exact uncompressed VBA source stream from `vbaProject.bin`.

### Initial Attempt & Debugging (`ThisDocument` vs `NewMacros`)

In our first pass, we searched for the first occurrence of `b"Attribut"` (`data.find(b"Attribut")`) and used `bit_count = max(4, decompressed_cur.bit_length())`:

```python
idx = data.find(b"Attribut")
# Compressed container starts 3 bytes before "Attribut" (0x01 + 2-byte chunk header + flag byte)
for start in range(max(0, idx - 10), idx):
    if data[start] == 0x01:
        dec = decompress_ovba(data[start:])
```

That first attempt exited with:
```text
Traceback (most recent call last):
  File "<string>", line 51, in <module>
    dec = decompress_ovba(data[start:])
  File "<string>", line 44, in decompress_ovba
    out.append(out[-offset])
               ~~~^^^^^^^^^
IndexError: bytearray index out of range
```

**Why it failed**:
1. `data.find(b"Attribut")` only matched the **first** module (`ThisDocument`), not the second module (`NewMacros`) where `Sub Format()` lives.
2. Per `[MS-OVBA] 2.4.1.3.19.1` (*CopyToken Help*), the bit length is computed from `ceil(log2(decompressed_current))`, which in integer arithmetic is `(decompressed_cur - 1).bit_length()` (clamped to a minimum of `4` bits), and each compressed chunk header carries a 3-bit signature `0b011` (`chunk_sig = (header >> 12) & 0x07`).

---

## 4. Step 3 — Full MS-OVBA Extraction & Automatic XOR Flag Decoding

Fixing the bit-count calculation (`max(4, (decompressed_cur - 1).bit_length())`), checking `chunk_sig == 0b011`, and iterating over **all** `b"Attribut"` matches (`re.finditer(b"Attribut", data)`) cleanly decompressed the `NewMacros` stream and decoded the flag in one shot:

### Command Executed
```bash
python3 -c '
import re

data = open("mrphisher_work/docm_extracted/word/vbaProject.bin", "rb").read()

def decompress_ovba(stream: bytes) -> bytes:
    out = bytearray()
    pos = 0
    if not stream or stream[pos] != 0x01:
        return b""
    pos += 1
    while pos + 2 <= len(stream):
        header = int.from_bytes(stream[pos:pos+2], "little")
        pos += 2
        chunk_size = (header & 0x0FFF) + 3
        chunk_sig = (header >> 12) & 0x07
        if chunk_sig != 0b011:
            break
        chunk_compressed = (header >> 15) & 0x01
        chunk_end = min(len(stream), pos + chunk_size - 2)
        if not chunk_compressed:
            out.extend(stream[pos:pos+4096])
            pos += 4096
            continue
        chunk_start = len(out)
        while pos < chunk_end:
            flag_byte = stream[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if ((flag_byte >> bit) & 1) == 0:
                    out.append(stream[pos])
                    pos += 1
                else:
                    if pos + 2 > chunk_end:
                        pos = chunk_end
                        break
                    token = int.from_bytes(stream[pos:pos+2], "little")
                    pos += 2
                    decompressed_cur = len(out) - chunk_start
                    bit_count = max(4, (decompressed_cur - 1).bit_length())
                    len_mask = 0xFFFF >> bit_count
                    off_mask = (~len_mask) & 0xFFFF
                    length = (token & len_mask) + 3
                    offset = ((token & off_mask) >> (16 - bit_count)) + 1
                    for _ in range(length):
                        out.append(out[-offset])
    return bytes(out)

for m in re.finditer(b"Attribut", data):
    idx = m.start()
    for start in range(max(0, idx - 6), idx):
        if data[start] == 0x01:
            try:
                dec = decompress_ovba(data[start:])
                text = dec.decode("latin1", errors="ignore")
                if "Sub Format" in text:
                    print("=== EXTRACTED VBA MACRO ===")
                    print(text)
                    arr_match = re.search(r"Array\(([^)]+)\)", text)
                    if arr_match:
                        nums = [int(x.strip()) for x in arr_match.group(1).split(",")]
                        flag = "".join(chr(nums[i] ^ i) for i in range(len(nums)))
                        print("\n=== DECODED FLAG ===")
                        print(flag)
            except Exception as e:
                pass
'
```

### Output
```text
=== EXTRACTED VBA MACRO ===
Attribute VB_Name = "NewMacros"
Sub Format()
Dim a()
Dim b As String
a = Array(102, 109, 99, 100, 127, 100, 53, 62, 105, 57, 61, 106, 62, 62, 55, 110, 113, 114, 118, 39, 36, 118, 47, 35, 32, 125, 34, 46, 46, 124, 43, 124, 25, 71, 26, 71, 21, 88)
For i = 0 To UBound(a)
b = b & Chr(a(i) Xor i)
Next
End Sub


=== DECODED FLAG ===
flag{a39a07a239aacd40c948d852a5c9f8d1}
```

---

## 5. How the Macro Obfuscation Works

Looking at the recovered `NewMacros` VBA code:

```vb
Attribute VB_Name = "NewMacros"
Sub Format()
Dim a()
Dim b As String
a = Array(102, 109, 99, 100, 127, 100, 53, 62, 105, 57, 61, 106, 62, 62, 55, 110, 113, 114, 118, 39, 36, 118, 47, 35, 32, 125, 34, 46, 46, 124, 43, 124, 25, 71, 26, 71, 21, 88)
For i = 0 To UBound(a)
b = b & Chr(a(i) Xor i)
Next
End Sub
```

1. Each character at 0-based position `i` (`0 <= i <= 37`) is XOR-encoded with its own array index `i`:
   - `i = 0`: `102 ^ 0 = 102` → `'f'`
   - `i = 1`: `109 ^ 1 = 108` → `'l'`
   - `i = 2`: `99 ^ 2 = 97` → `'a'`
   - `i = 3`: `100 ^ 3 = 103` → `'g'`
   - `i = 4`: `127 ^ 4 = 123` → `'{'`
2. The macro builds the string `b` in memory (`b = b & Chr(a(i) Xor i)`) without ever displaying or printing it.
3. Reversing the loop in Python (`''.join(chr(a[i] ^ i) for i in range(len(a)))`) reveals the complete flag:

```text
flag{a39a07a239aacd40c948d852a5c9f8d1}
```
