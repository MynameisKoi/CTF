# TryHackMe — Mr. Phisher Write-Up

- **Room**: [Mr. Phisher](https://tryhackme.com/room/mrphisher)
- **Category**: Malware Analysis / Office Macro Deobfuscation
- **Difficulty**: Easy
- **Artifacts**:
  - [`mr-phisher.zip`](./mr-phisher.zip) (`58,947` bytes)
  - [`MrPhisher.docm`](./MrPhisher.docm) (`63,346` bytes)
  - [`solve.py`](./solve.py)

---

## 1. Challenge Overview

> *"Mr. Phisher received a suspicious email with a Word document attached (`MrPhisher.docm`). He claims the document contains nothing malicious, but we suspect there is a hidden macro inside. Uncover the flag hidden within the macro."*

Because the TryHackMe lab machine for this room runs as an isolated GUI instance without inbound SSH credentials, the challenge artifacts (`MrPhisher.docm` and `mr-phisher.zip`) were exfiltrated from the GUI lab VM over the TryHackMe `tun0` VPN network to the Kali Linux analysis environment (`/home/kali/ctf/challenges`) via the Kali CTF Drop Server (`:9000`).

---

## 2. Initial Triage & Unpacking

Inspecting `mr-phisher.zip` confirms it packages `MrPhisher.docm`:

```bash
$ unzip -l mr-phisher.zip
Archive:  mr-phisher.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    63346  2022-01-29 15:48   MrPhisher.docm
---------                     -------
    63346                     1 file
```

Modern Microsoft Office `.docm` (Word Macro-Enabled Document) files are OOXML ZIP archives. Extracting `MrPhisher.docm` reveals the embedded OLE VBA project binary (`word/vbaProject.bin`):

```bash
$ unzip MrPhisher.docm -d docm_extracted
Archive:  MrPhisher.docm
  inflating: docm_extracted/[Content_Types].xml
  inflating: docm_extracted/_rels/.rels
  inflating: docm_extracted/word/document.xml
  inflating: docm_extracted/word/_rels/document.xml.rels
  inflating: docm_extracted/word/vbaProject.bin
  extracting: docm_extracted/word/media/image1.jpeg
  inflating: docm_extracted/word/theme/theme1.xml
  inflating: docm_extracted/word/_rels/vbaProject.bin.rels
  inflating: docm_extracted/word/vbaData.xml
  ...
```

---

## 3. Extracting the VBA Macro (`word/vbaProject.bin`)

Decompressing the MS-OVBA (`[MS-OVBA] 2.4.1`) compressed stream inside `word/vbaProject.bin` recovers the `NewMacros` module:

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

---

## 4. Deobfuscation & Flag Recovery

### How the Macro Works
1. It defines a 38-element array `a` of integers.
2. It loops `i` from `0` to `UBound(a)` (`37`).
3. At each index `i`, it computes `a(i) Xor i`, converts the resulting ASCII code to a character with `Chr(...)`, and appends it to string `b`.

### Solver Script ([`solve.py`](./solve.py))

```python
#!/usr/bin/env python3
"""Deobfuscate the XOR-encoded flag from the MrPhisher.docm VBA macro."""

a = [
    102, 109, 99, 100, 127, 100, 53, 62, 105, 57,
    61, 106, 62, 62, 55, 110, 113, 114, 118, 39,
    36, 118, 47, 35, 32, 125, 34, 46, 46, 124,
    43, 124, 25, 71, 26, 71, 21, 88
]

flag = "".join(chr(a[i] ^ i) for i in range(len(a)))
print(f"Flag: {flag}")
```

Running the solver produces the flag:

```text
$ python3 solve.py
Flag: flag{a39a07a239aacd40c948d852a5c9f8d1}
```

---

## 5. Final Flag

```text
flag{a39a07a239aacd40c948d852a5c9f8d1}
```
