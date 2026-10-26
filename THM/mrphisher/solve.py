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
