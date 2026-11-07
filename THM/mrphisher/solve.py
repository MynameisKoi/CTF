#!/usr/bin/env python3
"""
End-to-End MS-OVBA Stream Decompressor & Flag Decoder for TryHackMe - Mr. Phisher.
1. Reads word/vbaProject.bin directly from MrPhisher.docm (ZIP container).
2. Locates all MS-OVBA compressed streams (prefixed with 0x01 container signature
   before the compressed "Attribute VB_Name" header).
3. Decompresses each stream per the [MS-OVBA] 2.4.1 specification.
4. Extracts the 'NewMacros' -> 'Sub Format()' array and XOR-decodes the flag.
"""

import re
import zipfile
from pathlib import Path


def decompress_ovba(stream: bytes) -> bytes:
    """Decompress an MS-OVBA (2.4.1) compressed byte stream."""
    out = bytearray()
    pos = 0
    if not stream or stream[pos] != 0x01:
        return b""
    pos += 1
    while pos + 2 <= len(stream):
        header = int.from_bytes(stream[pos:pos + 2], "little")
        pos += 2
        chunk_size = (header & 0x0FFF) + 3
        chunk_sig = (header >> 12) & 0x07
        if chunk_sig != 0b011:
            break
        chunk_compressed = (header >> 15) & 0x01
        chunk_end = min(len(stream), pos + chunk_size - 2)
        if not chunk_compressed:
            out.extend(stream[pos:pos + 4096])
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
                    token = int.from_bytes(stream[pos:pos + 2], "little")
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


def main():
    docm_path = Path(__file__).resolve().parent / "MrPhisher.docm"
    with zipfile.ZipFile(docm_path, "r") as zf:
        data = zf.read("word/vbaProject.bin")

    for m in re.finditer(b"Attribut", data):
        idx = m.start()
        for start in range(max(0, idx - 6), idx):
            if data[start] == 0x01:
                try:
                    dec = decompress_ovba(data[start:])
                    text = dec.decode("latin1", errors="ignore")
                    if "Sub Format" in text:
                        print("=== EXTRACTED VBA MACRO ===")
                        print(text.strip())
                        arr_match = re.search(r"Array\(([^)]+)\)", text)
                        if arr_match:
                            nums = [int(x.strip()) for x in arr_match.group(1).split(",")]
                            flag = "".join(chr(nums[i] ^ i) for i in range(len(nums)))
                            print("\n=== DECODED FLAG ===")
                            print(flag)
                        return
                except Exception:
                    pass


if __name__ == "__main__":
    main()
