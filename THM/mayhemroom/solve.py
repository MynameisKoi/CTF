#!/usr/bin/env python3
"""
Automated DFIR solver for TryHackMe - Mayhem Room (Havoc C2 PCAP Analysis).
Extracts traffic.pcapng from evidence-1700022726858.zip, reassembles TCP streams,
recovers the initial PowerShell stager (install.ps1) and Havoc Demon AES-256-CTR
key/IV from the initial registration packet, decrypts all C2 requests and responses,
and prints all challenge answers.
"""

import re
import struct
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def reassemble_tcp_streams(pcapng_bytes: bytes) -> dict:
    """
    Parses PCAPNG Enhanced Packet Blocks (0x00000006) and reassembles TCP streams
    ordered by TCP sequence number.
    """
    offset = 0
    n = len(pcapng_bytes)
    streams = {}

    while offset + 8 <= n:
        block_type, block_len = struct.unpack_from("<II", pcapng_bytes, offset)
        if block_len < 12 or offset + block_len > n:
            break
        if block_type == 0x00000006:  # Enhanced Packet Block
            cap_len = struct.unpack_from("<I", pcapng_bytes, offset + 20)[0]
            raw = pcapng_bytes[offset + 28 : offset + 28 + cap_len]
            if len(raw) >= 54 and raw[12:14] == b"\x08\x00" and raw[23] == 6:
                ihl = (raw[14] & 0x0F) * 4
                src = ".".join(str(b) for b in raw[26:30])
                dst = ".".join(str(b) for b in raw[30:34])
                tstart = 14 + ihl
                sport, dport, seq = struct.unpack_from(">HHI", raw, tstart)
                thl = ((raw[tstart + 12] >> 4) & 0x0F) * 4
                payload = raw[tstart + thl :]
                if payload:
                    key = (src, sport, dst, dport)
                    streams.setdefault(key, {})[seq] = payload
        offset += block_len

    return {
        k: b"".join(segs[s] for s in sorted(segs))
        for k, segs in streams.items()
    }


def extract_http_bodies(stream_bytes: bytes) -> list[bytes]:
    """
    Extracts HTTP message bodies from a reassembled TCP stream.
    """
    bodies = []
    msgs = re.split(
        rb"(?:POST|GET) [^\r\n]+ HTTP/1\.[01]\r\n|HTTP/1\.[01] \d+ [^\r\n]+\r\n",
        stream_bytes,
    )[1:]
    for msg in msgs:
        if b"\r\n\r\n" not in msg:
            continue
        hdr_bytes, body = msg.split(b"\r\n\r\n", 1)
        hdr = hdr_bytes.decode("latin-1", errors="replace")
        m = re.search(r"Content-Length:\s*(\d+)", hdr, re.IGNORECASE)
        if m:
            body = body[: int(m.group(1))]
        elif "Transfer-Encoding: chunked" in hdr:
            # Simple HTTP chunked decoding
            out = bytearray()
            pos = 0
            while pos < len(body):
                line_end = body.find(b"\r\n", pos)
                if line_end == -1:
                    break
                clen = int(body[pos:line_end], 16)
                if clen == 0:
                    break
                out.extend(body[line_end + 2 : line_end + 2 + clen])
                pos = line_end + 2 + clen + 2
            body = bytes(out)
        bodies.append(body)
    return bodies


def main():
    base_dir = Path(__file__).resolve().parent
    zip_path = base_dir / "evidence-1700022726858.zip"
    pcap_path = base_dir / "traffic.pcapng"

    if not pcap_path.exists():
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(base_dir)

    streams = reassemble_tcp_streams(pcap_path.read_bytes())

    # 1. Extract initial PowerShell stager (install.ps1 on port 1337)
    stager_ps1 = ""
    for (src, sport, dst, dport), buf in streams.items():
        if src == "10.0.2.37" and sport == 1337 and b"Invoke-WebRequest" in buf:
            bodies = extract_http_bodies(buf)
            if bodies:
                stager_ps1 = bodies[0].decode("utf-8", errors="replace").strip()

    # 2. Extract and decrypt Havoc C2 streams on port 80 across all ephemeral ports
    client_bodies = []
    server_bodies = []
    for (src, sport, dst, dport), buf in streams.items():
        if src == "10.0.2.38" and dport == 80:
            client_bodies.extend(extract_http_bodies(buf))
        elif src == "10.0.2.37" and sport == 80:
            server_bodies.extend(extract_http_bodies(buf))

    aes_key = None
    aes_iv = None
    agent_id = None
    decrypted_chunks = []

    for body in client_bodies:
        if len(body) >= 20 and body[4:8] == b"\xde\xad\xbe\xef":
            agent_id = body[8:12].hex()
            cmd_id = struct.unpack(">I", body[12:16])[0]
            if cmd_id == 0x63:  # DEMON_INIT (99)
                aes_key = body[20:52]
                aes_iv = body[52:68]
                pt = aes_ctr_decrypt(aes_key, aes_iv, body[68:])
                decrypted_chunks.append(("Agent -> C2 (INIT)", pt))
            elif aes_key and len(body) > 20:
                pt = aes_ctr_decrypt(aes_key, aes_iv, body[20:])
                decrypted_chunks.append(("Agent -> C2", pt))

    for body in server_bodies:
        if aes_key and len(body) > 12:
            pt = aes_ctr_decrypt(aes_key, aes_iv, body[12:])
            decrypted_chunks.append(("C2 -> Agent", pt))

    full_text = "\n".join(
        f"[{direction}]\n"
        + "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "" for b in pt)
        for direction, pt in decrypted_chunks
    )

    sid_match = re.search(r"CLIENTSERVER\\paco\s+(S-1-5-21-[\d-]+)", full_text)
    ipv6_match = re.search(r"Link-local IPv6 Address[ .]+:\s*([^\r\n]+)", full_text)
    echo_flag_match = re.search(r"THM\{HavOc_C2_[^}]+\}", full_text)
    user_match = re.search(r"net user\s+(\S+)\s+(\S+)\s+/add", full_text)
    file_path_match = re.search(r"type\s+(C:\\Users\\[^\r\n]+\.csv)", full_text)
    csv_flag_match = re.search(r"THM\{I_Can_SEE_[^}]+\}", full_text)

    print("=" * 72)
    print("TryHackMe - Mayhem Room (Havoc C2 DFIR Analysis)")
    print("=" * 72)
    print(f"[+] Initial Stager (install.ps1):\n    {stager_ps1}\n")
    print(f"[+] Havoc Demon Agent ID    : {agent_id}")
    print(f"[+] Havoc Demon AES-256 Key : {aes_key.hex()}")
    print(f"[+] Havoc Demon AES-128 IV  : {aes_iv.hex()}\n")
    print("-" * 72)
    print(f"Q1. Compromised SID         : {sid_match.group(1) if sid_match else 'N/A'}")
    print(f"Q2. Link-local IPv6 Address : {ipv6_match.group(1) if ipv6_match else 'N/A'}")
    print(f"Q3. Printed Flag            : {echo_flag_match.group(0) if echo_flag_match else 'N/A'}")
    if user_match:
        print(f"Q4. Persistence Account     : {user_match.group(1)}:{user_match.group(2)}")
    print(f"Q5. Exfiltrated File Path   : {file_path_match.group(1) if file_path_match else 'N/A'}")
    print(f"    Exfiltrated File Flag   : {csv_flag_match.group(0) if csv_flag_match else 'N/A'}")
    print("=" * 72)


if __name__ == "__main__":
    main()
