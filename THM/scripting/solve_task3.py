#!/usr/bin/env python3
"""
TryHackMe - Scripting (Task 3: [Hard] Encrypted Server Chit Chat)
Communicates with an encrypted UDP server on port 4000 using PyCA cryptography (AES-GCM):
  1. Sends UDP 'hello' packet to establish connection.
  2. Sends 'ready' packet to receive encryption parameters (Key, IV, and target SHA256 checksum).
  3. Sends 'final' packet to receive candidate encrypted flags.
  4. Pairs sequential ciphertext and GCM authentication tag packets.
  5. Decrypts using AES-GCM and verifies SHA256 checksum to identify the valid flag.

Usage:
  python3 solve_task3.py [target_ip]
"""

import sys
import socket
import hashlib
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_IP = "10.146.186.83"
PORT = 4000

def solve(target_ip: str) -> str:
    print(f"[*] Connecting to UDP server at {target_ip}:{PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5.0)

    # Step 1: Handshake
    s.sendto(b"hello", (target_ip, PORT))
    resp1, _ = s.recvfrom(4096)
    print(f"[+] Server response: {resp1.decode(errors='replace')}")

    # Step 2: Request encryption parameters
    s.sendto(b"ready", (target_ip, PORT))
    info, _ = s.recvfrom(4096)
    print(f"[+] Parameter payload received ({len(info)} bytes)")

    key_match = re.search(rb"key:(\S+)", info)
    iv_match = re.search(rb"iv:(\S+)", info)
    if not key_match or not iv_match:
        raise ValueError("Could not parse Key and IV from server response")

    key = key_match.group(1)
    iv = iv_match.group(1)

    chk_prefix = b"checksum of "
    chk_idx = info.find(chk_prefix) + len(chk_prefix)
    expected_checksum = info[chk_idx : chk_idx + 32]

    print(f"[*] AES-GCM Key: {key.decode()} ({len(key)} bytes)")
    print(f"[*] Nonce / IV:  {iv.decode()} ({len(iv)} bytes)")
    print(f"[*] Target SHA256: {expected_checksum.hex()}")

    # Step 3: Request encrypted candidate flags
    s.sendto(b"final", (target_ip, PORT))
    packets = []
    while True:
        try:
            pkt, _ = s.recvfrom(4096)
            packets.append(pkt)
        except socket.timeout:
            break
    s.close()

    print(f"[*] Received {len(packets)} raw packets ({len(packets) // 2} candidate pairs)")

    aesgcm = AESGCM(key)
    valid_flag = ""

    # Step 4 & 5: Decrypt pairs of (ciphertext, tag) and verify checksum
    for i in range(0, len(packets), 2):
        ciphertext = packets[i]
        tag = packets[i + 1]
        data = ciphertext + tag

        try:
            plaintext = aesgcm.decrypt(iv, data, None)
            h = hashlib.sha256(plaintext).digest()
            is_target = (h == expected_checksum)

            flag_str = plaintext.decode("utf-8", errors="replace")
            print(f"    [{i // 2:02d}] Decrypted: {flag_str} | Target Match: {is_target}")

            if is_target:
                valid_flag = flag_str
        except Exception as e:
            print(f"    [{i // 2:02d}] Decryption failed: {e}")

    return valid_flag

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IP
    flag = solve(target_ip)
    print("=" * 55)
    print(f"[+] Final Flag: {flag}")
    print("=" * 55)

if __name__ == "__main__":
    main()
