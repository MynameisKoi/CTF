#!/usr/bin/env python3
"""
TryHackMe - Chrome (chromefiles-1697949492677.zip) Automated Forensics Solver
End-to-end automated pipeline:
  1. Parses traffic.pcapng inside chromefiles-1697949492677.zip to reconstruct
     the SMB2 client->server stream and extract transfer.exe and encrypted_files.
  2. Extracts the hardcoded AES-256-CBC key & IV from transfer.exe and decrypts
     encrypted_files into an in-memory ZIP archive (files.zip).
  3. Extracts the user's DPAPI MasterKey file and decrypts the 64-byte MasterKey
     using the cracked password ("bubbles").
  4. Extracts Chrome's Local State os_crypt.encrypted_key and decrypts the DPAPI
     blob using the MasterKey to obtain Chrome's 32-byte AES-256-GCM key.
  5. Queries Chrome's Default/Login Data SQLite database and decrypts all saved
     credentials, outputting the answers to all 5 room questions.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import re
import sqlite3
import struct
import tempfile
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ZIP_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "chromefiles-1697949492677.zip"
)


def defang_url(url: str) -> str:
    """Fully defang URL per TryHackMe format (e.g. hxxps[://]mysecuresite[.]thm/)."""
    url = re.sub(r"^https://", "hxxps[://]", url, flags=re.IGNORECASE)
    url = re.sub(r"^http://", "hxxp[://]", url, flags=re.IGNORECASE)
    return url.replace(".", "[.]")


def reassemble_smb_client_stream(pcapng_bytes: bytes) -> bytes:
    """Reassemble TCP stream from client -> SMB server (dst_port 445) in pcapng."""
    offset = 0
    n = len(pcapng_bytes)
    segments = {}

    while offset + 8 <= n:
        block_type, block_len = struct.unpack_from("<II", pcapng_bytes, offset)
        if block_len < 12 or offset + block_len > n:
            break
        if block_type == 6:  # Enhanced Packet Block (EPB)
            cap_len = struct.unpack_from("<I", pcapng_bytes, offset + 20)[0]
            pkt = pcapng_bytes[offset + 28 : offset + 28 + cap_len]
            if len(pkt) >= 54 and struct.unpack_from("!H", pkt, 12)[0] == 0x0800:
                ip_hdr = pkt[14:]
                ihl = (ip_hdr[0] & 0x0F) * 4
                if ip_hdr[9] == 6:  # TCP
                    tcp_hdr = ip_hdr[ihl:]
                    src_port, dst_port, seq = struct.unpack_from("!HHI", tcp_hdr, 0)
                    doff = ((tcp_hdr[12] >> 4) & 0x0F) * 4
                    payload = tcp_hdr[doff:]
                    if dst_port == 445 and payload:
                        segments[seq] = payload
        offset += block_len

    return b"".join(segments[s] for s in sorted(segments))


def extract_smb_files_from_stream(pcapng_bytes: bytes, stream: bytes):
    """Extract AES key/IV from transfer.exe and reconstruct encrypted_files from SMB2 WRITEs."""
    m_keys = re.search(
        b"\x41((?:[A-Za-z0-9]\x00){32})\x00\x21((?:[A-Za-z0-9]\x00){16})",
        pcapng_bytes,
    )
    if not m_keys:
        raise RuntimeError("Could not locate AES key and IV in transfer.exe stream")
    aes_key = m_keys.group(1).decode("utf-16le").encode("ascii")
    aes_iv = m_keys.group(2).decode("utf-16le").encode("ascii")

    # First 16-byte ciphertext block of encrypted_files (encrypting ZIP magic PK\x03\x04...)
    first_pt = b"PK\x03\x04\n\x00\x00\x00\x00\x00\xd1\x8c\x94U\x00\x00"
    first_ct = (
        Cipher(algorithms.AES(aes_key), modes.ECB())
        .encryptor()
        .update(bytes(a ^ b for a, b in zip(first_pt, aes_iv)))
    )

    # Locate the first SMB2 Write Request for encrypted_files and collect all writes for its FileId
    start_idx = stream.find(first_ct)
    if start_idx == -1:
        raise RuntimeError("Could not locate encrypted_files in SMB2 stream")

    # SMB2 header starts 112 bytes (0x70 DataOffset) before the write payload
    smb_hdr_start = start_idx - 0x70
    target_file_id = stream[smb_hdr_start + 64 + 16 : smb_hdr_start + 64 + 32]

    # Walk NBSS frames from the beginning of that NBSS record
    pos = smb_hdr_start - 4
    n = len(stream)
    writes = {}
    while pos + 4 <= n:
        if stream[pos] != 0x00:
            break
        nbss_len = struct.unpack_from(">I", stream, pos)[0] & 0x00FFFFFF
        if pos + 4 + nbss_len > n:
            break
        smb = stream[pos + 4 : pos + 4 + nbss_len]
        if smb[:4] == b"\xfeSMB":
            cmd = struct.unpack_from("<H", smb, 12)[0]
            if cmd == 9:  # SMB2 WRITE Request
                data_offset, write_len, file_offset = struct.unpack_from(
                    "<HIQ", smb, 64 + 2
                )
                file_id = smb[64 + 16 : 64 + 32]
                if file_id == target_file_id:
                    writes[file_offset] = smb[data_offset : data_offset + write_len]
        pos += 4 + nbss_len

    encrypted_files = b"".join(writes[o] for o in sorted(writes))
    return aes_key, aes_iv, encrypted_files


def dpapi_decrypt_masterkey(mk_file_bytes: bytes, sid: str, password: str) -> bytes:
    """Decrypt a Windows DPAPI v2 MasterKey file using user SID and password."""
    mk_len = struct.unpack_from("<Q", mk_file_bytes, 96)[0]
    mk_blob = mk_file_bytes[128 : 128 + mk_len]
    ver, salt, rounds, halgo, calgo = struct.unpack_from("<I16sIII", mk_blob, 0)
    ciphertext = mk_blob[32:]

    pwd_hash = hashlib.sha1(password.encode("utf-16le")).digest()
    user_key = hmac.new(
        pwd_hash, (sid + "\x00").encode("utf-16le"), hashlib.sha1
    ).digest()

    # Windows DPAPI custom PBKDF2-HMAC-SHA512
    block = hmac.new(user_key, salt + struct.pack(">I", 1), hashlib.sha512).digest()
    acc = bytearray(block)
    for _ in range(1, rounds):
        block = hmac.new(user_key, bytes(acc), hashlib.sha512).digest()
        for i in range(64):
            acc[i] ^= block[i]
    derived = bytes(acc)

    aes_key = derived[:32]
    aes_iv = derived[32:48]
    plain = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv)).decryptor().update(ciphertext)
    return plain[-64:]


def dpapi_decrypt_blob(blob_bytes: bytes, masterkey: bytes) -> bytes:
    """Decrypt a DPAPI blob (AES-256-CBC / SHA-512) using the 64-byte MasterKey."""
    pos = 4 + 16 + 4 + 16 + 4
    desc_len = struct.unpack_from("<I", blob_bytes, pos)[0]
    pos += 4 + desc_len
    calgo, calgo_len, salt_len = struct.unpack_from("<III", blob_bytes, pos)
    pos += 12
    salt = blob_bytes[pos : pos + salt_len]
    pos += salt_len
    hmac_key_len = struct.unpack_from("<I", blob_bytes, pos)[0]
    pos += 4 + hmac_key_len
    halgo, halgo_len, hmac2_len = struct.unpack_from("<III", blob_bytes, pos)
    pos += 12 + hmac2_len
    cipher_len = struct.unpack_from("<I", blob_bytes, pos)[0]
    pos += 4
    ciphertext = blob_bytes[pos : pos + cipher_len]

    session_key = hmac.new(
        hashlib.sha1(masterkey).digest(), salt, hashlib.sha512
    ).digest()
    aes_key = session_key[:32]
    aes_iv = b"\x00" * 16
    plain = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv)).decryptor().update(ciphertext)
    pad_len = plain[-1]
    return plain[:-pad_len]


def main():
    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        pcapng_bytes = zf.read("traffic.pcapng")

    stream = reassemble_smb_client_stream(pcapng_bytes)
    aes_key, aes_iv, encrypted_files = extract_smb_files_from_stream(
        pcapng_bytes, stream
    )

    # Decrypt encrypted_files -> files.zip
    decrypted_zip_bytes = (
        Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
        .decryptor()
        .update(encrypted_files)
    )

    first_password = "bubbles"
    sid = "S-1-5-21-3854677062-280096443-3674533662-1001"
    mk_rel_path = f"AppData/Roaming/Microsoft/Protect/{sid}/8c6b6187-8eaa-48bd-be16-98212a441580"
    local_state_path = "AppData/Local/Google/Chrome/User Data/Local State"
    login_data_path = "AppData/Local/Google/Chrome/User Data/Default/Login Data"

    with zipfile.ZipFile(io.BytesIO(decrypted_zip_bytes), "r") as inner_zip:
        mk_file_bytes = inner_zip.read(mk_rel_path)
        local_state = json.loads(inner_zip.read(local_state_path).decode("utf-8"))
        login_data_bytes = inner_zip.read(login_data_path)

    masterkey = dpapi_decrypt_masterkey(mk_file_bytes, sid, first_password)
    enc_chrome_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    chrome_aes_key = dpapi_decrypt_blob(enc_chrome_key, masterkey)

    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        tmp_db.write(login_data_bytes)
        tmp_db.flush()
        conn = sqlite3.connect(tmp_db.name)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, origin_url, username_value, password_value FROM logins ORDER BY id"
        )
        rows = cur.fetchall()
        conn.close()

    entries = {}
    for row_id, origin_url, username, pw_blob in rows:
        nonce = pw_blob[3:15]
        ct_tag = pw_blob[15:]
        pw_plain = AESGCM(chrome_aes_key).decrypt(nonce, ct_tag, None).decode("utf-8")
        entries[row_id] = (origin_url, defang_url(origin_url), username, pw_plain)

    print("=" * 75)
    print("TryHackMe: Chrome (chromefiles-1697949492677.zip) — Answers")
    print("=" * 75)
    print(f"Q1 - First password found          : {first_password}")
    print(f"Q2 - First index URL (defanged)    : {entries[1][1]}")
    print(f"Q3 - First index password          : {entries[1][3]}")
    print(f"Q4 - Second index URL (defanged)   : {entries[2][1]}")
    print(f"Q5 - Second index password         : {entries[2][3]}")
    print("=" * 75)


if __name__ == "__main__":
    main()
