#!/usr/bin/env python3
"""
TryHackMe - Block ('blockroom') SMB Session Key Derivation Script
Calculates the Random Session Key needed to decrypt SMB3 traffic in Wireshark
using NTLMv2 parameters extracted from the PCAP and the user's NT hash.
"""

import hashlib
import hmac

def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Standard RC4 encryption/decryption (symmetric stream cipher)."""
    S = list(range(256))
    j = 0
    out = bytearray()
    
    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
        
    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
        
    return bytes(out)

def derive_smb_session_key(username: str, domain: str, nt_hash_hex: str, ntproofstr_hex: str, enc_session_key_hex: str) -> str:
    """
    Derives the Random Session Key according to MS-NLMP specification:
      1. ResponseKeyNT = HMAC_MD5(NT_Hash, UPPER(Username) + Domain)
      2. KeyExchangeKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
      3. RandomSessionKey = RC4(KeyExchangeKey, EncryptedSessionKey)
    """
    nt_hash = bytes.fromhex(nt_hash_hex)
    user_domain_bytes = (username.upper() + domain).encode("utf-16le")
    
    # Step 1: Calculate ResponseKeyNT
    response_key_nt = hmac.new(nt_hash, user_domain_bytes, hashlib.md5).digest()
    
    # Step 2: Calculate KeyExchangeKey (Session Base Key)
    ntproofstr = bytes.fromhex(ntproofstr_hex)
    key_exchange_key = hmac.new(response_key_nt, ntproofstr, hashlib.md5).digest()
    
    # Step 3: Decrypt the Encrypted Session Key with RC4
    enc_session_key = bytes.fromhex(enc_session_key_hex)
    random_session_key = rc4_crypt(key_exchange_key, enc_session_key)
    
    return random_session_key.hex()

def main():
    print("=" * 65)
    print(" TryHackMe — Block ('blockroom') SMB Session Key Generator")
    print("=" * 65)
    
    users = [
        {
            "name": "mrealman (Question 1-3)",
            "user": "mrealman",
            "domain": "BLOCK",
            "nt_hash": "1f9175a516211660c7a8143b0f36ab44",
            "password": "Blockbuster1",
            "note": "Cracked using rockyou.txt / John the Ripper"
        },
        {
            "name": "eshellstrop (Question 4-6)",
            "user": "eshellstrop",
            "domain": "BLOCK",
            "nt_hash": "3f29138a04aadc19214e9c04028bf381",
            "password": "[Uncracked / Not Needed!]",
            "note": "NTLM session key derivation directly uses the NT hash"
        }
    ]

    for u in users:
        print(f"\n[*] Target: {u['name']}")
        print(f"    - Username: {u['user']}")
        print(f"    - Domain:   {u['domain']}")
        print(f"    - NT Hash:  {u['nt_hash']}")
        print(f"    - Password: {u['password']} ({u['note']})")

    print("\n" + "-" * 65)
    print("Wireshark Decryption Setup:")
    print("1. In Wireshark, go to Edit -> Preferences -> Protocols -> SMB2")
    print("2. Under 'Secret session keys for decryption', click Edit...")
    print("3. Add the Session ID from the packet capture and the corresponding")
    print("   Random Session Key computed via this script.")
    print("4. Decrypted SMB packets will reveal the plaintext SMB2/SMB3 commands.")
    print("5. Go to File -> Export Objects -> SMB... to extract the flag files.")
    print("=" * 65)

if __name__ == "__main__":
    main()
