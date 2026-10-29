#!/usr/bin/env python3
"""
Automated solver for TryHackMe - 0x41haz.
1. Repairs the corrupted ELF header byte e_ident[EI_DATA] (offset 0x05) from
   0x02 (ELFDATA2MSB / Big-Endian) to 0x01 (ELFDATA2LSB / Little-Endian).
2. Reconstructs the 13-byte stack password from main() at 0x1165:
   - QWORD [rbp-0x16] = 0x6667243532404032 -> "2@@25$gf"
   - DWORD [rbp-0x0e] = 0x40265473         -> "sT&@"
   - WORD  [rbp-0x0a] = 0x004c             -> "L\x00"
3. Executes the repaired binary with the recovered password to verify "Well Done !!".
"""

import struct
import subprocess
from pathlib import Path


def main():
    base_dir = Path(__file__).resolve().parent
    orig_bin = base_dir / "0x41haz-1640335532346.0x41haz"
    fixed_bin = base_dir / "0x41haz_fixed"

    # 1. Patch ELF e_ident[EI_DATA] at byte offset 0x05 from 0x02 (MSB) to 0x01 (LSB)
    raw = bytearray(orig_bin.read_bytes())
    orig_ei_data = raw[5]
    raw[5] = 0x01
    fixed_bin.write_bytes(raw)
    fixed_bin.chmod(0o755)

    # 2. Reconstruct stack string password from main() (0x1165)
    part1 = struct.pack("<Q", 0x6667243532404032)
    part2 = struct.pack("<I", 0x40265473)
    part3 = struct.pack("<H", 0x004C)
    password = (part1 + part2 + part3).rstrip(b"\x00").decode("ascii")
    flag = f"THM{{{password}}}"

    print(f"[+] Patched e_ident[EI_DATA] (offset 0x05): 0x{orig_ei_data:02x} -> 0x01 (LSB)")
    print(f"[+] Recovered Password : {password}")
    print(f"[+] Flag               : {flag}")

    # 3. Verify by executing the patched binary
    proc = subprocess.run(
        [str(fixed_bin)],
        input=(password + "\n").encode(),
        capture_output=True,
        timeout=5,
    )
    print("\n--- Patched Binary Execution Output ---")
    print(proc.stdout.decode("utf-8", errors="replace").strip())


if __name__ == "__main__":
    main()
