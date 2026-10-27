#!/usr/bin/env python3
"""
Automated solver for TryHackMe - Classic Passwd.
1. Statically decodes the stack string password ('AGB6js5d9dkG7') and integer constants
   (0x638a78 = 6523512, 0x2130 = 8496) from Challenge_1609966715991.Challenge.
2. Executes the binary with the recovered password to verify the flag output.
"""

import struct
import subprocess
from pathlib import Path


def main():
    bin_path = Path(__file__).resolve().parent / "Challenge_1609966715991.Challenge"
    bin_path.chmod(0o755)

    # 1. Reconstruct stack password from sym.vuln immediate values
    part1 = struct.pack("<Q", 0x6435736A36424741)
    part2 = struct.pack("<I", 0x476B6439)
    part3 = struct.pack("<H", 0x0037)
    password = (part1 + part2 + part3).rstrip(b"\x00").decode("ascii")

    # 2. Reconstruct flag from sym.gfl loop targets (0x638a78 and 0x2130)
    val1 = 0x638A78
    val2 = 0x2130
    static_flag = f"THM{{{val1}{val2}}}"

    print(f"[+] Recovered Password: {password}")
    print(f"[+] Static Flag:        {static_flag}")

    # 3. Verify by running the binary
    proc = subprocess.run(
        [str(bin_path)],
        input=(password + "\n").encode(),
        capture_output=True,
        timeout=5,
    )
    print("\n--- Binary Execution Output ---")
    print(proc.stdout.decode("utf-8", errors="replace").strip())


if __name__ == "__main__":
    main()
