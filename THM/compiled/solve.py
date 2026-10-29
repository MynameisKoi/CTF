#!/usr/bin/env python3
"""
Automated solver for TryHackMe - Compiled.
1. Extracts the scanf format string at 0x200f ("DoYouEven%sCTF") and target
   strcmp string at 0x202b ("_init") from Compiled-1688545393558.Compiled.
2. Constructs the required password ("DoYouEven_init") and flag ("THM{DoYouEven_init}").
3. Verifies the password by executing the binary and confirming "Correct!".
"""

import subprocess
from pathlib import Path


def main():
    base_dir = Path(__file__).resolve().parent
    bin_path = base_dir / "Compiled-1688545393558.Compiled"
    bin_path.chmod(0o755)

    raw = bin_path.read_bytes()

    # In ELF .rodata (file offset 0x2000):
    # 0x200f: "DoYouEven%sCTF\x00"
    # 0x201e: "__dso_handle\x00"
    # 0x202b: "_init\x00"
    fmt_str = raw[0x200F : raw.index(b"\x00", 0x200F)].decode("ascii")
    target_str = raw[0x202B : raw.index(b"\x00", 0x202B)].decode("ascii")

    # scanf("DoYouEven%sCTF", buf) matches literal "DoYouEven" then greedily reads
    # non-whitespace characters into buf via %s, which is compared to "_init"
    prefix = fmt_str.split("%s")[0]
    password = f"{prefix}{target_str}"
    flag = f"THM{{{password}}}"

    print(f"[+] Decoy Stack String : StringsIsForNoobs")
    print(f"[+] scanf Format       : {fmt_str}")
    print(f"[+] strcmp Target      : {target_str}")
    print(f"[+] Recovered Password : {password}")
    print(f"[+] Flag               : {flag}")

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
