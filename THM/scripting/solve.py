#!/usr/bin/env python3
"""
TryHackMe - Scripting (Task 1: [Easy] Base64)
Decodes a file that has been Base64-encoded 50 consecutive times.

General Process:
1. Read input from the file
2. Use a dedicated function to decode the data
3. Execute the decoding process in a loop of 50 iterations
"""

import sys
import base64
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent / "b64_1550406728131.txt"

def decode_base64(data: bytes) -> bytes:
    """Decodes a single layer of base64 data."""
    return base64.b64decode(data.strip())

def solve(input_path: Path, iterations: int = 50) -> str:
    """Reads input file and repeatedly applies base64 decoding."""
    # 1. Read input from the file
    with open(input_path, "rb") as f:
        data = f.read()

    print(f"[*] Loaded '{input_path.name}' ({len(data)} bytes)")
    print(f"[*] Peeling back {iterations} layers of Base64...")

    # 2 & 3. Use function to decode the file in a loop
    for i in range(1, iterations + 1):
        data = decode_base64(data)

    final_str = data.decode("utf-8", errors="replace").strip()
    return final_str

def main():
    target_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FILE
    if not target_file.is_file():
        print(f"Error: Target file '{target_file}' not found.", file=sys.stderr)
        sys.exit(1)

    flag = solve(target_file, iterations=50)
    print("=" * 45)
    print(f"[+] Final Decoded String: {flag}")
    print("=" * 45)

if __name__ == "__main__":
    main()
