#!/usr/bin/env bash
# TryHackMe - Scripting (Task 1: [Easy] Base64)
# Decodes a file that has been Base64-encoded 50 consecutive times.
#
# General Process:
# 1. Read input from the file
# 2. Use function to decode the file
# 3. Do process in a loop of 50 iterations

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_FILE="${1:-"$SCRIPT_DIR/b64_1550406728131.txt"}"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found!" >&2
    exit 1
fi

# Function to decode Base64 data from stdin
decode_base64() {
    base64 -d
}

echo "[*] Target file: $INPUT_FILE"
echo "[*] Decoding 50 layers of Base64 via pipeline loop..."

# Construct a 50-stage pipeline to stream-decode in memory efficiently
cmd="cat \"$INPUT_FILE\""
for i in {1..50}; do
    cmd="$cmd | decode_base64"
done

final_string=$(eval "$cmd")

echo "============================================="
echo "[+] Final Decoded String: $final_string"
echo "============================================="
