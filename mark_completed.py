#!/usr/bin/env python3
"""
Quick utility to mark TryHackMe rooms as completed in the local tracker,
update the datasets (CSV, JSON, Markdown), and rebuild the portal.

Usage:
    python3 mark_completed.py <room_code_1> [room_code_2 ...]
Example:
    python3 mark_completed.py blockroom
"""

import sys
import os
import json
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
THM_DIR = os.path.join(SCRIPT_DIR, "THM")
JSON_PATH = os.path.join(THM_DIR, "rooms_data.json")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 mark_completed.py <room_code_1> [room_code_2 ...]")
        sys.exit(1)

    codes_to_add = [c.strip().lower() for c in sys.argv[1:] if c.strip()]
    if not codes_to_add:
        print("No valid room codes provided.")
        sys.exit(1)

    if not os.path.exists(JSON_PATH):
        print(f"Error: {JSON_PATH} not found.")
        sys.exit(1)

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    existing_codes = set(c.lower() for c in data.get("completed_codes", []))
    added = []

    for code in codes_to_add:
        if code not in existing_codes:
            data.setdefault("completed_codes", []).append(code)
            existing_codes.add(code)
            added.append(code)

    if not added:
        print(f"All specified rooms are already marked as completed ({len(existing_codes)} total).")
    else:
        with open(JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"Successfully marked {len(added)} room(s) as completed: {', '.join(added)}")
        print(f"Total completed rooms: {len(data['completed_codes'])}")

    print("\n[*] Rebuilding catalog and portal...")
    subprocess.run([sys.executable, os.path.join(THM_DIR, "generate_room_list.py")], check=True)
    subprocess.run([sys.executable, os.path.join(SCRIPT_DIR, "build_portal.py")], check=True)
    print("\n[+] Done! Review index.html or push changes to GitHub.")

if __name__ == "__main__":
    main()
