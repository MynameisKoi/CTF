#!/usr/bin/env python3
"""
Builds the complete TryHackMe rooms catalog for user khoiduong2913:
  - thm_rooms_khoiduong2913.csv: All 26 room parameters + 2 status columns:
      * did_i_complete_the_room (Yes/No)
      * do_i_have_the_writeup (Yes/No)
  - README.md: Summary statistics, write-up index, and completed rooms table.
"""

import csv
import json
import os
import sys

THM_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JSON = os.path.join(THM_DIR, "rooms_data.json")


def get_local_writeups():
    """Return set of room codes (lowercase) that have a README.md writeup in THM/."""
    writeups = set()
    for entry in os.listdir(THM_DIR):
        room_dir = os.path.join(THM_DIR, entry)
        if os.path.isdir(room_dir) and os.path.isfile(
            os.path.join(room_dir, "README.md")
        ):
            writeups.add(entry.lower())
    return writeups


def format_val(val):
    if val is None:
        return ""
    if isinstance(val, (list, dict)):
        return json.dumps(val, ensure_ascii=False)
    if isinstance(val, str):
        return val.replace("\r\n", " ").replace("\n", " ").strip()
    return str(val)


def main():
    json_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_JSON
    if not os.path.isfile(json_path):
        raise FileNotFoundError(f"Could not find {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    username = data.get("username", "khoiduong2913")
    raw_rooms = data.get("rooms", [])
    completed_codes_list = data.get("completed_codes", [])
    completed_set = {c.lower() for c in completed_codes_list}
    writeups_set = get_local_writeups()

    # Collect all parameter keys across all room objects in deterministic order
    all_keys = []
    seen_keys = set()
    for r in raw_rooms:
        for k in r.keys():
            if k not in seen_keys:
                seen_keys.add(k)
                all_keys.append(k)

    # Deduplicate rooms by code (keeping the first occurrence) and append any
    # retired/legacy completed rooms not present in extended-search
    rooms_by_code = {}
    ordered_rooms = []
    for r in raw_rooms:
        code = str(r.get("code", "")).lower()
        if code and code not in rooms_by_code:
            rooms_by_code[code] = r
            ordered_rooms.append(r)

    for c in completed_codes_list:
        cl = c.lower()
        if cl not in rooms_by_code:
            stub = {"code": c, "title": c, "type": "retired/legacy"}
            rooms_by_code[cl] = stub
            ordered_rooms.append(stub)

    extra_cols = ["did_i_complete_the_room", "do_i_have_the_writeup"]
    fieldnames = all_keys + extra_cols
    csv_path = os.path.join(THM_DIR, "thm_rooms_khoiduong2913.csv")

    completed_count = 0
    writeup_count = 0

    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=fieldnames)
        writer.writeheader()
        for r in ordered_rooms:
            code = str(r.get("code", "")).lower()
            is_completed = (code in completed_set) or (code in writeups_set)
            has_writeup = code in writeups_set
            if is_completed:
                completed_count += 1
            if has_writeup:
                writeup_count += 1

            row = {k: format_val(r.get(k)) for k in all_keys}
            row["did_i_complete_the_room"] = "Yes" if is_completed else "No"
            row["do_i_have_the_writeup"] = "Yes" if has_writeup else "No"
            writer.writerow(row)

    # Also generate THM/README.md with overview, write-up rooms, and link to full CSV
    md_path = os.path.join(THM_DIR, "README.md")
    with open(md_path, "w", encoding="utf-8") as mf:
        mf.write(f"# TryHackMe Rooms Tracker (`{username}`)\n\n")
        mf.write("## Summary\n\n")
        mf.write(f"- **TryHackMe Username**: `{username}` (`{data.get('userId', '')}`)\n")
        mf.write(f"- **Total Rooms in Catalog**: `{len(ordered_rooms)}`\n")
        mf.write(f"- **Completed Rooms**: `{completed_count}`\n")
        mf.write(f"- **Rooms with Local Write-Up**: `{writeup_count}`\n")
        mf.write(
            f"- **Full Dataset (All {len(all_keys)} Room Parameters + 2 Status Columns)**: [`thm_rooms_khoiduong2913.csv`](./thm_rooms_khoiduong2913.csv)\n\n"
        )

        mf.write("## Columns Included in `thm_rooms_khoiduong2913.csv`\n\n")
        mf.write("| # | Column Name | Description |\n")
        mf.write("|---|---|---|\n")
        for idx, col in enumerate(fieldnames, 1):
            desc = (
                "Whether `khoiduong2913` has completed the room (`Yes` / `No`)"
                if col == "did_i_complete_the_room"
                else (
                    "Whether a write-up exists in `THM/<code>/README.md` (`Yes` / `No`)"
                    if col == "do_i_have_the_writeup"
                    else f"TryHackMe room parameter `{col}`"
                )
            )
            mf.write(f"| {idx} | `{col}` | {desc} |\n")

        mf.write("\n## Rooms with Completed Write-Ups in This Repository\n\n")
        mf.write(
            "| Code | Title | Type | Difficulty | Free | Completed | Has Writeup |\n"
        )
        mf.write("|---|---|---|---|---|---|---|\n")
        for r in sorted(ordered_rooms, key=lambda x: str(x.get("code", "")).lower()):
            code = str(r.get("code", ""))
            cl = code.lower()
            if cl in writeups_set:
                title = format_val(r.get("title")) or code
                rtype = format_val(r.get("type"))
                diff = format_val(r.get("difficulty"))
                free = format_val(r.get("freeToUse"))
                mf.write(
                    f"| [`{code}`](./{code}/) | {title} | {rtype} | {diff} | {free} | Yes | [Yes](./{code}/README.md) |\n"
                )

    print(f"Successfully generated:")
    print(f"  - CSV : {csv_path} ({len(ordered_rooms)} rows, {len(fieldnames)} columns)")
    print(f"  - MD  : {md_path}")
    print(f"  - Stats: {completed_count} completed rooms, {writeup_count} with write-ups")


if __name__ == "__main__":
    main()
