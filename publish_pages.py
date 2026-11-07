#!/usr/bin/env python3
"""
Publishes the lightweight CTF Portal site to the `gh-pages` branch.
Excludes large challenge captures (.pcap, .zip, .tar.gz) so GitHub Pages
deploys instantly without hitting upload/sync timeouts.
"""

import os
import shutil
import subprocess
import sys

CTF_DIR = os.path.dirname(os.path.abspath(__file__))
TMP_DIR = "/tmp/ctf-gh-pages"

def run(cmd, cwd=CTF_DIR):
    res = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"[-] Command failed: {cmd}\n{res.stderr}", file=sys.stderr)
        sys.exit(res.returncode)
    return res.stdout.strip()

def main():
    print("[*] Rebuilding portal index.html and README.md...")
    run(f"python3 {os.path.join(CTF_DIR, 'build_portal.py')}")

    if os.path.exists(TMP_DIR):
        shutil.rmtree(TMP_DIR, ignore_errors=True)

    print("[*] Setting up gh-pages worktree...")
    run("git worktree prune")
    run(f"git worktree add -B gh-pages {TMP_DIR} origin/gh-pages")

    try:
        print("[*] Syncing lightweight web files (excluding heavy capture binaries)...")
        exclude_args = (
            '--exclude=".git" '
            '--exclude="*.pcap*" '
            '--exclude="*.zip" '
            '--exclude="*.tar.gz" '
            '--exclude="*.evtx" '
            '--exclude="*.Challenge" '
            '--exclude="*.0x41haz*" '
            '--exclude="*.Compiled" '
            '--exclude="b64_*.txt"'
        )
        run(f"rsync -avc {exclude_args} {CTF_DIR}/ {TMP_DIR}/")

        print("[*] Committing and pushing to origin/gh-pages...")
        run("git add -A", cwd=TMP_DIR)
        status = run("git status --porcelain", cwd=TMP_DIR)
        if status:
            run('git commit -m "deploy: update portal on gh-pages"', cwd=TMP_DIR)
            run("git push -u origin gh-pages", cwd=TMP_DIR)
            print("[+] gh-pages branch successfully updated and pushed!")
        else:
            print("[+] gh-pages branch is already up to date.")
    finally:
        print("[*] Cleaning up worktree...")
        run(f"git worktree remove --force {TMP_DIR}")

    print("[+] Done! GitHub Pages live site updated: https://mynameiskoi.github.io/CTF/")

if __name__ == "__main__":
    main()
