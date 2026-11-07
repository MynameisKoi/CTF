#!/usr/bin/env python3
"""
Publishes the ultra-minimal CTF Portal site to the `gh-pages` branch.
Only `index.html` and `.nojekyll` are included in `gh-pages` (< 900 KB total),
while write-up links point directly to `https://github.com/MynameisKoi/CTF/blob/main/THM/<room>/README.md`.
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
        print("[*] Pruning gh-pages to keep ONLY index.html and .nojekyll...")
        for item in os.listdir(TMP_DIR):
            if item == ".git":
                continue
            item_path = os.path.join(TMP_DIR, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)

        shutil.copy2(os.path.join(CTF_DIR, "index.html"), os.path.join(TMP_DIR, "index.html"))
        open(os.path.join(TMP_DIR, ".nojekyll"), "w").close()

        print("[*] Committing and pushing to origin/gh-pages...")
        run("git add -A", cwd=TMP_DIR)
        status = run("git status --porcelain", cwd=TMP_DIR)
        if status:
            run('git commit -m "deploy: keep only index.html and .nojekyll on gh-pages"', cwd=TMP_DIR)
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
