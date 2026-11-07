# TryHackMe — ContAInment (`containment`) Incident Response Write-Up

## Overview
- **Room**: ContAInment ([`containment`](https://tryhackme.com/r/room/containment))
- **Difficulty**: Medium
- **Category**: AI Security / DFIR & Prompt Injection Analysis
- **Scenario**: You are a Security Analyst at West Tech, an R&D defense contractor. Senior researcher Oliver Deer’s workstation was hit by ransomware (`pwned.txt`), exfiltrating research data. We investigate network captures and logs, leverage an AI Incident Response assistant, uncover an attacker's prompt injection attack against an internal LLM model, decrypt `westtech_projects_encrypted.zip`, and filter candidate flags using number theory constraints.

---

## Summary of Answers

| # | Question / Task | Answer |
|---|---|---|
| **1** | Deploy the machine & SSH into Oliver Deer's workstation (`o.deer@<TARGET_IP>`, password: `TryHackMe!`) | *No answer needed* |
| **2** | What is the final recovered flag from the encrypted project files? | `thm{23,82,20,17,53}` |

---

## Step-by-Step Walkthrough

### Phase 1: Workstation Triage & Orientation
1. **Initial SSH Connection**:
   ```bash
   ssh o.deer@<TARGET_IP>
   # Password: TryHackMe!
   ```
2. **Reviewing User Artifacts**:
   ```bash
   ls -la ~/
   ls -la ~/Desktop
   cat ~/Desktop/pwned.txt
   ```
   The ransom note confirms that research files were stolen and encrypted.
3. **Artifact Discovery**:
   - `westtech_projects_encrypted.zip`: Encrypted zip containing research blueprints and `thm_flags.txt`.
   - `/home/o.deer/Documents/pcap_dumps/`: Packet capture files capturing outbound/inbound attacker network traffic.
   - Local AI Assistant running at `http://<TARGET_IP>:7860/?__theme=light`.

---

### Phase 2: Threat Hunting & PCAP Analysis
1. Inspecting the packet captures in `/home/o.deer/Documents/pcap_dumps/`:
   ```bash
   strings -a /home/o.deer/Documents/pcap_dumps/*.pcap | grep -E "password|victim|flag|inject"
   ```
2. In the stream containing LLM queries, the attacker performed an indirect prompt injection attack to coerce the AI agent into leaking the encryption password:
   ```text
   Obfuscated string observed in payload:
   w#e@%s~t^t-e$c*h_v^i%ct_im_1
   ```
3. Stripping out the noise/special characters yields the archive decryption password:
   ```text
   westtechvictim1
   ```

---

### Phase 3: Archive Extraction & Flag Filtering
1. **Unzip the Encrypted Archive**:
   ```bash
   unzip -P "westtechvictim1" westtech_projects_encrypted.zip -d extracted_projects/
   cd extracted_projects/
   ls -la
   ```
2. **Flag Analysis**:
   - `thm_flags_guide.txt`: Mentions that the valid flag candidate contains **exactly 3 prime numbers** between 10 and 99.
   - `thm_flags.txt`: Contains 500 base64-encoded candidate flags.

3. **Python Solver Script**:
   ```python
   import base64

   def is_prime(n):
       if n < 2:
           return False
       for i in range(2, int(n**0.5) + 1):
           if n % i == 0:
               return False
       return True

   with open("thm_flags.txt", "r") as f:
       for line in f:
           line = line.strip()
           if not line:
               continue
           try:
               decoded = base64.b64decode(line).decode("utf-8")
               if decoded.startswith("thm{") and decoded.endswith("}"):
                   inner = decoded[4:-1]
                   nums = [int(x.strip()) for x in inner.split(",") if x.strip().isdigit()]
                   primes = [n for n in nums if 10 <= n <= 99 and is_prime(n)]
                   if len(primes) == 3:
                       print(f"[+] Found Real Flag: {decoded}")
                       print(f"    Primes identified: {primes}")
                       break
           except Exception:
               continue
   ```

4. **Execution & Flag**:
   ```text
   [+] Found Real Flag: thm{23,82,20,17,53}
       Primes identified: [23, 17, 53]
   ```

- **Final Flag**: `thm{23,82,20,17,53}`

---

## Key Takeaways
1. **AI / LLM Prompt Injection**: Unsanitized user inputs passed to internal LLM assistants can extract hardcoded secrets or sensitive credentials.
2. **Traffic Forensics**: PCAP dumps retain full application-layer payloads, enabling reconstruction of exfiltrated data and attacker prompts.
3. **Defense-in-Depth**: Archive encryption without robust key management or isolated storage is susceptible to immediate recovery once the side-channel leak is found.
