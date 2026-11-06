#!/usr/bin/env python3
import json
import os
import html

CTF_DIR = os.path.dirname(os.path.abspath(__file__))
THM_DIR = os.path.join(CTF_DIR, "THM")
JSON_PATH = os.path.join(THM_DIR, "rooms_data.json")

def main():
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Local writeups in THM
    local_writeups = {}
    for entry in os.listdir(THM_DIR):
        p = os.path.join(THM_DIR, entry)
        if os.path.isdir(p) and os.path.isfile(os.path.join(p, "README.md")):
            local_writeups[entry.lower()] = f"./THM/{entry}/README.md"

    completed_set = {c.lower() for c in data.get("completed_codes", [])}
    
    # Filter ONLY kind == "rooms"
    raw_rooms = [r for r in data.get("rooms", []) if r.get("kind") == "rooms"]

    seen = set()
    rooms = []
    for r in raw_rooms:
        code = str(r.get("code", "")).strip()
        cl = code.lower()
        if not cl or cl in seen:
            continue
        seen.add(cl)

        is_completed = (cl in completed_set) or (cl in local_writeups)
        has_writeup = cl in local_writeups
        wu_path = local_writeups.get(cl, "")

        rooms.append({
            "code": code,
            "type": r.get("type", "challenge"),
            "title": r.get("title", code),
            "difficulty": r.get("difficulty", "medium"),
            "completed": is_completed,
            "has_writeup": has_writeup,
            "writeup_path": wu_path
        })

    # Sort rooms by title
    rooms.sort(key=lambda x: x["title"].lower())

    print(f"Loaded {len(rooms)} unique rooms with kind=='rooms'")

    # Generate index.html
    html_content = generate_html(rooms)
    with open(os.path.join(CTF_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html_content)
    print("Generated index.html")

    # Generate README.md
    readme_content = generate_readme(rooms)
    with open(os.path.join(CTF_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme_content)
    print("Updated README.md")

def generate_html(rooms):
    rooms_json = json.dumps(rooms, ensure_ascii=False)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CTF & TryHackMe Rooms Explorer</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #e5e7eb;
      --text-muted: #9ca3af;
      --primary: #38bdf8;
      --easy: #10b981;
      --medium: #f59e0b;
      --hard: #ef4444;
      --insane: #8b5cf6;
      --info: #06b6d4;
    }}
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}
    body {{
      background: var(--bg);
      color: var(--text);
      padding: 2rem 1.5rem;
      min-height: 100vh;
    }}
    .container {{
      max-width: 1280px;
      margin: 0 auto;
    }}
    header {{
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
    }}
    h1 {{
      font-size: 2rem;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .subtitle {{
      color: var(--text-muted);
      margin-top: 0.5rem;
      font-size: 0.95rem;
    }}
    .stats-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      margin: 1.5rem 0;
    }}
    .stat-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 0.75rem 1.25rem;
      border-radius: 8px;
      display: flex;
      flex-direction: column;
    }}
    .stat-val {{
      font-size: 1.4rem;
      font-weight: 700;
      color: var(--primary);
    }}
    .stat-lbl {{
      font-size: 0.8rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .controls {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }}
    .filter-group {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}
    .filter-label {{
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--text-muted);
      min-width: 90px;
    }}
    .btn {{
      background: #1f2937;
      color: var(--text);
      border: 1px solid var(--border);
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: all 0.2s;
    }}
    .btn:hover {{
      background: #374151;
      border-color: #4b5563;
    }}
    .btn.active {{
      background: var(--primary);
      color: #0b0f19;
      font-weight: 600;
      border-color: var(--primary);
    }}
    .btn.active[data-diff="easy"] {{ background: var(--easy); border-color: var(--easy); }}
    .btn.active[data-diff="medium"] {{ background: var(--medium); border-color: var(--medium); }}
    .btn.active[data-diff="hard"] {{ background: var(--hard); border-color: var(--hard); }}
    .btn.active[data-diff="insane"] {{ background: var(--insane); border-color: var(--insane); }}
    .btn.active[data-diff="info"] {{ background: var(--info); border-color: var(--info); }}
    .search-box {{
      width: 100%;
      background: #0f172a;
      border: 1px solid var(--border);
      padding: 0.6rem 1rem;
      color: #fff;
      border-radius: 6px;
      font-size: 0.95rem;
    }}
    .search-box:focus {{
      outline: none;
      border-color: var(--primary);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      padding: 0.85rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 0.9rem;
    }}
    th {{
      background: #131d2e;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }}
    tr:hover {{
      background: #1e293b;
    }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: capitalize;
    }}
    .badge-easy {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
    .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .badge-hard {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-insane {{ background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.4); }}
    .badge-info {{ background: rgba(6, 182, 212, 0.2); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.4); }}
    .badge-yes {{ background: rgba(16, 185, 129, 0.2); color: #34d399; font-weight: 700; }}
    .badge-no {{ background: rgba(107, 114, 128, 0.2); color: #9ca3af; }}
    .badge-writeup {{
      background: rgba(56, 189, 248, 0.2);
      color: #38bdf8;
      border: 1px solid rgba(56, 189, 248, 0.5);
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
    }}
    .badge-writeup:hover {{
      background: rgba(56, 189, 248, 0.4);
    }}
    a.room-link {{
      color: #fff;
      text-decoration: none;
      font-weight: 500;
    }}
    a.room-link:hover {{
      color: var(--primary);
      text-decoration: underline;
    }}
    .pagination {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 1.5rem;
      color: var(--text-muted);
      font-size: 0.85rem;
    }}
    .page-controls {{
      display: flex;
      gap: 0.5rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🎯 TryHackMe Rooms Directory</h1>
      <p class="subtitle">Complete catalog of TryHackMe rooms (filtered strictly by <code>kind: rooms</code>) with interactive difficulty filtering, completion tracking, and write-ups.</p>
    </header>

    <div class="stats-bar">
      <div class="stat-card">
        <span class="stat-val" id="stat-total">1402</span>
        <span class="stat-lbl">Total Rooms</span>
      </div>
      <div class="stat-card">
        <span class="stat-val" id="stat-completed" style="color: #34d399;">449</span>
        <span class="stat-lbl">Completed (khoiduong2913)</span>
      </div>
      <div class="stat-card">
        <span class="stat-val" id="stat-writeups" style="color: #38bdf8;">12</span>
        <span class="stat-lbl">Write-Ups in Repo</span>
      </div>
      <div class="stat-card">
        <span class="stat-val" id="stat-filtered">1402</span>
        <span class="stat-lbl">Showing Now</span>
      </div>
    </div>

    <div class="controls">
      <input type="text" id="search" class="search-box" placeholder="🔍 Search by room title, code, or type..." />
      
      <div class="filter-group">
        <span class="filter-label">Difficulty:</span>
        <button class="btn active" data-diff="all">All (1402)</button>
        <button class="btn" data-diff="easy">Easy (631)</button>
        <button class="btn" data-diff="medium">Medium (618)</button>
        <button class="btn" data-diff="hard">Hard (113)</button>
        <button class="btn" data-diff="insane">Insane (9)</button>
        <button class="btn" data-diff="info">Info (31)</button>
      </div>

      <div class="filter-group">
        <span class="filter-label">Completed:</span>
        <button class="btn active" data-comp="all">All</button>
        <button class="btn" data-comp="yes">Completed Only</button>
        <button class="btn" data-comp="no">Incomplete Only</button>
      </div>

      <div class="filter-group">
        <span class="filter-label">Writeup:</span>
        <button class="btn active" data-wu="all">All</button>
        <button class="btn" data-wu="yes">Has Writeup Only</button>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Code</th>
          <th>Type</th>
          <th>Title</th>
          <th>Difficulty</th>
          <th>Did I Complete the Room?</th>
          <th>Do I Have the Writeup?</th>
        </tr>
      </thead>
      <tbody id="rooms-tbody">
      </tbody>
    </table>

    <div class="pagination">
      <span id="page-info">Showing 1 to 50 of 1402</span>
      <div class="page-controls">
        <button class="btn" id="prev-btn">Previous</button>
        <button class="btn" id="next-btn">Next</button>
      </div>
    </div>
  </div>

  <script>
    const rooms = {rooms_json};
    let currentDifficulty = 'all';
    let currentComp = 'all';
    let currentWu = 'all';
    let searchQuery = '';
    let currentPage = 1;
    const pageSize = 50;

    function getFilteredRooms() {{
      return rooms.filter(r => {{
        if (currentDifficulty !== 'all' && r.difficulty.toLowerCase() !== currentDifficulty) return false;
        if (currentComp === 'yes' && !r.completed) return false;
        if (currentComp === 'no' && r.completed) return false;
        if (currentWu === 'yes' && !r.has_writeup) return false;
        if (searchQuery) {{
          const q = searchQuery.toLowerCase();
          return r.title.toLowerCase().includes(q) || r.code.toLowerCase().includes(q) || r.type.toLowerCase().includes(q);
        }}
        return true;
      }});
    }}

    function renderTable() {{
      const filtered = getFilteredRooms();
      document.getElementById('stat-filtered').innerText = filtered.length;
      
      const totalPages = Math.ceil(filtered.length / pageSize) || 1;
      if (currentPage > totalPages) currentPage = totalPages;
      if (currentPage < 1) currentPage = 1;

      const start = (currentPage - 1) * pageSize;
      const pageRooms = filtered.slice(start, start + pageSize);

      const tbody = document.getElementById('rooms-tbody');
      tbody.innerHTML = '';

      pageRooms.forEach(r => {{
        const tr = document.createElement('tr');
        
        const diffClass = 'badge-' + (r.difficulty.toLowerCase() || 'medium');
        const compHtml = r.completed ? '<span class="badge badge-yes">✅ Yes</span>' : '<span class="badge badge-no">❌ No</span>';
        const wuHtml = r.has_writeup 
          ? `<a class="badge badge-writeup" href="${{r.writeup_path}}">📝 Read Writeup</a>` 
          : '<span class="badge badge-no">No</span>';

        tr.innerHTML = `
          <td><code>${{r.code}}</code></td>
          <td><span class="badge" style="background:#1e293b; color:#cbd5e1;">${{r.type}}</span></td>
          <td><a class="room-link" href="https://tryhackme.com/r/room/${{r.code}}" target="_blank" rel="noopener">${{r.title}}</a></td>
          <td><span class="badge ${{diffClass}}">${{r.difficulty}}</span></td>
          <td>${{compHtml}}</td>
          <td>${{wuHtml}}</td>
        `;
        tbody.appendChild(tr);
      }});

      const end = Math.min(start + pageSize, filtered.length);
      document.getElementById('page-info').innerText = filtered.length 
        ? `Showing ${{start + 1}} to ${{end}} of ${{filtered.length}} rooms`
        : 'No rooms match your filter';

      document.getElementById('prev-btn').disabled = (currentPage <= 1);
      document.getElementById('next-btn').disabled = (currentPage >= totalPages);
    }}

    // Event listeners
    document.querySelectorAll('[data-diff]').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('[data-diff]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentDifficulty = btn.getAttribute('data-diff');
        currentPage = 1;
        renderTable();
      }});
    }});

    document.querySelectorAll('[data-comp]').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('[data-comp]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentComp = btn.getAttribute('data-comp');
        currentPage = 1;
        renderTable();
      }});
    }});

    document.querySelectorAll('[data-wu]').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('[data-wu]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentWu = btn.getAttribute('data-wu');
        currentPage = 1;
        renderTable();
      }});
    }});

    document.getElementById('search').addEventListener('input', (e) => {{
      searchQuery = e.target.value.trim();
      currentPage = 1;
      renderTable();
    }});

    document.getElementById('prev-btn').addEventListener('click', () => {{
      if (currentPage > 1) {{
        currentPage--;
        renderTable();
      }}
    }});

    document.getElementById('next-btn').addEventListener('click', () => {{
      currentPage++;
      renderTable();
    }});

    renderTable();
  </script>
</body>
</html>
"""

def generate_readme(rooms):
    diff_order = ["easy", "medium", "hard", "insane", "info"]
    diff_titles = {
        "easy": "🟢 Easy Rooms",
        "medium": "🟡 Medium Rooms",
        "hard": "🔴 Hard Rooms",
        "insane": "🟣 Insane Rooms",
        "info": "ℹ️ Info / Walkthrough Rooms"
    }

    rooms_by_diff = {d: [] for d in diff_order}
    for r in rooms:
        d = r["difficulty"].lower()
        if d in rooms_by_diff:
            rooms_by_diff[d].append(r)
        else:
            rooms_by_diff.setdefault("other", []).append(r)

    total_count = len(rooms)
    completed_count = sum(1 for r in rooms if r["completed"])
    writeup_count = sum(1 for r in rooms if r["has_writeup"])

    lines = []
    lines.append("# CTF Write-Ups & Challenge Artifacts\n")
    lines.append("Repository of Capture The Flag (CTF) challenge artifacts, solver scripts, and technical write-ups solved using the **Hermes Agent + Kali Linux** autonomous CTF harness.\n")
    lines.append(f"> **Live Interactive Room Explorer**: Open [`index.html`](./index.html) in your browser for real-time search and multi-criteria filtering across all {total_count:,} rooms!\n")

    lines.append("## Featured Challenges & Campaigns\n")
    lines.append("| Platform | Challenge | Category | Write-Up |")
    lines.append("| :--- | :--- | :--- | :--- |")
    lines.append("| **TryHackMe (THM)** | [Mr. Phisher](./THM/mrphisher/) | Malware Analysis / VBA Macro (`[MS-OVBA]`) | [`THM/mrphisher/README.md`](./THM/mrphisher/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Handbook for the Recently Compromised](./THM/handbookfortherecentlycompromised/) | DFIR / Windows Event Logs (`.evtx`) & MITRE ATT&CK | [`THM/handbookfortherecentlycompromised/README.md`](./THM/handbookfortherecentlycompromised/README.md) |")
    lines.append("| **TryHackMe (THM)** | [The Waiting Room](./THM/thewaitingroom/) | DFIR / Phishing / OneNote (`.one`), Sysmon & PCAP RC4 | [`THM/thewaitingroom/README.md`](./THM/thewaitingroom/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Classic Passwd](./THM/classicpasswd/) | Reverse Engineering / ELF `x86_64` & Stack Buffer Overflow | [`THM/classicpasswd/README.md`](./THM/classicpasswd/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Mayhem Room](./THM/mayhemroom/) | DFIR / Network Forensics (`.pcapng`) & Havoc C2 AES-256-CTR | [`THM/mayhemroom/README.md`](./THM/mayhemroom/README.md) |")
    lines.append("| **TryHackMe (THM)** | [0x41haz](./THM/0x41haz/) | Reverse Engineering / ELF Header Repair & `x86_64` Crackme | [`THM/0x41haz/README.md`](./THM/0x41haz/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Compiled](./THM/compiled/) | Reverse Engineering / ELF `x86_64` & `scanf` Format String Parsing | [`THM/compiled/README.md`](./THM/compiled/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Warzone 1](./THM/warzoneone/) | SOC / Network Traffic Analysis & MirrorBlast TA505 C2 | [`THM/warzoneone/README.md`](./THM/warzoneone/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Directory](./THM/directorydfirroom/) | DFIR / Incident Response & Windows Kerberoasting / Hash Cracking | [`THM/directorydfirroom/README.md`](./THM/directorydfirroom/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Scripting](./THM/scripting/) | Scripting / Python Socket Automations & AES-GCM UDP | [`THM/scripting/README.md`](./THM/scripting/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Chrome](./THM/chrome/) | Forensics / SMB2 Carving & Chrome DPAPI / SQLite Decryption | [`THM/chrome/README.md`](./THM/chrome/README.md) |")
    lines.append("| **TryHackMe (THM)** | [Extracted](./THM/extractedroom/) | Forensics / KeePass Memory Dump CVE-2023-32784 & KDBX Cracking | [`THM/extractedroom/README.md`](./THM/extractedroom/README.md) |")
    lines.append("| **Google Cloud Security** | [Operation Cymbal: Cold Room (Overview)](./Operation%20Cymbal/) | Threat Intelligence & Google SecOps (Chronicle SIEM) | [`Operation Cymbal/README.md`](./Operation%20Cymbal/README.md) |")
    lines.append("| **Google Cloud Security** | [Operation Cymbal — Deceptive Click](./Operation%20Cymbal/Deceptive%20Click/) | SocGholish / FAKEUPDATES, Kerberoasting & Exfiltration | [`Operation Cymbal/Deceptive Click/README.md`](./Operation%20Cymbal/Deceptive%20Click/README.md) |")
    lines.append("| **Google Cloud Security** | [Operation Cymbal — OAuth Heist](./Operation%20Cymbal/OAuth%20Heist/) | ShinyHunters / UNC6240, Okta MFA Bypass & DB Dump | [`Operation Cymbal/OAuth Heist/README.md`](./Operation%20Cymbal/OAuth%20Heist/README.md) |")
    lines.append("| **Google Cloud Security** | [Operation Cymbal — Rogue Synthesis](./Operation%20Cymbal/Rogue%20Synthesis/) | PROMPTFLUX AI Threat, Gemini API, Token Theft & Persistence | [`Operation Cymbal/Rogue Synthesis/README.md`](./Operation%20Cymbal/Rogue%20Synthesis/README.md) |\n")

    lines.append("## TryHackMe Rooms Directory (Interactive Difficulty Filter)\n")
    lines.append(f"- **Filter Criteria**: Strictly `kind: rooms` ({total_count:,} total rooms)")
    lines.append(f"- **Completed (`khoiduong2913`)**: {completed_count} / {total_count} ({completed_count / total_count * 100:.1f}%)")
    lines.append(f"- **Local Write-Ups**: {writeup_count} rooms\n")
    lines.append("Click below to expand rooms by difficulty:\n")

    for d in diff_order:
        diff_rooms = rooms_by_diff.get(d, [])
        title = diff_titles.get(d, d.capitalize())
        lines.append(f"<details>")
        lines.append(f"<summary><b>{title} ({len(diff_rooms):,} rooms)</b> — Click to expand / collapse</summary>\n")
        lines.append("| Code | Type | Title | Difficulty | Did I Complete the Room? | Do I Have the Writeup? |")
        lines.append("| :--- | :--- | :--- | :--- | :---: | :---: |")
        for r in diff_rooms:
            code = r["code"]
            rtype = r["type"]
            rtitle = r["title"].replace("|", "\\|")
            rdiff = r["difficulty"]
            comp_str = "Yes" if r["completed"] else "No"
            if r["has_writeup"]:
                wu_str = f"[Yes]({r['writeup_path']})"
            else:
                wu_str = "No"
            lines.append(f"| [`{code}`](https://tryhackme.com/r/room/{code}) | {rtype} | {rtitle} | {rdiff} | {comp_str} | {wu_str} |")
        lines.append("\n</details>\n")

    return "\n".join(lines)

if __name__ == "__main__":
    main()
