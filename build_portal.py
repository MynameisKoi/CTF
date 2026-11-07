#!/usr/bin/env python3
"""
Builds the CTF TryHackMe Rooms Portal:
  - index.html: TryHackMe-themed interactive single-page app with imageURL icons,
                deep multi-field search (code, title, description, tags), dynamic
                category count updates, cross-filter alert banners, and reset controls.
  - README.md: Main repository documentation with interactive collapsible sections.
"""

import json
import os

CTF_DIR = os.path.dirname(os.path.abspath(__file__))
THM_DIR = os.path.join(CTF_DIR, "THM")
JSON_PATH = os.path.join(THM_DIR, "rooms_data.json")

def main():
    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    local_writeups = {}
    for entry in os.listdir(THM_DIR):
        p = os.path.join(THM_DIR, entry)
        if os.path.isdir(p) and os.path.isfile(os.path.join(p, "README.md")):
            local_writeups[entry.lower()] = f"https://github.com/MynameisKoi/CTF/blob/main/THM/{entry}/README.md"

    completed_set = {c.lower() for c in data.get("completed_codes", [])}
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
        img_url = r.get("imageURL") or "https://tryhackme.com/static/images/logo/logo-square-white.svg"
        desc = r.get("description") or ""
        tags = r.get("tags") or []

        sub_tier = str(r.get("subscriptionTier", "")).strip().lower()
        if not sub_tier:
            sub_tier = "free" if r.get("freeToUse", True) else "premium"

        rooms.append({
            "code": code,
            "type": r.get("type", "challenge"),
            "title": r.get("title", code),
            "difficulty": r.get("difficulty", "medium"),
            "imageURL": img_url,
            "description": desc,
            "tags": tags,
            "freeToUse": bool(r.get("freeToUse", True)),
            "subscriptionTier": sub_tier,
            "published": r.get("published", ""),
            "completed": is_completed,
            "has_writeup": has_writeup,
            "writeup_path": wu_path
        })

    rooms.sort(key=lambda x: x.get("published") or "", reverse=True)
    print(f"Loaded {len(rooms)} rooms (kind: rooms)")

    html_content = generate_thm_html(rooms)
    with open(os.path.join(CTF_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html_content)
    print("Generated upgraded THM-themed index.html")

    readme_content = generate_readme(rooms)
    with open(os.path.join(CTF_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme_content)
    print("Updated README.md")

def generate_thm_html(rooms):
    rooms_json = json.dumps(rooms, ensure_ascii=False)
    total_rooms = len(rooms)
    total_completed = sum(1 for r in rooms if r.get("completed"))
    total_writeups = sum(1 for r in rooms if r.get("has_writeup"))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <title>TryHackMe Rooms Explorer | @khoiduong2913</title>
  <link rel="icon" type="image/svg+xml" href="https://tryhackme.com/static/images/favicon.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Ubuntu:wght@400;500;700&family=Ubuntu+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --thm-bg: #0d111a;
      --thm-nav: #141d2b;
      --thm-card: #161e2e;
      --thm-card-hover: #1f2a3f;
      --thm-border: #212c42;
      --thm-border-light: #2c3a54;
      --thm-green: #10b981;
      --thm-green-glow: rgba(16, 185, 129, 0.25);
      --thm-red: #ef4444;
      --thm-orange: #f59e0b;
      --thm-purple: #8b5cf6;
      --thm-cyan: #06b6d4;
      --thm-text: #e2e8f0;
      --thm-text-muted: #94a3b8;
      --thm-text-dark: #64748b;
    }}
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      background: var(--thm-bg);
      color: var(--thm-text);
      font-family: 'Ubuntu', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 0;
      min-height: 100vh;
      line-height: 1.5;
    }}
    .navbar {{
      background: var(--thm-nav);
      border-bottom: 1px solid var(--thm-border);
      padding: 0.85rem 1.5rem;
      position: sticky;
      top: 0;
      z-index: 100;
      box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    }}
    .nav-inner {{
      max-width: 1400px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      text-decoration: none;
      color: #fff;
    }}
    .thm-logo-icon {{
      width: 32px;
      height: 32px;
      filter: drop-shadow(0 0 6px rgba(239, 68, 68, 0.4));
    }}
    .brand-text {{
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}
    .brand-text span {{
      color: var(--thm-green);
    }}
    .nav-links {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .nav-btn {{
      background: #1f2a3f;
      border: 1px solid var(--thm-border);
      color: var(--thm-text);
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s;
    }}
    .nav-btn:hover {{
      background: #283752;
      border-color: var(--thm-green);
      color: #fff;
    }}
    .container {{
      max-width: 1400px;
      margin: 1.75rem auto;
      padding: 0 1.25rem;
    }}
    .banner {{
      background: linear-gradient(135deg, rgba(20, 29, 43, 0.95), rgba(22, 30, 46, 0.85));
      border: 1px solid var(--thm-border);
      border-radius: 12px;
      padding: 1.5rem 1.75rem;
      margin-bottom: 1.5rem;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1.25rem;
      box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    }}
    .banner-title h2 {{
      font-size: 1.6rem;
      font-weight: 700;
      color: #fff;
      margin-bottom: 0.25rem;
    }}
    .banner-title p {{
      color: var(--thm-text-muted);
      font-size: 0.92rem;
    }}
    .stats-deck {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }}
    .stat-pill {{
      background: rgba(13, 17, 26, 0.7);
      border: 1px solid var(--thm-border);
      padding: 0.6rem 1rem;
      border-radius: 8px;
      display: flex;
      flex-direction: column;
      align-items: center;
      min-width: 105px;
    }}
    .stat-pill-val {{
      font-size: 1.3rem;
      font-weight: 700;
      font-family: 'Ubuntu Mono', monospace;
      color: var(--thm-green);
    }}
    .stat-pill-lbl {{
      font-size: 0.72rem;
      color: var(--thm-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .controls-panel {{
      background: var(--thm-card);
      border: 1px solid var(--thm-border);
      border-radius: 12px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }}
    .search-row {{
      position: relative;
      display: flex;
      gap: 0.75rem;
    }}
    .search-input-wrap {{
      position: relative;
      flex: 1;
    }}
    .search-input {{
      width: 100%;
      background: #0f1522;
      border: 1px solid var(--thm-border);
      padding: 0.75rem 1rem 0.75rem 2.6rem;
      color: #fff;
      border-radius: 8px;
      font-size: 0.95rem;
      font-family: inherit;
      transition: all 0.2s;
    }}
    .search-input:focus {{
      outline: none;
      border-color: var(--thm-green);
      box-shadow: 0 0 0 3px var(--thm-green-glow);
    }}
    .search-icon {{
      position: absolute;
      left: 0.9rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--thm-text-muted);
      pointer-events: none;
    }}
    .btn-reset {{
      background: #1f2a3f;
      border: 1px solid var(--thm-border);
      color: var(--thm-text-muted);
      padding: 0 1rem;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      font-size: 0.85rem;
      white-space: nowrap;
      transition: all 0.2s;
    }}
    .btn-reset:hover {{
      background: #283752;
      color: #fff;
      border-color: var(--thm-red);
    }}
    .sort-wrap {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: #0f1522;
      border: 1px solid var(--thm-border);
      border-radius: 8px;
      padding: 0 0.75rem;
    }}
    .sort-label {{
      font-size: 0.82rem;
      color: var(--thm-text-muted);
      font-weight: 600;
      white-space: nowrap;
    }}
    .sort-select {{
      background: transparent;
      color: #fff;
      border: none;
      font-size: 0.85rem;
      padding: 0.65rem 0.25rem;
      cursor: pointer;
      outline: none;
      font-weight: 500;
      font-family: inherit;
    }}
    .sort-select option {{
      background: #141d2b;
      color: #fff;
    }}
    .sortable {{
      cursor: pointer;
      user-select: none;
      transition: color 0.15s;
    }}
    .sortable:hover {{
      color: #fff;
    }}
    .sort-icon {{
      font-size: 0.75rem;
      color: var(--thm-text-dark);
      margin-left: 0.25rem;
    }}
    .sortable:hover .sort-icon {{
      color: var(--thm-green);
    }}
    .room-date {{
      font-family: 'Fira Code', monospace;
      font-size: 0.8rem;
      color: var(--thm-text-muted);
      white-space: nowrap;
    }}
    .filter-row {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}
    .filter-label {{
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--thm-text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      min-width: 95px;
    }}
    .chip {{
      background: #111726;
      color: var(--thm-text-muted);
      border: 1px solid var(--thm-border);
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.82rem;
      font-weight: 500;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
    }}
    .chip:hover {{
      background: #1d2639;
      color: #fff;
      border-color: var(--thm-border-light);
    }}
    .chip.active {{
      background: var(--thm-green);
      color: #0b0f19;
      font-weight: 700;
      border-color: var(--thm-green);
      box-shadow: 0 0 10px var(--thm-green-glow);
    }}
    .chip.active[data-diff="easy"] {{ background: #10b981; border-color: #10b981; color: #0b0f19; }}
    .chip.active[data-diff="medium"] {{ background: #f59e0b; border-color: #f59e0b; color: #0b0f19; }}
    .chip.active[data-diff="hard"] {{ background: #ef4444; border-color: #ef4444; color: #fff; }}
    .chip.active[data-diff="insane"] {{ background: #8b5cf6; border-color: #8b5cf6; color: #fff; }}
    .chip.active[data-diff="info"] {{ background: #06b6d4; border-color: #06b6d4; color: #0b0f19; }}
    .chip.active[data-tier="free"] {{ background: #10b981; border-color: #10b981; color: #0b0f19; }}
    .chip.active[data-tier="premium"] {{ background: #f59e0b; border-color: #f59e0b; color: #0b0f19; }}
    .chip.active[data-tier="max"] {{ background: #a855f7; border-color: #a855f7; color: #fff; box-shadow: 0 0 10px rgba(168, 85, 247, 0.4); }}
    .chip.active[data-type="challenge"] {{ background: #3b82f6; border-color: #3b82f6; color: #fff; }}
    .chip.active[data-type="walkthrough"] {{ background: #10b981; border-color: #10b981; color: #0b0f19; }}
    .chip.active[data-comp="yes"] {{ background: #10b981; border-color: #10b981; color: #0b0f19; }}
    .chip.active[data-comp="no"] {{ background: #64748b; border-color: #64748b; color: #fff; }}
    .chip.active[data-wu="yes"] {{ background: #22c55e; border-color: #22c55e; color: #0b0f19; }}
    .chip-counter {{
      background: rgba(0, 0, 0, 0.3);
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      font-size: 0.75rem;
    }}
    .alert-banner {{
      background: rgba(245, 158, 11, 0.15);
      border: 1px solid rgba(245, 158, 11, 0.4);
      color: #fbbf24;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      font-size: 0.88rem;
      display: none;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      margin-bottom: 1.25rem;
    }}
    .alert-banner button {{
      background: #f59e0b;
      color: #0b0f19;
      border: none;
      padding: 0.3rem 0.75rem;
      border-radius: 4px;
      font-weight: 700;
      cursor: pointer;
      font-size: 0.8rem;
    }}
    .table-container {{
      background: var(--thm-card);
      border: 1px solid var(--thm-border);
      border-radius: 12px;
      overflow-x: auto;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }}
    th {{
      background: #131b2a;
      color: var(--thm-text-muted);
      font-size: 0.74rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      padding: 0.9rem 1.1rem;
      border-bottom: 1px solid var(--thm-border);
      white-space: nowrap;
    }}
    td {{
      padding: 0.75rem 1.1rem;
      border-bottom: 1px solid var(--thm-border);
      font-size: 0.88rem;
      vertical-align: middle;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    tr:hover td {{
      background: var(--thm-card-hover);
    }}
    .room-thumb {{
      width: 42px;
      height: 42px;
      min-width: 42px;
      border-radius: 8px;
      background: #0f1522;
      border: 1px solid var(--thm-border);
      object-fit: cover;
      padding: 2px;
    }}
    .room-title-link {{
      color: #fff;
      font-weight: 600;
      font-size: 0.93rem;
      text-decoration: none;
      transition: color 0.15s;
    }}
    .room-title-link:hover {{
      color: var(--thm-green);
      text-decoration: underline;
    }}
    .room-code-badge {{
      font-family: 'Ubuntu Mono', monospace;
      color: var(--thm-text-muted);
      font-size: 0.78rem;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      padding: 0.25rem 0.55rem;
      border-radius: 5px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .badge-easy {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
    .badge-medium {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .badge-hard {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-insane {{ background: rgba(139, 92, 246, 0.15); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.4); }}
    .badge-info {{ background: rgba(6, 182, 212, 0.15); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.4); }}
    .badge-type-challenge {{ background: #1a2436; color: #93c5fd; border: 1px solid #2b3952; }}
    .badge-type-walkthrough {{ background: #1b2826; color: #6ee7b7; border: 1px solid #224d3e; }}
    .badge-free {{ background: rgba(16, 185, 129, 0.12); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }}
    .badge-vip {{ background: rgba(245, 158, 11, 0.12); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); }}
    .badge-max {{ background: rgba(168, 85, 247, 0.18); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.45); font-weight: 700; }}
    .badge-completed {{
      background: rgba(16, 185, 129, 0.2);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.5);
    }}
    .badge-incomplete {{
      background: rgba(100, 116, 139, 0.15);
      color: #94a3b8;
      border: 1px solid #334155;
    }}
    .btn-writeup {{
      background: linear-gradient(135deg, #10b981, #059669);
      color: #fff;
      font-weight: 700;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      text-decoration: none;
      font-size: 0.78rem;
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
      transition: all 0.2s;
    }}
    .btn-writeup:hover {{
      filter: brightness(1.15);
      transform: translateY(-1px);
    }}
    .pagination-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1.25rem 0.5rem;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .page-summary {{
      color: var(--thm-text-muted);
      font-size: 0.88rem;
    }}
    .page-buttons {{
      display: flex;
      gap: 0.5rem;
      align-items: center;
    }}
    .page-btn {{
      background: var(--thm-card);
      border: 1px solid var(--thm-border);
      color: var(--thm-text);
      padding: 0.45rem 0.9rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 600;
      transition: all 0.2s;
    }}
    .page-btn:hover:not(:disabled) {{
      background: #1f2a3f;
      border-color: var(--thm-green);
      color: #fff;
    }}
    .page-btn:disabled {{
      opacity: 0.4;
      cursor: not-allowed;
    }}
    .empty-state {{
      padding: 3rem 1rem;
      text-align: center;
      color: var(--thm-text-muted);
    }}
    footer {{
      margin-top: 3rem;
      border-top: 1px solid var(--thm-border);
      padding: 1.75rem 0;
      text-align: center;
      color: var(--thm-text-dark);
      font-size: 0.85rem;
    }}
  </style>
</head>
<body>
  <nav class="navbar">
    <div class="nav-inner">
      <a href="./" class="brand">
        <svg class="thm-logo-icon" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M50 5L90 28V72L50 95L10 72V28L50 5Z" fill="#1b2338" stroke="#ef4444" stroke-width="6"/>
          <path d="M50 22C42 36 32 46 32 58C32 68 40 76 50 76C60 76 68 68 68 58C68 46 58 36 50 22Z" fill="#ef4444"/>
          <path d="M50 38C46 46 40 52 40 60C40 65 44 70 50 70C56 70 60 65 60 60C60 52 54 46 50 38Z" fill="#10b981"/>
        </svg>
        <span class="brand-text">TryHackMe <span>Tracker</span></span>
      </a>
      <div class="nav-links">
        <a href="https://github.com/MynameisKoi/CTF" target="_blank" rel="noopener" class="nav-btn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          GitHub Repo
        </a>
        <a href="https://tryhackme.com/p/khoiduong2913" target="_blank" rel="noopener" class="nav-btn">
          THM Profile (@khoiduong2913)
        </a>
      </div>
    </div>
  </nav>

  <div class="container">
    <div class="banner">
      <div class="banner-title">
        <h2>TryHackMe Challenge & Walkthrough Catalog</h2>
        <p>Filtered strictly by <code>kind: rooms</code> &bull; Showing full room metadata, completion progress, and local write-ups.</p>
      </div>
      <div class="stats-deck">
        <div class="stat-pill">
          <span class="stat-pill-val" id="stat-total-val">{total_rooms:,}</span>
          <span class="stat-pill-lbl">Rooms Total</span>
        </div>
        <div class="stat-pill">
          <span class="stat-pill-val" id="stat-completed-val" style="color: #34d399;">{total_completed:,}</span>
          <span class="stat-pill-lbl">Completed</span>
        </div>
        <div class="stat-pill">
          <span class="stat-pill-val" id="stat-writeups-val" style="color: #38bdf8;">{total_writeups:,}</span>
          <span class="stat-pill-lbl">Write-Ups</span>
        </div>
        <div class="stat-pill">
          <span class="stat-pill-val" id="stat-filtered-val" style="color: #fbbf24;">{total_rooms:,}</span>
          <span class="stat-pill-lbl">Matching</span>
        </div>
      </div>
    </div>

    <div class="controls-panel">
      <div class="search-row">
        <div class="search-input-wrap">
          <svg class="search-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <input type="text" id="search-input" class="search-input" placeholder="Search by title, code (e.g. blockroom), tags (smb, forensics, buffer overflow), or description...">
        </div>
        <div class="sort-wrap">
          <label for="sort-select" class="sort-label">Sort:</label>
          <select id="sort-select" class="sort-select">
            <option value="newest" selected>🕒 Newest First</option>
            <option value="oldest">⏳ Oldest First</option>
            <option value="title-asc">🔤 Title (A → Z)</option>
            <option value="title-desc">🔤 Title (Z → A)</option>
            <option value="diff-asc">🎯 Difficulty (Easy → Hard)</option>
            <option value="diff-desc">🎯 Difficulty (Hard → Easy)</option>
          </select>
        </div>
        <button class="btn-reset" id="btn-reset-filters">Reset</button>
      </div>

      <div class="filter-row">
        <span class="filter-label">Difficulty:</span>
        <button class="chip active" data-diff="all">All <span class="chip-counter" id="count-all">{total_rooms:,}</span></button>
        <button class="chip" data-diff="easy">🟢 Easy <span class="chip-counter" id="count-easy">631</span></button>
        <button class="chip" data-diff="medium">🟡 Medium <span class="chip-counter" id="count-medium">619</span></button>
        <button class="chip" data-diff="hard">🔴 Hard <span class="chip-counter" id="count-hard">113</span></button>
        <button class="chip" data-diff="insane">🟣 Insane <span class="chip-counter" id="count-insane">9</span></button>
        <button class="chip" data-diff="info">ℹ️ Info <span class="chip-counter" id="count-info">31</span></button>
      </div>

      <div class="filter-row">
        <span class="filter-label">Access / Tier:</span>
        <button class="chip active" data-tier="all">All Tiers <span class="chip-counter" id="count-tier-all">{total_rooms:,}</span></button>
        <button class="chip" data-tier="free">🟢 Free <span class="chip-counter" id="count-tier-free">738</span></button>
        <button class="chip" data-tier="premium">👑 VIP / Premium <span class="chip-counter" id="count-tier-premium">416</span></button>
        <button class="chip" data-tier="max">⚡ MAX Plan <span class="chip-counter" id="count-tier-max">249</span></button>
      </div>

      <div class="filter-row">
        <span class="filter-label">Format / Type:</span>
        <button class="chip active" data-type="all">All Types <span class="chip-counter" id="count-type-all">{total_rooms:,}</span></button>
        <button class="chip" data-type="challenge">⚔️ Challenge <span class="chip-counter" id="count-type-challenge">545</span></button>
        <button class="chip" data-type="walkthrough">📖 Walkthrough <span class="chip-counter" id="count-type-walkthrough">858</span></button>
      </div>

      <div class="filter-row">
        <span class="filter-label">Status:</span>
        <button class="chip active" data-comp="all">All Status <span class="chip-counter" id="count-comp-all">{total_rooms:,}</span></button>
        <button class="chip" data-comp="yes">✅ Completed <span class="chip-counter" id="count-comp-yes">{total_completed:,}</span></button>
        <button class="chip" data-comp="no">❌ Incomplete <span class="chip-counter" id="count-comp-no">{total_rooms - total_completed:,}</span></button>
      </div>

      <div class="filter-row">
        <span class="filter-label">Write-Up:</span>
        <button class="chip active" data-wu="all">All Rooms <span class="chip-counter" id="count-wu-all">{total_rooms:,}</span></button>
        <button class="chip" data-wu="yes">📝 Has Write-Up <span class="chip-counter" id="count-wu-yes">{total_writeups:,}</span></button>
      </div>
    </div>

    <div id="alert-banner" class="alert-banner">
      <span id="alert-text">Notice: matches exist in other categories.</span>
      <button id="alert-btn">Show All Difficulties</button>
    </div>

    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 50px;">Icon</th>
            <th>Code</th>
            <th>Type & Tier</th>
            <th class="sortable" data-sort-key="title">Title <span class="sort-icon" id="sort-icon-title">⇅</span></th>
            <th class="sortable" data-sort-key="diff">Difficulty <span class="sort-icon" id="sort-icon-diff">⇅</span></th>
            <th class="sortable" data-sort-key="date">Released <span class="sort-icon" id="sort-icon-date">▼</span></th>
            <th>Completed?</th>
            <th>Write-Up</th>
          </tr>
        </thead>
        <tbody id="rooms-table-body">
        </tbody>
      </table>
    </div>

    <div class="pagination-bar">
      <div class="page-summary" id="page-summary-text">
        Showing 1 to 50 of {total_rooms:,} rooms
      </div>
      <div class="page-buttons">
        <button class="page-btn" id="prev-page-btn">&larr; Previous</button>
        <span id="page-number-indicator" style="color: var(--thm-text-muted); font-size: 0.85rem; padding: 0 0.5rem;">Page 1</span>
        <button class="page-btn" id="next-page-btn">Next &rarr;</button>
      </div>
    </div>

    <footer>
      TryHackMe Rooms Tracker &bull; User ID: <code>khoiduong2913</code> &bull; Hosted on GitHub Pages &bull; CTF Write-Ups Repository
    </footer>
  </div>

  <script>
    const rooms = {rooms_json};
    let currentDifficulty = 'all';
    let currentTier = 'all';
    let currentType = 'all';
    let currentComp = 'all';
    let currentWu = 'all';
    let currentSort = 'newest';
    let searchQuery = '';
    let currentPage = 1;
    const pageSize = 50;

    const fallbackImg = "https://tryhackme.com/static/images/favicon.png";

    const diffWeight = {{
      'info': 1,
      'easy': 2,
      'medium': 3,
      'hard': 4,
      'insane': 5
    }};

    function formatDate(dStr) {{
      if (!dStr) return '<span style="color: var(--thm-text-dark); font-size: 0.8rem;">-</span>';
      try {{
        const d = new Date(dStr);
        if (isNaN(d.getTime())) return `<span class="room-date">${{dStr.split('T')[0] || dStr}}</span>`;
        const yyyy = d.getUTCFullYear();
        const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
        const dd = String(d.getUTCDate()).padStart(2, '0');
        return `<span class="room-date">${{yyyy}}-${{mm}}-${{dd}}</span>`;
      }} catch (e) {{
        return `<span class="room-date">${{dStr.split('T')[0] || dStr}}</span>`;
      }}
    }}

    function sortRooms(list) {{
      return list.slice().sort((a, b) => {{
        if (currentSort === 'newest') {{
          const da = a.published ? new Date(a.published).getTime() : 0;
          const db = b.published ? new Date(b.published).getTime() : 0;
          return db - da;
        }}
        if (currentSort === 'oldest') {{
          const da = a.published ? new Date(a.published).getTime() : 0;
          const db = b.published ? new Date(b.published).getTime() : 0;
          return da - db;
        }}
        if (currentSort === 'title-asc') {{
          return (a.title || '').localeCompare(b.title || '');
        }}
        if (currentSort === 'title-desc') {{
          return (b.title || '').localeCompare(a.title || '');
        }}
        if (currentSort === 'diff-asc') {{
          const wa = diffWeight[(a.difficulty || '').toLowerCase()] || 99;
          const wb = diffWeight[(b.difficulty || '').toLowerCase()] || 99;
          if (wa !== wb) return wa - wb;
          return (a.title || '').localeCompare(b.title || '');
        }}
        if (currentSort === 'diff-desc') {{
          const wa = diffWeight[(a.difficulty || '').toLowerCase()] || 0;
          const wb = diffWeight[(b.difficulty || '').toLowerCase()] || 0;
          if (wa !== wb) return wb - wa;
          return (a.title || '').localeCompare(b.title || '');
        }}
        return 0;
      }});
    }}

    function roomMatchesSearch(r, q) {{
      if (!q) return true;
      if (r.title.toLowerCase().includes(q)) return true;
      if (r.code.toLowerCase().includes(q)) return true;
      if (r.type && r.type.toLowerCase().includes(q)) return true;
      const tier = (r.subscriptionTier || (r.freeToUse ? 'free' : 'premium')).toLowerCase();
      if (tier === 'max' && 'max'.includes(q)) return true;
      if (tier === 'premium' && ('vip premium subscription').includes(q)) return true;
      if (tier === 'free' && ('free').includes(q)) return true;
      if (r.description && r.description.toLowerCase().includes(q)) return true;
      if (r.tags && r.tags.some(t => t.toLowerCase().includes(q))) return true;
      return false;
    }}

    function updateCounters() {{
      const q = searchQuery.toLowerCase().trim();
      
      const diffCounts = {{ all: 0, easy: 0, medium: 0, hard: 0, insane: 0, info: 0 }};
      const tierCounts = {{ all: 0, free: 0, premium: 0, max: 0 }};
      const typeCounts = {{ all: 0, challenge: 0, walkthrough: 0 }};
      const compCounts = {{ all: 0, yes: 0, no: 0 }};
      const wuCounts = {{ all: 0, yes: 0 }};

      rooms.forEach(r => {{
        if (!roomMatchesSearch(r, q)) return;

        const tier = (r.subscriptionTier || (r.freeToUse ? 'free' : 'premium')).toLowerCase();
        const matchDiff = (currentDifficulty === 'all' || (r.difficulty || '').toLowerCase() === currentDifficulty);
        const matchTier = (currentTier === 'all' || tier === currentTier);
        const matchType = (currentType === 'all' || (r.type || '').toLowerCase() === currentType);
        const matchComp = (currentComp === 'all' || (currentComp === 'yes' && r.completed) || (currentComp === 'no' && !r.completed));
        const matchWu = (currentWu === 'all' || (currentWu === 'yes' && r.has_writeup));

        // When evaluating Difficulty counts:
        if (matchTier && matchType && matchComp && matchWu) {{
          diffCounts.all++;
          const d = (r.difficulty || '').toLowerCase();
          if (diffCounts.hasOwnProperty(d)) diffCounts[d]++;
        }}

        // When evaluating Tier counts:
        if (matchDiff && matchType && matchComp && matchWu) {{
          tierCounts.all++;
          if (tier === 'max') tierCounts.max++;
          else if (tier === 'premium') tierCounts.premium++;
          else tierCounts.free++;
        }}

        // When evaluating Type counts:
        if (matchDiff && matchTier && matchComp && matchWu) {{
          typeCounts.all++;
          const t = (r.type || '').toLowerCase();
          if (typeCounts.hasOwnProperty(t)) typeCounts[t]++;
        }}

        // When evaluating Status counts:
        if (matchDiff && matchTier && matchType && matchWu) {{
          compCounts.all++;
          if (r.completed) compCounts.yes++;
          else compCounts.no++;
        }}

        // When evaluating Write-up counts:
        if (matchDiff && matchTier && matchType && matchComp) {{
          wuCounts.all++;
          if (r.has_writeup) wuCounts.yes++;
        }}
      }});

      for (const k in diffCounts) {{
        const el = document.getElementById('count-' + k);
        if (el) el.innerText = diffCounts[k].toLocaleString();
      }}

      for (const k in tierCounts) {{
        const el = document.getElementById('count-tier-' + k);
        if (el) el.innerText = tierCounts[k].toLocaleString();
      }}

      for (const k in typeCounts) {{
        const el = document.getElementById('count-type-' + k);
        if (el) el.innerText = typeCounts[k].toLocaleString();
      }}

      for (const k in compCounts) {{
        const el = document.getElementById('count-comp-' + k);
        if (el) el.innerText = compCounts[k].toLocaleString();
      }}

      for (const k in wuCounts) {{
        const el = document.getElementById('count-wu-' + k);
        if (el) el.innerText = wuCounts[k].toLocaleString();
      }}

      const totalEl = document.getElementById('stat-total-val');
      if (totalEl) totalEl.innerText = rooms.length.toLocaleString();
      const compEl = document.getElementById('stat-completed-val');
      if (compEl) compEl.innerText = rooms.filter(r => r.completed).length.toLocaleString();
      const wuEl = document.getElementById('stat-writeups-val');
      if (wuEl) wuEl.innerText = rooms.filter(r => r.has_writeup).length.toLocaleString();

      // Check cross-category alert
      const alertBanner = document.getElementById('alert-banner');
      if (searchQuery && currentDifficulty !== 'all' && diffCounts[currentDifficulty] === 0 && diffCounts.all > 0) {{
        document.getElementById('alert-text').innerHTML = `Found <strong>${{diffCounts.all}}</strong> matching room(s) in other difficulty categories!`;
        alertBanner.style.display = 'flex';
      }} else {{
        alertBanner.style.display = 'none';
      }}
    }}

    function filterRooms() {{
      const q = searchQuery.toLowerCase().trim();
      return rooms.filter(r => {{
        const tier = (r.subscriptionTier || (r.freeToUse ? 'free' : 'premium')).toLowerCase();
        if (currentDifficulty !== 'all' && (r.difficulty || '').toLowerCase() !== currentDifficulty) return false;
        if (currentTier !== 'all' && tier !== currentTier) return false;
        if (currentType !== 'all' && (r.type || '').toLowerCase() !== currentType) return false;
        if (currentComp === 'yes' && !r.completed) return false;
        if (currentComp === 'no' && r.completed) return false;
        if (currentWu === 'yes' && !r.has_writeup) return false;
        return roomMatchesSearch(r, q);
      }});
    }}

    function renderTable() {{
      updateCounters();
      const filtered = filterRooms();
      const sorted = sortRooms(filtered);
      document.getElementById('stat-filtered-val').innerText = sorted.length.toLocaleString();

      const totalPages = Math.ceil(sorted.length / pageSize) || 1;
      if (currentPage > totalPages) currentPage = totalPages;
      if (currentPage < 1) currentPage = 1;

      const start = (currentPage - 1) * pageSize;
      const pageItems = sorted.slice(start, start + pageSize);

      const tbody = document.getElementById('rooms-table-body');
      tbody.innerHTML = '';

      if (sorted.length === 0) {{
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No TryHackMe rooms found matching your current filter. Try clicking "Reset" or switching Difficulty to "All".</td></tr>`;
        document.getElementById('page-summary-text').innerText = '0 rooms found';
        document.getElementById('prev-page-btn').disabled = true;
        document.getElementById('next-page-btn').disabled = true;
        return;
      }}

      pageItems.forEach(r => {{
        const tr = document.createElement('tr');

        const diffClass = 'badge-' + (r.difficulty.toLowerCase() || 'medium');
        const typeClass = 'badge-type-' + (r.type.toLowerCase() === 'walkthrough' ? 'walkthrough' : 'challenge');
        
        const compHtml = r.completed 
          ? '<span class="badge badge-completed"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Completed</span>' 
          : '<span class="badge badge-incomplete">Incomplete</span>';

        const tier = (r.subscriptionTier || (r.freeToUse ? 'free' : 'premium')).toLowerCase();
        let tierHtml = '';
        if (tier === 'max') {{
          tierHtml = '<span class="badge badge-max" title="TryHackMe MAX Plan Room">⚡ MAX</span>';
        }} else if (tier === 'premium') {{
          tierHtml = '<span class="badge badge-vip" title="VIP / Premium Subscription Room">👑 VIP</span>';
        }} else {{
          tierHtml = '<span class="badge badge-free" title="Free Room">Free</span>';
        }}

        const wuHtml = r.has_writeup 
          ? `<a class="btn-writeup" href="${{r.writeup_path}}" target="_blank" rel="noopener"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg> Writeup</a>` 
          : '<span style="color: var(--thm-text-dark); font-size: 0.8rem;">No</span>';

        const safeImg = r.imageURL || fallbackImg;
        const dateHtml = formatDate(r.published);

        tr.innerHTML = `
          <td>
            <img class="room-thumb" src="${{safeImg}}" alt="${{r.code}}" loading="lazy" onerror="this.onerror=null;this.src='${{fallbackImg}}';">
          </td>
          <td><code class="room-code-badge">${{r.code}}</code></td>
          <td>
            <div style="display: inline-flex; gap: 0.35rem; align-items: center; flex-wrap: wrap;">
              <span class="badge ${{typeClass}}">${{r.type}}</span>
              ${{tierHtml}}
            </div>
          </td>
          <td>
            <a class="room-title-link" href="https://tryhackme.com/r/room/${{r.code}}" target="_blank" rel="noopener">
              ${{r.title}}
            </a>
          </td>
          <td><span class="badge ${{diffClass}}">${{r.difficulty}}</span></td>
          <td>${{dateHtml}}</td>
          <td>${{compHtml}}</td>
          <td>${{wuHtml}}</td>
        `;
        tbody.appendChild(tr);
      }});

      const end = Math.min(start + pageSize, sorted.length);
      document.getElementById('page-summary-text').innerText = `Showing ${{(start + 1).toLocaleString()}} to ${{end.toLocaleString()}} of ${{sorted.length.toLocaleString()}} rooms`;
      document.getElementById('page-number-indicator').innerText = `Page ${{currentPage}} of ${{totalPages}}`;

      document.getElementById('prev-page-btn').disabled = (currentPage <= 1);
      document.getElementById('next-page-btn').disabled = (currentPage >= totalPages);
      updateSortIcons();
    }}

    // Filter Buttons Handlers
    document.querySelectorAll('[data-diff]').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('[data-diff]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentDifficulty = btn.getAttribute('data-diff');
        currentPage = 1;
        renderTable();
      }});
    }});

    document.querySelectorAll('[data-tier]').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('[data-tier]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentTier = btn.getAttribute('data-tier');
        currentPage = 1;
        renderTable();
      }});
    }});

    document.querySelectorAll('[data-type]').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('[data-type]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentType = btn.getAttribute('data-type');
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

    document.getElementById('search-input').addEventListener('input', (e) => {{
      searchQuery = e.target.value;
      currentPage = 1;
      renderTable();
    }});

    function updateSortIcons() {{
      const icons = {{
        title: document.getElementById('sort-icon-title'),
        diff: document.getElementById('sort-icon-diff'),
        date: document.getElementById('sort-icon-date')
      }};
      if (!icons.title || !icons.diff || !icons.date) return;

      icons.title.innerText = '⇅';
      icons.diff.innerText = '⇅';
      icons.date.innerText = '⇅';

      if (currentSort === 'newest') icons.date.innerText = '▼';
      else if (currentSort === 'oldest') icons.date.innerText = '▲';
      else if (currentSort === 'title-asc') icons.title.innerText = '▲';
      else if (currentSort === 'title-desc') icons.title.innerText = '▼';
      else if (currentSort === 'diff-asc') icons.diff.innerText = '▲';
      else if (currentSort === 'diff-desc') icons.diff.innerText = '▼';
    }}

    document.getElementById('sort-select').addEventListener('change', (e) => {{
      currentSort = e.target.value;
      currentPage = 1;
      renderTable();
    }});

    document.querySelectorAll('.sortable').forEach(th => {{
      th.addEventListener('click', () => {{
        const key = th.getAttribute('data-sort-key');
        if (key === 'date') {{
          currentSort = (currentSort === 'newest') ? 'oldest' : 'newest';
        }} else if (key === 'title') {{
          currentSort = (currentSort === 'title-asc') ? 'title-desc' : 'title-asc';
        }} else if (key === 'diff') {{
          currentSort = (currentSort === 'diff-asc') ? 'diff-desc' : 'diff-asc';
        }}
        document.getElementById('sort-select').value = currentSort;
        currentPage = 1;
        renderTable();
      }});
    }});

    document.getElementById('btn-reset-filters').addEventListener('click', () => {{
      currentDifficulty = 'all';
      currentTier = 'all';
      currentType = 'all';
      currentComp = 'all';
      currentWu = 'all';
      currentSort = 'newest';
      searchQuery = '';
      document.getElementById('search-input').value = '';
      document.getElementById('sort-select').value = 'newest';
      
      document.querySelectorAll('[data-diff]').forEach(b => b.classList.remove('active'));
      document.querySelector('[data-diff="all"]').classList.add('active');

      document.querySelectorAll('[data-tier]').forEach(b => b.classList.remove('active'));
      document.querySelector('[data-tier="all"]').classList.add('active');

      document.querySelectorAll('[data-type]').forEach(b => b.classList.remove('active'));
      document.querySelector('[data-type="all"]').classList.add('active');

      document.querySelectorAll('[data-comp]').forEach(b => b.classList.remove('active'));
      document.querySelector('[data-comp="all"]').classList.add('active');

      document.querySelectorAll('[data-wu]').forEach(b => b.classList.remove('active'));
      document.querySelector('[data-wu="all"]').classList.add('active');

      currentPage = 1;
      renderTable();
    }});

    document.getElementById('alert-btn').addEventListener('click', () => {{
      currentDifficulty = 'all';
      document.querySelectorAll('[data-diff]').forEach(b => b.classList.remove('active'));
      document.querySelector('[data-diff="all"]').classList.add('active');
      currentPage = 1;
      renderTable();
    }});

    document.getElementById('prev-page-btn').addEventListener('click', () => {{
      if (currentPage > 1) {{
        currentPage--;
        renderTable();
      }}
    }});

    document.getElementById('next-page-btn').addEventListener('click', () => {{
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
    lines.append("> 🌐 **Live Interactive Rooms Explorer (GitHub Pages)**: Visit **[https://mynameiskoi.github.io/CTF/](https://mynameiskoi.github.io/CTF/)** or open [`index.html`](./index.html) locally for real-time search, difficulty filters, and TryHackMe room icons!\n")

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
    lines.append("| **TryHackMe (THM)** | [Block](./THM/blockroom/) | DFIR / LSASS Minidump & Encrypted SMB3 Session Key Derivation | [`THM/blockroom/README.md`](./THM/blockroom/README.md) |")
    lines.append("| **TryHackMe (THM)** | [After Hours](./THM/hh-afterhours-b090d1f0/) | DFIR / WMI CIM Repository Persistence, Raw DEFLATE & .NET Reversing | [`THM/hh-afterhours-b090d1f0/README.md`](./THM/hh-afterhours-b090d1f0/README.md) |")
    lines.append("| **Google Cloud Security** | [Operation Cymbal: Cold Room (Overview)](./Operation%20Cymbal/) | Threat Intelligence & Google SecOps (Chronicle SIEM) | [`Operation Cymbal/README.md`](./Operation%20Cymbal/README.md) |")
    lines.append("| **Google Cloud Security** | [Operation Cymbal — Deceptive Click](./Operation%20Cymbal/Deceptive%20Click/) | SocGholish / FAKEUPDATES, Kerberoasting & Exfiltration | [`Operation Cymbal/Deceptive Click/README.md`](./Operation%20Cymbal/Deceptive%20Click/README.md) |")
    lines.append("| **Google Cloud Security** | [Operation Cymbal — OAuth Heist](./Operation%20Cymbal/OAuth%20Heist/) | ShinyHunters / UNC6240, Okta MFA Bypass & DB Dump | [`Operation Cymbal/OAuth Heist/README.md`](./Operation%20Cymbal/OAuth%20Heist/README.md) |")
    lines.append("| **Google Cloud Security** | [Operation Cymbal — Rogue Synthesis](./Operation%20Cymbal/Rogue%20Synthesis/) | PROMPTFLUX AI Threat, Gemini API, Token Theft & Persistence | [`Operation Cymbal/Rogue Synthesis/README.md`](./Operation%20Cymbal/Rogue%20Synthesis/README.md) |\n")

    lines.append("## TryHackMe Rooms Directory (Interactive Difficulty Filter)\n")
    lines.append(f"- **Filter Criteria**: Strictly `kind: rooms` ({total_count:,} total rooms)")
    lines.append(f"- **Completed (`khoiduong2913`)**: {completed_count} / {total_count} ({completed_count / total_count * 100:.1f}%)")
    lines.append(f"- **Local Write-Ups**: {writeup_count} rooms")
    lines.append(f"- **Live Web App**: [https://mynameiskoi.github.io/CTF/](https://mynameiskoi.github.io/CTF/)\n")
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
            wu_str = f"[Yes]({r['writeup_path']})" if r["has_writeup"] else "No"
            lines.append(f"| [`{code}`](https://tryhackme.com/r/room/{code}) | {rtype} | {rtitle} | {rdiff} | {comp_str} | {wu_str} |")
        lines.append("\n</details>\n")

    return "\n".join(lines)

if __name__ == "__main__":
    main()
