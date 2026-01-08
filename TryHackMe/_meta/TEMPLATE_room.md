---
platform: tryhackme
room: "ROOM_TITLE"
slug: room-slug-kebab-case
path: "PATH_OR_SERIES_NAME"      # e.g., LinuxFundamentals / Network-Fundamentals / AoC 2025
topic: "00-foundations"          # one of: 00-foundations, 10-web, 20-linux, 30-windows, 40-networking, 50-crypto, 60-forensics, 70-cloud, 80-blue-team, 90-events
domain: ["linux"]                # choose 1–2 from TAGS.md Domain tags
skills: ["enum", "files-perms"]  # choose 2–5 from TAGS.md Skill tags
artifacts: ["lab-notes"]         # optional: cookbook / pattern-card / lab-notes / concept-notes
status: "wip"                    # todo | wip | done
date: 2026-01-08
---

# ROOM_TITLE (TryHackMe)

## 0) Summary (2–5 bullets)

- **What this room trains:** ...
- **Main concepts:** ...
- **What I will reuse elsewhere:** ...

## 1) Key Concepts (plain language)

- Concept A: ...
- Concept B: ...
- Pitfall: ...

## 2) Pattern Cards (generalizable)

### Pattern 1 — When I see X, I do Y
- **Signal:** ...
- **Hypothesis:** ...
- **Checks (minimal):**
  - `command ...`
  - `command ...`
- **Expected output:** ...
- **Next step decision:** ...

### Pattern 2 — Common mistake & fix
- **Mistake:** ...
- **Why it happens:** ...
- **Fix:** ...

## 3) Command Cookbook (only what I actually used)

> Keep commands reproducible. Use placeholders.

```bash
export T=TARGET_IP
# example:
# nmap -sS -sV -sC -p 22,80 -oA scans/tcp_targeted $T
