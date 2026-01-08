# TryHackMe Notes (Topic-first)

This folder is a **skills catalog**, not a course dump.

- Primary axis: **Topic / domain** (web, linux, windows, networking, blue-team, etc.)
- Secondary axis: **Path / series** (stored as metadata in front-matter: `path:`)
- Writing goal: **transferable patterns** + **reproducible command notes** (for myself)

> All content is intended for authorized training labs only (TryHackMe/HTB/pwn.college).
> No instructions should be used against systems without explicit permission.

---

## Philosophy (Why Topic-first)

Room counts grow fast. If folders follow the THM UI paths, notes become a "course timetable".
Topic-first turns rooms into reusable building blocks:

- When I meet a new target/service, I search by **skill** (enum, permissions, services)
- Not by "which path I happened to take"

This also aligns with interviewing / real work: people ask about domains (web/linux/cloud),
not about THM learning paths.

---

## Repository Rules (Non-negotiable)

### 1) Folder naming

- Use **kebab-case** for folders: `linux-fundamentals-part-1`
- One room = one folder:
  - `TryHackMe/<topic>/<room-slug>/README.md`

### 2) Metadata (front-matter)

Every room note starts with YAML front-matter:

- `platform`, `room`, `slug`, `path`, `topic`
- `domain`, `skills`, `artifacts`
- `status`, `date`

This enables consistent GitHub search.

### 3) INDEX as the source of truth

- Update `TryHackMe/_meta/INDEX.md` for each new room.
- The table is the "database"; folders are storage.

### 4) Writing style

Prefer:

- decision points (why I tried X, why it failed, what changed my hypothesis)
- reusable patterns (checklists / minimal commands)
- short "Takeaways" for transfer learning

Avoid:

- raw command-history dumps in public notes
- copy-paste exploit chains
- long screenshots-only writeups

---

## Safe-writing (Sanitization)

Use placeholders in public-facing notes:

- IP: `TARGET_IP`
- user: `USER_A`
- domain: `example.com`
- paths: `/home/user/...`
- secrets/tokens: `[REDACTED]`

Never publish:

- real credentials, API keys, tokens
- private target identifiers beyond training platforms
- complete exploit chains that are easily replayable
- doxxable context (school name, real location, unique IDs)

---

## Public vs Private (Recommended split)

- **Private repo**: full logs, full commands, full outputs, raw screenshots
- **Public repo**: sanitized notes focusing on:
  - methodology
  - detection ideas
  - remediation / hardening
  - general patterns / checklists

Platform-specific constraints (public):

- HTB writeups: only retired / allowed content
- pwn.college: meta-notes only (no challenge solutions)

---

## Where things go (Topic map)

- `00-foundations/`: CLI, Linux/Windows basics, intro security, learning-meta
- `10-web/`: HTTP fundamentals, web enumeration, auth/session concepts
- `20-linux/`: Linux enumeration/privesc patterns (pattern-level)
- `30-windows/`: Windows/AD patterns (pattern-level)
- `40-networking/`: scanning, DNS, routing, pcap basics
- `80-blue-team/`: detection/logging/triage notes
- `90-events/`: AoC, seasonal events

If unsure, default to **00-foundations**.

---

## Templates

- Room note template: `TryHackMe/_meta/TEMPLATE_room.md`
- Tag vocabulary: `TryHackMe/_meta/TAGS.md`
- Master index: `TryHackMe/_meta/INDEX.md`
