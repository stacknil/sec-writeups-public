# TryHackMe Index (Topic-first)

> Goal: turn many rooms into a searchable skills catalog (topic-first).
> Notes are written for **learning + reusability**, not for copying steps.
> Sensitive identifiers are sanitized (TARGET_IP, USER_A, example.com).

## Topic Map (Primary Axis)

- **00-foundations**: CLI, Linux/Windows basics, networking basics
- **10-web**: HTTP fundamentals, web enumeration, auth/session, web vulns concepts
- **20-linux**: Linux enumeration, privilege escalation patterns, services
- **30-windows**: Windows basics, AD basics, Windows enumeration/privesc patterns
- **40-networking**: scanning, routing, DNS, common protocols, traffic analysis basics
- **50-crypto**: crypto fundamentals in CTF context (concept notes)
- **60-forensics**: file/pcap/memory basics (concept notes)
- **70-cloud**: cloud fundamentals, IAM concepts, container basics (if/when needed)
- **80-blue-team**: logging, detection ideas, IR workflows (method notes)
- **90-events**: AoC / seasonal events (time-bounded)

> Secondary axis (Path/Series) is stored in front-matter (`path:`), not folder names.

---

## How to add a new room

1. Create a folder under the topic:
   - `TryHackMe/<topic>/<room-slug>/README.md`
2. Copy `TryHackMe/_meta/TEMPLATE_room.md` into `README.md`
3. Fill the front-matter:
   - `room`, `path`, `domain`, `skills`, `status`, `date`
4. Add one row into **Room Catalog** table below.

---

## Room Catalog

| Room | Topic | Path/Series | Status | Key patterns learned | Link |
|---|---|---|---|---|---|
| (example) Linux Fundamentals Part 1 | 00-foundations/linux-fundamentals | LinuxFundamentals | done | basic fs + permissions mental model | ../00-foundations/linux-fundamentals/linux-fundamentals-part-1/ |
| (example) Command Line | 00-foundations/command-line | Command Line | done | pipes + redirection + grep patterns | ../00-foundations/command-line/command-line/ |
| (example) How The Web Works | 10-web/how-the-web-works | HowTheWebWorks | wip | HTTP request lifecycle, headers | ../10-web/how-the-web-works/how-the-web-works/ |
| (example) Network Fundamentals | 40-networking/network-fundamentals | Network-Fundamentals | wip | TCP handshake, DNS flow | ../40-networking/network-fundamentals/network-fundamentals/ |
| (example) Windows Fundamentals | 30-windows/windows-fundamentals | WindowsFundamentals | todo | account model, services | ../30-windows/windows-fundamentals/windows-fundamentals/ |
| (example) THM AoC 2025 | 90-events/thm-aoc-2025 | THM AoC 2025 | wip | daily small patterns | ../90-events/thm-aoc-2025/ |

> Rules:
> - Use **room slug** in folder names (kebab-case).
> - "Key patterns learned" should be **1–2 short phrases**, not a story.
> - If a note is mostly CLI recipes, place it under `00-foundations/command-line/`.
