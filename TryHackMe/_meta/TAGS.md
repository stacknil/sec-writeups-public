# Tag Taxonomy (TryHackMe)

> Use a controlled vocabulary.
> Goal: consistent retrieval (GitHub search) and reusable mental models.
> Prefer **fewer tags** per room (3–8).

## 1) Domain tags (choose 1–2)

- `foundations`
- `web`
- `linux`
- `windows`
- `networking`
- `cloud`
- `forensics`
- `crypto`
- `blueteam`

## 2) Skill tags (choose 2–5)

### General workflow
- `recon`
- `enum`
- `foothold` (authorized labs only)
- `privesc` (pattern-level notes only)
- `lateral-movement` (concept only)
- `post-exploitation` (concept only)
- `reporting`

### Linux skills
- `files-perms`
- `processes`
- `services`
- `cron`
- `suid-sgid`
- `capabilities`
- `ssh`
- `logs`

### Windows skills
- `accounts`
- `services`
- `powershell`
- `event-logs`
- `ad-basics` (concept notes)
- `winrm` (concept notes)
- `registry`

### Web skills
- `http-basics`
- `headers-cookies`
- `auth-session`
- `web-enum`
- `input-validation`
- `sqli` (concept-level)
- `xss` (concept-level)
- `ssrf` (concept-level)
- `file-upload` (concept-level)

### Networking skills
- `tcp-ip`
- `dns`
- `arp`
- `dhcp`
- `routing`
- `pcap`
- `nmap`
- `proxying` (concept-level)

### Blue team skills
- `detection`
- `logging`
- `triage`
- `ir-basics`
- `threat-modeling`

## 3) Artifact tags (optional, 0–2)

- `cookbook` (command recipes)
- `pattern-card` (generalizable checklist)
- `lab-notes` (room-specific but sanitized)
- `concept-notes`

## 4) Hygiene rules

- Avoid inventing new tags unless necessary.
- Use `TARGET_IP`, `USER_A`, `example.com` placeholders in public notes.
- No full exploit chains or copy-paste payload walkthroughs in public repositories.
