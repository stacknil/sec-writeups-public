# Publication Policy (sec-writeups-public)

This repository is public. Everything published here must be safe, compliant, and non-actionable.

## 1) Allowed content

### TryHackMe
- Sanitized case studies focusing on methodology and reasoning.
- Defensive framing is required: remediation + detection ideas.

### Hack The Box
- **Retired content only** (e.g., retired machines/challenges, or content explicitly allowed by HTB).
- Write-ups are sanitized and report-like (no full exploit chain).

### pwn.college
- **Meta-notes only**: concepts, tooling notes, general techniques.
- **No challenge write-ups**, no step-by-step solutions, no scripts that solve specific tasks.

## 2) Prohibited content (hard rules)

- Live target identifiers: IPs/domains/usernames/emails linked to real systems
- Any credentials or secrets: API keys, tokens, cookies, session IDs, SSH keys, VPN configs
- Full exploit chains that enable one-click reproduction (especially RCE / privesc chains)
- Publishing platform-restricted write-ups (e.g., pwn.college solutions)

## 3) Sanitization standards

All write-ups must:
- Replace identifiers with placeholders (`TARGET_IP`, `SERVICE_X`, `USER_A`)
- Remove command dumps unless they are necessary and harmless
- Include:
  - **root cause**
  - **impact**
  - **remediation**
  - **detection ideas**

## 4) Goal of publishing

The purpose is to demonstrate:
- security methodology,
- systems thinking,
- clear reporting,
- and generalizable learning outcomes.

Not to provide offensive instructions.

## 5) If unsure, do not publish

When a piece of content is borderline:
- keep it private, or
- rewrite it as a high-level pattern note without actionable steps.
