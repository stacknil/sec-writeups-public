# sec-writeups-public (sanitized)

Public, sanitized security write-ups from authorized training platforms.

This repository is **not** a “how to hack” cookbook.
The goal is to document **reasoning, methodology, and engineering takeaways** in a way that is:
- **Reproducible** (logic > one-liners)
- **Abstractable** (patterns you can reuse)
- **Safe to publish** (sanitized, no live-target details)

## Scope

Content here comes from:
- **TryHackMe** (sanitized case studies)
- **Hack The Box** (**retired / allowed content only**)
- **pwn.college** (**meta-notes only**, no challenge write-ups)

If you want the full command logs, raw outputs, or step-by-step exploit chains:
they remain in my **private** repository.

## Repository layout

```text
sec-writeups-public/
├── tryhackme/
│   ├── rooms/
│   └── meta/
├── hackthebox/
│   ├── retired-machines/
│   └── starting-point/
└── pwncollege/
    └── meta-notes/
```

## Write-up format

Most write-ups follow a report-like structure:

**1. Executive summary** (what matters, in plain language)

**2. Scope / ROE** (authorized labs only; identifiers sanitized)

**3. Attack surface** (observed facts, not raw dumps)

**4. Findings → Impact → Fix** (vuln category, root cause, remediation, detection)

**5. Lessons learned** (generalizable patterns)

**6. References** (docs / papers / vendor guidance)

## Sanitization policy (short)

- No real target identifiers (use `TARGET_IP`, `example.com`, `USER_A`, etc.)

- No secrets (tokens, cookies, keys, VPN configs)

- No full exploit chains / weaponized payloads

- Prefer defensive framing: remediation + detection included

- Screenshots are minimized and sanitized

See POLICY.md  and SANITIZATION_CHECKLIST.md.

## Legal & ethical notice

All content here is intended for:

- authorized training platforms,

- lab environments, and

- explicitly permitted targets.

Do not use any of this against systems you do not own or do not have written permission to test.
You are responsible for complying with applicable laws and platform rules.

Do not use any of this against systems you do not own or do not have written permission to test.
You are responsible for complying with applicable laws and platform rules.
