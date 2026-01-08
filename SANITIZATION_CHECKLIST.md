# Sanitization Checklist (pre-publish)

## A) Scope & compliance
- [ ] Authorized lab/training only (ROE stated)
- [ ] HTB content is retired/allowed
- [ ] pwn.college: meta-notes only (no challenge walkthrough)

## B) Identifiers & secrets
- [ ] No public IPs / real domains / real usernames
- [ ] No tokens / cookies / session IDs / API keys
- [ ] No SSH keys / VPN configs / private endpoints
- [ ] Replace with placeholders: `TARGET_IP`, `example.com`, `USER_A`, `SERVICE_X`

## C) Actionability control
- [ ] No complete exploit chain from initial access → root
- [ ] Payloads are removed or reduced to non-weaponized form
- [ ] Avoid “copy-paste to win” steps

## D) Reporting quality
- [ ] Executive summary present
- [ ] Finding includes: root cause → impact → remediation
- [ ] At least one detection idea (logs/alerts/controls)
- [ ] Lessons learned generalized (pattern, not platform trivia)

## E) Screenshots & outputs
- [ ] Screenshots minimized and scrubbed (paths, usernames, IDs)
- [ ] Tool outputs summarized (no full `nmap`/`linpeas` dumps)
- [ ] Remove timestamps or unique markers when unnecessary

## Final gate
- [ ] If I hesitate: keep private and publish a pattern note instead
