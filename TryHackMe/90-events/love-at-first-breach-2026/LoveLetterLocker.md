---

platform: TryHackMe
room: Love at First Breach 2026 — LoveLetterLocker
slug: lafb2026-loveletterlocker
path: TryHackMe/LoveAtFirstBreach2026/LoveLetterLocker.md
topic: 10-web
domain: ["web-app-security", "access-control"]
skills: ["IDOR (Insecure Direct Object Reference)", "Broken Access Control", "Web enumeration"]
artifacts: ["lab-notes", "pattern-card"]
status: done
date: 2026-02-15
---

## 0) Summary

* Target is a simple web app “LoveLetterLocker” where users can register/login and store love letters.
* Letters are assigned sequential numeric IDs; the UI hints that “numbers make everything easier to find”.
* The letter view endpoint exposes an **IDOR**: changing the numeric letter ID in the URL reveals other users’ letters.
* Flag observed (from a letter page): `THM{1_c4n_r3ad_4ll_l3tt3rs_w1th_th1s_1d0r}`.

## 1) Key Concepts (plain language)

* **Broken Access Control（访问控制缺陷）**: the server fails to check whether the logged-in user is allowed to access a specific resource.
* **IDOR / Insecure Direct Object Reference（不安全的对象直接引用）**: an object (here: a letter) is referenced by a predictable identifier (here: an integer), and authorization is missing or insufficient.

Why this matters: if resource IDs are guessable and access checks are absent, an attacker can enumerate and exfiltrate private data.

## 2) Recon from screenshots

App identity and entry:

* Landing page: “Keep your love letters safe…”.
* The challenge card shows the service exposed at `http://TARGET_IP:5000` (replace the real host/IP in public notes).

Observed routes (from browser tabs / URLs):

* `GET /` (Home)
* `GET /register` (Register)
* `GET /login` (Login)
* `GET /letters` (My Letters listing)
* `GET /letters/new` (New letter editor)
* `GET /letter/<id>` (Letter detail view)  ✅ **primary attack surface**

UI hints:

* “Every love letter gets a unique number in the archive. Numbers make everything easier to find.”

  * Translation: sequential IDs → easy enumeration → likely IDOR.

## 3) Workflow (what was done)

1. Register a user (any username/password) via `/register`.
2. Login and reach `/letters`.
3. Create a new letter via `/letters/new` and save.
4. Open a letter from the list and observe the detail URL format: `/letter/<id>`.
5. Manually modify `<id>` in the address bar and access other letters.

This is a classic “horizontal privilege escalation” pattern: reading another user’s objects.

## 4) Evidence (sanitized)

* After saving a letter, the list shows:

  * “Total letters in Cupid’s archive: 3” (example number from the session).
  * A letter entry with an “Open” button.
* Letter detail example:

  * `/letter/1` shows a message containing the flag.

Flag observed:

* `THM{1_c4n_r3ad_4ll_l3tt3rs_w1th_th1s_1d0r}`

Suggested repo asset layout (optional):

* `assets/screenshots/` (store screenshots locally/private; do not publish raw target IPs)
* `assets/evidence.md` (sanitized notes)

## 5) Pattern Cards

### Pattern: Sequential object IDs + missing authz

Signals:

* URLs like `/resource/1`, `/resource/2`, …
* UI explicitly mentions “unique number” or “archive number”.
* “Works for me” behavior but no per-user access boundaries.

Exploit path (conceptual):

* Capture/observe your own object ID → increment/decrement → access others.

### Defenses (server-side)

* Enforce authorization checks on every object access:

  * `if letter.owner_id != session.user_id: return 403`
* Prefer non-guessable identifiers (UUIDv4) *and* still enforce authz.
* Avoid leaking global counts (e.g., “total letters in archive”) if it aids enumeration.
* Add audit logging + rate limiting for suspicious enumeration patterns.

## 6) Command Cookbook

Not applicable (browser-only workflow shown in screenshots).

## 7) Takeaways

* “Security by obscurity” (hiding IDs) never replaces authorization.
* IDOR is usually a product issue: it’s a business-logic bug, not a “fancy crypto” problem.
* If the UI hints at “numbers” and you see `/thing/<int>`, assume IDOR until proven otherwise.

## 8) References

* OWASP Top 10: Broken Access Control (concept)
