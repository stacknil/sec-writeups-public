---

platform: tryhackme
room: "BFFs — Getting Started: Inspecting the Site"
slug: bffs-inspecting-site
path: "Web-Fundamentals"
topic: "10-web"
domain: ["web"]
skills: ["recon", "source-review", "auth-defaults", "access-control"]
artifacts: ["lab-notes"]
status: "wip"
date: 2026-01-09
---

# Getting Started: Inspecting the Site (TryHackMe)

## 0) Summary (2–5 bullets)

* **What this room trains:** browser-first recon to discover **hidden admin surfaces** (admin panels) without heavy tooling.
* **Main concepts:** view-source review, comment-based information leakage, “security by obscurity”, and default-credential risk.
* **What I will reuse elsewhere:** a fast checklist for spotting **high-value endpoints** from HTML/JS/CSS artifacts.

## 1) Key Concepts (plain language)

* **Shell vs browser recon mindset:** treat the browser as a first-class recon tool before reaching for scanners or proxies.
* **HTML comments leak reality:** `<!-- ... -->` is not access control. Anything inside is effectively public.
* **Hidden endpoint ≠ protected endpoint:** unlinked URLs can still be reachable; the absence of a UI link is not a security control.
* **Default credentials are “low-friction compromise”:** pre-prod/staging systems often ship with test accounts, weak passwords, or “temporary” admin pages.
* **Pitfall:** jumping to brute force. In a real environment this is noisy and may trigger lockouts/alerts. Start with **minimal guesses** and document.

### EN–ZH glossary (small)

| Term (EN)                  | 中文         | Notes (plain)                                                          |
| -------------------------- | ---------- | ---------------------------------------------------------------------- |
| page source                | 页面源代码      | Raw HTML/JS/CSS as served to the browser                               |
| HTML comment               | HTML 注释    | `<!-- ... -->`, ignored by the browser rendering but visible to anyone |
| hidden endpoint            | 隐藏接口/隐藏页面  | Not linked in UI, but still accessible by URL                          |
| admin portal / admin panel | 管理员后台      | High-privilege interface; high impact if exposed                       |
| default credentials        | 默认凭据       | Factory/test username:password pairs                                   |
| security by obscurity      | 以“隐蔽”为安全策略 | Relying on secrecy (e.g., unlinked URL) instead of controls            |
| privilege escalation       | 权限提升       | Moving from low-privileged user to admin                               |
| access control             | 访问控制       | Rules enforcing who can access what                                    |

## 2) Pattern Cards (generalizable)

### Pattern 1 — “Source review” leaks an admin path

* **Signal:** a normal-looking public page, but it feels “pre-prod” (beta/test language) or unusually minimal.
* **Hypothesis:** the HTML/JS includes developer comments or leftover routes like `/test-admin`, `/staging`, `/debug`.
* **Checks (minimal):**

  * In browser: **View Page Source** (`Ctrl+U`)
  * Search for comment blocks: `Ctrl+F` → `<!--`
  * Also search for keywords: `admin`, `beta`, `test`, `todo`, `debug`
* **Expected output:** a comment or string referencing a hidden path (e.g., `/<HIDDEN_ADMIN_PATH>`).
* **Next step decision:**

  * If a path is found → visit it directly: `http://TARGET_IP/<HIDDEN_ADMIN_PATH>`
  * If nothing obvious → switch to higher-signal artifacts (linked JS/CSS), then reassess.

### Pattern 2 — Hidden admin login suggests default-credential exposure

* **Signal:** a reachable admin login page that looks “temporary” or explicitly says it should be removed.
* **Hypothesis:** the environment is using **default / weak test credentials**.
* **Checks (minimal):**

  * Try a **very small** set of common defaults (3–6 attempts max).
  * Stop if rate limits/lockouts appear; do not brute force.
* **Expected output:** successful login redirects to an admin portal (user management, posts moderation, settings).
* **Next step decision:**

  * If login succeeds → document impact (what admin can do), take screenshots, and map sensitive actions.
  * If login fails → pivot to non-credential routes (IDOR, misconfigured access, hidden features, client-side checks).

## 3) Command Cookbook (only what I actually used)

> Keep steps reproducible. Use placeholders.

```bash
export T="TARGET_IP"

# Browser-driven recon (no heavy tools):
# 1) Open public page:
#    http://$T/
# 2) View source:
#    Ctrl+U
# 3) Find comments:
#    Ctrl+F -> "<!--"
# 4) Visit leaked endpoint:
#    http://$T/<HIDDEN_ADMIN_PATH>
# 5) If login exists, try a tiny default-cred shortlist (avoid brute force).
```

* Notes:

  * Why this workflow: fastest path to “human mistake” signals (comments, debug paths, staging artifacts).
  * What to look for: TODOs, commented links, hard-coded routes, “remove before production” warnings.

## 4) Evidence (sanitized)

* Store screenshots / HTML snippets under `assets/` (optional):

  * `assets/source-comment.png` (leaked endpoint)
  * `assets/admin-login.png` (hidden admin login page)
  * `assets/admin-portal.png` (post-login portal view)

* Sanitization checklist:

  * Replace real IP with `TARGET_IP`.
  * Replace any discovered usernames/emails with `USER_A`, `USER_B`.
  * Do not include real tokens, cookies, session IDs.

## 5) Takeaways (transfer learning)

* **1 thing I would do faster next time:** open source + keyword search (comments/admin/todo) before touching any tooling.
* **1 check I keep forgetting:** scan linked JS files for routes and “feature flags” when HTML comments are clean.
* **1 reference worth re-reading:** WSTG guidance on information leakage and admin interface discovery.

## 6) References

* OWASP Web Security Testing Guide (WSTG) — *Information Gathering* sections (e.g., reviewing page content for leakage; admin interface discovery).
* OWASP Top 10 (2021) — *A05: Security Misconfiguration*; *A07: Identification and Authentication Failures*.
* MITRE CWE — *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*; *CWE-798: Use of Hard-coded Credentials*.
* OWASP Cheat Sheet Series — authentication and deployment hardening guidance (environment separation, credential hygiene).
