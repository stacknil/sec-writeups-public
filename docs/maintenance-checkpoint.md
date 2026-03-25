# Maintenance Checkpoint

Date: 2026-03-25

## Audit Status

The remote markdownlint debt workflow is now present on default branch `main` and visible through GitHub Actions:

* workflow file on `main`: `.github/workflows/markdownlint-debt.yml`
* workflow name: `Markdownlint Debt Audit`
* trigger: `workflow_dispatch`
* verified by: `gh workflow list -a`

Artifact-based auditing is therefore restored.

## Official Baseline

The new formal markdownlint debt baseline comes from the successful remote run on `main`:

* workflow run: `23525508132`
* result: `success`
* artifact: `markdownlint-debt-report`
* local baseline copy: `reports/markdownlint-debt.txt`

Current formal baseline:

* `1090` markdownlint findings
* `70` files with findings
* `66` active notes with findings

Most common rules in the official baseline:

* `MD012` — `759`
* `MD029` — `123`
* `MD007` — `59`
* `MD032` — `36`
* `MD041` — `27`
* `MD022` — `25`

## Highest-Friction Files

The current top active-note hotspots in the official remote baseline are:

* `TryHackMe/10-web/how-the-web-works/02-HTTP-in-detailed.md` — `214`
* `TryHackMe/00-foundations/intro-cybersecurity/search-skills.md` — `154`
* `TryHackMe/30-windows/windows-fundamentals/1.md` — `69`
* `TryHackMe/00-foundations/learning-meta/introductory-researching.md` — `63`
* `TryHackMe/90-events/thm-aoc-2025/Day 02 – Phishing - Merry Clickmas.md` — `54`
* `TryHackMe/00-foundations/learning-meta/become-a-hacker.md` — `53`
* `TryHackMe/40-networking/network-fundamentals/01-what-is-networking.md` — `51`

## Decision

The repo is now formally switched to **opportunistic markdownlint maintenance** as the default mode.

Effective operating mode:

* keep changed-files lint enforcement as the normal control plane
* perform markdownlint cleanup opportunistically when a file is already being touched
* reserve manual batch cleanup for rare, clearly clustered hotspots

Rationale:

* changed-files enforcement is already in place and is the right default control plane
* the manual debt workflow now provides a reliable repo-wide checkpoint when needed
* remaining debt can be monitored from the official baseline without making scheduled batch cleanup the default habit
* targeted batch cleanup remains available as an exception, not the standard mode

## Optional Exception Batch

If the repo owner wants an explicit exception batch later, the next high-value cluster is still:

1. `TryHackMe/10-web/how-the-web-works/02-HTTP-in-detailed.md`
2. `TryHackMe/00-foundations/intro-cybersecurity/search-skills.md`
3. `TryHackMe/30-windows/windows-fundamentals/1.md`
4. `TryHackMe/00-foundations/learning-meta/introductory-researching.md`
5. `TryHackMe/00-foundations/learning-meta/become-a-hacker.md`

That cluster remains the most efficient manual batch if opportunistic cleanup proves too slow.

## Follow-up

The intended manual workflow loop is now:

1. trigger `Markdownlint Debt Audit`
2. download the `markdownlint-debt-report` artifact
3. compare it against the last checkpoint or baseline report
4. decide whether any new targeted cleanup batch is justified
