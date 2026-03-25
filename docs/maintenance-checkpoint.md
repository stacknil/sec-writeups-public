# Maintenance Checkpoint

Date: 2026-03-25

## Audit Status

The manual GitHub Actions markdownlint debt audit could not be triggered from this workspace because the workflow is not present on remote `main`.

Observed blocker:

* `gh workflow run markdownlint-debt.yml --ref main` returned `HTTP 404: workflow markdownlint-debt.yml not found on the default branch`
* `gh workflow list` returned no workflow entries for the remote repository

This means there was no new GitHub artifact available to download for comparison. The current checkpoint therefore uses:

* previous baseline: `reports/markdownlint-debt.txt`
* fallback current snapshot: `reports/markdownlint-debt-current-local.txt`

The fallback current snapshot was produced locally with the repo-wide debt config mirrored into a temporary supported `markdownlint-cli2` config filename.

## Baseline Comparison

### Previous debt baseline

* `1579` markdownlint findings
* `84` files with findings
* `54` active notes with findings

### Current local fallback snapshot

* `942` markdownlint findings
* `77` files with findings
* `47` active notes with findings

### Delta

* `-637` findings overall
* `-7` files with findings
* `-7` active notes with findings

## Highest-Friction Files

The originally prioritized high-friction active notes are now all clean in the local tree:

* `TryHackMe/10-web/how-the-web-works/02-HTTP-in-detailed.md`
* `TryHackMe/00-foundations/intro-cybersecurity/search-skills.md`
* `TryHackMe/30-windows/windows-fundamentals/1.md`
* `TryHackMe/00-foundations/learning-meta/introductory-researching.md`
* `TryHackMe/00-foundations/learning-meta/become-a-hacker.md`
* `TryHackMe/40-networking/network-fundamentals/01-what-is-networking.md`
* `TryHackMe/00-foundations/intro-cybersecurity/offensive-security-intro.md`

Each of those files moved from its prior debt count to `0` findings in the current local fallback audit.

The remaining top active-note debt is now concentrated in a much smaller set:

* `TryHackMe/90-events/thm-aoc-2025/Day 02 – Phishing - Merry Clickmas.md` — `51` findings
* `TryHackMe/90-events/thm-aoc-2025/Day 10 - SOC Alert Triaging - Tinsel Triage.md` — `49` findings
* `TryHackMe/90-events/thm-aoc-2025/Day 12 - Phishing - Phishmas Greetings.md` — `34` findings
* `TryHackMe/30-windows/windows-fundamentals/2.md` — `10` findings
* `TryHackMe/00-foundations/intro-cybersecurity/defensive-security-intro.md` — `6` findings
* `TryHackMe/10-web/how-the-web-works/01-DNS-in-detail.md` — `6` findings
* `TryHackMe/80-blue-team/jr-analyst-intro/jr-analyst-intro.md` — `5` findings

## Decision

The repo is now formally switched to **opportunistic markdownlint maintenance** as the default mode.

Effective operating mode:

* keep changed-files lint enforcement as the normal control plane
* perform markdownlint cleanup opportunistically when a file is already being touched
* reserve manual batch cleanup for rare, clearly clustered hotspots

Rationale:

* the highest-friction foundational files are now mostly clean
* the remaining debt is more dispersed
* the biggest remaining concentrations are mostly in event notes rather than the most routinely maintained foundational notes
* the return on broad batch cleanup is now lower than when the top seven files were still dirty

## Optional Exception Batch

If the repo owner still wants one more manual debt-reduction batch before fully switching to opportunistic maintenance, the next smallest high-value batch is:

1. `TryHackMe/90-events/thm-aoc-2025/Day 02 – Phishing - Merry Clickmas.md`
2. `TryHackMe/90-events/thm-aoc-2025/Day 10 - SOC Alert Triaging - Tinsel Triage.md`
3. `TryHackMe/90-events/thm-aoc-2025/Day 12 - Phishing - Phishmas Greetings.md`

Those three files now dominate the remaining active-note markdownlint debt in the current local snapshot.

## Follow-up

To restore artifact-based manual auditing, the local workflow file must be pushed to remote `main`:

* `.github/workflows/markdownlint-debt.yml`

Once that exists on GitHub, the intended manual workflow loop becomes:

1. trigger `Markdownlint Debt Audit`
2. download the `markdownlint-debt-report` artifact
3. compare it against the last checkpoint or baseline report
4. decide whether any new targeted cleanup batch is justified
