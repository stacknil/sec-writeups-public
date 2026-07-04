# Pattern Library

Pattern Library v0.1 is the stable entry point for reusable security detection,
triage, and review patterns. Read these cards before browsing the larger note
archive when you need a compact, evidence-bounded defensive workflow.

## Authentication

* [SSH brute-force triage](auth/ssh-bruteforce-triage.md)
* [Multi-user probing](auth/multi-user-probing.md)
* [Sudo burst review](auth/sudo-burst-review.md)

## Detection Engineering

* [Alert deduplication](detection/alert-deduplication.md)
* [Cooldown suppression](detection/cooldown-suppression.md)
* [Bounded correlation](detection/bounded-correlation.md)

## Cloud

* [IAM policy attachment review](cloud/iam-policy-attachment-review.md)

## Supply Chain

* [SBOM dependency diff review](supply-chain/sbom-dependency-diff-review.md)

## Card Contract

Every stable card uses the same fields:

1. **Signal**
2. **Why it matters**
3. **False positives**
4. **Minimum evidence**
5. **Defensive next step**
6. **Related project**
7. **Related notes**

The minimum-evidence field is the claim boundary: a card should guide an
investigation without turning a weak signal into an unsupported conclusion.

## Project Bridges

| Pattern area | Related project |
| --- | --- |
| Authentication | [LogLens](https://github.com/stacknil/LogLens) |
| Detection engineering | [telemetry-lab](https://github.com/stacknil/telemetry-lab) |
| Cloud review | [telemetry-lab](https://github.com/stacknil/telemetry-lab) |
| Supply-chain review | [sbom-diff-and-risk](https://github.com/stacknil/scientific-computing-toolkit/tree/main/tools/sbom-diff-and-risk) |
