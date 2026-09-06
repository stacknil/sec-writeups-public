# Repo-Sentinel Baseline Review

## Status

This is a classification record for the current consumer baseline. The
committed `.reposentinel-baseline.json` is unchanged, and the consumer now
pins the reviewed `repo-sentinel-lite v0.8.1` release.

The review keeps raw token values out of repository history, issues, and
reviewer-facing output.

## Audit Scope

The pre-integration consumer snapshot is `sec-writeups-public` `main` at
`7db916e`. The
baseline is schema version `1`, generated at `2026-04-02T18:57:41Z`, and
contains 306 entries across 127 files.

The formal consumer integration uses the production PyPI package
`repo-sentinel-lite==0.8.1`. It is intentionally not pinned to the provider
repository's development branch.

Reproduction command:

```bash
repo-sentinel baseline audit \
  --format json \
  --baseline .reposentinel-baseline.json \
  .
```

## Historical v0.8 Development Classification

The following classification is retained as historical evidence from the
development-line audit. It is not the canonical consumer result for the
published `v0.8.1` integration.

| Audit class | Count | Classification | Decision |
| --- | ---: | --- | --- |
| Active `secret.high_entropy` | 274 | Reviewed documentation, path, and lab-example suppressions | Retain; do not regenerate automatically |
| Active `repo.required_file_missing` | 1 | Missing `LICENSE`; repository governance condition, not a secret false positive | Keep unresolved and do not call the baseline fully approved |
| Relocated | 5 | Existing README content moved to new lines | Retain the suppression; review the movement, do not rewrite automatically |
| Ambiguous | 26 | Duplicate path/link content in README and workflow files | Manually inspected as false positives; preserve audit visibility |
| Stale | 0 | No baseline entries disappeared in this audit | No removals required |
| Unmatched | 2,567 | Classified below by evidence type | Do not add to the committed baseline in this pass |

### Unmatched findings

| Evidence class | Count | Decision |
| --- | ---: | --- |
| Generated report artifacts under `reports/` | 2,414 | Fixture/artifact; keep as audit evidence and do not suppress through a bulk refresh |
| Assignment-context examples | 22 | Fixture; keep the educational command examples visible |
| Command placeholders | 19 | Fixture; preserve the teaching syntax and review through placeholder policy |
| Repository paths and documentation metadata | 81 | False positive; no credential claim is made from path-like text |
| Context-reviewed CI, documentation, and pattern-link metadata | 18 | False positive; repeated names and links are repository structure |
| Context-reviewed lab paths, flags, and example values | 13 | Fixture; values are challenge or lab examples, not production credentials |

The unmatched classification totals 2,567. No real credential is confirmed by
this review. A scan for common AWS, GitHub, OpenAI, Slack, private-key, JWT,
and long-hex marker formats found no matches; that heuristic does not replace
human review of future high-entropy findings.

## License Decision Resolution

The missing `LICENSE` governance condition is resolved by consumer commit
`1f829fb02ee662225aaf9b315784f34e4736e31e`, which adds a CC BY 4.0 license for
original written content and pattern cards. The scope notice explicitly
excludes third-party platform material, quotations, and linked resources.

The baseline change was targeted: it removed only the stale
`repo.required_file_missing` entry for `LICENSE`. No unrelated suppression was
regenerated.

The targeted license resolution is retained as historical governance
evidence. The canonical current audit is recorded below against the pinned
production release.

## v0.8.1 Integration Audit

The exact pinned audit was rerun with `repo-sentinel-lite==0.8.1` after adding
the consumer gate and synthetic contract. The redacted output contained no
raw token values.

Reproduction command:

```bash
python -m repo_sentinel baseline audit \
  --format json \
  --baseline .reposentinel-baseline.json \
  .
```

| Result | Count |
| --- | ---: |
| Active `secret.high_entropy` | 272 |
| Relocated | 7 |
| Changed | 0 |
| Ambiguous | 26 |
| Stale | 0 |
| Unmatched | 150 |
| Active `repo.required_file_missing` | 0 |

The exact consumer SHA, scanner version, command, artifact SHA-256, and remote
workflow results are kept together in the issue #5 closure record.

## Governance Decision

The current baseline remains a reviewed suppression record. Baseline drift is
reported by a non-blocking audit job, while the changed-file error gate is now
blocking for pull requests.

1. The missing `LICENSE` decision is resolved. Keep the targeted baseline
   cleanup and do not regenerate unrelated suppressions.
2. Keep baseline audit output non-blocking. The changed-file policy should fail
   on new error findings while baseline drift remains an independent review
   signal.
3. Pin the reviewed production release `repo-sentinel-lite==0.8.1`; do not use
   the provider's development branch as consumer proof.
4. Keep the synthetic pass/fail/redaction integration test in the consumer
   workflow as a release contract.
5. Preserve the rollback path: remove the remote job while retaining the local
   pre-push hook.

## Consumer Orchestration Contract

The blocking consumer workflow delegates its base/head policy to one testable
script. The contract keeps scanner behavior and workflow trust decisions
separate:

1. Require the checked-out worktree to resolve to the requested pull request
   head commit before collecting or scanning paths.
2. Read the suppression baseline only from the pull request base commit. If the
   base has no baseline, disable default-baseline discovery rather than trusting
   the pull request checkout.
3. Fail closed when the pull request modifies, deletes, or renames either
   `.reposentinel.toml` or `.reposentinel-baseline.json`.
4. With rename detection disabled, send the destination of an ordinary rename
   to the blocking scan as an added path and report its deleted source path as
   audit-only. Other added, copied, modified, and type-changed paths follow the
   same stable blocking-path order.
5. Keep only new error findings blocking. Warning findings and coverage skips
   remain report-only, and repository-level baseline drift remains visible in
   the independent non-blocking audit job.

Temporary-Git-repository tests cover the trusted-base and path-selection
boundary. The existing published-package fixture remains authoritative for the
scanner's pass, fail, and redaction behavior.

The workflow writes its report under the runner's temporary directory, outside
the checkout. Local report cleanup rejects tracked files, the checkout's `.git` path,
and symbolic-link outputs before deleting anything. This prevents a report
filename supplied by a pull request from removing input content before scanning.

The scanner subprocess uses `python -I -m repo_sentinel`, so Python excludes the
checkout and user site-packages from default module lookup and ignores `PYTHON*`
environment variables. Install the pinned scanner in the active virtual
environment or runner interpreter; a user-site-only or `PYTHONPATH` installation
is intentionally unsupported. A marker-only shadow-module fixture verifies that
checkout content cannot replace the scanner and hide an error finding.

Import isolation is not a sandbox or a trusted-workflow guarantee. The workflow
and orchestration script are still pull-request-owned; control-plane ownership
remains open in issue #10.
The interpreter and installed package set must themselves remain trusted.

## Relationship To Issue #5

This record closed [issue #5](https://github.com/stacknil/sec-writeups-public/issues/5)
through pull request #8 without treating the historical development-line counts
as current consumer evidence. Future comparisons should always record the exact
`repo-sentinel` release or commit used for the audit. Issue #9 adds regression
coverage for the consumer workflow boundary without changing the reviewed
baseline or warning policy.
