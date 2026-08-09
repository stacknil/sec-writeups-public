# Repo-Sentinel Baseline Review

## Status

This is a classification record for the current consumer baseline. The
committed `.reposentinel-baseline.json` is unchanged, and no remote
`repo-sentinel` gate is enabled by this review.

The review keeps raw token values out of repository history, issues, and
reviewer-facing output.

## Audit Scope

The consumer snapshot is `sec-writeups-public` `main` at `9a18c74`. The
baseline is schema version `1`, generated at `2026-04-02T18:57:41Z`, and
contains 306 entries across 127 files.

The candidate audit used `repo-sentinel-lite` commit `8a6e064` from the
v0.8 development line. It is recorded as an immutable audit input, not as a
released dependency or a claim that the remote gate is ready.

Reproduction command:

```bash
repo-sentinel baseline audit \
  --format json \
  --baseline .reposentinel-baseline.json \
  .
```

## Classification

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

A clean-worktree local validation used the installed `repo-sentinel 0.8.0`
CLI against that exact consumer commit. This is pre-release/local evidence,
not a formal remote dependency pin or a claim that the changed-file gate is
ready.

Reproduction command:

```bash
repo-sentinel baseline audit \
  --format json \
  --baseline .reposentinel-baseline.json \
  .
```

Evidence summary:

| Result | Count |
| --- | ---: |
| Active `secret.high_entropy` | 272 |
| Relocated | 7 |
| Changed | 0 |
| Ambiguous | 26 |
| Stale | 0 |
| Unmatched | 2,567 |
| Active `repo.required_file_missing` | 0 |

The redacted audit artifact SHA-256 is
`ce5e84b0bff3c8825c51141a9278612837ae7cbf80baaafd52b1c1a71167fe9a`.

## Governance Decision

The current baseline is useful as a reviewed suppression record, but it is not
ready to become a blocking remote gate yet.

1. The missing `LICENSE` decision is resolved. Keep the targeted baseline
   cleanup and do not regenerate unrelated suppressions.
2. Keep baseline audit output non-blocking. The changed-file policy should fail
   on new error findings while baseline drift remains an independent review
   signal.
3. Consume a reviewed `repo-sentinel` release or pin a reviewed immutable
   commit before enabling the remote job.
4. Add the synthetic pass/fail/redaction integration test in the consumer
   workflow before making the check required.
5. Preserve the rollback path: remove the remote job while retaining the local
   pre-push hook.

## Relationship To Issue #5

This record advances [issue #5](https://github.com/stacknil/sec-writeups-public/issues/5)
without claiming that the acceptance criteria are complete. The historical
issue snapshot and this v0.8 candidate audit are not directly comparable:
scanner rule coverage and baseline identity semantics changed between the two
runs. Future comparisons should always record the exact `repo-sentinel`
release or commit used for the audit. The license condition is now resolved;
issue #5 remains open pending the formal v0.8.0 release, exact pinned consumer
audit, synthetic pass/fail/redaction tests, and changed-file remote-gate
rollout while baseline audit remains non-blocking.
