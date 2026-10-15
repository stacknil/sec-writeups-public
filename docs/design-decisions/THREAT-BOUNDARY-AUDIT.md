# Trusted Authority Boundary Audit

Audit date: 2026-10-15. Scope: one local engineering increment, no deployment.

## Baseline and scope

The audited source is `stacknil/sec-writeups-public` main at
`d35e5a6`, fetched before creating the
dedicated local branch `authority-boundary-increment` under `stacknil/`.
The latest merge is PR #23, the mock signer core. PRs #19, #20, and #21
already delivered commit authority, the controller, and external policy input.
Historical notes describing those changes as unmerged are superseded by this
read-only remote inspection.

Two older main checkouts had unrelated document edits; neither was modified.
Existing authority branches and an unrelated dirty mutation checkout were
preserved. PR #22 remains a draft candidate-policy construction at `7c9e513`;
its candidate bundle is neither production policy nor this increment's base.
Issue #10 remains open and describes the larger control-plane boundary. Its
historical prerequisite list is not evidence that merged components are absent.

Reviewed source includes the acquisition/reader contracts, worker/controller
design records, policy contracts, signer service/store/registry, and signer
tests. This is a bounded boundary audit, not an exhaustive security certification.
Research materials outside these repositories were excluded.

## Threat assumptions and attacker capabilities

- PR authors control proposed content, filenames, scripts, and workflow changes.
  Those bytes must remain data to trusted scanning code.
- Only a trusted verifier may supply `VerifiedOidcClaims`. No real token,
  private key, installation credential, or authenticated provider was needed.
- The selected weakness requires an otherwise authorized execution's request
  to wait for the shared transaction lock across an expiry boundary. Queue
  contention may be benign; a caller able to submit concurrent authorized
  requests could influence it. Production reachability is unproven.
- The registry, store, process, injected clock, and adapters are trusted in this
  reference model. A PR author is not assumed able to forge verified claims,
  alter registry records, or control server time.

## Boundary classification

| Boundary | Classification and evidence | Decision |
| --- | --- | --- |
| PR content versus trusted execution | Existing local contracts cover isolated scanner imports, raw object identity, unsupported-entry refusal, inert target code, and exact pull-ref acquisition. | Preserve; no speculative rewrite. |
| Head H versus test-merge M | Historical canary evidence records M regeneration during merge with fixed B/H. The commit worker defines only `P_v(H)`. | Already rejected design; no new M-only experiment. |
| Protected name and App source | Historical canary evidence shows an ordinary Actions App name can be spoofed; dedicated expected-App binding rejects the other source's success. Same-name failure can affect availability. | Already characterized; do not change remote contexts or claim availability isolation. |
| Policy integrity and version binding | Explicit selector registry, external expected digest, frozen epoch identity, exact mirror/coverage controls, and v1 compatibility tests already exist. PR #22 is candidate evidence. | Preserve all bundle and policy bytes. |
| Replay and authority downgrade | Existing tests cover fresh finalization JTI, malformed-evidence consumption, frozen revision, revocation, same-H slot conflicts, publisher-bound receipts, and UNKNOWN reconciliation. | Preserve these invariants. |
| Expiry under transaction contention | Confirmed reproducible weakness: both service entrypoints sample time before waiting for the transaction lock. Stale time can authorize after token/evaluation expiry. | **Selected: transaction-time freshness.** |
| Missing or malformed input | Exact types/keys, independent evidence binding, fixed refusal vocabulary, and no publication for infrastructure refusal have existing tests. | Preserve fail-closed handling. |
| Real OIDC, durable storage, App publication | Explicitly absent production adapters. Hypothetical deployment risks are not confirmed deployed vulnerabilities. | Outside this increment; no credentials or activation. |

## Selected finding and severity

**Medium, reference implementation only:** stale authorization time across
transaction lock acquisition. It defeats an explicit lifetime boundary and can
reach the mock publisher after expiry. It does not establish token forgery,
arbitrary verdict injection, a head mismatch, or a deployed GitHub bypass.

`SignerService.issue_evaluation()` and `finalize_evaluation()` originally read
`now` before entering `store.transaction()`. The same snapshot drives OIDC
validity and, respectively, ticket timestamps or evaluation expiry. A request
queued at time T can therefore use T after the lock becomes available at T2.

The regression holds the real shared RLock, queues a background service call,
waits for the transaction-entry signal, advances an injected logical clock,
then releases the lock. No expiry sleeps, remote writes, scanner execution,
forged token bytes, or modified registry policy are involved. The original
source produced five failing assertions; the corrected source passes all four
test methods, including their admission/finalization subcases.

The precise result and reproduction commands are in
[SECURITY-INCREMENT.md](SECURITY-INCREMENT.md).

## Remaining uncertainty

This correction establishes freshness at transaction entry. It does not provide
an atomic wall-clock deadline at remote publication: a future blocking reader,
publisher, durable transaction, or outbox needs a separately reviewed timing
contract. Clock trust and clock rollback are also outside this change. Frozen
inclusive expiry comparisons remain unchanged.

No live canary was rerun and no present-day branch-rule configuration is
asserted. Existing canary evidence is historical, scoped evidence. The Windows
test suite does not certify the fixed Linux controller runtime or a production
OIDC verifier. Independent evidence here means a reproducible regression using
a real lock and synthetic inputs; no separate human review is claimed.

## Sources

- [Signer frozen contract](repo-sentinel-signer-v1.md).
- [Commit-intrinsic authority](repo-sentinel-commit-authority-v1.md).
- [External policy root](repo-sentinel-external-policy-root-v1.md).
- Canary repository: `stacknil/repo-sentinel-authority-canary`, inspected
  commit `d34538c`. Source-binding evidence: `evidence/canary-results.md`.
  Test-merge rejection: `evidence/test-merge-authority-gate-1.md`.
- [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)
  documents token time, execution, repository, and workflow claims; it does not
  prove that this mock core cryptographically verifies them.
- GitHub Docs, "About protected branches", section "Require status checks
  before merging", describes expected-App status sources. Canary conclusions
  above come from the recorded experiments, not a new settings inspection.
