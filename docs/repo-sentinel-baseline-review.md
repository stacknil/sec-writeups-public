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

### Trusted Object-Graph Foundation

Issue #10 separates the next control-plane work into independently reviewable
changes. This first foundation does not add a privileged event or claim merge
enforcement.

The orchestration module now exposes `build_gate_plan_from_graph()` so a future
base-owned caller can derive the same protected-policy, changed-path,
deletion-only, and accepted-base baseline decisions from a verifier-owned Git
object database without checking out the pull-request tree. All Git reads made
by the module use `--no-replace-objects`; a real replacement-ref regression
proves that the accepted-base baseline retains its original bytes.

The scanner invocation also accepts a separate execution directory and passes
the target repository as an absolute data path. This is the seam needed to keep
a future trusted caller outside the materialized target. Python isolated mode
continues to protect the installed scanner import. Existing callers retain their
current working directory by default, so changed-file error blocking, warning
reporting, deletion-only audit behavior, and baseline selection are unchanged.

This foundation does **not** fetch a pull-request ref, parse arbitrary trees,
materialize files, add `pull_request_target`, attach a result to a PR head, or
configure a required check. The next draft must implement a bounded regular-file
reader and its refusal states before adding the advisory workflow. The later
canary must then prove that target-owned workflow/helper changes remain data and
inspect the resulting Check API `head_sha` before any enforcement decision.

**Main risk:** a later caller could use the graph-planning API with an object
database or interpreter it does not actually control. **Compatibility impact:**
none is intended for the existing workflow; the new API is additive and the
default scanner working directory is preserved. **Rollback:** revert this
foundation without changing the corpus, baseline, report format, workflow event,
permissions, credentials, or repository settings.

### Bounded Raw Snapshot Reader

`scripts/repo_sentinel_reader.py` adds `read_snapshot(repository, commit_oid)`
for the next Issue #10 data-plane boundary. It returns an immutable `Snapshot`
with the commit, root tree, and sorted `(path, mode, oid, data)` file records.
It reads a caller-owned, stable object database without a target checkout.
The caller must trust Git, local repository configuration, and object storage.

The reader accepts full lowercase commit OIDs in SHA-1 and SHA-256 repositories.
It independently hashes the Git framing and raw bytes of every commit, tree,
and blob before using them. Tree membership is parsed from those verified raw
tree bytes. No-replace lookup applies to every Git command. Ambient `GIT_*`
variables and global/system Git config are excluded; lazy fetching is disabled.
Archive attributes, textconv, checkout filters, and executable file modes do
not transform or execute the returned bytes.

Path admission now represents logical Git-tree identity rather than host
filesystem portability. Each raw component must decode as strict UTF-8,
re-encode to the original bytes, and remain within the 255 raw-byte component
bound. Empty components, raw `/`, exact `.` or `..`, C0/C1 controls, DEL,
malformed framing, exact duplicate paths, and exact file/directory namespace
conflicts refuse the complete snapshot. Symlinks, gitlinks and other modes
remain unsupported.

The strict UTF-8 rule is a deliberate compatibility boundary for this reader,
not a claim that arbitrary non-NUL, non-slash Git path bytes are invalid Git.
Decoded names are not normalized, case-folded, transliterated, or repaired.
Logical identity is exact Python `str` equality, so case variants and NFC/NFD
variants remain distinct and exact-string sorting stays deterministic. Host-only
concerns such as `.git`, backslash, colon, Windows device names, wildcards, and
trailing dots or spaces are intentionally left to the materializer. Ordinary
Unicode and inert punctuation such as `&`, apostrophes, `!`, `~`, and `$` are
admitted without filename-specific exceptions.

Defaults bound the complete read to 4,096 files, 8,192 object reads, 16 MiB of
cumulative raw object bodies, 2 MiB per blob, 32 directory levels and 30 seconds.
Repeated objects count again. Output reads stop after the remaining byte cap
plus one sentinel byte, and a deadline timer kills a stalled Git child. The
byte budget is not an exact resident-memory or Git-internal allocation limit.
Failures raise `ReaderRefused` with a fixed code and return no partial snapshot;
raw Git stderr and target content are excluded from refusal messages.

Real bare-repository tests exercise both object formats, raw binary content,
archive attributes, replacement refs, type/mode mismatch, unsafe paths,
collisions, malformed trees and file/object/byte/depth budgets. A stalled child
checks the deadline, and injected transport corruption checks independent
identity validation. Run
`python -m unittest discover -s tests -p 'test_repo_sentinel_reader.py'`.

These APIs are not wired into the scanner or workflow yet. PR-ref acquisition,
producer/head binding, and enforcement remain separate work. Existing scan and
baseline behavior is unchanged. Rollback restores the prior reader/materializer
contract; there is no persisted state or migration.

### Temporary Snapshot Materialization

`materialized_snapshot(repository, commit_oid, scratch_root)` is a context
manager in `scripts/repo_sentinel_materialize.py`. It calls the bounded reader
before creating output. Only a complete snapshot can create a fresh private
directory below an existing, caller-owned scratch root. The scratch root itself
must be a real directory, not a symlink or Windows reparse point; its ancestors
and stability are caller trust requirements.

The empty private staging container is created first so root-dependent path
limits can be evaluated. Before any snapshot subdirectory or file is populated,
the materializer revalidates every `SnapshotFile.path`, derives all implicit
directories, and completes indexed collision and type-prefix checks across the
whole tree. This independent preflight also protects against caller-constructed
`Snapshot` values that did not originate in the reader.

Canonical materialization rejects Windows separators, drive/UNC/device forms,
ADS colons, reserved punctuation and device names, including the Windows-defined
superscript-digit `COM`/`LPT` aliases, trailing dots/spaces, and
ASCII-case-insensitive `.git` components on every supported host. Portable-v1
case aliases use an explicit ASCII-only `A-Z` mapping independent of the runner
OS. NFC and NFD keys detect Unicode portability aliases separately without
changing logical identity. This deterministic policy does not claim to emulate
every evolving filesystem-specific Unicode casing rule. Full Unicode lowercasing
or case folding is not used, so names such as `ẞ`/`ß`, `ß`/`SS`, and `İ`/`i`
remain distinct. Logical names can therefore be reader-valid but
materializer-invalid by design.

The preflight retains the reader's 255-byte component and depth bounds. It also
checks UTF-16 component and conservative `MAX_PATH` length against the actual
private staging root on Windows, and runtime `pathconf` component/full-path
limits on POSIX. Unavailable or indeterminate POSIX limits refuse the operation;
the absolute limit is consequently a documented runtime-root precondition
rather than an emulation of a foreign filesystem. Validated component tuples
are joined with `root.joinpath(*components)`; unvalidated logical path strings
never reach host path joining.

Files are created exclusively and read back with exact byte comparison before
the context yields `MaterializedSnapshot(snapshot, root)`. Existing files and
symlinks are never overwritten. Directory entries are checked before use;
regular files use no-follow reads where supported. Source Git modes remain in
the snapshot metadata, while output files request POSIX mode `0600` and
directories request `0700`, both subject to umask. Windows permissions depend
on the trusted parent ACL.
No source hook, import, action, attribute or executable file is run.

Normal exit, setup refusal and consumer exceptions clean the temporary output.
`MaterializationRefused` carries fixed reason codes, without raw OS error text.
Cleanup failure is explicit as `cleanup_failed`; it may supersede an earlier
exception and can leave residual output for the scratch owner to handle. A
hard process crash is outside this context-manager cleanup guarantee.

The caller must prevent concurrent mutation by other processes or the consumer.
These checks do not defend against a hostile local actor changing ancestors or
files during use. Reader byte/count limits bound the selected data, but its
deadline does not bound filesystem I/O, cleanup or consumer execution. Host
path-length or disk failures refuse materialization rather than shortening
paths or returning fewer files. Empty Git directories are not part of the
reader's file snapshot and are not reconstructed.

Run
`python -m unittest discover -s tests -p 'test_repo_sentinel_materialize.py'`
for real-object and direct-`Snapshot` fixtures covering bytes, executable-mode
metadata, empty files/trees, lifecycle, layered path refusal, aliases,
normalization and type collisions, path limits, preflight atomicity, symlinks,
same-length corruption, partial setup failures, and cleanup failures. Scanner
execution, PR-ref acquisition, and workflow activation remain unwired. Rollback
restores the prior reader/materializer contract; there is no persisted output
format or repository-setting migration.

### Exact Pull-Head Acquisition

`acquire_pull_snapshot(remote, pull_number, expected_head_oid, scratch_root)`
creates a fresh bare object database below a caller-owned scratch directory. It
fetches only `refs/pull/<number>/head` into one private ref, requires that ref to
equal the expected full lowercase SHA-1 or SHA-256 OID, and calls the existing
bounded reader before yielding `AcquiredSnapshot`. No checkout is created.

Network remotes are restricted to credential-free HTTPS URLs without query or
fragment data. A `Path` remote exists only for caller-controlled local fixtures.
Git runs with inherited `GIT_*` variables and global/system configuration
removed. Terminal prompting is disabled, inherited Git/SSH askpass helpers are
neutralized, and `SSH_ASKPASS_REQUIRE` cannot force a parent helper. Replacement
lookup and redirects are disabled, protocol selection is restricted, and
automatic maintenance is disabled.
The fetch is depth one, writes no `FETCH_HEAD`, imports no tags or submodules,
and uses an explicit force refspec into the fresh database.

The only resulting ref must be `refs/repo-sentinel/acquired-head` at the exact
expected OID. A moved or missing PR ref, an unexpected ref set, an object-format
mismatch, fetch failure, or reader refusal cannot yield a snapshot. The reader
then independently validates raw commit, tree and blob identities and admission
limits; acquisition does not replace those checks.

The default acquisition timeout is 60 seconds for initialization, fetch and ref
verification. The reader retains its separate timeout. A 64 MiB repository-size
check runs after fetch; it makes an over-budget result fail closed but is not a
hard transport or peak-disk quota because Git may exceed it before the fetch
returns. A trusted Git executable and enough scratch capacity for that interval
remain preconditions.

Normal exit, setup refusal and consumer exceptions remove the fresh database.
Cleanup failure is explicit and may leave residual files for the scratch owner.
Tests cover SHA-1/SHA-256 acquisition, exact raw bytes, unrequested refs, ref
movement, missing refs, input validation, reader refusal, timeout, repository
budget, symlinked scratch input and lifecycle cleanup.

Before the path-contract merge, a read-only HTTPS probe acquired the exact PR
#15 head `2f7b7a9bef43715141086b0d79bacbe67a178288` and tree
`960dc6c6496f1260f6fab74b64f26408024cd5fb`, then the reader refused
`unsupported_path`. Eight of that public tree's 242 regular-file paths were
outside the former portable ASCII reader subset. That historical result remains
evidence that acquisition propagated downstream reader refusal without
rewriting names, omitting files or yielding a partial snapshot.

After the path contract merged in PR #17 at
`d8e30ba019247a21b9d42e1c1d52900a1f1de623`, the same exact-head probe traversed
acquisition, the logical-path reader and the portable materializer. All 242
paths, modes and blob OIDs were preserved with exact file bytes, totalling
2,260,062 bytes. The SHA-256 manifest over each ordered
`path NUL mode NUL oid NUL sha256(data)` record was
`ad39acf89d0826ce2651ed14d12e143d7f0a8b5cb6b2eb219b46895688f45d0a`.
Both the bare acquisition database and materialized target were removed after
their contexts exited. Repository content was handled only as data and was not
executed; acquisition remained checkout-free.

This helper is not connected to a workflow or scanner invocation. It does not
add `pull_request_target`, secrets, caches, Check API writes, permissions or
repository enforcement. Rollback removes the acquisition helper/tests/docs;
the merged reader and materializer remain independently usable.

### Authoritative Worker Core

`scripts/repo_sentinel_authoritative.py` adds the data-only worker core for a
future authoritative gate. It is deliberately separate from GitHub event
parsing and from the dedicated-App publisher. The caller supplies validated
repository identity, pull request number, exact base/head object IDs, a trusted
base object database, a scratch root and an evidence root. The worker neither
derives identity from pull request text nor publishes a status.

The worker reads the trusted base with `read_snapshot()`, acquires the exact
head with `acquire_pull_snapshot()`, and computes D1 directly from immutable
snapshot records. A path is changed when it is absent from base or its mode or
blob object ID differs; a path is deleted when it is absent from head. There is
no rename inference and no GitHub changed-files API input. Indexed maps plus
deterministic sorting keep the operation O(n log n).

Before materialization or scanner execution, changed and deleted paths are
checked against the protected control plane:

- `.reposentinel.toml` and `.reposentinel-baseline.json`;
- `.github/workflows/**` and `.github/actions/**`;
- the existing gate, acquisition, reader, materializer, authoritative worker
  and integration-test scripts.

The exact `repo-sentinel-lite==0.8.1` wheel was also inspected for target-owned
suppression mechanisms. Its inline pattern is the concatenation of
`r"repo-sentinel:\s*"` and
`r"allow(?:\s+(?P<rules>[A-Za-z0-9_.\-, ]+))?"`, matched case-insensitively.
With no rule list it allows all findings on the finding line; with a
comma-separated kind/rule-ID list it allows matching findings. The scanner
checks the finding line and the immediately preceding line. It attempts
`utf-8`, `utf-8-sig`, `utf-16` and `cp1252` text decoding.

The worker uses a conservative source-control policy: if any changed or
deleted file contains that directive in either the base or head snapshot, the
change is classified as protected rather than scanned. This can block an
ordinary edit to a file that already carries a legitimate suppression, but it
prevents pull-request-owned source annotations from weakening the
authoritative result without introducing a bypass channel.

Scanner configuration resolution in `0.8.1` reads only
`<scan-root>/.reposentinel.toml`; it does not search parent directories, the
home directory or environment-selected alternate paths. A changed or deleted
root config is protected. The default baseline is always disabled. When the
base snapshot contains `.reposentinel-baseline.json`, its exact bytes are
written exclusively to a verifier-owned temporary file and passed with an
explicit `--baseline` argument. Head-owned default-baseline discovery never
becomes authoritative.

Only the admitted head snapshot is passed to `materialized_snapshot()`. The
worker additionally requires the acquired object database and materialized
target to stay below the caller-owned scratch root, while the target remains
disjoint from both object databases, the trusted execution directory and the
evidence root. The scanner runs as `python -I -m repo_sentinel` from a separate
trusted temporary control directory with `shell=False`, bounded stdout/stderr,
an explicit timeout and a report-size cap. Pull-request files named
`repo_sentinel.py`, `sitecustomize.py`, `usercustomize.py` or `*.pth` remain
materialized data rather than import sources.

Raw scanner output, report text and target paths are not printed. The result
contains a fixed verdict, exact base/head identities, changed/deleted counts,
report size and SHA-256, and the verified scanner version. Scanner errors,
malformed or missing reports, timeouts, size violations and cleanup failures
become fixed-code infrastructure refusals. Error findings block, warnings keep
the scanner's existing non-blocking contract, and ordinary deletions are
accounted separately rather than scanned.

This draft core does not add workflow YAML, credentials, GitHub App key or token
handling, Commit Status or Checks API calls, repository settings, or the
authoritative context name. Activation remains a later boundary after worker
and signer review. Rollback removes this module, its isolated tests and this
section without changing the existing informational workflow or baseline.

## Relationship To Issue #5

This record closed [issue #5](https://github.com/stacknil/sec-writeups-public/issues/5)
through pull request #8 without treating the historical development-line counts
as current consumer evidence. Future comparisons should always record the exact
`repo-sentinel` release or commit used for the audit. Issue #9 adds regression
coverage for the consumer workflow boundary without changing the reviewed
baseline or warning policy.
