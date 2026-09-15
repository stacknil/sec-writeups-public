# Repo Sentinel Commit Authority v1

Status: candidate policy epoch for independent review. It is not production-active.

## Problem

The existing authoritative worker evaluates a pull request relative to a trusted
base. That remains useful for changed-file policy, but its result is not an
intrinsic statement about one commit. Reusing that schema for commit authority
would make a status depend on a base SHA and pull request identity that are not
properties of the target commit.

The new boundary needs to answer one narrower question:

```text
Does exact commit H satisfy one immutable, externally selected policy epoch v?
```

## Invariant

The semantic predicate is:

```text
P_v(H) =
  exact snapshot H satisfies epoch-v admission and coverage policy
  AND protected controls match epoch v
  AND every suppression-bearing file is approved by epoch v
  AND the complete policy-scoped scan has no unsuppressed error findings
```

Its semantic result depends only on exact `H`, immutable epoch `v`, and the
immutable repository ID bound into the result. It does not accept or encode a
base SHA, pull request number, run identity, timestamp, temporary path, or
mutable branch state.

`P_v(H)` does not certify a future merged result. The same `H` in different pull
requests intentionally shares authority, and movement of a base branch does not
invalidate `P_v(H)`.

## Design Decision

### Separate worker

`scripts/repo_sentinel_commit_authoritative.py` is a separate semantic worker.
The reviewed base-relative worker in `scripts/repo_sentinel_authoritative.py`
remains independently usable and unchanged.

The commit worker reads an exact Git snapshot through the existing reader and
materializes it through the existing portable-v1 materializer. Repository
content remains data. Repository scripts are never imported or executed.

### Immutable policy bundle

The candidate bundle is stored under:

```text
policy/repo-sentinel-authority/v1/
```

It contains exactly:

```text
epoch.json
scanner-config.toml
baseline.json
protected-manifest.json
suppression-manifest.json
coverage-policy.json
dependencies.json
```

The bundle does not contain its own digest. The caller supplies the expected
digest from trusted configuration, and the worker recomputes:

```text
SHA256(
  domain separator
  + sorted relative path length
  + sorted relative path bytes
  + exact file byte length
  + SHA256(exact file bytes)
  ...
)
```

`epoch.json` binds the digest of every other component, the worker and portable
path-policy versions, the scanner distribution and wheel, and the supported
runtime tuple. Unknown files, missing files, duplicate JSON keys, duplicate
logical manifest paths, unsupported schema versions, or digest disagreement
fail closed.

The seven files committed at the same repository path are a reviewable mirror,
not the authority source. Before scanning, the worker requires that mirror to
match the separately supplied trusted bundle byte-for-byte with mode `100644`.
Missing, modified, additional, or ASCII-case-aliased mirror paths are a policy
admission failure. This special admission avoids a digest cycle in which the
baseline would contain findings for component hashes that themselves bind the
baseline. The external expected bundle digest remains the root of authority.
The mirror is marked `-text` in `.gitattributes` so checkout conversion cannot
change its bytes; `.gitattributes` is itself a protected control.

### Scanner identity and runtime

Epoch v1 pins:

```text
distribution: repo-sentinel-lite
version: 0.8.1
wheel SHA-256: 0a949a4d00c6e6ae37eba60a6cb74e4e15bc3ec5fce2f1d4c99aa0ef309b36e3
runtime: CPython 3.12.3, Linux, x86_64
runtime dependencies: none
```

The worker verifies the wheel bytes, copies them into verifier-owned scratch,
and imports the scanner directly from that wheel. It does not trust an ambient
installation. The scanner child uses an absolute interpreter, isolated mode, a
trusted working directory, `shell=False`, and a fixed environment containing
only locale and timezone values.

### Launch-boundary ownership

The commit-authoritative worker does not establish trust for the Python process
that imports it. Interpreter startup, native-loader state, import path,
user-site state, home-derived Python configuration, and equivalent pre-entry
process state are trusted launch preconditions. `_scanner_environment()`
protects the scanner child; it does not retroactively protect worker imports.

Responsibility is divided into three explicit boundaries:

```text
outer process bootstrap isolation  -> future production controller
worker semantic isolation          -> repo_sentinel_commit_authoritative.py
scanner child isolation            -> worker child environment
```

The future production controller must launch an absolute trusted Python
interpreter, use Python isolated mode where applicable, neutralize `PYTHON*`,
user-site and import customization, relevant `HOME` and `XDG_*` inputs,
`LD_PRELOAD`, `LD_LIBRARY_PATH`, and `DYLD_*`, use a controlled locale and
trusted working directory, and either control `PATH` or avoid depending on it.
Its acceptance tests must launch through hostile values for those inputs,
including a marker-producing shadow standard-library module, and require zero
marker execution, canonical bounded output, and the same `H`/epoch semantic
result. That controller and its regression are intentionally outside this
inactive worker PR.

### Config and baseline ownership

The scanner config and baseline are trusted epoch components. Exact canonical
copies must also exist in `H` with the approved Git mode and byte digest.

The target config remains present because scanner 0.8.1 reads it from the scan
root. The worker verifies it before and after materialization. The scanner CLI
is invoked with `--no-default-baseline` and an explicit `--baseline` path to the
trusted bundle copy; it never regenerates or derives a baseline from `H`, a base
branch, or current main.

### Protected controls and suppressions

The protected manifest binds exact logical path, Git mode, and SHA-256 of file
bytes. It also owns complete membership under `.github/workflows/` and
`.github/actions/`. Portable-v1 ASCII aliases are checked without Unicode
casefolding or normalization.

Before scanner exclusions, every snapshot blob is checked for the pinned 0.8.1
inline-suppression grammar across its supported text encodings. Every detected
suppression must have an exact approved path, mode, and content digest.

### Full-tree coverage

The scanner is never invoked with `--changed-files`. An independent inventory
classifies every snapshot file as:

```text
SCANNED
APPROVED_CONFIG_EXCLUSION
APPROVED_POLICY_BUNDLE_MIRROR
APPROVED_BINARY_EXCLUSION
APPROVED_OVERSIZE_EXCLUSION
APPROVED_UNSUPPORTED_ENCODING_EXCLUSION
```

The trusted scanner adapter records every successfully scanned logical path.
It also filters only the already admitted bundle mirror from scanner input; the
ordinary config exclusions remain governed by the pinned scanner semantics.
The worker reconciles the scanned path set and every reported skipped path
against the independent inventory. Aggregate counts are validated only after
path-level equality. Unreadable paths, symlink policy skips, unexplained
ignored files, unknown reasons, malformed coverage, or count/path disagreement
are infrastructure refusals or policy admission failures, never PASS.

### Result identity

The result has a dedicated schema and a domain-separated SHA-256 over canonical
JSON. Operational paths and run metadata are excluded. PASS, scanner findings,
and policy admission failures receive a semantic digest. Infrastructure
refusals receive no semantic authority.

Future publication semantics are intentionally outside this change:

```text
PASS                     -> success
SCANNER_FINDING          -> failure
POLICY_ADMISSION_FAILURE -> failure
INFRASTRUCTURE_REFUSAL   -> publish nothing
```

## Threat And Failure Model

The boundary assumes the reader's Git object database and verifier scratch are
owned by trusted compute for the duration of evaluation. It defends against:

- target changes to config, baseline, protected controls, or protected namespace
  membership;
- target changes to the reviewable in-tree policy-bundle mirror;
- new, moved, copied, re-encoded, or mode-changed inline suppressions;
- scanner omissions through config globs, binary detection, size limits, or
  encoding handling;
- target Python shadow modules, startup hooks, `.pth` files, and executable
  repository content;
- post-entry ambient environment influence over scanner Python, loader,
  package, locale, home, or path resolution;
- malformed, contradictory, oversized, missing, or incomplete scanner reports;
- temporary-directory, run-order, pull-request, or base-identity influence over
  the semantic digest.

Filesystem runtime failures, scanner timeouts, output overflow, cleanup failure,
and runtime mismatch are infrastructure refusals. They must not be translated
into PASS or a semantic failure status.

## Rejected Alternatives

1. Reuse the base-relative worker with an optional mode.
   Rejected because one schema would ambiguously represent two authority models.
2. Trust config or baseline bytes from `H`.
   Rejected because the evaluated commit could grant itself suppressions.
3. Treat a full-tree CLI invocation as coverage proof.
   Rejected because scanner 0.8.1 can omit ignored paths without reporting them.
4. Validate only aggregate coverage counts.
   Rejected because equal counts do not prove equal path coverage.
5. Inherit the parent environment and remove known-dangerous prefixes.
   Rejected because denylist isolation leaves unknown fallback channels.
6. Execute whichever scanner is installed in the runner environment.
   Rejected because a version string does not bind installed code to the reviewed
   wheel artifact.
7. Store the policy bundle digest inside the bundle.
   Rejected because it creates a self-referential identity.

## Compatibility

The reader, materializer, acquisition worker, base-relative authority worker,
scanner semantics, report schemas, workflow triggers, and branch rules are not
changed. The candidate v1 policy accepts the repository's existing strict UTF-8
logical paths through the merged reader/materializer contracts.

Any policy change requires a new epoch and an explicit migration decision. A
future controller needs a reviewed migration exception because changing the
controls that select v2 cannot be authorized by silently mutating v1.

## Validation

The implementation is covered by focused tests for schema identity, protected
controls, suppressions, full-tree coverage, report validation, runtime and
environment isolation, deterministic digest behavior, materialized readback,
and infrastructure cleanup. The final Draft PR records exact full-suite,
mutation, and real scanner evidence after the bundle is generated from the
staged reviewed state.

Outer process bootstrap isolation is a mandatory acceptance test for the future
production controller. It is not claimed by this worker's post-entry scanner
environment tests.

The baseline-provenance regression constructs a valid authenticated bundle
whose trusted baseline bytes differ from the separately protected repository
baseline in `H`. It asserts that the scanner receives the bundle bytes. Replacing
`bundle.baseline` with the target snapshot's `.reposentinel-baseline.json` bytes
changes the test result from PASS to infrastructure refusal and fails the test.
This kills the target-derived-baseline mutation without changing the candidate
policy bundle.

The administrative bundle command is:

```bash
python scripts/repo_sentinel_policy_bundle.py build \
  --repository . \
  --bundle policy/repo-sentinel-authority/v1 \
  --python-version 3.12.3 \
  --os-family Linux \
  --architecture x86_64
```

Evaluation never runs this command. Verification recomputes every component and
bundle digest without regeneration:

```bash
python scripts/repo_sentinel_policy_bundle.py verify \
  --bundle policy/repo-sentinel-authority/v1 \
  --expected-sha256 EXPECTED_BUNDLE_SHA256
```

## Rollback

This change adds no workflow and publishes no status. Before activation, rollback
is deletion of the new worker, bundle utility, candidate epoch, tests, and this
record. After a future epoch is activated, rollback must select a previously
reviewed immutable epoch through the separate trusted controller; manifests must
never be regenerated during evaluation.
