# Signer Transaction-Time Freshness

## Problem

An authorized request could wait for the signer lock across its token or
evaluation expiry, then be accepted using time sampled before that wait.
The bounded reproduction is documented in
[THREAT-BOUNDARY-AUDIT.md](THREAT-BOUNDARY-AUDIT.md).

## Invariant

Admission and finalization must sample authorization time after acquiring the
shared transaction lock. Expired OIDC is refused before admission or publication;
an expired evaluation with valid execution identity is refused after consuming
its finalization JTI, as required by the existing replay contract.

## Design decision

Move the existing `now = self._now()` statement inside `store.transaction()` in
the two service entrypoints. This changes two statement locations and introduces
no dependency, new error code, schema, authority source, or policy identity.
Ticket issuance time and TTL now begin at transaction entry. An existing
idempotent ticket retains its original frozen timestamps.

## Threat and failure model

The adversarial schedule is: request arrives with valid identity, waits behind
another lock holder, expires, then acquires the lock. Both new admission and
idempotent admission must refuse an expired identity. Finalization must refuse
expired identity or evaluation without reserving a slot or calling the publisher.
The local reproduction uses synthetic claims and a controlled clock; it assumes
neither stolen real credentials nor control over production server time.

## Rejected alternatives

1. Extend token/evaluation lifetimes or add queue-time grace. Rejected because
   this would weaken the frozen lifetime contract instead of checking it correctly.
2. Replace the shared lock with a new transaction/outbox architecture. Rejected
   because production persistence is a separate, unauthorized implementation scope.
3. Change `P_v(H)`, status contexts, or the candidate policy bundle. Rejected
   because none is responsible for this operational authorization-time defect.
4. Change equality-at-expiry semantics. Rejected because the existing inclusive
   contract is separate from the stale-time defect and remains explicitly tested.

## Compatibility

Existing valid requests, frozen registry selection, exact H, canonical payloads,
publisher source binding, JTI consumption order, and UNKNOWN transitions retain
their contracts. A request whose identity expires in the queue now fails closed.
The worker semantic digest contains no new operational timestamp. No workflow,
protected manifest, baseline, scanner policy, golden, or v1 bundle is changed.

## Validation

Environment: Windows, CPython 3.14.3, Git 2.53.0.windows.3. Tests use synthetic
fixtures and D-drive temporary storage. Ruff 0.16.7 uses `--isolated` so unrelated
parent-directory configuration cannot affect this repository's validation.

| Check | Result |
| --- | --- |
| Original signer suite before changes | 76 tests, OK. |
| New regression against original service | 4 methods run; FAILED (failures=5): three OIDC subcases, expired evaluation, and issuance timestamp. Inclusive-expiry control passed. |
| New regression after correction | 4 methods, OK. |
| All signer tests after correction | 80 tests, OK. |
| Full repository suite | 258 tests run: 253 passed, 5 platform skips. |
| Changed Python Ruff lint and format | Passed; two files already formatted. |
| Tags, README snapshot, pattern library | Passed. |
| Markdown/front matter | 157 files passed. |
| Pre-commit on the four changed files | Passed; out-of-scope hooks skipped. |
| Scanner integration | Synthetic PASS, FAIL, redaction, and import isolation passed. |
| Changed-file scanner without baseline | No findings. |
| Design-document markdownlint | 2 files, 0 errors. |
| Diff and manual privacy review | Passed; no credentials or machine identifiers added. |

The full-suite skips are four unavailable symlink cases and the POSIX-only
bootstrap test. They are not signer test skips. The placeholder script excludes
these design documents and reported no applicable Markdown; it is not a privacy
certification for these files. Manual review and the changed-file scanner cover
the new artifacts instead.

Initial tooling attempts found an unusable default Python launcher and a broken
virtualenv seed cache. Validation used an explicit CPython installation, a fresh
D-drive validation environment, and a separate virtualenv cache; no repository
test was weakened. An initial Ruff invocation inherited unrelated parent config;
the reported checks above use isolated configuration. Scanner false positives
on long public references and a test identifier were resolved with concise
references/naming, without baseline or suppression changes.

Exact commands, run from the repository with the validation Python environment
on PATH (all test fixtures are local):

```powershell
python -m unittest tests.test_repo_sentinel_signer_time -v
python -m unittest discover -s tests -p 'test_repo_sentinel_signer*.py'
python -m unittest discover -s tests -p 'test_*.py'
python -m ruff check --isolated --select E4,E7,E9,F,B signer/repo_sentinel_signer/service.py tests/test_repo_sentinel_signer_time.py
python -m ruff format --isolated --check signer/repo_sentinel_signer/service.py tests/test_repo_sentinel_signer_time.py
python scripts/render_tags_doc.py --check
python scripts/render_readme_snapshot.py --check
python scripts/check_pattern_library.py
python scripts/check_markdown.py
python scripts/test_repo_sentinel_integration.py
git diff --check
```

Pre-commit, the no-baseline changed-file scan, and markdownlint were passed the
exact four-file list below (markdownlint received only the two Markdown files).
No standalone build or static type-check configuration applies to this change.

To reproduce the original failure independently, create a disposable worktree
at base `d35e5a6` on the D drive, copy only
`tests/test_repo_sentinel_signer_time.py` into it, and run the first command.
Alternatively, in a disposable copy of this increment, move the two clock
reads back above their transaction blocks. Do not alter a dirty user checkout.

The tests observe externally meaningful decisions, timestamps, JTI replay,
slot creation, and publisher calls. They do not merely assert source placement.
Event synchronization makes the schedule deterministic; a five-second timeout
only detects a broken test setup and is not an expiry threshold.

## Precise changed-file list

- `signer/repo_sentinel_signer/service.py`: sample time after lock acquisition.
- `tests/test_repo_sentinel_signer_time.py`: contention regression and controls.

Two documents under `docs/design-decisions/`:

- `THREAT-BOUNDARY-AUDIT.md`: baseline, classifications, assumptions, severity,
  and evidence boundaries.
- `SECURITY-INCREMENT.md`: correction and reproduction.

## Rollback and release boundary

Revert this local correction and its regression/documentation together if review
rejects it; doing so restores the demonstrated stale-time weakness. No remote
status, deployment, credential, schema, or policy migration is needed.

This increment is local only. A later authorized security-boundary PR must be
draft and receive next-day review before merge. Production adapters and
publication-time expiry semantics require their own evidence and authorization.

Recommendation: **ACCEPT** the bounded local correction. A local commit attempt
was blocked because the configured GPG signer had no available secret key. The
four-file change remains staged on its dedicated branch. Signing was not
disabled, no key material was collected, and nothing was pushed or published.
