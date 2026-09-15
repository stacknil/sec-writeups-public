# Repo Sentinel Authority Controller v1

Status: candidate controller boundary for independent review. It is not
production-active and publishes no GitHub status.

## Problem

The commit-intrinsic worker defines the frozen predicate `P_v(H)`, but it assumes
that a trusted Python process has already imported the reviewed worker and
policy code. That assumption leaves a missing boundary between future trusted
GitHub-hosted execution and semantic evaluation.

The controller closes that gap for policy epoch `v1`:

```text
trusted GitHub-hosted execution envelope
        -> sanitized bootstrap
        -> trusted controller Python process
        -> exact H acquisition
        -> commit-intrinsic P_v(H)
        -> bounded canonical controller result
```

It does not authenticate a GitHub Actions invocation, publish authority, replace
the future signer, or certify a test-merge result.

## Invariant

Authority evaluation is reachable only after all of the following hold:

```text
absolute trusted CPython 3.12.3 Linux x86_64
+ isolated interpreter flags
+ exact fixed child environment
+ trusted control-root module identity
+ fixed production repository identity
+ exact refs/pull/<n>/head == H
+ fixed v1 policy bundle identity
+ distinct control, acquisition, and worker roots
```

The controller returns one of two outcomes:

```text
AUTHORITY_RESULT
INFRASTRUCTURE_REFUSAL
```

Only worker `PASS`, `SCANNER_FINDING`, and `POLICY_ADMISSION_FAILURE` results
become `AUTHORITY_RESULT`. Acquisition, runtime, bootstrap, orchestration,
worker-infrastructure, and cleanup failures become `INFRASTRUCTURE_REFUSAL`.
An infrastructure refusal carries no worker result or semantic digest.

## Design Decision

### Separate bootstrap and controller

`scripts/repo_sentinel_authority_bootstrap.sh` is a minimal POSIX bootstrap. It
does not discover Python from `PATH`, activate a virtual environment, source a
profile, import Python, or inspect repository content. The future trusted launch
configuration must supply:

1. an absolute trusted Python interpreter path;
2. the absolute reviewed controller entrypoint;
3. the controller request arguments.

The bootstrap clears known native-loader and shell-startup variables before it
executes `/usr/bin/env -i`. The Python child receives exactly:

```text
PATH=/usr/bin:/bin
LANG=C.UTF-8
LC_ALL=C.UTF-8
TZ=UTC
```

It launches the absolute interpreter with:

```text
-I -S -B
```

`-I` ignores Python environment and user-site influence, `-S` prevents site and
`.pth` startup processing, and `-B` prevents bytecode writes into the reviewed
control checkout.

The shell cannot undo loader or startup effects that occurred before the shell
process began. The future workflow must therefore launch the bootstrap itself
without target-controlled `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `BASH_ENV`,
or `ENV` state. On the approved Linux runtime, `/bin/sh` is the trusted,
non-interactive shell supplied by the runner image.

### Exact runtime and Git identity

The controller requires exactly:

```text
implementation: cpython
python_version: 3.12.3
os_family: Linux
architecture: x86_64
```

`3.12`, a later `3.12.x`, `3.13`, and PyPy are not equivalent for epoch `v1`.
The workflow must pass the resolved absolute interpreter path rather than a
caller `PATH` lookup or a virtual-environment shim.

The frozen acquisition module invokes `git`. The controller therefore fixes
`PATH` to `/usr/bin:/bin`, requires that lookup to select `/usr/bin/git`, rejects
symlink or reparse aliases, and runs a bounded `git --version` probe before
acquisition. A repository-local or caller-supplied `git` cannot participate.

### Trusted control root

The controller derives `CONTROL_ROOT` from its own absolute entrypoint. It does
not accept a caller-selected module root. Before imports, it rejects aliases and
requires the controller, acquisition, reader, materializer, policy-bundle, and
commit-worker modules to resolve to their exact reviewed files below:

```text
CONTROL_ROOT/scripts/
```

Only that scripts directory is explicitly added to `sys.path` after isolated
interpreter startup. `TARGET_ROOT`, the materialized commit, the caller's current
directory, `HOME`, and user site-packages are never added.

### Request contract

The strict request has exactly these fields:

```text
repository_id
owner_id
repository
remote_url
pull_number
head_oid
policy_epoch
expected_policy_bundle_sha256
scratch_root
scanner_artifact
```

Repository identity is fixed to:

```text
repository_id = 1130304545
owner_id = 219124580
repository = stacknil/sec-writeups-public
remote_url = https://github.com/stacknil/sec-writeups-public.git
```

The parser accepts each named option exactly once. It does not accept shell
fragments, environment-variable names, module names, command names, or a policy
bundle path. All subprocess calls use argument arrays and `shell=False`.

The operational pull number routes acquisition but is not passed into semantic
authority. No base SHA, merge base, current-main identity, test-merge SHA, PR
title, PR body, run ID, timestamp, or GitHub status field enters `P_v(H)`.

### Static policy selection

The only supported selector is:

```text
v1 -> policy/repo-sentinel-authority/v1/
```

The expected bundle digest is fixed in controller code:

```text
6f25ebb773ce1453e8de623bca5aaecc936f1f188288f8df20aedeadb3bf4612
```

The caller must repeat that digest, but cannot choose a different digest or
bundle path. Unknown epochs and digest disagreement fail before acquisition.
Future policy migration requires a separately reviewed controller change.

### Root separation and cleanup

The caller supplies an existing absolute `SCRATCH_ROOT`. The controller rejects
non-directories, symlinks, reparse points, unresolved paths, and overlap with
`CONTROL_ROOT`.

Inside verifier-owned scratch it creates one private workspace with sibling
roots:

```text
controller workspace/
  acquisition/
  worker/
```

The fresh Git database must be a descendant of `acquisition/`; worker scratch is
the distinct sibling `worker/`. The target cannot replace controller modules or
policy files through layout. The acquisition context cleans its Git database,
the worker cleans materialization and evidence, and the controller removes the
outer workspace. Cleanup failure overrides any earlier semantic success.

### Exact acquisition and worker handoff

The controller reuses the frozen acquisition contract to fetch only:

```text
refs/pull/<n>/head
```

It requires the acquired snapshot commit and fresh object database to bind exact
expected `H`. A mismatch is an infrastructure refusal. It then constructs the
frozen worker request from:

```text
repository ID
exact H object database
trusted v1 policy directory
trusted expected bundle digest
digest-verified scanner wheel path
private worker scratch
```

Repository content remains data. The target does not supply imports, commands,
environment variables, bundle selection, or executable control files.

### Bounded result envelope

Stdout contains exactly one canonical JSON object and a final newline. The
controller envelope contains:

```text
controller_schema_version
repository_id
head_oid
policy_epoch
policy_bundle_sha256
worker_result
worker_semantic_sha256
controller_outcome
fixed_refusal_code
```

Before returning authority, the controller validates the exact worker schema,
fixed repository and epoch identities, result counts, digest syntax, semantic
verdict/refusal relationship, report presence, and the worker's domain-separated
semantic digest. A malformed or infrastructure worker result is not reflected
as authority.

No raw report, path, URL, environment value, subprocess output, exception text,
token, or credential appears in the envelope. There are no untrusted display
fields, so newline, escape-sequence, and GitHub workflow-command injection are
not possible through diagnostics. The controller emits no free-form stderr.

## Threat And Failure Model

The production trust root will be:

```text
GitHub-hosted runner
+ reviewed immutable workflow SHA
+ reviewed bootstrap and controller files
```

The controller assumes that the runner kernel, dynamic loader, filesystem,
trusted workflow definition, absolute interpreter, `/usr/bin/env`, `/bin/sh`,
and `/usr/bin/git` are trusted. It does not defend against compromise of those
components.

After that launch boundary, it defends against:

- hostile `PYTHON*`, `HOME`, `XDG_*`, `PIP_*`, `REPO_SENTINEL_*`, virtualenv,
  shell-startup, loader, locale, timezone, and caller `PATH` state reaching
  Python or Git children;
- shadow `hashlib`, `json`, `sitecustomize`, `usercustomize`, `.pth`, fake
  Python, and fake Git artifacts in ambient or target-controlled locations;
- caller-selected repository, owner, remote, bundle, epoch, module, command, or
  control paths;
- ref movement or an acquired commit different from exact expected `H`;
- overlap or aliases between trusted controls and verifier scratch;
- target files being imported or executed;
- malformed, contradictory, or identity-reflecting worker results;
- raw Git, scanner, exception, environment, or filesystem diagnostics reaching
  stdout or stderr;
- stale semantic success surviving required cleanup failure.

Expected infrastructure failures include runtime mismatch, unavailable trusted
Git, network or acquisition refusal, filesystem errors, worker infrastructure
refusal, and cleanup failure. Future publication must publish nothing for these
outcomes.

## Rejected Alternatives

1. Inherit the parent environment and delete known variables.
   Rejected because a denylist cannot establish a complete process contract.
2. Discover Python or Git from caller `PATH`.
   Rejected because repository or user-local executables could shadow trusted
   tools.
3. Use `/usr/bin/env python` or activate a virtual environment.
   Rejected because interpreter identity would depend on ambient state.
4. Import controller modules before isolated interpreter entry.
   Rejected because `PYTHONPATH`, site hooks, and user configuration may have
   already affected imports.
5. Import worker code from acquired or materialized `H`.
   Rejected because the evaluated commit must remain data rather than control.
6. Allow caller-selected policy paths or digests.
   Rejected because the target could select its own authority policy.
7. Reuse base-relative or test-merge identity in `P_v(H)`.
   Rejected because those values are not intrinsic properties of exact `H`.
8. Convert infrastructure refusal into a semantic failure status.
   Rejected because future publication must distinguish no authority from an
   authoritative negative result.
9. Include raw diagnostics for convenience.
   Rejected because paths, URLs, credentials, hostile text, or workflow commands
   could cross the public result boundary.

## Compatibility

This change adds a controller boundary without modifying:

- workflow files, triggers, permissions, or branch/ruleset configuration;
- GitHub App, OIDC, signer, Commit Status, replay, or ticket protocols;
- pull-head acquisition refspec, protocol, redirect, depth, tag, timeout,
  repository-size, credential-isolation, or cleanup behavior;
- reader, materializer, base-relative worker, commit-worker, scanner, policy
  bundle, baseline, or report schemas.

The controller currently supports only production repository identity and epoch
`v1`. That deliberate narrowness is a compatibility boundary, not a general
controller framework.

## Validation

Focused tests cover:

- trusted bootstrap environment and flags;
- exact and wrong runtime identities;
- unknown epoch, wrong bundle digest, wrong repository identity, invalid and
  mismatched `H`, and invalid pull numbers;
- acquisition refusal and worker infrastructure refusal;
- worker `PASS`, `SCANNER_FINDING`, and `POLICY_ADMISSION_FAILURE` preservation;
- hostile Python, home, XDG, pip, virtualenv, Repo Sentinel, loader, and path
  environment state;
- fake Python, fake Git, shadow standard-library modules, startup hooks, user
  customizations, and `.pth` files;
- target Python and executable-looking files remaining data;
- fixed stdout, no raw diagnostics, cleanup override, and repeated deterministic
  results;
- mutation controls for environment inheritance, caller `PATH`, relative Python,
  missing isolated mode, policy selection, exact-head binding, target imports,
  raw exception output, and stale success after cleanup failure.

The existing commit-worker, base-relative worker, acquisition, reader,
materializer, gate, and full repository suites remain required regressions.

A production-style HTTPS probe must run on exact CPython 3.12.3 Linux x86_64
through the bootstrap. Public evidence records only trusted Python and Git
identity, repository ID, `H`, epoch, bundle digest, worker verdict and semantic
digest, controller outcome, and cleanup status. It must not record local paths,
tokens, or raw subprocess output.

## Rollback

No workflow or status publication is activated. Before a future workflow adopts
this controller, rollback is deletion of the bootstrap, controller, tests, and
this decision record.

After activation, rollback must point the immutable trusted workflow to a
previously reviewed controller/bootstrap SHA. It must not select policy or code
from target `H`, regenerate epoch `v1`, or weaken an infrastructure refusal into
a published semantic result.
