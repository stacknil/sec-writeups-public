# Repo Sentinel External Policy Root v1

Status: reviewed protocol plumbing only. Production authority is inactive. This
change creates no signer, GitHub App, workflow, status, branch rule, final v2
bundle, or production v2 bundle digest.

## Problem

The first controller protocol fixed the expected policy-bundle digest inside
controller source. Once the controller itself becomes a protected v2 control,
that design forms a cycle:

```text
controller bytes
  -> protected manifest
  -> bundle digest
  -> controller digest constant
  -> changed controller bytes
```

The policy identity must instead enter the trusted evaluation boundary from an
external authenticated policy-admission record:

```text
external authenticated policy root
  -> expected bundle digest
  -> trusted controller
  -> verified bundle
  -> P_v(H)
```

The controller validates an evaluation. It does not establish that the input
digest is authorized for production publication.

## Invariant

The controller supports exactly one selector and one trusted relative policy
root:

```text
selector: v2
policy epoch: repo-sentinel-authority-v2
bundle root: policy/repo-sentinel-authority/v2/
controller protocol: external-policy-root-v1
```

The caller cannot choose a bundle path, schema, mirror root, mandatory-control
set, scanner identity, or selector-to-epoch mapping. The expected bundle digest
is the only externally supplied policy identity. It must be an exact Python
`str` containing exactly 64 lowercase hexadecimal characters.

For a validated request, the same digest value is passed unchanged to bundle
verification, the commit-authoritative worker, worker-result validation, and
the controller result envelope. No repository-controlled runtime source
contains a final v2 digest.

## Design Decision

### Explicit trusted policy contracts

`PolicyBundleContract` is an immutable representation of a reviewed policy
contract. The verifier has an exact registry containing only `v1` and `v2`.
Callers pass a selector, not a caller-built contract.

The contract binds:

- bundle schema version;
- full policy epoch;
- worker semantic algorithm version;
- portable-path policy version;
- exact mirror root;
- mandatory protected paths;
- protected namespaces;
- scanner distribution, version, and artifact digest.

Unknown selectors fail closed. There is no `latest` lookup, directory scan, or
epoch inference from bundle contents.

### Version separation

The v2 contract deliberately keeps these existing semantics:

```text
bundle schema: 1
portable path policy: portable-v1
worker semantic algorithm: commit-authoritative-v1
scanner: repo-sentinel-lite 0.8.1
```

Only the policy epoch, mirror root, protected-control set, and controller
protocol change. The bundle digest domain remains
`repo-sentinel-authority-policy-bundle-v1` because serialization and hashing are
unchanged.

### External digest flow

The controller fixes the v2 selector, full epoch, and relative root. It accepts
an expected digest only after exact syntax validation and never compares it to
a compiled-in production digest. The worker receives both the selector and the
same digest. It resolves the selector through the trusted contract registry,
verifies the exact bundle, and derives mirror, protected, and coverage behavior
from that verified contract.

`AUTHORITY_RESULT` is retained to avoid an unnecessary result-name migration.
In `external-policy-root-v1`, it means a validated semantic authority evaluation
result only. It is not authenticated production publication authorization.
Direct local execution can produce `AUTHORITY_RESULT`; it cannot publish the
production Commit Status.

### Future signer registry record

A future signer-side registry record has an immutable `record_id` and
`revision`. Together they identify one reviewed record whose complete binding
includes at least:

```text
registry record ID and revision
repository ID
owner ID
policy selector
full policy epoch
approved bundle digest
controller protocol
trusted control source identity
approved workflow identity
action and dependency closure
runtime identity
scanner artifact identity
status context
dedicated App identity
```

The trusted control source identity includes the reviewed controller,
bootstrap, worker, verifier, acquisition, reader, and materializer closure. The
production workflow identity is recorded externally only after its source is
final. It is not written back into the protected repository tree.

No field in an admitted registry record may be updated in place. Changing any
field requires a new reviewed record and revision. Historical records remain
immutable even after they stop being active.

The registry enforces this epoch-to-digest invariant:

```text
(repository ID, full policy epoch) -> exactly one approved bundle digest
```

A frozen epoch cannot acquire a second meaning. Any semantic bundle-digest
change requires an explicit policy-epoch migration rather than a new digest
under the existing epoch.

Current activation is a separate, audited mapping:

```text
(repository ID, full policy epoch, status context)
  -> at most one active registry record revision
```

Activation is an explicit operation. A signer must never infer the active
record from the highest revision, newest timestamp, directory ordering, main
branch contents, or most recently observed record. Two active revisions for
one activation key make the registry invalid and evaluation fails closed.

This PR does not create that registry, choose a production App, or freeze a v2
record.

### Future evaluation admission record

Before production evaluation, a signer-side service must create an
authenticated server-side record containing at least:

```text
evaluation ID
registry record ID and revision
repository ID
exact head commit H
policy epoch
expected bundle digest
controller protocol
trusted control source identity
scanner artifact identity
workflow run ID
workflow run attempt
execution identity
issued-at time
expiry time
finalization state
```

Admission must resolve the uniquely active reviewed registry revision and
atomically persist that exact `record_id` and `revision` in the evaluation. If
the service cannot prove and persist one exact frozen revision, including
during a concurrent activation update, it must not issue an evaluation.

An evaluation ID is a lookup key, not a bearer authorization. The server-side
evaluation and registry records are authoritative. Client-returned revision,
digest, ticket JSON, controller result, or similar values are assertions to
compare, never authority to resolve or replace those records.

Operational admission fields stay outside `P_v(H)` and the worker semantic
digest. Run IDs, attempts, evaluation IDs, expiry, OIDC claims, and workflow
identity describe authenticated execution, not the commit-intrinsic policy
predicate.

### Registry lifecycle semantics

Finalization loads the evaluation server-side, then loads the exact immutable
registry record referenced by that evaluation. It validates the controller
result, OIDC identity, execution identity, approved workflow and dependency
closure, trusted control source, runtime and scanner identities, status
context, and dedicated App identity against those frozen records. It never
resolves a current, latest, highest, or otherwise newly active revision during
finalization.

For example, let registry revision R1 bind digest D1 and admit evaluation E.
If R2 is activated with a different allowed identity set before E completes,
E can only finalize under R1 and D1 or be rejected. It must never be
reinterpreted as R2, D2, R2's workflow or App, R2's control closure, or any
other current configuration.

Lifecycle operations have these fail-closed meanings:

- **Registry update:** affects future admission only. It cannot change an
  issued evaluation's referenced record.
- **Revocation:** may cause outstanding evaluations referencing the revoked
  record to be rejected. It cannot change their meaning, and the revoked record
  remains immutable historical evidence.
- **Expiry:** causes the evaluation to be rejected. There is no implicit
  refresh; another execution requires new admission and a new evaluation.
- **Rollback:** explicitly activates a reviewed record revision. It does not
  mutate a record, and outstanding evaluations remain bound to their admitted
  revisions.
- **Concurrent update:** admission must persist the selected revision
  transactionally, with compare-and-swap or an equivalent mechanism. It must
  not issue an evaluation whose exact frozen revision is uncertain.

The frozen registry record also governs publication identity. An evaluation
admitted under R1's status context and dedicated App identity cannot silently
publish through R2's context, App, or publisher policy.

These cases are normative regression requirements for a future signer service;
they do not claim that the service exists in this PR:

| Scenario | Required decision |
| --- | --- |
| R1/D1 admits E and no registry update occurs | Finalize only under R1/D1 after all frozen identities validate. |
| R1/D1 admits E, then R2 becomes active | Finalize under R1/D1 or reject; never reinterpret E under R2. |
| R1 is revoked before E finalizes | Reject E without changing its recorded meaning. |
| E expires before finalization | Reject E; require new admission for another execution. |
| Client claims R2 for an evaluation bound to R1 | Reject the mismatch. |
| Client changes the expected digest from D1 to D2 | Reject the mismatch. |
| Two revisions are active for one activation key | Treat the registry as invalid and fail closed. |
| An operation attempts to mutate R1 in place | Prohibit the operation. |
| New bundle semantics are proposed under a frozen epoch | Prohibit the change; require explicit epoch migration. |

## Threat And Failure Model

This protocol fails closed against:

- arbitrary or malformed digest values;
- caller-selected bundle paths or selector/path combinations;
- unknown selectors and unsupported epoch contents;
- v1 bundles presented as v2 and v2 bundles presented as v1;
- modified bundle bytes under a previously admitted digest;
- missing or modified mandatory controls;
- unreviewed workflow or action namespace members;
- v1/v2 mirror substitution or prefix fallback;
- worker results whose epoch or bundle digest differs from the request;
- a future caller treating local evaluation as signer authorization.

The protocol does not authenticate the external digest. Future production
security therefore depends on the signer registry, authenticated evaluation
admission, execution binding, expiry/replay controls, and dedicated App status
publication described above.

## Rejected Alternatives

1. **Keep the exact v2 digest in controller source.** Rejected because the
   controller is a v2 protected control and would recreate the self-reference
   cycle.
2. **Let callers provide arbitrary epoch/root pairs.** Rejected because it turns
   reviewed policy selection into input-controlled path selection.
3. **Discover the newest policy directory.** Rejected because directory state
   and ordering would decide authority outside a reviewed contract.
4. **Ignore all `policy/**` files during coverage.** Rejected because it would
   hide historical or unexpected policy artifacts instead of making a later v2
   migration decide them explicitly.
5. **Put workflow/OIDC/ticket fields into `P_v(H)`.** Rejected because those are
   operational authorization evidence, not commit-intrinsic semantics.
6. **Treat `AUTHORITY_RESULT` as publication authority.** Rejected because only
   a future authenticated signer-side finalization can authorize publication.

## Compatibility

The seven files below `policy/repo-sentinel-authority/v1/` remain byte-identical.
The v1 contract remains the default for the policy-bundle CLI and reproduces the
historical digest:

```text
6f25ebb773ce1453e8de623bca5aaecc936f1f188288f8df20aedeadb3bf4612
```

The v2 contract adds the bootstrap and controller to the mandatory protected
set while retaining complete `.github/workflows/**` and `.github/actions/**`
membership protection. No final `policy/repo-sentinel-authority/v2/` directory
is created here; tests build deterministic temporary bundles instead.

Acquisition, reader, materializer, scanner semantics, report schemas, v1
history, workflows, and branch rules are unchanged. Production authority stays
inactive.

## Validation

Validation for this boundary includes:

- exact v1 digest reproduction and contract-field verification;
- deterministic one-pass synthetic v2 bundle generation;
- digest mismatch and selector/root cross-wire rejection;
- bootstrap/controller mandatory-entry rejection;
- workflow/action namespace membership enforcement;
- exact v1/v2 mirror admission;
- controller digest pass-through and worker result binding;
- self-reference regression showing no generated digest is written into runtime
  sources;
- focused and full repository suites, lint, formatting, pre-commit, Markdown,
  taxonomy, snapshot, pattern-library, privacy, and credential checks;
- mutation checks for each removed digest back-edge and v1-global assumption.

Exact execution evidence belongs in the Draft PR validation record.

## Rollback

Before activation, rollback is a normal revert of the protocol-plumbing PR. No
production status, signer, App, workflow, branch rule, or v2 policy record needs
coordination because none is created here.

After a later v2 migration, rollback must be a new externally reviewed registry
revision. A signer must never silently fall back to v1, discover another policy
directory, or accept an unregistered digest.
