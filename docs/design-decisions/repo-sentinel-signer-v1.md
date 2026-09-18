# Repo Sentinel Signer v1 Reference Core

Status: mock-only reference implementation for review. Production authority is
inactive. This change creates no GitHub App, private key, installation token,
network OIDC verifier, HTTP service, workflow, Commit Status, or branch rule.

## Problem

The trusted controller can produce bounded evidence for the commit-intrinsic
predicate `P_v(H)`, but that evidence is not publication authorization. Target
repository content cannot select the policy, workflow identity, status context,
or publisher identity that gives the result authority.

The signer must establish a separate authorization chain:

```text
verified GitHub execution identity
  -> explicitly activated immutable registry revision
  -> server-side pull request head H
  -> immutable evaluation record
  -> independently validated controller evidence for P_v(H)
  -> one commit-scoped publication payload
  -> reviewed publisher adapter
```

This first implementation stops at a deterministic mock publisher. Its purpose
is to make the state machine, refusal behavior, concurrency rules, and adapter
boundaries executable before any production credential or remote write exists.

## Invariant

Authority is split into five independent statements:

```text
OIDC verifier        establishes execution identity
registry             establishes policy authorization
evaluation record    freezes registry revision and H
controller result    establishes bounded P_v(H) evidence
publication slot     establishes one immutable verdict payload for R/H/v
                     and one immutable publisher source
```

The publisher is only an output adapter. It does not select policy or reinterpret
evidence.

The signer protocol identifier is:

```text
repo-sentinel-signer-v1
```

The admitted controller protocol remains:

```text
external-policy-root-v1
```

Three negative boundaries are explicit:

- `evaluation_id` is an opaque lookup key, not a bearer capability.
- A controller `AUTHORITY_RESULT` is evidence, not publication authorization.
- Candidate v2 evidence and its digest are not production policy and are absent
  from signer registry fixtures and defaults.

## Design Decision

### Verified execution identity

`OidcVerifier` converts a raw token into `VerifiedOidcClaims`. The authorization
core accepts that exact immutable model, never an arbitrary decoded JWT mapping.
Only `MockOidcVerifier` exists in this change, and its name states that it performs
no cryptography. A production adapter must verify the signature, issuer, audience,
and token validity before constructing the model.

The verified model contains exact issuer, audience, subject, token ID, time
claims, repository identity, owner identity, event, runner environment, workflow
identity, run identity, and optional paired reusable-workflow identity. Numeric
repository and run claims accept integers or canonical decimal strings only.
Booleans, floats, signs, whitespace, leading zeroes, negatives, and non-decimal
forms fail closed.

Authorization requires:

```text
issuer             https://token.actions.githubusercontent.com
audience           repo-sentinel-authoritative-signer-v1
event              pull_request_target
runner environment github-hosted
repository IDs     exact registry values
workflow identity  exact registry values
run identity       exact evaluation values at finalization
```

`sub`, actor name, branch name, workflow name, and repository name alone are not
authority. The clock is injected. The accepted time relation is only:

```text
nbf <= now <= exp
iat <= now + configured clock skew
```

No undocumented fixed token lifetime is imposed.

### Server-side pull request identity

`PullRequestReader` supplies repository ID, pull number, state, exact head OID,
and base ref. `pull_request_target` OIDC claims establish the base-repository
execution identity; they do not establish H.

Admission requires an existing open pull request and takes H only from the
reader. Finalization reads the pull request again and requires the same open H.
A changed H or closed pull request is rejected. Base movement with unchanged H
does not invalidate `P_v(H)`.

### Immutable registry and explicit activation

`RegistryRecord` is a frozen value. A new operational configuration creates a
new revision. Existing keys cannot be overwritten with changed content.

The registry freezes one publication-authority identity per epoch:

```text
(repository_id, full_policy_epoch)
  -> exactly one (
       policy bundle digest,
       exact status context,
       publisher identity
     )
```

An operational revision may retain an existing epoch while changing reviewed
execution-only fields such as workflow SHA, but it must preserve that complete
authority identity. A digest, context, or publisher change is an explicit
authority migration rather than an operational revision.

Commit Status context names are a physical provider namespace. Signer v1 admits
only non-empty printable ASCII contexts up to GitHub's 100-character limit and
uses ASCII lowercase for namespace comparison while preserving the exact context
in the registry record and provider payload. The registry also preserves this
historical mapping:

```text
(repository_id, normalized_status_context)
  -> exactly one policy_epoch
```

Revocation does not release an epoch identity or context reservation. A new
epoch, including one introduced for publisher/App rotation, must use a distinct
normalized context. This prevents old statuses under one physical context from
acquiring a new authority meaning.

Storage and activation are separate. Admission resolves exactly:

```text
(repository_id, authority_slot)
  -> (record_id, revision)
```

There is no latest, highest-revision, timestamp, insertion-order, or filesystem
fallback. Missing or malformed activation fails closed. Revocation is separate
from record content and prevents both activation and finalization.

The active record chooses the policy selector, epoch, bundle digest, controller
schema, scanner identity, workflow identity, status context, and abstract
publisher identity. None is caller-selectable.

### Evaluation issuance and idempotency

`TicketRequest` contains only the pull number. Under one transaction lock,
admission validates OIDC, resolves one active registry revision, reads the live
pull request, and persists a frozen evaluation.

The durable idempotency key is:

```text
repository_id
run_id
run_attempt
pull_number
head_oid
registry_record_id
registry_revision
```

Repeated valid admission for that tuple returns the existing evaluation. It
cannot overwrite semantics. Admission token IDs are globally bound to their
first idempotency key.

The response returns only the inputs required by trusted controller execution:
evaluation ID, repository and pull identity, H, policy identity, controller
identity, scanner identity, and expiry.

### Frozen finalization

Finalization loads both the evaluation and its exact registry key from server
state. A later activation never changes an issued evaluation:

```text
E issued under R1
R2 activated
E still finalizes under R1, or is rejected if R1 is revoked
```

Finalization requires a fresh verified OIDC token with the same repository,
owner, workflow, optional reusable workflow, run ID, and run attempt. Admission
token IDs cannot finalize. A finalization token ID is consumed globally and
cannot be replayed against another evaluation.

The finalization token ID is consumed immediately after authenticated OIDC and
exact execution-tuple validation, before expiry, pull-request freshness, or
controller-evidence parsing. Later malformed or stale evidence does not make the
authenticated token reusable.

Expired evaluations fail closed and require new authenticated admission.

### Independent controller-result parsing

The signer imports no controller or worker module. It maintains an independent,
bounded parser for the current result envelope and worker result. Both levels
require exact keys and exact primitive types. Extra fields, missing fields,
boolean-as-integer substitutions, string subclasses, invalid digests, unknown
verdicts, unknown refusal codes, and binding substitutions are rejected before
publisher access.

An authority result must match the frozen evaluation and registry for controller
protocol and schema, repository ID, H, selector, epoch, bundle digest, scanner
distribution, scanner version, scanner artifact digest, and worker semantic
digest.

`INFRASTRUCTURE_REFUSAL` accepts only the fixed current controller refusal
vocabulary. It creates no publication payload and reserves no publication slot.
It remains retryable with a different fresh token from the same execution until
expiry.

Only these semantic verdicts map to publication:

```text
PASS                     -> success
SCANNER_FINDING          -> failure
POLICY_ADMISSION_FAILURE -> failure
```

The signer never creates `pending` or `error` status states.

### Immutable publication slot

The logical publication slot is:

```text
(repository_id, head_oid, policy_epoch)
```

Different pull requests containing the same H intentionally share the slot.
The first semantic finalization reserves one canonical payload digest containing
only repository ID, H, registry status context, mapped state, fixed description,
and null target URL. Publisher identity remains internal authority provenance;
it is stored in the immutable slot but is not encoded into a provider payload
field or its canonical digest.

An existing slot is reusable only when payload, payload digest, and publisher
identity all match. A different source is rejected before any existing-published
shortcut or provider access. Publication receipts bind provider record ID,
payload digest, and publisher identity; matching payload bytes alone are not
sufficient provenance.

Slot state is monotonic:

```text
RESERVED -> UNKNOWN -> PUBLISHED
RESERVED -----------> PUBLISHED
```

An identical later payload is idempotent. A different payload is a hard conflict
before publisher access. There is no last-writer-wins behavior.

Evaluation state is also monotonic:

```text
ISSUED -> RETRYABLE -> UNKNOWN -> PUBLISHED
ISSUED -----------------------> PUBLISHED
```

Allowed transitions may skip intermediate states but never move backward.

### Mock publication uncertainty

`MockPublisher` exercises four deterministic outcomes:

- published with a stable synthetic receipt;
- definite failure before publication;
- unknown before any visible receipt;
- unknown after a simulated write.

On `UNKNOWN`, the slot retains its exact payload and moves to `UNKNOWN`. A retry
can submit only that payload. Lookup can reconcile an unknown-after-write result
without another publish call. An unknown-before-write result may retry the same
payload. A definite failure remains retryable but cannot downgrade an already
unknown or published state.

The mock publisher identity is synthetic. It is not a GitHub App ID. Its
physical status key uses the same case-insensitive ASCII context normalization
as the registry, and both direct publication and lookup produce or return only
receipts attributable to that mock identity. Namespace safety is also tested
against a separate permissive test provider that accepts repeated writes.

### Transaction model

`InMemoryRegistry` and `InMemoryEvaluationStore` must share one reentrant lock.
Admission, activation, revision selection, finalization, slot reservation, and
mock publication transitions are serialized through that reference transaction
boundary. This gives deterministic compare-and-set-equivalent behavior for the
tests.

The lock-held mock publisher call is intentional for this reference core. A
production durable service will need a database transaction plus outbox or an
equivalent reconciliation design; it must preserve the same slot and uncertainty
invariants without relying on a process-local lock.

Finalization-JTI consumption is a durable security side effect. A production
store must commit that single-use claim independently of later
controller-evidence refusal, for example through a committed compare-and-set
boundary. It
must not place token consumption and evidence parsing in a transaction that
rolls back the consumed token when parsing or freshness validation raises.

## Threat and Failure Model

The core is designed to reject these classes:

- forged or structurally invalid claim models crossing the authorization API;
- OIDC identity substitution across repository, owner, workflow, run, or attempt;
- deriving H from attacker-influenced claim text;
- policy, digest, status context, or publisher selection by the caller;
- registry reinterpretation after admission;
- finalization after revocation, expiry, PR closure, or H movement;
- malformed or substituted controller and worker results;
- infrastructure failures converted into semantic statuses;
- opposite verdicts racing for one R/H/v slot;
- replay of admission or finalization token IDs;
- reinterpretation of one epoch through a new context or publisher identity;
- reuse of a case-insensitive physical context by a different epoch;
- reuse of a publication slot or receipt across publisher identities;
- uncertain publication followed by a different payload;
- state rollback from `UNKNOWN` or `PUBLISHED`.

This implementation does not claim to solve:

- cryptographic GitHub OIDC verification;
- durable multi-process storage or disaster recovery;
- real GitHub pull request reads;
- GitHub App authentication or Commit Status writes;
- HTTP authentication, rate limiting, deployment, or service isolation;
- immutable production signer artifact provenance;
- workflow activation or branch-protection rollout.

Those are later adapters and deployment gates, not hidden behavior in this PR.

## Rejected Alternatives

1. **Treat decoded JWT dictionaries as verified identity.**
   Rejected because decoding does not establish signature or issuer authenticity.
2. **Take H from `ref`, `sub`, `head_ref`, or workflow input.**
   Rejected because `pull_request_target` execution identity and target H are
   separate trust inputs.
3. **Select the latest registry revision.**
   Rejected because time and insertion ordering are not policy authorization.
4. **Allow the client to return registry metadata at finalization.**
   Rejected because an evaluation must remain bound to its server-side revision.
5. **Map infrastructure refusal to `pending` or `error`.**
   Rejected because infrastructure uncertainty is not `P_v(H)` evidence.
6. **Include pull number or run identity in the publication slot.**
   Rejected because `P_v(H)` is commit intrinsic and the same H must share one
   result across pull requests.
7. **Allow last writer to replace an existing verdict.**
   Rejected because late ordering could turn execution timing into authority.
8. **Retry a different payload after unknown publication.**
   Rejected because the first request may already have reached the provider.
9. **Embed candidate v2 policy identity in signer defaults.**
   Rejected because candidate evidence is not approved production policy.
10. **Add a production-looking non-cryptographic OIDC verifier.**
    Rejected because its name would conceal an unimplemented trust boundary.
11. **Treat publisher identity as part of the provider payload.**
    Rejected because signer provenance is not a GitHub Commit Status field and
    must not change the canonical provider request.
12. **Allow a new epoch to reuse an old context after revocation.**
    Rejected because historical statuses remain in the provider namespace and
    could be reinterpreted under the new authority.

## Compatibility

This change is additive and self-contained under `signer/`, signer tests, and
this design record. It does not modify acquisition, reader, materializer,
controller, worker, policy bundle, scanner behavior, reports, workflows, branch
rules, or PR #22.

The package is not exposed as a deployed service and adds no dependency. Existing
repository behavior remains unchanged unless the mock reference classes are
imported explicitly by tests or local review code.

## Validation

The contract suite covers:

- exact OIDC claim shape, numeric parsing, identity mutation, and time windows;
- mock verifier behavior and absence of a production-looking verifier;
- immutable registry records, epoch-authority uniqueness, explicit activation,
  frozen epoch authority, case-insensitive historical context reservation,
  revocation, and concurrent activation;
- evaluation revision freeze, admission idempotency, token replay, and expiry;
- PR head movement, closure, base-only movement, and same-H cross-PR sharing;
- exact controller and worker schema parsing and binding substitutions;
- all three semantic verdict mappings and infrastructure no-publish behavior;
- payload conflicts, late finalizers, unknown-before-write,
  unknown-after-write, publisher-bound reconciliation, receipt provenance,
  and monotonic state;
- authenticated malformed evidence consuming its finalization token before
  parser refusal, while a new token can still complete valid finalization;
- a permissive provider control proving cross-epoch context conflicts are
  rejected before a second provider write;
- concurrent admission and concurrent identical finalization.

Repository validation also runs the complete unit suite, Ruff, formatting,
pre-commit, Markdown/front matter, taxonomy, README snapshot, pattern-library,
placeholder, privacy, credential, and diff checks required by this repository.

## Rollback

Because there is no production adapter, workflow, credential, or branch rule,
rollback is removal of the additive mock package, tests, and this design record.
No remote authority state or published Commit Status requires migration.

If a later production adapter violates these invariants, disable that adapter
and its workflow or branch-rule integration first. Do not weaken the registry,
evaluation, parser, or publication-slot contracts to preserve availability.
