# SBOM Dependency Diff Review

## Signal

What evidence appears?

An SBOM, lockfile, package manifest, or dependency inventory changes between
builds, releases, commits, or environments.

Common evidence:

* new direct or transitive dependency
* dependency version upgrade or downgrade
* package source or registry changes
* license, maintainer, or package metadata changes
* vulnerability or risk score changes after dependency resolution

## Why it matters

What risk does it suggest?

Dependency diffs reveal when the software supply chain changed. A small diff
can introduce exploitable vulnerabilities, malicious packages, dependency
confusion exposure, license risk, or unexpected runtime behaviour.

## False positives

When can it be benign?

* routine patch upgrades
* dependency refresh from a trusted lockfile update
* package rename or metadata correction
* build tool normalization changing output order
* environment-specific optional dependencies

## Minimum evidence

What must be present before making a claim?

At minimum, show the before and after dependency state, package name, version,
package source, direct or transitive relationship, affected component, and the
reason the diff is risky.

Do not claim supply-chain compromise from a dependency change alone. The claim
needs suspicious provenance, unexpected source, risky version movement,
maintainer signal, known vulnerability, or mismatch with the approved change.

## Defensive next step

What should a defender check next?

Review the dependency's source repository, package registry metadata, release
notes, maintainer history, vulnerability data, license, and whether the change
matches the intended pull request or release plan.

## Related project

[sbom-diff-and-risk](https://github.com/stacknil/scientific-computing-toolkit/tree/main/tools/sbom-diff-and-risk)
