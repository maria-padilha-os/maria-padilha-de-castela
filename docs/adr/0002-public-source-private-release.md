# ADR 0002: Public source with no public artifact retention

- **Status:** Accepted
- **Date:** 2026-11-26
- **Decision owner:** `maria-padilha-de-castela` maintainer
- **Related:** [ADR 0001](0001-cybersecurity-os-base.md), [`docs/private-ci.md`](../private-ci.md), [`docs/private-image.md`](../private-image.md), [`.github/workflows/private-ci.yml`](../../.github/workflows/private-ci.yml)
- **Scope of this ADR:** choose how CI behaves when the source repository is public. It does not authorize a Pages site, a GitHub Release, a registry publication, or public distribution of an ISO.

## Context

The repository is **public by decision** ("public source, private release").
The source, build logic, tests, and policy are meant to be reviewable. The ISO,
checksums, logs, signatures, and release record remain private.

The first guard treated "private repository" as a prerequisite for every job.
On a public repository it failed before the static tests or the container build
started, so the public source could not be tested even though publishing was
already forbidden. The guard needs to distinguish the repository's visibility
from the artifact-retention decision.

## Options

### A. Keep the repository private

Private source, private CI, and repository-scoped Actions artifact retention.

- **Advantages:** one access domain; ordinary artifact retention is simple; the
  current private release-candidate path keeps working unchanged.
- **Disadvantages:** contradicts the public-source review decision, hides the
  build logic and policy tests, and leaves the public repository permanently
  red. Rejected for this project.

### B. Public source with no artifact retention (chosen)

Public source; CI runs the static checks and the container build/smoke test, but
a public repository uploads no artifact. A private repository keeps the existing
repository-scoped retention and the manual private release-candidate job.

- **Advantages:** the source and build logic are reviewable; no ISO or build log
  is retained on a public repository; there is no Pages, Release, or registry
  channel; the private release path still exists for the owner.
- **Disadvantages:** a public build leaves no promotable artifact. Any approved
  release must be rebuilt through the private release path rather than promoted
  from a public CI run.

### C. Public source plus a private mirror that builds

Keep the public source and run the build in a separate private mirror/runner that
retains artifacts.

- **Advantages:** public review and private artifact retention without making the
  source private; can keep longer-lived build evidence.
- **Disadvantages:** a second repository and runner to secure and keep in sync;
  two access domains and two commit histories can diverge; credentials and
  mirror automation add maintenance. Deferred until there is a concrete need
  for private builds of public commits.

## Decision

Adopt **Option B**.

`ci/check-private-access.sh` detects `public` or `private` repository mode from
the event payload and, with `--online`, the GitHub API. It prints the detected
state and the actions it allows. Both modes fail closed when GitHub Pages is
enabled, a non-draft GitHub Release exists, the metadata is inconsistent, or the
online check cannot be completed.

| mode | static checks and container build | artifact upload | Pages / releases / registry |
| --- | --- | --- | --- |
| public | yes | no | no |
| private | yes | repository-scoped Actions artifacts only | no |

The authorized-use boundary is unchanged. CI does not publish an image, does not
sign, and does not receive the offline signing key.

## Consequences

- A public repository can build and smoke-test the image but cannot retain the
  ISO as a CI artifact.
- A private repository retains ordinary artifacts for 14 days and a manually
  requested, environment-gated release candidate for 90 days.
- Pages, published releases, and registry publication remain hard failures.
- The manual release-candidate job is available only in private mode.
- A future private mirror must be recorded in a new decision before it is
  enabled; this ADR does not authorize one.
