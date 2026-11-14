# Private CI

The build and smoke test run in [`.github/workflows/private-ci.yml`](../.github/workflows/private-ci.yml).
The workflow is designed for a **private repository**: it refuses to build when
the repository is public, GitHub Pages is enabled, or a published GitHub
Release already exists.

## What the workflow does

1. **Access guard.** [`ci/check-private-access.sh`](../ci/check-private-access.sh)
   reads the event payload and, with `--online`, the GitHub API. It fails closed
   unless all of these are true:
   - `repository.private` is `true` and visibility is `private`;
   - `has_pages` is `false` (GitHub Pages is disabled);
   - there are no non-draft GitHub Releases.
2. **Repository tests.** `bash tests/all.sh` runs the static profile, frontend,
   installer-group, checksum, and access-control tests.
3. **Build and smoke test.** A disposable `archlinux:latest` container runs
   [`ci/private-ci.sh`](../ci/private-ci.sh), which:
   - runs [`build.sh`](../build.sh), the same container-only build used by hand;
   - records `out/SHA256SUMS` with [`ci/record-checksums.sh`](../ci/record-checksums.sh);
   - verifies the checksum before boot;
   - boots the exact ISO in QEMU with no display, no monitor, and no network
     device, collecting the serial console in `out/qemu-serial.log`;
   - waits for the image's `AUTHORIZED USE ONLY` serial login banner and fails on
     a kernel panic or timeout;
   - verifies the checksum again after the boot.
4. **Private retention.** The workflow uploads only with
   `actions/upload-artifact`. Artifact access is the repository's access control:
   a collaborator with read access to the private repository can download it; no
   unauthenticated artifact URL is created or printed.
5. **Optional release candidate.** A manual dispatch can set
   `release_candidate: true`. That job references the `private-release` GitHub
   Environment, which must be configured with required reviewers. It downloads
   the CI artifact, re-verifies the checksum and build metadata, and re-uploads
   it as `private-release-candidate-<run-id>`. It still does not sign anything
   and is not a release.

The workflow token is limited to `contents: read`. There is no `contents: write`,
`pages: write`, `packages: write`, or `id-token: write` permission, so the
workflow cannot create a release, deploy Pages, or publish a package.

## Artifact contents and names

| artifact | contents | retention |
| --- | --- | --- |
| `private-ci-<run-id>` | ISO, `SHA256SUMS`, `qemu-serial.log`, `build-metadata.txt` | 14 days |
| `private-release-candidate-<run-id>` | the same files, re-verified and gated by the `private-release` environment | 90 days |

`build-metadata.txt` records the repository, commit, ref, run id, build time,
ISO name, size, and SHA-256. It must not contain credentials, passphrases,
tokens, or private-key material; the release-candidate job checks for that.

## Access rules

- Keep the GitHub repository **private**. The source-review policy does not
  permit public build artifacts.
- Keep **GitHub Pages disabled** and do not create a Pages workflow.
- Keep **Releases write access** with the release owner only. Do not create a
  GitHub Release, draft or published, as a distribution channel.
- Do not publish to GitHub Packages, a container registry, an npm/package
  mirror, a public object store, a paste service, or an unauthenticated URL.
- Keep the default workflow token permission read-only and allow only the
  actions used here (`actions/checkout`, `actions/upload-artifact`,
  `actions/download-artifact`).
- Use a private runner with at least 20 GiB free for the ISO build. The build
  job defaults to `ubuntu-latest` but accepts the `PRIVATE_CI_RUNNER` repository
  variable; set it to a private self-hosted label with enough disk. The job fails
  early if less than 20 GiB is available.
- Configure the `private-release` environment with required reviewers, prevent
  self-review where the plan supports it, and restrict deployment to the
  protected release branch or tag.
- Do not add repository secrets for the release signing key. The key stays
  offline; CI is never allowed to see it.

GitHub Actions artifacts are a short-lived staging area, not a release archive.
They expire, and a new run can replace a candidate. Download an approved
candidate into private encrypted storage before its retention window ends.

## Revocation

A build, key, or artifact can be revoked. Revocation is recorded in the private
release record, not in a public issue or pull request.

1. Stop distributing the affected artifact and remove it from any private
   download location.
2. If the signing key is suspected compromised, use the offline revocation
   certificate, publish the revoked fingerprint and reason through the private
   owner channel, and never sign another release with that key.
3. Mark the release record as revoked with the date, reason, artifact SHA-256,
   key fingerprint, and replacement release (if any). If an artifact is leaked
   or its checksum cannot be trusted, treat it as revoked even if the key is
   intact.
4. Preserve the revocation record and the checksum/signature evidence. Delete
   only the revoked artifact copies after the record is complete, or retain
   them offline as incident evidence.
5. Rebuild from a reviewed commit, run the full private CI and checklist again,
   and sign with a new key whose fingerprint is verified through a separate
   channel.

Revocation cannot make an already-leaked ISO safe. Because the source and
policy may be public while artifacts are private, notify authorized users
through the private owner channel, not through a public release page.

## Artifact retention

- **CI staging:** 14 days. Treat it as disposable; do not link to it as a
  release.
- **Private release candidate:** 90 days in GitHub Actions, then deleted unless
  moved to private encrypted storage. The environment approval is not a release
  approval.
- **Signed private release:** keep the ISO, `SHA256SUMS`, detached signature,
  package manifest, and private release record in encrypted offline storage for
  at least one year after the release is superseded, or longer if the owner's
  records policy requires it. Keep the release record permanently.
- **Revoked release:** keep the record and revocation evidence permanently;
  destroy artifact copies after the incident record is complete, unless they
  are needed as evidence.
- **Key material:** the private signing key, passphrase, and revocation
  certificate are never part of CI retention. They stay in the owner's offline
  key custody.

The full approval sequence is in [the release checklist](release-checklist.md).
