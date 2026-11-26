# Private CI and public-source mode

The build and smoke test run in [`.github/workflows/private-ci.yml`](../.github/workflows/private-ci.yml).
The source repository is public by decision, while the built image, checksums,
logs, signatures, and release record are private. The workflow therefore has two
modes:

| detected mode | static checks and container build | artifact upload | Pages / releases / registry |
| --- | --- | --- | --- |
| public source | yes | no | no |
| private repository | yes | repository-scoped Actions artifacts only | no |

Both modes fail closed when GitHub Pages is enabled, a non-draft GitHub Release
exists, the event and API metadata disagree, or the online check cannot finish.
The decision is recorded in [ADR 0002](adr/0002-public-source-private-release.md).

## What the workflow does

1. **Access guard.** [`ci/check-private-access.sh`](../ci/check-private-access.sh)
   reads the event payload and, with `--online`, the GitHub API. It prints the
   detected state and the actions it allows:
   - `repository.private` and visibility must consistently describe a `public`
     or `private` repository;
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
4. **Retention decision.** In public-source mode the build runs on the runner and
   the ISO and logs are discarded: no `actions/upload-artifact` step runs, no
   artifact is named, and no download URL is created. In private-repository mode
   the workflow may upload only with `actions/upload-artifact`; artifact access
   is then the private repository's access control, and no unauthenticated
   artifact URL is created or printed.
5. **Optional release candidate.** A manual dispatch can set
   `release_candidate: true`. That job runs only in private-repository mode and
   references the `private-release` GitHub Environment, which must be configured
   with required reviewers. It downloads the CI artifact, re-verifies the
   checksum and build metadata, and re-uploads it as
   `private-release-candidate-<run-id>`. It still does not sign anything and is
   not a release.

The workflow token is limited to `contents: read`. There is no `contents: write`,
`pages: write`, `packages: write`, or `id-token: write` permission, so the
workflow cannot create a release, deploy Pages, or publish a package or container
image to a registry.

## Artifact contents and names

These artifacts exist only in private-repository mode.

| artifact | contents | retention |
| --- | --- | --- |
| `private-ci-<run-id>` | ISO, `SHA256SUMS`, `qemu-serial.log`, `build-metadata.txt` | 14 days |
| `private-release-candidate-<run-id>` | the same files, re-verified and gated by the `private-release` environment | 90 days |

`build-metadata.txt` records the repository, commit, ref, run id, build time,
ISO name, size, and SHA-256. It must not contain credentials, passphrases,
tokens, or private-key material; the release-candidate job checks for that.

## Access rules

- A public repository is allowed to run the static checks and the container
  build, but it must have no artifact retention. Do not add an upload step that
  runs in public-source mode.
- A **private repository** may retain artifacts through repository-scoped
  GitHub Actions only. The source-review policy still does not permit public
  build artifacts.
- Keep **GitHub Pages disabled** and do not create a Pages workflow.
- Keep **Releases write access** with the release owner only. Do not create a
  GitHub Release, draft or published, as a distribution channel.
- Do not publish to GitHub Packages, a container registry, an npm/package
  mirror, a public object store, a paste service, or an unauthenticated URL.
- Keep the default workflow token permission read-only and allow only the
  actions used here (`actions/checkout`, `actions/upload-artifact`,
  `actions/download-artifact`).
- Use a runner with at least 20 GiB free for the ISO build. The build job
  defaults to `ubuntu-latest` but accepts the `PRIVATE_CI_RUNNER` repository
  variable; set it to a self-hosted label with enough disk. The job fails early
  if less than 20 GiB is available.
- Configure the `private-release` environment with required reviewers, prevent
  self-review where the plan supports it, and restrict deployment to the
  protected release branch or tag.
- Do not add repository secrets for the release signing key. The key stays
  offline; CI is never allowed to see it.

GitHub Actions artifacts are a short-lived staging area, not a release archive.
They expire, and a new run can replace a candidate. Download an approved
candidate into private encrypted storage before its retention window ends. A
public-source build has no candidate to download; an approved release must be
rebuilt through the private release path.

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
5. Rebuild from a reviewed commit, run the full CI and checklist again, and sign
   with a new key whose fingerprint is verified through a separate channel.

Revocation cannot make an already-leaked ISO safe. Because the source and policy
may be public while artifacts are private, notify authorized users through the
private owner channel, not through a public release page.

## Artifact retention

- **Public-source CI:** no artifact retention. The ISO and logs are discarded
  when the job ends.
- **Private CI staging:** 14 days. Treat it as disposable; do not link to it as a
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
