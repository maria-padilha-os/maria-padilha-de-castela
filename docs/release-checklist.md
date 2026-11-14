# Private release checklist

A green CI run, an uploaded artifact, or a workflow-dispatch click is **not** a
release. A release requires **explicit human approval** and an **offline private
signing key**. Complete this checklist in the private release record outside
this checkout. Do not put the record, the key, the passphrase, or artifact URLs
in a public issue, pull request, page, or chat.

## 0. Approval

- [ ] The release owner is named.
- [ ] A second reviewer approves when the release policy requires two people.
- [ ] The approver explicitly records **approve** or **reject** with their name,
      role, UTC date/time, reviewed commit, CI run id, and release version.
- [ ] Approval is recorded in the private release record. A bot comment, a
      green check, or a workflow input is not a substitute.
- [ ] The `private-release` environment has required reviewers and a protected
      branch/tag rule. If it does not, stop and fix the repository settings
      before treating any artifact as a candidate.
- [ ] No public Pages site, public release, public package mirror, or
      unauthenticated artifact URL exists for this version.

## 1. Source and private CI

- [ ] The commit is reviewed and on the protected release branch/tag.
- [ ] `bash tests/all.sh` passes at that commit.
- [ ] The private-repository access guard passed for the build run.
- [ ] The CI run id and workflow ref match the approved commit.
- [ ] The ISO, `SHA256SUMS`, serial log, and `build-metadata.txt` come from that
      run, not from an older local build.
- [ ] `ci/verify-checksums.sh SHA256SUMS <artifact-dir>` passes locally after
      download.
- [ ] `qemu-serial.log` contains the `AUTHORIZED USE ONLY` banner and no kernel
      panic. A serial smoke boot does not replace the fuller VM install/boot
      checks in [`build/README.md`](../build/README.md).
- [ ] The artifact was downloaded from the repository-scoped artifact, not from
      a public mirror, cache, or forwarded URL.

## 2. Private signing key

- [ ] The release key is offline, passphrase-protected, and used only for
      private release signing.
- [ ] Its fingerprint was verified through a channel separate from the artifact
      and from this repository.
- [ ] The private key, passphrase, keyring export, and revocation certificate are
      not in the repository, CI, the runner, the artifact, or any log.
- [ ] CI did not sign the artifact and did not receive a signing secret.
- [ ] Sign the checksum file offline, not the ISO directly:

      gpg --detach-sign --armor SHA256SUMS
      gpg --verify SHA256SUMS.asc SHA256SUMS

- [ ] Record the signing-key fingerprint, signature file hash, and verification
      result in the private release record.
- [ ] If the key is unavailable, expired, or suspected compromised, **stop**.
      Do not improvise a replacement key in CI.

## 3. Private artifact handling

- [ ] Move the ISO, `SHA256SUMS`, `SHA256SUMS.asc`, serial log, package manifest,
      and build metadata into private encrypted storage.
- [ ] Do not publish, upload, mirror, attach, or link the ISO or any build
      artifact on a public page, release, package registry, object store, paste,
      issue, pull request, or social channel.
- [ ] Do not expose an unauthenticated download URL. Private storage links are
      shared only through the owner's private channel.
- [ ] Record the ISO SHA-256, size, Arch snapshot date, BlackArch package
      versions, verified repository key fingerprints, release key fingerprint,
      and the detached signature.
- [ ] Confirm that the published source tree does not contain the ISO, checksum,
      signature, signing key, or private release record.

## 4. Revocation

- [ ] Know where the offline revocation certificate and the release record are
      stored before signing.
- [ ] On key compromise, checksum mismatch, failed boot/security review,
      unauthorized disclosure, or a lost/untrusted artifact, mark the release
      **revoked** and stop distribution immediately.
- [ ] If the key is compromised, revoke it with the offline certificate, record
      the revoked fingerprint and reason, and notify authorized users through
      the private channel.
- [ ] Preserve the checksum and signature evidence and the revocation record.
      Delete revoked artifact copies only after the incident record is complete,
      unless they are retained as evidence.
- [ ] Rebuild from a reviewed commit, repeat this checklist, and sign with a new
      verified key. Never re-sign the same version with a compromised key.

Revocation cannot make a leaked ISO safe. Treat any public exposure as an
incident even if the artifact was signed.

## 5. Artifact retention

| item | retention | location |
| --- | --- | --- |
| ordinary CI artifact (`private-ci-<run-id>`) | 14 days | GitHub Actions, private repository access |
| private release candidate | 90 days | GitHub Actions plus private encrypted storage |
| signed ISO, checksums, signature, manifest | at least 1 year after superseded, or per records policy | offline encrypted storage |
| private release record and approvals | permanent | owner's private record |
| revocation record and evidence | permanent | owner's private record |
| private signing key, passphrase, revocation certificate | until rotated/revoked | offline key custody, never CI |

GitHub Actions artifacts expire and are not a backup. A signed release that has
not been copied to private storage is not retained.

## Sign-off

| field | value |
| --- | --- |
| release version | |
| commit | |
| CI run id | |
| ISO SHA-256 | |
| signing-key fingerprint | |
| approver name / role | |
| approval UTC date/time | |
| second reviewer (if required) | |
| decision (approve / reject / revoke) | |
| private record location | |
