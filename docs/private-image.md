# Private image policy

Maria Padilha de Castela is a **private release** image.

- The source repository may be public for review.
- Built ISOs, package caches, build logs, package manifests, checksums, and
  signatures are private release material.
- **Do not publish, upload, mirror, redistribute, or attach an ISO or build
  artifact to a public issue, pull request, page, package registry, or release.**
- Do not publish the release signing key, its passphrase, a keyring export, or
  the private release record.
- Do not add a public release workflow to `.github/`. The repository has no
  public artifact channel by design.
- Private CI may retain build artifacts only through the private repository's
  own access control. CI artifacts are staging, not releases: ordinary artifacts
  expire after 14 days and an approved private release candidate after 90 days.
  The [private CI document](private-ci.md) records the access rules, retention,
  and revocation procedure.

The private release record belongs outside this checkout and should contain:

1. the ISO SHA-256 and size;
2. the exact Arch snapshot date and the BlackArch package versions used;
3. `pacman -Q` output from the built root;
4. the verified repository key fingerprints;
5. the release signing-key fingerprint and the detached signature over
   `SHA256SUMS`.

The record is private. A private artifact without a verified signature is not a
release, and a public artifact is not permitted even if it is signed. Follow the
[release checklist](release-checklist.md) before signing, and record explicit
human approval in the private release record.

The authorized-use banner in `iso/airootfs/etc/issue` and
`iso/airootfs/etc/motd` is part of the image, not a substitute for permission.
Use the image only on systems you own or have explicit written permission to
test.
