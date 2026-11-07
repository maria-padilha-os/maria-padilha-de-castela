# Repository and release signing keys

This directory documents the key policy for the private image. It deliberately
contains no private key material.

- Repository trust comes from the `archlinux-keyring` and `blackarch-keyring`
  packages listed in `iso/packages.x86_64`. The pinned versions, the BlackArch
  source hash, and the checked-in public keyring are in
  `trusted-keyrings.txt`, `blackarch-fingerprints.txt`, and
  `pgp/blackarch.gpg`.
- `iso/pacman.conf` requires valid repository signatures and database
  signatures. Trusting an unsigned repository or disabling signature checking
  is not permitted.
- The release signing key is offline and private. It is never generated in this
  checkout, stored in this repository, printed in CI logs, or uploaded with an
  artifact. Its public fingerprint is recorded in the private release record
  outside this repository.
- Public keys may be committed only after fingerprint verification. Private
  keys, revocation certificates, passphrases, and keyring exports must never be
  committed.

The `pgp/` directory holds verified public key material only. It currently
contains the pinned BlackArch repository keyring. It never holds a release
private key or a secret keyring.
