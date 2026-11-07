# Signing policy

## Repository signatures

`iso/pacman.conf` requires valid repository and database signatures:

```text
SigLevel = Required DatabaseOptional
```

The trusted inputs are the `archlinux-keyring` and `blackarch-keyring` packages
listed in `iso/packages.x86_64`. Their pins and the BlackArch source hash are in
`iso/keys/trusted-keyrings.txt`.

Never "fix" a signature failure by trusting an unsigned repository or disabling
signature checking. Fix the trust input or stop the build.

## Release signature

The release signing key is offline. It must not be generated in this checkout,
stored in this repository, passed through CI logs, or uploaded with the image.

Before signing, verify the built image in a VM and record the private manifest
described in [`private-image.md`](private-image.md). Sign the checksum file
offline, for example:

```sh
sha256sum maria-padilha-de-castela-*.iso > sha256sums
gpg --detach-sign --armor sha256sums
gpg --verify sha256sums.asc sha256sums
```

Do not publish `sha256sums`, `sha256sums.asc`, the ISO, or the signing key. The
signature exists so the owner can verify a private artifact, not so the image
can be redistributed.

The public fingerprint is recorded in the private release record through a
channel separate from the artifact. No private key material belongs in
`iso/keys/` or anywhere else in this repository.
