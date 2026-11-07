# Maria Padilha de Castela

Private-release cybersecurity desktop image. **The source is public; the built
image is private and must not be published.** This is an authorized-lab tool,
not a general-purpose distribution.

> **Do not publish, upload, mirror, or redistribute an ISO from this repository
> or any build of it.** There is no public release channel, no public artifact
> host, and no public signing key.

## Status

**Archiso scaffold.** The first buildable profile is in [`iso/`](iso): Archiso
boot layout, a pinned Arch + BlackArch package source set, repository keyring
policy, a mandatory Hyprland/Quickshell desktop, and a minimal reviewed security
baseline. The static tests run anywhere. The ISO itself is only built inside an
Arch container; [`build.sh`](build.sh) refuses to run on a host.

No ISO, package archive, checksum, or signature is committed. Nothing is
installed on the host and the live root does not install packages at boot.

## Profile

| path | role |
| --- | --- |
| `iso/profiledef.sh` | archiso profile, boot modes, permissions |
| `iso/packages.x86_64` | live-root package allowlist |
| `iso/pacman.conf` | pinned Arch archive and BlackArch sources, strict signatures |
| `iso/keys/` | keyring pins and public-key policy; no private key material |
| `iso/denylist.txt` | phishing and credential-theft packages excluded from the image |
| `iso/airootfs/` | authorized-use banner, live user, greetd, enabled units, mkinitcpio |
| `iso/efiboot/`, `iso/syslinux/` | UEFI and BIOS boot entries |
| `build.sh` | container-only mkarchiso wrapper |
| `tests/iso.sh` | profile, package, secret, and public-release checks |

The desktop is mandatory: Hyprland, Quickshell, the Qt 6 runtime, the session
daemons, greetd/tuigreet, and the `maria-padilha` session package are in the
allowlist. The security baseline is deliberately small: Nmap, Wireshark,
packet/forensic inspection, and an isolated QEMU/libvirt lab. No scanner or
capture tool is started automatically.

## Build

The build must run as root inside a disposable Arch Linux container because
`mkarchiso`/`pacstrap` need loop devices and chroot. Do not run the build on a
host, and do not `pacman -S` the build tooling on the host.

```sh
# from this checkout, on a machine with Docker or Podman
docker run --rm -it --privileged \
  -v "$PWD:/work" \
  -w /work archlinux:latest
```

Inside the container:

```sh
pacman -Syu --needed --noconfirm archiso
./build.sh --desktop-package /path/to/maria-padilha-*.pkg.tar.zst
```

`--desktop-package` points at a package built from the separate
`maria-padilha-de` checkout. The build script publishes it into a scratch-local
package repository under `.scratch/` and never copies it into this checkout.
Omit it to build the core Hyprland/Quickshell fallback without the Maria shell.
Pass `--help` for all options; `--check` validates the profile without building.

Useful checks that need no root:

```sh
bash tests/all.sh
make test
```

The build output is gitignored under `out/`. Treat it as a private artifact:
record its hash and the verified signing-key fingerprint in the private release
record outside this repository, never in a public release.

## Authorized use

Use this image only on systems you own or for which you have explicit written
permission. The live banner says the same thing on every boot. Do not use the
image or its tools against third-party systems. No scans run by default, no
packet capture starts automatically, and no target list is generated from the
local network.

The source may be public so the work can be reviewed. Release artifacts, build
logs, package caches, and signing keys are not public.

## Relationship to the other repositories

It builds on the desktop from
[`maria-padilha-de`](https://github.com/maria-padilha-os/maria-padilha-de) and
[`maria-padilha-dotfiles`](https://github.com/maria-padilha-os/maria-padilha-dotfiles).
The normal desktop image is
[`maria-padilha-os`](https://github.com/maria-padilha-os/maria-padilha-os).

## Known gaps

- The desktop package is supplied by the separate private build; this
  repository does not carry a second copy of the shell.
- No installer, QEMU smoke test, or signed-release pipeline is wired yet.
- The live account is intentionally ephemeral and passwordless for recovery;
  do not reuse that configuration on an installed system.
