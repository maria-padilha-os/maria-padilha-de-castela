# Maria Padilha de Castela

Private-release cybersecurity desktop image. **The source is public; the built
image is private and must not be published.** This is an authorized-lab tool,
not a general-purpose distribution.

> **Do not publish, upload, mirror, or redistribute an ISO from this repository
> or any build of it.** There is no public release channel, no public artifact
> host, and no public signing key.

## Status

**Base decision accepted; archiso scaffold in place.** [ADR 0001](docs/adr/0001-cybersecurity-os-base.md)
chooses **Archiso + Calamares** with a curated package set from BlackArch as a
package source, not as the base image. The first buildable profile is in
[`iso/`](iso): boot layout, pinned Arch/BlackArch sources, keyring policy, a
mandatory Hyprland/Quickshell desktop, and a small reviewed security baseline.
The static tests run anywhere; the ISO is built only inside an Arch container,
and [`build.sh`](build.sh) refuses to run on a host.

Read next:

- [Authorized-use boundary](docs/policy/authorized-use.md)
- [Legal, licensing, and export considerations](docs/policy/legal-licensing-export.md)
- [Reference build](build/README.md)


No ISO, package archive, checksum, or signature is committed. Nothing is
installed on the host and the live root does not install packages at boot.

- exclusive security panels, not the normal desktop dashboard
- Nmap, Wireshark/forensics, and an isolated lab/VM launcher
- explicit authorized-lab mode, target-scope indicator, and stop/clear action
- no default scans, no bundled phishing templates, no credential theft
- hardened defaults and a private signed release pipeline

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
