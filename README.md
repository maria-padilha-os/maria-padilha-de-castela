# Maria Padilha de Castela

Private-release cybersecurity desktop image. **The source is public; the built
image is private and must not be published.** This is an authorized-lab tool,
not a general-purpose distribution.

> **Do not publish, upload, mirror, or redistribute an ISO from this repository
> or any build of it.** There is no public release channel, no public artifact
> host, and no public signing key.

## Status

**Base decision accepted; archiso scaffold, installer group selection, and the
private cyber frontend in place.** [ADR 0001](docs/adr/0001-cybersecurity-os-base.md)
chooses **Archiso + Calamares** with a curated package set from BlackArch as a
package source, not as the base image. The first buildable profile is in
[`iso/`](iso): boot layout, pinned Arch/BlackArch sources, keyring policy, a
mandatory Hyprland/Quickshell desktop, a small reviewed security baseline, and
an offline-safe Calamares packagechooser for the optional authorized tool groups.
The exclusive security tabs live in [`frontend/cyber/`](frontend/cyber/README.md)
and are copied into the image at `/usr/share/maria-padilha/cyber/`. The static
tests run anywhere; the ISO is built only inside an Arch container, and
[`build.sh`](build.sh) refuses to run on a host.

Read next:

- [Authorized-use boundary](docs/policy/authorized-use.md)
- [Authorized security tool groups](docs/policy/security-tool-groups.md)
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
| `iso/airootfs/etc/calamares/` | installer sequence, authorized-use notice, branding, group chooser |
| `iso/airootfs/usr/share/maria-padilha/cyber/` | private cyber tabs installed in the image |
| `frontend/cyber/` | source for the exclusive cyber frontend, manifest, and tests |
| `iso/airootfs/` | authorized-use banner, live user, greetd, enabled units, mkinitcpio |
| `iso/efiboot/`, `iso/syslinux/` | UEFI and BIOS boot entries |
| `build.sh` | container-only mkarchiso wrapper |
| `tests/iso.sh` | profile, package, secret, and public-release checks |

The desktop is mandatory: Hyprland, Quickshell, the Qt 6 runtime, the session
daemons, greetd/tuigreet, and the `maria-padilha` session package are in the
allowlist. The security baseline is deliberately small: Nmap, Wireshark,
packet/forensic inspection, and an isolated QEMU/libvirt lab. No scanner or
capture tool is started automatically.

## Installer security tool groups

Calamares offers a **mandatory core** and seven optional, user-selected groups:
Recon, Web, Wireless, Forensics, Reversing, Password Auditing, and Lab/VM tools.
The core is always installed from the image. Optional groups only add package
lists; **no group is selected by default**, and selecting one does not start a
service, scanner, capture, or target discovery. Optional groups need network
access or a local package cache; an offline install receives the core image.

The group definitions live in
[`iso/airootfs/etc/calamares/modules/packagechooser.conf`](iso/airootfs/etc/calamares/modules/packagechooser.conf)
and are wired through `settings.conf` to the Calamares `packages` module. Only
packages that can be redistributed are offered. Proprietary or unclear-license
tools are not shipped and are documented as user-installed in
[`docs/policy/security-tool-groups.md`](docs/policy/security-tool-groups.md).

## Exclusive cyber frontend

The security extensions are a separate, private surface, not the normal desktop
dashboard. They are exposed only when the build is private **and** the
`MARIA_PADILHA_CYBER_FRONTEND` flag is on. The dedicated namespace is
`maria-padilha.cyber` with panels under `maria-padilha.cyber.panels`; the normal
dashboard is not mounted from this surface.

The manifest registers Nmap, SET, Wireshark/forensics, and the lab/VM launcher.
Every tab has `"autoRun": false`. SET is registered for transparency but is
policy-blocked and is not shipped; the tab never renders a launch control. A
missing tool produces a structured fallback instead of failing the surface, and
no command is run. Every offensive panel renders the shared authorization
banner, lab-mode switch, target-scope indicator, and Stop/Clear actions from one
frame, so the controls cannot be omitted.

Authorization is fail-closed: written authorization must be acknowledged, lab
mode cannot be enabled before that, and a bounded target scope is required
before the runner will start anything. Stop cancels the current operation; Clear
removes the scope and queued targets. The host supplies the availability probe
and executor; this repository ships no privileged process spawner. Theme values
are semantic tokens only, so there are no hardcoded palette values.

See [`frontend/cyber/README.md`](frontend/cyber/README.md) for the manifest,
feature-flag, QML/browser integration, and tests. `tests/cyber-frontend.sh`
checks the manifest, tab enable/disable, missing-tool fallback, authorization
state, image mirror, no-auto-run rule, and the no-palette rule.

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
