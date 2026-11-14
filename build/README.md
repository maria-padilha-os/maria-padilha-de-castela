# Reference build

This directory contains the **minimal reference build inputs** for the
Archiso + Calamares decision in
[`docs/adr/0001-cybersecurity-os-base.md`](../docs/adr/0001-cybersecurity-os-base.md).
It is not a release pipeline and it does not contain an ISO.

**Nothing here was built in the ADR task.** Building requires an Arch Linux host
and network access for packages and mirrors. Do not publish the resulting
artifact, a Pages site, or a GitHub release.

## What the reference build is

- Official Arch Linux `x86_64` base, using the Archiso profile format.
- Calamares from Arch `extra`, with the security overlay in
  `archiso/profile/airootfs/etc/calamares/`.
- A small, reviewed package set from
  [`archiso/profile/packages.x86_64`](archiso/profile/packages.x86_64):
  network analysis, forensics, and isolated-lab virtualization.
- BlackArch as a **package repository only**, with package signatures required.
- An explicit authorized-use banner in `/etc/issue` and `/etc/motd`.
- No desktop/panel duplication. The `maria-padilha-de` build supplies the
  desktop and the final Calamares branding/module configuration.

The reference build is deliberately console-capable and incomplete as a
consumer desktop. That is the point: it proves the base, package provenance,
signing boundary, and policy controls before more tools are added.

## Installer security tool groups

The Calamares overlay offers a mandatory core plus optional Recon, Web,
Wireless, Forensics, Reversing, Password Auditing, and Lab/VM tool groups. The
group definitions are in
`archiso/profile/airootfs/etc/calamares/modules/packagechooser.conf` and are
consumed by the Calamares `packages` module after `unpackfs`. No group is
selected by default; selection only installs packages and starts no service,
scanner, or capture. Optional groups need network access or a local package
cache, while the core installs offline.

Only redistributable packages are offered. Proprietary or unclear-license tools
are documented as user-installed in
[`docs/policy/security-tool-groups.md`](../docs/policy/security-tool-groups.md).
The shared group definition is mirrored in the active `iso/` profile and checked
for drift by `tests/security-groups.sh`.

## Layout

```text
build/
├── README.md
└── archiso/
    └── profile/
        ├── profiledef.sh
        ├── packages.x86_64        # allowlist
        ├── denylist.txt           # known prohibited packages
        ├── pacman.conf            # strict signature policy
        └── airootfs/
            ├── etc/issue
            ├── etc/motd
            └── etc/calamares/     # sequence, branding, authorized-use notice,
                                   # packagechooser groups, package install
```

## Build-host prerequisites (not executed here)

On a current Arch Linux build host:

- `archiso` and `calamares` from Arch `extra`;
- `gnupg` for signing;
- the BlackArch keyring and mirrorlist installed from a reviewed source;
- a current Arch mirrorlist at `/etc/pacman.d/mirrorlist`;
- a BlackArch mirrorlist at `/etc/pacman.d/blackarch-mirrorlist`;
- enough disk space for the work directory and ISO (budget at least 20 GiB);
- network access for the build, unless a complete local package cache is used.

Populate and verify the keyrings before building:

```bash
sudo pacman-key --populate archlinux blackarch
pacman-key --list-keys | less   # verify the expected fingerprints
```

Never disable signature checking to make a mirror work. If the keyring or a
signature is wrong, fix the trust input or fail the build.

## Build command

Set an explicit, non-secret version. Do not use the current date as the only
version identifier; releases need a stable label.

```bash
export ISO_VERSION=2026.11.0
export ISO_LABEL=MARIAPADILHA_202611
sudo env ISO_VERSION="$ISO_VERSION" ISO_LABEL="$ISO_LABEL" \
  mkarchiso -v \
  -w /var/tmp/maria-padilha-work \
  -o /var/tmp/maria-padilha-out \
  build/archiso/profile
```

The output is a local artifact under `/var/tmp/maria-padilha-out`. It is not
committed. `.gitignore` excludes `out/`, `*.iso`, `*.img`, and package archives.

## Pre-signing checks

Run these on the built image or in a live VM. Do not sign until they pass.

1. **Package provenance**
   - `pacman -Q` matches the reviewed manifest.
   - No package from `denylist.txt` is installed.
   - Every package has a license entry in the license inventory.
2. **Signature policy**
   - `pacman.conf` uses `SigLevel = Required DatabaseOptional`.
   - No active `TrustAll` or `SigLevel = Never` directive appears anywhere.
   - The generated image manifest is hashed and the hash is signed offline.
3. **Authorized-use boundary**
   - `/etc/issue` and `/etc/motd` show the banner.
   - Calamares shows the authorized-use product name and no installation path
     silently enables a scanner.
   - The group chooser has no preselected optional group; selecting a group only
     installs packages and starts no service, scanner, or capture.
   - `tests/all.sh` passes, including `tests/security-groups.sh`.
4. **No default scans or capture**
   - No systemd service, timer, cron job, shell profile, autostart entry, or
     Calamares hook starts `nmap`, `masscan`, `zmap`, or an equivalent scanner.
   - No packet capture starts automatically.
   - No target list is populated from the local network.
5. **No phishing or credential theft**
   - No email templates, landing pages, credential-capture forms, or cloneable
     login pages are present.
   - No credential-dumping, keylogging, or browser/keychain extraction package is
     present.
   - SET and the other denylisted packages are absent.
6. **Installer and first boot**
   - Offline install in a VM succeeds with Calamares and no optional group
     selected; selected groups install only with network access or a local cache.
   - First boot shows the banner.
   - SSH server is not enabled by default.
   - No unexpected outbound connection is made by the live session.
7. **Size and manifest**
   - ISO size is within the design budget (≤ 6 GiB compressed).
   - Installed size is within the design budget (≤ 12 GiB).
   - Record `pacman -Q`, ISO SHA-256, build date, mirror snapshots, and the
     signing-key fingerprint in the private release record.

## Signing and release

The release key is offline and never enters this repository or CI logs. Follow
[the private release checklist](../docs/release-checklist.md) for explicit human
approval, private artifact handling, revocation, and retention.

```bash
sha256sum maria-padilha-de-castela-*.iso > SHA256SUMS
gpg --detach-sign --armor SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS
```

Publish the fingerprint through a channel separate from the artifact host. A
private artifact without a verified signature is not a release.

Do not tag, publish, or upload the artifact from this repository as part of the
ADR task. The repository remains source-only: no ISO, no Pages site, no GitHub
release, no signing key.

## Maintenance

- Rebuild at least monthly and after critical security advisories.
- Refresh keyrings and mirror lists as part of every build.
- Keep a package cache for the exact versions in each release; BlackArch does
  not provide a general snapshot archive comparable to Arch's official archive.
- Review every package addition against the authorized-use and legal documents.
- Update this reference build when Archiso, Calamares, or the desktop overlay
  changes its profile/module contract.

## Known limitations

- The Calamares module configuration is supplied by the desktop overlay; the
  sequence in this repository is not a substitute for an install test.
- The package list is x86_64-only and has no multilib repository.
- The active `iso/` profile includes the private cyber frontend at
  `airootfs/usr/share/maria-padilha/cyber/` (source:
  [`frontend/cyber/`](../frontend/cyber/README.md)). This older reference-build
  subtree does not duplicate the frontend. The SET package remains excluded from
  the image; its tab only detects an operator-installed copy and exposes an
  explicitly confirmed dual-use launcher with no target, template, or payload.
- Rolling repositories mean a later rebuild is not bit-identical without the
  package cache and recorded build environment.
