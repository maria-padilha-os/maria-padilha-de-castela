# Authorized security tool groups

**Status:** Normative for the installer group definitions. This document is an
engineering and licensing review aid, not legal advice.

The private Maria Padilha de Castela image ships a **mandatory core** and seven
optional, user-selected security tool groups. The groups are defined in
[`iso/airootfs/etc/calamares/modules/packagechooser.conf`](../../iso/airootfs/etc/calamares/modules/packagechooser.conf);
the reference build carries the same file under
`build/archiso/profile/airootfs/etc/calamares/modules/`.

> **AUTHORIZED USE ONLY.** Use the image only on systems you own or for which
> you hold explicit, written permission to test. Selecting a group does not
> authorize any target. No group is selected by default, and no group starts a
> service, scanner, capture, or target discovery.

## 1. Installer behavior

| property | value |
| --- | --- |
| Calamares module | `packagechooser`, method `packages` |
| selection mode | `optionalmultiple` (zero or more groups) |
| preselects | none; there is no `default:` group |
| mandatory core | listed in `iso/packages.x86_64` and always installed from the image |
| installation | the `packages` module installs selected packages after `unpackfs` |
| offline install | core installs; optional groups are skipped when there is no network (`skip_if_no_internet: true`) |
| services/scans | none enabled or started by the installer |

The core item is shown in the chooser for transparency. It is a description of
the mandatory base and baseline packages, not an optional add-on: the same
packages are in the live-root allowlist, so deselecting the item cannot remove
them. Optional groups are additive package lists only.

## 2. Group definitions

### Core (mandatory)

The core group contains the Arch base, kernel/firmware/microcode, archiso boot
support, networking, the mandatory Hyprland/Quickshell desktop and session,
greetd/tuigreet, Calamares, the Arch/BlackArch keyrings, and the reviewed
baseline: Nmap, Wireshark, tcpdump, The Sleuth Kit, TestDisk, QEMU, libvirt,
virt-manager, OVMF, and Firejail. Every core package is in
[`iso/packages.x86_64`](../../iso/packages.x86_64).

### Optional groups

Package names below are the Calamares package identifiers. Duplicates across
groups are harmless: the package manager installs a package once.

| group | id | packages | license family |
| --- | --- | --- | --- |
| Recon | `recon` | nmap, masscan, dnsrecon, whois, traceroute, arp-scan, amass, nikto, theharvester, dnsenum | NPSL, AGPL-3.0, GPL-2.0/3.0, Apache-2.0 |
| Web | `web` | nikto, gobuster, ffuf, dirb, whatweb, sqlmap, wfuzz, nuclei, mitmproxy | GPL-2.0, Apache-2.0, MIT |
| Wireless | `wireless` | aircrack-ng, reaver, bully, kismet, wifite, hcxtools, hcxdumptool, pixiewps, cowpatty, mdk4 | GPL-2.0/3.0, MIT |
| Forensics | `forensics` | sleuthkit, testdisk, ddrescue, binwalk, foremost, scalpel, guymager, exiftool, volatility3, autopsy | CPL-1.0, GPL-2.0/3.0, MIT, Artistic-1.0-Perl, Apache-2.0 |
| Reversing | `reversing` | radare2, rizin, ghidra, gdb, binutils, ltrace, strace, jadx, apktool, upx | LGPL-3.0, Apache-2.0, GPL-2.0/3.0 |
| Password Auditing | `password-auditing` | john, hashcat, hashcat-utils, crunch, ophcrack, fcrackzip, pdfcrack, hashid | GPL-2.0/3.0, MIT |
| Lab/VM tools | `lab-vm` | qemu-desktop, libvirt, virt-manager, edk2-ovmf, firejail, libguestfs, dnsmasq, nftables, podman | GPL-2.0, LGPL-2.1/3.0, BSD-2-Clause-Patent, Apache-2.0 |

The license family is a summary prompt, not a final SPDX determination. Before
a private release, generate the package-level license inventory from the built
image (`pacman -Qi`) and record the exact expressions, notices, source
obligations, and any non-code assets. The release checklist in
[`legal-licensing-export.md`](legal-licensing-export.md) applies to every
package in a selected group.

## 3. Redistribution boundary

Only packages whose licenses permit redistribution in a private image are in
the group definitions. The groups deliberately avoid packages whose primary
purpose is phishing, credential theft, credential dumping, network login
brute-force, malware, command-and-control, persistence, or stealth.

The following are **not shipped and not offered by the installer**:

- phishing/SET and credential-harvesting kits: `set`, `gophish`, `evilginx`,
  `king-phisher`, `modlishka`;
- credential dumpers and MITM capture: `mimikatz`, `lazagne`, `responder`;
- network login brute-force tools such as Hydra or Medusa;
- any package in [`iso/denylist.txt`](../../iso/denylist.txt).

The SET package remains excluded from the image and the installer. The private
cyber frontend detects an operator-installed SET through the host probe and
exposes a dual-use launcher/status panel. That panel has no default target,
template, or argument, generates no attack content, and refuses caller-supplied
target/template/payload content; launching requires the shared authorization
gates plus a separate explicit confirmation. A missing SET binary is just a
missing-tool fallback. The frontend never installs SET.

The Wireshark/forensics panel is likewise explicit and local. It can open a pcap
read-only through `tshark` and can start a live capture only after the shared
authorization gates plus a separate confirmation. It has no packet-injection,
replay, upload, or auto-transmit path. Live capture may use `CAP_NET_RAW` and
`CAP_NET_ADMIN` on the narrow capture helper or a distribution capture group;
no root is required by default. The required capabilities and their revocation
are documented in [`forensics-capabilities.md`](forensics-capabilities.md).

The Password Auditing group is deliberately offline-only: John the Ripper,
Hashcat, Hashcat-utils, Crunch, Ophcrack, fcrackzip, pdfcrack, and Hashid work
against files or hashes the operator already owns or is authorized to test.
They do not attack a login endpoint and no cracking job is started automatically.

## 4. Optional tools the user must install

Some useful tools cannot be redistributed in this image because they are
proprietary, commercially licensed, or have terms that are not compatible with
an image redistribution. They are **not** in the groups or the ISO. A user who
needs one must obtain it from the vendor and accept the vendor's license:

| tool | reason it is not shipped |
| --- | --- |
| Burp Suite Professional | commercial license; redistribution is not permitted |
| Nessus Professional | commercial license and activation terms |
| IDA Pro / IDA Free | proprietary license; edition-specific redistribution terms |
| Metasploit Pro | commercial license |
| Cobalt Strike | commercial, restricted-access license |
| Core Impact | commercial license |
| Canvas | commercial license |
| HCL AppScan | commercial license |

This table is illustrative, not exhaustive. A tool is not eligible for a group
merely because it is absent from this list; it still needs the policy, license,
and export review in [`authorized-use.md`](authorized-use.md) and
[`legal-licensing-export.md`](legal-licensing-export.md).

Any future tool that includes phishing templates, cloned login pages,
credential-capture forms, or credential-dumping functionality remains out of
scope even if its license permits redistribution.

## 5. No default service, scan, or capture

The installer group selection is intentionally passive:

- there is no `default:` item, so a fresh install starts with zero optional
  groups;
- selecting a group writes package names to Calamares GlobalStorage and runs
  the package manager only;
- no group adds a systemd unit, timer, cron job, shell profile, autostart
  entry, or Calamares post-install hook;
- libvirtd, bluetooth, NetworkManager, and the desktop session are not enabled
  by the group configuration; only the existing greetd/NetworkManager/bluetooth
  live-image units are enabled by the profile;
- no target list is populated from the local network or captured traffic;
- no interface is captured, no capture file is uploaded, and no packet is
  injected or replayed by the installer or the frontend; the Wireshark/forensics
  tab requires an explicit operator action and a separate confirmation.

A package being installed is not the same as a tool being run. The operator
must still define an explicit target scope before starting any tool, and stop
and clear the scope when finished.

## 6. Offline behavior

- The mandatory core is unpacked from the ISO squashfs and needs no network.
- Optional groups need the reviewed Arch/BlackArch repositories or a complete
  local package cache. With no network, `packages.conf` skips optional installs
  instead of failing the whole installation.
- The installer does not fetch a mirror list, download a wordlist, or contact a
  target during group selection.
- `tests/security-groups.sh` checks the offline configuration and runs without
  network, root, a package manager, or a Calamares installation.

An offline install therefore produces the core image without optional groups.
That is the safe default; no group is silently assumed or half-installed.

## 7. Enforcement

- `tests/security-groups.sh` validates the group ids, display names,
  descriptions, package lists, mandatory core, denylist exclusions, absence of
  secrets, no default group, and offline settings.
- `tests/all.sh` and `tests/iso.sh` retain the banner, package, denylist,
  signature, secret, and no-default-service checks.
- A change to a group definition requires review against
  [`authorized-use.md`](authorized-use.md) and the license/export checklist, and
  must pass the tests before a private build is signed.
- A package that cannot be redistributed is removed from the groups and moved
  to the user-installed list above; it is never silently downloaded by the
  installer.

## 8. No legal advice

This document records engineering controls and license prompts. It does not
create an attorney-client relationship or guarantee that a build is lawful in
any jurisdiction. Export classification, sanctions screening, and
jurisdiction-specific licensing require qualified review before distribution.
