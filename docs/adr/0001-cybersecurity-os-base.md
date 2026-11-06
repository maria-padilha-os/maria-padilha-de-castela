# ADR 0001: Cybersecurity OS base and scope

- **Status:** Accepted
- **Date:** 2026-11-06
- **Decision owner:** `maria-padilha-de-castela` maintainer
- **Related:** [`README.md`](../../README.md), [`docs/policy/authorized-use.md`](../policy/authorized-use.md), [`docs/policy/legal-licensing-export.md`](../policy/legal-licensing-export.md), [`build/README.md`](../../build/README.md)
- **Scope of this ADR:** choose the base image and the initial tool boundary only. It does not authorize a release, an ISO publication, a Pages site, or the use of any offensive tool.

## Context

`maria-padilha-de-castela` is a public-source, privately released cybersecurity
desktop for authorized lab work. It builds on the desktop and packaging work in
the sibling `maria-padilha-de` and `maria-padilha-dotfiles` repositories. The
source is public so the build logic and policy can be reviewed; release
artifacts, signing keys, and the release pipeline are private.

Two base strategies are realistic:

1. derive from a **BlackArch ISO/profile** and remove or add packages; or
2. build an **Archiso image with Calamares** and add selected packages from the
   BlackArch repository.

This decision has to be made before adding tools because the base determines
package provenance, signing, update cadence, image size, installer behavior, and
how strongly the authorized-use boundary can be enforced.

### Goals

- A small, curated, reviewable image rather than a general-purpose distribution.
- Explicit package provenance and verifiable signatures for every input.
- A build that the project controls end to end, including the installer, banner,
  first-boot defaults, and release signing.
- A policy that is enforced by the package manifest and tests, not only by prose.
- A maintenance load the project can sustain with a private release process.

### Non-goals

- A full penetration-testing catalogue or a "everything included" ISO.
- Phishing kits, credential theft, malware, command-and-control, persistence, or
  stealth tooling.
- Anonymous operation, evasion of law enforcement, or use against third parties.
- A stable long-term-support distribution, a public binary release, or a hosted
  download/Pages service in this task.

## Decision

**Adopt Archiso + Calamares.** The image uses the official Arch Linux
`x86_64` base and the project's existing desktop/installer integration, then
adds a small, reviewed set of packages from the BlackArch repository.

BlackArch is treated as a **package source**, not as the base distribution. The
project does not ship, remaster, or redistribute the BlackArch ISO, and does not
adopt the BlackArch installer as its installer. The reference profile lives in
[`build/archiso/profile`](../../build/archiso/profile), and the build recipe and
verification checklist live in [`build/README.md`](../../build/README.md).

The initial scope is a console-capable base plus installer and a small set of
network-analysis, forensics, and isolated-lab packages. Desktop and panel
packages come from `maria-padilha-de`; the security-specific scope is not a
second desktop stack. The Social-Engineer Toolkit (SET) is **not** in the
reference build. It may only be reconsidered after the phishing-template and
credential-capture controls in the authorized-use policy are implemented and
tested.

## Alternatives considered

### Alternative A: BlackArch ISO/profile as the base

Use a BlackArch full ISO, netinstall ISO, or a derivative of its Archiso profile
and installer, then remove unwanted tools and add project branding.

**Advantages**

- Fastest route to a bootable image with a large security-tool catalogue.
- BlackArch maintains package recipes, tool categories, and a rolling repository.
- The full ISO is a known, tested combination of Arch and BlackArch packages.
- Less project-owned build logic if the stock installer and package set are
  acceptable.

**Disadvantages**

- The full ISO is tens of gigabytes (historically in the roughly 20 GiB class),
  which is expensive to build, mirror, sign, test, and update.
- The netinstall ISO is small, but it delegates package selection to the user and
  produces an uncurated, much larger installed system.
- The stock installer is the BlackArch installer, not Calamares. Replacing it or
  deeply branding it means maintaining a fork of an installer the project does
  not control.
- Removing tools from a full ISO does not remove their package metadata,
  menus, desktop entries, templates, or dependencies. A subtraction-only model
  is difficult to audit and easy to regress.
- The BlackArch ISO is a product, not a stable derivative API. Its profile,
  installer, boot configuration, and package split can change between releases.
- The project would still need its own release key, checksum, and artifact
  signing; an upstream ISO signature covers only the upstream input, not a
  modified image.
- A large default tool set increases license, export-review, and attack-surface
  burden before any project value is added.

### Alternative B: Archiso + Calamares with selected BlackArch packages

Use the official Archiso `releng` profile as the structural base, install
Calamares from Arch `extra`, and add a reviewed package list from the BlackArch
repository. The project owns the profile, installer configuration, branding,
banner, package manifest, and release signing.

**Advantages**

- The package list is an explicit allowlist, so scope is visible in review and
  enforceable in tests.
- The image can stay small: only the desktop, installer, and vetted tools are
  included.
- Calamares is already the natural installer for the project's desktop work and
  gives control over partitioning, users, locale, bootloader, and first-boot
  behavior.
- The project can use Arch's broad, well-maintained mirror set for the base and
  a small, validated BlackArch mirror set for the added packages.
- The release signing chain belongs to the project: inputs are verified with
  Arch and BlackArch keyrings, and the output is signed with an offline project
  key.
- Policy controls (banner, no default scans, no phishing templates, no
  credential-theft packages) can be baked into the build and checked in CI.
- Fewer packages mean fewer licenses, fewer export classifications, fewer
  vulnerabilities, and a smaller update/QA surface.

**Disadvantages**

- The project owns more build engineering: Archiso profile maintenance,
  Calamares configuration, keyring bootstrap, package-cache policy, and
  install-test automation.
- Calamares module changes and Archiso changes must be tracked deliberately.
- BlackArch package quality and availability still vary by package and mirror.
- A rolling Arch base has no long-term-support branch; images age quickly.
- The initial build pipeline is more work than booting the stock BlackArch ISO.

### Why the project chose B

The main advantage of A is speed to a first boot, but that advantage disappears
as soon as the project removes tools, replaces the installer, adds a banner, and
enforces an allowlist. At that point the project is already maintaining a
derivative. Starting from Archiso + Calamares makes the same work explicit,
reviewable, and smaller. It also reuses the desktop integration the project
already maintains instead of creating a second desktop/installer stack.

## Comparison

| Dimension | BlackArch ISO/profile | Archiso + Calamares (selected BlackArch packages) |
| --- | --- | --- |
| Base and installer | BlackArch ISO with the BlackArch installer; a custom installer is a fork | Official Archiso `releng` structure; Calamares from Arch `extra`, configured by the project |
| Package source | BlackArch repository plus Arch; full ISO ships a very large set | Arch `core`/`extra` plus an explicit, reviewed BlackArch subset |
| Selection model | Subtraction from a large image, or user selection in netinstall | Additive allowlist committed to this repository |
| Package signing | BlackArch packager keys via `blackarch-keyring`; verify the ISO's published checksums/signatures | Arch keyring and BlackArch keyring, with `SigLevel = Required`; the project also signs its own output |
| Output signing | Upstream signature is invalidated by remastering; project still needs its own key | Project offline release key signs the checksum/manifest for each private build |
| Mirror availability | Smaller BlackArch mirror pool; mirrors can lag or disappear; no general package snapshot guarantee | Arch mirrors are broad; BlackArch still uses a smaller pool, so a package cache and mirror checks are required |
| Typical size | Full ISO is tens of GiB (roughly 20 GiB class historically); netinstall is sub-GiB before installed tools | Design budget of a few GiB for the ISO; installed size grows only with the reviewed manifest. Measure every build. |
| Update model | Rolling Arch + BlackArch; full ISO is a stale snapshot; no LTS branch | Rolling Arch + BlackArch; versioned private builds on a defined cadence; users update with `pacman` |
| Reproducibility | Full-ISO remaster is hard to reproduce; source inputs are not pinned by the image | Profile and manifest are in git; package versions can be recorded and cached. Rolling mirrors still require a package cache for exact rebuilds. |
| Maintenance burden | Low initial effort, high customization/removal and QA effort; upstream installer/profile churn | Medium/high initial pipeline effort, lower ongoing curation effort; project owns Calamares and Archiso updates |
| Policy fit | Large default surface and stock installer make "no default scans/no templates" harder to prove | Allowlist, banner, service defaults, and tests are first-class build inputs |
| Legal/export exposure | Broad catalogue requires review of many tools and licenses at once | Review is incremental and tied to each package addition |
| Main risk | The derived image becomes a large, stale, hard-to-audit fork | The project takes on pipeline and installer maintenance, and must keep the allowlist current |

### Signing and trust

- **Package trust:** the build host starts from a clean Arch keyring, installs
  `blackarch-keyring`, and populates both keyrings with
  `pacman-key --populate archlinux blackarch`. Repository entries use
  `SigLevel = Required DatabaseOptional`; `TrustAll` and
  `SigLevel = Never` are prohibited. Keyring updates are part of the build, not
  an afterthought.
- **ISO trust:** every build produces a SHA-256 manifest. The manifest (not only
  the ISO) is signed with an offline project key, and the public fingerprint is
  published through a channel separate from the artifact host. The private key
  never enters this repository, CI logs, or the build cache.
- **Derived artifacts:** a remastered BlackArch ISO cannot inherit the upstream
  signature. This is a decisive practical difference: with Archiso + Calamares,
  the project signs from the beginning instead of pretending an upstream ISO
  signature covers a modified image.
- **Key lifecycle:** use a dedicated release key with an offline primary key and
  a documented revocation certificate. Rotate or re-issue after compromise,
  record fingerprints per release, and require two-person approval for signing.

### Mirrors and availability

- Arch's official mirror pool is large and tiered; a generated, ranked
  `mirrorlist` is appropriate for the base.
- BlackArch's mirror pool is smaller. A single BlackArch mirror is a single
  point of failure, and mirrors may lag the repository. The build should use a
  reviewed mirror list with retries and health checks, not a hard-coded host.
- The project should keep a **local package cache** for the exact versions used
  in a release. Arch's official archive helps for Arch packages; BlackArch does
  not offer the same general snapshot guarantee, so the cache is the practical
  reproducibility mechanism.
- A failed mirror must fail the build closed. It must never silently substitute
  a package from an unverified source.

### Size

The full BlackArch ISO is sized for a large tool catalogue, not for a curated
desktop. The reference build sets a size budget rather than claiming a measured
number:

- ISO design budget: **≤ 6 GiB compressed** for the base, installer, desktop,
  and initial tool set.
- Installed design budget: **≤ 12 GiB** before user data and virtual machines.
- The build records the actual ISO size and `pacman -Q` manifest. A build that
  exceeds the budget needs an explicit review, not a silent exception.

These are budgets. The final numbers must be measured on the build host; the
repository does not contain an ISO.

### Update model

- Arch and BlackArch are rolling repositories. There is no stable release branch
  to pin for years.
- Private images are rebuilt on a regular cadence (at least monthly) and on
  critical security advisories. A rebuild refreshes keyrings, mirror lists,
  package versions, Calamares, and Archiso.
- The installed system updates with `pacman -Syu`. The image is an offline,
  reproducible starting point, not a frozen distribution.
- Each release records a package manifest and a source/license manifest. Users
  are told the image is a snapshot and must be updated after installation.
- Exact rebuilds require the package cache and a recorded build environment;
  without it, a later rebuild will legitimately pick up newer rolling packages.

### Maintenance burden

Archiso + Calamares has a higher upfront cost, but the work is visible and
bounded:

- maintain the Archiso profile and Calamares configuration;
- review every package addition against the policy and license list;
- keep keyrings, mirror lists, and the package cache healthy;
- run install and first-boot smoke tests in a VM;
- rebuild on a schedule and sign off-build;
- track Archiso, Calamares, and BlackArch changes.

The BlackArch ISO route hides some of this work initially, but the project would
still need to remove packages, replace the installer, add the banner, maintain
the fork, and sign its own output. The hidden work is larger and less testable.

## Reference build

The minimal reference build is defined by
[`build/archiso/profile/packages.x86_64`](../../build/archiso/profile/packages.x86_64)
and the profile in that directory:

- official Arch base, kernel, firmware, microcode, networking, and basic tools;
- Calamares from Arch `extra`;
- the project desktop/panel packages from `maria-padilha-de` (not duplicated
  here);
- a small set of reviewed tools: `nmap`, `wireshark-qt`, `sleuthkit`, and
  isolated-lab virtualization (`qemu-desktop`, `libvirt`, `virt-manager`,
  `firejail`);
- no SET, no phishing templates, no credential-theft packages, and no default
  scan services or timers;
- an explicit authorized-use banner in `/etc/issue` and `/etc/motd`.

The reference build is intentionally **not** a release pipeline. Building it
requires an Arch host and network access, which are outside this task. The
repository contains no ISO, no binary artifact, no Pages site, and no release
workflow. `build/README.md` documents the build command and the checks that must
pass before any private artifact is signed.

## Consequences

### Positive

- Scope is an allowlist that can be reviewed in a pull request and tested.
- The image is smaller and has a smaller vulnerability and licensing surface.
- The project controls signing, banner, installer behavior, and first-boot
  defaults.
- Desktop work is reused rather than forked.
- Package trust and output trust are separate, explicit chains.

### Negative

- The project owns the Archiso/Calamares pipeline and must maintain it.
- BlackArch package quality, mirrors, and rolling changes remain external risks.
- Calamares configuration is security-sensitive and needs install testing.
- The image will be stale quickly without a rebuild cadence.

### Mitigations

- Keep the package list short and require review for additions.
- Cache packages and record manifests for each release.
- Test installs in a VM, including offline install and first boot.
- Run `tests/all.sh` in CI and before signing.
- Fail closed on signature, mirror, or manifest errors.
- Revisit this ADR if the desktop integration changes or if the maintenance load
  exceeds the project's capacity.

## Enforcement and review

- Any package addition must update the manifest and the license inventory, and
  must pass the policy tests.
- Any change to the installer, banner, default services, or Calamares sequence
  requires review against the authorized-use policy.
- Any proposal to add a phishing, credential-theft, C2, persistence, or
  destructive tool is out of scope until this ADR is superseded.
- This ADR does not grant permission to test any system. Authorization is
  separate, written, and specific to a target and time window.

## References

- Arch Linux: <https://archlinux.org/>
- Archiso: <https://wiki.archlinux.org/title/Archiso>
- Calamares: <https://calamares.io/>
- BlackArch: <https://blackarch.org/>
- BlackArch packaging: <https://github.com/BlackArch/blackarch>
- Internal: [`docs/policy/authorized-use.md`](../policy/authorized-use.md)
- Internal: [`docs/policy/legal-licensing-export.md`](../policy/legal-licensing-export.md)
- Internal: [`build/README.md`](../../build/README.md)
