# Legal, licensing, and export considerations

**Status:** Review guidance, not legal advice. This document records the issues
the project must resolve before distributing any private build. It is not a
substitute for advice from qualified counsel in the relevant jurisdiction.

The project is a public-source repository with private binary releases. Even a
private release is a **distribution** to its recipients, so the obligations
below attach to the artifact and to the act of handing it to another person or
organization. Publishing source code is not a loophole.

## 1. Project license

The repository identifies itself as **GPL-3.0-only** (see
`.github/FUNDING.yml`). Before any binary is distributed, the project should:

- add the canonical GPL-3.0 text as `LICENSE`;
- add SPDX identifiers to project-owned source files where practical;
- keep copyright notices intact; and
- make the corresponding source available in the manner the GPL requires.

The build scripts and project-owned configuration are intended to be covered by
that license. Third-party packages remain under their own licenses; the project
license does not relicense them.

**Current gap:** the repository states GPL-3.0-only but does not contain a
canonical `LICENSE` file. Treat adding it as a release blocker, not as an
optional cleanup.

## 2. Third-party package licenses

Arch and BlackArch are collections of packages under many different licenses.
There is no single "BlackArch license" that covers the tools. Before a package
enters the manifest, record:

- package name, version, repository, and upstream URL;
- license expression as declared by the package (SPDX where possible);
- whether the license permits redistribution in a compiled image;
- whether the license requires source availability, notice retention, or a
  written offer;
- whether the package contains non-free assets, firmware, fonts, or data with a
  separate license; and
- whether the package has patent, trademark, or restricted-use terms.

Generate the inventory from the built image (`pacman -Qi` / package metadata),
not from memory. A package that is acceptable to install locally may still be
unacceptable to redistribute in an image.

### Copyleft and source offers

GPL, LGPL, AGPL, and similar licenses can require the project to provide the
corresponding source, scripts, or installation information when it distributes
binaries. For a private image, the practical options are:

- include a source archive alongside the artifact;
- provide a written offer valid for the required period; or
- rely on a compliant upstream source offer only where the license permits it.

The project should not assume that linking to an upstream download page is
sufficient. Keep the exact source versions for the binaries shipped.

### License examples that need specific attention

These are prompts for review, not final conclusions:

- **Nmap** is distributed under the Nmap Public Source License (NPSL), a
  GPL-derived license with additional terms. Review redistribution and notice
  obligations rather than assuming it is plain GPL.
- **Wireshark** is GPL-2.0-or-later. Keep notices and source obligations.
- **The Sleuth Kit** and forensic libraries may carry their own copyleft or
  permissive terms; check the actual package metadata.
- **QEMU, libvirt, and virt-manager** are GPL/LGPL family projects with
  redistribution obligations and optional components under other licenses.
- **Calamares** is GPL-3.0-or-later; the installer configuration and branding
  may also carry upstream notices.
- **Firmware and microcode** packages have separate redistribution terms. Do not
  treat them as ordinary GPL packages.
- **BlackArch packages** vary widely. Some tools are permissive, some are
  copyleft, and some may carry non-commercial, attribution, or restricted-use
  terms. A package being in BlackArch is not a license review.

### Trademarks and branding

Do not imply that BlackArch, Arch Linux, Calamares, or any upstream project
endorses this image. Follow their trademark and logo policies. The project name
and branding should be distinguishable from upstream. Do not ship upstream
logos in a way that suggests an official derivative.

## 3. Authorized-use and computer-misuse law

The image includes dual-use security tools. Possession or distribution is not
the same as authorized use, but the project should assume that the image could
be used unlawfully and should design against that:

- require the authorized-use banner and boundary in
  [`authorized-use.md`](authorized-use.md);
- do not ship phishing templates or credential-theft tooling;
- do not configure default scans or automatic target discovery;
- keep documentation that the image is for owned or explicitly authorized
  systems only; and
- refuse support requests that ask for help attacking third parties.

Computer-misuse and unauthorized-access laws vary by country and can apply
across borders. Examples include Brazil's Lei 12.737/2012 (and related
cybercrime provisions), the U.S. Computer Fraud and Abuse Act, the UK Computer
Misuse Act, the Council of Europe's Budapest Convention as implemented by its
signatories, and the EU's NIS2 framework. This list is illustrative, not
exhaustive. The operator is responsible for the law of every jurisdiction
touched by the test.

## 4. Export controls and sanctions

Security tools can be dual-use items. Depending on the tool, destination,
recipient, and end use, export-control rules may apply, including:

- the **Wassenaar Arrangement** controls on intrusion software and dual-use
  information-security items;
- the **EU Dual-Use Regulation (EU) 2021/821** and its annexes;
- **U.S. Export Administration Regulations (EAR)**, including controls and
  license exceptions that may apply to publicly available open-source code; and
- **Brazilian export-control and sanctions rules**, plus applicable UN, EU, and
  U.S. sanctions lists.

Relevant categories can include encryption, network analysis, intrusion
software, and exploitation frameworks. Open-source publication may qualify for
an exception in some regimes, but that is fact-specific and should not be
assumed. The project should:

- classify the tool set with counsel or a qualified export reviewer;
- screen recipients and destinations against applicable sanctions lists before
  a private release;
- obtain end-use/end-user statements for private distributions where
  appropriate;
- keep export-classification and screening records;
- avoid shipping exploit code, C2, or "intrusion software" that raises the
  classification unnecessarily; and
- stop a distribution if a destination or recipient is prohibited.

Export obligations can attach even when no money changes hands. A private
download link is still a transfer.

## 5. Privacy and data protection

Tools in the image can capture packets, hostnames, credentials, personal data,
and communications. Operators must comply with applicable privacy and
data-protection law, which may include Brazil's LGPD, the GDPR, and sectoral
rules. The project should document:

- what the tool captures by default (the reference build should capture nothing
  until a target and capture interface are explicitly selected);
- lawful basis and consent for any personal data collected during a test;
- minimization, access control, encryption, retention, and deletion;
- breach-notification duties; and
- cross-border transfer restrictions.

Do not ship packet captures, credentials, customer data, or test artifacts in
the repository or in a public release.

## 6. Distribution and release practice

- Release artifacts are private and go only to authorized recipients.
- The public repository contains source, policy, and build logic, not ISOs,
  signing keys, or customer data.
- Each private release should have a signed manifest, a package/license
  inventory, a checksum, and a record of the export and recipient review.
- Do not publish a GitHub Pages site, a public release, or an ISO in this task.
- Keep a takedown/correction process for packages that turn out to have
  unacceptable licenses or terms.

## 7. Pre-release checklist

Before signing a private build:

- [ ] canonical project `LICENSE` added and source-availability plan documented;
- [ ] package license inventory generated from the built image;
- [ ] copyleft source/notice obligations satisfied;
- [ ] no non-redistributable or unclassified package in the image;
- [ ] Nmap/NPSL and other special licenses reviewed;
- [ ] export classification and recipient screening completed;
- [ ] authorized-use banner and policy tests pass;
- [ ] no phishing templates or credential-theft tooling in the image;
- [ ] privacy/data-handling note included for operators; and
- [ ] legal review recorded for the release, with the reviewer and date.

## 8. No legal advice

This document is an engineering and compliance checklist. It does not create an
attorney-client relationship and does not guarantee that a build is lawful in
any jurisdiction. Obtain jurisdiction-specific advice before distributing the
image or the tool set.
