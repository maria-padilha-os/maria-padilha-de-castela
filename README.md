# Maria Padilha de Castela

Public-source cybersecurity desktop image. **Release builds remain private.**
This is an authorized-lab tool, not a general-purpose distribution.

## Status

**Base decision accepted.** [ADR 0001](docs/adr/0001-cybersecurity-os-base.md)
chooses **Archiso + Calamares** with a curated set of packages from the
BlackArch repository. BlackArch is a package source, not the base image.
The reference profile is source-only in [`build/`](build/README.md); no ISO,
Pages site, or release is published.

Read next:

- [Authorized-use boundary](docs/policy/authorized-use.md)
- [Legal, licensing, and export considerations](docs/policy/legal-licensing-export.md)
- [Reference build](build/README.md)

## Planned surface

- exclusive security panels, not the normal desktop dashboard
- Nmap, Wireshark/forensics, and an isolated lab/VM launcher
- explicit authorized-lab mode, target-scope indicator, and stop/clear action
- no default scans, no bundled phishing templates, no credential theft
- hardened defaults and a private signed release pipeline

SET is a future candidate, not part of the reference build. It can only be
reconsidered after the phishing-template and credential-capture controls are
implemented and tested.

## Authorized use

Use this only on systems you own or have written permission to test. Do not use
the image or its tools against third-party systems. The source is public so the
work can be reviewed; release artifacts and signing keys are not.

## Relationship to the other repositories

It builds on the desktop from
[`maria-padilha-de`](https://github.com/maria-padilha-os/maria-padilha-de) and
[`maria-padilha-dotfiles`](https://github.com/maria-padilha-os/maria-padilha-dotfiles).
The normal desktop image is
[`maria-padilha-os`](https://github.com/maria-padilha-os/maria-padilha-os).
