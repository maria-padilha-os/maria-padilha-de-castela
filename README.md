# Maria Padilha de Castela

Public-source cybersecurity desktop image. **Release builds remain private.**
This is an authorized-lab tool, not a general-purpose distribution.

## Status

**Scaffold / base decision.** The first task is an ADR comparing a BlackArch
profile against an Archiso + Calamares image that pulls selected BlackArch
packages. No ISO or installer exists yet.

## Planned surface

- exclusive security panels, not the normal desktop dashboard
- Nmap, SET, Wireshark/forensics, and an isolated lab/VM launcher
- explicit authorized-lab mode, target-scope indicator, and stop/clear action
- no default scans, no bundled phishing templates, no credential theft
- hardened defaults and a private signed release pipeline

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
