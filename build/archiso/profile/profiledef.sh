#!/usr/bin/env bash
# Archiso profile definition for the reference build.
# This file is sourced by mkarchiso; do not execute it directly.
#
# The reference build is not a release. See ../../README.md and
# docs/adr/0001-cybersecurity-os-base.md before changing it.

iso_name="maria-padilha-de-castela"
iso_label="${ISO_LABEL:-MARIAPADILHA}"
iso_publisher="Maria Padilha de Castela <https://github.com/maria-padilha-os/maria-padilha-de-castela>"
iso_application="Authorized-lab cybersecurity desktop (reference build)"
iso_version="${ISO_VERSION:-dev}"
install_dir="arch"
buildmodes=('iso')
bootmodes=('bios.syslinux.mbr' 'bios.syslinux.eltorito' 'uefi-x64.systemd-boot.esp' 'uefi-x64.systemd-boot.eltorito')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M' '-Xdict-size' '1M')
bootstrap_tarball_compression=('zstd' '-c' '-T0' '--auto-threads=logical' '--long' '-19')

file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/etc/gshadow"]="0:0:400"
  ["/root"]="0:0:750"
)
