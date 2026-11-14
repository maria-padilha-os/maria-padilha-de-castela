#!/usr/bin/env bash
# Profile definition for the private Maria Padilha de Castela image.
#
# This profile is consumed by mkarchiso. Build it with ../build.sh from inside
# an Arch Linux container; the script refuses to run on a host.
# shellcheck disable=SC2034

# Version pin: 0.1.0 (kept in sync with iso/package-version).
_profile_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
castela_version="${MARIA_PADILHA_CASTELA_VERSION:-$(<"${_profile_dir}/package-version")}"

iso_name="maria-padilha-de-castela"
iso_label="MARIAPADILHA_$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y%m)"
iso_publisher="Maria Padilha de Castela (private authorized-lab image)"
iso_application="Private authorized-lab cybersecurity desktop"
iso_version="${castela_version}"
install_dir="arch"
arch="x86_64"
pacman_conf="pacman.conf"
bootmodes=('bios.syslinux'
           'uefi.systemd-boot')
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M' '-Xdict-size' '1M')
bootstrap_tarball_compression=('zstd' '-c' '-T0' '--auto-threads=logical' '--long' '-19')
# Keep the graphical console and mirror boot progress to a serial console. The
# serial login banner is what the private CI QEMU smoke test waits for, and it
# also makes headless installer/recovery use possible.
kernel_params="quiet console=tty0 console=ttyS0,115200 systemd.show_status=1"

declare -A file_permissions=()
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/etc/sudoers.d/10-maria-live"]="0:0:440"
  ["/root"]="0:0:750"
  # The live user's capture directory and shell defaults are owner-only.
  ["/home/maria"]="1000:1000:700"
  ["/home/maria/.bashrc"]="1000:1000:600"
  ["/home/maria/.bash_profile"]="1000:1000:600"
  ["/home/maria/Captures"]="1000:1000:700"
  ["/home/maria/Captures/README.md"]="1000:1000:600"
)
