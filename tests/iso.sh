#!/usr/bin/env bash
# Static checks for the private Maria Padilha de Castela archiso profile.
#
# These checks need no root, mkarchiso, network, or Arch host. They verify the
# files that build.sh and mkarchiso consume, the required desktop and security
# packages, the authorized-use boundary, no secrets, and no public release
# metadata.
set -euo pipefail

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail=0
ok() { printf 'ok %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; fail=1; }

require_file() {
    if [[ -s "$1" ]]; then ok "$1"; else bad "$1 missing or empty"; fi
}

require_exec() {
    if [[ -x "$1" ]]; then ok "$1 executable"; else bad "$1 is not executable"; fi
}

for file in \
    README.md \
    build.sh \
    Makefile \
    iso/profiledef.sh \
    iso/packages.x86_64 \
    iso/pacman.conf \
    iso/denylist.txt \
    iso/package-version \
    iso/keys/README.md \
    iso/keys/trusted-keyrings.txt \
    iso/keys/blackarch-fingerprints.txt \
    iso/keys/pgp/README.md \
    iso/keys/pgp/blackarch.gpg \
    iso/airootfs/etc/issue \
    iso/airootfs/etc/motd \
    iso/airootfs/etc/maria-padilha-release \
    iso/airootfs/etc/os-release \
    iso/airootfs/etc/greetd/config.toml \
    iso/airootfs/etc/mkinitcpio.conf.d/archiso.conf \
    iso/efiboot/loader/entries/01-maria-padilha-de-castela-linux.conf \
    iso/syslinux/syslinux.cfg \
    iso/syslinux/archiso_sys.cfg \
    iso/syslinux/archiso_sys-linux.cfg \
    iso/airootfs/etc/calamares/settings.conf \
    iso/airootfs/etc/calamares/modules/welcome.conf \
    iso/airootfs/etc/calamares/modules/notes.conf \
    iso/airootfs/etc/calamares/modules/packagechooser.conf \
    iso/airootfs/etc/calamares/modules/packages.conf \
    iso/airootfs/etc/calamares/branding/maria-padilha/branding.desc \
    iso/airootfs/usr/share/maria-padilha/cyber/manifest.json \
    iso/airootfs/usr/share/maria-padilha/cyber/src/registry.js \
    iso/airootfs/usr/share/maria-padilha/cyber/src/authorization.js \
    iso/airootfs/usr/share/maria-padilha/cyber/src/runner.js \
    iso/airootfs/usr/share/maria-padilha/cyber/src/theme.css \
    iso/airootfs/usr/share/maria-padilha/cyber/qml/CyberShell.qml \
    iso/airootfs/usr/share/maria-padilha/cyber/qml/ToolPanelFrame.qml \
    docs/policy/security-tool-groups.md \
    tests/security-groups.sh \
    tests/cyber-frontend.sh; do
    require_file "$file"
done

for executable in build.sh tests/all.sh tests/iso.sh tests/security-groups.sh tests/cyber-frontend.sh iso/profiledef.sh; do
    require_exec "$executable"
done

for script in build.sh tests/all.sh tests/iso.sh tests/security-groups.sh tests/cyber-frontend.sh iso/profiledef.sh; do
    if bash -n "$script" 2>/dev/null; then
        ok "$script syntax"
    else
        bad "$script has a bash syntax error"
    fi
done

# Read the profile exactly as mkarchiso does, but with the version override
# unset so the checked-in pin is what the test sees.
profile_dump="$(bash --noprofile --norc -c '
    set -e
    unset MARIA_PADILHA_CASTELA_VERSION
    source "$1"
    printf "%s\n" "$iso_name" "$iso_label" "$iso_version" "$install_dir" "$pacman_conf" "${bootmodes[*]}"
' _ "$root/iso/profiledef.sh")"
mapfile -t profile < <(printf '%s\n' "$profile_dump")
iso_name="${profile[0]:-}"
iso_label="${profile[1]:-}"
iso_version="${profile[2]:-}"
install_dir="${profile[3]:-}"
pacman_conf="${profile[4]:-}"
bootmodes="${profile[5]:-}"

if [[ "$iso_name" == "maria-padilha-de-castela" ]]; then ok "iso_name is maria-padilha-de-castela"; else bad "iso_name is '${iso_name}'"; fi
if [[ "$iso_label" =~ ^[A-Z0-9_]{1,32}$ ]]; then ok "iso_label is valid"; else bad "iso_label is invalid or too long: '${iso_label}'"; fi
if [[ "$install_dir" =~ ^[a-z0-9]+$ ]]; then ok "install_dir is valid"; else bad "install_dir must be lowercase alphanumeric: '${install_dir}'"; fi
if [[ "$pacman_conf" == "pacman.conf" && -s "iso/$pacman_conf" ]]; then ok "pacman_conf points at iso/pacman.conf"; else bad "pacman_conf does not point at iso/pacman.conf"; fi
if [[ "$bootmodes" == *bios.syslinux* ]]; then ok "BIOS syslinux boot mode"; else bad "bios.syslinux boot mode missing"; fi
if [[ "$bootmodes" == *uefi.systemd-boot* ]]; then ok "UEFI systemd-boot boot mode"; else bad "uefi.systemd-boot boot mode missing"; fi

version="$(tr -d '[:space:]' < iso/package-version)"
if [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([._+-][A-Za-z0-9]+)*$ ]]; then
    ok "package version pin $version"
else
    bad "iso/package-version is not a version: '$version'"
fi
if [[ "$iso_version" == "$version" ]]; then ok "iso_version follows package version"; else bad "iso_version '$iso_version' != package version '$version'"; fi
for file in iso/profiledef.sh iso/airootfs/etc/maria-padilha-release; do
    if grep -qF -- "$version" "$file"; then
        ok "$file references package version $version"
    else
        bad "$file does not reference package version $version"
    fi
done
if grep -qF -- 'package-version' build.sh; then
    ok "build.sh reads the package version pin"
else
    bad "build.sh does not read package-version"
fi

# Package selection.
mapfile -t packages < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' iso/packages.x86_64 | grep -v '^$')
has_pkg() {
    local wanted="$1" candidate
    for candidate in "${packages[@]}"; do
        [[ "$candidate" == "$wanted" ]] && return 0
    done
    return 1
}

required_packages=(
    base
    linux
    linux-firmware
    intel-ucode
    amd-ucode
    mkinitcpio-archiso
    squashfs-tools
    syslinux
    zstd
    networkmanager
    wpa_supplicant
    wireless-regdb
    iw
    pipewire
    pipewire-pulse
    pipewire-alsa
    wireplumber
    hyprland
    quickshell
    qt6-base
    qt6-declarative
    qt6-wayland
    hyprlock
    hypridle
    hyprsunset
    xdg-desktop-portal-hyprland
    polkit
    polkit-gnome
    gnome-keyring
    greetd
    greetd-tuigreet
    maria-padilha
    nmap
    wireshark-qt
    tcpdump
    sleuthkit
    testdisk
    qemu-desktop
    libvirt
    virt-manager
    edk2-ovmf
    firejail
    calamares
    archlinux-keyring
    blackarch-keyring
    blackarch-mirrorlist
)
for package in "${required_packages[@]}"; do
    if has_pkg "$package"; then
        ok "package $package"
    else
        bad "required package $package is missing"
    fi
done

for package in \
    set gophish evilginx king-phisher lazagne mimikatz modlishka responder \
    sddm base-devel gcc make cmake ninja; do
    if has_pkg "$package"; then
        bad "package $package must not be installed in the live root"
    else
        ok "package $package excluded"
    fi
done

# The denylist is a backstop; no denylisted package may be allowlisted.
if [[ -s iso/denylist.txt ]]; then
    while IFS= read -r pkg; do
        case "$pkg" in
            ''|'#'*) continue ;;
        esac
        if has_pkg "$pkg"; then
            bad "denylisted package is allowlisted: $pkg"
        fi
    done < iso/denylist.txt
    ok "allowlist checked against denylist"
else
    bad "denylist.txt missing or empty"
fi

# Pinned sources and strict signatures.
if grep -q '^\[core\]' iso/pacman.conf && grep -q '^\[extra\]' iso/pacman.conf &&
    grep -q '^\[blackarch\]' iso/pacman.conf && grep -q '^Architecture' iso/pacman.conf; then
    ok "pacman.conf has core, extra, blackarch and Architecture"
else
    bad "pacman.conf is missing core/extra/blackarch/Architecture"
fi
if grep -qE '^[[:space:]]*SigLevel[[:space:]]*=[[:space:]]*Required' iso/pacman.conf; then
    ok "pacman.conf requires repository signatures"
else
    bad "pacman.conf does not require repository signatures"
fi
if grep -qE '^[[:space:]]*SigLevel[[:space:]]*=[[:space:]]*(Never|Optional[[:space:]]+TrustAll)' iso/pacman.conf; then
    bad "pacman.conf disables signature checking"
else
    ok "pacman.conf does not disable signature checking"
fi
# shellcheck disable=SC2016
if grep -qE '^Server = https://archive\.archlinux\.org/repos/[0-9]{4}/[0-9]{2}/[0-9]{2}/\$repo/os/\$arch$' iso/pacman.conf; then
    ok "Arch repositories are pinned to a dated archive snapshot"
else
    bad "Arch repositories are not pinned to a dated archive snapshot"
fi
# shellcheck disable=SC2016
if grep -qE '^Server = https://blackarch\.org/blackarch/\$repo/os/\$arch$' iso/pacman.conf; then
    ok "BlackArch repository source is pinned"
else
    bad "BlackArch repository source is not pinned"
fi
if grep -qE '^[[:space:]]*Include[[:space:]]*=' iso/pacman.conf; then
    bad "pacman.conf relies on a host mirrorlist Include"
else
    ok "pacman.conf does not rely on a host mirrorlist"
fi
for keyring in archlinux-keyring blackarch-keyring; do
    if grep -qF -- "$keyring" iso/keys/trusted-keyrings.txt; then
        ok "keyring policy records $keyring"
    else
        bad "keyring policy does not record $keyring"
    fi
done
if grep -qF -- 'SHA-512' iso/keys/trusted-keyrings.txt && grep -qF -- '20251011-2' iso/keys/trusted-keyrings.txt; then
    ok "BlackArch keyring pin includes version and hash"
else
    bad "BlackArch keyring pin is incomplete"
fi
if grep -qE '^[A-F0-9]{40}  ' iso/keys/blackarch-fingerprints.txt; then
    ok "BlackArch public-key fingerprints are recorded"
else
    bad "BlackArch public-key fingerprints are missing"
fi

# Authorized-use boundary and private-image notice.
for file in iso/airootfs/etc/issue iso/airootfs/etc/motd; do
    for term in 'AUTHORIZED USE ONLY' 'owned' 'written permission' 'No scans run by default'; do
        if grep -qiF -- "$term" "$file"; then
            ok "$file contains '$term'"
        else
            bad "$file does not contain '$term'"
        fi
    done
done
for file in README.md build.sh iso/airootfs/etc/issue iso/airootfs/etc/motd; do
    if grep -qiE 'private|do not publish|must not be published' "$file"; then
        ok "$file states the private-release boundary"
    else
        bad "$file does not state the private-release boundary"
    fi
done

# Greeter choice is greetd + tuigreet and the enabled units are present.
if grep -qF -- '[initial_session]' iso/airootfs/etc/greetd/config.toml &&
    grep -qF -- 'tuigreet' iso/airootfs/etc/greetd/config.toml &&
    grep -qF -- 'Maria Padilha' iso/airootfs/etc/greetd/config.toml; then
    ok "greetd + tuigreet is the configured greeter"
else
    bad "greetd config is not the documented greetd + tuigreet setup"
fi
if [[ -L iso/airootfs/etc/systemd/system/graphical.target.wants/greetd.service ]] &&
    [[ "$(readlink iso/airootfs/etc/systemd/system/graphical.target.wants/greetd.service)" == *greetd.service ]]; then
    ok "greetd.service is enabled"
else
    bad "greetd.service is not enabled in graphical.target.wants"
fi
if [[ -L iso/airootfs/etc/systemd/system/multi-user.target.wants/NetworkManager.service ]]; then
    ok "NetworkManager.service is enabled"
else
    bad "NetworkManager.service is not enabled"
fi
if [[ -L iso/airootfs/etc/systemd/system/multi-user.target.wants/bluetooth.service ]]; then
    ok "bluetooth.service is enabled"
else
    bad "bluetooth.service is not enabled"
fi

# Profile boot files.
if grep -qF -- '%INSTALL_DIR%' iso/efiboot/loader/entries/01-maria-padilha-de-castela-linux.conf &&
    grep -qF -- 'archisosearchuuid=%ARCHISO_UUID%' iso/efiboot/loader/entries/01-maria-padilha-de-castela-linux.conf; then
    ok "UEFI boot entry uses archiso paths"
else
    bad "UEFI boot entry is missing archiso placeholders"
fi
if grep -qF -- 'archiso_sys.cfg' iso/syslinux/syslinux.cfg &&
    grep -qF -- 'archisosearchuuid=%ARCHISO_UUID%' iso/syslinux/archiso_sys-linux.cfg; then
    ok "BIOS syslinux entry uses archiso paths"
else
    bad "BIOS syslinux entry is incomplete"
fi
if grep -q '^HOOKS=.*archiso' iso/airootfs/etc/mkinitcpio.conf.d/archiso.conf; then
    ok "mkinitcpio archiso hook enabled"
else
    bad "mkinitcpio archiso hook missing"
fi
if grep -Eq '^iso:' Makefile && grep -qF -- './build.sh' Makefile; then
    ok "Makefile has an iso target"
else
    bad "Makefile iso target missing"
fi

# Build guard and no host/live package installation.
if grep -qF -- 'mkarchiso' build.sh &&
    grep -qF -- 'refusing to build outside an Arch container' build.sh &&
    grep -qF -- '/.dockerenv' build.sh; then
    ok "build.sh checks mkarchiso and the Arch container guard"
else
    bad "build.sh is missing the mkarchiso/container guard"
fi
guard_output="$(mktemp)"
if MARIA_PADILHA_FORCE_OUTSIDE=1 "$root/build.sh" >"$guard_output" 2>&1; then
    bad "build.sh did not refuse to run outside a container"
elif grep -qi 'refusing to build outside an Arch container' "$guard_output"; then
    ok "build.sh refuses to run outside a container"
else
    bad "build.sh refused for an unexpected reason"
    cat "$guard_output"
fi
rm -f "$guard_output"

if grep -qE '(^|[[:space:]])(sudo|pkexec|systemctl|mount|pacman)([[:space:]]|$)' build.sh; then
    bad "build.sh contains a forbidden privileged or package-install command"
else
    ok "build.sh has no privileged or package-install command"
fi
if grep -RqiE --exclude='*.service' 'pacman[[:space:]]+-(S|Sy|Syu)|pacman-key[[:space:]]+--init' iso/airootfs 2>/dev/null; then
    bad "live root contains package installation or keyring initialization"
else
    ok "live root does not install packages"
fi

# No scanner or capture is wired to start automatically in the live overlay.
# The installer packagechooser only names optional packages; it must not start
# them, so it is excluded from this reference check and covered separately by
# tests/security-groups.sh. The private cyber frontend names tools in its tab
# manifest but has no process spawner; its no-auto-run rule is covered by
# tests/cyber-frontend.sh.
if grep -RqiE --exclude='packagechooser.conf' --exclude='notes.conf' --exclude='*.service' --exclude-dir='cyber' '(^|[^[:alnum:]_])(nmap|masscan|zmap|nikto|openvas|nessus|tcpdump|tshark|dumpcap)([^[:alnum:]_]|$)' iso/airootfs 2>/dev/null; then
    bad "scanner or capture reference in airootfs overlay (no default scans)"
else
    ok "no scanner or capture reference in airootfs overlay"
fi
if find iso/airootfs -type f \( -iname '*.eml' -o -iname '*.hbs' -o -iname '*phishing*' -o -iname '*credential-harvest*' \) -print -quit | grep -q .; then
    bad "phishing or credential-template asset in the live overlay"
else
    ok "no phishing or credential-template asset in the live overlay"
fi

# Secret and credential scan over the working tree (tracked and untracked).
secret_pattern='(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----)'
secret_hits="$(mktemp)"
if grep -RInE --exclude-dir=.git --exclude-dir=out --exclude-dir=.scratch -- "$secret_pattern" . >"$secret_hits" 2>/dev/null; then
    bad "possible tracked secret or API key"
    cat "$secret_hits"
else
    ok "no obvious API key or private key"
fi
rm -f "$secret_hits"

if find . -path ./.git -prune -o -path ./out -prune -o -path ./.scratch -prune -o \
    -type f \( -name '.env' -o -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \) -print -quit | grep -q .; then
    bad "a credential or environment file is present in the tree"
else
    ok "no .env or private credential file"
fi

# No public release metadata or uploaded artifact in this repository.
if git ls-files -- '*.iso' '*.img' '*.pkg.tar.zst' '*.sha256' '*.sig' | grep -q .; then
    bad "tracked ISO/image/checksum/signature artifact"
else
    ok "no tracked ISO/image/checksum/signature artifact"
fi
release_paths=(README.md build.sh Makefile iso .github)
if grep -RInE -I -- 'https://github\.com/[^[:space:]]+/releases|releases/download|gh release create|softprops/action-gh-release|upload-release-asset|actions/deploy-pages|gh-pages|generate_release_notes' "${release_paths[@]}" >/dev/null 2>&1; then
    bad "public release metadata or release automation found"
else
    ok "no public release metadata or release automation"
fi

exit "$fail"
