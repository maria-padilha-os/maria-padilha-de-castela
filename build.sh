#!/usr/bin/env bash
# Build the private Maria Padilha de Castela archiso image.
#
# This script only runs inside an Arch Linux container. It refuses to run on a
# host, does not install anything on the host, and does not modify the live
# system. mkarchiso/pacstrap need root and loop-device/chroot privileges inside that
# disposable container.
#
# The desktop shell package (maria-padilha) is built outside this repository.
# Pass a built package with --desktop-package; build.sh publishes it into a
# scratch-local package repository for the ISO build and never copies it into
# this checkout.
set -Eeuo pipefail

script_name="${0##*/}"
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
profile_src="$root/iso"
out_dir="${MARIA_PADILHA_OUT:-$root/out}"
work_root="${MARIA_PADILHA_WORK:-$root/.scratch/iso-build}"
desktop_package="${MARIA_PADILHA_DESKTOP_PACKAGE:-}"
keep_work=0
check_only=0

log() { printf '[build] %s\n' "$*" >&2; }
warn() { printf '[build] WARNING: %s\n' "$*" >&2; }
die() { printf '[build] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: $script_name [options]

Build the private Maria Padilha de Castela ISO from the archiso profile in
iso/. Run this as root inside an Arch Linux container.

options:
  --desktop-package PATH  built maria-padilha package for the local repo
  --check                 validate the profile and prerequisites, do not build
  --keep-work             keep .scratch/iso-build after a successful build
  -h, --help              show this help

Environment:
  MARIA_PADILHA_DESKTOP_PACKAGE  same as --desktop-package
  MARIA_PADILHA_OUT              output directory (default: ./out)
  MARIA_PADILHA_WORK             scratch directory (default: ./.scratch/iso-build)

The output is a private artifact. Do not publish, upload, mirror, or
redistribute it. Nothing is installed on the host and no repository package is
installed into the running live system by this script.
EOF
}

parse_args() {
    while (($#)); do
        case "$1" in
            --desktop-package)
                (($# >= 2)) || die "--desktop-package needs a path"
                desktop_package="$2"
                shift 2
                ;;
            --check)
                check_only=1
                shift
                ;;
            --keep-work)
                keep_work=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            *)
                die "unknown argument: $1 (try --help)"
                ;;
        esac
    done
    (($# == 0)) || die "unexpected argument: $1"
}

require_arch_container() {
    if [[ "${MARIA_PADILHA_FORCE_OUTSIDE:-0}" == "1" ]]; then
        die "refusing to build outside an Arch container (forced by MARIA_PADILHA_FORCE_OUTSIDE)"
    fi

    local os_id="" os_like=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        os_id="$(. /etc/os-release && printf '%s' "${ID:-}")"
        # shellcheck disable=SC1091
        os_like="$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")"
    fi

    if [[ "$os_id" != "arch" ]]; then
        die "refusing to build outside an Arch container (detected ID='${os_id:-unknown}', ID_LIKE='${os_like:-unknown}'); use docker/podman with archlinux:latest"
    fi
    [[ -e /etc/arch-release ]] || die "refusing to build: /etc/arch-release is missing; use an Arch container"

    local in_container=0 virt=""
    [[ -e /.dockerenv ]] && in_container=1
    [[ -e /run/.containerenv ]] && in_container=1
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt="$(systemd-detect-virt --container 2>/dev/null || true)"
        if [[ -n "$virt" && "$virt" != "none" ]]; then
            in_container=1
        fi
    fi
    ((in_container == 1)) || die "refusing to build outside an Arch container: no container marker found (/.dockerenv, /run/.containerenv or systemd-detect-virt)"
}

require_root() {
    if ((EUID != 0)); then
        die "run as root inside the Arch container (mkarchiso/pacstrap need loop devices and chroot)"
    fi
}

check_commands() {
    local -a missing=()
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if ((${#missing[@]})); then
        die "missing prerequisites: ${missing[*]}; install them in the Arch container, never on the host or in the live root"
    fi
}

verify_profile() {
    local file
    for file in \
        profiledef.sh \
        packages.x86_64 \
        pacman.conf \
        denylist.txt \
        package-version \
        keys/trusted-keyrings.txt \
        airootfs/etc/issue \
        airootfs/etc/motd \
        airootfs/etc/nftables.conf \
        airootfs/etc/NetworkManager/conf.d/10-maria-private.conf \
        airootfs/etc/profile.d/10-maria-private.sh \
        airootfs/etc/systemd/journald.conf.d/10-maria-private.conf \
        airootfs/etc/systemd/coredump.conf.d/10-maria-private.conf \
        airootfs/home/maria/.bashrc \
        airootfs/home/maria/.bash_profile \
        airootfs/home/maria/Captures/README.md \
        airootfs/usr/local/bin/maria-wipe-captures \
        airootfs/usr/local/bin/maria-clear-history \
        airootfs/usr/share/doc/maria-padilha/data-handling.md \
        airootfs/usr/share/doc/maria-padilha/network-hardening.md \
        airootfs/usr/share/doc/maria-padilha/sandboxing.md \
        airootfs/etc/mkinitcpio.conf.d/archiso.conf \
        airootfs/etc/calamares/settings.conf \
        airootfs/etc/calamares/modules/packagechooser.conf \
        airootfs/etc/calamares/modules/packages.conf \
        airootfs/usr/share/maria-padilha/cyber/manifest.json \
        airootfs/usr/share/maria-padilha/cyber/src/registry.js \
        airootfs/usr/share/maria-padilha/cyber/src/authorization.js \
        airootfs/usr/share/maria-padilha/cyber/src/runner.js \
        airootfs/usr/share/maria-padilha/cyber/src/nmap.js \
        airootfs/usr/share/maria-padilha/cyber/src/set.js \
        airootfs/usr/share/maria-padilha/cyber/src/forensics.js \
        airootfs/usr/share/maria-padilha/cyber/src/lab.js \
        airootfs/usr/share/maria-padilha/cyber/src/theme.css \
        airootfs/usr/share/maria-padilha/cyber/qml/CyberShell.qml \
        airootfs/usr/share/maria-padilha/cyber/qml/ToolPanelFrame.qml \
        airootfs/usr/share/maria-padilha/cyber/qml/NmapPanel.qml \
        airootfs/usr/share/maria-padilha/cyber/qml/SetPanel.qml \
        airootfs/usr/share/maria-padilha/cyber/qml/ForensicsPanel.qml \
        airootfs/usr/share/maria-padilha/cyber/qml/LabPanel.qml \
        efiboot/loader/loader.conf \
        efiboot/loader/entries/01-maria-padilha-de-castela-linux.conf \
        syslinux/syslinux.cfg
    do
        [[ -s "$profile_src/$file" ]] || die "profile file missing or empty: iso/$file"
    done

    local cyber_manifest="$profile_src/airootfs/usr/share/maria-padilha/cyber/manifest.json"
    grep -qF -- '"privateBuild": true' "$cyber_manifest" ||
        die "cyber frontend manifest is not private-build only"
    grep -qF -- 'MARIA_PADILHA_CYBER_FRONTEND' "$cyber_manifest" ||
        die "cyber frontend manifest is missing the feature flag"
    grep -qF -- '"autoRun": false' "$cyber_manifest" ||
        die "cyber frontend manifest declares no autoRun: false tabs"
    if grep -qF -- '"autoRun": true' "$cyber_manifest"; then
        die "cyber frontend manifest contains an auto-run tab"
    fi
    grep -qF -- '"hostBridgeDefault": false' "$cyber_manifest" ||
        die "cyber lab manifest does not disable host bridges by default"
    grep -qF -- '"isolatedNetworkDefault": true' "$cyber_manifest" ||
        die "cyber lab manifest does not default to the isolated network"
    grep -qF -- '"hostLanAttachment": "explicit-warning-and-confirmation"' "$cyber_manifest" ||
        die "cyber lab manifest is missing the host-LAN warning gate"

    if ! grep -qE '^[[:space:]]*SigLevel[[:space:]]*=[[:space:]]*Required' "$profile_src/pacman.conf"; then
        die "iso/pacman.conf does not require repository signatures"
    fi
    if grep -qE '^[[:space:]]*SigLevel[[:space:]]*=[[:space:]]*(Never|Optional[[:space:]]+TrustAll)' "$profile_src/pacman.conf"; then
        die "iso/pacman.conf disables signature checking"
    fi
    grep -q '^\[blackarch\]$' "$profile_src/pacman.conf" ||
        die "iso/pacman.conf is missing the [blackarch] repository"

    local pkg
    while IFS= read -r pkg; do
        case "$pkg" in
            ''|'#'*) continue ;;
        esac
        if grep -qxF -- "$pkg" "$profile_src/packages.x86_64"; then
            die "denylisted package is allowlisted: $pkg"
        fi
    done <"$profile_src/denylist.txt"

    grep -qxF -- 'nftables' "$profile_src/packages.x86_64" ||
        die "nftables is missing from the package allowlist"
    grep -qE 'hook input[^;]*;[[:space:]]*policy drop' \
        "$profile_src/airootfs/etc/nftables.conf" ||
        die "nftables input policy is not default-deny"
    if grep -qE 'hook input[^;]*;[[:space:]]*policy accept' \
        "$profile_src/airootfs/etc/nftables.conf"; then
        die "nftables input policy accepts by default"
    fi
    [[ "$(readlink "$profile_src/airootfs/etc/systemd/system/multi-user.target.wants/nftables.service" 2>/dev/null || true)" == *nftables.service ]] ||
        die "nftables.service is not enabled at boot"
    if [[ -e "$profile_src/airootfs/etc/systemd/system/multi-user.target.wants/bluetooth.service" ]]; then
        die "bluetooth.service is enabled at boot"
    fi
    [[ "$(readlink "$profile_src/airootfs/etc/systemd/system/bluetooth.service" 2>/dev/null || true)" == "/dev/null" ]] ||
        die "bluetooth.service is not masked"
    [[ "$(readlink "$profile_src/airootfs/etc/systemd/system/dbus-org.bluez.service" 2>/dev/null || true)" == "/dev/null" ]] ||
        die "the BlueZ D-Bus activation alias is not masked"
    [[ "$(readlink "$profile_src/airootfs/etc/systemd/system/sshd.service" 2>/dev/null || true)" == "/dev/null" ]] ||
        die "sshd.service is not masked"
    grep -qE '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*false' \
        "$profile_src/airootfs/etc/NetworkManager/conf.d/10-maria-private.conf" ||
        die "NetworkManager connectivity checking is not disabled"
    grep -qE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*volatile' \
        "$profile_src/airootfs/etc/systemd/journald.conf.d/10-maria-private.conf" ||
        die "journald is not configured for volatile storage"
    grep -qE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none' \
        "$profile_src/airootfs/etc/systemd/coredump.conf.d/10-maria-private.conf" ||
        die "coredump storage is not disabled"
    [[ -x "$profile_src/airootfs/usr/local/bin/maria-wipe-captures" ]] ||
        die "capture wipe workflow is not executable"
    [[ -x "$profile_src/airootfs/usr/local/bin/maria-clear-history" ]] ||
        die "history clear workflow is not executable"
}

stage_desktop_package() {
    if [[ -z "$desktop_package" ]]; then
        warn "no --desktop-package supplied; the working profile will fall back to the core Hyprland/Quickshell desktop without the maria-padilha session package"
        return 0
    fi

    [[ -f "$desktop_package" ]] || die "desktop package not found: $desktop_package"
    desktop_package="$(realpath -- "$desktop_package")"
    check_commands repo-add

    local repo_dir="$work_root/repo"
    rm -rf "$repo_dir"
    install -d -m 0755 "$repo_dir"
    cp -f "$desktop_package" "$repo_dir/"
    repo-add "$repo_dir/maria-padilha.db.tar.gz" "$repo_dir/$(basename -- "$desktop_package")" >/dev/null ||
        die "repo-add failed for $desktop_package"
    log "scratch package repository: $repo_dir"
}

prepare_profile() {
    local profile_work="$work_root/profile" repo_url
    rm -rf "$profile_work"
    cp -a "$profile_src" "$profile_work"

    if [[ -n "$desktop_package" ]]; then
        repo_url="$(printf '%s' "$work_root/repo" | sed 's/ /%20/g')"
        cat >>"$profile_work/pacman.conf" <<EOF

[maria-padilha]
SigLevel = Required DatabaseOptional
Server = file://$repo_url
EOF
    elif grep -qxF -- "maria-padilha" "$profile_work/packages.x86_64"; then
        sed -i '/^maria-padilha$/d' "$profile_work/packages.x86_64"
        warn "building the core desktop fallback without the maria-padilha package"
    fi

    printf '%s\n' "$profile_work"
}

build_iso() {
    local profile_work="$1"
    local pkgver iso_file
    pkgver="$(tr -d '[:space:]' <"$profile_src/package-version")"

    install -d -m 0755 "$work_root" "$out_dir"
    log "building private ISO with mkarchiso (work: $work_root/mkarchiso)"
    mkarchiso -v \
        -w "$work_root/mkarchiso" \
        -o "$out_dir" \
        -C "$profile_work/pacman.conf" \
        "$profile_work"

    iso_file="$out_dir/maria-padilha-de-castela-$pkgver-x86_64.iso"
    [[ -f "$iso_file" ]] || die "mkarchiso finished but $iso_file is missing"
    log "private ISO ready: $iso_file"
    du -h "$iso_file" | awk '{ print "[build] size: " $1 }'
}

main() {
    parse_args "$@"
    require_arch_container
    require_root

    local -a required=(mkarchiso pacstrap arch-chroot xorriso mksquashfs mkfs.fat mmd mcopy)
    check_commands "${required[@]}"

    verify_profile
    if ((check_only == 1)); then
        log "profile and build prerequisites look valid; not building (--check)"
        exit 0
    fi

    install -d -m 0755 "$work_root" "$out_dir"
    stage_desktop_package

    local profile_work
    profile_work="$(prepare_profile)"
    build_iso "$profile_work"

    if ((keep_work == 0)); then
        rm -rf "$work_root"
    else
        log "keeping working directory: $work_root"
    fi
}

main "$@"
