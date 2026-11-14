#!/usr/bin/env bash
# Static checks for the Calamares authorized security tool groups.
#
# These checks need no root, network, package manager, Calamares installation,
# or Arch host. They validate the group definitions, mandatory core packages,
# denylist exclusions, no-secret policy, and offline-safe installer defaults.
set -euo pipefail

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail=0
ok() { printf 'ok %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; fail=1; }

conf="iso/airootfs/etc/calamares/modules/packagechooser.conf"
mirror="build/archiso/profile/airootfs/etc/calamares/modules/packagechooser.conf"
packages_conf="iso/airootfs/etc/calamares/modules/packages.conf"
mirror_packages_conf="build/archiso/profile/airootfs/etc/calamares/modules/packages.conf"
settings="iso/airootfs/etc/calamares/settings.conf"
mirror_settings="build/archiso/profile/airootfs/etc/calamares/settings.conf"
manifest="iso/packages.x86_64"
denylist="iso/denylist.txt"
doc="docs/policy/security-tool-groups.md"

for file in "$conf" "$mirror" "$packages_conf" "$mirror_packages_conf" "$settings" "$mirror_settings" "$manifest" "$denylist" "$doc"; do
    if [[ -s "$file" ]]; then ok "$file present"; else bad "$file missing or empty"; fi
done

if ! cmp -s "$conf" "$mirror"; then
    bad "packagechooser.conf differs between iso/ and build/ reference profile"
else
    ok "packagechooser.conf is mirrored in the reference profile"
fi
if ! cmp -s "$packages_conf" "$mirror_packages_conf"; then
    bad "packages.conf differs between iso/ and build/ reference profile"
else
    ok "packages.conf is mirrored in the reference profile"
fi

if grep -qF 'airootfs/etc/calamares/modules/packagechooser.conf' build.sh &&
    grep -qF 'airootfs/etc/calamares/modules/packages.conf' build.sh; then
    ok "build.sh verifies the installer group configuration"
else
    bad "build.sh does not verify the installer group configuration"
fi

# Return one item block (without the "- id:" line) for the requested group id.
item_block() {
    awk -v want="$1" '
        /^  - id:/ {
            id = $3
            gsub(/"/, "", id)
            in_item = (id == want)
            next
        }
        in_item { print }
    ' "$conf"
}

# Return the package entries for one group id.
packages_for() {
    awk -v want="$1" '
        /^  - id:/ {
            id = $3
            gsub(/"/, "", id)
            in_item = (id == want)
            in_packages = 0
            next
        }
        in_item && /^    packages:[[:space:]]*$/ { in_packages = 1; next }
        in_item && in_packages && /^      - / {
            sub(/^      - /, "")
            print
            next
        }
        in_item && in_packages && !/^[[:space:]]*$/ { in_packages = 0 }
    ' "$conf"
}

groups=(core recon web wireless forensics reversing password-auditing lab-vm)
group_names=(
    'Core (mandatory)'
    'Recon'
    'Web'
    'Wireless'
    'Forensics'
    'Reversing'
    'Password Auditing'
    'Lab/VM tools'
)

for i in "${!groups[@]}"; do
    id="${groups[$i]}"
    name="${group_names[$i]}"
    block="$(item_block "$id")"
    if [[ -z "$block" ]]; then
        bad "group $id is missing"
        continue
    fi
    ok "group $id defined"

    if grep -qF "name: \"$name\"" <<<"$block"; then
        ok "group $id name is '$name'"
    else
        bad "group $id does not have display name '$name'"
    fi
    if grep -qF 'description:' <<<"$block"; then
        ok "group $id has a description"
    else
        bad "group $id has no description"
    fi
    if grep -qiE 'authorized|written permission|owned' <<<"$block"; then
        ok "group $id carries an authorization warning"
    else
        bad "group $id has no authorization warning"
    fi
    if grep -qE '^    packages:' <<<"$block"; then
        ok "group $id has a package list"
    else
        bad "group $id has no package list"
    fi
done

# Required representative packages for each group, plus the mandatory core.
expect_pkg() {
    local group=$1 pkg=$2
    if packages_for "$group" | grep -qxF -- "$pkg"; then
        ok "group $group includes $pkg"
    else
        bad "group $group is missing $pkg"
    fi
}

for pkg in base calamares nftables nmap wireshark-qt sleuthkit qemu-desktop libvirt; do
    expect_pkg core "$pkg"
done

for pkg in nmap masscan dnsrecon amass; do expect_pkg recon "$pkg"; done
for pkg in nikto gobuster ffuf nuclei; do expect_pkg web "$pkg"; done
for pkg in aircrack-ng kismet hcxdumptool; do expect_pkg wireless "$pkg"; done
for pkg in sleuthkit ddrescue binwalk volatility3; do expect_pkg forensics "$pkg"; done
for pkg in radare2 rizin ghidra gdb; do expect_pkg reversing "$pkg"; done
for pkg in john hashcat hashcat-utils ophcrack; do expect_pkg password-auditing "$pkg"; done
for pkg in qemu-desktop libvirt virt-manager edk2-ovmf; do expect_pkg lab-vm "$pkg"; done

# The core is mandatory and must be in the live-root allowlist. Deselecting the
# core item cannot remove packages that come from the image itself.
if packages_for core >/dev/null; then
    missing_core=0
    while IFS= read -r pkg; do
        [[ -n "$pkg" ]] || continue
        if ! grep -qxF -- "$pkg" "$manifest"; then
            bad "mandatory core package is not in $manifest: $pkg"
            missing_core=1
        fi
    done < <(packages_for core)
    ((missing_core == 0)) && ok "all mandatory core packages are in $manifest"
else
    bad "core group package list is unreadable"
fi

# The core item must say it is mandatory / always installed.
core_block="$(item_block core)"
if grep -qiE 'mandatory|always installed|cannot be removed' <<<"$core_block"; then
    ok "core group is documented as mandatory"
else
    bad "core group is not documented as mandatory"
fi

# No package may come from the denylist or from the prohibited policy list.
denied_hits=0
while IFS= read -r denied; do
    case "$denied" in ''|'#'*) continue ;; esac
    for id in "${groups[@]}"; do
        if packages_for "$id" | grep -qxF -- "$denied"; then
            bad "denylisted package $denied is in group $id"
            denied_hits=1
        fi
    done
done <"$denylist"
((denied_hits == 0)) && ok "no denylisted package appears in a group"

for pkg in hydra medusa mimikatz lazagne responder gophish evilginx king-phisher modlishka set; do
    if for id in "${groups[@]}"; do packages_for "$id"; done | grep -qxF -- "$pkg"; then
        bad "prohibited package $pkg appears in a group"
    fi
done
ok "no phishing, credential-theft, or network brute-force package in a group"

# Package names must be plain package identifiers, not shell fragments, URLs,
# credential paths, or secret material.
for id in "${groups[@]}"; do
    while IFS= read -r pkg; do
        [[ -n "$pkg" ]] || continue
        if [[ ! "$pkg" =~ ^[a-z0-9][a-z0-9+._-]*$ ]]; then
            bad "group $id contains an invalid package identifier: $pkg"
        fi
    done < <(packages_for "$id")
done
ok "group package identifiers are well formed"

# Safe defaults: no preselected group, no service/scan commands, no URLs.
if grep -qE '^[[:space:]]*default:' "$conf"; then
    bad "packagechooser.conf preselects a default group"
else
    ok "packagechooser.conf has no default group"
fi
if grep -qE '^[[:space:]]*mode:[[:space:]]*optionalmultiple[[:space:]]*$' "$conf"; then
    ok "packagechooser.conf allows zero optional groups"
else
    bad "packagechooser.conf is not in optionalmultiple mode"
fi
if grep -qE '^[[:space:]]*method:[[:space:]]*packages[[:space:]]*$' "$conf"; then
    ok "packagechooser.conf uses the packages method"
else
    bad "packagechooser.conf does not use the packages method"
fi
if grep -nE 'systemctl|ExecStart|@reboot|autostart|--scan|nmap[[:space:]]+-|curl[[:space:]]|wget[[:space:]]|https?://' "$conf" "$packages_conf"; then
    bad "installer group config contains a service, scan, network, or URL directive"
else
    ok "installer group config starts no service, scan, or network request"
fi

# The packages module must be offline-safe and must not install anything
# unconditionally.
if grep -qE '^[[:space:]]*skip_if_no_internet:[[:space:]]*true[[:space:]]*$' "$packages_conf"; then
    ok "optional package installs are skipped offline"
else
    bad "packages.conf does not set skip_if_no_internet: true"
fi
if grep -qE '^[[:space:]]*operations:[[:space:]]*\[[[:space:]]*\][[:space:]]*$' "$packages_conf"; then
    ok "packages.conf has no unconditional package operations"
else
    bad "packages.conf has unconditional package operations"
fi
if grep -qE '^[[:space:]]*backend:[[:space:]]*pacman[[:space:]]*$' "$packages_conf"; then
    ok "packages.conf uses the pacman backend"
else
    bad "packages.conf does not use the pacman backend"
fi

# Sequence wiring: chooser in show, packages in exec exactly once.
for settings_file in "$settings" "$mirror_settings"; do
    show_section="$(awk '/^  - show:/{s=1} /^  - exec:/{s=0} s' "$settings_file")"
    exec_section="$(awk '/^  - exec:/{s=1} /^  - show:/{if(s) s=0} s' "$settings_file")"
    label="${settings_file#*/airootfs/etc/calamares/}"
    if grep -qxE '[[:space:]]*- packagechooser[[:space:]]*' <<<"$show_section"; then
        ok "$label has packagechooser in the show sequence"
    else
        bad "$label does not have packagechooser in the show sequence"
    fi
    if grep -qxE '[[:space:]]*- packages[[:space:]]*' <<<"$exec_section"; then
        ok "$label has packages in the exec sequence"
    else
        bad "$label does not have packages in the exec sequence"
    fi
    if grep -qxE '[[:space:]]*- packagechooser[[:space:]]*' <<<"$exec_section"; then
        bad "$label incorrectly has packagechooser in the exec sequence"
    else
        ok "$label has no packagechooser exec job"
    fi
done

# No destructive command or host-repartitioning instruction in the installer
# group files or the test itself.
if grep -nE '(^|[^[:alnum:]_])(mkfs|wipefs|sgdisk|sfdisk|parted|fdisk|shred)([^[:alnum:]_]|$)|dd[[:space:]]+if=' \
    "$conf" "$packages_conf" "$settings"; then
    bad "destructive or repartitioning command in installer group files"
else
    ok "no destructive or repartitioning command in installer group files"
fi

# No secret in the new definitions or documentation.
secret_pattern='(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----)'
if grep -nE -- "$secret_pattern" "$conf" "$packages_conf" "$doc"; then
    bad "possible secret in the security group definitions or documentation"
else
    ok "no obvious secret in the security group definitions or documentation"
fi

# Documentation must cover the authorization, redistribution, and user-install
# boundaries.
for term in \
    'AUTHORIZED USE ONLY' \
    'mandatory core' \
    'No group is selected by default' \
    'redistribut' \
    'proprietary' \
    'Burp Suite' \
    'Nessus' \
    'IDA Pro' \
    'offline' \
    'denylist'; do
    if grep -qiF -- "$term" "$doc"; then
        ok "group documentation covers '$term'"
    else
        bad "group documentation does not cover '$term'"
    fi
done

exit "$fail"
