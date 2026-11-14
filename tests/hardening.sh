#!/usr/bin/env bash
# Static hardening checks for the private Maria Padilha de Castela image.
#
# The checks need no root, nftables, systemd, network, or package manager. They
# verify the shipped defaults: default-deny inbound firewall, minimal service
# enablement, no telemetry, no automatic offensive tooling, sandboxing
# documentation, secret/history controls, and the capture wipe workflow.
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

require_text() {
    local file=$1 pattern=$2
    if [[ ! -s "$file" ]]; then
        bad "$file missing or empty (wanted: $pattern)"
    elif grep -qiE -- "$pattern" "$file"; then
        ok "$file contains $pattern"
    else
        bad "$file does not contain $pattern"
    fi
}

unit_dir="iso/airootfs/etc/systemd/system"
fw="iso/airootfs/etc/nftables.conf"
nm_conf="iso/airootfs/etc/NetworkManager/conf.d/10-maria-private.conf"
journald_conf="iso/airootfs/etc/systemd/journald.conf.d/10-maria-private.conf"
coredump_conf="iso/airootfs/etc/systemd/coredump.conf.d/10-maria-private.conf"
profile_script="iso/airootfs/etc/profile.d/10-maria-private.sh"
wipe_script="iso/airootfs/usr/local/bin/maria-wipe-captures"
history_script="iso/airootfs/usr/local/bin/maria-clear-history"

for file in \
    "$fw" \
    "$nm_conf" \
    "$journald_conf" \
    "$coredump_conf" \
    "$profile_script" \
    iso/airootfs/home/maria/.bashrc \
    iso/airootfs/home/maria/.bash_profile \
    iso/airootfs/home/maria/Captures/README.md \
    "$wipe_script" \
    "$history_script" \
    docs/policy/network-hardening.md \
    docs/policy/sandboxing.md \
    docs/policy/data-handling.md \
    iso/airootfs/usr/share/doc/maria-padilha/network-hardening.md \
    iso/airootfs/usr/share/doc/maria-padilha/sandboxing.md \
    iso/airootfs/usr/share/doc/maria-padilha/data-handling.md; do
    require_file "$file"
done

require_exec "$wipe_script"
require_exec "$history_script"

for script in "$wipe_script" "$history_script" "$profile_script"; do
    if bash -n "$script" 2>/dev/null; then
        ok "$script syntax"
    else
        bad "$script has a bash syntax error"
    fi
done

# ---------------------------------------------------------------------------
# Default-deny inbound firewall.
# ---------------------------------------------------------------------------

require_text "$fw" 'table inet filter'
require_text "$fw" 'hook input'
require_text "$fw" 'hook forward'
require_text "$fw" 'hook output'

input_block="$(awk '
    /chain input[[:space:]]*\{/ { in_block = 1 }
    in_block { print }
    in_block && /^[[:space:]]*\}/ { exit }
' "$fw")"
forward_block="$(awk '
    /chain forward[[:space:]]*\{/ { in_block = 1 }
    in_block { print }
    in_block && /^[[:space:]]*\}/ { exit }
' "$fw")"

if grep -qE 'policy[[:space:]]+drop' <<<"$input_block"; then
    ok "input chain default policy is drop"
else
    bad "input chain default policy is not drop"
fi
if grep -qE 'policy[[:space:]]+accept' <<<"$input_block"; then
    bad "input chain has an accept default policy"
else
    ok "input chain has no accept default policy"
fi
if grep -qE 'policy[[:space:]]+drop' <<<"$forward_block"; then
    ok "forward chain default policy is drop"
else
    bad "forward chain default policy is not drop"
fi
if grep -qE 'iifname[[:space:]]+"lo"[[:space:]]+accept' <<<"$input_block"; then
    ok "loopback is explicitly accepted"
else
    bad "loopback is not explicitly accepted"
fi
if grep -qE 'ct[[:space:]]+state[[:space:]]+established,related[[:space:]]+accept' <<<"$input_block"; then
    ok "established/related replies are accepted"
else
    bad "established/related replies are not accepted"
fi
if grep -qE 'tcp[[:space:]]+dport[^;]*accept' <<<"$input_block"; then
    bad "input chain accepts a TCP port by default"
else
    ok "input chain accepts no TCP port by default"
fi
if grep -qE 'dnat|redirect|masquerade' "$fw"; then
    bad "firewall configures NAT/redirection by default"
else
    ok "firewall configures no NAT/redirection by default"
fi
if grep -qxF -- 'nftables' iso/packages.x86_64; then
    ok "nftables package is allowlisted"
else
    bad "nftables package is missing from the allowlist"
fi
if [[ -L "$unit_dir/multi-user.target.wants/nftables.service" ]] &&
    [[ "$(readlink "$unit_dir/multi-user.target.wants/nftables.service")" == *nftables.service ]]; then
    ok "nftables.service is enabled at boot"
else
    bad "nftables.service is not enabled at boot"
fi

# ---------------------------------------------------------------------------
# Minimal service enablement: exactly the three expected units.
# ---------------------------------------------------------------------------

mapfile -t enabled_units < <(
    find "$unit_dir" -type l -path '*.wants/*' -printf '%P\n' | LC_ALL=C sort
)
expected_units=(
    "graphical.target.wants/greetd.service"
    "multi-user.target.wants/NetworkManager.service"
    "multi-user.target.wants/nftables.service"
)
if [[ "${enabled_units[*]}" == "${expected_units[*]}" ]]; then
    ok "enabled units are exactly greetd, NetworkManager, and nftables"
else
    bad "unexpected enabled units: ${enabled_units[*]}"
fi

for unit in "${enabled_units[@]}"; do
    case "$unit" in
        *NetworkManager.service|*greetd.service|*nftables.service) ;;
        *) bad "unexpected enabled unit: $unit" ;;
    esac
done

check_mask() {
    local unit=$1
    if [[ -L "$unit_dir/$unit" ]] && [[ "$(readlink "$unit_dir/$unit")" == "/dev/null" ]]; then
        ok "$unit is masked"
    else
        bad "$unit is not masked"
    fi
}
for unit in \
    bluetooth.service dbus-org.bluez.service \
    sshd.service sshd.socket \
    libvirtd.service libvirtd.socket \
    virtqemud.service virtqemud.socket \
    docker.service podman.socket \
    avahi-daemon.service avahi-daemon.socket \
    cups.service cups.socket \
    rpcbind.service rpcbind.socket; do
    check_mask "$unit"
done

if find "$unit_dir" -type l -path '*.wants/*' \( -name '*.socket' -o -name '*.timer' -o -name '*.path' \) -print -quit | grep -q .; then
    bad "a socket, timer, or path unit is enabled at boot"
else
    ok "no socket, timer, or path unit is enabled at boot"
fi
if find iso/airootfs -type f \( -name '*.timer' -o -name '*.socket' -o -name '*.path' \) -print -quit | grep -q .; then
    bad "a timer, socket, or path unit file is shipped in the live overlay"
else
    ok "no timer, socket, or path unit file is shipped in the live overlay"
fi

# ---------------------------------------------------------------------------
# No telemetry.
# ---------------------------------------------------------------------------

if grep -qE '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*false' "$nm_conf"; then
    ok "NetworkManager connectivity checking is disabled"
else
    bad "NetworkManager connectivity checking is not disabled"
fi
if grep -qE '^[[:space:]]*uri[[:space:]]*=' "$nm_conf"; then
    bad "NetworkManager connectivity config contains a probe URI"
else
    ok "NetworkManager connectivity config contains no probe URI"
fi
if grep -qE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*volatile' "$journald_conf"; then
    ok "journald uses volatile storage"
else
    bad "journald is not configured for volatile storage"
fi
if grep -qE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*persistent' "$journald_conf"; then
    bad "journald is configured for persistent storage"
else
    ok "journald is not configured for persistent storage"
fi
if grep -qE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none' "$coredump_conf"; then
    ok "coredump storage is disabled"
else
    bad "coredump storage is not disabled"
fi

for pkg in \
    whoopsie apport popularity-contest ubuntu-report kuserfeedback \
    telegraf filebeat metricbeat auditbeat datadog-agent newrelic-infra \
    splunkforwarder; do
    if grep -qxF -- "$pkg" iso/packages.x86_64; then
        bad "telemetry package is allowlisted: $pkg"
    fi
done
ok "no known telemetry package is allowlisted"

if grep -RqiE --exclude='*.md' --exclude-dir=cyber \
    'google-analytics|sentry\.io|segment\.io|telemetry|analytics' \
    iso/airootfs/etc 2>/dev/null; then
    bad "telemetry endpoint or reference in /etc"
else
    ok "no telemetry endpoint or reference in /etc"
fi

# ---------------------------------------------------------------------------
# No automatic offensive tooling.
# ---------------------------------------------------------------------------

offensive='(^|[^[:alnum:]_])(nmap|masscan|zmap|nikto|openvas|nessus|tshark|tcpdump|dumpcap|setoolkit|responder|gophish|evilginx|mimikatz|lazagne)([^[:alnum:]_]|$)'
while IFS= read -r -d '' file; do
    if grep -qiE -- "$offensive" "$file"; then
        bad "offensive tool reference in a boot unit: $file"
    fi
done < <(find "$unit_dir" -type f -print0)
ok "no boot unit starts an offensive tool"

if [[ -d iso/airootfs/etc/xdg/autostart ]]; then
    while IFS= read -r -d '' file; do
        if grep -qiE -- "$offensive" "$file"; then
            bad "offensive tool reference in an autostart file: $file"
        fi
    done < <(find iso/airootfs/etc/xdg/autostart -type f -print0)
fi
ok "no desktop autostart starts an offensive tool"

if find iso/airootfs -type f \( -path '*/cron.d/*' -o -path '*/cron.daily/*' -o -path '*/cron.hourly/*' -o -path '*/cron.weekly/*' \) -print -quit | grep -q .; then
    bad "a cron job is shipped in the live overlay"
else
    ok "no cron job is shipped in the live overlay"
fi
if find iso/airootfs -type f -name '*.desktop' -print -quit | grep -q .; then
    bad "a desktop autostart entry is shipped in the live overlay"
else
    ok "no desktop autostart entry is shipped in the live overlay"
fi
if grep -qF -- '"autoRun": false' iso/airootfs/usr/share/maria-padilha/cyber/manifest.json &&
    ! grep -qF -- '"autoRun": true' iso/airootfs/usr/share/maria-padilha/cyber/manifest.json; then
    ok "cyber frontend declares no auto-run tabs"
else
    bad "cyber frontend has an auto-run tab or no autoRun declaration"
fi

# ---------------------------------------------------------------------------
# Secrets, shell history, and captured-data workflow.
# ---------------------------------------------------------------------------

require_text "$profile_script" 'HISTCONTROL=ignoreboth'
require_text "$profile_script" 'HISTIGNORE='
require_text "$profile_script" 'umask 077'
require_text iso/airootfs/home/maria/.bashrc 'HISTCONTROL=ignoreboth'
require_text iso/airootfs/home/maria/.bashrc 'MARIA_NO_HISTORY'
require_text "$wipe_script" '--yes'
require_text "$wipe_script" '--all'
require_text "$wipe_script" 'shred'
require_text "$wipe_script" 'realpath'
require_text "$wipe_script" '-type f'
require_text "$history_script" '--yes'
require_text "$history_script" 'history -c'
require_text "$history_script" 'HISTFILE'
require_text docs/policy/data-handling.md 'Storage=volatile'
require_text docs/policy/data-handling.md 'journald'
require_text docs/policy/data-handling.md 'shred'
require_text docs/policy/data-handling.md 'SSD'
require_text docs/policy/data-handling.md 'history -c'

for file in "$wipe_script" "$history_script"; do
    if grep -nE '^[[:space:]]*(sudo|pkexec|systemctl|mount|pacman)([[:space:]]|$)' "$file"; then
        bad "$file invokes a privileged or package command"
    else
        ok "$file does not invoke a privileged or package command"
    fi
done

# Shadow must not contain a crypt-style password hash. The live accounts are
# locked or passwordless only for the ephemeral live session.
if awk -F: '$2 ~ /^\$/ { found = 1 } END { exit found ? 0 : 1 }' iso/airootfs/etc/shadow; then
    bad "shadow contains a stored password hash"
else
    ok "shadow contains no stored password hash"
fi
if awk -F: '$1 == "root" && $2 == "!" { found = 1 } END { exit found ? 0 : 1 }' iso/airootfs/etc/shadow; then
    ok "root account is locked in shadow"
else
    bad "root account is not locked in shadow"
fi
if awk -F: '$1 == "maria" && ($2 == "" || $2 == "!" || $2 == "*") { found = 1 } END { exit found ? 0 : 1 }' iso/airootfs/etc/shadow; then
    ok "live user has no stored password hash"
else
    bad "live user has a stored password hash"
fi

if find . -path ./.git -prune -o -path ./out -prune -o -path ./.scratch -prune -o \
    -type f \( \
        -name 'authorized_keys' -o -name '.netrc' -o -name '.pgpass' \
        -o -name '.git-credentials' -o -name 'id_rsa' -o -name 'id_ed25519' \
        -o -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \
        -o -name '*.kdbx' -o -name '.bash_history' -o -name '.zsh_history' \
    \) -print -quit | grep -q .; then
    bad "a credential, key, or shell-history file is present in the tree"
else
    ok "no credential, key, or shell-history file is present in the tree"
fi

if find . -path ./.git -prune -o -path ./out -prune -o -path ./.scratch -prune -o \
    -type f \( -name '.env' -o -name '.env.*' \) -print -quit | grep -q .; then
    bad "an environment file is present in the tree"
else
    ok "no environment file is present in the tree"
fi

# The secret pattern is written as a regex so the test itself is not a key.
secret_pattern='(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----)'
secret_hits="$(mktemp)"
if grep -RInE --exclude-dir=.git --exclude-dir=out --exclude-dir=.scratch -- \
    "$secret_pattern" iso frontend docs tests build README.md build.sh Makefile .github \
    >"$secret_hits" 2>/dev/null; then
    bad "possible tracked secret or private key"
    cat "$secret_hits"
else
    ok "no obvious API key or private key"
fi
rm -f "$secret_hits"

# ---------------------------------------------------------------------------
# Sandboxing decision and limits.
# ---------------------------------------------------------------------------

require_text docs/policy/sandboxing.md 'AppArmor'
require_text docs/policy/sandboxing.md 'Firejail'
require_text docs/policy/sandboxing.md 'CAP_NET_RAW'
require_text docs/policy/sandboxing.md 'limits'
require_text docs/policy/sandboxing.md 'not a kernel'
if grep -qxF -- 'firejail' iso/packages.x86_64; then
    ok "firejail is in the package allowlist"
else
    bad "firejail is missing from the package allowlist"
fi
if [[ -e "$unit_dir/multi-user.target.wants/apparmor.service" ]]; then
    bad "apparmor.service is enabled without a reviewed profile set"
else
    ok "apparmor.service is not enabled without a reviewed profile set"
fi

# The image carries the same operator documentation as the repository.
for doc in network-hardening sandboxing data-handling; do
    if cmp -s "docs/policy/$doc.md" "iso/airootfs/usr/share/doc/maria-padilha/$doc.md"; then
        ok "$doc.md is mirrored into the image"
    else
        bad "$doc.md differs from the image documentation copy"
    fi
done

exit "$fail"
