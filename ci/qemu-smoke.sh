#!/usr/bin/env bash
# Boot the private ISO headlessly over a serial console and look for the
# authorized-use banner. This is a smoke test, not a full desktop test.
#
# The image must have a matching SHA256SUMS entry before QEMU is started. QEMU
# runs with no network device and no monitor; the only output is the serial log.
set -Eeuo pipefail

script_name="${0##*/}"
root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
image=""
checksums=""
log_path=""
timeout_seconds="${MARIA_PADILHA_SMOKE_TIMEOUT:-900}"
qemu="${MARIA_PADILHA_QEMU:-qemu-system-x86_64}"
dry_run=0

log() { printf '[smoke] %s\n' "$*" >&2; }
die() { printf '[smoke] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: $script_name IMAGE [--checksums SHA256SUMS] [--log PATH] [--timeout SECONDS] [--dry-run]

Boot IMAGE with QEMU, without a display or network, and pass the console to a
serial log. Success means the live image reached its authorized-use login
banner. IMAGE must match SHA256SUMS before boot.

  --checksums PATH  checksum file (default: SHA256SUMS next to IMAGE)
  --log PATH        serial log (default: qemu-serial.log next to IMAGE)
  --timeout SECONDS maximum boot time (default: 900)
  --dry-run         validate inputs and print the QEMU command; do not boot
  -h, --help        show this help
EOF
}

while (($#)); do
    case "$1" in
        --checksums)
            (($# >= 2)) || die "--checksums needs a path"
            checksums="$2"
            shift 2
            ;;
        --log)
            (($# >= 2)) || die "--log needs a path"
            log_path="$2"
            shift 2
            ;;
        --timeout)
            (($# >= 2)) || die "--timeout needs seconds"
            timeout_seconds="$2"
            shift 2
            ;;
        --dry-run)
            dry_run=1
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
        -*)
            die "unknown option: $1 (try --help)"
            ;;
        *)
            [[ -z "$image" ]] || die "only one image may be given"
            image="$1"
            shift
            ;;
    esac
done
(($# == 0)) || die "unexpected argument: $1"

[[ -n "$image" ]] || { usage >&2; exit 2; }
[[ -f "$image" ]] || die "image not found: $image"
[[ -s "$image" ]] || die "image is empty: $image"
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || die "invalid timeout: $timeout_seconds"

image_dir="$(CDPATH='' cd -- "$(dirname -- "$image")" && pwd)"
image="$(CDPATH='' cd -- "$image_dir" && pwd)/$(basename -- "$image")"
[[ -n "$checksums" ]] || checksums="$image_dir/SHA256SUMS"
[[ -n "$log_path" ]] || log_path="$image_dir/qemu-serial.log"

[[ -r "$checksums" ]] ||
    die "checksum file not found: $checksums (refusing to boot an unverified image)"

# Verify before doing anything else. A missing or mismatched checksum is a hard
# failure; there is no unsigned-boot override.
bash "$root/ci/verify-checksums.sh" "$checksums" "$image_dir"
log "checksum verified: $image"

log_dir="$(dirname -- "$log_path")"
mkdir -p -- "$log_dir"

qemu_args=(
    -name "maria-padilha-private-ci"
    -machine q35
    -m 3072
    -smp 2
    -no-reboot
    -display none
    -serial "file:$log_path"
    -monitor none
    -net none
    -cdrom "$image"
    -boot d
)

if ((dry_run == 1)); then
    printf '%q ' "$qemu" "${qemu_args[@]}"
    printf '\n'
    exit 0
fi

command -v "$qemu" >/dev/null 2>&1 || die "QEMU binary not found: $qemu"
[[ ! -e "$log_path" || -w "$log_path" ]] || die "serial log is not writable: $log_path"
: >"$log_path"

qemu_pid=""
cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

log "starting QEMU serial smoke boot (timeout ${timeout_seconds}s, no network)"
"$qemu" "${qemu_args[@]}" >/dev/null 2>&1 &
qemu_pid=$!

deadline=$(( $(date +%s) + timeout_seconds ))
success=0
failure=""
while kill -0 "$qemu_pid" 2>/dev/null; do
    if grep -qF -- 'AUTHORIZED USE ONLY' "$log_path" 2>/dev/null; then
        success=1
        break
    fi
    if grep -qiE -- 'kernel panic|end kernel panic|not syncing' "$log_path" 2>/dev/null; then
        failure="kernel panic"
        break
    fi
    if (( $(date +%s) >= deadline )); then
        failure="timed out after ${timeout_seconds}s"
        break
    fi
    sleep 2
done

# QEMU can exit immediately after writing the final banner line. Recheck once
# before declaring failure.
if ((success == 0)) && grep -qF -- 'AUTHORIZED USE ONLY' "$log_path" 2>/dev/null; then
    success=1
fi

cleanup
qemu_pid=""

if ((success == 1)); then
    log "serial boot reached the authorized-use login banner"
    log "serial log: $log_path"
    exit 0
fi

log "boot did not reach the authorized-use banner: ${failure:-QEMU exited before the marker}"
tail -n 120 "$log_path" >&2 || true
exit 1
