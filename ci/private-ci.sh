#!/usr/bin/env bash
# Private CI entry point. Run as root inside a disposable Arch container.
#
# It builds the ISO with build.sh, records SHA256SUMS, boots the image over a
# serial console in QEMU, and re-verifies the checksum. The workflow uploads the
# resulting files only through repository-scoped GitHub Actions artifacts.
set -Eeuo pipefail

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

out="${MARIA_PADILHA_OUT:-$root/out}"
export MARIA_PADILHA_OUT="$out"

log() { printf '[private-ci] %s\n' "$*" >&2; }
die() { printf '[private-ci] ERROR: %s\n' "$*" >&2; exit 1; }

mkdir -p -- "$out"

# A stale image from an earlier local run must never be mistaken for this build.
rm -f -- "$out"/maria-padilha-de-castela-*.iso \
    "$out/SHA256SUMS" \
    "$out/qemu-serial.log" \
    "$out/build-metadata.txt"

log "building the private ISO with build.sh"
./build.sh

shopt -s nullglob
images=("$out"/maria-padilha-de-castela-*.iso)
shopt -u nullglob
((${#images[@]} == 1)) ||
    die "expected exactly one built ISO in $out, found ${#images[@]}"
image="${images[0]}"
[[ -s "$image" ]] || die "built ISO is empty: $image"

log "recording SHA256SUMS"
bash ci/record-checksums.sh "$image" "$out/SHA256SUMS"
bash ci/verify-checksums.sh "$out/SHA256SUMS" "$out"

{
    printf 'schema=1\n'
    printf 'repository=%s\n' "${GITHUB_REPOSITORY:-$(git config --get remote.origin.url 2>/dev/null || printf 'unknown')}"
    printf 'commit=%s\n' "${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || printf 'unknown')}"
    printf 'ref=%s\n' "${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || printf 'unknown')}"
    printf 'run_id=%s\n' "${GITHUB_RUN_ID:-local}"
    printf 'built_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'iso=%s\n' "$(basename -- "$image")"
    printf 'iso_bytes=%s\n' "$(stat -c %s -- "$image")"
    printf 'sha256=%s\n' "$(awk '{ print $1 }' "$out/SHA256SUMS")"
} >"$out/build-metadata.txt"
chmod 0644 -- "$out/build-metadata.txt"

log "booting the private ISO over a serial console"
bash ci/qemu-smoke.sh "$image" --checksums "$out/SHA256SUMS" --log "$out/qemu-serial.log"

log "re-verifying the artifact after the smoke boot"
bash ci/verify-checksums.sh "$out/SHA256SUMS" "$out"

chmod 0755 -- "$out"
chmod 0644 -- "$out/SHA256SUMS" "$out/qemu-serial.log" "$out/build-metadata.txt" "$image"
log "private CI artifacts ready in $out"
