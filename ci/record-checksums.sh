#!/usr/bin/env bash
# Record SHA-256 checksums for a built image without embedding a path.
#
# usage: record-checksums.sh IMAGE [SHA256SUMS]
#
# The output is the standard sha256sum format and contains only the basename of
# the image, so the same file can be verified from any artifact directory. The
# write is atomic when an output path is supplied.
set -Eeuo pipefail

script_name="${0##*/}"

die() { printf '[checksums] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: $script_name IMAGE [SHA256SUMS]

Write a SHA256SUMS file for IMAGE. If SHA256SUMS is omitted, write to stdout.
The checksum line uses the image basename only.
EOF
}

(($# == 1 || $# == 2)) || { usage >&2; exit 2; }

image="$1"
output="${2:-}"

[[ -f "$image" ]] || die "image not found: $image"
[[ -s "$image" ]] || die "image is empty: $image"

name="$(basename -- "$image")"
[[ "$name" != *$'\n'* && "$name" != *$'\r'* ]] || die "image name contains a newline"

hash="$(sha256sum -- "$image" | awk '{ print $1 }')"
[[ "$hash" =~ ^[0-9a-f]{64}$ ]] || die "sha256sum returned an unexpected digest: ${hash:-empty}"
line="$hash  $name"

if [[ -z "$output" ]]; then
    printf '%s\n' "$line"
    exit 0
fi

output_dir="$(dirname -- "$output")"
mkdir -p -- "$output_dir"
tmp="$(mktemp "$output_dir/.SHA256SUMS.XXXXXX")"
cleanup() { rm -f -- "$tmp"; }
trap cleanup EXIT

printf '%s\n' "$line" >"$tmp"
chmod 0644 -- "$tmp"
mv -f -- "$tmp" "$output"
trap - EXIT

printf '[checksums] recorded %s for %s\n' "$hash" "$name" >&2
