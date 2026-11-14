#!/usr/bin/env bash
# Verify a SHA256SUMS file against a private artifact directory.
#
# usage: verify-checksums.sh SHA256SUMS [DIRECTORY]
#
# The parser is deliberately strict: it accepts the standard two-space
# sha256sum format, rejects absolute paths and path traversal, rejects symlinks,
# and fails on a missing or mismatched file. DIRECTORY defaults to the checksum
# file's directory.
set -Eeuo pipefail

script_name="${0##*/}"

die() { printf '[checksums] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: $script_name SHA256SUMS [DIRECTORY]

Verify every checksum line against DIRECTORY (default: the checksum file's
directory). Blank lines and lines beginning with # are ignored.
EOF
}

(($# == 1 || $# == 2)) || { usage >&2; exit 2; }

sums="$1"
directory="${2:-$(dirname -- "$sums")}"

[[ -r "$sums" ]] || die "checksum file is not readable: $sums"
[[ -d "$directory" ]] || die "artifact directory not found: $directory"

checked=0
failed=0
declare -A seen=()

while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    case "$line" in
        ''|'#'*) continue ;;
    esac

    if [[ ! "$line" =~ ^([0-9A-Fa-f]{64})\ \ ([^/].*)$ ]]; then
        printf '[checksums] FAIL malformed line: %s\n' "$line" >&2
        failed=1
        continue
    fi

    hash="${BASH_REMATCH[1],,}"
    name="${BASH_REMATCH[2]}"

    if [[ "$name" == *$'\n'* || "$name" == *$'\r'* || "$name" == *\\* ]]; then
        printf '[checksums] FAIL unsafe filename: %s\n' "$name" >&2
        failed=1
        continue
    fi
    if [[ "$name" == /* || "/$name/" == *"/../"* || "/$name/" == *"/./"* ]]; then
        printf '[checksums] FAIL path traversal or absolute path: %s\n' "$name" >&2
        failed=1
        continue
    fi
    if [[ -n "${seen[$name]:-}" ]]; then
        printf '[checksums] FAIL duplicate entry: %s\n' "$name" >&2
        failed=1
        continue
    fi
    seen[$name]=1

    path="$directory/$name"
    if [[ ! -f "$path" || -L "$path" ]]; then
        printf '[checksums] FAIL missing or non-regular file: %s\n' "$name" >&2
        failed=1
        continue
    fi

    actual="$(sha256sum -- "$path" | awk '{ print $1 }')"
    if [[ "$actual" != "$hash" ]]; then
        printf '[checksums] FAIL hash mismatch: %s\n' "$name" >&2
        printf '[checksums]   expected %s\n' "$hash" >&2
        printf '[checksums]   actual   %s\n' "$actual" >&2
        failed=1
        continue
    fi

    checked=$((checked + 1))
done <"$sums"

if ((failed != 0)); then
    exit 1
fi
((checked > 0)) || die "no checksum entries in $sums"

printf '[checksums] verified %d file(s) from %s\n' "$checked" "$sums"
