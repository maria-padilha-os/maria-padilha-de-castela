#!/usr/bin/env bash
# Fail closed unless this is a private repository with no public channels.
#
# The event-payload checks are local and require no network. --online adds a
# read-only GitHub API check for repository visibility, GitHub Pages, and
# published releases. No token, key, or artifact URL is printed.
set -Eeuo pipefail

script_name="${0##*/}"
event_path="${GITHUB_EVENT_PATH:-}"
repository="${GITHUB_REPOSITORY:-}"
online=0

log() { printf '[access-guard] %s\n' "$*" >&2; }
die() { printf '[access-guard] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: $script_name [--event PATH] [--repo OWNER/NAME] [--online]

Refuse to build or retain private artifacts unless the repository is private,
GitHub Pages is disabled, and there is no published GitHub Release.

  --event PATH    GitHub event JSON (default: \$GITHUB_EVENT_PATH)
  --repo OWNER/NAME  repository (default: \$GITHUB_REPOSITORY)
  --online        also verify repository state through the GitHub API; needs
                  GH_TOKEN with read access
  -h, --help      show this help

The default is offline so the check can be unit-tested without a token.
EOF
}

while (($#)); do
    case "$1" in
        --event)
            (($# >= 2)) || die "--event needs a path"
            event_path="$2"
            shift 2
            ;;
        --repo)
            (($# >= 2)) || die "--repo needs OWNER/NAME"
            repository="$2"
            shift 2
            ;;
        --online)
            online=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1 (try --help)"
            ;;
    esac
done

[[ -n "$event_path" ]] || die "GITHUB_EVENT_PATH is not set; refusing to run without repository-visibility evidence"
[[ -r "$event_path" ]] || die "event payload is not readable: $event_path"

# Extract only the fields this guard needs. Python is used instead of a YAML
# parser because the payload is JSON. The values are checked as strings so a
# missing field can never be mistaken for a permissive default.
read -r event_private event_visibility event_has_pages < <(
    python3 - "$event_path" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        payload = json.load(handle)
except Exception:
    sys.exit(2)

repository = payload.get("repository") or {}


def value(key):
    item = repository.get(key)
    if isinstance(item, bool):
        return "true" if item else "false"
    if item is None:
        return ""
    return str(item)


print(value("private"), value("visibility"), value("has_pages"))
PY
) || die "could not parse event payload: $event_path"

[[ "$event_private" == "true" ]] ||
    die "repository is not private (repository.private='${event_private:-missing}'); refusing to build or retain artifacts"
[[ "$event_visibility" == "private" ]] ||
    die "repository visibility is not private (repository.visibility='${event_visibility:-missing}')"
[[ "$event_has_pages" == "false" ]] ||
    die "GitHub Pages is enabled (repository.has_pages='${event_has_pages:-missing}'); disable Pages before private CI"
log "event payload confirms a private repository with Pages disabled"

if ((online == 1)); then
    [[ -n "$repository" ]] || die "GITHUB_REPOSITORY is not set; --online needs OWNER/NAME"
    command -v gh >/dev/null 2>&1 || die "gh is required for --online"
    [[ -n "${GH_TOKEN:-}" ]] || die "GH_TOKEN is required for --online"

    api_private="$(gh api "repos/$repository" --jq '.private' 2>/dev/null)" ||
        die "could not read repository metadata through the GitHub API"
    api_visibility="$(gh api "repos/$repository" --jq '.visibility' 2>/dev/null)" ||
        die "could not read repository visibility through the GitHub API"
    api_pages="$(gh api "repos/$repository" --jq '.has_pages' 2>/dev/null)" ||
        die "could not read the GitHub Pages state through the GitHub API"
    published_releases="$(gh api "repos/$repository/releases?per_page=100" \
        --jq '[.[] | select(.draft == false)] | length' 2>/dev/null)" ||
        die "could not read the release list through the GitHub API"

    [[ "$api_private" == "true" ]] || die "GitHub API says the repository is not private"
    [[ "$api_visibility" == "private" ]] || die "GitHub API says visibility is '${api_visibility:-unknown}', not private"
    [[ "$api_pages" == "false" ]] || die "GitHub API says Pages is still enabled; disable it first"
    [[ "$published_releases" == "0" ]] ||
        die "repository has ${published_releases:-unknown} published GitHub Release(s); remove the public release channel first"
    log "GitHub API confirms private visibility, Pages disabled, and no published releases"
fi

log "private access check passed"
