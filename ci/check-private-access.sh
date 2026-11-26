#!/usr/bin/env bash
# Guard the boundary between public source and private build artifacts.
#
# Public-source mode permits the static checks and the container build, but not
# artifact upload or retention. Private-repository mode additionally permits
# repository-scoped GitHub Actions artifacts. Both modes fail closed for GitHub
# Pages, published GitHub Releases, inconsistent metadata, and an unavailable
# online check. No token, key, or artifact URL is printed.
set -Eeuo pipefail

script_name="${0##*/}"
event_path="${GITHUB_EVENT_PATH:-}"
repository="${GITHUB_REPOSITORY:-}"
online=0
mode=""

log() { printf '[access-guard] %s\n' "$*" >&2; }
die() { printf '[access-guard] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
usage: $script_name [--event PATH] [--repo OWNER/NAME] [--online]

Detect public-source or private-repository mode and allow only the matching
build actions. Both modes refuse GitHub Pages, published GitHub Releases, and
registry publication.

  --event PATH    GitHub event JSON (default: \$GITHUB_EVENT_PATH)
  --repo OWNER/NAME  repository (default: \$GITHUB_REPOSITORY)
  --online        also verify repository state through the GitHub API; needs
                  GH_TOKEN with read access
  -h, --help      show this help

In public-source mode, static checks and the container build are allowed but
artifact upload is not. In private-repository mode, repository-scoped Actions
artifact retention is also allowed. The default is offline so the check can be
unit-tested without a token.
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

# A public source repository and a private repository are the only supported
# modes. A missing or contradictory pair is refused rather than guessed.
case "$event_private:$event_visibility" in
    true:private)
        event_mode=private
        ;;
    false:public)
        event_mode=public
        ;;
    *)
        die "repository visibility is missing or inconsistent (repository.private='${event_private:-missing}', repository.visibility='${event_visibility:-missing}'); refusing to build"
        ;;
esac

[[ "$event_has_pages" == "false" ]] ||
    die "GitHub Pages is enabled or unknown (repository.has_pages='${event_has_pages:-missing}'); disable Pages before CI"
log "event payload confirms ${event_mode} source with Pages disabled"

mode="$event_mode"
visibility="$event_visibility"
release_state="unchecked (offline)"

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

    case "$api_private:$api_visibility" in
        true:private)
            api_mode=private
            ;;
        false:public)
            api_mode=public
            ;;
        *)
            die "GitHub API visibility is missing or unsupported (private='${api_private:-unknown}', visibility='${api_visibility:-unknown}'); refusing to build"
            ;;
    esac

    [[ "$api_mode" == "$event_mode" ]] ||
        die "event payload says ${event_mode} but the GitHub API says ${api_mode}; refusing to guess"
    [[ "$api_pages" == "false" ]] ||
        die "GitHub API says Pages is enabled or unknown; disable it first"
    [[ "$published_releases" =~ ^[0-9]+$ ]] ||
        die "could not parse the published release count through the GitHub API"
    [[ "$published_releases" == "0" ]] ||
        die "repository has ${published_releases} published GitHub Release(s); remove the public release channel first"
    log "GitHub API confirms ${api_mode} visibility, Pages disabled, and no published releases"

    mode="$api_mode"
    visibility="$api_visibility"
    release_state="$published_releases"
fi

if [[ "$mode" == "private" ]]; then
    artifact_upload="private-only"
    artifact_retention="private"
else
    artifact_upload="no"
    artifact_retention="none"
fi

log "detected state: repository=${mode}; visibility=${visibility}; Pages=disabled; published releases=${release_state}"
log "allowed actions: static checks=yes; container build=yes; artifact upload=${artifact_upload}; Pages=no; releases=no; registry publication=no"

if [[ "$mode" == "public" ]]; then
    log "public-source access check passed; built artifacts are not retained"
else
    log "private access check passed; repository-scoped artifact retention is allowed"
fi

# Let the workflow branch on the detected mode without parsing log text.
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'mode=%s\n' "$mode" >>"$GITHUB_OUTPUT"
    printf 'artifact_retention=%s\n' "$artifact_retention" >>"$GITHUB_OUTPUT"
fi
