#!/usr/bin/env bash
# Static and unit checks for the private CI, checksum, and access-control
# configuration. These checks need no root, network, Docker, or QEMU.
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
    local file="$1" pattern="$2"
    if [[ ! -s "$file" ]]; then
        bad "$file missing or empty (wanted: $pattern)"
    elif grep -qiE -- "$pattern" "$file"; then
        ok "$file contains $pattern"
    else
        bad "$file does not contain $pattern"
    fi
}

mkdir -p .scratch
scratch="$(mktemp -d "$root/.scratch/private-ci-test.XXXXXX")"
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() { rm -rf -- "$scratch"; }
trap cleanup EXIT

for file in \
    .github/workflows/private-ci.yml \
    ci/check-private-access.sh \
    ci/private-ci.sh \
    ci/qemu-smoke.sh \
    ci/record-checksums.sh \
    ci/verify-checksums.sh \
    docs/private-ci.md \
    docs/release-checklist.md \
    tests/private-ci.sh; do
    require_file "$file"
done

for executable in \
    ci/check-private-access.sh \
    ci/private-ci.sh \
    ci/qemu-smoke.sh \
    ci/record-checksums.sh \
    ci/verify-checksums.sh \
    tests/private-ci.sh; do
    require_exec "$executable"
done

for script in ci/*.sh tests/private-ci.sh; do
    if bash -n "$script" 2>/dev/null; then
        ok "$script syntax"
    else
        bad "$script has a bash syntax error"
    fi
done

# The workflow must not be able to publish a page, release, or package.
workflow=.github/workflows/private-ci.yml
if grep -qE '^[[:space:]]*(pull_request_target|release|page_build):' "$workflow"; then
    bad "workflow has a public-release or unsafe trigger"
else
    ok "workflow triggers do not include a public release or unsafe PR target"
fi
if grep -qE 'secrets\.|gpg|GPG|detach-sign' "$workflow"; then
    bad "workflow references signing material or secrets; signing must stay offline"
else
    ok "workflow does not reference the private signing key"
fi
if grep -RInE -- 'actions/(deploy-pages|upload-pages-artifact)|softprops/action-gh-release|upload-release-asset|gh[[:space:]]+release[[:space:]]+create|docker[[:space:]]+push|oras[[:space:]]+push|npm[[:space:]]+publish|twine[[:space:]]+upload|aws[[:space:]]+s3|gsutil[[:space:]]+cp|rclone[[:space:]]+copy' \
    .github/workflows ci >/dev/null 2>&1; then
    bad "public release, Pages, mirror, or package-publish command found"
else
    ok "no public release, Pages, mirror, or package-publish command"
fi
if grep -RInE -- 'pages\.github\.io|github\.io/|public[_-]?artifact|artifact[_-]?url' \
    .github/workflows ci >/dev/null 2>&1; then
    bad "public artifact or Pages URL found in CI configuration"
else
    ok "no public artifact or Pages URL in CI configuration"
fi

# Parse the workflow with a real YAML parser when one is available, then assert
# the access-control structure. The JSON conversion avoids depending on PyYAML
# in the test runner.
workflow_json="$scratch/workflow.json"
yaml_ok=0
if command -v ruby >/dev/null 2>&1 && ruby -e 'require "yaml"; require "json"' >/dev/null 2>&1; then
    if ruby -ryaml -rjson -e 'puts JSON.generate(YAML.load_file(ARGV[0]))' "$workflow" >"$workflow_json" 2>/dev/null; then
        yaml_ok=1
    fi
elif command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml, json' >/dev/null 2>&1; then
    if python3 - "$workflow" >"$workflow_json" <<'PY' 2>/dev/null
import json
import sys
import yaml

with open(sys.argv[1], encoding="utf-8") as handle:
    data = yaml.safe_load(handle)
print(json.dumps(data))
PY
    then
        yaml_ok=1
    fi
fi

if ((yaml_ok == 1)); then
    if python3 - "$workflow_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    workflow = json.load(handle)

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def permissions(job=None):
    data = job.get("permissions") if job else workflow.get("permissions")
    return data or {}


triggers = workflow.get("on")
if triggers is None:
    triggers = workflow.get("true")
if triggers is None:
    triggers = workflow.get(True)
check(isinstance(triggers, dict), "workflow has no trigger map")
if isinstance(triggers, dict):
    for trigger in ("workflow_dispatch", "pull_request", "push"):
        check(trigger in triggers, f"workflow is missing trigger {trigger}")
    for trigger in ("release", "page_build", "pull_request_target"):
        check(trigger not in triggers, f"workflow must not use trigger {trigger}")

for label, perms in (("workflow", permissions()),):
    check(str(perms.get("contents", "")).lower() == "read", f"{label} contents permission is not read")
    for name, value in perms.items():
        check(str(value).lower() != "write", f"{label} permission {name} is write")

jobs = workflow.get("jobs") or {}
for job_name in ("access-guard", "static-tests", "build-and-smoke"):
    check(job_name in jobs, f"workflow is missing job {job_name}")

for job_name, job in jobs.items():
    for name, value in permissions(job).items():
        check(str(value).lower() != "write", f"job {job_name} permission {name} is write")
    for step in job.get("steps") or []:
        blob = f"{step.get('uses', '')}\n{step.get('run', '')}"
        for forbidden in (
            "actions/deploy-pages",
            "actions/upload-pages-artifact",
            "softprops/action-gh-release",
            "upload-release-asset",
            "gh release create",
            "docker push",
            "oras push",
            "npm publish",
            "twine upload",
            "aws s3",
            "gsutil cp",
            "rclone copy",
        ):
            check(forbidden not in blob, f"job {job_name} contains forbidden action: {forbidden}")

access_runs = "\n".join(str(step.get("run", "")) for step in (jobs.get("access-guard") or {}).get("steps", []))
check("ci/check-private-access.sh" in access_runs, "access guard does not run ci/check-private-access.sh")
check("--online" in access_runs, "access guard does not perform the online check")

test_runs = "\n".join(str(step.get("run", "")) for step in (jobs.get("static-tests") or {}).get("steps", []))
check("tests/all.sh" in test_runs, "static-tests does not run tests/all.sh")

build_job = jobs.get("build-and-smoke") or {}
build_runs = "\n".join(str(step.get("run", "")) for step in build_job.get("steps", []))
check("ci/private-ci.sh" in build_runs, "build job does not run ci/private-ci.sh")

uploads = []
for job_name, job in jobs.items():
    for step in job.get("steps") or []:
        if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
            uploads.append((job_name, step))
check(len(uploads) >= 2, "expected ordinary and release-candidate artifact uploads")
for job_name, step in uploads:
    with_ = step.get("with") or {}
    check(str(with_.get("retention-days", "")) != "", f"{job_name} upload has no retention-days")
    check(str(with_.get("if-no-files-found", "")) == "error", f"{job_name} upload does not fail when files are missing")
    check(str(with_.get("name", "")).lower().find("public") == -1, f"{job_name} upload name looks public")
    paths = str(with_.get("path", ""))
    for required in ("out/*.iso", "out/SHA256SUMS", "out/qemu-serial.log", "out/build-metadata.txt"):
        check(required in paths, f"{job_name} upload is missing {required}")

candidate = jobs.get("private-release-candidate") or {}
candidate_needs = candidate.get("needs", [])
if isinstance(candidate_needs, str):
    candidate_needs = [candidate_needs]
check("build-and-smoke" in candidate_needs, "release candidate does not depend on build-and-smoke")
check(candidate.get("environment") == "private-release", "release candidate is not gated by the private-release environment")
candidate_if = str(candidate.get("if", ""))
check("workflow_dispatch" in candidate_if and "release_candidate" in candidate_if,
      "release candidate is not manual release_candidate only")
check(any("actions/download-artifact@" in str(step.get("uses", "")) for step in candidate.get("steps", [])),
      "release candidate does not download the verified CI artifact")

if failures:
    for failure in failures:
        print(f"FAIL {failure}")
    sys.exit(1)
print("ok workflow private-access and artifact-retention configuration")
PY
    then
        ok "workflow YAML structure"
    else
        bad "workflow YAML structure"
    fi
else
    ok "workflow YAML parser unavailable; text checks only"
fi

if grep -q 'retention-days: 14' "$workflow" && grep -q 'retention-days: 90' "$workflow"; then
    ok "workflow documents 14-day CI and 90-day candidate retention"
else
    bad "workflow retention settings are incomplete"
fi

# Checksum scripts: record, verify, tamper detection, and path safety.
printf 'synthetic private image payload\n' >"$scratch/fixture.iso"
if bash ci/record-checksums.sh "$scratch/fixture.iso" "$scratch/SHA256SUMS" >/dev/null 2>&1; then
    ok "record-checksums.sh writes a checksum file"
else
    bad "record-checksums.sh failed"
fi
expected_hash="$(sha256sum "$scratch/fixture.iso" | awk '{ print $1 }')"
if [[ "$(<"$scratch/SHA256SUMS")" == "$expected_hash  fixture.iso" ]]; then
    ok "SHA256SUMS uses the standard hash and basename format"
else
    bad "SHA256SUMS format is wrong: $(<"$scratch/SHA256SUMS")"
fi
if bash ci/verify-checksums.sh "$scratch/SHA256SUMS" "$scratch" >/dev/null 2>&1; then
    ok "verify-checksums.sh accepts the matching artifact"
else
    bad "verify-checksums.sh rejected a matching artifact"
fi

printf 'tampered\n' >>"$scratch/fixture.iso"
if bash ci/verify-checksums.sh "$scratch/SHA256SUMS" "$scratch" >/dev/null 2>&1; then
    bad "verify-checksums.sh accepted a tampered artifact"
else
    ok "verify-checksums.sh rejects a tampered artifact"
fi
printf 'synthetic private image payload\n' >"$scratch/fixture.iso"

printf '%s  missing.iso\n' "$expected_hash" >"$scratch/missing.SHA256SUMS"
if bash ci/verify-checksums.sh "$scratch/missing.SHA256SUMS" "$scratch" >/dev/null 2>&1; then
    bad "verify-checksums.sh accepted a missing artifact"
else
    ok "verify-checksums.sh rejects a missing artifact"
fi

printf '%s  /tmp/absolute.iso\n' "$expected_hash" >"$scratch/absolute.SHA256SUMS"
if bash ci/verify-checksums.sh "$scratch/absolute.SHA256SUMS" "$scratch" >/dev/null 2>&1; then
    bad "verify-checksums.sh accepted an absolute path"
else
    ok "verify-checksums.sh rejects an absolute path"
fi

printf '%s  ../escape.iso\n' "$expected_hash" >"$scratch/traversal.SHA256SUMS"
if bash ci/verify-checksums.sh "$scratch/traversal.SHA256SUMS" "$scratch" >/dev/null 2>&1; then
    bad "verify-checksums.sh accepted path traversal"
else
    ok "verify-checksums.sh rejects path traversal"
fi

printf 'not-a-hash  fixture.iso\n' >"$scratch/malformed.SHA256SUMS"
if bash ci/verify-checksums.sh "$scratch/malformed.SHA256SUMS" "$scratch" >/dev/null 2>&1; then
    bad "verify-checksums.sh accepted a malformed hash"
else
    ok "verify-checksums.sh rejects a malformed hash"
fi

{
    printf '%s  fixture.iso\n' "$expected_hash"
    printf '%s  fixture.iso\n' "$expected_hash"
} >"$scratch/duplicate.SHA256SUMS"
if bash ci/verify-checksums.sh "$scratch/duplicate.SHA256SUMS" "$scratch" >/dev/null 2>&1; then
    bad "verify-checksums.sh accepted a duplicate entry"
else
    ok "verify-checksums.sh rejects a duplicate entry"
fi

{
    printf '# comment\n\n'
    printf '%s  fixture.iso\n' "$expected_hash"
} >"$scratch/comments.SHA256SUMS"
if bash ci/verify-checksums.sh "$scratch/comments.SHA256SUMS" "$scratch" >/dev/null 2>&1; then
    ok "verify-checksums.sh accepts comments and blank lines"
else
    bad "verify-checksums.sh rejected comments and blank lines"
fi

# The QEMU smoke test must verify the checksum first, disable networking, use a
# serial file, and expose a dry-run mode for CI validation.
printf 'boot fixture\n' >"$scratch/boot.iso"
bash ci/record-checksums.sh "$scratch/boot.iso" "$scratch/boot.SHA256SUMS" >/dev/null 2>&1
if bash ci/qemu-smoke.sh "$scratch/boot.iso" --checksums "$scratch/boot.SHA256SUMS" \
    --log "$scratch/qemu-serial.log" --dry-run >"$scratch/qemu-command.txt" 2>&1; then
    ok "qemu-smoke.sh dry run succeeds with a verified image"
else
    bad "qemu-smoke.sh dry run failed"
fi
for token in '-serial' '-cdrom' '-net none' '-display none'; do
    if grep -qF -- "$token" "$scratch/qemu-command.txt"; then
        ok "QEMU dry run includes $token"
    else
        bad "QEMU dry run is missing $token"
    fi
done
printf 'tampered\n' >>"$scratch/boot.iso"
if bash ci/qemu-smoke.sh "$scratch/boot.iso" --checksums "$scratch/boot.SHA256SUMS" \
    --log "$scratch/qemu-serial.log" --dry-run >/dev/null 2>&1; then
    bad "qemu-smoke.sh would boot an unverified image"
else
    ok "qemu-smoke.sh refuses to boot an unverified image"
fi

if grep -qF -- 'AUTHORIZED USE ONLY' ci/qemu-smoke.sh &&
    grep -qiF -- 'kernel panic' ci/qemu-smoke.sh; then
    ok "QEMU smoke test checks the banner and panics"
else
    bad "QEMU smoke test is missing its success/failure markers"
fi

# Private CI orchestration must build, checksum, smoke boot, and re-verify.
for term in './build.sh' 'record-checksums.sh' 'verify-checksums.sh' 'qemu-smoke.sh' 'SHA256SUMS'; do
    if grep -qF -- "$term" ci/private-ci.sh; then
        ok "private-ci.sh contains $term"
    else
        bad "private-ci.sh is missing $term"
    fi
done

# Access guard: private passes; public, Pages, missing fields, and public
# visibility all fail closed. No network or token is used.
make_event() {
    local path="$1" private="$2" visibility="$3" pages="$4"
    printf '{"repository":{"private":%s,"visibility":%s,"has_pages":%s}}\n' \
        "$private" "$visibility" "$pages" >"$path"
}

make_event "$scratch/private.json" true '"private"' false
if bash ci/check-private-access.sh --event "$scratch/private.json" >"$scratch/guard-private.out" 2>&1; then
    ok "access guard accepts a private repository with Pages disabled"
else
    bad "access guard rejected a valid private repository"
fi

make_event "$scratch/public.json" false '"public"' false
if bash ci/check-private-access.sh --event "$scratch/public.json" >"$scratch/guard-public.out" 2>&1; then
    bad "access guard accepted a public repository"
elif grep -qi 'not private' "$scratch/guard-public.out"; then
    ok "access guard rejects a public repository"
else
    bad "access guard rejected a public repository for the wrong reason"
fi

make_event "$scratch/visibility.json" true '"public"' false
if bash ci/check-private-access.sh --event "$scratch/visibility.json" >"$scratch/guard-visibility.out" 2>&1; then
    bad "access guard accepted public visibility"
elif grep -qi 'visibility' "$scratch/guard-visibility.out"; then
    ok "access guard rejects public visibility"
else
    bad "access guard rejected public visibility for the wrong reason"
fi

make_event "$scratch/pages.json" true '"private"' true
if bash ci/check-private-access.sh --event "$scratch/pages.json" >"$scratch/guard-pages.out" 2>&1; then
    bad "access guard accepted GitHub Pages"
elif grep -qi 'Pages' "$scratch/guard-pages.out"; then
    ok "access guard rejects GitHub Pages"
else
    bad "access guard rejected Pages for the wrong reason"
fi

printf '{"repository":{"private":true,"visibility":"private"}}\n' >"$scratch/no-pages-field.json"
if bash ci/check-private-access.sh --event "$scratch/no-pages-field.json" >/dev/null 2>&1; then
    bad "access guard accepted a missing has_pages field"
else
    ok "access guard fails closed when has_pages is missing"
fi

if bash ci/check-private-access.sh --event "$scratch/does-not-exist.json" >/dev/null 2>&1; then
    bad "access guard accepted a missing event payload"
else
    ok "access guard rejects a missing event payload"
fi

if bash ci/check-private-access.sh --help >/dev/null 2>&1; then
    ok "access guard help"
else
    bad "access guard help failed"
fi

# The docs must state the human approval, offline key, revocation, and retention
# boundary.
for term in 'explicit human approval' 'private signing key' 'offline' 'revocation' \
    'retention' 'SHA256SUMS' 'Pages' 'public release' 'unauthenticated'; do
    require_text docs/release-checklist.md "$term"
done
for term in 'private repository' 'artifact' 'retention' 'revocation' 'Pages' \
    'public release' 'unauthenticated' '14 days' '90 days'; do
    require_text docs/private-ci.md "$term"
done

# The serial smoke marker must be part of the image boot configuration.
if grep -qF -- 'console=ttyS0,115200' iso/profiledef.sh; then
    ok "profile enables a serial kernel console"
else
    bad "profile does not enable a serial kernel console"
fi
if [[ -L iso/airootfs/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service ]] &&
    [[ "$(readlink iso/airootfs/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service)" == *'serial-getty@.service' ]]; then
    ok "serial getty is enabled for the smoke boot"
else
    bad "serial getty is not enabled"
fi

exit "$fail"
