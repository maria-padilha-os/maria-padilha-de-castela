#!/usr/bin/env bash
# Static and behavioural checks for the private cyber frontend surface.
#
# Runs without root, network, a desktop session, or a package manager. The Node
# checks cover the manifest/registry/authorization/runner behaviour; the shell
# checks cover the image copy, shared controls, and the no-palette rule.
set -euo pipefail

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail=0
ok() { printf 'ok %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; fail=1; }

require_file() {
    if [[ -s "$1" ]]; then ok "$1"; else bad "$1 missing or empty"; fi
}

src="frontend/cyber"
image="iso/airootfs/usr/share/maria-padilha/cyber"

for file in \
    "$src/README.md" \
    "$src/manifest.json" \
    "$src/index.html" \
    "$src/package.json" \
    "$src/src/registry.js" \
    "$src/src/authorization.js" \
    "$src/src/runner.js" \
    "$src/src/nmap.js" \
    "$src/src/theme.css" \
    "$src/src/cyber.css" \
    "$src/src/app.js" \
    "$src/qml/qmldir" \
    "$src/qml/CyberShell.qml" \
    "$src/qml/CyberTheme.qml" \
    "$src/qml/AuthorizationBanner.qml" \
    "$src/qml/LabModeSwitch.qml" \
    "$src/qml/TargetScopeIndicator.qml" \
    "$src/qml/StopClearAction.qml" \
    "$src/qml/ToolPanelFrame.qml" \
    "$src/qml/ToolUnavailable.qml" \
    "$src/qml/RunButton.qml" \
    "$src/qml/CyberTabBar.qml" \
    "$src/qml/NmapPanel.qml" \
    "$src/qml/SetPanel.qml" \
    "$src/qml/ForensicsPanel.qml" \
    "$src/qml/LabPanel.qml" \
    "$src/test/manifest.test.cjs" \
    "$src/test/registry.test.cjs" \
    "$src/test/authorization.test.cjs" \
    "$src/test/runner.test.cjs" \
    "$src/test/nmap.test.cjs" \
    "$src/test/fixtures/nmap-basic.xml" \
    "$src/test/fixtures/nmap-error.xml" \
    "$src/test/fixtures/nmap-timeout.xml" \
    "$src/test/theme.test.cjs"
do
    require_file "$file"
done

# The active image profile must carry the same runtime files as the source
# surface. Tests stay at the source tree only.
mirror_files=(
    README.md
    manifest.json
    index.html
    package.json
    src/registry.js
    src/authorization.js
    src/runner.js
    src/nmap.js
    src/theme.css
    src/cyber.css
    src/app.js
    qml/qmldir
    qml/CyberShell.qml
    qml/CyberTheme.qml
    qml/AuthorizationBanner.qml
    qml/LabModeSwitch.qml
    qml/TargetScopeIndicator.qml
    qml/StopClearAction.qml
    qml/ToolPanelFrame.qml
    qml/ToolUnavailable.qml
    qml/RunButton.qml
    qml/CyberTabBar.qml
    qml/NmapPanel.qml
    qml/SetPanel.qml
    qml/ForensicsPanel.qml
    qml/LabPanel.qml
)
for file in "${mirror_files[@]}"; do
    require_file "$image/$file"
    if ! cmp -s "$src/$file" "$image/$file"; then
        bad "cyber image copy differs from source: $file"
    fi
done
ok "cyber runtime files are mirrored into the image profile"

if grep -qF 'airootfs/usr/share/maria-padilha/cyber' build.sh; then
    ok "build.sh verifies the cyber frontend profile files"
else
    bad "build.sh does not verify the cyber frontend profile files"
fi

# The surface must be private and flagged, not part of the normal dashboard.
for term in \
    'maria-padilha.cyber' \
    'maria-padilha.cyber.panels' \
    'MARIA_PADILHA_CYBER_FRONTEND' \
    'privateBuild' \
    'autoRun' \
    'policy-blocked' \
    'missing-tool' \
    'AUTHORIZED USE ONLY'
do
    if grep -RqF -- "$term" "$src" "$image"; then
        ok "cyber surface contains $term"
    else
        bad "cyber surface is missing $term"
    fi
done

for tab in nmap set forensics lab-vm; do
    if grep -qF "\"id\": \"$tab\"" "$src/manifest.json"; then
        ok "manifest registers tab $tab"
    else
        bad "manifest does not register tab $tab"
    fi
done

if grep -qF '"autoRun": false' "$src/manifest.json"; then
    ok "manifest declares no auto-run tabs"
else
    bad "manifest does not declare autoRun: false"
fi

# The Nmap surface must keep its target/profile/option validation and explicit
# authorized-lab confirmation instead of accepting free-form arguments.
for term in \
    'validateTarget' \
    'buildScanRequest' \
    'parseNmapXml' \
    'interpretScanResult' \
    'authorizedLab' \
    'authorized lab' \
    'shell: false' \
    'public targets are refused'
do
    if grep -RqF -- "$term" "$src/src/nmap.js" "$src/qml/NmapPanel.qml" "$src/src/app.js"; then
        ok "Nmap extension contains $term"
    else
        bad "Nmap extension is missing $term"
    fi
done

if grep -qF -- "-oX" "$src/src/nmap.js"; then
    ok "Nmap requests XML output on stdout"
else
    bad "Nmap does not request XML output"
fi

for forbidden in ' -sS' ' -sU' ' -O ' ' -A ' '--script'; do
    if grep -RqF -- "$forbidden" "$src/src/nmap.js"; then
        bad "Nmap module contains privileged/aggressive flag: $forbidden"
    else
        ok "Nmap module excludes $forbidden"
    fi
done

# No palette literal in component CSS or QML. The theme file is allowed only
# semantic aliases too, so it is included.
if grep -RInE '[#][0-9A-Fa-f]{3,8}\b|rgba?\(|hsla?\(|Qt\.rgba\(|Qt\.hsla\(' \
    "$src/src" "$src/qml" "$image/src" "$image/qml" >/dev/null 2>&1; then
    bad "hardcoded palette value in the cyber frontend"
else
    ok "no hardcoded palette values in CSS or QML"
fi

if grep -RqF -- '--cyber-color-surface' "$src/src/theme.css" &&
    grep -RqF -- 'var(--cyber-color-surface)' "$src/src/cyber.css"; then
    ok "components use semantic --cyber-* theme tokens"
else
    bad "components do not use semantic theme tokens"
fi

# Every offensive panel must use the shared frame, which owns all of the
# required safety controls.
for panel in NmapPanel SetPanel ForensicsPanel LabPanel; do
    if grep -qE '^[[:space:]]*ToolPanelFrame[[:space:]]*\{' "$src/qml/$panel.qml"; then
        ok "$panel uses the shared safety frame"
    else
        bad "$panel does not use the shared safety frame"
    fi
done
for control in AuthorizationBanner LabModeSwitch TargetScopeIndicator StopClearAction; do
    if grep -qE "^[[:space:]]*$control[[:space:]]*\\{" "$src/qml/ToolPanelFrame.qml"; then
        ok "shared frame renders $control"
    else
        bad "shared frame is missing $control"
    fi
done

# The surface does not include process spawning, service management, or a
# package install command. The host adapter is the only execution boundary.
if grep -RInE '(^|[^[:alnum:]_])(sudo|pkexec|systemctl|pacman|mount)[[:space:]]|Quickshell\.Io\.Process' \
    "$src/src" "$src/qml" "$image/src" "$image/qml" >/dev/null 2>&1; then
    bad "privileged command or process spawning in the cyber frontend"
else
    ok "cyber frontend ships no privileged command or process spawner"
fi

if command -v node >/dev/null 2>&1; then
    for script in "$src"/src/*.js; do
        if node --check "$script" >/dev/null 2>&1; then
            ok "node syntax: ${script#"$src/"}"
        else
            bad "node syntax error: $script"
        fi
    done
    if node --test "$src"/test/*.test.cjs >/tmp/cyber-node-test.$$ 2>&1; then
        ok "cyber frontend Node tests"
    else
        bad "cyber frontend Node tests failed"
        cat /tmp/cyber-node-test.$$
    fi
    rm -f /tmp/cyber-node-test.$$
else
    echo "SKIP cyber frontend Node tests (node not installed)"
fi

exit "$fail"
