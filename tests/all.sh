#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

fail=0
ok() { printf 'ok %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*"; fail=1; }

require_file() {
  if [ -s "$1" ]; then ok "$1"; else bad "$1 missing or empty"; fi
}

require_text() {
  local file=$1 pattern=$2
  if [ ! -s "$file" ]; then
    bad "$file missing or empty (wanted: $pattern)"
  elif grep -qiE -- "$pattern" "$file"; then
    ok "$file contains $pattern"
  else
    bad "$file does not contain $pattern"
  fi
}

# Required deliverables
for f in \
  README.md \
  docs/adr/0001-cybersecurity-os-base.md \
  docs/policy/authorized-use.md \
  docs/policy/legal-licensing-export.md \
  build/README.md \
  build/archiso/profile/profiledef.sh \
  build/archiso/profile/packages.x86_64 \
  build/archiso/profile/denylist.txt \
  build/archiso/profile/pacman.conf \
  build/archiso/profile/airootfs/etc/issue \
  build/archiso/profile/airootfs/etc/motd \
  build/archiso/profile/airootfs/etc/calamares/settings.conf \
  build/archiso/profile/airootfs/etc/calamares/modules/notes.conf \
  build/archiso/profile/airootfs/etc/calamares/modules/packagechooser.conf \
  build/archiso/profile/airootfs/etc/calamares/modules/packages.conf \
  docs/policy/security-tool-groups.md \
  docs/policy/forensics-capabilities.md \
  tests/security-groups.sh \
  tests/cyber-frontend.sh \
  frontend/cyber/manifest.json \
  frontend/cyber/src/registry.js \
  frontend/cyber/src/authorization.js \
  frontend/cyber/src/runner.js \
  frontend/cyber/src/nmap.js \
  frontend/cyber/src/set.js \
  frontend/cyber/src/forensics.js \
  frontend/cyber/qml/CyberShell.qml \
  frontend/cyber/qml/ToolPanelFrame.qml \
  frontend/cyber/qml/NmapPanel.qml \
  frontend/cyber/qml/SetPanel.qml \
  frontend/cyber/qml/ForensicsPanel.qml \
  frontend/cyber/test/nmap.test.cjs \
  frontend/cyber/test/set.test.cjs \
  frontend/cyber/test/forensics.test.cjs \
  frontend/cyber/test/fixtures/nmap-basic.xml \
  frontend/cyber/test/fixtures/nmap-error.xml \
  frontend/cyber/test/fixtures/nmap-timeout.xml \
  frontend/cyber/test/fixtures/generate-pcap.cjs \
  frontend/cyber/test/fixtures/lab-capture.pcap \
  frontend/cyber/test/fixtures/tshark-sensitive.json
do
  require_file "$f"
done

# The ADR must actually compare both bases and cover the requested dimensions.
adr=docs/adr/0001-cybersecurity-os-base.md
for term in \
  'BlackArch' \
  'Archiso' \
  'Calamares' \
  'signing' \
  'mirror' \
  'size' \
  'update model' \
  'maintenance burden' \
  'Decision' \
  'Reference build'
do
  require_text "$adr" "$term"
done

# Authorized-use boundary
policy=docs/policy/authorized-use.md
for term in \
  'owned' \
  'written permission' \
  'banner' \
  'No default scans' \
  'phishing template' \
  'credential theft' \
  'target scope'
do
  require_text "$policy" "$term"
done

# Wireshark/forensics capability and revocation boundary
forensics=docs/policy/forensics-capabilities.md
for term in \
  'CAP_NET_RAW' \
  'CAP_NET_ADMIN' \
  'setcap' \
  'revoke' \
  'no root' \
  'packet injection' \
  'upload' \
  'tshark'
do
  require_text "$forensics" "$term"
done

# Legal, licensing, and export review
legal=docs/policy/legal-licensing-export.md
for term in \
  'GPL-3.0-only' \
  'license' \
  'export' \
  'Wassenaar' \
  'sanctions' \
  'not legal advice'
do
  require_text "$legal" "$term"
done

# Banner must be explicit, not just linked documentation.
for term in 'AUTHORIZED USE ONLY' 'owned' 'written permission' 'No scans run by default'; do
  require_text build/archiso/profile/airootfs/etc/issue "$term"
  require_text build/archiso/profile/airootfs/etc/motd "$term"
done

# Build inputs must be syntactically plausible and preserve strict signatures.
if bash -n build/archiso/profile/profiledef.sh; then
  ok 'profiledef.sh syntax'
else
  bad 'profiledef.sh syntax'
fi

if grep -qE '^[[:space:]]*SigLevel[[:space:]]*=[[:space:]]*Required' build/archiso/profile/pacman.conf; then
  ok 'pacman.conf requires signatures'
else
  bad 'pacman.conf does not require signatures'
fi

if grep -qE '^[[:space:]]*SigLevel[[:space:]]*=[[:space:]]*(Never|Optional[[:space:]]+TrustAll)' build/archiso/profile/pacman.conf; then
  bad 'pacman.conf disables signature checking'
else
  ok 'pacman.conf does not disable signature checking'
fi

if grep -q '^\[blackarch\]$' build/archiso/profile/pacman.conf; then
  ok 'blackarch repository configured'
else
  bad 'blackarch repository missing'
fi

# The allowlist must not contain a denylisted package.
if [ -s build/archiso/profile/denylist.txt ]; then
  while IFS= read -r pkg; do
    case "$pkg" in
      ''|'#'*) continue ;;
    esac
    if grep -qxF -- "$pkg" build/archiso/profile/packages.x86_64; then
      bad "denylisted package in allowlist: $pkg"
    fi
  done < build/archiso/profile/denylist.txt
  ok 'allowlist checked against denylist'
else
  bad 'denylist.txt missing or empty'
fi

# Reference build must include the reviewed tools, not the phishing/credential
# theft packages.
for pkg in nmap wireshark-qt sleuthkit qemu-desktop libvirt virt-manager calamares; do
  if grep -qxF -- "$pkg" build/archiso/profile/packages.x86_64; then
    ok "package allowlisted: $pkg"
  else
    bad "package missing from allowlist: $pkg"
  fi
done

for pkg in set gophish evilginx mimikatz lazagne responder; do
  if grep -qxF -- "$pkg" build/archiso/profile/packages.x86_64; then
    bad "prohibited package in allowlist: $pkg"
  else
    ok "prohibited package absent: $pkg"
  fi
done

# No default scanner or capture configuration in the live/installer overlay.
# The packagechooser only names optional packages; it must not start them.
if grep -RqiE --exclude='packagechooser.conf' --exclude='notes.conf' '(nmap|masscan|zmap|nikto|openvas|nessus)' build/archiso/profile/airootfs; then
  bad 'scanner reference in airootfs overlay (no default scans)'
else
  ok 'no scanner reference in airootfs overlay'
fi

# No phishing-template assets in the build tree.
if find build -type f \( -iname '*.eml' -o -iname '*.hbs' -o -iname '*phishing*' -o -iname '*credential-harvest*' \) -print -quit | grep -q .; then
  bad 'phishing/credential-template asset in build tree'
else
  ok 'no phishing-template assets in build tree'
fi

# Calamares is wired to the security branding and the reference sequence.
if grep -qE '^branding:[[:space:]]*maria-padilha$' build/archiso/profile/airootfs/etc/calamares/settings.conf; then
  ok 'calamares branding configured'
else
  bad 'calamares branding missing'
fi

if grep -q 'Authorized Lab Use Only' build/archiso/profile/airootfs/etc/calamares/branding/maria-padilha/branding.desc 2>/dev/null; then
  ok 'calamares branding shows authorized use'
else
  bad 'calamares branding does not show authorized use'
fi

if grep -q 'AUTHORIZED USE ONLY' build/archiso/profile/airootfs/etc/calamares/modules/notes.conf; then
  ok 'calamares notes show authorized use'
else
  bad 'calamares notes do not show authorized use'
fi

# No ISO/image artifact may be tracked, and no Pages/release automation may be
# added as part of this source-only decision.
if [ -n "$(git ls-files -- '*.iso' '*.img' '*.pkg.tar.zst')" ]; then
  bad 'tracked image or package artifact'
else
  ok 'no tracked ISO/image/package artifact'
fi

if git grep -nEi 'gh-pages|actions/deploy-pages|softprops/action-gh-release|upload-release-asset|generate_release_notes' -- .github 2>/dev/null; then
  bad 'Pages or release automation found in .github'
else
  ok 'no Pages or release automation in .github'
fi

# No obvious tracked secret. Keep this last so the pattern itself is not
# mistaken for a key.
if git grep -nE 'sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY' -- . >/tmp/secret-scan.$$ 2>/dev/null; then
  echo "FAIL possible tracked secret"; cat /tmp/secret-scan.$$; fail=1
else
  echo "ok no obvious tracked secret"
fi
rm -f /tmp/secret-scan.$$
if bash tests/cyber-frontend.sh; then
  echo "ok tests/cyber-frontend.sh"
else
  echo "FAIL tests/cyber-frontend.sh"
  fail=1
fi
if bash tests/security-groups.sh; then
  echo "ok tests/security-groups.sh"
else
  echo "FAIL tests/security-groups.sh"
  fail=1
fi
if bash tests/iso.sh; then
  echo "ok tests/iso.sh"
else
  echo "FAIL tests/iso.sh"
  fail=1
fi
[ "$fail" -eq 0 ]
