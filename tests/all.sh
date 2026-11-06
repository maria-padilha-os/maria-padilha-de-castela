#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
fail=0
if [ ! -s README.md ]; then echo "FAIL README.md missing"; fail=1; else echo "ok README.md"; fi
if git grep -nE 'sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY' -- . >/tmp/secret-scan.$$ 2>/dev/null; then
  echo "FAIL possible tracked secret"; cat /tmp/secret-scan.$$; fail=1
else
  echo "ok no obvious tracked secret"
fi
rm -f /tmp/secret-scan.$$
[ "$fail" -eq 0 ]
