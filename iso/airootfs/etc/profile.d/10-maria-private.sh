# shellcheck shell=sh
# Maria Padilha de Castela private shell defaults.
#
# This is a defence-in-depth convenience control, not a substitute for keeping
# secrets out of command lines. Prefer an environment variable, a prompt, or a
# file descriptor over an argument that will be visible in the process table.
#
# - New files are owner-only, which covers captures, notes, and extracted data.
# - Commands that start with a space are not recorded by bash.
# - Common secret-bearing command lines are ignored by bash history.
# - The in-memory and on-disk history stay small and are cleared on request by
#   maria-clear-history.

umask 077

if [ -n "${BASH_VERSION:-}" ]; then
    HISTCONTROL=ignoreboth
    HISTIGNORE='*password*:*passwd*:*token*:*secret*:*api[_-]key*:*api_key*:*Authorization:*:*PRIVATE*KEY*:*Bearer *'
    HISTSIZE=500
    HISTFILESIZE=500
    export HISTCONTROL HISTIGNORE HISTSIZE HISTFILESIZE
fi
