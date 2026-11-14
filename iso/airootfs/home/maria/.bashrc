# Maria Padilha de Castela live-user shell defaults.
#
# Keep secrets out of persisted history and make new files owner-only. See
# /etc/profile.d/10-maria-private.sh and `maria-clear-history --help`.
umask 077

HISTCONTROL=ignoreboth
HISTIGNORE='*password*:*passwd*:*token*:*secret*:*api[_-]key*:*api_key*:*Authorization:*:*PRIVATE*KEY*:*Bearer *'
HISTSIZE=500
HISTFILESIZE=500
export HISTCONTROL HISTIGNORE HISTSIZE HISTFILESIZE

# Do not write history at all if the operator starts a shell with
# MARIA_NO_HISTORY=1. This is useful for a short, sensitive session.
if [ "${MARIA_NO_HISTORY:-0}" = "1" ]; then
    HISTFILE=/dev/null
    export HISTFILE
fi
