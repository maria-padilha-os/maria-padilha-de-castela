# Login shells read the private defaults from /etc/profile.d. This file only
# makes an interactive login shell behave like the live-user .bashrc.
[ -n "${BASH_VERSION:-}" ] && [ -r "$HOME/.bashrc" ] && . "$HOME/.bashrc"
