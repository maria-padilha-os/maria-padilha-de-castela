# Secrets, logs, shell history, and captured data

**Status:** Normative for the default private image. It covers how the image
keeps secrets out of logs and shell history and how an operator wipes captured
data. It does not grant permission to collect data from any system.

## 1. Where secrets leak

A secret can leak through more than a saved command. The default image treats
all of these as sensitive:

- command-line arguments, which are visible in the process table and may be
  logged by sudo, journald, or an application;
- shell history, including the in-memory list and the history file;
- application logs, journald, installer logs, and crash reports;
- core dumps and swap/hibernation images;
- packet captures, extracted files, browser state, and investigation notes;
- temporary files, clipboard history, and editor backups.

Do not put a password, token, private key, or credential in a command-line
argument. Prefer an interactive prompt (`read -rs`), a file descriptor, or an
environment variable set for one process. Even an environment variable can be
read by the same user and by root, so remove it when the command finishes and do
not export it globally.

## 2. Shell history controls

The live user's shell defaults are in `/etc/profile.d/10-maria-private.sh` and
`/home/maria/.bashrc`:

- `umask 077` makes new files, including captures and notes, owner-only;
- `HISTCONTROL=ignoreboth` stops bash recording duplicate lines and lines that
  begin with a space;
- `HISTIGNORE` ignores common secret-bearing patterns such as `password`,
  `token`, `secret`, API-key, `Authorization`, `Bearer`, and private-key text;
- `HISTSIZE=500` and `HISTFILESIZE=500` bound the in-memory and on-disk lists;
- `MARIA_NO_HISTORY=1` starts a shell with `HISTFILE=/dev/null` for a short
  sensitive session.

`HISTIGNORE` is a convenience filter, not a guarantee. A creative command can
still be recorded. The reliable habit is to never type the secret, or to prefix
the whole command with a space after confirming `ignoreboth` is active.

## 3. Logs and crash data

- `journald` uses volatile storage: `/etc/systemd/journald.conf.d/10-maria-private.conf`
  sets `Storage=volatile`, does not forward to syslog or wall, and caps the
  runtime journal. Live logs are in RAM and do not survive reboot.
- `systemd-coredump` is disabled by
  `/etc/systemd/coredump.conf.d/10-maria-private.conf` (`Storage=none`,
  `ProcessSizeMax=0`). A crash must not silently write credentials to disk.
- NetworkManager connectivity probes are disabled; see
  [`network-hardening.md`](network-hardening.md). No telemetry uploader is
  installed.
- The live image boots from a RAM-backed root, so ordinary live logs disappear
  on reboot. That does **not** make an in-session log safe to paste or attach.

If an authorized investigation needs crash data or persistent logs, enable them
explicitly for that session, keep them owner-only, and treat them as sensitive
evidence with the same retention rules as a capture.

## 4. Wipe/clear workflow

Two operator-run commands are installed. Both are dry-run by default, refuse
broad system paths where applicable, never call `sudo`, and do nothing at boot.

### Captures

```sh
maria-wipe-captures                  # dry run, default ~/Captures
maria-wipe-captures /path/to/captures
maria-wipe-captures --yes            # shred selected capture files
maria-wipe-captures --all --yes      # every regular file under the directory
maria-wipe-captures --no-shred --yes # rm only, for filesystems without overwrite support
```

The default selection is `*.pcap`, `*.pcapng`, `*.cap`, and their `.gz`, `.xz`,
and `.zst` variants. `--all` is explicit and can remove notes and extracted
files too. The command does not follow a symlinked directory and does not cross
a filesystem boundary.

### Shell and editor history

```sh
maria-clear-history            # dry run, lists files
maria-clear-history --yes      # shred history/state files
history -c                     # in every open shell
```

`maria-clear-history` removes the common bash/zsh/python/editor history files
and prints the reminder for the in-memory list. A separate process cannot clear
another shell's in-memory history; close those shells or run `history -c` in
each one.

### Order

1. Stop the tool or capture and confirm it has exited.
2. Copy out only what the written authorization requires, to an approved
   encrypted location.
3. Run `maria-clear-history --yes` and `history -c` in each sensitive shell.
4. Run `maria-wipe-captures --yes` for the local capture directory.
5. Close the sensitive shells and remove any temporary copies, editor backups,
   or clipboard entries.
6. Record the destruction in the engagement record, without recording the
   secret itself.

## 5. Secure-erase limits

`shred` overwrites a file through the filesystem, but it cannot guarantee
physical erasure on:

- SSDs and flash storage with wear leveling;
- copy-on-write filesystems, snapshots, and backups;
- journaling filesystems that retain old metadata or data blocks;
- remote, network, or virtualized storage;
- swap, hibernation, or crash images;
- data already copied, printed, screenshotted, or uploaded.

For high-sensitivity data, the reliable controls are full-disk encryption with
a key you can destroy, and destruction of the underlying media. Use the wipe
workflow to reduce local exposure, not as a claim of forensic erasure.

## 6. Absence-of-credentials checks

The repository tests do not just look for a hardcoded token. They check:

- no private-key blocks, provider API keys, or obvious access tokens in the
  tree;
- no `.env`, `.netrc`, `.pgpass`, `.git-credentials`, `authorized_keys`,
  SSH private key, PKCS#12, or keystore files;
- no password hash in `iso/airootfs/etc/shadow` (the live accounts are locked or
  passwordless for the ephemeral live session, never stored as a reusable
  crypt hash);
- no tracked shell history or capture/state files;
- the live-user capture directory is owner-only.

A passing test is not proof that a running system has no secret in memory. It
proves the shipped tree and default configuration do not carry one.

## 7. Incident response

If a secret may have leaked:

1. stop the tool and capture;
2. rotate or revoke the credential from a different, trusted device;
3. revoke any capture capability (see
   [`forensics-capabilities.md`](forensics-capabilities.md));
4. run the wipe workflow and close the session;
5. rebuild from a known-good image rather than trying to clean a live system in
   place;
6. record what was exposed and the rotation time in the private release record,
   never the secret value.
