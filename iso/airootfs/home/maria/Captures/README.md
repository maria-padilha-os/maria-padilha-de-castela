# Captures (sensitive)

This is the default local capture directory for the private image. Packet
captures, extracted files, and investigation notes can contain credentials,
tokens, private keys, and personal data.

- The directory is owner-only (`0700`); new files are created `0600` by the
  live-user shell defaults.
- Do not upload, paste, or attach a capture. The frontend has no upload path.
- Keep only what the written authorization requires.
- When finished, run `maria-wipe-captures` (dry run) and then
  `maria-wipe-captures --yes` to shred the files. Run `maria-clear-history --yes`
  in the same session to remove shell history. See
  `/usr/share/doc/maria-padilha/data-handling.md` or the repository document
  `docs/policy/data-handling.md`.

Secure overwrite is best-effort. On SSDs, copy-on-write filesystems, snapshots,
and remote storage, old blocks may survive; full-disk encryption and destruction
of the underlying media remain the only reliable controls.
