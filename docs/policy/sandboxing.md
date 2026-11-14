# Sandboxing choices and limits

**Status:** Normative for the default private image. This document records the
sandboxing decision, why the default image does not pretend to have more
isolation than it does, and what an operator must still treat as trusted.

## 1. Decision

The baseline ships **Firejail** for optional, per-application sandboxing and
does **not** enable an AppArmor profile set by default.

| control | default | role |
| --- | --- | --- |
| Firejail (`firejail` package) | installed, not a boot service | operator-launched per-application sandbox |
| AppArmor | kernel support may exist; profiles are not shipped or enforced | future path-based MAC hardening, not a default claim |
| systemd unit isolation | packaged units, no custom unconfined service | least-privilege service accounts and unit settings where the package provides them |
| nftables ingress policy | enabled | layer-3/4 default-deny, not application isolation |
| capture capabilities | not granted | narrow `CAP_NET_RAW`/`CAP_NET_ADMIN` only if an operator grants them |

Firejail is not started at boot and does not wrap the whole desktop. A sandbox
exists only when an operator launches a program through it. The cyber frontend
does not spawn a privileged helper and does not silently wrap a tool.

## 2. Why Firejail

Firejail is a practical per-application tool for this image because it:

- uses Linux namespaces (mount, PID, network, IPC, UTS, user) and seccomp;
- can drop capabilities and restrict filesystem visibility for one process;
- works without a system-wide policy for every application;
- is available in the reviewed repositories and can be audited by an operator.

Recommended use is explicit, for example running an untrusted viewer or a
single lab utility with a private network namespace. Do not assume the whole
session is sandboxed because the package is installed.

### Limits

Firejail is not a kernel MAC system and is **not** a substitute for a
hardened host. In particular:

- it only constrains processes launched through it; an application started
  normally is not sandboxed;
- the Firejail launcher is a setuid helper on many distributions, so a local
  privilege-escalation bug in the launcher matters;
- namespace and seccomp profiles are not a defense against kernel
  vulnerabilities or hardware attacks;
- filesystem and network isolation depend on the profile and options chosen;
  the default profile is not a guarantee;
- it does not protect data that the sandboxed process is allowed to read, and
  it does not encrypt captures or erase data after use;
- a sandboxed process that is given `CAP_NET_RAW` or `CAP_NET_ADMIN`, or that
  is placed in the host network namespace, has correspondingly more power;
- it cannot make an unauthorized target authorized.

Treat Firejail as a damage-limitation layer for an explicit task, not as a
boundary that makes hostile code safe.

## 3. AppArmor

AppArmor is a path-based Linux Security Module. It can confine a program with a
per-profile policy and is useful when the same binary must be restricted across
launches. It is **not enabled or claimed by this image** because:

- the image does not ship a reviewed profile set for Hyprland, Quickshell,
  Calamares, NetworkManager, or the security tools;
- enabling the LSM without complete profiles would give a false sense of
  confinement and could break the installer or desktop;
- profile maintenance, boot parameters, and denial review are a separate
  hardening project with its own tests.

### If AppArmor is added later

A future change must, at minimum:

1. enable the LSM consistently in the boot command line and verify it in the
   running kernel;
2. ship a small, reviewed profile set and a documented complain/enforce
   transition;
3. test that the desktop, installer, NetworkManager, and the cyber frontend
   still work under enforcement;
4. log and review denials without exposing secrets;
5. document that AppArmor profiles constrain a process, not a malicious kernel,
   and that unconfined processes remain unconfined.

AppArmor limits are also real: a permissive profile, an unconfined sibling
process, a writable profile path, or a kernel bug can defeat the intended
boundary. It does not replace the firewall, least privilege, or data handling.

## 4. Service and capability isolation

The default service set is deliberately small (see
[`network-hardening.md`](network-hardening.md)). Packaged units keep their
upstream users and unit hardening where provided. The image does not add a
privileged capture daemon:

- pcap inspection through `tshark -r` needs no special capability;
- live capture may use `CAP_NET_RAW`/`CAP_NET_ADMIN` on the narrow helper, or a
  distribution capture group, as documented in
  [`forensics-capabilities.md`](forensics-capabilities.md);
- the frontend never invokes `sudo`, `pkexec`, or a service manager;
- no root is required by default for capture, and no capability is granted by
  this repository.

Capabilities are narrower than root but are still powerful. Revoke them when the
engagement ends, as described in the forensics document.

## 5. Verification and non-claims

`tests/hardening.sh` checks that Firejail is in the allowlist, that the
sandboxing document exists with the required limits, and that no boot-time
sandbox or privileged process spawner is added. The tests do **not** execute a
sandbox or prove that a profile contains a hostile program.

This image does not claim:

- that every application is sandboxed by default;
- that Firejail or AppArmor makes unauthorized activity safe;
- that a sandbox replaces written authorization, target scope, or data
  retention rules;
- that a kernel compromise is contained.
