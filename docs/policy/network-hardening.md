# Network, service, and telemetry hardening

**Status:** Normative for the default private image. These controls are static
build inputs; the test suite checks them without root, a running system, or a
service manager.

The default install is conservative: it blocks new inbound connections, starts
only the units needed for the live desktop, sends no telemetry, and starts no
offensive tool automatically. An operator can still start an installed tool
manually, after the authorized-use and target-scope gates in the frontend.

## 1. Default-deny inbound firewall

The image ships one nftables ruleset at `/etc/nftables.conf` and enables
`nftables.service` at boot. `iso/packages.x86_64` includes the `nftables`
package, and the installer core group lists it as part of the baseline.

| hook | default | notes |
| --- | --- | --- |
| input | `drop` | New inbound connections are refused. |
| forward | `drop` | The live image is not a router. |
| output | `accept` | Explicitly started tools and package installation need egress. |

The only input exceptions are:

- loopback traffic (`iifname "lo"`);
- replies belonging to connections this host initiated
  (`ct state established,related`), with invalid packets dropped;
- DHCP client replies on UDP 68/546 (the host runs a client, not a DHCP server);
- ICMP/ICMPv6 error messages needed for path-MTU discovery and established
  flows. Inbound echo requests are not accepted.

There is no inbound `tcp dport` accept rule, no port-forwarding rule, and no NAT
rule. An operator who needs a service reachable must add an explicit, reviewed
firewall rule; that is a deliberate privileged change and is outside the
default image.

### Limits

The firewall is a layer-3/4 packet filter, not an application firewall, IDS, or
data-loss-prevention control. Output is allowed, so it does not prevent an
explicitly started tool, a compromised process, or an operator from sending data
out. Root can flush or replace the ruleset. It does not isolate applications
from each other; see [`sandboxing.md`](sandboxing.md) for that boundary.

## 2. Minimal service enablement

The active profile enables only:

| unit | target | why |
| --- | --- | --- |
| `greetd.service` | `graphical.target` | the supported greeter |
| `NetworkManager.service` | `multi-user.target` | network connectivity |
| `nftables.service` | `multi-user.target` | load the default-deny ruleset |

`display-manager.service` points at `greetd.service` for compatibility. No
socket, timer, path, or other `.wants` link is shipped.

Common listeners that are installed or may be pulled in are masked with a
`/dev/null` unit symlink so a package or D-Bus activation cannot start them:

- Bluetooth (`bluetooth.service` and `dbus-org.bluez.service`);
- OpenSSH server (`sshd.service`, `sshd.socket`);
- libvirt and its modular daemons (`libvirtd*`, `virt*qemud*`,
  `virt*networkd*`, `virt*storaged*`, and related sockets);
- Docker/Podman (`docker.service`, `podman.socket`);
- Avahi, CUPS, and rpcbind.

`openssh` remains installed for the client, and `bluez` remains installed for
optional peripherals, but neither is a boot-time server. A user who needs a
masked service must explicitly unmask and enable it; that is not the default and
is not done by the installer or the frontend.

### Limits

Masking prevents normal boot and activation by packaged units, not a privileged
operator from removing the mask. The live image still has a full root-capable
installer workflow; the service policy is a safe default, not an unbypassable
kernel control.

## 3. No telemetry

The image has no analytics, crash-report uploader, popularity contest, update
phone-home, or vendor telemetry agent. Specific controls:

- NetworkManager connectivity checking is disabled in
  `/etc/NetworkManager/conf.d/10-maria-private.conf`. This removes the periodic
  HTTP probe to a third-party endpoint.
- `journald` uses volatile storage (`Storage=volatile`) and does not forward to
  syslog or wall. Live logs do not survive reboot.
- `systemd-coredump` is disabled (`Storage=none`, `ProcessSizeMax=0`) so crash
  dumps cannot retain credentials or captured payloads.
- `iso/packages.x86_64` is an allowlist; known telemetry agents are not present.
- The cyber frontend has no upload, analytics, or remote-report path. It does
  not start a capture, scan, VM, or service automatically.

### Limits

A tool that the operator explicitly starts may itself contact the network; the
firewall does not block egress and this repository does not audit every
upstream application's optional update check. Do not run a tool whose network
behaviour is not acceptable for the engagement. A future package addition must
be reviewed for telemetry before it enters the allowlist.

## 4. No automatic offensive tooling

Nmap, Wireshark/`tshark`, `tcpdump`, SET, and the lab/VM launcher are installed
for explicit, operator-initiated work only. The default image ships:

- no service, timer, socket, path unit, cron job, shell profile, or desktop
  autostart that runs a scanner, capture, VM, or dual-use launcher;
- no target list populated from the local network or from captured traffic;
- no default scan, capture, injection, replay, or upload;
- no Calamares post-install hook that starts a tool.

The frontend's manifest sets `"autoRun": false` for every tab and requires the
authorization, lab-mode, target-scope, and per-tool confirmation gates. The
installer group chooser installs packages only; it does not start them.

## 5. Verification

`tests/hardening.sh` checks the firewall policy, the enabled-unit allowlist,
the masks, the connectivity/journald/coredump settings, the absence of
telemetry packages, and the no-auto-run rules. `tests/iso.sh` and
`tests/all.sh` run it as part of the repository suite. The checks are static and
do not run `systemctl`, `nft`, `sudo`, or any privileged command.

On a running image, an operator can inspect the live state with non-privileged
diagnostics such as `ss -lntup` and the journal. Applying a new ruleset is a
privileged action and must be reviewed like any other network change.
