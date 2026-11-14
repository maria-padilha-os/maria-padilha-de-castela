# Isolated lab/VM network and snapshot policy

**Status:** Normative for the private cyber frontend's Lab / VM panel. This is an
engineering safety boundary, not legal advice and not a claim that a VM network
makes an unauthorized target authorized.

> **AUTHORIZED USE ONLY.** Use the lab/VM panel only for systems, media, and
> networks you own or are explicitly authorized in writing to test. The panel
> does not grant authorization, does not discover targets, and does not start a
> VM by itself.

## 1. Default: LAB ONLY, no host bridge

The Lab / VM panel generates a libvirt domain on the `mp-lab-isolated` network by
default. The generated network definition has **no host bridge** and no route to
the host LAN. It uses libvirt's isolated forwarding mode:

```xml
<network>
  <name>mp-lab-isolated</name>
  <description>LAB ONLY: isolated libvirt network; no host forwarding or LAN route.</description>
  <forward mode='none'/>
  <ip address='10.213.0.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='10.213.0.100' end='10.213.0.199'/>
    </dhcp>
  </ip>
</network>
```

The domain gets one virtio interface on that network:

```xml
<interface type='network'>
  <source network='mp-lab-isolated'/>
  <model type='virtio'/>
</interface>
```

There is no `<forward mode='nat'/>`, `<forward mode='route'/>`,
`<forward mode='bridge'/>`, or host bridge source in the default domain or
network XML. The network is a libvirt-managed virtual segment, not a host LAN
bridge. The guest can talk to other guests on the same lab network, but not to
the host's real network through this interface.

The generated domain also has no host PCI/USB passthrough, no shared folder, no
host block device, and no automatic start. The operator must create the qcow2
disk first and explicitly ask the host adapter to define the generated XML.

## 2. Network labels

Every network choice carries an explicit label. The default is the only network
the panel offers without a warning acknowledgement:

| id | label | isolated | host bridge | default |
| --- | --- | --- | --- | --- |
| `isolated` | `LAB ONLY: isolated network (no host bridge, no LAN route)` | yes | no | yes |
| `host-lan` | `HOST LAN (NOT ISOLATED): explicit warning required` | no | yes, operator-supplied | no |

The isolated label begins with **LAB ONLY**. The host-LAN label says **HOST LAN**
and **NOT ISOLATED**; it must never be presented as a lab network.

## 3. Host LAN is an explicit, warned exception

Attaching a VM to the host LAN removes the main isolation property. The panel
shows this warning before the launch control becomes ready:

> **WARNING:** Attaching this VM to the host LAN removes lab isolation. The guest
> can reach real hosts, services, and the internet. Do this only on a network you
> own or are explicitly authorized to use, and take a clean snapshot before
> changing the VM network.

The host-LAN path requires all of the following:

1. the operator selects `host-lan`, which displays the warning;
2. the operator ticks a separate host-LAN acknowledgement;
3. the operator supplies the name of an existing host bridge; there is no
   default bridge name;
4. the shared written-authorization, lab-mode, and bounded-scope gates pass;
5. the operator clicks the explicit define action.

With no bridge name, the plan fails closed and no domain XML is returned. A
confirmed host-LAN plan is labelled **NOT ISOLATED** in the generated domain and
in the panel result. It is never the default path.

## 4. Snapshot guidance

Use a qcow2 disk so libvirt can take internal snapshots. The panel requires a
disk path ending in `.qcow2` and shows this guidance before the define action:

1. Create a clean baseline snapshot while the VM is powered off.
2. Keep the baseline snapshot immutable; do not install tools or open untrusted
   media in it.
3. Revert to the clean snapshot after every exercise, and verify the disk is
   clean before the next target.
4. Take a fresh snapshot before changing the VM network, installing media, or
   starting an untrusted target.
5. Keep snapshots and disks local. Never store credentials, captured secrets, or
   production data in a snapshot.

The documented operator flow, using the unprivileged session connection where
available, is:

```sh
virsh -c qemu:///session snapshot-create-as <domain> clean-baseline "clean lab baseline"
virsh -c qemu:///session snapshot-revert <domain> clean-baseline
```

These are operator instructions, not commands run by this repository's tests.
Use the connection and authorization appropriate to your own libvirt setup, and
do not use root for the panel or the test suite.

## 5. Host adapter contract

`frontend/cyber/src/lab.js` is a pure generator and validator. It does not
connect to libvirt, call `virsh`, spawn QEMU, write a disk, or modify a network.
The host adapter receives a runner invocation containing:

- `metadata.action = "define-domain"`;
- `metadata.domainXml`, the generated libvirt domain;
- `metadata.networkXml`, the isolated network definition or `null` for the
  warned host-LAN path;
- `metadata.network` and `metadata.isolated`;
- `metadata.hostBridge`, populated only for a confirmed host-LAN plan;
- `metadata.hostLanWarning`, empty for the isolated path;
- `metadata.snapshotGuidance`;
- `metadata.autoStart = false`.

The host adapter must:

- define the network before the domain on the isolated path;
- pass XML through an argv-style libvirt API or a no-shell `virsh` invocation;
- call libvirt only after the panel's explicit click and the runner's
  confirmation gate;
- never enable autostart on the network or domain;
- never start the VM as part of the define action;
- refuse a host-LAN attachment without the warning acknowledgement and an
  explicit existing bridge;
- keep the repository and tests free of any privileged command.

## 6. Tests and CI boundary

`frontend/cyber/test/lab.test.cjs` validates the generated domain XML, the
isolated network definition, the absence of host forwarding and host bridges by
default, the host-LAN warning and confirmation gate, input validation, and the
snapshot guidance. `tests/cyber-frontend.sh` also checks the mirrored image
files and labels.

The tests **do not start a VM**, define a real libvirt network, create a disk,
load a kernel module, or touch the host network. They run as the normal
unprivileged user and do not need libvirt, QEMU, or a desktop session. CI must
remain this way: it validates XML and policy only, never live virtualization.
