# Wireshark/forensics capabilities and revocation

**Status:** Normative for the Wireshark/forensics tab. This document describes
the privileges a capture needs and how to remove them. It is not an instruction
to grant privileges on a host, and the repository's build, installer, and tests
never run any of the commands below.

The forensics panel is **read-only by default**:

- it opens an existing pcap/pcapng file with `tshark -r ... -T json`;
- it does not modify or rewrite the capture;
- it has no packet injection, spoofing, replay, or transmission path;
- it never uploads, streams, or posts a capture to a remote endpoint;
- it does not start a capture on load, on tab activation, or from a timer;
- starting a capture or opening a file requires an explicit operator action and
  the shared authorization gates.

## 1. Commands

| operation | command | writes |
| --- | --- | --- |
| inspect a capture | `tshark -n -r <file> -T json` | nothing; the file is opened read-only |
| start a capture | `tshark -n -i <interface> [-f <allowlisted filter>] -w <new file> -F pcapng` | one new local pcapng file |
| stop a capture | `SIGINT` or `SIGTERM` to the capture process | nothing |

The frontend builds an argv array and sets `shell: false`. The host executor must
pass that argv directly to `tshark`; it must not join the values into a shell
command. Interface names, paths, and capture filters are validated locally, but
the host remains responsible for checking that the file does not already exist
and for applying the stop signal to the process it started.

## 2. Capabilities

A local pcap file can be inspected **without any special capability**. Live
capture is the only operation that needs more:

| capability | why it may be needed | default |
| --- | --- | --- |
| `CAP_NET_RAW` | open a packet socket and receive frames | not granted |
| `CAP_NET_ADMIN` | promiscuous or monitor-mode capture, interface configuration | not granted |

**No root is required by default.** The panel never invokes `sudo`, `pkexec`, a
setuid wrapper, a service manager, or a package manager. If the operator's
account lacks the capture capability, capture fails closed with a permission
error and the panel shows the error; pcap inspection still works.

### 2.1 Preferred unprivileged setup

Use the capabilities on the narrow helper that opens the capture device
(commonly `/usr/bin/dumpcap`, which `tshark` uses for live capture), not on the
whole desktop session and not on `tshark` with broad privileges. A distribution
may instead provide a dedicated `wireshark` group and a file-capability helper.

An administrator may, outside this repository, attach only the two capture
capabilities to that helper:

```sh
# Documentation only. Do not run this from the repository, the image build, or
# the test suite.
setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
getcap /usr/bin/dumpcap
```

If the distribution uses the group model, add only the operator account to the
capture group and start a fresh session so the group membership takes effect.
Do not make the helper world-writable and do not grant `CAP_SYS_ADMIN`.

### 2.2 Root

Running the whole desktop as root is not supported and is not a default. A
host may offer an explicit, separately reviewed privileged capture service, but
this repository does not ship one. The panel itself contains no privileged
process spawner.

## 3. Revocation

Revoke the capability when capture is no longer needed, after an engagement, or
before handing the machine to another operator.

```sh
# Documentation only. These are operator/administrator steps.
getcap /usr/bin/dumpcap
setcap -r /usr/bin/dumpcap
getcap /usr/bin/dumpcap          # must print nothing for the helper
```

If the distribution uses a capture group instead of file capabilities:

```sh
# Documentation only. Replace the account and group with the local names.
gpasswd -d <operator> wireshark
```

Then:

1. terminate any running capture (the panel's Stop action sends `SIGINT`);
2. log out and back in, or restart the session, so the kernel drops the old
   capability and group credentials;
3. re-check `getcap` and the session's capability set;
4. remove or archive local captures according to the engagement's retention
   rules; captures are not deleted automatically by this panel.

Removing the capability affects only live capture. Read-only pcap inspection
continues to work.

## 4. Capture files and sensitive payloads

Captures routinely contain credentials, tokens, cookies, private keys, personal
data, and material that is sensitive or regulated. Treat every capture as
sensitive evidence:

- keep the file local; the panel has no upload function and no network client;
- store it with owner-only permissions (`0600`) and encrypt it at rest where the
  engagement requires it;
- do not paste a raw capture into a ticket, chat, or report;
- use the redacted summary, not the raw packet bytes, for screenshots and notes;
- delete or archive the file according to the written authorization's retention
  and destruction terms.

The summary parser replaces payload fields (`data`, `tcp.payload`,
`http.file_data`, and similar) with `[REDACTED]`. It also redacts `Authorization`,
`Proxy-Authorization`, `Cookie`, `Set-Cookie`, `Basic`/`Bearer`/`Digest`
credentials, password/token/secret/API-key assignments, URL user-info, and
private-key blocks. If payload or a sensitive field is present, the panel emits
a warning and shows that the packet was redacted. These controls reduce
accidental disclosure; they do not make a capture safe to publish. The raw file
is still sensitive and must stay inside the authorized scope.

## 5. Host adapter contract

The host supplies only two optional functions to the surface:

- `probe(tab)` returns tool availability (`tshark` here); it must not capture;
- `execute(invocation)` runs the validated argv only on an explicit click.

An optional `stop` function may stop the process that `execute` started. The
runner calls it only when the operator presses Stop; no timer or visibility
change calls it. The invocation metadata for a capture contains
`action: "capture-start"`, `interface`, `outputPath`, `stopSignal: "SIGINT"`,
`uploads: false`, and `packetInjection: false`. A pcap open contains
`action: "pcap-open"`, `readOnly: true`, and `uploads: false`.

The executor must:

1. verify the capture path does not already exist and is inside the operator's
   chosen capture directory;
2. keep the capture file owner-only (`0600`);
3. send `SIGINT` (not `SIGKILL`) to stop a capture and wait briefly for tshark
   to flush the file;
4. never add an upload, network, injection, or privilege-escalation step.

## 6. Tests

`frontend/cyber/test/forensics.test.cjs` uses a **generated pcap fixture**
(`test/fixtures/generate-pcap.cjs` writes a deterministic Ethernet/IPv4/TCP/HTTP
packet with synthetic credentials). The tests never open an interface, never
run `tshark`, and never capture live traffic. They check the fixture magic,
interface and path validation, the fixed capture/open/stop argv, explicit
confirmation and authorization gates, refusal of upload/injection fields,
redaction of headers and payloads, and failure handling for malformed,
timed-out, and failed tshark results.
