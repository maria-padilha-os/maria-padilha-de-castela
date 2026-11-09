# Private cyber extension frontend

This is the exclusive, private frontend surface for security extensions. It is
**not** the normal desktop dashboard: it has its own namespace
(`maria-padilha.cyber`), its own panel namespace
(`maria-padilha.cyber.panels`), its own tab registry, and its own authorization
state.

The surface is source code in this repository and is copied into the image at
`/usr/share/maria-padilha/cyber/`. It is inert until a private build enables it.

## Exposure: private build + feature flag

Both conditions are required:

| input | value |
| --- | --- |
| build mode | `MARIA_PADILHA_BUILD=private` or `private-cyber` |
| feature flag | `MARIA_PADILHA_CYBER_FRONTEND=1` |

`resolveSurfaceMode()` in [`src/registry.js`](src/registry.js) returns
`enabled: false`, `namespace: null`, and `panelNamespace: null` for a public
build, the normal desktop session, or a private build with the flag off. No
manifest is loaded and no registry is created in that case.

For the browser shell, set `window.MARIA_PADILHA_BUILD` to `"private"` and
`window.MARIA_PADILHA_FLAGS = { cyberFrontend: true }` before loading
`src/app.js`. `index.html` intentionally leaves the flag off, so opening it
shows the disabled state until a private host enables it.

For the QML surface, instantiate `CyberShell` with:

```qml
CyberShell {
    buildMode: "private"
    cyberFrontendFlag: true
    // Optional host adapter:
    probe: function (tab) { /* return { available, command, reason } */ }
    executor: function (invocation) { /* start only on an explicit click */ }
}
```

## Manifest and tab registry

[`manifest.json`](manifest.json) is the single source of truth for the tabs:

| tab id | title | behavior |
| --- | --- | --- |
| `nmap` | Nmap | explicit, operator-started mapping |
| `set` | SET | registered but policy-blocked; no launch control |
| `forensics` | Wireshark / Forensics | capture-file inspection, no auto-capture |
| `lab-vm` | Lab / VM | isolated launcher, no auto-boot |

Every tab declares `"autoRun": false`. The manifest loader rejects a tab that
tries to auto-run, uses a panel outside the panel namespace, omits a shared
control, or duplicates an id.

Tabs can be enabled and disabled at runtime through `TabRegistry`:

```js
const registry = new TabRegistry(manifest);
registry.disable("forensics");
registry.enable("forensics");
registry.list({ includeDisabled: true });
```

Disabling a tab removes it from the active list but keeps it visible to
operators as disabled. The SET tab has `"policy.admitted": false`; the runner
returns `policy-blocked` and never renders a launch control for it.

## Shared safety controls

Every offensive panel uses `ToolPanelFrame.qml`, which renders all of these:

- the authorization banner from the manifest;
- the authorized lab-mode switch;
- the target-scope entry and always-visible scope indicator;
- the Stop and Clear actions.

A panel cannot omit a control by accident because the controls live in the
shared frame rather than in each tab. The browser surface uses the same manifest
text and state model in `src/app.js`.

Authorization is fail-closed:

1. written authorization must be acknowledged with a reference;
2. lab mode cannot be enabled until that acknowledgement exists;
3. a bounded target scope is required (wildcards and `0.0.0.0/0` are refused);
4. Stop cancels the current operation and keeps the scope for inspection;
5. Clear removes the scope and every queued target.

## Nmap extension

The Nmap tab has a target, a documented profile, a small allowlisted option set,
and a separate per-scan "authorized lab/private network" confirmation. The
target and profile are validated locally by [`src/nmap.js`](src/nmap.js) before
the runner is called. There is no free-form argument field and no default scan.

### Targets

`validateTarget()` canonicalizes a target and refuses anything outside the
following allowlist unless a caller explicitly passes `{ allowPublic: true }`
(the UI never does):

- IPv4 RFC 1918 ranges, loopback, link-local, shared address space, and the
  documentation/benchmark ranges used by lab fixtures (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`);
- IPv6 loopback, unique-local (`fc00::/7`), link-local, and documentation
  (`2001:db8::/32`);
- single-label lab names and names under approved suffixes such as `.localhost`,
  `.local`, `.lan`, `.lab`, `.test`, `.example`, `.invalid`, `.internal`, and
  `.home.arpa`.

IPv4 CIDRs are canonicalized to their network address. Hostnames are lowercased
and a trailing dot is removed. Leading-zero IPv4 octets are refused because a
value such as `010` is ambiguous between decimal and octal. A target containing
whitespace, shell control characters, a leading dash, or multiple targets in one
field is refused. When a scope is supplied, the target must be contained in that
scope.

### Profiles and options

Profiles only use unprivileged Nmap scans. There is no SYN scan, UDP scan, OS
detection, `-A`, NSE script selection, or privilege escalation.

| profile | flags | options |
| --- | --- | --- |
| `discovery` | `-sn` | `reason` |
| `tcp-connect` | `-sT` | `no-ping`, `open-only`, `reason`, `top-ports-100` |
| `service` | `-sT -sV` | `no-ping`, `open-only`, `reason`, `version-light`, `top-ports-100` |
| `top-100` | `-sT --top-ports 100` | `no-ping`, `open-only`, `reason` |

| option | flag |
| --- | --- |
| `no-ping` | `-Pn` |
| `open-only` | `--open` |
| `reason` | `--reason` |
| `version-light` | `--version-light` |
| `top-ports-100` | `--top-ports 100` |

`buildScanRequest()` returns a command and an argv array, always adds `-oX -` so
XML goes to stdout, and sets `shell: false`. The host executor must pass that
argv directly to Nmap (for example with an argv-style spawn API); it must never
join it into a shell command. `prepareScan()` additionally requires
`authorizedLab: true` and a bounded scope.

### XML results

`parseNmapXml()` reads Nmap's XML into hosts, addresses, hostnames, ports, port
states, services (name/product/version/extrainfo/tunnel), scripts, and run
statistics. `interpretScanResult()` also accepts an executor result containing
`stdout`/`xml`, `stderr`, a non-zero exit code, or a timeout status. Malformed
XML, DTD entity declarations, unknown entities, Nmap `exit="error"`, and
`exit="timeout"` fail closed with an `errors` array. `formatScanResult()` turns
the result into the plain-text host/port/service summary shown by both surfaces.
Timeouts are reported explicitly and never become an empty "success".

## Missing tools and no auto-run

The runner probes tool availability through a host-supplied function. A missing
tool produces a structured fallback with the missing command, the reason, and an
install hint. The tab stays enabled and keeps the shared controls; the launch
control is not offered. No exception is thrown and no command is executed.

`ToolRunner` never probes or executes on construction. `prepare()` probes but
does not execute. `start()` executes only when the caller passes
`{ confirmed: true }`, the tab is enabled, the tool is present, the tab is
admitted by policy, written authorization is acknowledged, lab mode is on, and a
bounded scope is set. The executor is injected by the host; this repository does
not ship a privileged runner.

## Theme

[`src/theme.css`](src/theme.css) contains semantic aliases only:

```css
--cyber-color-surface: var(--mp-color-surface, Canvas);
--cyber-color-text: var(--mp-color-text, CanvasText);
--cyber-color-accent: var(--mp-color-accent, Highlight);
```

The desktop shell can override the `--mp-*` tokens. If it does not, the
browser's system colors are used, so light, dark, and high-contrast themes work.
Components reference `--cyber-*` variables; there are no palette literals in the
CSS or QML. `CyberTheme.qml` derives its defaults from `SystemPalette` and
exposes writable `token*` properties for a host override.

## Tests

```sh
cd frontend/cyber && npm test
# or from the repository root:
node --test frontend/cyber/test/*.test.cjs
bash tests/cyber-frontend.sh
```

The tests cover manifest loading (including rejected manifests), tab
enable/disable, missing-tool fallback, the no-auto-run rule, authorization and
lab-mode state, the browser/QML shared controls, and the no-hardcoded-palette
rule. The Nmap tests add fixture XML for success, error, and timeout results plus
argument validation, public-target refusal, scope containment, option/profile
allowlists, and a check that the module ships no process spawner or network
client. They never run a live scan.

## Boundary

Use this surface only on systems you own or for which you hold explicit, written
permission. The surface does not grant authorization, does not discover targets,
does not bundle phishing templates, and does not start a scan, capture, VM, or
service by itself.
