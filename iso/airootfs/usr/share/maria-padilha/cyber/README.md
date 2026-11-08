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
rule.

## Boundary

Use this surface only on systems you own or for which you hold explicit, written
permission. The surface does not grant authorization, does not discover targets,
does not bundle phishing templates, and does not start a scan, capture, VM, or
service by itself.
