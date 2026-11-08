/*
 * Browser surface for the private cyber tabs.
 *
 * The surface is mounted only when the private build and feature flag are both
 * present. Rendering a tab is passive: it probes tool availability but never
 * starts a tool. Starting a tool requires a click and the runner's confirmed
 * path, which re-checks authorization and scope first.
 */

"use strict";

(function () {
    var state = {
        surface: null,
        activeTabId: "",
        lastStatus: ""
    };

    function el(tag, className, textValue) {
        var node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (typeof textValue === "string") {
            node.textContent = textValue;
        }
        return node;
    }

    function config() {
        var flags = window.MARIA_PADILHA_FLAGS || {};
        return {
            env: window.MARIA_PADILHA_ENV || {},
            flags: flags,
            buildMode: window.MARIA_PADILHA_BUILD ||
                (window.MARIA_PADILHA_BUILD_INFO &&
                    window.MARIA_PADILHA_BUILD_INFO.mode) ||
                "public",
            manifestUrl: window.MARIA_PADILHA_MANIFEST_URL || "manifest.json"
        };
    }

    function hostAdapter() {
        var host = window.MariaPadilhaCyberHost || {};
        return {
            probe: typeof host.probe === "function" ? host.probe : null,
            execute: typeof host.execute === "function" ? host.execute : null
        };
    }

    function showUnavailable(root, reason) {
        root.replaceChildren();
        var box = el("section", "mp-cyber-panel");
        box.appendChild(el("h1", "mp-cyber-panel-title", "Cyber extensions are not exposed"));
        box.appendChild(el("p", "mp-cyber-panel-copy",
            "This private surface is disabled for this build or session. The normal desktop dashboard is unchanged."));
        box.appendChild(el("p", "mp-cyber-status", reason || "feature flag is off"));
        root.appendChild(box);
    }

    function showError(root, error) {
        root.replaceChildren();
        var box = el("section", "mp-cyber-fallback");
        box.appendChild(el("h1", "mp-cyber-fallback-title", "Cyber surface failed to load"));
        box.appendChild(el("p", "mp-cyber-panel-copy", String(error && error.message ? error.message : error)));
        root.appendChild(box);
    }

    function statusLine(textValue) {
        state.lastStatus = textValue;
        var node = document.getElementById("mp-cyber-status");
        if (node) {
            node.textContent = textValue;
        }
    }

    function renderControls(container) {
        var auth = state.surface.authorization;
        var snapshot = auth.snapshot();

        var controls = el("div", "mp-cyber-controls");
        controls.id = "mp-cyber-controls";

        var ackLabel = el("label", "mp-cyber-checkbox");
        var ack = el("input");
        ack.type = "checkbox";
        ack.checked = snapshot.acknowledged;
        ack.addEventListener("change", function () {
            if (ack.checked) {
                var reference = window.prompt(snapshot.acknowledgement, snapshot.authorizationReference || "");
                var result = auth.acknowledge(reference || "");
                statusLine(result.ok ? "authorization acknowledged" : result.reason);
            } else {
                auth.withdrawAuthorization();
                statusLine("authorization withdrawn");
            }
            render();
        });
        ackLabel.appendChild(ack);
        ackLabel.appendChild(document.createTextNode(snapshot.acknowledgement));
        controls.appendChild(ackLabel);

        var labLabel = el("label", "mp-cyber-checkbox");
        var lab = el("input");
        lab.type = "checkbox";
        lab.checked = snapshot.labMode;
        lab.addEventListener("change", function () {
            var result = auth.setLabMode(lab.checked);
            statusLine(result.ok ? (lab.checked ? "lab mode enabled" : "lab mode disabled") : result.reason);
            render();
        });
        labLabel.appendChild(lab);
        labLabel.appendChild(document.createTextNode(snapshot.labModeLabel));
        controls.appendChild(labLabel);

        var scopeField = el("div", "mp-cyber-field");
        var scopeLabel = el("label", "mp-cyber-label", snapshot.targetScopeLabel);
        var scopeInput = el("input", "mp-cyber-input");
        scopeInput.type = "text";
        scopeInput.value = snapshot.scope;
        scopeInput.placeholder = state.surface.manifest.authorization.targetScopePlaceholder || "";
        scopeInput.addEventListener("change", function () {
            var result = auth.setTargetScope(scopeInput.value);
            statusLine(result.ok ? "target scope set" : result.reason);
            render();
        });
        scopeField.appendChild(scopeLabel);
        scopeField.appendChild(scopeInput);
        controls.appendChild(scopeField);

        var scope = el("div", "mp-cyber-scope", snapshot.scopeLabel);
        scope.setAttribute("data-armed", snapshot.canRun ? "true" : "false");
        controls.appendChild(scope);

        var actions = el("div", "mp-cyber-actions");
        var stop = el("button", "mp-cyber-button mp-cyber-button--danger", snapshot.stopLabel);
        stop.type = "button";
        stop.disabled = !snapshot.running;
        stop.addEventListener("click", function () {
            var result = state.surface.runner.stop();
            statusLine(result.reason);
            render();
        });
        actions.appendChild(stop);

        var clear = el("button", "mp-cyber-button", snapshot.clearLabel);
        clear.type = "button";
        clear.disabled = !snapshot.scope && snapshot.queuedTargets.length === 0;
        clear.addEventListener("click", function () {
            var result = state.surface.runner.clear();
            statusLine(result.reason);
            render();
        });
        actions.appendChild(clear);
        controls.appendChild(actions);

        container.appendChild(controls);
    }

    function fallbackBox(fallback) {
        var box = el("div", "mp-cyber-fallback");
        box.appendChild(el("h2", "mp-cyber-fallback-title", fallback.title));
        box.appendChild(el("p", "mp-cyber-panel-copy", fallback.message));
        box.appendChild(el("p", "mp-cyber-panel-copy", fallback.reason));
        box.appendChild(el("p", "mp-cyber-panel-copy", fallback.installHint));
        return box;
    }

    function renderPanel(container, tab) {
        var panel = el("section", "mp-cyber-panel");
        panel.id = "mp-cyber-panel";
        panel.setAttribute("aria-labelledby", "mp-cyber-panel-title");
        var heading = el("h1", "mp-cyber-panel-title", tab.title);
        heading.id = "mp-cyber-panel-title";
        panel.appendChild(heading);
        panel.appendChild(el("p", "mp-cyber-panel-copy", tab.description || ""));

        if (tab.policy && tab.policy.admitted === false) {
            panel.appendChild(fallbackBox({
                title: tab.title + " is excluded by policy",
                message: "This tab is visible for transparency but does not offer a launch control.",
                reason: tab.policy.reason,
                installHint: "Adding this tool requires a new policy review and template-removal test."
            }));
            container.appendChild(panel);
            return;
        }

        var prepared = state.surface.runner.prepare(tab.id);
        if (prepared.status === "missing-tool") {
            panel.appendChild(fallbackBox(prepared.fallback));
            container.appendChild(panel);
            return;
        }

        var run = el("button", "mp-cyber-button mp-cyber-button--accent", "Start " + tab.title + " (explicit)");
        run.type = "button";
        run.disabled = prepared.status !== "ready";
        run.addEventListener("click", function () {
            var result = state.surface.runner.start(tab.id, { confirmed: true });
            statusLine(JSON.stringify(result, null, 2));
            render();
        });
        panel.appendChild(run);

        var status = el("pre", "mp-cyber-status", state.lastStatus ||
            (prepared.status === "ready"
                ? "Ready. Review the target scope, then click Start."
                : prepared.reason));
        status.id = "mp-cyber-status";
        panel.appendChild(status);
        container.appendChild(panel);
    }

    function render() {
        var root = document.getElementById("mp-cyber-root");
        if (!root || !state.surface) {
            return;
        }
        root.replaceChildren();

        var header = el("header", "mp-cyber-header");
        header.appendChild(el("h1", "mp-cyber-title", state.surface.manifest.title));
        header.appendChild(el("span", "mp-cyber-namespace", state.surface.namespace));
        root.appendChild(header);

        root.appendChild(el("p", "mp-cyber-banner",
            state.surface.manifest.authorization.banner));

        renderControls(root);

        var nav = el("nav", "mp-cyber-tabs");
        nav.setAttribute("aria-label", "Cyber extension tabs");
        var tabs = state.surface.registry.list({ includeDisabled: true });
        tabs.forEach(function (tab) {
            var button = el("button", "mp-cyber-tab", tab.title);
            button.type = "button";
            button.disabled = !tab.enabled;
            button.setAttribute("aria-selected", tab.id === state.activeTabId ? "true" : "false");
            if (tab.status === "missing-tool") {
                button.title = tab.title + " is unavailable on this system";
            }
            button.addEventListener("click", function () {
                state.activeTabId = tab.id;
                state.lastStatus = "";
                render();
            });
            nav.appendChild(button);
        });
        root.appendChild(nav);

        var active = null;
        tabs.forEach(function (tab) {
            if (tab.id === state.activeTabId && tab.enabled) {
                active = tab;
            }
        });
        if (!active) {
            tabs.some(function (tab) {
                if (tab.enabled) {
                    active = tab;
                    state.activeTabId = tab.id;
                    return true;
                }
                return false;
            });
        }
        if (active) {
            renderPanel(root, active);
        } else {
            root.appendChild(el("p", "mp-cyber-panel-copy",
                "No cyber tab is enabled. Enable a tab explicitly when you are ready."));
        }
    }

    async function boot() {
        var root = document.getElementById("mp-cyber-root");
        if (!root) {
            return;
        }
        var cfg = config();
        var exposure = window.CyberRegistry.resolveSurfaceMode(cfg);
        if (!exposure.enabled) {
            showUnavailable(root, exposure.reason);
            return;
        }

        try {
            var response = await fetch(cfg.manifestUrl, { cache: "no-store" });
            if (!response.ok) {
                throw new Error("manifest request failed: " + response.status);
            }
            var manifest = window.CyberRegistry.loadManifest(await response.text());
            var adapter = hostAdapter();
            var registry = new window.CyberRegistry.TabRegistry(manifest);
            state.surface = {
                enabled: true,
                namespace: manifest.namespace,
                panelNamespace: manifest.panelNamespace,
                manifest: manifest,
                registry: registry,
                authorization: new window.CyberAuthorization.AuthorizationState(manifest.authorization),
                runner: null
            };
            state.surface.runner = new window.CyberRunner.ToolRunner({
                registry: registry,
                authorization: state.surface.authorization,
                probe: adapter.probe,
                execute: adapter.execute
            });
            state.activeTabId = (registry.list()[0] || {}).id || "";
            render();
        } catch (error) {
            showError(root, error);
        }
    }

    window.MariaPadilhaCyberApp = {
        boot: boot,
        state: state,
        render: render
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot, { once: true });
    } else {
        boot();
    }
}());
