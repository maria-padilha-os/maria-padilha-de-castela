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
        lastStatus: "",
        nmap: {
            target: "",
            profile: "tcp-connect",
            options: {},
            authorizedLab: false,
            resultText: ""
        },
        set: {
            confirmed: false,
            resultText: ""
        },
        forensics: {
            interface: "",
            filter: "none",
            capturePath: "",
            captureConfirmed: false,
            captureActive: false,
            captureResultText: "",
            openPath: "",
            openConfirmed: false,
            openResultText: ""
        }
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
            execute: typeof host.execute === "function" ? host.execute : null,
            stop: typeof host.stop === "function" ? host.stop : null,
            interfaces: typeof host.interfaces === "function"
                ? host.interfaces()
                : (Array.isArray(host.interfaces) ? host.interfaces : [])
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

    function nmapModule() {
        return window.CyberNmap || null;
    }

    function nmapRequest() {
        var Nmap = nmapModule();
        if (!Nmap) {
            return {ok: false, reason: "the Nmap helper module is not loaded"};
        }
        var snapshot = state.surface.authorization.snapshot();
        return Nmap.prepareScan({
            target: state.nmap.target,
            profile: state.nmap.profile,
            options: state.nmap.options,
            scope: snapshot.scope,
            authorizedLab: state.nmap.authorizedLab
        });
    }

    function fieldBox(labelText, control) {
        var box = el("div", "mp-cyber-field");
        box.appendChild(el("label", "mp-cyber-label", labelText));
        box.appendChild(control);
        return box;
    }

    function setModule() {
        return window.CyberSet || null;
    }

    function setRequest() {
        var Set = setModule();
        if (!Set) {
            return {ok: false, reason: "the SET helper module is not loaded"};
        }
        return Set.prepareLaunch({
            confirmed: state.set.confirmed,
            authorization: state.surface.authorization.snapshot()
        });
    }

    function renderSetPanel(panel, tab, prepared) {
        var Set = setModule();
        if (!Set) {
            panel.appendChild(fallbackBox({
                title: "SET helper unavailable",
                message: "The SET launcher/status module was not loaded, so no launch control is offered.",
                reason: "src/set.js is missing",
                installHint: "Restore the reviewed frontend file and reload the surface."
            }));
            return;
        }

        var authSnapshot = state.surface.authorization.snapshot();
        var available = prepared.status !== "missing-tool" &&
            state.surface.registry.get("set").toolAvailable === true;
        var report = Set.statusReport({
            available: available,
            command: "setoolkit",
            reason: prepared.status === "missing-tool"
                ? (prepared.fallback && prepared.fallback.reason) || prepared.reason
                : "SET is present"
        });

        panel.appendChild(el("p", "mp-cyber-error",
            authSnapshot.dualUseWarning || Set.DUAL_USE_WARNING));
        panel.appendChild(el("p", "mp-cyber-panel-copy",
            report.title + ": " + report.message));
        panel.appendChild(el("p", "mp-cyber-panel-copy",
            "This panel asks for no target, template, landing page, credential harvester, or payload. SET is launched with no arguments; any later action inside the tool remains the operator's responsibility and must stay inside the authorized scope."));

        if (prepared.status === "missing-tool") {
            panel.appendChild(fallbackBox(prepared.fallback || report));
            containerStatus(panel, prepared.reason);
            return;
        }

        var confirmLabel = el("label", "mp-cyber-checkbox");
        var confirm = el("input");
        confirm.type = "checkbox";
        confirm.id = "mp-set-launch-confirmed";
        confirm.checked = state.set.confirmed;
        confirm.addEventListener("change", function () {
            state.set.confirmed = confirm.checked;
            render();
        });
        confirmLabel.appendChild(confirm);
        confirmLabel.appendChild(document.createTextNode(
            authSnapshot.setConfirmationLabel ||
                "I confirm this SET launch is limited to systems I own or am explicitly authorized in writing to test."));
        panel.appendChild(confirmLabel);

        var request = setRequest();
        var validation = el("p", "mp-cyber-error", request.ok ? "" : request.reason);
        validation.hidden = request.ok;
        panel.appendChild(validation);

        var run = el("button", "mp-cyber-button mp-cyber-button--accent", "Launch SET (explicit)");
        run.type = "button";
        run.id = "mp-set-launch";
        run.disabled = prepared.status !== "ready" || !request.ok;
        run.addEventListener("click", function () {
            var plan = setRequest();
            if (!plan.ok) {
                state.lastStatus = plan.reason;
                render();
                return;
            }
            var result = state.surface.runner.start("set", {
                confirmed: true,
                args: plan.args,
                metadata: {
                    launch: "explicit",
                    generatedContent: false
                }
            });
            if (result.status !== "started") {
                state.lastStatus = result.status +
                    (result.reason ? ": " + result.reason : "");
                render();
                return;
            }
            state.set.resultText =
                "SET launch requested by explicit operator action. No target, template, or payload was supplied.";
            state.lastStatus = "SET launch requested.";
            render();
        });
        panel.appendChild(run);

        var resultBox = el("pre", "mp-cyber-status", state.set.resultText);
        resultBox.id = "mp-set-result";
        panel.appendChild(resultBox);

        containerStatus(panel, state.lastStatus ||
            (prepared.status === "ready"
                ? "Ready. Review the authorized scope, acknowledge authorization, enable lab mode, tick the confirmation, then click Launch SET."
                : prepared.reason));
    }

    function containerStatus(panel, textValue) {
        var status = el("pre", "mp-cyber-status", textValue);
        status.id = "mp-cyber-status";
        panel.appendChild(status);
    }

    function forensicsModule() {
        return window.CyberForensics || null;
    }

    function forensicsCaptureRequest() {
        var Forensics = forensicsModule();
        if (!Forensics) {
            return {ok: false, reason: "the forensics helper module is not loaded"};
        }
        return Forensics.prepareCapture({
            confirmed: state.forensics.captureConfirmed,
            authorizedLab: state.forensics.captureConfirmed,
            authorization: state.surface.authorization.snapshot(),
            interface: state.forensics.interface,
            outputPath: state.forensics.capturePath,
            filter: state.forensics.filter
        });
    }

    function forensicsOpenRequest() {
        var Forensics = forensicsModule();
        if (!Forensics) {
            return {ok: false, reason: "the forensics helper module is not loaded"};
        }
        return Forensics.prepareOpen({
            confirmed: state.forensics.openConfirmed,
            authorizedLab: state.forensics.openConfirmed,
            authorization: state.surface.authorization.snapshot(),
            capturePath: state.forensics.openPath
        });
    }

    function renderForensicsPanel(panel, tab, prepared) {
        var Forensics = forensicsModule();
        if (!Forensics) {
            panel.appendChild(fallbackBox({
                title: "Forensics helper unavailable",
                message: "The forensics capture/parser module was not loaded, so no capture or open control is offered.",
                reason: "src/forensics.js is missing",
                installHint: "Restore the reviewed frontend file and reload the surface."
            }));
            return;
        }

        var fs = state.forensics;
        var authSnapshot = state.surface.authorization.snapshot();
        var captureValidation = el("p", "mp-cyber-error", "");
        var captureStatus = el("pre", "mp-cyber-status", fs.captureResultText);
        var openValidation = el("p", "mp-cyber-error", "");
        var openStatus = el("pre", "mp-cyber-status", fs.openResultText);

        panel.appendChild(el("p", "mp-cyber-error",
            authSnapshot.sensitivePayloadWarning ||
            "Captures can contain credentials, tokens, cookies, private keys, and personal data. Payloads are redacted from the summary, but the raw capture remains sensitive. Never upload or auto-transmit a capture."));
        panel.appendChild(el("p", "mp-cyber-panel-copy",
            "Live capture needs CAP_NET_RAW/CAP_NET_ADMIN on the capture helper, or a distribution capture group. This panel never uses root by default and never grants capabilities. Opening a local pcap needs no special capability."));

        panel.appendChild(el("h2", "mp-cyber-panel-title", "Live capture (explicit)"));

        var interfaceBox = el("div", "mp-cyber-field");
        var interfaceInput = el("input", "mp-cyber-input");
        interfaceInput.type = "text";
        interfaceInput.value = fs.interface;
        interfaceInput.placeholder = "explicit interface (e.g. lo or eth0)";
        interfaceInput.setAttribute("list", "mp-forensics-interfaces");
        var interfaceList = el("datalist");
        interfaceList.id = "mp-forensics-interfaces";
        var interfaces = Forensics.normalizeInterfaces(
            state.surface.interfaces || []
        ).interfaces;
        interfaces.forEach(function (entry) {
            var option = el("option");
            option.value = entry.name;
            option.label = entry.description || entry.name;
            interfaceList.appendChild(option);
        });
        interfaceBox.appendChild(interfaceInput);
        interfaceBox.appendChild(interfaceList);
        panel.appendChild(fieldBox("Interface", interfaceBox));

        var capturePathInput = el("input", "mp-cyber-input");
        capturePathInput.type = "text";
        capturePathInput.value = fs.capturePath;
        capturePathInput.placeholder = "/home/operator/captures/lab.pcapng";
        capturePathInput.addEventListener("input", function () {
            fs.capturePath = capturePathInput.value;
            refreshCapture();
        });
        panel.appendChild(fieldBox("New local capture path", capturePathInput));

        var filterSelect = el("select", "mp-cyber-input");
        Forensics.listCaptureFilters().forEach(function (filter) {
            var option = el("option", "", filter.label);
            option.value = filter.id;
            option.selected = filter.id === fs.filter;
            filterSelect.appendChild(option);
        });
        filterSelect.addEventListener("change", function () {
            fs.filter = filterSelect.value;
            refreshCapture();
        });
        panel.appendChild(fieldBox("Capture filter (allowlisted)", filterSelect));

        var captureConfirmLabel = el("label", "mp-cyber-checkbox");
        var captureConfirm = el("input");
        captureConfirm.type = "checkbox";
        captureConfirm.id = "mp-forensics-capture-confirmed";
        captureConfirm.checked = fs.captureConfirmed;
        captureConfirm.addEventListener("change", function () {
            fs.captureConfirmed = captureConfirm.checked;
            refreshCapture();
        });
        captureConfirmLabel.appendChild(captureConfirm);
        captureConfirmLabel.appendChild(document.createTextNode(
            authSnapshot.captureConfirmationLabel ||
            "I confirm this capture is limited to traffic, systems, and media I own or am explicitly authorized in writing to examine."));
        panel.appendChild(captureConfirmLabel);

        panel.appendChild(captureValidation);

        var captureActions = el("div", "mp-cyber-actions");
        var startCapture = el("button", "mp-cyber-button mp-cyber-button--accent",
            "Start capture (explicit)");
        startCapture.type = "button";
        startCapture.addEventListener("click", function () {
            var request = forensicsCaptureRequest();
            if (!request.ok) {
                refreshCapture();
                return;
            }
            var result = state.surface.runner.start("forensics", {
                confirmed: true,
                args: request.args,
                metadata: {
                    action: "capture-start",
                    interface: request.interface,
                    outputPath: request.outputPath,
                    captureFilter: request.captureFilter,
                    stopSignal: request.stopSignal,
                    readOnly: false,
                    uploads: false,
                    packetInjection: false
                }
            });
            if (result.status !== "started") {
                state.lastStatus = result.status +
                    (result.reason ? ": " + result.reason : "");
                render();
                return;
            }
            fs.captureActive = true;
            fs.captureResultText = "Capture started on " + request.interface +
                " by explicit operator action. Use Stop capture when finished; nothing is uploaded.";
            state.lastStatus = "Capture started.";
            render();
        });
        captureActions.appendChild(startCapture);

        var stopCapture = el("button", "mp-cyber-button mp-cyber-button--danger",
            "Stop capture");
        stopCapture.type = "button";
        stopCapture.addEventListener("click", function () {
            var result = state.surface.runner.stop();
            fs.captureActive = false;
            fs.captureResultText = result.reason +
                (result.stop && result.stop.message ? ": " + result.stop.message : "") +
                ". The host executor sends SIGINT; no capture data is uploaded.";
            state.lastStatus = "Capture stop requested.";
            render();
        });
        captureActions.appendChild(stopCapture);
        panel.appendChild(captureActions);
        panel.appendChild(captureStatus);

        panel.appendChild(el("h2", "mp-cyber-panel-title", "Inspect an existing capture (read-only)"));
        var openPathInput = el("input", "mp-cyber-input");
        openPathInput.type = "text";
        openPathInput.value = fs.openPath;
        openPathInput.placeholder = "/home/operator/captures/lab.pcap";
        openPathInput.addEventListener("input", function () {
            fs.openPath = openPathInput.value;
            refreshOpen();
        });
        panel.appendChild(fieldBox("Local pcap/pcapng path", openPathInput));

        var openConfirmLabel = el("label", "mp-cyber-checkbox");
        var openConfirm = el("input");
        openConfirm.type = "checkbox";
        openConfirm.id = "mp-forensics-open-confirmed";
        openConfirm.checked = fs.openConfirmed;
        openConfirm.addEventListener("change", function () {
            fs.openConfirmed = openConfirm.checked;
            refreshOpen();
        });
        openConfirmLabel.appendChild(openConfirm);
        openConfirmLabel.appendChild(document.createTextNode(
            authSnapshot.openConfirmationLabel ||
            "I confirm this capture file is local, I am authorized to examine it, and it will not be uploaded or transmitted."));
        panel.appendChild(openConfirmLabel);

        panel.appendChild(openValidation);

        var openButton = el("button", "mp-cyber-button mp-cyber-button--accent",
            "Open and parse pcap (explicit)");
        openButton.type = "button";
        openButton.addEventListener("click", function () {
            var plan = forensicsOpenRequest();
            if (!plan.ok) {
                refreshOpen();
                return;
            }
            var result = state.surface.runner.start("forensics", {
                confirmed: true,
                args: plan.args,
                metadata: {
                    action: "pcap-open",
                    capturePath: plan.capturePath,
                    readOnly: true,
                    uploads: false,
                    packetInjection: false
                }
            });
            if (result.status !== "started") {
                state.lastStatus = result.status +
                    (result.reason ? ": " + result.reason : "");
                render();
                return;
            }
            finishOpen(result.result, plan.capturePath);
        });
        panel.appendChild(openButton);
        panel.appendChild(openStatus);

        panel.appendChild(el("pre", "mp-cyber-status", state.lastStatus ||
            (prepared.status === "ready"
                ? "Ready. Select an interface and a new capture path, or open a local pcap. Nothing starts until the explicit button and confirmation."
                : prepared.reason)));

        interfaceInput.addEventListener("input", function () {
            fs.interface = interfaceInput.value;
            refreshCapture();
        });
        refreshCapture();
        refreshOpen();

        function refreshCapture() {
            var request = forensicsCaptureRequest();
            captureValidation.textContent = request.ok ? "" : request.reason;
            captureValidation.hidden = request.ok;
            startCapture.disabled = prepared.status !== "ready" ||
                !request.ok || fs.captureActive;
            stopCapture.disabled = !fs.captureActive;
        }

        function refreshOpen() {
            var request = forensicsOpenRequest();
            openValidation.textContent = request.ok ? "" : request.reason;
            openValidation.hidden = request.ok;
            openButton.disabled = prepared.status !== "ready" || !request.ok;
        }

        function finishOpen(execution, capturePath) {
            if (execution && typeof execution.then === "function") {
                openStatus.textContent = "Reading the local capture; no upload is performed.";
                execution.then(function (value) {
                    finishOpen(value, capturePath);
                }, function (error) {
                    var failed = Forensics.interpretCaptureResult({
                        status: "failed",
                        message: error && error.message ? error.message : String(error)
                    }, {capturePath: capturePath});
                    fs.openResultText = Forensics.formatCaptureSummary(failed);
                    state.lastStatus = "Capture read failed.";
                    render();
                });
                return;
            }
            var parsed = Forensics.interpretCaptureResult(execution, {
                capturePath: capturePath
            });
            fs.openResultText = Forensics.formatCaptureSummary(parsed);
            state.lastStatus = parsed.ok
                ? "Capture parsed locally. Sensitive payloads are redacted; nothing was uploaded."
                : "Capture read failed.";
            render();
        }
    }

    function renderNmapPanel(panel, tab, prepared) {
        var Nmap = nmapModule();
        if (!Nmap) {
            panel.appendChild(fallbackBox({
                title: "Nmap helper unavailable",
                message: "The Nmap validator/parser module was not loaded, so no launch control is offered.",
                reason: "src/nmap.js is missing",
                installHint: "Restore the reviewed frontend file and reload the surface."
            }));
            return;
        }

        var nmap = state.nmap;
        var authSnapshot = state.surface.authorization.snapshot();
        var validation = el("p", "mp-cyber-error", "");
        var targetLine = el("div", "mp-cyber-scope", "");
        var run = el("button", "mp-cyber-button mp-cyber-button--accent", "Start Nmap (explicit)");
        run.type = "button";

        panel.appendChild(el("p", "mp-cyber-panel-copy",
            "Targets must be private, loopback, documentation/lab addresses, or names under an approved lab suffix. Public ranges are refused."));

        var targetInput = el("input", "mp-cyber-input");
        targetInput.type = "text";
        targetInput.value = nmap.target;
        targetInput.placeholder = "e.g. 192.168.1.10 or lab-vm.example";
        targetInput.addEventListener("input", function () {
            nmap.target = targetInput.value;
            refreshNmapState();
        });
        panel.appendChild(fieldBox("Target (private/authorized lab only)", targetInput));

        var profileSelect = el("select", "mp-cyber-input");
        Nmap.listProfiles().forEach(function (profile) {
            var option = el("option", "", profile.label);
            option.value = profile.id;
            option.selected = profile.id === nmap.profile;
            profileSelect.appendChild(option);
        });
        profileSelect.addEventListener("change", function () {
            nmap.profile = profileSelect.value;
            var available = Nmap.listOptions(nmap.profile).map(function (option) {
                return option.id;
            });
            Object.keys(nmap.options).forEach(function (id) {
                if (available.indexOf(id) === -1) {
                    delete nmap.options[id];
                }
            });
            render();
        });
        panel.appendChild(fieldBox("Profile", profileSelect));

        var currentProfile = Nmap.getProfile(nmap.profile);
        panel.appendChild(el("p", "mp-cyber-panel-copy",
            currentProfile ? currentProfile.description : ""));

        var optionBox = el("div", "mp-cyber-controls");
        Nmap.listOptions(nmap.profile).forEach(function (option) {
            var label = el("label", "mp-cyber-checkbox");
            var checkbox = el("input");
            checkbox.type = "checkbox";
            checkbox.checked = nmap.options[option.id] === true;
            checkbox.addEventListener("change", function () {
                if (checkbox.checked) {
                    nmap.options[option.id] = true;
                } else {
                    delete nmap.options[option.id];
                }
                refreshNmapState();
            });
            label.appendChild(checkbox);
            label.appendChild(document.createTextNode(option.label));
            label.title = option.description;
            optionBox.appendChild(label);
        });
        if (optionBox.childNodes.length > 0) {
            panel.appendChild(fieldBox("Options", optionBox));
        }

        var confirmLabel = el("label", "mp-cyber-checkbox");
        var confirm = el("input");
        confirm.type = "checkbox";
        confirm.id = "mp-nmap-authorized-lab";
        confirm.checked = nmap.authorizedLab;
        confirm.addEventListener("change", function () {
            nmap.authorizedLab = confirm.checked;
            refreshNmapState();
        });
        confirmLabel.appendChild(confirm);
        confirmLabel.appendChild(document.createTextNode(
            authSnapshot.labConfirmationLabel ||
                "I confirm this Nmap scan targets an authorized lab or private network."));
        panel.appendChild(confirmLabel);

        panel.appendChild(validation);
        panel.appendChild(targetLine);

        run.addEventListener("click", function () {
            var request = nmapRequest();
            if (!request.ok) {
                refreshNmapState();
                return;
            }
            var result = state.surface.runner.start("nmap", {
                confirmed: true,
                args: request.args,
                target: request.target,
                targets: request.targets,
                profile: request.profile,
                timeoutMs: request.timeoutMs,
                metadata: {xml: true, authorizedLab: true}
            });
            if (result.status !== "started") {
                state.lastStatus = result.status + (result.reason ? ": " + result.reason : "");
                render();
                return;
            }
            state.lastStatus = "Nmap scan started by explicit operator action.";
            finishNmap(result.result, request.timeoutMs);
        });
        panel.appendChild(run);

        var resultBox = el("pre", "mp-cyber-status", nmap.resultText);
        resultBox.id = "mp-nmap-result";
        panel.appendChild(resultBox);

        var status = el("pre", "mp-cyber-status", state.lastStatus ||
            (prepared.status === "ready"
                ? "Ready. Review the target and scope, check the authorized-lab confirmation, then click Start."
                : prepared.reason));
        status.id = "mp-cyber-status";
        panel.appendChild(status);

        function finishNmap(execution, timeoutMs) {
            var parsed;
            if (execution && typeof execution.then === "function") {
                execution.then(function (value) {
                    finishNmap(value, timeoutMs);
                }, function (error) {
                    var failed = Nmap.interpretScanResult({
                        status: "failed",
                        message: error && error.message ? error.message : String(error)
                    }, {timeoutMs: timeoutMs});
                    state.nmap.resultText = Nmap.formatScanResult(failed);
                    state.lastStatus = failed.timedOut
                        ? "Nmap scan timed out."
                        : "Nmap scan failed.";
                    render();
                });
                return;
            }
            parsed = Nmap.interpretScanResult(execution, {timeoutMs: timeoutMs});
            state.nmap.resultText = Nmap.formatScanResult(parsed);
            state.lastStatus = parsed.timedOut
                ? "Nmap scan timed out."
                : (parsed.ok ? "Nmap scan complete." : "Nmap scan failed.");
            render();
        }

        function refreshNmapState() {
            var request = nmapRequest();
            validation.textContent = request.ok ? "" : request.reason;
            validation.hidden = request.ok;
            targetLine.textContent = nmap.target.length > 0
                ? "TARGET: " + nmap.target
                : "NO TARGET - Nmap cannot start";
            targetLine.setAttribute("data-armed", request.ok ? "true" : "false");
            run.disabled = prepared.status !== "ready" || !request.ok;
        }

        refreshNmapState();
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
        if (tab.id === "set") {
            renderSetPanel(panel, tab, prepared);
            container.appendChild(panel);
            return;
        }

        if (tab.id === "forensics") {
            renderForensicsPanel(panel, tab, prepared);
            container.appendChild(panel);
            return;
        }

        if (prepared.status === "missing-tool") {
            panel.appendChild(fallbackBox(prepared.fallback));
            container.appendChild(panel);
            return;
        }

        if (tab.id === "nmap") {
            renderNmapPanel(panel, tab, prepared);
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
                runner: null,
                interfaces: adapter.interfaces
            };
            state.surface.runner = new window.CyberRunner.ToolRunner({
                registry: registry,
                authorization: state.surface.authorization,
                probe: adapter.probe,
                execute: adapter.execute,
                stop: adapter.stop
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
