/*
 * Private cyber frontend manifest and tab registry.
 *
 * This module is intentionally dependency-free and side-effect-free. Loading a
 * manifest or constructing a registry never starts a tool, a capture, or a VM.
 * The same file is used by the browser surface, the QML surface, and the Node
 * tests, so the registry rules are identical in every frontend.
 *
 * Namespace: maria-padilha.cyber
 */

"use strict";

var CYBER_SCHEMA_VERSION = 1;
var CYBER_NAMESPACE = "maria-padilha.cyber";
var CYBER_PANEL_NAMESPACE = "maria-padilha.cyber.panels";
var CYBER_FEATURE_FLAG = "MARIA_PADILHA_CYBER_FRONTEND";
var CYBER_SHARED_CONTROLS = [
    "authorization-banner",
    "lab-mode",
    "target-scope",
    "stop",
    "clear"
];

function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
    return typeof value === "string" && value.trim().length > 0;
}

function clone(value) {
    if (Array.isArray(value)) {
        return value.map(clone);
    }
    if (isObject(value)) {
        var out = {};
        Object.keys(value).forEach(function (key) {
            out[key] = clone(value[key]);
        });
        return out;
    }
    return value;
}

function fail(message) {
    throw new Error("cyber manifest: " + message);
}

function truthyFlag(value) {
    if (value === true || value === 1) {
        return true;
    }
    if (typeof value === "string") {
        return /^(1|true|yes|on)$/i.test(value.trim());
    }
    return false;
}

/*
 * A private build plus the explicit flag are both required. A public build or a
 * normal desktop session therefore never gets the namespace or tab registry.
 */
function resolveSurfaceMode(options) {
    options = options || {};
    var env = options.env || {};
    var flags = options.flags || {};
    var build = options.build || {};
    var buildMode = options.buildMode || build.mode ||
        env.MARIA_PADILHA_BUILD || "public";
    var flagValue = Object.prototype.hasOwnProperty.call(flags, "cyberFrontend")
        ? flags.cyberFrontend
        : env[CYBER_FEATURE_FLAG];
    var flagOn = truthyFlag(flagValue);
    var privateBuild = options.privateBuild === true ||
        build.private === true ||
        buildMode === "private" ||
        buildMode === "private-cyber";
    var enabled = flagOn && privateBuild;
    var reason;

    if (enabled) {
        reason = "private cyber frontend exposed";
    } else if (!flagOn) {
        reason = "feature flag " + CYBER_FEATURE_FLAG + " is off";
    } else {
        reason = "build mode " + buildMode + " is not a private cyber build";
    }

    return {
        enabled: enabled,
        namespace: enabled ? CYBER_NAMESPACE : null,
        panelNamespace: enabled ? CYBER_PANEL_NAMESPACE : null,
        featureFlag: CYBER_FEATURE_FLAG,
        buildMode: buildMode,
        reason: reason
    };
}

function validateControlList(tab, where) {
    if (!Array.isArray(tab.controls)) {
        fail(where + ".controls must be an array");
    }
    CYBER_SHARED_CONTROLS.forEach(function (control) {
        if (tab.controls.indexOf(control) === -1) {
            fail(where + " is missing shared control " + control);
        }
    });
}

function validateTool(tab, where) {
    if (!isObject(tab.tool)) {
        fail(where + ".tool must be an object");
    }
    if (!Array.isArray(tab.tool.commands) || tab.tool.commands.length === 0) {
        fail(where + ".tool.commands must be a non-empty array");
    }
    tab.tool.commands.forEach(function (command) {
        if (!isNonEmptyString(command)) {
            fail(where + ".tool.commands contains an empty command");
        }
        if (!/^[A-Za-z0-9][A-Za-z0-9+._/-]*$/.test(command)) {
            fail(where + ".tool command is not a plain executable name: " + command);
        }
    });
}

function validateLaunch(tab, where) {
    if (typeof tab.launch === "undefined") {
        return;
    }
    if (!isObject(tab.launch)) {
        fail(where + ".launch must be an object when present");
    }
    if (typeof tab.launch.args !== "undefined") {
        if (!Array.isArray(tab.launch.args)) {
            fail(where + ".launch.args must be an array");
        }
        if (tab.launch.args.length > 0) {
            fail(where + ".launch.args must be empty; no pre-filled arguments are allowed");
        }
    }
    ["allowArguments", "allowTarget", "allowTemplates", "allowPayloads"].forEach(function (key) {
        if (typeof tab.launch[key] !== "undefined" &&
            typeof tab.launch[key] !== "boolean") {
            fail(where + ".launch." + key + " must be a boolean when present");
        }
    });
}

function loadManifest(input) {
    var manifest = input;

    if (typeof input === "string") {
        try {
            manifest = JSON.parse(input);
        } catch (error) {
            fail("invalid JSON (" + error.message + ")");
        }
    }
    if (!isObject(manifest)) {
        fail("expected an object or a JSON string");
    }
    if (manifest.schemaVersion !== CYBER_SCHEMA_VERSION) {
        fail("schemaVersion must be " + CYBER_SCHEMA_VERSION);
    }
    if (manifest.namespace !== CYBER_NAMESPACE) {
        fail("namespace must be " + CYBER_NAMESPACE);
    }
    if (manifest.panelNamespace !== CYBER_PANEL_NAMESPACE) {
        fail("panelNamespace must be " + CYBER_PANEL_NAMESPACE);
    }
    if (manifest.featureFlag !== CYBER_FEATURE_FLAG) {
        fail("featureFlag must be " + CYBER_FEATURE_FLAG);
    }
    if (manifest.privateBuild !== true) {
        fail("privateBuild must be true");
    }
    if (!isNonEmptyString(manifest.title)) {
        fail("title must be a non-empty string");
    }
    if (!isObject(manifest.authorization) ||
        !isNonEmptyString(manifest.authorization.banner)) {
        fail("authorization.banner must be a non-empty string");
    }
    if (!Array.isArray(manifest.sharedControls)) {
        fail("sharedControls must be an array");
    }
    CYBER_SHARED_CONTROLS.forEach(function (control) {
        if (manifest.sharedControls.indexOf(control) === -1) {
            fail("sharedControls is missing " + control);
        }
    });
    if (!Array.isArray(manifest.tabs) || manifest.tabs.length === 0) {
        fail("tabs must be a non-empty array");
    }

    var seen = Object.create(null);
    var panelPrefix = manifest.panelNamespace + ".";
    manifest.tabs.forEach(function (tab, index) {
        var where = "tabs[" + index + "]";
        if (!isObject(tab)) {
            fail(where + " must be an object");
        }
        if (!isNonEmptyString(tab.id) || !/^[a-z][a-z0-9-]*$/.test(tab.id)) {
            fail(where + ".id is not a valid tab id");
        }
        if (seen[tab.id]) {
            fail("duplicate tab id " + tab.id);
        }
        seen[tab.id] = true;
        if (!isNonEmptyString(tab.title)) {
            fail(where + ".title must be a non-empty string");
        }
        if (!isNonEmptyString(tab.panel) ||
            tab.panel.indexOf(panelPrefix) !== 0) {
            fail(where + ".panel must live under " + panelPrefix);
        }
        if (tab.autoRun !== false) {
            fail(where + ".autoRun must be false; this surface never auto-runs a tool");
        }
        if (typeof tab.enabled !== "undefined" &&
            typeof tab.enabled !== "boolean") {
            fail(where + ".enabled must be a boolean when present");
        }
        if (typeof tab.offensive !== "boolean") {
            fail(where + ".offensive must be a boolean");
        }
        validateControlList(tab, where);
        validateTool(tab, where);
        validateLaunch(tab, where);
        if (tab.policy && tab.policy.admitted === true && tab.autoRun !== false) {
            fail(where + " is admitted by policy but would auto-run");
        }
    });

    return clone(manifest);
}

function normalizeAvailability(tab, result) {
    var available = false;
    var reason = "";
    var command = null;

    if (typeof result === "boolean") {
        available = result;
        reason = available ? "tool present" : "tool is not installed";
    } else if (typeof result === "string") {
        var lower = result.trim().toLowerCase();
        available = lower === "available" || lower === "present" ||
            lower === "ok" || lower === "true";
        reason = available ? "tool present" : "tool is not installed";
        if (!available &&
            lower !== "missing" &&
            lower !== "unavailable" &&
            lower !== "absent" &&
            lower !== "not-found" &&
            lower !== "false") {
            command = result.trim();
        }
    } else if (isObject(result)) {
        available = result.available === true;
        reason = isNonEmptyString(result.reason)
            ? result.reason
            : (available ? "tool present" : "tool is not installed");
        command = isNonEmptyString(result.command) ? result.command : null;
        if (!available && isNonEmptyString(result.missing)) {
            command = result.missing;
        }
    } else {
        reason = "no tool probe result";
    }

    if (!command && !available && tab.tool && tab.tool.commands.length) {
        command = tab.tool.commands[0];
    }

    return {
        available: available,
        command: command,
        reason: reason
    };
}

function missingToolFallback(tab, availability) {
    availability = availability || {
        available: false,
        command: tab.tool.commands[0],
        reason: "tool is not installed"
    };
    return {
        status: "missing-tool",
        tabId: tab.id,
        title: tab.title + " is unavailable",
        message: "This tool is not installed. No command was run.",
        reason: availability.reason,
        missingCommand: availability.command || tab.tool.commands[0],
        commands: tab.tool.commands.slice(),
        installHint: isNonEmptyString(tab.tool.installHint)
            ? tab.tool.installHint
            : "Install the tool from a reviewed package source, then reopen this tab.",
        autoRun: false
    };
}

function TabRegistry(manifest) {
    if (!isObject(manifest) || !Array.isArray(manifest.tabs)) {
        fail("TabRegistry requires a loaded manifest");
    }
    this.manifest = clone(manifest);
    this.namespace = manifest.namespace;
    this.panelNamespace = manifest.panelNamespace;
    this._tabs = Object.create(null);
    this._states = Object.create(null);
    this._order = [];

    var self = this;
    manifest.tabs.forEach(function (tab) {
        var enabled = tab.enabled !== false;
        self._tabs[tab.id] = clone(tab);
        self._order.push(tab.id);
        self._states[tab.id] = {
            id: tab.id,
            enabled: enabled,
            enabledByDefault: enabled,
            status: enabled ? "ready" : "disabled",
            toolAvailable: null,
            missingTool: null,
            fallback: null
        };
    });
}

TabRegistry.prototype.has = function (id) {
    return Object.prototype.hasOwnProperty.call(this._tabs, id);
};

TabRegistry.prototype._require = function (id) {
    if (!this.has(id)) {
        throw new Error("cyber registry: unknown tab " + id);
    }
    return this._tabs[id];
};

TabRegistry.prototype.get = function (id) {
    var tab = this._require(id);
    var state = this._states[id];
    var view = clone(tab);
    view.enabled = state.enabled;
    view.enabledByDefault = state.enabledByDefault;
    view.status = state.status;
    view.toolAvailable = state.toolAvailable;
    view.missingTool = state.missingTool;
    view.fallback = state.fallback ? clone(state.fallback) : null;
    return view;
};

TabRegistry.prototype.list = function (options) {
    options = options || {};
    var includeDisabled = options.includeDisabled === true;
    var self = this;
    return this._order.map(function (id) {
        return self.get(id);
    }).filter(function (tab) {
        return includeDisabled || tab.enabled;
    });
};

TabRegistry.prototype.ids = function () {
    return this._order.slice();
};

TabRegistry.prototype.setEnabled = function (id, enabled) {
    this._require(id);
    var state = this._states[id];
    state.enabled = enabled === true;
    if (!state.enabled) {
        state.status = "disabled";
    } else if (state.toolAvailable === false) {
        state.status = "missing-tool";
    } else {
        state.status = "ready";
    }
    return this.get(id);
};

TabRegistry.prototype.enable = function (id) {
    return this.setEnabled(id, true);
};

TabRegistry.prototype.disable = function (id) {
    return this.setEnabled(id, false);
};

TabRegistry.prototype.isEnabled = function (id) {
    this._require(id);
    return this._states[id].enabled;
};

TabRegistry.prototype.tabState = function (id) {
    this._require(id);
    return clone(this._states[id]);
};

TabRegistry.prototype.applyToolProbe = function (id, result) {
    var tab = this._require(id);
    var state = this._states[id];
    var availability = normalizeAvailability(tab, result);
    state.toolAvailable = availability.available;
    state.missingTool = availability.available
        ? null
        : (availability.command || tab.tool.commands[0]);
    state.fallback = availability.available
        ? null
        : missingToolFallback(tab, availability);
    if (!state.enabled) {
        state.status = "disabled";
    } else {
        state.status = availability.available ? "ready" : "missing-tool";
    }
    return clone(availability);
};

TabRegistry.prototype.missingToolFallback = function (id) {
    var state = this._states[id];
    this._require(id);
    if (!state.fallback) {
        var tab = this._tabs[id];
        return missingToolFallback(tab, {
            available: false,
            command: tab.tool.commands[0],
            reason: "tool availability has not been probed"
        });
    }
    return clone(state.fallback);
};

function createSurface(options) {
    options = options || {};
    var exposure = resolveSurfaceMode(options);
    if (!exposure.enabled) {
        return {
            enabled: false,
            namespace: null,
            panelNamespace: null,
            reason: exposure.reason,
            manifest: null,
            registry: null,
            authorization: null,
            runner: null
        };
    }

    var manifest = loadManifest(options.manifest || options.manifestJson);
    var registry = new TabRegistry(manifest);
    var authorization = options.authorization || null;
    var runner = options.runner || null;

    if (!authorization && typeof options.AuthorizationState === "function") {
        authorization = new options.AuthorizationState(manifest.authorization);
    }
    if (!runner && typeof options.ToolRunner === "function") {
        runner = new options.ToolRunner({
            registry: registry,
            authorization: authorization,
            probe: options.probe,
            execute: options.execute
        });
    }

    return {
        enabled: true,
        namespace: manifest.namespace,
        panelNamespace: manifest.panelNamespace,
        reason: exposure.reason,
        manifest: manifest,
        registry: registry,
        authorization: authorization,
        runner: runner
    };
}

function createRegistry(manifest) {
    return new TabRegistry(loadManifest(manifest));
}

function isSurfaceEnabled(options) {
    return resolveSurfaceMode(options).enabled;
}

var api = {
    CYBER_SCHEMA_VERSION: CYBER_SCHEMA_VERSION,
    CYBER_NAMESPACE: CYBER_NAMESPACE,
    CYBER_PANEL_NAMESPACE: CYBER_PANEL_NAMESPACE,
    CYBER_FEATURE_FLAG: CYBER_FEATURE_FLAG,
    CYBER_SHARED_CONTROLS: CYBER_SHARED_CONTROLS,
    loadManifest: loadManifest,
    resolveSurfaceMode: resolveSurfaceMode,
    isSurfaceEnabled: isSurfaceEnabled,
    normalizeAvailability: normalizeAvailability,
    missingToolFallback: missingToolFallback,
    TabRegistry: TabRegistry,
    createRegistry: createRegistry,
    createSurface: createSurface
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
}
