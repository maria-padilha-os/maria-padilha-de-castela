/*
 * Tool runner for the private cyber frontend.
 *
 * The runner is a gate, not a background daemon. It never probes or executes on
 * construction, never probes on a timer, and only calls the injected executor
 * when the caller explicitly passes confirmed: true to start().
 *
 * Missing tools produce a structured fallback instead of an exception. A tab is
 * still rendered, still shows the shared safety controls, and offers no way to
 * launch the absent tool.
 */

"use strict";

function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmpty(value) {
    return typeof value === "string" && value.trim().length > 0;
}

function hasProvided(value) {
    if (value === null || typeof value === "undefined" || value === false) {
        return false;
    }
    if (typeof value === "string") {
        return value.trim().length > 0;
    }
    if (Array.isArray(value)) {
        return value.length > 0;
    }
    if (isObject(value)) {
        return Object.keys(value).length > 0;
    }
    return true;
}

/*
 * Some tabs, such as SET, have no operator-supplied arguments, target,
 * templates, or payloads. Their manifest launch policy is enforced here so a
 * caller cannot bypass the panel and smuggle content into the runner.
 */
function launchRestriction(tab, options) {
    var launch = isObject(tab.launch) ? tab.launch : null;
    if (!launch) {
        return "";
    }
    if (launch.allowArguments === false && hasProvided(options.args)) {
        return "this tab does not accept launch arguments";
    }
    if (launch.allowTarget === false &&
        (hasProvided(options.target) || hasProvided(options.targets))) {
        return "this tab does not accept a target";
    }
    if (launch.allowTemplates === false &&
        (hasProvided(options.template) || hasProvided(options.templates))) {
        return "this tab does not accept templates";
    }
    if (launch.allowPayloads === false &&
        (hasProvided(options.payload) || hasProvided(options.payloads))) {
        return "this tab does not accept payloads";
    }
    return "";
}

function ToolRunner(options) {
    options = isObject(options) ? options : {};
    this.registry = options.registry || null;
    this.authorization = options.authorization || null;
    this.probe = typeof options.probe === "function" ? options.probe : null;
    this.execute = typeof options.execute === "function" ? options.execute : null;
    this.invocations = [];
    this.lastResult = null;
}

ToolRunner.prototype._authorizationSnapshot = function () {
    if (this.authorization && typeof this.authorization.snapshot === "function") {
        return this.authorization.snapshot();
    }
    return {
        acknowledged: false,
        labMode: false,
        scope: "",
        authorized: false,
        running: false,
        canRun: false
    };
};

ToolRunner.prototype._probeTool = function (tab) {
    if (!this.probe) {
        return {
            available: false,
            command: tab.tool.commands[0],
            reason: "no tool probe is configured"
        };
    }
    try {
        var result = this.probe(tab);
        if (result && typeof result.then === "function") {
            return {
                available: false,
                command: tab.tool.commands[0],
                reason: "asynchronous probes require the host adapter"
            };
        }
        return result;
    } catch (error) {
        return {
            available: false,
            command: tab.tool.commands[0],
            reason: "tool probe failed: " + (error && error.message ? error.message : String(error))
        };
    }
};

/*
 * Prepare a tab without executing anything. The probe is a host-supplied
 * availability check, not the tool itself. Returns one of:
 *   ready, tab-disabled, missing-tool, policy-blocked, launch-restricted,
 *   unauthorized, executor-not-configured.
 */
ToolRunner.prototype.prepare = function (tabId, options) {
    options = options || {};
    if (!this.registry) {
        return this._finish({
            status: "registry-not-configured",
            executed: false,
            reason: "no tab registry is configured"
        });
    }
    if (!this.registry.has(tabId)) {
        return this._finish({
            status: "unknown-tab",
            executed: false,
            reason: "unknown tab " + tabId
        });
    }

    var tab = this.registry.get(tabId);
    if (!tab.enabled) {
        return this._finish({
            status: "tab-disabled",
            executed: false,
            tabId: tabId,
            reason: "this tab is disabled"
        });
    }

    var availability = this.registry.applyToolProbe(tabId, this._probeTool(tab));
    if (!availability.available) {
        return this._finish({
            status: "missing-tool",
            executed: false,
            tabId: tabId,
            fallback: this.registry.missingToolFallback(tabId),
            reason: availability.reason
        });
    }

    if (tab.policy && tab.policy.admitted === false) {
        return this._finish({
            status: "policy-blocked",
            executed: false,
            tabId: tabId,
            reason: tab.policy.reason || "this tool is excluded by policy",
            fallback: {
                status: "policy-blocked",
                tabId: tabId,
                title: tab.title + " is excluded by policy",
                message: "This tool is excluded by policy. No command was run and no launch control is rendered.",
                reason: tab.policy.reason || "this tool is excluded by policy",
                missingCommand: null,
                commands: tab.tool.commands.slice(),
                installHint: "Adding this tool requires a new policy review and tests proving phishing templates remain absent.",
                autoRun: false
            }
        });
    }

    var restricted = launchRestriction(tab, options);
    if (restricted.length > 0) {
        return this._finish({
            status: "launch-restricted",
            executed: false,
            tabId: tabId,
            reason: restricted,
            autoRun: false
        });
    }

    var auth = this._authorizationSnapshot();
    if (!auth.authorized || !auth.canRun) {
        return this._finish({
            status: "unauthorized",
            executed: false,
            tabId: tabId,
            reason: !auth.acknowledged
                ? "written authorization has not been acknowledged"
                : (!auth.labMode
                    ? "authorized lab mode is not enabled"
                    : (!nonEmpty(auth.scope)
                        ? "a bounded target scope is required"
                        : "a tool is already running")),
            authorization: auth
        });
    }

    return this._finish({
        status: "ready",
        executed: false,
        tabId: tabId,
        command: availability.command || tab.tool.commands[0],
        commands: tab.tool.commands.slice(),
        scope: auth.scope,
        args: Array.isArray(options.args) ? options.args.slice() : [],
        shell: false,
        target: nonEmpty(options.target) ? options.target : null,
        targets: Array.isArray(options.targets) ? options.targets.slice() : null,
        profile: nonEmpty(options.profile) ? options.profile : null,
        timeoutMs: typeof options.timeoutMs === "number" ? options.timeoutMs : null,
        metadata: isObject(options.metadata) ? options.metadata : null,
        authorization: auth
    });
};

/*
 * The only path that can invoke a tool. Confirmation is mandatory, all gates
 * run first, and the executor is never called on a missing or unauthorized
 * tool. The caller must use the result; nothing runs in the background.
 */
ToolRunner.prototype.start = function (tabId, options) {
    options = options || {};
    if (options.confirmed !== true) {
        return this._finish({
            status: "confirmation-required",
            executed: false,
            tabId: tabId,
            reason: "explicit confirmation is required before a tool can start"
        });
    }

    var prepared = this.prepare(tabId, options);
    if (prepared.status !== "ready") {
        return prepared;
    }
    if (!this.execute) {
        return this._finish({
            status: "executor-not-configured",
            executed: false,
            tabId: tabId,
            reason: "no host executor is configured; nothing was run",
            prepared: prepared
        });
    }

    var invocation = {
        tabId: tabId,
        command: prepared.command,
        args: prepared.args.slice(),
        argv: [prepared.command].concat(prepared.args.slice()),
        shell: false,
        scope: prepared.scope,
        target: prepared.target,
        targets: prepared.targets,
        profile: prepared.profile,
        timeoutMs: prepared.timeoutMs,
        metadata: prepared.metadata,
        startedAt: Date.now()
    };

    var begin = null;
    if (this.authorization && typeof this.authorization.beginRun === "function") {
        begin = this.authorization.beginRun(tabId);
        if (!begin.ok) {
            return this._finish({
                status: "unauthorized",
                executed: false,
                tabId: tabId,
                reason: begin.reason,
                authorization: begin.state
            });
        }
    }

    var execution;
    try {
        execution = this.execute(invocation);
    } catch (error) {
        execution = {
            status: "failed",
            message: error && error.message ? error.message : String(error)
        };
    }

    this.invocations.push(invocation);
    return this._finish({
        status: "started",
        executed: true,
        tabId: tabId,
        invocation: invocation,
        result: execution,
        authorization: this._authorizationSnapshot()
    });
};

ToolRunner.prototype.stop = function () {
    var result = null;
    if (this.authorization && typeof this.authorization.stop === "function") {
        result = this.authorization.stop();
    }
    return this._finish({
        status: "stopped",
        executed: false,
        reason: "stop requested",
        authorization: result ? result.state : this._authorizationSnapshot()
    });
};

ToolRunner.prototype.clear = function () {
    var result = null;
    if (this.authorization && typeof this.authorization.clear === "function") {
        result = this.authorization.clear();
    }
    return this._finish({
        status: "cleared",
        executed: false,
        reason: "target scope and queue cleared",
        authorization: result ? result.state : this._authorizationSnapshot()
    });
};

ToolRunner.prototype._finish = function (result) {
    this.lastResult = result;
    return result;
};

function createRunner(options) {
    return new ToolRunner(options);
}

var api = {
    ToolRunner: ToolRunner,
    Runner: ToolRunner,
    createRunner: createRunner,
    createToolRunner: createRunner
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
}
