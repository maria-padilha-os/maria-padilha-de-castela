/*
 * Explicit authorization state for the private cyber frontend.
 *
 * The state is deliberately boring and fail-closed:
 *   - no scope and no lab mode is the default;
 *   - enabling lab mode requires an acknowledged written authorization;
 *   - running requires acknowledged authorization, lab mode, and a bounded
 *     target scope;
 *   - stop cancels the current operation;
 *   - clear removes the scope and any queued targets.
 *
 * This module never executes a tool. It only records whether the operator has
 * supplied the safety inputs that the tool runner requires.
 */

"use strict";

var DEFAULT_UNBOUNDED_PATTERNS = [
    "^0\\.0\\.0\\.0/0$",
    "^::/0$",
    "^\\*$",
    "^any$",
    "^all$",
    "^internet$",
    "^public$"
];

function authorizationObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmpty(value) {
    return typeof value === "string" && value.trim().length > 0;
}

function copyList(value) {
    return Array.isArray(value) ? value.slice() : [];
}

function AuthorizationState(config) {
    config = authorizationObject(config) ? config : {};
    this.banner = nonEmpty(config.banner)
        ? config.banner
        : "AUTHORIZED USE ONLY. Use only on owned systems or with explicit written permission.";
    this.acknowledgement = nonEmpty(config.acknowledgement)
        ? config.acknowledgement
        : "I have explicit written authorization for this target scope.";
    this.labModeLabel = nonEmpty(config.labModeLabel)
        ? config.labModeLabel
        : "Authorized lab mode";
    this.labConfirmationLabel = nonEmpty(config.labConfirmationLabel)
        ? config.labConfirmationLabel
        : "I confirm this scan targets an authorized lab or private network.";
    this.targetScopeLabel = nonEmpty(config.targetScopeLabel)
        ? config.targetScopeLabel
        : "Target scope";
    this.stopLabel = nonEmpty(config.stopLabel) ? config.stopLabel : "Stop";
    this.clearLabel = nonEmpty(config.clearLabel) ? config.clearLabel : "Clear";
    this.unboundedPatterns = copyList(config.unboundedScopes);
    if (this.unboundedPatterns.length === 0) {
        this.unboundedPatterns = DEFAULT_UNBOUNDED_PATTERNS.slice();
    }

    this.acknowledged = false;
    this.authorizationReference = "";
    this.labMode = false;
    this.scope = "";
    this.queuedTargets = [];
    this.running = false;
    this.activeTool = null;
    this.lastAction = "idle";
    this.lastActionAt = null;
    this.version = 0;
}

AuthorizationState.prototype._now = function () {
    return Date.now();
};

AuthorizationState.prototype._snapshot = function () {
    var authorized = this.acknowledged && this.labMode && nonEmpty(this.scope);
    return {
        banner: this.banner,
        acknowledgement: this.acknowledgement,
        labModeLabel: this.labModeLabel,
        labConfirmationLabel: this.labConfirmationLabel,
        targetScopeLabel: this.targetScopeLabel,
        stopLabel: this.stopLabel,
        clearLabel: this.clearLabel,
        acknowledged: this.acknowledged,
        authorizationReference: this.authorizationReference,
        labMode: this.labMode,
        scope: this.scope,
        scopeLabel: nonEmpty(this.scope) ? this.scope : "No target scope",
        queuedTargets: this.queuedTargets.slice(),
        authorized: authorized,
        running: this.running,
        activeTool: this.activeTool,
        canRun: authorized && !this.running,
        lastAction: this.lastAction,
        version: this.version
    };
};

AuthorizationState.prototype._result = function (ok, reason) {
    return {
        ok: ok === true,
        reason: reason || "",
        state: this._snapshot()
    };
};

AuthorizationState.prototype._touch = function (action) {
    this.version += 1;
    this.lastAction = action;
    this.lastActionAt = this._now();
    return this._snapshot();
};

AuthorizationState.prototype.snapshot = function () {
    return this._snapshot();
};

AuthorizationState.prototype.state = function () {
    return this._snapshot();
};

AuthorizationState.prototype.acknowledge = function (reference) {
    if (!nonEmpty(reference)) {
        return this._result(false, "a written authorization reference is required");
    }
    this.authorizationReference = reference.trim();
    this.acknowledged = true;
    this._touch("acknowledge");
    return this._result(true, "authorization acknowledged");
};

AuthorizationState.prototype.acknowledgeAuthorization = function (reference) {
    return this.acknowledge(reference);
};

AuthorizationState.prototype.setAuthorized = function (reference) {
    return this.acknowledge(reference);
};

AuthorizationState.prototype.withdrawAuthorization = function () {
    this.acknowledged = false;
    this.authorizationReference = "";
    this.labMode = false;
    this.running = false;
    this.activeTool = null;
    this._touch("withdraw-authorization");
    return this._result(true, "authorization withdrawn");
};

AuthorizationState.prototype.setLabMode = function (enabled) {
    if (enabled === true && !this.acknowledged) {
        return this._result(false, "acknowledge the written authorization before enabling lab mode");
    }
    this.labMode = enabled === true;
    if (!this.labMode) {
        this.running = false;
        this.activeTool = null;
    }
    this._touch(this.labMode ? "lab-mode-on" : "lab-mode-off");
    return this._result(true, this.labMode ? "lab mode enabled" : "lab mode disabled");
};

AuthorizationState.prototype.isLabMode = function () {
    return this.labMode;
};

AuthorizationState.prototype.isUnboundedScope = function (scope) {
    var value = typeof scope === "string" ? scope.trim().toLowerCase() : "";
    if (value === "") {
        return true;
    }
    var index;
    for (index = 0; index < this.unboundedPatterns.length; index += 1) {
        try {
            if (new RegExp(this.unboundedPatterns[index], "i").test(value)) {
                return true;
            }
        } catch (error) {
            /* A malformed policy pattern is ignored rather than widening scope. */
        }
    }
    return false;
};

AuthorizationState.prototype.setTargetScope = function (scope) {
    if (!nonEmpty(scope)) {
        return this._result(false, "a target scope is required");
    }
    var trimmed = scope.trim();
    if (this.isUnboundedScope(trimmed)) {
        return this._result(false, "unbounded or wildcard target scopes are not allowed");
    }
    this.scope = trimmed;
    this.queuedTargets = [];
    this._touch("scope-set");
    return this._result(true, "target scope set");
};

AuthorizationState.prototype.setScope = function (scope) {
    return this.setTargetScope(scope);
};

AuthorizationState.prototype.queueTarget = function (target) {
    if (!nonEmpty(target)) {
        return this._result(false, "a target is required");
    }
    if (!nonEmpty(this.scope)) {
        return this._result(false, "set a target scope before queuing a target");
    }
    var trimmed = target.trim();
    if (this.isUnboundedScope(trimmed)) {
        return this._result(false, "unbounded or wildcard targets are not allowed");
    }
    this.queuedTargets.push(trimmed);
    this._touch("target-queued");
    return this._result(true, "target queued inside scope");
};

AuthorizationState.prototype.canRun = function () {
    return this._snapshot().canRun;
};

AuthorizationState.prototype.beginRun = function (toolId) {
    if (!this.acknowledged) {
        return this._result(false, "written authorization has not been acknowledged");
    }
    if (!this.labMode) {
        return this._result(false, "authorized lab mode is not enabled");
    }
    if (!nonEmpty(this.scope)) {
        return this._result(false, "a bounded target scope is required");
    }
    if (this.running) {
        return this._result(false, "a tool is already running; stop it first");
    }
    this.running = true;
    this.activeTool = nonEmpty(toolId) ? toolId : "unknown";
    this._touch("start");
    return this._result(true, "run permitted");
};

AuthorizationState.prototype.stop = function () {
    var wasRunning = this.running;
    this.running = false;
    this.activeTool = null;
    this._touch("stop");
    return this._result(true, wasRunning ? "operation stopped" : "nothing was running");
};

AuthorizationState.prototype.clear = function () {
    this.running = false;
    this.activeTool = null;
    this.scope = "";
    this.queuedTargets = [];
    this._touch("clear");
    return this._result(true, "target scope and queued targets cleared");
};

AuthorizationState.prototype.reset = function () {
    this.running = false;
    this.activeTool = null;
    this.scope = "";
    this.queuedTargets = [];
    this.labMode = false;
    this.acknowledged = false;
    this.authorizationReference = "";
    this._touch("reset");
    return this._result(true, "authorization state reset");
};

AuthorizationState.prototype.describe = function () {
    return this._snapshot();
};

function createAuthorizationState(config) {
    return new AuthorizationState(config);
}

var api = {
    DEFAULT_UNBOUNDED_PATTERNS: DEFAULT_UNBOUNDED_PATTERNS,
    AuthorizationState: AuthorizationState,
    Authorization: AuthorizationState,
    createAuthorizationState: createAuthorizationState
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
}
