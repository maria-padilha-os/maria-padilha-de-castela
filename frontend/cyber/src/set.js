/*
 * Safe, shared Social-Engineer Toolkit (SET) launcher/status helpers.
 *
 * SET is a dual-use framework. This module never starts a process, never
 * probes the host by itself, and never creates a target, a template, a
 * phishing page, a credential harvester, or a payload. It only:
 *   - normalizes an availability result supplied by the host adapter;
 *   - describes the missing-tool/present status and the authorized-use warning;
 *   - validates an explicitly confirmed launch that carries no arguments,
 *     target, template, or generated content.
 *
 * The actual execution boundary remains the host-supplied ToolRunner executor.
 * SET itself is not shipped in the image; an operator-installed copy is
 * detected through the host probe.
 */

"use strict";

var SET_COMMAND = "setoolkit";
var SET_TAB_ID = "set";
var SET_TOOL_NAME = "Social-Engineer Toolkit (SET)";

var DUAL_USE_WARNING =
    "SET is a dual-use social-engineering framework. Use it only on systems " +
    "you own or are explicitly authorized in writing to test. Phishing, " +
    "credential harvesting, and payload delivery are prohibited.";

var AUTHORIZED_USE_TEXT =
    "Authorized lab use only: SET may be launched only for an owned system or " +
    "an engagement with explicit written permission that names the systems and " +
    "time window. This frontend does not grant authorization.";

var MISSING_INSTALL_HINT =
    "SET is not shipped in this image. If an operator-installed copy is present, " +
    "this tab detects it through the host probe; otherwise no command is run. " +
    "Adding SET to the image requires a separate policy review.";

var DEFAULT_ARGS = [];

var NO_ATTACK_CONTENT = {
    phishingPages: false,
    credentialHarvesters: false,
    payloads: false,
    templates: false,
    generatedContent: false
};

var BLOCKED_CONTENT = [
    {key: "target", label: "a target"},
    {key: "targets", label: "targets"},
    {key: "template", label: "a template"},
    {key: "templates", label: "templates"},
    {key: "payload", label: "a payload"},
    {key: "payloads", label: "payloads"},
    {key: "page", label: "a landing page"},
    {key: "pages", label: "landing pages"},
    {key: "url", label: "a URL"},
    {key: "email", label: "email content"},
    {key: "content", label: "generated content"},
    {key: "script", label: "a script"},
    {key: "html", label: "HTML content"}
];

function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmpty(value) {
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

function noAttackContent() {
    return clone(NO_ATTACK_CONTENT);
}

function hasContent(value) {
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

function normalizeAvailability(result) {
    var available = false;
    var reason = "";
    var command = SET_COMMAND;

    if (typeof result === "boolean") {
        available = result;
        reason = available ? "SET is present" : "SET is not installed";
    } else if (typeof result === "string") {
        var lower = result.trim().toLowerCase();
        available = lower === "available" || lower === "present" ||
            lower === "ok" || lower === "true";
        reason = available ? "SET is present" : "SET is not installed";
    } else if (isObject(result)) {
        if (typeof result.available === "boolean") {
            available = result.available;
        } else if (result.status === "available" || result.status === "ready") {
            available = true;
        } else if (result.status === "missing-tool") {
            available = false;
        }
        reason = nonEmpty(result.reason)
            ? result.reason
            : (available ? "SET is present" : "SET is not installed");
        command = nonEmpty(result.command) ? result.command : SET_COMMAND;
        if (!available && nonEmpty(result.missing)) {
            command = result.missing;
        }
    } else {
        reason = "no SET availability result";
    }

    return {
        available: available,
        command: command,
        reason: reason,
        status: available ? "available" : "missing-tool"
    };
}

/*
 * Normalize a host-supplied probe. The probe is an availability check, not the
 * tool: this function never executes SET and never contacts a host. A probe
 * failure becomes a missing-tool result instead of an exception.
 */
function detectAvailability(probe, context) {
    if (typeof probe !== "function") {
        return normalizeAvailability({
            available: false,
            command: SET_COMMAND,
            reason: "no tool probe is configured"
        });
    }

    var tab = isObject(context)
        ? context
        : {id: SET_TAB_ID, tool: {commands: [SET_COMMAND]}};

    try {
        var result = probe(tab);
        if (result && typeof result.then === "function") {
            return normalizeAvailability({
                available: false,
                command: SET_COMMAND,
                reason: "asynchronous probes require the host adapter"
            });
        }
        return normalizeAvailability(result);
    } catch (error) {
        return normalizeAvailability({
            available: false,
            command: SET_COMMAND,
            reason: "SET probe failed: " +
                (error && error.message ? error.message : String(error))
        });
    }
}

function statusReport(result) {
    var availability = normalizeAvailability(result);
    var available = availability.available;

    return {
        tool: "SET",
        toolName: SET_TOOL_NAME,
        command: SET_COMMAND,
        available: available,
        status: available ? "available" : "missing-tool",
        title: available ? "SET detected" : "SET is not installed",
        message: available
            ? "SET is installed. The launcher stays locked until written authorization is acknowledged, authorized lab mode is on, a bounded target scope is set, and the operator explicitly confirms the launch."
            : "SET is not installed. The tab stays visible with the shared safety controls, and no command is run.",
        reason: availability.reason,
        missingCommand: available ? null : (availability.command || SET_COMMAND),
        installHint: available ? "" : MISSING_INSTALL_HINT,
        dualUseWarning: DUAL_USE_WARNING,
        authorizedUse: AUTHORIZED_USE_TEXT,
        attackContent: noAttackContent(),
        autoRun: false,
        defaultTarget: null,
        defaultTemplate: null,
        defaultArgs: DEFAULT_ARGS.slice(),
        launchRequiresConfirmation: true
    };
}

function basePlan() {
    return {
        ok: false,
        status: "idle",
        reason: "",
        tool: "SET",
        toolName: SET_TOOL_NAME,
        command: SET_COMMAND,
        args: DEFAULT_ARGS.slice(),
        argv: [SET_COMMAND],
        shell: false,
        target: null,
        targets: [],
        template: null,
        payload: null,
        generatedContent: false,
        attackContent: noAttackContent(),
        dualUseWarning: DUAL_USE_WARNING,
        authorizedUse: AUTHORIZED_USE_TEXT,
        autoRun: false,
        executed: false,
        confirmationRequired: true
    };
}

function failedPlan(status, reason) {
    var plan = basePlan();
    plan.status = status;
    plan.reason = reason;
    return plan;
}

function contentReason(options) {
    var index;
    for (index = 0; index < BLOCKED_CONTENT.length; index += 1) {
        var entry = BLOCKED_CONTENT[index];
        if (hasContent(options[entry.key])) {
            return "SET launch does not accept " + entry.label +
                "; this frontend does not generate attack content";
        }
    }

    if (typeof options.args !== "undefined") {
        if (!Array.isArray(options.args)) {
            return "SET launch arguments must be an array";
        }
        if (options.args.length > 0) {
            return "SET launch does not accept arguments";
        }
    }

    return "";
}

function authorizationReason(authorization) {
    if (!isObject(authorization)) {
        return "written authorization has not been acknowledged";
    }
    if (authorization.acknowledged !== true) {
        return "written authorization has not been acknowledged";
    }
    if (authorization.labMode !== true) {
        return "authorized lab mode is not enabled";
    }
    if (!nonEmpty(authorization.scope)) {
        return "a bounded target scope is required before SET can launch";
    }
    if (authorization.running === true) {
        return "a tool is already running; stop it first";
    }
    return "";
}

/*
 * Validate an explicitly confirmed launch. There is no default action, no
 * default target, no template, and no argument list. The plan always carries an
 * empty argv tail; the caller cannot smuggle flags or generated content in.
 */
function prepareLaunch(options) {
    options = isObject(options) ? options : {};

    if (options.confirmed !== true) {
        return failedPlan(
            "confirmation-required",
            "explicit operator confirmation is required before SET can launch"
        );
    }

    var forbidden = contentReason(options);
    if (forbidden.length > 0) {
        return failedPlan("launch-restricted", forbidden);
    }

    var unauthorized = authorizationReason(options.authorization);
    if (unauthorized.length > 0) {
        return failedPlan("unauthorized", unauthorized);
    }

    var plan = basePlan();
    plan.ok = true;
    plan.status = "ready";
    plan.reason = "explicit operator confirmation accepted; SET will launch with no arguments";
    plan.authorization = clone(options.authorization);
    return plan;
}

function buildLaunchRequest(options) {
    return prepareLaunch(options);
}

function buildLaunchPlan(options) {
    return prepareLaunch(options);
}

function buildSetRequest(options) {
    return prepareLaunch(options);
}

function launchArgs() {
    return DEFAULT_ARGS.slice();
}

var api = {
    SET_COMMAND: SET_COMMAND,
    SET_TAB_ID: SET_TAB_ID,
    SET_TOOL_NAME: SET_TOOL_NAME,
    DUAL_USE_WARNING: DUAL_USE_WARNING,
    AUTHORIZED_USE_TEXT: AUTHORIZED_USE_TEXT,
    NO_ATTACK_CONTENT: NO_ATTACK_CONTENT,
    DEFAULT_ARGS: DEFAULT_ARGS,
    normalizeAvailability: normalizeAvailability,
    detectAvailability: detectAvailability,
    detectSet: detectAvailability,
    checkAvailability: detectAvailability,
    statusReport: statusReport,
    getStatus: statusReport,
    describeStatus: statusReport,
    prepareLaunch: prepareLaunch,
    prepareSetLaunch: prepareLaunch,
    buildLaunchRequest: buildLaunchRequest,
    buildLaunchPlan: buildLaunchPlan,
    buildSetRequest: buildSetRequest,
    launchArgs: launchArgs,
    noAttackContent: noAttackContent
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
}
