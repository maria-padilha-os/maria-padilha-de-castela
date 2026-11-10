"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const Set = require("../src/set.js");
const Registry = require("../src/registry.js");
const Authorization = require("../src/authorization.js");
const Runner = require("../src/runner.js");

const root = path.join(__dirname, "..");
const manifest = Registry.loadManifest(
    fs.readFileSync(path.join(root, "manifest.json"), "utf8")
);

function authorizedState() {
    const auth = new Authorization.AuthorizationState(manifest.authorization);
    auth.acknowledge("engagement-2026-11 / owned lab");
    auth.setLabMode(true);
    auth.setTargetScope("192.0.2.0/24");
    return auth;
}

function setFixture(probe) {
    const registry = new Registry.TabRegistry(manifest);
    const authorization = new Authorization.AuthorizationState(manifest.authorization);
    const executions = [];
    const runner = new Runner.ToolRunner({
        registry,
        authorization,
        probe,
        execute(invocation) {
            executions.push(invocation);
            return {pid: 4242};
        }
    });
    return {registry, authorization, runner, executions};
}

test("a missing SET produces a structured fallback without executing", () => {
    const availability = Set.detectAvailability(() => ({
        available: false,
        missing: "setoolkit",
        reason: "command not found"
    }));
    assert.equal(availability.available, false);
    assert.equal(availability.status, "missing-tool");
    assert.equal(availability.command, "setoolkit");

    const report = Set.statusReport(availability);
    assert.equal(report.status, "missing-tool");
    assert.equal(report.missingCommand, "setoolkit");
    assert.equal(report.autoRun, false);
    assert.match(report.message, /no command is run/i);
    assert.match(report.dualUseWarning, /dual-use/i);
    assert.match(report.authorizedUse, /owned|written permission/i);
    assert.deepEqual(report.defaultArgs, []);
    assert.equal(report.defaultTarget, null);
    assert.equal(report.defaultTemplate, null);
    assert.deepEqual(report.attackContent, {
        phishingPages: false,
        credentialHarvesters: false,
        payloads: false,
        templates: false,
        generatedContent: false
    });

    const {runner, executions} = setFixture(() => ({
        available: false,
        missing: "setoolkit",
        reason: "command not found"
    }));
    const prepared = runner.prepare("set");
    assert.equal(prepared.status, "missing-tool");
    assert.equal(prepared.executed, false);
    assert.equal(prepared.fallback.autoRun, false);
    assert.equal(prepared.fallback.missingCommand, "setoolkit");
    assert.match(prepared.fallback.message, /No command was run/);

    const started = runner.start("set", {confirmed: true});
    assert.equal(started.status, "missing-tool");
    assert.equal(started.executed, false);
    assert.equal(executions.length, 0);
});

test("SET detection reports status without running the tool", () => {
    let probes = 0;
    const availability = Set.detectAvailability(() => {
        probes += 1;
        return {available: true, command: "setoolkit", reason: "tool present"};
    });
    assert.equal(probes, 1);
    assert.equal(availability.available, true);

    const report = Set.statusReport(availability);
    assert.equal(report.status, "available");
    assert.equal(report.title, "SET detected");
    assert.equal(report.autoRun, false);
    assert.equal(report.launchRequiresConfirmation, true);
    assert.equal(report.attackContent.generatedContent, false);

    const preparedReport = Set.statusReport({status: "ready", command: "setoolkit"});
    assert.equal(preparedReport.available, true);
    assert.equal(preparedReport.status, "available");

    const noProbe = Set.detectAvailability(null);
    assert.equal(noProbe.available, false);
    assert.match(noProbe.reason, /no tool probe/i);

    const failedProbe = Set.detectAvailability(() => {
        throw new Error("probe failed");
    });
    assert.equal(failedProbe.available, false);
    assert.match(failedProbe.reason, /probe failed/);
});

test("SET has no default action, target, template, or payload", () => {
    const plan = Set.prepareLaunch();
    assert.equal(plan.ok, false);
    assert.equal(plan.status, "confirmation-required");
    assert.equal(plan.executed, false);
    assert.equal(plan.autoRun, false);
    assert.deepEqual(plan.args, []);
    assert.deepEqual(plan.argv, ["setoolkit"]);
    assert.equal(plan.target, null);
    assert.equal(plan.template, null);
    assert.equal(plan.payload, null);
    assert.equal(plan.generatedContent, false);

    const unconfirmed = Set.prepareLaunch({authorization: authorizedState().snapshot()});
    assert.equal(unconfirmed.ok, false);
    assert.equal(unconfirmed.status, "confirmation-required");

    const unauthorized = Set.prepareLaunch({confirmed: true});
    assert.equal(unauthorized.ok, false);
    assert.equal(unauthorized.status, "unauthorized");
    assert.match(unauthorized.reason, /authorization/i);
    assert.equal(unauthorized.executed, false);
});

test("SET launch requires authorization, lab mode, scope, and confirmation", () => {
    const auth = new Authorization.AuthorizationState(manifest.authorization);
    const noAuth = Set.prepareLaunch({confirmed: true, authorization: auth.snapshot()});
    assert.equal(noAuth.ok, false);
    assert.match(noAuth.reason, /authorization/i);

    auth.acknowledge("engagement-2026-11 / owned lab");
    const noLab = Set.prepareLaunch({confirmed: true, authorization: auth.snapshot()});
    assert.equal(noLab.ok, false);
    assert.match(noLab.reason, /lab mode/i);

    auth.setLabMode(true);
    const noScope = Set.prepareLaunch({confirmed: true, authorization: auth.snapshot()});
    assert.equal(noScope.ok, false);
    assert.match(noScope.reason, /target scope/i);

    auth.setTargetScope("192.0.2.0/24");
    const ready = Set.prepareLaunch({confirmed: true, authorization: auth.snapshot()});
    assert.equal(ready.ok, true);
    assert.equal(ready.status, "ready");
    assert.equal(ready.command, "setoolkit");
    assert.deepEqual(ready.args, []);
    assert.deepEqual(ready.argv, ["setoolkit"]);
    assert.equal(ready.shell, false);
    assert.equal(ready.target, null);
    assert.equal(ready.template, null);
    assert.equal(ready.payload, null);
    assert.equal(ready.generatedContent, false);
    assert.equal(ready.autoRun, false);
    assert.equal(ready.executed, false);
    assert.equal(ready.authorization.scope, "192.0.2.0/24");

    assert.equal(auth.beginRun("set").ok, true);
    const alreadyRunning = Set.prepareLaunch({
        confirmed: true,
        authorization: auth.snapshot()
    });
    assert.equal(alreadyRunning.ok, false);
    assert.match(alreadyRunning.reason, /already running/i);
    auth.stop();
});

test("SET rejects arguments, targets, templates, and payload content", () => {
    const auth = authorizedState().snapshot();
    const attempts = [
        {args: ["--phishing"]},
        {args: "template"},
        {target: "192.0.2.10"},
        {targets: ["192.0.2.10"]},
        {template: "login page"},
        {templates: ["login page"]},
        {payload: "reverse shell"},
        {payloads: ["reverse shell"]},
        {page: "<html></html>"},
        {html: "<form></form>"},
        {content: "credential form"}
    ];

    for (const attempt of attempts) {
        const plan = Set.prepareLaunch(Object.assign({confirmed: true, authorization: auth}, attempt));
        assert.equal(plan.ok, false, JSON.stringify(attempt));
        assert.equal(plan.status, "launch-restricted", JSON.stringify(attempt));
        assert.equal(plan.executed, false);
        assert.deepEqual(plan.args, []);
        assert.equal(plan.target, null);
        assert.equal(plan.template, null);
        assert.equal(plan.generatedContent, false);
    }
});

test("the runner launches SET only on explicit confirmation with an empty argv", () => {
    const {authorization, runner, executions} = setFixture(() => ({
        available: true,
        command: "setoolkit",
        reason: "tool present"
    }));

    assert.equal(runner.prepare("set").status, "unauthorized");
    assert.equal(executions.length, 0);

    authorization.acknowledge("engagement-2026-11 / owned lab");
    authorization.setLabMode(true);
    authorization.setTargetScope("192.0.2.0/24");

    assert.equal(runner.prepare("set").status, "ready");
    assert.equal(executions.length, 0);

    const unconfirmed = runner.start("set");
    assert.equal(unconfirmed.status, "confirmation-required");
    assert.equal(unconfirmed.executed, false);
    assert.equal(executions.length, 0);

    const started = runner.start("set", {confirmed: true});
    assert.equal(started.status, "started");
    assert.equal(started.executed, true);
    assert.equal(executions.length, 1);
    assert.equal(executions[0].command, "setoolkit");
    assert.deepEqual(executions[0].args, []);
    assert.deepEqual(executions[0].argv, ["setoolkit"]);
    assert.equal(executions[0].target, null);
    assert.equal(executions[0].scope, "192.0.2.0/24");
});

test("the runner refuses operator-supplied SET content", () => {
    const {authorization, runner, executions} = setFixture(() => ({
        available: true,
        command: "setoolkit"
    }));
    authorization.acknowledge("engagement-2026-11 / owned lab");
    authorization.setLabMode(true);
    authorization.setTargetScope("192.0.2.0/24");

    for (const attempt of [
        {args: ["--attack"]},
        {target: "192.0.2.10"},
        {template: "login page"},
        {payload: "payload"}
    ]) {
        const result = runner.start("set", Object.assign({confirmed: true}, attempt));
        assert.equal(result.status, "launch-restricted", JSON.stringify(attempt));
        assert.equal(result.executed, false);
        assert.equal(result.autoRun, false);
    }
    assert.equal(executions.length, 0);
});

test("the SET panel never starts a tool on load or from a timer", () => {
    const panel = fs.readFileSync(path.join(root, "qml", "SetPanel.qml"), "utf8");
    const onCompleted = panel.match(/Component\.onCompleted\s*:\s*\{[^}]*\}/);
    assert.ok(onCompleted, "SetPanel has a completed handler");
    assert.doesNotMatch(onCompleted[0], /runner\.start/);
    assert.match(onCompleted[0], /refreshAvailability/);
    assert.doesNotMatch(panel, /Timer\s*\{[\s\S]{0,400}?runner\.start/);

    const browser = fs.readFileSync(path.join(root, "src", "app.js"), "utf8");
    assert.doesNotMatch(browser, /boot\(\)[\s\S]{0,800}?runner\.start/);
    assert.doesNotMatch(browser, /setInterval\([^)]*runner\.start/);
});
