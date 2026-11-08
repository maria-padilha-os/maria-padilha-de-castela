"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const Registry = require("../src/registry.js");
const Authorization = require("../src/authorization.js");
const Runner = require("../src/runner.js");

const manifest = Registry.loadManifest(
    fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8")
);

function fixture(probe) {
    const registry = new Registry.TabRegistry(manifest);
    const authorization = new Authorization.AuthorizationState(manifest.authorization);
    const executions = [];
    const runner = new Runner.ToolRunner({
        registry,
        authorization,
        probe,
        execute(invocation) {
            executions.push(invocation);
            return { pid: 4242 };
        }
    });
    return { registry, authorization, runner, executions };
}

function authorize(authorization) {
    authorization.acknowledge("engagement-2026-11 / owned lab");
    authorization.setLabMode(true);
    authorization.setTargetScope("192.0.2.0/24");
}

test("constructing a runner never probes or executes a tool", () => {
    let probes = 0;
    let executions = 0;
    const registry = new Registry.TabRegistry(manifest);
    const authorization = new Authorization.AuthorizationState(manifest.authorization);
    new Runner.ToolRunner({
        registry,
        authorization,
        probe() {
            probes += 1;
            return { available: true, command: "nmap" };
        },
        execute() {
            executions += 1;
        }
    });
    assert.equal(probes, 0);
    assert.equal(executions, 0);
});

test("missing tools fall back without executing anything", () => {
    const { registry, runner, executions } = fixture((tab) => ({
        available: false,
        missing: tab.tool.commands[0],
        reason: "command not found"
    }));

    const prepared = runner.prepare("nmap");
    assert.equal(prepared.status, "missing-tool");
    assert.equal(prepared.executed, false);
    assert.equal(prepared.fallback.autoRun, false);
    assert.equal(prepared.fallback.missingCommand, "nmap");
    assert.match(prepared.fallback.message, /No command was run/);
    assert.equal(registry.isEnabled("nmap"), true);
    assert.equal(registry.get("nmap").status, "missing-tool");
    assert.equal(executions.length, 0);

    const started = runner.start("nmap", { confirmed: true });
    assert.equal(started.status, "missing-tool");
    assert.equal(started.executed, false);
    assert.equal(executions.length, 0);
});

test("a policy-blocked tab never offers a launch path", () => {
    const { runner, executions } = fixture(() => ({
        available: true,
        command: "setoolkit"
    }));
    const prepared = runner.prepare("set");
    assert.equal(prepared.status, "policy-blocked");
    assert.equal(prepared.executed, false);
    assert.match(prepared.reason, /policy|phishing|credential/i);

    const started = runner.start("set", { confirmed: true });
    assert.equal(started.status, "policy-blocked");
    assert.equal(executions.length, 0);
});

test("an available tool is still refused without authorization and scope", () => {
    const { runner, executions } = fixture(() => ({ available: true, command: "nmap" }));
    const prepared = runner.prepare("nmap");
    assert.equal(prepared.status, "unauthorized");
    assert.equal(prepared.executed, false);
    assert.match(prepared.reason, /authorization/);

    const started = runner.start("nmap", { confirmed: true });
    assert.equal(started.status, "unauthorized");
    assert.equal(executions.length, 0);
});

test("explicit confirmation is mandatory before execution", () => {
    const { authorization, runner, executions } = fixture(() => ({
        available: true,
        command: "nmap"
    }));
    authorize(authorization);

    const prepared = runner.prepare("nmap");
    assert.equal(prepared.status, "ready");
    assert.equal(executions.length, 0);

    const unconfirmed = runner.start("nmap");
    assert.equal(unconfirmed.status, "confirmation-required");
    assert.equal(unconfirmed.executed, false);
    assert.equal(executions.length, 0);

    const started = runner.start("nmap", {
        confirmed: true,
        args: ["-sn", "192.0.2.0/24"]
    });
    assert.equal(started.status, "started");
    assert.equal(started.executed, true);
    assert.equal(executions.length, 1);
    assert.equal(executions[0].command, "nmap");
    assert.deepEqual(executions[0].args, ["-sn", "192.0.2.0/24"]);
    assert.equal(executions[0].scope, "192.0.2.0/24");
});

test("a disabled tab cannot be prepared or started", () => {
    const { registry, authorization, runner, executions } = fixture(() => ({
        available: true,
        command: "nmap"
    }));
    authorize(authorization);
    registry.disable("nmap");

    const prepared = runner.prepare("nmap");
    assert.equal(prepared.status, "tab-disabled");
    assert.equal(runner.start("nmap", { confirmed: true }).status, "tab-disabled");
    assert.equal(executions.length, 0);
});

test("missing executor leaves an authorized run unexecuted", () => {
    let probes = 0;
    const registry = new Registry.TabRegistry(manifest);
    const authorization = new Authorization.AuthorizationState(manifest.authorization);
    authorize(authorization);
    const runner = new Runner.ToolRunner({
        registry,
        authorization,
        probe() {
            probes += 1;
            return { available: true, command: "nmap" };
        }
    });
    const started = runner.start("nmap", { confirmed: true });
    assert.equal(started.status, "executor-not-configured");
    assert.equal(started.executed, false);
    assert.equal(probes, 1);
});

test("stop and clear are available through the runner", () => {
    const { authorization, runner, executions } = fixture(() => ({
        available: true,
        command: "nmap"
    }));
    authorize(authorization);
    runner.start("nmap", { confirmed: true });
    assert.equal(executions.length, 1);

    const stopped = runner.stop();
    assert.equal(stopped.status, "stopped");
    assert.equal(authorization.snapshot().running, false);

    const cleared = runner.clear();
    assert.equal(cleared.status, "cleared");
    assert.equal(authorization.snapshot().scope, "");
});

test("a probe failure becomes a missing-tool fallback", () => {
    const { runner, executions } = fixture(() => {
        throw new Error("probe unavailable");
    });
    const prepared = runner.prepare("nmap");
    assert.equal(prepared.status, "missing-tool");
    assert.match(prepared.fallback.reason, /probe unavailable/);
    assert.equal(executions.length, 0);
});
