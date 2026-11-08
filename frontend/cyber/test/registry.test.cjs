"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const Registry = require("../src/registry.js");
const manifest = Registry.loadManifest(
    fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8")
);

test("tab registry loads tabs in manifest order", () => {
    const registry = new Registry.TabRegistry(manifest);
    assert.deepEqual(registry.ids(), ["nmap", "set", "forensics", "lab-vm"]);
    assert.deepEqual(registry.list().map((tab) => tab.id), [
        "nmap",
        "set",
        "forensics",
        "lab-vm"
    ]);
});

test("tabs can be disabled and enabled independently", () => {
    const registry = new Registry.TabRegistry(manifest);
    assert.equal(registry.isEnabled("forensics"), true);

    const disabled = registry.disable("forensics");
    assert.equal(disabled.enabled, false);
    assert.equal(disabled.status, "disabled");
    assert.equal(registry.isEnabled("forensics"), false);
    assert.ok(!registry.list().some((tab) => tab.id === "forensics"));
    assert.ok(registry.list({ includeDisabled: true }).some((tab) => tab.id === "forensics"));

    const enabled = registry.enable("forensics");
    assert.equal(enabled.enabled, true);
    assert.equal(registry.isEnabled("forensics"), true);

    registry.setEnabled("nmap", false);
    assert.equal(registry.get("nmap").enabled, false);
    assert.equal(registry.get("set").enabled, true);
});

test("the default tab state comes from the manifest", () => {
    const local = JSON.parse(JSON.stringify(manifest));
    local.tabs.find((tab) => tab.id === "lab-vm").enabled = false;
    const registry = new Registry.TabRegistry(local);
    assert.equal(registry.isEnabled("lab-vm"), false);
    assert.equal(registry.get("lab-vm").enabledByDefault, false);
    assert.equal(registry.get("nmap").enabledByDefault, true);
});

test("unknown tabs are rejected instead of silently ignored", () => {
    const registry = new Registry.TabRegistry(manifest);
    assert.throws(() => registry.get("not-a-tab"), /unknown tab/);
    assert.throws(() => registry.disable("not-a-tab"), /unknown tab/);
    assert.equal(registry.has("not-a-tab"), false);
});

test("tool probe state is reflected without disabling the tab", () => {
    const registry = new Registry.TabRegistry(manifest);
    const availability = registry.applyToolProbe("nmap", {
        available: false,
        command: "nmap",
        reason: "command not found"
    });
    assert.equal(availability.available, false);
    assert.equal(registry.isEnabled("nmap"), true);
    assert.equal(registry.get("nmap").status, "missing-tool");
    assert.equal(registry.get("nmap").missingTool, "nmap");
    assert.equal(registry.get("nmap").fallback.autoRun, false);

    registry.applyToolProbe("nmap", {
        available: true,
        command: "nmap",
        reason: "tool present"
    });
    assert.equal(registry.get("nmap").status, "ready");
    assert.equal(registry.get("nmap").fallback, null);
});

test("string probe results do not become missing command names", () => {
    const registry = new Registry.TabRegistry(manifest);
    const availability = registry.applyToolProbe("nmap", "missing");
    assert.equal(availability.available, false);
    assert.equal(availability.command, "nmap");
    assert.equal(registry.get("nmap").missingTool, "nmap");
    assert.equal(registry.get("nmap").fallback.missingCommand, "nmap");
});

test("disabled tabs remain disabled after a successful probe", () => {
    const registry = new Registry.TabRegistry(manifest);
    registry.disable("nmap");
    registry.applyToolProbe("nmap", { available: true, command: "nmap" });
    assert.equal(registry.get("nmap").enabled, false);
    assert.equal(registry.get("nmap").status, "disabled");
});
