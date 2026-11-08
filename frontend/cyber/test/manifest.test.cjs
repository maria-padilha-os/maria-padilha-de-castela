"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const Registry = require("../src/registry.js");

const manifestPath = path.join(__dirname, "..", "manifest.json");
const manifestText = fs.readFileSync(manifestPath, "utf8");

test("manifest loading accepts the checked-in private manifest", () => {
    const manifest = Registry.loadManifest(manifestText);
    assert.equal(manifest.schemaVersion, 1);
    assert.equal(manifest.namespace, "maria-padilha.cyber");
    assert.equal(manifest.panelNamespace, "maria-padilha.cyber.panels");
    assert.equal(manifest.featureFlag, "MARIA_PADILHA_CYBER_FRONTEND");
    assert.equal(manifest.privateBuild, true);
    assert.ok(manifest.authorization.banner.includes("AUTHORIZED USE ONLY"));
});

test("manifest exposes exactly the four requested cyber tabs", () => {
    const manifest = Registry.loadManifest(manifestText);
    assert.deepEqual(manifest.tabs.map((tab) => tab.id), [
        "nmap",
        "set",
        "forensics",
        "lab-vm"
    ]);
    for (const tab of manifest.tabs) {
        assert.equal(tab.autoRun, false, tab.id + " must not auto-run");
        assert.equal(tab.panel.indexOf(manifest.panelNamespace + "."), 0);
        for (const control of Registry.CYBER_SHARED_CONTROLS) {
            assert.ok(tab.controls.includes(control), tab.id + " missing " + control);
        }
    }
});

test("SET is registered but blocked by policy", () => {
    const manifest = Registry.loadManifest(manifestText);
    const setTab = manifest.tabs.find((tab) => tab.id === "set");
    assert.ok(setTab);
    assert.equal(setTab.policy.admitted, false);
    assert.match(setTab.policy.reason, /phishing|credential|policy/i);
});

test("private build plus feature flag exposes the namespace", () => {
    const off = Registry.resolveSurfaceMode({
        flags: { cyberFrontend: false },
        buildMode: "private"
    });
    assert.equal(off.enabled, false);
    assert.equal(off.namespace, null);

    const publicBuild = Registry.resolveSurfaceMode({
        flags: { cyberFrontend: true },
        buildMode: "public"
    });
    assert.equal(publicBuild.enabled, false);

    const on = Registry.resolveSurfaceMode({
        flags: { cyberFrontend: true },
        buildMode: "private"
    });
    assert.equal(on.enabled, true);
    assert.equal(on.namespace, "maria-padilha.cyber");
    assert.equal(on.panelNamespace, "maria-padilha.cyber.panels");
});

test("environment feature flag is supported", () => {
    const exposure = Registry.resolveSurfaceMode({
        env: {
            MARIA_PADILHA_BUILD: "private-cyber",
            MARIA_PADILHA_CYBER_FRONTEND: "1"
        }
    });
    assert.equal(exposure.enabled, true);
});

test("disabled surface loads no manifest and builds no registry", () => {
    const surface = Registry.createSurface({
        flags: { cyberFrontend: false },
        buildMode: "private",
        manifestJson: manifestText
    });
    assert.equal(surface.enabled, false);
    assert.equal(surface.registry, null);
    assert.equal(surface.manifest, null);
});

test("invalid manifests fail closed", () => {
    const base = JSON.parse(manifestText);

    assert.throws(() => Registry.loadManifest("{"), /invalid JSON/);

    const wrongNamespace = JSON.parse(JSON.stringify(base));
    wrongNamespace.namespace = "normal.desktop.dashboard";
    assert.throws(() => Registry.loadManifest(wrongNamespace), /namespace/);

    const autoRun = JSON.parse(JSON.stringify(base));
    autoRun.tabs[0].autoRun = true;
    assert.throws(() => Registry.loadManifest(autoRun), /autoRun must be false/);

    const duplicate = JSON.parse(JSON.stringify(base));
    duplicate.tabs[1].id = duplicate.tabs[0].id;
    assert.throws(() => Registry.loadManifest(duplicate), /duplicate tab id/);

    const missingBanner = JSON.parse(JSON.stringify(base));
    delete missingBanner.authorization.banner;
    assert.throws(() => Registry.loadManifest(missingBanner), /authorization\.banner/);

    const missingControl = JSON.parse(JSON.stringify(base));
    missingControl.tabs[0].controls = ["authorization-banner"];
    assert.throws(() => Registry.loadManifest(missingControl), /missing shared control/);

    const wrongPanel = JSON.parse(JSON.stringify(base));
    wrongPanel.tabs[0].panel = "normal.desktop.nmap";
    assert.throws(() => Registry.loadManifest(wrongPanel), /panel must live under/);
});
