"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const srcDir = path.join(root, "src");
const qmlDir = path.join(root, "qml");

function readAll(directory, extension) {
    return fs.readdirSync(directory)
        .filter((name) => name.endsWith(extension))
        .map((name) => ({
            name,
            text: fs.readFileSync(path.join(directory, name), "utf8")
        }));
}

const cssFiles = readAll(srcDir, ".css");
const qmlFiles = readAll(qmlDir, ".qml");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));

test("components use semantic theme tokens, not hardcoded palette values", () => {
    const paletteLiteral = /[#][0-9a-f]{3,8}\b|rgba?\(|hsla?\(|Qt\.rgba\(|Qt\.hsla\(/i;
    for (const file of cssFiles.concat(qmlFiles)) {
        assert.doesNotMatch(file.text, paletteLiteral,
            file.name + " contains a hardcoded palette value");
    }
});

test("the theme exposes semantic tokens and lets the host override them", () => {
    const theme = cssFiles.find((file) => file.name === "theme.css");
    assert.ok(theme, "theme.css is missing");
    for (const token of manifest.theme.tokens) {
        assert.match(theme.text, new RegExp("--cyber-[a-z-]*" + token.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase())),
            "theme token missing: " + token);
    }
    assert.match(theme.text, /var\(--mp-color-surface,/);
    assert.doesNotMatch(theme.text, /[#][0-9a-f]{3,8}\b/i);
});

test("component styles reference --cyber-* variables", () => {
    const styles = cssFiles.find((file) => file.name === "cyber.css");
    assert.ok(styles, "cyber.css is missing");
    assert.match(styles.text, /var\(--cyber-color-surface\)/);
    assert.match(styles.text, /var\(--cyber-color-text\)/);
    assert.match(styles.text, /var\(--cyber-color-danger\)/);
});

test("every QML panel uses the shared safety frame", () => {
    const panels = ["NmapPanel.qml", "SetPanel.qml", "ForensicsPanel.qml", "LabPanel.qml"];
    for (const panel of panels) {
        const text = fs.readFileSync(path.join(qmlDir, panel), "utf8");
        assert.match(text, /^\s*ToolPanelFrame\s*\{/m, panel + " must use ToolPanelFrame");
        assert.match(text, /authorization:/, panel + " must wire authorization");
    }
});

test("the shared QML frame contains every required control", () => {
    const frame = fs.readFileSync(path.join(qmlDir, "ToolPanelFrame.qml"), "utf8");
    assert.match(frame, /AuthorizationBanner\s*\{/);
    assert.match(frame, /LabModeSwitch\s*\{/);
    assert.match(frame, /TargetScopeIndicator\s*\{/);
    assert.match(frame, /StopClearAction\s*\{/);
    assert.match(frame, /property alias panelContent/);
});

test("QML never starts a tool on load", () => {
    for (const file of qmlFiles) {
        assert.doesNotMatch(file.text, /Component\.onCompleted\s*:\s*[^\n]*runner\.start/,
            file.name + " starts a tool on completion");
        assert.doesNotMatch(file.text, /Timer\s*\{[\s\S]{0,400}?runner\.start/,
            file.name + " starts a tool from a timer");
    }
    const runButton = qmlFiles.find((file) => file.name === "RunButton.qml");
    assert.ok(runButton);
    assert.match(runButton.text, /onClicked:\s*runControl\.startNow\(\)/);
    assert.match(runButton.text, /confirmed:\s*true/);
});

test("the QML shell is gated by both private build and feature flag", () => {
    const shell = fs.readFileSync(path.join(qmlDir, "CyberShell.qml"), "utf8");
    assert.match(shell, /property string buildMode/);
    assert.match(shell, /property bool cyberFrontendFlag/);
    assert.match(shell, /Registry\.resolveSurfaceMode/);
    assert.match(shell, /Registry\.loadManifest/);
});
