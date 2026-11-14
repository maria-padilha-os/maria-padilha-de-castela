"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const Lab = require("../src/lab.js");
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

test("the default network is labelled LAB ONLY and the host LAN path is separate", () => {
    const networks = Lab.listNetworks();
    assert.deepEqual(networks.map((network) => network.id), ["isolated", "host-lan"]);

    const isolated = networks.find((network) => network.id === "isolated");
    assert.equal(isolated.default, true);
    assert.equal(isolated.isolated, true);
    assert.equal(isolated.hostBridge, false);
    assert.equal(isolated.forwardMode, "none");
    assert.match(isolated.label, /LAB ONLY/i);
    assert.match(isolated.label, /no host bridge|no LAN route/i);

    const hostLan = networks.find((network) => network.id === "host-lan");
    assert.equal(hostLan.default, false);
    assert.equal(hostLan.isolated, false);
    assert.equal(hostLan.hostBridge, true);
    assert.equal(hostLan.requiresConfirmation, true);
    assert.match(hostLan.label, /HOST LAN/i);
    assert.match(hostLan.label, /NOT ISOLATED/i);
    assert.match(hostLan.warning, /WARNING/i);
    assert.match(hostLan.warning, /removes lab isolation/i);
});

test("the generated isolated network has no forwarding and no host bridge", () => {
    const xml = Lab.buildNetworkXml();
    assert.match(xml, /<name>mp-lab-isolated<\/name>/);
    assert.match(xml, /<forward mode='none'\/>/);
    assert.match(xml, /LAB ONLY/);
    assert.doesNotMatch(xml, /forward mode='(nat|route|bridge|open)'/);
    assert.doesNotMatch(xml, /<bridge\b/);
    assert.doesNotMatch(xml, /type='bridge'/);
    assert.doesNotMatch(xml, /host-lan/i);
    assert.equal(Lab.buildIsolatedNetworkXml(), xml);
    assert.throws(() => Lab.buildNetworkXml({network: "host-lan"}), /isolated LAB ONLY/i);
});

test("generated domain XML defaults to the isolated libvirt network", () => {
    const plan = Lab.prepareLaunch({
        vmName: "lab-one",
        memoryMiB: 4096,
        vcpus: 4
    });

    assert.equal(plan.ok, true);
    assert.equal(plan.status, "ready");
    assert.equal(plan.action, "define-domain");
    assert.equal(plan.executed, false);
    assert.equal(plan.autoRun, false);
    assert.equal(plan.autoStart, false);
    assert.equal(plan.isolated, true);
    assert.equal(plan.hostBridge, null);
    assert.equal(plan.hostBridgeDefault, false);
    assert.match(plan.networkLabel, /LAB ONLY/i);
    assert.equal(plan.diskPath, "/var/lib/libvirt/images/lab-one.qcow2");

    assert.match(plan.domainXml, /<name>lab-one<\/name>/);
    assert.match(plan.domainXml, /<memory unit='MiB'>4096<\/memory>/);
    assert.match(plan.domainXml, /<vcpu placement='static'>4<\/vcpu>/);
    assert.match(plan.domainXml, /<source file='\/var\/lib\/libvirt\/images\/lab-one.qcow2'\/>/);
    assert.match(plan.domainXml, /<interface type='network'>/);
    assert.match(plan.domainXml, /<source network='mp-lab-isolated'\/>/);
    assert.doesNotMatch(plan.domainXml, /type='bridge'/);
    assert.doesNotMatch(plan.domainXml, /<source bridge=/);
    assert.doesNotMatch(plan.domainXml, /host-lan/i);
    assert.doesNotMatch(plan.domainXml, /<forward\b/);

    assert.match(plan.networkXml, /<forward mode='none'\/>/);
    assert.doesNotMatch(plan.networkXml, /<bridge\b/);
    assert.ok(Array.isArray(plan.snapshotGuidance));
    assert.ok(plan.snapshotGuidance.length >= 4);
    assert.match(plan.snapshotGuidance.join("\n"), /snapshot/i);
    assert.match(plan.snapshotGuidance.join("\n"), /revert/i);
    assert.equal(plan.snapshotRequired, true);

    assert.equal(Lab.buildDomainXml({
        vmName: "lab-one",
        memoryMiB: 4096,
        vcpus: 4
    }), plan.domainXml);
});

test("host LAN attachment needs the warning acknowledgement and an explicit bridge", () => {
    const unconfirmed = Lab.prepareLaunch({network: "host-lan"});
    assert.equal(unconfirmed.ok, false);
    assert.equal(unconfirmed.status, "host-lan-confirmation-required");
    assert.equal(unconfirmed.executed, false);
    assert.match(unconfirmed.reason, /WARNING/i);
    assert.match(unconfirmed.reason, /removes lab isolation/i);
    assert.match(unconfirmed.network.label, /HOST LAN/i);

    assert.throws(
        () => Lab.buildDomainXml({network: "host-lan"}),
        /host LAN/i
    );

    const noBridge = Lab.prepareLaunch({
        network: "host-lan",
        hostLanConfirmed: true
    });
    assert.equal(noBridge.ok, false);
    assert.equal(noBridge.status, "host-lan-bridge-required");

    const confirmed = Lab.prepareLaunch({
        network: "host-lan",
        hostLanConfirmed: true,
        hostBridge: "br0"
    });
    assert.equal(confirmed.ok, true);
    assert.equal(confirmed.isolated, false);
    assert.equal(confirmed.hostBridge, "br0");
    assert.equal(confirmed.networkXml, null);
    assert.match(confirmed.hostLanWarning, /WARNING/i);
    assert.match(confirmed.domainXml, /<interface type='bridge'>/);
    assert.match(confirmed.domainXml, /<source bridge='br0'\/>/);
    assert.match(confirmed.domainXml, /NOT ISOLATED/);
});

test("VM name, disk, resource, and bridge inputs are validated", () => {
    for (const name of ["", "bad name", "lab<vm", "../lab", "-lab", "lab\nvm", "a".repeat(64)]) {
        const result = Lab.validateVmName(name);
        assert.equal(result.ok, false, JSON.stringify(name));
        assert.ok(result.reason.length > 0);
    }
    for (const name of ["lab", "lab-01", "lab.vm_1", "MP-LAB"]) {
        assert.equal(Lab.validateVmName(name).ok, true, name);
    }

    for (const disk of [
        "relative.qcow2",
        "/var/lib/libvirt/images/lab.img",
        "/var/lib/libvirt/images/../lab.qcow2",
        "/var/lib/libvirt/images//lab.qcow2",
        "https://example.invalid/lab.qcow2",
        "/var/lib/libvirt/images/lab copy.qcow2",
        ""
    ]) {
        const result = Lab.validateDiskPath(disk);
        assert.equal(result.ok, false, JSON.stringify(disk));
        assert.ok(result.reason.length > 0);
    }
    assert.equal(Lab.validateDiskPath("/var/lib/libvirt/images/lab.qcow2").ok, true);

    for (const bridge of ["", "br 0", "-br0", "br/0", "a".repeat(16)]) {
        assert.equal(Lab.validateBridgeName(bridge).ok, false, JSON.stringify(bridge));
    }
    assert.equal(Lab.validateBridgeName("br0").ok, true);

    assert.equal(Lab.prepareLaunch({memoryMiB: 0}).ok, false);
    assert.equal(Lab.prepareLaunch({memoryMiB: "lots"}).ok, false);
    assert.equal(Lab.prepareLaunch({vcpus: 0}).ok, false);
    assert.equal(Lab.prepareLaunch({vcpus: 33}).ok, false);
    assert.equal(Lab.prepareLaunch({vmName: "bad name"}).ok, false);
    assert.throws(() => Lab.buildDomainXml({vmName: "lab<vm"}), /VM name/i);
});

test("the manifest declares the isolated default and the host-LAN warning", () => {
    const tab = manifest.tabs.find((entry) => entry.id === "lab-vm");
    assert.ok(tab);
    assert.equal(tab.autoRun, false);
    assert.equal(tab.policy.isolatedNetworkDefault, true);
    assert.equal(tab.policy.defaultNetwork, "mp-lab-isolated");
    assert.equal(tab.policy.hostBridgeDefault, false);
    assert.equal(tab.policy.hostLanAttachment, "explicit-warning-and-confirmation");
    assert.equal(tab.policy.snapshotsRequired, true);
    assert.equal(tab.lab.isolatedForwardMode, "none");
    assert.equal(tab.lab.hostBridgeDefault, false);
    assert.equal(tab.lab.hostLanRequiresConfirmation, true);
    assert.deepEqual(tab.launch.args, []);
    assert.equal(tab.launch.allowArguments, false);
    assert.match(manifest.authorization.hostLanWarning, /WARNING/i);
    assert.match(manifest.authorization.hostLanConfirmationLabel, /host LAN/i);
    assert.match(manifest.authorization.snapshotGuidance, /snapshot/i);
});

test("the runner launches the lab definition only on explicit confirmation", () => {
    const registry = new Registry.TabRegistry(manifest);
    const authorization = authorizedState();
    const executions = [];
    const runner = new Runner.ToolRunner({
        registry,
        authorization,
        probe: () => ({available: true, command: "virsh", reason: "tool present"}),
        execute(invocation) {
            executions.push(invocation);
            return {pid: 4242};
        }
    });

    const plan = Lab.prepareLaunch({vmName: "lab-runner"});
    assert.equal(runner.prepare("lab-vm").status, "ready");
    assert.equal(executions.length, 0);

    const unconfirmed = runner.start("lab-vm", {args: [], metadata: {domainXml: plan.domainXml}});
    assert.equal(unconfirmed.status, "confirmation-required");
    assert.equal(unconfirmed.executed, false);
    assert.equal(executions.length, 0);

    const restricted = runner.start("lab-vm", {
        confirmed: true,
        args: ["--exec"]
    });
    assert.equal(restricted.status, "launch-restricted");
    assert.equal(restricted.executed, false);
    assert.equal(executions.length, 0);

    const started = runner.start("lab-vm", {
        confirmed: true,
        args: [],
        metadata: {
            action: plan.action,
            domainXml: plan.domainXml,
            networkXml: plan.networkXml,
            autoStart: false
        }
    });
    assert.equal(started.status, "started");
    assert.equal(started.executed, true);
    assert.equal(executions.length, 1);
    assert.deepEqual(executions[0].args, []);
    assert.equal(executions[0].metadata.autoStart, false);
    assert.match(executions[0].metadata.domainXml, /<source network='mp-lab-isolated'\/>/);
});

test("the lab panel never starts a VM on load or from a timer", () => {
    const panel = fs.readFileSync(path.join(root, "qml", "LabPanel.qml"), "utf8");
    const onCompleted = panel.match(/Component\.onCompleted\s*:\s*\{[^}]*\}/);
    assert.ok(onCompleted, "LabPanel has a completed handler");
    assert.doesNotMatch(onCompleted[0], /runner\.start/);
    assert.match(onCompleted[0], /refreshAvailability/);
    assert.doesNotMatch(panel, /Timer\s*\{[\s\S]{0,400}?runner\.start/);
    assert.match(panel, /Lab\.prepareLaunch/);
    assert.match(panel, /HOST_LAN_NETWORK_ID/);
    assert.match(panel, /hostLanWarning/);
    assert.match(panel, /snapshotGuidance|SNAPSHOT_GUIDANCE/);

    const browser = fs.readFileSync(path.join(root, "src", "app.js"), "utf8");
    assert.doesNotMatch(browser, /boot\(\)[\s\S]{0,800}?runner\.start/);
    assert.doesNotMatch(browser, /setInterval\([^)]*runner\.start/);
    assert.match(browser, /renderLabPanel/);
    assert.match(browser, /Lab\.prepareLaunch/);

    const moduleText = fs.readFileSync(path.join(root, "src", "lab.js"), "utf8");
    assert.doesNotMatch(moduleText, /child_process|execFile|spawn\(|XMLHttpRequest|fetch\(/);
    assert.doesNotMatch(moduleText, /virsh\s+define|virsh\s+start/);
});
