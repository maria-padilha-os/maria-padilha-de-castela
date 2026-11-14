"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const Forensics = require("../src/forensics.js");
const Registry = require("../src/registry.js");
const Authorization = require("../src/authorization.js");
const Runner = require("../src/runner.js");
const { buildSamplePcap } = require("./fixtures/generate-pcap.cjs");

const root = path.join(__dirname, "..");
const fixtures = path.join(__dirname, "fixtures");
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

test("the generated pcap fixture is a valid local capture", () => {
    const generated = buildSamplePcap();
    const committed = fs.readFileSync(path.join(fixtures, "lab-capture.pcap"));
    assert.deepEqual(generated, committed);

    const identified = Forensics.identifyCapture(committed);
    assert.equal(identified.ok, true);
    assert.equal(identified.format, "pcap");
    assert.equal(identified.byteOrder, "little");
    assert.equal(identified.magic, "d4c3b2a1");

    const pcapng = Forensics.identifyCapture(
        Buffer.from([0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00, 0x4d, 0x3c, 0x2b, 0x1a])
    );
    assert.equal(pcapng.ok, true);
    assert.equal(pcapng.format, "pcapng");

    assert.equal(Forensics.identifyCapture(Buffer.from("not a capture")).ok, false);
    assert.equal(Forensics.identifyCapture(Buffer.from([0xd4, 0xc3])).ok, false);
    assert.equal(Forensics.identifyCapture("d4c3b2a1").ok, false);

    const tempPath = path.join(os.tmpdir(), "maria-forensics-test-" + process.pid + ".pcap");
    fs.writeFileSync(tempPath, generated);
    try {
        assert.deepEqual(fs.readFileSync(tempPath), committed);
    } finally {
        fs.unlinkSync(tempPath);
    }
});

test("interface selection accepts explicit names and refuses wildcards or shell text", () => {
    for (const name of ["lo", "eth0", "wlan0", "enp0s3", "virbr0", "usbmon0", "eth0.100"]) {
        const result = Forensics.validateInterface(name);
        assert.equal(result.ok, true, name + ": " + result.reason);
        assert.equal(result.interface, name);
    }
    assert.equal(Forensics.validateInterface("lo").isLoopback, true);
    assert.equal(Forensics.validateInterface("eth0").isLoopback, false);

    for (const name of ["", "   ", "any", "all", "*", "-i", "eth 0", "eth0;id", "$(id)",
        "eth0/1", "eth0\n", "a".repeat(33)]) {
        const result = Forensics.validateInterface(name);
        assert.equal(result.ok, false, JSON.stringify(name) + " must be refused");
        assert.ok(result.reason.length > 0);
    }

    const listed = Forensics.normalizeInterfaces([
        "lo",
        { name: "eth0", description: "lab uplink" },
        "lo",
        { name: "bad name" }
    ]);
    assert.equal(listed.ok, false);
    assert.deepEqual(listed.interfaces.map((entry) => entry.name), ["lo", "eth0"]);
    assert.match(listed.errors[0], /interface/);

    const onlyGood = Forensics.listInterfaces(["lo", "eth0"]);
    assert.equal(onlyGood.ok, true);
    assert.equal(onlyGood.interfaces.length, 2);
});

test("capture requests use a fixed tshark argv, no root, no injection, and no overwrite", () => {
    const request = Forensics.buildCaptureRequest({
        interface: "lo",
        outputPath: "/home/operator/captures/lab.pcapng",
        filter: "tcp"
    });
    assert.equal(request.ok, true);
    assert.equal(request.action, "capture-start");
    assert.equal(request.command, "tshark");
    assert.equal(request.shell, false);
    assert.deepEqual(request.args, [
        "-n",
        "-i",
        "lo",
        "-f",
        "tcp",
        "-w",
        "/home/operator/captures/lab.pcapng",
        "-F",
        "pcapng"
    ]);
    assert.deepEqual(request.argv, ["tshark"].concat(request.args));
    assert.equal(request.stopSignal, "SIGINT");
    assert.equal(request.autoRun, false);
    assert.equal(request.overwrite, false);
    assert.equal(request.uploads, false);
    assert.equal(request.autoUpload, false);
    assert.equal(request.packetInjection, false);

    const unfiltered = Forensics.buildCaptureRequest({
        interface: "eth0",
        path: "/tmp/unfiltered.pcap"
    });
    assert.equal(unfiltered.ok, true);
    assert.deepEqual(unfiltered.args, [
        "-n",
        "-i",
        "eth0",
        "-w",
        "/tmp/unfiltered.pcap",
        "-F",
        "pcapng"
    ]);
    assert.equal(unfiltered.captureFilter, "none");

    assert.equal(Forensics.buildCaptureRequest({
        interface: "any",
        outputPath: "/tmp/lab.pcapng"
    }).ok, false);
    assert.equal(Forensics.buildCaptureRequest({
        interface: "lo",
        outputPath: "/tmp/lab.pcapng",
        filter: "host 8.8.8.8"
    }).ok, false);
    assert.equal(Forensics.buildCaptureRequest({
        interface: "lo",
        outputPath: "/tmp/lab.txt"
    }).ok, false);
    assert.equal(Forensics.buildCaptureRequest({
        interface: "lo",
        outputPath: "https://example.invalid/lab.pcapng"
    }).ok, false);
    assert.equal(Forensics.buildCaptureRequest({
        interface: "lo",
        outputPath: "/dev/zero.pcap"
    }).ok, false);
    assert.equal(Forensics.buildCaptureRequest({
        interface: "lo",
        outputPath: "/tmp/../etc/lab.pcap"
    }).ok, false);
});

test("capture preparation requires confirmation, authorization, lab mode, and scope", () => {
    const auth = new Authorization.AuthorizationState(manifest.authorization);
    const base = {
        interface: "lo",
        outputPath: "/home/operator/captures/lab.pcapng",
        filter: "tcp"
    };

    const unconfirmed = Forensics.prepareCapture(Object.assign({}, base, {
        authorizedLab: true,
        authorization: authorizedState().snapshot()
    }));
    assert.equal(unconfirmed.ok, false);
    assert.equal(unconfirmed.status, "confirmation-required");

    const unconfirmedLab = Forensics.prepareCapture(Object.assign({}, base, {
        confirmed: true,
        authorization: authorizedState().snapshot()
    }));
    assert.equal(unconfirmedLab.ok, false);
    assert.equal(unconfirmedLab.status, "unauthorized");
    assert.match(unconfirmedLab.reason, /authorized-lab/i);

    const noAuth = Forensics.prepareCapture(Object.assign({}, base, {
        confirmed: true,
        authorizedLab: true,
        authorization: auth.snapshot()
    }));
    assert.equal(noAuth.ok, false);
    assert.equal(noAuth.status, "unauthorized");
    assert.match(noAuth.reason, /authorization/i);

    auth.acknowledge("engagement-2026-11 / owned lab");
    const noLab = Forensics.prepareCapture(Object.assign({}, base, {
        confirmed: true,
        authorizedLab: true,
        authorization: auth.snapshot()
    }));
    assert.equal(noLab.ok, false);
    assert.match(noLab.reason, /lab mode/i);

    auth.setLabMode(true);
    const noScope = Forensics.prepareCapture(Object.assign({}, base, {
        confirmed: true,
        authorizedLab: true,
        authorization: auth.snapshot()
    }));
    assert.equal(noScope.ok, false);
    assert.match(noScope.reason, /target scope/i);

    auth.setTargetScope("192.0.2.0/24");
    const ready = Forensics.prepareCapture(Object.assign({}, base, {
        confirmed: true,
        authorizedLab: true,
        authorization: auth.snapshot()
    }));
    assert.equal(ready.ok, true);
    assert.equal(ready.status, "ready");
    assert.equal(ready.authorizedLab, true);
    assert.equal(ready.confirmed, true);
    assert.equal(ready.autoRun, false);
    assert.equal(ready.executed, false);
    assert.equal(ready.uploaded, undefined);
    assert.equal(ready.uploads, false);
});

test("capture preparation rejects upload, remote endpoint, and injection fields", () => {
    const auth = authorizedState().snapshot();
    const base = {
        confirmed: true,
        authorizedLab: true,
        authorization: auth,
        interface: "lo",
        outputPath: "/home/operator/captures/lab.pcapng"
    };
    for (const attempt of [
        { upload: true },
        { uploadUrl: "https://example.invalid/upload" },
        { remote: "example.invalid:443" },
        { endpoint: "https://example.invalid" },
        { url: "https://example.invalid" },
        { webhook: "https://example.invalid" },
        { telemetry: true },
        { inject: true },
        { injection: "tcp" },
        { send: true },
        { transmit: true },
        { spoof: true }
    ]) {
        const plan = Forensics.prepareCapture(Object.assign({}, base, attempt));
        assert.equal(plan.ok, false, JSON.stringify(attempt));
        assert.equal(plan.status, "capture-restricted", JSON.stringify(attempt));
        assert.equal(plan.executed, false);
        assert.equal(plan.uploads, false);
        assert.equal(plan.packetInjection, false);
    }
});

test("capture stop is a graceful signal, never a forced kill", () => {
    const stop = Forensics.buildStopRequest();
    assert.equal(stop.ok, true);
    assert.equal(stop.action, "capture-stop");
    assert.equal(stop.command, "tshark");
    assert.equal(stop.signal, "SIGINT");
    assert.equal(stop.graceful, true);
    assert.equal(stop.force, false);
    assert.equal(stop.autoRun, false);
    assert.equal(stop.executed, false);

    const withPid = Forensics.buildStopRequest({ pid: 4242 });
    assert.equal(withPid.ok, true);
    assert.equal(withPid.pid, 4242);

    assert.equal(Forensics.buildStopRequest({ pid: "4242" }).ok, false);
    assert.equal(Forensics.buildStopRequest({ pid: -1 }).ok, false);
    assert.equal(Forensics.buildStopRequest({ signal: "SIGKILL" }).ok, false);

    const prepared = Forensics.prepareStop({ pid: 7 });
    assert.equal(prepared.ok, true);
    assert.equal(prepared.signal, "SIGINT");
});

test("the runner stops a host-started capture through the explicit stop path", () => {
    const registry = new Registry.TabRegistry(manifest);
    const authorization = authorizedState();
    const executions = [];
    const stops = [];
    const runner = new Runner.ToolRunner({
        registry,
        authorization,
        probe: () => ({ available: true, command: "tshark" }),
        execute(invocation) {
            executions.push(invocation);
            return { pid: 4242 };
        },
        stop(invocation) {
            stops.push(invocation);
            return { status: "signalled" };
        }
    });

    const plan = Forensics.prepareCapture({
        confirmed: true,
        authorizedLab: true,
        authorization: authorization.snapshot(),
        interface: "lo",
        outputPath: "/home/operator/captures/lab.pcapng",
        filter: "tcp"
    });
    assert.equal(plan.ok, true);

    const started = runner.start("forensics", {
        confirmed: true,
        args: plan.args,
        metadata: {
            action: "capture-start",
            interface: plan.interface,
            outputPath: plan.outputPath,
            uploads: false,
            packetInjection: false
        }
    });
    assert.equal(started.status, "started");
    assert.equal(executions.length, 1);
    assert.equal(executions[0].command, "tshark");
    assert.equal(stops.length, 0);
    assert.equal(authorization.snapshot().running, true);

    const stopped = runner.stop();
    assert.equal(stopped.status, "stopped");
    assert.equal(stopped.signal, "SIGINT");
    assert.equal(stops.length, 1);
    assert.equal(stops[0].signal, "SIGINT");
    assert.equal(stops[0].pid, 4242);
    assert.equal(stops[0].graceful, true);
    assert.equal(authorization.snapshot().running, false);
});

test("pcap open is read-only, local, and parseable through tshark JSON", () => {
    const request = Forensics.buildOpenRequest({
        capturePath: "/home/operator/captures/lab.pcap"
    });
    assert.equal(request.ok, true);
    assert.equal(request.action, "pcap-open");
    assert.equal(request.command, "tshark");
    assert.equal(request.shell, false);
    assert.deepEqual(request.args, [
        "-n",
        "-r",
        "/home/operator/captures/lab.pcap",
        "-T",
        "json"
    ]);
    assert.deepEqual(request.argv, ["tshark"].concat(request.args));
    assert.equal(request.readOnly, true);
    assert.equal(request.writeCapture, false);
    assert.equal(request.overwrite, false);
    assert.equal(request.autoRun, false);
    assert.equal(request.uploads, false);
    assert.equal(request.packetInjection, false);

    assert.equal(Forensics.buildOpenRequest({ capturePath: "lab.pcap" }).ok, true);
    assert.equal(Forensics.buildOpenRequest({ capturePath: "https://example.invalid/a.pcap" }).ok, false);
    assert.equal(Forensics.buildOpenRequest({ capturePath: "/tmp/a.txt" }).ok, false);

    const noConfirm = Forensics.prepareOpen({
        capturePath: "/home/operator/captures/lab.pcap",
        authorizedLab: true,
        authorization: authorizedState().snapshot()
    });
    assert.equal(noConfirm.ok, false);
    assert.equal(noConfirm.status, "confirmation-required");

    const ready = Forensics.prepareOpen({
        capturePath: "/home/operator/captures/lab.pcap",
        confirmed: true,
        authorizedLab: true,
        authorization: authorizedState().snapshot()
    });
    assert.equal(ready.ok, true);
    assert.equal(ready.readOnly, true);
    assert.equal(ready.autoRun, false);
});

test("tshark JSON is parsed and every sensitive field and payload is redacted", () => {
    const json = fs.readFileSync(path.join(fixtures, "tshark-sensitive.json"), "utf8");
    const result = Forensics.parseTsharkJson(json);

    assert.equal(result.ok, true);
    assert.equal(result.status, "parsed");
    assert.equal(result.packetCount, 2);
    assert.equal(result.sensitive, true);
    assert.equal(result.payloadPacketCount, 1);
    assert.equal(result.autoUpload, false);
    assert.equal(result.uploads, false);
    assert.ok(result.warnings.some((warning) => /payload/i.test(warning)));
    assert.ok(result.warnings.some((warning) => /redacted/i.test(warning)));
    assert.ok(result.warnings.some((warning) => /never uploaded/i.test(warning)));

    const first = result.packets[0];
    assert.equal(first.source, "192.0.2.10");
    assert.equal(first.destination, "192.0.2.20");
    assert.equal(first.protocol, "HTTP");
    assert.equal(first.http.host, "lab-vm.example");
    assert.equal(first.hasPayload, true);
    assert.ok(first.redactedFields.includes("http.authorization"));
    assert.ok(first.redactedFields.includes("http.cookie"));
    assert.ok(first.redactedFields.includes("http.file_data"));
    assert.match(first.info, /\[REDACTED\]/);
    assert.match(first.http.uri, /\[REDACTED\]/);

    const summary = Forensics.formatCaptureSummary(result);
    for (const secret of [
        "dXNlcjpwYXNzd29yZA==",
        "fixture-session-value",
        "hunter2",
        "fixture-api-key",
        "fixture-token-value"
    ]) {
        assert.equal(summary.includes(secret), false, secret + " leaked into the summary");
    }
    assert.match(summary, /\[REDACTED\]/);
    assert.match(summary, /No capture data was uploaded\./);
    assert.match(summary, /Packets: 2/);

    assert.match(
        Forensics.redactSensitiveText("Authorization: Bearer abcdef0123456789"),
        /Authorization: \[REDACTED\]/
    );
    assert.match(
        Forensics.redactSensitiveText("Cookie: session=abc123; theme=dark"),
        /Cookie: \[REDACTED\]/
    );
    assert.match(
        Forensics.redactSensitiveText("password=hunter2&user=lab"),
        /password=\[REDACTED\]/
    );
    // Build the key marker in pieces so this test file is not itself a
    // private-key literal for the repository secret scan.
    const privateKeyFixture = [
        ["-----BEGIN", "RSA", "PRIVATE KEY-----"].join(" "),
        "MIIE",
        ["-----END", "RSA", "PRIVATE KEY-----"].join(" ")
    ].join("\n");
    assert.match(
        Forensics.redactSensitiveText(privateKeyFixture),
        /REDACTED PRIVATE KEY/
    );
    assert.equal(Forensics.redactSensitiveText("frame 1: 192.0.2.10 -> 192.0.2.20 TCP"), "frame 1: 192.0.2.10 -> 192.0.2.20 TCP");
});

test("malformed, timed-out, and failed tshark results fail closed", () => {
    const malformed = Forensics.parseTsharkJson("{not json");
    assert.equal(malformed.ok, false);
    assert.ok(malformed.errors.length > 0);

    const wrongShape = Forensics.parseTsharkJson('{"hello":"world"}');
    assert.equal(wrongShape.ok, false);
    assert.match(wrongShape.errors[0], /array of packets/i);

    const timedOut = Forensics.interpretCaptureResult({
        status: "timeout",
        timedOut: true
    }, { timeoutMs: 1500 });
    assert.equal(timedOut.ok, false);
    assert.equal(timedOut.status, "timeout");
    assert.match(timedOut.errors[0], /1500 ms/);

    const failed = Forensics.interpretCaptureResult({
        status: "failed",
        exitCode: 2,
        stderr: "tshark: The file could not be opened"
    });
    assert.equal(failed.ok, false);
    assert.equal(failed.status, "error");
    assert.ok(failed.errors.some((error) => /could not be opened/.test(error)));

    const noOutput = Forensics.interpretCaptureResult({ status: "failed" });
    assert.equal(noOutput.ok, false);
    assert.ok(noOutput.errors.some((error) => /did not return JSON/.test(error)));

    const fromStdout = Forensics.interpretCaptureResult({
        stdout: fs.readFileSync(path.join(fixtures, "tshark-sensitive.json"), "utf8"),
        stderr: "",
        exitCode: 0
    });
    assert.equal(fromStdout.ok, true);
    assert.equal(fromStdout.packetCount, 2);
    assert.equal(fromStdout.uploads, false);
});

test("capabilities are documented in code and no root is required by default", () => {
    const report = Forensics.capabilityReport();
    assert.equal(report.rootRequiredByDefault, false);
    assert.equal(report.packetInjection, false);
    assert.equal(report.autoUpload, false);
    assert.equal(report.automaticCapture, false);
    assert.deepEqual(report.required.map((entry) => entry.name).sort(), [
        "CAP_NET_ADMIN",
        "CAP_NET_RAW"
    ]);
    assert.ok(report.required.every((entry) => entry.grantedByDefault === false));
    assert.ok(report.revocation.length > 0);

    const status = Forensics.statusReport({
        available: false,
        missing: "tshark",
        reason: "command not found"
    });
    assert.equal(status.status, "missing-tool");
    assert.equal(status.autoRun, false);
    assert.equal(status.autoUpload, false);
    assert.equal(status.packetInjection, false);
    assert.equal(status.command, "tshark");
    assert.match(status.redaction, /payload/i);
});

test("the forensics module ships no process spawner, network client, or upload path", () => {
    const source = fs.readFileSync(path.join(__dirname, "..", "src", "forensics.js"), "utf8");
    assert.doesNotMatch(source, /child_process/);
    assert.doesNotMatch(source, /require\(["'](?:http|https|net|tls)["']\)/);
    assert.doesNotMatch(source, /\b(?:spawn|execFile|execSync|fork)\s*\(/);
    assert.doesNotMatch(source, /(?:^|[^.\w])exec\s*\(/m);
    assert.doesNotMatch(source, /\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(/);
    assert.doesNotMatch(source, /\b(?:tcpreplay|scapy|sendp|hping3)\b/);
    assert.doesNotMatch(source, /\b(sudo|pkexec|systemctl|pacman|mount)\s/);
    assert.doesNotMatch(source, /autoUpload\s*:\s*true/);
    assert.doesNotMatch(source, /packetInjection\s*:\s*true/);
});

test("the forensics panel never starts a capture on load and offers an explicit stop", () => {
    const panel = fs.readFileSync(path.join(root, "qml", "ForensicsPanel.qml"), "utf8");
    const onCompleted = panel.match(/Component\.onCompleted\s*:\s*\{[^}]*\}/);
    assert.ok(onCompleted, "ForensicsPanel has a completed handler");
    assert.doesNotMatch(onCompleted[0], /runner\.start/);
    assert.match(onCompleted[0], /refreshAvailability/);
    assert.doesNotMatch(panel, /Timer\s*\{[\s\S]{0,400}?runner\.start/);
    assert.match(panel, /prepareCapture/);
    assert.match(panel, /prepareOpen/);
    assert.match(panel, /buildStopRequest|Stop capture/);
    assert.match(panel, /No capture data is uploaded|never uploaded|No capture data was uploaded/i);

    const browser = fs.readFileSync(path.join(root, "src", "app.js"), "utf8");
    assert.doesNotMatch(browser, /boot\(\)[\s\S]{0,800}?runner\.start/);
    assert.doesNotMatch(browser, /setInterval\([^)]*runner\.start/);
    assert.match(browser, /renderForensicsPanel/);
});

test("the manifest marks forensics read-only with no injection or upload", () => {
    const tab = manifest.tabs.find((entry) => entry.id === "forensics");
    assert.ok(tab, "forensics tab is registered");
    assert.equal(tab.autoRun, false);
    assert.ok(tab.tool.commands.includes("tshark"));
    assert.equal(tab.policy.readOnly, true);
    assert.equal(tab.policy.packetInjection, false);
    assert.equal(tab.policy.uploads, false);
    assert.equal(tab.policy.autoCapture, false);
    assert.equal(tab.policy.sensitivePayloads, "redact-and-warn");
});

test("the capability and revocation documentation covers the capture boundary", () => {
    const doc = fs.readFileSync(
        path.join(root, "..", "..", "docs", "policy", "forensics-capabilities.md"),
        "utf8"
    );
    for (const term of [
        "CAP_NET_RAW",
        "CAP_NET_ADMIN",
        "setcap",
        "revoke",
        "no root",
        "packet injection",
        "upload",
        "tshark"
    ]) {
        assert.match(doc, new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
    }
});
