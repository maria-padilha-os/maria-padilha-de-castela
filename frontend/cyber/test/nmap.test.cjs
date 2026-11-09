"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const Nmap = require("../src/nmap.js");

const fixtures = path.join(__dirname, "fixtures");
const basicXml = fs.readFileSync(path.join(fixtures, "nmap-basic.xml"), "utf8");
const errorXml = fs.readFileSync(path.join(fixtures, "nmap-error.xml"), "utf8");
const timeoutXml = fs.readFileSync(path.join(fixtures, "nmap-timeout.xml"), "utf8");

test("documented profiles are unprivileged and only use allowlisted flags", () => {
    const profiles = Nmap.listProfiles();
    assert.deepEqual(profiles.map((profile) => profile.id), [
        "discovery",
        "tcp-connect",
        "service",
        "top-100"
    ]);

    const prohibited = ["-sS", "-sU", "-O", "-A", "--script", "--privileged"];
    for (const profile of profiles) {
        assert.ok(profile.label.length > 0, profile.id + " needs a label");
        assert.ok(profile.description.length > 0, profile.id + " needs documentation");
        for (const arg of profile.args) {
            assert.ok(!prohibited.includes(arg),
                profile.id + " uses privileged/aggressive flag " + arg);
        }
    }
});

test("private and documentation/lab targets are accepted and canonicalized", () => {
    const cases = [
        ["10.1.2.3", "10.1.2.3"],
        ["172.16.5.4", "172.16.5.4"],
        ["192.168.1.10", "192.168.1.10"],
        ["127.0.0.1", "127.0.0.1"],
        ["169.254.10.20", "169.254.10.20"],
        ["192.0.2.10", "192.0.2.10"],
        ["198.51.100.0/24", "198.51.100.0/24"],
        ["203.0.113.0/24", "203.0.113.0/24"],
        ["192.168.1.5/24", "192.168.1.0/24"],
        ["Lab-VM.Example.", "lab-vm.example"],
        ["localhost", "localhost"],
        ["lab-switch.lab", "lab-switch.lab"],
        ["fc00::1", "fc00::1"],
        ["fe80::1234", "fe80::1234"],
        ["2001:db8::10", "2001:db8::10"],
        ["2001:db8::10/64", "2001:db8::/64"]
    ];

    for (const [input, expected] of cases) {
        const result = Nmap.validateTarget(input);
        assert.equal(result.ok, true, input + " should be accepted: " + result.reason);
        assert.equal(result.canonical, expected);
        assert.equal(result.isPrivate, true);
    }
});

test("public, unbounded, ambiguous, and malformed targets are refused by default", () => {
    const rejected = [
        "8.8.8.8",
        "1.1.1.1",
        "0.0.0.0/0",
        "0.0.0.0",
        "203.0.114.10",
        "10.0.0.1/8x",
        "10.0.0.0/7",
        "192.168.0.0/15",
        "fc00::/6",
        "2001:db8::/31",
        "999.1.1.1",
        "010.0.0.1",
        "example.com",
        "www.example.net",
        "",
        "   ",
        "-iL",
        "10.0.0.1; id",
        "10.0.0.1 && id",
        "10.0.0.1 | tee /tmp/pwned",
        "$(id)",
        "`id`",
        "10.0.0.1\n10.0.0.2",
        "10.0.0.1 -oN /tmp/out",
        "10.0.0.1,10.0.0.2"
    ];

    for (const input of rejected) {
        const result = Nmap.validateTarget(input);
        assert.equal(result.ok, false, input + " must be rejected");
        assert.ok(result.reason.length > 0);
    }
});

test("public targets require an explicit opt-in and stay marked non-private", () => {
    const refused = Nmap.validateTarget("8.8.8.8");
    assert.equal(refused.ok, false);
    assert.match(refused.reason, /public|lab|private/i);

    const allowed = Nmap.validateTarget("8.8.8.8", { allowPublic: true });
    assert.equal(allowed.ok, true);
    assert.equal(allowed.canonical, "8.8.8.8");
    assert.equal(allowed.isPrivate, false);
});

test("target scope containment is checked for addresses, CIDRs, and lab names", () => {
    assert.equal(Nmap.targetInScope("192.0.2.10", "192.0.2.0/24").ok, true);
    assert.equal(Nmap.targetInScope("192.0.2.0/24", "192.0.2.0/24").ok, true);
    assert.equal(Nmap.targetInScope("192.0.2.0/16", "192.0.2.0/24").ok, false);
    assert.equal(Nmap.targetInScope("192.0.3.10", "192.0.2.0/24").ok, false);
    assert.equal(Nmap.targetInScope("10.0.0.1", "192.0.2.0/24").ok, false);
    assert.equal(Nmap.targetInScope("lab-vm.example", "lab-vm.example").ok, true);
    assert.equal(Nmap.targetInScope("lab-vm.example", "example").ok, true);
    assert.equal(Nmap.targetInScope("other.example", "lab-vm.example").ok, false);
    assert.equal(Nmap.targetInScope("10.0.0.1", "lab-vm.example").ok, false);
});

test("profiles, options, and timeouts are allowlisted", () => {
    assert.equal(Nmap.getProfile("connect").id, "tcp-connect");
    assert.equal(Nmap.getProfile("not-a-profile"), null);

    const request = Nmap.buildScanRequest({
        target: "192.0.2.10",
        scope: "192.0.2.0/24",
        profile: "service",
        options: ["open-only", "noPing"],
        timeoutMs: 30000
    });
    assert.equal(request.ok, true);
    assert.equal(request.command, "nmap");
    assert.equal(request.shell, false);
    assert.equal(request.timeoutMs, 30000);
    assert.deepEqual(request.args, [
        "-sT",
        "-sV",
        "-Pn",
        "--open",
        "-oX",
        "-",
        "192.0.2.10"
    ]);
    assert.deepEqual(request.argv, ["nmap"].concat(request.args));

    const unknownProfile = Nmap.buildScanRequest({
        target: "192.0.2.10",
        profile: "syn-scan"
    });
    assert.equal(unknownProfile.ok, false);
    assert.match(unknownProfile.reason, /unknown Nmap profile/);

    const unknownOption = Nmap.buildScanRequest({
        target: "192.0.2.10",
        profile: "tcp-connect",
        options: ["--script=vuln"]
    });
    assert.equal(unknownOption.ok, false);
    assert.match(unknownOption.reason, /unknown Nmap option/);

    const incompatible = Nmap.buildScanRequest({
        target: "192.0.2.10",
        profile: "discovery",
        options: ["top-ports-100"]
    });
    assert.equal(incompatible.ok, false);
    assert.match(incompatible.reason, /not available for profile/);

    const badTimeout = Nmap.buildScanRequest({
        target: "192.0.2.10",
        timeoutMs: 9999999
    });
    assert.equal(badTimeout.ok, false);
    assert.match(badTimeout.reason, /timeoutMs/);
});

test("the built argv never contains a shell or an arbitrary target flag", () => {
    const request = Nmap.buildScanRequest({
        target: "10.0.0.5",
        scope: "10.0.0.0/8",
        profile: "top-100",
        options: ["open-only", "reason"]
    });
    assert.equal(request.ok, true);
    assert.deepEqual(request.args, [
        "-sT",
        "--top-ports",
        "100",
        "--open",
        "--reason",
        "-oX",
        "-",
        "10.0.0.5"
    ]);
    assert.equal(request.shell, false);
    assert.equal(request.args.some((arg) => arg === "-c" || arg === "sh" || arg === "bash"), false);
});

test("IPv6 targets get the -6 flag and are still validated", () => {
    const request = Nmap.buildScanRequest({
        target: "2001:db8::10",
        scope: "2001:db8::/32",
        profile: "tcp-connect"
    });
    assert.equal(request.ok, true);
    assert.deepEqual(request.args, [
        "-6",
        "-sT",
        "-oX",
        "-",
        "2001:db8::10"
    ]);

    assert.equal(Nmap.validateTarget("2001:4860:4860::8888").ok, false);
    assert.equal(Nmap.validateTarget("::/0").ok, false);
});

test("a request outside the configured scope is refused", () => {
    const result = Nmap.buildScanRequest({
        target: "192.168.2.10",
        scope: "192.168.1.0/24",
        profile: "tcp-connect"
    });
    assert.equal(result.ok, false);
    assert.match(result.reason, /outside the configured scope/);
});

test("prepareScan requires the explicit authorized-lab confirmation and scope", () => {
    const unconfirmed = Nmap.prepareScan({
        target: "192.0.2.10",
        scope: "192.0.2.0/24"
    });
    assert.equal(unconfirmed.ok, false);
    assert.match(unconfirmed.reason, /authorized-lab confirmation/);

    const unscoped = Nmap.prepareScan({
        target: "192.0.2.10",
        authorizedLab: true
    });
    assert.equal(unscoped.ok, false);
    assert.match(unscoped.reason, /target scope/);

    const ready = Nmap.prepareScan({
        target: "192.0.2.10",
        scope: "192.0.2.0/24",
        authorizedLab: true,
        profile: "service"
    });
    assert.equal(ready.ok, true);
    assert.equal(ready.authorizedLab, true);
    assert.equal(ready.autoRun, false);
});

test("Nmap XML is parsed into hosts, ports, and services", () => {
    const result = Nmap.parseNmapXml(basicXml);
    assert.equal(result.ok, true);
    assert.equal(result.timedOut, false);
    assert.deepEqual(result.errors, []);
    assert.equal(result.hosts.length, 1);

    const host = result.hosts[0];
    assert.equal(host.address, "192.0.2.10");
    assert.equal(host.status, "up");
    assert.deepEqual(host.addresses, [
        { addr: "192.0.2.10", addrtype: "ipv4", vendor: "" }
    ]);
    assert.equal(host.hostname, "lab-vm.example");

    assert.equal(host.ports.length, 2);
    assert.equal(host.ports[0].portid, 22);
    assert.equal(host.ports[0].protocol, "tcp");
    assert.equal(host.ports[0].state, "open");
    assert.equal(host.ports[0].service.name, "ssh");
    assert.equal(host.ports[0].service.product, "OpenSSH");
    assert.equal(host.ports[0].service.version, "9.6");
    assert.equal(host.ports[1].service.name, "https");
    assert.equal(host.ports[1].service.product, "nginx & test");
    assert.equal(host.ports[1].service.tunnel, "ssl");

    assert.equal(result.summary.exit, "success");
    assert.equal(result.summary.elapsedSeconds, 1.23);
    assert.equal(result.summary.hostsUp, 1);
    assert.equal(result.summary.hostsTotal, 1);
});

test("Nmap XML errors and timeouts are surfaced instead of hidden", () => {
    const failed = Nmap.parseNmapXml(errorXml);
    assert.equal(failed.ok, false);
    assert.equal(failed.status, "error");
    assert.equal(failed.timedOut, false);
    assert.ok(failed.errors.some((error) => /exited with status error/.test(error)));
    assert.ok(failed.errors.some((error) => /route & stopped/.test(error)));
    assert.equal(failed.hosts.length, 1);

    const timedOut = Nmap.parseNmapXml(timeoutXml);
    assert.equal(timedOut.ok, false);
    assert.equal(timedOut.timedOut, true);
    assert.equal(timedOut.status, "timeout");
    assert.ok(timedOut.errors.some((error) => /timed out/i.test(error)));
});

test("malformed or unsafe XML fails closed without throwing", () => {
    const cases = [
        "",
        "<nmaprun><host></nmaprun>",
        "<nmaprun><host/></nmaprun>",
        "<nmaprun><host/></nmaprun> trailing",
        "<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><nmaprun/>",
        "<html><body>not nmap</body></html>",
        "<nmaprun>&bogus;</nmaprun>"
    ];
    for (const xml of cases) {
        const result = Nmap.parseNmapXml(xml);
        assert.equal(result.ok, false, xml);
        assert.ok(Array.isArray(result.errors));
        assert.ok(result.errors.length > 0);
    }
});

test("executor results are interpreted for XML, stderr, failures, and timeouts", () => {
    const fromStdout = Nmap.interpretScanResult({ stdout: basicXml, stderr: "", exitCode: 0 });
    assert.equal(fromStdout.ok, true);
    assert.equal(fromStdout.hosts[0].ports[0].portid, 22);

    const timedOut = Nmap.interpretScanResult({
        status: "timeout",
        timedOut: true,
        stderr: ""
    }, { timeoutMs: 1500 });
    assert.equal(timedOut.ok, false);
    assert.equal(timedOut.timedOut, true);
    assert.match(timedOut.errors[0], /1500 ms/);

    const failed = Nmap.interpretScanResult({
        status: "failed",
        exitCode: 2,
        stderr: "nmap: failed to open device"
    });
    assert.equal(failed.ok, false);
    assert.equal(failed.timedOut, false);
    assert.ok(failed.errors.some((error) => /failed to open device/.test(error)));

    const noXml = Nmap.interpretScanResult({ status: "failed" });
    assert.equal(noXml.ok, false);
    assert.ok(noXml.errors.some((error) => /did not return XML/.test(error)));
});

test("the human-readable summary shows hosts, ports, services, and errors", () => {
    const parsed = Nmap.parseNmapXml(basicXml);
    const text = Nmap.formatScanResult(parsed);
    assert.match(text, /192\.0\.2\.10 \(lab-vm\.example\) - up/);
    assert.match(text, /tcp\/22 open ssh \(OpenSSH 9\.6\)/);
    assert.match(text, /tcp\/443 open https/);
    assert.match(text, /Nmap status: success/);

    const failed = Nmap.formatScanResult(Nmap.parseNmapXml(errorXml));
    assert.match(failed, /Errors:/);
    assert.match(failed, /exited with status error/);
});

test("the Nmap module ships no process spawner or network client", () => {
    const source = fs.readFileSync(path.join(__dirname, "..", "src", "nmap.js"), "utf8");
    assert.doesNotMatch(source, /child_process|require\(["'](?:http|https|net)["']\)/);
    assert.doesNotMatch(source, /\b(?:spawn|execFile|execSync)\s*\(/);
    assert.doesNotMatch(source, /(?:^|[^.\w])exec\s*\(/m);
    assert.doesNotMatch(source, /\b(sudo|pkexec|systemctl|pacman|mount)\s/);
});
