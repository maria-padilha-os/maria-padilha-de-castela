"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const Authorization = require("../src/authorization.js");

function enabledState() {
    const auth = new Authorization.AuthorizationState({
        banner: "AUTHORIZED USE ONLY",
        unboundedScopes: ["^0\\.0\\.0\\.0/0$", "^\\*$"]
    });
    assert.equal(auth.acknowledge("engagement-2026-11 / owned lab").ok, true);
    assert.equal(auth.setLabMode(true).ok, true);
    assert.equal(auth.setTargetScope("192.0.2.0/24").ok, true);
    return auth;
}

test("authorization is fail-closed by default", () => {
    const auth = new Authorization.AuthorizationState({
        banner: "AUTHORIZED USE ONLY. Owned systems or written permission only."
    });
    const snapshot = auth.snapshot();
    assert.equal(snapshot.acknowledged, false);
    assert.equal(snapshot.labMode, false);
    assert.equal(snapshot.scope, "");
    assert.equal(snapshot.authorized, false);
    assert.equal(snapshot.canRun, false);
    assert.ok(snapshot.banner.includes("AUTHORIZED USE ONLY"));
    assert.equal(auth.beginRun("nmap").ok, false);
});

test("lab mode requires an acknowledged written authorization", () => {
    const auth = new Authorization.AuthorizationState({ banner: "AUTHORIZED USE ONLY" });
    const refused = auth.setLabMode(true);
    assert.equal(refused.ok, false);
    assert.match(refused.reason, /acknowledge/);
    assert.equal(auth.snapshot().labMode, false);

    const emptyReference = auth.acknowledge("   ");
    assert.equal(emptyReference.ok, false);
    assert.equal(auth.snapshot().acknowledged, false);

    const accepted = auth.acknowledge("engagement-2026-11 / owned lab");
    assert.equal(accepted.ok, true);
    assert.equal(accepted.state.acknowledged, true);
    assert.equal(auth.setLabMode(true).ok, true);
});

test("a bounded target scope is required before a run", () => {
    const auth = new Authorization.AuthorizationState({ banner: "AUTHORIZED USE ONLY" });
    auth.acknowledge("engagement-2026-11 / owned lab");
    auth.setLabMode(true);

    assert.equal(auth.beginRun("nmap").ok, false);
    assert.equal(auth.setTargetScope("   ").ok, false);
    assert.equal(auth.setTargetScope("*").ok, false);
    assert.equal(auth.setTargetScope("0.0.0.0/0").ok, false);
    assert.equal(auth.setTargetScope("public").ok, false);
    assert.equal(auth.snapshot().scope, "");

    assert.equal(auth.setTargetScope("192.0.2.0/24").ok, true);
    assert.equal(auth.snapshot().scope, "192.0.2.0/24");
    assert.equal(auth.canRun(), true);
});

test("stop cancels the current operation but keeps the scope", () => {
    const auth = enabledState();
    const started = auth.beginRun("nmap");
    assert.equal(started.ok, true);
    assert.equal(auth.snapshot().running, true);
    assert.equal(auth.snapshot().activeTool, "nmap");
    assert.equal(auth.canRun(), false);

    const stopped = auth.stop();
    assert.equal(stopped.ok, true);
    assert.equal(auth.snapshot().running, false);
    assert.equal(auth.snapshot().activeTool, null);
    assert.equal(auth.snapshot().scope, "192.0.2.0/24");
    assert.equal(auth.snapshot().lastAction, "stop");
});

test("clear removes the scope and queued targets", () => {
    const auth = enabledState();
    assert.equal(auth.queueTarget("192.0.2.10").ok, true);
    assert.equal(auth.snapshot().queuedTargets.length, 1);

    const cleared = auth.clear();
    assert.equal(cleared.ok, true);
    assert.equal(auth.snapshot().scope, "");
    assert.deepEqual(auth.snapshot().queuedTargets, []);
    assert.equal(auth.snapshot().running, false);
    assert.equal(auth.snapshot().canRun, false);
    assert.equal(auth.snapshot().lastAction, "clear");
});

test("withdrawing authorization disables lab mode and running state", () => {
    const auth = enabledState();
    auth.beginRun("nmap");
    const withdrawn = auth.withdrawAuthorization();
    assert.equal(withdrawn.ok, true);
    assert.equal(auth.snapshot().acknowledged, false);
    assert.equal(auth.snapshot().labMode, false);
    assert.equal(auth.snapshot().running, false);
});

test("a second run is refused while one is active", () => {
    const auth = enabledState();
    assert.equal(auth.beginRun("nmap").ok, true);
    const second = auth.beginRun("forensics");
    assert.equal(second.ok, false);
    assert.match(second.reason, /already running/);
});
