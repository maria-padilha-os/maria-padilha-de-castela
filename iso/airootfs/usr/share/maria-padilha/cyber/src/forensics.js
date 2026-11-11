/*
 * Safe, shared Wireshark/forensics helpers.
 *
 * This module never starts a process, never opens a device, never performs a
 * network request, and never uploads a capture. It only:
 *   - validates an operator-supplied interface and capture path;
 *   - turns a fixed capture/open profile into an argv array for tshark;
 *   - describes the required Linux capabilities and the stop signal;
 *   - parses the JSON that tshark produces for a pcap;
 *   - redacts sensitive headers, credentials, and payload bytes from the
 *     summary shown in the UI.
 *
 * Security properties:
 *   - no root is required by default; capture capabilities are optional and
 *     documented separately;
 *   - there is no packet injection or transmission path;
 *   - captures are opened read-only (`-r`) and never rewritten;
 *   - opening a pcap is a local read: no name resolution and no network I/O;
 *   - no upload, remote endpoint, or telemetry field is accepted;
 *   - every payload field is replaced with a redaction marker, and credential
 *     patterns are redacted even outside payload fields.
 *
 * The host executor is the only execution boundary. It must pass the returned
 * argv directly to tshark without a shell.
 */

"use strict";

var TSHARK_COMMAND = "tshark";
var WIRESHARK_COMMAND = "wireshark";
var STOP_SIGNAL = "SIGINT";
var DEFAULT_CAPTURE_FILTER = "none";
var MAX_INTERFACE_LENGTH = 32;
var MAX_PATH_LENGTH = 4096;
var MAX_REDACT_LENGTH = 131072;
var CAPTURE_EXTENSIONS = [".pcap", ".pcapng", ".cap"];

var CAPTURE_FILTERS = {
    "none": {
        id: "none",
        label: "No capture filter (all traffic on the selected interface)",
        description: "Capture everything visible on the selected interface.",
        expression: ""
    },
    "ip": {
        id: "ip",
        label: "IPv4 only (ip)",
        description: "Capture IPv4 traffic only.",
        expression: "ip"
    },
    "ipv6": {
        id: "ipv6",
        label: "IPv6 only (ip6)",
        description: "Capture IPv6 traffic only.",
        expression: "ip6"
    },
    "tcp": {
        id: "tcp",
        label: "TCP only (tcp)",
        description: "Capture TCP segments only.",
        expression: "tcp"
    },
    "udp": {
        id: "udp",
        label: "UDP only (udp)",
        description: "Capture UDP datagrams only.",
        expression: "udp"
    },
    "icmp": {
        id: "icmp",
        label: "ICMP/ICMPv6 only (icmp or icmp6)",
        description: "Capture ICMP and ICMPv6 traffic only.",
        expression: "icmp or icmp6"
    },
    "arp": {
        id: "arp",
        label: "ARP only (arp)",
        description: "Capture ARP traffic only.",
        expression: "arp"
    },
    "dns": {
        id: "dns",
        label: "DNS only (port 53)",
        description: "Capture traffic to or from port 53. Payloads are still redacted.",
        expression: "port 53"
    },
    "http": {
        id: "http",
        label: "HTTP only (port 80)",
        description: "Capture cleartext HTTP on port 80. Sensitive fields are redacted from the summary.",
        expression: "tcp port 80"
    },
    "tls": {
        id: "tls",
        label: "TLS only (port 443)",
        description: "Capture TLS records on port 443. Encrypted payloads remain opaque.",
        expression: "tcp port 443"
    }
};

var FILTER_ORDER = [
    "none",
    "ip",
    "ipv6",
    "tcp",
    "udp",
    "icmp",
    "arp",
    "dns",
    "http",
    "tls"
];

var FILTER_ALIASES = {
    "all": "none",
    "any": "none",
    "ip4": "ip",
    "ip6": "ipv6",
    "icmp6": "icmp",
    "icmpv6": "icmp"
};

var CAPABILITIES = {
    rootRequiredByDefault: false,
    packetInjection: false,
    autoUpload: false,
    automaticCapture: false,
    captureCommand: TSHARK_COMMAND,
    openCommand: TSHARK_COMMAND,
    required: [
        {
            name: "CAP_NET_RAW",
            scope: "process",
            reason: "Open a capture device and receive raw frames.",
            grantedByDefault: false,
            optional: true
        },
        {
            name: "CAP_NET_ADMIN",
            scope: "process",
            reason: "Promiscuous or monitor-mode capture on an interface.",
            grantedByDefault: false,
            optional: true
        }
    ],
    revocation: [
        "Remove the file capabilities from the capture helper.",
        "Remove the operator from the packet-capture group.",
        "Re-check the live capability set and restart the session."
    ]
};

var BLOCKED_REMOTE_FIELDS = [
    {key: "upload", label: "an upload"},
    {key: "uploads", label: "uploads"},
    {key: "uploadUrl", label: "an upload URL"},
    {key: "remote", label: "a remote endpoint"},
    {key: "remoteHost", label: "a remote host"},
    {key: "endpoint", label: "a remote endpoint"},
    {key: "url", label: "a URL"},
    {key: "webhook", label: "a webhook"},
    {key: "telemetry", label: "telemetry"},
    {key: "inject", label: "packet injection"},
    {key: "injection", label: "packet injection"},
    {key: "send", label: "packet transmission"},
    {key: "transmit", label: "packet transmission"},
    {key: "spoof", label: "packet spoofing"}
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

function unique(values) {
    var seen = Object.create(null);
    var out = [];
    values.forEach(function (value) {
        if (!seen[value]) {
            seen[value] = true;
            out.push(value);
        }
    });
    return out;
}

function failure(reason, status, extra) {
    var result = {
        ok: false,
        status: status || "invalid",
        reason: reason,
        errors: [reason],
        autoRun: false,
        executed: false,
        uploads: false,
        packetInjection: false
    };
    if (isObject(extra)) {
        Object.keys(extra).forEach(function (key) {
            result[key] = extra[key];
        });
    }
    return result;
}

function asErrorList(value) {
    if (Array.isArray(value)) {
        return value.filter(nonEmpty).map(function (item) {
            return item.trim();
        });
    }
    if (nonEmpty(value)) {
        return [value.trim()];
    }
    return [];
}

/* ------------------------------------------------------------------------- *
 * Interface, path, and filter validation
 * ------------------------------------------------------------------------- */

function validateInterface(value) {
    if (typeof value !== "string") {
        return failure("an interface name must be a string");
    }
    if (/[\0\r\n]/.test(value)) {
        return failure("interface contains a NUL or newline");
    }
    var raw = value.trim();
    if (raw.length === 0) {
        return failure("an interface is required");
    }
    if (raw.length > MAX_INTERFACE_LENGTH) {
        return failure("interface name is too long");
    }
    if (raw.charAt(0) === "-") {
        return failure("an interface must not begin with a dash");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9_.:@+-]*$/.test(raw)) {
        return failure("interface contains whitespace, shell characters, or unsupported punctuation");
    }
    var lower = raw.toLowerCase();
    if (lower === "any" || lower === "all" || lower === "*") {
        return failure("select one explicit interface; a wildcard or all-interface capture is refused");
    }
    return {
        ok: true,
        interface: raw,
        name: raw,
        isLoopback: lower === "lo" || lower.indexOf("lo.") === 0
    };
}

function normalizeInterfaces(input) {
    var values = [];
    var errors = [];

    if (typeof input === "undefined" || input === null) {
        values = [];
    } else if (Array.isArray(input)) {
        values = input.slice();
    } else {
        values = [input];
    }

    var seen = Object.create(null);
    var interfaces = [];
    values.forEach(function (value) {
        var name = value;
        var description = "";
        if (isObject(value)) {
            name = value.name || value.interface || value.id;
            description = nonEmpty(value.description) ? value.description : "";
        }
        var result = validateInterface(name);
        if (!result.ok) {
            errors.push(result.reason);
            return;
        }
        if (seen[result.interface]) {
            return;
        }
        seen[result.interface] = true;
        interfaces.push({
            name: result.interface,
            interface: result.interface,
            description: description,
            isLoopback: result.isLoopback
        });
    });

    return {
        ok: errors.length === 0,
        interfaces: interfaces,
        errors: unique(errors)
    };
}

function listInterfaces(input) {
    return normalizeInterfaces(input);
}

function normalizeFilter(value) {
    if (typeof value === "undefined" || value === null || value === "") {
        return DEFAULT_CAPTURE_FILTER;
    }
    if (!nonEmpty(value)) {
        return null;
    }
    var key = value.trim().toLowerCase().replace(/_/g, "-");
    if (Object.prototype.hasOwnProperty.call(CAPTURE_FILTERS, key)) {
        return key;
    }
    if (Object.prototype.hasOwnProperty.call(FILTER_ALIASES, key)) {
        return FILTER_ALIASES[key];
    }
    return null;
}

function listCaptureFilters() {
    return FILTER_ORDER.map(function (id) {
        return clone(CAPTURE_FILTERS[id]);
    });
}

function validateCapturePath(value, options) {
    options = options || {};
    if (typeof value !== "string") {
        return failure("a capture path must be a string");
    }
    var raw = value.trim();
    if (raw.length === 0) {
        return failure("a capture path is required");
    }
    if (raw.length > MAX_PATH_LENGTH) {
        return failure("capture path is too long");
    }
    if (raw.charAt(0) === "-") {
        return failure("a capture path must not begin with a dash");
    }
    if (/[\0\r\n]/.test(raw)) {
        return failure("capture path contains a NUL or newline");
    }
    if (/[;&|`$<>\\]/.test(raw)) {
        return failure("capture path contains shell control characters");
    }
    if (raw.indexOf("://") !== -1) {
        return failure("capture path must be a local file, not a URL or remote endpoint");
    }
    var segments = raw.split("/");
    if (segments.indexOf("..") !== -1) {
        return failure("capture path must not contain a parent-directory segment");
    }
    if (raw === "/dev" || raw.indexOf("/dev/") === 0) {
        return failure("capture path must not point at a device node");
    }

    var lower = raw.toLowerCase();
    var matched = null;
    CAPTURE_EXTENSIONS.forEach(function (extension) {
        if (lower.slice(-extension.length) === extension) {
            matched = extension;
        }
    });
    if (!matched) {
        return failure("capture path must end in " + CAPTURE_EXTENSIONS.join(", "));
    }

    return {
        ok: true,
        path: raw,
        capturePath: raw,
        extension: matched,
        format: matched === ".pcapng" ? "pcapng" : "pcap",
        mustExist: options.mustExist === true
    };
}

/* ------------------------------------------------------------------------- *
 * Capture start / stop and pcap open requests
 * ------------------------------------------------------------------------- */

function baseCapturePlan() {
    return {
        ok: false,
        status: "idle",
        action: "capture-start",
        command: TSHARK_COMMAND,
        shell: false,
        args: [],
        argv: [TSHARK_COMMAND],
        interface: null,
        outputPath: null,
        captureFilter: null,
        filterExpression: "",
        stopSignal: STOP_SIGNAL,
        readOnly: false,
        writeCapture: true,
        overwrite: false,
        autoRun: false,
        executed: false,
        uploads: false,
        autoUpload: false,
        packetInjection: false,
        capabilities: clone(CAPABILITIES)
    };
}

function buildCaptureRequest(options) {
    options = isObject(options) ? options : {};

    var iface = validateInterface(options.interface);
    if (!iface.ok) {
        return failure(iface.reason, "invalid", {action: "capture-start"});
    }

    var outputPath = typeof options.outputPath !== "undefined"
        ? options.outputPath
        : options.path;
    var path = validateCapturePath(outputPath);
    if (!path.ok) {
        return failure(path.reason, "invalid", {action: "capture-start"});
    }

    var filterId = normalizeFilter(
        typeof options.filter !== "undefined" ? options.filter : options.captureFilter
    );
    if (!filterId) {
        return failure("unknown capture filter; choose " + FILTER_ORDER.join(", "),
            "invalid", {action: "capture-start"});
    }
    var filter = CAPTURE_FILTERS[filterId];

    var args = ["-n", "-i", iface.interface];
    if (filter.expression.length > 0) {
        args.push("-f", filter.expression);
    }
    args.push("-w", path.path, "-F", "pcapng");

    var plan = baseCapturePlan();
    plan.ok = true;
    plan.status = "ready";
    plan.interface = iface.interface;
    plan.outputPath = path.path;
    plan.outputFormat = "pcapng";
    plan.captureFilter = filterId;
    plan.filterExpression = filter.expression;
    plan.args = args;
    plan.argv = [TSHARK_COMMAND].concat(args);
    plan.reason = "explicit capture request for interface " + iface.interface;
    return plan;
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
        return "a bounded target scope is required before a capture or pcap open";
    }
    if (authorization.running === true) {
        return "a tool is already running; stop it first";
    }
    return "";
}

function blockedRemoteReason(options) {
    var index;
    for (index = 0; index < BLOCKED_REMOTE_FIELDS.length; index += 1) {
        var entry = BLOCKED_REMOTE_FIELDS[index];
        var value = options[entry.key];
        if (value === null || typeof value === "undefined" || value === false) {
            continue;
        }
        if (typeof value === "string" && value.trim().length === 0) {
            continue;
        }
        if (Array.isArray(value) && value.length === 0) {
            continue;
        }
        if (isObject(value) && Object.keys(value).length === 0) {
            continue;
        }
        return "this panel does not accept " + entry.label +
            "; captures are never uploaded, transmitted, or injected";
    }
    return "";
}

function prepareCapture(options) {
    options = isObject(options) ? options : {};

    if (options.confirmed !== true) {
        return failure(
            "explicit operator confirmation is required before capture",
            "confirmation-required",
            {action: "capture-start"}
        );
    }

    var blocked = blockedRemoteReason(options);
    if (blocked.length > 0) {
        return failure(blocked, "capture-restricted", {action: "capture-start"});
    }

    if (options.authorizedLab !== true) {
        return failure(
            "explicit authorized-lab confirmation is required before capture",
            "unauthorized",
            {action: "capture-start"}
        );
    }

    var unauthorized = authorizationReason(options.authorization);
    if (unauthorized.length > 0) {
        return failure(unauthorized, "unauthorized", {action: "capture-start"});
    }

    var plan = buildCaptureRequest(options);
    if (!plan.ok) {
        return plan;
    }
    plan.authorizedLab = true;
    plan.confirmed = true;
    plan.authorization = clone(options.authorization);
    plan.reason = "explicit operator confirmation accepted; tshark will capture to a new local file";
    return plan;
}

function buildStopRequest(options) {
    options = isObject(options) ? options : {};

    var signal = nonEmpty(options.signal) ? options.signal.trim().toUpperCase() : STOP_SIGNAL;
    if (signal !== "SIGINT" && signal !== "SIGTERM") {
        return failure("only SIGINT or SIGTERM may stop a capture", "invalid",
            {action: "capture-stop"});
    }

    var pid = options.pid;
    if (typeof pid !== "undefined" && pid !== null && pid !== "") {
        if (typeof pid !== "number" || !isFinite(pid) || Math.floor(pid) !== pid || pid <= 0) {
            return failure("capture pid must be a positive whole number", "invalid",
                {action: "capture-stop"});
        }
    } else {
        pid = null;
    }

    return {
        ok: true,
        status: "ready",
        action: "capture-stop",
        command: TSHARK_COMMAND,
        signal: signal,
        graceful: true,
        force: false,
        pid: pid,
        reason: "stop the capture process gracefully; no further packets are captured",
        autoRun: false,
        executed: false,
        uploads: false,
        packetInjection: false
    };
}

function prepareStop(options) {
    return buildStopRequest(options);
}

function baseOpenPlan() {
    return {
        ok: false,
        status: "idle",
        action: "pcap-open",
        command: TSHARK_COMMAND,
        shell: false,
        args: [],
        argv: [TSHARK_COMMAND],
        capturePath: null,
        readOnly: true,
        writeCapture: false,
        overwrite: false,
        autoRun: false,
        executed: false,
        uploads: false,
        autoUpload: false,
        packetInjection: false,
        capabilities: clone(CAPABILITIES)
    };
}

function buildOpenRequest(options) {
    options = isObject(options) ? options : {};
    var capturePath = typeof options.capturePath !== "undefined"
        ? options.capturePath
        : options.path;
    var path = validateCapturePath(capturePath, {mustExist: true});
    if (!path.ok) {
        return failure(path.reason, "invalid", {action: "pcap-open"});
    }

    var args = ["-n", "-r", path.path, "-T", "json"];
    var plan = baseOpenPlan();
    plan.ok = true;
    plan.status = "ready";
    plan.capturePath = path.path;
    plan.captureFormat = path.format;
    plan.args = args;
    plan.argv = [TSHARK_COMMAND].concat(args);
    plan.reason = "read-only pcap inspection with tshark; no capture file is modified";
    return plan;
}

function prepareOpen(options) {
    options = isObject(options) ? options : {};

    if (options.confirmed !== true) {
        return failure(
            "explicit operator confirmation is required before opening a capture",
            "confirmation-required",
            {action: "pcap-open"}
        );
    }

    var blocked = blockedRemoteReason(options);
    if (blocked.length > 0) {
        return failure(blocked, "capture-restricted", {action: "pcap-open"});
    }

    if (options.authorizedLab !== true) {
        return failure(
            "explicit authorized-lab confirmation is required before opening a capture",
            "unauthorized",
            {action: "pcap-open"}
        );
    }

    var unauthorized = authorizationReason(options.authorization);
    if (unauthorized.length > 0) {
        return failure(unauthorized, "unauthorized", {action: "pcap-open"});
    }

    var plan = buildOpenRequest(options);
    if (!plan.ok) {
        return plan;
    }
    plan.authorizedLab = true;
    plan.confirmed = true;
    plan.authorization = clone(options.authorization);
    return plan;
}

/* ------------------------------------------------------------------------- *
 * Pcap identification (local bytes only)
 * ------------------------------------------------------------------------- */

function toBytes(value) {
    if (value instanceof Uint8Array) {
        return value;
    }
    if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    if (Array.isArray(value)) {
        return Uint8Array.from ? Uint8Array.from(value) : new Uint8Array(value);
    }
    return null;
}

function identifyCapture(input) {
    var bytes = toBytes(input);
    if (!bytes) {
        return {
            ok: false,
            format: "unknown",
            reason: "capture bytes must be a Buffer, Uint8Array, or byte array"
        };
    }
    if (bytes.length < 4) {
        return {
            ok: false,
            format: "unknown",
            reason: "capture is too short to identify"
        };
    }

    var b0 = bytes[0];
    var b1 = bytes[1];
    var b2 = bytes[2];
    var b3 = bytes[3];

    if (b0 === 0x0a && b1 === 0x0d && b2 === 0x0d && b3 === 0x0a) {
        return {
            ok: true,
            format: "pcapng",
            byteOrder: "little",
            magic: "0a0d0d0a",
            bytes: bytes.length,
            reason: "pcapng capture header"
        };
    }

    var pcapMagic = {
        "d4c3b2a1": {order: "little", units: "microseconds"},
        "a1b2c3d4": {order: "big", units: "microseconds"},
        "4d3cb2a1": {order: "little", units: "nanoseconds"},
        "a1b23c4d": {order: "big", units: "nanoseconds"}
    };
    var hex = [b0, b1, b2, b3].map(function (value) {
        return (value < 16 ? "0" : "") + value.toString(16);
    }).join("");

    if (pcapMagic[hex]) {
        return {
            ok: true,
            format: "pcap",
            byteOrder: pcapMagic[hex].order,
            timestampUnits: pcapMagic[hex].units,
            magic: hex,
            bytes: bytes.length,
            reason: "classic pcap capture header"
        };
    }

    return {
        ok: false,
        format: "unknown",
        reason: "not a pcap or pcapng capture"
    };
}

/* ------------------------------------------------------------------------- *
 * Sensitive-data redaction
 * ------------------------------------------------------------------------- */

function applyPattern(text, regex, replacement) {
    var count = 0;
    var out = text.replace(regex, function (match) {
        count += 1;
        if (typeof replacement === "function") {
            return replacement.apply(null, arguments);
        }
        return replacement;
    });
    return {text: out, count: count};
}

function redactSensitive(value) {
    if (typeof value !== "string") {
        return {text: typeof value === "undefined" || value === null ? "" : String(value), count: 0};
    }

    var text = value;
    if (text.length > MAX_REDACT_LENGTH) {
        text = text.slice(0, MAX_REDACT_LENGTH) + " [truncated]";
    }

    var total = 0;
    var steps = [];

    steps.push(applyPattern(
        text,
        /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
        "[REDACTED PRIVATE KEY]"
    ));
    text = steps[steps.length - 1].text;

    steps.push(applyPattern(
        text,
        /((?:proxy-)?authorization\s*:\s*)([^\r\n]+)/gi,
        function (match, prefix) {
            return prefix + "[REDACTED]";
        }
    ));
    text = steps[steps.length - 1].text;

    steps.push(applyPattern(
        text,
        /((?:set-)?cookie\s*:\s*)([^\r\n]+)/gi,
        function (match, prefix) {
            return prefix + "[REDACTED]";
        }
    ));
    text = steps[steps.length - 1].text;

    steps.push(applyPattern(
        text,
        /\b(Basic|Bearer|Digest)\s+[A-Za-z0-9._~+\/=-]{6,}/gi,
        function (match, scheme) {
            return scheme + " [REDACTED]";
        }
    ));
    text = steps[steps.length - 1].text;

    steps.push(applyPattern(
        text,
        /((?:password|passwd|pwd|secret|token|session|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&;,\r\n]+)/gi,
        function (match, prefix) {
            return prefix + "[REDACTED]";
        }
    ));
    text = steps[steps.length - 1].text;

    steps.push(applyPattern(
        text,
        /(\b[a-z][a-z0-9+.-]*:\/\/)([^\/\s:@]+):([^\/\s@]+)@/gi,
        function (match, scheme) {
            return scheme + "[REDACTED]@";
        }
    ));
    text = steps[steps.length - 1].text;

    steps.forEach(function (step) {
        total += step.count;
    });

    return {
        text: text,
        count: total,
        redacted: total > 0
    };
}

function redactSensitiveText(value) {
    return redactSensitive(value).text;
}

function containsSensitive(value) {
    return redactSensitive(value).count > 0;
}

function isPayloadField(key) {
    return /(^|\.)(?:data|payload|file_data|raw)$/i.test(key) ||
        /^(?:data|tcp|udp)\.(?:data|payload|file_data)$/i.test(key) ||
        /^http\.file_data$/i.test(key);
}

function isSensitiveField(key) {
    return /(^|\.)(?:authorization|proxy_authorization|cookie|set_cookie|password|passwd|secret|token|session|api_key|apikey|access_key|client_secret|private_key)$/i
        .test(key);
}

/* ------------------------------------------------------------------------- *
 * TShark JSON parsing
 * ------------------------------------------------------------------------- */

function parseJson(input) {
    if (typeof input === "string") {
        var source = input.replace(/^\uFEFF/, "").trim();
        if (source.length === 0) {
            return {ok: false, errors: ["tshark returned empty JSON"]};
        }
        try {
            return {ok: true, value: JSON.parse(source)};
        } catch (error) {
            var lines = source.split(/\r?\n/).filter(nonEmpty);
            if (lines.length > 1) {
                try {
                    return {
                        ok: true,
                        value: lines.map(function (line) {
                            return JSON.parse(line);
                        })
                    };
                } catch (lineError) {
                    /* fall through to the single parse error */
                }
            }
            return {
                ok: false,
                errors: ["tshark JSON is malformed: " + error.message]
            };
        }
    }
    if (Array.isArray(input) || isObject(input)) {
        return {ok: true, value: input};
    }
    return {ok: false, errors: ["tshark output must be JSON text or objects"]};
}

function packetLayers(packet) {
    if (!isObject(packet)) {
        return {};
    }
    var source = isObject(packet._source) ? packet._source : packet;
    var layers = isObject(source.layers) ? source.layers : source;
    if (isObject(layers.layers)) {
        layers = layers.layers;
    }
    return isObject(layers) ? layers : {};
}

function scalar(value) {
    if (Array.isArray(value)) {
        return value.length > 0 ? scalar(value[0]) : "";
    }
    if (isObject(value)) {
        if (typeof value.show !== "undefined") {
            return scalar(value.show);
        }
        if (typeof value.value !== "undefined") {
            return scalar(value.value);
        }
        return "";
    }
    if (typeof value === "undefined" || value === null) {
        return "";
    }
    return String(value);
}

function fieldValue(layers, names) {
    var index;
    for (index = 0; index < names.length; index += 1) {
        if (Object.prototype.hasOwnProperty.call(layers, names[index])) {
            var value = scalar(layers[names[index]]);
            if (value.length > 0) {
                return value;
            }
        }
    }
    return "";
}

function recordRedaction(redactions, field) {
    if (redactions.indexOf(field) === -1) {
        redactions.push(field);
    }
}

function packetSummary(packet, index) {
    var layers = packetLayers(packet);
    var redactions = [];
    var payloadFields = [];
    var sensitiveFields = [];

    Object.keys(layers).forEach(function (key) {
        var value = scalar(layers[key]);
        if (value.length === 0) {
            return;
        }
        if (isPayloadField(key)) {
            payloadFields.push(key);
            recordRedaction(redactions, key);
            return;
        }
        if (isSensitiveField(key)) {
            sensitiveFields.push(key);
            recordRedaction(redactions, key);
            return;
        }
        if (containsSensitive(value)) {
            recordRedaction(redactions, key);
        }
    });

    var rawInfo = fieldValue(layers, [
        "_ws.col.Info",
        "http.request.uri",
        "http.response.code",
        "dns.qry.name"
    ]);
    var info = redactSensitive(rawInfo);

    var source = fieldValue(layers, [
        "ip.src",
        "ipv6.src",
        "arp.src.proto_ipv4",
        "eth.src"
    ]);
    var destination = fieldValue(layers, [
        "ip.dst",
        "ipv6.dst",
        "arp.dst.proto_ipv4",
        "eth.dst"
    ]);
    var srcPort = fieldValue(layers, ["tcp.srcport", "udp.srcport", "sctp.srcport"]);
    var dstPort = fieldValue(layers, ["tcp.dstport", "udp.dstport", "sctp.dstport"]);
    var protocol = fieldValue(layers, ["_ws.col.Protocol", "frame.protocols", "ip.proto"]);
    var length = fieldValue(layers, ["frame.len", "frame.cap_len", "data.len"]);
    var number = fieldValue(layers, ["frame.number"]);

    var httpMethod = fieldValue(layers, ["http.request.method"]);
    var httpHost = fieldValue(layers, ["http.host"]);
    var httpUri = fieldValue(layers, ["http.request.uri"]);
    var httpStatus = fieldValue(layers, ["http.response.code"]);

    var tlsServerName = fieldValue(layers, [
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions.server_name"
    ]);

    return {
        index: index + 1,
        number: number.length > 0 ? number : String(index + 1),
        time: fieldValue(layers, ["frame.time", "frame.time_epoch"]),
        source: source,
        destination: destination,
        srcPort: srcPort,
        dstPort: dstPort,
        protocol: protocol,
        length: length,
        info: info.text,
        http: {
            method: httpMethod,
            host: httpHost,
            uri: redactSensitive(httpUri).text,
            statusCode: httpStatus
        },
        tls: {
            serverName: tlsServerName
        },
        hasPayload: payloadFields.length > 0,
        payloadFields: unique(payloadFields),
        sensitiveFields: unique(sensitiveFields),
        redactedFields: unique(redactions),
        sensitive: payloadFields.length > 0 || sensitiveFields.length > 0 ||
            redactions.length > 0 || info.count > 0
    };
}

function parseTsharkJson(input) {
    var parsed = parseJson(input);
    if (!parsed.ok) {
        return {
            ok: false,
            status: "error",
            format: "tshark-json",
            packets: [],
            packetCount: 0,
            errors: parsed.errors,
            warnings: [],
            sensitive: false,
            redactedFields: [],
            uploads: false,
            autoUpload: false,
            autoRun: false
        };
    }

    var value = parsed.value;
    var packets;
    if (Array.isArray(value)) {
        packets = value;
    } else if (isObject(value) && Array.isArray(value.packets)) {
        packets = value.packets;
    } else if (isObject(value) && (isObject(value._source) || isObject(value.layers))) {
        packets = [value];
    } else {
        return {
            ok: false,
            status: "error",
            format: "tshark-json",
            packets: [],
            packetCount: 0,
            errors: ["tshark JSON must contain an array of packets"],
            warnings: [],
            sensitive: false,
            redactedFields: [],
            uploads: false,
            autoUpload: false,
            autoRun: false
        };
    }

    var summaries = packets.map(packetSummary);
    var redactedFields = [];
    var payloadCount = 0;
    var sensitiveCount = 0;
    summaries.forEach(function (packet) {
        packet.redactedFields.forEach(function (field) {
            recordRedaction(redactedFields, field);
        });
        if (packet.hasPayload) {
            payloadCount += 1;
        }
        if (packet.sensitive) {
            sensitiveCount += 1;
        }
    });

    var warnings = [];
    if (payloadCount > 0) {
        warnings.push("Packet payload data was present in " + payloadCount +
            " packet(s) and has been redacted from this summary.");
    }
    if (sensitiveCount > 0) {
        warnings.push("Sensitive headers, credentials, or tokens were detected in " +
            sensitiveCount + " packet(s) and redacted.");
    }
    warnings.push("This summary is local only; captures are never uploaded or transmitted.");

    return {
        ok: true,
        status: "parsed",
        format: "tshark-json",
        packets: summaries,
        packetCount: summaries.length,
        errors: [],
        warnings: unique(warnings),
        sensitive: sensitiveCount > 0 || payloadCount > 0,
        sensitivePacketCount: sensitiveCount,
        payloadPacketCount: payloadCount,
        redactedFields: redactedFields,
        uploads: false,
        autoUpload: false,
        autoRun: false
    };
}

function interpretCaptureResult(result, options) {
    options = isObject(options) ? options : {};
    var timeoutMs = options.timeoutMs || null;

    if (typeof result === "undefined" || result === null) {
        return {
            ok: false,
            status: "error",
            format: "unknown",
            packets: [],
            packetCount: 0,
            errors: ["tshark returned no result."],
            warnings: [],
            uploads: false,
            autoUpload: false
        };
    }

    if (typeof result === "string") {
        return parseTsharkJson(result);
    }

    if (!isObject(result)) {
        return {
            ok: false,
            status: "error",
            format: "unknown",
            packets: [],
            packetCount: 0,
            errors: ["unrecognized tshark result"],
            warnings: [],
            uploads: false,
            autoUpload: false
        };
    }

    var timedOut = result.timedOut === true ||
        result.timeout === true ||
        /^(timeout|timed-out|etimedout)$/i.test(String(result.status || "")) ||
        /^(ETIMEDOUT|TIMEOUT)$/i.test(String(result.code || ""));

    var errors = [];
    if (result.stderr) {
        errors = errors.concat(asErrorList(result.stderr));
    }
    if (result.error) {
        errors = errors.concat(asErrorList(result.error));
    }
    if (result.message) {
        errors = errors.concat(asErrorList(result.message));
    }
    if (typeof result.exitCode !== "undefined" && result.exitCode !== null &&
        Number(result.exitCode) !== 0) {
        errors.push("tshark exited with code " + result.exitCode + ".");
    }

    var json = typeof result.json !== "undefined"
        ? result.json
        : (typeof result.stdout !== "undefined" ? result.stdout : result.output);
    if (typeof json === "undefined" && Array.isArray(result.packets)) {
        json = result;
    }

    var parsed = null;
    if (typeof json !== "undefined" && json !== null &&
        !(typeof json === "string" && json.trim() === "")) {
        parsed = parseTsharkJson(json);
    }

    if (parsed && parsed.ok) {
        parsed.capturePath = nonEmpty(options.capturePath) ? options.capturePath : null;
        if (timedOut) {
            parsed.ok = false;
            parsed.status = "timeout";
            parsed.errors = ["tshark timed out" +
                (timeoutMs ? " after " + timeoutMs + " ms" : "") + "."];
            return parsed;
        }
        if (errors.length > 0) {
            parsed.errors = unique(parsed.errors.concat(errors));
            parsed.ok = false;
            parsed.status = "error";
        }
        return parsed;
    }

    if (timedOut) {
        return {
            ok: false,
            status: "timeout",
            format: "tshark-json",
            packets: [],
            packetCount: 0,
            errors: unique(["tshark timed out" +
                (timeoutMs ? " after " + timeoutMs + " ms" : "") + "."]
                .concat(errors)),
            warnings: [],
            uploads: false,
            autoUpload: false
        };
    }

    if (errors.length === 0) {
        errors.push("tshark did not return JSON output; use tshark where it is available.");
    }
    if (parsed && Array.isArray(parsed.errors)) {
        errors = errors.concat(parsed.errors);
    }
    return {
        ok: false,
        status: "error",
        format: "tshark-json",
        packets: [],
        packetCount: 0,
        errors: unique(errors),
        warnings: [],
        uploads: false,
        autoUpload: false
    };
}

function formatCaptureSummary(result) {
    result = isObject(result) ? result : {};
    var lines = [];

    if (nonEmpty(result.capturePath)) {
        lines.push("Capture: " + result.capturePath);
    }
    if (result.timedOut) {
        lines.push("TIMEOUT: the capture inspection did not finish.");
    }
    if (Array.isArray(result.errors) && result.errors.length > 0) {
        lines.push("Errors:");
        result.errors.forEach(function (error) {
            lines.push("  " + error);
        });
    }
    if (Array.isArray(result.warnings) && result.warnings.length > 0) {
        lines.push("Warnings:");
        result.warnings.forEach(function (warning) {
            lines.push("  " + warning);
        });
    }

    var packets = Array.isArray(result.packets) ? result.packets : [];
    lines.push("Packets: " + (typeof result.packetCount === "number"
        ? result.packetCount
        : packets.length));

    if (packets.length === 0) {
        lines.push("No packets were reported.");
        lines.push("No capture data was uploaded.");
        return lines.join("\n");
    }

    packets.forEach(function (packet) {
        var source = packet.source || "?";
        if (packet.srcPort) {
            source += ":" + packet.srcPort;
        }
        var destination = packet.destination || "?";
        if (packet.dstPort) {
            destination += ":" + packet.dstPort;
        }
        var line = "#" + (packet.number || packet.index) + " " +
            source + " -> " + destination + " " +
            (packet.protocol || "?") +
            (packet.length ? " len=" + packet.length : "");
        if (packet.info) {
            line += " " + packet.info;
        }
        lines.push(line);
        if (packet.hasPayload) {
            lines.push("  payload: [REDACTED]");
        }
    });

    lines.push("No capture data was uploaded.");
    return lines.join("\n");
}

/* ------------------------------------------------------------------------- *
 * Availability and capability reporting
 * ------------------------------------------------------------------------- */

function normalizeAvailability(result) {
    var available = false;
    var reason = "";
    var command = TSHARK_COMMAND;

    if (typeof result === "boolean") {
        available = result;
        reason = available ? "tshark is present" : "tshark is not installed";
    } else if (typeof result === "string") {
        var lower = result.trim().toLowerCase();
        available = lower === "available" || lower === "present" ||
            lower === "ok" || lower === "true";
        reason = available ? "tshark is present" : "tshark is not installed";
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
            : (available ? "tshark is present" : "tshark is not installed");
        command = nonEmpty(result.command) ? result.command : TSHARK_COMMAND;
        if (!available && nonEmpty(result.missing)) {
            command = result.missing;
        }
    } else {
        reason = "no tshark availability result";
    }

    return {
        available: available,
        command: command,
        reason: reason,
        status: available ? "available" : "missing-tool"
    };
}

function detectAvailability(probe, context) {
    if (typeof probe !== "function") {
        return normalizeAvailability({
            available: false,
            command: TSHARK_COMMAND,
            reason: "no tshark probe is configured"
        });
    }
    var tab = isObject(context)
        ? context
        : {id: "forensics", tool: {commands: [TSHARK_COMMAND]}};
    try {
        var result = probe(tab);
        if (result && typeof result.then === "function") {
            return normalizeAvailability({
                available: false,
                command: TSHARK_COMMAND,
                reason: "asynchronous probes require the host adapter"
            });
        }
        return normalizeAvailability(result);
    } catch (error) {
        return normalizeAvailability({
            available: false,
            command: TSHARK_COMMAND,
            reason: "tshark probe failed: " +
                (error && error.message ? error.message : String(error))
        });
    }
}

function capabilityReport() {
    return clone(CAPABILITIES);
}

function statusReport(result) {
    var availability = normalizeAvailability(result);
    return {
        tool: "tshark",
        toolName: "Wireshark / tshark",
        command: TSHARK_COMMAND,
        available: availability.available,
        status: availability.status,
        reason: availability.reason,
        autoRun: false,
        autoCapture: false,
        autoUpload: false,
        packetInjection: false,
        captureRequiresConfirmation: true,
        openRequiresConfirmation: true,
        redaction: "payloads and credential patterns are redacted",
        capabilities: capabilityReport()
    };
}

var api = {
    TSHARK_COMMAND: TSHARK_COMMAND,
    WIRESHARK_COMMAND: WIRESHARK_COMMAND,
    STOP_SIGNAL: STOP_SIGNAL,
    DEFAULT_CAPTURE_FILTER: DEFAULT_CAPTURE_FILTER,
    CAPTURE_EXTENSIONS: CAPTURE_EXTENSIONS,
    CAPTURE_FILTERS: CAPTURE_FILTERS,
    CAPABILITIES: CAPABILITIES,
    validateInterface: validateInterface,
    normalizeInterfaces: normalizeInterfaces,
    listInterfaces: listInterfaces,
    normalizeFilter: normalizeFilter,
    listCaptureFilters: listCaptureFilters,
    listFilters: listCaptureFilters,
    validateCapturePath: validateCapturePath,
    validatePath: validateCapturePath,
    buildCaptureRequest: buildCaptureRequest,
    buildCaptureArgs: buildCaptureRequest,
    prepareCapture: prepareCapture,
    startCaptureRequest: buildCaptureRequest,
    buildStopRequest: buildStopRequest,
    stopCaptureRequest: buildStopRequest,
    prepareStop: prepareStop,
    buildOpenRequest: buildOpenRequest,
    buildPcapRequest: buildOpenRequest,
    prepareOpen: prepareOpen,
    openPcapRequest: buildOpenRequest,
    identifyCapture: identifyCapture,
    redactSensitive: redactSensitive,
    redactSensitiveText: redactSensitiveText,
    containsSensitive: containsSensitive,
    parseTsharkJson: parseTsharkJson,
    parseCapture: parseTsharkJson,
    parsePcap: parseTsharkJson,
    interpretCaptureResult: interpretCaptureResult,
    inspectCaptureResult: interpretCaptureResult,
    formatCaptureSummary: formatCaptureSummary,
    formatResult: formatCaptureSummary,
    normalizeAvailability: normalizeAvailability,
    detectAvailability: detectAvailability,
    checkAvailability: detectAvailability,
    statusReport: statusReport,
    capabilityReport: capabilityReport,
    getCapabilities: capabilityReport
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
}
