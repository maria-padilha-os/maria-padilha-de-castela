/*
 * Safe, shared Nmap front-end helpers.
 *
 * This module never starts a process and never performs a lookup or network
 * request. It only validates operator input, turns a documented profile and a
 * small option set into an argv array, and parses Nmap's XML output.
 *
 * Security properties:
 *   - one target is a canonical private/lab address, CIDR, or lab hostname;
 *   - public targets are refused unless a caller explicitly opts in;
 *   - the target is never interpolated into a shell string;
 *   - profiles and options are allowlists, so arbitrary Nmap flags cannot be
 *     smuggled through the target field;
 *   - every request asks Nmap for XML on stdout (`-oX -`);
 *   - no profile requires root or privilege escalation.
 */

"use strict";

var NMAP_COMMAND = "nmap";
var DEFAULT_PROFILE = "tcp-connect";
var DEFAULT_TIMEOUT_MS = 120000;
var MIN_TIMEOUT_MS = 1000;
var MAX_TIMEOUT_MS = 600000;
var MAX_TARGETS = 16;
var MAX_TARGET_LENGTH = 253;

var PROFILE_ORDER = ["discovery", "tcp-connect", "service", "top-100"];

/*
 * Profiles deliberately use unprivileged Nmap scans only. In particular there
 * is no SYN scan, OS detection, UDP scan, NSE script selection, or `-A`.
 */
var PROFILES = {
    "discovery": {
        id: "discovery",
        label: "Host discovery (no port scan)",
        description: "Unprivileged host discovery. Does not scan ports.",
        args: ["-sn"],
        options: ["reason"]
    },
    "tcp-connect": {
        id: "tcp-connect",
        label: "TCP connect scan",
        description: "Unprivileged full TCP connect scan of Nmap's default ports.",
        args: ["-sT"],
        options: ["no-ping", "open-only", "reason", "top-ports-100"]
    },
    "service": {
        id: "service",
        label: "TCP connect + service versions",
        description: "Unprivileged TCP connect scan with lightweight service/version detection.",
        args: ["-sT", "-sV"],
        options: ["no-ping", "open-only", "reason", "version-light", "top-ports-100"]
    },
    "top-100": {
        id: "top-100",
        label: "Top 100 TCP ports",
        description: "Unprivileged TCP connect scan of Nmap's top 100 ports.",
        args: ["-sT", "--top-ports", "100"],
        options: ["no-ping", "open-only", "reason"]
    }
};

var PROFILE_ALIASES = {
    "ping": "discovery",
    "host-discovery": "discovery",
    "connect": "tcp-connect",
    "tcp": "tcp-connect",
    "version": "service",
    "versions": "service",
    "service-version": "service",
    "top100": "top-100",
    "top-ports": "top-100"
};

var OPTION_ORDER = [
    "no-ping",
    "open-only",
    "reason",
    "version-light",
    "top-ports-100"
];

var OPTIONS = {
    "no-ping": {
        id: "no-ping",
        label: "Skip host discovery (-Pn)",
        description: "Treat the target as online instead of probing it first.",
        args: ["-Pn"],
        profiles: ["tcp-connect", "service", "top-100"]
    },
    "open-only": {
        id: "open-only",
        label: "Show open ports only (--open)",
        description: "Suppress closed and filtered port lines from the report.",
        args: ["--open"],
        profiles: ["tcp-connect", "service", "top-100"]
    },
    "reason": {
        id: "reason",
        label: "Show state reasons (--reason)",
        description: "Include Nmap's reason for each host and port state.",
        args: ["--reason"],
        profiles: ["discovery", "tcp-connect", "service", "top-100"]
    },
    "version-light": {
        id: "version-light",
        label: "Light version detection (--version-light)",
        description: "Use the lighter service-version probe set with the service profile.",
        args: ["--version-light"],
        profiles: ["service"]
    },
    "top-ports-100": {
        id: "top-ports-100",
        label: "Top 100 ports (--top-ports 100)",
        description: "Limit the scan to Nmap's 100 most common ports.",
        args: ["--top-ports", "100"],
        profiles: ["tcp-connect", "service"]
    }
};

var OPTION_ALIASES = {
    "pn": "no-ping",
    "noping": "no-ping",
    "no_ping": "no-ping",
    "open": "open-only",
    "open_only": "open-only",
    "show-reason": "reason",
    "reasons": "reason",
    "version_light": "version-light",
    "light": "version-light",
    "top-ports": "top-ports-100",
    "top_ports_100": "top-ports-100",
    "top100": "top-ports-100"
};

var PRIVATE_V4_RANGES = [
    {network: "10.0.0.0", prefix: 8, label: "RFC 1918 private"},
    {network: "172.16.0.0", prefix: 12, label: "RFC 1918 private"},
    {network: "192.168.0.0", prefix: 16, label: "RFC 1918 private"},
    {network: "127.0.0.0", prefix: 8, label: "loopback"},
    {network: "169.254.0.0", prefix: 16, label: "link-local"},
    {network: "100.64.0.0", prefix: 10, label: "shared address space"},
    {network: "192.0.2.0", prefix: 24, label: "documentation/lab"},
    {network: "198.51.100.0", prefix: 24, label: "documentation/lab"},
    {network: "203.0.113.0", prefix: 24, label: "documentation/lab"},
    {network: "198.18.0.0", prefix: 15, label: "benchmark/lab"}
];

var PRIVATE_V6_RANGES = [
    {network: "::1", prefix: 128, label: "loopback"},
    {network: "fc00::", prefix: 7, label: "unique local"},
    {network: "fe80::", prefix: 10, label: "link-local"},
    {network: "2001:db8::", prefix: 32, label: "documentation/lab"}
];

var APPROVED_HOST_SUFFIXES = [
    "localhost",
    "local",
    "localdomain",
    "lan",
    "lab",
    "test",
    "example",
    "invalid",
    "internal",
    "intranet",
    "home",
    "home.arpa"
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

function failure(reason, extra) {
    var result = {
        ok: false,
        status: "invalid",
        reason: reason,
        errors: [reason]
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

function normalizeProfileId(profile) {
    if (!nonEmpty(profile)) {
        return DEFAULT_PROFILE;
    }
    var key = profile.trim().toLowerCase().replace(/_/g, "-");
    if (Object.prototype.hasOwnProperty.call(PROFILES, key)) {
        return key;
    }
    if (Object.prototype.hasOwnProperty.call(PROFILE_ALIASES, key)) {
        return PROFILE_ALIASES[key];
    }
    return null;
}

function getProfile(profile) {
    var id = normalizeProfileId(profile);
    return id && Object.prototype.hasOwnProperty.call(PROFILES, id)
        ? PROFILES[id]
        : null;
}

function listProfiles() {
    return PROFILE_ORDER.map(function (id) {
        return clone(PROFILES[id]);
    });
}

function normalizeOptionId(option) {
    if (!nonEmpty(option)) {
        return null;
    }
    var key = option.trim().toLowerCase().replace(/_/g, "-");
    if (Object.prototype.hasOwnProperty.call(OPTIONS, key)) {
        return key;
    }
    if (Object.prototype.hasOwnProperty.call(OPTION_ALIASES, key)) {
        return OPTION_ALIASES[key];
    }
    return null;
}

function listOptions(profile) {
    var selected = profile ? getProfile(profile) : null;
    return OPTION_ORDER.filter(function (id) {
        return !selected || selected.options.indexOf(id) !== -1;
    }).map(function (id) {
        return clone(OPTIONS[id]);
    });
}

function normalizeOptions(input, profile) {
    var selected = profile && profile.id ? profile : getProfile(profile);
    var requested = [];
    var errors = [];

    if (typeof input === "undefined" || input === null || input === false) {
        requested = [];
    } else if (typeof input === "string") {
        requested = input.split(/[,\s]+/).filter(nonEmpty);
    } else if (Array.isArray(input)) {
        requested = input.slice();
    } else if (isObject(input)) {
        Object.keys(input).forEach(function (key) {
            if (input[key] === true || input[key] === 1 ||
                input[key] === "1" || input[key] === "true") {
                requested.push(key);
            }
        });
    } else {
        return failure("options must be an object, array, or comma-separated list");
    }

    var enabled = [];
    requested.forEach(function (raw) {
        var id = normalizeOptionId(raw);
        if (!id) {
            errors.push("unknown Nmap option: " + String(raw));
            return;
        }
        if (selected && selected.options.indexOf(id) === -1) {
            errors.push("option " + id + " is not available for profile " + selected.id);
            return;
        }
        if (enabled.indexOf(id) === -1) {
            enabled.push(id);
        }
    });

    enabled.sort(function (a, b) {
        return OPTION_ORDER.indexOf(a) - OPTION_ORDER.indexOf(b);
    });

    if (errors.length > 0) {
        return failure(errors.join("; "), {errors: unique(errors)});
    }
    return {
        ok: true,
        options: enabled
    };
}

/* ------------------------------------------------------------------------- *
 * Target parsing and canonicalization
 * ------------------------------------------------------------------------- */

function parseIPv4(value) {
    if (typeof value !== "string") {
        return null;
    }
    var parts = value.split(".");
    if (parts.length !== 4) {
        return null;
    }
    var octets = [];
    var index;
    for (index = 0; index < parts.length; index += 1) {
        if (!/^\d{1,3}$/.test(parts[index])) {
            return null;
        }
        /* Reject leading zeros: 010 can mean decimal 10 or octal 8. */
        if (parts[index].length > 1 && parts[index].charAt(0) === "0") {
            return null;
        }
        var octet = Number(parts[index]);
        if (octet < 0 || octet > 255) {
            return null;
        }
        octets.push(octet);
    }
    var numeric = ((octets[0] * 16777216) +
        (octets[1] * 65536) +
        (octets[2] * 256) +
        octets[3]) >>> 0;
    return {
        version: 4,
        octets: octets,
        value: numeric
    };
}

function ipv4ToString(value) {
    value = value >>> 0;
    return [
        (value >>> 24) & 255,
        (value >>> 16) & 255,
        (value >>> 8) & 255,
        value & 255
    ].join(".");
}

function ipv4Mask(prefix) {
    if (prefix <= 0) {
        return 0;
    }
    return (0xffffffff << (32 - prefix)) >>> 0;
}

function ipv4Network(value, prefix) {
    return (value & ipv4Mask(prefix)) >>> 0;
}

function ipv4InRange(value, network, prefix) {
    return ipv4Network(value, prefix) === ipv4Network(network, prefix);
}

function privateIPv4Range(value, prefix) {
    if (typeof prefix !== "number") {
        prefix = 32;
    }
    var index;
    for (index = 0; index < PRIVATE_V4_RANGES.length; index += 1) {
        var range = PRIVATE_V4_RANGES[index];
        var network = parseIPv4(range.network);
        if (prefix >= range.prefix && network &&
            ipv4InRange(value, network.value, range.prefix)) {
            return range;
        }
    }
    return null;
}

function parseIPv6(value) {
    if (typeof value !== "string" || value.indexOf(":") === -1) {
        return null;
    }
    if (!/^[0-9A-Fa-f:.]+$/.test(value) || value.indexOf("%") !== -1) {
        return null;
    }

    var text = value;
    var lastColon = text.lastIndexOf(":");
    var tail = text.slice(lastColon + 1);
    if (tail.indexOf(".") !== -1) {
        var embedded = parseIPv4(tail);
        if (!embedded) {
            return null;
        }
        text = text.slice(0, lastColon + 1) + "0:0";
    }

    var halves = text.split("::");
    if (halves.length > 2) {
        return null;
    }
    var left = halves[0] === "" ? [] : halves[0].split(":");
    var right = halves.length === 2
        ? (halves[1] === "" ? [] : halves[1].split(":"))
        : [];
    var groups = left.concat(right);

    if (halves.length === 2) {
        if (groups.length >= 8) {
            return null;
        }
        var fill = 8 - groups.length;
        var zeros = [];
        var index;
        for (index = 0; index < fill; index += 1) {
            zeros.push("0");
        }
        groups = left.concat(zeros, right);
    } else if (groups.length !== 8) {
        return null;
    }

    var numbers = [];
    var groupIndex;
    for (groupIndex = 0; groupIndex < groups.length; groupIndex += 1) {
        if (!/^[0-9A-Fa-f]{1,4}$/.test(groups[groupIndex])) {
            return null;
        }
        numbers.push(parseInt(groups[groupIndex], 16));
    }
    return {
        version: 6,
        groups: numbers
    };
}

function ipv6ToString(groups) {
    var hex = groups.map(function (group) {
        return group.toString(16);
    });
    var bestStart = -1;
    var bestLength = 0;
    var index = 0;
    while (index < hex.length) {
        if (hex[index] !== "0") {
            index += 1;
            continue;
        }
        var start = index;
        while (index < hex.length && hex[index] === "0") {
            index += 1;
        }
        var length = index - start;
        if (length > bestLength) {
            bestStart = start;
            bestLength = length;
        }
    }
    if (bestLength < 2) {
        return hex.join(":");
    }
    var left = hex.slice(0, bestStart).join(":");
    var right = hex.slice(bestStart + bestLength).join(":");
    if (left === "" && right === "") {
        return "::";
    }
    if (left === "") {
        return "::" + right;
    }
    if (right === "") {
        return left + "::";
    }
    return left + "::" + right;
}

function ipv6PrefixMatches(groups, networkGroups, prefix) {
    var fullGroups = Math.floor(prefix / 16);
    var remaining = prefix % 16;
    var index;
    for (index = 0; index < fullGroups; index += 1) {
        if (groups[index] !== networkGroups[index]) {
            return false;
        }
    }
    if (remaining > 0) {
        var mask = (0xffff << (16 - remaining)) & 0xffff;
        if ((groups[fullGroups] & mask) !== (networkGroups[fullGroups] & mask)) {
            return false;
        }
    }
    return true;
}

function ipv6Network(groups, prefix) {
    var network = groups.slice();
    var fullGroups = Math.floor(prefix / 16);
    var remaining = prefix % 16;
    var index;
    if (remaining > 0) {
        var mask = (0xffff << (16 - remaining)) & 0xffff;
        network[fullGroups] = network[fullGroups] & mask;
    }
    for (index = fullGroups + (remaining > 0 ? 1 : 0); index < 8; index += 1) {
        network[index] = 0;
    }
    return network;
}

function privateIPv6Range(groups, prefix) {
    if (typeof prefix !== "number") {
        prefix = 128;
    }
    var index;
    for (index = 0; index < PRIVATE_V6_RANGES.length; index += 1) {
        var range = PRIVATE_V6_RANGES[index];
        var network = parseIPv6(range.network);
        if (prefix >= range.prefix && network &&
            ipv6PrefixMatches(groups, network.groups, range.prefix)) {
            return range;
        }
    }
    return null;
}

function parseHostname(value) {
    if (typeof value !== "string") {
        return null;
    }
    var name = value.trim().toLowerCase();
    if (name.length > 0 && name.charAt(name.length - 1) === ".") {
        name = name.slice(0, -1);
    }
    if (name.length === 0 || name.length > MAX_TARGET_LENGTH) {
        return null;
    }
    var labels = name.split(".");
    var index;
    for (index = 0; index < labels.length; index += 1) {
        if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(labels[index])) {
            return null;
        }
    }
    return {
        version: 0,
        hostname: name,
        labels: labels
    };
}

function approvedHostname(name) {
    if (name.indexOf(".") === -1) {
        return true;
    }
    var index;
    for (index = 0; index < APPROVED_HOST_SUFFIXES.length; index += 1) {
        var suffix = APPROVED_HOST_SUFFIXES[index];
        if (name === suffix || name.slice(-(suffix.length + 1)) === "." + suffix) {
            return true;
        }
    }
    return false;
}

function targetFailure(reason, target) {
    return failure(reason, {target: target || ""});
}

function validateTarget(value, options) {
    options = options || {};
    if (typeof value !== "string") {
        return targetFailure("a target must be a string");
    }
    var raw = value.trim();
    if (raw.length === 0) {
        return targetFailure("a target is required");
    }
    if (raw.length > MAX_TARGET_LENGTH) {
        return targetFailure("target is too long", raw);
    }
    if (raw.charAt(0) === "-") {
        return targetFailure("a target must not begin with a dash", raw);
    }
    if (!/^[A-Za-z0-9.:/_-]+$/.test(raw)) {
        return targetFailure("target contains whitespace, shell characters, or unsupported punctuation", raw);
    }
    if (raw.indexOf(",") !== -1) {
        return targetFailure("enter one target per field; use the target list option for multiple targets", raw);
    }

    var slash = raw.indexOf("/");
    var address = slash === -1 ? raw : raw.slice(0, slash);
    var prefix = null;
    var entry = null;

    if (slash !== -1) {
        var prefixText = raw.slice(slash + 1);
        if (!/^\d{1,3}$/.test(prefixText)) {
            return targetFailure("invalid CIDR prefix", raw);
        }
        prefix = Number(prefixText);
    }

    if (raw.indexOf(":") !== -1) {
        var ipv6 = parseIPv6(address);
        if (!ipv6) {
            return targetFailure("invalid IPv6 address", raw);
        }
        if (prefix === null) {
            prefix = 128;
        }
        if (prefix < 0 || prefix > 128) {
            return targetFailure("IPv6 CIDR prefix must be between 0 and 128", raw);
        }
        var ipv6Range = privateIPv6Range(ipv6.groups, prefix);
        entry = {
            kind: slash === -1 ? "ipv6" : "ipv6-cidr",
            version: 6,
            canonical: slash === -1
                ? ipv6ToString(ipv6.groups)
                : ipv6ToString(ipv6Network(ipv6.groups, prefix)) + "/" + prefix,
            address: ipv6ToString(ipv6.groups),
            groups: ipv6.groups,
            networkGroups: ipv6Network(ipv6.groups, prefix),
            prefix: prefix,
            isPrivate: ipv6Range !== null,
            rangeLabel: ipv6Range ? ipv6Range.label : ""
        };
    } else if (slash !== -1) {
        var ipv4Cidr = parseIPv4(address);
        if (!ipv4Cidr) {
            return targetFailure("invalid IPv4 CIDR address", raw);
        }
        if (prefix < 0 || prefix > 32) {
            return targetFailure("IPv4 CIDR prefix must be between 0 and 32", raw);
        }
        var ipv4Range = privateIPv4Range(ipv4Network(ipv4Cidr.value, prefix), prefix);
        entry = {
            kind: "ipv4-cidr",
            version: 4,
            canonical: ipv4ToString(ipv4Network(ipv4Cidr.value, prefix)) + "/" + prefix,
            address: ipv4ToString(ipv4Cidr.value),
            value: ipv4Cidr.value,
            networkValue: ipv4Network(ipv4Cidr.value, prefix),
            prefix: prefix,
            isPrivate: ipv4Range !== null,
            rangeLabel: ipv4Range ? ipv4Range.label : ""
        };
    } else if (/^\d+(?:\.\d+){3}$/.test(address)) {
        var ipv4 = parseIPv4(address);
        if (!ipv4) {
            return targetFailure("invalid IPv4 address (octets must be 0-255 without leading zeros)", raw);
        }
        var singleRange = privateIPv4Range(ipv4.value);
        entry = {
            kind: "ipv4",
            version: 4,
            canonical: ipv4ToString(ipv4.value),
            address: ipv4ToString(ipv4.value),
            value: ipv4.value,
            networkValue: ipv4.value,
            prefix: 32,
            isPrivate: singleRange !== null,
            rangeLabel: singleRange ? singleRange.label : ""
        };
    } else if (/^[0-9.]+$/.test(address)) {
        return targetFailure("invalid IP address", raw);
    } else {
        var hostname = parseHostname(address);
        if (!hostname) {
            return targetFailure("invalid hostname", raw);
        }
        var hostnameApproved = approvedHostname(hostname.hostname);
        entry = {
            kind: "hostname",
            version: 0,
            canonical: hostname.hostname,
            address: hostname.hostname,
            hostname: hostname.hostname,
            labels: hostname.labels,
            prefix: null,
            isPrivate: hostnameApproved,
            rangeLabel: hostnameApproved ? "approved lab name" : ""
        };
    }

    if (!entry.isPrivate && options.allowPublic !== true) {
        return targetFailure("target is outside approved lab/private ranges; public targets are refused by default", raw);
    }

    return {
        ok: true,
        input: raw,
        target: entry.canonical,
        canonical: entry.canonical,
        kind: entry.kind,
        version: entry.version,
        isPrivate: entry.isPrivate,
        rangeLabel: entry.rangeLabel,
        entry: entry
    };
}

function validateTargets(input, options) {
    var values;
    if (Array.isArray(input)) {
        values = input.slice();
    } else if (typeof input === "string" && input.indexOf(",") !== -1) {
        values = input.split(",").map(function (value) {
            return value.trim();
        });
    } else {
        values = [input];
    }

    if (values.length === 0) {
        return targetFailure("at least one target is required");
    }
    if (values.length > MAX_TARGETS) {
        return targetFailure("at most " + MAX_TARGETS + " targets are allowed per request");
    }

    var entries = [];
    var errors = [];
    values.forEach(function (value) {
        var result = validateTarget(value, options);
        if (!result.ok) {
            errors.push(result.reason);
        } else {
            entries.push(result);
        }
    });
    if (errors.length > 0) {
        return failure(unique(errors).join("; "), {errors: unique(errors)});
    }
    return {
        ok: true,
        targets: entries.map(function (entry) {
            return entry.canonical;
        }),
        entries: entries
    };
}

function targetInScope(target, scope) {
    var targetResult = isObject(target) && target.ok
        ? target
        : validateTarget(target);
    var scopeResult = isObject(scope) && scope.ok
        ? scope
        : validateTarget(scope);

    if (!targetResult.ok) {
        return failure("invalid target: " + targetResult.reason);
    }
    if (!scopeResult.ok) {
        return failure("invalid scope: " + scopeResult.reason);
    }

    var targetEntry = targetResult.entry;
    var scopeEntry = scopeResult.entry;

    if (targetEntry.version === 4 && scopeEntry.version === 4) {
        if (scopeEntry.prefix === 32) {
            if (targetEntry.prefix !== 32 || targetEntry.value !== scopeEntry.value) {
                return failure("target is outside the configured scope");
            }
            return {ok: true, reason: "target is inside scope"};
        }
        if (targetEntry.prefix < scopeEntry.prefix ||
            !ipv4InRange(targetEntry.networkValue, scopeEntry.networkValue, scopeEntry.prefix)) {
            return failure("target is outside the configured scope");
        }
        return {ok: true, reason: "target is inside scope"};
    }

    if (targetEntry.version === 6 && scopeEntry.version === 6) {
        if (scopeEntry.prefix === 128) {
            if (targetEntry.prefix !== 128 ||
                ipv6ToString(targetEntry.networkGroups) !== ipv6ToString(scopeEntry.networkGroups)) {
                return failure("target is outside the configured scope");
            }
            return {ok: true, reason: "target is inside scope"};
        }
        if (targetEntry.prefix < scopeEntry.prefix ||
            !ipv6PrefixMatches(targetEntry.networkGroups, scopeEntry.networkGroups, scopeEntry.prefix)) {
            return failure("target is outside the configured scope");
        }
        return {ok: true, reason: "target is inside scope"};
    }

    if (targetEntry.version === 0 && scopeEntry.version === 0) {
        if (targetEntry.canonical === scopeEntry.canonical ||
            targetEntry.canonical.slice(-(scopeEntry.canonical.length + 1)) ===
                "." + scopeEntry.canonical) {
            return {ok: true, reason: "target is inside scope"};
        }
        return failure("target is outside the configured scope");
    }

    return failure("cannot verify an address target against a hostname scope, or a hostname target against an address scope");
}

/* ------------------------------------------------------------------------- *
 * Argument construction
 * ------------------------------------------------------------------------- */

function normalizeTimeout(value) {
    if (typeof value === "undefined" || value === null || value === "") {
        return {
            ok: true,
            timeoutMs: DEFAULT_TIMEOUT_MS
        };
    }
    var timeout = Number(value);
    if (!isFinite(timeout) || Math.floor(timeout) !== timeout) {
        return failure("timeoutMs must be a whole number of milliseconds");
    }
    if (timeout < MIN_TIMEOUT_MS || timeout > MAX_TIMEOUT_MS) {
        return failure("timeoutMs must be between " + MIN_TIMEOUT_MS + " and " + MAX_TIMEOUT_MS);
    }
    return {
        ok: true,
        timeoutMs: timeout
    };
}

function validateArgv(args) {
    if (!Array.isArray(args) || args.length === 0) {
        return failure("Nmap arguments must be a non-empty array");
    }
    var index;
    for (index = 0; index < args.length; index += 1) {
        var arg = args[index];
        if (typeof arg !== "string" || arg.length === 0) {
            return failure("every Nmap argument must be a non-empty string");
        }
        if (arg.length > 1024) {
            return failure("an Nmap argument is too long");
        }
        if (/[\0\r\n]/.test(arg)) {
            return failure("an Nmap argument contains NUL or a newline");
        }
        if (/[;&|`$<>\\]/.test(arg)) {
            return failure("an Nmap argument contains shell control characters");
        }
    }
    return {
        ok: true,
        args: args.slice(),
        shell: false
    };
}

function buildScanRequest(options) {
    options = isObject(options) ? options : {};
    var profile = getProfile(options.profile);
    if (!profile) {
        return failure("unknown Nmap profile: " + String(options.profile) +
            " (choose " + PROFILE_ORDER.join(", ") + ")");
    }

    var targetInput = typeof options.targets !== "undefined"
        ? options.targets
        : options.target;
    if (typeof targetInput === "undefined" || targetInput === null ||
        (typeof targetInput === "string" && targetInput.trim() === "")) {
        return failure("a target is required");
    }

    var targets = validateTargets(targetInput, {
        allowPublic: options.allowPublic === true
    });
    if (!targets.ok) {
        return targets;
    }

    var optionsResult = normalizeOptions(
        typeof options.options !== "undefined" ? options.options : options.flags,
        profile
    );
    if (!optionsResult.ok) {
        return optionsResult;
    }

    var scopeText = "";
    if (nonEmpty(options.scope)) {
        var scope = validateTarget(options.scope);
        if (!scope.ok) {
            return failure("invalid target scope: " + scope.reason);
        }
        var scopeIndex;
        for (scopeIndex = 0; scopeIndex < targets.entries.length; scopeIndex += 1) {
            var inside = targetInScope(targets.entries[scopeIndex], scope);
            if (!inside.ok) {
                return failure(inside.reason + ": " + targets.entries[scopeIndex].canonical);
            }
        }
        scopeText = scope.canonical;
    }

    var timeout = normalizeTimeout(options.timeoutMs);
    if (!timeout.ok) {
        return timeout;
    }

    var args = [];
    var hasIPv6 = targets.entries.some(function (entry) {
        return entry.version === 6;
    });
    if (hasIPv6) {
        args.push("-6");
    }
    args = args.concat(profile.args);
    optionsResult.options.forEach(function (id) {
        args = args.concat(OPTIONS[id].args);
    });
    /* Ask for machine-readable output on stdout; never write an output file. */
    args.push("-oX", "-");
    targets.targets.forEach(function (target) {
        args.push(target);
    });

    var argvCheck = validateArgv(args);
    if (!argvCheck.ok) {
        return argvCheck;
    }

    return {
        ok: true,
        status: "ready",
        command: NMAP_COMMAND,
        shell: false,
        args: argvCheck.args,
        argv: [NMAP_COMMAND].concat(argvCheck.args),
        targets: targets.targets,
        target: targets.targets.join(","),
        profile: profile.id,
        profileLabel: profile.label,
        options: optionsResult.options,
        scope: scopeText,
        timeoutMs: timeout.timeoutMs,
        xml: true,
        autoRun: false
    };
}

/*
 * The UI calls this path. It adds the explicit authorized-lab confirmation and
 * a bounded scope on top of buildScanRequest(). Neither is inferred.
 */
function prepareScan(options) {
    options = isObject(options) ? options : {};
    var request = buildScanRequest(options);
    if (!request.ok) {
        return request;
    }
    if (options.authorizedLab !== true) {
        return failure("explicit authorized-lab confirmation is required before an Nmap scan");
    }
    if (!nonEmpty(options.scope)) {
        return failure("a bounded target scope is required before an Nmap scan");
    }
    request.authorizedLab = true;
    return request;
}

/* ------------------------------------------------------------------------- *
 * Nmap XML parsing
 * ------------------------------------------------------------------------- */

function decodeXmlEntities(text) {
    if (typeof text !== "string") {
        return "";
    }
    return text.replace(/&(#x[0-9A-Fa-f]+|#[0-9]+|amp|lt|gt|quot|apos);/g, function (match, body) {
        var lower = body.toLowerCase();
        if (lower === "amp") {
            return "&";
        }
        if (lower === "lt") {
            return "<";
        }
        if (lower === "gt") {
            return ">";
        }
        if (lower === "quot") {
            return "\"";
        }
        if (lower === "apos") {
            return "'";
        }
        var code;
        if (lower.slice(0, 2) === "#x") {
            code = parseInt(lower.slice(2), 16);
        } else {
            code = parseInt(lower.slice(1), 10);
        }
        if (!isFinite(code) || code < 0 || code > 0x10ffff) {
            return match;
        }
        if (String.fromCodePoint) {
            return String.fromCodePoint(code);
        }
        return String.fromCharCode(code);
    });
}

function parseAttributes(text) {
    var attrs = {};
    if (typeof text !== "string") {
        return attrs;
    }
    var re = /([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
    var match;
    while ((match = re.exec(text)) !== null) {
        var value = typeof match[2] === "string" ? match[2] : match[3];
        attrs[match[1]] = decodeXmlEntities(value);
    }
    return attrs;
}

function parseXml(text) {
    if (typeof text !== "string") {
        return {
            ok: false,
            errors: ["Nmap XML must be text"]
        };
    }
    var source = text.replace(/^\uFEFF/, "").trim();
    if (source.length === 0) {
        return {
            ok: false,
            errors: ["Nmap XML is empty"]
        };
    }
    if (/<!ENTITY/i.test(source)) {
        return {
            ok: false,
            errors: ["Nmap XML must not contain entity declarations"]
        };
    }
    if (/<!DOCTYPE[^>]*\[/i.test(source)) {
        return {
            ok: false,
            errors: ["Nmap XML must not contain an internal DTD subset"]
        };
    }

    source = source
        .replace(/<!--[\s\S]*?-->/g, "")
        .replace(/<\?[\s\S]*?\?>/g, "")
        .replace(/<!DOCTYPE[^>]*>/gi, "");

    if (/&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9A-Fa-f]+);)/.test(source)) {
        return {
            ok: false,
            errors: ["Nmap XML contains an unknown or malformed entity reference"]
        };
    }

    var document = {
        name: "#document",
        attrs: {},
        children: [],
        text: ""
    };
    var stack = [document];
    var errors = [];
    var lastIndex = 0;
    var token = /<([A-Za-z_][A-Za-z0-9_.:-]*)((?:\s+[A-Za-z_][A-Za-z0-9_.:-]*\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|<\/([A-Za-z_][A-Za-z0-9_.:-]*)\s*>|([^<]+)/g;
    var match;

    while ((match = token.exec(source)) !== null) {
        if (match.index !== lastIndex) {
            errors.push("invalid XML before position " + match.index);
        }
        lastIndex = token.lastIndex;

        if (typeof match[1] === "string" && match[1].length > 0) {
            var node = {
                name: match[1],
                attrs: parseAttributes(match[2]),
                children: [],
                text: ""
            };
            stack[stack.length - 1].children.push(node);
            if (match[3] !== "/") {
                stack.push(node);
            }
        } else if (typeof match[4] === "string" && match[4].length > 0) {
            var current = stack[stack.length - 1];
            if (current.name !== match[4]) {
                errors.push("mismatched closing tag </" + match[4] + ">");
            } else {
                stack.pop();
            }
        } else if (typeof match[5] === "string") {
            if (/\S/.test(match[5])) {
                if (stack.length === 1) {
                    errors.push("text outside the XML root element");
                } else {
                    stack[stack.length - 1].text += decodeXmlEntities(match[5]);
                }
            }
        }
    }

    if (lastIndex < source.length) {
        errors.push("unrecognized XML near the end of the document");
    }
    while (stack.length > 1) {
        errors.push("unclosed XML element <" + stack[stack.length - 1].name + ">");
        stack.pop();
    }
    if (document.children.length !== 1) {
        errors.push("Nmap XML must have exactly one root element");
    }
    if (errors.length > 0) {
        return {
            ok: false,
            errors: unique(errors)
        };
    }
    return {
        ok: true,
        root: document.children[0],
        errors: []
    };
}

function childNodes(node, name) {
    if (!node || !Array.isArray(node.children)) {
        return [];
    }
    return node.children.filter(function (child) {
        return child.name === name;
    });
}

function childNode(node, name) {
    return childNodes(node, name)[0] || null;
}

function attr(node, name) {
    if (!node || !node.attrs || !Object.prototype.hasOwnProperty.call(node.attrs, name)) {
        return "";
    }
    return node.attrs[name];
}

function numericAttr(node, name) {
    var value = attr(node, name);
    if (value === "") {
        return null;
    }
    var number = Number(value);
    return isFinite(number) ? number : null;
}

function truthyAttr(node, name) {
    return /^(1|true|yes|on)$/i.test(attr(node, name));
}

function parseService(node) {
    if (!node) {
        return null;
    }
    return {
        name: attr(node, "name"),
        product: attr(node, "product"),
        version: attr(node, "version"),
        extrainfo: attr(node, "extrainfo"),
        tunnel: attr(node, "tunnel"),
        method: attr(node, "method"),
        conf: attr(node, "conf"),
        ostype: attr(node, "ostype"),
        devicetype: attr(node, "devicetype"),
        servicefp: attr(node, "servicefp")
    };
}

function parseScripts(node) {
    return childNodes(node, "script").map(function (script) {
        return {
            id: attr(script, "id"),
            output: attr(script, "output") || script.text
        };
    });
}

function parseHost(node) {
    var statusNode = childNode(node, "status");
    var addressNodes = childNodes(node, "address");
    var addresses = addressNodes.map(function (address) {
        return {
            addr: attr(address, "addr"),
            addrtype: attr(address, "addrtype"),
            vendor: attr(address, "vendor")
        };
    });
    var primary = null;
    var addressIndex;
    for (addressIndex = 0; addressIndex < addresses.length; addressIndex += 1) {
        if (addresses[addressIndex].addrtype === "ipv4" ||
            addresses[addressIndex].addrtype === "ipv6") {
            primary = addresses[addressIndex].addr;
            break;
        }
    }
    if (!primary && addresses.length > 0) {
        primary = addresses[0].addr;
    }

    var hostnameNodes = childNodes(childNode(node, "hostnames"), "hostname");
    var hostnames = hostnameNodes.map(function (hostname) {
        return attr(hostname, "name");
    }).filter(nonEmpty);

    var portsNode = childNode(node, "ports");
    var ports = childNodes(portsNode, "port").map(function (port) {
        var stateNode = childNode(port, "state");
        var portid = numericAttr(port, "portid");
        return {
            protocol: attr(port, "protocol") || "tcp",
            portid: portid,
            port: portid,
            state: attr(stateNode, "state") || "unknown",
            reason: attr(stateNode, "reason"),
            service: parseService(childNode(port, "service")),
            scripts: parseScripts(port)
        };
    });

    var osNode = childNode(node, "os");
    var osMatches = childNodes(osNode, "osmatch").map(function (osMatch) {
        return {
            name: attr(osMatch, "name"),
            accuracy: numericAttr(osMatch, "accuracy"),
            line: attr(osMatch, "line")
        };
    });

    return {
        status: attr(statusNode, "state") || "unknown",
        reason: attr(statusNode, "reason"),
        addresses: addresses,
        address: primary,
        hostnames: hostnames,
        hostname: hostnames.length > 0 ? hostnames[0] : "",
        ports: ports,
        osMatches: osMatches,
        starttime: numericAttr(node, "starttime"),
        endtime: numericAttr(node, "endtime")
    };
}

function parseRunStats(root) {
    var runstats = childNode(root, "runstats");
    var finished = childNode(runstats, "finished");
    var hosts = childNode(runstats, "hosts");
    return {
        exit: attr(finished, "exit"),
        errormsg: attr(finished, "errormsg"),
        time: numericAttr(finished, "time"),
        timestr: attr(finished, "timestr"),
        elapsedSeconds: numericAttr(finished, "elapsed"),
        text: attr(finished, "summary") || (finished ? finished.text : ""),
        timedOut: truthyAttr(finished, "timedout") ||
            truthyAttr(finished, "timeout") ||
            /timeout|timed[ -]?out/i.test(attr(finished, "exit")),
        hostsUp: numericAttr(hosts, "up"),
        hostsDown: numericAttr(hosts, "down"),
        hostsTotal: numericAttr(hosts, "total")
    };
}

function parseNmapXml(xml) {
    if (xml && typeof xml === "object" && typeof xml.toString === "function" &&
        typeof xml !== "string") {
        xml = xml.toString("utf8");
    }
    var parsed = parseXml(xml);
    if (!parsed.ok) {
        return {
            ok: false,
            status: "error",
            timedOut: false,
            errors: parsed.errors,
            warnings: [],
            hosts: [],
            summary: null
        };
    }

    var root = parsed.root;
    if (root.name !== "nmaprun") {
        return {
            ok: false,
            status: "error",
            timedOut: false,
            errors: ["expected an <nmaprun> root element, got <" + root.name + ">"],
            warnings: [],
            hosts: [],
            summary: null
        };
    }

    var warnings = [];
    var errors = [];
    var summary = parseRunStats(root);
    if (!summary.exit) {
        errors.push("Nmap XML has no <runstats><finished> element; the scan may be incomplete.");
    }
    if (summary.timedOut) {
        errors.push("Nmap reported that the scan timed out.");
    } else if (summary.exit && !/^success$/i.test(summary.exit)) {
        errors.push("Nmap exited with status " + summary.exit +
            (summary.errormsg ? ": " + summary.errormsg : "."));
    } else if (summary.errormsg) {
        errors.push(summary.errormsg);
    }

    var hosts = childNodes(root, "host").map(parseHost);
    var upHosts = hosts.filter(function (host) {
        return host.status === "up";
    }).length;

    return {
        ok: errors.length === 0,
        status: summary.timedOut ? "timeout" : (errors.length === 0 ? "complete" : "error"),
        timedOut: summary.timedOut,
        errors: unique(errors),
        warnings: unique(warnings),
        hosts: hosts,
        hostCount: hosts.length,
        upHostCount: upHosts,
        summary: summary
    };
}

function interpretScanResult(result, options) {
    options = isObject(options) ? options : {};
    var timeoutMs = options.timeoutMs || null;

    if (typeof result === "undefined" || result === null) {
        return {
            ok: false,
            status: "error",
            timedOut: false,
            errors: ["Nmap returned no result."],
            warnings: [],
            hosts: [],
            summary: null
        };
    }

    if (typeof result === "string" ||
        (typeof result === "object" && typeof result.toString === "function" &&
            typeof result.length === "number")) {
        return parseNmapXml(result);
    }

    if (!isObject(result)) {
        return {
            ok: false,
            status: "error",
            timedOut: false,
            errors: ["unrecognized Nmap result"],
            warnings: [],
            hosts: [],
            summary: null
        };
    }

    var timedOut = result.timedOut === true ||
        result.timeout === true ||
        /^(timeout|timed-out|etimedout)$/i.test(String(result.status || "")) ||
        /^(ETIMEDOUT|TIMEOUT)$/i.test(String(result.code || ""));

    var errors = [];
    var warnings = [];
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
        errors.push("Nmap exited with code " + result.exitCode + ".");
    }

    var xml = result.xml || result.stdout || result.output || result.data;
    var parsed = null;
    if (typeof xml === "string" && xml.trim() !== "") {
        parsed = parseNmapXml(xml);
    }

    if (parsed) {
        if (timedOut) {
            parsed.timedOut = true;
            parsed.ok = false;
            parsed.status = "timeout";
            parsed.errors = ["Nmap timed out" +
                (timeoutMs ? " after " + timeoutMs + " ms" : "") + "."]
                .concat(parsed.errors);
        } else if (parsed.ok && errors.length > 0) {
            /* stderr is often advisory when the XML itself is complete. */
            parsed.warnings = unique(parsed.warnings.concat(errors));
        } else if (errors.length > 0) {
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
            timedOut: true,
            errors: unique(["Nmap timed out" +
                (timeoutMs ? " after " + timeoutMs + " ms" : "") + "."]
                .concat(errors)),
            warnings: warnings,
            hosts: [],
            summary: null
        };
    }

    if (errors.length === 0) {
        errors.push("Nmap did not return XML output.");
    }
    return {
        ok: false,
        status: "error",
        timedOut: false,
        errors: unique(errors),
        warnings: warnings,
        hosts: [],
        summary: null
    };
}

function formatScanResult(result) {    result = isObject(result) ? result : {};
    var lines = [];

    if (result.timedOut) {
        lines.push("TIMEOUT: the Nmap scan did not finish.");
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

    if (result.summary && typeof result.summary === "object") {
        var summary = result.summary;
        var summaryLine = "Nmap status: " + (summary.exit || "unknown");
        if (typeof summary.elapsedSeconds === "number") {
            summaryLine += ", elapsed " + summary.elapsedSeconds + "s";
        }
        if (typeof summary.hostsUp === "number") {
            summaryLine += ", hosts up " + summary.hostsUp +
                (typeof summary.hostsTotal === "number" ? "/" + summary.hostsTotal : "");
        }
        lines.push(summaryLine);
    }

    var hosts = Array.isArray(result.hosts) ? result.hosts : [];
    if (hosts.length === 0) {
        lines.push("No hosts were reported.");
        return lines.join("\n");
    }

    hosts.forEach(function (host) {
        var label = host.address || "(no address)";
        if (host.hostname) {
            label += " (" + host.hostname + ")";
        }
        lines.push("");
        lines.push(label + " - " + (host.status || "unknown"));
        if (!Array.isArray(host.ports) || host.ports.length === 0) {
            lines.push("  no ports reported");
            return;
        }
        host.ports.forEach(function (port) {
            var service = port.service && port.service.name
                ? " " + port.service.name
                : "";
            if (port.service && port.service.product) {
                service += " (" + port.service.product +
                    (port.service.version ? " " + port.service.version : "") + ")";
            }
            lines.push("  " + (port.protocol || "tcp") + "/" + port.portid +
                " " + (port.state || "unknown") + service);
        });
    });
    return lines.join("\n");
}

function canonicalizeTarget(value, options) {
    var result = validateTarget(value, options);
    return result.ok ? result.canonical : null;
}

function isPrivateTarget(value) {
    var result = validateTarget(value);
    return result.ok && result.isPrivate === true;
}

function isPublicTarget(value) {
    var result = validateTarget(value, {allowPublic: true});
    return result.ok && result.isPrivate === false;
}

var api = {
    NMAP_COMMAND: NMAP_COMMAND,
    DEFAULT_PROFILE: DEFAULT_PROFILE,
    DEFAULT_TIMEOUT_MS: DEFAULT_TIMEOUT_MS,
    MIN_TIMEOUT_MS: MIN_TIMEOUT_MS,
    MAX_TIMEOUT_MS: MAX_TIMEOUT_MS,
    MAX_TARGETS: MAX_TARGETS,
    PROFILES: PROFILES,
    OPTIONS: OPTIONS,
    listProfiles: listProfiles,
    listOptions: listOptions,
    getProfile: getProfile,
    normalizeOptions: normalizeOptions,
    parseIPv4: parseIPv4,
    parseIPv6: parseIPv6,
    validateTarget: validateTarget,
    canonicalizeTarget: canonicalizeTarget,
    isPrivateTarget: isPrivateTarget,
    isPublicTarget: isPublicTarget,
    validateTargets: validateTargets,
    targetInScope: targetInScope,
    validateArgv: validateArgv,
    validateArguments: validateArgv,
    buildScanRequest: buildScanRequest,
    buildNmapArgs: buildScanRequest,
    buildArgs: buildScanRequest,
    prepareScan: prepareScan,
    parseNmapXml: parseNmapXml,
    parseXml: parseNmapXml,
    interpretScanResult: interpretScanResult,
    formatScanResult: formatScanResult,
    formatResult: formatScanResult,
    formatScanSummary: formatScanResult
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
}
