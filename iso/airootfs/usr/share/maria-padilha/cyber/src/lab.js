/*
 * Safe, shared QEMU/libvirt lab launcher helpers.
 *
 * This module never connects to libvirt, starts QEMU, touches a network, or
 * writes a file. It only validates operator input and renders a libvirt network
 * definition and domain XML for the host adapter to define after an explicit
 * click.
 *
 * Security properties:
 *   - the default network is LAB ONLY and uses libvirt forward mode "none";
 *   - the generated network and domain contain no host bridge by default;
 *   - host-LAN attachment requires an explicit warning acknowledgement and an
 *     operator-supplied existing bridge name;
 *   - VM names, disk paths, and bridge names are validated before they are
 *     interpolated into XML;
 *   - a qcow2 disk is required so the snapshot guidance can be followed;
 *   - nothing is defined, started, or auto-run by this module.
 */

"use strict";

var DEFAULT_NETWORK_ID = "isolated";
var LAB_NETWORK_NAME = "mp-lab-isolated";
var LAB_NETWORK_LABEL = "LAB ONLY: isolated network (no host bridge, no LAN route)";
var HOST_LAN_NETWORK_ID = "host-lan";
var HOST_LAN_NETWORK_LABEL = "HOST LAN (NOT ISOLATED): explicit warning required";
var DEFAULT_VM_NAME = "mp-lab-vm";
var DEFAULT_MEMORY_MIB = 2048;
var DEFAULT_VCPUS = 2;
var MIN_MEMORY_MIB = 512;
var MAX_MEMORY_MIB = 65536;
var MIN_VCPUS = 1;
var MAX_VCPUS = 32;
var MAX_VM_NAME_LENGTH = 63;
var MAX_DISK_PATH_LENGTH = 255;
var MAX_BRIDGE_NAME_LENGTH = 15;
var ISOLATED_SUBNET = "10.213.0.0/24";

var HOST_LAN_WARNING = "WARNING: Attaching this VM to the host LAN removes lab isolation. " +
    "The guest can reach real hosts, services, and the internet. Do this only on a network " +
    "you own or are explicitly authorized to use, and take a clean snapshot before changing " +
    "the VM network.";

var SNAPSHOT_GUIDANCE = [
    "Use a qcow2 disk so libvirt can snapshot it before any target runs.",
    "Create a clean baseline snapshot while the VM is powered off: " +
        "virsh snapshot-create-as <domain> clean-baseline \"clean lab baseline\".",
    "Revert to the clean snapshot after every exercise: " +
        "virsh snapshot-revert <domain> clean-baseline.",
    "Take a fresh snapshot before changing the VM network, installing media, or " +
        "starting an untrusted target.",
    "Keep snapshots and disks local, and never store credentials, captured secrets, " +
        "or production data in a snapshot."
];

var NETWORK_ORDER = [DEFAULT_NETWORK_ID, HOST_LAN_NETWORK_ID];

var NETWORKS = {
    "isolated": {
        id: "isolated",
        name: LAB_NETWORK_NAME,
        label: LAB_NETWORK_LABEL,
        description: "LAB ONLY libvirt network with no forwarding, host bridge, or LAN route.",
        isolated: true,
        hostBridge: false,
        forwardMode: "none",
        default: true,
        requiresConfirmation: false,
        warning: ""
    },
    "host-lan": {
        id: "host-lan",
        name: HOST_LAN_NETWORK_ID,
        label: HOST_LAN_NETWORK_LABEL,
        description: "Explicit non-isolated attachment to an existing host bridge.",
        isolated: false,
        hostBridge: true,
        forwardMode: "bridge",
        default: false,
        requiresConfirmation: true,
        warning: HOST_LAN_WARNING
    }
};

var NETWORK_ALIASES = {
    "lab": "isolated",
    "lab-only": "isolated",
    "lab_only": "isolated",
    "none": "isolated",
    "default": "isolated",
    "hostlan": "host-lan",
    "host_lan": "host-lan",
    "lan": "host-lan",
    "bridge": "host-lan"
};

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

function firstPresent() {
    var index;
    for (index = 0; index < arguments.length; index += 1) {
        if (typeof arguments[index] !== "undefined" && arguments[index] !== null) {
            return arguments[index];
        }
    }
    return undefined;
}

function failure(reason, extra) {
    var result = {
        ok: false,
        status: "invalid",
        reason: reason,
        errors: [reason],
        autoRun: false,
        autoStart: false,
        executed: false
    };
    if (isObject(extra)) {
        Object.keys(extra).forEach(function (key) {
            result[key] = extra[key];
        });
    }
    return result;
}

function escapeXml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/'/g, "&apos;")
        .replace(/"/g, "&quot;");
}

function normalizeNetworkId(value) {
    if (!nonEmpty(value)) {
        return DEFAULT_NETWORK_ID;
    }
    var key = value.trim().toLowerCase();
    if (Object.prototype.hasOwnProperty.call(NETWORKS, key)) {
        return key;
    }
    if (Object.prototype.hasOwnProperty.call(NETWORK_ALIASES, key)) {
        return NETWORK_ALIASES[key];
    }
    return null;
}

function getNetwork(id) {
    var key = normalizeNetworkId(id);
    return key && Object.prototype.hasOwnProperty.call(NETWORKS, key)
        ? clone(NETWORKS[key])
        : null;
}

function listNetworks() {
    return NETWORK_ORDER.map(function (id) {
        return clone(NETWORKS[id]);
    });
}

function validateVmName(value) {
    var name = typeof value === "undefined" || value === null
        ? DEFAULT_VM_NAME
        : String(value).trim();
    if (name.length === 0) {
        return failure("a VM name is required");
    }
    if (name.length > MAX_VM_NAME_LENGTH) {
        return failure("VM name must be at most " + MAX_VM_NAME_LENGTH + " characters");
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name)) {
        return failure("VM name must start with a letter or digit and contain only letters, digits, dot, underscore, or dash");
    }
    return {ok: true, name: name};
}

function defaultDiskPath(name) {
    var checked = validateVmName(name);
    var safeName = checked.ok ? checked.name : DEFAULT_VM_NAME;
    return "/var/lib/libvirt/images/" + safeName + ".qcow2";
}

function validateDiskPath(value) {
    var diskPath = typeof value === "undefined" || value === null
        ? defaultDiskPath(DEFAULT_VM_NAME)
        : String(value).trim();
    if (diskPath.length === 0) {
        return failure("a local qcow2 disk path is required");
    }
    if (diskPath.length > MAX_DISK_PATH_LENGTH) {
        return failure("disk path is too long");
    }
    if (diskPath.charAt(0) !== "/") {
        return failure("disk path must be absolute");
    }
    if (!/^\/[A-Za-z0-9._+@%/-]+$/.test(diskPath)) {
        return failure("disk path contains characters that are not allowed");
    }
    if (diskPath.indexOf("//") !== -1) {
        return failure("disk path must not contain empty path segments");
    }
    var segments = diskPath.split("/").slice(1);
    var invalid = segments.some(function (segment) {
        return segment === "" || segment === "." || segment === "..";
    });
    if (invalid) {
        return failure("disk path must not contain dot or parent segments");
    }
    if (!/\.qcow2$/i.test(diskPath)) {
        return failure("disk path must end in .qcow2 so snapshots are available");
    }
    return {ok: true, path: diskPath};
}

function validateBridgeName(value) {
    var name = typeof value === "undefined" || value === null
        ? ""
        : String(value).trim();
    if (name.length === 0) {
        return failure("host LAN attachment requires an explicit existing host bridge name");
    }
    if (name.length > MAX_BRIDGE_NAME_LENGTH ||
        !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(name)) {
        return failure("host bridge name is not a valid interface name");
    }
    return {ok: true, name: name};
}

function integerInRange(value, fallback, min, max, label) {
    var text = typeof value === "undefined" || value === null || value === ""
        ? String(fallback)
        : String(value).trim();
    if (!/^[0-9]+$/.test(text)) {
        return failure(label + " must be a whole number");
    }
    var number = parseInt(text, 10);
    if (number < min || number > max) {
        return failure(label + " must be between " + min + " and " + max);
    }
    return {ok: true, value: number};
}

function resolveNetwork(options) {
    options = isObject(options) ? options : {};
    var requested = options.network || options.networkId || options.networkMode;
    var network = getNetwork(requested);
    if (!network) {
        return failure("unknown lab network: " + String(requested));
    }

    if (network.isolated) {
        return {
            ok: true,
            network: network,
            hostBridge: null,
            warning: ""
        };
    }

    if (options.hostLanConfirmed !== true) {
        return failure(HOST_LAN_WARNING, {
            status: "host-lan-confirmation-required",
            requiresConfirmation: true,
            warning: HOST_LAN_WARNING,
            network: network
        });
    }

    var bridge = validateBridgeName(options.hostBridge || options.bridge);
    if (!bridge.ok) {
        return failure(bridge.reason, {
            status: "host-lan-bridge-required",
            requiresConfirmation: true,
            warning: HOST_LAN_WARNING,
            network: network
        });
    }

    return {
        ok: true,
        network: network,
        hostBridge: bridge.name,
        warning: HOST_LAN_WARNING
    };
}

function renderIsolatedNetworkXml() {
    return [
        "<network>",
        "  <name>" + escapeXml(LAB_NETWORK_NAME) + "</name>",
        "  <description>LAB ONLY: isolated libvirt network; no host forwarding or LAN route.</description>",
        "  <forward mode='none'/>",
        "  <ip address='10.213.0.1' netmask='255.255.255.0'>",
        "    <dhcp>",
        "      <range start='10.213.0.100' end='10.213.0.199'/>",
        "    </dhcp>",
        "  </ip>",
        "</network>",
        ""
    ].join("\n");
}

function buildNetworkXml(options) {
    options = isObject(options) ? options : {};
    var requested = options.network || options.networkId || options.networkMode;
    var network = getNetwork(requested);
    if (!network || !network.isolated) {
        throw new Error("only the isolated LAB ONLY network has a generated network definition");
    }
    return renderIsolatedNetworkXml();
}

function buildIsolatedNetworkXml() {
    return renderIsolatedNetworkXml();
}

function renderDomainXml(spec) {
    var lines = [
        "<domain type='qemu'>",
        "  <name>" + escapeXml(spec.name) + "</name>",
        "  <description>" +
            (spec.isolated
                ? "Maria Padilha lab VM; LAB ONLY network; no host LAN attachment."
                : "Maria Padilha lab VM; HOST LAN attachment is NOT ISOLATED.") +
            "</description>",
        "  <memory unit='MiB'>" + spec.memoryMiB + "</memory>",
        "  <vcpu placement='static'>" + spec.vcpus + "</vcpu>",
        "  <os>",
        "    <type arch='x86_64' machine='q35'>hvm</type>",
        "    <boot dev='hd'/>",
        "  </os>",
        "  <features>",
        "    <acpi/>",
        "    <apic/>",
        "  </features>",
        "  <devices>",
        "    <disk type='file' device='disk'>",
        "      <driver name='qemu' type='qcow2'/>",
        "      <source file='" + escapeXml(spec.diskPath) + "'/>",
        "      <target dev='vda' bus='virtio'/>",
        "    </disk>"
    ];

    if (spec.isolated) {
        lines.push("    <interface type='network'>");
        lines.push("      <source network='" + escapeXml(spec.networkName) + "'/>");
        lines.push("      <model type='virtio'/>");
        lines.push("    </interface>");
    } else {
        lines.push("    <interface type='bridge'>");
        lines.push("      <source bridge='" + escapeXml(spec.hostBridge) + "'/>");
        lines.push("      <model type='virtio'/>");
        lines.push("    </interface>");
    }

    lines.push("    <graphics type='spice' autoport='yes' listen='127.0.0.1'/>");
    lines.push("    <video>");
    lines.push("      <model type='qxl'/>");
    lines.push("    </video>");
    lines.push("    <console type='pty'/>");
    lines.push("  </devices>");
    lines.push("</domain>");
    lines.push("");
    return lines.join("\n");
}

function prepareLaunch(options) {
    options = isObject(options) ? options : {};

    var name = validateVmName(firstPresent(options.vmName, options.name));
    if (!name.ok) {
        return name;
    }
    var disk = validateDiskPath(firstPresent(options.diskPath, options.disk,
        defaultDiskPath(name.name)));
    if (!disk.ok) {
        return disk;
    }
    var memory = integerInRange(firstPresent(options.memoryMiB, options.memory),
        DEFAULT_MEMORY_MIB, MIN_MEMORY_MIB, MAX_MEMORY_MIB, "memory");
    if (!memory.ok) {
        return memory;
    }
    var vcpus = integerInRange(firstPresent(options.vcpus, options.vcpu),
        DEFAULT_VCPUS, MIN_VCPUS, MAX_VCPUS, "vCPU count");
    if (!vcpus.ok) {
        return vcpus;
    }
    var network = resolveNetwork(options);
    if (!network.ok) {
        return network;
    }

    var domainXml = renderDomainXml({
        name: name.name,
        memoryMiB: memory.value,
        vcpus: vcpus.value,
        diskPath: disk.path,
        isolated: network.network.isolated,
        networkName: network.network.isolated ? LAB_NETWORK_NAME : network.network.name,
        hostBridge: network.hostBridge
    });

    return {
        ok: true,
        status: "ready",
        action: "define-domain",
        autoRun: false,
        autoStart: false,
        executed: false,
        requiresExplicitConfirmation: true,
        domainName: name.name,
        diskPath: disk.path,
        memoryMiB: memory.value,
        vcpus: vcpus.value,
        network: network.network,
        networkLabel: network.network.label,
        isolated: network.network.isolated,
        hostBridge: network.hostBridge,
        hostLanWarning: network.warning,
        domainXml: domainXml,
        networkXml: network.network.isolated ? renderIsolatedNetworkXml() : null,
        snapshotGuidance: SNAPSHOT_GUIDANCE.slice(),
        snapshotRequired: true,
        hostBridgeDefault: false,
        subnet: network.network.isolated ? ISOLATED_SUBNET : null
    };
}

function buildDomainXml(options) {
    var plan = prepareLaunch(options);
    if (!plan.ok) {
        var error = new Error(plan.reason);
        error.status = plan.status;
        error.details = plan;
        throw error;
    }
    return plan.domainXml;
}

function describeNetwork(id) {
    var network = getNetwork(id);
    return network ? network.label : null;
}

var api = {
    DEFAULT_NETWORK_ID: DEFAULT_NETWORK_ID,
    LAB_NETWORK_NAME: LAB_NETWORK_NAME,
    LAB_NETWORK_LABEL: LAB_NETWORK_LABEL,
    HOST_LAN_NETWORK_ID: HOST_LAN_NETWORK_ID,
    HOST_LAN_NETWORK_LABEL: HOST_LAN_NETWORK_LABEL,
    HOST_LAN_WARNING: HOST_LAN_WARNING,
    DEFAULT_VM_NAME: DEFAULT_VM_NAME,
    DEFAULT_DISK_PATH: defaultDiskPath(DEFAULT_VM_NAME),
    DEFAULT_MEMORY_MIB: DEFAULT_MEMORY_MIB,
    DEFAULT_VCPUS: DEFAULT_VCPUS,
    ISOLATED_SUBNET: ISOLATED_SUBNET,
    SNAPSHOT_GUIDANCE: SNAPSHOT_GUIDANCE.slice(),
    listNetworks: listNetworks,
    getNetwork: getNetwork,
    describeNetwork: describeNetwork,
    validateVmName: validateVmName,
    validateDiskPath: validateDiskPath,
    validateBridgeName: validateBridgeName,
    defaultDiskPath: defaultDiskPath,
    buildNetworkXml: buildNetworkXml,
    buildIsolatedNetworkXml: buildIsolatedNetworkXml,
    buildDomainXml: buildDomainXml,
    prepareLaunch: prepareLaunch
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
}
