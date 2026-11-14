import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../src/lab.js" as Lab

/*
 * Lab / VM launcher.
 *
 * The panel generates a libvirt domain definition and, for the default path, an
 * isolated LAB ONLY network definition. It never connects to libvirt, creates a
 * bridge, starts a network, or boots a VM on load. The shared frame supplies the
 * authorization banner, lab-mode switch, target scope, and Stop/Clear controls.
 * The host adapter receives the generated XML only after an explicit click.
 *
 * The default network has no host bridge and no LAN route. Selecting the host
 * LAN path shows a warning and requires a separate acknowledgement before the
 * launch control becomes ready.
 */
ToolPanelFrame {
    id: labFrame
    property var shell: null
    property bool missing: false
    property var fallbackData: null

    property string vmName: Lab.DEFAULT_VM_NAME
    property string diskPath: Lab.DEFAULT_DISK_PATH
    property string networkId: Lab.DEFAULT_NETWORK_ID
    property bool hostLanConfirmed: false
    property bool readyToLaunch: false
    property string validationText: ""
    property string statusText: ""
    property string resultText: ""
    property var networkModel: Lab.listNetworks()

    authorization: shell ? shell.authorization : null
    title: "Lab / VM"
    description: "Isolated QEMU/libvirt lab launcher. It generates a domain on the default LAB ONLY network and includes snapshot guidance. No VM, bridge, network, or service starts by itself."
    toolName: "QEMU/libvirt"

    panelContent: ColumnLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        Text {
            Layout.fillWidth: true
            text: labFrame.labWarning()
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }

        Text {
            text: "VM name"
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            font.bold: true
        }

        TextField {
            id: vmNameField
            Layout.fillWidth: true
            text: labFrame.vmName
            placeholderText: "short lab VM name (letters, digits, dot, dash, underscore)"
            selectByMouse: true
            color: CyberTheme.fieldText
            font.family: CyberTheme.fontMono
            palette.base: CyberTheme.field
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onTextChanged: {
                labFrame.vmName = text;
                labFrame.revalidate();
            }
        }

        Text {
            text: "qcow2 disk path"
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            font.bold: true
        }

        TextField {
            id: diskPathField
            Layout.fillWidth: true
            text: labFrame.diskPath
            placeholderText: "/var/lib/libvirt/images/lab.qcow2"
            selectByMouse: true
            color: CyberTheme.fieldText
            font.family: CyberTheme.fontMono
            palette.base: CyberTheme.field
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onTextChanged: {
                labFrame.diskPath = text;
                labFrame.revalidate();
            }
        }

        Text {
            text: "Network (LAB ONLY is the default)"
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            font.bold: true
        }

        ComboBox {
            id: networkBox
            Layout.fillWidth: true
            model: labFrame.networkModel
            textRole: "label"
            currentIndex: labFrame.networkIndex(labFrame.networkId)
            font.family: CyberTheme.fontFamily
            onActivated: {
                if (index >= 0 && index < labFrame.networkModel.length) {
                    labFrame.networkId = labFrame.networkModel[index].id;
                    if (labFrame.networkId !== Lab.HOST_LAN_NETWORK_ID) {
                        labFrame.hostLanConfirmed = false;
                    }
                    labFrame.revalidate();
                }
            }
        }

        Text {
            Layout.fillWidth: true
            visible: labFrame.networkId === Lab.HOST_LAN_NETWORK_ID
            text: labFrame.hostLanWarningText()
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            font.bold: true
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        CheckBox {
            id: hostLanConfirmBox
            Layout.fillWidth: true
            visible: labFrame.networkId === Lab.HOST_LAN_NETWORK_ID
            checked: labFrame.hostLanConfirmed
            text: labFrame.hostLanLabel()
            font.family: CyberTheme.fontFamily
            font.bold: true
            palette.windowText: CyberTheme.text
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onToggled: {
                labFrame.hostLanConfirmed = checked;
                labFrame.revalidate();
            }
        }

        TextField {
            id: hostBridgeField
            Layout.fillWidth: true
            visible: labFrame.networkId === Lab.HOST_LAN_NETWORK_ID
            placeholderText: "existing host bridge name (no default; e.g. br0)"
            selectByMouse: true
            color: CyberTheme.fieldText
            font.family: CyberTheme.fontMono
            palette.base: CyberTheme.field
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onTextChanged: labFrame.revalidate()
        }

        Text {
            Layout.fillWidth: true
            text: "Snapshot guidance: " + labFrame.snapshotText()
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        ToolUnavailable {
            Layout.fillWidth: true
            visible: labFrame.missing
            fallbackData: labFrame.fallbackData
            toolName: "QEMU/libvirt"
        }

        Text {
            Layout.fillWidth: true
            visible: labFrame.validationText.length > 0
            text: labFrame.validationText
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Button {
            Layout.fillWidth: true
            visible: !labFrame.missing
            enabled: labFrame.readyToLaunch && labFrame.shell !== null &&
                labFrame.shell.runner !== null
            text: labFrame.networkId === Lab.HOST_LAN_NETWORK_ID
                ? "Define VM on host LAN (explicit, NOT ISOLATED)"
                : "Define isolated lab VM (explicit)"
            font.family: CyberTheme.fontFamily
            palette.button: labFrame.networkId === Lab.HOST_LAN_NETWORK_ID
                ? CyberTheme.danger
                : CyberTheme.accent
            palette.buttonText: CyberTheme.onAccent
            onClicked: labFrame.startNow()
        }

        Text {
            Layout.fillWidth: true
            visible: labFrame.resultText.length > 0
            text: labFrame.resultText
            color: CyberTheme.text
            font.family: CyberTheme.fontMono
            font.pixelSize: 12
            wrapMode: Text.WrapAnywhere
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
    }

    Component.onCompleted: {
        refreshAvailability();
        revalidate();
    }

    function authorizationSnapshot() {
        if (shell && shell.authorization) {
            return shell.authorization.snapshot();
        }
        return null;
    }

    function labWarning() {
        var snapshot = authorizationSnapshot();
        return (snapshot && snapshot.labVmWarning) || Lab.LAB_NETWORK_LABEL;
    }

    function hostLanWarningText() {
        var snapshot = authorizationSnapshot();
        return (snapshot && snapshot.hostLanWarning) || Lab.HOST_LAN_WARNING;
    }

    function hostLanLabel() {
        var snapshot = authorizationSnapshot();
        return (snapshot && snapshot.hostLanConfirmationLabel) || "I understand this VM will leave the isolated LAB ONLY network, can reach the host LAN, and that I have authorization and a clean snapshot.";
    }

    function snapshotText() {
        var snapshot = authorizationSnapshot();
        return (snapshot && snapshot.snapshotGuidance) || Lab.SNAPSHOT_GUIDANCE[0];
    }

    function networkIndex(id) {
        var index;
        for (index = 0; index < networkModel.length; index += 1) {
            if (networkModel[index].id === id) {
                return index;
            }
        }
        return 0;
    }

    function buildPlan() {
        return Lab.prepareLaunch({
            vmName: vmName,
            diskPath: diskPath,
            network: networkId,
            hostLanConfirmed: hostLanConfirmed,
            hostBridge: hostBridgeField.text
        });
    }

    function refreshAvailability() {
        if (!shell || !shell.runner) {
            missing = true;
            fallbackData = null;
            statusText = "No host tool probe is configured. No VM or network was defined.";
            revalidate();
            return;
        }

        var prepared = shell.runner.prepare("lab-vm");
        missing = prepared.status === "missing-tool";
        fallbackData = prepared.fallback || null;
        statusText = missing
            ? (fallbackData ? fallbackData.reason : prepared.reason)
            : "QEMU/libvirt is available. Nothing has been defined or started.";
        revalidate();
    }

    function revalidate() {
        if (!shell || !shell.runner) {
            readyToLaunch = false;
            validationText = "No host executor is configured; nothing will run.";
            return;
        }
        if (missing) {
            readyToLaunch = false;
            validationText = fallbackData
                ? fallbackData.reason
                : "QEMU/libvirt is not installed; no VM definition will be sent.";
            return;
        }

        var prepared = shell.runner.prepare("lab-vm");
        var plan = buildPlan();
        readyToLaunch = prepared.status === "ready" && plan.ok === true;
        validationText = plan.ok
            ? (prepared.status === "ready" ? "" : (prepared.reason || ""))
            : plan.reason;
    }

    function startNow() {
        if (!readyToLaunch || !shell || !shell.runner) {
            return;
        }

        var plan = buildPlan();
        if (!plan.ok) {
            validationText = plan.reason;
            readyToLaunch = false;
            return;
        }

        var result = shell.runner.start("lab-vm", {
            confirmed: true,
            args: [],
            metadata: {
                action: plan.action,
                domainName: plan.domainName,
                domainXml: plan.domainXml,
                networkXml: plan.networkXml,
                network: plan.network,
                isolated: plan.isolated,
                hostBridge: plan.hostBridge,
                hostLanWarning: plan.hostLanWarning,
                snapshotGuidance: plan.snapshotGuidance,
                autoStart: false
            }
        });
        if (result.status !== "started") {
            resultText = result.status + (result.reason ? ": " + result.reason : "");
            return;
        }
        resultText = plan.isolated
            ? "Definition for " + plan.domainName + " prepared on " + plan.networkLabel + ". No VM was started. " + plan.snapshotGuidance[0]
            : "HOST LAN definition for " + plan.domainName + " prepared. This is NOT isolated. " + plan.snapshotGuidance[0];
        revalidate();
    }
}
