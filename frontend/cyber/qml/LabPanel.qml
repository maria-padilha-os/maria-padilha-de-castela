import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * Lab / VM launcher. It never creates a bridge, starts libvirtd, or boots a VM
 * on load. The host adapter receives one explicit launch request after the
 * authorization and scope gates pass.
 * Shared controls rendered by ToolPanelFrame: AuthorizationBanner,
 * LabModeSwitch, TargetScopeIndicator, and StopClearAction (Stop / Clear).
 */
ToolPanelFrame {
    id: labFrame
    property var shell: null
    property bool missing: false
    property var fallbackData: null

    authorization: shell ? shell.authorization : null
    title: "Lab / VM"
    description: "Isolated virtual machines for authorized lab work. No VM, bridge, or service starts by itself."
    toolName: "QEMU/libvirt"

    panelContent: ColumnLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        Text {
            Layout.fillWidth: true
            text: "Use a lab network you own and control. The launcher passes the VM name or arguments only after an explicit start."
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }

        TextField {
            id: vmField
            Layout.fillWidth: true
            placeholderText: "VM name or operator-supplied launch arguments"
            selectByMouse: true
            color: CyberTheme.fieldText
            font.family: CyberTheme.fontMono
            palette.base: CyberTheme.field
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
        }

        ToolUnavailable {
            Layout.fillWidth: true
            visible: labFrame.missing
            fallbackData: labFrame.fallbackData
            toolName: "QEMU/libvirt"
        }

        RunButton {
            Layout.fillWidth: true
            visible: !labFrame.missing
            runner: labFrame.shell ? labFrame.shell.runner : null
            tabId: "lab-vm"
            label: "Launch isolated lab VM (explicit)"
            ready: labFrame.shell !== null
            argsText: vmField.text
        }
    }

    Component.onCompleted: refreshAvailability()

    function refreshAvailability() {
        if (!shell || !shell.runner) {
            return;
        }
        var prepared = shell.runner.prepare("lab-vm");
        missing = prepared.status === "missing-tool";
        fallbackData = prepared.fallback || null;
    }
}
