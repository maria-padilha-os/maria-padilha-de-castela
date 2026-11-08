import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * Wireshark / forensics tab. The panel inspects an operator-supplied capture or
 * image; no packet capture, mount, or modification starts automatically.
 * Shared controls rendered by ToolPanelFrame: AuthorizationBanner,
 * LabModeSwitch, TargetScopeIndicator, and StopClearAction (Stop / Clear).
 */
ToolPanelFrame {
    id: forensicsFrame
    property var shell: null
    property bool missing: false
    property var fallbackData: null

    authorization: shell ? shell.authorization : null
    title: "Wireshark / Forensics"
    description: "Capture-file inspection and forensic review. No capture starts automatically and no media is modified."
    toolName: "Wireshark"

    panelContent: ColumnLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        Text {
            Layout.fillWidth: true
            text: "Provide a capture or image path you own or are authorized to examine. The host adapter opens it only after an explicit start."
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }

        TextField {
            id: sourceField
            Layout.fillWidth: true
            placeholderText: "capture or image path (operator supplied)"
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
            visible: forensicsFrame.missing
            fallbackData: forensicsFrame.fallbackData
            toolName: "Wireshark"
        }

        RunButton {
            Layout.fillWidth: true
            visible: !forensicsFrame.missing
            runner: forensicsFrame.shell ? forensicsFrame.shell.runner : null
            tabId: "forensics"
            label: "Open with Wireshark (explicit)"
            ready: forensicsFrame.shell !== null
            argsText: sourceField.text
        }
    }

    Component.onCompleted: refreshAvailability()

    function refreshAvailability() {
        if (!shell || !shell.runner) {
            return;
        }
        var prepared = shell.runner.prepare("forensics");
        missing = prepared.status === "missing-tool";
        fallbackData = prepared.fallback || null;
    }
}
