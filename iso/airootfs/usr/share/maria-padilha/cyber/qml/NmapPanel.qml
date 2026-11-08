import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * Nmap tab. The operator supplies the arguments and must click the explicit
 * start control; nothing is scanned on load, on tab activation, or on a timer.
 * Shared controls rendered by ToolPanelFrame: AuthorizationBanner,
 * LabModeSwitch, TargetScopeIndicator, and StopClearAction (Stop / Clear).
 */
ToolPanelFrame {
    id: nmapFrame
    property var shell: null
    property bool missing: false
    property var fallbackData: null

    authorization: shell ? shell.authorization : null
    title: "Nmap"
    description: "Explicit, operator-started network mapping for an authorized target scope. No default scan or target discovery runs."
    toolName: "nmap"

    panelContent: ColumnLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        Text {
            Layout.fillWidth: true
            text: "Enter only the arguments you intend to run. The target must already be inside the visible scope."
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }

        TextField {
            id: argsField
            Layout.fillWidth: true
            placeholderText: "operator-supplied nmap arguments (no default scan profile)"
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
            visible: nmapFrame.missing
            fallbackData: nmapFrame.fallbackData
            toolName: "nmap"
        }

        RunButton {
            Layout.fillWidth: true
            visible: !nmapFrame.missing
            runner: nmapFrame.shell ? nmapFrame.shell.runner : null
            tabId: "nmap"
            label: "Start Nmap (explicit)"
            ready: nmapFrame.shell !== null
            argsText: argsField.text
        }
    }

    Component.onCompleted: refreshAvailability()

    function refreshAvailability() {
        if (!shell || !shell.runner) {
            return;
        }
        var prepared = shell.runner.prepare("nmap");
        missing = prepared.status === "missing-tool";
        fallbackData = prepared.fallback || null;
    }
}
