import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * SET tab. SET is registered so the framework and operators can see the tab,
 * but it is excluded by policy and is not shipped. No launch control is
 * rendered, even if a setoolkit binary happens to be present.
 * Shared controls rendered by ToolPanelFrame: AuthorizationBanner,
 * LabModeSwitch, TargetScopeIndicator, and StopClearAction (Stop / Clear).
 */
ToolPanelFrame {
    id: setFrame
    property var shell: null

    authorization: shell ? shell.authorization : null
    title: "SET"
    description: "The Social-Engineer Toolkit is outside the authorized-use boundary. This tab is a transparent placeholder; it never offers a launch control."
    toolName: "SET"

    panelContent: ColumnLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        ToolUnavailable {
            Layout.fillWidth: true
            fallbackData: ({
                title: "SET is excluded by policy",
                message: "No launch control is rendered for SET. No command was run.",
                reason: "SET and bundled phishing or credential-capture templates are not shipped.",
                installHint: "Adding SET requires a new policy review, removal of phishing templates, and a test proving the templates are absent."
            })
            toolName: "SET"
        }

        Text {
            Layout.fillWidth: true
            text: "If SET is present on a host anyway, it is still not launched from this surface. Use the shared Stop and Clear actions to reset the lab state."
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }
    }
}
