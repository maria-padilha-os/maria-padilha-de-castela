import QtQuick 2.15
import QtQuick.Layouts 1.15

/*
 * Missing-tool fallback. It keeps the tab usable (the shared controls remain
 * visible) while making it explicit that the tool is absent and that no
 * command was run.
 */
Rectangle {
    id: fallback
    property var fallbackData: null
    property string toolName: ""

    implicitHeight: fallbackLayout.implicitHeight + CyberTheme.space3 * 2
    color: CyberTheme.surface
    border.width: CyberTheme.borderWidth * 2
    border.color: CyberTheme.danger
    radius: CyberTheme.radius

    ColumnLayout {
        id: fallbackLayout
        anchors.fill: parent
        anchors.margins: CyberTheme.space3
        spacing: CyberTheme.space2

        Text {
            Layout.fillWidth: true
            text: fallback.fallbackData
                ? fallback.fallbackData.title
                : (fallback.toolName.length > 0 ? fallback.toolName + " is unavailable" : "Tool unavailable")
            color: CyberTheme.text
            font.family: CyberTheme.fontFamily
            font.bold: true
            font.pixelSize: 16
            wrapMode: Text.WordWrap
        }

        Text {
            Layout.fillWidth: true
            text: fallback.fallbackData
                ? fallback.fallbackData.message
                : "The tool is not installed. No command was run."
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }

        Text {
            Layout.fillWidth: true
            visible: text.length > 0
            text: fallback.fallbackData && fallback.fallbackData.reason
                ? fallback.fallbackData.reason
                : ""
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontMono
            font.pixelSize: 12
            wrapMode: Text.WordWrap
        }

        Text {
            Layout.fillWidth: true
            visible: text.length > 0
            text: fallback.fallbackData && fallback.fallbackData.installHint
                ? fallback.fallbackData.installHint
                : ""
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }
    }
}
