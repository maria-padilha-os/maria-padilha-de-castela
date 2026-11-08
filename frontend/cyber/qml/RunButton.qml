import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * Explicit run control. It is disabled until the runner reports ready, and it
 * only calls the confirmed start path on a click. No Component.onCompleted,
 * timer, or visibility change invokes the runner.
 */
ColumnLayout {
    id: runControl
    property var runner: null
    property string tabId: ""
    property string label: "Start (explicit)"
    property bool ready: false
    property string argsText: ""
    property string lastStatus: ""

    spacing: CyberTheme.space1

    Button {
        id: runButton
        Layout.fillWidth: true
        text: runControl.label
        enabled: runControl.ready && runControl.runner !== null
        font.family: CyberTheme.fontFamily
        palette.button: CyberTheme.accent
        palette.buttonText: CyberTheme.onAccent
        onClicked: runControl.startNow()
    }

    Text {
        Layout.fillWidth: true
        visible: runControl.lastStatus.length > 0
        text: runControl.lastStatus
        color: CyberTheme.textMuted
        font.family: CyberTheme.fontMono
        font.pixelSize: 12
        wrapMode: Text.WrapAnywhere
        Accessible.role: Accessible.StaticText
        Accessible.name: text
    }

    function startNow() {
        if (!runner) {
            lastStatus = "No host executor is configured; nothing was run.";
            return;
        }
        var result = runner.start(tabId, {
            confirmed: true,
            args: argsText.length > 0 ? argsText.split(/\s+/).filter(function (part) { return part.length > 0; }) : []
        });
        lastStatus = result.status + (result.reason ? ": " + result.reason : "");
        resultReady(result);
    }

    signal resultReady(var result)
}
