import QtQuick 2.15
import QtQuick.Controls 2.15

/*
 * Lab-mode switch shared by every panel. Enabling lab mode is refused by the
 * authorization state until written authorization has been acknowledged.
 */
CheckBox {
    id: labSwitch
    property var authorization: null
    property bool labMode: false
    property string failureText: ""

    text: authorization ? authorization.labModeLabel : "Authorized lab mode"
    checked: labMode
    font.family: CyberTheme.fontFamily
    palette.windowText: CyberTheme.text
    palette.highlight: CyberTheme.accent
    palette.highlightedText: CyberTheme.onAccent

    function refresh() {
        if (!authorization) {
            labMode = false;
            return;
        }
        labMode = authorization.snapshot().labMode;
    }

    onToggled: {
        if (!authorization) {
            checked = false;
            return;
        }
        var result = authorization.setLabMode(checked);
        labMode = result.state.labMode;
        failureText = result.ok ? "" : result.reason;
        checked = labMode;
    }

    ToolTip.visible: failureText.length > 0
    ToolTip.text: failureText
}
