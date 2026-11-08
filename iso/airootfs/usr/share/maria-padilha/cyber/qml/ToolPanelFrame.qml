import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * Common frame for every cyber tab. The authorization banner, lab-mode switch,
 * target-scope indicator, and Stop/Clear actions are rendered here so a panel
 * cannot accidentally omit them. The frame only refreshes state on completion;
 * it never starts a tool.
 */
ColumnLayout {
    id: frame
    property var authorization: null
    property string title: ""
    property string description: ""
    property string toolName: ""
    property alias panelContent: body.data
    spacing: CyberTheme.space3

    AuthorizationBanner {
        Layout.fillWidth: true
        message: authorization ? authorization.banner : ""
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space3

        LabModeSwitch {
            id: labSwitch
            authorization: frame.authorization
        }

        TargetScopeIndicator {
            id: scopeControl
            Layout.fillWidth: true
            authorization: frame.authorization
        }
    }

    StopClearAction {
        id: stopClear
        authorization: frame.authorization
    }

    ColumnLayout {
        id: body
        Layout.fillWidth: true
        spacing: CyberTheme.space2
    }

    Component.onCompleted: refresh()

    function refresh() {
        labSwitch.refresh();
        scopeControl.refresh();
        stopClear.refresh();
    }

    onAuthorizationChanged: refresh()
}
