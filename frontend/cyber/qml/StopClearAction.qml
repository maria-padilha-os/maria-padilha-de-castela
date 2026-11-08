import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * Stop and Clear are present on every cyber tool panel. Stop cancels the
 * current operation; Clear removes the target scope and any queued targets.
 * Neither action launches anything.
 */
RowLayout {
    id: stopClear
    property var authorization: null
    property bool running: false
    property bool hasScope: false
    spacing: CyberTheme.space2

    Button {
        text: stopClear.authorization ? stopClear.authorization.stopLabel : "Stop"
        enabled: stopClear.running
        font.family: CyberTheme.fontFamily
        palette.button: CyberTheme.danger
        palette.buttonText: CyberTheme.onAccent
        onClicked: {
            if (stopClear.authorization) {
                stopClear.authorization.stop();
                stopClear.refresh();
            }
        }
    }

    Button {
        text: stopClear.authorization ? stopClear.authorization.clearLabel : "Clear"
        enabled: stopClear.hasScope
        font.family: CyberTheme.fontFamily
        onClicked: {
            if (stopClear.authorization) {
                stopClear.authorization.clear();
                stopClear.refresh();
            }
        }
    }

    function refresh() {
        if (!authorization) {
            running = false;
            hasScope = false;
            return;
        }
        var snapshot = authorization.snapshot();
        running = snapshot.running;
        hasScope = snapshot.scope.length > 0 || snapshot.queuedTargets.length > 0;
    }
}
