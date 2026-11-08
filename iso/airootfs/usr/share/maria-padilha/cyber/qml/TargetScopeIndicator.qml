import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * Target-scope entry and always-visible scope indicator. The scope is local
 * text only; nothing here discovers a network, enumerates hosts, or populates a
 * target list.
 */
ColumnLayout {
    id: scopeControl
    property var authorization: null
    property string scope: ""
    property string failureText: ""
    spacing: CyberTheme.space1

    Text {
        text: authorization ? authorization.targetScopeLabel : "Target scope (owned or explicitly authorized only)"
        color: CyberTheme.textMuted
        font.family: CyberTheme.fontFamily
        font.pixelSize: 12
        font.bold: true
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        TextField {
            id: scopeField
            Layout.fillWidth: true
            placeholderText: "e.g. 192.0.2.0/24 or lab-vm.example"
            text: scopeControl.scope
            selectByMouse: true
            color: CyberTheme.fieldText
            font.family: CyberTheme.fontMono
            palette.base: CyberTheme.field
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onEditingFinished: scopeControl.applyScope()

            Keys.onReturnPressed: scopeControl.applyScope()
            Keys.onEnterPressed: scopeControl.applyScope()
        }

        Button {
            text: "Set scope"
            font.family: CyberTheme.fontFamily
            onClicked: scopeControl.applyScope()
        }
    }

    Text {
        Layout.fillWidth: true
        text: scopeControl.scope.length > 0
            ? "SCOPE: " + scopeControl.scope
            : "NO TARGET SCOPE - tools cannot start"
        color: scopeControl.scope.length > 0 ? CyberTheme.text : CyberTheme.danger
        font.family: CyberTheme.fontMono
        font.pixelSize: 12
        wrapMode: Text.WrapAnywhere
        Accessible.role: Accessible.StaticText
        Accessible.name: text
    }

    Text {
        visible: scopeControl.failureText.length > 0
        Layout.fillWidth: true
        text: scopeControl.failureText
        color: CyberTheme.danger
        font.family: CyberTheme.fontFamily
        font.pixelSize: 12
        wrapMode: Text.WordWrap
    }

    function refresh() {
        if (!authorization) {
            scope = "";
            return;
        }
        scope = authorization.snapshot().scope;
    }

    function applyScope() {
        if (!authorization) {
            return;
        }
        var result = authorization.setTargetScope(scopeField.text);
        scope = result.state.scope;
        failureText = result.ok ? "" : result.reason;
        scopeField.text = scope;
    }
}
