import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../src/nmap.js" as Nmap

/*
 * Nmap tab. The operator chooses a canonical target, a documented profile, and
 * a small allowlisted option set. The shared frame supplies the authorization
 * banner, lab-mode switch, target scope, and Stop/Clear. This panel adds the
 * per-scan authorized-lab confirmation and calls Nmap only from an explicit
 * click, after the target has passed local validation.
 *
 * Nothing is scanned on load, on tab activation, or on a timer. The host adapter
 * receives an argv array and must execute it without a shell.
 */
ToolPanelFrame {
    id: nmapFrame
    property var shell: null
    property bool missing: false
    property var fallbackData: null

    property string target: ""
    property string profileId: Nmap.DEFAULT_PROFILE
    property var selectedOptions: ({})
    property bool authorizedLabConfirmed: false
    property bool readyToStart: false
    property string validationText: ""
    property string resultText: ""
    property var profileModel: Nmap.listProfiles()
    property var optionModel: []

    authorization: shell ? shell.authorization : null
    title: "Nmap"
    description: "Explicit, operator-started network mapping for an authorized lab/private target. No default scan or target discovery runs."
    toolName: "nmap"

    panelContent: ColumnLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        Text {
            Layout.fillWidth: true
            text: "Targets must be private, loopback, documentation/lab addresses, or names under an approved lab suffix. Public ranges are refused."
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }

        TextField {
            id: targetField
            Layout.fillWidth: true
            placeholderText: "target (e.g. 192.168.1.10 or lab-vm.example)"
            selectByMouse: true
            color: CyberTheme.fieldText
            font.family: CyberTheme.fontMono
            palette.base: CyberTheme.field
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onTextChanged: {
                nmapFrame.target = text;
                nmapFrame.revalidate();
            }
        }

        Text {
            text: "Profile"
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            font.bold: true
        }

        ComboBox {
            id: profileBox
            Layout.fillWidth: true
            model: nmapFrame.profileModel
            textRole: "label"
            currentIndex: nmapFrame.profileIndex(nmapFrame.profileId)
            font.family: CyberTheme.fontFamily
            onActivated: {
                nmapFrame.profileId = nmapFrame.profileModel[index].id;
                nmapFrame.refreshOptions();
            }
        }

        Text {
            Layout.fillWidth: true
            text: nmapFrame.currentProfileDescription()
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            wrapMode: Text.WordWrap
        }

        Repeater {
            model: nmapFrame.optionModel

            delegate: CheckBox {
                Layout.fillWidth: true
                text: modelData.label
                checked: nmapFrame.selectedOptions[modelData.id] === true
                font.family: CyberTheme.fontFamily
                palette.windowText: CyberTheme.text
                palette.highlight: CyberTheme.accent
                palette.highlightedText: CyberTheme.onAccent
                onToggled: nmapFrame.setOption(modelData.id, checked)
            }
        }

        CheckBox {
            id: authorizedLabBox
            Layout.fillWidth: true
            checked: nmapFrame.authorizedLabConfirmed
            text: nmapFrame.authorizationLabel()
            font.family: CyberTheme.fontFamily
            font.bold: true
            palette.windowText: CyberTheme.text
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onToggled: {
                nmapFrame.authorizedLabConfirmed = checked;
                nmapFrame.revalidate();
            }
        }

        Text {
            Layout.fillWidth: true
            visible: nmapFrame.validationText.length > 0
            text: nmapFrame.validationText
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Text {
            Layout.fillWidth: true
            text: nmapFrame.target.length > 0
                ? "TARGET: " + nmapFrame.target
                : "NO TARGET - Nmap cannot start"
            color: nmapFrame.target.length > 0 ? CyberTheme.text : CyberTheme.danger
            font.family: CyberTheme.fontMono
            font.pixelSize: 12
            wrapMode: Text.WrapAnywhere
        }

        ToolUnavailable {
            Layout.fillWidth: true
            visible: nmapFrame.missing
            fallbackData: nmapFrame.fallbackData
            toolName: "nmap"
        }

        Button {
            Layout.fillWidth: true
            visible: !nmapFrame.missing
            enabled: nmapFrame.readyToStart && nmapFrame.shell !== null &&
                nmapFrame.shell.runner !== null
            text: "Start Nmap (explicit)"
            font.family: CyberTheme.fontFamily
            palette.button: CyberTheme.accent
            palette.buttonText: CyberTheme.onAccent
            onClicked: nmapFrame.startNow()
        }

        Text {
            Layout.fillWidth: true
            visible: nmapFrame.resultText.length > 0
            text: nmapFrame.resultText
            color: CyberTheme.text
            font.family: CyberTheme.fontMono
            font.pixelSize: 12
            wrapMode: Text.WrapAnywhere
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
    }

    Component.onCompleted: {
        refreshAvailability();
        refreshOptions();
        revalidate();
    }

    function currentProfile() {
        return Nmap.getProfile(profileId);
    }

    function authorizationLabel() {
        if (shell && shell.authorization) {
            var snapshot = shell.authorization.snapshot();
            if (snapshot.labConfirmationLabel) {
                return snapshot.labConfirmationLabel;
            }
        }
        return "I confirm this Nmap scan targets an authorized lab or private network.";
    }

    function currentProfileDescription() {
        var profile = currentProfile();
        return profile ? profile.description : "";
    }

    function profileIndex(id) {
        var index;
        for (index = 0; index < profileModel.length; index += 1) {
            if (profileModel[index].id === id) {
                return index;
            }
        }
        return 0;
    }

    function refreshOptions() {
        var available = Nmap.listOptions(profileId);
        var ids = available.map(function (option) { return option.id; });
        var next = {};
        Object.keys(selectedOptions).forEach(function (id) {
            if (ids.indexOf(id) !== -1 && selectedOptions[id] === true) {
                next[id] = true;
            }
        });
        selectedOptions = next;
        optionModel = available;
        revalidate();
    }

    function setOption(id, enabled) {
        var next = {};
        Object.keys(selectedOptions).forEach(function (key) {
            if (selectedOptions[key] === true) {
                next[key] = true;
            }
        });
        if (enabled === true) {
            next[id] = true;
        } else {
            delete next[id];
        }
        selectedOptions = next;
        revalidate();
    }

    function buildRequest() {
        var scope = "";
        if (shell && shell.authorization) {
            scope = shell.authorization.snapshot().scope;
        }
        return Nmap.prepareScan({
            target: target,
            profile: profileId,
            options: selectedOptions,
            scope: scope,
            authorizedLab: authorizedLabConfirmed
        });
    }

    function revalidate() {
        var request = buildRequest();
        readyToStart = request.ok && !missing && shell !== null;
        validationText = request.ok ? "" : request.reason;
    }

    function startNow() {
        if (!readyToStart || !shell || !shell.runner) {
            return;
        }
        var request = buildRequest();
        if (!request.ok) {
            validationText = request.reason;
            readyToStart = false;
            return;
        }
        var result = shell.runner.start("nmap", {
            confirmed: true,
            args: request.args,
            target: request.target,
            targets: request.targets,
            profile: request.profile,
            timeoutMs: request.timeoutMs
        });
        if (result.status !== "started") {
            resultText = result.status + (result.reason ? ": " + result.reason : "");
            return;
        }
        var parsed = Nmap.interpretScanResult(result.result, {
            timeoutMs: request.timeoutMs
        });
        resultText = Nmap.formatScanResult(parsed);
        revalidate();
    }

    function refreshAvailability() {
        if (!shell || !shell.runner) {
            return;
        }
        var prepared = shell.runner.prepare("nmap");
        missing = prepared.status === "missing-tool";
        fallbackData = prepared.fallback || null;
        revalidate();
    }
}
