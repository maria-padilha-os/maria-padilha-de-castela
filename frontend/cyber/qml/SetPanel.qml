import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../src/set.js" as Set

/*
 * SET launcher/status panel.
 *
 * SET is a dual-use Social-Engineer Toolkit. This panel detects an
 * operator-installed SET through the host probe, explains the authorized-lab
 * boundary, and offers no default action. The launch control stays disabled
 * until the shared authorization state is satisfied and the operator explicitly
 * ticks the confirmation. The launch carries no arguments, target, template,
 * page, credential harvester, or payload; this frontend generates no attack
 * content. Nothing starts on load, on tab activation, or on a timer.
 *
 * Shared controls rendered by ToolPanelFrame: AuthorizationBanner,
 * LabModeSwitch, TargetScopeIndicator, and StopClearAction (Stop / Clear).
 */
ToolPanelFrame {
    id: setFrame
    property var shell: null
    property bool missing: false
    property var fallbackData: null
    property bool launchConfirmed: false
    property bool readyToLaunch: false
    property string validationText: ""
    property string statusText: ""
    property string warningText: Set.DUAL_USE_WARNING
    property string resultText: ""

    authorization: shell ? shell.authorization : null
    title: "SET"
    description: "Detects an operator-installed Social-Engineer Toolkit and launches it only after an explicit authorized-lab confirmation. No target, template, phishing page, credential harvester, or payload is bundled or generated."
    toolName: "SET"

    panelContent: ColumnLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        Text {
            Layout.fillWidth: true
            text: setFrame.warningText
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            font.bold: true
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Text {
            Layout.fillWidth: true
            text: setFrame.statusText
            color: CyberTheme.text
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Text {
            Layout.fillWidth: true
            text: "This panel asks for no target, template, landing page, credential harvester, or payload. SET is launched with no arguments; any later action inside the tool remains the operator's responsibility and must stay inside the authorized scope."
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }

        ToolUnavailable {
            Layout.fillWidth: true
            visible: setFrame.missing
            fallbackData: setFrame.fallbackData
            toolName: "SET"
        }

        CheckBox {
            id: launchConfirmBox
            Layout.fillWidth: true
            visible: !setFrame.missing
            checked: setFrame.launchConfirmed
            text: setFrame.authorizationLabel()
            font.family: CyberTheme.fontFamily
            font.bold: true
            palette.windowText: CyberTheme.text
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onToggled: {
                setFrame.launchConfirmed = checked;
                setFrame.revalidate();
            }
        }

        Text {
            Layout.fillWidth: true
            visible: setFrame.validationText.length > 0
            text: setFrame.validationText
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Button {
            Layout.fillWidth: true
            visible: !setFrame.missing
            enabled: setFrame.readyToLaunch && setFrame.shell !== null &&
                setFrame.shell.runner !== null
            text: "Launch SET (explicit)"
            font.family: CyberTheme.fontFamily
            palette.button: CyberTheme.accent
            palette.buttonText: CyberTheme.onAccent
            onClicked: setFrame.startNow()
        }

        Text {
            Layout.fillWidth: true
            visible: setFrame.resultText.length > 0
            text: setFrame.resultText
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontMono
            font.pixelSize: 12
            wrapMode: Text.WrapAnywhere
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
    }

    Component.onCompleted: {
        refreshAvailability();
        revalidate();
    }

    function authorizationSnapshot() {
        if (shell && shell.authorization) {
            return shell.authorization.snapshot();
        }
        return null;
    }

    function authorizationLabel() {
        var snapshot = authorizationSnapshot();
        if (snapshot && snapshot.setConfirmationLabel) {
            return snapshot.setConfirmationLabel;
        }
        return "I confirm this SET launch is limited to systems I own or am explicitly authorized in writing to test.";
    }

    function refreshAvailability() {
        if (!shell || !shell.runner || !shell.registry) {
            missing = true;
            fallbackData = null;
            statusText = "No host tool probe is configured. SET was not detected and no command was run.";
            revalidate();
            return;
        }

        var prepared = shell.runner.prepare("set");
        missing = prepared.status === "missing-tool";
        fallbackData = prepared.fallback || null;

        var tab = shell.registry.get("set");
        var report = Set.statusReport({
            available: tab !== null && tab.toolAvailable === true,
            command: "setoolkit",
            reason: missing
                ? (fallbackData ? fallbackData.reason : prepared.reason)
                : "SET is present"
        });
        statusText = report.title + ": " + report.message;
        warningText = (authorizationSnapshot() &&
            authorizationSnapshot().dualUseWarning) ||
            Set.DUAL_USE_WARNING;
        revalidate();
    }

    function revalidate() {
        if (!shell || !shell.runner) {
            readyToLaunch = false;
            validationText = "No host executor is configured; nothing will run.";
            return;
        }
        if (missing) {
            readyToLaunch = false;
            validationText = fallbackData
                ? fallbackData.reason
                : "SET is not installed; no command will run.";
            return;
        }

        var plan = Set.prepareLaunch({
            confirmed: launchConfirmed,
            authorization: authorizationSnapshot()
        });
        readyToLaunch = plan.ok === true;
        validationText = plan.ok ? "" : plan.reason;
    }

    function startNow() {
        if (!readyToLaunch || !shell || !shell.runner) {
            return;
        }
        var plan = Set.prepareLaunch({
            confirmed: true,
            authorization: authorizationSnapshot()
        });
        if (!plan.ok) {
            validationText = plan.reason;
            readyToLaunch = false;
            return;
        }

        var result = shell.runner.start("set", {
            confirmed: true,
            args: plan.args,
            metadata: {
                launch: "explicit",
                generatedContent: false
            }
        });
        if (result.status !== "started") {
            resultText = result.status + (result.reason ? ": " + result.reason : "");
            return;
        }
        resultText = "SET launch requested by explicit operator action. No target, template, or payload was supplied.";
        revalidate();
    }
}
