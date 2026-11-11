import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../src/forensics.js" as Forensics

/*
 * Wireshark / forensics tab.
 *
 * The panel can start an explicit local tshark capture on one validated
 * interface, stop the capture that the host executor started, and open an
 * operator-supplied pcap read-only with tshark for a redacted summary. It never
 * captures on load, never injects or transmits a packet, and never uploads a
 * capture. Payload and credential fields are redacted from the summary.
 *
 * Shared controls rendered by ToolPanelFrame: AuthorizationBanner,
 * LabModeSwitch, TargetScopeIndicator, and StopClearAction (Stop / Clear).
 */
ToolPanelFrame {
    id: forensicsFrame
    property var shell: null
    property bool missing: false
    property var fallbackData: null
    property var interfaceModel: []
    property var filterModel: Forensics.listCaptureFilters()

    property string interfaceName: ""
    property string captureFilterId: Forensics.DEFAULT_CAPTURE_FILTER
    property string capturePath: ""
    property bool captureConfirmed: false
    property bool captureReady: false
    property bool captureActive: false
    property string captureValidation: ""
    property string captureStatus: ""

    property string openPath: ""
    property bool openConfirmed: false
    property bool openReady: false
    property string openValidation: ""
    property string openStatus: ""
    property string openResult: ""

    property string sensitiveWarning: Forensics.CAPABILITIES.required.length > 0
        ? "Captures can contain credentials, tokens, cookies, private keys, and personal data. Payloads and sensitive fields are redacted from the summary, but the raw capture remains sensitive. Never upload or auto-transmit a capture."
        : ""

    authorization: shell ? shell.authorization : null
    title: "Wireshark / Forensics"
    description: "Explicit local capture and read-only pcap inspection with tshark. No capture starts automatically, no packet is injected, and no capture is uploaded."
    toolName: "tshark"

    panelContent: ColumnLayout {
        Layout.fillWidth: true
        spacing: CyberTheme.space2

        Text {
            Layout.fillWidth: true
            text: forensicsFrame.sensitiveWarning
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            font.bold: true
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Text {
            Layout.fillWidth: true
            text: "Live capture needs CAP_NET_RAW/CAP_NET_ADMIN on the capture helper, or a distribution capture group. This panel never uses root by default and never grants capabilities. Opening a pcap needs no special capability."
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
        }

        ToolUnavailable {
            Layout.fillWidth: true
            visible: forensicsFrame.missing
            fallbackData: forensicsFrame.fallbackData
            toolName: "tshark"
        }

        Text {
            Layout.fillWidth: true
            text: "Live capture (explicit)"
            color: CyberTheme.text
            font.family: CyberTheme.fontFamily
            font.bold: true
            font.pixelSize: 14
        }

        Text {
            Layout.fillWidth: true
            text: "Interface"
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            font.bold: true
        }

        ComboBox {
            id: interfaceBox
            Layout.fillWidth: true
            editable: true
            model: forensicsFrame.interfaceModel
            textRole: "name"
            currentIndex: -1
            editText: forensicsFrame.interfaceName
            font.family: CyberTheme.fontMono
            palette.button: CyberTheme.field
            palette.buttonText: CyberTheme.fieldText
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onEditTextChanged: {
                if (activeFocus && editText !== forensicsFrame.interfaceName) {
                    forensicsFrame.interfaceName = editText;
                    forensicsFrame.revalidateCapture();
                }
            }
            onActivated: {
                if (index >= 0 && index < forensicsFrame.interfaceModel.length) {
                    forensicsFrame.interfaceName = forensicsFrame.interfaceModel[index].name;
                    forensicsFrame.revalidateCapture();
                }
            }
        }

        TextField {
            id: capturePathField
            Layout.fillWidth: true
            placeholderText: "new local capture path (e.g. /home/operator/captures/lab.pcapng)"
            selectByMouse: true
            color: CyberTheme.fieldText
            font.family: CyberTheme.fontMono
            palette.base: CyberTheme.field
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onTextChanged: {
                forensicsFrame.capturePath = text;
                forensicsFrame.revalidateCapture();
            }
        }

        ComboBox {
            id: filterBox
            Layout.fillWidth: true
            model: forensicsFrame.filterModel
            textRole: "label"
            currentIndex: forensicsFrame.filterIndex(forensicsFrame.captureFilterId)
            font.family: CyberTheme.fontFamily
            onActivated: {
                if (index >= 0 && index < forensicsFrame.filterModel.length) {
                    forensicsFrame.captureFilterId = forensicsFrame.filterModel[index].id;
                    forensicsFrame.revalidateCapture();
                }
            }
        }

        CheckBox {
            id: captureConfirmBox
            Layout.fillWidth: true
            visible: !forensicsFrame.missing
            checked: forensicsFrame.captureConfirmed
            text: forensicsFrame.captureAuthorizationLabel()
            font.family: CyberTheme.fontFamily
            font.bold: true
            palette.windowText: CyberTheme.text
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onToggled: {
                forensicsFrame.captureConfirmed = checked;
                forensicsFrame.revalidateCapture();
            }
        }

        Text {
            Layout.fillWidth: true
            visible: forensicsFrame.captureValidation.length > 0
            text: forensicsFrame.captureValidation
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: CyberTheme.space2

            Button {
                Layout.fillWidth: true
                visible: !forensicsFrame.missing
                enabled: forensicsFrame.captureReady && !forensicsFrame.captureActive &&
                    forensicsFrame.shell !== null && forensicsFrame.shell.runner !== null
                text: "Start capture (explicit)"
                font.family: CyberTheme.fontFamily
                palette.button: CyberTheme.accent
                palette.buttonText: CyberTheme.onAccent
                onClicked: forensicsFrame.startCapture()
            }

            Button {
                Layout.fillWidth: true
                visible: !forensicsFrame.missing
                enabled: forensicsFrame.captureActive && forensicsFrame.shell !== null
                text: "Stop capture"
                font.family: CyberTheme.fontFamily
                palette.button: CyberTheme.danger
                palette.buttonText: CyberTheme.onAccent
                onClicked: forensicsFrame.stopCapture()
            }
        }

        Text {
            Layout.fillWidth: true
            visible: forensicsFrame.captureStatus.length > 0
            text: forensicsFrame.captureStatus
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontMono
            font.pixelSize: 12
            wrapMode: Text.WrapAnywhere
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Text {
            Layout.fillWidth: true
            text: "Inspect an existing capture (read-only)"
            color: CyberTheme.text
            font.family: CyberTheme.fontFamily
            font.bold: true
            font.pixelSize: 14
        }

        TextField {
            id: openPathField
            Layout.fillWidth: true
            placeholderText: "local pcap or pcapng path (operator supplied)"
            selectByMouse: true
            color: CyberTheme.fieldText
            font.family: CyberTheme.fontMono
            palette.base: CyberTheme.field
            palette.text: CyberTheme.fieldText
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onTextChanged: {
                forensicsFrame.openPath = text;
                forensicsFrame.revalidateOpen();
            }
        }

        CheckBox {
            id: openConfirmBox
            Layout.fillWidth: true
            visible: !forensicsFrame.missing
            checked: forensicsFrame.openConfirmed
            text: forensicsFrame.openAuthorizationLabel()
            font.family: CyberTheme.fontFamily
            font.bold: true
            palette.windowText: CyberTheme.text
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onToggled: {
                forensicsFrame.openConfirmed = checked;
                forensicsFrame.revalidateOpen();
            }
        }

        Text {
            Layout.fillWidth: true
            visible: forensicsFrame.openValidation.length > 0
            text: forensicsFrame.openValidation
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Button {
            Layout.fillWidth: true
            visible: !forensicsFrame.missing
            enabled: forensicsFrame.openReady && forensicsFrame.shell !== null &&
                forensicsFrame.shell.runner !== null
            text: "Open and parse pcap (explicit)"
            font.family: CyberTheme.fontFamily
            palette.button: CyberTheme.accent
            palette.buttonText: CyberTheme.onAccent
            onClicked: forensicsFrame.openCapture()
        }

        Text {
            Layout.fillWidth: true
            visible: forensicsFrame.openStatus.length > 0
            text: forensicsFrame.openStatus
            color: CyberTheme.textMuted
            font.family: CyberTheme.fontFamily
            font.pixelSize: 12
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Text {
            Layout.fillWidth: true
            visible: forensicsFrame.openResult.length > 0
            text: forensicsFrame.openResult
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
        revalidateCapture();
        revalidateOpen();
    }

    function authorizationSnapshot() {
        if (shell && shell.authorization) {
            return shell.authorization.snapshot();
        }
        return null;
    }

    function captureAuthorizationLabel() {
        var snapshot = authorizationSnapshot();
        if (snapshot && snapshot.captureConfirmationLabel) {
            return snapshot.captureConfirmationLabel;
        }
        return "I confirm this capture is limited to traffic, systems, and media I own or am explicitly authorized in writing to examine.";
    }

    function openAuthorizationLabel() {
        var snapshot = authorizationSnapshot();
        if (snapshot && snapshot.openConfirmationLabel) {
            return snapshot.openConfirmationLabel;
        }
        return "I confirm this capture file is local, I am authorized to examine it, and it will not be uploaded or transmitted.";
    }

    function filterIndex(id) {
        var index;
        for (index = 0; index < filterModel.length; index += 1) {
            if (filterModel[index].id === id) {
                return index;
            }
        }
        return 0;
    }

    function refreshInterfaces() {
        var supplied = shell && shell.interfaces ? shell.interfaces : [];
        var result = Forensics.normalizeInterfaces(supplied);
        interfaceModel = result.interfaces;
        if (interfaceName.length === 0 && interfaceModel.length > 0) {
            interfaceName = interfaceModel[0].name;
        }
    }

    function refreshAvailability() {
        if (!shell || !shell.runner) {
            missing = true;
            fallbackData = null;
            captureStatus = "No host tool probe is configured. tshark was not detected and no command was run.";
            revalidateCapture();
            revalidateOpen();
            return;
        }
        var prepared = shell.runner.prepare("forensics");
        missing = prepared.status === "missing-tool";
        fallbackData = prepared.fallback || null;
        refreshInterfaces();
        var snapshot = authorizationSnapshot();
        sensitiveWarning = (snapshot && snapshot.sensitivePayloadWarning) ||
            sensitiveWarning;
        revalidateCapture();
        revalidateOpen();
    }

    function buildCapture() {
        return Forensics.prepareCapture({
            confirmed: captureConfirmed,
            authorizedLab: captureConfirmed,
            authorization: authorizationSnapshot(),
            interface: interfaceName,
            outputPath: capturePath,
            filter: captureFilterId
        });
    }

    function revalidateCapture() {
        if (!shell || !shell.runner) {
            captureReady = false;
            captureValidation = "No host executor is configured; nothing will run.";
            return;
        }
        if (missing) {
            captureReady = false;
            captureValidation = fallbackData
                ? fallbackData.reason
                : "tshark is not installed; no capture will run.";
            return;
        }
        var plan = buildCapture();
        captureReady = plan.ok === true;
        captureValidation = plan.ok ? "" : plan.reason;
    }

    function startCapture() {
        if (!captureReady || !shell || !shell.runner) {
            return;
        }
        var plan = buildCapture();
        if (!plan.ok) {
            captureValidation = plan.reason;
            captureReady = false;
            return;
        }
        var result = shell.runner.start("forensics", {
            confirmed: true,
            args: plan.args,
            metadata: {
                action: "capture-start",
                interface: plan.interface,
                outputPath: plan.outputPath,
                captureFilter: plan.captureFilter,
                stopSignal: plan.stopSignal,
                readOnly: false,
                uploads: false,
                packetInjection: false
            }
        });
        if (result.status !== "started") {
            captureStatus = result.status + (result.reason ? ": " + result.reason : "");
            return;
        }
        captureActive = true;
        captureStatus = "Capture started on " + plan.interface +
            " by explicit operator action; stop it when finished. No capture data is uploaded.";
        revalidateCapture();
    }

    function stopCapture() {
        if (!shell || !shell.runner) {
            captureActive = false;
            captureStatus = "No host runner is configured; nothing was running.";
            return;
        }
        var result = shell.runner.stop();
        captureActive = false;
        captureStatus = result.reason +
            (result.stop && result.stop.message ? ": " + result.stop.message : "") +
            ". The host executor sends SIGINT; no capture data is uploaded.";
        revalidateCapture();
    }

    function buildOpen() {
        return Forensics.prepareOpen({
            confirmed: openConfirmed,
            authorizedLab: openConfirmed,
            authorization: authorizationSnapshot(),
            capturePath: openPath
        });
    }

    function revalidateOpen() {
        if (!shell || !shell.runner) {
            openReady = false;
            openValidation = "No host executor is configured; nothing will run.";
            return;
        }
        if (missing) {
            openReady = false;
            openValidation = fallbackData
                ? fallbackData.reason
                : "tshark is not installed; pcap parsing is unavailable.";
            return;
        }
        var plan = buildOpen();
        openReady = plan.ok === true;
        openValidation = plan.ok ? "" : plan.reason;
    }

    function openCapture() {
        if (!openReady || !shell || !shell.runner) {
            return;
        }
        var plan = buildOpen();
        if (!plan.ok) {
            openValidation = plan.reason;
            openReady = false;
            return;
        }
        var result = shell.runner.start("forensics", {
            confirmed: true,
            args: plan.args,
            metadata: {
                action: "pcap-open",
                capturePath: plan.capturePath,
                readOnly: true,
                uploads: false,
                packetInjection: false
            }
        });
        if (result.status !== "started") {
            openStatus = result.status + (result.reason ? ": " + result.reason : "");
            return;
        }
        finishOpen(result.result, plan.capturePath);
    }

    function finishOpen(execution, capturePath) {
        if (execution && typeof execution.then === "function") {
            openStatus = "Reading the local capture; no upload is performed.";
            execution.then(function (value) {
                finishOpen(value, capturePath);
            }, function (error) {
                openResult = Forensics.formatCaptureSummary(
                    Forensics.interpretCaptureResult({
                        status: "failed",
                        message: error && error.message ? error.message : String(error)
                    }, {capturePath: capturePath})
                );
                openStatus = "Capture read failed.";
            });
            return;
        }
        var parsed = Forensics.interpretCaptureResult(execution, {
            capturePath: capturePath
        });
        openResult = Forensics.formatCaptureSummary(parsed);
        openStatus = parsed.ok
            ? "Capture parsed locally. Sensitive payloads are redacted; nothing was uploaded."
            : "Capture read failed.";
    }
}
