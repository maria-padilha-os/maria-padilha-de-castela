import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../src/registry.js" as Registry
import "../src/authorization.js" as Authorization
import "../src/runner.js" as Runner

/*
 * Root of the private cyber surface.
 *
 * This is a separate panel namespace and tab registry from the normal desktop
 * dashboard. It is mounted only when the host sets buildMode to a private mode
 * and turns on the feature flag. Initializing the surface loads a manifest and
 * refreshes state; it never starts a tool.
 */
Rectangle {
    id: shellRoot
    property string buildMode: "public"
    property bool cyberFrontendFlag: false
    property string manifestJson: ""
    property string manifestUrl: Qt.resolvedUrl("../manifest.json")
    property var probe: null
    property var executor: null
    property var stopExecutor: null
    property var interfaces: []

    property var manifest: null
    property var registry: null
    property var authorization: null
    property var runner: null
    property var surface: null
    property string activeTabId: ""
    property string errorText: ""
    property bool exposed: surface !== null && surface.enabled === true

    color: CyberTheme.surface

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: CyberTheme.space4
        spacing: CyberTheme.space3

        RowLayout {
            Layout.fillWidth: true

            Text {
                Layout.fillWidth: true
                text: shellRoot.manifest ? shellRoot.manifest.title : "Cyber extensions"
                color: CyberTheme.text
                font.family: CyberTheme.fontFamily
                font.bold: true
                font.pixelSize: 20
            }

            Text {
                text: shellRoot.exposed ? shellRoot.surface.namespace : "not exposed"
                color: CyberTheme.textMuted
                font.family: CyberTheme.fontMono
                font.pixelSize: 12
            }
        }

        CyberTabBar {
            Layout.fillWidth: true
            registry: shellRoot.registry
            activeTabId: shellRoot.activeTabId
            onTabActivated: function (tabId) {
                shellRoot.activeTabId = tabId;
            }
        }

        Loader {
            id: panelLoader
            Layout.fillWidth: true
            Layout.fillHeight: true
            sourceComponent: shellRoot.exposed ? shellRoot.componentFor(shellRoot.activeTabId) : null
            onLoaded: {
                if (item) {
                    item.shell = shellRoot;
                }
            }
        }

        Text {
            Layout.fillWidth: true
            visible: shellRoot.errorText.length > 0
            text: shellRoot.errorText
            color: CyberTheme.danger
            font.family: CyberTheme.fontFamily
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
    }

    Component { id: nmapComponent; NmapPanel {} }
    Component { id: setComponent; SetPanel {} }
    Component { id: forensicsComponent; ForensicsPanel {} }
    Component { id: labComponent; LabPanel {} }

    Component.onCompleted: initialize()

    function componentFor(tabId) {
        if (tabId === "nmap") {
            return nmapComponent;
        }
        if (tabId === "set") {
            return setComponent;
        }
        if (tabId === "forensics") {
            return forensicsComponent;
        }
        if (tabId === "lab-vm") {
            return labComponent;
        }
        return null;
    }

    function readManifest() {
        if (manifestJson.length > 0) {
            return manifestJson;
        }
        var request = new XMLHttpRequest();
        request.open("GET", manifestUrl, false);
        request.send(null);
        if (request.status === 0 || (request.status >= 200 && request.status < 300)) {
            return request.responseText;
        }
        throw new Error("could not load manifest: status " + request.status);
    }

    function initialize() {
        var exposure = Registry.resolveSurfaceMode({
            flags: { cyberFrontend: cyberFrontendFlag },
            buildMode: buildMode
        });
        if (!exposure.enabled) {
            errorText = "Private cyber surface is disabled: " + exposure.reason;
            return;
        }

        try {
            manifest = Registry.loadManifest(readManifest());
            registry = new Registry.TabRegistry(manifest);
            authorization = new Authorization.AuthorizationState(manifest.authorization);
            runner = new Runner.ToolRunner({
                registry: registry,
                authorization: authorization,
                probe: probe,
                execute: executor,
                stop: stopExecutor
            });
            surface = {
                enabled: true,
                namespace: manifest.namespace,
                panelNamespace: manifest.panelNamespace,
                manifest: manifest,
                registry: registry,
                authorization: authorization,
                runner: runner
            };
            var visibleTabs = registry.list();
            activeTabId = visibleTabs.length > 0 ? visibleTabs[0].id : "";
            errorText = "";
        } catch (error) {
            errorText = "Cyber surface failed to load: " + error.message;
        }
    }
}
