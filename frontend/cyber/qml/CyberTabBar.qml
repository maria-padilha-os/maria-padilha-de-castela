import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

/*
 * Tab registry view. Tabs can be enabled or disabled independently; disabled
 * tabs stay visible but cannot be activated. The bar never starts a tool.
 */
RowLayout {
    id: tabBar
    property var registry: null
    property string activeTabId: ""
    signal tabActivated(string tabId)

    spacing: CyberTheme.space1

    Repeater {
        model: tabBar.registry ? tabBar.registry.list({ includeDisabled: true }) : []

        Button {
            id: tabButton
            readonly property var tabData: modelData
            text: tabData.title
            enabled: tabData.enabled
            checkable: true
            checked: tabData.id === tabBar.activeTabId
            font.family: CyberTheme.fontFamily
            palette.button: CyberTheme.surfaceRaised
            palette.buttonText: CyberTheme.text
            palette.highlight: CyberTheme.accent
            palette.highlightedText: CyberTheme.onAccent
            onClicked: tabBar.tabActivated(tabData.id)
        }
    }
}
