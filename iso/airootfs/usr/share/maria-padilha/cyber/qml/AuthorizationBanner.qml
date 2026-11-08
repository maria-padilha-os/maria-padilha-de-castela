import QtQuick 2.15
import QtQuick.Layouts 1.15

/*
 * Shared authorization banner. Every cyber panel renders it, including tabs
 * whose tool is missing. It is not a one-time click-through and cannot be
 * dismissed.
 */
Rectangle {
    id: banner
    property string message: "AUTHORIZED USE ONLY. Use only on systems you own or for which you hold explicit written permission."
    property color textColor: CyberTheme.text
    property color borderColor: CyberTheme.danger
    property color fillColor: CyberTheme.surfaceRaised

    implicitHeight: bannerText.implicitHeight + CyberTheme.space3 * 2
    color: fillColor
    border.width: CyberTheme.borderWidth * 2
    border.color: borderColor
    radius: CyberTheme.radius

    Text {
        id: bannerText
        anchors.fill: parent
        anchors.margins: CyberTheme.space3
        text: banner.message
        color: banner.textColor
        font.family: CyberTheme.fontFamily
        font.bold: true
        wrapMode: Text.WordWrap
        Accessible.role: Accessible.StaticText
        Accessible.name: "Authorized use only"
    }
}
