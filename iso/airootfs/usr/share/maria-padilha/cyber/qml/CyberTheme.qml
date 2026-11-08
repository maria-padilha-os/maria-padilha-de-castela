pragma Singleton
import QtQuick 2.15

/*
 * Semantic theme for the private cyber surface.
 *
 * The defaults come from the host's SystemPalette; the desktop shell may
 * override the token* properties. There are no palette literals in this file or
 * in any cyber panel. Light, dark, and high-contrast host themes therefore keep
 * working.
 */
Item {
    id: theme
    visible: false

    SystemPalette {
        id: nativePalette
        colorGroup: SystemPalette.Active
    }

    property color tokenSurface: nativePalette.window
    property color tokenSurfaceRaised: nativePalette.button
    property color tokenText: nativePalette.windowText
    property color tokenTextMuted: nativePalette.dark
    property color tokenAccent: nativePalette.highlight
    property color tokenOnAccent: nativePalette.highlightedText
    property color tokenDanger: nativePalette.brightText
    property color tokenBorder: nativePalette.mid
    property color tokenFocus: nativePalette.highlight
    property color tokenField: nativePalette.base
    property color tokenFieldText: nativePalette.text

    property int space1: 4
    property int space2: 8
    property int space3: 12
    property int space4: 16
    property int space6: 24
    property int radius: 8
    property int borderWidth: 1
    property string fontFamily: Qt.application.font.family
    property string fontMono: "monospace"

    readonly property color surface: tokenSurface
    readonly property color surfaceRaised: tokenSurfaceRaised
    readonly property color text: tokenText
    readonly property color textMuted: tokenTextMuted
    readonly property color accent: tokenAccent
    readonly property color onAccent: tokenOnAccent
    readonly property color danger: tokenDanger
    readonly property color border: tokenBorder
    readonly property color focus: tokenFocus
    readonly property color field: tokenField
    readonly property color fieldText: tokenFieldText
}
