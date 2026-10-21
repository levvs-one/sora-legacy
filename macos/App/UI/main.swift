import AppKit

// Plain explicit entry point: no storyboard, no @NSApplicationMain
// (kept compatible with the 10.13 floor and with a hand-maintained
// Xcode project — project.yml lists these files directly).
let delegate = AppDelegate()
NSApplication.shared.delegate = delegate
NSApplication.shared.run()
