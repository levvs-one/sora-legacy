import AppKit

/// App lifecycle: menu-bar item + main window, crash-guard recovery
/// for the system proxy at launch, and an honest shutdown (restore
/// the proxy we set, disconnect the session we started) at quit.
final class AppDelegate: NSObject, NSApplicationDelegate {
    let settings = Settings()
    let proxy = SystemProxyController()
    let helper: HelperClient
    private var menuBar: MenuBarController?
    private var mainWindow: MainWindowController?

    override init() {
        let override = Settings().helperPathOverride
        self.helper = HelperClient(helperPath: override)
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        // Crash guard first: if a previous run died owning the system
        // proxy, give the user's settings back before anything else.
        if proxy.recoverLeftoverIfNeeded() {
            NSLog("SoraLegacy: restored system proxy left over from a previous run")
        }
        let window = MainWindowController(helper: helper, settings: settings, proxy: proxy)
        mainWindow = window
        menuBar = MenuBarController(helper: helper, onOpenWindow: { window.show() },
                                    onQuit: { NSApp.terminate(nil) })
        window.show()
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Synchronous, best effort, bounded by the helper's own quick
        // daemon round-trip: restore the proxy first (never leave it
        // pointing at a proxy that is about to stop), then disconnect.
        if proxy.hasLeftoverFlag {
            _ = proxy.restore()
            _ = helper.disconnect()
        }
        return .terminateNow
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Menu-bar app: closing the window must not quit.
        return false
    }
}
