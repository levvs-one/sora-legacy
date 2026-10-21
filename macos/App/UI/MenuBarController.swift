import AppKit

/// The menu-bar face of the client: a text status item (SF Symbols
/// do not exist on the 10.13 floor, so the item is plain text — state
/// in words) with status, open and quit.
final class MenuBarController: NSObject {
    private let item: NSStatusItem
    private let helper: HelperClient
    private let statusItem = NSMenuItem(title: "Status: …", action: nil, keyEquivalent: "")
    private var timer: Timer?

    init(helper: HelperClient, onOpenWindow: @escaping () -> Void, onQuit: @escaping () -> Void) {
        self.helper = helper
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()
        item.button?.title = "Sora ⭘"
        let menu = NSMenu()
        menu.addItem(statusItem)
        menu.addItem(.separator())
        let open = NSMenuItem(title: "Open Sora Legacy", action: #selector(openTapped), keyEquivalent: "")
        open.target = self
        menu.addItem(open)
        let quit = NSMenuItem(title: "Quit", action: #selector(quitTapped), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        item.menu = menu
        self.onOpenWindow = onOpenWindow
        self.onQuit = onQuit
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
    }

    private var onOpenWindow: (() -> Void)?
    private var onQuit: (() -> Void)?

    @objc private func openTapped() { onOpenWindow?() }
    @objc private func quitTapped() { onQuit?() }

    private func refresh() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            let result = self.helper.status()
            DispatchQueue.main.async {
                switch result {
                case .success(let status):
                    self.statusItem.title = "Status: \(status.state.lowercased())"
                    self.item.button?.title = status.isConnected ? "Sora ●" : "Sora ⭘"
                case .failure:
                    self.statusItem.title = "Status: service unreachable"
                    self.item.button?.title = "Sora ?"
                }
            }
        }
    }
}
