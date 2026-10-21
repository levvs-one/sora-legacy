import AppKit

/// The one window of the client: status, connect/disconnect, the
/// server list with import, mode and settings, the engine catalog
/// (from the helper's engineinfo — data, not UI hardcode) and the
/// capability matrix rendered verbatim from Capabilities.
///
/// AppKit APIs are 10.13-era throughout: NSStackView, NSTableView,
/// NSPopUpButton. Nothing newer is used in the common path; where a
/// newer nicety would help it is simply absent rather than gated —
/// the floor is the design.
final class MainWindowController: NSObject, NSTableViewDataSource {
    private let helper: HelperClient
    private let settings: Settings
    private let proxy: SystemProxyController

    private let window: NSWindow
    private let statusLabel = NSTextField(labelWithString: "Status: …")
    private let detailLabel = NSTextField(labelWithString: "")
    private let connectButton = NSButton(title: "Connect", target: nil, action: nil)
    private let disconnectButton = NSButton(title: "Disconnect", target: nil, action: nil)
    private let modePopup = NSPopUpButton()
    private let killSwitchBox = NSButton(checkboxWithTitle:
        "Kill switch (on macOS: requested, NOT enforced — the core has no packet filter here)",
        target: nil, action: nil)
    private let table = NSTableView()
    private let importField = NSTextField()
    private let catalogView = NSTextView()
    private let capabilityView = NSTextView()

    private var servers: [ServerInfo] = []
    private var selectedId: String?
    private var timer: Timer?

    init(helper: HelperClient, settings: Settings, proxy: SystemProxyController) {
        self.helper = helper
        self.settings = settings
        self.proxy = proxy
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 560),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Sora Legacy"
        super.init()
        buildContent()
        reloadServers()
        reloadCatalog()
        refreshStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            self?.refreshStatus()
        }
    }

    func show() {
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: Layout (10.13 AppKit, no storyboard)

    private func buildContent() {
        modePopup.addItems(withTitles: ["System proxy", "TUN (service)"])
        modePopup.selectItem(at: settings.mode == "tun" ? 1 : 0)
        killSwitchBox.state = settings.killSwitch ? .on : .off

        connectButton.target = self; connectButton.action = #selector(connectTapped)
        disconnectButton.target = self; disconnectButton.action = #selector(disconnectTapped)
        modePopup.target = self; modePopup.action = #selector(modeChanged)
        killSwitchBox.target = self; killSwitchBox.action = #selector(killSwitchChanged)

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("server"))
        column.title = "Servers"
        column.width = 560
        table.addTableColumn(column)
        table.headerView = nil
        table.dataSource = self
        table.target = self
        table.doubleAction = #selector(serverDoubleClicked)
        let tableScroll = NSScrollView()
        tableScroll.documentView = table
        tableScroll.hasVerticalScroller = true
        tableScroll.borderType = .bezelBorder

        importField.placeholderString = "Paste share links, or a subscription https:// URL, then Import"
        let importButton = NSButton(title: "Import", target: self, action: #selector(importTapped))
        let importRow = NSStackView(views: [importField, importButton])
        importRow.orientation = .horizontal
        importField.widthAnchor.constraint(greaterThanOrEqualToConstant: 420).isActive = true

        catalogView.isEditable = false
        capabilityView.isEditable = false
        let catalogScroll = scroll(catalogView, height: 110)
        let capabilityScroll = scroll(capabilityView, height: 90)

        let buttons = NSStackView(views: [connectButton, disconnectButton])
        buttons.orientation = .horizontal
        let root = NSStackView(views: [
            statusLabel, detailLabel, buttons, modePopup, killSwitchBox,
            NSTextField(labelWithString: "Servers (double-click to select)"),
            tableScroll, importRow,
            NSTextField(labelWithString: "Engines and features — from the core catalog"),
            catalogScroll,
            NSTextField(labelWithString: "What this client can do on this system"),
            capabilityScroll,
        ])
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 8
        root.translatesAutoresizingMaskIntoConstraints = false
        let content = NSView()
        content.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 14),
            root.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -14),
            root.topAnchor.constraint(equalTo: content.topAnchor, constant: 14),
            root.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -14),
            tableScroll.widthAnchor.constraint(equalTo: root.widthAnchor),
        ])
        window.contentView = content

        let sys = Capabilities.runningSystem()
        let rows = Capabilities.matrix(systemVersion: "\(sys.major).\(sys.minor).\(sys.patch)")
        capabilityView.string = rows.map { "• \($0.summary)\n  [\($0.availability)] \($0.cost)" }
            .joined(separator: "\n")
        if !Capabilities.meetsFloor(major: sys.major, minor: sys.minor) {
            detailLabel.stringValue = "This system is below the client's 10.13 floor; expect missing pieces."
        } else if !Capabilities.serviceAvailable(major: sys.major, minor: sys.minor) {
            detailLabel.stringValue = "The core service needs macOS 12 or newer (its measured floor); " +
                "on this system the client can only show status and this explanation."
        }
    }

    private func scroll(_ textView: NSTextView, height: CGFloat) -> NSScrollView {
        let s = NSScrollView()
        s.documentView = textView
        s.hasVerticalScroller = true
        s.borderType = .bezelBorder
        s.heightAnchor.constraint(equalToConstant: height).isActive = true
        return s
    }

    // MARK: Actions

    @objc private func modeChanged() {
        settings.mode = (modePopup.indexOfSelectedItem == 1) ? "tun" : "proxy"
    }

    @objc private func killSwitchChanged() {
        settings.killSwitch = (killSwitchBox.state == .on)
    }

    @objc private func serverDoubleClicked() {
        guard table.clickedRow >= 0, table.clickedRow < servers.count else { return }
        let id = servers[table.clickedRow].id
        run { [weak self] in
            guard let self = self else { return }
            let selected = self.helper.select(id: id)
            DispatchQueue.main.async {
                if case .success = selected {
                    self.selectedId = id
                }
                self.reloadServers()
            }
        }
    }

    @objc private func importTapped() {
        let text = importField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        run { [weak self] in
            guard let self = self else { return }
            let result = text.hasPrefix("https://")
                ? self.helper.importSubscription(url: text)
                : self.helper.importLinks(text)
            DispatchQueue.main.async {
                switch result {
                case .success(let doc):
                    self.servers = doc.servers
                    self.selectedId = doc.selected ?? self.selectedId
                    self.table.reloadData()
                    self.detailLabel.stringValue = "Imported \(doc.servers.count) server(s)."
                case .failure(let f):
                    self.detailLabel.stringValue = "Import failed: \(f)"
                }
            }
        }
    }

    @objc private func connectTapped() {
        guard let id = selectedId ?? servers.first?.id else {
            detailLabel.stringValue = "Import a server first."
            return
        }
        let mode = settings.mode
        let kill = settings.killSwitch
        run { [weak self] in
            guard let self = self else { return }
            switch self.helper.connect(id: id, mode: mode, killSwitch: kill) {
            case .success(let status):
                if mode == "proxy" {
                    self.applySystemProxy(after: status)
                }
                self.refreshStatus()
            case .failure(let f):
                DispatchQueue.main.async {
                    self.detailLabel.stringValue = "Connect failed: \(f)"
                }
            }
        }
    }

    /// Proxy mode, second half: point the system proxy at the
    /// daemon's loopback proxy. Authorization denial is a displayed
    /// state; on failure the session is disconnected again so the
    /// system is never left half-configured by us.
    private func applySystemProxy(after status: HelperStatus) {
        guard let lp = status.localProxy else {
            // GetAbout via the helper's status: the connect answer has
            // no local proxy, so ask for a fresh status.
            if case .success(let fresh) = helper.status(), let lp = fresh.localProxy {
                applySystemProxyPort(lp.port)
            } else {
                DispatchQueue.main.async { [weak self] in
                    self?.detailLabel.stringValue = "Connected, but the core reported no local proxy port; system proxy not changed."
                }
            }
            return
        }
        applySystemProxyPort(lp.port)
    }

    private func applySystemProxyPort(_ port: Int) {
        switch proxy.apply(port: port) {
        case .success:
            DispatchQueue.main.async { [weak self] in
                self?.detailLabel.stringValue = "System proxy now points at 127.0.0.1:\(port)."
            }
        case .failure(.authorizationDenied):
            DispatchQueue.main.async { [weak self] in
                self?.detailLabel.stringValue = "System proxy NOT changed: administrator authorization was denied. Disconnecting."
            }
            _ = helper.disconnect()
        case .failure(let e):
            DispatchQueue.main.async { [weak self] in
                self?.detailLabel.stringValue = "System proxy NOT changed: \(e). Disconnecting."
            }
            _ = helper.disconnect()
        }
    }

    @objc private func disconnectTapped() {
        run { [weak self] in
            guard let self = self else { return }
            // Restore first (contract (b)): never leave the proxy
            // pointing at a listener that is about to stop.
            if self.proxy.hasLeftoverFlag {
                _ = self.proxy.restore()
            }
            let result = self.helper.disconnect()
            DispatchQueue.main.async {
                switch result {
                case .success:
                    self.detailLabel.stringValue = "Disconnected."
                case .failure(let f):
                    self.detailLabel.stringValue = "Disconnect failed: \(f)"
                }
                self.refreshStatus()
            }
        }
    }

    // MARK: Data

    private func reloadServers() {
        run { [weak self] in
            guard let self = self else { return }
            if case .success(let doc) = self.helper.servers() {
                DispatchQueue.main.async {
                    self.servers = doc.servers
                    self.selectedId = doc.selected ?? self.selectedId
                    self.table.reloadData()
                }
            }
        }
    }

    private func reloadCatalog() {
        run { [weak self] in
            guard let self = self else { return }
            let result = self.helper.engineInfo()
            DispatchQueue.main.async {
                switch result {
                case .success(let catalog):
                    self.catalogView.string = catalog.engines.map { e in
                        "\(e.kind) (min \(e.minVersion))\n  protocols: \(e.protocols.joined(separator: ", "))\n  features: \(e.features.joined(separator: ", "))"
                    }.joined(separator: "\n")
                case .failure:
                    self.catalogView.string = "Engine catalog unavailable (helper not found)."
                }
            }
        }
    }

    private func refreshStatus() {
        run { [weak self] in
            guard let self = self else { return }
            let result = self.helper.status()
            DispatchQueue.main.async {
                switch result {
                case .success(let status):
                    self.statusLabel.stringValue = "Status: \(status.state.lowercased())"
                    var parts: [String] = []
                    if let v = status.coreVersion { parts.append("core \(v)") }
                    if let p = status.platform { parts.append(p) }
                    if let lp = status.localProxy { parts.append("proxy 127.0.0.1:\(lp.port)") }
                    if status.killSwitchRequested == true {
                        parts.append(status.killSwitchEnforced == true
                            ? "kill switch enforced"
                            : "kill switch requested, NOT enforced on macOS")
                    }
                    self.detailLabel.stringValue = parts.joined(separator: " · ")
                case .failure:
                    self.statusLabel.stringValue = "Status: service unreachable"
                    self.detailLabel.stringValue = "Is the core service installed? See service/darwin."
                }
            }
        }
    }

    /// Helper calls are blocking subprocess runs; always off-main.
    /// Everything they produce for the screen hops back with
    /// DispatchQueue.main.async before touching AppKit (the pattern
    /// MenuBarController.refresh uses): AppKit is main-thread-only.
    private func run(_ work: @escaping () -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            work()
        }
    }

    // MARK: NSTableViewDataSource

    func numberOfRows(in tableView: NSTableView) -> Int { return servers.count }

    func tableView(_ tableView: NSTableView, objectValueFor tableColumn: NSTableColumn?, row: Int) -> Any? {
        guard row < servers.count else { return nil }
        let s = servers[row]
        let mark = (s.id == selectedId) ? "✓ " : ""
        return "\(mark)\(s.displayName)"
    }
}
