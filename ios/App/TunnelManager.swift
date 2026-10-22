import Foundation
import NetworkExtension
import SoraLegacyCore

/// Owns the NETunnelProviderManager: install/update the provider
/// configuration, start/stop, observe status. The connect pipeline
/// mirrors Android's SoraVpnService.startEngine exactly:
///
///   selected server -> PlanDocument(localPort, [server])
///   -> mobileAPI.buildPlan -> mobileAPI.renderSingBoxConfig
///   -> TunConfig.injectTunInbound(rendered, mtu, strictRoute)
///   -> TunnelConfigExchange saved to the App Group + provider
///      configuration -> manager.connection.startVPNTunnel()
final class TunnelManager {
    private(set) var state: ConnectionState = .stopped {
        didSet { if state != oldValue { onChange?() } }
    }
    private(set) var lastError: String? {
        didSet { onChange?() }
    }
    /// Called on the main queue whenever state/lastError changes
    /// (UIKit UI — see AppDelegate for why not SwiftUI).
    var onChange: (() -> Void)?
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    /// Monotonic token of the current connect attempt. Every
    /// connect() and every cancel-during-start bumps it; the
    /// background pipeline and the install completions capture the
    /// token they were started with and refuse to act when it no
    /// longer matches — otherwise a tunnel would come up after the
    /// user pressed Cancel during `.starting`, before
    /// installAndStart ever ran (review minor M4).
    private var connectEpoch = 0

    func load() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            DispatchQueue.main.async {
                self?.manager = managers?.first
                self?.refreshState()
                self?.observeStatus()
            }
        }
    }

    func connect() {
        guard let server = AppStore.shared.selected() else {
            lastError = "No server selected. Import a link or a subscription first."
            state = .error
            return
        }
        connectEpoch += 1
        let epoch = connectEpoch
        state = .starting
        lastError = nil
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let store = AppStore.shared
                let planInput = PlanDocument(localPort: Int64(store.localPort()), servers: [server])
                let plan = try AppStore.mobileAPI.buildPlan(planInput)
                let rendered = try AppStore.mobileAPI.renderSingBoxConfig(plan)
                let config = try TunConfig.injectTunInbound(
                    configJSON: rendered, mtu: store.tunMTU(), strictRoute: store.strictRoute())
                let exchange = TunnelConfigExchange(
                    configJSON: config, serverName: server.label, localPort: store.localPort())
                store.saveExchange(exchange)
                DispatchQueue.main.async {
                    // Cancelled while the pipeline ran: the epoch
                    // moved on (and state left .starting) — do not
                    // install or start anything.
                    guard self.connectEpoch == epoch, self.state == .starting else { return }
                    self.installAndStart(exchange, epoch: epoch)
                }
            } catch {
                DispatchQueue.main.async {
                    guard self.connectEpoch == epoch else { return }
                    // The technical detail goes to the log only:
                    // lastError is rendered verbatim by the status
                    // screen, so it carries authored sentences, never
                    // an engine/localizedDescription string.
                    NSLog("[tunnel] connect pipeline failed: %@", "\(error)")
                    self.lastError = "The server configuration could not be prepared. Check the selected server and try again."
                    self.state = .error
                }
            }
        }
    }

    private func installAndStart(_ exchange: TunnelConfigExchange, epoch: Int) {
        let manager = self.manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = SoraLegacyIdentifiers.tunnelBundleID
        proto.serverAddress = exchange.serverName ?? "sora-legacy"
        proto.providerConfiguration = exchange.providerDictionary
        manager.protocolConfiguration = proto
        manager.localizedDescription = "Sora Legacy"
        // VPN On Demand stays OFF by default: the user connects
        // explicitly. Enabling it is a settings decision for the
        // owner (see README §verify-on-mac), not a silent default —
        // an always-on rule set the user never asked for would
        // re-connect a tunnel they deliberately stopped.
        manager.isOnDemandEnabled = false
        manager.isEnabled = true
        manager.saveToPreferences { [weak self] error in
            if let error {
                DispatchQueue.main.async {
                    guard self?.connectEpoch == epoch else { return }
                    NSLog("[tunnel] saveToPreferences failed: %@", "\(error)")
                    self?.lastError = "The VPN configuration could not be saved."; self?.state = .error
                }
                return
            }
            manager.loadFromPreferences { _ in
                DispatchQueue.main.async {
                    // Re-check at the last moment: a Cancel that
                    // landed during save/load must win over the
                    // start it raced with.
                    guard let self, self.connectEpoch == epoch, self.state == .starting else { return }
                    self.manager = manager
                    do { try manager.connection.startVPNTunnel() }
                    catch {
                        NSLog("[tunnel] startVPNTunnel failed: %@", "\(error)")
                        self.lastError = "The tunnel could not be started."; self.state = .error
                    }
                }
            }
        }
    }

    func disconnect() {
        if state == .starting {
            // Cancel before the tunnel exists: invalidate the
            // in-flight pipeline (epoch bump — its completions all
            // check it) and settle in .stopped. There is no live
            // connection to stop yet; stopVPNTunnel is still called
            // defensively in case preferences installed a manager
            // whose status has not been observed yet.
            connectEpoch += 1
            manager?.connection.stopVPNTunnel()
            state = .stopped
            return
        }
        state = .stopping
        manager?.connection.stopVPNTunnel()
    }

    private func observeStatus() {
        guard statusObserver == nil else { return }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            self?.refreshState()
        }
    }

    private func refreshState() {
        guard let manager else { state = .stopped; return }
        switch manager.connection.status {
        case .connected: state = .running
        case .connecting, .reasserting: state = .starting
        case .disconnecting: state = .stopping
        default: if state != .error { state = .stopped }
        }
    }
}
