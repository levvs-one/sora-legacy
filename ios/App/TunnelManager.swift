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
                DispatchQueue.main.async { self.installAndStart(exchange) }
            } catch {
                DispatchQueue.main.async {
                    self.lastError = (error as? MobileAPIError).map {
                        switch $0 { case .engine(let m), .badJSON(let m): return m }
                    } ?? error.localizedDescription
                    self.state = .error
                }
            }
        }
    }

    private func installAndStart(_ exchange: TunnelConfigExchange) {
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
                DispatchQueue.main.async { self?.lastError = error.localizedDescription; self?.state = .error }
                return
            }
            manager.loadFromPreferences { _ in
                DispatchQueue.main.async {
                    self?.manager = manager
                    do { try manager.connection.startVPNTunnel() }
                    catch { self?.lastError = error.localizedDescription; self?.state = .error }
                }
            }
        }
    }

    func disconnect() {
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
