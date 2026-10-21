import Foundation
import NetworkExtension
import SoraLegacyCore

/// Packet Tunnel provider: owns the TUN through NetworkExtension and
/// the engine through the LibboxBridge (BoxService of the pin).
///
/// Flow: the app writes a TunnelConfigExchange (provider
/// configuration + App Group mirror) -> startTunnel loads it ->
/// bridge.setup in the App Group container -> bridge.startService ->
/// libbox's tun inbound calls PlatformInterface.openTun, which
/// converts TunOptions into NEPacketTunnelNetworkSettings via
/// applyTunOptions below and returns the utun fd the pin's own
/// GetTunnelFileDescriptor finds. Nothing about addresses or routes
/// is invented here: everything comes from TunOptions, which the
/// engine computed from the injected tun inbound.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let bridge: LibboxBridge = {
        #if canImport(Libbox)
        return LibboxBridgeImpl()
        #else
        return UnavailableBridge()
        #endif
    }()
    private var current: TunnelConfigExchange?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        guard let exchange = loadExchange() else {
            completionHandler(NSError(domain: "SoraLegacyTunnel", code: 1,
                                      userInfo: [NSLocalizedDescriptionKey: "startTunnel without config"]))
            return
        }
        current = exchange
        #if canImport(Libbox)
        (bridge as? LibboxBridgeImpl)?.provider = self
        #endif
        let group = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: SoraLegacyIdentifiers.appGroup)
        let base = group?.path ?? NSTemporaryDirectory()
        do {
            try bridge.setup(basePath: base, workingPath: base + "/libbox",
                             tempPath: NSTemporaryDirectory())
        } catch { completionHandler(error); return }
        // Start on a background queue: Start() blocks while the
        // engine calls openTun, which installs the network settings.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                try self.bridge.startService(configJSON: exchange.configJSON)
                completionHandler(nil)
            } catch { completionHandler(error) }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        try? bridge.stopService()
        current = nil
        completionHandler()
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        bridge.pause() // BoxService.Pause (service_pause.go)
        completionHandler()
    }

    override func wake() {
        bridge.wake() // BoxService.Wake (service_pause.go)
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        // The only app->provider message is "status": one byte 0x01.
        let running = bridge.isRunning
        completionHandler?(Data([running ? 1 : 0]))
    }

    // MARK: TunOptions -> network settings (called by openTun)

    /// Installs settings built from the engine's TunOptions and
    /// blocks until NetworkExtension answers, because openTun must
    /// only return the fd once the utun exists with these settings.
    func applyTunOptions(_ snap: TunOptionsSnapshot) throws {
        let settings = Self.makeSettings(from: snap)
        let semaphore = DispatchSemaphore(value: 0)
        var installError: Error?
        setTunnelNetworkSettings(settings) { error in
            installError = error
            semaphore.signal()
        }
        if semaphore.wait(timeout: .now() + 15) == .timedOut {
            throw LibboxBridgeError.openTunFailed("setTunnelNetworkSettings timed out")
        }
        if let installError { throw installError }
    }

    static func makeSettings(from snap: TunOptionsSnapshot) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: snap.mtu > 0 ? snap.mtu : Int32(TunConfig.defaultMTU))

        if !snap.inet4Address.isEmpty {
            let parsed = snap.inet4Address.map(splitCIDR)
            let ipv4 = NEIPv4Settings(addresses: parsed.map(\.address),
                                      subnetMasks: parsed.map { mask(prefix: $0.prefix, v6: false) })
            if snap.autoRoute {
                ipv4.includedRoutes = snap.inet4RouteAddress.isEmpty
                    ? [NEIPv4Route.default()]
                    : snap.inet4RouteAddress.map(route4)
                ipv4.excludedRoutes = snap.inet4RouteExcludeAddress.map(route4)
            }
            settings.ipv4Settings = ipv4
        }
        if !snap.inet6Address.isEmpty {
            let parsed = snap.inet6Address.map(splitCIDR)
            let ipv6 = NEIPv6Settings(addresses: parsed.map(\.address),
                                      networkPrefixLengths: parsed.map { NSNumber(value: $0.prefix) })
            if snap.autoRoute {
                ipv6.includedRoutes = snap.inet6RouteAddress.isEmpty
                    ? [NEIPv6Route.default()]
                    : snap.inet6RouteAddress.map(route6)
                ipv6.excludedRoutes = snap.inet6RouteExcludeAddress.map(route6)
            }
            settings.ipv6Settings = ipv6
        }
        if let dns = snap.dnsServerAddress, !dns.isEmpty {
            let dnsSettings = NEDNSSettings(servers: [dns])
            dnsSettings.matchDomains = [""] // all DNS through the hijack server
            settings.dnsSettings = dnsSettings
        }
        if snap.httpProxyEnabled, !snap.httpProxyServer.isEmpty {
            let proxy = NEProxySettings()
            proxy.httpEnabled = true
            proxy.httpServer = NEProxyServer(address: snap.httpProxyServer,
                                             port: Int(snap.httpProxyServerPort))
            proxy.httpsEnabled = true
            proxy.httpsServer = proxy.httpServer
            proxy.exceptionList = snap.httpProxyBypassDomain
            proxy.matchDomains = snap.httpProxyMatchDomain
            settings.proxySettings = proxy
        }
        return settings
    }

    private static func splitCIDR(_ cidr: String) -> (address: String, prefix: Int) {
        let parts = cidr.split(separator: "/")
        return (String(parts.first ?? ""), parts.count > 1 ? Int(parts[1]) ?? 0 : 0)
    }
    private static func route4(_ cidr: String) -> NEIPv4Route {
        let parsed = splitCIDR(cidr)
        return NEIPv4Route(destinationAddress: parsed.address, subnetMask: mask(prefix: parsed.prefix, v6: false))
    }
    private static func route6(_ cidr: String) -> NEIPv6Route {
        let parsed = splitCIDR(cidr)
        return NEIPv6Route(destinationAddress: parsed.address, networkPrefixLength: NSNumber(value: parsed.prefix))
    }
    private static func mask(prefix: Int, v6: Bool) -> String {
        let clamped = max(0, min(32, prefix))
        let value: UInt32 = clamped == 0 ? 0 : UInt32.max << (32 - clamped)
        return [24, 16, 8, 0].map { String((value >> UInt32($0)) & 0xFF) }.joined(separator: ".")
    }

    // MARK: Config loading

    private func loadExchange() -> TunnelConfigExchange? {
        if let proto = protocolConfiguration as? NETunnelProviderProtocol,
           let exchange = TunnelConfigExchange(providerDictionary: proto.providerConfiguration) {
            return exchange
        }
        let defaults = UserDefaults(suiteName: SoraLegacyIdentifiers.appGroup)
        guard let data = defaults?.data(forKey: ServerStore.exchangeKey) else { return nil }
        return try? JSONDecoder().decode(TunnelConfigExchange.self, from: data)
    }
}

/// Used when the Libbox framework is not linked (a build without
/// the Mac bind step): start fails honestly instead of pretending.
final class UnavailableBridge: LibboxBridge {
    func setup(basePath: String, workingPath: String, tempPath: String) throws {}
    func startService(configJSON: String) throws { throw LibboxBridgeError.frameworkMissing }
    func stopService() throws {}
    var isRunning: Bool { false }
    func pause() {}
    func wake() {}
    func resetNetwork() {}
}
