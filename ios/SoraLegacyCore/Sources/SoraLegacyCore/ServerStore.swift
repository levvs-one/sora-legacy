import Foundation

/// Secret storage seam: server credentials are passwords. The app
/// target backs this with the Keychain (App/KeychainSecrets.swift);
/// tests back it with memory. Nothing else in the core touches
/// secrets directly. Writes throw: a Keychain failure (e.g. a bad
/// access group) must surface to the caller as an error, never be
/// swallowed — a server whose credentials silently failed to save
/// would reappear after relaunch without them.
public protocol SecretsStore {
    func secret(forKey key: String) -> String?
    func setSecret(_ value: String?, forKey key: String) throws
}

/// Shared app<->extension store. State lives in the App Group suite
/// so the PacketTunnel extension — which the system may start
/// alone — reads the same facts the app wrote. Precisely what the
/// suite holds: the server list with `credentials` stripped (the
/// full credential documents live only in the Keychain, under each
/// server's id), the selection, the settings — and the tunnel
/// exchange. The exchange is the one deliberate exception to
/// "no credentials in the suite": it carries the full rendered
/// sing-box config, outbound credentials inside, because the
/// extension needs the complete config to run the tunnel at all
/// (Android writes the same rendered config to its private
/// filesDir, and the exchange is also mirrored into the
/// providerConfiguration for the same reason). It is not a
/// credential store — credentials at rest are the Keychain's job —
/// but it is not credential-free either, and docs must not claim
/// otherwise.
public final class ServerStore {
    public static let serversKey = "servers.v1"
    public static let selectedIDKey = "selected_id"
    public static let localPortKey = "local_port"
    public static let tunMTUKey = "tun_mtu"
    public static let strictRouteKey = "strict_route"
    public static let exchangeKey = "tunnel_exchange"

    private let defaults: UserDefaults
    private let secrets: SecretsStore

    public init(defaults: UserDefaults, secrets: SecretsStore) {
        self.defaults = defaults
        self.secrets = secrets
    }

    // MARK: Servers

    /// Servers with credentials re-attached from the secret store.
    public func servers() -> [Server] {
        guard let data = defaults.data(forKey: Self.serversKey),
              let stored = try? JSONDecoder().decode([Server].self, from: data) else { return [] }
        return stored.map { server in
            var server = server
            if let raw = secrets.secret(forKey: server.id),
               let credData = raw.data(using: .utf8),
               let creds = try? JSONDecoder().decode([String: String].self, from: credData) {
                server.credentials = creds
            }
            return server
        }
    }

    public func saveServers(_ servers: [Server]) throws {
        for server in servers {
            if let creds = server.credentials,
               let data = try? JSONEncoder().encode(creds) {
                try secrets.setSecret(String(decoding: data, as: UTF8.self), forKey: server.id)
            } else {
                try secrets.setSecret(nil, forKey: server.id)
            }
        }
        let stripped = servers.map { server -> Server in
            var server = server
            server.credentials = nil
            return server
        }
        if let data = try? JSONEncoder().encode(stripped) {
            defaults.set(data, forKey: Self.serversKey)
        }
        if selectedID() != nil, !servers.contains(where: { $0.id == selectedID() }) {
            defaults.removeObject(forKey: Self.selectedIDKey)
        }
    }

    public func addServers(_ new: [Server]) throws {
        var all = servers()
        for server in new where !all.contains(where: { $0.id == server.id }) {
            all.append(server)
        }
        try saveServers(all)
    }

    public func removeServer(id: String) throws {
        try saveServers(servers().filter { $0.id != id })
        try secrets.setSecret(nil, forKey: id)
    }

    // MARK: Selection & settings (defaults mirror Android ServerStore)

    public func selectedID() -> String? { defaults.string(forKey: Self.selectedIDKey) }
    public func select(id: String?) {
        if let id { defaults.set(id, forKey: Self.selectedIDKey) }
        else { defaults.removeObject(forKey: Self.selectedIDKey) }
    }
    public func selected() -> Server? {
        guard let id = selectedID() else { return servers().first }
        return servers().first { $0.id == id }
    }

    /// Android ServerStore.localPort() default: 7890 (mobileapi's
    /// DefaultLocalPort).
    public func localPort() -> Int {
        let value = defaults.integer(forKey: Self.localPortKey)
        return value == 0 ? 7890 : value
    }
    public func setLocalPort(_ port: Int) { defaults.set(port, forKey: Self.localPortKey) }

    /// Android ServerStore.tunMtu() default: 1500.
    public func tunMTU() -> Int {
        let value = defaults.integer(forKey: Self.tunMTUKey)
        return value == 0 ? TunConfig.defaultMTU : value
    }
    public func setTunMTU(_ mtu: Int) { defaults.set(mtu, forKey: Self.tunMTUKey) }

    /// Android ServerStore.strictRoute() default: false.
    public func strictRoute() -> Bool { defaults.bool(forKey: Self.strictRouteKey) }
    public func setStrictRoute(_ on: Bool) { defaults.set(on, forKey: Self.strictRouteKey) }

    // MARK: Tunnel exchange mirror

    public func saveExchange(_ exchange: TunnelConfigExchange) {
        if let data = try? JSONEncoder().encode(exchange) {
            defaults.set(data, forKey: Self.exchangeKey)
        }
    }
    public func exchange() -> TunnelConfigExchange? {
        guard let data = defaults.data(forKey: Self.exchangeKey) else { return nil }
        return try? JSONDecoder().decode(TunnelConfigExchange.self, from: data)
    }
}

/// In-memory secrets for tests and previews.
public final class InMemorySecrets: SecretsStore {
    private var values: [String: String] = [:]
    public init() {}
    public func secret(forKey key: String) -> String? { values[key] }
    public func setSecret(_ value: String?, forKey key: String) { values[key] = value }
}
