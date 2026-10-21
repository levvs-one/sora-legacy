import Foundation

/// One imported server, mirroring `core/mobileapi.Server` field for
/// field (mobileapi.go). `credentials` is credential material: it is
/// stored in the Keychain (see `ServerStore`), never logged, and the
/// `raw` JSON is what plan documents are built from.
public struct Server: Codable, Equatable, Identifiable {
    public var id: String
    public var name: String?
    public var `protocol`: String
    public var server: String
    public var port: Int64
    public var transport: String?
    public var security: String?
    public var credentialRef: String?
    public var credentials: [String: String]?

    enum CodingKeys: String, CodingKey {
        case id, name, server, port, transport, security, credentials
        case `protocol` = "protocol"
        case credentialRef = "credential_ref"
    }

    public var label: String {
        if let name, !name.isEmpty { return name }
        return "\(server):\(port)"
    }
}

/// The plan document of `core/mobileapi` (`Plan` in mobileapi.go):
/// the input of BuildPlan/RenderSingBoxConfig and the normalized
/// output of BuildPlan.
public struct PlanDocument: Codable, Equatable {
    public var sessionID: String?
    public var localPort: Int64?
    public var servers: [Server]
    public var groups: [Group]?
    public var rules: [Rule]?

    public struct Group: Codable, Equatable {
        public var name: String
        public var type: String
        public var members: [String]
    }
    public struct Rule: Codable, Equatable {
        public var type: String
        public var value: String?
        public var target: String
    }
    enum CodingKeys: String, CodingKey {
        case servers, groups, rules
        case sessionID = "session_id"
        case localPort = "local_port"
    }
    public init(sessionID: String? = nil, localPort: Int64? = nil, servers: [Server]) {
        self.sessionID = sessionID
        self.localPort = localPort
        self.servers = servers
    }
}

/// Static engine catalog as `mobileapi.EngineInfo()` returns it.
public struct EngineInfo: Codable, Equatable {
    public struct Engine: Codable, Equatable {
        public var kind: String
        public var minVersion: String
        public var protocols: [String]
        public var features: [String]
        enum CodingKeys: String, CodingKey {
            case kind, protocols, features
            case minVersion = "min_version"
        }
    }
    public var engines: [Engine]
    public var defaultPreference: [String]
    enum CodingKeys: String, CodingKey {
        case engines
        case defaultPreference = "default_preference"
    }
}

public enum ConnectionState: String, Codable, Equatable {
    case stopped, starting, running, stopping, error
}

/// What the app hands the PacketTunnel extension, through the
/// provider configuration and mirrored into the App Group suite (the
/// system can restart the extension without the app, so the mirror is
/// the fallback source — same pattern as the main sora tree).
public struct TunnelConfigExchange: Codable, Equatable {
    public var configJSON: String
    public var serverName: String?
    public var localPort: Int
    public init(configJSON: String, serverName: String? = nil, localPort: Int = 7890) {
        self.configJSON = configJSON
        self.serverName = serverName
        self.localPort = localPort
    }
    public var providerDictionary: [String: Any] {
        var dict: [String: Any] = ["configJSON": configJSON, "localPort": localPort]
        if let serverName { dict["serverName"] = serverName }
        return dict
    }
    public init?(providerDictionary dict: [String: Any]?) {
        guard let dict, let config = dict["configJSON"] as? String else { return nil }
        configJSON = config
        serverName = dict["serverName"] as? String
        localPort = dict["localPort"] as? Int ?? 7890
    }
}

/// Canonical identifiers (Android applicationId is
/// `one.levvs.sora.legacy`, android/app/build.gradle.kts).
public enum SoraLegacyIdentifiers {
    public static let bundleID = "one.levvs.sora.legacy"
    public static let tunnelBundleID = "one.levvs.sora.legacy.PacketTunnel"
    public static let appGroup = "group.one.levvs.sora.legacy"
    /// The keychain access group exactly as written in both
    /// targets' entitlements. The `$(AppIdentifierPrefix)` prefix
    /// is expanded by Xcode at signing time (to the team prefix)
    /// in entitlements and plists only — never in Swift sources —
    /// so this literal must not be passed to `kSecAttrAccessGroup`
    /// verbatim. App/KeychainSecrets.swift uses this constant as
    /// the expected group and resolves the real prefix at runtime
    /// before putting anything in a query.
    public static let keychainGroup = "$(AppIdentifierPrefix)one.levvs.sora.legacy"
}
