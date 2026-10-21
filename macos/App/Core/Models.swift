import Foundation

/// Decodable shapes of the `sora-ctl` helper's JSON output
/// (macos/helper). The client never parses the core's wire protocol;
/// it decodes exactly these documents.

public struct HelperStatus: Decodable, Equatable {
    public var state: String
    public var sessionId: String?
    public var coreVersion: String?
    public var platform: String?
    public var localProxy: Endpoint?
    public var engines: [EngineBuild]?
    public var mode: String?
    public var serverId: String?
    public var killSwitchRequested: Bool?
    public var killSwitchEnforced: Bool?
    public var errorKey: String?

    public struct Endpoint: Decodable, Equatable {
        public var host: String
        public var port: Int
    }
    public struct EngineBuild: Decodable, Equatable {
        public var kind: String
        public var installed: Bool
        public var version: String
    }

    enum CodingKeys: String, CodingKey {
        case state
        case sessionId = "session_id"
        case coreVersion = "core_version"
        case platform
        case localProxy = "local_proxy"
        case engines
        case mode
        case serverId = "server_id"
        case killSwitchRequested = "kill_switch_requested"
        case killSwitchEnforced = "kill_switch_enforced"
        case errorKey = "error_key"
    }

    public var isConnected: Bool { return state == "CONNECTED" }
}

public struct ServerInfo: Decodable, Equatable {
    public var id: String
    public var name: String?
    public var proto: String
    public var host: String
    public var port: Int

    enum CodingKeys: String, CodingKey {
        case id, name, host, port
        case proto = "protocol"
    }

    public var displayName: String {
        if let name = name, !name.isEmpty { return name }
        return "\(proto) \(host):\(port)"
    }
}

public struct ServersDocument: Decodable {
    public var servers: [ServerInfo]
    public var selected: String?
    public var source: String?
}

/// One engine of the static catalog the helper's `engineinfo` prints
/// (core/mobileapi.EngineInfo over core/engine.Catalog). Obfuscation
/// and protocol features reach the UI only through this data:
/// the client contains no hardcoded feature list of its own.
public struct EngineCatalog: Decodable {
    public struct Engine: Decodable, Equatable {
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

/// The helper's failure document, printed to stderr with exit != 0.
public struct HelperError: Decodable {
    public var error: String
}
