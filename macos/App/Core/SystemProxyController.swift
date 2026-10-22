import Foundation

/// Owns the macOS system proxy for system-proxy mode.
///
/// The daemon side of that mode is only a loopback listener: the core
/// opens its local proxy on 127.0.0.1:<port> (reported by GetAbout),
/// and pointing the *system* proxy at it is the user session's job —
/// core/guard states the same split ("The system proxy belongs to the
/// signed-in user and is managed by the user UI").
///
/// Implementation: `/usr/sbin/networksetup`, the documented admin
/// tool for exactly these settings, driven as a subprocess. The
/// alternative (SCPreferences + Authorization Services from
/// SystemConfiguration) is what a future signed build may switch to;
/// networksetup keeps this client free of C bridging on a 10.13 floor
/// and its failure modes are plain text we can classify honestly.
///
/// Contract (the same one the main tree's limited macOS client uses):
///  (a) Snapshot before change, restore on stop. The previous state of
///      every touched service (HTTP/HTTPS/SOCKS enable, server, port,
///      bypass domains) is captured BEFORE the first write and
///      persisted to UserDefaults together with the "we set it" flag —
///      persisted BEFORE applying, so a crash still leaves the guard
///      armed; the next launch restores first
///      (recoverLeftoverIfNeeded).
///  (b) Never leave a proxy pointing at a dead port. Disconnect order
///      in the app is: restore proxy first (this controller), then
///      ask the daemon to disconnect.
///  (c) Honest authorization failure. Changing network settings can
///      require administrator rights; networksetup's refusal maps to
///      SystemProxyError.authorizationDenied, shown as a state —
///      never swallowed into a fake "connected".
public enum SystemProxyError: Error, Equatable {
    case authorizationDenied
    case toolUnavailable
    case commandFailed(String)
    case noServices
}

/// Persisted pre-Sora state of one network service.
public struct ServiceProxySnapshot: Codable, Equatable {
    public var service: String
    public var httpEnabled: Bool
    public var httpServer: String
    public var httpPort: Int
    public var httpsEnabled: Bool
    public var httpsServer: String
    public var httpsPort: Int
    public var socksEnabled: Bool
    public var socksServer: String
    public var socksPort: Int
    public var bypass: [String]
}

public final class SystemProxyController {
    private let defaults: UserDefaults
    private let toolPath = "/usr/sbin/networksetup"

    private enum Key {
        static let weSet = "soralegacy.proxy.weSet"
        static let snapshot = "soralegacy.proxy.snapshot"
        static let port = "soralegacy.proxy.port"
    }

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public var hasLeftoverFlag: Bool { return defaults.bool(forKey: Key.weSet) }

    public func loadSnapshot() -> [ServiceProxySnapshot]? {
        guard let data = defaults.data(forKey: Key.snapshot) else { return nil }
        return try? JSONDecoder().decode([ServiceProxySnapshot].self, from: data)
    }

    // MARK: Subprocess

    /// Runs networksetup, returning stdout. A refusal mentioning
    /// authorization maps to .authorizationDenied; anything else is
    /// carried verbatim (trimmed) as the failure payload — for the
    /// log. The UI maps each error case to its own authored sentence
    /// and never renders this raw tool text.
    @discardableResult
    func tool(_ arguments: [String]) -> Result<String, SystemProxyError> {
        guard FileManager.default.isExecutableFile(atPath: toolPath) else {
            return .failure(.toolUnavailable)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: toolPath)
        process.arguments = arguments
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        do { try process.run() } catch { return .failure(.toolUnavailable) }
        process.waitUntilExit()
        let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        if process.terminationStatus != 0 {
            let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let text = (err.isEmpty ? out : err).trimmingCharacters(in: .whitespacesAndNewlines)
            if text.contains("Authorization") || text.contains("uthorization") {
                return .failure(.authorizationDenied)
            }
            return .failure(.commandFailed(text))
        }
        return .success(out)
    }

    // MARK: Reading state

    /// Enabled network services (disabled ones are prefixed "*").
    public func services() -> Result<[String], SystemProxyError> {
        switch tool(["-listallnetworkservices"]) {
        case .failure(let e): return .failure(e)
        case .success(let out):
            var names = out.components(separatedBy: "\n").dropFirst()
            let result = names.filter { !$0.hasPrefix("*") && !$0.isEmpty }
                .map { $0.trimmingCharacters(in: .whitespaces) }
            return result.isEmpty ? .failure(.noServices) : .success(result)
        }
    }

    /// Parses one `-get*proxy` answer: "Enabled: Yes", "Server: x",
    /// "Port: n" lines.
    static func parseProxy(_ out: String) -> (enabled: Bool, server: String, port: Int) {
        var enabled = false
        var server = ""
        var port = 0
        for line in out.components(separatedBy: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            switch parts[0] {
            case "Enabled": enabled = (value == "Yes")
            case "Server": server = value
            case "Port": port = Int(value) ?? 0
            default: break
            }
        }
        return (enabled, server, port)
    }

    public func snapshot(service: String) -> Result<ServiceProxySnapshot, SystemProxyError> {
        let http: (Bool, String, Int)
        let https: (Bool, String, Int)
        let socks: (Bool, String, Int)
        switch tool(["-getwebproxy", service]) {
        case .failure(let e): return .failure(e)
        case .success(let o): http = SystemProxyController.parseProxy(o)
        }
        switch tool(["-getsecurewebproxy", service]) {
        case .failure(let e): return .failure(e)
        case .success(let o): https = SystemProxyController.parseProxy(o)
        }
        switch tool(["-getsocksfirewallproxy", service]) {
        case .failure(let e): return .failure(e)
        case .success(let o): socks = SystemProxyController.parseProxy(o)
        }
        var bypass: [String] = []
        if case .success(let out) = tool(["-getproxybypassdomains", service]) {
            bypass = out.components(separatedBy: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("There aren't any") }
        }
        return .success(ServiceProxySnapshot(
            service: service,
            httpEnabled: http.0, httpServer: http.1, httpPort: http.2,
            httpsEnabled: https.0, httpsServer: https.1, httpsPort: https.2,
            socksEnabled: socks.0, socksServer: socks.1, socksPort: socks.2,
            bypass: bypass))
    }

    // MARK: Apply / restore

    /// Points every service's HTTP/HTTPS/SOCKS proxy at
    /// 127.0.0.1:`port`. Snapshot is persisted (and the crash guard
    /// armed) BEFORE the first change.
    public func apply(port: Int) -> Result<Void, SystemProxyError> {
        let names: [String]
        switch services() {
        case .failure(let e): return .failure(e)
        case .success(let s): names = s
        }
        var snapshots: [ServiceProxySnapshot] = []
        for name in names {
            switch snapshot(service: name) {
            case .failure(let e): return .failure(e)
            case .success(let s): snapshots.append(s)
            }
        }
        // (a) Persist first.
        if let data = try? JSONEncoder().encode(snapshots) {
            defaults.set(data, forKey: Key.snapshot)
        }
        defaults.set(port, forKey: Key.port)
        defaults.set(true, forKey: Key.weSet)
        defaults.synchronize()

        for snap in snapshots {
            for kind in ["webproxy", "securewebproxy", "socksfirewallproxy"] {
                switch tool(["-set\(kind)", snap.service, "127.0.0.1", "\(port)"]) {
                case .failure(let e):
                    _ = restore()
                    return .failure(e)
                case .success: break
                }
            }
        }
        return .success(())
    }

    /// Restores the snapshot verbatim; a service whose proxy was off
    /// gets its state switched off again (not a zeroed server entry).
    @discardableResult
    public func restore() -> Result<Void, SystemProxyError> {
        guard hasLeftoverFlag else { return .success(()) }
        guard let snapshots = loadSnapshot() else {
            // Snapshot unreadable: only clear our own entries — ones
            // pointing at our recorded loopback port — never others.
            return stripOurEntries()
        }
        for snap in snapshots {
            setOne(service: snap.service, kind: "webproxy",
                   enabled: snap.httpEnabled, server: snap.httpServer, port: snap.httpPort)
            setOne(service: snap.service, kind: "securewebproxy",
                   enabled: snap.httpsEnabled, server: snap.httpsServer, port: snap.httpsPort)
            setOne(service: snap.service, kind: "socksfirewallproxy",
                   enabled: snap.socksEnabled, server: snap.socksServer, port: snap.socksPort)
            if !snap.bypass.isEmpty {
                _ = tool(["-setproxybypassdomains", snap.service] + snap.bypass)
            }
        }
        clearPersisted()
        return .success(())
    }

    private func setOne(service: String, kind: String, enabled: Bool, server: String, port: Int) {
        if enabled && !server.isEmpty {
            _ = tool(["-set\(kind)", service, server, "\(port)"])
        } else {
            _ = tool(["-set\(kind)state", service, "off"])
        }
    }

    private func stripOurEntries() -> Result<Void, SystemProxyError> {
        let port = defaults.integer(forKey: Key.port)
        guard port > 0, case .success(let names) = services() else {
            clearPersisted()
            return .success(())
        }
        for name in names {
            guard case .success(let snap) = snapshot(service: name) else { continue }
            if snap.httpServer == "127.0.0.1" && snap.httpPort == port {
                _ = tool(["-setwebproxystate", name, "off"])
                _ = tool(["-setsecurewebproxystate", name, "off"])
                _ = tool(["-setsocksfirewallproxystate", name, "off"])
            }
        }
        clearPersisted()
        return .success(())
    }

    /// Launch-time crash guard: if the flag is set, a previous run
    /// died owning the proxy — give the settings back before any new
    /// session can start. Returns true when a restore ran.
    public func recoverLeftoverIfNeeded() -> Bool {
        guard hasLeftoverFlag else { return false }
        _ = restore()
        return true
    }

    private func clearPersisted() {
        defaults.removeObject(forKey: Key.snapshot)
        defaults.removeObject(forKey: Key.port)
        defaults.set(false, forKey: Key.weSet)
        defaults.synchronize()
    }
}
