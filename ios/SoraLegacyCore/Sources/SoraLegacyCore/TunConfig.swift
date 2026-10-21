import Foundation

/// Swift mirror of the Android client's TunConfig.kt — same
/// guarantees, same constants, so both mobile clients hand libbox the
/// same TUN shape.
///
/// mobileapi renders an application-mode plan: a loopback mixed
/// inbound, no TUN ("Mobile clients own the TUN", mobileapi.go). On
/// iOS the TUN is created by sing-box's tun inbound asking our
/// PlatformInterface.openTun() for a fd, so the client adds exactly
/// that inbound to the rendered document before handing it to
/// Libbox.newService. If a render ever ships its own tun inbound, it
/// is left untouched.
///
/// The addresses mirror the desktop render's session shape:
/// 172.19.0.1/30 gives libbox the second address its
/// GetDNSServerAddress() derives the hijack DNS server from
/// (experimental/libbox/tun.go: a /32 — Bits()==32 — makes it throw),
/// so the /30 is a contract, not a preference.
public enum TunConfig {
    public static let tunTag = "tun-in"
    public static let inet4Address = "172.19.0.1/30"
    public static let inet6Address = "fdfe:dcba:9876::1/126"
    public static let defaultMTU = 1500

    public enum TunConfigError: Error, Equatable {
        case notJSON
        case rootNotObject
    }

    /// Returns `configJSON` with exactly one tun inbound: the input
    /// unchanged when it already carries one, otherwise the rendered
    /// document plus the canonical inbound appended to `inbounds`.
    public static func injectTunInbound(configJSON: String, mtu: Int = defaultMTU,
                                        strictRoute: Bool = false) throws -> String {
        guard let data = configJSON.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) else {
            throw TunConfigError.notJSON
        }
        guard var root = parsed as? [String: Any] else { throw TunConfigError.rootNotObject }
        var inbounds = root["inbounds"] as? [[String: Any]] ?? []
        if inbounds.contains(where: { $0["type"] as? String == "tun" }) {
            return configJSON
        }
        let tun: [String: Any] = [
            "type": "tun",
            "tag": tunTag,
            "address": [inet4Address, inet6Address],
            "mtu": mtu,
            "auto_route": true,
            "strict_route": strictRoute,
            "stack": "mixed",
        ]
        inbounds.append(tun)
        root["inbounds"] = inbounds
        let out = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return String(decoding: out, as: UTF8.self)
    }
}
