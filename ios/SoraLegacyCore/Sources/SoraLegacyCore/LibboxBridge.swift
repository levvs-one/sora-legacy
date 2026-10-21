import Foundation

/// The seam between the client and the libbox xcframework
/// (upstream sing-box 1.12.12, experimental/libbox — every signature
/// below was read from that tree, not from the lx fork of the main
/// sora client: for this pin `BoxService` is the real API).
///
/// Go facts this seam mirrors (file:line in the pin):
///  * `Setup(options *SetupOptions) error` — setup.go; SetupOptions
///    has exactly BasePath, WorkingPath, TempPath, Username, IsTVOS,
///    FixAndroidStack.
///  * `NewService(configContent string, platformInterface
///    PlatformInterface) (*BoxService, error)`, `(*BoxService).Start()
///    error`, `(*BoxService).Close() error` — service.go.
///  * `CheckConfig(configContent string) error` — config.go,
///    used here as a preflight.
///  * `Version() string` — setup.go.
///  * BoxService also carries Pause()/Wake()/ResetNetwork()/
///    UpdateWIFIState() for iOS (service_pause.go).
///
/// The implementation lives in the PacketTunnel target
/// (PacketTunnel/LibboxBridgeImpl.swift) because the platform
/// interface needs the extension's packet flow; this protocol is all
/// the rest of the code ever sees.
public protocol LibboxBridge: AnyObject {
    /// One-time per-process setup. Must precede `startService`.
    func setup(basePath: String, workingPath: String, tempPath: String) throws
    /// Preflight + create + start the BoxService for `configJSON`
    /// (a rendered config with the TUN inbound already injected).
    func startService(configJSON: String) throws
    /// Close the service. Safe when already stopped.
    func stopService() throws
    var isRunning: Bool { get }
    /// iOS power hooks (service_pause.go): pause on sleep, wake on
    /// wake, reset network after a path change.
    func pause()
    func wake()
    func resetNetwork()
    /// The engine version string — `Version()` in the pin's
    /// setup.go, cited in this file's header and exposed here so the
    /// citation is backed by a real seam method, not prose.
    func version() -> String
}

public enum LibboxBridgeError: Error, Equatable {
    case frameworkMissing
    case invalidConfig(String)
    case startFailed(String)
    case openTunFailed(String)
}

/// Value snapshot of libbox's TunOptions (tun.go of the pin: 19
/// getters — counted line by line in the interface, tun.go:14-34)
/// as the PacketTunnel provider consumes it to build
/// NEPacketTunnelNetworkSettings. Every one of the 19 getters is
/// drained into a field here by `PlatformInterfaceImpl.snapshot`
/// (PacketTunnel/LibboxBridgeImpl.swift) — including the two route
/// ranges and the two package lists below. Pure value type so the
/// settings construction is testable without the framework.
public struct TunOptionsSnapshot: Equatable {
    public var inet4Address: [String] = []   // "addr/prefix"
    public var inet6Address: [String] = []
    public var dnsServerAddress: String?
    public var mtu: Int32 = 0
    public var autoRoute: Bool = false
    public var strictRoute: Bool = false
    public var inet4RouteAddress: [String] = []
    public var inet6RouteAddress: [String] = []
    public var inet4RouteExcludeAddress: [String] = []
    public var inet6RouteExcludeAddress: [String] = []
    /// Effective auto-route ranges the pin's wrapper computed with
    /// `BuildAutoRouteRanges` (service.go, sing-tun tun_rules.go)
    /// and hands to the platform through GetInet4/6RouteRange:
    /// the route addresses (or the whole space under auto_route)
    /// with the exclude addresses already subtracted, plus the
    /// tunnel subnet on Darwin. When non-empty these ARE the
    /// included routes — see the helpers below.
    public var inet4RouteRange: [String] = []
    public var inet6RouteRange: [String] = []
    /// Android package filters from the tun inbound
    /// (GetIncludePackage/GetExcludePackage). The values are kept
    /// here for honesty and logging, but iOS cannot apply them:
    /// per-app VPN filtering is an MDM-only capability
    /// (per-app VPN payload), a non-MDM packet-tunnel provider has
    /// no API to include/exclude individual apps. The provider
    /// logs an explicit refusal when these are non-empty
    /// (PacketTunnelProvider.applyTunOptions); they are never
    /// silently dropped — see BUILD-MAC.md §6 and README.
    public var includePackage: [String] = []
    public var excludePackage: [String] = []
    public var httpProxyEnabled: Bool = false
    public var httpProxyServer: String = ""
    public var httpProxyServerPort: Int32 = 0
    public var httpProxyBypassDomain: [String] = []
    public var httpProxyMatchDomain: [String] = []
    public init() {}

    // MARK: Effective routes for NEPacketTunnelNetworkSettings

    /// Included IPv4 route CIDRs for the NE settings: the pin's
    /// precomputed route ranges when present (they already encode
    /// route addresses, the auto-route default and the excludes),
    /// otherwise the raw route addresses. Empty means "no explicit
    /// routes" — the provider substitutes the NE default route
    /// under auto_route, mirroring BuildAutoRouteRanges' 0.0.0.0/0.
    public var includedRouteCIDRs4: [String] {
        !inet4RouteRange.isEmpty ? inet4RouteRange : inet4RouteAddress
    }
    /// Included IPv6 route CIDRs; same rule as `includedRouteCIDRs4`.
    public var includedRouteCIDRs6: [String] {
        !inet6RouteRange.isEmpty ? inet6RouteRange : inet6RouteAddress
    }
    /// Excluded IPv4 routes for the NE settings. Empty when the
    /// route ranges are in use: BuildAutoRouteRanges already
    /// subtracted the excludes from them, so handing the excludes
    /// to NE again would be a second, wrong application.
    public var excludedRouteCIDRs4: [String] {
        inet4RouteRange.isEmpty ? inet4RouteExcludeAddress : []
    }
    /// Excluded IPv6 routes; same rule as `excludedRouteCIDRs4`.
    public var excludedRouteCIDRs6: [String] {
        inet6RouteRange.isEmpty ? inet6RouteExcludeAddress : []
    }
}

/// Prefix length of a textual netmask, split out of the Darwin
/// interface enumeration (PacketTunnel/LibboxBridgeImpl.swift) so
/// the parsing is testable on Linux. getnameinfo renders IPv6
/// netmasks in canonical — possibly compressed — form
/// ("ffff:ffff::"), and a naive split on ":" yields empty groups
/// there; the compressed form is expanded before counting bits.
public enum NetmaskPrefixLength {
    public static func ipv4(_ mask: String) -> Int? {
        let parts = mask.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }
        return parts.reduce(0) { $0 + $1.nonzeroBitCount }
    }

    public static func ipv6(_ mask: String) -> Int? {
        // Expand "::" (at most one per address): the groups it
        // stands for are all-zero in a netmask's rendering, but the
        // group count must total 8 before bits are counted.
        let halves = mask.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        func groups(_ text: String) -> [String] {
            text.isEmpty ? [] : text.split(separator: ":").map(String.init)
        }
        var parts = groups(halves[0])
        if halves.count == 2 {
            let tail = groups(halves[1])
            guard parts.count + tail.count <= 8 else { return nil }
            parts += Array(repeating: "0", count: 8 - parts.count - tail.count) + tail
        }
        guard parts.count == 8 else { return nil }
        var bits = 0
        for part in parts {
            guard let value = UInt16(part, radix: 16) else { return nil }
            bits += value.nonzeroBitCount
        }
        return bits
    }
}
