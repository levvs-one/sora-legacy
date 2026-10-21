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
}

public enum LibboxBridgeError: Error, Equatable {
    case frameworkMissing
    case invalidConfig(String)
    case startFailed(String)
    case openTunFailed(String)
}

/// Value snapshot of libbox's TunOptions (tun.go of the pin: 20
/// getters) as the PacketTunnel provider consumes it to build
/// NEPacketTunnelNetworkSettings. Pure value type so the settings
/// construction is testable without the framework.
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
    public var httpProxyEnabled: Bool = false
    public var httpProxyServer: String = ""
    public var httpProxyServerPort: Int32 = 0
    public var httpProxyBypassDomain: [String] = []
    public var httpProxyMatchDomain: [String] = []
    public init() {}
}
