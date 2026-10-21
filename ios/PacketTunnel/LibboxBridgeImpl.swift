import Foundation
import Network
import SoraLegacyCore

#if canImport(Libbox)
import Libbox

// Real bridge over the generated Libbox framework (upstream
// sing-box 1.12.12, experimental/libbox). Every Go signature used
// here was read line-by-line from the pin's sources in
// ~/workspace/.legplat/src/sing-box-1.12.12/experimental/libbox/:
//
//   Setup(options *SetupOptions) error                    setup.go
//   NewService(config, platformInterface) (*BoxService,   service.go
//     error); (*BoxService).Start() error; .Close() error
//   CheckConfig(configContent string) error               config.go
//   Version() string                                       setup.go
//   GetTunnelFileDescriptor() int32                       tun_darwin.go
//   PlatformInterface — 18 methods                        platform.go
//   LocalDNSTransport — Raw/Lookup/Exchange               dns.go
//   TunOptions — 19 getters                               tun.go
//   StringIterator — Len/HasNext/Next                     iterator.go
//
// What only a Mac can settle is gomobile's generated Swift spelling
// of those signatures in Libbox.h — every generated spelling used
// below carries TODO(verify-on-mac) at its site, and BUILD-MAC.md
// §7 is the reconciliation checklist. Nothing outside this file
// references Libbox types.

/// Iterator plumbing (iterator.go contract: destructive Next(),
/// HasNext(), plus Len() on StringIterator).
// TODO(verify-on-mac): the protocol name
// LibboxStringIteratorProtocol and the len/hasNext/next method
// spellings are generated (iterator.go).
final class StringIteratorImpl: NSObject, LibboxStringIteratorProtocol {
    private var items: [String]
    init(_ items: [String]) { self.items = items }
    func len() -> Int32 { Int32(items.count) }
    func hasNext() -> Bool { !items.isEmpty }
    func next() -> String { items.isEmpty ? "" : items.removeFirst() }
}

// TODO(verify-on-mac): the protocol name
// LibboxNetworkInterfaceIteratorProtocol and its hasNext/next
// spellings are generated (platform.go returns this iterator type
// from GetInterfaces).
final class NetworkInterfaceIteratorImpl: NSObject, LibboxNetworkInterfaceIteratorProtocol {
    private var items: [LibboxNetworkInterface]
    init(_ items: [LibboxNetworkInterface]) { self.items = items }
    func hasNext() -> Bool { !items.isEmpty }
    func next() -> LibboxNetworkInterface? { items.isEmpty ? nil : items.removeFirst() }
}

/// Local DNS transport (dns.go): Raw()==false, so libbox only calls
/// Lookup and expects addresses back through ExchangeContext.Success
/// as newline-joined IPs — the Android client's LocalDnsTransport.kt
/// makes the same choice with the system resolver; here the resolver
/// is getaddrinfo (the platform's own path on Darwin).
// TODO(verify-on-mac): the protocol name
// LibboxLocalDNSTransportProtocol and the raw/lookup/exchange
// method spellings are generated (dns.go), as are
// LibboxExchangeContext's success/errorCode methods used inside
// lookup/exchange below.
final class LocalDNSTransportImpl: NSObject, LibboxLocalDNSTransportProtocol {
    func raw() -> Bool { false }

    func lookup(_ ctx: LibboxExchangeContext?, network: String, domain: String) {
        guard let ctx else { return }
        var hints = addrinfo()
        hints.ai_family = network == "ip4" ? AF_INET : (network == "ip6" ? AF_INET6 : AF_UNSPEC)
        hints.ai_socktype = SOCK_DGRAM
        var result: UnsafeMutablePointer<addrinfo>?
        let host = domain.hasSuffix(".") ? String(domain.dropLast()) : domain
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else {
            ctx.errorCode(2) // SERVFAIL — honest failure, no fake answer
            return
        }
        defer { freeaddrinfo(result) }
        var addresses: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen,
                           &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                let text = String(cString: buffer)
                // Go parses these with netip: an IPv6 zone ("%en0")
                // would be rejected — strip it, same lesson as the
                // Android client's zoneFreeHostAddress.
                addresses.append(text.split(separator: "%").first.map(String.init) ?? text)
            }
            cursor = info.pointee.ai_next
        }
        ctx.success(addresses.joined(separator: "\n"))
    }

    func exchange(_ ctx: LibboxExchangeContext?, message: Data?) {
        // Unreachable by contract while raw()==false; fail loudly
        // rather than silently (mirrors the Android throw).
        ctx?.errorCode(4) // NOTIMP
    }
}

extension PlatformInterfaceImpl {
    /// TunOptions (tun.go:14-34 — exactly 19 getters, counted in the
    /// interface) drained into the core's value snapshot: every one
    /// of the 19, in the interface's order. GetDNSServerAddress
    /// throws when the first IPv4 address is a /32 — our injected
    /// /30 keeps that unreachable, and a throw here degrades to
    /// "no hijack DNS", not a crash.
    // TODO(verify-on-mac): every getter spelling on
    // LibboxTunOptionsProtocol below is generated (tun.go),
    // including the four drained last-but-two; also
    // LibboxStringBoxProtocol's `value` property
    // (GetDNSServerAddress's return) and, in drainPrefixes,
    // LibboxRoutePrefixProtocol's string() (tun.go RoutePrefix).
    static func snapshot(of options: LibboxTunOptionsProtocol) -> TunOptionsSnapshot {
        var snap = TunOptionsSnapshot()
        snap.inet4Address = drainPrefixes(options.getInet4Address())
        snap.inet6Address = drainPrefixes(options.getInet6Address())
        snap.dnsServerAddress = try? options.getDNSServerAddress()?.value
        snap.mtu = options.getMTU()
        snap.autoRoute = options.getAutoRoute()
        snap.strictRoute = options.getStrictRoute()
        snap.inet4RouteAddress = drainPrefixes(options.getInet4RouteAddress())
        snap.inet6RouteAddress = drainPrefixes(options.getInet6RouteAddress())
        snap.inet4RouteExcludeAddress = drainPrefixes(options.getInet4RouteExcludeAddress())
        snap.inet6RouteExcludeAddress = drainPrefixes(options.getInet6RouteExcludeAddress())
        // The wrapper's BuildAutoRouteRanges result (service.go):
        // the effective included routes — the provider builds the
        // NE settings from these (see TunOptionsSnapshot's helpers),
        // they are not decorative.
        snap.inet4RouteRange = drainPrefixes(options.getInet4RouteRange())
        snap.inet6RouteRange = drainPrefixes(options.getInet6RouteRange())
        // Android package filters: drained and kept in the snapshot,
        // but not applicable on iOS — per-app filtering is MDM-only,
        // so the provider refuses them loudly instead of applying
        // or silently dropping them (see TunOptionsSnapshot).
        snap.includePackage = drainStrings(options.getIncludePackage())
        snap.excludePackage = drainStrings(options.getExcludePackage())
        snap.httpProxyEnabled = options.isHTTPProxyEnabled()
        snap.httpProxyServer = options.getHTTPProxyServer() ?? ""
        snap.httpProxyServerPort = options.getHTTPProxyServerPort()
        snap.httpProxyBypassDomain = drainStrings(options.getHTTPProxyBypassDomain())
        snap.httpProxyMatchDomain = drainStrings(options.getHTTPProxyMatchDomain())
        return snap
    }

    static func drainPrefixes(_ iterator: LibboxRoutePrefixIteratorProtocol?) -> [String] {
        guard let iterator else { return [] }
        var out: [String] = []
        while iterator.hasNext() {
            if let prefix = iterator.next() { out.append(prefix.string()) }
        }
        return out
    }
}

/// The PlatformInterface implementation: all 18 methods of
/// platform.go, in the pin's order. Capabilities iOS does not expose
/// are answered honestly (throw / false / empty), never emulated.
final class PlatformInterfaceImpl: NSObject, LibboxPlatformInterfaceProtocol {
    weak var provider: PacketTunnelProvider?
    private var monitor: NWPathMonitor?
    private var listener: LibboxInterfaceUpdateListenerProtocol?

    // 1. LocalDNSTransport() LocalDNSTransport
    func localDNSTransport() -> LibboxLocalDNSTransportProtocol? { LocalDNSTransportImpl() }

    // 2. UsePlatformAutoDetectInterfaceControl() bool — iOS routes
    // the extension's own sockets outside its tunnel by design, so
    // the fd-protect dance Android needs (VpnService.protect) has no
    // iOS counterpart; SFI answers false too.
    func usePlatformAutoDetectInterfaceControl() -> Bool { false }

    // 3. AutoDetectInterfaceControl(fd) error — unreachable while
    // (2) is false; a no-op success, not an emulation of protect().
    func autoDetectInterfaceControl(_ fd: Int32) throws {}

    // 4. OpenTun(options) (int32, error) — the TUN is created by
    // NetworkExtension from the settings the provider installs in
    // startTunnel BEFORE the service starts; the fd of that utun is
    // exactly what the pin's own darwin helper finds
    // (tun_darwin.go, "kanged from wireguard-apple").
    func openTun(_ options: LibboxTunOptionsProtocol?) throws -> Int32 {
        guard let provider, let options else {
            throw LibboxBridgeError.openTunFailed("no provider/options")
        }
        // Building the settings from TunOptions is the provider's
        // job (it owns setTunnelNetworkSettings); it blocks until
        // the settings are installed, then we hand back the fd.
        try provider.applyTunOptions(Self.snapshot(of: options))
        // TODO(verify-on-mac): generated spelling of
        // GetTunnelFileDescriptor (tun_darwin.go).
        let fd = LibboxGetTunnelFileDescriptor()
        if fd < 0 { throw LibboxBridgeError.openTunFailed("no utun fd found") }
        return fd
    }

    // 5. WriteLog(message)
    func writeLog(_ message: String?) {
        if let message { NSLog("[libbox] %@", message) }
    }

    // 6. UseProcFS() bool — no /proc on iOS.
    func useProcFS() -> Bool { false }

    // 7-9. Connection owner / package mapping: iOS exposes no public
    // API for any of these (no uid<->package model in the sandbox).
    // Throwing is the honest answer; the engine degrades to "unknown
    // owner" instead of receiving an invented uid.
    func findConnectionOwner(_ ipProtocol: Int32, sourceAddress: String?, sourcePort: Int32,
                             destinationAddress: String?, destinationPort: Int32) throws -> Int32 {
        throw LibboxBridgeError.startFailed("findConnectionOwner: no iOS API")
    }
    func packageName(byUid uid: Int32) throws -> String {
        throw LibboxBridgeError.startFailed("packageNameByUid: no iOS API")
    }
    func uid(byPackageName packageName: String?) throws -> Int32 {
        throw LibboxBridgeError.startFailed("uidByPackageName: no iOS API")
    }

    // 10-11. Default interface monitor over NWPathMonitor.
    func startDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
        self.listener = listener
        let monitor = NWPathMonitor()
        self.monitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            self?.report(path)
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        report(monitor.currentPath)
    }
    func closeDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
        monitor?.cancel()
        monitor = nil
        self.listener = nil
    }
    private func report(_ path: NWPath) {
        guard let listener else { return }
        let iface = path.availableInterfaces.first
        // TODO(verify-on-mac): the generated spelling of
        // InterfaceUpdateListener.updateDefaultInterface
        // (platform.go: name, index, isExpensive, isConstrained).
        listener.updateDefaultInterface(
            iface?.name ?? "",
            interfaceIndex: Int32(iface?.index ?? -1),
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained)
    }

    // 12. GetInterfaces() — getifaddrs enumeration: names, CIDR
    // addresses (zone-stripped: libbox parses them with
    // netip.MustParsePrefix, service.go — a zone would panic the
    // engine), flags, type by interface kind/name. MTU: Darwin
    // does carry it — ifi_mtu in the AF_LINK record's ifa_data —
    // but this loop does not decode AF_LINK records, so MTU stays
    // 0 = unknown rather than a guessed value (decoding ifi_mtu
    // is a verify-on-mac candidate, BUILD-MAC.md §7). DNS servers
    // are not exposed per interface by getifaddrs and stay empty
    // (documented in BUILD-MAC.md §7 as a known gap, not a
    // fabricated value).
    func getInterfaces() throws -> LibboxNetworkInterfaceIteratorProtocol? {
        NetworkInterfaceIteratorImpl(Self.enumerateInterfaces())
    }

    static func enumerateInterfaces() -> [LibboxNetworkInterface] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var byName: [String: LibboxNetworkInterface] = [:]
        var order: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let ifa = current.pointee
            let name = String(cString: ifa.ifa_name)
            if byName[name] == nil {
                // TODO(verify-on-mac): the generated property
                // setters of LibboxNetworkInterface (platform.go:
                // Index, MTU, Name, Flags, Type, Metered, and
                // Addresses/DNSServer below).
                let item = LibboxNetworkInterface()
                item.index = Int32(if_nametoindex(name))
                item.mtu = 0
                item.name = name
                item.flags = Int32(bitPattern: UInt32(ifa.ifa_flags))
                item.type = interfaceType(name: name)
                item.metered = false
                byName[name] = item
                order.append(name)
            }
            if let address = sockaddrString(ifa.ifa_addr), let mask = sockaddrString(ifa.ifa_netmask),
               let prefix = prefixLength(mask: mask, isV6: address.contains(":")) {
                let clean = address.split(separator: "%").first.map(String.init) ?? address
                appendAddress(byName[name], "\(clean)/\(prefix)")
            }
            cursor = ifa.ifa_next
        }
        return order.compactMap { byName[$0] }
    }

    private static func appendAddress(_ item: LibboxNetworkInterface?, _ cidr: String) {
        // TODO(verify-on-mac): generated iterator/property spelling
        // for NetworkInterface.Addresses (platform.go: StringIterator).
        guard let item else { return }
        let existing = drainStrings(item.addresses)
        item.addresses = StringIteratorImpl(existing + [cidr])
        if item.dnsServer == nil { item.dnsServer = StringIteratorImpl([]) }
    }

    private static func drainStrings(_ iterator: LibboxStringIteratorProtocol?) -> [String] {
        guard let iterator else { return [] }
        var out: [String] = []
        while iterator.hasNext() { out.append(iterator.next()) }
        return out
    }

    private static func interfaceType(name: String) -> Int32 {
        // platform.go constants: WIFI/CELLULAR/ETHERNET/OTHER come
        // from sing-box constant.InterfaceType*.
        // TODO(verify-on-mac): the generated spellings of the
        // LibboxInterfaceType* constants below.
        if name.hasPrefix("en") { return LibboxInterfaceTypeWIFI }
        if name.hasPrefix("pdp_ip") { return LibboxInterfaceTypeCellular }
        if name.hasPrefix("bridge") || name.hasPrefix("eth") { return LibboxInterfaceTypeEthernet }
        return LibboxInterfaceTypeOther
    }

    private static func sockaddrString(_ pointer: UnsafeMutablePointer<sockaddr>?) -> String? {
        guard let pointer else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let length = pointer.pointee.sa_family == sa_family_t(AF_INET6)
            ? socklen_t(MemoryLayout<sockaddr_in6>.size) : socklen_t(MemoryLayout<sockaddr_in>.size)
        guard getnameinfo(pointer, length, &buffer, socklen_t(buffer.count),
                          nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: buffer)
    }

    private static func prefixLength(mask: String, isV6: Bool) -> Int? {
        // The parsing lives in the core (NetmaskPrefixLength)
        // because the IPv6 form is a real trap: getnameinfo renders
        // the netmask compressed ("ffff:ffff::"), where splitting
        // on ":" yields empty groups — the previous inline version
        // returned nil there and the interface's address was
        // silently dropped from GetInterfaces. Unit-tested on
        // Linux (NetmaskPrefixLengthTests).
        isV6 ? NetmaskPrefixLength.ipv6(mask) : NetmaskPrefixLength.ipv4(mask)
    }

    // 13. UnderNetworkExtension() — true: this code only ever runs
    // inside the packet-tunnel extension.
    func underNetworkExtension() -> Bool { true }

    // 14. IncludeAllNetworks() — false: the client does not request
    // the include-all-networks entitlement behaviour.
    func includeAllNetworks() -> Bool { false }

    // 15. ReadWIFIState() — public iOS API does not expose SSID/BSSID
    // to a network extension (NEHotspotNetwork is app-side and
    // entitlement/location gated). Returning nil is the contract's
    // "no state" answer (service.go tolerates nil); the app-side
    // fetch is a verify-on-mac item, not faked here.
    func readWIFIState() -> LibboxWIFIState? { nil }

    // 16. SystemCertificates() — iOS has no public API to enumerate
    // the system trust store from an extension (SecTrustSettings is
    // macOS-only). Empty iterator is the honest answer; if the
    // engine then distrusts a chain, that surfaces as a TLS error,
    // not as a silently wrong root set. Verify-on-mac item.
    func systemCertificates() -> LibboxStringIteratorProtocol? { StringIteratorImpl([]) }

    // 17. ClearDNSCache() — no public flush API on iOS; the contract
    // returns void and upstream clients no-op where the platform
    // offers nothing. Documented, not emulated.
    func clearDNSCache() {}

    // 18. SendNotification(notification) — an extension cannot post
    // UNUserNotifications for engine events reliably (no granted
    // authorization of its own); the honest behaviour is to log the
    // notification so it is not silently dropped, and let the app
    // surface state it polls itself.
    func sendNotification(_ notification: LibboxNotification?) throws {
        if let notification {
            NSLog("[libbox notification] %@ %@", notification.title ?? "", notification.body ?? "")
        }
    }
}

/// LibboxBridge over BoxService (service.go of the pin).
final class LibboxBridgeImpl: LibboxBridge {
    private var service: LibboxBoxService?
    private var platform: PlatformInterfaceImpl?
    private var setupDone = false
    weak var provider: PacketTunnelProvider?

    func setup(basePath: String, workingPath: String, tempPath: String) throws {
        if setupDone { return }
        // TODO(verify-on-mac): SetupOptions generated property
        // spellings (setup.go fields: BasePath, WorkingPath,
        // TempPath, Username, IsTVOS, FixAndroidStack).
        let options = LibboxSetupOptions()
        options.basePath = basePath
        options.workingPath = workingPath
        options.tempPath = tempPath
        options.username = ""
        options.isTVOS = false
        // FixAndroidStack is the Android stack escape hatch
        // (setup.go); on iOS it stays false.
        options.fixAndroidStack = false
        var error: NSError?
        // TODO(verify-on-mac): the generated name LibboxSetup
        // itself (setup.go: Setup(options) error).
        LibboxSetup(options, &error)
        if let error { throw LibboxBridgeError.startFailed(error.localizedDescription) }
        setupDone = true
    }

    func startService(configJSON: String) throws {
        var error: NSError?
        // Preflight (config.go CheckConfig): refuse before creating
        // a service, so a bad config fails as invalidConfig.
        // TODO(verify-on-mac): the generated name LibboxCheckConfig
        // itself (config.go: CheckConfig(configContent) error).
        LibboxCheckConfig(configJSON, &error)
        if let error { throw LibboxBridgeError.invalidConfig(error.localizedDescription) }
        let platform = PlatformInterfaceImpl()
        platform.provider = provider
        self.platform = platform
        // TODO(verify-on-mac): NewService generated spelling
        // (service.go: NewService(configContent, platformInterface)).
        let created = LibboxNewService(configJSON, platform, &error)
        if let error { throw LibboxBridgeError.startFailed(error.localizedDescription) }
        guard let created else { throw LibboxBridgeError.frameworkMissing }
        // TODO(verify-on-mac): the generated spelling of
        // BoxService.Start (service.go).
        created.start(&error)
        if let error { throw LibboxBridgeError.startFailed(error.localizedDescription) }
        service = created
    }

    func stopService() throws {
        var error: NSError?
        // TODO(verify-on-mac): the generated spelling of
        // BoxService.Close (service.go).
        service?.close(&error)
        service = nil
        platform = nil
        if let error { throw LibboxBridgeError.startFailed(error.localizedDescription) }
    }

    var isRunning: Bool { service != nil }
    // TODO(verify-on-mac): the generated spellings of the
    // BoxService power methods below (service_pause.go: Pause /
    // Wake / ResetNetwork).
    func pause() { service?.pause() }
    func wake() { service?.wake() }
    func resetNetwork() { service?.resetNetwork() }

    func version() -> String {
        // TODO(verify-on-mac): the generated name LibboxVersion
        // (setup.go: Version() string — no error return).
        LibboxVersion()
    }
}
#endif
