import XCTest
@testable import SoraLegacyCore

/// TunOptionsSnapshot: the pin's TunOptions interface
/// (experimental/libbox/tun.go:14-34) has exactly 19 getters, and
/// the snapshot is the value type all 19 drain into. The drain
/// itself lives in PacketTunnel/LibboxBridgeImpl.swift (it needs
/// the generated framework), so what is pinned here is the shape
/// the drain fills — every getter has a field — plus the pure
/// route-selection and netmask logic the provider builds
/// NEPacketTunnelNetworkSettings from.
final class TunOptionsTests: XCTestCase {

    func testSnapshotHasAFieldForEveryTunOptionsGetter() {
        var snap = TunOptionsSnapshot()
        // GetInet4Address / GetInet6Address
        snap.inet4Address = ["172.19.0.1/30"]
        snap.inet6Address = ["fdfe:dcba:9876::1/126"]
        // GetDNSServerAddress
        snap.dnsServerAddress = "172.19.0.2"
        // GetMTU / GetAutoRoute / GetStrictRoute
        snap.mtu = 1500
        snap.autoRoute = true
        snap.strictRoute = true
        // GetInet4/6RouteAddress
        snap.inet4RouteAddress = ["1.0.0.0/8"]
        snap.inet6RouteAddress = ["200::/7"]
        // GetInet4/6RouteExcludeAddress
        snap.inet4RouteExcludeAddress = ["10.0.0.0/8"]
        snap.inet6RouteExcludeAddress = ["fe80::/10"]
        // GetInet4/6RouteRange
        snap.inet4RouteRange = ["0.0.0.0/5"]
        snap.inet6RouteRange = ["::/1"]
        // GetIncludePackage / GetExcludePackage — stored, and on
        // iOS refused loudly by the provider (MDM-only capability),
        // never applied.
        snap.includePackage = ["com.example.app"]
        snap.excludePackage = ["com.example.other"]
        // IsHTTPProxyEnabled / GetHTTPProxyServer / …Port /
        // GetHTTPProxyBypassDomain / GetHTTPProxyMatchDomain
        snap.httpProxyEnabled = true
        snap.httpProxyServer = "127.0.0.1"
        snap.httpProxyServerPort = 8080
        snap.httpProxyBypassDomain = ["localhost"]
        snap.httpProxyMatchDomain = [""]

        let copy = snap
        XCTAssertEqual(copy, snap) // Equatable covers every field above
        XCTAssertEqual(snap.inet4RouteRange, ["0.0.0.0/5"])
        XCTAssertEqual(snap.inet6RouteRange, ["::/1"])
        XCTAssertEqual(snap.includePackage, ["com.example.app"])
        XCTAssertEqual(snap.excludePackage, ["com.example.other"])
    }

    func testRouteRangesWinOverRouteAddressesAndExcludesAreNotReapplied() {
        var snap = TunOptionsSnapshot()
        snap.inet4RouteAddress = ["1.0.0.0/8"]
        snap.inet4RouteExcludeAddress = ["10.0.0.0/8"]
        // What BuildAutoRouteRanges hands over already has the
        // excludes subtracted from the route addresses.
        snap.inet4RouteRange = ["1.0.0.0/8", "11.0.0.0/8"]
        XCTAssertEqual(snap.includedRouteCIDRs4, ["1.0.0.0/8", "11.0.0.0/8"])
        XCTAssertEqual(snap.excludedRouteCIDRs4, [])
    }

    func testWithoutRangesRouteAddressesAndExcludesPassThrough() {
        var snap = TunOptionsSnapshot()
        snap.inet6RouteAddress = ["200::/7"]
        snap.inet6RouteExcludeAddress = ["fe80::/10"]
        XCTAssertEqual(snap.includedRouteCIDRs6, ["200::/7"])
        XCTAssertEqual(snap.excludedRouteCIDRs6, ["fe80::/10"])
    }

    func testEmptySnapshotMeansNoExplicitRoutes() {
        let snap = TunOptionsSnapshot()
        XCTAssertTrue(snap.includedRouteCIDRs4.isEmpty)
        XCTAssertTrue(snap.includedRouteCIDRs6.isEmpty)
        XCTAssertTrue(snap.excludedRouteCIDRs4.isEmpty)
        XCTAssertTrue(snap.excludedRouteCIDRs6.isEmpty)
    }
}

/// Netmask parsing behind GetInterfaces: the IPv6 form arrives
/// from getnameinfo already compressed, which the previous inline
/// parser (split on ":", UInt16 per group) failed on, silently
/// dropping the interface's address.
final class NetmaskPrefixLengthTests: XCTestCase {
    func testIPv6Uncompressed() {
        XCTAssertEqual(NetmaskPrefixLength.ipv6("ffff:ffff:ffff:ffff:0:0:0:0"), 64)
        XCTAssertEqual(NetmaskPrefixLength.ipv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 128)
        XCTAssertEqual(NetmaskPrefixLength.ipv6("ffff:ff00:0:0:0:0:0:0"), 24)
    }

    func testIPv6Compressed() {
        XCTAssertEqual(NetmaskPrefixLength.ipv6("ffff:ffff:ffff:ffff::"), 64)
        XCTAssertEqual(NetmaskPrefixLength.ipv6("ffff:ffff::"), 32)
        XCTAssertEqual(NetmaskPrefixLength.ipv6("::"), 0)
        XCTAssertEqual(NetmaskPrefixLength.ipv6("ff00::"), 8)
    }

    func testIPv6Invalid() {
        XCTAssertNil(NetmaskPrefixLength.ipv6("ffff:ffff"))            // too few groups, no "::"
        XCTAssertNil(NetmaskPrefixLength.ipv6("ffff::ffff::"))         // two "::"
        XCTAssertNil(NetmaskPrefixLength.ipv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) // 9 groups
        XCTAssertNil(NetmaskPrefixLength.ipv6("zzzz::"))
        XCTAssertNil(NetmaskPrefixLength.ipv6(""))
    }

    func testIPv4() {
        XCTAssertEqual(NetmaskPrefixLength.ipv4("255.255.255.0"), 24)
        XCTAssertEqual(NetmaskPrefixLength.ipv4("255.255.240.0"), 20)
        XCTAssertEqual(NetmaskPrefixLength.ipv4("0.0.0.0"), 0)
        XCTAssertNil(NetmaskPrefixLength.ipv4("255.255.255"))
        XCTAssertNil(NetmaskPrefixLength.ipv4("255.255.255.256"))
    }
}

/// The bridge seam carries version() (the pin's Version(),
/// setup.go): a stub proves the protocol shape the PacketTunnel
/// implementation must satisfy.
final class LibboxBridgeSeamTests: XCTestCase {
    final class StubBridge: LibboxBridge {
        func setup(basePath: String, workingPath: String, tempPath: String) throws {}
        func startService(configJSON: String) throws {}
        func stopService() throws {}
        var isRunning: Bool { false }
        func pause() {}
        func wake() {}
        func resetNetwork() {}
        func version() -> String { "1.12.12" }
    }
    func testVersionPassesThroughSeam() {
        let bridge: LibboxBridge = StubBridge()
        XCTAssertEqual(bridge.version(), "1.12.12")
    }
}
