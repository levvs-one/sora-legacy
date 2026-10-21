import XCTest
@testable import SoraLegacyMacCore

final class CoreTests: XCTestCase {

    func testFloor() {
        XCTAssertFalse(Capabilities.meetsFloor(major: 10, minor: 12))
        XCTAssertTrue(Capabilities.meetsFloor(major: 10, minor: 13))
        XCTAssertTrue(Capabilities.meetsFloor(major: 11, minor: 0))
        XCTAssertTrue(Capabilities.meetsFloor(major: 14, minor: 2))
        XCTAssertFalse(Capabilities.meetsFloor(major: 9, minor: 9))
    }

    func testMatrixIsHonest() {
        let rows = Capabilities.matrix(systemVersion: "10.13.6")
        XCTAssertEqual(rows.count, 3)
        let ne = rows.first { $0.mode == .networkExtension }
        XCTAssertEqual(ne?.availability, "not-implemented")
        let tun = rows.first { $0.mode == .tunViaService }
        XCTAssertTrue(tun?.cost.contains("NOT enforced") ?? false,
                      "the TUN row must state the kill-switch limit")
        XCTAssertTrue(tun?.cost.contains("verify-on-mac") ?? false,
                      "nothing on macOS may claim hardware verification from this tree")
    }

    func testServiceFloor() {
        // Measured from the daemon/helper Mach-O load commands.
        XCTAssertFalse(Capabilities.serviceAvailable(major: 10, minor: 13))
        XCTAssertFalse(Capabilities.serviceAvailable(major: 11, minor: 7))
        XCTAssertTrue(Capabilities.serviceAvailable(major: 12, minor: 0))
        XCTAssertTrue(Capabilities.serviceAvailable(major: 26, minor: 0))
    }

    func testStatusDecoding() throws {
        let json = """
        {"state":"CONNECTED","session_id":"s1","core_version":"dev",
         "platform":"darwin/arm64",
         "local_proxy":{"host":"127.0.0.1","port":7890},
         "engines":[{"kind":"sing-box","installed":true,"version":"1.14.3"}],
         "kill_switch_requested":true,"kill_switch_enforced":false}
        """.data(using: .utf8)!
        let status = try JSONDecoder().decode(HelperStatus.self, from: json)
        XCTAssertTrue(status.isConnected)
        XCTAssertEqual(status.localProxy?.port, 7890)
        XCTAssertEqual(status.engines?.first?.kind, "sing-box")
        XCTAssertEqual(status.killSwitchEnforced, false)
    }

    func testCatalogDecoding() throws {
        // Shape is the helper's engineinfo output (core/mobileapi).
        let json = """
        {"engines":[{"kind":"sing-box","min_version":"1.14.0",
         "protocols":["vless"],"features":["tls_fragment"]}],
         "default_preference":["sing-box","xray","mihomo"]}
        """.data(using: .utf8)!
        let catalog = try JSONDecoder().decode(EngineCatalog.self, from: json)
        XCTAssertEqual(catalog.engines.first?.features, ["tls_fragment"])
        XCTAssertEqual(catalog.defaultPreference.count, 3)
    }

    func testServersDecoding() throws {
        let json = """
        {"servers":[{"id":"a","name":"Local","protocol":"socks5",
         "host":"127.0.0.1","port":1080}],"selected":"a","source":"daemon"}
        """.data(using: .utf8)!
        let doc = try JSONDecoder().decode(ServersDocument.self, from: json)
        XCTAssertEqual(doc.servers.first?.displayName, "Local")
        XCTAssertEqual(doc.selected, "a")
    }

    func testParseProxyOutput() {
        let out = "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\nAuthenticated Proxy Enabled: 0\n"
        let parsed = SystemProxyController.parseProxy(out)
        XCTAssertTrue(parsed.enabled)
        XCTAssertEqual(parsed.server, "127.0.0.1")
        XCTAssertEqual(parsed.port, 7890)
        let off = SystemProxyController.parseProxy("Enabled: No\nServer:\nPort: 0\n")
        XCTAssertFalse(off.enabled)
    }

    func testHelperMissingIsHonest() {
        let client = HelperClient(helperPath: "/nonexistent/sora-ctl")
        if case .success = client.status() {
            XCTFail("a missing helper must fail, not fake a status")
        }
    }
}
