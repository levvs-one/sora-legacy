import XCTest
@testable import SoraLegacyCore

final class TunConfigTests: XCTestCase {
    private func inbounds(_ json: String) throws -> [[String: Any]] {
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        return root["inbounds"] as? [[String: Any]] ?? []
    }

    func testInjectsExactlyOneTunWithAndroidAddresses() throws {
        let rendered = #"{"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":7890}],"outbounds":[]}"#
        let out = try TunConfig.injectTunInbound(configJSON: rendered, mtu: 1500, strictRoute: false)
        let list = try inbounds(out)
        let tuns = list.filter { $0["type"] as? String == "tun" }
        XCTAssertEqual(tuns.count, 1)
        XCTAssertEqual(list.count, 2)
        let tun = try XCTUnwrap(tuns.first)
        XCTAssertEqual(tun["tag"] as? String, "tun-in")
        // Verbatim Android constants (TunConfig.kt).
        XCTAssertEqual(tun["address"] as? [String], ["172.19.0.1/30", "fdfe:dcba:9876::1/126"])
        XCTAssertEqual(tun["mtu"] as? Int, 1500)
        XCTAssertEqual(tun["auto_route"] as? Bool, true)
        XCTAssertEqual(tun["strict_route"] as? Bool, false)
        XCTAssertEqual(tun["stack"] as? String, "mixed")
    }

    func testExistingTunIsLeftUntouched() throws {
        let rendered = #"{"inbounds":[{"type":"tun","tag":"mine","address":["10.0.0.1/30"]}]}"#
        let out = try TunConfig.injectTunInbound(configJSON: rendered)
        XCTAssertEqual(out, rendered)
    }

    func testMissingInboundsArrayIsCreated() throws {
        let out = try TunConfig.injectTunInbound(configJSON: #"{"outbounds":[]}"#)
        XCTAssertEqual(try inbounds(out).filter { $0["type"] as? String == "tun" }.count, 1)
    }

    func testStrictRouteAndMTUPassThrough() throws {
        let out = try TunConfig.injectTunInbound(configJSON: "{}", mtu: 1400, strictRoute: true)
        let tun = try XCTUnwrap(try inbounds(out).first)
        XCTAssertEqual(tun["mtu"] as? Int, 1400)
        XCTAssertEqual(tun["strict_route"] as? Bool, true)
    }

    func testInvalidJSONThrows() {
        XCTAssertThrowsError(try TunConfig.injectTunInbound(configJSON: "not json")) {
            XCTAssertEqual($0 as? TunConfig.TunConfigError, .notJSON)
        }
        XCTAssertThrowsError(try TunConfig.injectTunInbound(configJSON: "[]")) {
            XCTAssertEqual($0 as? TunConfig.TunConfigError, .rootNotObject)
        }
    }
}
