import XCTest
@testable import SoraLegacyCore

final class StoreAndAPITests: XCTestCase {
    private var suiteName = ""
    private func makeStore() -> (ServerStore, InMemorySecrets) {
        suiteName = "test-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        let secrets = InMemorySecrets()
        return (ServerStore(defaults: defaults, secrets: secrets), secrets)
    }

    private var sample: Server {
        Server(id: "s1", name: "NL", protocol: "vless", server: "example.com", port: 443,
               transport: "tcp", security: "reality", credentialRef: "mobile:s1",
               credentials: ["uuid": "00000000-0000-0000-0000-000000000000"])
    }

    func testCredentialsLiveInSecretsNotInDefaults() throws {
        let (store, secrets) = makeStore()
        try store.saveServers([sample])
        XCTAssertNotNil(secrets.secret(forKey: "s1"))
        let data = try XCTUnwrap(UserDefaults(suiteName: suiteName)?.data(forKey: ServerStore.serversKey))
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("00000000-0000"))
        XCTAssertEqual(store.servers().first?.credentials?["uuid"], "00000000-0000-0000-0000-000000000000")
    }

    func testSelectionAndDefaultsMirrorAndroid() throws {
        let (store, _) = makeStore()
        XCTAssertEqual(store.localPort(), 7890)
        XCTAssertEqual(store.tunMTU(), 1500)
        XCTAssertFalse(store.strictRoute())
        try store.saveServers([sample])
        store.select(id: "s1")
        XCTAssertEqual(store.selected()?.id, "s1")
        try store.removeServer(id: "s1")
        XCTAssertNil(store.selectedID())
        XCTAssertTrue(store.servers().isEmpty)
    }

    func testExchangeRoundTrip() {
        let (store, _) = makeStore()
        let exchange = TunnelConfigExchange(configJSON: "{}", serverName: "NL", localPort: 7890)
        store.saveExchange(exchange)
        XCTAssertEqual(store.exchange(), exchange)
        XCTAssertEqual(TunnelConfigExchange(providerDictionary: exchange.providerDictionary), exchange)
    }

    func testMobileAPIJSONShapes() throws {
        let servers = try MobileAPIJSON.decodeServers(
            #"[{"id":"a","protocol":"trojan","server":"h","port":8443,"credentials":{"password":"p"}}]"#)
        XCTAssertEqual(servers.first?.port, 8443)
        XCTAssertEqual(servers.first?.credentials?["password"], "p")
        let plan = PlanDocument(localPort: 7890, servers: servers)
        let encoded = try MobileAPIJSON.encodePlan(plan)
        XCTAssertTrue(encoded.contains("\"local_port\":7890"))
        XCTAssertEqual(try MobileAPIJSON.decodePlan(encoded).servers.count, 1)
        let info = MobileAPIJSON.decodeEngineInfo(
            #"{"engines":[{"kind":"sing-box","min_version":"1.12.12","protocols":["vless"],"features":[]}],"default_preference":["sing-box"]}"#)
        XCTAssertEqual(info.engines.first?.minVersion, "1.12.12")
    }
}

/// Fake MobileAPI proving the protocol seam carries the full flow
/// without the generated framework.
final class FakeMobileAPITests: XCTestCase {
    struct Fake: MobileAPI {
        func importLinks(_ text: String) throws -> [Server] {
            [Server(id: "x", protocol: "vless", server: "h", port: 443)]
        }
        func parseSubscription(_ body: Data) throws -> [Server] { try importLinks("") }
        func buildPlan(_ plan: PlanDocument) throws -> PlanDocument { plan }
        func renderSingBoxConfig(_ plan: PlanDocument) throws -> String { "{}" }
        func engineInfo() -> EngineInfo { EngineInfo(engines: [], defaultPreference: []) }
    }
    func testFlowThroughSeam() throws {
        let api: MobileAPI = Fake()
        let servers = try api.importLinks("vless://…")
        let config = try api.renderSingBoxConfig(PlanDocument(servers: servers))
        let injected = try TunConfig.injectTunInbound(configJSON: config)
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(injected.utf8)) as? [String: Any])
        let tun = try XCTUnwrap((root["inbounds"] as? [[String: Any]])?.first)
        XCTAssertEqual(tun["address"] as? [String], [TunConfig.inet4Address, TunConfig.inet6Address])
    }
}
