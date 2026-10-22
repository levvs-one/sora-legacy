import XCTest
@testable import SoraLegacyCore

/// Tier tests for the additive iOS 12 libbox tier (LEGACY-FULL
/// WS4). The fixtures are shaped like `core/mobileapi` renders
/// (the legacy renderer's own DNS/outbound shapes, read from
/// core/engine/singbox/render.go), NOT like the main tree's
/// generator output. External verification — the adapted fixtures
/// through the real sing-box 1.11.15 linux binary's `check` — is
/// driven by `testExportTierConfigsForExternalCheck` + the run
/// recorded in reports/LEGACY-FULL-4-IOS12.md §5.
final class EngineTierTests: XCTestCase {

    // MARK: Fixtures (legacy renderer shapes)

    /// DNS section exactly as core/engine/singbox/render.go emits
    /// it for a plan with an HTTPS resolver by IP, the system
    /// bootstrap and FakeIP mode on.
    private static let dnsNewFormat = """
        {"servers":[
          {"tag":"dns-1","type":"https","server":"1.1.1.1"},
          {"tag":"local","type":"local"},
          {"tag":"fakeip","type":"fakeip","inet4_range":"198.18.0.0/15"}
        ],"rules":[
          {"domain_suffix":["lan"],"server":"dns-1"},
          {"query_type":["A","AAAA"],"server":"fakeip"}
        ],"final":"dns-1","strategy":"ipv4_only"}
        """

    private static func config(dns: String, outbounds: String, endpoints: String? = nil) -> String {
        var s = """
        {"log":{"level":"warn","timestamp":false},
         "dns":\(dns),
         "inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":7890}],
         "outbounds":\(outbounds),
         "route":{"auto_detect_interface":true,"default_domain_resolver":{"server":"dns-1"},
                  "rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"}],
                  "final":"proxy"},
         "experimental":{"clash_api":{"external_controller":"127.0.0.1:9090","secret":""},
                         "cache_file":{"enabled":true,"path":"cache.db","store_fakeip":true}}}
        """
        if let endpoints {
            s = s.replacingOccurrences(of: "\"outbounds\":", with: "\"endpoints\":\(endpoints),\"outbounds\":")
        }
        return s
    }

    /// VLESS + REALITY + Vision, fingerprint chrome_pq_psk (in the
    /// 1.12 uTLS set, NOT in the 1.11 set), TLS fragment on.
    private static let vlessRealityFragment = config(dns: dnsNewFormat, outbounds: """
        [{"type":"vless","tag":"proxy","server":"edge.example.com","server_port":443,
          "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision",
          "packet_encoding":"xudp",
          "tls":{"enabled":true,"server_name":"www.example.com",
                 "utls":{"enabled":true,"fingerprint":"chrome_pq_psk"},
                 "reality":{"enabled":true,"public_key":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw","short_id":"6ba85179e30d4fc2"},
                 "fragment":true}},
         {"type":"direct","tag":"direct"}]
        """)

    private static let hysteria2 = config(dns: dnsNewFormat, outbounds: """
        [{"type":"hysteria2","tag":"proxy","server":"edge.example.com","server_port":443,
          "password":"hy2-test-password","server_ports":["20000:30000"],
          "hop_interval":"30s",
          "obfs":{"type":"salamander","password":"obfs-test-password"},
          "tls":{"enabled":true,"server_name":"edge.example.com"}},
         {"type":"direct","tag":"direct"}]
        """)

    private static let wireguard = config(dns: dnsNewFormat, outbounds: """
        [{"type":"direct","tag":"direct"}]
        """, endpoints: """
        [{"type":"wireguard","tag":"proxy","address":["10.7.0.2/32"],"mtu":1420,
          "private_key":"cKE7LmCF61IhqqABGhvJ44jWXp8fKymcMAEVAzLDYVk=",
          "peers":[{"address":"198.51.100.7","port":51820,
                    "public_key":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw=",
                    "allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":25}]}]
        """)

    private static let anytls = config(dns: dnsNewFormat, outbounds: """
        [{"type":"anytls","tag":"proxy","server":"edge.example.com","server_port":443,
          "password":"anytls-test-password",
          "tls":{"enabled":true,"server_name":"edge.example.com"}},
         {"type":"direct","tag":"direct"}]
        """)

    private func parse(_ json: String) -> [String: Any] {
        (try! JSONSerialization.jsonObject(with: Data(json.utf8))) as! [String: Any]
    }

    private func outbound(_ root: [String: Any], tag: String = "proxy") -> [String: Any] {
        ((root["outbounds"] as! [[String: Any]]).first { ($0["tag"] as? String) == tag })!
    }

    // MARK: Pin table

    func testPinTable() {
        let t13 = EngineTier.ios13
        XCTAssertEqual(t13.singBoxVersion, "1.12.12")
        XCTAssertEqual(t13.deploymentTarget, "13.0")
        XCTAssertEqual(t13.gomobileVersion, "v0.1.8")
        XCTAssertEqual(t13.goModDirective, "1.23.1")
        XCTAssertEqual(t13.sourceSHA256,
                       "f08add81eab7e4d6091195179bb39fa3f64dbb0326feaa022994566b702d1245")

        let t12 = EngineTier.ios12
        XCTAssertEqual(t12.singBoxVersion, "1.11.15")
        XCTAssertEqual(t12.deploymentTarget, "12.0")
        XCTAssertEqual(t12.gomobileVersion, "v0.1.4")
        XCTAssertEqual(t12.goModDirective, "1.20")
        // The directive is not the build floor: WS3 measured the
        // pin failing on Go 1.20 (quic-go !go1.21 ECH guard) and
        // building on 1.22.12.
        XCTAssertEqual(t12.measuredBuildGo, "1.22.12")
        XCTAssertEqual(t12.sourceSHA256,
                       "97d58dd873d7cf9b5e4b4aca5516568f3b2e6f5c3dbc93241c82fff5e4a609fd")
        XCTAssertEqual(t12.linuxBinarySHA256,
                       "950af37eb2d7e55dddae34a18411cd617303fd99d2dc75bc76b6dd9fcd97d9c5")
    }

    func testCapabilityDeltas() {
        let c13 = EngineTier.ios13.capabilities
        let c12 = EngineTier.ios12.capabilities
        XCTAssertEqual(c13.dnsFormat, .new)
        XCTAssertEqual(c12.dnsFormat, .legacy)
        XCTAssertEqual(c13.platformInterfaceMethods, 18)
        XCTAssertEqual(c12.platformInterfaceMethods, 16)
        XCTAssertEqual(c13.localDNSRegistration, .platformInterfaceMethod)
        XCTAssertEqual(c12.localDNSRegistration, .globalRegisterFunction)
        XCTAssertTrue(c13.systemCertificates)
        XCTAssertFalse(c12.systemCertificates)
        XCTAssertTrue(c13.anytls && c13.tlsFragment)
        XCTAssertFalse(c12.anytls || c12.tlsFragment)
        // Neither upstream pin, on either tier:
        XCTAssertFalse(c13.xhttp || c12.xhttp)
        XCTAssertFalse(c13.amneziaWG || c12.amneziaWG)
        XCTAssertFalse(c13.echQueryServerName || c12.echQueryServerName)
        // The fingerprint delta is exactly one name.
        XCTAssertEqual(c13.utlsFingerprints.symmetricDifference(c12.utlsFingerprints),
                       ["chrome_pq_psk"])
        XCTAssertEqual(c12.utlsFingerprints.count, 14)
        XCTAssertEqual(c13.utlsFingerprints.count, 15)
        // Obfuscation derivation agrees on both tiers.
        for caps in [c13, c12] {
            XCTAssertTrue(caps.obfuscation.reality && caps.obfuscation.vision && caps.obfuscation.ech)
            XCTAssertEqual(caps.obfuscation.hy2Obfs, ["salamander"])
        }
        XCTAssertTrue(c13.obfuscation.tlsFragment)
        XCTAssertFalse(c12.obfuscation.tlsFragment)
    }

    // MARK: ios13 identity

    func testIOS13AdapterIsIdentity() throws {
        let adapted = try TierConfigAdapter.adapt(configJSON: Self.vlessRealityFragment, for: .ios13)
        XCTAssertEqual(adapted.configJSON, Self.vlessRealityFragment)
        XCTAssertTrue(adapted.degraded.isEmpty)
    }

    // MARK: ios12 DNS translation

    func testIOS12DNSTranslation() throws {
        let adapted = try TierConfigAdapter.adapt(configJSON: Self.hysteria2, for: .ios12)
        // The fixture's only degradation is the route resolver
        // removal (pinned in detail by
        // testIOS12RouteDefaultDomainResolverDegrades).
        XCTAssertEqual(adapted.degraded,
                       [TierDegradation(feature: "routeDefaultDomainResolver",
                                        detail: "dns-1")])
        let root = parse(adapted.configJSON)
        let dns = root["dns"] as! [String: Any]
        let servers = dns["servers"] as! [[String: Any]]
        XCTAssertEqual(servers.count, 3)
        XCTAssertEqual(servers[0]["address"] as? String, "https://1.1.1.1/dns-query")
        XCTAssertNil(servers[0]["type"])
        XCTAssertEqual(servers[1]["address"] as? String, "local")
        XCTAssertEqual(servers[2]["address"] as? String, "fakeip")
        let fakeip = dns["fakeip"] as! [String: Any]
        XCTAssertEqual(fakeip["enabled"] as? Bool, true)
        XCTAssertEqual(fakeip["inet4_range"] as? String, "198.18.0.0/15")
        let rules = dns["rules"] as! [[String: Any]]
        XCTAssertTrue(rules.contains {
            ($0["query_type"] as? [String]) == ["A", "AAAA"] && ($0["server"] as? String) == "fakeip"
        }, "the query_type rule still steers A/AAAA at the fakeip server entry")
        XCTAssertEqual(dns["final"] as? String, "dns-1")
        XCTAssertEqual(dns["strategy"] as? String, "ipv4_only")
        let route = root["route"] as! [String: Any]
        XCTAssertNil(route["default_domain_resolver"],
                     "1.11 has no route.default_domain_resolver")
    }

    func testIOS12DNSHostnameResolverAndDetour() throws {
        // A hostname resolver (domain_resolver -> address_resolver)
        // on a proxy-only detour (both are this renderer's shapes).
        let dns = """
            {"servers":[
              {"tag":"dns-1","type":"tls","server":"dns.example.com","server_port":853,
               "domain_resolver":"local","detour":"proxy"},
              {"tag":"local","type":"local"}
            ],"final":"dns-1","strategy":"ipv4_only","disable_cache":true}
            """
        let cfg = Self.config(dns: dns, outbounds: """
            [{"type":"direct","tag":"proxy"}]
            """)
        let adapted = try TierConfigAdapter.adapt(configJSON: cfg, for: .ios12)
        let root = parse(adapted.configJSON)
        let servers = (root["dns"] as! [String: Any])["servers"] as! [[String: Any]]
        XCTAssertEqual(servers[0]["address"] as? String, "tls://dns.example.com:853")
        XCTAssertEqual(servers[0]["address_resolver"] as? String, "local")
        XCTAssertEqual(servers[0]["detour"] as? String, "proxy")
        XCTAssertEqual((root["dns"] as! [String: Any])["disable_cache"] as? Bool, true)
    }

    func testIOS12DNSUntranslatableKeyRefuses() {
        let dns = """
            {"servers":[{"tag":"dns-1","type":"https","server":"1.1.1.1","tls":{"enabled":true}}],
             "final":"dns-1"}
            """
        let cfg = Self.config(dns: dns, outbounds: "[{\"type\":\"direct\",\"tag\":\"proxy\"}]")
        XCTAssertThrowsError(try TierConfigAdapter.adapt(configJSON: cfg, for: .ios12)) { error in
            guard case TierAdaptError.dnsUntranslatable = error as! TierAdaptError else {
                return XCTFail("want dnsUntranslatable, got \(error)")
            }
        }
    }

    // MARK: ios12 outbound gates

    func testIOS12AnyTLSRefused() {
        XCTAssertThrowsError(try TierConfigAdapter.adapt(configJSON: Self.anytls, for: .ios12)) { error in
            XCTAssertEqual(error as? TierAdaptError,
                           .mandatoryUnavailable(feature: "anytls", detail: "proxy"))
        }
        // The same config is legal on the shipped tier.
        XCTAssertNoThrow(try TierConfigAdapter.adapt(configJSON: Self.anytls, for: .ios13))
    }

    func testIOS12XHTTPRefused() {
        let cfg = Self.config(dns: Self.dnsNewFormat, outbounds: """
            [{"type":"vless","tag":"proxy","server":"edge.example.com","server_port":443,
              "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811",
              "transport":{"type":"xhttp","path":"/xhttp"},
              "tls":{"enabled":true,"server_name":"edge.example.com"}},
             {"type":"direct","tag":"direct"}]
            """)
        XCTAssertThrowsError(try TierConfigAdapter.adapt(configJSON: cfg, for: .ios12)) { error in
            XCTAssertEqual(error as? TierAdaptError,
                           .mandatoryUnavailable(feature: "xhttpTransport", detail: "proxy"))
        }
    }

    func testIOS12RealityKeyShareRefused() throws {
        // REALITY key_share is the lx fork's spelling (the
        // renderer's "hybrid"/"classical" values); neither upstream
        // pin carries it, so the adapter refuses rather than
        // letting the engine fail on an unknown field.
        let withKeyShare = Self.config(dns: Self.dnsNewFormat, outbounds: """
            [{"type":"vless","tag":"proxy","server":"edge.example.com","server_port":443,
              "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision",
              "tls":{"enabled":true,"server_name":"www.example.com",
                     "utls":{"enabled":true,"fingerprint":"chrome"},
                     "reality":{"enabled":true,"public_key":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw","short_id":"6ba85179e30d4fc2","key_share":"hybrid"}}},
             {"type":"direct","tag":"direct"}]
            """)
        XCTAssertThrowsError(try TierConfigAdapter.adapt(configJSON: withKeyShare, for: .ios12)) { error in
            XCTAssertEqual(error as? TierAdaptError,
                           .mandatoryUnavailable(feature: "realityKeyShare", detail: "proxy"))
        }
        // The same config is untouched on the shipped tier (the
        // adapter is the identity there).
        XCTAssertNoThrow(try TierConfigAdapter.adapt(configJSON: withKeyShare, for: .ios13))
        // Negative control: the identical config without key_share
        // adapts — the gate fires on that field alone, and the
        // REALITY block survives adaptation intact.
        let withoutKeyShare = Self.config(dns: Self.dnsNewFormat, outbounds: """
            [{"type":"vless","tag":"proxy","server":"edge.example.com","server_port":443,
              "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision",
              "tls":{"enabled":true,"server_name":"www.example.com",
                     "utls":{"enabled":true,"fingerprint":"chrome"},
                     "reality":{"enabled":true,"public_key":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw","short_id":"6ba85179e30d4fc2"}}},
             {"type":"direct","tag":"direct"}]
            """)
        let adapted = try TierConfigAdapter.adapt(configJSON: withoutKeyShare, for: .ios12)
        let reality = (outbound(parse(adapted.configJSON))["tls"] as! [String: Any])["reality"] as! [String: Any]
        XCTAssertEqual(reality["public_key"] as? String,
                       "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw")
        XCTAssertNil(reality["key_share"])
    }

    func testIOS12RouteDefaultDomainResolverDegrades() throws {
        // The shared fixture carries route.default_domain_resolver
        // {"server":"dns-1"}: 1.11 has no spelling for it, so the
        // field is removed AND the removal is recorded in
        // degraded — a programmatic consumer (UI/log) must see it,
        // not only the docs.
        let adapted = try TierConfigAdapter.adapt(configJSON: Self.hysteria2, for: .ios12)
        XCTAssertEqual(adapted.degraded,
                       [TierDegradation(feature: "routeDefaultDomainResolver",
                                        detail: "dns-1")])
        let route = parse(adapted.configJSON)["route"] as! [String: Any]
        XCTAssertNil(route["default_domain_resolver"],
                     "1.11 has no route.default_domain_resolver")
        // Negative control: a config without the field records no
        // such degradation (and nothing else degrades either).
        let withoutResolver = """
            {"dns":\(Self.dnsNewFormat),
             "outbounds":[{"type":"direct","tag":"proxy"}],
             "route":{"auto_detect_interface":true,"final":"proxy"}}
            """
        let clean = try TierConfigAdapter.adapt(configJSON: withoutResolver, for: .ios12)
        XCTAssertTrue(clean.degraded.isEmpty)
        XCTAssertNil((parse(clean.configJSON)["route"] as! [String: Any])["default_domain_resolver"])
    }

    func testIOS12FragmentAndFingerprintDegrade() throws {
        let adapted = try TierConfigAdapter.adapt(configJSON: Self.vlessRealityFragment, for: .ios12)
        XCTAssertEqual(Set(adapted.degraded.map(\.feature)),
                       ["tlsFragment", "utlsFingerprint", "routeDefaultDomainResolver"])
        let tls = outbound(parse(adapted.configJSON))["tls"] as! [String: Any]
        XCTAssertNil(tls["fragment"], "1.11 refuses the fragment field at load")
        let utls = tls["utls"] as! [String: Any]
        XCTAssertEqual(utls["fingerprint"] as? String, "chrome",
                       "REALITY keeps uTLS with the all-pin fingerprint, marked degraded")
        XCTAssertEqual(adapted.degraded.first { $0.feature == "utlsFingerprint" }?.detail,
                       "chrome_pq_psk")
    }

    func testIOS12PlainTLSFingerprintDropsUTLS() throws {
        let cfg = Self.config(dns: Self.dnsNewFormat, outbounds: """
            [{"type":"trojan","tag":"proxy","server":"edge.example.com","server_port":443,
              "password":"trojan-test-password",
              "tls":{"enabled":true,"server_name":"edge.example.com",
                     "utls":{"enabled":true,"fingerprint":"chrome_pq_psk"}}},
             {"type":"direct","tag":"direct"}]
            """)
        let adapted = try TierConfigAdapter.adapt(configJSON: cfg, for: .ios12)
        XCTAssertEqual(adapted.degraded, [TierDegradation(feature: "utlsFingerprint",
                                                         detail: "chrome_pq_psk"),
                                          TierDegradation(feature: "routeDefaultDomainResolver",
                                                          detail: "dns-1")])
        let tls = outbound(parse(adapted.configJSON))["tls"] as! [String: Any]
        XCTAssertNil(tls["utls"], "plain TLS omits uTLS instead of emitting a refused name")
    }

    func testIOS12InSetFingerprintUntouched() throws {
        let cfg = Self.config(dns: Self.dnsNewFormat, outbounds: """
            [{"type":"trojan","tag":"proxy","server":"edge.example.com","server_port":443,
              "password":"trojan-test-password",
              "tls":{"enabled":true,"server_name":"edge.example.com",
                     "utls":{"enabled":true,"fingerprint":"chrome"}}},
             {"type":"direct","tag":"direct"}]
            """)
        let adapted = try TierConfigAdapter.adapt(configJSON: cfg, for: .ios12)
        XCTAssertEqual(adapted.degraded,
                       [TierDegradation(feature: "routeDefaultDomainResolver",
                                        detail: "dns-1")],
                       "the in-set fingerprint itself is untouched; only the route resolver degrades")
        let tls = outbound(parse(adapted.configJSON))["tls"] as! [String: Any]
        XCTAssertEqual((tls["utls"] as! [String: Any])["fingerprint"] as? String, "chrome")
    }

    func testIOS12ECHQueryServerNameDegrades() throws {
        let cfg = Self.config(dns: Self.dnsNewFormat, outbounds: """
            [{"type":"trojan","tag":"proxy","server":"edge.example.com","server_port":443,
              "password":"trojan-test-password",
              "tls":{"enabled":true,"server_name":"edge.example.com",
                     "ech":{"enabled":true,"query_server_name":"ech.example.com"}}},
             {"type":"direct","tag":"direct"}]
            """)
        let adapted = try TierConfigAdapter.adapt(configJSON: cfg, for: .ios12)
        XCTAssertEqual(adapted.degraded, [TierDegradation(feature: "echQueryServerName",
                                                         detail: "ech.example.com"),
                                          TierDegradation(feature: "routeDefaultDomainResolver",
                                                          detail: "dns-1")])
        let tls = outbound(parse(adapted.configJSON))["tls"] as! [String: Any]
        XCTAssertNil((tls["ech"] as! [String: Any])["query_server_name"])
    }

    func testIOS12WireGuardPlainPassesAWGGates() throws {
        let adapted = try TierConfigAdapter.adapt(configJSON: Self.wireguard, for: .ios12)
        XCTAssertEqual(adapted.degraded,
                       [TierDegradation(feature: "routeDefaultDomainResolver",
                                        detail: "dns-1")],
                       "plain WireGuard itself degrades nothing; only the route resolver does")
        let awg = Self.config(dns: Self.dnsNewFormat, outbounds: "[{\"type\":\"direct\",\"tag\":\"direct\"}]",
                              endpoints: """
            [{"type":"wireguard","tag":"proxy","address":["10.7.0.2/32"],
              "private_key":"cKE7LmCF61IhqqABGhvJ44jWXp8fKymcMAEVAzLDYVk=","h1":"100000-100100",
              "peers":[{"address":"198.51.100.7","port":51820,
                        "public_key":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw=",
                        "allowed_ips":["0.0.0.0/0"]}]}]
            """)
        XCTAssertThrowsError(try TierConfigAdapter.adapt(configJSON: awg, for: .ios12)) { error in
            XCTAssertEqual(error as? TierAdaptError,
                           .mandatoryUnavailable(feature: "amneziaWG", detail: "proxy"))
        }
    }

    // MARK: External check export (sora pattern)

    /// Writes the adapted fixtures to `$WS4_EXPORT_DIR` for the
    /// real-binary `sing-box check` run, plus the unadapted VLESS
    /// fixture as the negative control. No-op without the env var.
    func testExportTierConfigsForExternalCheck() throws {
        guard let dir = ProcessInfo.processInfo.environment["WS4_EXPORT_DIR"] else { return }
        let fm = FileManager.default
        try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let fixtures: [(String, String)] = [
            ("vless-reality-fragment", Self.vlessRealityFragment),
            ("hysteria2", Self.hysteria2),
            ("wireguard", Self.wireguard),
        ]
        for (name, raw) in fixtures {
            let adapted = try TierConfigAdapter.adapt(configJSON: raw, for: .ios12)
            try adapted.configJSON.write(toFile: "\(dir)/\(name).json",
                                         atomically: true, encoding: .utf8)
        }
        try Self.vlessRealityFragment.write(toFile: "\(dir)/raw-vless-reality-fragment.json",
                                            atomically: true, encoding: .utf8)

        // Real renders: every *.json in $WS4_IMPORT_DIR (produced by
        // core/mobileapi.RenderSingBoxConfig on Linux) is adapted
        // and written as real-<name>; the unadapted originals stay
        // in the import dir as negative controls for the same run.
        if let importDir = ProcessInfo.processInfo.environment["WS4_IMPORT_DIR"] {
            var refusals: [String] = []
            for name in try fm.contentsOfDirectory(atPath: importDir) where name.hasSuffix(".json") {
                let raw = try String(contentsOfFile: "\(importDir)/\(name)", encoding: .utf8)
                do {
                    let adapted = try TierConfigAdapter.adapt(configJSON: raw, for: .ios12)
                    try adapted.configJSON.write(toFile: "\(dir)/real-\(name)",
                                                 atomically: true, encoding: .utf8)
                } catch let error as TierAdaptError {
                    // A mandatory gate firing on a real render is
                    // evidence, not a test failure: the refusal is
                    // recorded and the loop continues (AnyTLS is
                    // the expected case — the Go catalog renders it
                    // for 1.12, this tier must refuse it).
                    refusals.append("\(name): \(error)")
                }
            }
            if !refusals.isEmpty {
                try refusals.joined(separator: "\n")
                    .write(toFile: "\(dir)/refusals.txt",
                           atomically: true, encoding: .utf8)
            }
        }
    }
}
