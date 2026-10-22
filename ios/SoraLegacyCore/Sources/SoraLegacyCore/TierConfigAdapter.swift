import Foundation

/// One feature of a rendered config that a tier cannot emit and
/// the adapter therefore dropped or substituted — the degradable
/// class of the main tree's tier model: the stored plan and the
/// rendered (newer-format) config keep the feature; the tier's
/// engine never sees it; this value is what lets the UI and the
/// logs say so honestly instead of the drop being silent.
public struct TierDegradation: Equatable {
    /// Technical feature name (e.g. "tlsFragment",
    /// "utlsFingerprint", "echQueryServerName").
    public var feature: String
    /// The concrete value where one exists (the fingerprint name,
    /// the ECH query server name), else empty.
    public var detail: String
    public init(feature: String, detail: String = "") {
        self.feature = feature
        self.detail = detail
    }
}

/// The result of adapting a rendered config to a tier: the config
/// to hand libbox, plus every degradation applied on the way.
public struct TierAdaptedConfig: Equatable {
    public var configJSON: String
    public var degraded: [TierDegradation]
    public init(configJSON: String, degraded: [TierDegradation]) {
        self.configJSON = configJSON
        self.degraded = degraded
    }
}

public enum TierAdaptError: Error, Equatable {
    case notJSON
    case rootNotObject
    /// A feature that changes what the server speaks (protocol,
    /// transport, obfs framing, REALITY key-share spelling): the
    /// adapter refuses instead of emitting a different connection
    /// under the same plan. The core catalog normally refuses
    /// these plans even earlier (for the static sing-box entry);
    /// this is the adapter-level backstop for configs that arrive
    /// by any other path.
    case mandatoryUnavailable(feature: String, detail: String)
    /// A DNS key or server shape with no pre-1.12 spelling: the
    /// translation refuses rather than dropping it silently.
    case dnsUntranslatable(String)
}

/// Adapts a config rendered by `core/mobileapi` (which renders
/// for the static catalog entry — the 1.12.0 floor) to a tier's
/// libbox pin.
///
/// For `.ios13` this is the identity: the rendered format IS the
/// pin's format, and the existing client path is untouched.
///
/// For `.ios12` (sing-box 1.11.15) it performs, in order:
///  1. mandatory gates over outbounds/endpoints (AnyTLS, XHTTP,
///     AmneziaWG parameters, REALITY `key_share`) — refusal, see
///     `TierAdaptError.mandatoryUnavailable`;
///  2. degradable drops/substitutions in outbound TLS blocks
///     (`fragment`, ECH `query_server_name`, out-of-set uTLS
///     fingerprints), each recorded in `degraded`;
///  3. DNS translation to the pre-1.12 format (mirrors the main
///     tree's `LibboxConfigBuilder.legacyDNSConfig`, adapted to
///     this renderer's shapes: `detour` exists in 1.11's server
///     options and is carried; the fakeip server becomes the
///     `dns.fakeip` block plus an `{"address": "fakeip"}` server
///     entry, the spelling 1.11 routes the query_type rule
///     through);
///  4. removal of `route.default_domain_resolver` (no 1.11
///     spelling; outbound server names resolve through the DNS
///     servers' `address_resolver` chain instead).
///
/// The translation's honesty rule is the main tree's: every key
/// must have a known counterpart or the adaptation throws —
/// nothing is silently dropped except the four documented spots
/// (the two TLS drops, the fingerprint substitution, and
/// `default_domain_resolver`, each of which is either recorded in
/// `degraded` or, for the resolver, a pure routing hint whose
/// 1.11 mechanism is the address_resolver chain kept in step 3).
public enum TierConfigAdapter {
    public static func adapt(configJSON: String, for tier: EngineTier) throws -> TierAdaptedConfig {
        guard tier != .ios13 else {
            return TierAdaptedConfig(configJSON: configJSON, degraded: [])
        }
        let caps = tier.capabilities
        guard let data = configJSON.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) else {
            throw TierAdaptError.notJSON
        }
        guard var root = parsed as? [String: Any] else { throw TierAdaptError.rootNotObject }
        var degraded: [TierDegradation] = []

        // 1+2. Outbound / endpoint gates and TLS degradations.
        for section in ["outbounds", "endpoints"] {
            guard var list = root[section] as? [[String: Any]] else { continue }
            for i in list.indices {
                list[i] = try adaptOutbound(list[i], caps: caps, degraded: &degraded)
            }
            root[section] = list
        }

        // 3. DNS translation.
        if caps.dnsFormat == .legacy, let dns = root["dns"] as? [String: Any] {
            root["dns"] = try translateDNS(dns)
        }

        // 4. route.default_domain_resolver has no 1.11 spelling.
        if var route = root["route"] as? [String: Any], route["default_domain_resolver"] != nil {
            route.removeValue(forKey: "default_domain_resolver")
            root["route"] = route
        }

        let out = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return TierAdaptedConfig(configJSON: String(decoding: out, as: UTF8.self),
                                 degraded: degraded)
    }

    // MARK: Outbounds

    private static let amneziaWGKeys: Set<String> = [
        "jc", "jmin", "jmax", "h1", "h2", "h3", "h4",
        "s1", "s2", "s3", "s4", "i1", "i2", "i3", "i4", "i5",
    ]

    private static func adaptOutbound(_ outbound: [String: Any], caps: TierCapabilities,
                                      degraded: inout [TierDegradation]) throws -> [String: Any] {
        var out = outbound
        let type = out["type"] as? String ?? ""
        let tag = out["tag"] as? String ?? type

        if type == "anytls", !caps.anytls {
            throw TierAdaptError.mandatoryUnavailable(feature: "anytls", detail: tag)
        }
        if let transport = out["transport"] as? [String: Any],
           (transport["type"] as? String) == "xhttp", !caps.xhttp {
            throw TierAdaptError.mandatoryUnavailable(feature: "xhttpTransport", detail: tag)
        }
        if type == "wireguard", !caps.amneziaWG,
           !amneziaWGKeys.intersection(out.keys).isEmpty {
            throw TierAdaptError.mandatoryUnavailable(feature: "amneziaWG", detail: tag)
        }

        guard var tls = out["tls"] as? [String: Any] else { return out }

        if let reality = tls["reality"] as? [String: Any], reality["key_share"] != nil {
            // The lx fork's spelling; neither upstream pin carries
            // it and the core catalog refuses such plans for the
            // static entry — the adapter refuses too rather than
            // letting the engine fail on an unknown field.
            throw TierAdaptError.mandatoryUnavailable(feature: "realityKeyShare", detail: tag)
        }

        if (tls["fragment"] as? Bool) == true, !caps.tlsFragment {
            tls.removeValue(forKey: "fragment")
            tls.removeValue(forKey: "record_fragment")
            degraded.append(TierDegradation(feature: "tlsFragment", detail: tag))
        }

        if var ech = tls["ech"] as? [String: Any],
           let qsn = ech["query_server_name"] as? String, !qsn.isEmpty,
           !caps.echQueryServerName {
            ech.removeValue(forKey: "query_server_name")
            tls["ech"] = ech
            degraded.append(TierDegradation(feature: "echQueryServerName", detail: qsn))
        }

        if var utls = tls["utls"] as? [String: Any],
           let fingerprint = utls["fingerprint"] as? String, !fingerprint.isEmpty,
           !caps.utlsFingerprints.contains(fingerprint) {
            if tls["reality"] != nil {
                // A REALITY client without uTLS is refused by the
                // engine at load, so the fingerprint is substituted
                // with the one name every pin resolves — and marked.
                utls["fingerprint"] = "chrome"
                tls["utls"] = utls
            } else {
                // Plain TLS: omit uTLS entirely (the engine's plain
                // TLS stack) rather than emitting a name the pin
                // refuses at load.
                tls.removeValue(forKey: "utls")
            }
            degraded.append(TierDegradation(feature: "utlsFingerprint", detail: fingerprint))
        }

        out["tls"] = tls
        return out
    }

    // MARK: DNS translation (new format -> pre-1.12 format)

    /// Address-scheme spellings of the legacy DNS format, by
    /// new-format server type (sing-box 1.11 `option/dns.go`: the
    /// address string's scheme selects the transport; no scheme
    /// means UDP).
    private static let legacyDNSAddressSchemes: [String: String] = [
        "https": "https://", "tls": "tls://", "quic": "quic://",
        "h3": "h3://", "tcp": "tcp://", "udp": "",
    ]

    /// DNS top-level keys with a 1.11 counterpart (1.11
    /// `option.DNSOptions` + `DNSClientOptions`). Anything else
    /// gates — see the honesty rule in the type docstring.
    private static let legacyDNSKeys: Set<String> = [
        "servers", "rules", "final", "strategy", "disable_cache",
        "disable_expire", "independent_cache", "cache_capacity",
        "client_subnet", "reverse_mapping",
    ]

    /// New-format server keys with a 1.11 counterpart. `detour` is
    /// in this renderer's output (proxy-only DNS) and IS a 1.11
    /// server field (`option.DNSServerOptions.Detour`), so it is
    /// carried verbatim — the one place this translation differs
    /// from the main tree's, whose renderer never emits it.
    private static let legacyDNSServerKeys: Set<String> = [
        "type", "tag", "server", "server_port", "path",
        "domain_resolver", "detour", "inet4_range", "inet6_range",
    ]

    private static func translateDNS(_ dns: [String: Any]) throws -> [String: Any] {
        for key in dns.keys where !legacyDNSKeys.contains(key) {
            throw TierAdaptError.dnsUntranslatable("dns key \"\(key)\" has no legacy spelling")
        }
        guard let servers = dns["servers"] as? [[String: Any]] else {
            throw TierAdaptError.dnsUntranslatable("dns.servers is not a server list")
        }
        var translated: [[String: Any]] = []
        var fakeipBlock: [String: Any]?
        for srv in servers {
            for key in srv.keys where !legacyDNSServerKeys.contains(key) {
                throw TierAdaptError.dnsUntranslatable("dns server key \"\(key)\" has no legacy spelling")
            }
            guard let type = srv["type"] as? String, let tag = srv["tag"] as? String else {
                throw TierAdaptError.dnsUntranslatable("dns server without type/tag")
            }
            if type == "fakeip" {
                guard fakeipBlock == nil else {
                    throw TierAdaptError.dnsUntranslatable("duplicate fakeip server")
                }
                var block: [String: Any] = ["enabled": true]
                if let v4 = srv["inet4_range"] { block["inet4_range"] = v4 }
                if let v6 = srv["inet6_range"] { block["inet6_range"] = v6 }
                fakeipBlock = block
                translated.append(["tag": tag, "address": "fakeip"])
                continue
            }
            var out: [String: Any] = ["tag": tag]
            if type == "local" {
                out["address"] = "local"
            } else {
                guard let scheme = legacyDNSAddressSchemes[type],
                      let host = srv["server"] as? String else {
                    throw TierAdaptError.dnsUntranslatable("dns server type \"\(type)\" has no legacy spelling")
                }
                var address = legacyAddress(scheme: scheme, host: host,
                                            port: intValue(srv["server_port"]))
                if type == "https" {
                    // This renderer emits no `path`; the 1.11
                    // transport's default is /dns-query, spelled
                    // out here as the measured corpus does.
                    address += (srv["path"] as? String) ?? "/dns-query"
                } else if srv["path"] != nil {
                    throw TierAdaptError.dnsUntranslatable("dns server type \"\(type)\" carries a path")
                }
                out["address"] = address
            }
            if let resolver = srv["domain_resolver"] { out["address_resolver"] = resolver }
            if let detour = srv["detour"] { out["detour"] = detour }
            translated.append(out)
        }
        var out: [String: Any] = ["servers": translated]
        for key in dns.keys where key != "servers" {
            out[key] = dns[key]
        }
        if let fakeipBlock { out["fakeip"] = fakeipBlock }
        return out
    }

    private static func legacyAddress(scheme: String, host: String, port: Int?) -> String {
        let hasPort = (port ?? 0) > 0
        if host.contains(":") {
            // IPv6 literal: the URL forms need brackets. A bare
            // udp address has no unambiguous host:port spelling
            // for an IPv6 literal, so it takes the explicit
            // udp:// scheme (1.11 parses it identically to bare).
            let prefix = scheme.isEmpty ? "udp://" : scheme
            return "\(prefix)[\(host)]" + (hasPort ? ":\(port!)" : "")
        }
        return scheme + host + (hasPort ? ":\(port!)" : "")
    }

    private static func intValue(_ value: Any?) -> Int? {
        if let i = value as? Int { return i }
        if let n = value as? NSNumber { return n.intValue }
        return nil
    }
}
