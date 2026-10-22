import Foundation

/// One libbox pin the iOS client can be built against, as data —
/// the additive-tier pattern of the main sora tree's `EngineTier`
/// (apple/SoraCore): the client never branches on an OS version or
/// a tier name anywhere else; every gate reads this table, whose
/// values are measured facts with a cited source per row.
///
/// Tiers:
///  - `.ios13` — the shipped tier, unchanged: upstream sing-box
///    **1.12.12**, sagernet/gomobile v0.1.8, deployment target 13.0
///    (BUILD-MAC.md §1: the pin's `build_libbox` passes no
///    `-iosversion`, so the gomobile default 13.0 IS the floor).
///  - `.ios12` — the additive tier of LEGACY-FULL WS4: upstream
///    sing-box **1.11.15** (newest patch of the 1.11 line),
///    sagernet/gomobile v0.1.4, deployment target 12.0. The floor is
///    NOT the gomobile default (13.0 in v0.1.4 too) — it is set
///    explicitly with `-iosversion 12.0`, which the pin's gomobile
///    accepts for the `ios` target: its only version validation is
///    the Mac Catalyst gate (see `TierEvidence`). The Go runtime's
///    own floor is iOS 12 (go.dev/wiki/MinimumRequirements, "iOS"
///    section: "iOS 12 or later"), so 12.0 is exactly the lowest
///    honest target — 11.x is NOT claimed anywhere in this table.
public enum EngineTier: String, Codable, CaseIterable, Equatable {
    case ios13
    case ios12

    /// Exact engine version this tier binds (the libbox pin).
    public var singBoxVersion: String {
        switch self {
        case .ios13: return "1.12.12"
        case .ios12: return "1.11.15"
        }
    }

    /// SHA-256 of the pin's source archive, measured with
    /// `sha256sum` on the downloaded artifact (1.12.12:
    /// `~/workspace/.legplat/downloads/SHA256SUMS.local`; 1.11.15:
    /// sora `apple/Legacy/engines-legacy.lock`, re-measured in the
    /// WS4 evidence run — report LEGACY-FULL-4-IOS12.md §2).
    public var sourceSHA256: String {
        switch self {
        case .ios13: return "f08add81eab7e4d6091195179bb39fa3f64dbb0326feaa022994566b702d1245"
        case .ios12: return "97d58dd873d7cf9b5e4b4aca5516568f3b2e6f5c3dbc93241c82fff5e4a609fd"
        }
    }

    /// SHA-256 of the pin's official linux-amd64 release archive —
    /// the binary the config-corpus `sing-box check` runs are
    /// executed with (no iOS xcframework is published for either
    /// pin; libbox is built from the source archive above).
    public var linuxBinarySHA256: String {
        switch self {
        case .ios13: return "7c103cb2f9a7dc54cb82962043596718ed27989a478d6405f0939a9b775f889f"
        case .ios12: return "950af37eb2d7e55dddae34a18411cd617303fd99d2dc75bc76b6dd9fcd97d9c5"
        }
    }

    /// The sagernet/gomobile version the pin's `go.mod` resolves
    /// its `build_libbox` to (read from each pin's go.mod).
    public var gomobileVersion: String {
        switch self {
        case .ios13: return "v0.1.8"
        case .ios12: return "v0.1.4"
        }
    }

    /// SHA-256 of that gomobile's source archive (sora
    /// `apple/Legacy/engines-legacy.lock`, re-measured in WS4).
    public var gomobileSourceSHA256: String {
        switch self {
        case .ios13: return "ecbc071eea4c21152cf7c458490ab4404850a2629447856c5770661870a32047"
        case .ios12: return "6101c7f89334e1b53f4bef648bd54c5032bae51661aa8584fdf01dbecdfc4d4a"
        }
    }

    /// The `go` directive of the pin's go.mod. A module-resolution
    /// floor, NOT a buildable-toolchain claim: for `.ios12` the
    /// directive says 1.20 but the pin does NOT build with the Go
    /// 1.20 line — its quic-go fork carries a deliberate
    /// `//go:build !go1.21` guard in the ECH path
    /// (sagernet/quic-go v0.49.0-beta.1 `internal/qtls_ech/
    /// go_oldversion.go`: "ECH can't be built using outdated Go
    /// versions"), measured by LEGACY-FULL WS3 building this pin
    /// (macos/TIERS.md §3.3). See `measuredBuildGo`.
    public var goModDirective: String {
        switch self {
        case .ios13: return "1.23.1"
        case .ios12: return "1.20"
        }
    }

    /// A host Go version MEASURED to build this pin (not derived
    /// from the go.mod directive). `.ios12`: WS3 built the pin's
    /// CLI with Go 1.22.12 after the 1.20 failure above; the
    /// libbox bind compiles the same module graph (with_ech is in
    /// the pin's own tag list), so the tier recipe requires a
    /// ≥ 1.21 host (BUILD-MAC.md §8). `.ios13`: no older-line
    /// measurement exists; the tree's documented host is go1.24.7
    /// (BUILD-MAC.md §2.2).
    public var measuredBuildGo: String {
        switch self {
        case .ios13: return "1.24.7"
        case .ios12: return "1.22.12"
        }
    }

    /// Deployment target this tier's project variant sets. For
    /// `.ios13` this equals the gomobile default (the floor the pin
    /// produces unmodified); for `.ios12` it is one major below
    /// the gomobile default and must be passed explicitly at bind
    /// time (`-iosversion 12.0`, BUILD-MAC.md §8) — an unmodified
    /// `build_libbox` run produces a 13.0 framework, not this tier.
    public var deploymentTarget: String {
        switch self {
        case .ios13: return "13.0"
        case .ios12: return "12.0"
        }
    }

    /// The capability table of this tier's pin. All config gating
    /// for the tier goes through these values (`TierConfigAdapter`);
    /// there is no other place a tier difference may be spelled.
    public var capabilities: TierCapabilities {
        switch self {
        case .ios13: return .ios13
        case .ios12: return .ios12
        }
    }
}

/// DNS wire format of a tier's engine (sing-box changelog 1.12.0:
/// "Refactor DNS servers" — the typed-server format is 1.12+).
public enum TierDNSFormat: String, Codable, Equatable {
    /// sing-box 1.12+ format: typed servers (`type`/`server`/`path`).
    case new
    /// Pre-1.12 format: `address` strings, the fake-IP pool as the
    /// `dns.fakeip` block, `domain_resolver` spelled
    /// `address_resolver`, no `route.default_domain_resolver`.
    case legacy
}

/// How the tier's libbox receives the platform's local DNS
/// transport (experimental/libbox of each pin, read from source).
public enum TierLocalDNSRegistration: String, Codable, Equatable {
    /// 1.12.12: `PlatformInterface.LocalDNSTransport()` — a method
    /// of the platform interface itself (platform.go).
    case platformInterfaceMethod
    /// 1.11.15: the interface has no such method; the transport is
    /// handed over through the package-level
    /// `RegisterLocalDNSTransport(transport)` (dns.go), called by
    /// the bridge before `NewService`.
    case globalRegisterFunction
}

/// The measured capability table of one libbox pin. Sources:
/// sora `apple/Legacy/ENGINES.md` §4 delta table (which covers
/// v1.11.15 column-by-column against the newer lines), the
/// LEGACY-PLAT-OBFS binary probes of the shipped 1.12.12 payload,
/// and the WS4 corpus/probe runs on the real 1.11.15 linux binary
/// (report LEGACY-FULL-4-IOS12.md §5). A `false` names its probe in
/// the comment.
public struct TierCapabilities: Equatable {
    /// DNS server format (ENGINES §4 row 1).
    public var dnsFormat: TierDNSFormat
    /// PlatformInterface method count of the pin's libbox
    /// (experimental/libbox/platform.go, counted from source:
    /// 1.12.12 = 18, 1.11.15 = 16 — the older interface lacks
    /// `LocalDNSTransport()` and `SystemCertificates()`).
    public var platformInterfaceMethods: Int
    /// Local DNS transport registration style (see the enum).
    public var localDNSRegistration: TierLocalDNSRegistration
    /// `PlatformInterface.SystemCertificates()` exists. False on
    /// 1.11.15: no such method anywhere in its libbox (grep of the
    /// pin tree) — the tier's bridge has no certificates seam to
    /// implement; Go falls back to its own root handling, an open
    /// verify-on-mac question carried in the tier notes.
    public var systemCertificates: Bool
    /// AnyTLS protocol (ENGINES §4 row 16: added in sing-box
    /// 1.12.0; `protocol/anytls` absent from the 1.11 tree).
    public var anytls: Bool
    /// Outbound TLS `fragment` (ENGINES §4 row 22: added in
    /// 1.12.0; probe on 1.11.15: `unknown field "fragment"`).
    public var tlsFragment: Bool
    /// ECH `query_server_name` (ENGINES §4 row 21: 1.13+). False
    /// on BOTH tiers here — the static core catalog claims it for
    /// no shipped build, and `mobileapi` refuses such plans before
    /// render; the tier adapter still drops+marks it defensively.
    public var echQueryServerName: Bool
    /// V2Ray XHTTP transport in the upstream libbox build
    /// (ENGINES §4 row 19: lx-fork only; upstream 1.11/1.12 stock
    /// libbox tags carry no `with_xhttp`). False on both tiers;
    /// the core catalog refuses XHTTP plans for the static
    /// sing-box entry before render.
    public var xhttp: Bool
    /// AmneziaWG parameters on the WireGuard endpoint
    /// (ENGINES §4 row 15: lx-fork only; probe on 1.11.15:
    /// `unknown field "h1"`; upstream 1.12.12 refuses the same
    /// way — LEGACY-PLAT-OBFS). False on both tiers.
    public var amneziaWG: Bool
    /// uTLS fingerprint names the pin's uTLS build resolves
    /// (ENGINES §4 row 23). An unknown name is refused by the
    /// engine at load, so the adapter must never emit one outside
    /// this set for the tier.
    public var utlsFingerprints: Set<String>

    public init(dnsFormat: TierDNSFormat, platformInterfaceMethods: Int,
                localDNSRegistration: TierLocalDNSRegistration,
                systemCertificates: Bool, anytls: Bool, tlsFragment: Bool,
                echQueryServerName: Bool, xhttp: Bool, amneziaWG: Bool,
                utlsFingerprints: Set<String>) {
        self.dnsFormat = dnsFormat
        self.platformInterfaceMethods = platformInterfaceMethods
        self.localDNSRegistration = localDNSRegistration
        self.systemCertificates = systemCertificates
        self.anytls = anytls
        self.tlsFragment = tlsFragment
        self.echQueryServerName = echQueryServerName
        self.xhttp = xhttp
        self.amneziaWG = amneziaWG
        self.utlsFingerprints = utlsFingerprints
    }

    /// Fingerprints of the 1.12 uTLS build (ENGINES §4 row 23,
    /// "1.12" column): the 1.11 list plus `chrome_pq_psk`.
    private static let utlsV112: Set<String> = [
        "chrome", "chrome_psk", "chrome_psk_shuffle",
        "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk",
        "firefox", "edge", "safari", "360", "qq", "ios", "android",
        "random", "randomized",
    ]

    /// Upstream sing-box 1.12.12 — the shipped tier. The feature
    /// values are the static core catalog's claims for this pin
    /// (core/engine/catalog.go, validated by LEGACY-PLAT-OBFS on
    /// the real payload binary: 37 PASS / 11 FAIL of 48, the FAILs
    /// being exactly the `false` rows below plus lx spellings).
    public static let ios13 = TierCapabilities(
        dnsFormat: .new,                    // row 1: новый формат
        platformInterfaceMethods: 18,       // platform.go 1.12.12
        localDNSRegistration: .platformInterfaceMethod,
        systemCertificates: true,           // platform.go 1.12.12
        anytls: true,                       // row 16: есть (1.12.0+)
        tlsFragment: true,                  // row 22: есть (1.12.0+)
        echQueryServerName: false,          // row 21: 1.13+, гейт каталога
        xhttp: false,                       // row 19: нет в upstream libbox
        amneziaWG: false,                   // row 15: нет в upstream
        utlsFingerprints: utlsV112          // row 23: список 1.12
    )

    /// Upstream sing-box 1.11.15 — the additive iOS 12 tier.
    public static let ios12 = TierCapabilities(
        dnsFormat: .legacy,                 // row 1: старый формат
        platformInterfaceMethods: 16,       // platform.go 1.11.15
        localDNSRegistration: .globalRegisterFunction,
        systemCertificates: false,          // метода в пине нет
        anytls: false,                      // row 16: нет (probe: no protocol/anytls)
        tlsFragment: false,                 // row 22: нет (probe: unknown field)
        echQueryServerName: false,          // row 21: нет
        xhttp: false,                       // row 19: нет
        amneziaWG: false,                   // row 15: нет (probe: unknown field "h1")
        utlsFingerprints: [                // row 23, список 1.11: без chrome_pq_psk
            "chrome", "chrome_psk", "chrome_psk_shuffle",
            "chrome_padding_psk_shuffle", "chrome_pq",
            "firefox", "edge", "safari", "360", "qq", "ios", "android",
            "random", "randomized",
        ]
    )

    /// Censorship/obfuscation means this tier honestly offers,
    /// derived from the same table (mirrors the derivation in the
    /// main tree's `ObfuscationCapabilities`): REALITY/Vision and
    /// ECH exist on both pins (ENGINES §4 rows 5, 20); Hy2
    /// salamander obfs + port hopping exist on both (rows 7, 10).
    public var obfuscation: TierObfuscation {
        TierObfuscation(capabilities: self)
    }
}

/// The obfuscation surface of one tier, derived — never spelled
/// separately, so UI labels and the adapter can never disagree.
public struct TierObfuscation: Equatable {
    public var reality: Bool
    public var vision: Bool
    public var ech: Bool
    public var echQueryServerName: Bool
    public var tlsFragment: Bool
    public var xhttp: Bool
    public var amneziaWG: Bool
    /// Hysteria2 obfs types: `salamander` on both pins (row 10);
    /// `gecko` is a 1.14 addition neither upstream pin has (row 11).
    public var hy2Obfs: [String]

    public init(capabilities caps: TierCapabilities) {
        reality = true
        vision = true
        ech = true
        echQueryServerName = caps.echQueryServerName
        tlsFragment = caps.tlsFragment
        xhttp = caps.xhttp
        amneziaWG = caps.amneziaWG
        hy2Obfs = ["salamander"]
    }
}

/// Primary-source facts behind the `.ios12` floor, kept in code so
/// the claim is checkable from the tree itself. Full protocol:
/// report LEGACY-FULL-4-IOS12.md §2–§3.
public enum TierEvidence {
    /// sagernet/gomobile v0.1.4 (the 1.11.15 pin's gomobile),
    /// `cmd/gomobile/build.go`: the `-iosversion` flag is a plain
    /// string variable whose default is "13.0" — a default, not a
    /// minimum. The only numeric validation in the whole gomobile
    /// tree is the Mac Catalyst gate (`build.go` runBuildImpl and
    /// `bind_iosapp.go` goAppleBind: `platform == "maccatalyst" &&
    /// v < 13.0`); for the `ios` platform the value flows verbatim
    /// into clang's `-miphoneos-version-min=` (`cmd/gomobile/
    /// env.go`). Executable probe on Linux (WS4): the built
    /// v0.1.4 `gomobile bind -target ios -iosversion 12.0` parses
    /// the flag and fails only with `-target="ios" requires
    /// Xcode` — identically to 13.0.
    public static let gomobileV014AcceptsIOS12 = true

    /// The official golang.org/x/mobile gomobile used for the
    /// Mobileapi bind (pinned pseudo-version in BUILD-MAC.md §2.2)
    /// behaves the same by construction: `cmd/gomobile/
    /// ios_version.go` `validateCatalystVersion` returns nil
    /// immediately for any platform other than "maccatalyst", and
    /// its own test suite asserts `{platform: "ios", iOSVersion:
    /// "invalid"}` produces no error.
    public static let officialGomobileAcceptsIOS12 = true

    /// go.dev/wiki/MinimumRequirements, section "iOS": "iOS 12 or
    /// later" — the Go runtime's own floor for GOOS=ios. A libbox
    /// for this tier is built with a ≥ 1.21 host (the pin does not
    /// build with Go 1.20 — quic-go's `!go1.21` ECH guard, WS3;
    /// see `EngineTier.measuredBuildGo`), and that runtime's
    /// stated iOS minimum is exactly 12.0; nothing in the pin or
    /// either gomobile cuts 12.0 off, and 11.x is below the
    /// runtime floor (not claimed).
    public static let goRuntimeFloor = "12.0"
}
