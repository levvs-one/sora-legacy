import Foundation

/// The capability matrix of the macOS legacy client, as data.
///
/// Every row states what this client can do on a given system, what it
/// needs, and — where the honest answer is "no" or "not verified" —
/// why. The UI renders these rows verbatim; no screen invents its own
/// capability claims. The facts behind the rows:
///
/// - TUN: the engine runs inside the root LaunchDaemon
///   (service/darwin) and creates its utun with auto_route. The core's
///   host-side route helper (core/engine/tunroute) is Linux-only and
///   the kill-switch firewall on darwin is a no-op
///   (core/guard/nftables_other.go) — both are stated, not hidden.
/// - System proxy: no TUN at all. The daemon session runs in
///   application mode, which always opens its loopback local proxy,
///   and this app (user session) points the macOS system proxy at it
///   via SystemProxyController. The system proxy belongs to the
///   signed-in user (core/guard documents the same split).
/// - Floors, measured from the Mach-O load commands of the real
///   binaries (2026-10-22, see engines-darwin.lock): the core daemon
///   and the helper declare min macOS 12.0 (the Go toolchain's darwin
///   floor) — below 12.0 this app launches and explains, but the
///   service cannot run. Engines differ per arch: Xray 12.0,
///   mihomo 10.13/11.0, sing-box only as the upstream
///   legacy-macos-10.13 Intel build (the regular 1.14.3 darwin builds
///   declare min macOS 26.0; on Apple Silicon below 26 there is no
///   sing-box). The per-engine truth at runtime is the daemon's
///   GetAbout / the core catalog — this matrix is the summary, not a
///   substitute.
/// - NetworkExtension: not implemented. It would need a developer ID,
///   the network-extension entitlement, system-extension approval and
///   notarization; on the old systems this client targets it is also
///   the wrong tool. It is listed as a prospect, never as a feature.
public enum CapabilityMode: String {
    case tunViaService
    case systemProxy
    case networkExtension
}

public struct Capability: Equatable {
    public let mode: CapabilityMode
    /// What the user can be told, in one line.
    public let summary: String
    /// "available", "degraded", "not-implemented" — machine-stable
    /// data for code and tests; the UI does not show these tokens.
    public let availability: String
    /// The price or the blocker, in plain words for the user.
    public let cost: String
}

public enum Capabilities {
    /// Minimum system this CLIENT targets: macOS 10.13 (High Sierra).
    /// AppKit APIs used in the common path all exist there; anything
    /// newer is behind an availability check with a stated fallback.
    public static let minimumSystem = "10.13"

    /// Minimum system the SERVICE (daemon + helper) runs on, measured
    /// from their Mach-O load commands: 12.0. Below it the client can
    /// only explain the situation — see serviceAvailable.
    public static let serviceMinimumSystem = "12.0"

    /// Whether the core service can run on this system at all.
    public static func serviceAvailable(major: Int, minor: Int) -> Bool {
        // macOS majors are 10, 11, 12, ... 26: the daemon floor is a
        // plain major-version comparison.
        return major >= 12
    }

    public static func matrix(systemVersion: String) -> [Capability] {
        let sys = runningSystem()
        let service = serviceAvailable(major: sys.major, minor: sys.minor)
        let serviceState = service ? "available-unverified" : "unavailable-below-service-floor"
        return [
            Capability(
                mode: .tunViaService,
                summary: "TUN through the core service",
                availability: serviceState,
                cost: "Needs the core service installed and macOS 12 or newer. " +
                      "Kill switch is NOT enforced on macOS. " +
                      "Not verified on real hardware."
            ),
            Capability(
                mode: .systemProxy,
                summary: "System proxy through the core service",
                availability: serviceState,
                cost: "Needs the core service and macOS 12 or newer. " +
                      "Only apps that use the system proxy are covered — not all traffic. " +
                      "Changing the system proxy may ask for administrator approval."
            ),
            Capability(
                mode: .networkExtension,
                summary: "NetworkExtension / PacketTunnel provider",
                availability: "not-implemented",
                cost: "Not available in this client."
            ),
        ]
    }

    /// Whether the running system meets the client's floor.
    public static func meetsFloor(major: Int, minor: Int) -> Bool {
        if major > 10 { return true }
        if major == 10 { return minor >= 13 }
        return false
    }

    /// Components of the running system version, for the floor check
    /// and for honest display. ProcessInfo's version is available
    /// since 10.10, safely below the floor.
    public static func runningSystem() -> (major: Int, minor: Int, patch: Int) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion)
    }
}
