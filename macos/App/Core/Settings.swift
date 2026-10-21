import Foundation

/// User-facing preferences of the macOS client, in UserDefaults.
/// Kept separate from the helper's state file (owned by the daemon
/// flow) and from the proxy snapshot (owned by SystemProxyController).
public final class Settings {
    private let defaults: UserDefaults
    public init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    private enum Key {
        static let mode = "soralegacy.mode"            // "tun" | "proxy"
        static let killSwitch = "soralegacy.killSwitch"
        static let helperPath = "soralegacy.helperPath"
    }

    /// Connection mode: "tun" (service TUN) or "proxy" (system proxy).
    /// Default is "proxy": it needs no TUN path to work and degrades
    /// honestly; TUN is one explicit choice away.
    public var mode: String {
        get { return defaults.string(forKey: Key.mode) ?? "proxy" }
        set { defaults.set(newValue, forKey: Key.mode) }
    }

    /// The user's kill-switch wish. On macOS the core records it but
    /// does not enforce it (NoopFirewall) — the UI labels it exactly
    /// that way wherever it appears; this flag is a wish, not a claim.
    public var killSwitch: Bool {
        get { return defaults.bool(forKey: Key.killSwitch) }
        set { defaults.set(newValue, forKey: Key.killSwitch) }
    }

    /// Optional explicit helper path (support / development).
    public var helperPathOverride: String? {
        get { return defaults.string(forKey: Key.helperPath) }
        set { defaults.set(newValue, forKey: Key.helperPath) }
    }
}
