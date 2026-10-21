import Foundation
import Security
import SoraLegacyCore

/// A Keychain write failure, carrying the SecItem OSStatus. The
/// status is the whole payload: error text never contains the
/// secret value, only the operation that failed.
enum KeychainSecretsError: Error, CustomStringConvertible {
    case add(OSStatus)
    case delete(OSStatus)
    case probe(OSStatus)
    var description: String {
        switch self {
        case .add(let status): return "Keychain SecItemAdd failed (OSStatus \(status))"
        case .delete(let status): return "Keychain SecItemDelete failed (OSStatus \(status))"
        case .probe(let status): return "Keychain access-group probe failed (OSStatus \(status))"
        }
    }
}

/// Keychain backing for ServerStore's SecretsStore seam: generic
/// passwords in the shared access group (entitlements), so the app
/// writes credentials and — if it ever needs them — the extension
/// reads the same items. Values are the credential JSON documents;
/// they are never logged.
///
/// Access group (this was review blocker B2): the entitlements of
/// both targets grant exactly one group,
/// `$(AppIdentifierPrefix)one.levvs.sora.legacy`, where the prefix
/// placeholder is expanded by Xcode at signing time — in
/// entitlements and plists only, never in Swift sources. Putting
/// the raw Models constant (or the bare bundle id) into
/// `kSecAttrAccessGroup` therefore names a group no entitlement
/// grants, and every SecItem call fails with
/// errSecMissingEntitlement. Instead the group is resolved once at
/// runtime from `SoraLegacyIdentifiers.keychainGroup`: a throwaway
/// probe item is added without an explicit group, the group it
/// landed in is read back, and the probe is deleted. The resolved
/// value must match the constant with the placeholder expanded;
/// if the probe fails, the query omits the group entirely (with a
/// single entitled group the default is that group) and the
/// fallback is logged — never silent.
final class KeychainSecrets: SecretsStore {
    private let service = SoraLegacyIdentifiers.bundleID
    private let accessGroup: String?

    init() {
        accessGroup = Self.resolveAccessGroup(service: service)
    }

    func secret(forKey key: String) -> String? {
        var query = baseQuery(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            // A read failure is not "no secret": log the OSStatus
            // (never the value) so a broken group is diagnosable.
            NSLog("[keychain] read failed for key %@: OSStatus %d", key, status)
            return nil
        }
        return String(decoding: data, as: UTF8.self)
    }

    func setSecret(_ value: String?, forKey key: String) throws {
        let query = baseQuery(key)
        // Delete-then-add is the update path; every OSStatus is
        // checked and a failure is thrown to the caller (ServerStore
        // propagates it; the view controllers log and surface it) —
        // a swallowed failure here is credentials silently lost.
        let deleteStatus = SecItemDelete(query as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw KeychainSecretsError.delete(deleteStatus)
        }
        guard let value else { return }
        var attributes = query
        attributes[kSecValueData as String] = Data(value.utf8)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let addStatus = SecItemAdd(attributes as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainSecretsError.add(addStatus)
        }
    }

    private func baseQuery(_ key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    /// Resolves `$(AppIdentifierPrefix)` in
    /// `SoraLegacyIdentifiers.keychainGroup` to the team prefix the
    /// binary was actually signed with, via a probe item. Returns
    /// nil (→ queries omit the group) when the probe fails or the
    /// resolved group does not match the expected constant; both
    /// cases are logged.
    private static func resolveAccessGroup(service: String) -> String? {
        let probeAccount = "sora.access-group-probe"
        var probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: probeAccount,
        ]
        SecItemDelete(probe as CFDictionary) // clear a stale probe
        probe[kSecValueData as String] = Data()
        let addStatus = SecItemAdd(probe as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            NSLog("[keychain] access-group probe add failed: OSStatus %d — queries will omit the group", addStatus)
            return nil
        }
        defer {
            var delete = probe
            delete.removeValue(forKey: kSecValueData as String)
            SecItemDelete(delete as CFDictionary)
        }
        var readBack = probe
        readBack.removeValue(forKey: kSecValueData as String)
        readBack[kSecReturnAttributes as String] = true
        readBack[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let readStatus = SecItemCopyMatching(readBack as CFDictionary, &item)
        guard readStatus == errSecSuccess,
              let attributes = item as? [String: Any],
              let resolved = attributes[kSecAttrAccessGroup as String] as? String else {
            NSLog("[keychain] access-group probe read failed: OSStatus %d — queries will omit the group", readStatus)
            return nil
        }
        // Cross-check against the Models constant: the resolved
        // group must be the constant with its placeholder expanded
        // to a non-empty prefix.
        let template = SoraLegacyIdentifiers.keychainGroup
        let placeholder = "$(AppIdentifierPrefix)"
        if template.hasPrefix(placeholder) {
            let suffix = String(template.dropFirst(placeholder.count))
            guard resolved.hasSuffix(suffix), resolved.count > suffix.count else {
                NSLog("[keychain] resolved access group does not match the entitlements constant — queries will omit the group")
                return nil
            }
        }
        return resolved
    }
}

/// The store every screen shares: App Group defaults + Keychain.
enum AppStore {
    static let shared: ServerStore = {
        let defaults = UserDefaults(suiteName: SoraLegacyIdentifiers.appGroup) ?? .standard
        return ServerStore(defaults: defaults, secrets: KeychainSecrets())
    }()
    static let mobileAPI: MobileAPI = {
        #if canImport(Mobileapi)
        return GeneratedMobileAPI()
        #else
        return UnavailableMobileAPI()
        #endif
    }()
}

/// Honest stand-in for builds without the Mobileapi framework
/// (BUILD-MAC.md §2 not run): imports fail with the reason instead
/// of crashing on a missing symbol.
struct UnavailableMobileAPI: MobileAPI {
    private var error: MobileAPIError { .engine("Mobileapi framework not linked — run BUILD-MAC.md §2") }
    func importLinks(_ text: String) throws -> [Server] { throw error }
    func parseSubscription(_ body: Data) throws -> [Server] { throw error }
    func buildPlan(_ plan: PlanDocument) throws -> PlanDocument { throw error }
    func renderSingBoxConfig(_ plan: PlanDocument) throws -> String { throw error }
    func engineInfo() -> EngineInfo { EngineInfo(engines: [], defaultPreference: []) }
}
