import Foundation
import Security
import SoraLegacyCore

/// Keychain backing for ServerStore's SecretsStore seam: generic
/// passwords in the shared access group (entitlements), so the app
/// writes credentials and — if it ever needs them — the extension
/// reads the same items. Values are the credential JSON documents;
/// they are never logged.
final class KeychainSecrets: SecretsStore {
    private let service = SoraLegacyIdentifiers.bundleID

    func secret(forKey key: String) -> String? {
        var query = baseQuery(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    func setSecret(_ value: String?, forKey key: String) {
        let query = baseQuery(key)
        SecItemDelete(query as CFDictionary)
        guard let value else { return }
        var attributes = query
        attributes[kSecValueData as String] = Data(value.utf8)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(attributes as CFDictionary, nil)
    }

    private func baseQuery(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrAccessGroup as String: SoraLegacyIdentifiers.bundleID,
        ]
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
